use core::ops::Deref;
use std_shims::{vec, vec::Vec, collections::HashMap};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY};

use monero_rpc::ScannableBlock;
use monero_serai::{
  io::*,
  primitives::Commitment,
  transaction::{Timelock, Pruned, Transaction},
};
use crate::{
  address::SubaddressIndex, ViewPair, GuaranteedViewPair, output::*, PaymentId, Extra,
  SharedKeyDerivations,
};

/// A collection of potentially additionally timelocked outputs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Timelocked(Vec<WalletOutput>);

impl Timelocked {
  /// Return the outputs which aren't subject to an additional timelock.
  #[must_use]
  pub fn not_additionally_locked(self) -> Vec<WalletOutput> {
    let mut res = vec![];
    for output in &self.0 {
      if output.additional_timelock() == Timelock::None {
        res.push(output.clone());
      }
    }
    res
  }

  /// Return the outputs whose additional timelock unlocks by the specified block/time.
  ///
  /// Additional timelocks are almost never used outside of miner transactions, and are
  /// increasingly planned for removal. Ignoring non-miner additionally-timelocked outputs is
  /// recommended.
  ///
  /// `block` is the block number of the block the additional timelock must be satsified by.
  ///
  /// `time` is represented in seconds since the epoch and is in terms of Monero's on-chain clock.
  /// That means outputs whose additional timelocks are statisfied by `Instant::now()` (the time
  /// according to the local system clock) may still be locked due to variance with Monero's clock.
  #[must_use]
  pub fn additional_timelock_satisfied_by(self, block: usize, time: u64) -> Vec<WalletOutput> {
    let mut res = vec![];
    for output in &self.0 {
      if (output.additional_timelock() <= Timelock::Block(block)) ||
        (output.additional_timelock() <= Timelock::Time(time))
      {
        res.push(output.clone());
      }
    }
    res
  }

  /// Ignore the timelocks and return all outputs within this container.
  #[must_use]
  pub fn ignore_additional_timelock(mut self) -> Vec<WalletOutput> {
    let mut res = vec![];
    core::mem::swap(&mut self.0, &mut res);
    res
  }
}

/// Errors when scanning a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum ScanError {
  /// The block was for an unsupported protocol version.
  #[cfg_attr(feature = "std", error("unsupported protocol version ({0})"))]
  UnsupportedProtocol(u8),
  /// The ScannableBlock was invalid.
  #[cfg_attr(feature = "std", error("invalid scannable block ({0})"))]
  InvalidScannableBlock(&'static str),
}

#[derive(Clone)]
struct InternalScanner {
  pair: ViewPair,
  guaranteed: bool,
  subaddresses: HashMap<CompressedEdwardsY, Option<SubaddressIndex>>,
}

impl Zeroize for InternalScanner {
  fn zeroize(&mut self) {
    self.pair.zeroize();
    self.guaranteed.zeroize();

    // This may not be effective, unfortunately
    for (mut key, mut value) in self.subaddresses.drain() {
      key.zeroize();
      value.zeroize();
    }
  }
}
impl Drop for InternalScanner {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl ZeroizeOnDrop for InternalScanner {}

impl InternalScanner {
  fn new(pair: ViewPair, guaranteed: bool) -> Self {
    let mut subaddresses = HashMap::new();
    subaddresses.insert(pair.spend().compress(), None);
    Self { pair, guaranteed, subaddresses }
  }

  fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    let (spend, _) = self.pair.subaddress_keys(subaddress);
    self.subaddresses.insert(spend.compress(), Some(subaddress));
  }

  fn scan_transaction(
    &self,
    output_index_for_first_ringct_output: u64,
    tx_hash: [u8; 32],
    tx: &Transaction<Pruned>,
  ) -> Result<Timelocked, ScanError> {
    // Only scan TXs creating RingCT outputs
    // For the full details on why this check is equivalent, please see the documentation in `scan`
    if tx.version() != 2 {
      return Ok(Timelocked(vec![]));
    }

    // Read the extra field
    let Ok(extra) = Extra::read::<&[u8]>(&mut tx.prefix().extra.as_ref()) else {
      return Ok(Timelocked(vec![]));
    };

    let Some((tx_keys, additional)) = extra.keys() else {
      return Ok(Timelocked(vec![]));
    };
    let payment_id = extra.payment_id();

    let mut res = vec![];
    for (o, output) in tx.prefix().outputs.iter().enumerate() {
      let Some(output_key) = decompress_point(output.key.to_bytes()) else { continue };

      // Monero checks with each TX key and with the additional key for this output

      // This will be None if there's no additional keys, Some(None) if there's additional keys
      // yet not one for this output (which is non-standard), and Some(Some(_)) if there's an
      // additional key for this output
      // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
      //   /src/cryptonote_basic/cryptonote_format_utils.cpp#L1060-L1070
      let additional = additional.as_ref().map(|additional| additional.get(o));

      #[allow(clippy::manual_let_else)]
      for key in tx_keys.iter().map(|key| Some(Some(key))).chain(core::iter::once(additional)) {
        // Get the key, or continue if there isn't one
        let key = match key {
          Some(Some(key)) => key,
          Some(None) | None => continue,
        };
        // Calculate the ECDH
        let ecdh = Zeroizing::new(self.pair.view.deref() * key);
        let output_derivations = SharedKeyDerivations::output_derivations(
          if self.guaranteed {
            Some(SharedKeyDerivations::uniqueness(&tx.prefix().inputs))
          } else {
            None
          },
          ecdh.clone(),
          o,
        );

        // Check the view tag matches, if there is a view tag
        if let Some(actual_view_tag) = output.view_tag {
          if actual_view_tag != output_derivations.view_tag {
            continue;
          }
        }

        // P - shared == spend
        let Some(subaddress) = ({
          // The output key may be of torsion [0, 8)
          // Our subtracting of a prime-order element means any torsion will be preserved
          // If someone wanted to malleate output keys with distinct torsions, only one will be
          // scanned accordingly (the one which has matching torsion of the spend key)
          let subaddress_spend_key =
            output_key - (&output_derivations.shared_key * ED25519_BASEPOINT_TABLE);
          self.subaddresses.get(&subaddress_spend_key.compress())
        }) else {
          continue;
        };
        let subaddress = *subaddress;

        // The key offset is this shared key
        let mut key_offset = output_derivations.shared_key;
        if let Some(subaddress) = subaddress {
          // And if this was to a subaddress, it's additionally the offset from subaddress spend
          // key to the normal spend key
          key_offset += self.pair.subaddress_derivation(subaddress);
        }
        // Since we've found an output to us, get its amount
        let mut commitment = Commitment::zero();

        // Miner transaction
        if let Some(amount) = output.amount {
          commitment.amount = amount;
        // Regular transaction
        } else {
          let Transaction::V2 { proofs: Some(ref proofs), .. } = &tx else {
            // Invalid transaction, as of consensus rules at the time of writing this code
            Err(ScanError::InvalidScannableBlock("non-miner v2 transaction without RCT proofs"))?
          };

          commitment = match proofs.base.encrypted_amounts.get(o) {
            Some(amount) => output_derivations.decrypt(amount),
            // Invalid transaction, as of consensus rules at the time of writing this code
            None => Err(ScanError::InvalidScannableBlock(
              "RCT proofs without an encrypted amount per output",
            ))?,
          };

          // Rebuild the commitment to verify it
          if Some(&commitment.calculate()) != proofs.base.commitments.get(o) {
            continue;
          }
        }

        // Decrypt the payment ID
        let payment_id = payment_id.map(|id| id ^ SharedKeyDerivations::payment_id_xor(ecdh));

        res.push(WalletOutput {
          absolute_id: AbsoluteId {
            transaction: tx_hash,
            index_in_transaction: o.try_into().unwrap(),
          },
          relative_id: RelativeId {
            index_on_blockchain: output_index_for_first_ringct_output + u64::try_from(o).unwrap(),
          },
          data: OutputData { key: output_key, key_offset, commitment },
          metadata: Metadata {
            additional_timelock: tx.prefix().additional_timelock,
            subaddress,
            payment_id,
            arbitrary_data: extra.data(),
          },
        });

        // Break to prevent public keys from being included multiple times, triggering multiple
        // inclusions of the same output
        break;
      }
    }

    Ok(Timelocked(res))
  }

  fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
    // This is the output index for the first RingCT output within the block
    // We mutate it to be the output index for the first RingCT for each transaction
    let ScannableBlock { block, transactions, output_index_for_first_ringct_output } = block;
    if block.transactions.len() != transactions.len() {
      Err(ScanError::InvalidScannableBlock(
        "scanning a ScannableBlock with more/less transactions than it should have",
      ))?;
    }
    let Some(mut output_index_for_first_ringct_output) = output_index_for_first_ringct_output
    else {
      return Ok(Timelocked(vec![]));
    };

    if block.header.hardfork_version > 16 {
      Err(ScanError::UnsupportedProtocol(block.header.hardfork_version))?;
    }

    // We obtain all TXs in full
    let mut txs_with_hashes = vec![(
      block.miner_transaction.hash(),
      Transaction::<Pruned>::from(block.miner_transaction.clone()),
    )];
    for (hash, tx) in block.transactions.iter().zip(transactions) {
      txs_with_hashes.push((*hash, tx));
    }

    let mut res = Timelocked(vec![]);
    for (hash, tx) in txs_with_hashes {
      // Push all outputs into our result
      {
        let mut this_txs_outputs = vec![];
        core::mem::swap(
          &mut self.scan_transaction(output_index_for_first_ringct_output, hash, &tx)?.0,
          &mut this_txs_outputs,
        );
        res.0.extend(this_txs_outputs);
      }

      // Update the RingCT starting index for the next TX
      if matches!(tx, Transaction::V2 { .. }) {
        output_index_for_first_ringct_output += u64::try_from(tx.prefix().outputs.len()).unwrap()
      }
    }

    // If the block's version is >= 12, drop all unencrypted payment IDs
    // https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
    //   src/wallet/wallet2.cpp#L2739-L2744
    if block.header.hardfork_version >= 12 {
      for output in &mut res.0 {
        if matches!(output.metadata.payment_id, Some(PaymentId::Unencrypted(_))) {
          output.metadata.payment_id = None;
        }
      }
    }

    Ok(res)
  }
}

/// A transaction scanner to find outputs received.
///
/// When an output is successfully scanned, the output key MUST be checked against the local
/// database for lack of prior observation. If it was prior observed, that output is an instance
/// of the
/// [burning bug](https://web.getmonero.org/2018/09/25/a-post-mortum-of-the-burning-bug.html) and
/// MAY be unspendable. Only the prior received output(s) or the newly received output will be
/// spendable (as spending one will burn all of them).
///
/// Once checked, the output key MUST be saved to the local database so future checks can be
/// performed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scanner(InternalScanner);

impl Scanner {
  /// Create a Scanner from a ViewPair.
  pub fn new(pair: ViewPair) -> Self {
    Self(InternalScanner::new(pair, false))
  }

  /// Register a subaddress to scan for.
  ///
  /// Subaddresses must be explicitly registered ahead of time in order to be successfully scanned.
  pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    self.0.register_subaddress(subaddress)
  }

  /// Scan a block.
  pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
    self.0.scan(block)
  }
}

/// A transaction scanner to find outputs received which are guaranteed to be spendable.
///
/// 'Guaranteed' outputs, or transactions outputs to the burning bug, are not officially specified
/// by the Monero project. They should only be used if necessary. No support outside of
/// monero-wallet is promised.
///
/// "guaranteed to be spendable" assumes satisfaction of any timelocks in effect.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GuaranteedScanner(InternalScanner);

impl GuaranteedScanner {
  /// Create a GuaranteedScanner from a GuaranteedViewPair.
  pub fn new(pair: GuaranteedViewPair) -> Self {
    Self(InternalScanner::new(pair.0, true))
  }

  /// Register a subaddress to scan for.
  ///
  /// Subaddresses must be explicitly registered ahead of time in order to be successfully scanned.
  pub fn register_subaddress(&mut self, subaddress: SubaddressIndex) {
    self.0.register_subaddress(subaddress)
  }

  /// Scan a block.
  pub fn scan(&mut self, block: ScannableBlock) -> Result<Timelocked, ScanError> {
    self.0.scan(block)
  }
}
