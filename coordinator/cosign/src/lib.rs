#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{fmt::Debug, future::Future};
use std::collections::HashMap;

use blake2::{Digest, Blake2s256};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{NetworkId, SeraiAddress},
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
  Public, Block, Serai, TemporalSerai,
};

use serai_db::*;
use serai_task::*;

/// The cosigns which are intended to be performed.
mod intend;
/// The evaluator of the cosigns.
mod evaluator;
use evaluator::LatestCosignedBlockNumber;

/// The schnorrkel context to used when signing a cosign.
pub const COSIGN_CONTEXT: &[u8] = b"serai-cosign";

/// A 'global session', defined as all validator sets used for cosigning at a given moment.
///
/// We evaluate cosign faults within a global session. This ensures even if cosigners cosign
/// distinct blocks at distinct positions within a global session, we still identify the faults.
/*
  There is the attack where a validator set is given an alternate blockchain with a key generation
  event at block #n, while most validator sets are given a blockchain with a key generation event
  at block number #(n+1). This prevents whoever has the alternate blockchain from verifying the
  cosigns on the primary blockchain, and detecting the faults, if they use the keys as of the block
  prior to the block being cosigned.

  We solve this by binding cosigns to a global session ID, which has a specific start block, and
  reading the keys from the start block. This means that so long as all validator sets agree on the
  start of a global session, they can verify all cosigns produced by that session, regardless of
  how it advances. Since agreeing on the start of a global session is mandated, there's no way to
  have validator sets follow two distinct global sessions without breaking the bounds of the
  cosigning protocol.
*/
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct GlobalSession {
  pub(crate) start_block_number: u64,
  pub(crate) sets: Vec<ValidatorSet>,
  pub(crate) keys: HashMap<NetworkId, SeraiAddress>,
  pub(crate) stakes: HashMap<NetworkId, u64>,
  pub(crate) total_stake: u64,
}
impl GlobalSession {
  fn id(mut cosigners: Vec<ValidatorSet>) -> [u8; 32] {
    cosigners.sort_by_key(|a| borsh::to_vec(a).unwrap());
    Blake2s256::digest(borsh::to_vec(&cosigners).unwrap()).into()
  }
}

create_db! {
  Cosign {
    // The following are populated by the intend task and used throughout the library

    // An index of Substrate blocks
    SubstrateBlocks: (block_number: u64) -> [u8; 32],
    // The last block to be cosigned by a global session.
    GlobalSessionsLastBlock: (global_session: [u8; 32]) -> u64,
    // The latest global session intended.
    //
    // This is distinct from the latest global session for which we've evaluated the cosigns for.
    LatestGlobalSessionIntended: () -> ([u8; 32], GlobalSession),

    // The following are managed by the `intake_cosign` function present in this file

    // The latest cosigned block for each network.
    //
    // This will only be populated with cosigns predating or during the most recent global session
    // to have its start cosigned.
    //
    // The global session changes upon a notable block, causing each global session to have exactly
    // one notable block. All validator sets will explicitly produce a cosign for their notable
    // block, causing the latest cosigned block for a global session to either be the global
    // session's notable cosigns or the network's latest cosigns.
    NetworksLatestCosignedBlock: (global_session: [u8; 32], network: NetworkId) -> SignedCosign,
    // Cosigns received for blocks not locally recognized as finalized.
    Faults: (global_session: [u8; 32]) -> Vec<SignedCosign>,
    // The global session which faulted.
    FaultedSession: () -> [u8; 32],
  }
}

/// If the block has events.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
enum HasEvents {
  /// The block had a notable event.
  ///
  /// This is a special case as blocks with key gen events change the keys used for cosigning, and
  /// accordingly must be cosigned before we advance past them.
  Notable,
  /// The block had an non-notable event justifying a cosign.
  NonNotable,
  /// The block didn't have an event justifying a cosign.
  No,
}

/// An intended cosign.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
struct CosignIntent {
  /// The global session this cosign is being performed under.
  global_session: [u8; 32],
  /// The number of the block to cosign.
  block_number: u64,
  /// The hash of the block to cosign.
  block_hash: [u8; 32],
  /// If this cosign must be handled before further cosigns are.
  notable: bool,
}

/// A cosign.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Cosign {
  /// The global session this cosign is being performed under.
  pub global_session: [u8; 32],
  /// The number of the block to cosign.
  pub block_number: u64,
  /// The hash of the block to cosign.
  pub block_hash: [u8; 32],
  /// The actual cosigner.
  pub cosigner: NetworkId,
}

/// A signed cosign.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SignedCosign {
  /// The cosign.
  pub cosign: Cosign,
  /// The signature for the cosign.
  pub signature: [u8; 64],
}

impl SignedCosign {
  fn verify_signature(&self, signer: serai_client::Public) -> bool {
    let Ok(signer) = schnorrkel::PublicKey::from_bytes(&signer.0) else { return false };
    let Ok(signature) = schnorrkel::Signature::from_bytes(&self.signature) else { return false };

    signer.verify_simple(COSIGN_CONTEXT, &borsh::to_vec(&self.cosign).unwrap(), &signature).is_ok()
  }
}

/// Fetch the keys used for cosigning by a specific network.
async fn keys_for_network(
  serai: &TemporalSerai<'_>,
  network: NetworkId,
) -> Result<Option<(Session, KeyPair)>, String> {
  let Some(latest_session) =
    serai.validator_sets().session(network).await.map_err(|e| format!("{e:?}"))?
  else {
    // If this network hasn't had a session declared, move on
    return Ok(None);
  };

  // Get the keys for the latest session
  if let Some(keys) = serai
    .validator_sets()
    .keys(ValidatorSet { network, session: latest_session })
    .await
    .map_err(|e| format!("{e:?}"))?
  {
    return Ok(Some((latest_session, keys)));
  }

  // If the latest session has yet to set keys, use the prior session
  if let Some(prior_session) = latest_session.0.checked_sub(1).map(Session) {
    if let Some(keys) = serai
      .validator_sets()
      .keys(ValidatorSet { network, session: prior_session })
      .await
      .map_err(|e| format!("{e:?}"))?
    {
      return Ok(Some((prior_session, keys)));
    }
  }

  Ok(None)
}

/// Fetch the `ValidatorSet`s, and their associated keys, used for cosigning as of this block.
async fn cosigning_sets(serai: &TemporalSerai<'_>) -> Result<Vec<(ValidatorSet, Public)>, String> {
  let mut sets = Vec::with_capacity(serai_client::primitives::NETWORKS.len());
  for network in serai_client::primitives::NETWORKS {
    let Some((session, keys)) = keys_for_network(serai, network).await? else {
      // If this network doesn't have usable keys, move on
      continue;
    };

    sets.push((ValidatorSet { network, session }, keys.0));
  }
  Ok(sets)
}

/// An object usable to request notable cosigns for a block.
pub trait RequestNotableCosigns: 'static + Send {
  /// The error type which may be encountered when requesting notable cosigns.
  type Error: Debug;

  /// Request the notable cosigns for this global session.
  fn request_notable_cosigns(
    &self,
    global_session: [u8; 32],
  ) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

/// An error used to indicate the cosigning protocol has faulted.
pub struct Faulted;

/// The interface to manage cosigning with.
pub struct Cosigning<D: Db> {
  db: D,
}
impl<D: Db> Cosigning<D> {
  /// Spawn the tasks to intend and evaluate cosigns.
  ///
  /// The database specified must only be used with a singular instance of the Serai network, and
  /// only used once at any given time.
  pub fn spawn<R: RequestNotableCosigns>(
    db: D,
    serai: Serai,
    request: R,
    tasks_to_run_upon_cosigning: Vec<TaskHandle>,
  ) -> Self {
    let (intend_task, _intend_task_handle) = Task::new();
    let (evaluator_task, evaluator_task_handle) = Task::new();
    tokio::spawn(
      (intend::CosignIntendTask { db: db.clone(), serai })
        .continually_run(intend_task, vec![evaluator_task_handle]),
    );
    tokio::spawn(
      (evaluator::CosignEvaluatorTask { db: db.clone(), request })
        .continually_run(evaluator_task, tasks_to_run_upon_cosigning),
    );
    Self { db }
  }

  /// The latest cosigned block number.
  pub fn latest_cosigned_block_number(&self) -> Result<u64, Faulted> {
    if FaultedSession::get(&self.db).is_some() {
      Err(Faulted)?;
    }

    Ok(LatestCosignedBlockNumber::get(&self.db).unwrap_or(0))
  }

  /// Fetch the notable cosigns for a global session in order to respond to requests.
  ///
  /// If this global session hasn't produced any notable cosigns, this will return the latest
  /// cosigns for this session.
  pub fn notable_cosigns(&self, global_session: [u8; 32]) -> Vec<SignedCosign> {
    let mut cosigns = Vec::with_capacity(serai_client::primitives::NETWORKS.len());
    for network in serai_client::primitives::NETWORKS {
      if let Some(cosign) = NetworksLatestCosignedBlock::get(&self.db, global_session, network) {
        cosigns.push(cosign);
      }
    }
    cosigns
  }

  /// The cosigns to rebroadcast ever so often.
  ///
  /// This will be the most recent cosigns, in case the initial broadcast failed, or the faulty
  /// cosigns, in case of a fault, to induce identification of the fault by others.
  pub fn cosigns_to_rebroadcast(&self) -> Vec<SignedCosign> {
    if let Some(faulted) = FaultedSession::get(&self.db) {
      let mut cosigns = Faults::get(&self.db, faulted).expect("faulted with no faults");
      // Also include all of our recognized-as-honest cosigns in an attempt to induce fault
      // identification in those who see the faulty cosigns as honest
      for network in serai_client::primitives::NETWORKS {
        if let Some(cosign) = NetworksLatestCosignedBlock::get(&self.db, faulted, network) {
          if cosign.cosign.global_session == faulted {
            cosigns.push(cosign);
          }
        }
      }
      cosigns
    } else {
      let Some((latest_global_session, _latest_global_session_info)) =
        LatestGlobalSessionIntended::get(&self.db)
      else {
        return vec![];
      };
      let mut cosigns = Vec::with_capacity(serai_client::primitives::NETWORKS.len());
      for network in serai_client::primitives::NETWORKS {
        if let Some(cosign) =
          NetworksLatestCosignedBlock::get(&self.db, latest_global_session, network)
        {
          cosigns.push(cosign);
        }
      }
      cosigns
    }
  }

  /// Intake a cosign from the Serai network.
  ///
  /// - Returns Err(_) if there was an error trying to validate the cosign and it should be retired
  ///   later.
  /// - Returns Ok(true) if the cosign was successfully handled or could not be handled at this
  ///   time.
  /// - Returns Ok(false) if the cosign was invalid.
  //
  // We collapse a cosign which shouldn't be handled yet into a valid cosign (`Ok(true)`) as we
  // assume we'll either explicitly request it if we need it or we'll naturally see it (or a later,
  // more relevant, cosign) again.
  //
  // Takes `&mut self` as this should only be called once at any given moment.
  // TODO: Don't overload bool here
  pub fn intake_cosign(&mut self, signed_cosign: &SignedCosign) -> Result<bool, String> {
    let cosign = &signed_cosign.cosign;
    let network = cosign.cosigner;

    // Check this isn't a dated cosign within its global session (as it would be if rebroadcasted)
    if let Some(existing) =
      NetworksLatestCosignedBlock::get(&self.db, cosign.global_session, network)
    {
      if existing.cosign.block_number >= cosign.block_number {
        return Ok(true);
      }
    }

    // Check our indexed blockchain includes a block with this block number
    let Some(our_block_hash) = SubstrateBlocks::get(&self.db, cosign.block_number) else {
      return Ok(true);
    };

    // Check the cosign aligns with the global session we're currently working on
    let Some((global_session, global_session_info)) =
      evaluator::currently_evaluated_global_session(&self.db)
    else {
      // We haven't recognized any global sessions yet
      return Ok(true);
    };
    if cosign.global_session != global_session {
      return Ok(true);
    }

    // Check the cosigned block number is in range to the global session
    if cosign.block_number < global_session_info.start_block_number {
      // Cosign is for a block predating the global session
      return Ok(false);
    }
    if let Some(last_block) = GlobalSessionsLastBlock::get(&self.db, cosign.global_session) {
      if cosign.block_number > last_block {
        // Cosign is for a block after the last block this global session should have signed
        return Ok(false);
      }
    }

    // Check the cosign's signature
    {
      let key = Public::from({
        let Some(key) = global_session_info.keys.get(&network) else {
          return Ok(false);
        };
        *key
      });

      if !signed_cosign.verify_signature(key) {
        return Ok(false);
      }
    }

    // Since we verified this cosign's signature, and have a chain sufficiently long, handle the
    // cosign

    let mut txn = self.db.txn();

    if our_block_hash == cosign.block_hash {
      NetworksLatestCosignedBlock::set(&mut txn, cosign.global_session, network, signed_cosign);
    } else {
      let mut faults = Faults::get(&txn, cosign.global_session).unwrap_or(vec![]);
      // Only handle this as a fault if this set wasn't prior faulty
      if !faults.iter().any(|cosign| cosign.cosign.cosigner == network) {
        faults.push(signed_cosign.clone());
        Faults::set(&mut txn, cosign.global_session, &faults);

        let mut weight_cosigned = 0;
        for fault in &faults {
          let Some(stake) = global_session_info.stakes.get(&fault.cosign.cosigner) else {
            Err("cosigner with recognized key didn't have a stake entry saved".to_string())?
          };
          weight_cosigned += stake;
        }

        // Check if the sum weight means a fault has occurred
        if weight_cosigned >= ((global_session_info.total_stake * 17) / 100) {
          FaultedSession::set(&mut txn, &cosign.global_session);
        }
      }
    }

    txn.commit();
    Ok(true)
  }
}
