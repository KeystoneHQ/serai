#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{fmt::Debug, future::Future};

use blake2::{Digest, Blake2s256};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  primitives::{Amount, NetworkId, SeraiAddress},
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
  Block, Serai, TemporalSerai,
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
#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct GlobalSession {
  cosigners: Vec<ValidatorSet>,
}
impl GlobalSession {
  fn new(mut cosigners: Vec<ValidatorSet>) -> Self {
    cosigners.sort_by_key(|a| borsh::to_vec(a).unwrap());
    Self { cosigners }
  }
  fn id(&self) -> [u8; 32] {
    Blake2s256::digest(borsh::to_vec(self).unwrap()).into()
  }
}

create_db! {
  Cosign {
    // A mapping from a global session's ID to its start block (number, hash).
    GlobalSessions: (global_session: [u8; 32]) -> (u64, [u8; 32]),
    // An archive of all cosigns ever received.
    //
    // This will only be populated with cosigns predating or during the most recent global session
    // to have its start cosigned.
    Cosigns: (block_number: u64) -> Vec<SignedCosign>,
    // The latest cosigned block for each network.
    //
    // This will only be populated with cosigns predating or during the most recent global session
    // to have its start cosigned.
    NetworksLatestCosignedBlock: (network: NetworkId) -> SignedCosign,
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

/// The identification of a cosigner.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Cosigner {
  /// The network which produced this cosign.
  ValidatorSet(NetworkId),
  /// The individual validator which produced this cosign.
  Validator(SeraiAddress),
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
  pub cosigner: Cosigner,
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

/// Construct a `TemporalSerai` bound to the time used for cosigning this block.
async fn temporal_serai_used_for_cosigning(
  serai: &Serai,
  block_number: u64,
) -> Result<(Block, TemporalSerai<'_>), String> {
  let block = serai
    .finalized_block_by_number(block_number)
    .await
    .map_err(|e| format!("{e:?}"))?
    .ok_or("block wasn't finalized".to_string())?;

  // If we're cosigning block `n`, it's cosigned by the sets as of block `n-1`
  // (as block `n` may update the sets declared but that update shouldn't take effect here
  // until it's cosigned)
  let serai = serai.as_of(block.header.parent_hash.into());

  Ok((block, serai))
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

/// Fetch the `ValidatorSet`s used for cosigning as of this block.
async fn cosigning_sets(serai: &TemporalSerai<'_>) -> Result<Vec<ValidatorSet>, String> {
  let mut sets = Vec::with_capacity(serai_client::primitives::NETWORKS.len());
  for network in serai_client::primitives::NETWORKS {
    let Some((session, _)) = keys_for_network(serai, network).await? else {
      // If this network doesn't have usable keys, move on
      continue;
    };

    sets.push(ValidatorSet { network, session });
  }
  Ok(sets)
}

/// Fetch the `ValidatorSet`s used for cosigning this block.
async fn cosigning_sets_for_block(
  serai: &Serai,
  block_number: u64,
) -> Result<(Block, Vec<ValidatorSet>), String> {
  let (block, serai) = temporal_serai_used_for_cosigning(serai, block_number).await?;
  cosigning_sets(&serai).await.map(|sets| (block, sets))
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
  serai: Serai,
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
      (intend::CosignIntendTask { db: db.clone(), serai: serai.clone() })
        .continually_run(intend_task, vec![evaluator_task_handle]),
    );
    tokio::spawn(
      (evaluator::CosignEvaluatorTask { db: db.clone(), serai: serai.clone(), request })
        .continually_run(evaluator_task, tasks_to_run_upon_cosigning),
    );
    Self { db, serai }
  }

  /// The latest cosigned block number.
  pub fn latest_cosigned_block_number(&self) -> Result<u64, Faulted> {
    if FaultedSession::get(&self.db).is_some() {
      Err(Faulted)?;
    }

    Ok(LatestCosignedBlockNumber::get(&self.db).unwrap_or(0))
  }

  /// Fetch the notable cosigns for a global session in order to respond to requests.
  pub fn notable_cosigns(&self, global_session: [u8; 32]) -> Vec<SignedCosign> {
    todo!("TODO")
  }

  /// The cosigns to rebroadcast ever so often.
  ///
  /// This will be the most recent cosigns, in case the initial broadcast failed, or the faulty
  /// cosigns, in case of a fault, to induce identification of the fault by others.
  pub fn cosigns_to_rebroadcast(&self) -> Vec<SignedCosign> {
    if let Some(faulted) = FaultedSession::get(&self.db) {
      let mut cosigns = Faults::get(&self.db, faulted).unwrap();
      // Also include all of our recognized-as-honest cosigns in an attempt to induce fault
      // identification in those who see the faulty cosigns as honest
      for network in serai_client::primitives::NETWORKS {
        if let Some(cosign) = NetworksLatestCosignedBlock::get(&self.db, network) {
          if cosign.cosign.global_session == faulted {
            cosigns.push(cosign);
          }
        }
      }
      cosigns
    } else {
      let mut cosigns = Vec::with_capacity(serai_client::primitives::NETWORKS.len());
      for network in serai_client::primitives::NETWORKS {
        if let Some(cosign) = NetworksLatestCosignedBlock::get(&self.db, network) {
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
  pub async fn intake_cosign(&mut self, signed_cosign: SignedCosign) -> Result<bool, String> {
    let cosign = &signed_cosign.cosign;

    // Check if we've prior handled this cosign
    let mut txn = self.db.txn();
    let mut cosigns_for_this_block_position =
      Cosigns::get(&txn, cosign.block_number).unwrap_or(vec![]);
    if cosigns_for_this_block_position.iter().any(|existing| existing.cosign == *cosign) {
      return Ok(true);
    }

    // Check we can verify this cosign's signature
    let Some((global_session_start_block_number, global_session_start_block_hash)) =
      GlobalSessions::get(&txn, cosign.global_session)
    else {
      // Unrecognized global session
      return Ok(true);
    };

    // Check the cosign's signature
    let network = match cosign.cosigner {
      Cosigner::ValidatorSet(network) => {
        let Some((_session, keys)) =
          keys_for_network(&self.serai.as_of(global_session_start_block_hash), network).await?
        else {
          return Ok(false);
        };

        if !signed_cosign.verify_signature(keys.0) {
          return Ok(false);
        }

        network
      }
      Cosigner::Validator(_) => return Ok(false),
    };

    // Check our finalized blockchain exceeds this block number
    if self.serai.latest_finalized_block().await.map_err(|e| format!("{e:?}"))?.number() <
      cosign.block_number
    {
      // Unrecognized block number
      return Ok(true);
    }

    // Since we verified this cosign's signature, and have a chain sufficiently long, handle the
    // cosign

    // Save the cosign to the database
    cosigns_for_this_block_position.push(signed_cosign.clone());
    Cosigns::set(&mut txn, cosign.block_number, &cosigns_for_this_block_position);

    let our_block_hash = self
      .serai
      .block_hash(cosign.block_number)
      .await
      .map_err(|e| format!("{e:?}"))?
      .expect("requested hash of a finalized block yet received None");
    if our_block_hash == cosign.block_hash {
      // If this is for a future global session, we don't acknowledge this cosign at this time
      if global_session_start_block_number > LatestCosignedBlockNumber::get(&txn).unwrap_or(0) {
        drop(txn);
        return Ok(true);
      }

      if NetworksLatestCosignedBlock::get(&txn, network)
        .map(|cosign| cosign.cosign.block_number)
        .unwrap_or(0) <
        cosign.block_number
      {
        NetworksLatestCosignedBlock::set(&mut txn, network, &signed_cosign);
      }
    } else {
      let mut faults = Faults::get(&txn, cosign.global_session).unwrap_or(vec![]);
      // Only handle this as a fault if this set wasn't prior faulty
      if !faults.iter().any(|cosign| cosign.cosign.cosigner == Cosigner::ValidatorSet(network)) {
        faults.push(signed_cosign.clone());
        Faults::set(&mut txn, cosign.global_session, &faults);

        let mut weight_cosigned = 0;
        let mut total_weight = 0;
        for set in cosigning_sets(&self.serai.as_of(global_session_start_block_hash)).await? {
          let stake = self
            .serai
            .as_of(global_session_start_block_hash)
            .validator_sets()
            .total_allocated_stake(set.network)
            .await
            .map_err(|e| format!("{e:?}"))?
            .unwrap_or(Amount(0))
            .0;
          // Increment total_weight with this set's stake
          total_weight += stake;

          // Check if this set cosigned this block or not
          if faults
            .iter()
            .any(|cosign| cosign.cosign.cosigner == Cosigner::ValidatorSet(set.network))
          {
            weight_cosigned += total_weight
          }
        }

        // Check if the sum weight means a fault has occurred
        assert!(
          total_weight != 0,
          "evaluating valid cosign when no stake was present in the system"
        );
        if weight_cosigned >= ((total_weight * 17) / 100) {
          FaultedSession::set(&mut txn, &cosign.global_session);
        }
      }
    }

    txn.commit();
    Ok(true)
  }
}
