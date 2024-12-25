use core::future::Future;

use serai_client::{primitives::Amount, Serai};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{
  *,
  intend::{BlockEventData, BlockEvents},
};

create_db!(
  SubstrateCosignEvaluator {
    // The latest cosigned block number.
    LatestCosignedBlockNumber: () -> u64,
    // The latest global session evaluated.
    // TODO: Also include the weights here
    LatestGlobalSessionEvaluated: () -> ([u8; 32], Vec<ValidatorSet>),
  }
);

/// A task to determine if a block has been cosigned and we should handle it.
pub(crate) struct CosignEvaluatorTask<D: Db, R: RequestNotableCosigns> {
  pub(crate) db: D,
  pub(crate) serai: Serai,
  pub(crate) request: R,
}

async fn get_latest_global_session_evaluated(
  txn: &mut impl DbTxn,
  serai: &Serai,
  parent_hash: [u8; 32],
) -> Result<([u8; 32], Vec<ValidatorSet>), String> {
  Ok(match LatestGlobalSessionEvaluated::get(txn) {
    Some(res) => res,
    None => {
      // This is the initial global session
      // Fetch the sets participating and declare it the latest value recognized
      let sets = cosigning_sets_by_parent_hash(serai, parent_hash).await?;
      let initial_global_session = GlobalSession::new(sets.clone()).id();
      LatestGlobalSessionEvaluated::set(txn, &(initial_global_session, sets.clone()));
      (initial_global_session, sets)
    }
  })
}

impl<D: Db, R: RequestNotableCosigns> ContinuallyRan for CosignEvaluatorTask<D, R> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let latest_cosigned_block_number = LatestCosignedBlockNumber::get(&self.db).unwrap_or(0);

      let mut known_cosign = None;
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some(BlockEventData { block_number, parent_hash, block_hash, has_events }) =
          BlockEvents::try_recv(&mut txn)
        else {
          break;
        };
        // Make sure these two feeds haven't desynchronized somehow
        // We could remove our `LatestCosignedBlockNumber`, making the latest cosigned block number
        // the next message in the channel's block number minus one, but that'd only work when the
        // channel isn't empty
        assert_eq!(block_number, latest_cosigned_block_number + 1);

        match has_events {
          // Because this had notable events, we require an explicit cosign for this block by a
          // supermajority of the prior block's validator sets
          HasEvents::Notable => {
            let (global_session, sets) =
              get_latest_global_session_evaluated(&mut txn, &self.serai, parent_hash).await?;

            let mut weight_cosigned = 0;
            let mut total_weight = 0;
            let (_, global_session_start_block) = GlobalSessions::get(&txn, global_session)
              .ok_or_else(|| {
                "checking if intended cosign was satisfied within an unrecognized global session"
                  .to_string()
              })?;
            for set in sets {
              // Fetch the weight for this set, as of the start of the global session
              // This simplifies the logic around which set of stakes to use when evaluating
              // cosigns, even if it's lossy as it isn't accurate to how stake may fluctuate within
              // a session
              let stake = self
                .serai
                .as_of(global_session_start_block)
                .validator_sets()
                .total_allocated_stake(set.network)
                .await
                .map_err(|e| format!("{e:?}"))?
                .unwrap_or(Amount(0))
                .0;
              total_weight += stake;

              // Check if we have the cosign from this set
              if NetworksLatestCosignedBlock::get(&txn, global_session, set.network)
                .map(|signed_cosign| signed_cosign.cosign.block_number) ==
                Some(block_number)
              {
                // Since have this cosign, add the set's weight to the weight which has cosigned
                weight_cosigned += stake;
              }
            }
            // Check if the sum weight doesn't cross the required threshold
            if weight_cosigned < (((total_weight * 83) / 100) + 1) {
              // Request the necessary cosigns over the network
              // TODO: Add a timer to ensure this isn't called too often
              self
                .request
                .request_notable_cosigns(global_session)
                .await
                .map_err(|e| format!("{e:?}"))?;
              // We return an error so the delay before this task is run again increases
              return Err(format!(
                "notable block (#{block_number}) wasn't yet cosigned. this should resolve shortly",
              ));
            }

            // Since this block changes the global session, update it
            {
              let sets = cosigning_sets(&self.serai.as_of(block_hash)).await?;
              let global_session = GlobalSession::new(sets.clone()).id();
              LatestGlobalSessionEvaluated::set(&mut txn, &(global_session, sets));
            }
          }
          // Since this block didn't have any notable events, we simply require a cosign for this
          // block or a greater block by the current validator sets
          HasEvents::NonNotable => {
            // Check if this was satisfied by a cached result which wasn't calculated incrementally
            let known_cosigned = if let Some(known_cosign) = known_cosign {
              known_cosign >= block_number
            } else {
              // Clear `known_cosign` which is no longer helpful
              known_cosign = None;
              false
            };

            // If it isn't already known to be cosigned, evaluate the latest cosigns
            if !known_cosigned {
              /*
                LatestCosign is populated with the latest cosigns for each network which don't
                exceed the latest global session we've evaluated the start of. This current block
                is during the latest global session we've evaluated the start of.
              */

              // Get the global session for this block
              let (global_session, sets) =
                get_latest_global_session_evaluated(&mut txn, &self.serai, parent_hash).await?;
              let (_, global_session_start_block) = GlobalSessions::get(&txn, global_session)
                .ok_or_else(|| {
                  "checking if intended cosign was satisfied within an unrecognized global session"
                    .to_string()
                })?;

              let mut weight_cosigned = 0;
              let mut total_weight = 0;
              let mut lowest_common_block: Option<u64> = None;
              for set in sets {
                let stake = self
                  .serai
                  .as_of(global_session_start_block)
                  .validator_sets()
                  .total_allocated_stake(set.network)
                  .await
                  .map_err(|e| format!("{e:?}"))?
                  .unwrap_or(Amount(0))
                  .0;
                // Increment total_weight with this set's stake
                total_weight += stake;

                // Check if this set cosigned this block or not
                let Some(cosign) =
                  NetworksLatestCosignedBlock::get(&txn, global_session, set.network)
                else {
                  continue;
                };
                if cosign.cosign.block_number >= block_number {
                  weight_cosigned += total_weight
                }

                // Update the lowest block common to all of these cosigns
                lowest_common_block = lowest_common_block
                  .map(|existing| existing.min(cosign.cosign.block_number))
                  .or(Some(cosign.cosign.block_number));
              }

              // Check if the sum weight doesn't cross the required threshold
              if weight_cosigned < (((total_weight * 83) / 100) + 1) {
                // Request the superseding notable cosigns over the network
                // If this session hasn't yet produced notable cosigns, then we presume we'll see
                // the desired non-notable cosigns as part of normal operations, without needing to
                // explicitly request them
                self
                  .request
                  .request_notable_cosigns(global_session)
                  .await
                  .map_err(|e| format!("{e:?}"))?;
                // We return an error so the delay before this task is run again increases
                return Err(format!(
                  "block (#{block_number}) wasn't yet cosigned. this should resolve shortly",
                ));
              }

              // Update the cached result for the block we know is cosigned
              /*
                There may be a higher block which was cosigned, but once we get to this block,
                we'll re-evaluate and find it then. The alternative would be an optimistic
                re-evaluation now. Both are fine, so the lower-complexity option is preferred.
              */
              known_cosign = lowest_common_block;
            }
          }
          // If this block has no events necessitating cosigning, we can immediately consider the
          // block cosigned (making this block a NOP)
          HasEvents::No => {}
        }

        // Since we checked we had the necessary cosigns, increment the latest cosigned block
        LatestCosignedBlockNumber::set(&mut txn, &block_number);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
