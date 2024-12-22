use core::future::Future;

use serai_client::{primitives::Amount, Serai};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{*, intend::BlockHasEvents};

create_db!(
  SubstrateCosignEvaluator {
    LatestCosignedBlockNumber: () -> u64,
  }
);

/// A task to determine if a block has been cosigned and we should handle it.
pub(crate) struct CosignEvaluatorTask<D: Db, R: RequestNotableCosigns> {
  pub(crate) db: D,
  pub(crate) serai: Serai,
  pub(crate) request: R,
}

// TODO: Add a cache for the stake values

impl<D: Db, R: RequestNotableCosigns> ContinuallyRan for CosignEvaluatorTask<D, R> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let latest_cosigned_block_number = LatestCosignedBlockNumber::get(&self.db).unwrap_or(0);

      let mut known_cosign = None;
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some((block_number, has_events)) = BlockHasEvents::try_recv(&mut txn) else { break };
        // Make sure these two feeds haven't desynchronized somehow
        // We could remove our `LatestCosignedBlockNumber`, making the latest cosigned block number
        // the next message in the channel's block number minus one, but that'd only work when the
        // channel isn't empty
        assert_eq!(block_number, latest_cosigned_block_number + 1);

        let cosigns_for_block = Cosigns::get(&txn, block_number).unwrap_or(vec![]);

        match has_events {
          // Because this had notable events, we require an explicit cosign for this block by a
          // supermajority of the prior block's validator sets
          HasEvents::Notable => {
            let mut weight_cosigned = 0;
            let mut total_weight = 0;
            let (_block, sets) = cosigning_sets_for_block(&self.serai, block_number).await?;
            let global_session = GlobalSession::new(sets.clone()).id();
            let (_, global_session_start_block) = GlobalSessions::get(&txn, global_session).expect(
              "checking if intended cosign was satisfied within an unrecognized global session",
            );
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
              if cosigns_for_block
                .iter()
                .any(|cosign| cosign.cosigner == Cosigner::ValidatorSet(set.network))
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
              let (_block, sets) = cosigning_sets_for_block(&self.serai, block_number).await?;
              let global_session = GlobalSession::new(sets.clone()).id();
              let (_, global_session_start_block) = GlobalSessions::get(&txn, global_session)
                .expect(
                  "checking if intended cosign was satisfied within an unrecognized global session",
                );

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
                let Some(cosign) = NetworksLatestCosignedBlock::get(&txn, set.network) else {
                  continue;
                };
                if cosign.block_number >= block_number {
                  weight_cosigned += total_weight
                }

                // Update the lowest block common to all of these cosigns
                lowest_common_block = lowest_common_block
                  .map(|existing| existing.min(cosign.block_number))
                  .or(Some(cosign.block_number));
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
