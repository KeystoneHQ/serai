use core::future::Future;

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::{
  HasEvents, GlobalSession, NetworksLatestCosignedBlock, RequestNotableCosigns,
  intend::{GlobalSessionsChannel, BlockEventData, BlockEvents},
};

create_db!(
  SubstrateCosignEvaluator {
    // The latest cosigned block number.
    LatestCosignedBlockNumber: () -> u64,
    // The latest global session evaluated.
    LatestGlobalSessionEvaluated: () -> ([u8; 32], GlobalSession),
  }
);

/// A task to determine if a block has been cosigned and we should handle it.
pub(crate) struct CosignEvaluatorTask<D: Db, R: RequestNotableCosigns> {
  pub(crate) db: D,
  pub(crate) request: R,
}

fn get_latest_global_session_evaluated(
  txn: &mut impl DbTxn,
  block_number: u64,
) -> ([u8; 32], GlobalSession) {
  let mut res = {
    let existing = match LatestGlobalSessionEvaluated::get(txn) {
      Some(existing) => existing,
      None => {
        let first = GlobalSessionsChannel::try_recv(txn)
          .expect("fetching latest global session yet none declared");
        LatestGlobalSessionEvaluated::set(txn, &first);
        first
      }
    };
    assert!(
      existing.1.start_block_number <= block_number,
      "candidate's start block number exceeds our block number"
    );
    existing
  };

  if let Some(next) = GlobalSessionsChannel::peek(txn) {
    assert!(
      block_number <= next.1.start_block_number,
      "get_latest_global_session_evaluated wasn't called incrementally"
    );
    // If it's time for this session to activate, take it from the channel and set it
    if block_number == next.1.start_block_number {
      GlobalSessionsChannel::try_recv(txn).unwrap();
      LatestGlobalSessionEvaluated::set(txn, &next);
      res = next;
    }
  }

  res
}

impl<D: Db, R: RequestNotableCosigns> ContinuallyRan for CosignEvaluatorTask<D, R> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let latest_cosigned_block_number = LatestCosignedBlockNumber::get(&self.db).unwrap_or(0);

      let mut known_cosign = None;
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some(BlockEventData { block_number, has_events }) = BlockEvents::try_recv(&mut txn)
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
            let (global_session, global_session_info) =
              get_latest_global_session_evaluated(&mut txn, block_number);

            let mut weight_cosigned = 0;
            for set in global_session_info.sets {
              // Check if we have the cosign from this set
              if NetworksLatestCosignedBlock::get(&txn, global_session, set.network)
                .map(|signed_cosign| signed_cosign.cosign.block_number) ==
                Some(block_number)
              {
                // Since have this cosign, add the set's weight to the weight which has cosigned
                weight_cosigned +=
                  global_session_info.stakes.get(&set.network).ok_or_else(|| {
                    "ValidatorSet in global session yet didn't have its stake".to_string()
                  })?;
              }
            }
            // Check if the sum weight doesn't cross the required threshold
            if weight_cosigned < (((global_session_info.total_stake * 83) / 100) + 1) {
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
              let (global_session, global_session_info) =
                get_latest_global_session_evaluated(&mut txn, block_number);

              let mut weight_cosigned = 0;
              let mut lowest_common_block: Option<u64> = None;
              for set in global_session_info.sets {
                // Check if this set cosigned this block or not
                let Some(cosign) =
                  NetworksLatestCosignedBlock::get(&txn, global_session, set.network)
                else {
                  continue;
                };
                if cosign.cosign.block_number >= block_number {
                  weight_cosigned +=
                    global_session_info.stakes.get(&set.network).ok_or_else(|| {
                      "ValidatorSet in global session yet didn't have its stake".to_string()
                    })?;
                }

                // Update the lowest block common to all of these cosigns
                lowest_common_block = lowest_common_block
                  .map(|existing| existing.min(cosign.cosign.block_number))
                  .or(Some(cosign.cosign.block_number));
              }

              // Check if the sum weight doesn't cross the required threshold
              if weight_cosigned < (((global_session_info.total_stake * 83) / 100) + 1) {
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
