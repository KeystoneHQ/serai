use core::future::Future;

use serai_client::{SeraiError, Serai, validator_sets::primitives::ValidatorSet};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::*;

create_db!(
  CosignIntend {
    ScanCosignFrom: () -> u64,
  }
);

db_channel! {
  CosignIntendChannels {
    BlockHasEvents: () -> (u64, HasEvents),
    IntendedCosigns: (set: ValidatorSet) -> CosignIntent,
  }
}

async fn block_has_events_justifying_a_cosign(
  serai: &Serai,
  block: u64,
) -> Result<HasEvents, SeraiError> {
  let serai = serai.as_of(
    serai
      .finalized_block_by_number(block)
      .await?
      .expect("couldn't get block which should've been finalized")
      .hash(),
  );

  if !serai.validator_sets().key_gen_events().await?.is_empty() {
    return Ok(HasEvents::Notable);
  }

  if !serai.coins().burn_with_instruction_events().await?.is_empty() {
    return Ok(HasEvents::NonNotable);
  }

  Ok(HasEvents::No)
}

/// A task to determine which blocks we should intend to cosign.
pub(crate) struct CosignIntendTask<D: Db> {
  pub(crate) db: D,
  pub(crate) serai: Serai,
}

impl<D: Db> ContinuallyRan for CosignIntendTask<D> {
  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, String>> {
    async move {
      let start_block_number = ScanCosignFrom::get(&self.db).unwrap_or(1);
      let latest_block_number =
        self.serai.latest_finalized_block().await.map_err(|e| format!("{e:?}"))?.number();

      for block_number in start_block_number ..= latest_block_number {
        let mut txn = self.db.txn();

        let mut has_events = block_has_events_justifying_a_cosign(&self.serai, block_number)
          .await
          .map_err(|e| format!("{e:?}"))?;

        match has_events {
          HasEvents::Notable | HasEvents::NonNotable => {
            let (block, sets) = cosigning_sets_for_block(&self.serai, block_number).await?;

            // If this is notable, it creates a new global session, which we index into the
            // database now
            if has_events == HasEvents::Notable {
              let sets = cosigning_sets(&self.serai.as_of(block.hash())).await?;
              GlobalSessions::set(
                &mut txn,
                GlobalSession::new(sets).id(),
                &(block.number(), block.hash()),
              );
            }

            // If this block doesn't have any cosigners, meaning it'll never be cosigned, we flag it
            // as not having any events requiring cosigning so we don't attempt to sign/require a
            // cosign for it
            if sets.is_empty() {
              has_events = HasEvents::No;
            } else {
              let global_session = GlobalSession::new(sets.clone()).id();
              // Tell each set of their expectation to cosign this block
              for set in sets {
                log::debug!("{:?} will be cosigning block #{block_number}", set);
                IntendedCosigns::send(
                  &mut txn,
                  set,
                  &CosignIntent {
                    global_session,
                    block_number,
                    block_hash: block.hash(),
                    notable: has_events == HasEvents::Notable,
                  },
                );
              }
            }
          }
          HasEvents::No => {}
        }
        // Populate a singular feed with every block's status for the evluator to work off of
        BlockHasEvents::send(&mut txn, &(block_number, has_events));
        // Mark this block as handled, meaning we should scan from the next block moving on
        ScanCosignFrom::set(&mut txn, &(block_number + 1));
        txn.commit();
      }

      Ok(start_block_number <= latest_block_number)
    }
  }
}
