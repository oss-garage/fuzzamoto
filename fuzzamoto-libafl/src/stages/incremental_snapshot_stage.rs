use std::marker::PhantomData;
use std::num::NonZeroUsize;

use libafl::{
    Error, HasMetadata,
    corpus::HasCurrentCorpusId,
    executors::Executor,
    stages::{Restartable, Stage, mutational::MutatedTransform},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasRand},
};
use libafl_bolts::rands::Rand;
use libafl_nyx::executor::NyxExecutor;

use fuzzamoto_ir::Program;

use crate::input::IrInput;

#[derive(Debug, Clone, Copy)]
pub enum SnapshotPlacementPolicy {
    Balanced,
}

pub struct IncrementalSnapshotStage<IS, S, OT> {
    inner_stage: IS,
    policy: SnapshotPlacementPolicy,
    max_reuse_count: usize,
    phantom: PhantomData<(S, OT)>,
}

impl<IS, S, OT> IncrementalSnapshotStage<IS, S, OT> {
    pub fn new(inner_stage: IS, policy: SnapshotPlacementPolicy, max_reuse_count: usize) -> Self {
        Self {
            inner_stage,
            policy,
            max_reuse_count,
            phantom: PhantomData,
        }
    }

    /// Choose where to take the snapshot based on the placement policy
    fn choose_position(&self, rand: &mut impl Rand, program_len: usize) -> Option<usize> {
        if program_len == 0 {
            return None;
        }

        match self.policy {
            SnapshotPlacementPolicy::Balanced => {
                if program_len == 1 {
                    Some(0)
                } else if rand.coinflip(0.5_f64) {
                    // First half
                    let half = (program_len / 2).max(1);
                    let nz_half = NonZeroUsize::new(half).expect("half should be non-zero");
                    Some(rand.below(nz_half))
                } else {
                    // Second half
                    let half = program_len / 2;
                    let range = program_len - half;
                    let nz_range = NonZeroUsize::new(range).expect("range should be non-zero");
                    Some(half + rand.below(nz_range))
                }
            }
        }
    }
}

impl<IS, EM, S, Z, OT> Stage<NyxExecutor<S, OT>, EM, S, Z> for IncrementalSnapshotStage<IS, S, OT>
where
    IS: Stage<NyxExecutor<S, OT>, EM, S, Z> + Restartable<S>,
    S: HasCorpus<IrInput>
        + HasRand
        + HasMetadata
        + HasCurrentTestcase<IrInput>
        + HasCurrentCorpusId
        + HasExecutions,
    OT: libafl::observers::ObserversTuple<IrInput, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut NyxExecutor<S, OT>,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // No incremental snapshot should exist at this point.
        assert!(!executor.helper.nyx_process.aux_tmp_snapshot_created());

        // Load input in case of eviction
        {
            let mut testcase = state.current_testcase_mut()?;
            let _ = IrInput::try_transform_from(&mut testcase, state)?;
        }

        let program_len = {
            let testcase = state.current_testcase()?;
            let input = testcase.input().as_ref().unwrap();
            input.ir().instructions.len()
        };

        if program_len == 0 || state.rand_mut().coinflip(0.04) {
            // Skip creating an incremental snapshot if we're using the empty program or
            // randomly decide to use the root.
            if self.inner_stage.should_restart(state)? {
                self.inner_stage.perform(fuzzer, executor, state, manager)?;
            }
            let _ = self.inner_stage.clear_progress(state);

            return Ok(());
        }

        let chosen_pos = self.choose_position(state.rand_mut(), program_len);

        let new_prefix_len = {
            let testcase = state.current_testcase()?;
            let input = testcase.input().as_ref().unwrap();
            chosen_pos.and_then(|pos| find_valid_snapshot_position(input.ir(), pos))
        };

        if let Some(prefix_len) = new_prefix_len {
            executor
                .helper
                .nyx_process
                .option_set_delete_incremental_snapshot(false);
            executor.helper.nyx_process.option_apply();

            // Set frozen_prefix_len on the input so inner_stage is aware of it
            {
                let mut testcase = state.current_testcase_mut()?;
                let input = testcase.input_mut().as_mut().unwrap();
                input.frozen_prefix_len = Some(prefix_len);
            }

            log::info!("Created incremental snapshot at position {prefix_len}");

            for reuse_count in 1..=self.max_reuse_count {
                if reuse_count == self.max_reuse_count {
                    // Discard the incremental snapshot at the end of the last iteration.
                    // The inner mutational stage may not call run_target if the mutation
                    // is skipped, so call it explicitly. Without this, the assert at the
                    // top of this function is hit.
                    executor
                        .helper
                        .nyx_process
                        .option_set_delete_incremental_snapshot(true);
                    executor.helper.nyx_process.option_apply();

                    let testcase = state.current_testcase()?;
                    let input = testcase.input().as_ref().unwrap().clone();
                    drop(testcase);
                    executor.run_target(fuzzer, state, manager, &input)?;
                } else {
                    if self.inner_stage.should_restart(state)? {
                        self.inner_stage.perform(fuzzer, executor, state, manager)?;
                    }
                    let _ = self.inner_stage.clear_progress(state);
                }
            }

            // Reset frozen_prefix_len
            {
                let mut testcase = state.current_testcase_mut()?;
                let input = testcase.input_mut().as_mut().unwrap();
                input.frozen_prefix_len = None;
            }
        } else {
            log::info!("No valid position to create incremental snapshot",);

            return Ok(());
        }

        Ok(())
    }
}

impl<IS, S, OT> Restartable<S> for IncrementalSnapshotStage<IS, S, OT>
where
    S: HasMetadata,
    IS: Restartable<S>,
{
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

/// Find a valid position for the snapshot that's not inside a block.
#[expect(clippy::cast_possible_wrap)]
fn find_valid_snapshot_position(program: &Program, target_pos: usize) -> Option<usize> {
    let instructions = &program.instructions;

    if instructions.is_empty() {
        return None;
    }

    let target_pos = target_pos.min(instructions.len());

    let mut block_depth: usize = 0;
    let mut valid_positions = Vec::new();

    for (i, instr) in instructions.iter().enumerate() {
        if block_depth == 0 {
            valid_positions.push(i);
        }

        if instr.operation.is_block_begin() {
            block_depth += 1;
        }
        if instr.operation.is_block_end() {
            block_depth = block_depth.saturating_sub(1);
        }
    }

    if block_depth == 0 {
        valid_positions.push(instructions.len());
    }

    if valid_positions.is_empty() {
        return None;
    }

    valid_positions
        .into_iter()
        .min_by_key(|&pos| (pos as isize - target_pos as isize).unsigned_abs())
}
