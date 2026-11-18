use crate::input::IrInput;
use fuzzamoto_ir::{Instruction, Operation, PerTestcaseMetadata, Program};
use fuzzamoto_ir::{ProbeResult, ProbeResults};
use libafl::ExecutesInput;
use libafl::{
    HasMetadata,
    corpus::{Corpus, CorpusId},
    executors::{Executor, HasObservers},
    observers::{ObserversTuple, StdOutObserver},
    stages::{
        Restartable, Stage,
        mutational::{MutatedTransform, MutatedTransformPost},
    },
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::{impl_serdeany, tuples::Handle};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use base64::prelude::{BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};

pub struct ProbingStage<T> {
    handle: Handle<T>,
}

impl<T> ProbingStage<T> {
    pub fn new(observer_handle: &Handle<T>) -> Self {
        Self {
            handle: observer_handle.clone(),
        }
    }
}

/// Runtime metadata for fuzzamoto. This data is changed at runtime in response to the harness execution during fuzzing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    // TODO: If you want to add another metadata, then add it to `PerTestcaseMetadata` (not here!)
    metadatas: HashMap<CorpusId, ProbedMetadata>,
    mutation_idx: usize,
}

/// Probe results of a corpus entry and the hash of the program they were recorded for
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbedMetadata {
    program_hash: u64,
    metadata: Option<PerTestcaseMetadata>,
}

fn program_hash(program: &Program) -> u64 {
    let mut hasher = DefaultHasher::new();
    program.hash(&mut hasher);
    hasher.finish()
}

impl RuntimeMetadata {
    /// Returns the probe results for `id`, unless they were recorded for a different program
    pub fn metadata_mut(
        &mut self,
        id: CorpusId,
        program: &Program,
    ) -> Option<&mut PerTestcaseMetadata> {
        let probed = self.metadatas.get_mut(&id)?;
        probed.metadata.as_ref()?;
        if probed.program_hash != program_hash(program) {
            return None;
        }
        probed.metadata.as_mut()
    }

    fn is_probed(&self, id: CorpusId, program: &Program) -> bool {
        self.metadatas
            .get(&id)
            .is_some_and(|probed| probed.program_hash == program_hash(program))
    }

    fn set_probe_results(
        &mut self,
        id: CorpusId,
        program: &Program,
        metadata: Option<PerTestcaseMetadata>,
    ) {
        let program_hash = program_hash(program);
        self.metadatas.insert(
            id,
            ProbedMetadata {
                program_hash,
                metadata,
            },
        );
    }

    pub fn increment_idx(&mut self) {
        self.mutation_idx += 1;
    }

    pub fn reset_idx(&mut self) {
        self.mutation_idx = 0;
    }

    pub fn mutation_idx(&self) -> usize {
        self.mutation_idx
    }
}

impl_serdeany!(RuntimeMetadata);

/// Parse the incoming message from the other peer and process it
fn process_probe_results(metadata: &mut Option<PerTestcaseMetadata>, results: &ProbeResults) {
    for result in results {
        match result {
            ProbeResult::GetBlockTxn { get_block_txn } => {
                metadata
                    .get_or_insert_default()
                    .add_block_tx_request(get_block_txn.clone());
            }
            ProbeResult::CompactBlock { announcement } => {
                metadata
                    .get_or_insert_default()
                    .add_compact_block_announcement(announcement.clone());
            }
            ProbeResult::BlockAnnounced { announcement } => {
                metadata
                    .get_or_insert_default()
                    .add_block_announcement(announcement.clone());
            }
            ProbeResult::Failure { command, reason } => {
                log::info!("Command {command:?} couldn't be parsed; reason: {reason:?}");
            }
            ProbeResult::RecentBlockes { result } => {
                metadata
                    .get_or_insert_default()
                    .add_recent_blocks(result.clone());
            }
        }
    }
}

impl<E, EM, OT, S, T, Z> Stage<E, EM, S, Z> for ProbingStage<T>
where
    E: Executor<EM, IrInput, S, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<IrInput, S>,
    Z: ExecutesInput<E, EM, IrInput, S>,
    T: AsRef<StdOutObserver>,
    S: HasMetadata + HasCorpus<IrInput> + HasCurrentTestcase<IrInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        if !state.has_metadata::<RuntimeMetadata>() {
            state.add_metadata(RuntimeMetadata::default());
        }

        let mut testcase = state.current_testcase_mut()?.clone();
        let Ok(input) = IrInput::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        let mut cloned_input = input.clone();
        let cur = state
            .corpus()
            .current()
            .expect("CorpusId should be available during stage execution");

        if state
            .metadata::<RuntimeMetadata>()?
            .is_probed(cur, input.ir())
        {
            return Ok(());
        }

        // Prepend a `Probe` instruction to the program. Note: since `Probe` does not create any variables,
        // we don't have to care worry about adjusting variable indices here
        debug_assert_eq!(Operation::Probe.num_outputs(), 0);
        let mut builder = fuzzamoto_ir::ProgramBuilder::new(input.ir().context.clone());
        assert!(builder.instructions.is_empty());
        builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::Probe,
            })
            .expect("appending EnableProbe should always succeed");
        builder
            .append_all(input.ir().instructions.iter().cloned())
            .expect("Partial append should always succeed if full append succeeded");
        let Ok(new_program) = builder.finalize() else {
            return Ok(());
        };

        // now swap it with the new program
        *cloned_input.ir_mut() = new_program;
        let (untransformed, post) = cloned_input.try_transform_into(state)?;
        log::info!(
            "Probing for testcase {:?} (in {:?})",
            cur,
            testcase.file_path()
        );
        let _exit_kind = fuzzer.execute_input(state, executor, manager, &untransformed)?;

        let observers = executor.observers();
        let stdout_observer = observers[&self.handle].as_ref();
        let buffer = stdout_observer
            .output
            .as_ref()
            .ok_or(libafl::Error::illegal_state("StdOutObserver has no stdout"))?;
        let mut probe_results = None;
        if !buffer.is_empty() {
            let chunks: Vec<Vec<u8>> = buffer.split(|b| *b == b'\n').map(<[u8]>::to_vec).collect();

            for chunk in chunks {
                if chunk.is_empty() {
                    continue;
                }

                if let Ok(decoded) = BASE64_STANDARD.decode(&chunk)
                    && let Ok(results) = postcard::from_bytes::<ProbeResults>(&decoded)
                {
                    process_probe_results(&mut probe_results, &results);
                } else {
                    log::info!("Failed to decode the message from the target!");
                }
            }
        }

        post.post_exec(state, None)?;
        log::info!("Done Probing for testcase {cur:?}");
        state
            .metadata_mut::<RuntimeMetadata>()?
            .set_probe_results(cur, input.ir(), probe_results);
        Ok(())
    }
}

impl<S, T> Restartable<S> for ProbingStage<T> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuzzamoto_ir::{GetBlockTxn, ProgramContext};

    fn program(num_instructions: usize) -> Program {
        let context = ProgramContext {
            num_nodes: 1,
            num_connections: 1,
            timestamp: 0,
        };
        let instructions = (0..num_instructions)
            .map(|_| Instruction {
                inputs: vec![],
                operation: Operation::LoadNode(0),
            })
            .collect();
        Program::unchecked_new(context, instructions)
    }

    fn block_txn_request(triggering_instruction_index: usize) -> ProbeResult {
        ProbeResult::GetBlockTxn {
            get_block_txn: GetBlockTxn {
                connection_index: 0,
                triggering_instruction_index,
                block_variable: 0,
                tx_indices_variables: vec![1],
            },
        }
    }

    fn probe(
        runtime: &mut RuntimeMetadata,
        id: CorpusId,
        program: &Program,
        results: &ProbeResults,
    ) {
        let mut metadata = None;
        process_probe_results(&mut metadata, results);
        runtime.set_probe_results(id, program, metadata);
    }

    #[test]
    fn probe_results_are_only_used_for_the_probed_program() {
        let mut runtime = RuntimeMetadata::default();
        let id = CorpusId::from(0_usize);
        let probed = program(5);
        let minimized = program(2);

        probe(&mut runtime, id, &probed, &vec![block_txn_request(4)]);

        assert!(runtime.is_probed(id, &probed));
        assert_eq!(
            runtime
                .metadata_mut(id, &probed)
                .unwrap()
                .block_txn_request()
                .len(),
            1
        );
        assert!(!runtime.is_probed(id, &minimized));
        assert!(runtime.metadata_mut(id, &minimized).is_none());
        assert!(
            runtime
                .metadata_mut(CorpusId::from(1_usize), &probed)
                .is_none()
        );
    }

    #[test]
    fn reprobing_replaces_previous_results() {
        let mut runtime = RuntimeMetadata::default();
        let id = CorpusId::from(0_usize);
        let probed = program(5);
        let minimized = program(2);

        probe(&mut runtime, id, &probed, &vec![block_txn_request(4)]);
        probe(&mut runtime, id, &minimized, &vec![block_txn_request(1)]);

        assert!(runtime.metadata_mut(id, &probed).is_none());
        let requests = runtime
            .metadata_mut(id, &minimized)
            .unwrap()
            .block_txn_request();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].triggering_instruction_index, 1);
    }

    #[test]
    fn probe_without_results_has_no_metadata() {
        let mut runtime = RuntimeMetadata::default();
        let id = CorpusId::from(0_usize);
        let probed = program(5);
        let failure = ProbeResult::Failure {
            command: "getblocktxn".to_string(),
            reason: "test".to_string(),
        };

        probe(&mut runtime, id, &probed, &vec![failure]);

        assert!(runtime.is_probed(id, &probed));
        assert!(runtime.metadata_mut(id, &probed).is_none());
    }
}
