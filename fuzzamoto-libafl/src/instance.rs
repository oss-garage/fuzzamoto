use std::{borrow::Cow, cell::RefCell, marker::PhantomData, process, rc::Rc, time::Duration};

use fuzzamoto_ir::{
    AddConnectionGenerator, AddTxToBlockGenerator, AddrRelayGenerator, AddrRelayV2Generator,
    AdvanceTimeGenerator, BlockGenerator, BlockTxnGenerator, BloomFilterAddGenerator,
    BloomFilterClearGenerator, BloomFilterLoadGenerator, CombineMutator, CompactBlockGenerator,
    CompactFilterQueryGenerator, GetAddrGenerator, GetDataGenerator, HeaderGenerator, InputMutator,
    InventoryGenerator, LargeTxGenerator, LongChainGenerator, OneParentOneChildGenerator,
    OperationMutator, Program, ReorgBlockGenerator, SendBlockGenerator, SendMessageGenerator,
    SingleTxGenerator, TipBlockGenerator, TxoGenerator, WitnessGenerator,
    cutting::CuttingMinimizer, instr_block::InstrBlockMinimizer, nopping::NoppingMinimizer,
};

use libafl::{
    Error, NopFuzzer,
    corpus::{CachedOnDiskCorpus, Corpus, CorpusId, OnDiskCorpus, Testcase},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, NopEventManager,
        ProgressReporter, SendExiting,
    },
    executors::Executor,
    feedback_and, feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, HasObserverHandle, MaxMapFeedback, TimeFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    mutators::{ComposedByMutations, TuneableScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, StdOutObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, QueueScheduler, StdWeightedScheduler,
        powersched::PowerSchedule,
    },
    stages::{ClosureStage, IfStage, StagesTuple, TuneableMutationalStage, WhileStage},
    state::{HasCorpus, HasMaxSize, HasRand, StdState},
};
use libafl_bolts::{
    HasLen, Named,
    core_affinity::CoreId,
    current_nanos,
    rands::{Rand, StdRand},
    tuples::{Handled, NamedTuple, tuple_list},
};

use std::collections::BTreeMap;

use libafl_nyx::{executor::NyxExecutor, helper::NyxHelper, settings::NyxSettings};
use rand::{SeedableRng, rngs::SmallRng};
use typed_builder::TypedBuilder;

use crate::{
    feedbacks::{CaptureTimeoutFeedback, CrashCauseFeedback},
    input::IrInput,
    mutators::{IrGenerator, IrMutator, IrSpliceMutator, LibAflByteMutator},
    options::FuzzerOptions,
    schedulers::SupportedSchedulers,
    stages::{
        IncrementalSnapshotStage, IrMinimizerStage, ProbingStage, SnapshotPlacementPolicy,
        StabilityCheckStage, VerifyTimeoutsStage,
    },
};

#[cfg(feature = "bench")]
use crate::stages::BenchStatsStage;
#[cfg(not(feature = "bench"))]
use libafl::stages::nop::NopStage;

macro_rules! weighted_mutations {
    ($options:expr, $rng:expr, $(($weight:expr, $mutation:expr)),+ $(,)?) => {{
        (
            tuple_list!($($mutation),+),
            [$($options.mutator_weight($mutation.name(), $weight, $rng)),+],
        )
    }};
}

pub type ClientState =
    StdState<CachedOnDiskCorpus<IrInput>, IrInput, StdRand, OnDiskCorpus<IrInput>>;

#[derive(TypedBuilder)]
pub struct Instance<'a, EM> {
    options: &'a FuzzerOptions,
    /// The harness. We create it before forking, then `take()` it inside the client.
    mgr: EM,
    client_description: ClientDescription,
}

const AUX_BUFFER_SIZE: usize = 0x20000;

fn log_weights<MT>(
    options: &FuzzerOptions,
    id: CoreId,
    mutations: &MT,
    weights: &[f32],
) -> Result<(), Error>
where
    MT: NamedTuple,
{
    let names = mutations.names();
    let map: BTreeMap<Cow<'_, str>, f32> = names.into_iter().zip(weights.iter().copied()).collect();

    let config_path = options.output_dir(id).join("config.json");
    let file = std::fs::File::create(config_path)?;
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &map)
        .map_err(|_| Error::serialize("Failed to serialize weights".to_string()))?;
    Ok(())
}

impl<EM> Instance<'_, EM>
where
    EM: EventFirer<IrInput, ClientState>
        + EventRestarter<ClientState>
        + ProgressReporter<ClientState>
        + SendExiting
        + EventReceiver<IrInput, ClientState>,
{
    pub fn run(mut self, state: Option<ClientState>) -> Result<(), Error> {
        let parent_cpu_id = self
            .options
            .cores
            .ids
            .first()
            .expect("unable to get first core id");

        let timeout = Duration::from_millis(u64::from(self.options.timeout));
        let settings = NyxSettings::builder()
            .cpu_id(self.client_description.core_id().0)
            .parent_cpu_id(Some(parent_cpu_id.0))
            .input_buffer_size(self.options.buffer_size)
            .aux_buffer_size(AUX_BUFFER_SIZE)
            .timeout_secs(u8::try_from(timeout.as_secs())?)
            .timeout_micro_secs(timeout.subsec_micros())
            .workdir_path(Cow::from(
                self.options.work_dir().to_str().unwrap().to_string(),
            ))
            .build();

        let helper = NyxHelper::new(self.options.shared_dir(), settings)?;

        let trace_observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::from_mut_ptr("trace", helper.bitmap_buffer, helper.bitmap_size)
        })
        .track_indices()
        .track_novelties();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let stdout_observer = StdOutObserver::new(Cow::Borrowed("hprintf_output")).unwrap();

        let map_feedback = MaxMapFeedback::new(&trace_observer);
        let map_feedback_name = map_feedback.name().to_string();
        let trace_handle = map_feedback.observer_handle().clone();

        #[cfg(feature = "bench")]
        let bench_stats_stage = BenchStatsStage::new(
            u32::try_from(self.client_description.core_id().0)
                .expect("core_id should fit into u32"),
            map_feedback_name.clone(),
            helper.bitmap_size,
            Duration::from_secs(self.options.bench_snapshot_secs()),
            self.options.bench_dir().join(format!(
                "bench-cpu_{:03}.csv",
                self.client_description.core_id().0
            )),
        );
        #[cfg(not(feature = "bench"))]
        let bench_stats_stage = NopStage::new();

        let map_observer_handle = trace_observer.handle();
        let stdout_observer_handle = stdout_observer.handle();

        // Feedback to rate the interestingness of an input
        let mut feedback = feedback_or!(
            // New maximization map feedback
            feedback_and_fast!(
                // Disable coverage feedback if the corpus is static
                ConstFeedback::new(!self.options.static_corpus),
                // Disable coverage feedback if we're minimizing an input
                ConstFeedback::new(self.options.minimize_input.is_none()),
                map_feedback
            ),
            // Time feedback
            TimeFeedback::new(&time_observer),
        );

        let enable_capture_timeouts = Rc::new(RefCell::new(true));
        let capture_timeout_feedback = CaptureTimeoutFeedback::new(
            Rc::clone(&enable_capture_timeouts),
            &self.options.crashes_dir(self.client_description.core_id()),
        );
        let timeout_verify_stage = IfStage::new(
            |_, _, _, _| Ok(!self.options.ignore_hangs),
            tuple_list!(VerifyTimeoutsStage::new(
                enable_capture_timeouts,
                Duration::from_millis(u64::from(self.options.timeout)),
                self.options.hang_multiple,
            )),
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and!(
            feedback_or_fast!(
                feedback_or!(
                    CrashFeedback::new(),
                    CrashCauseFeedback::new(
                        stdout_observer_handle.clone(),
                        &self.options.crashes_dir(self.client_description.core_id())
                    )
                ),
                feedback_and!(
                    ConstFeedback::new(!self.options.ignore_hangs),
                    capture_timeout_feedback,
                )
            ),
            // Only store objective if it triggers new coverage (compared to other solutions)
            MaxMapFeedback::with_name("mapfeedback_metadata_objective", &trace_observer)
        );

        // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved
                    CachedOnDiskCorpus::new(
                        self.options.queue_dir(self.client_description.core_id()),
                        self.options.corpus_cache,
                    )?,
                    // Corpus in which we store solutions
                    OnDiskCorpus::new(self.options.crashes_dir(self.client_description.core_id()))?,
                    &mut feedback,
                    &mut objective,
                )?
            }
        };

        let scheduler = if self.options.minimize_input.is_some() {
            // Avoid scheduler metatdata dependency
            SupportedSchedulers::Queue(QueueScheduler::new(), PhantomData)
        } else {
            // A minimization+queue policy to get testcasess from the corpus
            SupportedSchedulers::LenTimeMinimizer(
                IndexesLenTimeMinimizerScheduler::new(
                    &trace_observer,
                    StdWeightedScheduler::with_schedule(
                        &mut state,
                        &trace_observer,
                        Some(PowerSchedule::explore()),
                    ),
                ),
                PhantomData,
            )
        };

        let observers = tuple_list!(trace_observer, time_observer, stdout_observer);

        state.set_max_size(self.options.buffer_size);

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        if let Some(rerun_input) = &self.options.rerun_input {
            let input = IrInput::unparse(rerun_input);

            let mut executor = NyxExecutor::builder().build(helper, observers);

            let exit_kind = executor
                .run_target(
                    &mut NopFuzzer::new(),
                    &mut state,
                    &mut NopEventManager::new(),
                    &input,
                )
                .expect("Error running target");
            println!("Rerun finished with ExitKind {exit_kind:?}");
            // We're done :)
            process::exit(0);
        }

        let mut executor = NyxExecutor::builder()
            .stdout(stdout_observer_handle.clone())
            .build(helper, observers);

        let ir_context_dump = self.options.work_dir().join("dump/ir.context");
        let bytes = std::fs::read(ir_context_dump).expect("Could not read ir context file");
        let full_program_context: fuzzamoto_ir::FullProgramContext =
            postcard::from_bytes(&bytes).expect("could not deser ir context");

        if self
            .options
            .input_dir()
            .read_dir()
            .unwrap()
            .next()
            .is_none()
        {
            let initial_input = IrInput::new(Program::unchecked_new(
                full_program_context.context.clone(),
                vec![],
            ));
            let bytes = postcard::to_allocvec(&initial_input).unwrap();

            let file_path = self.options.input_dir().join("initial_input");
            std::fs::write(&file_path, bytes).unwrap();
        }

        let rng = SmallRng::seed_from_u64(state.rand_mut().next());
        let mut swarm_rng = SmallRng::seed_from_u64(self.options.swarm_seed);

        //IrSpliceMutator::new(ConcatMutator::new(), rng.clone()),
        let (mutations, weights) = weighted_mutations![
            self.options,
            &mut swarm_rng,
            (2000.0, IrMutator::new(InputMutator::new(), rng.clone())),
            (
                1000.0,
                IrMutator::new(OperationMutator::new(LibAflByteMutator::new()), rng.clone())
            ),
            (
                100.0,
                IrGenerator::new(
                    TipBlockGenerator::new(&full_program_context.headers),
                    rng.clone()
                )
            ),
            (
                100.0,
                IrGenerator::new(
                    ReorgBlockGenerator::new(full_program_context.headers.clone()),
                    rng.clone()
                )
            ),
            (
                100.0,
                IrSpliceMutator::new(CombineMutator::new(), rng.clone())
            ),
            (
                10.0,
                IrGenerator::new(AdvanceTimeGenerator::default(), rng.clone())
            ),
            (
                40.0,
                IrGenerator::new(SendMessageGenerator::default(), rng.clone())
            ),
            (50.0, IrGenerator::new(SingleTxGenerator, rng.clone())),
            (50.0, IrGenerator::new(LongChainGenerator, rng.clone())),
            (50.0, IrGenerator::new(LargeTxGenerator, rng.clone())),
            (
                50.0,
                IrGenerator::new(OneParentOneChildGenerator, rng.clone())
            ),
            (
                20.0,
                IrGenerator::new(
                    TxoGenerator::new(full_program_context.txos.clone()),
                    rng.clone()
                )
            ),
            (20.0, IrGenerator::new(WitnessGenerator::new(), rng.clone())),
            (20.0, IrGenerator::new(InventoryGenerator, rng.clone())),
            (20.0, IrGenerator::new(GetDataGenerator, rng.clone())),
            (
                50.0,
                IrGenerator::new(BlockGenerator::default(), rng.clone())
            ),
            (
                50.0,
                IrGenerator::new(
                    HeaderGenerator::new(full_program_context.headers.clone()),
                    rng.clone()
                )
            ),
            (50.0, IrGenerator::new(SendBlockGenerator, rng.clone())),
            (50.0, IrGenerator::new(AddTxToBlockGenerator, rng.clone())),
            (
                10.0,
                IrGenerator::new(CompactFilterQueryGenerator, rng.clone())
            ),
            (
                20.0,
                IrGenerator::new(BloomFilterLoadGenerator, rng.clone())
            ),
            (20.0, IrGenerator::new(BloomFilterAddGenerator, rng.clone())),
            (
                20.0,
                IrGenerator::new(BloomFilterClearGenerator, rng.clone())
            ),
            (
                20.0,
                IrGenerator::new(AddrRelayGenerator::default(), rng.clone())
            ),
            (
                20.0,
                IrGenerator::new(AddrRelayV2Generator::default(), rng.clone())
            ),
            (10.0, IrGenerator::new(GetAddrGenerator, rng.clone())),
            (200.0, IrGenerator::new(CompactBlockGenerator, rng.clone())),
            (200.0, IrGenerator::new(BlockTxnGenerator, rng.clone())),
            (
                20.0,
                IrGenerator::new(AddConnectionGenerator::handshake_outbound(), rng.clone())
            ),
            (
                50.0,
                IrGenerator::new(AddConnectionGenerator::handshake_inbound(), rng.clone())
            ),
            (
                20.0,
                IrGenerator::new(AddConnectionGenerator::outbound(), rng.clone())
            ),
            (
                50.0,
                IrGenerator::new(AddConnectionGenerator::inbound(), rng.clone())
            ),
        ];
        log_weights(
            self.options,
            self.client_description.core_id(),
            &mutations,
            &weights,
        )?;

        let tuneable_mutator = TuneableScheduledMutator::new(&mut state, mutations);
        let sum = weights.iter().sum::<f32>();
        debug_assert_eq!(tuneable_mutator.mutations().len(), weights.len());

        tuneable_mutator
            .set_mutation_probabilities(
                &mut state,
                weights.iter().map(|w| w / sum).collect::<Vec<f32>>(),
            )
            .unwrap();

        tuneable_mutator
            .set_iter_probabilities_pow(&mut state, vec![0.025f32, 0.1, 0.4, 0.3, 0.1, 0.05, 0.025])
            .unwrap();

        let mutator = tuneable_mutator;

        let minimizing_crash = self.options.minimize_input.is_some();

        // Counter holding the number of successful minimizations in the last round
        let continue_minimizing = RefCell::new(1u64);

        let probing = ProbingStage::new(&stdout_observer_handle);
        let stability = StabilityCheckStage::new(&map_observer_handle, &map_feedback_name, 8);

        let mutation_stage = TuneableMutationalStage::new(&mut state, mutator);

        let incremental_snapshot_stage =
            IncrementalSnapshotStage::new(mutation_stage, SnapshotPlacementPolicy::Balanced, 50);

        let mut stages = tuple_list!(
            ClosureStage::new(|_a: &mut _, _b: &mut _, _c: &mut _, _d: &mut _| {
                // Always try minimizing at least for one pass
                *continue_minimizing.borrow_mut() = 1;
                Ok(())
            }),
            WhileStage::new(
                |_, _, _, _| Ok((!self.options.static_corpus || minimizing_crash)
                    && *continue_minimizing.borrow() > 0),
                tuple_list!(
                    ClosureStage::new(|_a: &mut _, _b: &mut _, _c: &mut _, _d: &mut _| {
                        // Reset the minimization counter
                        *continue_minimizing.borrow_mut() = 0;
                        Ok(())
                    }),
                    IrMinimizerStage::<CuttingMinimizer, _, _>::new(
                        trace_handle.clone(),
                        200,
                        minimizing_crash,
                        &continue_minimizing
                    ),
                    IrMinimizerStage::<InstrBlockMinimizer, _, _>::new(
                        trace_handle.clone(),
                        200,
                        minimizing_crash,
                        &continue_minimizing
                    ),
                    IrMinimizerStage::<NoppingMinimizer, _, _>::new(
                        trace_handle.clone(),
                        200,
                        minimizing_crash,
                        &continue_minimizing
                    ),
                )
            ),
            IfStage::new(
                |_, _, _, _| Ok(self.options.minimize_input.is_none()),
                tuple_list!(
                    stability,
                    probing,
                    incremental_snapshot_stage,
                    timeout_verify_stage,
                    bench_stats_stage,
                )
            ),
        );
        self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
    }

    fn fuzz<Z, E, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        Z: Fuzzer<E, EM, IrInput, ClientState, ST> + Evaluator<E, EM, IrInput, ClientState>,
        ST: StagesTuple<E, EM, ClientState, Z>,
    {
        let corpus_dirs = [self.options.input_dir()];

        if state.must_load_initial_inputs() {
            if let Some(minimize_input) = &self.options.minimize_input {
                let input = IrInput::unparse(minimize_input);
                state.corpus_mut().add(Testcase::from(input)).unwrap();
            } else if self.options.static_corpus {
                state
                    .load_initial_inputs_forced(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {corpus_dirs:?}");
                        process::exit(0);
                    });
            } else {
                state
                    .load_initial_inputs(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {corpus_dirs:?}");
                        process::exit(0);
                    });
            }

            if self.options.prune_disabled {
                let corpus = state.corpus_mut();
                let disabled_corpus_ids: Vec<CorpusId> = (0..corpus.count_disabled())
                    .map(|idx| corpus.nth_from_all(idx + corpus.count()))
                    .collect();
                for id in &disabled_corpus_ids {
                    let _ = corpus.remove(*id);
                }
                println!(
                    "Pruned {} disabled inputs from corpus",
                    disabled_corpus_ids.len()
                );
            }

            println!("We imported {} inputs from disk", state.corpus().count());
        }

        if self.options.minimize_input.is_some() {
            fuzzer.fuzz_one(stages, executor, state, &mut self.mgr)?;
        } else if let Some(iters) = self.options.iterations {
            fuzzer.fuzz_loop_for(stages, executor, state, &mut self.mgr, iters)?;

            // It's important, that we store the state before restarting!
            // Else, the parent will not respawn a new child and quit.
            self.mgr.on_restart(state)?;
        } else {
            fuzzer.fuzz_loop(stages, executor, state, &mut self.mgr)?;
        }

        Ok(())
    }
}
