use std::marker::PhantomData;
use std::ops::IndexMut;
use std::path::Path;
use std::time::Duration;

use libafl::{
    Error,
    executors::{Executor, ExitKind, HasObservers, HasTimeout, SetTimeout},
    inputs::HasTargetBytes,
    observers::{ObserversTuple, StdOutObserver},
    state::HasExecutions,
};
use libafl_bolts::{
    AsSlice,
    tuples::{Handle, RefIndexable},
};

use std::sync::{Arc, Mutex};

use bedrock_lab::{
    Checkpoint, Event, EventSink, FuzzOutcome, LabOpts, RngMode, RunOutcome, VirtDuration, VirtTime,
};
use bedrock_vm::{ExitKind as VmExitKind, LinuxBootConfig, VmBuilder, load_kernel};

/// The guest image has no `bedrock-console.ko`, so kernel and harness output
/// has to go through the emulated UART. Anything else produces a silent guest.
const CMDLINE: &str = "console=ttyS0 nopti nokaslr mitigations=off audit=0";

/// Seeds the hypervisor's RDRAND/RDSEED emulation.
const DEFAULT_RNG_SEED: u64 = 0xbed0_f022;

#[derive(Default)]
struct ConsoleCollector {
    lines: Mutex<Vec<u8>>,
}

impl ConsoleCollector {
    /// Take everything collected since the last call.
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.lines.lock().unwrap())
    }
}

impl EventSink for ConsoleCollector {
    fn on_event(&self, event: Event<'_>) {
        if let Event::SerialLine { line, .. } = event {
            let mut buf = self.lines.lock().unwrap();
            buf.extend_from_slice(line);
            buf.push(b'\n');
        }
    }
}

pub struct BedrockHelper {
    /// Snapshot taken where the guest requested its first input.
    checkpoint: Checkpoint,
    /// Identifier the coverage map is registered under: `cov-afl` for the
    /// agent-owned AFL++ map.
    coverage_id: Vec<u8>,
    /// Stable coverage map.
    coverage: Box<[u8]>,
    /// Largest test case the guest's input buffer can take.
    input_size: usize,
    /// Per-test-case budget in guest virtual time.
    timeout: Duration,
    /// Virtual time of the checkpoint.
    base_time: VirtTime,
    /// Emulated TSC frequency.
    tsc_frequency: u64,
    /// Guest console output, drained once per test case.
    console: Arc<ConsoleCollector>,
}

impl BedrockHelper {
    /// Boot the guest, run the scenario's one-time setup, and checkpoint when
    /// the guest first asks for an input.
    pub fn new(
        vmlinux: &Path,
        initramfs: &Path,
        memory_mb: usize,
        setup_timeout: Duration,
        timeout: Duration,
        dump_dir: &Path,
    ) -> Result<Self, Error> {
        let err = |e: String| Error::illegal_state(e);

        // Build and boot the guest.
        let mut vm = VmBuilder::new()
            .memory_mb(memory_mb)
            .build()
            .map_err(|e| err(format!("failed to create VM: {e}")))?;
        let kernel = std::fs::read(vmlinux)?;
        let initrd = std::fs::read(initramfs)?;
        let (entry, end) = {
            let memory = vm
                .memory_mut()
                .map_err(|e| err(format!("failed to map guest memory: {e}")))?;
            load_kernel(memory, &kernel).map_err(|e| err(format!("failed to load kernel: {e}")))?
        };
        let boot = LinuxBootConfig::new(entry, end)
            .cmdline(CMDLINE)
            .initramfs(&initrd);
        vm.setup_linux_boot(&boot)
            .map_err(|e| err(format!("failed to set up boot: {e}")))?;

        // The agent signals ready once its input buffer is registered, which is
        // before the scenario spawns its target — too early to fork from.
        let freq = bedrock_vm::DEFAULT_TSC_FREQUENCY;
        let console = Arc::new(ConsoleCollector::default());
        let ready = Checkpoint::initial_when_ready_with(
            vm,
            VirtTime::from_secs(setup_timeout.as_secs().max(1), freq),
            LabOpts {
                sink: console.clone(),
                rng: RngMode::Seeded(DEFAULT_RNG_SEED),
                file_store_dir: Some(dump_dir.to_path_buf()),
                ..Default::default()
            },
        )
        .map_err(|e| err(format!("guest never signalled ready: {e}")))?;

        // Branch off the ready VM and run the branch until the first input request.
        let mut setup = ready
            .branch()
            .map_err(|e| err(format!("failed to fork setup branch: {e}")))?;
        let deadline = ready.time()
            + VirtDuration::from_secs(setup_timeout.as_secs().max(1), ready.tsc_frequency());
        let (_, outcome) = setup
            .run_until(deadline)
            .map_err(|e| err(format!("setup run failed: {e}")))?;
        if !matches!(
            outcome,
            RunOutcome::Yielded {
                kind: VmExitKind::FuzzNextInput
            }
        ) {
            return Err(err(format!(
                "scenario never requested an input during setup (got {outcome:?})"
            )));
        }

        let input_size = setup
            .fuzz_input_capacity()
            .map_err(|e| err(format!("failed to size the input buffer: {e}")))?;

        // Find the target's coverage buffer and size our map to match it.
        let ids = setup
            .feedback_buffer_ids()
            .map_err(|e| err(format!("failed to list feedback buffers: {e}")))?;
        let coverage_id = ids
            .iter()
            .find(|id| id.starts_with(b"cov-"))
            .cloned()
            .ok_or_else(|| {
                err(
                    "guest registered no cov-* buffer: is the target built with \
                     afl-clang-fast (and the scenario built with BITCOIND_PATH set, \
                     so the agent knows the map size)?"
                        .to_string(),
                )
            })?;
        let coverage_len = setup
            .feedback_buffers_to_vec(&coverage_id)
            .map_err(|e| err(format!("failed to read the coverage buffer: {e}")))?
            .first()
            .map_or(0, Vec::len);
        if coverage_len == 0 {
            return Err(err("guest's coverage buffer is empty".to_string()));
        }

        // Discard console logs so the collector is fresh.
        console.take();

        let base_time = setup.current_time();
        let tsc_frequency = setup.tsc_frequency();
        let checkpoint = setup
            .checkpoint()
            .map_err(|e| err(format!("failed to checkpoint after setup: {e}")))?;

        Ok(Self {
            checkpoint,
            coverage_id,
            coverage: vec![0u8; coverage_len].into_boxed_slice(),
            input_size,
            timeout,
            base_time,
            tsc_frequency,
            console,
        })
    }

    /// Pointer to the coverage map, for `StdMapObserver::from_mut_ptr`.
    pub fn coverage_ptr(&mut self) -> *mut u8 {
        self.coverage.as_mut_ptr()
    }

    /// Size of the coverage map in bytes.
    #[must_use]
    pub fn coverage_size(&self) -> usize {
        self.coverage.len()
    }

    /// Largest test case the guest will accept.
    #[must_use]
    pub fn input_size(&self) -> usize {
        self.input_size
    }
}

/// Executes one fuzzamoto test case per forked bedrock VM.
pub struct BedrockExecutor<S, OT> {
    helper: BedrockHelper,
    /// Where the guest's console output goes.
    stdout: Option<Handle<StdOutObserver>>,
    observers: OT,
    phantom: PhantomData<S>,
}

impl<S, OT> BedrockExecutor<S, OT> {
    pub fn new(helper: BedrockHelper, observers: OT) -> Self {
        Self {
            helper,
            stdout: None,
            observers,
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn with_stdout(mut self, stdout: Handle<StdOutObserver>) -> Self {
        self.stdout = Some(stdout);
        self
    }
}

impl<EM, I, OT, S, Z> Executor<EM, I, S, Z> for BedrockExecutor<S, OT>
where
    S: HasExecutions,
    I: HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        let bytes = input.target_bytes();
        let buffer = bytes.as_slice();
        if buffer.len() > self.helper.input_size() {
            return Err(Error::illegal_state(format!(
                "input does not fit in the guest's input buffer: {} > {}",
                buffer.len(),
                self.helper.input_size()
            )));
        }

        // Branch off the checkpoint and give it an input.
        let mut branch = self
            .helper
            .checkpoint
            .branch()
            .map_err(|e| Error::illegal_state(format!("failed to fork the VM: {e}")))?;
        branch
            .serve_fuzz_input(buffer)
            .map_err(|e| Error::illegal_state(format!("failed to deliver the input: {e}")))?;

        let budget_ms = u64::try_from(self.helper.timeout.as_millis()).unwrap_or(u64::MAX);
        let deadline = self.helper.base_time
            + VirtDuration::from_millis(budget_ms.max(1), self.helper.tsc_frequency);
        let (_, outcome) = branch
            .run_until(deadline)
            .map_err(|e| Error::illegal_state(format!("failed to run the VM: {e}")))?;

        let exit_kind = match outcome {
            // The guest simultaneously requests the next input and reports last run's outcome.
            RunOutcome::Yielded {
                kind: VmExitKind::FuzzNextInput,
            } => match branch
                .fuzz_outcome()
                .map_err(|e| Error::illegal_state(format!("failed to read the outcome: {e}")))?
            {
                FuzzOutcome::Ok | FuzzOutcome::Skip => ExitKind::Ok,
                FuzzOutcome::Fail(_) | FuzzOutcome::Unknown(_) => ExitKind::Crash,
            },
            RunOutcome::ReachedTime => ExitKind::Timeout,
            RunOutcome::Yielded {
                kind: VmExitKind::VmcallShutdown,
            } => ExitKind::Crash,
            other => {
                return Err(Error::illegal_state(format!(
                    "unexpected VM outcome: {other:?}"
                )));
            }
        };

        // Copy this fork's edge counters into the stable map the observers read.
        let id = self.helper.coverage_id.clone();
        let buffers = branch
            .feedback_buffers_to_vec(&id)
            .map_err(|e| Error::illegal_state(format!("failed to read coverage: {e}")))?;
        self.helper.coverage.fill(0);
        for buf in buffers {
            let n = buf.len().min(self.helper.coverage.len());
            for (dst, src) in self.helper.coverage[..n].iter_mut().zip(&buf[..n]) {
                *dst = dst.saturating_add(*src);
            }
        }

        if let Some(handle) = self.stdout.clone() {
            let output = self.helper.console.take();
            self.observers_mut().index_mut(&handle).observe(output);
        }

        Ok(exit_kind)
    }
}

impl<S, OT> HasObservers for BedrockExecutor<S, OT> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<S, OT> HasTimeout for BedrockExecutor<S, OT> {
    fn timeout(&self) -> Duration {
        self.helper.timeout
    }
}

impl<S, OT> SetTimeout for BedrockExecutor<S, OT> {
    fn set_timeout(&mut self, timeout: Duration) {
        self.helper.timeout = timeout;
    }
}
