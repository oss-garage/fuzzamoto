use crate::runners::Runner;

pub mod generic;

/// `ScenarioInput` is a trait for scenario input types
pub trait ScenarioInput<'a>: Sized {
    /// Decode the input from a byte slice
    fn decode(bytes: &'a [u8]) -> Result<Self, String>;
}

/// `ScenarioResult` describes the various outcomes of running a scenario
pub enum ScenarioResult {
    /// Scenario ran successfully
    Ok,
    /// Scenario indicated that the test case should be skipped
    Skip,
    /// Scenario indicated that the test case failed (i.e. the target node crashed)
    Fail(String),
}

/// `Scenario` is the interface for test scenarios that can be run against a target node
pub trait Scenario<'a, I>: Sized
where
    I: ScenarioInput<'a>,
{
    /// Create a new instance of the scenario, preparing the initial state of the test
    fn new(args: &[String]) -> Result<Self, String>;
    // Run the test
    fn run(&mut self, testcase: I, runner: &dyn Runner) -> ScenarioResult;
}

#[macro_export]
macro_rules! fuzzamoto_main {
    ($scenario_type:ty, $testcase_type:ty) => {
        fn main() -> std::process::ExitCode {
            use env_logger;
            use fuzzamoto::runners::{Runner, StdRunner};
            use std::process::{Command, ExitCode};

            env_logger::init();

            // Initializing the runner before initializing the scenario is important when executing
            // in Nyx to ensure `nyx_init` is called before targets are spawned.
            let runner = StdRunner::new();

            // Define the scenario type with the target as its generic parameter
            let args: Vec<String> = std::env::args().collect();
            let mut scenario = match <$scenario_type>::new(&args) {
                Ok(scenario) => scenario,
                Err(e) => {
                    log::error!("Failed to initialize scenario: {}", e);
                    let exit_code = std::env::var("FUZZAMOTO_INIT_ERROR_EXIT_CODE")
                        .map_or(0, |v| v.parse().unwrap_or(0));
                    return ExitCode::from(exit_code);
                }
            };

            // Invoke the patched signal handler to reset coverage counters.
            if cfg!(feature = "coverage") {
                if let Ok(output) = Command::new("pgrep").arg("bitcoind").output() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let mut lines = stdout.lines();
                    assert_eq!(lines.clone().count(), 1);
                    let pid = lines.next().unwrap().trim();

                    // Send SIGUSR1 to bitcoind which will invoke the patched signal handler.
                    if let Ok(signal_output) = Command::new("kill").args(["-10", pid]).output() {
                        assert!(signal_output.status.success());
                    }
                } else {
                    return ExitCode::FAILURE;
                }
            }

            // Ensure the runner dropped prior to the scenario when returning from main.
            let runner = runner;

            log::info!("Scenario initialized! Executing input...");

            // In nyx mode the snapshot is taken here and a new fuzz input is provided each reset.
            let input = runner.get_fuzz_input();

            let Ok(testcase) = <$testcase_type>::decode(&input) else {
                log::warn!("Failed to decode test case!");
                // TODO drop(target);
                runner.skip();
                return ExitCode::SUCCESS;
            };

            match scenario.run(testcase, &runner) {
                ScenarioResult::Ok => {}
                ScenarioResult::Skip => {
                    // TODO drop(target);
                    runner.skip();
                    return ExitCode::SUCCESS;
                }
                ScenarioResult::Fail(err) => {
                    runner.fail(&format!("Test case failed: {}", err));
                    return ExitCode::from(1);
                }
            }

            log::info!("Test case ran successfully!");
            return ExitCode::SUCCESS;
        }
    };
}
