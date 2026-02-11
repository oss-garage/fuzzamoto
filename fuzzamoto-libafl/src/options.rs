use rand::{Rng, RngCore};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use libafl_bolts::core_affinity::{CoreId, Cores};

/// Profiles that define which mutators/generators are enabled
#[derive(Debug, Clone, Default, ValueEnum)]
pub enum Profile {
    /// All generators except slow/specialized ones
    #[default]
    Default,
    /// All generators enabled
    All,
    /// Generators focused on connection and handshake testing
    Connections,
}

#[readonly::make]
#[derive(Parser, Debug)]
#[clap(author, about, long_about = None)]
#[command(
    name = format!("fuzzamoto-libafl"),
    about,
    long_about = "Fuzzamoto IR fuzzer"
)]
pub struct FuzzerOptions {
    #[arg(short, long, help = "Input directory")]
    pub input: String,

    #[arg(short, long, help = "Output directory")]
    pub output: String,

    #[arg(short, long, help = "Shared directory")]
    pub share: String,

    #[arg(short, long, help = "Input buffer size", default_value_t = 8388608)]
    pub buffer_size: usize,

    #[arg(long, help = "Log file")]
    pub log: Option<String>,

    #[arg(long, help = "Timeout in milli-seconds", default_value = "1000")]
    pub timeout: u32,

    #[arg(long, help = "Don't report hangs as bugs", default_value_t = false)]
    pub ignore_hangs: bool,

    #[arg(
        long,
        help = "Multiplier applied to timeout value to determine hang detection threshold (hang_timeout = hang_multiple * timeout)",
        default_value_t = 5
    )]
    pub hang_multiple: u32,

    #[arg(
        long,
        help = "Client launch delay in milli-seconds",
        default_value = "1000"
    )]
    pub launch_delay: u64,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    pub port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    pub cores: Cores,

    #[arg(
        long,
        help = "Don't add new inputs to the corpus",
        default_value_t = false
    )]
    pub static_corpus: bool,

    #[arg(
        long,
        help = "Remove disabled corpus entries after intial load",
        default_value_t = false
    )]
    pub prune_disabled: bool,

    #[arg(
        long,
        help = "Pushover token",
        requires = "pushover_user",
        env = "FUZZAMOTO_PUSHOVER_TOKEN"
    )]
    pub pushover_token: Option<String>,

    #[arg(
        long,
        help = "Pushover user",
        requires = "pushover_token",
        env = "FUZZAMOTO_PUSHOVER_USER"
    )]
    pub pushover_user: Option<String>,

    #[arg(
        long,
        help = "Number of corpus entries cached in memory",
        env = "FUZZAMOTO_CORPUS_CACHE",
        default_value_t = 5000
    )]
    pub corpus_cache: usize,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    pub verbose: bool,

    #[clap(long, help = "Enable AFL++ style output", conflicts_with = "verbose")]
    pub tui: bool,

    #[arg(long = "iterations", help = "Maximum numer of iterations")]
    pub iterations: Option<u64>,

    #[arg(
        short = 'r',
        help = "An input to rerun, instead of starting to fuzz. Will ignore all other settings."
    )]
    pub rerun_input: Option<PathBuf>,

    #[arg(short = 'm', long, help = "An input to minimize")]
    pub minimize_input: Option<PathBuf>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated list of mutators/generators to enable (overrides profile)"
    )]
    pub mutators: Option<Vec<String>>,

    #[cfg(feature = "bench")]
    #[arg(
        long,
        help = "Benchmark snapshot interval in seconds",
        default_value_t = 30
    )]
    pub bench_snapshot_secs: u64,

    #[arg(
        long,
        help = "Probability of enabling a generator/mutator in swarm testing mode",
        default_value_t = 1.0,
        value_parser = |v: &str| {
            let p: f64 = v.parse().map_err(|_| "Swarm must be a number between 0.0 and 1.0")?;
            if (0.0..=1.0).contains(&p) {
                Ok(p)
            } else {
                Err("Swarm must be a number between 0.0 and 1.0")
            }
        }
    )]
    pub swarm: f64,

    #[arg(
        long,
        help = "Seed for swarm testing (defaults to current Unix time)",
        default_value_t = unix_time()
    )]
    pub swarm_seed: u64,

    #[arg(
        long,
        default_value = "default",
        help = "Profile that defines which generators are enabled"
    )]
    pub profile: Profile,

    #[arg(long, help = "Enable incremental snapshots", default_value_t = false)]
    pub incremental_snapshots: bool,
}

fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl FuzzerOptions {
    pub fn input_dir(&self) -> PathBuf {
        PathBuf::from(&self.input)
    }

    pub fn shared_dir(&self) -> PathBuf {
        PathBuf::from(&self.share)
    }

    pub fn output_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = PathBuf::from(&self.output);
        dir.push(format!("cpu_{:03}", core_id.0));
        dir
    }

    #[cfg(feature = "bench")]
    pub fn bench_dir(&self) -> PathBuf {
        let mut dir = PathBuf::from(&self.output);
        dir.push("bench");
        dir
    }

    #[cfg(feature = "bench")]
    pub fn bench_snapshot_secs(&self) -> u64 {
        self.bench_snapshot_secs
    }

    pub fn queue_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = self.output_dir(core_id).clone();
        dir.push("queue");
        dir
    }

    pub fn work_dir(&self) -> PathBuf {
        let mut dir = PathBuf::from(&self.output);
        dir.push("workdir");
        dir
    }

    pub fn crashes_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = self.output_dir(core_id).clone();
        dir.push("crashes");
        dir
    }

    /// Returns the weight for a mutator/generator, or 0.0 if it's disabled
    pub fn mutator_weight<R: RngCore>(&self, name: &str, weight: f32, rng: &mut R) -> f32 {
        let base_weight = match &self.mutators {
            Some(list) => {
                if list.iter().any(|m| m == name) {
                    weight
                } else {
                    0.0
                }
            }
            None => {
                match self.profile {
                    Profile::Default => {
                        // Generators disabled in the default profile
                        const DISABLED: &[&str] = &[
                            "AddConnectionGenerator:out:handshake",
                            "AddConnectionGenerator:in:handshake",
                            "AddConnectionGenerator:out",
                            "AddConnectionGenerator:in",
                        ];
                        if DISABLED.contains(&name) {
                            0.0
                        } else {
                            weight
                        }
                    }
                    Profile::All => weight,
                    Profile::Connections => {
                        const ENABLED: &[&str] = &[
                            "InputMutator",
                            "OperationMutator",
                            "AddConnectionGenerator:out:handshake",
                            "AddConnectionGenerator:in:handshake",
                            "AddConnectionGenerator:out",
                            "AddConnectionGenerator:in",
                            "AdvanceTimeGenerator",
                            "HeaderGenerator",
                            "BlockGenerator",
                            "TxoGenerator",
                            "SingleTxGenerator",
                            "SendBlockGenerator",
                        ];
                        if ENABLED.contains(&name) { weight } else { 0.0 }
                    }
                }
            }
        };

        if self.swarm < 1.0 && base_weight > 0.0 {
            if rng.gen_bool(self.swarm) {
                base_weight
            } else {
                0.0
            }
        } else {
            base_weight
        }
    }
}
