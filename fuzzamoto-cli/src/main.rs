mod commands;
mod error;
mod utils;

use clap::{Parser, Subcommand};
use commands::{CoverageCommand, InitCommand, IrCommand, init::InitOptions, ir};
use error::Result;
use std::path::PathBuf;

use crate::commands::coverage_batch::CoverageBatchCommand;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new fuzzamoto fuzzing campaign with Nyx
    Init {
        #[arg(long, help = "Path to the nyx share directory that should be created")]
        sharedir: PathBuf,
        #[arg(
            long,
            help = "Path to the crash handler that should be copied into the share directory"
        )]
        crash_handler: PathBuf,
        #[arg(
            long,
            help = "Path to the bitcoind binary that should be copied into the share directory"
        )]
        bitcoind: PathBuf,
        #[arg(
            long,
            help = "Path to the secondary bitcoind binary that should be copied into the share directory"
        )]
        secondary_bitcoind: Option<PathBuf>,
        #[arg(
            long,
            help = "Path to the fuzzamoto scenario binary that should be copied into the share directory"
        )]
        scenario: PathBuf,

        #[arg(long, help = "Path to the nyx installation")]
        nyx_dir: PathBuf,

        #[arg(
            long,
            help = "Path to the file with the RPC commands that should be copied into the share directory"
        )]
        rpc_path: Option<PathBuf>,

        #[arg(
            long,
            help = "Path to a serialized IR seed program to execute before the Nyx snapshot"
        )]
        seedprogram: Option<PathBuf>,
    },

    /// Create a html coverage report for a given corpus
    Coverage {
        #[arg(long, help = "Path to the output directory for the coverage report")]
        output: PathBuf,
        #[arg(long, help = "Path to the input corpus directory")]
        corpus: PathBuf,
        #[arg(
            long,
            help = "Path to the bitcoind binary that should be copied into the share directory"
        )]
        bitcoind: PathBuf,
        #[arg(
            long,
            help = "Path to the fuzzamoto scenario binary that should be run with coverage measurer"
        )]
        scenario: PathBuf,
        #[arg(
            long,
            value_name = "PROFRAWS",
            num_args = 1..,
            help = "profraws files to merge"
        )]
        profraws: Option<Vec<PathBuf>>,
        #[arg(
            long,
            default_value_t = false,
            help = "Only execute the corpus testcases and write .profraw files; skip merging profraws and HTML report generation"
        )]
        run_only: bool,
    },

    /// Create a html coverage report for a given corpus, runs using multiple docker instances
    CoverageBatch {
        #[arg(long, help = "Path to the output directory for the coverage report")]
        output: PathBuf,
        #[arg(long, help = "Path to the input corpus directory")]
        corpus: PathBuf,
        #[arg(long, help = "The docker image id of fuzzamoto-coverage")]
        docker_image: String,
        #[arg(
            long,
            value_parser = |s: &str| {
                let v: usize = s.parse().map_err(|_| "must be a positive integer")?;
                if v == 0 {
                    Err("The number of cpu to use must be greater than 0")
                } else {
                    Ok(v)
                }
            },
            help = "Number of CPUs to use (defaults to available parallelism)"
        )]
        cpu: Option<usize>,
        #[arg(long, help = "Name of the fuzzamoto scenario")]
        scenario: String,
    },

    /// Fuzzamoto intermediate representation (IR) commands
    IR {
        #[command(subcommand)]
        command: ir::IRCommands,
    },
}

fn main() -> Result<()> {
    // Log info by default
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Init {
            sharedir,
            crash_handler,
            bitcoind,
            secondary_bitcoind,
            scenario,
            nyx_dir,
            rpc_path,
            seedprogram,
        } => InitCommand::execute(
            sharedir,
            crash_handler,
            bitcoind,
            scenario,
            nyx_dir,
            InitOptions {
                secondary_bitcoind: secondary_bitcoind.as_ref(),
                rpc_path: rpc_path.as_ref(),
                seedprogram: seedprogram.as_ref(),
            },
        ),
        Commands::Coverage {
            output,
            corpus,
            bitcoind,
            scenario,
            profraws,
            run_only,
        } => CoverageCommand::execute(
            output,
            corpus,
            bitcoind,
            scenario,
            profraws.clone(),
            *run_only,
        ),
        Commands::CoverageBatch {
            output,
            corpus,
            docker_image,
            cpu,
            scenario,
        } => CoverageBatchCommand::execute(output, corpus, docker_image, *cpu, scenario),
        Commands::IR { command } => IrCommand::execute(command),
    }
}
