use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use redagent_app::{report_markdown, run, Config};
use redagent_core::Ledger;

#[derive(Debug, Parser)]
#[command(
    name = "redagent",
    version,
    about = "Autonomous offensive-security agent (Phase 0)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a single deterministic intent against RedHands over MCP.
    Run {
        goal: String,
        /// Path to the checksum-pinned RedHands binary.
        #[arg(long)]
        redhands: PathBuf,
        /// SQLite ledger to create or append to.
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
    },
    /// Render a ledger as a Markdown report.
    Report {
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
    },
    /// Verify the hash chain of a ledger.
    Verify {
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            goal,
            redhands,
            ledger,
        } => {
            let config = Config::new(goal, redhands, ledger.clone());
            run(&config)?;
            print!("{}", report_markdown(&ledger)?);
        }
        Command::Report { ledger } => print!("{}", report_markdown(&ledger)?),
        Command::Verify { ledger } => {
            let count = Ledger::open(&ledger)?.verify_chain()?;
            println!("OK: {count} events, hash chain verified");
        }
    }
    Ok(())
}
