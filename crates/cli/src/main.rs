use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use redagent_app::{
    report_markdown, run, Config, LlmConfig, DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL,
};
use redagent_core::Ledger;

#[derive(Debug, Parser)]
#[command(
    name = "redagent",
    version,
    about = "Autonomous offensive-security agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run an engagement against RedHands over MCP.
    Run {
        goal: String,
        /// Path to the checksum-pinned RedHands binary.
        #[arg(long)]
        redhands: PathBuf,
        /// SQLite ledger to create or append to.
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
        /// Use the LLM planner instead of the deterministic Phase 0 planner.
        #[arg(long)]
        llm: bool,
        /// OpenAI-compatible chat endpoint (env: REDAGENT_LLM_BASE_URL).
        #[arg(long, default_value = DEFAULT_LLM_BASE_URL)]
        llm_base_url: String,
        /// Model name (env: REDAGENT_LLM_MODEL).
        #[arg(long, default_value = DEFAULT_LLM_MODEL)]
        llm_model: String,
        /// Environment variable holding the LLM API key.
        #[arg(long, default_value = "REDAGENT_LLM_API_KEY")]
        llm_api_key_env: String,
        /// ⚠️ Auto-approve every gated RedHands tool without human review.
        #[arg(long)]
        auto_approve: bool,
        #[arg(long, default_value_t = 8)]
        max_tool_calls: usize,
        #[arg(long, default_value_t = 6)]
        max_intents: usize,
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

fn resolve_llm_config(base_url: &str, model: &str, key_env: &str) -> Result<LlmConfig> {
    let api_key = match std::env::var(key_env) {
        Ok(key) if !key.trim().is_empty() => key,
        _ if key_env == "REDAGENT_LLM_API_KEY" => match std::env::var("ICA_API_KEY") {
            Ok(key) if !key.trim().is_empty() => key,
            _ => bail!(
                "no LLM API key: set REDAGENT_LLM_API_KEY (or ICA_API_KEY), or pass --llm-api-key-env"
            ),
        },
        _ => bail!("no LLM API key in environment variable {key_env}"),
    };
    Ok(LlmConfig {
        base_url: if key_env == "REDAGENT_LLM_API_KEY" {
            std::env::var("REDAGENT_LLM_BASE_URL").unwrap_or_else(|_| base_url.to_string())
        } else {
            base_url.to_string()
        },
        api_key,
        model: if key_env == "REDAGENT_LLM_API_KEY" {
            std::env::var("REDAGENT_LLM_MODEL").unwrap_or_else(|_| model.to_string())
        } else {
            model.to_string()
        },
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            goal,
            redhands,
            ledger,
            llm,
            llm_base_url,
            llm_model,
            llm_api_key_env,
            auto_approve,
            max_tool_calls,
            max_intents,
        } => {
            let mut config = Config::new(goal, redhands, ledger.clone())
                .with_limits(max_tool_calls, max_intents);
            if llm {
                config = config.with_llm(resolve_llm_config(
                    &llm_base_url,
                    &llm_model,
                    &llm_api_key_env,
                )?);
            }
            if auto_approve {
                eprintln!(
                    "⚠️  AUTO-APPROVE ENABLED: every gated RedHands tool will be approved without human review. Authorized engagements only."
                );
                config = config.with_approval_mode(redagent_app::ApprovalMode::ApproveAll);
            }
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
