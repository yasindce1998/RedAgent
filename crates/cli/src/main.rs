use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use redagent_app::{report_markdown, run, Config, LlmConfig};
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
        /// OpenAI-compatible chat endpoint (or env: REDAGENT_LLM_BASE_URL).
        #[arg(long)]
        llm_base_url: Option<String>,
        /// Model name (or env: REDAGENT_LLM_MODEL).
        #[arg(long)]
        llm_model: Option<String>,
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
        /// Re-run each tool after verification to confirm the finding.
        #[arg(long)]
        retest: bool,
        /// Comma-separated RedHands toolsets to expose (e.g. nmap,vuln).
        /// Tool ids, not profiles: "all" is not a valid value.
        #[arg(long, default_value = "health")]
        toolsets: String,
        /// Auto-admit read-only, non-gated tools from the live catalog.
        /// Without this, only the explicitly allowlisted tools may run.
        #[arg(long)]
        allow_read_only: bool,
    },
    /// Export an engagement as SARIF, CycloneDX, MITRE Navigator or Markdown.
    Export {
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
        #[arg(long, default_value = "markdown")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
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
    /// Start the REST/SSE control API for the desktop UI.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        /// Directory holding engagement ledgers.
        #[arg(long, default_value = ".")]
        ledger_dir: PathBuf,
        /// Path to the checksum-pinned RedHands binary.
        #[arg(long)]
        redhands: PathBuf,
        #[arg(long, default_value_t = 300)]
        approval_timeout_secs: u64,
    },
}

fn resolve_llm_config(
    base_url: Option<String>,
    model: Option<String>,
    key_env: &str,
) -> Result<LlmConfig> {
    let api_key = match std::env::var(key_env) {
        Ok(key) if !key.trim().is_empty() => key,
        _ => bail!("no LLM API key in environment variable {key_env}"),
    };
    let base_url = base_url
        .or_else(|| std::env::var("REDAGENT_LLM_BASE_URL").ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("set REDAGENT_LLM_BASE_URL or pass --llm-base-url for --llm")
        })?;
    let model = model
        .or_else(|| std::env::var("REDAGENT_LLM_MODEL").ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("set REDAGENT_LLM_MODEL or pass --llm-model for --llm"))?;
    Ok(LlmConfig {
        base_url,
        api_key,
        model,
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
            retest,
            toolsets,
            allow_read_only,
        } => {
            let mut config = Config::new(goal, redhands, ledger.clone())
                .with_limits(max_tool_calls, max_intents)
                .with_retest(retest)
                .with_toolsets(toolsets);
            if allow_read_only {
                config = config.with_allowed_tools(Vec::<String>::new());
            }
            if llm {
                config = config.with_llm(resolve_llm_config(
                    llm_base_url,
                    llm_model,
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
        Command::Export {
            ledger,
            format,
            output,
        } => {
            let view = redagent_app::load_view(&ledger)?;
            let format: redagent_export::ExportFormat = format.parse()?;
            let content = redagent_export::export(&view, format)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, content)?;
                    println!("wrote {}", path.display());
                }
                None => print!("{content}"),
            }
        }
        Command::Report { ledger } => print!("{}", report_markdown(&ledger)?),
        Command::Verify { ledger } => {
            let count = Ledger::open(&ledger)?.verify_chain()?;
            println!("OK: {count} events, hash chain verified");
        }
        Command::Serve {
            bind,
            ledger_dir,
            redhands,
            approval_timeout_secs,
        } => {
            let bind = bind.parse::<std::net::SocketAddr>()?;
            let config = redagent_api::ApiConfig {
                bind,
                ledger_dir,
                redhands_binary: redhands,
                approval_timeout: std::time::Duration::from_secs(approval_timeout_secs),
            };
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(redagent_api::serve(config))?;
        }
    }
    Ok(())
}
