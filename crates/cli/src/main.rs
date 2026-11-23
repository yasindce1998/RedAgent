use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use redagent_app::{report_markdown, run, Config, LlmConfig};
use redagent_conformance::{render_report, run_conformance, ConformanceReport};
use redagent_contract::ToolServerManifest;
use redagent_core::Ledger;
use redagent_scope::{PolicyRule, Scope};
use redagent_signing::{Checkpoint, SigningKey};
use serde::{Deserialize, Serialize};

/// Repeated wherever signing keys or anchors are created: signatures only
/// detect tampering while the key and a trusted anchor live outside the ledger.
const INDEPENDENT_KEY_WARNING: &str = "WARNING: store the signing key independently of the ledger it signs, and publish anchors independently too. Anyone who can edit the ledger and read the key can simply recompute the head hash and re-sign, defeating tamper detection.";

#[derive(Debug, Deserialize)]
struct ScopeConfig {
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    rules: Vec<PolicyRule>,
    #[serde(default)]
    target_paths: Vec<String>,
}

fn apply_scope_file(mut config: Config, path: Option<&PathBuf>) -> Result<Config> {
    let Some(path) = path else {
        return Ok(config);
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading scope file {}", path.display()))?;
    let scope: ScopeConfig = serde_json::from_str(&text)
        .with_context(|| format!("parsing scope file {}", path.display()))?;
    config = config
        .with_scope(Scope::new(scope.cidrs, scope.domains, scope.ports)?)
        .with_rules(scope.rules)
        .with_target_paths(scope.target_paths);
    Ok(config)
}

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
        /// JSON file declaring scope (cidrs/domains/ports), rules and target paths.
        #[arg(long)]
        scope_file: Option<PathBuf>,
        /// Tool-server adapter manifest (defaults to the built-in RedHands encoding).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Fail closed when no scope is declared.
        #[arg(long)]
        require_scope: bool,
        /// Disable tool-output injection signal detection.
        #[arg(long)]
        no_injection_guard: bool,
        /// Ed25519 signing key file; enables signed ledger checkpoints.
        #[arg(long)]
        signing_key: Option<PathBuf>,
        #[arg(long, default_value_t = 50)]
        checkpoint_interval: usize,
    },
    /// Verify any MCP tool server against a RedAgent adapter manifest
    Conformance {
        /// Path to the tool server binary to probe over stdio.
        #[arg(long)]
        binary: PathBuf,
        /// Adapter manifest (defaults to ToolServerManifest::redhands()).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Per-request timeout, in seconds.
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
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
    /// Compare two engagement ledgers: fixed, still-open and new findings.
    Retest {
        /// The current (new) engagement ledger.
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
        /// The baseline ledger to compare against.
        #[arg(long)]
        against: PathBuf,
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
        /// Verify ed25519 signed checkpoints as well as the hash chain.
        #[arg(long)]
        signatures: bool,
        /// Public key hex (from `keygen`) required with --signatures.
        #[arg(long)]
        public_key: Option<String>,
        /// Independently stored anchor file to check against the ledger head.
        #[arg(long)]
        anchor: Option<PathBuf>,
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
    /// Generate a new ed25519 signing key.
    ///
    /// WARNING: the generated key must be stored independently of the ledger
    /// it signs. Anyone who can edit the ledger and read this key can
    /// recompute the head hash and re-sign, defeating tamper detection.
    Keygen {
        /// Path to write the signing key JSON file to (parent dirs are created).
        #[arg(long)]
        output: PathBuf,
        /// Replace an existing file at --output.
        #[arg(long)]
        overwrite: bool,
    },
    /// Sign the current ledger head into a portable anchor file.
    ///
    /// WARNING: the signing key must be stored independently of the ledger it
    /// signs, and the resulting anchor published independently too. Otherwise
    /// an attacker who can edit the ledger can roll it back together with the
    /// anchor and present a shorter, internally consistent history.
    Anchor {
        #[arg(long, default_value = "redagent.db")]
        ledger: PathBuf,
        /// Path to the Ed25519 signing key JSON file created by `keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Path to write the signed checkpoint (pretty JSON) to.
        #[arg(long)]
        output: PathBuf,
        /// Replace an existing file at --output.
        #[arg(long)]
        overwrite: bool,
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

/// Generate a fresh Ed25519 signing key and persist it at `output`.
///
/// An existing file is only replaced when `overwrite` is true. Never prints
/// secret key material: only the public key hex and short key id are reported.
pub fn keygen(output: &Path, overwrite: bool) -> Result<SigningKey> {
    let key = SigningKey::generate().context("generating signing key")?;
    key.to_file(output, overwrite)?;

    println!("signing key written to {}", output.display());
    println!("public key: {}", key.public_hex());
    println!("key id:     {}", key.key_id());
    eprintln!("{INDEPENDENT_KEY_WARNING}");

    Ok(key)
}

/// Sign the current head of `ledger` with `key` and write the resulting
/// checkpoint as pretty JSON to `output`.
///
/// The last stored event is used as the head (this branch has no checkpoint
/// event kind to skip). An empty ledger is rejected. An existing `output` is
/// only replaced when `overwrite` is true.
pub fn anchor(
    ledger_path: &Path,
    key_path: &Path,
    output: &Path,
    overwrite: bool,
) -> Result<Checkpoint> {
    let key = SigningKey::from_file(key_path)?;
    let ledger = Ledger::open(ledger_path)?;
    let events = ledger.events()?;
    let head = events
        .last()
        .ok_or_else(|| anyhow!("cannot anchor an empty ledger: {}", ledger_path.display()))?;

    let ts = Utc::now().to_rfc3339();
    let checkpoint = key.sign(head.seq, &head.hash, &ts)?;
    write_json_pretty(output, &checkpoint, overwrite)?;

    println!("wrote anchor to {}", output.display());
    println!("key id: {}", checkpoint.key_id);
    eprintln!("{INDEPENDENT_KEY_WARNING}");

    Ok(checkpoint)
}

/// Probe a tool server with the conformance suite and print its report.
///
/// A missing `--manifest` selects the built-in RedHands adapter. The returned
/// report is always `Ok` when the server could be spawned, including a failed
/// verdict, so callers decide whether a failing report is fatal.
pub fn conformance(
    binary: &Path,
    manifest_path: Option<&Path>,
    timeout_secs: u64,
) -> Result<ConformanceReport> {
    let manifest = match manifest_path {
        Some(path) => ToolServerManifest::from_file(path)
            .with_context(|| format!("loading manifest from {}", path.display()))?,
        None => ToolServerManifest::redhands(),
    };
    let report = run_conformance(
        binary,
        &[],
        &[],
        &manifest,
        Duration::from_secs(timeout_secs),
    )
    .with_context(|| format!("running conformance against {}", binary.display()))?;
    print!("{}", render_report(&report));
    Ok(report)
}

/// Serialize `value` as pretty JSON at `path`, creating parent directories and
/// refusing to replace an existing file unless `overwrite` is true.
fn write_json_pretty<T: Serialize>(path: &Path, value: &T, overwrite: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating anchor directory {}", parent.display()))?;
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("opening anchor file {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .with_context(|| format!("writing anchor JSON to {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flushing anchor file {}", path.display()))?;
    Ok(())
}

fn main() -> Result<()> {
    // Set REDAGENT_LOG=debug (or trace) to inspect planner/worker spans.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("REDAGENT_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
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
            scope_file,
            manifest,
            require_scope,
            no_injection_guard,
            signing_key,
            checkpoint_interval,
        } => {
            let mut config = Config::new(goal, redhands, ledger.clone())
                .with_limits(max_tool_calls, max_intents)
                .with_retest(retest)
                .with_toolsets(toolsets)
                .with_required_scope(require_scope)
                .with_injection_guard(!no_injection_guard)
                .with_checkpoint_interval(checkpoint_interval);
            if let Some(path) = manifest {
                config =
                    config
                        .with_manifest(ToolServerManifest::from_file(&path).with_context(
                            || format!("loading manifest from {}", path.display()),
                        )?);
            }
            if let Some(path) = signing_key {
                config = config
                    .with_signing_key(SigningKey::from_file(&path).context("loading signing key")?);
                eprintln!("{INDEPENDENT_KEY_WARNING}");
            }
            config = apply_scope_file(config, scope_file.as_ref())?;
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
        Command::Conformance {
            binary,
            manifest,
            timeout_secs,
        } => {
            let report = conformance(&binary, manifest.as_deref(), timeout_secs)?;
            if !report.passed {
                bail!("conformance check failed for {}", report.server);
            }
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
        Command::Retest {
            ledger,
            against,
            format,
            output,
        } => {
            let old = redagent_app::load_view(&against)?;
            let new = redagent_app::load_view(&ledger)?;
            let format = match format.to_ascii_lowercase().as_str() {
                "markdown" | "md" => redagent_export::DiffFormat::Markdown,
                "json" => redagent_export::DiffFormat::Json,
                other => bail!("unsupported diff format '{other}' (expected markdown or json)"),
            };
            let content = redagent_export::diff_retest(&old, &new, format)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, content)?;
                    println!("wrote {}", path.display());
                }
                None => print!("{content}"),
            }
        }
        Command::Report { ledger } => print!("{}", report_markdown(&ledger)?),
        Command::Verify {
            ledger,
            signatures,
            public_key,
            anchor,
        } => {
            let ledger = Ledger::open(&ledger)?;
            let events = ledger.events()?;
            let count = ledger.verify_chain()?;
            println!("OK: {count} events, hash chain verified");
            if signatures {
                let key = public_key.clone().ok_or_else(|| {
                    anyhow::anyhow!("--signatures requires --public-key <hex> from `keygen`")
                })?;
                let valid = redagent_core::verify_signed_checkpoints(&events, &key)?;
                println!("OK: {valid} signed checkpoints verified");
            }
            if let Some(path) = anchor {
                let checkpoint: Checkpoint = serde_json::from_str(&std::fs::read_to_string(&path)?)
                    .context("parsing anchor file")?;
                let event = events
                    .iter()
                    .find(|event| event.seq == checkpoint.seq)
                    .ok_or_else(|| anyhow::anyhow!("anchor seq not found in ledger"))?;
                if event.hash != checkpoint.head_hash {
                    bail!(
                        "anchor head hash does not match ledger event {}",
                        checkpoint.seq
                    );
                }
                let key = public_key
                    .ok_or_else(|| anyhow::anyhow!("--anchor requires --public-key <hex>"))?;
                if !redagent_signing::verify(&checkpoint, &key)? {
                    bail!("anchor signature is invalid");
                }
                println!("OK: anchor at seq {} matches the ledger", checkpoint.seq);
            }
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
        Command::Keygen { output, overwrite } => {
            keygen(&output, overwrite)?;
        }
        Command::Anchor {
            ledger,
            key,
            output,
            overwrite,
        } => {
            anchor(&ledger, &key, &output, overwrite)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use redagent_core::EventBody;
    use redagent_signing::verify;

    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp directory")
    }

    /// Create a ledger with a single event so it has a non-empty head.
    fn ledger_with_event(dir: &Path) -> PathBuf {
        let path = dir.join("ledger.db");
        let ledger = Ledger::open(&path).expect("open ledger");
        ledger
            .append(&EventBody::EngagementStarted {
                goal: "anchor test".to_owned(),
                redhands_version: "0.4.0".to_owned(),
            })
            .expect("append event");
        path
    }

    #[test]
    fn keygen_writes_key_and_round_trips() {
        let dir = temp_dir();
        let path = dir.path().join("nested").join("signing-key.json");
        let key = keygen(&path, false).expect("keygen should create the key");
        assert!(path.is_file(), "key file must exist, including parent dirs");

        let loaded = SigningKey::from_file(&path).expect("reload the key file");
        assert_eq!(loaded.public_hex(), key.public_hex());
        assert_eq!(loaded.key_id(), key.key_id());
    }

    #[test]
    fn keygen_refuses_overwrite_unless_requested() {
        let dir = temp_dir();
        let path = dir.path().join("signing-key.json");
        let first = keygen(&path, false).expect("first keygen");

        assert!(
            keygen(&path, false).is_err(),
            "second keygen must refuse to overwrite"
        );
        let still_first = SigningKey::from_file(&path).expect("reload original key");
        assert_eq!(still_first.public_hex(), first.public_hex());

        let second = keygen(&path, true).expect("keygen with --overwrite");
        let reloaded = SigningKey::from_file(&path).expect("reload overwritten key");
        assert_eq!(reloaded.public_hex(), second.public_hex());
    }

    #[test]
    fn anchor_rejects_empty_ledger() {
        let dir = temp_dir();
        let ledger_path = dir.path().join("empty.db");
        Ledger::open(&ledger_path).expect("create empty ledger");
        let key_path = dir.path().join("key.json");
        keygen(&key_path, false).expect("keygen");
        let output = dir.path().join("anchor.json");

        let error = anchor(&ledger_path, &key_path, &output, false)
            .expect_err("anchoring an empty ledger must fail");
        assert!(error.to_string().contains("empty ledger"));
        assert!(!output.exists(), "no anchor file should be written");
    }

    #[test]
    fn anchor_writes_valid_json_with_matching_head_and_key_id() {
        let dir = temp_dir();
        let ledger_path = ledger_with_event(dir.path());
        let key_path = dir.path().join("key.json");
        let key = keygen(&key_path, false).expect("keygen");
        let head = Ledger::open(&ledger_path)
            .expect("open ledger")
            .events()
            .expect("read events")
            .pop()
            .expect("ledger has one event");
        let output = dir.path().join("nested").join("anchor.json");

        let checkpoint = anchor(&ledger_path, &key_path, &output, false).expect("anchor");
        let text = fs::read_to_string(&output).expect("read anchor file");
        assert!(text.contains('\n'), "anchor JSON should be pretty printed");
        let parsed: Checkpoint = serde_json::from_str(&text).expect("parse anchor JSON");

        assert_eq!(parsed, checkpoint);
        assert_eq!(checkpoint.seq, head.seq);
        assert_eq!(checkpoint.head_hash, head.hash);
        assert_eq!(checkpoint.key_id, key.key_id());
        assert!(verify(&checkpoint, &key.public_hex()).expect("signature verification"));
    }

    #[test]
    fn anchor_respects_overwrite() {
        let dir = temp_dir();
        let ledger_path = ledger_with_event(dir.path());
        let key_path = dir.path().join("key.json");
        keygen(&key_path, false).expect("keygen");
        let output = dir.path().join("anchor.json");

        let first = anchor(&ledger_path, &key_path, &output, false).expect("first anchor");
        assert!(
            anchor(&ledger_path, &key_path, &output, false).is_err(),
            "second anchor must refuse to overwrite"
        );

        // Appending an event changes the head, so the rewritten anchor differs.
        let ledger = Ledger::open(&ledger_path).expect("open ledger");
        ledger
            .append(&EventBody::EngagementCompleted { findings: 0 })
            .expect("append second event");
        drop(ledger);

        let second = anchor(&ledger_path, &key_path, &output, true).expect("overwrite anchor");
        assert_ne!(second.seq, first.seq);
        let parsed: Checkpoint =
            serde_json::from_str(&fs::read_to_string(&output).expect("read rewritten anchor"))
                .expect("parse rewritten anchor");
        assert_eq!(parsed, second);
    }

    #[test]
    fn cli_parses_conformance_and_run_manifest_flags() {
        let cli = Cli::try_parse_from([
            "redagent",
            "conformance",
            "--binary",
            "/bin/true",
            "--timeout-secs",
            "3",
        ])
        .expect("parse conformance subcommand");
        match cli.command {
            Command::Conformance {
                binary,
                manifest,
                timeout_secs,
            } => {
                assert_eq!(binary, PathBuf::from("/bin/true"));
                assert!(manifest.is_none());
                assert_eq!(timeout_secs, 3);
            }
            other => panic!("unexpected subcommand: {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "redagent",
            "run",
            "a goal",
            "--redhands",
            "/bin/true",
            "--manifest",
            "adapter.json",
        ])
        .expect("parse run subcommand");
        match cli.command {
            Command::Run { manifest, .. } => {
                assert_eq!(manifest, Some(PathBuf::from("adapter.json")));
            }
            other => panic!("unexpected subcommand: {other:?}"),
        }
    }

    #[cfg(unix)]
    fn silent_script(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("silent-server.sh");
        fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write script");
        let mut permissions = fs::metadata(&path).expect("stat script").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("make script executable");
        path
    }

    #[cfg(unix)]
    #[test]
    fn conformance_reports_failed_verdict_for_silent_server() {
        let dir = temp_dir();
        let binary = silent_script(dir.path());
        let report = conformance(&binary, None, 2).expect("spawn silent server");
        assert!(!report.passed);
        assert_eq!(report.server, "redhands");
        assert!(report.checks.iter().any(|check| !check.passed));
    }

    #[cfg(unix)]
    #[test]
    fn conformance_loads_manifest_from_file() {
        let dir = temp_dir();
        let binary = silent_script(dir.path());
        let manifest_path = dir.path().join("manifest.json");
        let mut manifest = ToolServerManifest::redhands();
        manifest.name = "custom-server".to_string();
        let file = fs::File::create(&manifest_path).expect("create manifest");
        serde_json::to_writer(file, &manifest).expect("write manifest");

        let report = conformance(&binary, Some(&manifest_path), 2).expect("spawn silent server");
        assert_eq!(report.server, "custom-server");
        assert!(!report.passed);
    }
}
