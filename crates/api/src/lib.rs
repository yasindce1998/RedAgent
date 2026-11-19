//! Phase 2 HTTP control API for RedAgent.
//!
//! This crate exposes the ledger, engagement reports and live approval flow
//! over an axum router. It deliberately contains no engine logic: runs are
//! delegated to [`redagent_app::run_with`] on a blocking thread so the HTTP
//! runtime stays responsive while an operator is being asked to approve a
//! tool call.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{unfold, Stream};
use redagent_app::{ApprovalHandler, Config as AppConfig, LlmConfig};
use redagent_core::{EngagementView, Ledger, StoredEvent};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::MissedTickBehavior;

/// Everything needed to start the API server.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub bind: SocketAddr,
    pub ledger_dir: PathBuf,
    pub redhands_binary: PathBuf,
    pub approval_timeout: Duration,
}

/// One approval request that is waiting for an operator decision.
#[derive(Clone, Serialize)]
pub struct PendingApproval {
    pub request_id: String,
    pub intent_id: String,
    pub tool: String,
    pub message: String,
    pub proposal: Option<redagent_core::CallProposal>,
}

/// Body of `POST /api/engagements`.
#[derive(Debug, Deserialize)]
pub struct RunRequest {
    pub goal: String,
    pub ledger: Option<String>,
    #[serde(default)]
    pub llm: bool,
    #[serde(default)]
    pub auto_approve: bool,
    #[serde(default = "default_max")]
    pub max_tool_calls: usize,
    #[serde(default = "default_max_intents")]
    pub max_intents: usize,
    #[serde(default)]
    pub retest: bool,
    #[serde(default = "default_toolsets")]
    pub toolsets: String,
    #[serde(default)]
    pub allow_read_only: bool,
    #[serde(default)]
    pub scope: Option<ScopeConfig>,
    #[serde(default)]
    pub target_paths: Vec<String>,
    #[serde(default)]
    pub require_declared_scope: bool,
    #[serde(default = "default_true")]
    pub injection_guard: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub rules: Vec<redagent_scope::PolicyRule>,
}

fn default_true() -> bool {
    true
}

fn default_toolsets() -> String {
    "health".to_string()
}

pub fn default_max() -> usize {
    8
}

pub fn default_max_intents() -> usize {
    6
}

/// Shared, cheaply cloneable application state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: ApiConfig,
    pending: Mutex<HashMap<String, PendingEntry>>,
    next_id: AtomicU64,
}

/// A registered approval plus the channel used to wake the blocked engine.
struct PendingEntry {
    approval: PendingApproval,
    sender: Sender<bool>,
    /// Filled in by [`AppState::decide`] before the bool is sent, so the
    /// blocked handler can report who made the decision.
    decided_by: Arc<Mutex<Option<String>>>,
}

/// Lock a mutex, recovering the value even if a previous holder panicked.
///
/// Approval bookkeeping is best-effort state; a poisoned mutex must never
/// turn an HTTP decision into a server panic (which would also make every
/// later decision fail on the same poisoned lock).
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl AppState {
    pub fn new(config: ApiConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                pending: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(0),
            }),
        }
    }

    /// Snapshot of all approvals currently waiting for a decision.
    pub fn pending_approvals(&self) -> Vec<PendingApproval> {
        let pending = lock_or_recover(&self.inner.pending);
        let mut out: Vec<PendingApproval> = pending.values().map(|e| e.approval.clone()).collect();
        out.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        out
    }

    /// Resolve a pending approval.
    ///
    /// Removing the entry under the mutex makes this a single-winner
    /// operation: only one caller can ever deliver a decision for a given
    /// request id, so a double-decision (e.g. a retried HTTP request) can
    /// never send twice. A request that has already been decided, that timed
    /// out, or that never existed all produce the same clear error.
    pub fn decide(&self, request_id: &str, approved: bool, decided_by: &str) -> anyhow::Result<()> {
        let entry = {
            let mut pending = lock_or_recover(&self.inner.pending);
            pending.remove(request_id).ok_or_else(|| {
                anyhow!(
                    "approval request '{request_id}' is unknown, already decided, or has expired"
                )
            })?
        };

        // The receiver may already have been dropped by a handler that timed
        // out between the removal above and this send. That is not a panic and
        // not a successful decision: report it as an expired request. The
        // entry is already gone, so a retry still cannot double-decide.
        {
            let mut by = lock_or_recover(&entry.decided_by);
            *by = Some(decided_by.to_string());
        }
        entry.sender.send(approved).map_err(|_| {
            anyhow!("approval request '{request_id}' has expired or its waiter disconnected")
        })?;
        Ok(())
    }

    fn next_request_id(&self) -> String {
        let counter = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Mix the counter in so two requests in the same nanosecond differ.
        let mixed = now ^ counter.rotate_left(17).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        format!("{now:016x}{mixed:016x}")
    }
}

/// The approval handler handed to the engine. When `auto_approve` is set the
/// handler short-circuits; otherwise it registers a request and blocks until
/// `AppState::decide` sends a result (or the configured timeout elapses).
pub(crate) struct ApiApprovalHandler {
    state: AppState,
    auto_approve: bool,
}

impl ApprovalHandler for ApiApprovalHandler {
    fn decide(
        &self,
        intent_id: &str,
        tool: &str,
        message: &str,
        proposal: Option<&redagent_core::CallProposal>,
    ) -> anyhow::Result<(bool, String)> {
        if self.auto_approve {
            return Ok((true, "auto-approve".to_string()));
        }

        let request_id = self.state.next_request_id();
        let approval = PendingApproval {
            request_id: request_id.clone(),
            intent_id: intent_id.to_string(),
            tool: tool.to_string(),
            message: message.to_string(),
            proposal: proposal.cloned(),
        };

        let (sender, receiver): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        let decided_by = Arc::new(Mutex::new(None));
        {
            let mut pending = lock_or_recover(&self.state.inner.pending);
            pending.insert(
                request_id.clone(),
                PendingEntry {
                    approval,
                    sender,
                    decided_by: Arc::clone(&decided_by),
                },
            );
        }

        // Never hold the map mutex while blocked on the operator.
        let approved = match receiver.recv_timeout(self.state.inner.config.approval_timeout) {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => {
                // A decision may have been removed by `decide` but not yet
                // sent; in that case the map no longer contains the id and
                // this removal is simply a no-op. Either way the timed-out
                // request must not be left hanging in the pending list.
                lock_or_recover(&self.state.inner.pending).remove(&request_id);
                return Ok((false, "timeout".to_string()));
            }
            Err(RecvTimeoutError::Disconnected) => {
                lock_or_recover(&self.state.inner.pending).remove(&request_id);
                return Ok((false, "timeout".to_string()));
            }
        };

        let label = lock_or_recover(&decided_by)
            .clone()
            .unwrap_or_else(|| "api".to_string());
        Ok((approved, label))
    }
}

/// Error wrapper that maps onto the API's HTTP status codes.
enum ApiError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message).into_response(),
            Self::Internal(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        }
    }
}

/// Only simple, filesystem-safe ledger stems are accepted.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn checked_id(id: &str) -> Result<&str, ApiError> {
    if valid_id(id) {
        Ok(id)
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid ledger id '{id}': expected characters [A-Za-z0-9_-]"
        )))
    }
}

fn ledger_path(state: &AppState, id: &str) -> Result<PathBuf, ApiError> {
    let id = checked_id(id)?;
    Ok(state.inner.config.ledger_dir.join(format!("{id}.db")))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

async fn list_engagements(State(state): State<AppState>) -> Result<Json<Vec<String>>, ApiError> {
    let dir = &state.inner.config.ledger_dir;
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ApiError::Internal(format!("cannot read ledger directory: {e}")))?;
    let mut ids = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| ApiError::Internal(format!("cannot read ledger entry: {e}")))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("db") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                ids.push(stem.to_string());
            }
        }
    }
    ids.sort();
    Ok(Json(ids))
}

async fn get_engagement(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<EngagementView>, ApiError> {
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }
    let view = redagent_app::load_view(&path)
        .map_err(|e| ApiError::Internal(format!("cannot load engagement '{id}': {e}")))?;
    Ok(Json(view))
}

async fn get_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<StoredEvent>>, ApiError> {
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }
    let ledger =
        Ledger::open(&path).map_err(|e| ApiError::Internal(format!("cannot open ledger: {e}")))?;
    let events = ledger
        .events()
        .map_err(|e| ApiError::Internal(format!("cannot read events: {e}")))?;
    Ok(Json(events))
}

async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<String, ApiError> {
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }
    redagent_app::report_markdown(&path)
        .map_err(|e| ApiError::Internal(format!("cannot render report: {e}")))
}

async fn export_engagement(
    State(state): State<AppState>,
    Path((id, format)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate the format first so an unknown format is always a 400,
    // regardless of whether the requested engagement happens to exist.
    let format: redagent_export::ExportFormat = format
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("unsupported export format: {e}")))?;
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }
    let view = redagent_app::load_view(&path)
        .map_err(|e| ApiError::Internal(format!("cannot load engagement: {e}")))?;
    let content = redagent_export::export(&view, format)
        .map_err(|e| ApiError::Internal(format!("export failed: {e}")))?;
    let filename = redagent_export::filename(&view, format);
    Ok((
        [
            (
                header::CONTENT_TYPE,
                redagent_export::content_type(format).to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        content,
    ))
}

/// Build the snapshot stream for one ledger.
///
/// The first tick of a `tokio::time::interval` completes immediately, so a
/// completed engagement still emits exactly one snapshot before finishing.
/// Any failure to (re)load the view -- including the ledger being deleted
/// mid-stream -- ends the stream by returning `None`, and a finished
/// engagement ends it as well, so no future is left behind. Missing ticks
/// are skipped rather than bursted to avoid emitting duplicate snapshots
/// after a slow tick.
fn snapshot_stream(
    path: PathBuf,
    period: Duration,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    unfold(
        Some((interval, path)),
        |state: Option<(tokio::time::Interval, PathBuf)>| async move {
            let (mut interval, path) = state?;
            interval.tick().await;

            // `Ledger::open` creates a fresh empty SQLite file when the path
            // is missing, so `load_view` alone would silently resurrect a
            // deleted ledger and stream empty snapshots forever. Check the
            // file still exists on every tick and end the stream otherwise.
            if !path.is_file() {
                return None;
            }
            let view = match redagent_app::load_view(&path) {
                Ok(view) => view,
                Err(_) => return None,
            };
            // Close the remaining TOCTOU window: if the file vanished between
            // `is_file` and `load_view`, SQLite recreated an empty database.
            // A real ledger always starts with an EngagementStarted event,
            // so a goal-less, unfinished view means the ledger is gone.
            if view.goal.is_none() && !view.completed && view.abort_reason.is_none() {
                return None;
            }
            let finished = view.completed || view.abort_reason.is_some();
            let data = match serde_json::to_string(&view) {
                Ok(data) => data,
                Err(_) => return None,
            };
            let event = Event::default().event("snapshot").data(data);
            let next = if finished {
                None
            } else {
                Some((interval, path))
            };
            Some((Ok(event), next))
        },
    )
}

async fn stream_engagement(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }
    Ok(Sse::new(snapshot_stream(path, Duration::from_millis(750))))
}

#[derive(Deserialize)]
struct ApprovalDecision {
    approved: bool,
    decided_by: String,
}

async fn list_approvals(State(state): State<AppState>) -> Json<Vec<PendingApproval>> {
    Json(state.pending_approvals())
}

async fn decide_approval(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    Json(decision): Json<ApprovalDecision>,
) -> Result<StatusCode, ApiError> {
    // The id is only a HashMap key (never a filesystem path), but apply the
    // same allow-list as every other id-taking route so decoded path tricks
    // (`/`, `..`, NUL) are rejected uniformly with a 400.
    checked_id(&request_id)?;
    state
        .decide(&request_id, decision.approved, &decision.decided_by)
        .map_err(|e| ApiError::NotFound(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

fn generated_id(state: &AppState) -> String {
    format!("engagement-{}", state.next_request_id())
}

async fn create_engagement(
    State(state): State<AppState>,
    Json(request): Json<RunRequest>,
) -> Result<Json<EngagementView>, ApiError> {
    let id = match &request.ledger {
        Some(ledger) => checked_id(ledger)?.to_string(),
        None => generated_id(&state),
    };
    let ledger_path = state.inner.config.ledger_dir.join(format!("{id}.db"));
    let config = AppConfig::new(
        request.goal.clone(),
        state.inner.config.redhands_binary.clone(),
        ledger_path,
    )
    .with_limits(request.max_tool_calls, request.max_intents)
    .with_retest(request.retest)
    .with_toolsets(&request.toolsets)
    .with_required_scope(request.require_declared_scope)
    .with_injection_guard(request.injection_guard)
    .with_target_paths(request.target_paths.clone());
    let config = match request.scope {
        Some(scope) => config
            .with_scope(
                redagent_scope::Scope::new(scope.cidrs, scope.domains, scope.ports)
                    .map_err(|e| ApiError::BadRequest(e.to_string()))?,
            )
            .with_rules(scope.rules),
        None => config,
    };
    let mut config = if request.allow_read_only {
        config.with_allowed_tools(Vec::<String>::new())
    } else {
        config
    };

    if request.llm {
        let api_key = std::env::var("REDAGENT_LLM_API_KEY").ok();
        let base_url = std::env::var("REDAGENT_LLM_BASE_URL").ok();
        let model = std::env::var("REDAGENT_LLM_MODEL").ok();
        match (api_key, base_url, model) {
            (Some(api_key), Some(base_url), Some(model)) => {
                config = config.with_llm(LlmConfig {
                    base_url,
                    api_key,
                    model,
                });
            }
            _ => {
                return Err(ApiError::BadRequest(
                    "llm mode requires REDAGENT_LLM_API_KEY, REDAGENT_LLM_BASE_URL and \
                     REDAGENT_LLM_MODEL to be set"
                        .to_string(),
                ));
            }
        }
    }

    let auto_approve = request.auto_approve;
    if auto_approve {
        config = config.with_approval_mode(redagent_app::ApprovalMode::ApproveAll);
    }

    let task_state = state.clone();
    let view = tokio::task::spawn_blocking(move || {
        let handler = ApiApprovalHandler {
            state: task_state,
            auto_approve,
        };
        redagent_app::run_with(&config, &redagent_app::HeuristicVerifier, &handler)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("engine task failed: {e}")))?
    .map_err(|e| ApiError::Internal(format!("engagement failed: {e}")))?;

    Ok(Json(view))
}

/// Build the axum router for the API.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/engagements",
            get(list_engagements).post(create_engagement),
        )
        .route("/api/engagements/{id}", get(get_engagement))
        .route("/api/engagements/{id}/events", get(get_events))
        .route("/api/engagements/{id}/report", get(get_report))
        .route(
            "/api/engagements/{id}/export/{format}",
            get(export_engagement),
        )
        .route("/api/engagements/{id}/stream", get(stream_engagement))
        .route("/api/approvals", get(list_approvals))
        .route("/api/approvals/{request_id}", post(decide_approval))
        .with_state(state)
}

/// Bind the configured address and serve until the process is shut down.
pub async fn serve(config: ApiConfig) -> anyhow::Result<()> {
    let bind = config.bind;
    let app = router(AppState::new(config));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use futures_util::StreamExt;
    use redagent_core::{EngagementView, EventBody};
    use std::path::Path;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn test_state(dir: &Path) -> AppState {
        test_state_with_timeout(dir, Duration::from_secs(2))
    }

    fn test_state_with_timeout(dir: &Path, approval_timeout: Duration) -> AppState {
        AppState::new(ApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            ledger_dir: dir.to_path_buf(),
            redhands_binary: PathBuf::from("unused-redhands"),
            approval_timeout,
        })
    }

    fn write_ledger(dir: &Path, stem: &str, goal: &str, completed: bool) {
        let ledger = Ledger::open(&dir.join(format!("{stem}.db"))).unwrap();
        ledger
            .append(&EventBody::EngagementStarted {
                goal: goal.to_string(),
                redhands_version: "v0.6.3".to_string(),
            })
            .unwrap();
        if completed {
            ledger
                .append(&EventBody::EngagementCompleted { findings: 0 })
                .unwrap();
        }
    }

    async fn body_string(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let dir = tempdir().unwrap();
        let app = router(test_state(dir.path()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn list_projection_and_report() {
        let dir = tempdir().unwrap();
        let app = router(test_state(dir.path()));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/engagements")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ids: Vec<String> = serde_json::from_str(&body_string(response).await).unwrap();
        assert!(ids.is_empty());

        let ledger = Ledger::open(&dir.path().join("demo.db")).unwrap();
        ledger
            .append(&EventBody::EngagementStarted {
                goal: "probe the target".to_string(),
                redhands_version: "v0.6.3".to_string(),
            })
            .unwrap();
        drop(ledger);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/engagements")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let ids: Vec<String> = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(ids, vec!["demo".to_string()]);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/engagements/demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let view: EngagementView = serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(view.goal.as_deref(), Some("probe the target"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/engagements/demo/report")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report = body_string(response).await;
        assert!(report.contains("probe the target"));
    }

    #[tokio::test]
    async fn approval_registry_round_trip() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let handler = ApiApprovalHandler {
            state: state.clone(),
            auto_approve: false,
        };
        let (tx, rx) = mpsc::channel();

        let worker = std::thread::spawn(move || {
            let decision = handler
                .decide("intent-7", "redhands_scan", "approve this call?", None)
                .unwrap();
            tx.send(decision).unwrap();
        });

        let pending = loop {
            let pending = state.pending_approvals();
            if !pending.is_empty() {
                break pending;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool, "redhands_scan");
        assert_eq!(pending[0].message, "approve this call?");
        assert!(!pending[0].request_id.is_empty());

        state
            .decide(&pending[0].request_id, true, "operator-alice")
            .unwrap();
        let (approved, decided_by) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(approved);
        assert_eq!(decided_by, "operator-alice");
        assert!(state.pending_approvals().is_empty());
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn unsafe_ledger_id_is_rejected() {
        let dir = tempdir().unwrap();
        let app = router(test_state(dir.path()));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/engagements")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"goal":"x","ledger":"../evil"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn approval_http_decision_endpoints() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state.clone());
        let handler = ApiApprovalHandler {
            state: state.clone(),
            auto_approve: false,
        };
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let decision = handler
                .decide("intent-9", "redhands_exec", "dangerous call", None)
                .unwrap();
            tx.send(decision).unwrap();
        });

        let pending = loop {
            let pending = state.pending_approvals();
            if !pending.is_empty() {
                break pending;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let request_id = pending[0].request_id.clone();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/approvals")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed: Vec<serde_json::Value> =
            serde_json::from_str(&body_string(response).await).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["request_id"], request_id);

        let uri = format!("/api/approvals/{request_id}");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"approved":false,"decided_by":"bob"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let (approved, decided_by) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!approved);
        assert_eq!(decided_by, "bob");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"approved":true,"decided_by":"bob"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn completed_engagement_stream_emits_one_snapshot() {
        let dir = tempdir().unwrap();
        let ledger = Ledger::open(&dir.path().join("done.db")).unwrap();
        ledger
            .append(&EventBody::EngagementStarted {
                goal: "streamed goal".to_string(),
                redhands_version: "v0.6.3".to_string(),
            })
            .unwrap();
        ledger
            .append(&EventBody::EngagementCompleted { findings: 0 })
            .unwrap();
        drop(ledger);

        let app = router(test_state(dir.path()));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/engagements/done/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let body = body_string(response).await;
        assert!(body.starts_with("event: snapshot\ndata: "));
        assert!(body.contains("streamed goal"));
        assert!(body.ends_with("\n\n"));
    }

    // --- Hardening regression tests -------------------------------------

    #[test]
    fn decide_after_timeout_is_reported_clearly() {
        let dir = tempdir().unwrap();
        // A short timeout makes the handler time out while we hold the id.
        let state = test_state_with_timeout(dir.path(), Duration::from_millis(30));
        let handler = ApiApprovalHandler {
            state: state.clone(),
            auto_approve: false,
        };
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let decision = handler
                .decide("intent-timeout", "tool", "message", None)
                .unwrap();
            tx.send(decision).unwrap();
        });

        let pending = loop {
            let pending = state.pending_approvals();
            if !pending.is_empty() {
                break pending;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let request_id = pending[0].request_id.clone();

        // The handler times out and removes its own entry.
        let (approved, decided_by) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!approved);
        assert_eq!(decided_by, "timeout");
        worker.join().unwrap();
        assert!(state.pending_approvals().is_empty());

        // A late HTTP decision for the expired id must fail cleanly (no panic,
        // no double-decision, and a message that explains what happened).
        let err = state
            .decide(&request_id, true, "late-operator")
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("unknown")
                || message.contains("already decided")
                || message.contains("expired"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn double_decide_is_rejected() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let (sender, receiver) = mpsc::channel();
        let approval = PendingApproval {
            request_id: "once".to_string(),
            intent_id: "i".to_string(),
            tool: "t".to_string(),
            message: "m".to_string(),
            proposal: None,
        };
        state.inner.pending.lock().unwrap().insert(
            "once".to_string(),
            PendingEntry {
                approval,
                sender,
                decided_by: Arc::new(Mutex::new(None)),
            },
        );

        state.decide("once", true, "alice").unwrap();
        let err = state.decide("once", false, "bob").unwrap_err();
        assert!(err.to_string().contains("already decided"));
        // Only the first decision was delivered to the (still alive) receiver.
        assert!(receiver.recv_timeout(Duration::from_millis(50)).unwrap());
        assert!(state.pending_approvals().is_empty());
    }

    #[test]
    fn decide_to_dropped_receiver_returns_clear_error() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let (sender, receiver) = mpsc::channel();
        drop(receiver); // simulate a handler that timed out and was dropped
        let approval = PendingApproval {
            request_id: "dropped".to_string(),
            intent_id: "i".to_string(),
            tool: "t".to_string(),
            message: "m".to_string(),
            proposal: None,
        };
        state.inner.pending.lock().unwrap().insert(
            "dropped".to_string(),
            PendingEntry {
                approval,
                sender,
                decided_by: Arc::new(Mutex::new(None)),
            },
        );

        let err = state.decide("dropped", true, "alice").unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("expired") || message.contains("disconnected"),
            "unexpected error: {message}"
        );
        assert!(state.pending_approvals().is_empty());
    }

    #[test]
    fn decide_recovers_from_poisoned_decided_by_mutex() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let decided_by = Arc::new(Mutex::new(None));
        let poisoned = Arc::clone(&decided_by);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison the decided_by mutex");
        })
        .join();
        assert!(decided_by.is_poisoned());

        let (sender, _receiver) = mpsc::channel();
        let approval = PendingApproval {
            request_id: "poison".to_string(),
            intent_id: "i".to_string(),
            tool: "t".to_string(),
            message: "m".to_string(),
            proposal: None,
        };
        state.inner.pending.lock().unwrap().insert(
            "poison".to_string(),
            PendingEntry {
                approval,
                sender,
                decided_by,
            },
        );

        // Must not panic even though the mutex is poisoned.
        state.decide("poison", true, "alice").unwrap();
    }

    #[tokio::test]
    async fn all_id_routes_reject_encoded_path_tricks() {
        let dir = tempdir().unwrap();
        let app = router(test_state(dir.path()));

        // Each segment is a single decoded path component that a client can
        // smuggle past the router via percent-encoding. All must be rejected
        // by checked_id before any filesystem access.
        let bad_ids = ["..", "%2e%2e", "a%2Fb", "a%20b", "%00", "a%00b", "bad%21id"];
        for bad in bad_ids {
            let paths = [
                format!("/api/engagements/{bad}"),
                format!("/api/engagements/{bad}/events"),
                format!("/api/engagements/{bad}/report"),
                format!("/api/engagements/{bad}/export/sarif"),
                format!("/api/engagements/{bad}/stream"),
            ];
            for path in paths {
                let response = app
                    .clone()
                    .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "expected 400 for {path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn decide_route_rejects_malformed_request_id() {
        let dir = tempdir().unwrap();
        let app = router(test_state(dir.path()));
        let bad_ids = ["..", "%2e%2e", "a%2Fb", "%00", "bad%21id"];
        for bad in bad_ids {
            let uri = format!("/api/approvals/{bad}");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"approved":true,"decided_by":"bob"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for {uri}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_export_format_is_bad_request() {
        let dir = tempdir().unwrap();
        write_ledger(dir.path(), "demo", "export goal", true);
        let app = router(test_state(dir.path()));

        // Existing ledger: unknown format must be a 400, not a 500.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/engagements/demo/export/pdf")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Even with a missing ledger the format is validated first, so the
        // answer is still 400 rather than a misleading 404.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/engagements/missing/export/pdf")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn export_headers_cannot_be_injected_by_goal() {
        let dir = tempdir().unwrap();
        // Quotes, CRLF and a would-be header name in the goal. The export
        // crate reduces the goal to a `[a-z0-9-]` slug for the filename.
        let goal = "evil\"goal\r\nX-Evil: 1";
        write_ledger(dir.path(), "inject", goal, true);
        let app = router(test_state(dir.path()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/engagements/inject/export/sarif")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/sarif+json"
        );

        let disposition = response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap();
        // Exactly one Content-Disposition value, properly quoted.
        assert_eq!(
            response
                .headers()
                .get_all(header::CONTENT_DISPOSITION)
                .iter()
                .count(),
            1
        );
        let inner = disposition
            .strip_prefix("attachment; filename=\"")
            .and_then(|s| s.strip_suffix('"'))
            .expect("well-formed quoted filename");
        assert!(
            inner
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
            "unsafe filename: {inner}"
        );
        // No injected header and no CRLF in any header value.
        assert!(response.headers().get("x-evil").is_none());
        for (name, value) in response.headers() {
            let text = value.to_str().unwrap();
            assert!(
                !text.contains('\r') && !text.contains('\n'),
                "CRLF in header {name}: {text:?}"
            );
        }
    }

    #[tokio::test]
    async fn completed_stream_terminates_promptly() {
        let dir = tempdir().unwrap();
        write_ledger(dir.path(), "done", "streamed goal", true);
        let path = dir.path().join("done.db");

        let stream = snapshot_stream(path, Duration::from_millis(10));
        // A completed engagement emits one snapshot and then ends the stream;
        // it must not keep a future/interval alive.
        let events = tokio::time::timeout(Duration::from_secs(2), stream.collect::<Vec<_>>())
            .await
            .expect("stream did not terminate on completion");
        assert_eq!(events.len(), 1);
        assert!(events[0].is_ok());
        assert!(format!("{:?}", events[0]).contains("streamed goal"));
    }

    #[tokio::test]
    async fn stream_stops_when_ledger_is_deleted() {
        let dir = tempdir().unwrap();
        write_ledger(dir.path(), "live", "live goal", false);
        let path = dir.path().join("live.db");

        let mut stream = Box::pin(snapshot_stream(path.clone(), Duration::from_millis(20)));
        // First tick is immediate and the engagement is still in progress.
        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("no first snapshot")
            .expect("stream ended early");
        assert!(first.is_ok());

        // Delete the ledger mid-stream: the next reload fails and the stream
        // must terminate instead of spinning forever.
        std::fs::remove_file(&path).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("stream did not stop after ledger deletion");
        assert!(
            next.is_none(),
            "stream should end when the ledger disappears"
        );
    }
}
