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
use std::sync::{Arc, Mutex};
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
        let pending = self.inner.pending.lock().expect("approval mutex poisoned");
        let mut out: Vec<PendingApproval> = pending.values().map(|e| e.approval.clone()).collect();
        out.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        out
    }

    /// Resolve a pending approval. Returns an error for unknown or already
    /// decided request ids.
    pub fn decide(&self, request_id: &str, approved: bool, decided_by: &str) -> anyhow::Result<()> {
        let entry = {
            let mut pending = self.inner.pending.lock().expect("approval mutex poisoned");
            pending.remove(request_id).ok_or_else(|| {
                anyhow!("unknown or already decided approval request '{request_id}'")
            })?
        };
        *entry.decided_by.lock().expect("decided_by mutex poisoned") = Some(decided_by.to_string());
        entry
            .sender
            .send(approved)
            .map_err(|_| anyhow!("approval wait channel closed for '{request_id}'"))?;
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
    fn decide(&self, intent_id: &str, tool: &str, message: &str) -> anyhow::Result<(bool, String)> {
        if self.auto_approve {
            return Ok((true, "auto-approve".to_string()));
        }

        let request_id = self.state.next_request_id();
        let approval = PendingApproval {
            request_id: request_id.clone(),
            intent_id: intent_id.to_string(),
            tool: tool.to_string(),
            message: message.to_string(),
        };

        let (sender, receiver): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        let decided_by = Arc::new(Mutex::new(None));
        {
            let mut pending = self
                .state
                .inner
                .pending
                .lock()
                .expect("approval mutex poisoned");
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
                let mut pending = self
                    .state
                    .inner
                    .pending
                    .lock()
                    .expect("approval mutex poisoned");
                pending.remove(&request_id);
                return Ok((false, "timeout".to_string()));
            }
            Err(RecvTimeoutError::Disconnected) => {
                let mut pending = self
                    .state
                    .inner
                    .pending
                    .lock()
                    .expect("approval mutex poisoned");
                pending.remove(&request_id);
                return Ok((false, "timeout".to_string()));
            }
        };

        let label = decided_by
            .lock()
            .expect("decided_by mutex poisoned")
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
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }
    let view = redagent_app::load_view(&path)
        .map_err(|e| ApiError::Internal(format!("cannot load engagement: {e}")))?;
    let format: redagent_export::ExportFormat = format
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("unsupported export format: {e}")))?;
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

async fn stream_engagement(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let path = ledger_path(&state, &id)?;
    if !path.is_file() {
        return Err(ApiError::NotFound(format!("engagement '{id}' not found")));
    }

    let interval = tokio::time::interval(Duration::from_millis(750));
    let stream = unfold(
        Some((interval, path)),
        |state: Option<(tokio::time::Interval, PathBuf)>| async move {
            let (mut interval, path) = state?;
            interval.tick().await;
            let view = match redagent_app::load_view(&path) {
                Ok(view) => view,
                Err(_) => return None,
            };
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
    );
    Ok(Sse::new(stream))
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
    let mut config = AppConfig::new(
        request.goal.clone(),
        state.inner.config.redhands_binary.clone(),
        ledger_path,
    )
    .with_limits(request.max_tool_calls, request.max_intents)
    .with_retest(request.retest);

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
    use redagent_core::{EngagementView, EventBody};
    use std::path::Path;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn test_state(dir: &Path) -> AppState {
        AppState::new(ApiConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            ledger_dir: dir.to_path_buf(),
            redhands_binary: PathBuf::from("unused-redhands"),
            approval_timeout: Duration::from_secs(2),
        })
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
                .decide("intent-7", "redhands_scan", "approve this call?")
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
                .decide("intent-9", "redhands_exec", "dangerous call")
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
}
