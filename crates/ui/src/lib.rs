//! RedAgent control UI, shared between the native desktop and WASM web shells.
//!
//! The UI is a thin projection viewer: all state is fetched from the API and
//! every mutation is an explicit POST. It holds no ledger of its own. The two
//! thin binaries (`native` and `web`) only pick a renderer and launch [`app`].

use dioxus::prelude::*;
use redagent_core::EngagementView;
use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8787";
const POLL_INTERVAL_MS: u64 = 1500;

const ROOT_STYLE: &str = "background:#0b1020;color:#e8ecf5;font-family:system-ui,-apple-system,sans-serif;min-height:100vh;";
const HEADER_STYLE: &str = "display:flex;align-items:center;gap:14px;padding:14px 22px;background:#0b1020;border-bottom:1px solid #26324c;";
const TITLE_STYLE: &str = "font-size:20px;font-weight:700;color:#ff4d5e;letter-spacing:0.4px;white-space:nowrap;margin:0;";
const BODY_STYLE: &str = "display:flex;gap:18px;align-items:flex-start;padding:18px 22px;";
const SIDEBAR_STYLE: &str =
    "width:310px;flex-shrink:0;display:flex;flex-direction:column;gap:14px;";
const MAIN_STYLE: &str = "flex:1;min-width:0;display:flex;flex-direction:column;gap:16px;";
const CARD_STYLE: &str =
    "background:#151d30;border:1px solid #26324c;border-radius:12px;padding:16px;";
const SECTION_TITLE_STYLE: &str =
    "font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:#8b96ad;margin:0 0 12px;";
const FIELD_LABEL_STYLE: &str = "display:block;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b96ad;margin:10px 0 5px;";
const INPUT_STYLE: &str = "width:100%;box-sizing:border-box;background:#0f1628;color:#e8ecf5;border:1px solid #26324c;border-radius:8px;padding:8px 10px;";
const MUTED_STYLE: &str = "color:#8b96ad;font-size:12px;margin:6px 0;";
const PRIMARY_BUTTON_STYLE: &str = "background:#ff4d5e;color:#0b1020;border:none;border-radius:8px;padding:9px 14px;font-weight:700;cursor:pointer;";
const DENY_BUTTON_STYLE: &str = "background:#232d44;color:#ff9aa6;border:1px solid #ff4d5e;border-radius:8px;padding:9px 14px;font-weight:700;cursor:pointer;";
const LINK_STYLE: &str = "display:inline-block;background:#232d44;color:#8ad6ff;border:1px solid #3b4a6b;border-radius:8px;padding:8px 12px;font-size:13px;font-weight:700;text-decoration:none;";
const ERROR_STYLE: &str = "background:#3a1220;color:#ffd7dc;border:1px solid #ff4d5e;border-radius:8px;padding:10px 16px;margin:12px 22px 0;";
const TH_STYLE: &str = "text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b96ad;padding:6px 8px;border-bottom:1px solid #26324c;";
const TD_STYLE: &str =
    "font-size:13px;padding:7px 8px;border-bottom:1px solid #202a42;vertical-align:top;";
const PRE_STYLE: &str = "background:#0b1020;color:#d7e0f0;border:1px solid #202a42;border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px;margin:6px 0 0;";

/// Platform-neutral async sleep used by the polling loop.
#[cfg(not(target_arch = "wasm32"))]
async fn sleep_ms(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}

/// Browser timer used by the polling loop on WASM.
#[cfg(target_arch = "wasm32")]
async fn sleep_ms(ms: u64) {
    gloo_timers::future::TimeoutFuture::new(ms as u32).await;
}

#[derive(Clone, Deserialize)]
struct Health {
    status: String,
    version: String,
}

#[derive(Clone, Deserialize)]
pub struct PendingApproval {
    pub request_id: String,
    pub intent_id: String,
    pub tool: String,
    pub message: String,
}

/// Body of `POST /api/engagements`. The RedHands path is intentionally absent:
/// the API resolves it from server-side configuration.
#[derive(Clone, Serialize)]
pub struct RunForm {
    pub goal: String,
    pub ledger: Option<()>,
    pub llm: bool,
    pub auto_approve: bool,
    pub max_tool_calls: u32,
    pub max_intents: u32,
}

/// All shared UI state, grouped so async handlers can be spawned cheaply.
#[derive(Clone, Copy)]
pub struct ApiState {
    pub base_url: Signal<String>,
    pub engagements: Signal<Vec<String>>,
    pub selected: Signal<Option<String>>,
    pub detail: Signal<Option<EngagementView>>,
    pub approvals: Signal<Vec<PendingApproval>>,
    pub error: Signal<Option<String>>,
    pub connected: Signal<Option<String>>,
    /// Incremented at the start of every refresh/mutation. Async responses
    /// from an older generation are discarded so a slow request can never
    /// overwrite the result of a newer selection or clear a newer error.
    epoch: Signal<u64>,
    /// Approval request ids whose decision POST is currently in flight. Used
    /// to debounce the approve/deny buttons.
    decisions: Signal<Vec<String>>,
}

/// Ids interpolated into API paths must match the server's `checked_id`
/// allow-list. This rejects `/`, `..`, NUL bytes, quotes and whitespace
/// before a URL is ever built.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// RFC 3986 unreserved percent-encoding for a single path segment.
fn percent_encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Validate and encode an id for use as one URL path segment.
fn checked_segment(label: &str, id: &str) -> Result<String, String> {
    if !valid_id(id) {
        return Err(format!(
            "invalid {label} '{id}': expected characters [A-Za-z0-9_-]"
        ));
    }
    Ok(percent_encode_segment(id))
}

fn engagement_api_url(base: &str, id: &str) -> Result<String, String> {
    Ok(format!(
        "{}/api/engagements/{}",
        base.trim_end_matches('/'),
        checked_segment("engagement id", id)?
    ))
}

fn approval_api_url(base: &str, request_id: &str) -> Result<String, String> {
    Ok(format!(
        "{}/api/approvals/{}",
        base.trim_end_matches('/'),
        checked_segment("approval request id", request_id)?
    ))
}

fn export_base_url(base: &str, id: &str) -> Result<String, String> {
    Ok(format!(
        "{}/api/engagements/{}/export",
        base.trim_end_matches('/'),
        checked_segment("engagement id", id)?
    ))
}

/// Register an in-flight decision; `false` means one is already pending for
/// `id`, so the caller should ignore a repeated click.
fn begin_decision(in_flight: &mut Vec<String>, id: &str) -> bool {
    if in_flight.iter().any(|pending| pending == id) {
        return false;
    }
    in_flight.push(id.to_string());
    true
}

fn finish_decision(in_flight: &mut Vec<String>, id: &str) {
    in_flight.retain(|pending| pending != id);
}

/// Start a new async generation and return its id. Older generations must
/// check [`is_current`] before writing any shared state.
fn begin_refresh(state: &mut ApiState) -> u64 {
    let mut epoch = state.epoch.write();
    *epoch = epoch.wrapping_add(1);
    *epoch
}

fn is_current(current: u64, epoch: u64) -> bool {
    current == epoch
}

/// Root component shared by the native and web shells.
pub fn app() -> Element {
    let mut base_url = use_signal(|| DEFAULT_BASE_URL.to_string());
    let engagements = use_signal(Vec::<String>::new);
    let selected = use_signal(|| None::<String>);
    let detail = use_signal(|| None::<EngagementView>);
    let approvals = use_signal(Vec::<PendingApproval>::new);
    let error = use_signal(|| None::<String>);
    let connected = use_signal(|| None::<String>);
    let epoch = use_signal(|| 0_u64);
    let decisions = use_signal(Vec::<String>::new);
    let goal = use_signal(String::new);
    let redhands_path = use_signal(String::new);
    let llm = use_signal(|| false);
    let auto_approve = use_signal(|| false);

    let api = ApiState {
        base_url,
        engagements,
        selected,
        detail,
        approvals,
        error,
        connected,
        epoch,
        decisions,
    };

    // Background polling: refetch everything roughly every 1.5 seconds.
    use_future(move || async move {
        loop {
            refresh_all(api).await;
            sleep_ms(POLL_INTERVAL_MS).await;
        }
    });

    let version = connected();
    let (badge_text, badge_style) = match version {
        Some(version) => (
            format!("● connected · {version}"),
            "background:#10261c;color:#5ee6a8;border:1px solid #2c6b4f;border-radius:999px;padding:5px 11px;font-size:12px;white-space:nowrap;",
        ),
        None => (
            "● offline".to_string(),
            "background:#2a1320;color:#ff9aa6;border:1px solid #ff4d5e;border-radius:999px;padding:5px 11px;font-size:12px;white-space:nowrap;",
        ),
    };

    rsx! {
        div { style: ROOT_STYLE,
            header { style: HEADER_STYLE,
                h1 { style: TITLE_STYLE, "RedAgent · Control" }
                input {
                    style: "background:#0f1628;color:#e8ecf5;border:1px solid #26324c;border-radius:8px;padding:7px 10px;width:260px;",
                    r#type: "text",
                    spellcheck: false,
                    value: base_url(),
                    oninput: move |event| base_url.set(event.value()),
                }
                span { style: badge_style, "{badge_text}" }
                button {
                    style: "background:#232d44;color:#e8ecf5;border:1px solid #3b4a6b;border-radius:8px;padding:8px 14px;font-weight:700;cursor:pointer;",
                    onclick: move |_| {
                        let api = api;
                        spawn(async move { refresh_all(api).await; });
                    },
                    "Refresh"
                }
            }

            if let Some(message) = error() {
                div { style: ERROR_STYLE, "⚠ {message}" }
            }

            div { style: BODY_STYLE,
                {sidebar(engagements, selected, goal, redhands_path, llm, auto_approve, api)}
                main { style: MAIN_STYLE,
                    {engagement_detail(detail, approvals, api)}
                }
            }
        }
    }
}

pub fn sidebar(
    engagements: Signal<Vec<String>>,
    mut selected: Signal<Option<String>>,
    goal: Signal<String>,
    redhands_path: Signal<String>,
    llm: Signal<bool>,
    auto_approve: Signal<bool>,
    api: ApiState,
) -> Element {
    let ids = engagements();
    let current = selected();

    rsx! {
        aside { style: SIDEBAR_STYLE,
            div { style: CARD_STYLE,
                h2 { style: SECTION_TITLE_STYLE, "Engagements" }
                if ids.is_empty() {
                    p { style: MUTED_STYLE, "No engagements yet." }
                } else {
                    div { style: "display:flex;flex-direction:column;gap:6px;",
                        for id in ids.iter() {
                            {
                                let id = id.clone();
                                let is_selected = current.as_deref() == Some(id.as_str());
                                let item_style = if is_selected {
                                    "background:#3a1622;color:#fff;border:1px solid #ff4d5e;border-radius:8px;padding:8px 10px;text-align:left;cursor:pointer;font-size:13px;"
                                } else {
                                    "background:#0f1628;color:#c8d1e4;border:1px solid #26324c;border-radius:8px;padding:8px 10px;text-align:left;cursor:pointer;font-size:13px;"
                                };
                                rsx! {
                                    button {
                                        key: "{id}",
                                        style: item_style,
                                        onclick: move |_| selected.set(Some(id.clone())),
                                        "{id}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            {run_form(goal, redhands_path, llm, auto_approve, api)}
        }
    }
}

pub fn run_form(
    mut goal: Signal<String>,
    mut redhands_path: Signal<String>,
    mut llm: Signal<bool>,
    mut auto_approve: Signal<bool>,
    api: ApiState,
) -> Element {
    rsx! {
        div { style: CARD_STYLE,
            h2 { style: SECTION_TITLE_STYLE, "New engagement" }

            label { style: FIELD_LABEL_STYLE, "Goal" }
            input {
                style: INPUT_STYLE,
                r#type: "text",
                placeholder: "e.g. audit the target host",
                value: goal(),
                oninput: move |event| goal.set(event.value()),
            }

            label { style: FIELD_LABEL_STYLE, "RedHands path" }
            input {
                style: INPUT_STYLE,
                r#type: "text",
                placeholder: "/usr/local/bin/redhands",
                value: redhands_path(),
                oninput: move |event| redhands_path.set(event.value()),
            }
            p { style: MUTED_STYLE, "RedHands binary configured server-side" }

            label { style: "display:flex;align-items:center;gap:8px;font-size:13px;margin-top:12px;cursor:pointer;",
                input {
                    r#type: "checkbox",
                    checked: llm(),
                    onchange: move |event| llm.set(event.checked()),
                }
                "Enable LLM planner"
            }
            label { style: "display:flex;align-items:center;gap:8px;font-size:13px;margin-top:8px;cursor:pointer;",
                input {
                    r#type: "checkbox",
                    checked: auto_approve(),
                    onchange: move |event| auto_approve.set(event.checked()),
                }
                "⚠️ Auto approve"
            }

            button {
                style: "width:100%;margin-top:14px;background:#ff4d5e;color:#0b1020;border:none;border-radius:8px;padding:10px 14px;font-weight:700;cursor:pointer;",
                onclick: move |_| {
                    let form = RunForm {
                        goal: goal(),
                        ledger: None,
                        llm: llm(),
                        auto_approve: auto_approve(),
                        max_tool_calls: 8,
                        max_intents: 6,
                    };
                    spawn(async move { start_engagement(api, form).await; });
                },
                "Run"
            }
        }
    }
}

pub fn engagement_detail(
    detail: Signal<Option<EngagementView>>,
    approvals: Signal<Vec<PendingApproval>>,
    api: ApiState,
) -> Element {
    let guard = detail.read();
    let Some(view) = guard.as_ref() else {
        return rsx! {
            section { style: CARD_STYLE,
                h2 { style: SECTION_TITLE_STYLE, "Engagement detail" }
                p { style: MUTED_STYLE, "Select an engagement from the sidebar to inspect it." }
            }
        };
    };

    let goal_text = view.goal.clone().unwrap_or_else(|| "(none)".to_string());
    let status_text = if view.completed {
        "completed"
    } else if view.abort_reason.is_some() {
        "aborted"
    } else {
        "in progress"
    };
    let findings_count = view.findings.len().to_string();
    let abort_text = view.abort_reason.clone().unwrap_or_default();
    let budget_text = view.budget_exhausted.clone().unwrap_or_default();

    // Export links are plain anchors: the API serves the formats directly.
    // Only build them for a validated selection so a malformed id can never
    // produce a broken (or injected) href.
    let export_base = api
        .selected
        .read()
        .as_deref()
        .and_then(|id| export_base_url(&base_url(&api), id).ok());

    rsx! {
        section { style: MAIN_STYLE,
            div { style: "display:flex;gap:14px;flex-wrap:wrap;",
                {status_card("Goal", &goal_text, true)}
                {status_card("Status", status_text, false)}
                {status_card("Findings", &findings_count, false)}
            }

            if !abort_text.is_empty() {
                div { style: "background:#3a1220;color:#ffd7dc;border:1px solid #ff4d5e;border-radius:12px;padding:12px 16px;",
                    "Aborted: {abort_text}"
                }
            }
            if !budget_text.is_empty() {
                div { style: "background:#2d2410;color:#ffe6a8;border:1px solid #c99b32;border-radius:12px;padding:12px 16px;",
                    "Budget exhausted: {budget_text}"
                }
            }

            section { style: CARD_STYLE,
                h2 { style: SECTION_TITLE_STYLE, "Findings" }
                if view.findings.is_empty() {
                    p { style: MUTED_STYLE, "No findings recorded." }
                } else {
                    table { style: "width:100%;border-collapse:collapse;",
                        thead {
                            tr {
                                th { style: TH_STYLE, "ID" }
                                th { style: TH_STYLE, "Title" }
                                th { style: TH_STYLE, "Severity" }
                                th { style: TH_STYLE, "Evidence" }
                            }
                        }
                        tbody {
                            for finding in view.findings.iter() {
                                {
                                    let id = finding.id.clone();
                                    let title = finding.title.clone();
                                    let severity = finding.severity.clone();
                                    let seq = finding.evidence_seq;
                                    rsx! {
                                        tr { key: "{id}",
                                            td { style: TD_STYLE, "{id}" }
                                            td { style: TD_STYLE, "{title}" }
                                            td { style: TD_STYLE, "{severity}" }
                                            td { style: TD_STYLE, "#{seq}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            section { style: CARD_STYLE,
                h2 { style: SECTION_TITLE_STYLE, "Verification" }
                if view.verifications.is_empty() {
                    p { style: MUTED_STYLE, "No verification results." }
                } else {
                    ul { style: "list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px;",
                        for verification in view.verifications.iter() {
                            {
                                let finding_id = verification.finding_id.clone();
                                let verdict = verification.verdict.clone();
                                let seq = verification.evidence_seq;
                                rsx! {
                                    li {
                                        key: "{finding_id}",
                                        style: "background:#0f1628;border:1px solid #26324c;border-radius:8px;padding:8px 10px;font-size:13px;",
                                        "{finding_id} → {verdict} → evidence #{seq}"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            {approval_queue(approvals, api)}

            section { style: CARD_STYLE,
                h2 { style: SECTION_TITLE_STYLE, "Tool evidence" }
                if view.tool_calls.is_empty() {
                    p { style: MUTED_STYLE, "No tool calls recorded." }
                } else {
                    for call in view.tool_calls.iter() {
                        {
                            let tool = call.tool.clone();
                            let intent_id = call.intent_id.clone();
                            let is_error = call.is_error;
                            let content = call.content.clone();
                            let header_style = if is_error {
                                "font-size:13px;color:#ff8f9b;font-weight:700;"
                            } else {
                                "font-size:13px;color:#8ad6ff;font-weight:700;"
                            };
                            let error_label = if is_error { " · error" } else { "" };
                            rsx! {
                                div { key: "{intent_id}-{tool}", style: "margin-bottom:14px;",
                                    div { style: header_style, "{tool} · intent {intent_id}{error_label}" }
                                    pre { style: PRE_STYLE, "{content}" }
                                }
                            }
                        }
                    }
                }
            }

            section { style: CARD_STYLE,
                h2 { style: SECTION_TITLE_STYLE, "Export" }
                if let Some(export_base) = export_base {
                    div { style: "display:flex;gap:10px;flex-wrap:wrap;",
                        a { style: LINK_STYLE, href: "{export_base}/sarif", "SARIF" }
                        a { style: LINK_STYLE, href: "{export_base}/cyclonedx", "CycloneDX" }
                        a { style: LINK_STYLE, href: "{export_base}/mitre", "MITRE" }
                    }
                } else {
                    p { style: MUTED_STYLE, "Invalid engagement id; export unavailable." }
                }
            }
        }
    }
}

pub fn approval_queue(approvals: Signal<Vec<PendingApproval>>, api: ApiState) -> Element {
    let pending = approvals();
    // Subscribing here makes the buttons update as decisions start/finish.
    let in_flight = (api.decisions)();

    rsx! {
        section { style: CARD_STYLE,
            h2 { style: SECTION_TITLE_STYLE, "Approvals" }
            if pending.is_empty() {
                p { style: MUTED_STYLE, "No pending approvals." }
            } else {
                div { style: "display:flex;flex-direction:column;gap:10px;",
                    for item in pending.iter() {
                        {
                            let request_id = item.request_id.clone();
                            let approve_id = request_id.clone();
                            let deny_id = request_id.clone();
                            let intent_id = item.intent_id.clone();
                            let tool = item.tool.clone();
                            let message = item.message.clone();
                            // Once a decision is in flight, disable both
                            // buttons so a double-click cannot POST twice.
                            let busy = in_flight.iter().any(|pending| pending == &request_id);
                            let approve_style = if busy {
                                "background:#3a2a30;color:#8b7680;border:none;border-radius:8px;padding:9px 14px;font-weight:700;cursor:not-allowed;"
                            } else {
                                PRIMARY_BUTTON_STYLE
                            };
                            let deny_style = if busy {
                                "background:#232d44;color:#6b5560;border:1px solid #55404a;border-radius:8px;padding:9px 14px;font-weight:700;cursor:not-allowed;"
                            } else {
                                DENY_BUTTON_STYLE
                            };
                            rsx! {
                                div { key: "{request_id}", style: "background:#0f1628;border:1px solid #ff4d5e;border-radius:10px;padding:12px;",
                                    div { style: "font-size:13px;color:#ff9aa6;font-weight:700;", "{tool} · {intent_id}" }
                                    div { style: MUTED_STYLE, "{message}" }
                                    div { style: "display:flex;gap:8px;margin-top:10px;",
                                        button {
                                            style: approve_style,
                                            disabled: busy,
                                            onclick: move |_| {
                                                let id = approve_id.clone();
                                                spawn(async move { decide_approval(api, id, true).await; });
                                            },
                                            "Approve"
                                        }
                                        button {
                                            style: deny_style,
                                            disabled: busy,
                                            onclick: move |_| {
                                                let id = deny_id.clone();
                                                spawn(async move { decide_approval(api, id, false).await; });
                                            },
                                            "Deny"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn status_card(label: &str, value: &str, accent: bool) -> Element {
    let value_style = if accent {
        "font-size:18px;font-weight:700;color:#ff4d5e;margin-top:6px;word-break:break-word;"
    } else {
        "font-size:18px;font-weight:700;color:#e8ecf5;margin-top:6px;word-break:break-word;"
    };

    rsx! {
        div { style: CARD_STYLE,
            div { style: "font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b96ad;", "{label}" }
            div { style: value_style, "{value}" }
        }
    }
}

fn base_url(state: &ApiState) -> String {
    state
        .base_url
        .read()
        .trim_end_matches('/')
        .trim()
        .to_string()
}

async fn get_json<T>(client: &reqwest::Client, url: String) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let response = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|err| format!("GET {url} failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {url} returned HTTP {status}"));
    }
    response
        .json::<T>()
        .await
        .map_err(|err| format!("GET {url} decode failed: {err}"))
}

/// One polling pass. Every failure is accumulated into the error banner; no
/// fetch failure is ever fatal to the UI.
///
/// A generation counter guards every write: if a newer refresh (or a
/// mutation such as approve/deny) started while we were awaiting a response,
/// this pass is stale and discards its result instead of overwriting newer
/// state or clearing a newer error.
async fn refresh_all(mut state: ApiState) {
    let epoch = begin_refresh(&mut state);
    let client = reqwest::Client::new();
    let base = base_url(&state);
    let mut problems: Vec<String> = Vec::new();

    let health = get_json::<Health>(&client, format!("{base}/api/health")).await;
    if !is_current((state.epoch)(), epoch) {
        return;
    }
    match health {
        Ok(health) if health.status == "ok" => state.connected.set(Some(health.version)),
        Ok(health) => {
            state.connected.set(None);
            problems.push(format!("health status: {}", health.status));
        }
        Err(err) => {
            state.connected.set(None);
            problems.push(err);
        }
    }

    let list = get_json::<Vec<String>>(&client, format!("{base}/api/engagements")).await;
    if !is_current((state.epoch)(), epoch) {
        return;
    }
    match list {
        Ok(list) => {
            let keep = state
                .selected
                .read()
                .as_ref()
                .filter(|id| list.contains(id))
                .cloned();
            if let Some(id) = keep.or_else(|| list.first().cloned()) {
                state.selected.set(Some(id));
            } else {
                state.selected.set(None);
            }
            state.engagements.set(list);
        }
        Err(err) => problems.push(err),
    }

    let current = state.selected.read().clone();
    match current {
        Some(id) => match engagement_api_url(&base, &id) {
            Err(err) => {
                // A malformed selection is surfaced in the error banner and
                // never turned into a broken HTTP request.
                problems.push(err);
                state.detail.set(None);
            }
            Ok(url) => {
                let detail = get_json::<EngagementView>(&client, url).await;
                if !is_current((state.epoch)(), epoch) {
                    return;
                }
                match detail {
                    Ok(view) => {
                        // The user may have selected another engagement while
                        // this request was in flight. Only apply the detail if
                        // it still belongs to the current selection.
                        if state.selected.read().as_deref() == Some(id.as_str()) {
                            state.detail.set(Some(view));
                        }
                    }
                    Err(err) => problems.push(err),
                }
            }
        },
        None => state.detail.set(None),
    }

    let approvals =
        get_json::<Vec<PendingApproval>>(&client, format!("{base}/api/approvals")).await;
    if !is_current((state.epoch)(), epoch) {
        return;
    }
    match approvals {
        Ok(list) => state.approvals.set(list),
        Err(err) => problems.push(err),
    }

    // Only the newest generation is allowed to clear or set the banner.
    if problems.is_empty() {
        state.error.set(None);
    } else {
        state.error.set(Some(problems.join(" | ")));
    }
}

async fn decide_approval(mut state: ApiState, request_id: String, approved: bool) {
    let base = base_url(&state);
    let url = match approval_api_url(&base, &request_id) {
        Ok(url) => url,
        Err(err) => {
            state.error.set(Some(err));
            return;
        }
    };

    // Debounce approve/deny: ignore a repeated click while one POST is already
    // in flight for the same request id.
    {
        let mut in_flight = state.decisions.write();
        if !begin_decision(&mut in_flight, &request_id) {
            return;
        }
    }

    let epoch = begin_refresh(&mut state);
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "approved": approved,
        "decided_by": "operator",
    });
    let result = client.post(url.as_str()).json(&payload).send().await;

    // Always clear the in-flight marker, including on error paths.
    {
        let mut in_flight = state.decisions.write();
        finish_decision(&mut in_flight, &request_id);
    }
    if !is_current((state.epoch)(), epoch) {
        return;
    }

    match result {
        Ok(response) if response.status().is_success() => {
            // refresh_all starts its own generation and repaints everything,
            // including removing the decided approval from the queue.
            refresh_all(state).await;
        }
        Ok(response) => {
            state.error.set(Some(format!(
                "POST {url} returned HTTP {}",
                response.status()
            )));
        }
        Err(err) => state.error.set(Some(format!("POST {url} failed: {err}"))),
    }
}

async fn start_engagement(mut state: ApiState, form: RunForm) {
    let epoch = begin_refresh(&mut state);
    let client = reqwest::Client::new();
    let base = base_url(&state);
    let url = format!("{base}/api/engagements");

    let result = client.post(url.as_str()).json(&form).send().await;
    if !is_current((state.epoch)(), epoch) {
        return;
    }
    match result {
        Ok(response) if response.status().is_success() => {
            match response.json::<EngagementView>().await {
                Ok(view) => {
                    if !is_current((state.epoch)(), epoch) {
                        return;
                    }
                    state.detail.set(Some(view));
                    state.error.set(None);
                    refresh_all(state).await;
                }
                Err(err) => state
                    .error
                    .set(Some(format!("new engagement decode failed: {err}"))),
            }
        }
        Ok(response) => {
            state.error.set(Some(format!(
                "POST {url} returned HTTP {}",
                response.status()
            )));
        }
        Err(err) => state.error.set(Some(format!("POST {url} failed: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_id_matches_api_allow_list() {
        for id in ["demo", "eng-1", "eng_2", "A0_-9", "0123456789abcdef"] {
            assert!(valid_id(id), "{id} should be valid");
        }
        for id in [
            "", "..", ".", "a/b", "a\\b", "a b", "a%2Fb", "a\0b", "a\r\nb", "a\"b", "a#b", "a?b",
            "é",
        ] {
            assert!(!valid_id(id), "{id:?} should be invalid");
        }
    }

    #[test]
    fn engagement_url_validates_and_encodes() {
        assert_eq!(
            engagement_api_url("http://host:8787/", "demo").unwrap(),
            "http://host:8787/api/engagements/demo"
        );
        assert_eq!(
            engagement_api_url("http://host:8787///", "eng_1").unwrap(),
            "http://host:8787/api/engagements/eng_1"
        );
        for bad in ["..", "a/b", "%2e%2e", "a\0b", "a b"] {
            assert!(
                engagement_api_url("http://host", bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn approval_url_validates_and_encodes() {
        assert_eq!(
            approval_api_url("http://host", "0123456789abcdef").unwrap(),
            "http://host/api/approvals/0123456789abcdef"
        );
        for bad in ["", "..", "a/b", "a\0b"] {
            assert!(
                approval_api_url("http://host", bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn export_base_url_validates_and_encodes() {
        assert_eq!(
            export_base_url("http://host/", "demo").unwrap(),
            "http://host/api/engagements/demo/export"
        );
        for bad in ["..", "a/b", "a\"b", "a\r\nX: y"] {
            assert!(
                export_base_url("http://host", bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn percent_encoding_only_touches_unreserved_bytes() {
        // valid ids contain only unreserved bytes, so encoding is a no-op;
        // the helper still encodes anything unexpected for defence in depth.
        assert_eq!(percent_encode_segment("a-b_C.9"), "a-b_C.9");
        assert_eq!(percent_encode_segment("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn decision_tracker_debounces_and_clears() {
        let mut in_flight = Vec::new();
        assert!(begin_decision(&mut in_flight, "req-1"));
        assert!(!begin_decision(&mut in_flight, "req-1"));
        assert!(begin_decision(&mut in_flight, "req-2"));
        assert_eq!(in_flight, vec!["req-1", "req-2"]);
        finish_decision(&mut in_flight, "req-1");
        assert_eq!(in_flight, vec!["req-2"]);
        // Idempotent removal.
        finish_decision(&mut in_flight, "req-1");
        assert_eq!(in_flight, vec!["req-2"]);
        assert!(begin_decision(&mut in_flight, "req-1"));
    }

    #[test]
    fn is_current_detects_stale_generations() {
        let epoch = 7u64;
        assert!(is_current(epoch, epoch));
        assert!(!is_current(epoch - 1, epoch));
        assert!(!is_current(epoch + 1, epoch));
    }
}
