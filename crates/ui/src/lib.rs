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

// ── Design tokens ──────────────────────────────────────────────────────────
// One palette, one spacing rhythm, one set of surfaces. Components reference
// these instead of hard-coding colours so the product reads as one system.
const ROOT_STYLE: &str = "background:#090d18;color:#e9eef8;font-family:Inter,system-ui,-apple-system,'Segoe UI',sans-serif;min-height:100vh;font-size:13px;";
const RAIL_STYLE: &str = "width:72px;flex-shrink:0;background:#0c1220;border-right:1px solid #1e2942;display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 0;";
const HEADER_STYLE: &str = "display:flex;align-items:center;gap:16px;padding:0 28px;height:68px;background:#0b1120;border-bottom:1px solid #1e2942;";
const TITLE_STYLE: &str = "font-size:16px;font-weight:750;color:#f3f6fb;letter-spacing:-0.2px;white-space:nowrap;margin:0;";
const BRAND_MARK_STYLE: &str = "width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,#ff5b6c,#b50f2c);color:#0b1020;font-weight:800;font-size:13px;display:flex;align-items:center;justify-content:center;box-shadow:0 6px 18px rgba(255,77,94,.28);";
const BODY_STYLE: &str = "display:flex;gap:24px;align-items:flex-start;padding:24px 28px 40px;";
const SIDEBAR_STYLE: &str =
    "width:292px;flex-shrink:0;display:flex;flex-direction:column;gap:16px;";
const MAIN_STYLE: &str = "flex:1;min-width:0;display:flex;flex-direction:column;gap:18px;";
const CARD_STYLE: &str = "background:linear-gradient(180deg,#141c2e,#111829);border:1px solid #23304c;border-radius:16px;padding:20px;box-shadow:0 12px 34px rgba(0,0,0,.22);";
const SECTION_TITLE_STYLE: &str = "font-size:11px;text-transform:uppercase;letter-spacing:1.4px;color:#8d9ab5;font-weight:700;margin:0 0 14px;";
const FIELD_LABEL_STYLE: &str = "display:block;font-size:10px;text-transform:uppercase;letter-spacing:1.2px;color:#8492ad;font-weight:700;margin:14px 0 6px;";
const INPUT_STYLE: &str = "width:100%;box-sizing:border-box;background:#0c1322;color:#e9eef8;border:1px solid #26334f;border-radius:10px;padding:10px 12px;font-size:13px;";
const MUTED_STYLE: &str = "color:#8d9ab5;font-size:12px;line-height:1.55;margin:8px 0;";
const PRIMARY_BUTTON_STYLE: &str = "background:linear-gradient(135deg,#ff5b6c,#e11d38);color:#fff;border:1px solid #ff6b7a;border-radius:10px;padding:10px 16px;font-weight:700;font-size:13px;cursor:pointer;box-shadow:0 6px 16px rgba(225,29,56,.22);";
const DENY_BUTTON_STYLE: &str = "background:#182136;color:#ff9aa6;border:1px solid #5b2c3a;border-radius:10px;padding:10px 16px;font-weight:700;font-size:13px;cursor:pointer;";
const SECONDARY_BUTTON_STYLE: &str = "background:#162033;color:#d9e2f2;border:1px solid #2a3959;border-radius:10px;padding:9px 14px;font-weight:650;font-size:12px;cursor:pointer;";
const ERROR_STYLE: &str = "background:#35121e;color:#ffd9df;border:1px solid #ff4d5e;border-radius:12px;padding:11px 18px;margin:16px 28px 0;font-size:13px;";
const TH_STYLE: &str = "text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1.2px;color:#8492ad;padding:8px 10px;border-bottom:1px solid #26334f;font-weight:700;";
const TD_STYLE: &str = "font-size:13px;padding:11px 10px;border-bottom:1px solid #1d2941;vertical-align:top;color:#dbe4f3;";
const PRE_STYLE: &str = "background:#080d18;color:#cdd9ec;border:1px solid #1d2941;border-radius:10px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.6;margin:0;";
const MONO_STYLE: &str = "font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;";
const PILL_BASE: &str = "display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-size:11px;font-weight:700;letter-spacing:.2px;";

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

/// Sections of the control room. The rail swaps the main panel rather than
/// stacking every section into one long scrolling page.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum NavSection {
    #[default]
    Overview,
    Findings,
    Verification,
    Approvals,
    Evidence,
    Exports,
}

impl NavSection {
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Findings => "Findings",
            Self::Verification => "Verification",
            Self::Approvals => "Approvals",
            Self::Evidence => "Evidence",
            Self::Exports => "Exports",
        }
    }

    fn glyph(self) -> &'static str {
        match self {
            Self::Overview => "◈",
            Self::Findings => "◇",
            Self::Verification => "✓",
            Self::Approvals => "⚑",
            Self::Evidence => "▤",
            Self::Exports => "↗",
        }
    }
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
    pub proposal: Option<redagent_core::CallProposal>,
}

/// Body of `POST /api/engagements`. The RedHands path is intentionally absent:
/// the API resolves it from server-side configuration.
#[derive(Clone, Serialize)]
pub struct RunForm {
    pub goal: String,
    pub ledger: Option<()>,
    pub llm: bool,
    pub auto_approve: bool,
    pub retest: bool,
    pub toolsets: String,
    pub allow_read_only: bool,
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
    pub section: Signal<NavSection>,
    /// Incremented at the start of every refresh/mutation. Async responses
    /// from an older generation are discarded so a slow request can never
    /// overwrite the result of a newer selection or clear a newer error.
    epoch: Signal<u64>,
    /// Approval request ids whose decision POST is currently in flight. Used
    /// to debounce the approve/deny buttons.
    decisions: Signal<Vec<String>>,
}

/// All inputs for the "new engagement" form, grouped so components stay
/// small and the API surface of the UI is easy to reason about.
#[derive(Clone, Copy)]
pub struct FormState {
    pub goal: Signal<String>,
    pub redhands_path: Signal<String>,
    pub toolsets: Signal<String>,
    pub allow_read_only: Signal<bool>,
    pub llm: Signal<bool>,
    pub auto_approve: Signal<bool>,
    pub retest: Signal<bool>,
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
    let base_url = use_signal(|| DEFAULT_BASE_URL.to_string());
    let engagements = use_signal(Vec::<String>::new);
    let selected = use_signal(|| None::<String>);
    let detail = use_signal(|| None::<EngagementView>);
    let approvals = use_signal(Vec::<PendingApproval>::new);
    let error = use_signal(|| None::<String>);
    let connected = use_signal(|| None::<String>);
    let section = use_signal(NavSection::default);
    let epoch = use_signal(|| 0_u64);
    let decisions = use_signal(Vec::<String>::new);
    let form = FormState {
        goal: use_signal(String::new),
        redhands_path: use_signal(String::new),
        toolsets: use_signal(|| "health".to_string()),
        allow_read_only: use_signal(|| false),
        llm: use_signal(|| false),
        auto_approve: use_signal(|| false),
        retest: use_signal(|| false),
    };

    let api = ApiState {
        base_url,
        engagements,
        selected,
        detail,
        approvals,
        error,
        connected,
        section,
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
            format!("{PILL_BASE};background:#10261c;color:#5ee6a8;border:1px solid #2c6b4f;"),
        ),
        None => (
            "● offline".to_string(),
            format!("{PILL_BASE};background:#2a1320;color:#ff9aa6;border:1px solid #ff4d5e;"),
        ),
    };
    let breadcrumb = selected().unwrap_or_else(|| "no engagement selected".to_string());
    let mut base_for_input = base_url;
    let api_for_button = api;

    rsx! {
        div { style: ROOT_STYLE,
            div { style: "display:flex;min-height:100vh;",
                {nav_rail(api)}
                div { style: "flex:1;min-width:0;",
                    header { style: HEADER_STYLE,
                        div { style: BRAND_MARK_STYLE, "RA" }
                        div {
                            h1 { style: TITLE_STYLE, "RedAgent" }
                            div { style: "font-size:10px;color:#8492ad;letter-spacing:1.4px;margin-top:3px;", "AUTONOMOUS SECURITY OPERATIONS" }
                        }
                        div { style: "width:1px;height:30px;background:#23304c;margin:0 6px;" }
                        div { style: "font-size:12px;color:#8492ad;", "Workspace" }
                        span { style: "color:#44557a;padding:0 4px;", "/" }
                        span { style: "font-size:12px;color:#dbe4f3;font-weight:700;", "{breadcrumb}" }
                        div { style: "flex:1;" }
                        span { style: format!("{PILL_BASE};background:#13203a;color:#9ad4ff;border:1px solid #2b3d5c;"), "AUTO · 1.5s" }
                        span { style: badge_style, "{badge_text}" }
                        input {
                            style: "background:#0c1322;color:#e9eef8;border:1px solid #26334f;border-radius:10px;padding:8px 10px;width:220px;font-size:12px;",
                            r#type: "text",
                            spellcheck: false,
                            value: base_for_input(),
                            oninput: move |event| base_for_input.set(event.value()),
                        }
                        button {
                            style: SECONDARY_BUTTON_STYLE,
                            onclick: move |_| {
                                let api = api_for_button;
                                spawn(async move { refresh_all(api).await; });
                            },
                            "↻ Refresh"
                        }
                    }

                    if let Some(message) = error() {
                        div { style: ERROR_STYLE, "⚠ {message}" }
                    }

                    div { style: BODY_STYLE,
                        {sidebar(engagements, selected, form, api)}
                        main { style: MAIN_STYLE,
                            {engagement_detail(detail, approvals, api)}
                        }
                    }
                }
            }
        }
    }
}

/// Left icon rail with real section switching.
pub fn nav_rail(api: ApiState) -> Element {
    let active = api.section.read();
    let sections = [
        NavSection::Overview,
        NavSection::Findings,
        NavSection::Verification,
        NavSection::Approvals,
        NavSection::Evidence,
        NavSection::Exports,
    ];
    rsx! {
        nav { style: RAIL_STYLE,
            div { style: BRAND_MARK_STYLE, "RA" }
            div { style: "width:30px;height:1px;background:#23304c;margin:8px 0 6px;" }
            for section in sections.iter().copied() {
                {
                    let mut target = api.section;
                    let is_active = *active == section;
                    let (bg, fg, border) = if is_active {
                        ("#2a1420", "#ff7a88", "#ff4d5e")
                    } else {
                        ("transparent", "#7d8aa6", "transparent")
                    };
                    let button_style = format!(
                        "width:44px;height:44px;border-radius:12px;background:{bg};color:{fg};border:1px solid {border};font-size:19px;cursor:pointer;display:flex;align-items:center;justify-content:center;"
                    );
                    let label = section.label();
                    rsx! {
                        button {
                            key: "{label}",
                            style: button_style,
                            title: label,
                            onclick: move |_| target.set(section),
                            "{section.glyph()}"
                        }
                    }
                }
            }
            div { style: "flex:1;" }
            div { style: "width:34px;height:34px;border-radius:10px;background:#121b2d;border:1px solid #23304c;color:#8d9ab5;display:flex;align-items:center;justify-content:center;font-size:14px;", "⌘" }
        }
    }
}

pub fn sidebar(
    engagements: Signal<Vec<String>>,
    mut selected: Signal<Option<String>>,
    form: FormState,
    api: ApiState,
) -> Element {
    let ids = engagements();
    let current = selected();
    let count = ids.len();

    rsx! {
        aside { style: SIDEBAR_STYLE,
            div { style: CARD_STYLE,
                div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;",
                    h2 { style: "font-size:11px;text-transform:uppercase;letter-spacing:1.4px;color:#8d9ab5;font-weight:700;margin:0;", "Engagements" }
                    span { style: format!("{PILL_BASE};background:#1b2740;color:#9ad4ff;border:1px solid #2b3d5c;"), "{count}" }
                }
                if ids.is_empty() {
                    div { style: "border:1px dashed #2a3959;border-radius:12px;padding:18px 14px;text-align:center;",
                        div { style: "font-size:22px;color:#536582;margin-bottom:6px;", "◈" }
                        p { style: MUTED_STYLE, "No engagements yet. Run one to see it here." }
                    }
                } else {
                    div { style: "display:flex;flex-direction:column;gap:5px;",
                        for id in ids.iter() {
                            {
                                let id = id.clone();
                                let is_selected = current.as_deref() == Some(id.as_str());
                                let item_style = if is_selected {
                                    "background:linear-gradient(90deg,#331622,#24172a);border:1px solid #ff4d5e;border-radius:11px;padding:10px 12px;text-align:left;cursor:pointer;width:100%;display:flex;align-items:center;gap:10px;"
                                } else {
                                    "background:transparent;border:1px solid transparent;border-radius:11px;padding:10px 12px;text-align:left;cursor:pointer;width:100%;display:flex;align-items:center;gap:10px;"
                                };
                                let dot = if is_selected { "#ff5b6c" } else { "#3f7f68" };
                                rsx! {
                                    button {
                                        key: "{id}",
                                        style: item_style,
                                        onclick: move |_| selected.set(Some(id.clone())),
                                        span { style: format!("width:7px;height:7px;border-radius:99px;background:{dot};flex-shrink:0;"), "" }
                                        span { style: format!("font-size:13px;font-weight:{};color:{};flex:1;text-align:left;", if is_selected { "700" } else { "500" }, if is_selected { "#ffffff" } else { "#c3cee2" }), "{id}" }
                                        span { style: "color:#5d6d8b;font-size:12px;", "›" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            {run_form(form, api)}
        }
    }
}

pub fn run_form(form: FormState, api: ApiState) -> Element {
    let FormState {
        mut goal,
        redhands_path,
        mut toolsets,
        mut allow_read_only,
        mut llm,
        mut auto_approve,
        mut retest,
    } = form;
    let option_row = "display:flex;align-items:center;gap:9px;font-size:12px;color:#c3cee2;margin-top:10px;cursor:pointer;";
    rsx! {
        div { style: CARD_STYLE,
            h2 { style: SECTION_TITLE_STYLE, "New engagement" }
            p { style: "font-size:12px;color:#8492ad;margin:-6px 0 4px;", "Goal in. Evidence out." }

            label { style: FIELD_LABEL_STYLE, "Objective" }
            input {
                style: INPUT_STYLE,
                r#type: "text",
                placeholder: "e.g. verify the lab tool plane",
                value: goal(),
                oninput: move |event| goal.set(event.value()),
            }

            label { style: FIELD_LABEL_STYLE, "Toolsets" }
            input {
                style: INPUT_STYLE,
                r#type: "text",
                placeholder: "health or nmap,vuln",
                value: toolsets(),
                oninput: move |event| toolsets.set(event.value()),
            }
            p { style: "font-size:11px;color:#667792;margin:5px 0 0;", "Toolset ids, not install profiles. RedHands path is server-side." }

            label { style: option_row,
                input { r#type: "checkbox", checked: llm(), onchange: move |e| llm.set(e.checked()) }
                "LLM planner"
            }
            label { style: option_row,
                input { r#type: "checkbox", checked: allow_read_only(), onchange: move |e| allow_read_only.set(e.checked()) }
                "Allow read-only catalog tools"
            }
            label { style: option_row,
                input { r#type: "checkbox", checked: retest(), onchange: move |e| retest.set(e.checked()) }
                "Retest findings"
            }
            label { style: "display:flex;align-items:center;gap:9px;font-size:12px;color:#ff9aa6;margin-top:10px;cursor:pointer;",
                input { r#type: "checkbox", checked: auto_approve(), onchange: move |e| auto_approve.set(e.checked()) }
                "⚠ Auto-approve gated tools"
            }

            button {
                style: format!("{PRIMARY_BUTTON_STYLE};width:100%;margin-top:16px;"),
                onclick: move |_| {
                    let form = RunForm {
                        goal: goal(),
                        ledger: None,
                        llm: llm(),
                        auto_approve: auto_approve(),
                        retest: retest(),
                        toolsets: toolsets(),
                        allow_read_only: allow_read_only(),
                        max_tool_calls: 8,
                        max_intents: 6,
                    };
                    spawn(async move { start_engagement(api, form).await; });
                },
                "Run engagement →"
            }
            p { style: "font-size:10px;color:#5d6d8b;text-align:center;margin:10px 0 0;letter-spacing:.4px;", {format!("PATH: {}", redhands_path().trim())} }
        }
    }
}

fn severity_pill(severity: &str) -> String {
    let (bg, border, fg) = match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => ("#3a1420", "#ff4d5e", "#ff9aa6"),
        "medium" => ("#332612", "#c99b32", "#ffd68a"),
        "info" | "low" => ("#102a24", "#2c6b4f", "#7ce0b6"),
        _ => ("#1b2740", "#2b3d5c", "#9ad4ff"),
    };
    format!("{PILL_BASE};background:{bg};border:1px solid {border};color:{fg};")
}

fn verdict_pill(verdict: &str) -> String {
    let (bg, border, fg) = match verdict {
        "verified" | "still_reproducible" => ("#102a24", "#2c6b4f", "#7ce0b6"),
        "fixed" => ("#10243a", "#2c5a8a", "#9ad4ff"),
        _ => ("#332612", "#c99b32", "#ffd68a"),
    };
    format!("{PILL_BASE};background:{bg};border:1px solid {border};color:{fg};")
}

fn findings_panel(view: &EngagementView, compact: bool) -> Element {
    let findings_total = view.findings.len();
    let shown: Vec<_> = if compact {
        view.findings.iter().take(5).collect()
    } else {
        view.findings.iter().collect()
    };
    rsx! {
        section { style: CARD_STYLE,
            div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;",
                h2 { style: "font-size:11px;text-transform:uppercase;letter-spacing:1.4px;color:#8d9ab5;font-weight:700;margin:0;", "Findings" }
                span { style: format!("{PILL_BASE};background:#1b2740;color:#9ad4ff;border:1px solid #2b3d5c;"), "{findings_total}" }
            }
            if shown.is_empty() {
                div { style: "text-align:center;padding:22px;border:1px dashed #2a3959;border-radius:12px;",
                    div { style: "font-size:22px;color:#536582;", "◇" }
                    p { style: MUTED_STYLE, "No findings recorded yet." }
                }
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
                        for finding in shown.iter() {
                            {
                                let id = finding.id.clone();
                                let title = finding.title.clone();
                                let severity = finding.severity.clone();
                                let seq = finding.evidence_seq;
                                let pill = severity_pill(&severity);
                                rsx! {
                                    tr { key: "{id}",
                                        td { style: format!("{TD_STYLE};{MONO_STYLE};color:#9ad4ff;"), "{id}" }
                                        td { style: TD_STYLE, "{title}" }
                                        td { style: TD_STYLE, span { style: pill, "{severity}" } }
                                        td { style: format!("{TD_STYLE};{MONO_STYLE};color:#8d9ab5;"), "#{seq}" }
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

fn verification_panel(view: &EngagementView) -> Element {
    rsx! {
        section { style: CARD_STYLE,
            h2 { style: SECTION_TITLE_STYLE, "Verification & retests" }
            if view.verifications.is_empty() && view.retests.is_empty() {
                p { style: MUTED_STYLE, "No verification results yet." }
            } else {
                div { style: "display:flex;flex-direction:column;gap:8px;",
                    for item in view.verifications.iter() {
                        {
                            let id = item.finding_id.clone();
                            let verdict = item.verdict.clone();
                            let seq = item.evidence_seq;
                            let pill = verdict_pill(&verdict);
                            rsx! {
                                div { key: "v-{id}", style: "background:#0c1322;border:1px solid #1e2942;border-radius:11px;padding:10px 12px;display:flex;align-items:center;gap:12px;",
                                    span { style: format!("{MONO_STYLE};color:#9ad4ff;"), "{id}" }
                                    span { style: pill, "{verdict}" }
                                    span { style: "color:#8492ad;font-size:11px;", "evidence #{seq}" }
                                }
                            }
                        }
                    }
                    for item in view.retests.iter() {
                        {
                            let id = item.finding_id.clone();
                            let verdict = item.verdict.clone();
                            let seq = item.evidence_seq;
                            let pill = verdict_pill(&verdict);
                            rsx! {
                                div { key: "r-{id}", style: "background:#0c1322;border:1px solid #1e2942;border-radius:11px;padding:10px 12px;display:flex;align-items:center;gap:12px;",
                                    span { style: format!("{MONO_STYLE};color:#ff9aa6;"), "retest · {id}" }
                                    span { style: pill, "{verdict}" }
                                    span { style: "color:#8492ad;font-size:11px;", "evidence #{seq}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn evidence_panel(view: &EngagementView) -> Element {
    let tool_call_count = view.tool_calls.len();
    rsx! {
        section { style: CARD_STYLE,
            div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;",
                h2 { style: "font-size:11px;text-transform:uppercase;letter-spacing:1.4px;color:#8d9ab5;font-weight:700;margin:0;", "Tool evidence" }
                span { style: format!("{PILL_BASE};background:#1b2740;color:#9ad4ff;border:1px solid #2b3d5c;"), "{tool_call_count} calls" }
            }
            if view.tool_calls.is_empty() {
                p { style: MUTED_STYLE, "No tool calls recorded." }
            } else {
                for call in view.tool_calls.iter() {
                    {
                        let tool = call.tool.clone();
                        let intent_id = call.intent_id.clone();
                        let is_error = call.is_error;
                        let content = call.content.clone();
                        let dot = if is_error { "#ff5b6c" } else { "#43d9a3" };
                        let label = if is_error { "#ff9aa6" } else { "#9ad4ff" };
                        rsx! {
                            div { key: "{intent_id}-{tool}", style: "margin-bottom:16px;border:1px solid #1e2942;border-radius:12px;overflow:hidden;",
                                div { style: "display:flex;align-items:center;gap:9px;background:#121b2d;padding:9px 12px;border-bottom:1px solid #1e2942;",
                                    span { style: format!("width:7px;height:7px;border-radius:99px;background:{dot};"), "" }
                                    span { style: format!("font-size:12px;font-weight:700;color:{label};"), "{tool}" }
                                    span { style: format!("{MONO_STYLE};color:#667792;"), "intent {intent_id}" }
                                }
                                pre { style: PRE_STYLE, "{content}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn export_panel(export_base: Option<&str>) -> Element {
    let formats = [
        ("SARIF", "Static analysis interchange", "sarif"),
        ("CycloneDX", "SBOM / vulnerability BOM", "cyclonedx"),
        ("MITRE", "ATT&CK Navigator layer", "mitre"),
        ("Markdown", "Human-readable dossier", "markdown"),
        ("HTML", "Branded standalone report", "html"),
    ];
    rsx! {
        section { style: CARD_STYLE,
            h2 { style: SECTION_TITLE_STYLE, "Export engagement" }
            if let Some(base) = export_base {
                div { style: "display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;",
                    for (label, description, slug) in formats {
                        {
                            let href = format!("{base}/{slug}");
                            let label = label.to_string();
                            let description = description.to_string();
                            rsx! {
                                a { key: "{slug}", href: "{href}", style: "display:block;background:#0c1322;border:1px solid #26334f;border-radius:12px;padding:14px;text-decoration:none;",
                                    div { style: "display:flex;align-items:center;justify-content:space-between;",
                                        span { style: "color:#e9eef8;font-size:13px;font-weight:700;", "{label}" }
                                        span { style: "color:#ff7a88;font-size:14px;", "↗" }
                                    }
                                    p { style: "color:#8492ad;font-size:11px;margin:6px 0 0;", "{description}" }
                                }
                            }
                        }
                    }
                }
            } else {
                p { style: MUTED_STYLE, "Invalid engagement id; exports unavailable." }
            }
        }
    }
}

fn section_panel(
    section: NavSection,
    view: &EngagementView,
    approvals: Signal<Vec<PendingApproval>>,
    api: ApiState,
    export_base: Option<&str>,
) -> Element {
    match section {
        NavSection::Overview => rsx! {
            {findings_panel(view, true)}
            {verification_panel(view)}
            {approval_queue(approvals, api)}
        },
        NavSection::Findings => rsx! { {findings_panel(view, false)} },
        NavSection::Verification => rsx! { {verification_panel(view)} },
        NavSection::Approvals => rsx! { {approval_queue(approvals, api)} },
        NavSection::Evidence => rsx! { {evidence_panel(view)} },
        NavSection::Exports => rsx! { {export_panel(export_base)} },
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
                div { style: "font-size:30px;color:#ff4d5e;margin-bottom:10px;", "◈" }
                h2 { style: "font-size:18px;color:#e9eef8;margin:0 0 6px;", "No engagement selected" }
                p { style: MUTED_STYLE, "Choose an engagement from the sidebar, or launch a new one to begin." }
            }
        };
    };

    let section = *api.section.read();
    let goal_text = view
        .goal
        .clone()
        .unwrap_or_else(|| "(untitled)".to_string());
    let status_text = if view.completed {
        "completed"
    } else if view.abort_reason.is_some() {
        "aborted"
    } else {
        "running"
    };
    let abort_text = view.abort_reason.clone().unwrap_or_default();
    let budget_text = view.budget_exhausted.clone().unwrap_or_default();
    let engagement_id = api.selected.read().clone().unwrap_or_default();
    let ver = view
        .redhands_version
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let export_base = export_base_url(&base_url(&api), &engagement_id).ok();

    rsx! {
        section { style: MAIN_STYLE,
            div { style: "display:flex;align-items:flex-end;justify-content:space-between;gap:16px;",
                div {
                    div { style: "font-size:10px;letter-spacing:1.6px;color:#8492ad;text-transform:uppercase;font-weight:700;", {section.label()} }
                    h2 { style: "font-size:24px;letter-spacing:-0.5px;color:#f3f6fb;margin:6px 0 0;", "{goal_text}" }
                    p { style: format!("color:#667792;font-size:11px;margin:6px 0 0;{MONO_STYLE}"), "engagement / {engagement_id} · redhands {ver}" }
                }
                span { style: verdict_pill(status_text), "{status_text}" }
            }

            div { style: "display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;",
                {metric_card("◎", "Goal", &goal_text, "authorized objective", true)}
                {metric_card("◉", "Status", status_text, "engine state", false)}
                {metric_card("◇", "Findings", &view.findings.len().to_string(), "recorded evidence", false)}
                {metric_card("▤", "Tool calls", &view.tool_calls.len().to_string(), "audit trail", false)}
            }

            if !abort_text.is_empty() {
                div { style: "background:#35121e;color:#ffd9df;border:1px solid #ff4d5e;border-radius:12px;padding:12px 16px;font-size:12px;", "Aborted: {abort_text}" }
            }
            if !budget_text.is_empty() {
                div { style: "background:#2d2410;color:#ffe6a8;border:1px solid #c99b32;border-radius:12px;padding:12px 16px;font-size:12px;", "Budget exhausted: {budget_text}" }
            }

            {section_panel(section, view, approvals, api, export_base.as_deref())}
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
                div { style: "display:flex;align-items:center;gap:10px;background:#0c1322;border:1px solid #1e2942;border-radius:11px;padding:12px 14px;",
                    span { style: "color:#43d9a3;font-size:14px;", "✓" }
                    p { style: "color:#8492ad;font-size:12px;margin:0;", "Queue clear — gated tools default to deny when approval is required." }
                }
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
                            let proposal = item.proposal.clone();
                            // Once a decision is in flight, disable both
                            // buttons so a double-click cannot POST twice.
                            let busy = in_flight.iter().any(|pending| pending == &request_id);
                            let approve_style = if busy {
                                "background:#2a2028;color:#7d6a72;border:1px solid #3d2f38;border-radius:10px;padding:10px 16px;font-weight:700;cursor:not-allowed;"
                            } else {
                                PRIMARY_BUTTON_STYLE
                            };
                            let deny_style = if busy {
                                "background:#161d2e;color:#6b5c64;border:1px solid #2f2830;border-radius:10px;padding:10px 16px;font-weight:700;cursor:not-allowed;"
                            } else {
                                DENY_BUTTON_STYLE
                            };
                            rsx! {
                                div { key: "{request_id}", style: "background:#0c1322;border:1px solid #ff4d5e;border-radius:12px;padding:14px;box-shadow:0 0 0 3px rgba(255,77,94,.06);",
                                    div { style: "display:flex;align-items:center;gap:10px;",
                                        span { style: format!("{PILL_BASE};background:#3a1420;color:#ff9aa6;border:1px solid #ff4d5e;"), "APPROVAL REQUIRED" }
                                        span { style: format!("{MONO_STYLE};color:#9ad4ff;"), "{tool} · {intent_id}" }
                                    }
                                    div { style: "font-size:12px;color:#c3cee2;margin-top:10px;line-height:1.5;", "{message}" }
                                    if let Some(proposal) = proposal {
                                        div { style: "background:#080d18;border:1px solid #23304c;border-radius:10px;padding:11px;margin-top:10px;",
                                            div { style: "display:flex;align-items:center;gap:8px;flex-wrap:wrap;",
                                                span { style: format!("{PILL_BASE};background:#1b2740;color:#9ad4ff;border:1px solid #2b3d5c;"), "SCOPE: {proposal.scope_verdict}" }
                                                for flag in proposal.risk_flags.iter() {
                                                    { let flag = flag.clone(); rsx! { span { style: format!("{PILL_BASE};background:#3a1420;color:#ff9aa6;border:1px solid #ff4d5e;"), "{flag}" } } }
                                                }
                                            }
                                            div { style: "font-size:10px;letter-spacing:1.2px;color:#8492ad;text-transform:uppercase;font-weight:700;margin-top:10px;", "Exact arguments" }
                                            pre { style: format!("{PRE_STYLE};margin-top:6px;max-height:160px;"), "{proposal.arguments}" }
                                            if let Some(diff) = proposal.diff {
                                                div { style: "font-size:10px;letter-spacing:1.2px;color:#8492ad;text-transform:uppercase;font-weight:700;margin-top:10px;", "Change since previous call" }
                                                pre { style: format!("{PRE_STYLE};margin-top:6px;max-height:120px;"), "{diff}" }
                                            }
                                        }
                                    }
                                    div { style: "display:flex;gap:8px;margin-top:12px;",
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

pub fn metric_card(icon: &str, label: &str, value: &str, subtitle: &str, accent: bool) -> Element {
    let (border, value_color, icon_bg) = if accent {
        ("#ff4d5e", "#ff7a88", "#331622")
    } else {
        ("#23304c", "#f3f6fb", "#182136")
    };
    rsx! {
        div { style: format!("background:linear-gradient(180deg,#141c2e,#101728);border:1px solid {border};border-radius:14px;padding:15px 16px;box-shadow:0 8px 22px rgba(0,0,0,.18);"),
            div { style: "display:flex;align-items:center;justify-content:space-between;",
                div { style: format!("width:28px;height:28px;border-radius:9px;background:{icon_bg};color:{value_color};display:flex;align-items:center;justify-content:center;font-size:14px;"), "{icon}" }
                div { style: "font-size:10px;text-transform:uppercase;letter-spacing:1.2px;color:#8492ad;font-weight:700;", "{label}" }
            }
            div { style: format!("font-size:17px;font-weight:750;color:{value_color};margin-top:12px;word-break:break-word;letter-spacing:-0.2px;"), "{value}" }
            div { style: "font-size:11px;color:#667792;margin-top:4px;", "{subtitle}" }
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

    #[test]
    fn navigation_sections_are_distinct() {
        let sections = [
            NavSection::Overview,
            NavSection::Findings,
            NavSection::Verification,
            NavSection::Approvals,
            NavSection::Evidence,
            NavSection::Exports,
        ];
        let labels: Vec<_> = sections.iter().map(|s| s.label()).collect();
        let glyphs: Vec<_> = sections.iter().map(|s| s.glyph()).collect();
        assert_eq!(
            labels,
            vec![
                "Overview",
                "Findings",
                "Verification",
                "Approvals",
                "Evidence",
                "Exports"
            ]
        );
        for (index, glyph) in glyphs.iter().enumerate() {
            assert!(!glyph.is_empty());
            assert!(!glyphs[..index].contains(glyph), "duplicate glyph {glyph}");
        }
    }

    #[test]
    fn severity_and_verdict_pills_use_distinct_palettes() {
        let critical = severity_pill("critical");
        let info = severity_pill("info");
        let unknown = severity_pill("something-else");
        assert!(critical.contains("#ff4d5e"));
        assert!(info.contains("#2c6b4f"));
        assert!(unknown.contains("#2b3d5c"));
        assert_ne!(critical, info);

        let verified = verdict_pill("verified");
        let fixed = verdict_pill("fixed");
        let pending = verdict_pill("cannot_confirm");
        assert!(verified.contains("#7ce0b6"));
        assert!(fixed.contains("#9ad4ff"));
        assert!(pending.contains("#ffd68a"));
        assert_ne!(verified, pending);
    }
}
