//! Export an [`EngagementView`] into machine- and human-readable report
//! formats: SARIF 2.1.0, CycloneDX 1.5, a MITRE ATT&CK Navigator layer,
//! Markdown (delegated to [`redagent_core::render_markdown`]) and a standalone
//! HTML report. The crate also produces retest diffs via [`diff_retest`].
//!
//! The crate is intentionally small and dependency-light: hashing uses the
//! workspace `sha2`/`hex` crates and technique detection is a plain character
//! scanner, so no regex engine is required. The HTML report is fully
//! self-contained (inline CSS only, no scripts or external assets) and every
//! value derived from an engagement is HTML-escaped before rendering.

use redagent_core::EngagementView;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::fmt::Write as _;

/// A supported report export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Sarif,
    CycloneDx,
    MitreNavigator,
    Markdown,
    Html,
}

/// The serialization format for a [`diff_retest`] report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffFormat {
    Markdown,
    Json,
}

impl std::str::FromStr for ExportFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sarif" => Ok(Self::Sarif),
            "cyclonedx" | "cyclone-dx" => Ok(Self::CycloneDx),
            "mitre" | "mitre-navigator" => Ok(Self::MitreNavigator),
            "markdown" | "md" => Ok(Self::Markdown),
            "html" => Ok(Self::Html),
            other => Err(anyhow::anyhow!("unknown export format: {other}")),
        }
    }
}

/// Escape a string for safe interpolation into HTML text or attributes.
///
/// `&` is replaced first so the entities introduced by the other replacements
/// are not themselves escaped. Every character that can terminate a text node
/// or an attribute value is covered: `<`, `>`, `&`, `"` and `'`.
fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Build a safe, lowercase slug from the engagement goal.
///
/// Only ASCII alphanumeric characters and `-` survive; runs of other
/// characters collapse to a single dash, leading/trailing dashes are removed,
/// and the result is capped at 40 characters. An empty result falls back to
/// `"engagement"`.
fn goal_slug(view: &EngagementView) -> String {
    let Some(goal) = view.goal.as_deref() else {
        return "engagement".to_string();
    };

    let mut slug = String::new();
    let mut previous_was_dash = false;
    for ch in goal.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_was_dash = false;
        } else if !previous_was_dash {
            slug.push('-');
            previous_was_dash = true;
        }
    }

    let mut slug: String = slug.trim_matches('-').chars().take(40).collect();
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "engagement".to_string()
    } else {
        slug
    }
}

/// Sanitize a finding title into a stable SARIF rule identifier.
fn sanitize_rule_id(title: &str) -> String {
    let mut id = String::new();
    let mut previous_was_dash = false;
    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            id.push(ch.to_ascii_lowercase());
            previous_was_dash = false;
        } else if !previous_was_dash {
            id.push('-');
            previous_was_dash = true;
        }
    }
    let id = id.trim_matches('-');
    if id.is_empty() {
        "rule".to_string()
    } else {
        id.to_string()
    }
}

/// Map a finding severity to a SARIF result level.
fn sarif_level(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Derive a deterministic `urn:uuid:...` from the engagement contents using
/// SHA-256 (first 32 hex digits, arranged in the UUID 8-4-4-4-12 layout).
///
/// The seed is the canonical JSON serialization of the *whole* view. Struct
/// field order is fixed and there are no unordered maps, so the seed is
/// deterministic; JSON escaping makes the field boundaries unambiguous. This
/// also disambiguates engagements that share a goal and findings but differ
/// elsewhere (verification/retest verdicts, tool output, version, ...), which
/// a seed built from only a few hand-picked fields would collide on.
fn serial_number(view: &EngagementView) -> String {
    let seed = serde_json::to_string(view).unwrap_or_default();

    let digest = sha2::Sha256::digest(seed.as_bytes());
    let hex = hex::encode(digest);
    let id = &hex[..32];
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &id[0..8],
        &id[8..12],
        &id[12..16],
        &id[16..20],
        &id[20..32]
    )
}

/// A byte is a "word" byte for MITRE id boundary checks (ASCII `\b`
/// semantics: letters, digits and underscore). Non-ASCII UTF-8 bytes are not
/// word bytes, which is consistent with treating non-ASCII text as a boundary.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Find MITRE ATT&CK technique IDs (`T` followed by four digits) in `text`.
/// Lowercase `t` is accepted and normalized to uppercase. The id must sit on
/// word boundaries on both sides so tokens such as `XT1059`, `T10599` and
/// `AT1059x` are not false positives, while `T1059`, `(T1059)`, `T1059.003`
/// and `CWE-T1059` are recognized. Results keep the order in which they appear.
fn scan_technique_ids(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i + 4 < bytes.len() {
        let is_t = bytes[i] == b'T' || bytes[i] == b't';
        let left_boundary = i == 0 || !is_word_byte(bytes[i - 1]);
        let right_boundary = i + 5 >= bytes.len() || !is_word_byte(bytes[i + 5]);
        if is_t
            && left_boundary
            && right_boundary
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4].is_ascii_digit()
        {
            found.push(format!(
                "T{}{}{}{}",
                bytes[i + 1] as char,
                bytes[i + 2] as char,
                bytes[i + 3] as char,
                bytes[i + 4] as char
            ));
            i += 5;
        } else {
            i += 1;
        }
    }
    found
}

/// Append a technique entry unless `id` was already recorded, keeping
/// first-seen order stable.
fn record_technique(
    seen: &mut Vec<String>,
    techniques: &mut Vec<Value>,
    id: String,
    comment: String,
) {
    if !seen.contains(&id) {
        seen.push(id.clone());
        techniques.push(json!({
            "techniqueID": id,
            "color": "#ff4d5e",
            "comment": comment,
        }));
    }
}

/// The filename for an engagement exported in `format`:
/// `redagent-<goal-slug>-<format>.<ext>`.
pub fn filename(view: &EngagementView, format: ExportFormat) -> String {
    let slug = goal_slug(view);
    let (kind, extension) = match format {
        ExportFormat::Sarif => ("sarif", "sarif"),
        ExportFormat::CycloneDx => ("cyclonedx", "cdx.json"),
        ExportFormat::MitreNavigator => ("mitre", "mitre.json"),
        ExportFormat::Markdown => ("markdown", "md"),
        ExportFormat::Html => ("html", "html"),
    };
    format!("redagent-{slug}-{kind}.{extension}")
}

/// The MIME content type for `format`.
pub fn content_type(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Sarif => "application/sarif+json",
        ExportFormat::CycloneDx => "application/vnd.cyclonedx+json",
        ExportFormat::MitreNavigator => "application/json",
        ExportFormat::Markdown => "text/markdown",
        ExportFormat::Html => "text/html; charset=utf-8",
    }
}

/// Render `view` in `format`. JSON formats are returned pretty-printed.
pub fn export(view: &EngagementView, format: ExportFormat) -> anyhow::Result<String> {
    match format {
        ExportFormat::Markdown => Ok(redagent_core::render_markdown(view)),
        ExportFormat::Sarif => to_json(&to_sarif(view)),
        ExportFormat::CycloneDx => to_json(&to_cyclonedx(view)),
        ExportFormat::MitreNavigator => to_json(&to_mitre(view)),
        ExportFormat::Html => export_html(view),
    }
}

fn to_json(value: &Value) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

fn to_sarif(view: &EngagementView) -> Value {
    let goal = view.goal.clone().unwrap_or_default();
    let redhands_version = view.redhands_version.clone().unwrap_or_default();
    let properties = json!({ "goal": goal, "redhands_version": redhands_version });

    // Several findings can sanitize to the same rule id. SARIF requires rule
    // ids to be unique within a run, so emit each rule once while keeping one
    // result per finding (results may reference the same rule).
    let mut seen_rule_ids = std::collections::HashSet::new();
    let rules: Vec<Value> = view
        .findings
        .iter()
        .filter_map(|finding| {
            let id = sanitize_rule_id(&finding.title);
            if !seen_rule_ids.insert(id.clone()) {
                return None;
            }
            Some(json!({
                "id": id.clone(),
                "name": id,
                "shortDescription": { "text": finding.title },
            }))
        })
        .collect();

    let results: Vec<Value> = view
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": sanitize_rule_id(&finding.title),
                "level": sarif_level(&finding.severity),
                "message": { "text": finding.title },
                "locations": [{
                    "logicalLocations": [{
                        "name": format!("event-#{}", finding.evidence_seq),
                    }],
                }],
                "properties": properties.clone(),
            })
        })
        .collect();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RedAgent",
                    "version": "0.3.0",
                    "rules": rules,
                },
            },
            "results": results,
            "properties": properties,
        }],
    })
}

fn to_cyclonedx(view: &EngagementView) -> Value {
    let vulnerabilities: Vec<Value> = view
        .findings
        .iter()
        .map(|finding| {
            json!({
                "id": finding.id.clone(),
                "description": format!("{} ({})", finding.title, finding.severity),
                "recommendation": format!("review evidence event #{}", finding.evidence_seq),
            })
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number(view),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "RedAgent engagement",
            },
        },
        "vulnerabilities": vulnerabilities,
    })
}

fn to_mitre(view: &EngagementView) -> Value {
    // Record `(technique id, comment)` pairs in first-seen order. Finding
    // titles are scanned first so the comment is the title that mentioned the
    // technique; tool output is scanned afterwards.
    let mut seen: Vec<String> = Vec::new();
    let mut techniques: Vec<Value> = Vec::new();

    for finding in &view.findings {
        for id in scan_technique_ids(&finding.title) {
            record_technique(&mut seen, &mut techniques, id, finding.title.clone());
        }
    }

    let tool_comment = view
        .findings
        .first()
        .map(|finding| finding.title.clone())
        .unwrap_or_else(|| "tool output".to_string());
    for call in &view.tool_calls {
        for id in scan_technique_ids(&call.content) {
            record_technique(&mut seen, &mut techniques, id, tool_comment.clone());
        }
    }

    let name = view
        .goal
        .clone()
        .unwrap_or_else(|| "RedAgent engagement".to_string());
    let mut layer = json!({
        "name": name,
        "versions": { "navigator": "5.1.0" },
        "domain": "attack-enterprise",
        "showTactics": true,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff4d5e", "#ffd166"],
            "min": 0,
            "max": 1,
        },
    });

    if seen.is_empty() {
        layer["showSubtechniques"] = json!(false);
    }

    layer
}

/// Inline stylesheet for [`export_html`]. Kept static so the report has no
/// external assets and needs no network access to render.
const HTML_CSS: &str = r#"
:root {
  --bg: #0b1020;
  --panel: #151d30;
  --accent: #ff4d5e;
  --text: #e7ebf5;
  --muted: #9aa5bd;
  --line: #27324d;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 20px 48px; }
.hero {
  background: var(--panel);
  border: 1px solid var(--line);
  border-top: 4px solid var(--accent);
  border-radius: 12px;
  padding: 24px;
}
h1 { margin: 0 0 4px; font-size: 26px; letter-spacing: .3px; }
.brand {
  margin: 0 0 20px; color: var(--accent); font-weight: 600;
  font-size: 13px; text-transform: uppercase; letter-spacing: 1.2px;
}
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin: 0; }
.meta > div { min-width: 0; }
dt { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .8px; }
dd { margin: 4px 0 0; overflow-wrap: anywhere; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin: 20px 0 32px; }
.kpi { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
.kpi .value { font-size: 30px; font-weight: 700; color: var(--accent); }
.kpi .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .8px; }
section:not(.kpis) { margin: 0 0 32px; }
h2 { font-size: 18px; border-left: 3px solid var(--accent); padding-left: 10px; margin: 0 0 14px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .6px; }
tr:last-child td { border-bottom: 0; }
.sev-critical, .sev-high { color: #ff6b7a; font-weight: 700; }
.sev-medium { color: #ffd166; font-weight: 600; }
.sev-low, .sev-info { color: #7fd1a6; }
ul { list-style: none; margin: 0; padding: 0; }
ul li { padding: 8px 0; border-bottom: 1px solid var(--line); }
ul li:last-child { border-bottom: 0; }
.muted { color: var(--muted); }
pre {
  margin: 0 0 14px; padding: 14px; background: #0d1426;
  border: 1px solid var(--line); border-radius: 8px;
  overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere;
  font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
pre:last-child { margin-bottom: 0; }
.tool-name { color: var(--accent); }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip {
  display: inline-block; background: rgba(255, 77, 94, .12);
  border: 1px solid var(--accent); color: #ff8d99; border-radius: 999px;
  padding: 4px 12px; font: 600 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
footer { margin-top: 40px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
footer p { margin: 4px 0; }
@media (max-width: 600px) {
  .wrap { padding: 20px 14px 36px; }
  .meta, .kpis { grid-template-columns: 1fr; }
}
"#;

/// The human-readable engagement status, also used by the Markdown renderer.
fn status_label(view: &EngagementView) -> String {
    if view.completed {
        "completed".to_string()
    } else if let Some(reason) = &view.abort_reason {
        format!("aborted — {reason}")
    } else {
        "in progress".to_string()
    }
}

/// A fixed set of severity CSS classes; unknown severities get no class.
fn severity_class(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => "sev-high",
        "medium" => "sev-medium",
        "low" | "info" => "sev-low",
        _ => "",
    }
}

/// Render `view` as a self-contained HTML5 report with inline CSS only.
///
/// There are no scripts, external stylesheets, images or network links. Every
/// string originating from the engagement is passed through [`escape_html`]
/// before being interpolated into the document.
pub fn export_html(view: &EngagementView) -> anyhow::Result<String> {
    let mut out = String::new();

    let goal = escape_html(view.goal.as_deref().unwrap_or("(none)"));
    let version = escape_html(view.redhands_version.as_deref().unwrap_or("(unknown)"));
    let status = escape_html(&status_label(view));

    // Technique chips are derived from finding titles using the existing
    // scanner; keep first-seen order and de-duplicate.
    let mut techniques: Vec<String> = Vec::new();
    for finding in &view.findings {
        for id in scan_technique_ids(&finding.title) {
            if !techniques.contains(&id) {
                techniques.push(id);
            }
        }
    }
    let high_critical = view
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity.to_ascii_lowercase().as_str(),
                "critical" | "high"
            )
        })
        .count();

    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>RedAgent engagement report</title>\n");
    out.push_str("<style>\n");
    out.push_str(HTML_CSS);
    out.push_str("\n</style>\n</head>\n<body>\n<div class=\"wrap\">\n");

    // Header.
    out.push_str("<header class=\"hero\">\n");
    out.push_str("<h1>RedAgent engagement report</h1>\n");
    out.push_str("<p class=\"brand\">generated by RedAgent</p>\n");
    out.push_str("<dl class=\"meta\">\n");
    writeln!(out, "<div><dt>Goal</dt><dd>{goal}</dd></div>")?;
    writeln!(
        out,
        "<div><dt>RedHands version</dt><dd>{version}</dd></div>"
    )?;
    writeln!(out, "<div><dt>Status</dt><dd>{status}</dd></div>")?;
    out.push_str("<div><dt>Generated</dt><dd>generated by RedAgent</dd></div>\n");
    out.push_str("</dl>\n");
    if let Some(reason) = &view.budget_exhausted {
        writeln!(
            out,
            "<p class=\"muted\">Budget exhausted: {}</p>",
            escape_html(reason)
        )?;
    }
    out.push_str("</header>\n");

    // KPI cards.
    out.push_str("<section class=\"kpis\">\n");
    let kpis = [
        (view.findings.len(), "Findings"),
        (high_critical, "High / critical"),
        (view.tool_calls.len(), "Tool calls"),
        (view.verifications.len() + view.retests.len(), "Verdicts"),
        (techniques.len(), "Techniques"),
    ];
    for (value, label) in kpis {
        writeln!(
            out,
            "<div class=\"kpi\"><div class=\"value\">{value}</div><div class=\"label\">{label}</div></div>"
        )?;
    }
    out.push_str("</section>\n");

    // Findings table.
    out.push_str("<section>\n<h2>Findings</h2>\n<div class=\"card\">\n");
    if view.findings.is_empty() {
        out.push_str("<p class=\"muted\">No findings recorded.</p>\n");
    } else {
        out.push_str("<table>\n<thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Evidence</th></tr></thead>\n<tbody>\n");
        for finding in &view.findings {
            writeln!(
                out,
                "<tr><td>{}</td><td>{}</td><td class=\"sev-{}\">{}</td><td>#{}</td></tr>",
                escape_html(&finding.id),
                escape_html(&finding.title),
                severity_class(&finding.severity),
                escape_html(&finding.severity),
                finding.evidence_seq
            )?;
        }
        out.push_str("</tbody>\n</table>\n");
    }
    out.push_str("</div>\n</section>\n");

    // Verification list.
    out.push_str("<section>\n<h2>Verification</h2>\n<div class=\"card\">\n");
    if view.verifications.is_empty() {
        out.push_str("<p class=\"muted\">No verifications recorded.</p>\n");
    } else {
        out.push_str("<ul>\n");
        for verification in &view.verifications {
            writeln!(
                out,
                "<li><strong>{}</strong> → {} <span class=\"muted\">· evidence #{}</span></li>",
                escape_html(&verification.finding_id),
                escape_html(&verification.verdict),
                verification.evidence_seq
            )?;
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</div>\n</section>\n");

    // Retest list.
    out.push_str("<section>\n<h2>Retests</h2>\n<div class=\"card\">\n");
    if view.retests.is_empty() {
        out.push_str("<p class=\"muted\">No retests recorded.</p>\n");
    } else {
        out.push_str("<ul>\n");
        for retest in &view.retests {
            writeln!(
                out,
                "<li><strong>{}</strong> → {} <span class=\"muted\">· evidence #{}</span></li>",
                escape_html(&retest.finding_id),
                escape_html(&retest.verdict),
                retest.evidence_seq
            )?;
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</div>\n</section>\n");

    // Tool evidence, one <pre> block per call.
    out.push_str("<section>\n<h2>Tool evidence</h2>\n<div class=\"card\">\n");
    if view.tool_calls.is_empty() {
        out.push_str("<p class=\"muted\">No tool calls recorded.</p>\n");
    } else {
        for call in &view.tool_calls {
            out.push_str("<pre>");
            writeln!(
                out,
                "<span class=\"tool-name\">{}</span> — intent {}{}",
                escape_html(&call.tool),
                escape_html(&call.intent_id),
                if call.is_error { " (error)" } else { "" }
            )?;
            out.push_str(&escape_html(&call.content));
            out.push_str("</pre>\n");
        }
    }
    out.push_str("</div>\n</section>\n");

    // MITRE Navigator technique chips.
    out.push_str("<section>\n<h2>MITRE Navigator techniques</h2>\n<div class=\"card\">\n");
    if techniques.is_empty() {
        out.push_str("<p class=\"muted\">No MITRE ATT&amp;CK technique IDs detected in finding titles.</p>\n");
    } else {
        out.push_str("<div class=\"chips\">\n");
        for id in &techniques {
            writeln!(out, "<span class=\"chip\">{}</span>", escape_html(id))?;
        }
        out.push_str("</div>\n");
    }
    out.push_str("</div>\n</section>\n");

    // Footer.
    out.push_str("<footer>\n");
    out.push_str("<p>RedAgent engagement report · generated by RedAgent · MIT licensed.</p>\n");
    out.push_str("<p>Authorization notice: this report documents authorized security testing only. Use of these findings outside the authorized scope is prohibited.</p>\n");
    out.push_str("</footer>\n");

    out.push_str("</div>\n</body>\n</html>\n");
    Ok(out)
}

/// Internal pairing of findings between two engagement snapshots.
struct StillOpen<'a> {
    old: &'a redagent_core::projections::FindingView,
    current: &'a redagent_core::projections::FindingView,
    old_verdict: Option<&'a str>,
    new_verdict: Option<&'a str>,
}

struct Diff<'a> {
    fixed: Vec<&'a redagent_core::projections::FindingView>,
    still_open: Vec<StillOpen<'a>>,
    new: Vec<&'a redagent_core::projections::FindingView>,
}

/// Trim and lowercase a title for the fallback matching pass.
fn normalize_title(title: &str) -> String {
    title.trim().to_lowercase()
}

/// The most recent verdict recorded for a finding (`retests` take precedence
/// over `verifications`), if any.
fn latest_verdict<'a>(view: &'a EngagementView, finding_id: &str) -> Option<&'a str> {
    view.retests
        .iter()
        .rev()
        .find(|r| r.finding_id == finding_id)
        .map(|r| r.verdict.as_str())
        .or_else(|| {
            view.verifications
                .iter()
                .rev()
                .find(|v| v.finding_id == finding_id)
                .map(|v| v.verdict.as_str())
        })
}

/// Match findings by id first, then by normalized title, and classify them.
/// All result lists are sorted by id (with stable tie-breakers).
fn build_diff<'a>(old: &'a EngagementView, new: &'a EngagementView) -> Diff<'a> {
    let old_findings = &old.findings;
    let new_findings = &new.findings;

    let mut old_matched = vec![false; old_findings.len()];
    let mut new_matched = vec![false; new_findings.len()];
    let mut pairs: Vec<(usize, usize)> = Vec::new();

    // Pass 1: exact id.
    let mut by_id: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, finding) in new_findings.iter().enumerate() {
        by_id.entry(finding.id.as_str()).or_default().push(i);
    }
    for (oi, old_finding) in old_findings.iter().enumerate() {
        if let Some(indices) = by_id.get(old_finding.id.as_str()) {
            if let Some(&ni) = indices.iter().find(|&&ni| !new_matched[ni]) {
                old_matched[oi] = true;
                new_matched[ni] = true;
                pairs.push((oi, ni));
            }
        }
    }

    // Pass 2: normalized title, for findings without an id match.
    let mut by_title: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, finding) in new_findings.iter().enumerate() {
        if !new_matched[i] {
            by_title
                .entry(normalize_title(&finding.title))
                .or_default()
                .push(i);
        }
    }
    for (oi, old_finding) in old_findings.iter().enumerate() {
        if old_matched[oi] {
            continue;
        }
        if let Some(indices) = by_title.get(&normalize_title(&old_finding.title)) {
            if let Some(&ni) = indices.iter().find(|&&ni| !new_matched[ni]) {
                old_matched[oi] = true;
                new_matched[ni] = true;
                pairs.push((oi, ni));
            }
        }
    }

    let mut diff = Diff {
        fixed: Vec::new(),
        still_open: Vec::new(),
        new: Vec::new(),
    };
    for (oi, ni) in pairs {
        let old_finding = &old_findings[oi];
        let current = &new_findings[ni];
        diff.still_open.push(StillOpen {
            old: old_finding,
            current,
            old_verdict: latest_verdict(old, &old_finding.id),
            new_verdict: latest_verdict(new, &current.id),
        });
    }
    for (i, finding) in old_findings.iter().enumerate() {
        if !old_matched[i] {
            diff.fixed.push(finding);
        }
    }
    for (i, finding) in new_findings.iter().enumerate() {
        if !new_matched[i] {
            diff.new.push(finding);
        }
    }

    diff.fixed.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.evidence_seq.cmp(&b.evidence_seq))
    });
    diff.still_open.sort_by(|a, b| {
        a.current
            .id
            .cmp(&b.current.id)
            .then_with(|| a.current.title.cmp(&b.current.title))
            .then_with(|| a.current.evidence_seq.cmp(&b.current.evidence_seq))
    });
    diff.new.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.evidence_seq.cmp(&b.evidence_seq))
    });

    diff
}

fn finding_entry(finding: &redagent_core::projections::FindingView) -> Value {
    json!({
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "evidence_seq": finding.evidence_seq,
    })
}

/// Compare two engagement snapshots and report fixed, still-open and new
/// findings in `format`.
///
/// Findings are matched by `id` first; unmatched findings fall back to a
/// case-insensitive, trimmed title comparison. Both `fixed` and `new` use the
/// finding's own data, while `still_open` reflects the current (`new`) finding
/// and Markdown additionally annotates severity and verdict changes.
pub fn diff_retest(
    old: &EngagementView,
    new: &EngagementView,
    format: DiffFormat,
) -> anyhow::Result<String> {
    let diff = build_diff(old, new);

    match format {
        DiffFormat::Json => {
            let fixed: Vec<Value> = diff.fixed.iter().copied().map(finding_entry).collect();
            let still_open: Vec<Value> = diff
                .still_open
                .iter()
                .map(|pair| finding_entry(pair.current))
                .collect();
            let added: Vec<Value> = diff.new.iter().copied().map(finding_entry).collect();
            to_json(&json!({
                "fixed": fixed,
                "still_open": still_open,
                "new": added,
            }))
        }
        DiffFormat::Markdown => {
            let mut out = String::new();
            out.push_str("# Retest diff\n\n");

            out.push_str(&format!("## Fixed ({})\n\n", diff.fixed.len()));
            if diff.fixed.is_empty() {
                out.push_str("_none_\n\n");
            } else {
                for finding in &diff.fixed {
                    writeln!(
                        out,
                        "- `{}` — {} (severity: {}, evidence #{})",
                        finding.id, finding.title, finding.severity, finding.evidence_seq
                    )?;
                }
                out.push('\n');
            }

            out.push_str(&format!("## Still open ({})\n\n", diff.still_open.len()));
            if diff.still_open.is_empty() {
                out.push_str("_none_\n\n");
            } else {
                for pair in &diff.still_open {
                    let mut line = format!(
                        "- `{}` — {} (severity: {}",
                        pair.current.id, pair.current.title, pair.current.severity
                    );
                    if !pair
                        .old
                        .severity
                        .eq_ignore_ascii_case(&pair.current.severity)
                    {
                        line.push_str(&format!(", was {}", pair.old.severity));
                    }
                    line.push_str(&format!(", evidence #{})", pair.current.evidence_seq));
                    if let (Some(old_verdict), Some(new_verdict)) =
                        (pair.old_verdict, pair.new_verdict)
                    {
                        if old_verdict != new_verdict {
                            line.push_str(&format!(" [verdict: {old_verdict} → {new_verdict}]"));
                        }
                    }
                    out.push_str(&line);
                    out.push('\n');
                }
                out.push('\n');
            }

            out.push_str(&format!("## New ({})\n\n", diff.new.len()));
            if diff.new.is_empty() {
                out.push_str("_none_\n\n");
            } else {
                for finding in &diff.new {
                    writeln!(
                        out,
                        "- `{}` — {} (severity: {}, evidence #{})",
                        finding.id, finding.title, finding.severity, finding.evidence_seq
                    )?;
                }
                out.push('\n');
            }

            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redagent_core::projections::{FindingView, RetestView, ToolCallView, VerificationView};
    use std::str::FromStr;

    fn sample_view() -> EngagementView {
        EngagementView {
            goal: Some("Probe the Target!".to_string()),
            redhands_version: Some("v7.1".to_string()),
            findings: vec![
                FindingView {
                    id: "f-1".to_string(),
                    title: "Command execution via T1059".to_string(),
                    severity: "critical".to_string(),
                    evidence_seq: 4,
                },
                FindingView {
                    id: "f-2".to_string(),
                    title: "Privilege escalation".to_string(),
                    severity: "medium".to_string(),
                    evidence_seq: 5,
                },
                FindingView {
                    id: "f-3".to_string(),
                    title: "Info leak".to_string(),
                    severity: "low".to_string(),
                    evidence_seq: 9,
                },
                FindingView {
                    id: "f-4".to_string(),
                    title: "Another high".to_string(),
                    severity: "HIGH".to_string(),
                    evidence_seq: 12,
                },
            ],
            tool_calls: vec![ToolCallView {
                intent_id: "i-1".to_string(),
                tool: "redhands_scan".to_string(),
                content: "output referenced T1059 twice".to_string(),
                is_error: false,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn from_str_accepts_all_documented_spellings_case_insensitively() {
        assert_eq!(
            ExportFormat::from_str("sarif").unwrap(),
            ExportFormat::Sarif
        );
        assert_eq!(
            ExportFormat::from_str("SARIF").unwrap(),
            ExportFormat::Sarif
        );
        assert_eq!(
            ExportFormat::from_str("cyclonedx").unwrap(),
            ExportFormat::CycloneDx
        );
        assert_eq!(
            ExportFormat::from_str("Cyclone-DX").unwrap(),
            ExportFormat::CycloneDx
        );
        assert_eq!(
            ExportFormat::from_str("mitre").unwrap(),
            ExportFormat::MitreNavigator
        );
        assert_eq!(
            ExportFormat::from_str("MITRE-Navigator").unwrap(),
            ExportFormat::MitreNavigator
        );
        assert_eq!(
            ExportFormat::from_str("markdown").unwrap(),
            ExportFormat::Markdown
        );
        assert_eq!(
            ExportFormat::from_str("MD").unwrap(),
            ExportFormat::Markdown
        );
        assert_eq!(ExportFormat::from_str("html").unwrap(), ExportFormat::Html);
        assert_eq!(ExportFormat::from_str("HTML").unwrap(), ExportFormat::Html);
    }

    #[test]
    fn from_str_rejects_unknown_formats() {
        for input in ["", "pdf", "sarifx", "cyclone", "navigator", "txt"] {
            assert!(
                ExportFormat::from_str(input).is_err(),
                "expected `{input}` to be rejected"
            );
        }
    }

    #[test]
    fn content_types_are_stable() {
        assert_eq!(content_type(ExportFormat::Sarif), "application/sarif+json");
        assert_eq!(
            content_type(ExportFormat::CycloneDx),
            "application/vnd.cyclonedx+json"
        );
        assert_eq!(
            content_type(ExportFormat::MitreNavigator),
            "application/json"
        );
        assert_eq!(content_type(ExportFormat::Markdown), "text/markdown");
        assert_eq!(content_type(ExportFormat::Html), "text/html; charset=utf-8");
    }

    #[test]
    fn filenames_are_safe_and_use_format_extensions() {
        let view = sample_view();
        assert_eq!(
            filename(&view, ExportFormat::Sarif),
            "redagent-probe-the-target-sarif.sarif"
        );
        assert_eq!(
            filename(&view, ExportFormat::CycloneDx),
            "redagent-probe-the-target-cyclonedx.cdx.json"
        );
        assert_eq!(
            filename(&view, ExportFormat::MitreNavigator),
            "redagent-probe-the-target-mitre.mitre.json"
        );
        assert_eq!(
            filename(&view, ExportFormat::Markdown),
            "redagent-probe-the-target-markdown.md"
        );
        assert_eq!(
            filename(&view, ExportFormat::Html),
            "redagent-probe-the-target-html.html"
        );

        // Every character is lowercase alphanumeric, '-' or '.' (extensions).
        for format in [
            ExportFormat::Sarif,
            ExportFormat::CycloneDx,
            ExportFormat::MitreNavigator,
            ExportFormat::Markdown,
            ExportFormat::Html,
        ] {
            let name = filename(&view, format);
            assert!(name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'));
        }
    }

    #[test]
    fn filename_uses_fallback_and_caps_slug_length() {
        let mut view = EngagementView::default();
        assert!(view.goal.is_none());
        assert_eq!(
            filename(&view, ExportFormat::Sarif),
            "redagent-engagement-sarif.sarif"
        );

        view.goal = Some("!!! --- ///".to_string());
        assert_eq!(
            filename(&view, ExportFormat::Markdown),
            "redagent-engagement-markdown.md"
        );

        view.goal = Some("a".repeat(80));
        let name = filename(&view, ExportFormat::Sarif);
        assert_eq!(name, format!("redagent-{}-sarif.sarif", "a".repeat(40)));
    }

    #[test]
    fn sarif_export_has_required_structure() {
        let doc: Value =
            serde_json::from_str(&export(&sample_view(), ExportFormat::Sarif).unwrap()).unwrap();
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(
            doc["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );

        let run = &doc["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "RedAgent");
        assert_eq!(run["tool"]["driver"]["version"], "0.3.0");
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 4);
        assert_eq!(run["properties"]["goal"], "Probe the Target!");
        assert_eq!(run["properties"]["redhands_version"], "v7.1");

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0]["ruleId"], "command-execution-via-t1059");
        assert_eq!(results[0]["message"]["text"], "Command execution via T1059");
        assert_eq!(
            results[0]["locations"][0]["logicalLocations"][0]["name"],
            "event-#4"
        );
        assert_eq!(results[0]["properties"]["goal"], "Probe the Target!");
        assert_eq!(results[0]["properties"]["redhands_version"], "v7.1");

        let levels: Vec<&str> = results
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert_eq!(levels, vec!["error", "warning", "note", "error"]);

        // Rule ids must match their result's ruleId.
        let rule_ids: Vec<&str> = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        for result in results {
            let id = result["ruleId"].as_str().unwrap();
            assert!(rule_ids.contains(&id));
        }
    }

    #[test]
    fn cyclonedx_export_has_required_structure_and_stable_serial() {
        let view = sample_view();
        let doc: Value =
            serde_json::from_str(&export(&view, ExportFormat::CycloneDx).unwrap()).unwrap();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["metadata"]["component"]["name"], "RedAgent engagement");

        let serial = doc["serialNumber"].as_str().unwrap();
        assert!(serial.starts_with("urn:uuid:"));
        let uuid = &serial["urn:uuid:".len()..];
        assert_eq!(uuid.len(), 36);
        for (i, ch) in uuid.chars().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                assert_eq!(ch, '-');
            } else {
                assert!(ch.is_ascii_hexdigit());
            }
        }

        // Deterministic for the same input.
        assert_eq!(
            export(&view, ExportFormat::CycloneDx).unwrap(),
            export(&view, ExportFormat::CycloneDx).unwrap()
        );
        // Sensitive to the goal.
        let mut other = sample_view();
        other.goal = Some("Different goal".to_string());
        let other_doc: Value =
            serde_json::from_str(&export(&other, ExportFormat::CycloneDx).unwrap()).unwrap();
        assert_ne!(doc["serialNumber"], other_doc["serialNumber"]);

        let vulns = doc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 4);
        assert_eq!(vulns[0]["id"], "f-1");
        assert_eq!(
            vulns[0]["description"],
            "Command execution via T1059 (critical)"
        );
        assert_eq!(vulns[0]["recommendation"], "review evidence event #4");
    }

    #[test]
    fn mitre_export_deduplicates_techniques() {
        let doc: Value =
            serde_json::from_str(&export(&sample_view(), ExportFormat::MitreNavigator).unwrap())
                .unwrap();
        assert_eq!(doc["name"], "Probe the Target!");
        assert_eq!(doc["versions"]["navigator"], "5.1.0");
        assert_eq!(doc["domain"], "attack-enterprise");
        assert_eq!(doc["showTactics"], true);
        assert_eq!(doc["gradient"]["colors"][0], "#ff4d5e");
        assert_eq!(doc["gradient"]["colors"][1], "#ffd166");
        assert_eq!(doc["gradient"]["min"], 0);
        assert_eq!(doc["gradient"]["max"], 1);

        let techniques = doc["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), 1);
        assert_eq!(techniques[0]["techniqueID"], "T1059");
        assert_eq!(techniques[0]["color"], "#ff4d5e");
        assert_eq!(techniques[0]["comment"], "Command execution via T1059");
        assert_eq!(
            techniques
                .iter()
                .filter(|t| t["techniqueID"] == "T1059")
                .count(),
            1
        );
    }

    #[test]
    fn mitre_export_without_techniques_does_not_invent_any() {
        let view = EngagementView {
            goal: Some("No techniques".to_string()),
            findings: vec![FindingView {
                id: "f-1".to_string(),
                title: "Plain finding".to_string(),
                severity: "info".to_string(),
                evidence_seq: 1,
            }],
            tool_calls: vec![ToolCallView {
                intent_id: "i-1".to_string(),
                tool: "tool".to_string(),
                content: "nothing interesting here".to_string(),
                is_error: false,
            }],
            ..Default::default()
        };
        let doc: Value =
            serde_json::from_str(&export(&view, ExportFormat::MitreNavigator).unwrap()).unwrap();
        assert_eq!(doc["techniques"].as_array().unwrap().len(), 0);
        assert_eq!(doc["showSubtechniques"], false);
    }

    #[test]
    fn markdown_export_delegates_to_core() {
        let view = sample_view();
        let rendered = export(&view, ExportFormat::Markdown).unwrap();
        assert_eq!(rendered, redagent_core::render_markdown(&view));
        assert!(rendered.contains("Probe the Target!"));
        assert!(rendered.contains("Command execution via T1059"));
    }

    #[test]
    fn scanner_normalizes_lowercase_and_ignores_wrong_length_ids() {
        assert_eq!(
            scan_technique_ids("t1059 and T1234 and T12 and T12345"),
            vec!["T1059", "T1234"]
        );
        assert!(scan_technique_ids("no techniques here").is_empty());
    }

    /// A technique id must sit on ASCII word boundaries: a preceding or
    /// following letter/digit/underscore means it is part of a larger token
    /// (e.g. `XT1059`, `T10599`, `AT1059x`) and must not be reported.
    #[test]
    fn scanner_requires_word_boundaries() {
        let cases: &[(&str, &[&str])] = &[
            ("T1059", &["T1059"]),
            ("(T1059)", &["T1059"]),
            ("T1059.003", &["T1059"]),
            ("CWE-T1059", &["T1059"]),
            ("t1059", &["T1059"]),
            ("XT1059", &[]),
            ("T10599", &[]),
            ("AT1059x", &[]),
            ("_T1059", &[]),
            ("T1059_x", &[]),
            ("1T1059", &[]),
            ("T10591", &[]),
            ("see XT1059, then T1059 and AT1059x", &["T1059"]),
        ];
        for (text, expected) in cases {
            let got = scan_technique_ids(text);
            let got: Vec<&str> = got.iter().map(String::as_str).collect();
            assert_eq!(got, *expected, "input: {text}");
        }
    }

    #[test]
    fn sarif_deduplicates_rules_but_keeps_all_results() {
        let view = EngagementView {
            findings: vec![
                FindingView {
                    id: "f-1".to_string(),
                    title: "Access denied!".to_string(),
                    severity: "high".to_string(),
                    evidence_seq: 1,
                },
                FindingView {
                    id: "f-2".to_string(),
                    title: "Access denied?".to_string(),
                    severity: "low".to_string(),
                    evidence_seq: 2,
                },
            ],
            ..Default::default()
        };

        let doc: Value =
            serde_json::from_str(&export(&view, ExportFormat::Sarif).unwrap()).unwrap();
        let run = &doc["runs"][0];

        // Both titles sanitize to `access-denied`; the rule table must contain
        // a single entry while both results remain.
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "duplicate rule ids in {rules:?}");
        assert_eq!(rules[0]["id"], "access-denied");

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "access-denied");
        assert_eq!(results[1]["ruleId"], "access-denied");
        assert_eq!(results[0]["message"]["text"], "Access denied!");
        assert_eq!(results[1]["message"]["text"], "Access denied?");
    }

    #[test]
    fn cyclonedx_serial_disambiguates_otherwise_identical_engagements() {
        let base = || EngagementView {
            goal: Some("Same goal".to_string()),
            findings: vec![FindingView {
                id: "f-1".to_string(),
                title: "Finding".to_string(),
                severity: "high".to_string(),
                evidence_seq: 3,
            }],
            ..Default::default()
        };

        let serial = |view: &EngagementView| {
            let doc: Value =
                serde_json::from_str(&export(view, ExportFormat::CycloneDx).unwrap()).unwrap();
            doc["serialNumber"].as_str().unwrap().to_string()
        };

        let plain = base();
        let mut verified = base();
        verified.verifications.push(VerificationView {
            finding_id: "f-1".to_string(),
            verdict: "confirmed".to_string(),
            evidence_seq: 4,
        });
        let mut retested = base();
        retested.retests.push(RetestView {
            finding_id: "f-1".to_string(),
            verdict: "fixed".to_string(),
            evidence_seq: 5,
        });
        let mut versioned = base();
        versioned.redhands_version = Some("v9.9".to_string());

        let plain_serial = serial(&plain);
        assert_ne!(plain_serial, serial(&verified));
        assert_ne!(plain_serial, serial(&retested));
        assert_ne!(plain_serial, serial(&versioned));
    }

    #[test]
    fn exports_handle_empty_findings_and_invalid_severities() {
        let empty = EngagementView::default();
        for format in [
            ExportFormat::Sarif,
            ExportFormat::CycloneDx,
            ExportFormat::MitreNavigator,
        ] {
            let doc: Value = serde_json::from_str(&export(&empty, format).unwrap()).unwrap();
            assert!(doc.is_object(), "{format:?}");
        }
        let sarif: Value =
            serde_json::from_str(&export(&empty, ExportFormat::Sarif).unwrap()).unwrap();
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        let view = EngagementView {
            findings: vec![FindingView {
                id: "f-1".to_string(),
                title: "Odd severity".to_string(),
                severity: "not-a-severity".to_string(),
                evidence_seq: 1,
            }],
            ..Default::default()
        };
        let sarif: Value =
            serde_json::from_str(&export(&view, ExportFormat::Sarif).unwrap()).unwrap();
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "note");
    }

    // ---- HTML export ----------------------------------------------------

    #[test]
    fn escape_html_escapes_all_special_characters() {
        assert_eq!(escape_html(""), "");
        assert_eq!(escape_html("plain text"), "plain text");
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_html("it's"), "it&#39;s");
        assert_eq!(
            escape_html("<a href=\"x&y\">it's</a>"),
            "&lt;a href=&quot;x&amp;y&quot;&gt;it&#39;s&lt;/a&gt;"
        );
        // Entities introduced by escaping are not escaped a second time.
        assert_eq!(escape_html("&amp;"), "&amp;amp;");
    }

    #[test]
    fn html_export_contains_all_required_sections() {
        let view = EngagementView {
            goal: Some("Probe & Pwn".to_string()),
            redhands_version: Some("v7.1".to_string()),
            findings: vec![FindingView {
                id: "f-1".to_string(),
                title: "Command execution via T1059".to_string(),
                severity: "critical".to_string(),
                evidence_seq: 4,
            }],
            tool_calls: vec![ToolCallView {
                intent_id: "i-1".to_string(),
                tool: "redhands_scan".to_string(),
                content: "output <b>bold</b> & more".to_string(),
                is_error: true,
            }],
            verifications: vec![VerificationView {
                finding_id: "f-1".to_string(),
                verdict: "confirmed".to_string(),
                evidence_seq: 7,
            }],
            retests: vec![RetestView {
                finding_id: "f-1".to_string(),
                verdict: "fixed".to_string(),
                evidence_seq: 9,
            }],
            completed: true,
            ..Default::default()
        };

        let html = export_html(&view).unwrap();
        assert!(html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("<style>") && html.contains("</style>"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("src=\"http") && !html.contains("href=\"http"));

        // Dark RedAgent theme.
        assert!(html.contains("#0b1020"));
        assert!(html.contains("#151d30"));
        assert!(html.contains("#ff4d5e"));
        // Responsive layout.
        assert!(html.contains("viewport"));
        assert!(html.contains("@media"));

        // Header.
        assert!(html.contains("RedAgent engagement report"));
        assert!(html.contains("generated by RedAgent"));
        assert!(html.contains("Probe &amp; Pwn"));
        assert!(html.contains("v7.1"));
        assert!(html.contains("completed"));

        // KPI cards + findings table.
        assert!(html.contains("class=\"kpis\""));
        assert!(html.contains("class=\"kpi\""));
        assert!(html.contains("<th>ID</th><th>Title</th><th>Severity</th><th>Evidence</th>"));
        assert!(html.contains("Command execution via T1059"));
        assert!(html.contains("sev-high"));

        // Verification / retest lists.
        assert!(html.contains("<h2>Verification</h2>"));
        assert!(html.contains("confirmed"));
        assert!(html.contains("<h2>Retests</h2>"));
        assert!(html.contains("fixed"));

        // Tool evidence in <pre> blocks, with escaped output.
        assert!(html.contains("<h2>Tool evidence</h2>"));
        assert!(html.contains("<pre>"));
        assert!(html.contains("redhands_scan"));
        assert!(html.contains("(error)"));
        assert!(html.contains("output &lt;b&gt;bold&lt;/b&gt; &amp; more"));

        // MITRE Navigator technique chips from finding titles.
        assert!(html.contains("<h2>MITRE Navigator techniques</h2>"));
        assert!(html.contains("class=\"chip\">T1059</span>"));

        // Footer notice.
        assert!(html.contains("<footer>"));
        assert!(html.contains("Authorization notice"));
        assert!(html.contains("MIT licensed"));
    }

    #[test]
    fn html_export_escapes_untrusted_strings_everywhere() {
        let view = EngagementView {
            goal: Some("<img src=x onerror=alert(1)>".to_string()),
            redhands_version: Some("\"v1\" & 'beta'".to_string()),
            findings: vec![FindingView {
                id: "<id>".to_string(),
                title: "<script>x</script>".to_string(),
                severity: "\"high\"".to_string(),
                evidence_seq: 1,
            }],
            tool_calls: vec![ToolCallView {
                intent_id: "'i'".to_string(),
                tool: "<tool>".to_string(),
                content: "<&>\"'".to_string(),
                is_error: false,
            }],
            verifications: vec![VerificationView {
                finding_id: "<f>".to_string(),
                verdict: "<v>".to_string(),
                evidence_seq: 2,
            }],
            retests: vec![RetestView {
                finding_id: "<f>".to_string(),
                verdict: "<r>".to_string(),
                evidence_seq: 3,
            }],
            abort_reason: Some("<abort>".to_string()),
            budget_exhausted: Some("<budget>".to_string()),
            ..Default::default()
        };

        let html = export_html(&view).unwrap();
        for raw in [
            "<img",
            "<script>",
            "</script>",
            "<id>",
            "<tool>",
            "<f>",
            "<v>",
            "<r>",
            "<abort>",
            "<budget>",
            "<&>\"'",
        ] {
            assert!(!html.contains(raw), "unescaped user input: {raw}");
        }
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&quot;v1&quot; &amp; &#39;beta&#39;"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(html.contains("&lt;&amp;&gt;&quot;&#39;"));
    }

    #[test]
    fn html_export_handles_empty_view() {
        let html = export_html(&EngagementView::default()).unwrap();
        assert!(html.contains("No findings recorded."));
        assert!(html.contains("No verifications recorded."));
        assert!(html.contains("No retests recorded."));
        assert!(html.contains("No tool calls recorded."));
        assert!(html.contains("No MITRE ATT&amp;CK technique IDs"));
        assert_eq!(
            html.matches("class=\"chip\"").count(),
            0,
            "empty view must not invent techniques"
        );
    }

    #[test]
    fn html_format_dispatches_through_export() {
        let view = sample_view();
        assert_eq!(
            export(&view, ExportFormat::Html).unwrap(),
            export_html(&view).unwrap()
        );
    }

    // ---- Retest diff ----------------------------------------------------

    fn finding(id: &str, title: &str, severity: &str, seq: i64) -> FindingView {
        FindingView {
            id: id.to_string(),
            title: title.to_string(),
            severity: severity.to_string(),
            evidence_seq: seq,
        }
    }

    fn diff_views() -> (EngagementView, EngagementView) {
        let old = EngagementView {
            findings: vec![
                finding("f-1", "Command execution via T1059", "high", 4),
                finding("f-2", "Privilege escalation", "medium", 5),
                finding("f-3", "Info leak", "low", 9),
            ],
            verifications: vec![VerificationView {
                finding_id: "f-1".to_string(),
                verdict: "confirmed".to_string(),
                evidence_seq: 6,
            }],
            ..Default::default()
        };
        let new = EngagementView {
            findings: vec![
                finding("f-1", "Command execution via T1059", "critical", 14),
                finding("f-3", "Info leak", "low", 9),
                finding("f-5", "New issue", "info", 20),
            ],
            verifications: vec![VerificationView {
                finding_id: "f-1".to_string(),
                verdict: "confirmed".to_string(),
                evidence_seq: 6,
            }],
            retests: vec![RetestView {
                finding_id: "f-1".to_string(),
                verdict: "still_reproducible".to_string(),
                evidence_seq: 15,
            }],
            ..Default::default()
        };
        (old, new)
    }

    #[test]
    fn diff_json_reports_fixed_still_open_and_new() {
        let (old, new) = diff_views();
        let doc: Value =
            serde_json::from_str(&diff_retest(&old, &new, DiffFormat::Json).unwrap()).unwrap();

        let fixed = doc["fixed"].as_array().unwrap();
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0]["id"], "f-2");
        assert_eq!(fixed[0]["title"], "Privilege escalation");
        assert_eq!(fixed[0]["severity"], "medium");
        assert_eq!(fixed[0]["evidence_seq"], 5);

        let still_open = doc["still_open"].as_array().unwrap();
        assert_eq!(still_open.len(), 2);
        // Sorted by id, and reflects the new finding's data.
        assert_eq!(still_open[0]["id"], "f-1");
        assert_eq!(still_open[0]["severity"], "critical");
        assert_eq!(still_open[0]["evidence_seq"], 14);
        assert_eq!(still_open[1]["id"], "f-3");

        let added = doc["new"].as_array().unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0]["id"], "f-5");
        assert_eq!(added[0]["title"], "New issue");
        assert_eq!(added[0]["severity"], "info");
        assert_eq!(added[0]["evidence_seq"], 20);
    }

    #[test]
    fn diff_markdown_has_sections_counts_and_changes() {
        let (old, new) = diff_views();
        let md = diff_retest(&old, &new, DiffFormat::Markdown).unwrap();
        assert!(md.starts_with("# Retest diff"));
        assert!(md.contains("## Fixed (1)"));
        assert!(md.contains("- `f-2` — Privilege escalation"));
        assert!(md.contains("## Still open (2)"));
        assert!(md.contains(
            "- `f-1` — Command execution via T1059 (severity: critical, was high, evidence #14)"
        ));
        assert!(md.contains("[verdict: confirmed → still_reproducible]"));
        assert!(md.contains("## New (1)"));
        assert!(md.contains("- `f-5` — New issue"));
        // Sections appear in a stable order.
        assert!(md.find("## Fixed").unwrap() < md.find("## Still open").unwrap());
        assert!(md.find("## Still open").unwrap() < md.find("## New").unwrap());
    }

    #[test]
    fn diff_handles_empty_views_without_panicking() {
        let empty = EngagementView::default();

        let json = diff_retest(&empty, &empty, DiffFormat::Json).unwrap();
        let doc: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["fixed"].as_array().unwrap().len(), 0);
        assert_eq!(doc["still_open"].as_array().unwrap().len(), 0);
        assert_eq!(doc["new"].as_array().unwrap().len(), 0);

        let md = diff_retest(&empty, &empty, DiffFormat::Markdown).unwrap();
        assert!(md.contains("## Fixed (0)"));
        assert!(md.contains("## Still open (0)"));
        assert!(md.contains("## New (0)"));
        assert_eq!(md.matches("_none_").count(), 3);

        // Population from an empty baseline: everything is new.
        let populated = EngagementView {
            findings: vec![finding("f-1", "A", "low", 1)],
            ..Default::default()
        };
        let doc: Value =
            serde_json::from_str(&diff_retest(&empty, &populated, DiffFormat::Json).unwrap())
                .unwrap();
        assert_eq!(doc["new"].as_array().unwrap().len(), 1);
        assert_eq!(doc["fixed"].as_array().unwrap().len(), 0);

        // Removal back to empty: everything is fixed.
        let doc: Value =
            serde_json::from_str(&diff_retest(&populated, &empty, DiffFormat::Json).unwrap())
                .unwrap();
        assert_eq!(doc["fixed"].as_array().unwrap().len(), 1);
        assert_eq!(doc["new"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn diff_matches_by_id_before_normalized_title() {
        // Same id but different titles -> matched by id.
        let old = EngagementView {
            findings: vec![finding("same", "Original title", "high", 1)],
            ..Default::default()
        };
        let new = EngagementView {
            findings: vec![finding("same", "Renamed title", "high", 2)],
            ..Default::default()
        };
        let doc: Value =
            serde_json::from_str(&diff_retest(&old, &new, DiffFormat::Json).unwrap()).unwrap();
        assert_eq!(doc["still_open"].as_array().unwrap().len(), 1);
        assert_eq!(doc["still_open"][0]["title"], "Renamed title");
        assert_eq!(doc["fixed"].as_array().unwrap().len(), 0);
        assert_eq!(doc["new"].as_array().unwrap().len(), 0);

        // Different ids but titles matching after trim + case fold -> matched
        // by normalized title.
        let old = EngagementView {
            findings: vec![finding("old-id", "  SQL Injection ", "high", 1)],
            ..Default::default()
        };
        let new = EngagementView {
            findings: vec![finding("new-id", "sql injection", "high", 2)],
            ..Default::default()
        };
        let doc: Value =
            serde_json::from_str(&diff_retest(&old, &new, DiffFormat::Json).unwrap()).unwrap();
        assert_eq!(doc["fixed"].as_array().unwrap().len(), 0);
        assert_eq!(doc["new"].as_array().unwrap().len(), 0);
        assert_eq!(doc["still_open"].as_array().unwrap().len(), 1);
        assert_eq!(doc["still_open"][0]["id"], "new-id");

        // A title that only matches after case folding is still a match.
        let old = EngagementView {
            findings: vec![finding("a", "T1059 Execution", "high", 1)],
            ..Default::default()
        };
        let new = EngagementView {
            findings: vec![finding("b", "t1059 execution", "high", 2)],
            ..Default::default()
        };
        let doc: Value =
            serde_json::from_str(&diff_retest(&old, &new, DiffFormat::Json).unwrap()).unwrap();
        assert_eq!(doc["still_open"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn diff_json_output_is_deterministic() {
        let (old, new) = diff_views();
        let once = diff_retest(&old, &new, DiffFormat::Json).unwrap();
        let twice = diff_retest(&old, &new, DiffFormat::Json).unwrap();
        assert_eq!(once, twice);

        // Reversing the input order of findings must not change the output.
        let mut reversed = EngagementView {
            findings: vec![
                finding("f-5", "New issue", "info", 20),
                finding("f-3", "Info leak", "low", 9),
                finding("f-1", "Command execution via T1059", "critical", 14),
            ],
            ..Default::default()
        };
        reversed.verifications = new.verifications.clone();
        reversed.retests = new.retests.clone();
        assert_eq!(
            once,
            diff_retest(&old, &reversed, DiffFormat::Json).unwrap()
        );

        // Markdown is deterministic too.
        assert_eq!(
            diff_retest(&old, &new, DiffFormat::Markdown).unwrap(),
            diff_retest(&old, &new, DiffFormat::Markdown).unwrap()
        );
    }
}
