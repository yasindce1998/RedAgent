//! Export an [`EngagementView`] into machine- and human-readable report
//! formats: SARIF 2.1.0, CycloneDX 1.5, a MITRE ATT&CK Navigator layer, and
//! Markdown (delegated to [`redagent_core::render_markdown`]).
//!
//! The crate is intentionally small and dependency-light: hashing uses the
//! workspace `sha2`/`hex` crates and technique detection is a plain character
//! scanner, so no regex engine is required.

use redagent_core::EngagementView;
use serde_json::{json, Value};
use sha2::Digest;

/// A supported report export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Sarif,
    CycloneDx,
    MitreNavigator,
    Markdown,
}

impl std::str::FromStr for ExportFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sarif" => Ok(Self::Sarif),
            "cyclonedx" | "cyclone-dx" => Ok(Self::CycloneDx),
            "mitre" | "mitre-navigator" => Ok(Self::MitreNavigator),
            "markdown" | "md" => Ok(Self::Markdown),
            other => Err(anyhow::anyhow!("unknown export format: {other}")),
        }
    }
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

/// Derive a deterministic `urn:uuid:...` from the goal and findings using
/// SHA-256 (first 32 hex digits, arranged in the UUID 8-4-4-4-12 layout).
fn serial_number(view: &EngagementView) -> String {
    let mut seed = String::new();
    seed.push_str(view.goal.as_deref().unwrap_or(""));
    seed.push('\u{1f}');
    for finding in &view.findings {
        seed.push_str(&finding.id);
        seed.push('\u{1e}');
        seed.push_str(&finding.title);
        seed.push('\u{1e}');
        seed.push_str(&finding.severity);
        seed.push('\u{1e}');
        seed.push_str(&finding.evidence_seq.to_string());
        seed.push('\u{1f}');
    }

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

/// Find MITRE ATT&CK technique IDs (`T` followed by four digits) in `text`.
/// Lowercase `t` is accepted and normalized to uppercase. Results keep the
/// order in which they appear.
fn scan_technique_ids(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i + 4 < bytes.len() {
        let is_t = bytes[i] == b'T' || bytes[i] == b't';
        if is_t
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
    }
}

/// Render `view` in `format`. JSON formats are returned pretty-printed.
pub fn export(view: &EngagementView, format: ExportFormat) -> anyhow::Result<String> {
    match format {
        ExportFormat::Markdown => Ok(redagent_core::render_markdown(view)),
        ExportFormat::Sarif => to_json(&to_sarif(view)),
        ExportFormat::CycloneDx => to_json(&to_cyclonedx(view)),
        ExportFormat::MitreNavigator => to_json(&to_mitre(view)),
    }
}

fn to_json(value: &Value) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

fn to_sarif(view: &EngagementView) -> Value {
    let goal = view.goal.clone().unwrap_or_default();
    let redhands_version = view.redhands_version.clone().unwrap_or_default();
    let properties = json!({ "goal": goal, "redhands_version": redhands_version });

    let rules: Vec<Value> = view
        .findings
        .iter()
        .map(|finding| {
            let id = sanitize_rule_id(&finding.title);
            json!({
                "id": id.clone(),
                "name": id,
                "shortDescription": { "text": finding.title },
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use redagent_core::projections::{FindingView, ToolCallView};
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

        // Every character is lowercase alphanumeric, '-' or '.' (extensions).
        for format in [
            ExportFormat::Sarif,
            ExportFormat::CycloneDx,
            ExportFormat::MitreNavigator,
            ExportFormat::Markdown,
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
    fn scanner_normalizes_lowercase_and_ignores_short_ids() {
        assert_eq!(
            scan_technique_ids("t1059 and T1234 and T12 and T12345"),
            vec!["T1059", "T1234", "T1234"]
        );
        assert!(scan_technique_ids("no techniques here").is_empty());
    }
}
