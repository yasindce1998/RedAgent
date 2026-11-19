use std::path::{Path, PathBuf};
use std::time::Duration;

use redagent_conformance::{render_report, run_conformance, ConformanceReport};
use redagent_contract::{ApprovalSemantics, ToolServerManifest};

fn fake_server() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_fake-tool-server")).to_path_buf()
}

fn run(envs: &[(&str, &str)], manifest: &ToolServerManifest) -> ConformanceReport {
    run_conformance(&fake_server(), &[], envs, manifest, Duration::from_secs(5)).unwrap()
}

fn find<'a>(report: &'a ConformanceReport, fragment: &str) -> &'a redagent_conformance::Check {
    report
        .checks
        .iter()
        .find(|check| check.name.contains(fragment))
        .unwrap_or_else(|| panic!("no check matching `{fragment}` in {report:#?}"))
}

#[test]
fn healthy_server_passes_every_named_check() {
    let report = run(&[], &ToolServerManifest::redhands());

    assert!(report.passed, "report: {report:#?}");
    assert_eq!(report.server, "redhands");
    assert_eq!(report.checks.len(), 7);
    for fragment in [
        "initialize",
        "tools/list",
        "normalize",
        "read-only",
        "read-only tool returns content",
        "unknown tool",
        "gated_echo",
    ] {
        assert!(find(&report, fragment).passed, "failed check: {fragment}");
    }
    assert!(find(&report, "gated_echo").detail.contains("approval"));

    let markdown = render_report(&report);
    assert!(markdown.contains("# Conformance report: redhands"));
    assert!(markdown.contains("- [x]"));
    assert!(!markdown.contains("- [ ]"));
    assert!(markdown.contains("**Verdict: PASS** — 7/7 checks passed"));
}

#[test]
fn malformed_tools_list_fails_a_specific_check_without_error() {
    let report = run(
        &[("FAKE_CONFORMANCE_MODE", "malformed_tools_list")],
        &ToolServerManifest::redhands(),
    );

    assert!(!report.passed);
    let list = find(&report, "tools/list");
    assert!(!list.passed);
    assert!(list.detail.contains("no `tools` array"), "{}", list.detail);
    assert!(!find(&report, "normalize").passed);
    assert!(render_report(&report).contains("**Verdict: FAIL**"));
    assert!(render_report(&report).contains("- [ ]"));
}

#[test]
fn invalid_tool_is_reported_by_the_normalization_check() {
    let report = run(
        &[("FAKE_CONFORMANCE_MODE", "invalid_tool")],
        &ToolServerManifest::redhands(),
    );

    assert!(!report.passed);
    assert!(find(&report, "tools/list").passed);
    let normalization = find(&report, "normalize");
    assert!(!normalization.passed);
    assert!(normalization.detail.contains("empty or missing name"));
    assert!(normalization
        .detail
        .contains("inputSchema is not an object"));
}

#[test]
fn gated_echo_check_skips_when_not_applicable() {
    let mut manifest = ToolServerManifest::redhands();
    manifest.approval = ApprovalSemantics::ServerInitiatedElicitation;
    let report = run(&[], &manifest);
    assert!(report.passed);
    assert!(find(&report, "gated_echo").detail.contains("skipped"));

    let manifest = ToolServerManifest::redhands();
    let report = run(&[("FAKE_CONFORMANCE_MODE", "no_gated_echo")], &manifest);
    assert!(report.passed, "report: {report:#?}");
    assert!(find(&report, "gated_echo")
        .detail
        .contains("does not advertise"));
}

#[test]
fn garbage_responses_are_skipped_not_panics() {
    let report = run_conformance(
        &fake_server(),
        &[],
        &[("FAKE_CONFORMANCE_MODE", "garbage_line")],
        &ToolServerManifest::redhands(),
        Duration::from_millis(500),
    )
    .unwrap();

    assert!(!report.passed);
    assert!(!find(&report, "tools/list").passed);
    assert!(find(&report, "tools/list").detail.contains("timeout"));
}

#[test]
fn render_report_includes_all_check_names() {
    let report = run(&[], &ToolServerManifest::redhands());
    let markdown = render_report(&report);
    for check in &report.checks {
        assert!(markdown.contains(&check.name));
        assert!(markdown.contains(&check.detail));
    }
}
