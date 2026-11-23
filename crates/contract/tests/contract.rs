use serde_json::{json, Value};
use tempfile::tempdir;

use redagent_contract::{normalize_tool, normalize_tools, ApprovalSemantics, ToolServerManifest};

/// Build a minimal valid tool with extra fields merged in.
fn tool_with(extra: Value) -> Value {
    let mut value = json!({"name": "probe", "inputSchema": {"type": "object"}});
    if let (Value::Object(base), Value::Object(extra)) = (&mut value, extra) {
        base.extend(extra);
    }
    value
}

#[test]
fn redhands_manifest_matches_v063() {
    let manifest = ToolServerManifest::redhands();
    assert_eq!(manifest.name, "redhands");
    assert_eq!(
        manifest.protocol_versions,
        ["2026-07-28", "2025-03-26", "2024-11-05"]
    );
    assert_eq!(
        manifest.policy_paths.read_only,
        ["/x-redhands-policy/readOnly", "/annotations/readOnlyHint"]
    );
    assert_eq!(
        manifest.policy_paths.requires_approval,
        [
            "/x-redhands-policy/requiresApproval",
            "/annotations/destructiveHint"
        ]
    );
    assert_eq!(
        manifest.policy_paths.network_access,
        ["/x-redhands-policy/networkAccess"]
    );
    assert_eq!(manifest.approval, ApprovalSemantics::InlineInputRequests);
    assert!(manifest.tools_list);
    assert!(manifest.tool_call);
    manifest
        .validate()
        .expect("redhands manifest must be valid");
}

#[test]
fn normalization_table() {
    struct Case {
        label: &'static str,
        raw: Value,
        read_only: bool,
        approval: bool,
        network: bool,
    }

    let cases = [
        Case {
            label: "both read-only signals true",
            raw: tool_with(json!({
                "x-redhands-policy": {"readOnly": true, "requiresApproval": false},
                "annotations": {"readOnlyHint": true, "destructiveHint": false}
            })),
            read_only: true,
            approval: false,
            network: false,
        },
        Case {
            label: "one read-only signal false wins",
            raw: tool_with(json!({
                "x-redhands-policy": {"readOnly": true},
                "annotations": {"readOnlyHint": false}
            })),
            read_only: false,
            approval: true,
            network: false,
        },
        Case {
            label: "one read-only signal present and true",
            raw: tool_with(json!({"x-redhands-policy": {"readOnly": true}})),
            read_only: true,
            approval: true,
            network: false,
        },
        Case {
            label: "no signals at all fails closed",
            raw: tool_with(json!({})),
            read_only: false,
            approval: true,
            network: false,
        },
        Case {
            label: "non-boolean read-only signal is not a grant",
            raw: tool_with(json!({"x-redhands-policy": {"readOnly": "true"}})),
            read_only: false,
            approval: true,
            network: false,
        },
        Case {
            label: "explicit approval via policy",
            raw: tool_with(json!({"x-redhands-policy": {"requiresApproval": true}})),
            read_only: false,
            approval: true,
            network: false,
        },
        Case {
            label: "both approval signals false",
            raw: tool_with(json!({
                "x-redhands-policy": {"requiresApproval": false},
                "annotations": {"destructiveHint": false}
            })),
            read_only: false,
            approval: false,
            network: false,
        },
        Case {
            label: "any approval signal true wins",
            raw: tool_with(json!({
                "x-redhands-policy": {"requiresApproval": false},
                "annotations": {"destructiveHint": true}
            })),
            read_only: false,
            approval: true,
            network: false,
        },
        Case {
            label: "network access declared",
            raw: tool_with(json!({"x-redhands-policy": {"networkAccess": true}})),
            read_only: false,
            approval: true,
            network: true,
        },
        Case {
            label: "non-boolean network signal is not a grant",
            raw: tool_with(json!({"x-redhands-policy": {"networkAccess": 1}})),
            read_only: false,
            approval: true,
            network: false,
        },
        Case {
            label: "annotations-only read-only hint",
            raw: tool_with(
                json!({"annotations": {"readOnlyHint": true, "destructiveHint": false}}),
            ),
            read_only: true,
            approval: false,
            network: false,
        },
    ];

    let manifest = ToolServerManifest::redhands();
    for case in cases {
        let normalized = normalize_tool(&case.raw, &manifest)
            .unwrap_or_else(|error| panic!("case `{}`: {error:#}", case.label));
        assert_eq!(normalized.name, "probe", "case {}", case.label);
        assert_eq!(normalized.read_only, case.read_only, "case {}", case.label);
        assert_eq!(
            normalized.requires_approval, case.approval,
            "case {}",
            case.label
        );
        assert_eq!(
            normalized.network_access, case.network,
            "case {}",
            case.label
        );
    }
}

#[test]
fn normalize_tool_rejects_structurally_invalid_tools() {
    let manifest = ToolServerManifest::redhands();
    let invalid = [
        json!({"inputSchema": {}}),
        json!({"name": "", "inputSchema": {}}),
        json!({"name": "   ", "inputSchema": {}}),
        json!({"name": 7, "inputSchema": {}}),
        json!({"name": "probe"}),
        json!({"name": "probe", "inputSchema": "object"}),
        json!({"name": "probe", "inputSchema": []}),
    ];
    for raw in invalid {
        assert!(
            normalize_tool(&raw, &manifest).is_err(),
            "expected rejection for {raw}"
        );
    }
}

#[test]
fn real_v063_tools_list_normalizes() {
    // Shape taken from RedHands v0.6.3 `tools/list`, including the extension
    // fields RedAgent does not model directly.
    let payload = json!({
        "tools": [
            {
                "name": "redhands_health",
                "description": "Check RedHands health",
                "inputSchema": {"type": "object", "properties": {}},
                "x-redhands-policy": {
                    "readOnly": true,
                    "networkAccess": false,
                    "requiresPrivileges": false,
                    "requiresApproval": false,
                    "retrySafe": true,
                    "cacheable": false
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            },
            {
                "name": "gated_echo",
                "description": "Echo text after operator approval",
                "inputSchema": {"type": "object", "properties": {}},
                "x-redhands-policy": {
                    "readOnly": false,
                    "networkAccess": false,
                    "requiresPrivileges": false,
                    "requiresApproval": true,
                    "retrySafe": false,
                    "cacheable": false
                },
                "annotations": {
                    "readOnlyHint": false,
                    "destructiveHint": true,
                    "idempotentHint": false,
                    "openWorldHint": false
                }
            }
        ],
        "ttlMs": 300000
    });

    let manifest = ToolServerManifest::redhands();
    let tools = normalize_tools(&payload, &manifest).unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "redhands_health");
    assert_eq!(tools[0].description, "Check RedHands health");
    assert!(tools[0].read_only);
    assert!(!tools[0].requires_approval);
    assert!(!tools[0].network_access);
    assert_eq!(
        tools[0].input_schema,
        json!({"type": "object", "properties": {}})
    );

    assert_eq!(tools[1].name, "gated_echo");
    assert!(!tools[1].read_only);
    assert!(tools[1].requires_approval);
    assert!(!tools[1].network_access);

    // The array itself is accepted as well as the enclosing result object.
    let from_array = normalize_tools(&payload["tools"], &manifest).unwrap();
    assert_eq!(from_array, tools);
}

#[test]
fn unknown_policy_fields_fail_closed() {
    let raw = tool_with(json!({
        "name": "generic_tool",
        "vendor-policy": {"readOnly": true, "approved": false, "network": true}
    }));
    let normalized = normalize_tool(&raw, &ToolServerManifest::redhands()).unwrap();
    assert!(!normalized.read_only);
    assert!(normalized.requires_approval);
    assert!(!normalized.network_access);

    // A manifest that does declare those pointers can opt in explicitly.
    let mut manifest = ToolServerManifest::redhands();
    manifest.policy_paths.read_only = vec!["/vendor-policy/readOnly".to_string()];
    manifest.policy_paths.requires_approval = vec!["/vendor-policy/approved".to_string()];
    manifest.policy_paths.network_access = vec!["/vendor-policy/network".to_string()];
    manifest.validate().unwrap();
    let normalized = normalize_tool(&raw, &manifest).unwrap();
    assert!(normalized.read_only);
    assert!(!normalized.requires_approval);
    assert!(normalized.network_access);
}

#[test]
fn json_pointer_escapes_and_arrays_resolve() {
    let mut manifest = ToolServerManifest::redhands();
    manifest.policy_paths.read_only = vec!["/x~1custom/flags/0".to_string()];
    manifest.policy_paths.requires_approval = vec!["/tilde~0name".to_string()];
    manifest.policy_paths.network_access = vec!["/missing".to_string()];
    let raw = json!({
        "name": "probe",
        "inputSchema": {},
        "x/custom": {"flags": [true, false]},
        "tilde~name": false
    });
    let normalized = normalize_tool(&raw, &manifest).unwrap();
    assert!(normalized.read_only);
    assert!(!normalized.requires_approval);
    assert!(!normalized.network_access);
}

#[test]
fn validate_table() {
    struct Case {
        label: &'static str,
        change: fn(&mut ToolServerManifest),
        valid: bool,
    }

    let cases = [
        Case {
            label: "valid baseline",
            change: |_| {},
            valid: true,
        },
        Case {
            label: "empty name",
            change: |m| m.name.clear(),
            valid: false,
        },
        Case {
            label: "whitespace name",
            change: |m| m.name = "   ".to_string(),
            valid: false,
        },
        Case {
            label: "empty protocol versions",
            change: |m| m.protocol_versions.clear(),
            valid: false,
        },
        Case {
            label: "tools_list disabled",
            change: |m| m.tools_list = false,
            valid: false,
        },
        Case {
            label: "tool_call disabled is allowed",
            change: |m| m.tool_call = false,
            valid: true,
        },
        Case {
            label: "None approval is allowed",
            change: |m| m.approval = ApprovalSemantics::None,
            valid: true,
        },
        Case {
            label: "server-initiated approval is allowed",
            change: |m| m.approval = ApprovalSemantics::ServerInitiatedElicitation,
            valid: true,
        },
        Case {
            label: "malformed read-only pointer",
            change: |m| m.policy_paths.read_only[0] = "readOnly".to_string(),
            valid: false,
        },
        Case {
            label: "malformed approval pointer",
            change: |m| m.policy_paths.requires_approval[0] = "requiresApproval".to_string(),
            valid: false,
        },
        Case {
            label: "malformed network pointer",
            change: |m| m.policy_paths.network_access[0] = "".to_string(),
            valid: false,
        },
    ];

    for case in cases {
        let mut manifest = ToolServerManifest::redhands();
        (case.change)(&mut manifest);
        let result = manifest.validate();
        assert_eq!(
            result.is_ok(),
            case.valid,
            "case `{}`: {result:?}",
            case.label
        );
    }
}

#[test]
fn manifest_file_round_trip_is_pretty() {
    let manifest = ToolServerManifest::redhands();
    let dir = tempdir().unwrap();
    let path = dir.path().join("manifest.json");

    manifest.to_file(&path).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.starts_with("{\n  \"name\":"), "{contents}");
    assert!(contents.contains("\n  \"policy_paths\": {"), "{contents}");
    assert_eq!(
        serde_json::from_str::<Value>(&contents).unwrap(),
        serde_json::to_value(&manifest).unwrap()
    );

    let loaded = ToolServerManifest::from_file(&path).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded).unwrap(),
        serde_json::to_value(&manifest).unwrap()
    );
}
