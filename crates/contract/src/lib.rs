//! Tool-plane agnostic contract for RedAgent.
//!
//! A [`ToolServerManifest`] describes how a particular MCP-like tool server
//! encodes its safety metadata. [`normalize_tool`] and [`normalize_tools`]
//! flatten those server-specific encodings into the single representation the
//! rest of RedAgent consumes.
//!
//! All decoding is deliberately fail-closed: a missing or non-boolean safety
//! signal never grants a permission. A tool is read-only only when at least
//! one declared pointer is present and every present pointer says `true`; it
//! requires approval when any declared pointer says `true` or no declared
//! pointer is present at all.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How a tool server asks an operator to approve a gated tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalSemantics {
    /// Approval is requested inline in the `tools/call` result
    /// (`resultType: "input_required"` plus `inputRequests`) and granted by
    /// re-issuing the call with `inputResponses`.
    InlineInputRequests,
    /// Approval arrives as a separate server-initiated elicitation request.
    ServerInitiatedElicitation,
    /// The server has no approval mechanism at all. This is a valid manifest:
    /// [`ToolServerManifest::validate`] deliberately accepts it.
    None,
}

/// Server-specific JSON pointer locations of the three safety booleans.
///
/// Pointers are RFC 6901 strings such as `/x-redhands-policy/readOnly`. A
/// server with an entirely different schema can supply its own pointers
/// without RedAgent needing to know the tool plane's details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPaths {
    pub read_only: Vec<String>,
    pub requires_approval: Vec<String>,
    pub network_access: Vec<String>,
}

/// Declarative description of a tool server's protocol and policy encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolServerManifest {
    pub name: String,
    pub protocol_versions: Vec<String>,
    pub policy_paths: PolicyPaths,
    pub approval: ApprovalSemantics,
    pub tools_list: bool,
    pub tool_call: bool,
}

impl ToolServerManifest {
    /// The manifest for RedHands v0.6.3.
    ///
    /// RedHands serves the 2026-07-28, 2025-03-26 and 2024-11-05 protocol
    /// revisions. It advertises policy in the `x-redhands-policy` extension
    /// and mirrors it in standard MCP `annotations`; approval is inline.
    pub fn redhands() -> Self {
        Self {
            name: "redhands".to_string(),
            protocol_versions: vec![
                "2026-07-28".to_string(),
                "2025-03-26".to_string(),
                "2024-11-05".to_string(),
            ],
            policy_paths: PolicyPaths {
                read_only: vec![
                    "/x-redhands-policy/readOnly".to_string(),
                    "/annotations/readOnlyHint".to_string(),
                ],
                requires_approval: vec![
                    "/x-redhands-policy/requiresApproval".to_string(),
                    "/annotations/destructiveHint".to_string(),
                ],
                network_access: vec!["/x-redhands-policy/networkAccess".to_string()],
            },
            approval: ApprovalSemantics::InlineInputRequests,
            tools_list: true,
            tool_call: true,
        }
    }

    /// Load and validate a manifest from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest from {}", path.display()))?;
        let manifest: Self = serde_json::from_str(&contents)
            .with_context(|| format!("parsing manifest from {}", path.display()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Write the manifest as pretty-printed JSON.
    pub fn to_file(&self, path: &Path) -> Result<()> {
        let contents =
            serde_json::to_string_pretty(self).context("serializing tool server manifest")?;
        std::fs::write(path, contents)
            .with_context(|| format!("writing manifest to {}", path.display()))
    }

    /// Reject structurally invalid manifests.
    ///
    /// A tool-server manifest must name a server, declare at least one
    /// protocol version, declare `tools/list` support (otherwise there is no
    /// tool plane to describe) and use well-formed JSON pointers. `approval`
    /// may be [`ApprovalSemantics::None`], and `tool_call` may be `false`:
    /// those describe a server that cannot call tools, which is unusual but
    /// not structurally invalid.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("manifest name must not be empty");
        }
        if self.protocol_versions.is_empty() {
            bail!("manifest must declare at least one protocol version");
        }
        if !self.tools_list {
            bail!("manifest must declare tools_list support");
        }
        for (label, pointers) in [
            ("read_only", &self.policy_paths.read_only),
            ("requires_approval", &self.policy_paths.requires_approval),
            ("network_access", &self.policy_paths.network_access),
        ] {
            for pointer in pointers {
                if !pointer.starts_with('/') {
                    bail!(
                        "policy path `{pointer}` in {label} is not a JSON pointer (must start with '/')"
                    );
                }
            }
        }
        Ok(())
    }
}

/// A tool normalized into RedAgent's tool-plane agnostic representation.
#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub read_only: bool,
    pub requires_approval: bool,
    pub network_access: bool,
}

/// Resolve an RFC 6901 JSON pointer against a value.
///
/// Object keys and array indices are supported, along with `~1` (`/`) and
/// `~0` (`~`) escapes. Malformed pointers simply do not resolve; callers use
/// that as "signal absent", which fails closed.
fn resolve_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if !pointer.starts_with('/') {
        return None;
    }
    let mut current = root;
    for token in pointer[1..].split('/') {
        let token = token.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get(&token)?,
            Value::Array(items) => items.get(token.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Collect the values actually present at a set of pointers.
fn present_values<'a>(raw: &'a Value, pointers: &[String]) -> Vec<&'a Value> {
    pointers
        .iter()
        .filter_map(|pointer| resolve_pointer(raw, pointer))
        .collect()
}

/// Normalize one raw `tools/list` entry under a manifest.
///
/// Fails closed: read-only requires *all* present read-only signals to be
/// boolean `true` (and at least one to be present); approval is required when
/// any approval signal is `true` or when no approval signal is present;
/// network access is granted only when a pointer explicitly says `true`.
pub fn normalize_tool(raw: &Value, manifest: &ToolServerManifest) -> Result<NormalizedTool> {
    let name = raw
        .get("name")
        .and_then(Value::as_str)
        .context("tool has no string `name`")?;
    if name.trim().is_empty() {
        bail!("tool `name` must not be empty");
    }
    let input_schema = raw
        .get("inputSchema")
        .or_else(|| raw.get("input_schema"))
        .filter(|value| value.is_object())
        .context("tool has no object `inputSchema`")?;

    let read_only_signals = present_values(raw, &manifest.policy_paths.read_only);
    let read_only = !read_only_signals.is_empty()
        && read_only_signals
            .iter()
            .all(|value| value.as_bool() == Some(true));

    let approval_signals = present_values(raw, &manifest.policy_paths.requires_approval);
    let requires_approval = approval_signals.is_empty()
        || approval_signals
            .iter()
            .any(|value| value.as_bool() == Some(true));

    let network_signals = present_values(raw, &manifest.policy_paths.network_access);
    let network_access = network_signals
        .iter()
        .any(|value| value.as_bool() == Some(true));

    Ok(NormalizedTool {
        name: name.to_string(),
        description: raw
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        input_schema: input_schema.clone(),
        read_only,
        requires_approval,
        network_access,
    })
}

/// Normalize a whole tool list.
///
/// Accepts either a JSON array of tools or a `tools/list` result object with
/// a `tools` array, so callers can pass the raw response straight through.
pub fn normalize_tools(
    raw_list: &Value,
    manifest: &ToolServerManifest,
) -> Result<Vec<NormalizedTool>> {
    let tools = match raw_list.as_array() {
        Some(tools) => tools,
        None => raw_list
            .get("tools")
            .and_then(Value::as_array)
            .context("expected a JSON array of tools (or an object with a `tools` array)")?,
    };
    tools
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            normalize_tool(raw, manifest)
                .with_context(|| format!("normalizing tool at index {index}"))
        })
        .collect()
}
