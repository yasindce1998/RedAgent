//! Trust-boundary primitives for RedAgent.
//!
//! This crate owns two independent concerns:
//!
//! * [`Scope`] decides whether a target (an IP, CIDR, hostname, `host:port` or
//!   an `http(s)` URL) is inside a declared scope.
//! * [`PolicyRule`] / [`evaluate_rules`] implement a small, deterministic
//!   first-match-wins rule language layered on top of the scope decision.
//!
//! An empty scope means "no scope was declared". In that case
//! [`Scope::allows_target`] and [`Scope::allows_url`] return
//! [`ScopeDecision::InScope`]; callers that require an explicit scope must
//! check [`Scope::is_empty`] and fail closed themselves.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{anyhow, Context};
use ipnet::IpNet;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// The outcome of checking a single target against a [`Scope`].
#[derive(Clone, Debug, PartialEq)]
pub enum ScopeDecision {
    /// The target is inside the declared scope (or no scope was declared).
    InScope,
    /// The target was parsed successfully but is not covered by the scope.
    OutOfScope { reason: String },
    /// The target could not be interpreted, so no decision could be made.
    /// Callers should usually fail closed on this variant.
    Unresolvable { reason: String },
}

/// A declared scope: a set of networks, a set of domains and an optional port
/// allowlist. All three lists are optional; when all are empty the scope is
/// considered undeclared (see [`Scope::is_empty`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scope {
    // `IpNet` does not implement serde traits unless ipnet's `serde` feature is
    // enabled, so networks are stored as parsed values but (de)serialized via
    // their canonical string form.
    #[serde(
        serialize_with = "serialize_cidrs",
        deserialize_with = "deserialize_cidrs"
    )]
    cidrs: Vec<IpNet>,
    /// Always lowercased by [`Scope::new`]; targets are lowercased before
    /// comparison as well, so domain matching is case-insensitive.
    domains: Vec<String>,
    ports: Vec<u16>,
}

fn serialize_cidrs<S>(cidrs: &[IpNet], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let strings: Vec<String> = cidrs.iter().map(ToString::to_string).collect();
    <Vec<String> as Serialize>::serialize(&strings, serializer)
}

fn deserialize_cidrs<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings = Vec::<String>::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| IpNet::from_str(&s).map_err(D::Error::custom))
        .collect()
}

impl Scope {
    /// Build a scope, validating every CIDR and normalising domains to
    /// lowercase. Malformed CIDRs (and blank domains) are rejected with a
    /// descriptive error.
    pub fn new(cidrs: Vec<String>, domains: Vec<String>, ports: Vec<u16>) -> anyhow::Result<Self> {
        let mut parsed_cidrs = Vec::with_capacity(cidrs.len());
        for cidr in &cidrs {
            let net = IpNet::from_str(cidr).with_context(|| format!("invalid CIDR '{cidr}'"))?;
            parsed_cidrs.push(net);
        }

        let mut normalised_domains = Vec::with_capacity(domains.len());
        for domain in &domains {
            let trimmed = domain.trim();
            if trimmed.is_empty() {
                return Err(anyhow!("invalid domain: empty domain string"));
            }
            if trimmed.chars().any(char::is_whitespace) {
                return Err(anyhow!("invalid domain '{domain}': contains whitespace"));
            }
            normalised_domains.push(trimmed.to_lowercase());
        }

        Ok(Self {
            cidrs: parsed_cidrs,
            domains: normalised_domains,
            ports,
        })
    }

    /// Returns true when no scope entry of any kind was declared.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.domains.is_empty() && self.ports.is_empty()
    }

    /// Check a target expressed as a bare IPv4/IPv6 address, a CIDR, a
    /// hostname, a `host:port` pair (including bracketed IPv6), or an
    /// `http(s)://...` URL.
    pub fn allows_target(&self, target: &str) -> ScopeDecision {
        // No declared scope means there is nothing to restrict.
        if self.is_empty() {
            return ScopeDecision::InScope;
        }

        if target.contains("://") {
            return self.allows_url(target);
        }

        match parse_target(target) {
            Ok((host, port)) => self.check_host_port(&host, port, target),
            Err(err) => ScopeDecision::Unresolvable {
                reason: format!("cannot parse target '{target}': {err:#}"),
            },
        }
    }

    /// Parse an HTTP(S) URL and check its host (and explicitly supplied port)
    /// against this scope. Credentials, path, query and fragment are ignored.
    pub fn allows_url(&self, url: &str) -> ScopeDecision {
        if self.is_empty() {
            return ScopeDecision::InScope;
        }

        let parsed = match url::Url::parse(url) {
            Ok(parsed) => parsed,
            Err(err) => {
                return ScopeDecision::Unresolvable {
                    reason: format!("cannot parse URL '{url}': {err}"),
                }
            }
        };

        if !matches!(parsed.scheme(), "http" | "https") {
            return ScopeDecision::Unresolvable {
                reason: format!("unsupported URL scheme '{}'", parsed.scheme()),
            };
        }

        let host = match parsed.host() {
            Some(url::Host::Domain(domain)) => Host::Domain(domain.to_lowercase()),
            Some(url::Host::Ipv4(ip)) => Host::Ip(ip.into()),
            Some(url::Host::Ipv6(ip)) => Host::Ip(ip.into()),
            None => {
                return ScopeDecision::Unresolvable {
                    reason: format!("URL '{url}' has no host"),
                }
            }
        };

        self.check_host_port(&host, parsed.port(), url)
    }

    fn check_host_port(&self, host: &Host, port: Option<u16>, original: &str) -> ScopeDecision {
        let host_matches = match host {
            Host::Ip(ip) => self.cidrs.iter().any(|net| net.contains(ip)),
            Host::Network(network) => self
                .cidrs
                .iter()
                .any(|allowed| network_contains(allowed, network)),
            Host::Domain(domain) => self.domains.iter().any(|allowed| {
                domain == allowed
                    || domain
                        .strip_suffix(allowed)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }),
        };

        if !host_matches {
            return ScopeDecision::OutOfScope {
                reason: format!("'{original}' does not match any declared CIDR or domain"),
            };
        }

        if let Some(port) = port {
            if !self.ports.is_empty() && !self.ports.contains(&port) {
                return ScopeDecision::OutOfScope {
                    reason: format!("port {port} is not in the allowed port list"),
                };
            }
        }

        ScopeDecision::InScope
    }
}

/// True when `inner` is entirely contained in `outer`.
fn network_contains(outer: &IpNet, inner: &IpNet) -> bool {
    outer.network().is_ipv4() == inner.network().is_ipv4()
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.network())
}

/// A parsed target host: a single address, a network, or a normalised domain.
#[derive(Debug)]
enum Host {
    Ip(IpAddr),
    Network(IpNet),
    Domain(String),
}

fn parse_target(target: &str) -> anyhow::Result<(Host, Option<u16>)> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty target"));
    }
    if trimmed.contains("://") {
        return Err(anyhow!("URL targets must be checked with allows_url"));
    }

    // A CIDR (IPv4 or IPv6) is the whole target and never carries a port.
    if trimmed.contains('/') {
        let network =
            IpNet::from_str(trimmed).with_context(|| format!("invalid CIDR '{trimmed}'"))?;
        return Ok((Host::Network(network), None));
    }

    // Bracketed IPv6, optionally followed by `:port`.
    if let Some(rest) = trimmed.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| anyhow!("unclosed '[' in target '{target}'"))?;
        let address = &rest[..close];
        let port = parse_port_suffix(&rest[close + 1..])?;
        let ip = Ipv6Addr::from_str(address)
            .with_context(|| format!("invalid IPv6 address '{address}'"))?;
        return Ok((Host::Ip(ip.into()), port));
    }

    // More than one colon with no brackets can only be a bare IPv6 address.
    let colon_count = trimmed.matches(':').count();
    if colon_count > 1 {
        let ip = Ipv6Addr::from_str(trimmed)
            .with_context(|| format!("invalid IPv6 address '{trimmed}'"))?;
        return Ok((Host::Ip(ip.into()), None));
    }
    if colon_count == 1 {
        let (host, port_str) = trimmed.split_once(':').expect("one colon present");
        let port = parse_port(port_str)?;
        return Ok((parse_host(host)?, Some(port)));
    }

    Ok((parse_host(trimmed)?, None))
}

fn parse_port_suffix(suffix: &str) -> anyhow::Result<Option<u16>> {
    if suffix.is_empty() {
        Ok(None)
    } else if let Some(port) = suffix.strip_prefix(':') {
        parse_port(port).map(Some)
    } else {
        Err(anyhow!("unexpected text after ']': '{suffix}'"))
    }
}

fn parse_port(port: &str) -> anyhow::Result<u16> {
    if port.is_empty() {
        return Err(anyhow!("empty port"));
    }
    port.parse::<u16>()
        .with_context(|| format!("invalid port '{port}'"))
}

fn parse_host(host: &str) -> anyhow::Result<Host> {
    if host.is_empty() {
        return Err(anyhow!("empty host"));
    }
    if let Ok(ip) = IpAddr::from_str(host) {
        return Ok(Host::Ip(ip));
    }
    // IpNet's FromStr also accepts bare addresses, but those were handled
    // above, so reaching here means the input really had a prefix length.
    if let Ok(network) = IpNet::from_str(host) {
        return Ok(Host::Network(network));
    }
    let lower = host.to_lowercase();
    if is_valid_hostname(&lower) {
        Ok(Host::Domain(lower))
    } else {
        Err(anyhow!("invalid host or address '{host}'"))
    }
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }
    if hostname.starts_with('.') || hostname.ends_with('.') {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// The effect a matching [`PolicyRule`] applies.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum RuleEffect {
    Allow,
    Deny,
    RequireApproval,
    AutoApprove,
}

/// A single policy rule. `tool_pattern` is a case-insensitive glob where `*`
/// matches any sequence of characters (including the empty sequence).
#[derive(Clone, Debug, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub tool_pattern: String,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub in_scope: Option<bool>,
    pub effect: RuleEffect,
}

/// Return the first rule whose pattern and optional predicates match, together
/// with its id. Returns `None` when no rule matches.
pub fn evaluate_rules(
    rules: &[PolicyRule],
    tool: &str,
    read_only: bool,
    in_scope: bool,
) -> Option<(RuleEffect, String)> {
    rules
        .iter()
        .find(|rule| rule_matches(rule, tool, read_only, in_scope))
        .map(|rule| (rule.effect, rule.id.clone()))
}

fn rule_matches(rule: &PolicyRule, tool: &str, read_only: bool, in_scope: bool) -> bool {
    wildcard_matches(&rule.tool_pattern, tool)
        && rule.read_only.is_none_or(|expected| expected == read_only)
        && rule.in_scope.is_none_or(|expected| expected == in_scope)
}

/// Case-insensitive glob match where `*` matches any (possibly empty) run of
/// characters. All other characters are matched literally.
pub fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let value: Vec<char> = value.to_lowercase().chars().collect();

    let (mut p, mut v) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut retry = 0usize;

    while v < value.len() {
        if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Extract strings and numbers from the given dotted paths. Numeric segments
/// index into arrays (e.g. `hosts.0`), and arrays found at a leaf are expanded
/// recursively. Values are deduplicated while preserving discovery order.
pub fn extract_targets(args: &serde_json::Value, paths: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();

    for path in paths {
        let segments: Vec<&str> = path.split('.').collect();
        if let Some(value) = resolve_path(args, &segments) {
            collect_leaves(value, &mut found, &mut seen);
        }
    }

    found
}

fn resolve_path<'a>(
    root: &'a serde_json::Value,
    segments: &[&str],
) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in segments {
        if segment.is_empty() {
            return None;
        }
        current = match current {
            serde_json::Value::Object(map) => map.get(*segment)?,
            serde_json::Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn collect_leaves(value: &serde_json::Value, found: &mut Vec<String>, seen: &mut HashSet<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_leaves(item, found, seen);
            }
        }
        serde_json::Value::String(string) => push_unique(string.clone(), found, seen),
        serde_json::Value::Number(number) => push_unique(number.to_string(), found, seen),
        _ => {}
    }
}

fn push_unique(value: String, found: &mut Vec<String>, seen: &mut HashSet<String>) {
    if seen.insert(value.clone()) {
        found.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope(cidrs: &[&str], domains: &[&str], ports: &[u16]) -> Scope {
        Scope::new(
            cidrs.iter().map(|s| s.to_string()).collect(),
            domains.iter().map(|s| s.to_string()).collect(),
            ports.to_vec(),
        )
        .unwrap()
    }

    fn is_in_scope(decision: &ScopeDecision) -> bool {
        matches!(decision, ScopeDecision::InScope)
    }

    // -- Scope::new -------------------------------------------------------

    #[test]
    fn scope_new_validates_cidrs_and_normalises_domains() {
        assert!(Scope::new(vec!["10.0.0.0/8".into()], vec![], vec![]).is_ok());
        assert!(Scope::new(vec!["2001:db8::/32".into()], vec![], vec![]).is_ok());

        for bad in ["not-a-cidr", "10.0.0.0/99", "10.0.0.0/", ""] {
            let err = Scope::new(vec![bad.into()], vec![], vec![]).unwrap_err();
            assert!(
                err.to_string().contains("invalid CIDR"),
                "unexpected error for {bad:?}: {err:#}"
            );
        }

        let err = Scope::new(vec![], vec!["   ".into()], vec![]).unwrap_err();
        assert!(err.to_string().contains("empty domain"));

        let s = scope(&[], &["ExAmPlE.COM"], &[]);
        assert!(is_in_scope(&s.allows_target("HOST.EXAMPLE.COM")));
    }

    #[test]
    fn empty_scope_is_declared_as_empty_and_allows_everything() {
        let s = scope(&[], &[], &[]);
        assert!(s.is_empty());
        assert!(is_in_scope(&s.allows_target("anything at all")));
        assert!(is_in_scope(&s.allows_target("10.0.0.1")));
        assert!(is_in_scope(&s.allows_url("ftp://example.com")));
        assert!(!scope(&["10.0.0.0/8"], &[], &[]).is_empty());
    }

    #[test]
    fn scope_survives_serde_round_trip() {
        let original = scope(
            &["10.0.0.0/8", "2001:db8::/32"],
            &["Example.com"],
            &[80, 443],
        );
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: Scope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.cidrs, original.cidrs);
        assert_eq!(decoded.domains, original.domains);
        assert_eq!(decoded.ports, original.ports);
        assert!(is_in_scope(
            &decoded.allows_url("https://a.example.com/app")
        ));
    }

    // -- allows_target: CIDRs --------------------------------------------

    #[test]
    fn ipv4_cidr_targets() {
        let s = scope(&["10.0.0.0/8"], &[], &[]);
        let cases = [
            ("10.0.0.1", true),
            ("10.255.255.254", true),
            ("10.0.0.0/8", true),
            ("10.1.0.0/16", true),
            ("10.0.0.0/7", false), // wider than the declared scope
            ("11.0.0.1", false),
            ("192.168.1.1", false),
            ("192.168.1.0/24", false),
        ];
        for (target, expected) in cases {
            assert_eq!(
                is_in_scope(&s.allows_target(target)),
                expected,
                "target {target}"
            );
        }
    }

    #[test]
    fn ipv6_cidr_targets() {
        let s = scope(&["2001:db8::/32"], &[], &[]);
        let cases = [
            ("2001:db8::1", true),
            ("2001:db8:abcd::ff", true),
            ("[2001:db8::1]", true),
            ("2001:db8::/32", true),
            ("2001:db8:1234::/48", true),
            ("2001:db8::/16", false), // wider than the declared scope
            ("2001:db9::1", false),
            ("::1", false),
        ];
        for (target, expected) in cases {
            assert_eq!(
                is_in_scope(&s.allows_target(target)),
                expected,
                "target {target}"
            );
        }
    }

    #[test]
    fn mixed_cidr_versions_do_not_match() {
        let s = scope(&["10.0.0.0/8"], &[], &[]);
        assert!(!is_in_scope(&s.allows_target("::ffff:10.0.0.1")));
    }

    // -- allows_target/URL: domains --------------------------------------

    #[test]
    fn domain_matching_and_subdomain_vs_suffix_trick() {
        let s = scope(&[], &["example.com"], &[]);
        let cases = [
            ("example.com", true),
            ("EXAMPLE.COM", true),
            ("a.example.com", true),
            ("a.b.c.example.com", true),
            ("evil-example.com", false),
            ("notexample.com", false),
            ("example.com.evil.test", false),
            ("example.co", false),
        ];
        for (target, expected) in cases {
            assert_eq!(
                is_in_scope(&s.allows_target(target)),
                expected,
                "target {target}"
            );
            assert_eq!(
                is_in_scope(&s.allows_url(&format!("https://{target}/"))),
                expected,
                "URL host {target}"
            );
        }
    }

    // -- ports ------------------------------------------------------------

    #[test]
    fn port_rules_apply_only_when_a_port_is_present() {
        let s = scope(&["10.0.0.0/8"], &["example.com"], &[80, 443]);
        let cases = [
            ("10.0.0.1", true),
            ("10.0.0.1:443", true),
            ("example.com:80", true),
            ("example.com", true),
            ("[2001:db8::1]:443", false), // address is not in the CIDR
            ("example.com:8080", false),
            ("10.0.0.1:22", false),
        ];
        for (target, expected) in cases {
            assert_eq!(
                is_in_scope(&s.allows_target(target)),
                expected,
                "target {target}"
            );
        }

        let unscoped_ports = scope(&["10.0.0.0/8"], &[], &[]);
        assert!(is_in_scope(&unscoped_ports.allows_target("10.0.0.1:65535")));
    }

    // -- URLs -------------------------------------------------------------

    #[test]
    fn urls_with_credentials_path_query_and_fragment() {
        let s = scope(&["10.0.0.0/8"], &["example.com"], &[80, 443]);
        let allowed = [
            "http://user:pass@example.com:80/a/b?q=1#frag",
            "https://user@example.com/path",
            "https://example.com",
            "http://10.0.0.5/x",
            "https://10.0.0.5:443/x",
        ];
        for url in allowed {
            assert!(is_in_scope(&s.allows_url(url)), "URL {url}");
            assert!(is_in_scope(&s.allows_target(url)), "target-URL {url}");
        }

        assert!(!is_in_scope(&s.allows_url("https://evil-example.com/x")));
        assert!(!is_in_scope(&s.allows_url("https://example.com:8443/x")));
    }

    #[test]
    fn malformed_targets_and_urls_are_unresolvable() {
        let s = scope(&["10.0.0.0/8"], &["example.com"], &[80]);
        let bad = [
            "",
            "   ",
            "not a host!",
            "example.com:notaport",
            "example.com:",
            "[::1",
            "[not-ipv6]:80",
            "10.0.0.0/33",
            "http://",
            "ftp://example.com/x",
            "example.com/path",
        ];
        for target in bad {
            let decision = if target.contains("://") {
                s.allows_url(target)
            } else {
                s.allows_target(target)
            };
            assert!(
                matches!(decision, ScopeDecision::Unresolvable { .. }),
                "target {target:?} produced {decision:?}"
            );
        }
    }

    // -- wildcard_matches -------------------------------------------------

    #[test]
    fn wildcard_matching_table() {
        let cases = [
            ("*", "anything", true),
            ("", "", true),
            ("", "x", false),
            ("REDHANDS_*", "redhands_health", true),
            ("redhands_*", "REDHANDS_HEALTH", true),
            ("a*b*c", "axxbxxc", true),
            ("a*b*c", "abc", true),
            ("a*b", "ab", true),
            ("*example.com", "a.b.example.com", true),
            ("a?b", "axb", false), // '?' is literal, not a wildcard
            ("a*b", "ac", false),
            ("*x", "abc", false),
            ("x*", "y", false),
        ];
        for (pattern, value, expected) in cases {
            assert_eq!(
                wildcard_matches(pattern, value),
                expected,
                "pattern {pattern:?} vs {value:?}"
            );
        }
    }

    // -- evaluate_rules ---------------------------------------------------

    #[test]
    fn rule_precedence_is_first_match_and_predicates_are_honoured() {
        let rules: Vec<PolicyRule> = serde_json::from_value(json!([
            {
                "id": "skip-read-only",
                "tool_pattern": "read_*",
                "read_only": true,
                "in_scope": false,
                "effect": "Deny"
            },
            {
                "id": "first-match",
                "tool_pattern": "READ_*",
                "effect": "AutoApprove"
            },
            {
                "id": "never-reached",
                "tool_pattern": "*",
                "effect": "Deny"
            }
        ]))
        .unwrap();

        assert_eq!(
            evaluate_rules(&rules, "read_file", false, true),
            Some((RuleEffect::AutoApprove, "first-match".into()))
        );
        assert_eq!(
            evaluate_rules(&rules, "read_file", true, false),
            Some((RuleEffect::Deny, "skip-read-only".into()))
        );
        assert_eq!(
            evaluate_rules(&rules, "other", false, true),
            Some((RuleEffect::Deny, "never-reached".into()))
        );
        assert_eq!(evaluate_rules(&[], "anything", true, true), None);
    }

    // -- extract_targets --------------------------------------------------

    #[test]
    fn target_extraction_follows_paths_indices_and_arrays() {
        let args = json!({
            "target": "first.example.com",
            "host": 8080,
            "params": { "url": "https://second.example.com/x" },
            "hosts": ["third.example.com", "first.example.com", 42],
            "nested": [["deep.example.com"], { "ignored": true }],
            "flag": true
        });
        let paths = [
            "target".to_string(),
            "host".to_string(),
            "params.url".to_string(),
            "hosts".to_string(),
            "hosts.0".to_string(),
            "nested.0".to_string(),
            "flag".to_string(),
            "missing.path".to_string(),
            "hosts.99".to_string(),
        ];

        assert_eq!(
            extract_targets(&args, &paths),
            vec![
                "first.example.com".to_string(),
                "8080".to_string(),
                "https://second.example.com/x".to_string(),
                "third.example.com".to_string(),
                "42".to_string(),
                "deep.example.com".to_string(),
            ]
        );
    }
}
