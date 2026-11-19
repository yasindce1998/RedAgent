# RedAgent threat model

Status: living document. Items marked **planned** are not yet shipped.

## Assets

| Asset | Sensitivity | Storage |
|---|---|---|
| Engagement ledger (events, hashes) | High — audit record | SQLite, one file per engagement |
| Evidence blobs | High — raw tool output | SHA-256-addressed files beside ledger |
| LLM / tool-server credentials | Critical | Process env / API config; never in ledger or UI |
| Signing key (**planned**) | Critical | 0600 file or external KMS |
| Approval decisions | High — accountability | Ledger events with `decided_by` |
| UI/API session | Medium | Loopback HTTP API, no auth in v0.3.x |

## Trust boundaries

```
operator ──► Dioxus UI ──► Axum API ──► Rust engine ──► MCP ──► Go tool plane ──► target
                                        │                         │
                                      ledger           untrusted tool output
                                        │                         │
                                      blobs            LLM planner ◄─┘
```

1. **Operator → UI/API**: the API currently binds to loopback by default. It has no
   authentication; anyone with local access can read ledgers and approve tools.
   Deployment must keep it on loopback or behind an authenticating proxy.
2. **Rust engine → Go tool plane**: all target actions cross an MCP boundary. The
   engine never executes a shell directly; argv is constructed and validated in
   RedHands. This is the strongest boundary in the system.
3. **Target → tool output → planner**: scanner output, HTTP banners and file
   contents are attacker-controlled. They must be treated as data, never as
   instructions.
4. **Planner → guard**: an LLM can hallucinate tools, targets or arguments. The
   guard is the last authority before a call leaves the process.
5. **Ledger → verifier**: hash chaining detects accidental corruption and simple
   edits, but a full rewrite that also recomputes hashes is undetectable without
   an external anchor.

## Threats and mitigations

| Threat | Mitigation | Status |
|---|---|---|
| Out-of-scope scanning/exploitation | Tool allowlist, RedHands engagement scope, default-deny approval | Loaded in RedHands; **argument-level CIDR/domain scope enforcement planned (v0.4.0)** |
| Approval bypass via shell tricks | No shell in RedAgent; structured `tools/call` only; single-use grants | Shipped |
| Malicious tool result prompts the planner to do something else | Nonce-framed untrusted data, schema-validated plans, tool names checked against live catalog | Shipped; heuristics + divergence signals **planned (v0.4.0)** |
| LLM invents a tool or target | Planner validation against live `tools/list`; argument/schema checks | Shipped |
| Ledger rewriting | Hash chain over stored payload bytes; evidence blobs hashed on read | Shipped |
| Full ledger rehash | **Planned:** ed25519 checkpoints + external anchor + `verify --signatures` (v0.4.1) | Planned |
| Evidence blob corruption | SHA-256 verified on read; missing/corrupt blobs error clearly | Shipped |
| Path traversal through API ids | Strict `[A-Za-z0-9_-]` id validation on every route | Shipped |
| API key leak in LLM errors | Full error-chain redaction of the key | Shipped |
| Runaway tool loop | Tool-call and intent budgets in guard; budget events | Shipped |
| Runaway LLM spend | **Planned:** token budgets from `usage`, forced wrap-up (v0.6.0) | Planned |
| Untrusted MCP server impersonating a safe tool server | **Planned:** adapter manifest + conformance suite; unknown policy fields fail closed (v0.5.1) | Planned |
| Dependency compromise | **Planned:** cargo-deny / cargo-audit in CI; release attestations | In progress |

## Residual risks

- **Signing is not enough on its own.** A compromised signing key or an anchor
  stored next to the ledger defeats the scheme. Keep the key and anchor
  independent of the machine holding the ledger.
- **Scope extraction is heuristic.** Tool schemas do not consistently annotate
  target fields; the guard must fail closed when a target-like value cannot be
  resolved, and operators must review scope files.
- **RedHands binary integrity is assumed.** Install from checksum-verified
  releases; RedAgent does not re-verify the Go binary at launch.
- **Local API is unauthenticated.** Anyone with local access can approve tools.
- **Autonomous planning is non-deterministic.** Replay mode with recorded LLM
  responses is the mitigation for audit and CI, not a guarantee of identical
  live behaviour.

## Authorization

RedAgent is an offensive-security tool. Use it only against systems you own or
are explicitly authorized to test.
