# RedAgent

Autonomous offensive-security agent for [RedHands](https://github.com/yasindce1998/RedHands).

RedHands is the **tool plane**: 294 typed MCP tools, approval policies, engagement
scope, audit log and targetdb. RedAgent is the **control plane**: a planner, a
typed event ledger, a guard and (from Phase 2) a Dioxus UI. The two planes are
joined by one protocol boundary — MCP over stdio (local) or HTTP (remote). No
FFI, no shared memory, no shared database.

No code from ARTEX is used. It is a reference for *ideas only*. All code here is
original and MIT licensed.

## Current status — Phase 0

Working loop:

```
goal → deterministic intent → guard allowlist → RedHands MCP tools/call
     → hash-chained ledger events → Markdown report
```

The Phase 0 planner is deliberately deterministic (`redhands_health`). It
exists to prove the architecture end to end; a schema-validated LLM planner
implements the same `Planner` trait in Phase 1.

## Architecture

See [docs/adr/0001-architecture.md](docs/adr/0001-architecture.md) for the
decision record. Short version:

- **Go stays in RedHands**, unchanged.
- **Rust owns the agent**, eventually compiled into one binary with the UI.
- **MCP is the only seam** between the two.
- **One append-only SQLite ledger** is the source of truth; graphs, coverage,
  findings and audit views are projections, never independently mutated.
- Every target action is a typed `tools/call` — no free-form shell.

### Crates

| Crate | Responsibility |
|---|---|
| `redagent-core` | Event ledger (hash-chained), typed events, projections, report rendering |
| `redagent-mcp` | Minimal synchronous MCP client over stdio; JSON-RPC 2.0 |
| `redagent-agent` | `Planner` trait + Phase 0 deterministic planner |
| `redagent-guard` | Tool allowlist + hard tool-call budget |
| `redagent-app` | Single wiring point and the engagement engine |
| `redagent-cli` | `redagent run / report / verify` |
| `fake-mcp-server` | Test-only deterministic MCP server (workspace test binary) |

## Build and test

```sh
cargo build --release            # produces target/release/redagent
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI runs format, clippy, tests and a release build on Linux, macOS and Windows.

## Usage

Requires a **checksum-verified RedHands v0.6.3** binary (the contract version
for Phase 0):

```sh
redagent run "verify the lab tool plane" \
  --redhands /path/to/redhands \
  --ledger engagement.db

redagent report --ledger engagement.db        # re-render the Markdown report
redagent verify --ledger engagement.db        # verify the hash chain
```

`run` spawns RedHands in stdio mode with `REDHANDS_TOOLSETS=health`,
`REDHANDS_AUTH=none` and every state directory redirected next to the ledger —
so no files are written to your working directory. The tool catalog, guard
decision, tool output and finding are all recorded as events in the ledger.

## Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Ledger, typed intent, MCP loop, guard, CLI, CI | ✅ this release |
| 1 | LLM planner, worker/verifier, approval elicitation, budgets | next |
| 2 | Dioxus desktop UI + Axum REST/SSE projections | planned |
| 3 | Evidence blobs, retest loop, exports, Dioxus WASM web console | planned |
| 4 | RBAC/KMS, OTel, WASM plugins (only if measured) | planned |

## License

MIT — Copyright (c) 2026 Mohammed Yasin. See [LICENSE](LICENSE).
