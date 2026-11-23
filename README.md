<div align="center">

<img src="docs/logo.svg" alt="RedAgent logo" width="170" />

# RedAgent

**Goal in. Evidence out.**

An autonomous offensive-security agent for [RedHands](https://github.com/yasindce1998/RedHands) — the tool plane that already wraps 294 security tools behind approval policies, scope gates and a full audit trail.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Built in Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](Cargo.toml)
[![CI](https://github.com/yasindce1998/RedAgent/actions/workflows/ci.yml/badge.svg)](https://github.com/yasindce1998/RedAgent/actions/workflows/ci.yml)
[![Phase 0](https://img.shields.io/badge/phase-0%20shipped-brightgreen.svg)](#roadmap)
[![RedHands contract](https://img.shields.io/badge/RedHands-v0.6.3-red.svg)](#quick-start)

</div>

---

## MCP gives you tools. RedAgent gives them a brain.

RedHands exposes capabilities. RedAgent decides **what to try next**, remembers what happened two steps ago, and binds every conclusion to the tool output that produced it. No shell free-for-all, no orphaned findings, no "what did the agent actually do?" moments.

| | |
|---|---|
| 🎯 **Goal-driven** | Describe the objective, not the command sequence. Typed intents replace brittle click-paths. |
| 🔗 **MCP-native execution** | Every action is a structured `tools/call` to RedHands — the same argv validation, approval policy and engagement scope operators already trust. |
| 🧾 **Receipts by default** | An append-only, hash-chained ledger records each intent, guard decision, tool result and finding. Reports are projections — audit is not an afterthought. |
| 🛡️ **Guardrails in code** | Allowlists and hard budgets are enforced before a call leaves the process, not hoped for in a prompt. |
| 🧾 **Evidence with receipts** | Every tool output is stored as a content-addressed blob and linked from the ledger; `--retest` re-runs tools to confirm findings. |
| 📤 **Enterprise-ready exports** | SARIF 2.1.0, CycloneDX 1.5 and MITRE ATT&CK Navigator layers generated from the same projection data. |
| 🖥️ **Native + web control room** | Dioxus desktop and WASM web UIs share components; an Axum REST/SSE API streams projections and routes approvals — no Node, no database server. |
| ⚡ **Two planes, one protocol** | Go stays where it shines (the tool plane); Rust owns the control plane and the native UI. One protocol between them: MCP. |

> **Status:** v0.5.0 — auditor-grade reporting. SARIF, CycloneDX, MITRE Navigator, branded HTML and a fixed/still-open/new retest diff, on top of signed evidence and the trust boundary.

## How it works

![RedAgent autonomous loop: goal → planner → guard → RedHands via MCP → hash-chained ledger, with observations feeding back into planning](docs/how-it-works.svg)

## Quick start

Requires Rust stable and a checksum-verified **RedHands v0.6.3** binary (the pinned contract version).

```sh
cargo build --release

./target/release/redagent run "verify the lab tool plane" \
  --redhands /path/to/redhands \
  --ledger engagement.db

./target/release/redagent report  --ledger engagement.db   # re-render findings
./target/release/redagent verify  --ledger engagement.db   # check the hash chain
```

### LLM planner

```sh
export REDAGENT_LLM_API_KEY="..."
export REDAGENT_LLM_BASE_URL="https://your-openai-compatible-endpoint/v1"
export REDAGENT_LLM_MODEL="your-model"

./target/release/redagent run "enumerate the lab and report exposure" \
  --llm --toolsets nmap,vuln --allow-read-only \
  --redhands /path/to/redhands --ledger llm-run.db
```

The planner receives the real `tools/list` catalog, returns JSON-only intents, and every tool name, argument object and policy flag is validated before execution — a hallucinated tool never reaches RedHands. Malformed plans get exactly one retry, then abort into the ledger.

`--toolsets` takes **toolset ids**, not install profiles (`nmap,vuln` = nmap + nuclei; `all` is not a valid value). Without `--allow-read-only` the guard permits only `redhands_health`; with it, the live catalog's read-only, non-gated tools are admitted automatically. Gated tools still require operator approval.

### Approvals

Gated RedHands tools return an inline `input_required` result. By default RedAgent **denies** — nothing proceeds without an operator. For an isolated lab you can opt in explicitly:

```sh
./target/release/redagent run "..." --llm --auto-approve \
  --redhands /path/to/redhands --ledger lab.db
```

`--auto-approve` prints a loud warning and records `decided_by: auto-approve` in the ledger for every approval. Approval grants last exactly one tool call, matching RedHands' contract.

### Signed evidence (v0.4.1)

```sh
redagent keygen --output signer.json
redagent run "signed engagement" --signing-key signer.json \
  --checkpoint-interval 50 --redhands /path/to/redhands --ledger signed.db
redagent anchor --ledger signed.db --key signer.json --output anchor.json
redagent verify --ledger signed.db --signatures \
  --public-key <hex-from-keygen> --anchor anchor.json
```

Checkpoints sign the chain head every N events; an anchor is a portable signed
statement of the head at a point in time. **Store the key and anchors
independently of the ledger** — otherwise a rewrite can simply be re-signed.

### Scope and rules (v0.4.0)

```sh
redagent run "audit the lab" --llm --toolsets nmap,vuln --allow-read-only \
  --scope-file scope.json --require-scope \
  --redhands /path/to/redhands --ledger lab.db
```

`scope.json` declares `cidrs`, `domains`, `ports`, `target_paths`, and ordered
`rules` with effects `allow`, `deny`, `require_approval`, or `auto_approve`. The
guard extracts target-like arguments and **denies before the call leaves the
process** if a target is out of scope or cannot be resolved. Approvals now show
the exact arguments, scope verdict, risk flags and a diff from the previous call.
Tool-output injections are recorded as ledger signals. See
[THREAT_MODEL.md](THREAT_MODEL.md) for the boundary and residual risks.

The engine spawns RedHands over stdio with a minimal toolset and redirects every state directory next to the ledger — your working directory stays clean, and the resulting `.db` is a portable, verifiable engagement record.

### Evidence & exports (Phase 3)

```sh
# Re-run each tool after verification and record a retest verdict
./target/release/redagent run "..." --retest \
  --redhands /path/to/redhands --ledger engagement.db

# Machine-readable exports from any engagement ledger
./target/release/redagent export --ledger engagement.db --format sarif --output findings.sarif
./target/release/redagent export --ledger engagement.db --format cyclonedx
./target/release/redagent export --ledger engagement.db --format mitre
```

Tool outputs are stored as SHA-256 blobs under `evidence_blobs/` next to the ledger and referenced by hash in the audit trail. Retests record `still_reproducible`, `fixed` or `cannot_confirm` verdicts.

Export formats: `sarif` (2.1.0), `cyclonedx` (1.5), `mitre` (ATT&CK Navigator layer), `markdown`, and `html` (self-contained branded dossier). Compare two engagements with:

```sh
redagent retest --against baseline.db --ledger current.db --format markdown
redagent retest --against baseline.db --ledger current.db --format json
```

### Control room (Phase 2)

```sh
# Terminal 1: REST/SSE control API
./target/release/redagent serve --redhands /path/to/redhands \
  --ledger-dir ./engagements --bind 127.0.0.1:8787

# Terminal 2: native Dioxus desktop UI, or the WASM web console
cargo run --release -p redagent-ui
cargo build --release -p redagent-ui --no-default-features --features web \
  --bin redagent-ui-web --target wasm32-unknown-unknown
```

The UI lists engagements, streams live ledger projections over SSE (with polling fallback), shows findings and verifications, and lets an operator approve or deny gated tools in flight. The server also exposes plain HTTP endpoints for SOAR/scripting:

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | liveness |
| `GET /api/engagements` | engagement ids |
| `GET /api/engagements/{id}` | projection JSON |
| `GET /api/engagements/{id}/events` | raw ledger events |
| `GET /api/engagements/{id}/report` | Markdown report |
| `GET /api/engagements/{id}/export/{format}` | SARIF / CycloneDX / MITRE / Markdown download |
| `GET /api/engagements/{id}/stream` | SSE projection stream |
| `GET /api/approvals` | pending approvals |
| `POST /api/approvals/{id}` | approve / deny |
| `POST /api/engagements` | launch an engagement |

## Built different

- **No copied code, no license contamination.** Every line is original — RedAgent is clean-room, MIT, and yours.
- **No FFI, no sidecar services, no database server.** Two processes, one protocol, one Cargo.lock.
- **No hidden state.** Graphs, coverage and findings are projections of immutable events — replay, verify and export them at any time.
- **Operator-first safety.** Approved-tool gating lives in RedHands; RedAgent never gains a path around it. Authorized engagements only.

## Architecture

See [ADR 0001](docs/adr/0001-architecture.md) for the full decision record.

| Crate | Role |
|---|---|
| `redagent-core` | Event ledger, hash chain, projections, report rendering |
| `redagent-mcp` | Minimal dual-era MCP stdio client + test server |
| `redagent-llm` | OpenAI-compatible JSON chat client |
| `redagent-agent` | `Planner` trait, deterministic + LLM planners |
| `redagent-guard` | Tool allowlist and call budget |
| `redagent-evidence` | Content-addressed SHA-256 blob store |
| `redagent-app` | Engine: approvals, verifier, retest, single wiring point |
| `redagent-export` | SARIF / CycloneDX / MITRE Navigator / Markdown |
| `redagent-api` | Axum REST + SSE control API, in-flight approval queue |
| `redagent-ui` | Shared Dioxus components + native desktop and WASM web binaries |
| `redagent-cli` | `run` / `report` / `verify` / `export` / `serve` |

CI runs format, clippy, tests and release builds on Linux, macOS and Windows, plus a **live-e2e job** that downloads RedHands v0.6.3 with its published SHA-256 and drives the complete loop against the real Go server.

## Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Ledger, typed intent, MCP loop, guard, CLI, CI | ✅ shipped |
| 1 | LLM planner, verifier, approval elicitation, budgets | ✅ shipped |
| 2 | Dioxus desktop UI + Axum REST/SSE projections | ✅ shipped |
| 3 | Evidence blobs, retest loop, exports, Dioxus WASM web console | ✅ shipped |
| 4 | RBAC/KMS, OTel, WASM plugins (only if measured) | planned |

## Legal & license

MIT — Copyright (c) 2026 Mohammed Yasin. See [LICENSE](LICENSE).

RedAgent is an offensive-security tool. Use it only against systems you own or are explicitly authorized to test.

<div align="center">

**RedHands finds the tools. RedAgent finds the path.**

</div>
