# ADR 0001 — RedAgent architecture

Status: accepted

## Context

RedHands (Go, MIT) is a mature MCP tool server: 294 typed tools, approval
policies, engagement scope, audit log, targetdb, campaign engine. MCP exposes
capabilities but provides no autonomy — no planner, no cross-step memory, no
coverage tracking, no adaptive re-planning.

Existing autonomous-pentest designs were reviewed for patterns such as
planner/worker loops, dual graphs, evidence binding and approval gates. Their
implementations were judged too fragmented and heavyweight for this project.
All RedAgent code is original; no external implementation was copied.

## Decision

- **Go remains the tool plane** — RedHands is consumed over MCP, unchanged.
- **Rust is the control plane and UI language.** One binary compiles the core,
  CLI and (from Phase 2) the Dioxus UI.
- **MCP is the only boundary between Go and Rust** — no FFI, no shared memory,
  no shared database. Local mode spawns a checksum-pinned `redhands` binary over
  stdio; remote mode connects over HTTP.
- **An append-only SQLite event ledger is the single source of truth.** The
  asset/exploration graphs, coverage ledger, findings and audit chain are
  projections derived from events, never independently mutated.
- **Typed intents and schema-validated LLM output**; no free-form shell is
  exposed to the agent — every target action is a `tools/call` on RedHands.
- **Dioxus** is the planned Phase 2 UI (desktop + optional WASM web console).
  The UI crate will hold no business logic, so the choice stays reversible.
- **License: MIT.** All code is original and clean-room.

## Consequences

Positive: strong compile-time guarantees for policy/state code, one release
artifact for the agent, clean independent release cycles for the two planes,
no AGPL obligations.

Costs: Rust has a steeper learning curve and slower iteration than Go; LLM and
MCP SDK ecosystems are thinner (mitigated by plain HTTP + a minimal JSON-RPC
client). Adding a third process or language requires a measured bottleneck.

## Scope of Phase 0

Event ledger, deterministic single-intent planner, minimal MCP stdio client,
guard allowlist/budget, CLI (`run` / `report` / `verify`) and CI.

## Phase 1 decisions

- **LLM planner** implements the same `Planner` trait. It receives the live
  `tools/list` catalog, emits JSON-only intents, validates every tool name and
  argument object, and retries once on malformed output. A hallucinated tool
  never reaches RedHands.
- **Approvals fail closed.** Gated tools return RedHands' inline
  `input_required` result; the default handler denies. `--auto-approve` is an
  explicit, loudly warned lab-only option and is recorded in the ledger.
- **Verifier** is a trait; Phase 1 uses a heuristic implementation so results
  are checked before findings are recorded. An LLM verifier can replace it
  without changing the engine.
- Budgets are enforced in the guard before each call and recorded as events.

## Phase 2 decisions

- **Axum control API** exposes the ledger as REST plus an SSE projection stream.
  It never mutates ledger history; run requests append new events through the
  same engine. In-flight approvals are routed through a channel-backed handler
  and a `POST /api/approvals/{id}` endpoint — the operator decision is recorded
  in the ledger, so remote approval has the same audit semantics as local.
- **Dioxus native UI** (0.7 native renderer, no webview and no Node) renders
  projections and posts commands over the API. It holds no business logic: all
  decisions remain in `redagent-app`.
- The UI ships as a separate binary (`redagent-ui`); the CLI gains `serve` to
  start the API. One Rust workspace, no frontend toolchain.

## Phase 3 decisions

- **Evidence blobs** are SHA-256 content-addressed files stored next to the
  ledger; events reference hashes, never duplicate large output. The audit
  trail stays compact and verifiable.
- **Retest** is an opt-in engine flag that re-runs a tool after verification and
  records a `still_reproducible` / `fixed` / `cannot_confirm` verdict as events.
  It reuses the same guard and MCP path — no separate execution mechanism.
- **Exports** (SARIF 2.1.0, CycloneDX 1.5, MITRE Navigator) are pure functions
  of projections. They are available from both the CLI and the API, so the
  engine never needs to know about report formats.
- **Web console** reuses the same Dioxus components as the desktop UI via a
  WASM binary; platform-specific sleeps are isolated behind a single helper.
  The browser talks only to the Axum API — no direct ledger access.

RBAC/KMS, OpenTelemetry and optional WASM plugins remain later phases.
