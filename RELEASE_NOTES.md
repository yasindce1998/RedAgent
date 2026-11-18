# RedAgent v0.1.0

First release — the Phase 0 foundation: a typed agent loop over RedHands MCP.

- **Hash-chained SQLite event ledger** with integrity verification and derived projections (findings, intents, audit)
- **Minimal dual-era MCP stdio client** (`initialize`, `tools/list`, `tools/call`) verified against the real RedHands v0.6.3 binary
- **Deterministic Phase 0 planner** behind a `Planner` trait — an LLM planner drops in later without changing the engine
- **Guard** with tool allowlist and hard call budget
- **CLI**: `redagent run / report / verify`, producing Markdown engagement reports
- **CI**: format, clippy, tests and release builds on Linux/macOS/Windows, plus a live-e2e job against a checksum-pinned RedHands v0.6.3

Contract version: **RedHands v0.6.3**. Only authorized engagements. MIT licensed.

Verify a download:

```sh
sha256sum -c SHA256SUMS
./redagent_0.1.0/redagent --version   # redagent 0.1.0
```
