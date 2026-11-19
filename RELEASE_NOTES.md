# RedAgent v0.3.0

Phase 3 — evidence, verification, machine-readable exports and a web console.

- **Content-addressed evidence** — every successful tool output is written as a SHA-256 blob next to the ledger and referenced by hash in `EvidenceStored` events; reports show the evidence table
- **Retest loop** — `redagent run --retest` re-runs each tool through the same guard and MCP path, recording `still_reproducible` / `fixed` / `cannot_confirm` verdicts
- **Exports** — SARIF 2.1.0, CycloneDX 1.5, MITRE ATT&CK Navigator and Markdown, available from `redagent export` and `GET /api/engagements/{id}/export/{format}`
- **Dioxus WASM web console** — native desktop and browser UIs share one component library; the web binary talks only to the Axum API, with platform-specific timers isolated behind one helper
- **CI** — new `web-ui` job checks the WASM build on every PR

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

Verify a download:

```sh
sha256sum -c SHA256SUMS
./redagent_0.3.0/redagent --version   # redagent 0.3.0
```
