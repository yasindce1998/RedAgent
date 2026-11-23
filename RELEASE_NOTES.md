# RedAgent v0.6.0

Resilient agent loop — the final item of the improvement roadmap.

- **Backtracking**: rejected plans become `PlanRejected` ledger events; the planner is retried with a structured memory projection (targets, coverage, open findings, redacted credentials) and the earlier failure reasons, bounded by `--replan-attempts`
- **Token budgets**: `--max-llm-tokens` enforces model `usage` counters before any tool call; overruns produce `TokenBudgetExhausted` events
- **Tracing**: `REDAGENT_LOG=debug|trace` prints planner/worker span timings from the CLI and API
- **CLI/API parity**: `--replan-attempts` and `--max-llm-tokens` available on both surfaces
- Docs: `THREAT_MODEL.md`, ADR decisions and a real signed/scoped `docs/walkthrough.md`

This release completes all five improvement work packages on top of v0.5.1's
adapter/conformance suite, v0.5.0's auditor exports, v0.4.1's signed evidence
and v0.4.0's trust boundary.

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

```sh
sha256sum -c SHA256SUMS
./redagent_0.6.0/redagent --version   # redagent 0.6.0
```
