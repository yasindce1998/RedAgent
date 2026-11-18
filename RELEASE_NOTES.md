# RedAgent v0.2.0

Phase 1 and Phase 2 — an autonomous agent loop with a native control room.

## Autonomous loop (Phase 1)

- **LLM planner** — schema-validated JSON intents checked against the live RedHands `tools/list` catalog; hallucinated tools never execute; one retry on malformed plans
- **Approval elicitation** — RedHands' inline `input_required` results replayed with `inputResponses`; default deny, explicit `--auto-approve` for labs, every decision recorded
- **Verifier** — results checked before findings are recorded; verification links appear in reports
- **Budgets** — tool-call and intent caps enforced in code with ledger events

## Control room (Phase 2)

- **Axum REST/SSE API** — engagement list/detail/events/report, live `event: snapshot` stream, run endpoint, and an in-flight approval queue with `GET /api/approvals` / `POST /api/approvals/{id}`
- **Dioxus 0.7 native desktop UI** — engagement list, status cards, findings/verification tables, approval queue, tool evidence, run form and polling; no webview, no Node
- **`redagent serve`** — starts the API with configurable bind address, ledger dir, RedHands binary and approval timeout
- **Serializable projections** — one typed contract shared by engine, API and UI

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

Verify a download:

```sh
sha256sum -c SHA256SUMS
./redagent_0.2.0/redagent --version   # redagent 0.2.0
```
