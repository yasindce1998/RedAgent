# RedAgent v0.5.1

Tool-plane agnostic adapter layer and conformance suite.

- **`redagent-contract`** — manifest describing protocol versions, capabilities, approval semantics and JSON pointers to a tool server's policy fields; `ToolServerManifest::redhands()` ships the built-in profile; normalization fails closed when policy fields are absent
- **`redagent-conformance`** — seven-check verification of handshake, catalog, schema, read-only signals, a real tool call, error semantics and inline approvals
- **`redagent conformance --binary <path> [--manifest <file>]`** — run the suite against any MCP tool server, with a Markdown pass/fail report
- **`redagent run --manifest <file>`** — normalize the live catalog through the adapter manifest before planning
- Verified live against the checksum-pinned RedHands v0.6.3 release: 7/7 checks, 287 tools normalized

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

```sh
sha256sum -c SHA256SUMS
./redagent_0.5.1/redagent --version   # redagent 0.5.1
```
