# RedAgent v0.3.1

Hardening release — 14 bugs fixed with regression tests, verified against the
real RedHands tool plane.

## Highlights

- **Security**: API keys are redacted from every LLM error path; export filenames and API ids cannot inject headers or escape the ledger directory
- **Ledger integrity**: hashes are verified against the stored payload bytes; future/unknown event kinds no longer break older readers; evidence blobs are integrity-checked on read
- **Agent correctness**: retest verdicts no longer claim `fixed` for findings that never verified; planner validates rationale, required arguments, duplicates and untrusted data framing
- **Real chaining**: `--toolsets nmap,vuln` and `--allow-read-only` expose the live catalog with RedHands policy metadata so LLM plans can use more than `redhands_health`
- **Control room**: approval decision races, SSE leaks on deleted ledgers, stale UI responses and unsafe URL construction fixed
- **Exports**: MITRE technique word boundaries, SARIF rule dedup and collision-free CycloneDX serials

## Verification

- 123 workspace tests, fmt, clippy `-D warnings`, native release build and WASM target check all green
- Old v0.3.0 ledgers still verify with the hardened binary
- Live run against checksum-pinned RedHands v0.6.3 with retest and non-default toolsets; exports and API validation checks passed

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

```sh
sha256sum -c SHA256SUMS
./redagent_0.3.1/redagent --version   # redagent 0.3.1
```
