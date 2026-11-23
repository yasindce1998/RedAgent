# RedAgent v0.5.0

Auditor-grade reporting on top of the signed, scope-enforced evidence chain.

- **HTML export** — self-contained branded dossier with inline CSS, responsive layout, findings/verification/evidence sections and MITRE technique chips; every untrusted string is HTML-escaped
- **Retest diff** — `redagent retest --against baseline.db --ledger current.db` reports fixed / still-open / new findings in Markdown or JSON
- **MITRE Navigator layer** — now driven by `T####` IDs extracted from finding titles and tool output
- **SARIF 2.1.0 / CycloneDX 1.5** gains from the earlier hardening pass remain available
- API exports accept `html`; the Dioxus UI exposes an HTML export card

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

```sh
sha256sum -c SHA256SUMS
./redagent_0.5.0/redagent --version   # redagent 0.5.0
```
