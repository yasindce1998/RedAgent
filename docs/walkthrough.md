# Walkthrough: a signed, scoped engagement

This is the output of a real run against a checksum-pinned RedHands v0.6.3
binary. It shows the trust features working together.

## 1. Prepare a signing key and a scope

```sh
redagent keygen --output signer.json
cat > scope.json <<'EOF'
{
  "cidrs": [],
  "domains": ["example.com"],
  "ports": [],
  "target_paths": ["target", "host"],
  "rules": []
}
EOF
```

`keygen` prints only the public key hex and key id. Store `signer.json`
**separately from the ledger**.

## 2. Run an engagement

```sh
redagent run "verify the lab tool plane" \
  --redhands /path/to/redhands \
  --ledger engagement.db \
  --scope-file scope.json --require-scope \
  --signing-key signer.json --checkpoint-interval 2 \
  --replan-attempts 1
```

If a tool argument contains a target outside `example.com` — or a target the
guard cannot resolve — the call is denied *before* it leaves the process and a
`ScopeDenied` event is recorded. Without `--scope-file`, `--require-scope`
aborts immediately.

## 3. Report excerpt

```markdown
# RedAgent engagement report

- **Goal:** verify the lab tool plane
- **RedHands:** v0.6.3
- **Status:** completed

## Findings

### Verify RedHands health (4) (info)

Evidence: ledger event #4

## Verification

- **finding-1** → verified → ledger event #4

## Signed checkpoints

| Ledger seq | Head hash | Key ID | Signature | Signed at |
|---|---|---|---|---|
| 2 | 2d135e3b… | b5eaeba1… | 3338ea35… | 2026-11-23T11:16:14Z |
```

## 4. Verify and export

```sh
redagent verify --ledger engagement.db --signatures \
  --public-key <hex-from-keygen>
# OK: 12 events, hash chain verified
# OK: 4 signed checkpoints verified

redagent anchor --ledger engagement.db --key signer.json --output anchor.json
redagent export --ledger engagement.db --format html --output dossier.html
redagent retest --against baseline.db --ledger engagement.db --format markdown
```

## 5. Verify any tool server

```sh
redagent conformance --binary /path/to/any-mcp-server --timeout-secs 15
# Verdict: PASS — 7/7 checks passed
```

For planner/worker tracing, set `REDAGENT_LOG=debug` or `trace`.
