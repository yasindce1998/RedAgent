# RedAgent v0.4.1

Signed evidence — ed25519 checkpoints and portable anchors for the event ledger.

- **`redagent keygen`** generates a signing key with an independent-storage warning and 0600 file permissions
- **Automatic checkpoints**: `redagent run --signing-key <file> --checkpoint-interval N` signs the chain head every N events; checkpoints are ledger events and appear in reports
- **`redagent anchor`** writes a portable signed checkpoint of the current ledger head
- **`redagent verify --signatures --public-key <hex> [--anchor <file>]`** verifies every checkpoint against its ledger event and validates the external anchor
- Ledger remains backward compatible: old ledgers verify without checkpoints and new event fields use serde defaults

Security note: a hash chain plus signatures only protects against ledger rewriting when the signing key and anchor are stored independently of the ledger. See `THREAT_MODEL.md`.

Contract version: **RedHands v0.6.3**. MIT licensed. Authorized engagements only.

```sh
sha256sum -c SHA256SUMS
./redagent_0.4.1/redagent --version   # redagent 0.4.1
```
