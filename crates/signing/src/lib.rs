//! Ed25519 signing for RedAgent ledger checkpoints.
//!
//! A checkpoint binds an append-only ledger's sequence number and head hash to
//! a signature made with a dedicated key. This detects rewriting of the ledger,
//! **but only if the signing key and an external anchor are kept independently
//! of the ledger being protected**:
//!
//! * An attacker who can edit the ledger *and* read the signing key can simply
//!   recompute the head hash and re-sign the rewritten history, so the key
//!   should live in a separate trust domain (ideally offline).
//! * An attacker who can edit the ledger can otherwise roll it back together
//!   with all of its checkpoints and present a shorter, internally consistent
//!   history. A verifier therefore needs an independent anchor — a published
//!   checkpoint, an external append-only log, or similar — holding a trusted
//!   public key and a trusted `(seq, head_hash)` pair.
//!
//! Signatures are a detection mechanism, not a substitute for that anchor.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Prefix of the canonical message, binding signatures to this format version.
const MESSAGE_PREFIX: &str = "redagent-checkpoint-v1";
/// Number of bytes in an Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;
/// Number of hex characters in an Ed25519 public key.
const PUBLIC_HEX_LEN: usize = 64;
/// Number of bytes in an Ed25519 signature.
const SIGNATURE_LEN: usize = 64;
/// Number of hex characters in an Ed25519 signature.
const SIGNATURE_HEX_LEN: usize = 128;
/// Number of hex characters in a key id (8 bytes).
const KEY_ID_HEX_LEN: usize = 16;

/// A signed statement about one position in the ledger.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Checkpoint {
    /// Monotonically increasing event sequence number covered by this checkpoint.
    pub seq: i64,
    /// Lowercase SHA-256 hex digest of the ledger head at `seq`.
    pub head_hash: String,
    /// First 16 hex characters of the signer's public key.
    pub key_id: String,
    /// Lowercase hex encoding of the 64-byte Ed25519 signature.
    pub signature: String,
    /// Signing timestamp, as supplied by the caller (must be non-empty).
    pub ts: String,
}

/// An Ed25519 signing key used to produce [`Checkpoint`] signatures.
///
/// Keep the key material outside the ledger it signs; see the [module docs](crate)
/// for why an independent external anchor is also required.
pub struct SigningKey {
    inner: DalekSigningKey,
}

/// On-disk representation of a signing key.
///
/// The secret is stored as lowercase hex; the public key is stored alongside it
/// solely so [`SigningKey::from_file`] can detect corrupted or substituted keys.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    secret_hex: String,
    public_hex: String,
}

impl SigningKey {
    /// Generate a fresh key from the operating system's CSPRNG.
    ///
    /// Uses `rand_core`'s `OsRng` and reports entropy failures as errors rather
    /// than panicking.
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; PUBLIC_KEY_LEN];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut secret)
            .map_err(|error| anyhow!("generating Ed25519 key material: {error}"))?;
        Ok(Self {
            inner: DalekSigningKey::from_bytes(&secret),
        })
    }

    /// Load a key from a JSON file written by [`SigningKey::to_file`].
    ///
    /// The derived public key must match the public key stored in the file; a
    /// mismatch is rejected as an error.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("reading signing key from {}", path.display()))?;
        let stored: KeyFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing signing key at {}", path.display()))?;

        let secret = decode_fixed::<PUBLIC_KEY_LEN>(&stored.secret_hex)
            .ok_or_else(|| anyhow!("invalid secret key material in {}", path.display()))?;
        let inner = DalekSigningKey::from_bytes(&secret);
        let derived = inner.verifying_key().to_bytes();
        let stored_public = decode_fixed::<PUBLIC_KEY_LEN>(&stored.public_hex)
            .ok_or_else(|| anyhow!("invalid public key material in {}", path.display()))?;
        if derived != stored_public {
            return Err(anyhow!(
                "public key in {} does not match the stored secret key",
                path.display()
            ));
        }
        Ok(Self { inner })
    }

    /// Write the key as JSON to `path`.
    ///
    /// On Unix the file is created with mode `0600`. An existing file is only
    /// replaced when `overwrite` is `true`.
    pub fn to_file(&self, path: &Path, overwrite: bool) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating key directory {}", parent.display()))?;
            }
        }

        let key_file = KeyFile {
            secret_hex: hex::encode(self.inner.to_bytes()),
            public_hex: self.public_hex(),
        };

        let mut options = OpenOptions::new();
        options.write(true);
        if overwrite {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("opening signing key file {}", path.display()))?;
        serde_json::to_writer_pretty(&mut file, &key_file)
            .with_context(|| format!("writing signing key to {}", path.display()))?;
        file.flush()
            .with_context(|| format!("flushing signing key at {}", path.display()))?;

        // `mode` applies only when a file is created; enforce 0600 even when
        // overwriting a file that previously had different permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("setting permissions on {}", path.display()))?;
        }
        Ok(())
    }

    /// Lowercase hex encoding of the full Ed25519 public key.
    pub fn public_hex(&self) -> String {
        hex::encode(self.inner.verifying_key().to_bytes())
    }

    /// Short key identifier: the first 16 hex characters of the public key.
    pub fn key_id(&self) -> String {
        self.public_hex().chars().take(KEY_ID_HEX_LEN).collect()
    }

    /// Sign a ledger position, returning a [`Checkpoint`].
    ///
    /// Rejects an invalid `head_hash` or an empty `ts`. The signed message is
    /// `"redagent-checkpoint-v1|{seq}|{head_hash}|{key_id}|{ts}"`.
    pub fn sign(&self, seq: i64, head_hash: &str, ts: &str) -> Result<Checkpoint> {
        validate_hash(head_hash)?;
        if ts.trim().is_empty() {
            return Err(anyhow!("timestamp must not be empty"));
        }
        let key_id = self.key_id();
        let message = canonical_message(seq, head_hash, &key_id, ts);
        let signature: Signature = self.inner.sign(message.as_bytes());
        Ok(Checkpoint {
            seq,
            head_hash: head_hash.to_owned(),
            key_id,
            signature: hex::encode(signature.to_bytes()),
            ts: ts.to_owned(),
        })
    }
}

/// Verify a checkpoint against a lowercase hex Ed25519 public key.
///
/// Returns `Ok(false)` (never an error and never a panic) for malformed hex,
/// malformed signatures, a key id that does not match `public_hex`, or a
/// signature that does not verify over the canonical message. `Ok(true)` means
/// the signature is valid and only that.
///
/// Remember that a valid signature proves nothing about the ledger unless the
/// public key and a trusted checkpoint are anchored independently; see the
/// [module docs](crate).
pub fn verify(checkpoint: &Checkpoint, public_hex: &str) -> Result<bool> {
    let Some(public) = decode_lower_hex::<PUBLIC_KEY_LEN>(public_hex, PUBLIC_HEX_LEN) else {
        return Ok(false);
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public) else {
        return Ok(false);
    };

    let expected_key_id: String = hex::encode(public).chars().take(KEY_ID_HEX_LEN).collect();
    if checkpoint.key_id != expected_key_id {
        return Ok(false);
    }
    if validate_hash(&checkpoint.head_hash).is_err() || checkpoint.ts.trim().is_empty() {
        return Ok(false);
    }
    let Some(signature_bytes) =
        decode_lower_hex::<SIGNATURE_LEN>(&checkpoint.signature, SIGNATURE_HEX_LEN)
    else {
        return Ok(false);
    };

    let message = canonical_message(
        checkpoint.seq,
        &checkpoint.head_hash,
        &checkpoint.key_id,
        &checkpoint.ts,
    );
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .is_ok())
}

/// Require exactly 64 lowercase hex characters (`b'0'..=b'9' | b'a'..=b'f'`).
pub fn validate_hash(hash: &str) -> Result<()> {
    if is_lower_hex(hash, PUBLIC_HEX_LEN) {
        Ok(())
    } else {
        Err(anyhow!(
            "hash must be exactly {PUBLIC_HEX_LEN} lowercase hex characters"
        ))
    }
}

/// Decode exactly `N` bytes worth of lowercase hex, rejecting any other form.
fn decode_lower_hex<const N: usize>(value: &str, hex_len: usize) -> Option<[u8; N]> {
    if !is_lower_hex(value, hex_len) || value.len() != N * 2 {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

/// Decode hex of the expected length, also accepting uppercase (for key files).
fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

fn is_lower_hex(value: &str, hex_len: usize) -> bool {
    value.len() == hex_len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The exact byte string covered by a checkpoint signature.
fn canonical_message(seq: i64, head_hash: &str, key_id: &str, ts: &str) -> String {
    format!("{MESSAGE_PREFIX}|{seq}|{head_hash}|{key_id}|{ts}")
}
