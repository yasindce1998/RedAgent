use std::fs;

use redagent_signing::{validate_hash, verify, Checkpoint, SigningKey};

const TS: &str = "2026-11-19T00:00:00Z";

fn hash_a() -> String {
    "ab".repeat(32)
}

fn hash_b() -> String {
    "cd".repeat(32)
}

fn checkpoint() -> (SigningKey, Checkpoint) {
    let key = SigningKey::generate().expect("key generation");
    let cp = key
        .sign(7, &hash_a(), TS)
        .expect("signing a valid checkpoint");
    (key, cp)
}

#[test]
fn generate_sign_verify_round_trip() {
    let (key, cp) = checkpoint();
    assert_eq!(cp.seq, 7);
    assert_eq!(cp.head_hash, hash_a());
    assert_eq!(cp.ts, TS);
    assert_eq!(cp.key_id, key.key_id());
    assert_eq!(cp.key_id, &key.public_hex()[..16]);
    assert_eq!(cp.signature.len(), 128);
    assert_eq!(cp.signature, cp.signature.to_lowercase());

    assert!(verify(&cp, &key.public_hex()).expect("verify must not error"));

    let other = SigningKey::generate().expect("second key generation");
    assert_ne!(key.public_hex(), other.public_hex());
}

#[test]
fn canonical_message_is_exactly_the_documented_format() {
    let (key, cp) = checkpoint();
    let public: [u8; 32] = hex::decode(key.public_hex())
        .expect("hex public key")
        .try_into()
        .expect("32 public key bytes");
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public).expect("valid public key");
    let signature: [u8; 64] = hex::decode(&cp.signature)
        .expect("hex signature")
        .try_into()
        .expect("64 signature bytes");
    let message = format!(
        "redagent-checkpoint-v1|{}|{}|{}|{}",
        cp.seq, cp.head_hash, cp.key_id, cp.ts
    );
    assert!(verifying
        .verify_strict(
            message.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&signature)
        )
        .is_ok());
}

#[test]
fn tampered_fields_are_rejected() {
    let (key, cp) = checkpoint();
    let public = key.public_hex();

    let mut changed_hash = cp.clone();
    changed_hash.head_hash = hash_b();
    assert!(!verify(&changed_hash, &public).expect("verify must not error"));

    let mut changed_seq = cp.clone();
    changed_seq.seq = cp.seq + 1;
    assert!(!verify(&changed_seq, &public).expect("verify must not error"));

    let mut changed_ts = cp.clone();
    changed_ts.ts = "2026-11-20T00:00:00Z".to_owned();
    assert!(!verify(&changed_ts, &public).expect("verify must not error"));

    let mut changed_key_id = cp.clone();
    changed_key_id.key_id = "0000000000000000".to_owned();
    assert!(!verify(&changed_key_id, &public).expect("verify must not error"));

    let mut changed_hash = cp;
    changed_hash.head_hash = "ef".repeat(32);
    assert!(!verify(&changed_hash, &public).expect("verify must not error"));
}

#[test]
fn wrong_and_malformed_public_keys_are_rejected() {
    let (_, cp) = checkpoint();
    let other = SigningKey::generate().expect("second key generation");
    assert!(!verify(&cp, &other.public_hex()).expect("verify must not error"));

    let empty = "";
    let non_hex = "not-hex";
    let bad_char = "g".repeat(64);
    let short = "ab".repeat(31);
    let upper = "AB".repeat(32);
    for bad in [
        empty,
        non_hex,
        bad_char.as_str(),
        short.as_str(),
        upper.as_str(),
    ] {
        assert!(
            !verify(&cp, bad).expect("verify must not error"),
            "bad public key {bad:?} was accepted"
        );
    }
}

#[test]
fn malformed_checkpoint_data_is_rejected_without_panicking() {
    let (key, cp) = checkpoint();
    let public = key.public_hex();

    let empty = "";
    let non_hex = "zz";
    let short = "ab".repeat(63);
    let upper = "AB".repeat(64);
    let long = "ab".repeat(65);
    for bad_signature in [
        empty,
        non_hex,
        short.as_str(),
        upper.as_str(),
        long.as_str(),
    ] {
        let mut bad = cp.clone();
        bad.signature = bad_signature.to_owned();
        assert!(
            !verify(&bad, &public).expect("verify must not error"),
            "bad signature {bad_signature:?} was accepted"
        );
    }

    let mut bad_hash = cp.clone();
    bad_hash.head_hash = "not a hash".to_owned();
    assert!(!verify(&bad_hash, &public).expect("verify must not error"));

    let mut bad_key_id = cp;
    bad_key_id.key_id = "xyz".to_owned();
    assert!(!verify(&bad_key_id, &public).expect("verify must not error"));

    assert!(key.sign(1, "bad", TS).is_err());
    assert!(key.sign(1, &hash_a(), "").is_err());
    assert!(key.sign(1, &hash_a(), "   ").is_err());
}

#[test]
fn validate_hash_table() {
    let short = "ab".repeat(31);
    let upper = "AB".repeat(32);
    let non_hex = "g".repeat(64);
    let valid = "ab".repeat(32);
    let cases = [
        ("", false),
        (short.as_str(), false),
        (upper.as_str(), false),
        (non_hex.as_str(), false),
        (valid.as_str(), true),
    ];
    for (value, expected) in cases {
        assert_eq!(
            validate_hash(value).is_ok(),
            expected,
            "validate_hash({value:?})"
        );
    }

    let mut uppercase_with_digits = "A".repeat(64);
    uppercase_with_digits.replace_range(0..1, "0");
    assert!(validate_hash(&uppercase_with_digits).is_err());
}

#[test]
fn key_file_round_trip_and_overwrite() {
    let dir = tempfile::tempdir().expect("temp directory");
    let path = dir.path().join("nested").join("signing-key.json");
    let key = SigningKey::generate().expect("key generation");

    key.to_file(&path, false).expect("write key file");
    let contents = fs::read_to_string(&path).expect("read key file");
    assert!(contents.contains("secret_hex"));
    assert!(contents.contains("public_hex"));

    let loaded = SigningKey::from_file(&path).expect("load key file");
    assert_eq!(loaded.public_hex(), key.public_hex());
    assert_eq!(loaded.key_id(), key.key_id());
    let cp = loaded
        .sign(11, &hash_a(), TS)
        .expect("sign with loaded key");
    assert!(verify(&cp, &key.public_hex()).expect("verify must not error"));

    let other = SigningKey::generate().expect("second key generation");
    assert!(
        other.to_file(&path, false).is_err(),
        "overwrote without consent"
    );
    other.to_file(&path, true).expect("overwrite allowed");
    let reloaded = SigningKey::from_file(&path).expect("reload key file");
    assert_eq!(reloaded.public_hex(), other.public_hex());

    assert!(
        SigningKey::from_file(&dir.path().join("missing.json")).is_err(),
        "missing file must error"
    );
}

#[test]
fn key_file_rejects_corrupt_or_mismatched_data() {
    let dir = tempfile::tempdir().expect("temp directory");
    let path = dir.path().join("key.json");
    let key = SigningKey::generate().expect("key generation");
    key.to_file(&path, false).expect("write key file");

    fs::write(&path, "not json").expect("write garbage");
    assert!(SigningKey::from_file(&path).is_err());

    // Restore a well-formed file, then replace its public key with one derived
    // from a different secret; that mismatch must be rejected.
    key.to_file(&path, true).expect("rewrite key file");
    let wrong_public = SigningKey::generate()
        .expect("second key generation")
        .public_hex();
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read key file"))
            .expect("parse key file");
    value["public_hex"] = serde_json::Value::String(wrong_public);
    fs::write(
        &path,
        serde_json::to_string(&value).expect("serialize key file"),
    )
    .expect("write mismatched key file");
    assert!(
        SigningKey::from_file(&path).is_err(),
        "mismatched public key must be rejected"
    );

    value["secret_hex"] = serde_json::Value::String("zz".to_owned());
    fs::write(
        &path,
        serde_json::to_string(&value).expect("serialize key file"),
    )
    .expect("write invalid secret file");
    assert!(SigningKey::from_file(&path).is_err());
}

#[cfg(unix)]
#[test]
fn key_file_mode_is_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp directory");
    let path = dir.path().join("key.json");
    let key = SigningKey::generate().expect("key generation");

    key.to_file(&path, false).expect("write key file");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "new key file mode");

    // Overwriting a file with looser permissions must tighten them again.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen permissions");
    key.to_file(&path, true).expect("overwrite key file");
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "overwritten key file mode");
}
