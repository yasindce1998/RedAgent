//! Content-addressed storage for tool-output evidence blobs.
//!
//! Blobs are keyed by the SHA-256 hex digest of their content and written as
//! `root/<first2>/<hash>.txt`. Writes are idempotent and hashes are validated
//! on read so that a caller can never escape the store with a crafted path.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

/// A content-addressed store of tool-output snapshots.
pub struct EvidenceStore {
    root: PathBuf,
}

impl EvidenceStore {
    /// Open (creating if needed) the store rooted at `root`.
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("creating evidence root {}", root.display()))?;
        Ok(Self { root })
    }

    /// Store `content`, returning its lowercase SHA-256 hex digest.
    ///
    /// Re-writing the same content is a no-op: the digest is deterministic and
    /// the destination file is overwritten with identical bytes.
    pub fn put(&self, content: &str) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let directory = self.root.join(&hash[..2]);
        fs::create_dir_all(&directory)
            .with_context(|| format!("creating evidence directory {}", directory.display()))?;
        let path = directory.join(format!("{hash}.txt"));
        fs::write(&path, content)
            .with_context(|| format!("writing evidence blob {}", path.display()))?;
        Ok(hash)
    }

    /// Read the blob identified by `hash`. Invalid digests are rejected before
    /// any filesystem access, so path traversal is impossible. The bytes on
    /// disk are hashed again: a truncated or corrupted blob is reported as an
    /// error instead of being returned as if it were valid evidence.
    pub fn get(&self, hash: &str) -> Result<String> {
        validate_hash(hash)?;
        let path = self.path(hash);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(anyhow!(
                    "evidence blob {hash} not found in store at {}",
                    self.root.display()
                ));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading evidence blob {hash} at {}", path.display())
                });
            }
        };

        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != hash {
            return Err(anyhow!(
                "evidence blob {hash} is corrupt: on-disk content hashes to {actual}"
            ));
        }
        String::from_utf8(bytes).with_context(|| format!("evidence blob {hash} is not valid UTF-8"))
    }

    /// The on-disk location for `hash`: `root/<first2>/<hash>.txt`.
    ///
    /// This is a pure path builder and never touches the filesystem. Invalid
    /// digests are mapped to an inert, root-contained placeholder path so this
    /// method cannot escape the store even if a caller passes untrusted input;
    /// [`Self::get`] rejects such digests with a clear error before reading.
    pub fn path(&self, hash: &str) -> PathBuf {
        if validate_hash(hash).is_err() {
            return self.root.join("invalid-hash").join("invalid.txt");
        }
        self.root.join(&hash[..2]).join(format!("{hash}.txt"))
    }

    /// The root directory of this store.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A valid digest is exactly 64 lowercase hex characters. Rejecting anything
/// else also rules out separators and `..` components used for traversal.
fn validate_hash(hash: &str) -> Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(anyhow!("invalid evidence hash '{hash}'"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, EvidenceStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("blobs");
        let store = EvidenceStore::new(root.clone()).expect("create store");
        (dir, store)
    }

    #[test]
    fn put_get_round_trip() {
        let (_dir, store) = store();
        let hash = store.put("### Status: OK").unwrap();
        assert_eq!(store.get(&hash).unwrap(), "### Status: OK");
    }

    #[test]
    fn hash_is_deterministic_sha256() {
        let (_dir, store) = store();
        let hash = store.put("### Status: OK").unwrap();
        assert_eq!(
            hash,
            "2b5abaaecee368f53b6be957107db6e6f713f1c7e3deb39e1a932d894764dc51"
        );
        assert_eq!(store.put("### Status: OK").unwrap(), hash);
    }

    #[test]
    fn put_is_idempotent_overwrite() {
        let (_dir, store) = store();
        let first = store.put("same bytes").unwrap();
        let second = store.put("same bytes").unwrap();
        assert_eq!(first, second);
        assert_eq!(store.get(&first).unwrap(), "same bytes");
        assert_eq!(
            fs::read_to_string(store.path(&first)).unwrap(),
            "same bytes"
        );
    }

    #[test]
    fn path_layout() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("blobs");
        let store = EvidenceStore::new(root.clone()).unwrap();
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(
            store.path(hash),
            root.join("ab").join(format!("{hash}.txt"))
        );
    }

    #[test]
    fn invalid_and_traversal_hashes_rejected() {
        let (_dir, store) = store();
        assert!(store.get("").is_err(), "empty hash");
        assert!(store.get("short").is_err(), "short hash");
        assert!(
            store
                .get("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
                .is_err(),
            "non-hex hash"
        );
        assert!(
            store
                .get("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")
                .is_err(),
            "uppercase hash"
        );
        let traversal = format!("{}x", "../".repeat(21));
        assert_eq!(traversal.len(), 64);
        assert!(store.get(&traversal).is_err(), "traversal hash");
        // The public path builder must never produce an escaping path either.
        let path = store.path(&traversal);
        assert!(path.starts_with(store.root()), "{:?} escapes root", path);
        assert!(!path.components().any(|c| c.as_os_str() == ".."));
    }

    #[test]
    fn get_reports_missing_blob_clearly() {
        let (_dir, store) = store();
        let hash = "ab".repeat(32);
        let err = store.get(&hash).unwrap_err().to_string();
        assert!(err.contains(&hash), "{err}");
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn get_rejects_corrupt_blob() {
        let (_dir, store) = store();
        let hash = store.put("original content").unwrap();
        fs::write(store.path(&hash), "tampered content").unwrap();
        let err = store.get(&hash).unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
        assert!(err.contains(&hash), "{err}");
    }

    #[test]
    fn get_rejects_partial_blob() {
        let (_dir, store) = store();
        let content = "a tool output long enough to be truncated into a partial write";
        let hash = store.put(content).unwrap();
        fs::write(store.path(&hash), &content[..12]).unwrap();
        let err = store.get(&hash).unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn new_creates_root_recursively() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("a").join("b").join("blobs");
        let store = EvidenceStore::new(root.clone()).unwrap();
        assert!(root.is_dir());
        assert_eq!(store.root(), root.as_path());
    }
}
