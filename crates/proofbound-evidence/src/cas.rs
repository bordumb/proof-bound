use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{canonical_json, domain_hash, verify_domain_hash};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("evidence store I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("evidence JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid digest syntax: {0}")]
    InvalidDigest(String),
    #[error("stored object {digest} is corrupt for domain {domain}")]
    Corrupt { digest: String, domain: String },
    #[error("refusing symlink at sealed evidence boundary: {0}")]
    Symlink(PathBuf),
}

#[derive(Debug, Clone)]
pub struct ContentAddressedStore {
    root: PathBuf,
}

impl ContentAddressedStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put<T: Serialize>(&self, domain: &str, value: &T) -> Result<String, StoreError> {
        let bytes = canonical_json(value)?;
        self.put_bytes(domain, &bytes)
    }

    pub fn put_bytes(&self, domain: &str, bytes: &[u8]) -> Result<String, StoreError> {
        let digest = domain_hash(domain, bytes);
        let path = self.path_for(&digest)?;
        let parent = path.parent().expect("CAS object path always has a parent");
        self.ensure_directory(parent)?;

        if path.exists() {
            self.reject_symlink(&path)?;
            let existing = fs::read(&path).map_err(|source| StoreError::Io {
                path: path.clone(),
                source,
            })?;
            if existing != bytes || !verify_domain_hash(domain, &existing, &digest) {
                return Err(StoreError::Corrupt {
                    digest,
                    domain: domain.to_owned(),
                });
            }
            return Ok(digest);
        }

        let temp = parent.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            &digest["sha256:".len()..][..16]
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|source| StoreError::Io {
                path: temp.clone(),
                source,
            })?;
        file.write_all(bytes).map_err(|source| StoreError::Io {
            path: temp.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| StoreError::Io {
            path: temp.clone(),
            source,
        })?;
        fs::rename(&temp, &path).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(digest)
    }

    pub fn get<T: DeserializeOwned>(&self, domain: &str, digest: &str) -> Result<T, StoreError> {
        let bytes = self.get_bytes(domain, digest)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn get_bytes(&self, domain: &str, digest: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.path_for(digest)?;
        self.reject_symlink(&path)?;
        let bytes = fs::read(&path).map_err(|source| StoreError::Io { path, source })?;
        if !verify_domain_hash(domain, &bytes, digest) {
            return Err(StoreError::Corrupt {
                digest: digest.to_owned(),
                domain: domain.to_owned(),
            });
        }
        Ok(bytes)
    }

    pub fn contains_valid(&self, domain: &str, digest: &str) -> bool {
        self.get_bytes(domain, digest).is_ok()
    }

    pub fn path_for(&self, digest: &str) -> Result<PathBuf, StoreError> {
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(StoreError::InvalidDigest(digest.to_owned()));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(StoreError::InvalidDigest(digest.to_owned()));
        }
        Ok(self
            .root
            .join("sha256")
            .join(&hex[..2])
            .join(format!("{hex}.json")))
    }

    fn ensure_directory(&self, path: &Path) -> Result<(), StoreError> {
        // Ancestors outside the configured store are not part of the sealed
        // boundary (on macOS `/var` itself is commonly a system symlink).
        // Reject links at the store root and at every descendant instead.
        if self.root.exists() {
            self.reject_symlink(&self.root)?;
        } else {
            fs::create_dir_all(&self.root).map_err(|source| StoreError::Io {
                path: self.root.clone(),
                source,
            })?;
        }
        let relative = path.strip_prefix(&self.root).map_err(|_| StoreError::Io {
            path: path.to_owned(),
            source: std::io::Error::other("evidence path escapes store root"),
        })?;
        let mut current = self.root.clone();
        for component in relative.components() {
            current.push(component);
            if current.exists() {
                self.reject_symlink(&current)?;
            }
        }
        fs::create_dir_all(path).map_err(|source| StoreError::Io {
            path: path.to_owned(),
            source,
        })
    }

    fn reject_symlink(&self, path: &Path) -> Result<(), StoreError> {
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata.file_type().is_symlink()
        {
            return Err(StoreError::Symlink(path.to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClosureKind, ClosureLimits, build_closure};
    use serde_json::json;

    use super::*;

    #[test]
    fn round_trip_and_detect_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let store = ContentAddressedStore::new(temp.path());
        let digest = store.put("test/1", &json!({"ok": true})).unwrap();
        let actual: serde_json::Value = store.get("test/1", &digest).unwrap();
        assert_eq!(actual, json!({"ok": true}));

        fs::write(store.path_for(&digest).unwrap(), b"{}").unwrap();
        assert!(matches!(
            store.get_bytes("test/1", &digest),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn semantic_byte_change_changes_content_addressed_receipt_identity() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        let source = temp.path().join("src/model.rs");
        fs::write(&source, b"first meaning").unwrap();
        let before = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            Some("TEST-CLAIM-001".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();

        fs::write(&source, b"second meaning").unwrap();
        let after = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            Some("TEST-CLAIM-001".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();
        assert_ne!(before.id, after.id);

        let store = ContentAddressedStore::new(temp.path().join("store"));
        let before_receipt = json!({
            "schema": "proofbound-evidence/1",
            "semantic_source_closure": before.id,
        });
        let after_receipt = json!({
            "schema": "proofbound-evidence/1",
            "semantic_source_closure": after.id,
        });
        let before_identity = store.put("proofbound-evidence/1", &before_receipt).unwrap();
        let after_identity = store.put("proofbound-evidence/1", &after_receipt).unwrap();
        assert_ne!(before_identity, after_identity);
    }
}
