use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use walkdir::WalkDir;

use crate::{canonical_json, domain_hash, sha256_bytes};

const DISCOVERY_METHODS: &[&str] = &[
    "assumption-review-claim-union/1",
    "build-tool-transitive/1",
    "evidence-unit-inputs/1",
    "external-evidence/1",
    "project-presentation/1",
    "project-runner/1",
    "toolchains/1",
    "unit-claim-union/1",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClosureKind {
    Semantic,
    Runner,
    Presentation,
    ExternalEvidence,
    Toolchain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureMember {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureRecord {
    pub schema: String,
    pub id: String,
    pub kind: ClosureKind,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub members: Vec<ClosureMember>,
    pub total_bytes: u64,
    pub discovery: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_identity: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ClosureLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for ClosureLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_total_bytes: 1 << 32,
            max_file_bytes: 64 << 20,
        }
    }
}

#[derive(Debug, Error)]
pub enum ClosureError {
    #[error("closure root is not a canonical directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("invalid closure pattern {pattern}: {message}")]
    InvalidPattern { pattern: String, message: String },
    #[error("unsupported closure discovery method: {0}")]
    InvalidDiscovery(String),
    #[error("closure path is non-canonical or escapes its root: {0}")]
    UnsafePath(PathBuf),
    #[error("symlink is forbidden at sealed closure boundary: {0}")]
    Symlink(PathBuf),
    #[error("closure I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("closure exceeds file limit {0}")]
    TooManyFiles(usize),
    #[error("closure file {path} exceeds byte limit {limit}")]
    FileTooLarge { path: PathBuf, limit: u64 },
    #[error("closure exceeds total byte limit {0}")]
    TooManyBytes(u64),
    #[error("closure contains no files")]
    Empty,
    #[error("closure member mismatch for {0}")]
    MemberMismatch(String),
    #[error("closure identity mismatch: expected {expected}, computed {actual}")]
    IdentityMismatch { expected: String, actual: String },
    #[error("closure serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn build_closure(
    root: &Path,
    kind: ClosureKind,
    patterns: &[String],
    claim_id: Option<String>,
    discovery: impl Into<String>,
    limits: ClosureLimits,
) -> Result<ClosureRecord, ClosureError> {
    let discovery = discovery.into();
    validate_discovery(&discovery)?;
    let root = root.canonicalize().map_err(|source| ClosureError::Io {
        path: root.to_owned(),
        source,
    })?;
    if !root.is_dir()
        || fs::symlink_metadata(&root)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
    {
        return Err(ClosureError::InvalidRoot(root));
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        validate_relative(Path::new(pattern))?;
        let glob = Glob::new(pattern).map_err(|error| ClosureError::InvalidPattern {
            pattern: pattern.clone(),
            message: error.to_string(),
        })?;
        builder.add(glob);
    }
    let matcher = builder
        .build()
        .map_err(|error| ClosureError::InvalidPattern {
            pattern: "<set>".to_owned(),
            message: error.to_string(),
        })?;

    let mut members = BTreeMap::new();
    let mut total_bytes = 0_u64;
    let walker = WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry
                .path()
                .strip_prefix(&root)
                .ok()
                .is_none_or(|relative| !excluded_state_path(relative))
        });
    for entry in walker {
        let entry = entry.map_err(|error| ClosureError::Io {
            path: error.path().unwrap_or(&root).to_owned(),
            source: error
                .into_io_error()
                .unwrap_or_else(|| std::io::Error::other("walk failed")),
        })?;
        let absolute = entry.path();
        let relative = absolute
            .strip_prefix(&root)
            .map_err(|_| ClosureError::UnsafePath(absolute.to_owned()))?;
        if relative.as_os_str().is_empty() || !matcher.is_match(relative) {
            continue;
        }
        validate_relative(relative)?;
        if entry.file_type().is_symlink() {
            return Err(ClosureError::Symlink(relative.to_owned()));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if members.len() >= limits.max_files {
            return Err(ClosureError::TooManyFiles(limits.max_files));
        }
        let metadata = entry.metadata().map_err(|error| ClosureError::Io {
            path: relative.to_owned(),
            source: error.into(),
        })?;
        if metadata.len() > limits.max_file_bytes {
            return Err(ClosureError::FileTooLarge {
                path: relative.to_owned(),
                limit: limits.max_file_bytes,
            });
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(ClosureError::TooManyBytes(limits.max_total_bytes))?;
        if total_bytes > limits.max_total_bytes {
            return Err(ClosureError::TooManyBytes(limits.max_total_bytes));
        }
        let bytes = fs::read(absolute).map_err(|source| ClosureError::Io {
            path: relative.to_owned(),
            source,
        })?;
        let path = relative.to_string_lossy().replace('\\', "/");
        members.insert(
            path.clone(),
            ClosureMember {
                path,
                sha256: sha256_bytes(&bytes),
                bytes: metadata.len(),
            },
        );
    }
    if members.is_empty() {
        return Err(ClosureError::Empty);
    }

    let mut record = ClosureRecord {
        schema: "proofbound-closure/1".to_owned(),
        id: String::new(),
        kind,
        root: ".".to_owned(),
        claim_id,
        members: members.into_values().collect(),
        total_bytes,
        discovery,
        tool_identity: None,
    };
    record.id = closure_identity(&record)?;
    Ok(record)
}

fn excluded_state_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                ".git"
                    | ".proofbound"
                    | ".lake"
                    | ".venv"
                    | "node_modules"
                    | "target"
                    | "__pycache__"
                    | ".pytest_cache"
                    | ".ruff_cache"
                    | ".mypy_cache"
            )
        )
    })
}

pub fn validate_closure(root: &Path, record: &ClosureRecord) -> Result<(), ClosureError> {
    validate_discovery(&record.discovery)?;
    for member in &record.members {
        let relative = Path::new(&member.path);
        validate_relative(relative)?;
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| ClosureError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ClosureError::Symlink(path));
        }
        let bytes = fs::read(&path).map_err(|source| ClosureError::Io {
            path: path.clone(),
            source,
        })?;
        if member.bytes != bytes.len() as u64 || member.sha256 != sha256_bytes(&bytes) {
            return Err(ClosureError::MemberMismatch(member.path.clone()));
        }
    }
    let actual = closure_identity(record)?;
    if actual != record.id {
        return Err(ClosureError::IdentityMismatch {
            expected: record.id.clone(),
            actual,
        });
    }
    Ok(())
}

/// Build one content-addressed closure from the exact union of already
/// validated closures. This is used by evidence units that support more than
/// one claim: their receipt must bind the whole set of claim-specific source
/// closures rather than silently selecting the first claim.
pub fn merge_closures(
    records: &[ClosureRecord],
    discovery: impl Into<String>,
    limits: ClosureLimits,
) -> Result<ClosureRecord, ClosureError> {
    let discovery = discovery.into();
    validate_discovery(&discovery)?;
    let first = records.first().ok_or(ClosureError::Empty)?;
    let mut members = BTreeMap::<String, ClosureMember>::new();
    let mut total_bytes = 0_u64;
    for record in records {
        if record.kind != first.kind || record.root != first.root {
            return Err(ClosureError::MemberMismatch(
                "closure kind or root".to_owned(),
            ));
        }
        for member in &record.members {
            validate_relative(Path::new(&member.path))?;
            if let Some(existing) = members.get(&member.path) {
                if existing != member {
                    return Err(ClosureError::MemberMismatch(member.path.clone()));
                }
                continue;
            }
            if members.len() >= limits.max_files {
                return Err(ClosureError::TooManyFiles(limits.max_files));
            }
            if member.bytes > limits.max_file_bytes {
                return Err(ClosureError::FileTooLarge {
                    path: PathBuf::from(&member.path),
                    limit: limits.max_file_bytes,
                });
            }
            total_bytes = total_bytes
                .checked_add(member.bytes)
                .ok_or(ClosureError::TooManyBytes(limits.max_total_bytes))?;
            if total_bytes > limits.max_total_bytes {
                return Err(ClosureError::TooManyBytes(limits.max_total_bytes));
            }
            members.insert(member.path.clone(), member.clone());
        }
    }
    if members.is_empty() {
        return Err(ClosureError::Empty);
    }
    let mut record = ClosureRecord {
        schema: "proofbound-closure/1".to_owned(),
        id: String::new(),
        kind: first.kind,
        root: first.root.clone(),
        claim_id: None,
        members: members.into_values().collect(),
        total_bytes,
        discovery,
        tool_identity: None,
    };
    record.id = closure_identity(&record)?;
    Ok(record)
}

fn closure_identity(record: &ClosureRecord) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(record)?;
    value
        .as_object_mut()
        .expect("record serializes to object")
        .insert("id".to_owned(), serde_json::Value::String(String::new()));
    Ok(domain_hash(
        "proofbound-closure/1",
        &canonical_json(&value)?,
    ))
}

fn validate_relative(path: &Path) -> Result<(), ClosureError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ClosureError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn validate_discovery(discovery: &str) -> Result<(), ClosureError> {
    if DISCOVERY_METHODS.contains(&discovery) {
        Ok(())
    } else {
        Err(ClosureError::InvalidDiscovery(discovery.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use super::*;

    #[test]
    fn public_schema_discovery_vocabulary_matches_runtime() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let schema: serde_json::Value = serde_json::from_slice(
            &fs::read(workspace.join("schemas/closure.schema.json")).unwrap(),
        )
        .unwrap();
        let schema_methods = schema["properties"]["discovery"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            schema_methods,
            DISCOVERY_METHODS.iter().copied().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn runtime_closure_record_is_emitted_for_public_schema_test() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("src")).unwrap();
        fs::write(source.path().join("src/meaning.txt"), b"meaning\n").unwrap();
        let record = build_closure(
            source.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            Some("TEST-CLAIM-001".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();

        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                }
            })
            .unwrap_or_else(|| workspace.join("target"));
        let fixture = target.join("proofbound-schema-fixtures/closure-record.json");
        fs::create_dir_all(fixture.parent().unwrap()).unwrap();
        fs::write(fixture, canonical_json(&record).unwrap()).unwrap();
    }

    #[test]
    fn closure_is_sorted_and_detects_drift() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/z.rs"), "z").unwrap();
        fs::write(temp.path().join("src/a.rs"), "a").unwrap();
        let record = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            Some("TEST-CLAIM-001".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();
        assert_eq!(record.members[0].path, "src/a.rs");
        validate_closure(temp.path(), &record).unwrap();
        fs::write(temp.path().join("src/a.rs"), "changed").unwrap();
        assert!(validate_closure(temp.path(), &record).is_err());
    }

    #[test]
    fn presentation_only_change_preserves_semantic_closure_identity() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::create_dir(temp.path().join("docs")).unwrap();
        fs::write(temp.path().join("src/model.rs"), "meaning").unwrap();
        fs::write(temp.path().join("docs/guide.md"), "first presentation").unwrap();

        let semantic_before = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            Some("TEST-CLAIM-001".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();
        let presentation_before = build_closure(
            temp.path(),
            ClosureKind::Presentation,
            &["docs/**".to_owned()],
            None,
            "project-presentation/1",
            ClosureLimits::default(),
        )
        .unwrap();

        fs::write(temp.path().join("docs/guide.md"), "second presentation").unwrap();

        let semantic_after = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            Some("TEST-CLAIM-001".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();
        let presentation_after = build_closure(
            temp.path(),
            ClosureKind::Presentation,
            &["docs/**".to_owned()],
            None,
            "project-presentation/1",
            ClosureLimits::default(),
        )
        .unwrap();

        assert_eq!(semantic_before.id, semantic_after.id);
        assert_ne!(presentation_before.id, presentation_after.id);
        assert_eq!(semantic_after.members, semantic_before.members);
    }

    #[test]
    fn traversal_pattern_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let error = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["../**".to_owned()],
            None,
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ClosureError::UnsafePath(_)));
    }

    #[test]
    fn unregistered_discovery_vocabulary_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let error = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/**".to_owned()],
            None,
            "ad-hoc-discovery",
            ClosureLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ClosureError::InvalidDiscovery(_)));
    }

    #[test]
    fn merged_closure_is_a_sorted_exact_union() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/a.rs"), "a").unwrap();
        fs::write(temp.path().join("src/b.rs"), "b").unwrap();
        let first = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/a.rs".to_owned()],
            Some("A".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();
        let second = build_closure(
            temp.path(),
            ClosureKind::Semantic,
            &["src/b.rs".to_owned()],
            Some("B".to_owned()),
            "build-tool-transitive/1",
            ClosureLimits::default(),
        )
        .unwrap();
        let merged = merge_closures(
            &[second, first],
            "unit-claim-union/1",
            ClosureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            merged
                .members
                .iter()
                .map(|member| member.path.as_str())
                .collect::<Vec<_>>(),
            ["src/a.rs", "src/b.rs"]
        );
        assert!(merged.claim_id.is_none());
        validate_closure(temp.path(), &merged).unwrap();
    }
}
