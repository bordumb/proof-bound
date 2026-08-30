use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use globset::{Glob, GlobSetBuilder};
use serde::de::DeserializeOwned;
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

use crate::{
    AssumptionManifest, ClaimManifest, DemoRegistry, EvidenceUnitManifest, ModelCheckUnitManifest,
    PolicyManifest, ProjectManifest, ReviewManifest, SemanticError, TranslationUnitManifest,
    validate_bundle,
};

#[derive(Debug, Clone, Copy)]
pub struct ManifestLimits {
    pub max_bytes: u64,
    pub max_files: usize,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_bytes: 2 << 20,
            max_files: 100_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("manifest exceeds {limit} bytes: {path}")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("manifest boundary contains a symlink: {0}")]
    Symlink(PathBuf),
    #[error("manifest path is absolute, non-normal, or escapes the project: {0}")]
    UnsafePath(PathBuf),
    #[error("invalid manifest glob {pattern}: {message}")]
    Glob { pattern: String, message: String },
    #[error("manifest pattern matched no files: {0}")]
    NoMatches(String),
    #[error("manifest path is matched ambiguously: {0}")]
    AmbiguousPath(PathBuf),
    #[error("manifest collection exceeds {0} files")]
    TooManyFiles(usize),
    #[error("invalid TOML in {path}: {message}")]
    Toml { path: PathBuf, message: String },
    #[error("invalid JSON in {path}: {message}")]
    Json { path: PathBuf, message: String },
    #[error(transparent)]
    Semantic(#[from] SemanticError),
}

#[derive(Debug)]
pub struct ProjectBundle {
    pub root: PathBuf,
    pub project: ProjectManifest,
    pub claims: BTreeMap<String, (PathBuf, ClaimManifest)>,
    pub assumptions: BTreeMap<String, (PathBuf, AssumptionManifest)>,
    pub evidence_units: BTreeMap<String, (PathBuf, EvidenceUnitManifest)>,
    pub translation_units: BTreeMap<String, (PathBuf, TranslationUnitManifest)>,
    pub model_check_units: BTreeMap<String, (PathBuf, ModelCheckUnitManifest)>,
    pub policies: BTreeMap<String, (PathBuf, PolicyManifest)>,
    pub reviews: BTreeMap<String, (PathBuf, ReviewManifest)>,
    pub demos: Option<(PathBuf, DemoRegistry)>,
}

impl ProjectBundle {
    pub fn load(root: &Path) -> Result<Self, ManifestError> {
        let root = root.canonicalize().map_err(|source| ManifestError::Io {
            path: root.to_owned(),
            source,
        })?;
        let project_path = root.join("proofbound.toml");
        let project: ProjectManifest = load_toml(&project_path, ManifestLimits::default())?;
        let limits = ManifestLimits {
            max_bytes: project.limits.max_manifest_bytes,
            max_files: project.limits.max_files,
        };

        let claims = load_collection(
            &root,
            &project.claim_manifests,
            limits,
            |value: &ClaimManifest| value.id.clone(),
        )?;
        let assumptions = load_collection(
            &root,
            &project.assumption_manifests,
            limits,
            |value: &AssumptionManifest| value.id.clone(),
        )?;
        let evidence_units = load_collection(
            &root,
            &project.evidence_units,
            limits,
            |value: &EvidenceUnitManifest| value.id.clone(),
        )?;
        let translation_units = load_collection(
            &root,
            &project.translation_units,
            limits,
            |value: &TranslationUnitManifest| value.id.clone(),
        )?;
        let model_check_units = load_collection(
            &root,
            &project.model_check_units,
            limits,
            |value: &ModelCheckUnitManifest| value.id.clone(),
        )?;
        let policies = load_collection(
            &root,
            &project.policy_manifests,
            limits,
            |value: &PolicyManifest| value.id.clone(),
        )?;
        let reviews = load_collection(
            &root,
            &project.review_manifests,
            limits,
            |value: &ReviewManifest| value.id.clone(),
        )?;
        let demos = if let Some(relative) = project.demo_registry.as_ref() {
            let path = resolve_path(&root, relative)?;
            let manifest: DemoRegistry = load_toml(&path, limits)?;
            Some((path, manifest))
        } else {
            None
        };

        let bundle = Self {
            root,
            project,
            claims,
            assumptions,
            evidence_units,
            translation_units,
            model_check_units,
            policies,
            reviews,
            demos,
        };
        validate_bundle(&bundle)?;
        Ok(bundle)
    }
}

pub fn load_toml<T: DeserializeOwned>(
    path: &Path,
    limits: ManifestLimits,
) -> Result<T, ManifestError> {
    let bytes = read_sealed(path, limits)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| ManifestError::Toml {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    toml::from_str(text).map_err(|error| ManifestError::Toml {
        path: path.to_owned(),
        message: error.to_string(),
    })
}

pub fn load_json<T: DeserializeOwned>(
    path: &Path,
    limits: ManifestLimits,
) -> Result<T, ManifestError> {
    let bytes = read_sealed(path, limits)?;
    serde_json::from_slice(&bytes).map_err(|error| ManifestError::Json {
        path: path.to_owned(),
        message: error.to_string(),
    })
}

fn read_sealed(path: &Path, limits: ManifestLimits) -> Result<Vec<u8>, ManifestError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ManifestError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ManifestError::Symlink(path.to_owned()));
    }
    if metadata.len() > limits.max_bytes {
        return Err(ManifestError::TooLarge {
            path: path.to_owned(),
            limit: limits.max_bytes,
        });
    }
    fs::read(path).map_err(|source| ManifestError::Io {
        path: path.to_owned(),
        source,
    })
}

fn load_collection<T, F>(
    root: &Path,
    patterns: &[String],
    limits: ManifestLimits,
    id: F,
) -> Result<BTreeMap<String, (PathBuf, T)>, ManifestError>
where
    T: DeserializeOwned,
    F: Fn(&T) -> String,
{
    let paths = expand_patterns(root, patterns, limits.max_files)?;
    let mut values: BTreeMap<String, (PathBuf, T)> = BTreeMap::new();
    for path in paths {
        let value: T = load_toml(&path, limits)?;
        let item_id = id(&value);
        if let Some((old_path, _)) = values.get(&item_id) {
            return Err(ManifestError::Semantic(SemanticError::DuplicateId {
                id: item_id,
                first: old_path.clone(),
                second: path,
            }));
        }
        values.insert(item_id, (path, value));
    }
    Ok(values)
}

fn expand_patterns(
    root: &Path,
    patterns: &[String],
    max_files: usize,
) -> Result<Vec<PathBuf>, ManifestError> {
    let mut matched = BTreeSet::new();
    for pattern in patterns {
        validate_relative(Path::new(pattern))?;
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new(pattern).map_err(|error| ManifestError::Glob {
            pattern: pattern.clone(),
            message: error.to_string(),
        })?);
        let set = builder.build().map_err(|error| ManifestError::Glob {
            pattern: pattern.clone(),
            message: error.to_string(),
        })?;
        let mut this_pattern = 0_usize;
        for entry in WalkDir::new(root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(include_entry)
        {
            let entry = entry.map_err(|error| ManifestError::Io {
                path: error.path().unwrap_or(root).to_owned(),
                source: error
                    .into_io_error()
                    .unwrap_or_else(|| std::io::Error::other("walk failed")),
            })?;
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| ManifestError::UnsafePath(entry.path().to_owned()))?;
            if relative.as_os_str().is_empty() || !set.is_match(relative) {
                continue;
            }
            if entry.file_type().is_symlink() {
                return Err(ManifestError::Symlink(relative.to_owned()));
            }
            if !entry.file_type().is_file() {
                continue;
            }
            this_pattern += 1;
            if !matched.insert(entry.path().to_owned()) {
                return Err(ManifestError::AmbiguousPath(relative.to_owned()));
            }
            if matched.len() > max_files {
                return Err(ManifestError::TooManyFiles(max_files));
            }
        }
        if this_pattern == 0 {
            return Err(ManifestError::NoMatches(pattern.clone()));
        }
    }
    Ok(matched.into_iter().collect())
}

fn include_entry(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    entry.depth() == 0
        || !matches!(
            name.as_ref(),
            ".git" | ".proofbound" | "target" | ".lake" | ".venv"
        )
}

fn resolve_path(root: &Path, relative: &str) -> Result<PathBuf, ManifestError> {
    let relative = Path::new(relative);
    validate_relative(relative)?;
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| ManifestError::UnsafePath(path.clone()))?;
    let canonical_parent = parent.canonicalize().map_err(|source| ManifestError::Io {
        path: parent.to_owned(),
        source,
    })?;
    if !canonical_parent.starts_with(root) {
        return Err(ManifestError::UnsafePath(path));
    }
    Ok(path)
}

fn validate_relative(path: &Path) -> Result<(), ManifestError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ManifestError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Tiny {
        #[serde(rename = "schema")]
        _schema: String,
    }

    #[test]
    fn unknown_toml_field_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("x.toml");
        fs::write(&path, "schema = \"x/1\"\nunknown = true\n").unwrap();
        let error = load_toml::<Tiny>(&path, ManifestLimits::default()).unwrap_err();
        assert!(matches!(error, ManifestError::Toml { .. }));
    }

    #[test]
    fn traversal_glob_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let error = expand_patterns(temp.path(), &["../*.toml".to_owned()], 10).unwrap_err();
        assert!(matches!(error, ManifestError::UnsafePath(_)));
    }
}
