use std::{path::Path, process::Command};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitIdentity {
    pub revision: String,
    pub tree_state: String,
    pub dirty_paths: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("could not execute git: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("git command failed: {0}")]
    Git(String),
    #[error("git output was not UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub fn git_identity(root: &Path) -> Result<GitIdentity, ProvenanceError> {
    let revision = git(root, &["rev-parse", "HEAD"])?;
    let status = git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    let mut dirty_paths: Vec<_> = status
        .lines()
        .filter_map(|line| line.get(3..))
        .map(ToOwned::to_owned)
        .collect();
    dirty_paths.sort();
    dirty_paths.dedup();
    Ok(GitIdentity {
        revision,
        tree_state: if dirty_paths.is_empty() {
            "clean"
        } else {
            "dirty"
        }
        .to_owned(),
        dirty_paths,
    })
}

fn git(root: &Path, args: &[&str]) -> Result<String, ProvenanceError> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() {
        return Err(ProvenanceError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
