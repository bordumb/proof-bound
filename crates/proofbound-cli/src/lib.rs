#![recursion_limit = "256"]

//! Proofbound's orchestration layer.
//!
//! The CLI is intentionally separate from the assurance semantics in
//! `proofbound-core`: this crate resolves project manifests, executes typed
//! adapters, stores immutable receipts, and renders projections.

mod adapter;
mod closures;
mod compile;
mod demo;
mod diff;
mod doctor;
mod model;
mod report;
mod scaffold;

pub use compile::{
    CheckOptions, check_project, load_compiled, release_project, release_smoke, update_unit,
};
pub use demo::run_demo;
pub use diff::diff_revisions;
pub use doctor::doctor;
pub use model::{CompiledProject, UnitRun};
pub use report::{
    render_assumptions, render_claim, render_explanation, render_graph, render_status,
};
pub use scaffold::init_project;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Find the nearest ancestor containing a Proofbound project manifest.
pub fn find_project_root(start: &Path) -> Result<PathBuf> {
    let start = start
        .canonicalize()
        .with_context(|| format!("could not resolve {}", start.display()))?;
    for candidate in start.ancestors() {
        if candidate.join("proofbound.toml").is_file() {
            return Ok(candidate.to_owned());
        }
    }
    bail!(
        "PB-CLI-0001: no proofbound.toml found at or above {}; run `proofbound init`",
        start.display()
    )
}

pub(crate) fn safe_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            let character = char::from(byte);
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}
