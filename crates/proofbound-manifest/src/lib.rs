//! Strict, fail-closed Proofbound manifests.

mod load;
mod model;
mod validate;

pub use load::{ManifestError, ManifestLimits, ProjectBundle, load_json, load_toml};
pub use model::*;
pub use validate::{SemanticError, validate_bundle};
