use std::path::PathBuf;

use proofbound_evidence::{ClosureKind, ClosureLimits, build_closure};
use proofbound_manifest::ProjectBundle;

#[test]
fn every_registered_claim_has_a_bounded_semantic_closure() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = crate_dir.parent().and_then(|path| path.parent()).unwrap();
    let bundle = ProjectBundle::load(root)
        .unwrap_or_else(|error| panic!("root manifest bundle must validate: {error}"));
    let limits = ClosureLimits {
        max_files: bundle.project.limits.max_files,
        max_total_bytes: bundle.project.limits.max_total_bytes,
        max_file_bytes: bundle.project.limits.max_manifest_bytes.max(64 << 20),
    };

    for (claim_id, (_, claim)) in &bundle.claims {
        let patterns = if claim.source_roots.is_empty() {
            &bundle.project.source.semantic
        } else {
            &claim.source_roots
        };
        let closure = build_closure(
            root,
            ClosureKind::Semantic,
            patterns,
            Some(claim_id.clone()),
            "build-tool-transitive/1",
            limits,
        )
        .unwrap_or_else(|error| panic!("semantic closure for {claim_id} failed: {error}"));
        assert!(
            !closure.members.is_empty(),
            "semantic closure for {claim_id} must not be empty"
        );
    }
}
