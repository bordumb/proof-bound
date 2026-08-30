use std::path::PathBuf;

use proofbound_manifest::ProjectBundle;

#[test]
fn repository_manifests_form_one_closed_bundle() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = crate_dir.parent().and_then(|path| path.parent()).unwrap();
    let bundle = ProjectBundle::load(root)
        .unwrap_or_else(|error| panic!("root Proofbound manifest bundle must validate: {error}"));
    assert!(bundle.claims.len() >= 18);
    assert!(bundle.evidence_units.len() >= 10);
}
