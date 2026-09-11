use std::path::PathBuf;

use proofbound_ir_prototype::{validate_enforced_capture_bytes, validate_enforced_model_report};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate belongs to the workspace")
        .to_path_buf()
}

#[test]
fn retained_capture_derives_the_registered_report_exactly() {
    let repository = repository();
    let result = repository.join("docs/experiments/0018-os-enforced-effects/results");
    let capture = std::fs::read(result.join("capture.json")).unwrap();
    let expected = std::fs::read(result.join("rust-report.json")).unwrap();
    let report = validate_enforced_capture_bytes(&repository, &capture).unwrap();

    assert_eq!(
        proofbound_evidence::canonical_json(&report).unwrap(),
        expected
    );
    assert_eq!(
        report.attacks.iter().filter(|attack| attack.exact).count(),
        30
    );
    assert_eq!(report.metrics.denied_reusable, 0);
    validate_enforced_model_report(&report).unwrap();
}

#[test]
fn noncanonical_capture_and_forged_report_fail_closed() {
    let repository = repository();
    let result = repository.join("docs/experiments/0018-os-enforced-effects/results");
    let mut capture = std::fs::read(result.join("capture.json")).unwrap();
    capture.push(b'\n');
    assert_eq!(
        validate_enforced_capture_bytes(&repository, &capture)
            .unwrap_err()
            .code,
        "EFX-NONCANONICAL"
    );

    let valid = std::fs::read(result.join("capture.json")).unwrap();
    let mut report = validate_enforced_capture_bytes(&repository, &valid).unwrap();
    report.identity = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        validate_enforced_model_report(&report).unwrap_err().code,
        "EFX-REPORT-IDENTITY"
    );
}
