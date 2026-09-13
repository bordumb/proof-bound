use std::{fs, path::PathBuf};

use proofbound_evidence::canonical_json;
use proofbound_ir_prototype::{BatchedCapture, validate_batched_capture_bytes};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn retained_batch_derives_the_registered_report_exactly() {
    let root = repository();
    let result = root.join("docs/experiments/0019-batched-enforcement-latency/results");
    let capture = fs::read(result.join("capture.json")).expect("capture");
    let report = validate_batched_capture_bytes(&root, &capture).expect("valid capture");
    assert_eq!(
        canonical_json(&report).expect("canonical report"),
        fs::read(result.join("rust-report.json")).expect("retained report")
    );
    assert_eq!(report.metrics.completed_slots, 51);
    assert_eq!(report.metrics.scheduler_attack_rejections, 10);
}

#[test]
fn noncanonical_and_partial_batches_fail_closed() {
    let root = repository();
    let path = root.join("docs/experiments/0019-batched-enforcement-latency/results/capture.json");
    let bytes = fs::read(path).expect("capture");
    let mut padded = bytes.clone();
    padded.push(b'\n');
    assert_eq!(
        validate_batched_capture_bytes(&root, &padded)
            .expect_err("noncanonical")
            .code,
        "BFX-NONCANONICAL"
    );
    let mut capture: BatchedCapture = serde_json::from_slice(&bytes).expect("typed capture");
    capture.completed_slots -= 1;
    let altered = canonical_json(&capture).expect("altered capture");
    assert_eq!(
        validate_batched_capture_bytes(&root, &altered)
            .expect_err("partial")
            .code,
        "BFX-PARTIAL"
    );
}
