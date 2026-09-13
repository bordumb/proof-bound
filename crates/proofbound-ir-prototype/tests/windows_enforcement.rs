use std::path::PathBuf;

use proofbound_evidence::canonical_json;
use proofbound_ir_prototype::{
    WindowsCapture, WindowsPolicy, compile_windows_policy, validate_windows_capture_bytes,
    validate_windows_policy, validate_windows_report,
};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn capture() -> WindowsCapture {
    serde_json::from_slice(
        &std::fs::read(
            repository()
                .join("docs/experiments/0021-windows-enforcement-portability/results/capture.json"),
        )
        .expect("retained capture"),
    )
    .expect("typed capture")
}

fn capture_rejection(
    mut capture: WindowsCapture,
    mutate: impl FnOnce(&mut WindowsCapture),
) -> &'static str {
    mutate(&mut capture);
    let bytes = canonical_json(&capture).expect("canonical mutation");
    validate_windows_capture_bytes(&repository(), &bytes)
        .expect_err("attack must fail")
        .code
}

fn policy_rejection(
    mut policy: WindowsPolicy,
    mutate: impl FnOnce(&mut WindowsPolicy),
) -> &'static str {
    mutate(&mut policy);
    validate_windows_policy(&policy)
        .expect_err("attack must fail")
        .code
}

#[test]
fn retained_windows_capture_is_unanswered_without_fallback() {
    let bytes = std::fs::read(
        repository()
            .join("docs/experiments/0021-windows-enforcement-portability/results/capture.json"),
    )
    .unwrap();
    let report = validate_windows_capture_bytes(&repository(), &bytes).unwrap();
    validate_windows_report(&report).unwrap();
    assert_eq!(report.availability, "unsupported");
    assert!(!report.metrics.supported_execution);
    assert_eq!(report.policy_attacks.len(), 18);
}

#[test]
fn all_registered_capture_and_policy_attacks_fail_exactly() {
    let original = capture();
    let policy = compile_windows_policy().unwrap();
    let attacks = [
        capture_rejection(original.clone(), |value| value.schema = "old".to_owned()),
        capture_rejection(original.clone(), |value| {
            value.contract_sha256 = "sha256:bad".to_owned()
        }),
        capture_rejection(original.clone(), |value| {
            value.requested_platform.minimum_release = "Windows 10".to_owned()
        }),
        capture_rejection(original.clone(), |value| {
            value.candidate_mechanisms.pop();
        }),
        capture_rejection(original.clone(), |value| value.fallback_used = true),
        capture_rejection(original.clone(), |value| {
            value.availability = "supported".to_owned()
        }),
        capture_rejection(original, |value| value.identity = "sha256:bad".to_owned()),
        policy_rejection(policy.clone(), |value| value.schema = "old".to_owned()),
        policy_rejection(policy.clone(), |value| {
            value
                .appcontainer
                .capabilities
                .push("internet-client".to_owned())
        }),
        policy_rejection(policy.clone(), |value| {
            value.appcontainer.network_authority = "outbound".to_owned()
        }),
        policy_rejection(policy.clone(), |value| {
            value.restricted_token.disable_max_privilege = false
        }),
        policy_rejection(policy.clone(), |value| {
            value.restricted_token.integrity_level = "medium".to_owned()
        }),
        policy_rejection(policy.clone(), |value| {
            value.job_object.active_process_limit = 2
        }),
        policy_rejection(policy.clone(), |value| {
            value.job_object.breakaway = "allow".to_owned()
        }),
        policy_rejection(policy.clone(), |value| {
            value
                .path_authority
                .push(("project-root".to_owned(), "modify".to_owned()))
        }),
        policy_rejection(policy.clone(), |value| {
            value
                .environment
                .push(("PATH".to_owned(), "sha256:bad".to_owned()))
        }),
        policy_rejection(policy.clone(), |value| {
            value.executable_allowlist.push("any".to_owned())
        }),
        policy_rejection(policy, |value| value.identity = "sha256:bad".to_owned()),
    ];
    assert_eq!(
        attacks,
        [
            "WIN-CAPTURE-SCHEMA",
            "WIN-CONTRACT",
            "WIN-TARGET",
            "WIN-MECHANISM",
            "WIN-FALLBACK",
            "WIN-FALLBACK",
            "WIN-CAPTURE-IDENTITY",
            "WIN-POLICY-SCHEMA",
            "WIN-APPCONTAINER",
            "WIN-APPCONTAINER",
            "WIN-TOKEN",
            "WIN-TOKEN",
            "WIN-JOB",
            "WIN-JOB",
            "WIN-PATH-AUTHORITY",
            "WIN-ENVIRONMENT",
            "WIN-EXECUTABLE",
            "WIN-POLICY-IDENTITY",
        ]
    );
}
