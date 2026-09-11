use std::path::PathBuf;

use proofbound_evidence::canonical_json;
use proofbound_ir_prototype::{LinuxCapture, validate_linux_capture_bytes, validate_linux_report};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn capture() -> LinuxCapture {
    serde_json::from_slice(
        &std::fs::read(
            repository()
                .join("docs/experiments/0020-linux-enforcement-portability/results/capture.json"),
        )
        .expect("retained capture"),
    )
    .expect("typed capture")
}

fn rejection(mut capture: LinuxCapture, mutate: impl FnOnce(&mut LinuxCapture)) -> &'static str {
    mutate(&mut capture);
    let bytes = canonical_json(&capture).expect("canonical mutation");
    validate_linux_capture_bytes(&repository(), &bytes)
        .expect_err("attack must fail")
        .code
}

#[test]
fn retained_unsupported_capture_is_fail_closed() {
    let bytes = std::fs::read(
        repository()
            .join("docs/experiments/0020-linux-enforcement-portability/results/capture.json"),
    )
    .unwrap();
    let report = validate_linux_capture_bytes(&repository(), &bytes).unwrap();
    validate_linux_report(&report).unwrap();
    assert_eq!(report.availability, "unsupported");
    assert!(!report.metrics.supported_execution);
    assert_eq!(report.metrics.positive_executions, 0);
    assert_eq!(report.metrics.authority_probe_executions, 0);
    assert_eq!(report.policy_attacks.len(), 16);
}

#[test]
fn all_registered_unsupported_attacks_fail_exactly() {
    let original = capture();
    let attacks = [
        rejection(original.clone(), |value| value.schema = "old".to_owned()),
        rejection(original.clone(), |value| {
            value.contract_sha256 = format!("sha256:{}", "0".repeat(64))
        }),
        rejection(original.clone(), |value| {
            value.platform.os = "macos".to_owned()
        }),
        rejection(original.clone(), |value| {
            value.platform.architecture = "riscv64".to_owned()
        }),
        rejection(original.clone(), |value| {
            value.platform.kernel = "unknown".to_owned()
        }),
        rejection(original.clone(), |value| {
            value.platform.image_identity = "sha256:bad".to_owned()
        }),
        rejection(original.clone(), |value| {
            value.platform.enforcer_sha256 = "sha256:bad".to_owned()
        }),
        rejection(original.clone(), |value| {
            value
                .platform
                .seccomp_network_syscalls
                .pop()
                .map(|_| ())
                .unwrap()
        }),
        rejection(original.clone(), |value| value.platform.no_new_privs = true),
        rejection(original.clone(), |value| {
            value.platform.landlock_abi = Some(3)
        }),
        rejection(original.clone(), |value| value.platform.probe_exit_code = 0),
        rejection(original.clone(), |value| {
            value.platform.probe_stdout = "substitute".to_owned()
        }),
        rejection(original.clone(), |value| {
            value.platform.probe_stderr.clear()
        }),
        rejection(original.clone(), |value| {
            value.scheduler = "serial-fallback".to_owned()
        }),
        rejection(original.clone(), |value| {
            value.container_confinement_counted = true
        }),
        rejection(original, |value| {
            value.identity = format!("sha256:{}", "0".repeat(64))
        }),
    ];
    assert_eq!(
        attacks,
        [
            "LNX-CAPTURE-SCHEMA",
            "LNX-CONTRACT",
            "LNX-PLATFORM",
            "LNX-PLATFORM",
            "LNX-PLATFORM",
            "LNX-MECHANISM",
            "LNX-MECHANISM",
            "LNX-MECHANISM",
            "LNX-CONTAINER-FALLBACK",
            "LNX-PLATFORM",
            "LNX-CONTAINER-FALLBACK",
            "LNX-CONTAINER-FALLBACK",
            "LNX-CONTAINER-FALLBACK",
            "LNX-MECHANISM",
            "LNX-CONTAINER-FALLBACK",
            "LNX-CAPTURE-IDENTITY",
        ]
    );
}
