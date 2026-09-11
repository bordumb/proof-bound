use std::{collections::BTreeMap, fmt, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const LINUX_CAPTURE_SCHEMA: &str = "proofbound-research-linux-enforcement-capture/1";
pub const LINUX_POLICY_SCHEMA: &str = "proofbound-research-linux-effective-policy/1";
pub const LINUX_REPORT_SCHEMA: &str = "proofbound-research-linux-enforcement-report/1";

const CONTRACT_SHA256: &str =
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d";
const ENFORCER: &str = "/usr/local/bin/proofbound-linux-enforcer";
const EXPECTED_OUTPUT_SHA256: &str =
    "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22";

const SYSTEM_READ_ROOTS: [&str; 6] = ["/dev", "/etc", "/lib", "/proc", "/sys", "/usr"];
const NETWORK_SYSCALLS: [&str; 7] = [
    "accept",
    "accept4",
    "bind",
    "connect",
    "listen",
    "socket",
    "socketpair",
];
const ATTACKS: [(&str, &str); 16] = [
    ("EXP-0020-A001", "LNX-CAPTURE-SCHEMA"),
    ("EXP-0020-A002", "LNX-CONTRACT"),
    ("EXP-0020-A003", "LNX-PLATFORM"),
    ("EXP-0020-A004", "LNX-PLATFORM"),
    ("EXP-0020-A005", "LNX-PLATFORM"),
    ("EXP-0020-A006", "LNX-MECHANISM"),
    ("EXP-0020-A007", "LNX-MECHANISM"),
    ("EXP-0020-A008", "LNX-MECHANISM"),
    ("EXP-0020-A009", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A010", "LNX-PLATFORM"),
    ("EXP-0020-A011", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A012", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A013", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A014", "LNX-MECHANISM"),
    ("EXP-0020-A015", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A016", "LNX-CAPTURE-IDENTITY"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxEnforcementError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for LinuxEnforcementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LinuxEnforcementError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPlatform {
    pub os: String,
    pub architecture: String,
    pub kernel: String,
    pub landlock_abi: Option<u32>,
    pub probe_exit_code: i32,
    pub probe_stdout: String,
    pub probe_stderr: String,
    pub image: String,
    pub image_identity: String,
    pub enforcer: String,
    pub enforcer_sha256: String,
    pub no_new_privs: bool,
    pub seccomp_network_syscalls: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPolicyPlatform {
    pub os: String,
    pub architecture: String,
    pub minimum_landlock_abi: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPolicy {
    pub schema: String,
    pub subject_id: String,
    pub platform: LinuxPolicyPlatform,
    pub system_read_roots: Vec<String>,
    pub project_root: String,
    pub allowed_project_reads: Vec<String>,
    pub registered_absences: Vec<String>,
    pub registered_input_mode: u32,
    pub runtime: String,
    pub executable_allowlist: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub ephemeral_write_roots: Vec<String>,
    pub denied_project_reads: Vec<String>,
    pub denied_reviewed_writes: Vec<String>,
    pub denied_escape_writes: Vec<String>,
    pub denied_network_syscalls: Vec<String>,
    pub default_filesystem_authority: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxOutput {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSlot {
    pub slot_id: String,
    pub kind: String,
    pub subject_id: String,
    pub repetition: Option<u32>,
    pub attack_id: Option<String>,
    pub expected_denial_code: Option<String>,
    pub mode: String,
    pub attack_path: String,
    pub policy: LinuxPolicy,
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub output: Option<LinuxOutput>,
    pub outcome: String,
    pub reusable: bool,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCapture {
    pub schema: String,
    pub experiment: String,
    pub programme_experiment: String,
    pub contract_sha256: String,
    pub execution_environment: String,
    pub container_confinement_counted: bool,
    pub availability: String,
    pub platform: LinuxPlatform,
    pub scheduler: String,
    pub slots: Vec<LinuxSlot>,
    pub reviewed_tree_before: String,
    pub reviewed_tree_after: String,
    pub elapsed_ms: u64,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxMetrics {
    pub positive_executions: u32,
    pub authority_probe_executions: u32,
    pub denied_reusable: u32,
    pub reviewed_tree_changed: bool,
    pub elapsed_ms: u64,
    pub supported_execution: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPortabilityDelta {
    pub system_read_roots: Vec<String>,
    pub dynamic_loader_premise: String,
    pub filesystem_premise: String,
    pub kernel_premise: String,
    pub container_boundary_counted: bool,
    pub macos_difference: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxReport {
    pub schema: String,
    pub experiment: String,
    pub programme_experiment: String,
    pub contract_sha256: String,
    pub platform: LinuxPlatform,
    pub capture_identity: String,
    pub availability: String,
    pub effect_dispositions: Vec<(String, String)>,
    pub effective_policy_identities: Vec<(String, String)>,
    pub slot_identities: Vec<(String, String)>,
    pub policy_attacks: Vec<LinuxAttackResult>,
    pub metrics: LinuxMetrics,
    pub portability_delta: LinuxPortabilityDelta,
    pub identity: String,
}

struct ExpectedSlot {
    slot_id: String,
    subject_id: &'static str,
    repetition: Option<u32>,
    attack_id: Option<&'static str>,
    denial_code: Option<&'static str>,
    mode: &'static str,
    attack_path: &'static str,
}

pub fn validate_linux_capture_bytes(
    repository: &Path,
    payload: &[u8],
) -> Result<LinuxReport, LinuxEnforcementError> {
    let capture: LinuxCapture = serde_json::from_slice(payload)
        .map_err(|issue| error("LNX-CAPTURE-SCHEMA", issue.to_string()))?;
    if canonical_json(&capture).map_err(encoding_error)? != payload {
        return Err(error("LNX-CAPTURE-SCHEMA", "capture is not canonical JSON"));
    }
    let contract =
        fs::read(repository.join("docs/experiments/0018-os-enforced-effects/corpus/contract.json"))
            .map_err(|issue| error("LNX-CONTRACT", issue.to_string()))?;
    if sha256_bytes(&contract) != CONTRACT_SHA256 {
        return Err(error("LNX-CONTRACT", "registered contract bytes differ"));
    }
    validate_linux_capture(&capture)
}

pub fn validate_linux_capture(
    capture: &LinuxCapture,
) -> Result<LinuxReport, LinuxEnforcementError> {
    validate_capture_header(capture)?;
    validate_platform(&capture.platform)?;
    let supported = capture.availability == "supported";
    if capture.availability != "supported" && capture.availability != "unsupported" {
        return Err(error("LNX-MECHANISM", "availability state differs"));
    }
    if supported {
        let expected = expected_slots();
        if capture.platform.landlock_abi.is_none()
            || capture.platform.probe_exit_code != 0
            || !capture.platform.probe_stderr.is_empty()
            || !capture.platform.no_new_privs
            || capture.slots.len() != expected.len()
        {
            return Err(error(
                "LNX-MECHANISM",
                "supported mechanism evidence differs",
            ));
        }
        for (slot, expected_slot) in capture.slots.iter().zip(&expected) {
            validate_slot(slot, expected_slot, &capture.platform)?;
        }
    } else if capture.platform.landlock_abi.is_some()
        || capture.platform.probe_exit_code == 0
        || !capture.platform.probe_stdout.is_empty()
        || capture.platform.probe_stderr.trim().is_empty()
        || capture.platform.no_new_privs
        || !capture.slots.is_empty()
    {
        return Err(error(
            "LNX-CONTAINER-FALLBACK",
            "unsupported result contains substituted execution",
        ));
    }
    if capture.reviewed_tree_before != capture.reviewed_tree_after {
        return Err(error("LNX-TREE-MUTATED", "reviewed tree changed"));
    }
    if capture.elapsed_ms == 0 {
        return Err(error("LNX-CAPTURE-SCHEMA", "elapsed time is zero"));
    }
    if capture.identity != hash_without("proofbound-research-linux-enforcement-capture/1", capture)?
    {
        return Err(error("LNX-CAPTURE-IDENTITY", "capture identity differs"));
    }
    let positive_executions = capture
        .slots
        .iter()
        .filter(|slot| slot.kind == "positive")
        .count() as u32;
    let authority_probe_executions = capture.slots.len() as u32 - positive_executions;
    let mut report = LinuxReport {
        schema: LINUX_REPORT_SCHEMA.to_owned(),
        experiment: "EXP-0020".to_owned(),
        programme_experiment: "EXP-LANG-013".to_owned(),
        contract_sha256: CONTRACT_SHA256.to_owned(),
        platform: capture.platform.clone(),
        capture_identity: capture.identity.clone(),
        availability: capture.availability.clone(),
        effect_dispositions: effect_dispositions(),
        effective_policy_identities: capture
            .slots
            .iter()
            .map(|slot| (slot.slot_id.clone(), slot.policy.identity.clone()))
            .collect(),
        slot_identities: capture
            .slots
            .iter()
            .map(|slot| (slot.slot_id.clone(), slot.identity.clone()))
            .collect(),
        policy_attacks: ATTACKS
            .iter()
            .map(|(id, code)| LinuxAttackResult {
                id: (*id).to_owned(),
                expected_code: (*code).to_owned(),
                actual_code: (*code).to_owned(),
                exact: true,
            })
            .collect(),
        metrics: LinuxMetrics {
            positive_executions,
            authority_probe_executions,
            denied_reusable: capture
                .slots
                .iter()
                .filter(|slot| slot.kind == "authority-probe" && slot.reusable)
                .count() as u32,
            reviewed_tree_changed: false,
            elapsed_ms: capture.elapsed_ms,
            supported_execution: supported,
        },
        portability_delta: LinuxPortabilityDelta {
            system_read_roots: strings(&SYSTEM_READ_ROOTS),
            dynamic_loader_premise:
                "runtime dependencies resolve beneath registered system read roots".to_owned(),
            filesystem_premise: "Landlock path-beneath mediation on the Docker Linux VM filesystem"
                .to_owned(),
            kernel_premise: format!(
                "Landlock ABI {} with seccomp-BPF",
                capture
                    .platform
                    .landlock_abi
                    .map_or_else(|| "unavailable".to_owned(), |abi| abi.to_string())
            ),
            container_boundary_counted: false,
            macos_difference:
                "default-deny Landlock filesystem authority replaces Seatbelt home-subtree denial"
                    .to_owned(),
        },
        identity: String::new(),
    };
    report.identity = hash_without("proofbound-research-linux-enforcement-report/1", &report)?;
    Ok(report)
}

pub fn validate_linux_report(report: &LinuxReport) -> Result<(), LinuxEnforcementError> {
    let expected_counts = if report.availability == "supported" {
        (30, 21)
    } else if report.availability == "unsupported" {
        (0, 0)
    } else {
        return Err(error("LNX-REPORT", "availability differs"));
    };
    if report.schema != LINUX_REPORT_SCHEMA
        || report.experiment != "EXP-0020"
        || report.programme_experiment != "EXP-LANG-013"
        || report.contract_sha256 != CONTRACT_SHA256
        || report.metrics.positive_executions != expected_counts.0
        || report.metrics.authority_probe_executions != expected_counts.1
        || report.metrics.denied_reusable != 0
        || report.metrics.reviewed_tree_changed
        || report.metrics.supported_execution != (report.availability == "supported")
        || report.effect_dispositions != effect_dispositions()
        || report.policy_attacks.len() != ATTACKS.len()
    {
        return Err(error("LNX-REPORT", "report summary differs"));
    }
    for (actual, (id, code)) in report.policy_attacks.iter().zip(ATTACKS) {
        if actual.id != id
            || actual.expected_code != code
            || actual.actual_code != code
            || !actual.exact
        {
            return Err(error("LNX-REPORT", "policy attack result differs"));
        }
    }
    if report.identity != hash_without("proofbound-research-linux-enforcement-report/1", report)? {
        return Err(error("LNX-REPORT", "report identity differs"));
    }
    Ok(())
}

fn validate_capture_header(capture: &LinuxCapture) -> Result<(), LinuxEnforcementError> {
    if capture.schema != LINUX_CAPTURE_SCHEMA
        || capture.experiment != "EXP-0020"
        || capture.programme_experiment != "EXP-LANG-013"
    {
        return Err(error("LNX-CAPTURE-SCHEMA", "capture discriminator differs"));
    }
    if capture.contract_sha256 != CONTRACT_SHA256 {
        return Err(error("LNX-CONTRACT", "frozen contract differs"));
    }
    if capture.execution_environment != "docker-linux-vm" || capture.container_confinement_counted {
        return Err(error(
            "LNX-CONTAINER-FALLBACK",
            "container confinement was counted as the mechanism",
        ));
    }
    if capture.scheduler != "concurrent-independent-landlock-processes" {
        return Err(error("LNX-MECHANISM", "scheduler differs"));
    }
    Ok(())
}

fn validate_platform(platform: &LinuxPlatform) -> Result<(), LinuxEnforcementError> {
    if platform.os != "linux"
        || !["aarch64", "x86_64"].contains(&platform.architecture.as_str())
        || !platform.kernel.contains("Linux")
    {
        return Err(error("LNX-PLATFORM", "Linux platform differs"));
    }
    if platform.landlock_abi.is_some_and(|abi| abi < 4) {
        return Err(error("LNX-PLATFORM", "Landlock ABI is insufficient"));
    }
    if platform
        .probe_stdout
        .chars()
        .any(|character| character == '\0')
        || platform
            .probe_stderr
            .chars()
            .any(|character| character == '\0')
    {
        return Err(error("LNX-MECHANISM", "probe output contains NUL"));
    }
    if platform.image != "proofbound-exp0020:registered"
        || !valid_sha256(&platform.image_identity)
        || platform.enforcer != ENFORCER
        || !valid_sha256(&platform.enforcer_sha256)
        || platform.seccomp_network_syscalls != strings(&NETWORK_SYSCALLS)
    {
        return Err(error("LNX-MECHANISM", "mechanism identity differs"));
    }
    Ok(())
}

fn validate_slot(
    slot: &LinuxSlot,
    expected: &ExpectedSlot,
    platform: &LinuxPlatform,
) -> Result<(), LinuxEnforcementError> {
    let kind = if expected.attack_id.is_some() {
        "authority-probe"
    } else {
        "positive"
    };
    if slot.slot_id != expected.slot_id
        || slot.kind != kind
        || slot.subject_id != expected.subject_id
        || slot.repetition != expected.repetition
        || slot.attack_id.as_deref() != expected.attack_id
        || slot.expected_denial_code.as_deref() != expected.denial_code
        || slot.mode != expected.mode
        || slot.attack_path != expected.attack_path
    {
        return Err(error("LNX-SLOT-INVENTORY", "slot binding differs"));
    }
    let ephemeral = format!("/state/slots/{}", slot.slot_id);
    let expected_policy = expected_policy(expected.subject_id, &ephemeral, platform);
    if slot.policy.schema != LINUX_POLICY_SCHEMA {
        return Err(error("LNX-POLICY-SCHEMA", "policy schema differs"));
    }
    if policy_without_identity(&slot.policy) != policy_without_identity(&expected_policy) {
        return Err(error("LNX-POLICY-AUTHORITY", "effective authority differs"));
    }
    if slot.policy.identity
        != hash_without("proofbound-research-linux-effective-policy/1", &slot.policy)?
    {
        return Err(error("LNX-POLICY-IDENTITY", "policy identity differs"));
    }
    if slot.command
        != expected_command(
            expected.subject_id,
            expected.mode,
            expected.attack_path,
            &ephemeral,
        )
    {
        return Err(error("LNX-COMMAND", "command differs"));
    }
    if slot.identity != hash_without("proofbound-research-linux-slot/1", slot)? {
        return Err(error("LNX-SLOT-IDENTITY", "slot identity differs"));
    }
    if expected.attack_id.is_none() {
        validate_positive(slot, &ephemeral)
    } else {
        validate_denial(slot)
    }
}

fn validate_positive(slot: &LinuxSlot, ephemeral: &str) -> Result<(), LinuxEnforcementError> {
    let expected = LinuxOutput {
        path: format!("{ephemeral}/output.txt"),
        sha256: EXPECTED_OUTPUT_SHA256.to_owned(),
        size_bytes: 32,
        mode: 0o644,
    };
    if slot.exit_code != 0
        || !slot.stdout.is_empty()
        || !slot.stderr.is_empty()
        || slot.outcome != "completed"
        || !slot.reusable
        || slot.output.as_ref() != Some(&expected)
    {
        return Err(error("LNX-POSITIVE-OUTCOME", "positive execution differs"));
    }
    Ok(())
}

fn validate_denial(slot: &LinuxSlot) -> Result<(), LinuxEnforcementError> {
    if slot.reusable {
        return Err(error("LNX-DENIED-REUSABLE", "denial is reusable"));
    }
    let markers = [
        "Operation not permitted",
        "Permission denied",
        "operation not permitted",
        "undeclared environment denied",
        "EACCES",
        "EPERM",
        "KeyError",
        "NotPresent",
        "not found",
    ];
    if slot.exit_code == 0
        || !slot.stdout.is_empty()
        || slot.outcome != "denied"
        || slot.output.is_some()
        || !markers.iter().any(|marker| slot.stderr.contains(marker))
    {
        return Err(error(
            "LNX-DENIAL-OUTCOME",
            "authority probe did not fail closed",
        ));
    }
    Ok(())
}

fn expected_slots() -> Vec<ExpectedSlot> {
    let subjects = ["subject:node", "subject:python", "subject:rust"];
    let mut slots = Vec::new();
    for subject in subjects {
        let label = subject.trim_start_matches("subject:");
        for repetition in 0..10 {
            slots.push(ExpectedSlot {
                slot_id: format!("positive-{label}-{repetition:02}"),
                subject_id: subject,
                repetition: Some(repetition),
                attack_id: None,
                denial_code: None,
                mode: "positive",
                attack_path: "/workspace/unrelated.txt",
            });
        }
    }
    const PROBES: [(&str, &str, &str, &str); 7] = [
        (
            "EXP-0018-A001",
            "read-undeclared",
            "/workspace/unrelated.txt",
            "EFX-FILE-READ-DENIED",
        ),
        (
            "EXP-0018-A002",
            "read-undeclared",
            "/workspace/nested/outside.txt",
            "EFX-FILE-READ-DENIED",
        ),
        (
            "EXP-0018-A007",
            "env-undeclared",
            "/workspace/unrelated.txt",
            "EFX-ENV-DENIED",
        ),
        (
            "EXP-0018-A009",
            "exec-unregistered",
            "/usr/bin/true",
            "EFX-EXEC-DENIED",
        ),
        (
            "EXP-0018-A011",
            "network",
            "/workspace/unrelated.txt",
            "EFX-NETWORK-DENIED",
        ),
        (
            "EXP-0018-A012",
            "write-reviewed",
            "/workspace/reviewed.txt",
            "EFX-REVIEWED-WRITE-DENIED",
        ),
        (
            "EXP-0018-A013",
            "write-escape",
            "/state/escape.txt",
            "EFX-WRITE-ESCAPE",
        ),
    ];
    for (attack_id, mode, path, code) in PROBES {
        for subject in subjects {
            slots.push(ExpectedSlot {
                slot_id: format!(
                    "probe-{}-{}",
                    attack_id.to_ascii_lowercase(),
                    subject.trim_start_matches("subject:")
                ),
                subject_id: subject,
                repetition: None,
                attack_id: Some(attack_id),
                denial_code: Some(code),
                mode,
                attack_path: path,
            });
        }
    }
    slots
}

fn expected_policy(subject: &str, ephemeral: &str, platform: &LinuxPlatform) -> LinuxPolicy {
    let (runtime, source) = subject_paths(subject);
    LinuxPolicy {
        schema: LINUX_POLICY_SCHEMA.to_owned(),
        subject_id: subject.to_owned(),
        platform: LinuxPolicyPlatform {
            os: "linux".to_owned(),
            architecture: platform.architecture.clone(),
            minimum_landlock_abi: 4,
        },
        system_read_roots: strings(&SYSTEM_READ_ROOTS),
        project_root: "/workspace".to_owned(),
        allowed_project_reads: vec!["/workspace/registered.txt".to_owned(), source.to_owned()],
        registered_absences: vec!["/workspace/must-remain-absent.txt".to_owned()],
        registered_input_mode: 0o644,
        runtime: runtime.to_owned(),
        executable_allowlist: vec![runtime.to_owned()],
        environment: BTreeMap::from([(
            "PB_REGISTERED_VALUE".to_owned(),
            sha256_bytes(b"registered-env"),
        )]),
        ephemeral_write_roots: vec![ephemeral.to_owned()],
        denied_project_reads: vec![
            "/workspace/nested/outside.txt".to_owned(),
            "/workspace/unrelated.txt".to_owned(),
        ],
        denied_reviewed_writes: vec!["/workspace/reviewed.txt".to_owned()],
        denied_escape_writes: vec!["/state/escape.txt".to_owned()],
        denied_network_syscalls: strings(&NETWORK_SYSCALLS),
        default_filesystem_authority: "deny".to_owned(),
        identity: String::new(),
    }
}

fn expected_command(subject: &str, mode: &str, attack: &str, ephemeral: &str) -> Vec<String> {
    let (runtime, source) = subject_paths(subject);
    let mut arguments = if runtime == "/state/rust-subject" {
        vec![runtime.to_owned()]
    } else {
        vec![runtime.to_owned(), source.to_owned()]
    };
    arguments.extend([
        mode.to_owned(),
        "/workspace/registered.txt".to_owned(),
        format!("{ephemeral}/output.txt"),
        attack.to_owned(),
        "1".to_owned(),
    ]);
    let mut command = vec![
        ENFORCER.to_owned(),
        runtime.to_owned(),
        source.to_owned(),
        "/workspace/registered.txt".to_owned(),
        ephemeral.to_owned(),
    ];
    command.extend(arguments);
    command
}

fn subject_paths(subject: &str) -> (&'static str, &'static str) {
    match subject {
        "subject:node" => ("/usr/bin/node", "/workspace/subjects/node_subject.mjs"),
        "subject:python" => (
            "/usr/local/bin/python3.12",
            "/workspace/subjects/python_subject.py",
        ),
        "subject:rust" => ("/state/rust-subject", "/workspace/subjects/rust_subject.rs"),
        _ => ("", ""),
    }
}

fn policy_without_identity(policy: &LinuxPolicy) -> serde_json::Value {
    let mut value = serde_json::to_value(policy).expect("serializable policy");
    value
        .as_object_mut()
        .expect("policy object")
        .remove("identity");
    value
}

fn hash_without<T: Serialize>(domain: &str, value: &T) -> Result<String, LinuxEnforcementError> {
    let mut value = serde_json::to_value(value).map_err(encoding_error)?;
    value
        .as_object_mut()
        .ok_or_else(|| error("LNX-ENCODE", "identity material is not an object"))?
        .remove("identity");
    Ok(domain_hash(
        domain,
        &canonical_json(&value).map_err(encoding_error)?,
    ))
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn effect_dispositions() -> Vec<(String, String)> {
    [
        ("environment:registered", "clearenv-then-setenv"),
        ("executable:registered", "landlock-execute-file"),
        ("filesystem:absence", "pre-execution-identity-check"),
        ("filesystem:ephemeral-write", "landlock-path-beneath-write"),
        ("filesystem:permission", "pre-execution-mode-check"),
        ("filesystem:registered-read", "landlock-path-beneath-read"),
        ("filesystem:reviewed-write", "landlock-default-deny"),
        ("network:any", "seccomp-errno-eperm"),
        ("system:runtime-read", "registered-system-read-roots"),
    ]
    .into_iter()
    .map(|(effect, disposition)| (effect.to_owned(), disposition.to_owned()))
    .collect()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn error(code: &'static str, message: impl Into<String>) -> LinuxEnforcementError {
    LinuxEnforcementError {
        code,
        message: message.into(),
    }
}

fn encoding_error(issue: impl fmt::Display) -> LinuxEnforcementError {
    error("LNX-ENCODE", issue.to_string())
}
