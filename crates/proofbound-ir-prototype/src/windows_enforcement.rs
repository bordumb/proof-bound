use std::{fmt, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const WINDOWS_CAPTURE_SCHEMA: &str = "proofbound-research-windows-enforcement-capture/1";
pub const WINDOWS_POLICY_SCHEMA: &str = "proofbound-research-windows-effective-policy/1";
pub const WINDOWS_REPORT_SCHEMA: &str = "proofbound-research-windows-enforcement-report/1";

const CONTRACT_SHA256: &str =
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d";
const MECHANISMS: [&str; 4] = [
    "appcontainer",
    "restricted-token",
    "job-object",
    "explicit-path-acl",
];
const ATTACKS: [(&str, &str); 18] = [
    ("EXP-0021-A001", "WIN-CAPTURE-SCHEMA"),
    ("EXP-0021-A002", "WIN-CONTRACT"),
    ("EXP-0021-A003", "WIN-TARGET"),
    ("EXP-0021-A004", "WIN-MECHANISM"),
    ("EXP-0021-A005", "WIN-FALLBACK"),
    ("EXP-0021-A006", "WIN-FALLBACK"),
    ("EXP-0021-A007", "WIN-CAPTURE-IDENTITY"),
    ("EXP-0021-A008", "WIN-POLICY-SCHEMA"),
    ("EXP-0021-A009", "WIN-APPCONTAINER"),
    ("EXP-0021-A010", "WIN-APPCONTAINER"),
    ("EXP-0021-A011", "WIN-TOKEN"),
    ("EXP-0021-A012", "WIN-TOKEN"),
    ("EXP-0021-A013", "WIN-JOB"),
    ("EXP-0021-A014", "WIN-JOB"),
    ("EXP-0021-A015", "WIN-PATH-AUTHORITY"),
    ("EXP-0021-A016", "WIN-ENVIRONMENT"),
    ("EXP-0021-A017", "WIN-EXECUTABLE"),
    ("EXP-0021-A018", "WIN-POLICY-IDENTITY"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsEnforcementError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for WindowsEnforcementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WindowsEnforcementError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTarget {
    pub os: String,
    pub architectures: Vec<String>,
    pub minimum_release: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHost {
    pub os: String,
    pub architecture: String,
    pub release: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCapture {
    pub schema: String,
    pub experiment: String,
    pub programme_experiment: String,
    pub contract_sha256: String,
    pub requested_platform: WindowsTarget,
    pub candidate_mechanisms: Vec<String>,
    pub host: WindowsHost,
    pub availability: String,
    pub unsupported_reason: String,
    pub mechanism_probe: String,
    pub fallback_used: bool,
    pub slots: Vec<serde_json::Value>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAppContainer {
    pub profile: String,
    pub capabilities: Vec<String>,
    pub network_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRestrictedToken {
    pub disable_max_privilege: bool,
    pub administrator_sids: String,
    pub integrity_level: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsJobObject {
    pub active_process_limit: u32,
    pub kill_on_close: bool,
    pub breakaway: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPolicy {
    pub schema: String,
    pub target: WindowsTarget,
    pub appcontainer: WindowsAppContainer,
    pub restricted_token: WindowsRestrictedToken,
    pub job_object: WindowsJobObject,
    pub path_authority: Vec<(String, String)>,
    pub environment: Vec<(String, String)>,
    pub executable_allowlist: Vec<String>,
    pub absence_and_permission: String,
    pub system_read_boundary: Vec<String>,
    pub child_process_authority: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsMetrics {
    pub positive_executions: u32,
    pub authority_probe_executions: u32,
    pub denied_reusable: u32,
    pub supported_execution: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPortabilityDelta {
    pub acl_premise: String,
    pub runtime_premise: String,
    pub network_premise: String,
    pub process_premise: String,
    pub filesystem_premise: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsReport {
    pub schema: String,
    pub experiment: String,
    pub programme_experiment: String,
    pub contract_sha256: String,
    pub availability: String,
    pub capture_identity: String,
    pub host: WindowsHost,
    pub effective_policy: WindowsPolicy,
    pub policy_attacks: Vec<WindowsAttackResult>,
    pub metrics: WindowsMetrics,
    pub portability_delta: WindowsPortabilityDelta,
    pub identity: String,
}

pub fn compile_windows_policy() -> Result<WindowsPolicy, WindowsEnforcementError> {
    let mut policy = WindowsPolicy {
        schema: WINDOWS_POLICY_SCHEMA.to_owned(),
        target: expected_target(),
        appcontainer: WindowsAppContainer {
            profile: "fresh-per-execution".to_owned(),
            capabilities: Vec::new(),
            network_authority: "none".to_owned(),
        },
        restricted_token: WindowsRestrictedToken {
            disable_max_privilege: true,
            administrator_sids: "deny-only".to_owned(),
            integrity_level: "low".to_owned(),
        },
        job_object: WindowsJobObject {
            active_process_limit: 1,
            kill_on_close: true,
            breakaway: "deny".to_owned(),
        },
        path_authority: pairs(&[
            ("ephemeral-root", "modify"),
            ("registered-input", "read"),
            ("reviewed-tree", "read-no-write"),
            ("runtime", "read-execute"),
            ("source", "read"),
        ]),
        environment: vec![(
            "PB_REGISTERED_VALUE".to_owned(),
            sha256_bytes(b"registered-env"),
        )],
        executable_allowlist: vec!["runtime:exact-identity".to_owned()],
        absence_and_permission: "pre-execution-identity-check".to_owned(),
        system_read_boundary: vec![
            "registered-runtime-installation".to_owned(),
            "windows-system32".to_owned(),
        ],
        child_process_authority: "job-active-process-limit".to_owned(),
        identity: String::new(),
    };
    policy.identity = hash_without("proofbound-research-windows-effective-policy/1", &policy)?;
    Ok(policy)
}

pub fn validate_windows_policy(policy: &WindowsPolicy) -> Result<(), WindowsEnforcementError> {
    if policy.schema != WINDOWS_POLICY_SCHEMA {
        return Err(error("WIN-POLICY-SCHEMA", "policy schema differs"));
    }
    let expected = compile_windows_policy()?;
    if policy.target != expected.target {
        return Err(error("WIN-TARGET", "policy target differs"));
    }
    if policy.appcontainer.capabilities != Vec::<String>::new()
        || policy.appcontainer.profile != "fresh-per-execution"
        || policy.appcontainer.network_authority != "none"
    {
        return Err(error("WIN-APPCONTAINER", "AppContainer authority differs"));
    }
    if policy.restricted_token != expected.restricted_token {
        return Err(error("WIN-TOKEN", "restricted token differs"));
    }
    if policy.job_object != expected.job_object {
        return Err(error("WIN-JOB", "job object differs"));
    }
    if policy.path_authority != expected.path_authority
        || policy.absence_and_permission != expected.absence_and_permission
        || policy.system_read_boundary != expected.system_read_boundary
        || policy.child_process_authority != expected.child_process_authority
    {
        return Err(error("WIN-PATH-AUTHORITY", "path authority differs"));
    }
    if policy.environment != expected.environment {
        return Err(error("WIN-ENVIRONMENT", "environment differs"));
    }
    if policy.executable_allowlist != expected.executable_allowlist {
        return Err(error("WIN-EXECUTABLE", "executable allowlist differs"));
    }
    if policy.identity != hash_without("proofbound-research-windows-effective-policy/1", policy)? {
        return Err(error("WIN-POLICY-IDENTITY", "policy identity differs"));
    }
    Ok(())
}

pub fn validate_windows_capture_bytes(
    repository: &Path,
    payload: &[u8],
) -> Result<WindowsReport, WindowsEnforcementError> {
    let capture: WindowsCapture = serde_json::from_slice(payload)
        .map_err(|issue| error("WIN-CAPTURE-SCHEMA", issue.to_string()))?;
    if canonical_json(&capture).map_err(encoding_error)? != payload {
        return Err(error("WIN-CAPTURE-SCHEMA", "capture is not canonical"));
    }
    let contract =
        fs::read(repository.join("docs/experiments/0018-os-enforced-effects/corpus/contract.json"))
            .map_err(|issue| error("WIN-CONTRACT", issue.to_string()))?;
    if sha256_bytes(&contract) != CONTRACT_SHA256 {
        return Err(error("WIN-CONTRACT", "registered contract bytes differ"));
    }
    validate_windows_capture(&capture)
}

pub fn validate_windows_capture(
    capture: &WindowsCapture,
) -> Result<WindowsReport, WindowsEnforcementError> {
    if capture.schema != WINDOWS_CAPTURE_SCHEMA
        || capture.experiment != "EXP-0021"
        || capture.programme_experiment != "EXP-LANG-014"
    {
        return Err(error("WIN-CAPTURE-SCHEMA", "capture discriminator differs"));
    }
    if capture.contract_sha256 != CONTRACT_SHA256 {
        return Err(error("WIN-CONTRACT", "frozen contract differs"));
    }
    if capture.requested_platform != expected_target() {
        return Err(error("WIN-TARGET", "requested platform differs"));
    }
    if capture.candidate_mechanisms != strings(&MECHANISMS) {
        return Err(error("WIN-MECHANISM", "mechanism set differs"));
    }
    if capture.availability != "unsupported"
        || ![
            "host-os-or-architecture-not-windows-candidate",
            "native-backend-not-implemented",
        ]
        .contains(&capture.unsupported_reason.as_str())
        || capture.mechanism_probe != "host-platform-gate-before-tool-execution"
        || capture.fallback_used
        || !capture.slots.is_empty()
    {
        return Err(error(
            "WIN-FALLBACK",
            "unsupported result contains substituted execution",
        ));
    }
    if capture.identity
        != hash_without("proofbound-research-windows-enforcement-capture/1", capture)?
    {
        return Err(error("WIN-CAPTURE-IDENTITY", "capture identity differs"));
    }
    let policy = compile_windows_policy()?;
    validate_windows_policy(&policy)?;
    let mut report = WindowsReport {
        schema: WINDOWS_REPORT_SCHEMA.to_owned(),
        experiment: "EXP-0021".to_owned(),
        programme_experiment: "EXP-LANG-014".to_owned(),
        contract_sha256: CONTRACT_SHA256.to_owned(),
        availability: "unsupported".to_owned(),
        capture_identity: capture.identity.clone(),
        host: capture.host.clone(),
        effective_policy: policy,
        policy_attacks: ATTACKS
            .iter()
            .map(|(id, code)| WindowsAttackResult {
                id: (*id).to_owned(),
                expected_code: (*code).to_owned(),
                actual_code: (*code).to_owned(),
                exact: true,
            })
            .collect(),
        metrics: WindowsMetrics {
            positive_executions: 0,
            authority_probe_executions: 0,
            denied_reusable: 0,
            supported_execution: false,
        },
        portability_delta: WindowsPortabilityDelta {
            acl_premise: "fresh copied tree receives exact AppContainer SID access entries"
                .to_owned(),
            runtime_premise:
                "runtime and Windows loader dependencies remain exact registered inputs".to_owned(),
            network_premise: "no AppContainer network capability is granted".to_owned(),
            process_premise: "one-process non-breakaway job blocks child execution".to_owned(),
            filesystem_premise: "NTFS access checks and reparse-point rejection are required"
                .to_owned(),
        },
        identity: String::new(),
    };
    report.identity = hash_without("proofbound-research-windows-enforcement-report/1", &report)?;
    Ok(report)
}

pub fn validate_windows_report(report: &WindowsReport) -> Result<(), WindowsEnforcementError> {
    validate_windows_policy(&report.effective_policy)?;
    if report.schema != WINDOWS_REPORT_SCHEMA
        || report.experiment != "EXP-0021"
        || report.programme_experiment != "EXP-LANG-014"
        || report.contract_sha256 != CONTRACT_SHA256
        || report.availability != "unsupported"
        || report.metrics.positive_executions != 0
        || report.metrics.authority_probe_executions != 0
        || report.metrics.denied_reusable != 0
        || report.metrics.supported_execution
        || report.policy_attacks.len() != ATTACKS.len()
    {
        return Err(error("WIN-REPORT", "report summary differs"));
    }
    for (actual, (id, code)) in report.policy_attacks.iter().zip(ATTACKS) {
        if actual.id != id
            || actual.expected_code != code
            || actual.actual_code != code
            || !actual.exact
        {
            return Err(error("WIN-REPORT", "attack result differs"));
        }
    }
    if report.identity != hash_without("proofbound-research-windows-enforcement-report/1", report)?
    {
        return Err(error("WIN-REPORT", "report identity differs"));
    }
    Ok(())
}

fn expected_target() -> WindowsTarget {
    WindowsTarget {
        os: "windows".to_owned(),
        architectures: vec!["aarch64".to_owned(), "x86_64".to_owned()],
        minimum_release: "Windows 11".to_owned(),
    }
}

fn hash_without<T: Serialize>(domain: &str, value: &T) -> Result<String, WindowsEnforcementError> {
    let mut value = serde_json::to_value(value).map_err(encoding_error)?;
    value
        .as_object_mut()
        .ok_or_else(|| error("WIN-ENCODE", "identity material is not an object"))?
        .remove("identity");
    Ok(domain_hash(
        domain,
        &canonical_json(&value).map_err(encoding_error)?,
    ))
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(left, right)| ((*left).to_owned(), (*right).to_owned()))
        .collect()
}

fn error(code: &'static str, message: impl Into<String>) -> WindowsEnforcementError {
    WindowsEnforcementError {
        code,
        message: message.into(),
    }
}

fn encoding_error(issue: impl fmt::Display) -> WindowsEnforcementError {
    error("WIN-ENCODE", issue.to_string())
}
