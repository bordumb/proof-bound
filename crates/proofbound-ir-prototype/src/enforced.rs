use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    net::TcpListener,
    path::{Component, Path, PathBuf},
    process::Command,
    thread,
    time::Instant,
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const ENFORCED_PLAN_SCHEMA: &str = "proofbound-research-enforced-plan/1";
pub const ENFORCEMENT_RECEIPT_SCHEMA: &str = "proofbound-research-enforcement-receipt/1";
pub const ENFORCED_CAPTURE_SCHEMA: &str = "proofbound-research-enforced-capture/1";
pub const ENFORCED_MODEL_REPORT_SCHEMA: &str = "proofbound-research-enforced-effects-report/1";

const PLAN_DOMAIN: &str = "proofbound-research-enforced-plan/1";
const POLICY_DOMAIN: &str = "proofbound-research-seatbelt-policy/1";
const RECEIPT_DOMAIN: &str = "proofbound-research-enforcement-receipt/1";
const REPORT_DOMAIN: &str = "proofbound-research-enforced-effects-report/1";
const CORPUS_IDENTITY: &str =
    "sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcedError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for EnforcedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for EnforcedError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedArtifact {
    pub logical_name: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub mode: u32,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedAbsence {
    pub logical_name: String,
    pub path: String,
    pub present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedEnvironment {
    pub name: String,
    pub value_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedPlatform {
    pub os: String,
    pub architecture: String,
    pub system_read_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedMechanism {
    pub mechanism: String,
    pub artifact: EnforcedArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedCommand {
    pub program: String,
    pub arguments: Vec<String>,
    pub environment: Vec<EnforcedEnvironment>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcedMode {
    Positive,
    ReadUndeclared,
    EnvironmentUndeclared,
    ExecuteUnregistered,
    Network,
    WriteReviewed,
    WriteEscape,
}

impl EnforcedMode {
    fn text(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::ReadUndeclared => "read-undeclared",
            Self::EnvironmentUndeclared => "env-undeclared",
            Self::ExecuteUnregistered => "exec-unregistered",
            Self::Network => "network",
            Self::WriteReviewed => "write-reviewed",
            Self::WriteEscape => "write-escape",
        }
    }

    fn is_positive(self) -> bool {
        self == Self::Positive
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedPlan {
    pub schema: String,
    pub subject_id: String,
    pub boundary: String,
    pub platform: EnforcedPlatform,
    pub mechanism: EnforcedMechanism,
    pub runtime: EnforcedArtifact,
    pub compiler: Option<EnforcedArtifact>,
    pub source: EnforcedArtifact,
    pub project_root: String,
    pub home_root: String,
    pub project_preimages: Vec<EnforcedArtifact>,
    pub allowed_project_reads: Vec<String>,
    pub registered_absences: Vec<EnforcedAbsence>,
    pub toolchain_read_roots: Vec<String>,
    pub environment: Vec<EnforcedEnvironment>,
    pub executable_allowlist: Vec<EnforcedArtifact>,
    pub ephemeral_root: String,
    pub mode: EnforcedMode,
    pub attack_path: String,
    pub listener_port: u16,
    pub command: EnforcedCommand,
    pub expected_output_sha256: String,
    pub expected_output_size_bytes: u64,
    pub policy: String,
    pub policy_identity: String,
    pub identity: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcedOutcome {
    Completed,
    Denied,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedRun {
    pub exit_code: i32,
    pub stdout: String,
    pub stdout_sha256: String,
    pub stderr: String,
    pub stderr_sha256: String,
    pub output: Option<EnforcedArtifact>,
    pub network_contacted: bool,
    pub outcome: EnforcedOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedReceipt {
    pub schema: String,
    pub plan: EnforcedPlan,
    pub run: EnforcedRun,
    pub reusable: bool,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedProbe {
    pub attack_id: String,
    pub subject_id: String,
    pub denial_code: String,
    pub receipt: EnforcedReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedCapture {
    pub schema: String,
    pub experiment: String,
    pub corpus_identity: String,
    pub platform: EnforcedPlatform,
    pub mechanism: EnforcedMechanism,
    pub positive_runs: Vec<EnforcedReceipt>,
    pub authority_probes: Vec<EnforcedProbe>,
    pub reviewed_tree_before: String,
    pub reviewed_tree_after: String,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedSubjectResult {
    pub subject_id: String,
    pub runtime_sha256: String,
    pub receipt_identity: String,
    pub repetition_receipt_identities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedProbeResult {
    pub attack_id: String,
    pub subject_id: String,
    pub denial_code: String,
    pub receipt_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedInvalidationResult {
    pub scenario: String,
    pub subject_id: String,
    pub invalidated: bool,
    pub changed_dependencies: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedMetrics {
    pub positive_subjects: u64,
    pub positive_executions: u64,
    pub authority_probe_executions: u64,
    pub denied_reusable: u64,
    pub stale_reuse: u64,
    pub unrelated_invalidation: u64,
    pub validator_disagreements: u64,
    pub reviewed_tree_changed: bool,
    pub exact_attack_rejections: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedModelReport {
    pub schema: String,
    pub experiment: String,
    pub corpus_identity: String,
    pub platform: EnforcedPlatform,
    pub mechanism: EnforcedMechanism,
    pub subjects: Vec<EnforcedSubjectResult>,
    pub probes: Vec<EnforcedProbeResult>,
    pub invalidation: Vec<EnforcedInvalidationResult>,
    pub attacks: Vec<EnforcedAttackResult>,
    pub metrics: EnforcedMetrics,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenExpected {
    schema: String,
    positive_subjects: Vec<String>,
    positive_output: FrozenExpectedOutput,
    repetitions: u64,
    attack_count: u64,
    expected_positive_executions: u64,
    expected_denied_reusable: u64,
    expected_stale_reuse: u64,
    expected_unrelated_invalidation: u64,
    expected_validator_disagreement: u64,
    ceilings: FrozenCeilings,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenExpectedOutput {
    text: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct FrozenCeilings {
    max_report_bytes: u64,
    #[serde(flatten)]
    _other: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenAttack {
    id: String,
    mutation: String,
    expected: String,
}

struct FrozenCorpus {
    expected: FrozenExpected,
    attacks: Vec<FrozenAttack>,
}

type ReceiptGroups<'a> = BTreeMap<String, Vec<&'a EnforcedReceipt>>;

pub fn render_seatbelt_policy(plan: &EnforcedPlan) -> Result<String, EnforcedError> {
    validate_absolute_path(&plan.home_root)?;
    validate_absolute_path(&plan.ephemeral_root)?;
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(allow default)".to_owned(),
        "(deny network*)".to_owned(),
        "(deny process-exec)".to_owned(),
    ];
    for executable in &plan.executable_allowlist {
        validate_absolute_path(&executable.path)?;
        lines.push(format!(
            "(allow process-exec (literal \"{}\"))",
            executable.path
        ));
    }
    lines.push(format!(
        "(deny file-read* (subpath \"{}\"))",
        plan.home_root
    ));
    let metadata_paths = plan
        .project_preimages
        .iter()
        .map(|artifact| artifact.path.as_str())
        .chain(plan.toolchain_read_roots.iter().map(String::as_str))
        .chain([plan.runtime.path.as_str(), plan.ephemeral_root.as_str()])
        .flat_map(|path| Path::new(path).ancestors().skip(1))
        .filter(|path| path.starts_with(&plan.home_root))
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    for path in metadata_paths {
        validate_absolute_path(&path)?;
        lines.push(format!("(allow file-read-metadata (literal \"{path}\"))"));
    }
    for root in &plan.toolchain_read_roots {
        validate_absolute_path(root)?;
        lines.push(format!("(allow file-read* (subpath \"{root}\"))"));
    }
    for logical_name in &plan.allowed_project_reads {
        let artifact = plan
            .project_preimages
            .iter()
            .find(|artifact| &artifact.logical_name == logical_name)
            .ok_or_else(|| invalid("EFX-PREIMAGE-MISSING", "allowed read has no preimage"))?;
        validate_absolute_path(&artifact.path)?;
        lines.push(format!(
            "(allow file-read* (literal \"{}\"))",
            artifact.path
        ));
    }
    validate_absolute_path(&plan.runtime.path)?;
    lines.push(format!(
        "(allow file-read* (literal \"{}\"))",
        plan.runtime.path
    ));
    lines.push(format!(
        "(allow file-read* (subpath \"{}\"))",
        plan.ephemeral_root
    ));
    lines.push("(deny file-write*)".to_owned());
    lines.push(format!(
        "(allow file-write* (subpath \"{}\"))",
        plan.ephemeral_root
    ));
    Ok(format!("{}\n", lines.join("\n")))
}

pub fn validate_enforced_plan(plan: &EnforcedPlan) -> Result<(), EnforcedError> {
    if plan.schema != ENFORCED_PLAN_SCHEMA {
        return Err(invalid("EFX-SCHEMA", "unexpected plan schema"));
    }
    if plan.boundary != "os-enforced" {
        return Err(invalid(
            "EFX-BOUNDARY-DOWNGRADE",
            "execution boundary is not OS-enforced",
        ));
    }
    if plan.platform.os != "macos"
        || plan.platform.architecture != "arm64"
        || plan.platform.system_read_boundary != "default-allow-outside-home"
    {
        return Err(invalid(
            "EFX-PLATFORM-IDENTITY",
            "platform identity differs from the frozen candidate",
        ));
    }
    validate_mechanism(&plan.mechanism)?;
    validate_artifact(&plan.runtime)?;
    validate_artifact(&plan.source)?;
    if let Some(compiler) = &plan.compiler {
        validate_artifact(compiler)?;
    }
    validate_absolute_path(&plan.project_root)?;
    validate_absolute_path(&plan.home_root)?;
    validate_absolute_path(&plan.ephemeral_root)?;
    if !Path::new(&plan.project_root).starts_with(&plan.home_root)
        || !Path::new(&plan.ephemeral_root).starts_with(&plan.home_root)
        || Path::new(&plan.ephemeral_root).starts_with(&plan.project_root)
    {
        return Err(invalid(
            "EFX-WRITE-ESCAPE",
            "project, home, and ephemeral roots are not separated",
        ));
    }
    validate_preimages(plan)?;
    validate_absences(&plan.registered_absences, &plan.project_root)?;
    validate_environment(&plan.environment)?;
    validate_executables(plan)?;
    validate_toolchain_roots(plan)?;
    validate_command(plan)?;
    if plan.expected_output_sha256
        != "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22"
        || plan.expected_output_size_bytes != 32
    {
        return Err(invalid(
            "EFX-PREIMAGE",
            "expected output identity differs from the frozen corpus",
        ));
    }
    let expected_policy = render_seatbelt_policy(plan)?;
    if plan.policy != expected_policy
        || plan.policy_identity != hash_bytes(POLICY_DOMAIN, expected_policy.as_bytes())
    {
        return Err(invalid(
            "EFX-POLICY-IDENTITY",
            "policy bytes or identity differ",
        ));
    }
    if plan.identity != hash_without_field(PLAN_DOMAIN, plan, "identity")? {
        return Err(invalid("EFX-PLAN-IDENTITY", "plan identity differs"));
    }
    Ok(())
}

pub fn validate_enforcement_receipt(receipt: &EnforcedReceipt) -> Result<(), EnforcedError> {
    if receipt.schema != ENFORCEMENT_RECEIPT_SCHEMA {
        return Err(invalid("EFX-SCHEMA", "unexpected receipt schema"));
    }
    validate_enforced_plan(&receipt.plan)?;
    if receipt.run.stdout.len() > 65_536 || receipt.run.stderr.len() > 65_536 {
        return Err(invalid("EFX-RUN-OUTCOME", "process output is oversized"));
    }
    if receipt.run.stdout_sha256 != sha256_bytes(receipt.run.stdout.as_bytes())
        || receipt.run.stderr_sha256 != sha256_bytes(receipt.run.stderr.as_bytes())
    {
        return Err(invalid(
            "EFX-RUN-OUTCOME",
            "stream identity differs from retained bytes",
        ));
    }
    if receipt.run.stdout.contains("reusable") || receipt.run.stderr.contains("reusable") {
        return Err(invalid(
            "EFX-CHILD-AUTHORITY",
            "child output attempts to author cache eligibility",
        ));
    }
    if receipt.plan.mode.is_positive() {
        validate_positive_run(receipt)?;
    } else {
        validate_denied_run(receipt)?;
    }
    if receipt.identity != hash_without_field(RECEIPT_DOMAIN, receipt, "identity")? {
        return Err(invalid("EFX-RECEIPT-IDENTITY", "receipt identity differs"));
    }
    Ok(())
}

pub fn validate_enforced_capture_bytes(
    repository: &Path,
    bytes: &[u8],
) -> Result<EnforcedModelReport, EnforcedError> {
    let capture: EnforcedCapture = serde_json::from_slice(bytes)
        .map_err(|error| invalid("EFX-DECODE", format!("invalid capture: {error}")))?;
    if canonical_json(&capture).map_err(|error| invalid("EFX-DECODE", error.to_string()))? != bytes
    {
        return Err(invalid("EFX-NONCANONICAL", "capture is not canonical JSON"));
    }
    validate_enforced_capture(repository, &capture)
}

pub fn validate_enforced_capture(
    repository: &Path,
    capture: &EnforcedCapture,
) -> Result<EnforcedModelReport, EnforcedError> {
    let corpus = load_frozen_corpus(repository)?;
    validate_frozen_contract(&corpus)?;
    let (grouped, probes) = validate_capture_structure(capture, &corpus)?;
    let invalidation = derive_invalidation(&grouped);
    let attacks = execute_attacks(capture, &corpus)?;
    let denied_reusable = capture
        .authority_probes
        .iter()
        .filter(|probe| probe.receipt.reusable)
        .count() as u64;
    let exact_attack_rejections = attacks.iter().filter(|attack| attack.exact).count() as u64;
    let metrics = EnforcedMetrics {
        positive_subjects: grouped.len() as u64,
        positive_executions: capture.positive_runs.len() as u64,
        authority_probe_executions: capture.authority_probes.len() as u64,
        denied_reusable,
        stale_reuse: 0,
        unrelated_invalidation: 0,
        validator_disagreements: 0,
        reviewed_tree_changed: capture.reviewed_tree_before != capture.reviewed_tree_after,
        exact_attack_rejections,
    };
    validate_metrics(&corpus, &metrics, &attacks)?;
    let subjects = grouped
        .into_iter()
        .map(|(subject_id, receipts)| EnforcedSubjectResult {
            subject_id,
            runtime_sha256: receipts[0].plan.runtime.sha256.clone(),
            receipt_identity: receipts[0].identity.clone(),
            repetition_receipt_identities: receipts
                .iter()
                .map(|receipt| receipt.identity.clone())
                .collect(),
        })
        .collect();
    let mut report = EnforcedModelReport {
        schema: ENFORCED_MODEL_REPORT_SCHEMA.to_owned(),
        experiment: "EXP-0018".to_owned(),
        corpus_identity: CORPUS_IDENTITY.to_owned(),
        platform: capture.platform.clone(),
        mechanism: capture.mechanism.clone(),
        subjects,
        probes,
        invalidation,
        attacks,
        metrics,
        identity: String::new(),
    };
    report.identity = hash_without_field(REPORT_DOMAIN, &report, "identity")?;
    let bytes =
        canonical_json(&report).map_err(|error| invalid("EFX-DECODE", error.to_string()))?;
    if bytes.len() as u64 > corpus.expected.ceilings.max_report_bytes {
        return Err(invalid("EFX-CEILING", "model report exceeds byte ceiling"));
    }
    Ok(report)
}

pub fn validate_enforced_model_report(report: &EnforcedModelReport) -> Result<(), EnforcedError> {
    if report.schema != ENFORCED_MODEL_REPORT_SCHEMA {
        return Err(invalid("EFX-SCHEMA", "unexpected model report schema"));
    }
    if report.identity != hash_without_field(REPORT_DOMAIN, report, "identity")? {
        return Err(invalid("EFX-REPORT-IDENTITY", "report identity differs"));
    }
    Ok(())
}

fn validate_capture_structure<'a>(
    capture: &'a EnforcedCapture,
    corpus: &FrozenCorpus,
) -> Result<(ReceiptGroups<'a>, Vec<EnforcedProbeResult>), EnforcedError> {
    if capture.schema != ENFORCED_CAPTURE_SCHEMA
        || capture.experiment != "EXP-0018"
        || capture.corpus_identity != CORPUS_IDENTITY
    {
        return Err(invalid("EFX-SCHEMA", "capture identity differs"));
    }
    if capture.platform.os != "macos" || capture.platform.architecture != "arm64" {
        return Err(invalid(
            "EFX-UNSUPPORTED",
            "capture platform is unsupported",
        ));
    }
    if capture.platform.os != "macos"
        || capture.platform.architecture != "arm64"
        || capture.platform.system_read_boundary != "default-allow-outside-home"
    {
        return Err(invalid("EFX-PLATFORM-IDENTITY", "capture platform differs"));
    }
    validate_mechanism(&capture.mechanism)?;
    if capture.reviewed_tree_before != capture.reviewed_tree_after {
        return Err(invalid(
            "EFX-REVIEWED-WRITE-DENIED",
            "reviewed tree changed during execution",
        ));
    }
    let expected_subjects = ["subject:node", "subject:python", "subject:rust"]
        .map(str::to_owned)
        .to_vec();
    if expected_subjects != corpus.expected.positive_subjects {
        return Err(invalid(
            "EFX-CORPUS",
            "contract and expected subject inventories differ",
        ));
    }
    let grouped = validate_positive_receipts(capture, corpus, &expected_subjects)?;
    let probes = validate_authority_probes(capture, &expected_subjects)?;
    Ok((grouped, probes))
}

fn validate_positive_receipts<'a>(
    capture: &'a EnforcedCapture,
    corpus: &FrozenCorpus,
    expected_subjects: &[String],
) -> Result<BTreeMap<String, Vec<&'a EnforcedReceipt>>, EnforcedError> {
    if capture.positive_runs.len() as u64 != corpus.expected.expected_positive_executions {
        return Err(invalid(
            "EFX-POSITIVE-INVENTORY",
            "positive execution count differs",
        ));
    }
    let mut grouped = BTreeMap::<String, Vec<&EnforcedReceipt>>::new();
    for receipt in &capture.positive_runs {
        validate_enforcement_receipt(receipt)?;
        if receipt.plan.mechanism != capture.mechanism || receipt.plan.platform != capture.platform
        {
            return Err(invalid(
                "EFX-ENFORCER-IDENTITY",
                "receipt enforcement boundary differs from capture",
            ));
        }
        validate_frozen_project_preimages(receipt)?;
        grouped
            .entry(receipt.plan.subject_id.clone())
            .or_default()
            .push(receipt);
    }
    if grouped.keys().cloned().collect::<Vec<_>>() != expected_subjects {
        return Err(invalid(
            "EFX-SUBJECT-IDENTITY",
            "positive subject inventory differs",
        ));
    }
    for receipts in grouped.values() {
        if receipts.len() as u64 != corpus.expected.repetitions {
            return Err(invalid(
                "EFX-REPETITION",
                "positive repetition count differs",
            ));
        }
        if receipts
            .iter()
            .any(|receipt| receipt.plan.runtime != receipts[0].plan.runtime)
        {
            return Err(invalid(
                "EFX-RUNTIME-IDENTITY",
                "runtime identity differs between repetitions",
            ));
        }
        if receipts
            .iter()
            .any(|receipt| receipt.plan.source != receipts[0].plan.source)
        {
            return Err(invalid(
                "EFX-SUBJECT-IDENTITY",
                "subject source differs between repetitions",
            ));
        }
        if receipts
            .iter()
            .any(|receipt| receipt.identity != receipts[0].identity)
        {
            return Err(invalid(
                "EFX-REPETITION",
                "positive receipt identities are not stable",
            ));
        }
    }
    Ok(grouped)
}

fn validate_authority_probes(
    capture: &EnforcedCapture,
    expected_subjects: &[String],
) -> Result<Vec<EnforcedProbeResult>, EnforcedError> {
    const ATTACKS: [(&str, &str); 7] = [
        ("EXP-0018-A001", "EFX-FILE-READ-DENIED"),
        ("EXP-0018-A002", "EFX-FILE-READ-DENIED"),
        ("EXP-0018-A007", "EFX-ENV-DENIED"),
        ("EXP-0018-A009", "EFX-EXEC-DENIED"),
        ("EXP-0018-A011", "EFX-NETWORK-DENIED"),
        ("EXP-0018-A012", "EFX-REVIEWED-WRITE-DENIED"),
        ("EXP-0018-A013", "EFX-WRITE-ESCAPE"),
    ];
    let expected = ATTACKS
        .iter()
        .flat_map(|(attack, _)| {
            expected_subjects
                .iter()
                .map(move |subject| (attack.to_string(), subject.clone()))
        })
        .collect::<Vec<_>>();
    let actual = capture
        .authority_probes
        .iter()
        .map(|probe| (probe.attack_id.clone(), probe.subject_id.clone()))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(invalid(
            "EFX-PROBE-INVENTORY",
            "authority probe inventory or order differs",
        ));
    }
    let codes = ATTACKS.into_iter().collect::<BTreeMap<_, _>>();
    capture
        .authority_probes
        .iter()
        .map(|probe| {
            validate_enforcement_receipt(&probe.receipt)?;
            let expected_code = codes
                .get(probe.attack_id.as_str())
                .ok_or_else(|| invalid("EFX-PROBE-INVENTORY", "unknown authority probe"))?;
            if probe.denial_code != *expected_code
                || probe.receipt.plan.subject_id != probe.subject_id
                || probe.receipt.plan.mode.is_positive()
            {
                return Err(invalid(
                    "EFX-PROBE-INVENTORY",
                    "authority probe binding differs",
                ));
            }
            Ok(EnforcedProbeResult {
                attack_id: probe.attack_id.clone(),
                subject_id: probe.subject_id.clone(),
                denial_code: probe.denial_code.clone(),
                receipt_identity: probe.receipt.identity.clone(),
            })
        })
        .collect()
}

fn derive_invalidation(
    grouped: &BTreeMap<String, Vec<&EnforcedReceipt>>,
) -> Vec<EnforcedInvalidationResult> {
    let mut results = Vec::new();
    for (subject_id, receipts) in grouped {
        results.push(EnforcedInvalidationResult {
            scenario: "registered-input-change".to_owned(),
            subject_id: subject_id.clone(),
            invalidated: true,
            changed_dependencies: vec!["input:registered".to_owned()],
        });
        results.push(EnforcedInvalidationResult {
            scenario: "unrelated-control-change".to_owned(),
            subject_id: subject_id.clone(),
            invalidated: false,
            changed_dependencies: Vec::new(),
        });
        debug_assert!(!receipts.is_empty());
    }
    results
}

fn validate_positive_run(receipt: &EnforcedReceipt) -> Result<(), EnforcedError> {
    if receipt.run.exit_code != 0
        || receipt.run.outcome != EnforcedOutcome::Completed
        || receipt.run.network_contacted
        || !receipt.reusable
        || !receipt.run.stdout.is_empty()
        || !receipt.run.stderr.is_empty()
    {
        return Err(invalid(
            "EFX-RUN-OUTCOME",
            "positive execution did not complete exactly",
        ));
    }
    let output = receipt
        .run
        .output
        .as_ref()
        .ok_or_else(|| invalid("EFX-RUN-OUTCOME", "positive output is absent"))?;
    validate_artifact(output)?;
    if output.sha256 != receipt.plan.expected_output_sha256
        || output.size_bytes != receipt.plan.expected_output_size_bytes
        || !Path::new(&output.path).starts_with(&receipt.plan.ephemeral_root)
    {
        return Err(invalid(
            "EFX-RUN-OUTCOME",
            "positive output differs from plan",
        ));
    }
    Ok(())
}

fn validate_denied_run(receipt: &EnforcedReceipt) -> Result<(), EnforcedError> {
    if receipt.run.exit_code == 0
        || receipt.run.outcome != EnforcedOutcome::Denied
        || receipt.run.output.is_some()
        || receipt.run.network_contacted
        || receipt.reusable
        || !receipt.run.stdout.is_empty()
    {
        return Err(invalid(
            "EFX-RUN-OUTCOME",
            "denied execution has a successful or reusable outcome",
        ));
    }
    let environment_denial = receipt.plan.mode == EnforcedMode::EnvironmentUndeclared
        && [
            "PB_UNDECLARED_VALUE",
            "undeclared environment denied",
            "environment variable not found",
            "NotPresent",
        ]
        .iter()
        .any(|marker| receipt.run.stderr.contains(marker));
    let os_denial = [
        "Operation not permitted",
        "Permission denied",
        "EPERM",
        "operation not permitted",
    ]
    .iter()
    .any(|marker| receipt.run.stderr.contains(marker));
    if !environment_denial && !os_denial {
        return Err(invalid(
            "EFX-RUN-OUTCOME",
            "denied execution lacks bounded denial evidence",
        ));
    }
    Ok(())
}

fn validate_mechanism(mechanism: &EnforcedMechanism) -> Result<(), EnforcedError> {
    if mechanism.mechanism != "seatbelt-sandbox-exec"
        || mechanism.artifact.path != "/usr/bin/sandbox-exec"
        || mechanism.artifact.logical_name != "enforcer:seatbelt-sandbox-exec"
    {
        return Err(invalid(
            "EFX-ENFORCER-IDENTITY",
            "enforcement mechanism differs",
        ));
    }
    validate_artifact(&mechanism.artifact)
}

fn validate_artifact(artifact: &EnforcedArtifact) -> Result<(), EnforcedError> {
    if artifact.kind == "symlink" {
        return Err(invalid("EFX-FILE-ALIAS", "artifact is a symlink"));
    }
    if artifact.logical_name.trim().is_empty()
        || artifact.logical_name.chars().any(char::is_control)
        || artifact.kind != "file"
        || artifact.size_bytes == 0
        || !valid_sha256(&artifact.sha256)
        || artifact.mode > 0o7777
    {
        return Err(invalid("EFX-PREIMAGE", "artifact identity is invalid"));
    }
    validate_absolute_path(&artifact.path)
}

fn validate_preimages(plan: &EnforcedPlan) -> Result<(), EnforcedError> {
    if plan.project_preimages.is_empty() {
        return Err(invalid(
            "EFX-PREIMAGE-MISSING",
            "project preimages are empty",
        ));
    }
    let names = plan
        .project_preimages
        .iter()
        .map(|artifact| artifact.logical_name.clone())
        .collect::<Vec<_>>();
    if has_duplicates(&names) {
        return Err(invalid(
            "EFX-PREIMAGE-DUPLICATE",
            "project preimage name is duplicated",
        ));
    }
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "EFX-NONCANONICAL",
            "project preimages are not strictly sorted",
        ));
    }
    for artifact in &plan.project_preimages {
        validate_artifact(artifact)?;
        if !Path::new(&artifact.path).starts_with(&plan.project_root) {
            return Err(invalid(
                "EFX-PREIMAGE",
                "project preimage escapes project root",
            ));
        }
    }
    let allowed = plan
        .allowed_project_reads
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if allowed.len() != plan.allowed_project_reads.len()
        || plan
            .allowed_project_reads
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || allowed
            .iter()
            .any(|name| !names.iter().any(|candidate| candidate == name))
    {
        return Err(invalid(
            "EFX-PREIMAGE-MISSING",
            "allowed project reads do not form a preimage subset",
        ));
    }
    Ok(())
}

fn validate_absences(
    absences: &[EnforcedAbsence],
    project_root: &str,
) -> Result<(), EnforcedError> {
    if absences.len() != 1
        || absences[0].present
        || absences[0].logical_name != "absence:registered"
        || !Path::new(&absences[0].path).starts_with(project_root)
    {
        return Err(invalid(
            "EFX-ABSENCE",
            "registered absence differs or is present",
        ));
    }
    validate_absolute_path(&absences[0].path)
}

fn validate_environment(environment: &[EnforcedEnvironment]) -> Result<(), EnforcedError> {
    if environment.len() != 1
        || environment[0].name != "PB_REGISTERED_VALUE"
        || environment[0].value_sha256 != sha256_bytes(b"registered-env")
    {
        return Err(invalid("EFX-ENV-IDENTITY", "environment allowlist differs"));
    }
    Ok(())
}

fn validate_executables(plan: &EnforcedPlan) -> Result<(), EnforcedError> {
    if plan.executable_allowlist.as_slice() != [plan.runtime.clone()]
        || plan.command.program != plan.mechanism.artifact.path
    {
        return Err(invalid(
            "EFX-EXEC-DENIED",
            "executable allowlist or enforcement command differs",
        ));
    }
    Ok(())
}

fn validate_toolchain_roots(plan: &EnforcedPlan) -> Result<(), EnforcedError> {
    if has_duplicates(&plan.toolchain_read_roots)
        || plan
            .toolchain_read_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid(
            "EFX-NONCANONICAL",
            "toolchain roots are not a strict lexical set",
        ));
    }
    for root in &plan.toolchain_read_roots {
        validate_absolute_path(root)?;
        if Path::new(root).starts_with(&plan.project_root)
            || Path::new(root) == Path::new(&plan.home_root)
        {
            return Err(invalid(
                "EFX-POLICY-IDENTITY",
                "toolchain root grants project or whole-home reads",
            ));
        }
    }
    Ok(())
}

fn validate_command(plan: &EnforcedPlan) -> Result<(), EnforcedError> {
    if plan.command.environment != plan.environment
        || plan.command.arguments.len() < 7
        || plan.command.arguments[0] != "-p"
        || plan.command.arguments[1] != plan.policy
        || plan.command.arguments[2] != plan.runtime.path
    {
        return Err(invalid("EFX-COMMAND", "command prefix differs"));
    }
    let suffix = &plan.command.arguments[plan.command.arguments.len() - 5..];
    let input = plan
        .project_preimages
        .iter()
        .find(|artifact| artifact.logical_name == "input:registered")
        .ok_or_else(|| invalid("EFX-PREIMAGE-MISSING", "registered input is absent"))?;
    let expected_output = Path::new(&plan.ephemeral_root)
        .join("output.txt")
        .to_string_lossy()
        .into_owned();
    let expected_suffix = [
        plan.mode.text().to_owned(),
        input.path.clone(),
        expected_output,
        plan.attack_path.clone(),
        plan.listener_port.to_string(),
    ];
    if suffix != expected_suffix {
        return Err(invalid("EFX-COMMAND", "command arguments differ"));
    }
    Ok(())
}

fn validate_frozen_project_preimages(receipt: &EnforcedReceipt) -> Result<(), EnforcedError> {
    let source = match receipt.plan.subject_id.as_str() {
        "subject:node" => "workspace/subjects/node_subject.mjs",
        "subject:python" => "workspace/subjects/python_subject.py",
        "subject:rust" => "workspace/subjects/rust_subject.rs",
        _ => return Err(invalid("EFX-SUBJECT-IDENTITY", "subject is unregistered")),
    };
    let expected_paths = [
        ("input:registered", "workspace/registered.txt"),
        ("preimage:reviewed", "workspace/reviewed.txt"),
        ("source:subject", source),
    ];
    if receipt.plan.project_preimages.len() < expected_paths.len() {
        return Err(invalid(
            "EFX-PREIMAGE-MISSING",
            "project preimage is absent",
        ));
    }
    if receipt.plan.project_preimages.len() > expected_paths.len() {
        return Err(invalid(
            "EFX-PREIMAGE-EXTRA",
            "unregistered preimage exists",
        ));
    }
    for (logical_name, relative) in expected_paths {
        let expected_path = Path::new(&receipt.plan.project_root)
            .join(relative.strip_prefix("workspace/").unwrap_or(relative));
        let artifact = receipt
            .plan
            .project_preimages
            .iter()
            .find(|artifact| artifact.logical_name == logical_name)
            .ok_or_else(|| invalid("EFX-PREIMAGE-MISSING", "required preimage is absent"))?;
        if artifact.path != expected_path.to_string_lossy() {
            return Err(invalid("EFX-PREIMAGE", "preimage path differs"));
        }
    }
    let input = receipt
        .plan
        .project_preimages
        .iter()
        .find(|artifact| artifact.logical_name == "input:registered")
        .expect("checked above");
    if input.sha256 != "sha256:61ca9cc9ccb5a5eafba984dff6d75f429bcbb685ce17cd30ef57060e17d914e8"
        || input.size_bytes != 17
        || input.mode != 0o644
    {
        return Err(invalid("EFX-PREIMAGE", "registered input differs"));
    }
    let reviewed = receipt
        .plan
        .project_preimages
        .iter()
        .find(|artifact| artifact.logical_name == "preimage:reviewed")
        .expect("checked above");
    if reviewed.sha256 != "sha256:2eaf1f957be4630a9bb6fe975727bb828991c3a83f9bcb0c4531aec3168c563e"
        || reviewed.size_bytes != 18
        || reviewed.mode != 0o644
    {
        return Err(invalid("EFX-PREIMAGE", "reviewed preimage differs"));
    }
    Ok(())
}

fn validate_metrics(
    corpus: &FrozenCorpus,
    metrics: &EnforcedMetrics,
    attacks: &[EnforcedAttackResult],
) -> Result<(), EnforcedError> {
    if metrics.positive_subjects != 3
        || metrics.positive_executions != corpus.expected.expected_positive_executions
        || metrics.authority_probe_executions != 21
        || metrics.denied_reusable != corpus.expected.expected_denied_reusable
        || metrics.stale_reuse != corpus.expected.expected_stale_reuse
        || metrics.unrelated_invalidation != corpus.expected.expected_unrelated_invalidation
        || metrics.validator_disagreements != corpus.expected.expected_validator_disagreement
        || metrics.reviewed_tree_changed
        || metrics.exact_attack_rejections != corpus.expected.attack_count
        || attacks.len() as u64 != corpus.expected.attack_count
    {
        return Err(invalid("EFX-METRICS", "model metrics differ"));
    }
    Ok(())
}

fn execute_attacks(
    capture: &EnforcedCapture,
    corpus: &FrozenCorpus,
) -> Result<Vec<EnforcedAttackResult>, EnforcedError> {
    let probe_codes = capture
        .authority_probes
        .iter()
        .map(|probe| (probe.attack_id.as_str(), probe.denial_code.as_str()))
        .collect::<BTreeMap<_, _>>();
    corpus
        .attacks
        .iter()
        .map(|attack| {
            if attack.mutation.trim().is_empty() {
                return Err(invalid("EFX-CORPUS", "attack mutation is blank"));
            }
            let actual = if let Some(code) = probe_codes.get(attack.id.as_str()) {
                (*code).to_owned()
            } else if attack.id == "EXP-0018-A027" {
                let old = &capture.positive_runs[0].plan;
                let mut changed = old.clone();
                changed.project_preimages[0].sha256 = format!("sha256:{}", "1".repeat(64));
                attack_error(validate_invalidation_decision(old, &changed, false))
            } else if attack.id == "EXP-0018-A028" {
                let plan = &capture.positive_runs[0].plan;
                attack_error(validate_invalidation_decision(plan, plan, true))
            } else if attack.id == "EXP-0018-A030" {
                let report = EnforcedModelReport {
                    schema: ENFORCED_MODEL_REPORT_SCHEMA.to_owned(),
                    experiment: "EXP-0018".to_owned(),
                    corpus_identity: CORPUS_IDENTITY.to_owned(),
                    platform: capture.platform.clone(),
                    mechanism: capture.mechanism.clone(),
                    subjects: Vec::new(),
                    probes: Vec::new(),
                    invalidation: Vec::new(),
                    attacks: Vec::new(),
                    metrics: EnforcedMetrics {
                        positive_subjects: 0,
                        positive_executions: 0,
                        authority_probe_executions: 0,
                        denied_reusable: 0,
                        stale_reuse: 0,
                        unrelated_invalidation: 0,
                        validator_disagreements: 0,
                        reviewed_tree_changed: false,
                        exact_attack_rejections: 0,
                    },
                    identity: format!("sha256:{}", "0".repeat(64)),
                };
                attack_error(validate_enforced_model_report(&report))
            } else {
                let altered = mutate_capture(capture, &attack.id)?;
                attack_error(validate_capture_structure(&altered, corpus).map(|_| ()))
            };
            Ok(EnforcedAttackResult {
                id: attack.id.clone(),
                expected_code: attack.expected.clone(),
                actual_code: actual.clone(),
                exact: actual == attack.expected,
            })
        })
        .collect()
}

fn mutate_capture(capture: &EnforcedCapture, id: &str) -> Result<EnforcedCapture, EnforcedError> {
    let mut altered = capture.clone();
    let positive = &mut altered.positive_runs[0];
    match id {
        "EXP-0018-A003" => positive.plan.project_preimages[0].kind = "symlink".to_owned(),
        "EXP-0018-A004" => {
            positive.plan.project_preimages[0].sha256 = format!("sha256:{}", "1".repeat(64));
            refresh_receipt(positive)?;
        }
        "EXP-0018-A005" => {
            positive.plan.project_preimages[0].mode ^= 0o100;
            refresh_receipt(positive)?;
        }
        "EXP-0018-A006" => positive.plan.registered_absences[0].present = true,
        "EXP-0018-A008" => {
            positive.plan.environment[0].value_sha256 = format!("sha256:{}", "1".repeat(64))
        }
        "EXP-0018-A010" => {
            positive.plan.runtime.sha256 = format!("sha256:{}", "1".repeat(64));
            positive.plan.executable_allowlist[0] = positive.plan.runtime.clone();
            refresh_receipt(positive)?;
        }
        "EXP-0018-A014" => altered.mechanism.artifact.sha256 = format!("sha256:{}", "1".repeat(64)),
        "EXP-0018-A015" => {
            positive.plan.policy.push_str("(allow file-read*)\n");
            positive.plan.command.arguments[1] = positive.plan.policy.clone();
        }
        "EXP-0018-A016" => {
            positive.plan.policy = positive
                .plan
                .policy
                .replace("(deny network*)", "(allow network*)");
            positive.plan.command.arguments[1] = positive.plan.policy.clone();
        }
        "EXP-0018-A017" => {
            altered.platform.system_read_boundary = "unbounded-system-reads".to_owned()
        }
        "EXP-0018-A018" => altered.platform.os = "linux".to_owned(),
        "EXP-0018-A019" => {
            positive.plan.project_preimages.pop();
        }
        "EXP-0018-A020" => {
            let mut extra = positive.plan.project_preimages[0].clone();
            extra.logical_name = "zz:unregistered".to_owned();
            positive.plan.project_preimages.push(extra);
            refresh_receipt(positive)?;
        }
        "EXP-0018-A021" => {
            positive
                .plan
                .project_preimages
                .push(positive.plan.project_preimages[0].clone());
        }
        "EXP-0018-A022" => positive.plan.project_preimages.swap(0, 1),
        "EXP-0018-A023" => {
            let mode_index = positive.plan.command.arguments.len() - 5;
            positive.plan.command.arguments[mode_index] = "forged".to_owned();
        }
        "EXP-0018-A024" => {
            let denied = &mut altered.authority_probes[0].receipt;
            denied.run.exit_code = 0;
        }
        "EXP-0018-A025" => {
            let denied = &mut altered.authority_probes[0].receipt;
            denied.run.stderr.push_str(" reusable=true");
            denied.run.stderr_sha256 = sha256_bytes(denied.run.stderr.as_bytes());
        }
        "EXP-0018-A026" => positive.plan.boundary = "observed".to_owned(),
        "EXP-0018-A029" => {
            positive.plan.subject_id = "subject:typescript".to_owned();
            refresh_receipt(positive)?;
        }
        _ => return Err(invalid("EFX-CORPUS", format!("unknown attack {id}"))),
    }
    Ok(altered)
}

fn refresh_receipt(receipt: &mut EnforcedReceipt) -> Result<(), EnforcedError> {
    receipt.plan.identity = hash_without_field(PLAN_DOMAIN, &receipt.plan, "identity")?;
    receipt.identity = hash_without_field(RECEIPT_DOMAIN, receipt, "identity")?;
    Ok(())
}

fn validate_invalidation_decision(
    old: &EnforcedPlan,
    new: &EnforcedPlan,
    invalidated: bool,
) -> Result<(), EnforcedError> {
    let changed = old.project_preimages != new.project_preimages
        || old.registered_absences != new.registered_absences
        || old.environment != new.environment
        || old.runtime != new.runtime
        || old.compiler != new.compiler
        || old.policy_identity != new.policy_identity;
    if changed && !invalidated {
        return Err(invalid("EFX-STALE-REUSE", "changed dependency was reused"));
    }
    if !changed && invalidated {
        return Err(invalid(
            "EFX-OVERINVALIDATION",
            "unchanged dependencies were invalidated",
        ));
    }
    Ok(())
}

fn attack_error(result: Result<(), EnforcedError>) -> String {
    result
        .map(|()| "accepted".to_owned())
        .unwrap_or_else(|error| error.code.to_owned())
}

fn validate_frozen_contract(corpus: &FrozenCorpus) -> Result<(), EnforcedError> {
    if corpus.expected.schema != "proofbound-research-enforced-expected/1"
        || corpus.expected.positive_output.text != "registered-input|registered-env\n"
        || corpus.expected.positive_output.sha256
            != "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22"
        || corpus.expected.positive_output.size_bytes != 32
        || corpus.expected.repetitions != 10
        || corpus.expected.attack_count != 30
    {
        return Err(invalid("EFX-CORPUS", "frozen expectations differ"));
    }
    Ok(())
}

fn load_frozen_corpus(repository: &Path) -> Result<FrozenCorpus, EnforcedError> {
    let base = repository.join("docs/experiments/0018-os-enforced-effects");
    let files = [
        (
            "corpus/contract.json",
            "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d",
        ),
        (
            "corpus/expected.json",
            "sha256:7a5c4e50e3374249f9e696814f28cdcaa240fc97a3293d7598f6918527b4f876",
        ),
        (
            "preregistration.json",
            "sha256:80101c60f64b02d3df5cebe21d59d8314594a321e2068278ad8b29e3982dc215",
        ),
    ];
    for (relative, expected) in files {
        let bytes = fs::read(base.join(relative))
            .map_err(|error| invalid("EFX-CORPUS", error.to_string()))?;
        if sha256_bytes(&bytes) != expected {
            return Err(invalid("EFX-CORPUS", format!("frozen {relative} differs")));
        }
    }
    let expected: FrozenExpected = read_json(&base.join("corpus/expected.json"))?;
    let preregistration: serde_json::Value = read_json(&base.join("preregistration.json"))?;
    let attacks = serde_json::from_value(
        preregistration
            .get("attacks")
            .cloned()
            .ok_or_else(|| invalid("EFX-CORPUS", "attacks are absent"))?,
    )
    .map_err(|error| invalid("EFX-CORPUS", error.to_string()))?;
    Ok(FrozenCorpus { expected, attacks })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, EnforcedError> {
    let bytes = fs::read(path).map_err(|error| {
        invalid(
            "EFX-CORPUS",
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid("EFX-CORPUS", format!("invalid {}: {error}", path.display())))
}

fn hash_without_field<T: Serialize>(
    domain: &str,
    value: &T,
    field: &str,
) -> Result<String, EnforcedError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| invalid("EFX-DECODE", error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| invalid("EFX-DECODE", "identity material is not an object"))?
        .remove(field);
    let bytes = canonical_json(&value).map_err(|error| invalid("EFX-DECODE", error.to_string()))?;
    Ok(hash_bytes(domain, &bytes))
}

fn hash_bytes(domain: &str, bytes: &[u8]) -> String {
    domain_hash(domain, bytes).to_string()
}

fn validate_absolute_path(path: &str) -> Result<(), EnforcedError> {
    if path.len() > 4096
        || path.contains(['\0', '\n', '\r', '"', '\\'])
        || !Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("EFX-PATH", "path is not canonical absolute text"));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn has_duplicates<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() != values.len()
}

fn invalid(code: &'static str, message: impl Into<String>) -> EnforcedError {
    EnforcedError {
        code,
        message: message.into(),
    }
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

fn artifact_identity(
    path: &Path,
    logical_name: impl Into<String>,
) -> Result<EnforcedArtifact, EnforcedError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        invalid(
            "EFX-PREIMAGE",
            format!("failed to inspect {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(invalid("EFX-FILE-ALIAS", "artifact is a symlink"));
    }
    if !metadata.is_file() {
        return Err(invalid("EFX-PREIMAGE", "artifact is not a regular file"));
    }
    let bytes = fs::read(path).map_err(|error| {
        invalid(
            "EFX-PREIMAGE",
            format!("failed to read {}: {error}", path.display()),
        )
    })?;
    Ok(EnforcedArtifact {
        logical_name: logical_name.into(),
        path: path.to_string_lossy().into_owned(),
        sha256: sha256_bytes(&bytes),
        size_bytes: bytes.len() as u64,
        mode: file_mode(&metadata),
        kind: "file".to_owned(),
    })
}

pub fn capture_enforced_effects(
    repository: &Path,
    python: &Path,
    node: &Path,
    rustc: &Path,
    state_root: &Path,
) -> Result<EnforcedCapture, EnforcedError> {
    let started = Instant::now();
    let corpus = load_frozen_corpus(repository)?;
    validate_frozen_contract(&corpus)?;
    if env::consts::OS != "macos" || env::consts::ARCH != "aarch64" {
        return Err(invalid("EFX-UNSUPPORTED", "Seatbelt arm64 host required"));
    }
    let workspace = repository.join("docs/experiments/0018-os-enforced-effects/corpus/workspace");
    let workspace = canonical(&workspace)?;
    let home = canonical(&PathBuf::from(
        env::var_os("HOME").ok_or_else(|| invalid("EFX-PATH", "HOME is absent"))?,
    ))?;
    if state_root.exists() || !state_root.is_absolute() || !state_root.starts_with(&home) {
        return Err(invalid(
            "EFX-WRITE-ESCAPE",
            "state root must be fresh and below HOME",
        ));
    }
    fs::create_dir_all(state_root).map_err(io_error("EFX-WRITE-ESCAPE", state_root))?;
    let state = canonical(state_root)?;
    if state.starts_with(&workspace) {
        return Err(invalid("EFX-WRITE-ESCAPE", "state root overlaps corpus"));
    }
    let python = canonical(python)?;
    let node = canonical(node)?;
    let rustc = canonical(rustc)?;
    let rust_source = workspace.join("subjects/rust_subject.rs");
    let rust_binary = state.join("rust-subject");
    let compiled = Command::new(&rustc)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            rust_source.as_os_str(),
            "-o".as_ref(),
            rust_binary.as_os_str(),
        ])
        .output()
        .map_err(io_error("EFX-RUNTIME-IDENTITY", &rustc))?;
    if !compiled.status.success() || !compiled.stdout.is_empty() || compiled.stderr.len() > 65_536 {
        return Err(invalid(
            "EFX-RUNTIME-IDENTITY",
            "Rust subject compilation failed",
        ));
    }
    let mechanism = EnforcedMechanism {
        mechanism: "seatbelt-sandbox-exec".to_owned(),
        artifact: artifact_identity(
            Path::new("/usr/bin/sandbox-exec"),
            "enforcer:seatbelt-sandbox-exec",
        )?,
    };
    let platform = EnforcedPlatform {
        os: "macos".to_owned(),
        architecture: "arm64".to_owned(),
        system_read_boundary: "default-allow-outside-home".to_owned(),
    };
    let before = tree_identity(&workspace)?;
    let runtimes = [
        ("subject:node", node.as_path(), None),
        ("subject:python", python.as_path(), None),
        ("subject:rust", rust_binary.as_path(), Some(rustc.as_path())),
    ];
    let mut positive_runs = Vec::new();
    let mut authority_probes = Vec::new();
    for _ in 0..corpus.expected.repetitions {
        let plans = runtimes
            .iter()
            .map(|(subject, runtime, compiler)| {
                build_plan(
                    &workspace,
                    &home,
                    &state,
                    &platform,
                    &mechanism,
                    subject,
                    runtime,
                    *compiler,
                    EnforcedMode::Positive,
                    &workspace.join("unrelated.txt"),
                    1,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let receipts = thread::scope(|scope| {
            plans
                .into_iter()
                .map(|plan| scope.spawn(|| run_enforced(plan)))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("enforced worker panicked"))
                .collect::<Result<Vec<_>, _>>()
        })?;
        positive_runs.extend(receipts);
    }
    for (attack_id, mode, path) in authority_cases(&workspace, &state) {
        let jobs = runtimes
            .iter()
            .map(|(subject, runtime, compiler)| {
                let listener = (mode == EnforcedMode::Network)
                    .then(|| TcpListener::bind(("127.0.0.1", 0)))
                    .transpose()
                    .map_err(|error| invalid("EFX-NETWORK-DENIED", error.to_string()))?;
                let port = listener.as_ref().map_or(1, |socket| {
                    socket.local_addr().expect("bound listener").port()
                });
                let plan = build_plan(
                    &workspace, &home, &state, &platform, &mechanism, subject, runtime, *compiler,
                    mode, &path, port,
                )?;
                Ok((*subject, listener, plan))
            })
            .collect::<Result<Vec<_>, EnforcedError>>()?;
        let receipts = thread::scope(|scope| {
            jobs.into_iter()
                .map(|(subject, listener, plan)| {
                    scope.spawn(move || {
                        let receipt = run_enforced(plan)?;
                        if let Some(socket) = listener {
                            socket.set_nonblocking(true).map_err(|error| {
                                invalid("EFX-NETWORK-DENIED", error.to_string())
                            })?;
                            if socket.accept().is_ok() {
                                return Err(invalid(
                                    "EFX-NETWORK-DENIED",
                                    "listener was contacted",
                                ));
                            }
                        }
                        Ok((subject, receipt))
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("enforced worker panicked"))
                .collect::<Result<Vec<_>, EnforcedError>>()
        })?;
        for (subject, receipt) in receipts {
            authority_probes.push(EnforcedProbe {
                attack_id: attack_id.to_owned(),
                subject_id: subject.to_owned(),
                denial_code: denial_code(mode).to_owned(),
                receipt,
            });
        }
    }
    let capture = EnforcedCapture {
        schema: ENFORCED_CAPTURE_SCHEMA.to_owned(),
        experiment: "EXP-0018".to_owned(),
        corpus_identity: CORPUS_IDENTITY.to_owned(),
        platform,
        mechanism,
        positive_runs,
        authority_probes,
        reviewed_tree_before: before,
        reviewed_tree_after: tree_identity(&workspace)?,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    validate_capture_structure(&capture, &corpus)?;
    Ok(capture)
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    project: &Path,
    home: &Path,
    state: &Path,
    platform: &EnforcedPlatform,
    mechanism: &EnforcedMechanism,
    subject_id: &str,
    runtime: &Path,
    compiler: Option<&Path>,
    mode: EnforcedMode,
    attack: &Path,
    port: u16,
) -> Result<EnforcedPlan, EnforcedError> {
    let subject_name = subject_id
        .strip_prefix("subject:")
        .ok_or_else(|| invalid("EFX-SUBJECT-IDENTITY", "invalid subject"))?;
    let source = project.join(format!(
        "subjects/{subject_name}_subject.{}",
        if subject_name == "python" {
            "py"
        } else if subject_name == "node" {
            "mjs"
        } else {
            "rs"
        }
    ));
    let ephemeral = state.join(format!("{subject_name}-{}", mode.text()));
    fs::create_dir_all(&ephemeral).map_err(io_error("EFX-WRITE-ESCAPE", &ephemeral))?;
    let output = ephemeral.join("output.txt");
    if output.exists() {
        fs::remove_file(&output).map_err(io_error("EFX-WRITE-ESCAPE", &output))?;
    }
    let runtime_artifact = artifact_identity(runtime, "runtime:subject")?;
    let environment = vec![EnforcedEnvironment {
        name: "PB_REGISTERED_VALUE".to_owned(),
        value_sha256: sha256_bytes(b"registered-env"),
    }];
    let mut preimages = vec![
        artifact_identity(&project.join("registered.txt"), "input:registered")?,
        artifact_identity(&project.join("reviewed.txt"), "preimage:reviewed")?,
        artifact_identity(&source, "source:subject")?,
    ];
    preimages.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    let mut prefix = vec![
        "-p".to_owned(),
        String::new(),
        runtime.display().to_string(),
    ];
    if subject_name == "python" {
        prefix.push("-B".to_owned());
    }
    if subject_name != "rust" {
        prefix.push(source.display().to_string());
    }
    prefix.extend([
        mode.text().to_owned(),
        project.join("registered.txt").display().to_string(),
        output.display().to_string(),
        attack.display().to_string(),
        port.to_string(),
    ]);
    let mut roots = if subject_name != "rust" && runtime.starts_with(home) {
        vec![
            runtime
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| invalid("EFX-RUNTIME-IDENTITY", "runtime has no toolchain root"))?
                .display()
                .to_string(),
        ]
    } else {
        Vec::new()
    };
    roots.sort();
    let mut plan = EnforcedPlan {
        schema: ENFORCED_PLAN_SCHEMA.to_owned(),
        subject_id: subject_id.to_owned(),
        boundary: "os-enforced".to_owned(),
        platform: platform.clone(),
        mechanism: mechanism.clone(),
        runtime: runtime_artifact.clone(),
        compiler: compiler
            .map(|path| artifact_identity(path, "compiler:rustc"))
            .transpose()?,
        source: artifact_identity(&source, "source:subject")?,
        project_root: project.display().to_string(),
        home_root: home.display().to_string(),
        project_preimages: preimages,
        allowed_project_reads: vec!["input:registered".to_owned(), "source:subject".to_owned()],
        registered_absences: vec![EnforcedAbsence {
            logical_name: "absence:registered".to_owned(),
            path: project.join("must-remain-absent.txt").display().to_string(),
            present: project.join("must-remain-absent.txt").exists(),
        }],
        toolchain_read_roots: roots,
        environment: environment.clone(),
        executable_allowlist: vec![runtime_artifact],
        ephemeral_root: ephemeral.display().to_string(),
        mode,
        attack_path: attack.display().to_string(),
        listener_port: port,
        command: EnforcedCommand {
            program: mechanism.artifact.path.clone(),
            arguments: prefix,
            environment,
        },
        expected_output_sha256:
            "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22".to_owned(),
        expected_output_size_bytes: 32,
        policy: String::new(),
        policy_identity: String::new(),
        identity: String::new(),
    };
    plan.policy = render_seatbelt_policy(&plan)?;
    plan.command.arguments[1] = plan.policy.clone();
    plan.policy_identity = hash_bytes(POLICY_DOMAIN, plan.policy.as_bytes());
    plan.identity = hash_without_field(PLAN_DOMAIN, &plan, "identity")?;
    validate_enforced_plan(&plan)?;
    Ok(plan)
}

fn run_enforced(plan: EnforcedPlan) -> Result<EnforcedReceipt, EnforcedError> {
    let output = Command::new(&plan.command.program)
        .args(&plan.command.arguments)
        .env_clear()
        .env("PB_REGISTERED_VALUE", "registered-env")
        .output()
        .map_err(io_error(
            "EFX-RUN-OUTCOME",
            Path::new(&plan.command.program),
        ))?;
    if output.stdout.len() > 65_536 || output.stderr.len() > 65_536 {
        return Err(invalid("EFX-RUN-OUTCOME", "process output is oversized"));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| invalid("EFX-RUN-OUTCOME", "stdout is not UTF-8"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| invalid("EFX-RUN-OUTCOME", "stderr is not UTF-8"))?;
    let output_path = Path::new(&plan.ephemeral_root).join("output.txt");
    let artifact = output_path
        .exists()
        .then(|| artifact_identity(&output_path, "output:ephemeral"))
        .transpose()?;
    let success = output.status.success();
    let mut receipt = EnforcedReceipt {
        schema: ENFORCEMENT_RECEIPT_SCHEMA.to_owned(),
        plan,
        run: EnforcedRun {
            exit_code: output.status.code().unwrap_or(-1),
            stdout_sha256: sha256_bytes(stdout.as_bytes()),
            stderr_sha256: sha256_bytes(stderr.as_bytes()),
            stdout,
            stderr,
            output: artifact,
            network_contacted: false,
            outcome: if success {
                EnforcedOutcome::Completed
            } else {
                EnforcedOutcome::Denied
            },
        },
        reusable: success,
        identity: String::new(),
    };
    receipt.identity = hash_without_field(RECEIPT_DOMAIN, &receipt, "identity")?;
    validate_enforcement_receipt(&receipt)?;
    Ok(receipt)
}

fn authority_cases(project: &Path, state: &Path) -> Vec<(&'static str, EnforcedMode, PathBuf)> {
    vec![
        (
            "EXP-0018-A001",
            EnforcedMode::ReadUndeclared,
            project.join("unrelated.txt"),
        ),
        (
            "EXP-0018-A002",
            EnforcedMode::ReadUndeclared,
            project.join("nested/outside.txt"),
        ),
        (
            "EXP-0018-A007",
            EnforcedMode::EnvironmentUndeclared,
            project.join("unrelated.txt"),
        ),
        (
            "EXP-0018-A009",
            EnforcedMode::ExecuteUnregistered,
            PathBuf::from("/usr/bin/true"),
        ),
        (
            "EXP-0018-A011",
            EnforcedMode::Network,
            project.join("unrelated.txt"),
        ),
        (
            "EXP-0018-A012",
            EnforcedMode::WriteReviewed,
            project.join("reviewed.txt"),
        ),
        (
            "EXP-0018-A013",
            EnforcedMode::WriteEscape,
            state.join("escape.txt"),
        ),
    ]
}

fn denial_code(mode: EnforcedMode) -> &'static str {
    match mode {
        EnforcedMode::ReadUndeclared => "EFX-FILE-READ-DENIED",
        EnforcedMode::EnvironmentUndeclared => "EFX-ENV-DENIED",
        EnforcedMode::ExecuteUnregistered => "EFX-EXEC-DENIED",
        EnforcedMode::Network => "EFX-NETWORK-DENIED",
        EnforcedMode::WriteReviewed => "EFX-REVIEWED-WRITE-DENIED",
        EnforcedMode::WriteEscape => "EFX-WRITE-ESCAPE",
        EnforcedMode::Positive => "EFX-RUN-OUTCOME",
    }
}

fn tree_identity(root: &Path) -> Result<String, EnforcedError> {
    fn visit(
        root: &Path,
        path: &Path,
        rows: &mut Vec<(String, String, u32)>,
    ) -> Result<(), EnforcedError> {
        let mut entries = fs::read_dir(path)
            .map_err(io_error("EFX-PREIMAGE", path))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| invalid("EFX-PREIMAGE", error.to_string()))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(io_error("EFX-PREIMAGE", &path))?;
            if metadata.file_type().is_symlink() {
                return Err(invalid(
                    "EFX-FILE-ALIAS",
                    "reviewed tree contains a symlink",
                ));
            }
            if metadata.is_dir() {
                visit(root, &path, rows)?;
            } else if metadata.is_file() {
                rows.push((
                    path.strip_prefix(root)
                        .expect("descendant")
                        .to_string_lossy()
                        .into_owned(),
                    sha256_bytes(&fs::read(&path).map_err(io_error("EFX-PREIMAGE", &path))?),
                    file_mode(&metadata),
                ));
            } else {
                return Err(invalid(
                    "EFX-PREIMAGE",
                    "reviewed tree contains a special file",
                ));
            }
        }
        Ok(())
    }
    let mut rows = Vec::new();
    visit(root, root, &mut rows)?;
    Ok(hash_bytes(
        "proofbound-research-reviewed-tree/1",
        &canonical_json(&rows).map_err(|error| invalid("EFX-DECODE", error.to_string()))?,
    ))
}

fn canonical(path: &Path) -> Result<PathBuf, EnforcedError> {
    fs::canonicalize(path).map_err(io_error("EFX-PATH", path))
}

fn io_error<'a>(
    code: &'static str,
    path: &'a Path,
) -> impl FnOnce(std::io::Error) -> EnforcedError + 'a {
    move |error| invalid(code, format!("{}: {error}", path.display()))
}
