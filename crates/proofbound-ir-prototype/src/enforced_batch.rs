use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Instant,
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

use crate::{
    ENFORCED_CAPTURE_SCHEMA, ENFORCED_PLAN_SCHEMA, ENFORCEMENT_RECEIPT_SCHEMA, EnforcedAbsence,
    EnforcedArtifact, EnforcedCapture, EnforcedCommand, EnforcedEnvironment, EnforcedMechanism,
    EnforcedMode, EnforcedOutcome, EnforcedPlan, EnforcedPlatform, EnforcedProbe, EnforcedReceipt,
    EnforcedRun, render_seatbelt_policy, validate_enforced_capture, validate_enforced_plan,
    validate_enforcement_receipt,
};

pub const BATCHED_CAPTURE_SCHEMA: &str = "proofbound-research-batched-enforcement-capture/1";
pub const BATCHED_REPORT_SCHEMA: &str = "proofbound-research-batched-enforcement-report/1";

const CORPUS_IDENTITY: &str =
    "sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43";
const POLICY_DOMAIN: &str = "proofbound-research-seatbelt-policy/1";
const PLAN_DOMAIN: &str = "proofbound-research-enforced-plan/1";
const RECEIPT_DOMAIN: &str = "proofbound-research-enforcement-receipt/1";
const REPORT_DOMAIN: &str = "proofbound-research-batched-enforcement-report/1";
const EXPECTED_OUTPUT: &str =
    "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchedError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for BatchedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BatchedError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BatchedSlotKind {
    Positive,
    AuthorityProbe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchedSlot {
    pub slot_id: String,
    pub kind: BatchedSlotKind,
    pub subject_id: String,
    pub repetition: Option<u32>,
    pub attack_id: Option<String>,
    pub expected_denial_code: Option<String>,
    pub receipt: EnforcedReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchedCapture {
    pub schema: String,
    pub experiment: String,
    pub corpus_identity: String,
    pub scheduler: String,
    pub max_in_flight: u32,
    pub platform: EnforcedPlatform,
    pub mechanism: EnforcedMechanism,
    pub slots: Vec<BatchedSlot>,
    pub completed_slots: u32,
    pub reviewed_tree_before: String,
    pub reviewed_tree_after: String,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchedAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchedMetrics {
    pub positive_executions: u32,
    pub authority_probe_executions: u32,
    pub completed_slots: u32,
    pub denied_reusable: u32,
    pub unique_ephemeral_roots: u32,
    pub unique_positive_outputs: u32,
    pub base_attack_rejections: u32,
    pub scheduler_attack_rejections: u32,
    pub stale_reuse: u32,
    pub unrelated_invalidation: u32,
    pub reviewed_tree_changed: bool,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchedReport {
    pub schema: String,
    pub experiment: String,
    pub corpus_identity: String,
    pub scheduler: String,
    pub platform: EnforcedPlatform,
    pub mechanism: EnforcedMechanism,
    pub base_report_identity: String,
    pub slot_identities: Vec<(String, String)>,
    pub base_attacks: Vec<crate::EnforcedAttackResult>,
    pub scheduler_attacks: Vec<BatchedAttackResult>,
    pub metrics: BatchedMetrics,
    pub identity: String,
}

struct SubjectTemplate {
    subject_id: &'static str,
    runtime: EnforcedArtifact,
    compiler: Option<EnforcedArtifact>,
    source: EnforcedArtifact,
    toolchain_read_roots: Vec<String>,
}

struct Job {
    slot_id: String,
    kind: BatchedSlotKind,
    subject_id: String,
    repetition: Option<u32>,
    attack_id: Option<String>,
    expected_denial_code: Option<String>,
    listener: Option<TcpListener>,
    plan: EnforcedPlan,
}

pub fn capture_batched_enforcement(
    repository: &Path,
    python: &Path,
    node: &Path,
    rustc: &Path,
    state_root: &Path,
) -> Result<BatchedCapture, BatchedError> {
    let started = Instant::now();
    if env::consts::OS != "macos" || env::consts::ARCH != "aarch64" {
        return Err(error(
            "BFX-UNSUPPORTED",
            "macOS arm64 Seatbelt host required",
        ));
    }
    let workspace =
        canonical(&repository.join("docs/experiments/0018-os-enforced-effects/corpus/workspace"))?;
    let home = canonical(&PathBuf::from(
        env::var_os("HOME").ok_or_else(|| error("BFX-PATH", "HOME is absent"))?,
    ))?;
    if state_root.exists() || !state_root.is_absolute() || !state_root.starts_with(&home) {
        return Err(error(
            "BFX-EPHEMERAL-ALIAS",
            "state root must be fresh and below HOME",
        ));
    }
    fs::create_dir_all(state_root).map_err(io_error("BFX-EPHEMERAL-ALIAS", state_root))?;
    let state = canonical(state_root)?;
    if state.starts_with(&workspace) {
        return Err(error("BFX-EPHEMERAL-ALIAS", "state overlaps the corpus"));
    }
    let python = canonical(python)?;
    let node = canonical(node)?;
    let rustc = canonical(rustc)?;
    let rust_source = workspace.join("subjects/rust_subject.rs");
    let rust_binary = state.join("rust-subject");
    compile_rust_subject(&rustc, &rust_source, &rust_binary)?;
    let mechanism = EnforcedMechanism {
        mechanism: "seatbelt-sandbox-exec".to_owned(),
        artifact: artifact(
            Path::new("/usr/bin/sandbox-exec"),
            "enforcer:seatbelt-sandbox-exec",
        )?,
    };
    let platform = EnforcedPlatform {
        os: "macos".to_owned(),
        architecture: "arm64".to_owned(),
        system_read_boundary: "default-allow-outside-home".to_owned(),
    };
    let templates = build_templates(&workspace, &home, &python, &node, &rustc, &rust_binary)?;
    let before = tree_identity(&workspace)?;
    let jobs = build_jobs(&workspace, &home, &state, &platform, &mechanism, &templates)?;
    if jobs.len() != 51 {
        return Err(error("BFX-SLOT-MISSING", "scheduler job inventory differs"));
    }
    let slots = thread::scope(|scope| {
        jobs.into_iter()
            .map(|job| scope.spawn(move || execute_job(job)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().expect("batch worker panicked"))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let mut capture = BatchedCapture {
        schema: BATCHED_CAPTURE_SCHEMA.to_owned(),
        experiment: "EXP-0019".to_owned(),
        corpus_identity: CORPUS_IDENTITY.to_owned(),
        scheduler: "concurrent-isolated-processes".to_owned(),
        max_in_flight: 51,
        platform,
        mechanism,
        completed_slots: slots.len() as u32,
        slots,
        reviewed_tree_before: before,
        reviewed_tree_after: tree_identity(&workspace)?,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    capture
        .slots
        .sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    validate_batched_capture(repository, &capture)?;
    Ok(capture)
}

pub fn validate_batched_capture_bytes(
    repository: &Path,
    bytes: &[u8],
) -> Result<BatchedReport, BatchedError> {
    let capture: BatchedCapture = serde_json::from_slice(bytes)
        .map_err(|issue| error("BFX-DECODE", format!("invalid capture: {issue}")))?;
    if canonical_json(&capture).map_err(encoding_error)? != bytes {
        return Err(error("BFX-NONCANONICAL", "capture is not canonical JSON"));
    }
    validate_batched_capture(repository, &capture)
}

pub fn validate_batched_capture(
    repository: &Path,
    capture: &BatchedCapture,
) -> Result<BatchedReport, BatchedError> {
    validate_structure(capture)?;
    let base_capture = base_projection(capture)?;
    let base_report = validate_enforced_capture(repository, &base_capture)
        .map_err(|issue| error(issue.code, issue.message))?;
    let scheduler_attacks = execute_scheduler_attacks(capture)?;
    let positive = capture
        .slots
        .iter()
        .filter(|slot| slot.kind == BatchedSlotKind::Positive)
        .collect::<Vec<_>>();
    let probes = capture
        .slots
        .iter()
        .filter(|slot| slot.kind == BatchedSlotKind::AuthorityProbe)
        .collect::<Vec<_>>();
    let metrics = BatchedMetrics {
        positive_executions: positive.len() as u32,
        authority_probe_executions: probes.len() as u32,
        completed_slots: capture.completed_slots,
        denied_reusable: probes.iter().filter(|slot| slot.receipt.reusable).count() as u32,
        unique_ephemeral_roots: capture
            .slots
            .iter()
            .map(|slot| &slot.receipt.plan.ephemeral_root)
            .collect::<BTreeSet<_>>()
            .len() as u32,
        unique_positive_outputs: positive
            .iter()
            .filter_map(|slot| slot.receipt.run.output.as_ref().map(|item| &item.path))
            .collect::<BTreeSet<_>>()
            .len() as u32,
        base_attack_rejections: base_report.attacks.iter().filter(|item| item.exact).count() as u32,
        scheduler_attack_rejections: scheduler_attacks.iter().filter(|item| item.exact).count()
            as u32,
        stale_reuse: base_report.metrics.stale_reuse as u32,
        unrelated_invalidation: base_report.metrics.unrelated_invalidation as u32,
        reviewed_tree_changed: capture.reviewed_tree_before != capture.reviewed_tree_after,
        elapsed_ms: capture.elapsed_ms,
    };
    if metrics.positive_executions != 30
        || metrics.authority_probe_executions != 21
        || metrics.completed_slots != 51
        || metrics.denied_reusable != 0
        || metrics.unique_ephemeral_roots != 51
        || metrics.unique_positive_outputs != 30
        || metrics.base_attack_rejections != 30
        || metrics.scheduler_attack_rejections != 10
        || metrics.stale_reuse != 0
        || metrics.unrelated_invalidation != 0
        || metrics.reviewed_tree_changed
    {
        return Err(error(
            "BFX-METRICS",
            format!("batch metrics differ: {metrics:?}; scheduler attacks: {scheduler_attacks:?}"),
        ));
    }
    let mut report = BatchedReport {
        schema: BATCHED_REPORT_SCHEMA.to_owned(),
        experiment: "EXP-0019".to_owned(),
        corpus_identity: CORPUS_IDENTITY.to_owned(),
        scheduler: capture.scheduler.clone(),
        platform: capture.platform.clone(),
        mechanism: capture.mechanism.clone(),
        base_report_identity: base_report.identity,
        slot_identities: capture
            .slots
            .iter()
            .map(|slot| (slot.slot_id.clone(), slot.receipt.identity.clone()))
            .collect(),
        base_attacks: base_report.attacks,
        scheduler_attacks,
        metrics,
        identity: String::new(),
    };
    report.identity = hash_without(REPORT_DOMAIN, &report, "identity")?;
    validate_batched_report(&report)?;
    Ok(report)
}

pub fn validate_batched_report(report: &BatchedReport) -> Result<(), BatchedError> {
    if report.schema != BATCHED_REPORT_SCHEMA || report.experiment != "EXP-0019" {
        return Err(error("BFX-SCHEMA", "batch report schema differs"));
    }
    if report.identity != hash_without(REPORT_DOMAIN, report, "identity")? {
        return Err(error(
            "BFX-REPORT-IDENTITY",
            "batch report identity differs",
        ));
    }
    Ok(())
}

fn validate_structure(capture: &BatchedCapture) -> Result<(), BatchedError> {
    if capture.schema != BATCHED_CAPTURE_SCHEMA
        || capture.experiment != "EXP-0019"
        || capture.corpus_identity != CORPUS_IDENTITY
        || capture.scheduler != "concurrent-isolated-processes"
        || capture.max_in_flight != 51
    {
        return Err(error("BFX-SCHEMA", "batch capture identity differs"));
    }
    if capture.completed_slots != capture.slots.len() as u32 {
        return Err(error("BFX-PARTIAL", "batch completion count differs"));
    }
    let actual_ids = capture
        .slots
        .iter()
        .map(|slot| slot.slot_id.clone())
        .collect::<Vec<_>>();
    let unique_ids = actual_ids.iter().collect::<BTreeSet<_>>();
    if unique_ids.len() != actual_ids.len() {
        return Err(error("BFX-SLOT-DUPLICATE", "batch slot is duplicated"));
    }
    let expected = expected_slots();
    if actual_ids.len() < expected.len() {
        return Err(error("BFX-SLOT-MISSING", "batch slot is absent"));
    }
    if actual_ids.len() > expected.len() {
        return Err(error("BFX-SLOT-DUPLICATE", "batch has an extra slot"));
    }
    if actual_ids.iter().cloned().collect::<BTreeSet<_>>()
        != expected.iter().cloned().collect::<BTreeSet<_>>()
    {
        return Err(error("BFX-SLOT-BINDING", "batch slot inventory differs"));
    }
    if actual_ids != expected {
        return Err(error("BFX-NONCANONICAL", "batch slots are not canonical"));
    }
    let roots = capture
        .slots
        .iter()
        .map(|slot| slot.receipt.plan.ephemeral_root.clone())
        .collect::<Vec<_>>();
    if roots.iter().collect::<BTreeSet<_>>().len() != roots.len() {
        return Err(error("BFX-EPHEMERAL-ALIAS", "ephemeral root is shared"));
    }
    let outputs = capture
        .slots
        .iter()
        .filter(|slot| slot.kind == BatchedSlotKind::Positive)
        .filter_map(|slot| {
            slot.receipt
                .run
                .output
                .as_ref()
                .map(|item| item.path.clone())
        })
        .collect::<Vec<_>>();
    if outputs.iter().collect::<BTreeSet<_>>().len() != outputs.len() {
        return Err(error("BFX-OUTPUT-ALIAS", "positive output is shared"));
    }
    if capture.reviewed_tree_before != capture.reviewed_tree_after {
        return Err(error("EFX-REVIEWED-WRITE-DENIED", "reviewed tree changed"));
    }
    for slot in &capture.slots {
        validate_slot_binding(slot)?;
        if slot.receipt.plan.platform != capture.platform
            || slot.receipt.plan.mechanism != capture.mechanism
        {
            return Err(error("BFX-SLOT-BINDING", "slot boundary differs"));
        }
        validate_enforcement_receipt(&slot.receipt)
            .map_err(|issue| error(issue.code, issue.message))?;
    }
    Ok(())
}

fn validate_slot_binding(slot: &BatchedSlot) -> Result<(), BatchedError> {
    if slot.receipt.plan.subject_id != slot.subject_id {
        return Err(error("BFX-SLOT-BINDING", "slot subject differs"));
    }
    match slot.kind {
        BatchedSlotKind::Positive => {
            let repetition = slot
                .repetition
                .ok_or_else(|| error("BFX-SLOT-BINDING", "positive repetition is absent"))?;
            let suffix = subject_suffix(&slot.subject_id)?;
            if slot.slot_id != format!("positive-{repetition:02}-{suffix}")
                || repetition >= 10
                || slot.attack_id.is_some()
                || slot.expected_denial_code.is_some()
                || slot.receipt.plan.mode != EnforcedMode::Positive
            {
                return Err(error("BFX-SLOT-BINDING", "positive slot differs"));
            }
        }
        BatchedSlotKind::AuthorityProbe => {
            let attack = slot
                .attack_id
                .as_deref()
                .ok_or_else(|| error("BFX-SLOT-BINDING", "probe attack is absent"))?;
            let (ordinal, mode, denial) = authority_definition(attack)
                .ok_or_else(|| error("BFX-SLOT-BINDING", "probe attack is unknown"))?;
            let suffix = subject_suffix(&slot.subject_id)?;
            if slot.slot_id != format!("probe-{ordinal:03}-{suffix}")
                || slot.repetition.is_some()
                || slot.expected_denial_code.as_deref() != Some(denial)
                || slot.receipt.plan.mode != mode
            {
                return Err(error("BFX-SLOT-BINDING", "authority slot differs"));
            }
        }
    }
    Ok(())
}

fn base_projection(capture: &BatchedCapture) -> Result<EnforcedCapture, BatchedError> {
    let mut by_subject = BTreeMap::<String, &EnforcedReceipt>::new();
    for slot in capture
        .slots
        .iter()
        .filter(|slot| slot.kind == BatchedSlotKind::Positive)
    {
        by_subject
            .entry(slot.subject_id.clone())
            .or_insert(&slot.receipt);
    }
    let subjects = ["subject:node", "subject:python", "subject:rust"];
    let mut positive_runs = Vec::new();
    for _ in 0..10 {
        for subject in subjects {
            positive_runs.push(
                (*by_subject
                    .get(subject)
                    .ok_or_else(|| error("BFX-SLOT-MISSING", "positive subject is absent"))?)
                .clone(),
            );
        }
    }
    let authority_probes = capture
        .slots
        .iter()
        .filter(|slot| slot.kind == BatchedSlotKind::AuthorityProbe)
        .map(|slot| EnforcedProbe {
            attack_id: slot.attack_id.clone().expect("validated"),
            subject_id: slot.subject_id.clone(),
            denial_code: slot.expected_denial_code.clone().expect("validated"),
            receipt: slot.receipt.clone(),
        })
        .collect();
    Ok(EnforcedCapture {
        schema: ENFORCED_CAPTURE_SCHEMA.to_owned(),
        experiment: "EXP-0018".to_owned(),
        corpus_identity: CORPUS_IDENTITY.to_owned(),
        platform: capture.platform.clone(),
        mechanism: capture.mechanism.clone(),
        positive_runs,
        authority_probes,
        reviewed_tree_before: capture.reviewed_tree_before.clone(),
        reviewed_tree_after: capture.reviewed_tree_after.clone(),
        elapsed_ms: capture.elapsed_ms,
    })
}

fn execute_scheduler_attacks(
    capture: &BatchedCapture,
) -> Result<Vec<BatchedAttackResult>, BatchedError> {
    const ATTACKS: [(&str, &str); 10] = [
        ("EXP-0019-A031", "BFX-SLOT-MISSING"),
        ("EXP-0019-A032", "BFX-SLOT-DUPLICATE"),
        ("EXP-0019-A033", "BFX-NONCANONICAL"),
        ("EXP-0019-A034", "BFX-SLOT-BINDING"),
        ("EXP-0019-A035", "BFX-EPHEMERAL-ALIAS"),
        ("EXP-0019-A036", "BFX-OUTPUT-ALIAS"),
        ("EXP-0019-A037", "BFX-PARTIAL"),
        ("EXP-0019-A038", "EFX-POLICY-IDENTITY"),
        ("EXP-0019-A039", "EFX-RUN-OUTCOME"),
        ("EXP-0019-A040", "BFX-REPORT-IDENTITY"),
    ];
    ATTACKS
        .into_iter()
        .map(|(id, expected)| {
            let actual = if id == "EXP-0019-A040" {
                let report = empty_forged_report(capture);
                rejection_code(validate_batched_report(&report))
            } else {
                let altered = mutate_capture(capture, id)?;
                rejection_code(validate_structure(&altered))
            };
            Ok(BatchedAttackResult {
                id: id.to_owned(),
                expected_code: expected.to_owned(),
                actual_code: actual.clone(),
                exact: actual == expected,
            })
        })
        .collect()
}

fn mutate_capture(capture: &BatchedCapture, id: &str) -> Result<BatchedCapture, BatchedError> {
    let mut altered = capture.clone();
    match id {
        "EXP-0019-A031" => {
            altered.slots.pop();
            altered.completed_slots -= 1;
        }
        "EXP-0019-A032" => {
            altered.slots.push(altered.slots[0].clone());
            altered.completed_slots += 1;
        }
        "EXP-0019-A033" => altered.slots.swap(0, 1),
        "EXP-0019-A034" => {
            let first = altered.slots[0].receipt.clone();
            altered.slots[0].receipt = altered.slots[1].receipt.clone();
            altered.slots[1].receipt = first;
        }
        "EXP-0019-A035" => {
            altered.slots[1].receipt.plan.ephemeral_root =
                altered.slots[0].receipt.plan.ephemeral_root.clone();
        }
        "EXP-0019-A036" => {
            let path = altered.slots[0]
                .receipt
                .run
                .output
                .as_ref()
                .expect("positive output")
                .path
                .clone();
            altered.slots[1]
                .receipt
                .run
                .output
                .as_mut()
                .expect("positive output")
                .path = path;
        }
        "EXP-0019-A037" => altered.completed_slots -= 1,
        "EXP-0019-A038" => {
            altered.slots[0]
                .receipt
                .plan
                .policy
                .push_str("(allow file-read*)\n");
            let policy = altered.slots[0].receipt.plan.policy.clone();
            altered.slots[0].receipt.plan.command.arguments[1] = policy;
        }
        "EXP-0019-A039" => {
            let probe = altered
                .slots
                .iter_mut()
                .find(|slot| slot.kind == BatchedSlotKind::AuthorityProbe)
                .expect("probe");
            probe.receipt.reusable = true;
        }
        _ => return Err(error("BFX-CORPUS", format!("unknown attack {id}"))),
    }
    Ok(altered)
}

fn empty_forged_report(capture: &BatchedCapture) -> BatchedReport {
    BatchedReport {
        schema: BATCHED_REPORT_SCHEMA.to_owned(),
        experiment: "EXP-0019".to_owned(),
        corpus_identity: CORPUS_IDENTITY.to_owned(),
        scheduler: capture.scheduler.clone(),
        platform: capture.platform.clone(),
        mechanism: capture.mechanism.clone(),
        base_report_identity: format!("sha256:{}", "0".repeat(64)),
        slot_identities: Vec::new(),
        base_attacks: Vec::new(),
        scheduler_attacks: Vec::new(),
        metrics: BatchedMetrics {
            positive_executions: 0,
            authority_probe_executions: 0,
            completed_slots: 0,
            denied_reusable: 0,
            unique_ephemeral_roots: 0,
            unique_positive_outputs: 0,
            base_attack_rejections: 0,
            scheduler_attack_rejections: 0,
            stale_reuse: 0,
            unrelated_invalidation: 0,
            reviewed_tree_changed: false,
            elapsed_ms: 0,
        },
        identity: format!("sha256:{}", "0".repeat(64)),
    }
}

fn build_templates(
    workspace: &Path,
    home: &Path,
    python: &Path,
    node: &Path,
    rustc: &Path,
    rust_binary: &Path,
) -> Result<Vec<SubjectTemplate>, BatchedError> {
    [
        ("subject:node", node, None, "node_subject.mjs"),
        ("subject:python", python, None, "python_subject.py"),
        ("subject:rust", rust_binary, Some(rustc), "rust_subject.rs"),
    ]
    .into_iter()
    .map(|(subject_id, runtime, compiler, source)| {
        let toolchain_read_roots = if subject_id != "subject:rust" && runtime.starts_with(home) {
            vec![
                runtime
                    .parent()
                    .and_then(Path::parent)
                    .ok_or_else(|| error("BFX-RUNTIME", "runtime has no toolchain root"))?
                    .display()
                    .to_string(),
            ]
        } else {
            Vec::new()
        };
        Ok(SubjectTemplate {
            subject_id,
            runtime: artifact(runtime, "runtime:subject")?,
            compiler: compiler
                .map(|path| artifact(path, "compiler:rustc"))
                .transpose()?,
            source: artifact(&workspace.join("subjects").join(source), "source:subject")?,
            toolchain_read_roots,
        })
    })
    .collect()
}

fn build_jobs(
    workspace: &Path,
    home: &Path,
    state: &Path,
    platform: &EnforcedPlatform,
    mechanism: &EnforcedMechanism,
    templates: &[SubjectTemplate],
) -> Result<Vec<Job>, BatchedError> {
    let mut jobs = Vec::new();
    for repetition in 0..10 {
        for template in templates {
            let suffix = subject_suffix(template.subject_id)?;
            let slot_id = format!("positive-{repetition:02}-{suffix}");
            jobs.push(Job {
                plan: build_plan(
                    workspace,
                    home,
                    state,
                    platform,
                    mechanism,
                    template,
                    EnforcedMode::Positive,
                    &workspace.join("unrelated.txt"),
                    1,
                    &slot_id,
                )?,
                slot_id,
                kind: BatchedSlotKind::Positive,
                subject_id: template.subject_id.to_owned(),
                repetition: Some(repetition),
                attack_id: None,
                expected_denial_code: None,
                listener: None,
            });
        }
    }
    for (ordinal, attack_id, mode, attack_path, denial) in authority_cases(workspace, state) {
        for template in templates {
            let listener = (mode == EnforcedMode::Network)
                .then(|| TcpListener::bind(("127.0.0.1", 0)))
                .transpose()
                .map_err(|issue| error("EFX-NETWORK-DENIED", issue.to_string()))?;
            let port = listener.as_ref().map_or(1, |socket| {
                socket.local_addr().expect("listener address").port()
            });
            let suffix = subject_suffix(template.subject_id)?;
            let slot_id = format!("probe-{ordinal:03}-{suffix}");
            jobs.push(Job {
                plan: build_plan(
                    workspace,
                    home,
                    state,
                    platform,
                    mechanism,
                    template,
                    mode,
                    &attack_path,
                    port,
                    &slot_id,
                )?,
                slot_id,
                kind: BatchedSlotKind::AuthorityProbe,
                subject_id: template.subject_id.to_owned(),
                repetition: None,
                attack_id: Some(attack_id.to_owned()),
                expected_denial_code: Some(denial.to_owned()),
                listener,
            });
        }
    }
    Ok(jobs)
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    project: &Path,
    home: &Path,
    state: &Path,
    platform: &EnforcedPlatform,
    mechanism: &EnforcedMechanism,
    template: &SubjectTemplate,
    mode: EnforcedMode,
    attack_path: &Path,
    listener_port: u16,
    slot_id: &str,
) -> Result<EnforcedPlan, BatchedError> {
    let ephemeral = state.join("slots").join(slot_id);
    fs::create_dir_all(&ephemeral).map_err(io_error("BFX-EPHEMERAL-ALIAS", &ephemeral))?;
    let output = ephemeral.join("output.txt");
    let mut preimages = vec![
        artifact(&project.join("registered.txt"), "input:registered")?,
        artifact(&project.join("reviewed.txt"), "preimage:reviewed")?,
        template.source.clone(),
    ];
    preimages.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    let environment = vec![EnforcedEnvironment {
        name: "PB_REGISTERED_VALUE".to_owned(),
        value_sha256: sha256_bytes(b"registered-env"),
    }];
    let mut arguments = vec![
        "-p".to_owned(),
        String::new(),
        template.runtime.path.clone(),
    ];
    if template.subject_id == "subject:python" {
        arguments.push("-B".to_owned());
    }
    if template.subject_id != "subject:rust" {
        arguments.push(template.source.path.clone());
    }
    arguments.extend([
        mode_text(mode).to_owned(),
        project.join("registered.txt").display().to_string(),
        output.display().to_string(),
        attack_path.display().to_string(),
        listener_port.to_string(),
    ]);
    let mut plan = EnforcedPlan {
        schema: ENFORCED_PLAN_SCHEMA.to_owned(),
        subject_id: template.subject_id.to_owned(),
        boundary: "os-enforced".to_owned(),
        platform: platform.clone(),
        mechanism: mechanism.clone(),
        runtime: template.runtime.clone(),
        compiler: template.compiler.clone(),
        source: template.source.clone(),
        project_root: project.display().to_string(),
        home_root: home.display().to_string(),
        project_preimages: preimages,
        allowed_project_reads: vec!["input:registered".to_owned(), "source:subject".to_owned()],
        registered_absences: vec![EnforcedAbsence {
            logical_name: "absence:registered".to_owned(),
            path: project.join("must-remain-absent.txt").display().to_string(),
            present: project.join("must-remain-absent.txt").exists(),
        }],
        toolchain_read_roots: template.toolchain_read_roots.clone(),
        environment: environment.clone(),
        executable_allowlist: vec![template.runtime.clone()],
        ephemeral_root: ephemeral.display().to_string(),
        mode,
        attack_path: attack_path.display().to_string(),
        listener_port,
        command: EnforcedCommand {
            program: mechanism.artifact.path.clone(),
            arguments,
            environment,
        },
        expected_output_sha256: EXPECTED_OUTPUT.to_owned(),
        expected_output_size_bytes: 32,
        policy: String::new(),
        policy_identity: String::new(),
        identity: String::new(),
    };
    plan.policy = render_seatbelt_policy(&plan).map_err(from_enforced)?;
    plan.command.arguments[1] = plan.policy.clone();
    plan.policy_identity = domain_hash(POLICY_DOMAIN, plan.policy.as_bytes()).to_string();
    plan.identity = hash_without(PLAN_DOMAIN, &plan, "identity")?;
    validate_enforced_plan(&plan).map_err(from_enforced)?;
    Ok(plan)
}

fn execute_job(job: Job) -> Result<BatchedSlot, BatchedError> {
    let receipt = run_plan(job.plan)?;
    if let Some(listener) = job.listener {
        listener
            .set_nonblocking(true)
            .map_err(|issue| error("EFX-NETWORK-DENIED", issue.to_string()))?;
        if listener.accept().is_ok() {
            return Err(error("EFX-NETWORK-DENIED", "listener was contacted"));
        }
    }
    Ok(BatchedSlot {
        slot_id: job.slot_id,
        kind: job.kind,
        subject_id: job.subject_id,
        repetition: job.repetition,
        attack_id: job.attack_id,
        expected_denial_code: job.expected_denial_code,
        receipt,
    })
}

fn run_plan(plan: EnforcedPlan) -> Result<EnforcedReceipt, BatchedError> {
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
        return Err(error("EFX-RUN-OUTCOME", "process output is oversized"));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| error("EFX-RUN-OUTCOME", "stdout is not UTF-8"))?;
    let stderr = String::from_utf8(output.stderr)
        .map_err(|_| error("EFX-RUN-OUTCOME", "stderr is not UTF-8"))?;
    let output_path = Path::new(&plan.ephemeral_root).join("output.txt");
    let output_artifact = output_path
        .exists()
        .then(|| artifact(&output_path, "output:ephemeral"))
        .transpose()?;
    let completed = output.status.success();
    let mut receipt = EnforcedReceipt {
        schema: ENFORCEMENT_RECEIPT_SCHEMA.to_owned(),
        plan,
        run: EnforcedRun {
            exit_code: output.status.code().unwrap_or(-1),
            stdout_sha256: sha256_bytes(stdout.as_bytes()),
            stderr_sha256: sha256_bytes(stderr.as_bytes()),
            stdout,
            stderr,
            output: output_artifact,
            network_contacted: false,
            outcome: if completed {
                EnforcedOutcome::Completed
            } else {
                EnforcedOutcome::Denied
            },
        },
        reusable: completed,
        identity: String::new(),
    };
    receipt.identity = hash_without(RECEIPT_DOMAIN, &receipt, "identity")?;
    validate_enforcement_receipt(&receipt).map_err(from_enforced)?;
    Ok(receipt)
}

fn compile_rust_subject(rustc: &Path, source: &Path, output: &Path) -> Result<(), BatchedError> {
    let result = Command::new(rustc)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([source.as_os_str(), "-o".as_ref(), output.as_os_str()])
        .output()
        .map_err(io_error("BFX-RUNTIME", rustc))?;
    if !result.status.success() || !result.stdout.is_empty() || result.stderr.len() > 65_536 {
        return Err(error("BFX-RUNTIME", "Rust subject compilation failed"));
    }
    Ok(())
}

fn expected_slots() -> Vec<String> {
    let mut slots = Vec::new();
    for repetition in 0..10 {
        for subject in ["node", "python", "rust"] {
            slots.push(format!("positive-{repetition:02}-{subject}"));
        }
    }
    for ordinal in [1, 2, 7, 9, 11, 12, 13] {
        for subject in ["node", "python", "rust"] {
            slots.push(format!("probe-{ordinal:03}-{subject}"));
        }
    }
    slots.sort();
    slots
}

fn authority_cases(
    project: &Path,
    state: &Path,
) -> Vec<(u32, &'static str, EnforcedMode, PathBuf, &'static str)> {
    vec![
        (
            1,
            "EXP-0018-A001",
            EnforcedMode::ReadUndeclared,
            project.join("unrelated.txt"),
            "EFX-FILE-READ-DENIED",
        ),
        (
            2,
            "EXP-0018-A002",
            EnforcedMode::ReadUndeclared,
            project.join("nested/outside.txt"),
            "EFX-FILE-READ-DENIED",
        ),
        (
            7,
            "EXP-0018-A007",
            EnforcedMode::EnvironmentUndeclared,
            project.join("unrelated.txt"),
            "EFX-ENV-DENIED",
        ),
        (
            9,
            "EXP-0018-A009",
            EnforcedMode::ExecuteUnregistered,
            PathBuf::from("/usr/bin/true"),
            "EFX-EXEC-DENIED",
        ),
        (
            11,
            "EXP-0018-A011",
            EnforcedMode::Network,
            project.join("unrelated.txt"),
            "EFX-NETWORK-DENIED",
        ),
        (
            12,
            "EXP-0018-A012",
            EnforcedMode::WriteReviewed,
            project.join("reviewed.txt"),
            "EFX-REVIEWED-WRITE-DENIED",
        ),
        (
            13,
            "EXP-0018-A013",
            EnforcedMode::WriteEscape,
            state.join("escape.txt"),
            "EFX-WRITE-ESCAPE",
        ),
    ]
}

fn authority_definition(id: &str) -> Option<(u32, EnforcedMode, &'static str)> {
    match id {
        "EXP-0018-A001" => Some((1, EnforcedMode::ReadUndeclared, "EFX-FILE-READ-DENIED")),
        "EXP-0018-A002" => Some((2, EnforcedMode::ReadUndeclared, "EFX-FILE-READ-DENIED")),
        "EXP-0018-A007" => Some((7, EnforcedMode::EnvironmentUndeclared, "EFX-ENV-DENIED")),
        "EXP-0018-A009" => Some((9, EnforcedMode::ExecuteUnregistered, "EFX-EXEC-DENIED")),
        "EXP-0018-A011" => Some((11, EnforcedMode::Network, "EFX-NETWORK-DENIED")),
        "EXP-0018-A012" => Some((12, EnforcedMode::WriteReviewed, "EFX-REVIEWED-WRITE-DENIED")),
        "EXP-0018-A013" => Some((13, EnforcedMode::WriteEscape, "EFX-WRITE-ESCAPE")),
        _ => None,
    }
}

fn mode_text(mode: EnforcedMode) -> &'static str {
    match mode {
        EnforcedMode::Positive => "positive",
        EnforcedMode::ReadUndeclared => "read-undeclared",
        EnforcedMode::EnvironmentUndeclared => "env-undeclared",
        EnforcedMode::ExecuteUnregistered => "exec-unregistered",
        EnforcedMode::Network => "network",
        EnforcedMode::WriteReviewed => "write-reviewed",
        EnforcedMode::WriteEscape => "write-escape",
    }
}

fn subject_suffix(subject: &str) -> Result<&str, BatchedError> {
    subject
        .strip_prefix("subject:")
        .filter(|suffix| ["node", "python", "rust"].contains(suffix))
        .ok_or_else(|| error("BFX-SLOT-BINDING", "subject is unknown"))
}

fn artifact(path: &Path, logical_name: &str) -> Result<EnforcedArtifact, BatchedError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error("BFX-PREIMAGE", path))?;
    if metadata.file_type().is_symlink() {
        return Err(error("EFX-FILE-ALIAS", "artifact is a symlink"));
    }
    if !metadata.is_file() {
        return Err(error("BFX-PREIMAGE", "artifact is not a regular file"));
    }
    let bytes = fs::read(path).map_err(io_error("BFX-PREIMAGE", path))?;
    Ok(EnforcedArtifact {
        logical_name: logical_name.to_owned(),
        path: path.display().to_string(),
        sha256: sha256_bytes(&bytes),
        size_bytes: bytes.len() as u64,
        mode: file_mode(&metadata),
        kind: "file".to_owned(),
    })
}

fn tree_identity(root: &Path) -> Result<String, BatchedError> {
    fn visit(
        root: &Path,
        path: &Path,
        rows: &mut Vec<(String, String, u32)>,
    ) -> Result<(), BatchedError> {
        let mut entries = fs::read_dir(path)
            .map_err(io_error("BFX-PREIMAGE", path))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|issue| error("BFX-PREIMAGE", issue.to_string()))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(io_error("BFX-PREIMAGE", &path))?;
            if metadata.file_type().is_symlink() {
                return Err(error("EFX-FILE-ALIAS", "reviewed tree contains a symlink"));
            }
            if metadata.is_dir() {
                visit(root, &path, rows)?;
            } else if metadata.is_file() {
                rows.push((
                    path.strip_prefix(root)
                        .expect("descendant")
                        .display()
                        .to_string(),
                    sha256_bytes(&fs::read(&path).map_err(io_error("BFX-PREIMAGE", &path))?),
                    file_mode(&metadata),
                ));
            } else {
                return Err(error("BFX-PREIMAGE", "reviewed tree has a special file"));
            }
        }
        Ok(())
    }
    let mut rows = Vec::new();
    visit(root, root, &mut rows)?;
    Ok(domain_hash(
        "proofbound-research-reviewed-tree/1",
        &canonical_json(&rows).map_err(encoding_error)?,
    )
    .to_string())
}

fn hash_without<T: Serialize>(
    domain: &str,
    value: &T,
    field: &str,
) -> Result<String, BatchedError> {
    let mut value = serde_json::to_value(value).map_err(encoding_error)?;
    value
        .as_object_mut()
        .ok_or_else(|| error("BFX-DECODE", "identity material is not an object"))?
        .remove(field);
    Ok(domain_hash(domain, &canonical_json(&value).map_err(encoding_error)?).to_string())
}

fn rejection_code<T>(result: Result<T, BatchedError>) -> String {
    match result {
        Ok(_) => "ACCEPTED".to_owned(),
        Err(issue) => issue.code.to_owned(),
    }
}

fn canonical(path: &Path) -> Result<PathBuf, BatchedError> {
    fs::canonicalize(path).map_err(io_error("BFX-PATH", path))
}

fn error(code: &'static str, message: impl Into<String>) -> BatchedError {
    BatchedError {
        code,
        message: message.into(),
    }
}

fn from_enforced(issue: crate::EnforcedError) -> BatchedError {
    error(issue.code, issue.message)
}

fn encoding_error(issue: impl fmt::Display) -> BatchedError {
    error("BFX-DECODE", issue.to_string())
}

fn io_error<'a>(
    code: &'static str,
    path: &'a Path,
) -> impl FnOnce(std::io::Error) -> BatchedError + 'a {
    move |issue| error(code, format!("{}: {issue}", path.display()))
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
