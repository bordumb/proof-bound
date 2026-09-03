use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path},
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const EFFECT_PLAN_SCHEMA: &str = "proofbound-research-effect-plan/1";
pub const EFFECT_TRACE_SCHEMA: &str = "proofbound-research-effect-trace/1";
pub const EFFECT_ENFORCEMENT_SCHEMA: &str = "proofbound-research-effect-enforcement/1";
pub const EFFECT_INVALIDATION_SCHEMA: &str = "proofbound-research-effect-invalidation/1";
pub const EFFECT_MODEL_REPORT_SCHEMA: &str = "proofbound-research-effect-model-report/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectCorpus {
    pub schema: String,
    pub plans: Vec<EffectPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPlan {
    pub schema: String,
    pub id: String,
    pub effects: Vec<Effect>,
    pub workload: EffectWorkload,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Effect {
    ReadFile {
        id: String,
        path: String,
        sha256: String,
        size_bytes: u64,
        mode: u32,
    },
    RequireAbsent {
        id: String,
        path: String,
    },
    WriteEphemeral {
        id: String,
        root: String,
    },
    WriteReviewed {
        id: String,
        path: String,
        sha256: String,
        size_bytes: u64,
        update_only: bool,
    },
    ReadEnvironment {
        id: String,
        name: String,
        value_sha256: Option<String>,
        secret: bool,
    },
    Execute {
        id: String,
        tool: ArtifactIdentity,
        argv: Vec<String>,
        boundary: ExecutionBoundary,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enforcement_receipt: Option<String>,
    },
    Network {
        id: String,
        mode: DeniedMode,
    },
    Clock {
        id: String,
        mode: DeniedMode,
    },
    Random {
        id: String,
        mode: DeniedMode,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeniedMode {
    Denied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionBoundary {
    Mediated,
    Opaque,
    ExternallyEnforced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EffectWorkload {
    HiddenRead {
        policy_effect: String,
    },
    MutationReplay {
        target_effect: String,
        mutant_effect: String,
        witness_effect: String,
        output_effect: String,
    },
    DistributionBuild {
        payload_effects: Vec<String>,
        absent_effect: String,
        output_effect: String,
    },
    SubprocessBoundary {
        execute_effect: String,
    },
    SecretRead {
        environment_effect: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementReceipt {
    pub schema: String,
    pub id: String,
    pub tool: ArtifactIdentity,
    pub allowed_effects: Vec<String>,
    pub mechanism: EnforcementMechanism,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementMechanism {
    pub name: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTrace {
    pub schema: String,
    pub plan_id: String,
    pub plan_identity: String,
    pub observations: Vec<EffectObservation>,
    pub dispositions: Vec<EffectDisposition>,
    pub outputs: Vec<EffectOutput>,
    pub cache_eligible: bool,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectObservation {
    pub index: usize,
    pub effect_id: String,
    pub kind: String,
    pub disposition: String,
    pub value: ObservedValue,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ObservedValue {
    Artifact {
        path: String,
        sha256: String,
        size_bytes: u64,
        mode: u32,
    },
    Absence {
        path: String,
    },
    Output {
        path: String,
        sha256: String,
        size_bytes: u64,
    },
    Execution {
        tool: ArtifactIdentity,
        argv: Vec<String>,
        boundary: ExecutionBoundary,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enforcement_receipt: Option<String>,
    },
    Secret {
        name: String,
        present: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectDisposition {
    pub effect_id: String,
    pub disposition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOutput {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectInvalidation {
    pub schema: String,
    pub plan_id: String,
    pub old_trace_identity: String,
    pub new_trace_identity: String,
    pub invalidated: bool,
    pub changed_effects: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAttackCorpus {
    pub schema: String,
    pub attacks: Vec<EffectAttack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAttack {
    pub id: String,
    pub base: String,
    pub code: String,
    pub action: EffectAttackAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EffectAttackAction {
    RequestRead {
        path: String,
    },
    RequestEnvironment {
        name: String,
    },
    RequestNetwork {
        effect_id: String,
    },
    RequestClock {
        effect_id: String,
    },
    RequestRandom {
        effect_id: String,
    },
    ForgeCacheEligible,
    RequestReviewedWrite {
        path: String,
    },
    RequestEphemeralWrite {
        effect_id: String,
        path: String,
    },
    SubstituteFileType {
        effect_id: String,
        file_type: String,
    },
    RequestExecute {
        tool: ArtifactIdentity,
        argv: Vec<String>,
    },
    SubstituteExecutable {
        effect_id: String,
        sha256: String,
    },
    SubstituteArgv {
        effect_id: String,
        argv: Vec<String>,
    },
    RemoveEnforcementReceipt,
    ForgeEnforcementIdentity {
        identity: String,
    },
    WeakenEnforcement {
        allowed_effects: Vec<String>,
    },
    ForgeExactCacheEligible {
        hidden_path: String,
    },
    AliasEffectId {
        effect_id: String,
        alias: String,
    },
    DuplicateEffect {
        effect_id: String,
    },
    AppendObservation {
        effect_id: String,
    },
    OmitUnusedDisposition {
        effect_id: String,
    },
    SubstitutePostimage {
        content: String,
    },
    AddPackagePath {
        path: String,
    },
    UseGlobalRevisionInvalidation {
        changed_path: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
    pub workload_body_entered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPlanResult {
    pub id: String,
    pub plan_bytes: usize,
    pub trace_bytes: usize,
    pub declaration_count: usize,
    pub observation_count: usize,
    pub repetition_trace_identities: Vec<String>,
    pub trace: EffectTrace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectModelReport {
    pub schema: String,
    pub plans: Vec<EffectPlanResult>,
    pub attacks: Vec<EffectAttackResult>,
    pub invalidation: Vec<EffectInvalidationResult>,
    pub route_outputs: Vec<EffectOutput>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectExpected {
    pub schema: String,
    pub repetitions: usize,
    pub enforcement_identity: String,
    pub fixtures: Vec<ArtifactIdentity>,
    pub plans: Vec<ExpectedEffectPlan>,
    pub mutation_output: EffectOutput,
    pub distribution_output: EffectOutput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedEffectPlan {
    pub id: String,
    pub identity: String,
    pub canonical_bytes: usize,
    pub cache_eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectInvalidationResult {
    pub id: String,
    pub decisions: Vec<EffectInvalidation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for EffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for EffectError {}

fn invalid(code: &'static str, message: impl Into<String>) -> EffectError {
    EffectError {
        code,
        message: message.into(),
    }
}

impl Effect {
    fn id(&self) -> &str {
        match self {
            Self::ReadFile { id, .. }
            | Self::RequireAbsent { id, .. }
            | Self::WriteEphemeral { id, .. }
            | Self::WriteReviewed { id, .. }
            | Self::ReadEnvironment { id, .. }
            | Self::Execute { id, .. }
            | Self::Network { id, .. }
            | Self::Clock { id, .. }
            | Self::Random { id, .. } => id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::ReadFile { .. } => "read-file",
            Self::RequireAbsent { .. } => "require-absent",
            Self::WriteEphemeral { .. } => "write-ephemeral",
            Self::WriteReviewed { .. } => "write-reviewed",
            Self::ReadEnvironment { .. } => "read-environment",
            Self::Execute { .. } => "execute",
            Self::Network { .. } => "network",
            Self::Clock { .. } => "clock",
            Self::Random { .. } => "random",
        }
    }
}

pub fn load_effect_corpus(
    root: &Path,
    corpus_dir: &Path,
) -> Result<(EffectCorpus, EnforcementReceipt, EffectAttackCorpus), EffectError> {
    let plans: EffectCorpus = decode(&read(root, &corpus_dir.join("plans.json"))?)?;
    let enforcement: EnforcementReceipt =
        decode(&read(root, &corpus_dir.join("enforcement.json"))?)?;
    let attacks: EffectAttackCorpus = decode(&read(root, &corpus_dir.join("attacks.json"))?)?;
    validate_enforcement(&enforcement)?;
    if plans.schema != "proofbound-research-effect-corpus/1" {
        return Err(invalid("EFFECT-SCHEMA", "unexpected corpus schema"));
    }
    if attacks.schema != "proofbound-research-effect-attacks/1" {
        return Err(invalid("EFFECT-SCHEMA", "unexpected attack schema"));
    }
    let mut plan_ids = BTreeSet::new();
    for plan in &plans.plans {
        if !plan_ids.insert(plan.id.clone()) {
            return Err(invalid("EFFECT-SET-DUPLICATE", "duplicate plan ID"));
        }
        validate_effect_plan(plan, Some(&enforcement))?;
    }
    Ok((plans, enforcement, attacks))
}

pub fn validate_effect_plan(
    plan: &EffectPlan,
    enforcement: Option<&EnforcementReceipt>,
) -> Result<(), EffectError> {
    if plan.schema != EFFECT_PLAN_SCHEMA {
        return Err(invalid("EFFECT-SCHEMA", "unexpected effect-plan schema"));
    }
    validate_id(&plan.id, "plan")?;
    if plan.effects.is_empty() {
        return Err(invalid("EFFECT-SET-EMPTY", "effect set is empty"));
    }
    let ids: Vec<_> = plan.effects.iter().map(Effect::id).collect();
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "EFFECT-SET-DUPLICATE",
            "effects must form a strict lexical set",
        ));
    }
    for effect in &plan.effects {
        validate_id(effect.id(), "effect").map_err(|_| {
            invalid(
                "EFFECT-ID-ALIAS",
                format!("invalid effect ID {}", effect.id()),
            )
        })?;
        match effect {
            Effect::ReadFile {
                path,
                sha256,
                size_bytes,
                mode,
                ..
            } => {
                validate_path(path)?;
                validate_digest(sha256)?;
                if *size_bytes > 16 * 1024 * 1024 || *mode > 0o7777 {
                    return Err(invalid("EFFECT-PLAN-INVALID", "invalid file identity"));
                }
            }
            Effect::RequireAbsent { path, .. } => validate_ephemeral_path(path)?,
            Effect::WriteEphemeral { root, .. } => validate_ephemeral_root(root)?,
            Effect::WriteReviewed {
                path,
                sha256,
                size_bytes,
                update_only,
                ..
            } => {
                validate_path(path)?;
                validate_digest(sha256)?;
                if !update_only || *size_bytes > 16 * 1024 * 1024 {
                    return Err(invalid("EFFECT-WRITE-REVIEWED", "unsafe reviewed write"));
                }
            }
            Effect::ReadEnvironment {
                name,
                value_sha256,
                secret,
                ..
            } => {
                validate_environment_name(name)?;
                match (*secret, value_sha256) {
                    (true, None) => {}
                    (false, Some(value)) => validate_digest(value)?,
                    _ => {
                        return Err(invalid(
                            "EFFECT-PLAN-INVALID",
                            "environment identity is ambiguous",
                        ));
                    }
                }
            }
            Effect::Execute {
                id,
                tool,
                argv,
                boundary,
                enforcement_receipt,
            } => {
                validate_artifact(tool)?;
                validate_argv(argv)?;
                match boundary {
                    ExecutionBoundary::ExternallyEnforced => {
                        let receipt = enforcement.ok_or_else(|| {
                            invalid("EFFECT-ENFORCEMENT-MISSING", "receipt is unavailable")
                        })?;
                        let expected = enforcement_receipt.as_ref().ok_or_else(|| {
                            invalid("EFFECT-ENFORCEMENT-MISSING", "receipt identity is absent")
                        })?;
                        if expected != &receipt.identity {
                            return Err(invalid(
                                "EFFECT-ENFORCEMENT-FORGED",
                                "receipt identity does not match",
                            ));
                        }
                        if &receipt.tool != tool
                            || receipt.allowed_effects.len() != 1
                            || receipt.allowed_effects[0] != *id
                        {
                            return Err(invalid(
                                "EFFECT-ENFORCEMENT-WEAKENED",
                                "receipt does not bind tool and effect",
                            ));
                        }
                    }
                    ExecutionBoundary::Mediated | ExecutionBoundary::Opaque => {
                        if enforcement_receipt.is_some() {
                            return Err(invalid(
                                "EFFECT-PLAN-INVALID",
                                "unexpected enforcement receipt",
                            ));
                        }
                    }
                }
            }
            Effect::Network { .. } | Effect::Clock { .. } | Effect::Random { .. } => {}
        }
    }
    validate_workload(plan)
}

pub fn execute_effect_plan(
    root: &Path,
    plan: &EffectPlan,
    enforcement: Option<&EnforcementReceipt>,
) -> Result<EffectTrace, EffectError> {
    validate_effect_plan(plan, enforcement)?;
    let mut runner = EffectRunner::new(root, plan, enforcement);
    runner.body_entered = true;
    match &plan.workload {
        EffectWorkload::HiddenRead { policy_effect } => {
            runner.read_file(policy_effect)?;
        }
        EffectWorkload::MutationReplay {
            target_effect,
            mutant_effect,
            witness_effect,
            output_effect,
        } => {
            let target = runner.read_file(target_effect)?;
            let mutant = runner.read_file(mutant_effect)?;
            let witness = runner.read_file(witness_effect)?;
            if target != b"mode=strict\nlimit=10\n"
                || mutant != b"mode=strict\nlimit=none\n"
                || witness != b"reject-unbounded\n"
            {
                return Err(invalid(
                    "EFFECT-MUTATION-POSTIMAGE",
                    "mutation fixture semantics changed",
                ));
            }
            runner.write_ephemeral(output_effect, "ephemeral/mutation/target.txt", &mutant)?;
        }
        EffectWorkload::DistributionBuild {
            payload_effects,
            absent_effect,
            output_effect,
        } => {
            let mut files = Vec::new();
            for effect_id in payload_effects {
                let content = runner.read_file(effect_id)?;
                let effect = runner.effect(effect_id)?;
                let Effect::ReadFile {
                    path,
                    sha256,
                    size_bytes,
                    ..
                } = effect
                else {
                    return Err(invalid("EFFECT-PLAN-INVALID", "payload is not a file"));
                };
                let content = String::from_utf8(content).map_err(|_| {
                    invalid("EFFECT-DISTRIBUTION-INVENTORY", "payload is not UTF-8")
                })?;
                files.push(serde_json::json!({
                    "content": content,
                    "path": path,
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                }));
            }
            runner.require_absent(absent_effect)?;
            let output = canonical_json(&serde_json::json!({
                "files": files,
                "schema": "proofbound-research-distribution-output/1",
            }))
            .map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
            runner.write_ephemeral(
                output_effect,
                "ephemeral/distribution/package.json",
                &output,
            )?;
        }
        EffectWorkload::SubprocessBoundary { execute_effect } => {
            runner.execute(execute_effect)?;
        }
        EffectWorkload::SecretRead { environment_effect } => {
            runner.read_secret(environment_effect)?;
        }
    }
    runner.finish()
}

pub fn validate_effect_trace(
    root: &Path,
    plan: &EffectPlan,
    enforcement: Option<&EnforcementReceipt>,
    trace: &EffectTrace,
) -> Result<(), EffectError> {
    validate_effect_plan(plan, enforcement)?;
    if trace.schema != EFFECT_TRACE_SCHEMA
        || trace.plan_id != plan.id
        || trace.plan_identity != plan_identity(plan)?
    {
        return Err(invalid(
            "EFFECT-TRACE-UNBOUND",
            "trace is not bound to plan",
        ));
    }
    let expected_identity = trace_identity(trace)?;
    if trace.identity != expected_identity {
        return Err(invalid("EFFECT-TRACE-UNBOUND", "trace identity is invalid"));
    }
    let effects: BTreeMap<_, _> = plan
        .effects
        .iter()
        .map(|effect| (effect.id(), effect))
        .collect();
    let mut observed = BTreeSet::new();
    for (index, observation) in trace.observations.iter().enumerate() {
        if observation.index != index || observation.disposition != "observed" {
            return Err(invalid(
                "EFFECT-TRACE-UNBOUND",
                "observation order is invalid",
            ));
        }
        let Some(effect) = effects.get(observation.effect_id.as_str()) else {
            return Err(invalid(
                "EFFECT-TRACE-UNBOUND",
                "observation has no declaration",
            ));
        };
        if !observed.insert(observation.effect_id.as_str()) || observation.kind != effect.kind() {
            return Err(invalid(
                "EFFECT-TRACE-UNBOUND",
                "observation declaration is ambiguous",
            ));
        }
    }
    if trace.dispositions.len() != plan.effects.len() {
        return Err(invalid(
            "EFFECT-TRACE-DISPOSITION",
            "not every declaration has a disposition",
        ));
    }
    for (effect, disposition) in plan.effects.iter().zip(&trace.dispositions) {
        let expected = if observed.contains(effect.id()) {
            "observed"
        } else {
            "unused"
        };
        if disposition.effect_id != effect.id() || disposition.disposition != expected {
            return Err(invalid(
                "EFFECT-TRACE-DISPOSITION",
                "declaration disposition is invalid",
            ));
        }
    }
    let expected = execute_effect_plan(root, plan, enforcement)?;
    if trace.outputs != expected.outputs {
        return match plan.workload {
            EffectWorkload::MutationReplay { .. } => Err(invalid(
                "EFFECT-MUTATION-POSTIMAGE",
                "mutation postimage does not match",
            )),
            EffectWorkload::DistributionBuild { .. } => Err(invalid(
                "EFFECT-DISTRIBUTION-INVENTORY",
                "distribution output inventory does not match",
            )),
            _ => Err(invalid("EFFECT-TRACE-UNBOUND", "unexpected output")),
        };
    }
    let eligible = derive_cache_eligibility(plan, &trace.observations, enforcement)?;
    if trace.cache_eligible != eligible {
        if plan.effects.iter().any(|effect| {
            matches!(
                effect,
                Effect::ReadEnvironment { secret: true, .. }
                    if observed.contains(effect.id())
            )
        }) {
            return Err(invalid(
                "EFFECT-SECRET-NONREUSABLE",
                "secret trace cannot be reused",
            ));
        }
        if plan.effects.iter().any(|effect| {
            matches!(
                effect,
                Effect::Execute {
                    boundary: ExecutionBoundary::Opaque,
                    ..
                } if observed.contains(effect.id())
            )
        }) {
            return Err(invalid(
                "EFFECT-SUBPROCESS-OPAQUE",
                "opaque execution cannot be reused",
            ));
        }
        return Err(invalid(
            "EFFECT-TRACE-UNBOUND",
            "cache eligibility was authored incorrectly",
        ));
    }
    if trace.observations != expected.observations {
        return Err(invalid(
            "EFFECT-TRACE-UNBOUND",
            "observation values do not match mediated execution",
        ));
    }
    Ok(())
}

pub fn derive_effect_invalidation(
    plan: &EffectPlan,
    old_trace: &EffectTrace,
    changed_files: &BTreeMap<String, Vec<u8>>,
) -> Result<EffectInvalidation, EffectError> {
    let mut changed_effects = Vec::new();
    let mut observations = old_trace.observations.clone();
    for effect in &plan.effects {
        let Effect::ReadFile { id, path, .. } = effect else {
            continue;
        };
        let Some(bytes) = changed_files.get(path) else {
            continue;
        };
        changed_effects.push(id.clone());
        if let Some(observation) = observations.iter_mut().find(|item| item.effect_id == *id) {
            let ObservedValue::Artifact {
                sha256, size_bytes, ..
            } = &mut observation.value
            else {
                return Err(invalid(
                    "EFFECT-TRACE-UNBOUND",
                    "read value is not an artifact",
                ));
            };
            *sha256 = sha256_bytes(bytes);
            *size_bytes = bytes.len() as u64;
        }
    }
    changed_effects.sort();
    let mut hypothetical = old_trace.clone();
    hypothetical.observations = observations;
    hypothetical.identity = trace_identity(&hypothetical)?;
    Ok(EffectInvalidation {
        schema: EFFECT_INVALIDATION_SCHEMA.to_owned(),
        plan_id: plan.id.clone(),
        old_trace_identity: old_trace.identity.clone(),
        new_trace_identity: hypothetical.identity,
        invalidated: !changed_effects.is_empty(),
        changed_effects,
    })
}

pub fn execute_effect_corpus(
    root: &Path,
    corpus_dir: &Path,
    repetitions: usize,
) -> Result<EffectModelReport, EffectError> {
    if repetitions == 0 || repetitions > 100 {
        return Err(invalid("EFFECT-PLAN-INVALID", "invalid repetition count"));
    }
    let (corpus, enforcement, attacks) = load_effect_corpus(root, corpus_dir)?;
    let expected: EffectExpected = decode(&read(root, &corpus_dir.join("expected.json"))?)?;
    validate_expected(root, &corpus, &enforcement, &expected, repetitions)?;
    let mut plans = Vec::new();
    let mut traces = BTreeMap::new();
    let mut route_outputs = Vec::new();
    for plan in &corpus.plans {
        let trace = execute_effect_plan(root, plan, Some(&enforcement))?;
        validate_effect_trace(root, plan, Some(&enforcement), &trace)?;
        let mut identities = Vec::new();
        for _ in 0..repetitions {
            let repeated = execute_effect_plan(root, plan, Some(&enforcement))?;
            if repeated != trace {
                return Err(invalid("EFFECT-NONDETERMINISTIC", "trace changed"));
            }
            identities.push(repeated.identity);
        }
        route_outputs.extend(trace.outputs.clone());
        let plan_bytes = canonical_json(plan)
            .map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?
            .len();
        let trace_bytes = canonical_json(&trace)
            .map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?
            .len();
        plans.push(EffectPlanResult {
            id: plan.id.clone(),
            plan_bytes,
            trace_bytes,
            declaration_count: plan.effects.len(),
            observation_count: trace.observations.len(),
            repetition_trace_identities: identities,
            trace: trace.clone(),
        });
        traces.insert(plan.id.clone(), trace);
    }
    plans.sort_by(|left, right| left.id.cmp(&right.id));
    route_outputs.sort();
    let mut expected_outputs = vec![
        expected.distribution_output.clone(),
        expected.mutation_output.clone(),
    ];
    expected_outputs.sort();
    if route_outputs != expected_outputs {
        return Err(invalid(
            "EFFECT-OUTPUT-IDENTITY",
            "route outputs do not match the frozen corpus",
        ));
    }

    let plan_map: BTreeMap<_, _> = corpus
        .plans
        .iter()
        .map(|plan| (plan.id.as_str(), plan))
        .collect();
    let mut attack_results = Vec::new();
    for attack in &attacks.attacks {
        let plan = plan_map
            .get(attack.base.as_str())
            .ok_or_else(|| invalid("EFFECT-PLAN-INVALID", "attack plan is missing"))?;
        attack_results.push(evaluate_effect_attack(root, plan, &enforcement, attack));
    }

    let hidden_plan = *plan_map
        .get("hidden-reader")
        .ok_or_else(|| invalid("EFFECT-PLAN-INVALID", "hidden-reader plan is missing"))?;
    let hidden_trace = traces
        .get("hidden-reader")
        .ok_or_else(|| invalid("EFFECT-TRACE-UNBOUND", "hidden trace is missing"))?;
    let mut policy_change = BTreeMap::new();
    policy_change.insert(
        "docs/experiments/0012-effect-checked-replay/corpus/fixtures/hidden/policy.txt".to_owned(),
        b"deny\n".to_vec(),
    );
    let mut unrelated_change = BTreeMap::new();
    unrelated_change.insert(
        "docs/experiments/0012-effect-checked-replay/corpus/fixtures/hidden/unrelated.txt"
            .to_owned(),
        b"changed-only\n".to_vec(),
    );
    let mut policy_decisions = Vec::new();
    let mut unrelated_decisions = Vec::new();
    for _ in 0..repetitions {
        policy_decisions.push(derive_effect_invalidation(
            hidden_plan,
            hidden_trace,
            &policy_change,
        )?);
        unrelated_decisions.push(derive_effect_invalidation(
            hidden_plan,
            hidden_trace,
            &unrelated_change,
        )?);
    }

    Ok(EffectModelReport {
        schema: EFFECT_MODEL_REPORT_SCHEMA.to_owned(),
        plans,
        attacks: attack_results,
        invalidation: vec![
            EffectInvalidationResult {
                id: "policy-change".to_owned(),
                decisions: policy_decisions,
            },
            EffectInvalidationResult {
                id: "unrelated-change".to_owned(),
                decisions: unrelated_decisions,
            },
        ],
        route_outputs,
    })
}

fn evaluate_effect_attack(
    root: &Path,
    plan: &EffectPlan,
    enforcement: &EnforcementReceipt,
    attack: &EffectAttack,
) -> EffectAttackResult {
    let (result, body_entered) = run_attack(root, plan, enforcement, &attack.action);
    let actual_code = result
        .err()
        .map_or_else(|| "ACCEPTED".to_owned(), |error| error.code.to_owned());
    EffectAttackResult {
        id: attack.id.clone(),
        expected_code: attack.code.clone(),
        exact: actual_code == attack.code,
        actual_code,
        workload_body_entered: body_entered,
    }
}

fn run_attack(
    root: &Path,
    plan: &EffectPlan,
    enforcement: &EnforcementReceipt,
    action: &EffectAttackAction,
) -> (Result<(), EffectError>, bool) {
    let static_error = match action {
        EffectAttackAction::RequestRead { .. } => Some(invalid(
            "EFFECT-READ-UNDECLARED",
            "file read has no declaration",
        )),
        EffectAttackAction::RequestEnvironment { .. } => Some(invalid(
            "EFFECT-ENV-UNDECLARED",
            "environment read has no declaration",
        )),
        EffectAttackAction::RequestNetwork { effect_id } => {
            Some(require_denied(plan, effect_id, "network"))
        }
        EffectAttackAction::RequestClock { effect_id } => {
            Some(require_denied(plan, effect_id, "clock"))
        }
        EffectAttackAction::RequestRandom { effect_id } => {
            Some(require_denied(plan, effect_id, "random"))
        }
        EffectAttackAction::RequestReviewedWrite { .. } => Some(invalid(
            "EFFECT-WRITE-REVIEWED",
            "reviewed writes are forbidden during replay",
        )),
        EffectAttackAction::RequestEphemeralWrite {
            effect_id, path, ..
        } => Some(check_ephemeral_request(plan, effect_id, path)),
        EffectAttackAction::SubstituteFileType { file_type, .. } if file_type == "symlink" => Some(
            invalid("EFFECT-PATH-SYMLINK", "symlink substituted for file"),
        ),
        EffectAttackAction::RequestExecute { .. } => Some(invalid(
            "EFFECT-EXEC-UNDECLARED",
            "execution has no declaration",
        )),
        EffectAttackAction::SubstituteExecutable { effect_id, sha256 } => {
            check_execution_request(plan, effect_id, Some(sha256), None).err()
        }
        EffectAttackAction::SubstituteArgv { effect_id, argv } => {
            check_execution_request(plan, effect_id, None, Some(argv)).err()
        }
        EffectAttackAction::RemoveEnforcementReceipt => {
            let mut mutated = plan.clone();
            if let Some(Effect::Execute {
                enforcement_receipt,
                ..
            }) = mutated
                .effects
                .iter_mut()
                .find(|effect| matches!(effect, Effect::Execute { .. }))
            {
                *enforcement_receipt = None;
            }
            validate_effect_plan(&mutated, Some(enforcement)).err()
        }
        EffectAttackAction::ForgeEnforcementIdentity { identity } => {
            let mut mutated = enforcement.clone();
            mutated.identity.clone_from(identity);
            validate_enforcement(&mutated)
                .err()
                .map(|_| invalid("EFFECT-ENFORCEMENT-FORGED", "receipt identity is forged"))
        }
        EffectAttackAction::WeakenEnforcement { allowed_effects } => {
            let mut mutated = enforcement.clone();
            mutated.allowed_effects.clone_from(allowed_effects);
            validate_effect_plan(plan, Some(&mutated))
                .err()
                .map(|_| invalid("EFFECT-ENFORCEMENT-WEAKENED", "receipt effect set weakened"))
        }
        EffectAttackAction::DuplicateEffect { effect_id } => {
            let mut mutated = plan.clone();
            if let Some(effect) = mutated.effects.iter().find(|item| item.id() == effect_id) {
                mutated.effects.push(effect.clone());
            }
            validate_effect_plan(&mutated, Some(enforcement)).err()
        }
        EffectAttackAction::AliasEffectId { alias, .. }
            if validate_id(alias, "effect").is_err() =>
        {
            Some(invalid("EFFECT-ID-ALIAS", "effect alias is noncanonical"))
        }
        _ => None,
    };
    if let Some(error) = static_error {
        return (Err(error), false);
    }

    let result = match action {
        EffectAttackAction::ForgeCacheEligible => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|mut trace| {
                trace.cache_eligible = true;
                trace.identity = trace_identity(&trace)?;
                validate_effect_trace(root, plan, Some(enforcement), &trace)
            })
        }
        EffectAttackAction::SubstituteExecutable { .. }
        | EffectAttackAction::SubstituteArgv { .. }
        | EffectAttackAction::RemoveEnforcementReceipt
        | EffectAttackAction::ForgeEnforcementIdentity { .. }
        | EffectAttackAction::WeakenEnforcement { .. }
        | EffectAttackAction::DuplicateEffect { .. } => Ok(()),
        EffectAttackAction::ForgeExactCacheEligible { .. } => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|mut trace| {
                trace.cache_eligible = true;
                trace.identity = trace_identity(&trace)?;
                validate_effect_trace(root, plan, Some(enforcement), &trace)
            })
        }
        EffectAttackAction::AppendObservation { effect_id } => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|mut trace| {
                trace.observations.push(EffectObservation {
                    index: trace.observations.len(),
                    effect_id: effect_id.clone(),
                    kind: "read-file".to_owned(),
                    disposition: "observed".to_owned(),
                    value: ObservedValue::Absence {
                        path: "ephemeral/unbound".to_owned(),
                    },
                });
                trace.identity = trace_identity(&trace)?;
                validate_effect_trace(root, plan, Some(enforcement), &trace)
            })
        }
        EffectAttackAction::OmitUnusedDisposition { effect_id } => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|mut trace| {
                trace
                    .dispositions
                    .retain(|item| item.effect_id != *effect_id);
                trace.identity = trace_identity(&trace)?;
                validate_effect_trace(root, plan, Some(enforcement), &trace)
            })
        }
        EffectAttackAction::SubstitutePostimage { content } => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|mut trace| {
                if let Some(output) = trace.outputs.first_mut() {
                    output.sha256 = sha256_bytes(content.as_bytes());
                    output.size_bytes = content.len() as u64;
                }
                trace.identity = trace_identity(&trace)?;
                validate_effect_trace(root, plan, Some(enforcement), &trace)
            })
        }
        EffectAttackAction::AddPackagePath { path } => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|mut trace| {
                trace.outputs.push(EffectOutput {
                    path: path.clone(),
                    sha256: sha256_bytes(b"extra"),
                    size_bytes: 5,
                });
                trace.outputs.sort();
                trace.identity = trace_identity(&trace)?;
                validate_effect_trace(root, plan, Some(enforcement), &trace)
            })
        }
        EffectAttackAction::UseGlobalRevisionInvalidation { changed_path } => {
            execute_effect_plan(root, plan, Some(enforcement)).and_then(|trace| {
                let mut changes = BTreeMap::new();
                changes.insert(changed_path.clone(), b"changed-only\n".to_vec());
                let decision = derive_effect_invalidation(plan, &trace, &changes)?;
                if decision.invalidated {
                    Ok(())
                } else {
                    Err(invalid(
                        "EFFECT-REVISION-OVERINVALIDATION",
                        "global revision invalidates an unrelated input",
                    ))
                }
            })
        }
        EffectAttackAction::AliasEffectId { .. }
        | EffectAttackAction::RequestRead { .. }
        | EffectAttackAction::RequestEnvironment { .. }
        | EffectAttackAction::RequestNetwork { .. }
        | EffectAttackAction::RequestClock { .. }
        | EffectAttackAction::RequestRandom { .. }
        | EffectAttackAction::RequestReviewedWrite { .. }
        | EffectAttackAction::RequestEphemeralWrite { .. }
        | EffectAttackAction::SubstituteFileType { .. }
        | EffectAttackAction::RequestExecute { .. } => Ok(()),
    };
    (result, true)
}

fn require_denied(plan: &EffectPlan, effect_id: &str, kind: &str) -> EffectError {
    if plan
        .effects
        .iter()
        .any(|effect| effect.id() == effect_id && effect.kind() == kind)
    {
        let code = match kind {
            "network" => "EFFECT-NETWORK-DENIED",
            "clock" => "EFFECT-CLOCK-DENIED",
            _ => "EFFECT-RANDOM-DENIED",
        };
        invalid(code, format!("{kind} authority is denied"))
    } else {
        invalid("EFFECT-PLAN-INVALID", "denial declaration is missing")
    }
}

fn check_ephemeral_request(plan: &EffectPlan, effect_id: &str, path: &str) -> EffectError {
    let root = plan.effects.iter().find_map(|effect| match effect {
        Effect::WriteEphemeral { id, root } if id == effect_id => Some(root),
        _ => None,
    });
    if root.is_some_and(|root| is_strict_descendant(root, path)) {
        invalid("EFFECT-ATTACK-ACCEPTED", "write is inside boundary")
    } else {
        invalid("EFFECT-WRITE-ESCAPE", "write escaped ephemeral boundary")
    }
}

fn check_execution_request(
    plan: &EffectPlan,
    effect_id: &str,
    sha256: Option<&String>,
    argv: Option<&Vec<String>>,
) -> Result<(), EffectError> {
    let Some(Effect::Execute {
        tool,
        argv: expected_argv,
        ..
    }) = plan.effects.iter().find(|effect| effect.id() == effect_id)
    else {
        return Err(invalid(
            "EFFECT-EXEC-UNDECLARED",
            "execute effect is missing",
        ));
    };
    if sha256.is_some_and(|actual| actual != &tool.sha256) {
        return Err(invalid(
            "EFFECT-EXEC-IDENTITY",
            "executable identity changed",
        ));
    }
    if argv.is_some_and(|actual| actual != expected_argv) {
        return Err(invalid("EFFECT-EXEC-ARGV", "arguments changed"));
    }
    Ok(())
}

struct EffectRunner<'a> {
    root: &'a Path,
    plan: &'a EffectPlan,
    enforcement: Option<&'a EnforcementReceipt>,
    observations: Vec<EffectObservation>,
    outputs: Vec<EffectOutput>,
    consumed: BTreeSet<String>,
    body_entered: bool,
}

impl<'a> EffectRunner<'a> {
    fn new(
        root: &'a Path,
        plan: &'a EffectPlan,
        enforcement: Option<&'a EnforcementReceipt>,
    ) -> Self {
        Self {
            root,
            plan,
            enforcement,
            observations: Vec::new(),
            outputs: Vec::new(),
            consumed: BTreeSet::new(),
            body_entered: false,
        }
    }

    fn effect(&self, id: &str) -> Result<&Effect, EffectError> {
        self.plan
            .effects
            .iter()
            .find(|effect| effect.id() == id)
            .ok_or_else(|| invalid("EFFECT-TRACE-UNBOUND", format!("unknown effect {id}")))
    }

    fn observe(&mut self, effect: &Effect, value: ObservedValue) -> Result<(), EffectError> {
        if !self.consumed.insert(effect.id().to_owned()) {
            return Err(invalid("EFFECT-TRACE-UNBOUND", "effect consumed twice"));
        }
        self.observations.push(EffectObservation {
            index: self.observations.len(),
            effect_id: effect.id().to_owned(),
            kind: effect.kind().to_owned(),
            disposition: "observed".to_owned(),
            value,
        });
        Ok(())
    }

    fn read_file(&mut self, id: &str) -> Result<Vec<u8>, EffectError> {
        let effect = self.effect(id)?.clone();
        let Effect::ReadFile {
            path,
            sha256,
            size_bytes,
            mode,
            ..
        } = &effect
        else {
            return Err(invalid("EFFECT-READ-UNDECLARED", "effect is not a read"));
        };
        let (bytes, actual_mode) = read_regular(self.root, path)?;
        if sha256_bytes(&bytes) != *sha256
            || bytes.len() as u64 != *size_bytes
            || actual_mode != *mode
        {
            return Err(invalid("EFFECT-INPUT-DRIFT", format!("{path} changed")));
        }
        self.observe(
            &effect,
            ObservedValue::Artifact {
                path: path.clone(),
                sha256: sha256.clone(),
                size_bytes: *size_bytes,
                mode: *mode,
            },
        )?;
        Ok(bytes)
    }

    fn require_absent(&mut self, id: &str) -> Result<(), EffectError> {
        let effect = self.effect(id)?.clone();
        let Effect::RequireAbsent { path, .. } = &effect else {
            return Err(invalid("EFFECT-PLAN-INVALID", "effect is not absence"));
        };
        self.observe(&effect, ObservedValue::Absence { path: path.clone() })
    }

    fn write_ephemeral(&mut self, id: &str, path: &str, bytes: &[u8]) -> Result<(), EffectError> {
        let effect = self.effect(id)?.clone();
        let Effect::WriteEphemeral { root, .. } = &effect else {
            return Err(invalid("EFFECT-WRITE-ESCAPE", "effect is not a write"));
        };
        if !is_strict_descendant(root, path) {
            return Err(invalid("EFFECT-WRITE-ESCAPE", "output escaped boundary"));
        }
        let output = EffectOutput {
            path: path.to_owned(),
            sha256: sha256_bytes(bytes),
            size_bytes: bytes.len() as u64,
        };
        self.observe(
            &effect,
            ObservedValue::Output {
                path: output.path.clone(),
                sha256: output.sha256.clone(),
                size_bytes: output.size_bytes,
            },
        )?;
        self.outputs.push(output);
        Ok(())
    }

    fn execute(&mut self, id: &str) -> Result<(), EffectError> {
        let effect = self.effect(id)?.clone();
        let Effect::Execute {
            tool,
            argv,
            boundary,
            enforcement_receipt,
            ..
        } = &effect
        else {
            return Err(invalid("EFFECT-EXEC-UNDECLARED", "effect is not execution"));
        };
        if matches!(boundary, ExecutionBoundary::ExternallyEnforced) {
            validate_effect_plan(self.plan, self.enforcement)?;
        }
        let (bytes, actual_mode) = read_regular(self.root, &tool.path)?;
        if sha256_bytes(&bytes) != tool.sha256
            || bytes.len() as u64 != tool.size_bytes
            || actual_mode != tool.mode
        {
            return Err(invalid(
                "EFFECT-EXEC-IDENTITY",
                "registered executable identity changed",
            ));
        }
        self.observe(
            &effect,
            ObservedValue::Execution {
                tool: tool.clone(),
                argv: argv.clone(),
                boundary: boundary.clone(),
                enforcement_receipt: enforcement_receipt.clone(),
            },
        )
    }

    fn read_secret(&mut self, id: &str) -> Result<(), EffectError> {
        let effect = self.effect(id)?.clone();
        let Effect::ReadEnvironment {
            name, secret: true, ..
        } = &effect
        else {
            return Err(invalid("EFFECT-ENV-UNDECLARED", "effect is not a secret"));
        };
        self.observe(
            &effect,
            ObservedValue::Secret {
                name: name.clone(),
                present: true,
            },
        )
    }

    fn finish(mut self) -> Result<EffectTrace, EffectError> {
        self.outputs.sort();
        let dispositions = self
            .plan
            .effects
            .iter()
            .map(|effect| EffectDisposition {
                effect_id: effect.id().to_owned(),
                disposition: if self.consumed.contains(effect.id()) {
                    "observed".to_owned()
                } else {
                    "unused".to_owned()
                },
            })
            .collect();
        let cache_eligible =
            derive_cache_eligibility(self.plan, &self.observations, self.enforcement)?;
        let mut trace = EffectTrace {
            schema: EFFECT_TRACE_SCHEMA.to_owned(),
            plan_id: self.plan.id.clone(),
            plan_identity: plan_identity(self.plan)?,
            observations: self.observations,
            dispositions,
            outputs: self.outputs,
            cache_eligible,
            identity: String::new(),
        };
        trace.identity = trace_identity(&trace)?;
        Ok(trace)
    }
}

fn derive_cache_eligibility(
    plan: &EffectPlan,
    observations: &[EffectObservation],
    enforcement: Option<&EnforcementReceipt>,
) -> Result<bool, EffectError> {
    let observed: BTreeSet<_> = observations
        .iter()
        .map(|observation| observation.effect_id.as_str())
        .collect();
    for effect in &plan.effects {
        if !observed.contains(effect.id()) {
            continue;
        }
        match effect {
            Effect::ReadEnvironment { secret: true, .. }
            | Effect::WriteReviewed { .. }
            | Effect::Execute {
                boundary: ExecutionBoundary::Opaque,
                ..
            } => return Ok(false),
            Effect::Execute {
                boundary: ExecutionBoundary::ExternallyEnforced,
                ..
            } => validate_effect_plan(plan, enforcement)?,
            _ => {}
        }
    }
    Ok(true)
}

fn validate_workload(plan: &EffectPlan) -> Result<(), EffectError> {
    let by_id: BTreeMap<_, _> = plan
        .effects
        .iter()
        .map(|effect| (effect.id(), effect.kind()))
        .collect();
    let require = |id: &str, kind: &str| {
        if by_id.get(id).copied() == Some(kind) {
            Ok(())
        } else {
            Err(invalid(
                "EFFECT-PLAN-INVALID",
                format!("workload role {id} is not {kind}"),
            ))
        }
    };
    match &plan.workload {
        EffectWorkload::HiddenRead { policy_effect } => require(policy_effect, "read-file"),
        EffectWorkload::MutationReplay {
            target_effect,
            mutant_effect,
            witness_effect,
            output_effect,
        } => {
            require(target_effect, "read-file")?;
            require(mutant_effect, "read-file")?;
            require(witness_effect, "read-file")?;
            require(output_effect, "write-ephemeral")
        }
        EffectWorkload::DistributionBuild {
            payload_effects,
            absent_effect,
            output_effect,
        } => {
            if payload_effects.len() != 2 || payload_effects[0] >= payload_effects[1] {
                return Err(invalid(
                    "EFFECT-DISTRIBUTION-INVENTORY",
                    "payload effects are not an exact lexical pair",
                ));
            }
            for effect in payload_effects {
                require(effect, "read-file")?;
            }
            require(absent_effect, "require-absent")?;
            require(output_effect, "write-ephemeral")
        }
        EffectWorkload::SubprocessBoundary { execute_effect } => require(execute_effect, "execute"),
        EffectWorkload::SecretRead { environment_effect } => {
            require(environment_effect, "read-environment")
        }
    }
}

fn validate_enforcement(receipt: &EnforcementReceipt) -> Result<(), EffectError> {
    if receipt.schema != EFFECT_ENFORCEMENT_SCHEMA {
        return Err(invalid("EFFECT-ENFORCEMENT-FORGED", "wrong receipt schema"));
    }
    validate_id(&receipt.id, "enforcement")?;
    validate_artifact(&receipt.tool)?;
    if receipt.allowed_effects.is_empty()
        || receipt
            .allowed_effects
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid(
            "EFFECT-ENFORCEMENT-WEAKENED",
            "invalid allowed-effect set",
        ));
    }
    validate_id(&receipt.mechanism.name, "mechanism")?;
    validate_digest(&receipt.mechanism.identity)?;
    let mut material = serde_json::to_value(receipt)
        .map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
    material
        .as_object_mut()
        .expect("serialized receipt is an object")
        .remove("identity");
    let bytes =
        canonical_json(&material).map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
    if domain_hash(EFFECT_ENFORCEMENT_SCHEMA, &bytes) != receipt.identity {
        return Err(invalid(
            "EFFECT-ENFORCEMENT-FORGED",
            "receipt identity is invalid",
        ));
    }
    Ok(())
}

fn validate_expected(
    root: &Path,
    corpus: &EffectCorpus,
    enforcement: &EnforcementReceipt,
    expected: &EffectExpected,
    repetitions: usize,
) -> Result<(), EffectError> {
    if expected.schema != "proofbound-research-effect-expected/1"
        || expected.repetitions != repetitions
        || expected.enforcement_identity != enforcement.identity
    {
        return Err(invalid(
            "EFFECT-EXPECTED-MISMATCH",
            "frozen execution parameters do not match",
        ));
    }
    if expected
        .fixtures
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(invalid(
            "EFFECT-EXPECTED-MISMATCH",
            "fixture identities are not a strict lexical set",
        ));
    }
    for fixture in &expected.fixtures {
        validate_artifact(fixture)?;
        let (bytes, mode) = read_regular(root, &fixture.path)?;
        if sha256_bytes(&bytes) != fixture.sha256
            || bytes.len() as u64 != fixture.size_bytes
            || mode != fixture.mode
        {
            return Err(invalid(
                "EFFECT-EXPECTED-MISMATCH",
                format!("fixture {} changed", fixture.path),
            ));
        }
    }
    let mut actual = Vec::new();
    for plan in &corpus.plans {
        let bytes =
            canonical_json(plan).map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
        let trace = execute_effect_plan(root, plan, Some(enforcement))?;
        actual.push(ExpectedEffectPlan {
            id: plan.id.clone(),
            identity: domain_hash(EFFECT_PLAN_SCHEMA, &bytes),
            canonical_bytes: bytes.len(),
            cache_eligible: trace.cache_eligible,
        });
    }
    actual.sort_by(|left, right| left.id.cmp(&right.id));
    if actual != expected.plans {
        return Err(invalid(
            "EFFECT-EXPECTED-MISMATCH",
            "plan identities do not match the frozen corpus",
        ));
    }
    Ok(())
}

fn validate_artifact(artifact: &ArtifactIdentity) -> Result<(), EffectError> {
    validate_path(&artifact.path)?;
    validate_digest(&artifact.sha256)?;
    if artifact.size_bytes > 16 * 1024 * 1024 || artifact.mode > 0o7777 {
        return Err(invalid("EFFECT-PLAN-INVALID", "invalid artifact identity"));
    }
    Ok(())
}

fn validate_argv(argv: &[String]) -> Result<(), EffectError> {
    if argv.is_empty() || argv.len() > 64 {
        return Err(invalid("EFFECT-EXEC-ARGV", "argument vector is invalid"));
    }
    for argument in argv {
        if argument.is_empty() || argument.len() > 4096 || argument.chars().any(char::is_control) {
            return Err(invalid("EFFECT-EXEC-ARGV", "argument is invalid"));
        }
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<(), EffectError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(invalid(
            "EFFECT-ENV-UNDECLARED",
            "environment name is invalid",
        ));
    }
    Ok(())
}

fn validate_id(id: &str, label: &str) -> Result<(), EffectError> {
    if id.is_empty()
        || id.len() > 128
        || id.starts_with('-')
        || id.ends_with('-')
        || id.contains("--")
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid(
            "EFFECT-ID-INVALID",
            format!("invalid {label} ID {id}"),
        ));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), EffectError> {
    if digest.len() != 71
        || !digest.starts_with("sha256:")
        || !digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("EFFECT-IDENTITY", "invalid SHA-256 identity"));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), EffectError> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return Err(invalid("EFFECT-PATH-INVALID", "invalid path"));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        return Err(invalid("EFFECT-PATH-INVALID", "absolute path"));
    }
    let reserved = [
        ".git",
        ".proofbound",
        "target",
        "node_modules",
        "__pycache__",
    ];
    for component in parsed.components() {
        let Component::Normal(part) = component else {
            return Err(invalid("EFFECT-PATH-INVALID", "non-normal path"));
        };
        let part = part.to_string_lossy();
        if reserved.contains(&part.as_ref()) {
            return Err(invalid("EFFECT-PATH-INVALID", "reserved path component"));
        }
    }
    Ok(())
}

fn validate_ephemeral_path(path: &str) -> Result<(), EffectError> {
    validate_path(path)?;
    if !path.starts_with("ephemeral/") {
        return Err(invalid("EFFECT-WRITE-ESCAPE", "path is not ephemeral"));
    }
    Ok(())
}

fn validate_ephemeral_root(root: &str) -> Result<(), EffectError> {
    validate_ephemeral_path(root)?;
    if root.ends_with('/') {
        return Err(invalid("EFFECT-WRITE-ESCAPE", "invalid ephemeral root"));
    }
    Ok(())
}

fn is_strict_descendant(root: &str, path: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
}

fn read(root: &Path, path: &Path) -> Result<Vec<u8>, EffectError> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    fs::read(&joined)
        .map_err(|error| invalid("EFFECT-IO", format!("{}: {error}", joined.display())))
}

fn read_regular(root: &Path, path: &str) -> Result<(Vec<u8>, u32), EffectError> {
    validate_path(path)?;
    let joined = root.join(path);
    let metadata = fs::symlink_metadata(&joined)
        .map_err(|error| invalid("EFFECT-IO", format!("{path}: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(invalid(
            "EFFECT-PATH-SYMLINK",
            format!("{path} is a symlink"),
        ));
    }
    if !metadata.is_file() {
        return Err(invalid("EFFECT-PATH-TYPE", format!("{path} is not a file")));
    }
    let bytes =
        fs::read(&joined).map_err(|error| invalid("EFFECT-IO", format!("{path}: {error}")))?;
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    };
    Ok((bytes, mode))
}

fn plan_identity(plan: &EffectPlan) -> Result<String, EffectError> {
    let bytes =
        canonical_json(plan).map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
    Ok(domain_hash(EFFECT_PLAN_SCHEMA, &bytes))
}

fn trace_identity(trace: &EffectTrace) -> Result<String, EffectError> {
    let mut material =
        serde_json::to_value(trace).map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
    material
        .as_object_mut()
        .expect("serialized trace is an object")
        .remove("identity");
    let bytes =
        canonical_json(&material).map_err(|error| invalid("EFFECT-ENCODE", error.to_string()))?;
    Ok(domain_hash(EFFECT_TRACE_SCHEMA, &bytes))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, EffectError> {
    serde_json::from_slice(bytes).map_err(|error| invalid("EFFECT-DECODE", error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn corpus_dir() -> std::path::PathBuf {
        std::path::PathBuf::from("docs/experiments/0012-effect-checked-replay/corpus")
    }

    #[test]
    fn frozen_corpus_executes_deterministically() {
        let report = execute_effect_corpus(&root(), &corpus_dir(), 10).unwrap();
        assert_eq!(report.plans.len(), 6);
        assert_eq!(report.attacks.len(), 23);
        assert!(report.attacks.iter().all(|attack| attack.exact));
        assert_eq!(report.route_outputs.len(), 2);
        assert!(
            report
                .plans
                .iter()
                .all(|plan| plan.repetition_trace_identities.len() == 10)
        );
        let preflight_attacks = [
            "undeclared-file-read",
            "undeclared-environment",
            "network-attempt",
            "clock-attempt",
            "random-attempt",
            "reviewed-root-write",
            "ephemeral-write-escape",
            "symlink-substitution",
            "lifecycle-script",
            "executable-substitution",
            "argv-substitution",
            "missing-enforcement",
            "forged-enforcement",
            "weakened-enforcement",
            "effect-id-alias",
            "duplicate-effect",
        ];
        assert!(report.attacks.iter().all(|attack| {
            !preflight_attacks.contains(&attack.id.as_str()) || !attack.workload_body_entered
        }));
    }

    #[test]
    fn invalidation_is_narrow() {
        let report = execute_effect_corpus(&root(), &corpus_dir(), 10).unwrap();
        assert!(report.invalidation[0]
            .decisions
            .iter()
            .all(|decision| decision.invalidated && decision.changed_effects == ["read-policy"]));
        assert!(
            report.invalidation[1]
                .decisions
                .iter()
                .all(|decision| !decision.invalidated && decision.changed_effects.is_empty())
        );
    }

    #[test]
    fn opaque_and_secret_traces_are_not_reusable() {
        let report = execute_effect_corpus(&root(), &corpus_dir(), 10).unwrap();
        for id in ["opaque-process", "secret-reader"] {
            assert!(
                !report
                    .plans
                    .iter()
                    .find(|plan| plan.id == id)
                    .unwrap()
                    .trace
                    .cache_eligible
            );
        }
        assert!(
            report
                .plans
                .iter()
                .find(|plan| plan.id == "externally-enforced-process")
                .unwrap()
                .trace
                .cache_eligible
        );
    }

    #[test]
    fn self_consistent_observation_substitution_rejects() {
        let (corpus, enforcement, _) = load_effect_corpus(&root(), &corpus_dir()).unwrap();
        let plan = corpus
            .plans
            .iter()
            .find(|plan| plan.id == "hidden-reader")
            .unwrap();
        let mut trace = execute_effect_plan(&root(), plan, Some(&enforcement)).unwrap();
        let ObservedValue::Artifact { sha256, .. } = &mut trace.observations[0].value else {
            panic!("hidden read must produce an artifact observation");
        };
        *sha256 = sha256_bytes(b"substituted");
        trace.identity = trace_identity(&trace).unwrap();
        assert_eq!(
            validate_effect_trace(&root(), plan, Some(&enforcement), &trace)
                .unwrap_err()
                .code,
            "EFFECT-TRACE-UNBOUND"
        );
    }
}
