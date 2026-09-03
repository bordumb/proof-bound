use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::assurance::decode_strict_json;

pub const ASSURANCE_V2_PROGRAM_SCHEMA: &str = "proofbound-research-assurance-program/2";
pub const ASSURANCE_V2_REPORT_SCHEMA: &str = "proofbound-research-assurance-kernel-report/2";
pub const ASSURANCE_V2_MODEL_REPORT_SCHEMA: &str = "proofbound-research-assurance-model-report/2";

const MODEL_SCHEMA: &str = "proofbound-research-assurance-model/2";
const TEMPLATES_SCHEMA: &str = "proofbound-research-assurance-templates/2";
const ATTACKS_SCHEMA: &str = "proofbound-research-assurance-attacks/2";
const GENERATION_SCHEMA: &str = "proofbound-research-assurance-generation/2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Model {
    pub schema: String,
    pub program_schema: String,
    pub report_schema: String,
    pub families: Vec<FamilyDefinition>,
    pub dependency_roles: Vec<String>,
    pub effect_capabilities: Vec<String>,
    pub effect_boundaries: Vec<String>,
    pub artifact_roles: Vec<String>,
    pub uncertainties: Vec<UncertaintyDefinition>,
    pub specification_roles: Vec<String>,
    pub derivation_rules: Vec<String>,
    pub object_constructors: Vec<String>,
    pub validation_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyDefinition {
    pub id: String,
    pub formal: String,
    pub linkage: String,
    pub required_artifact_roles: Vec<String>,
    pub requires_specification: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyDefinition {
    pub kind: String,
    pub consequence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Templates {
    pub schema: String,
    pub profiles: Vec<AssuranceV2Profile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Profile {
    pub id: String,
    pub family: String,
    pub dependency_roles: Vec<String>,
    pub effects: Vec<ProfileEffect>,
    pub artifact_roles: Vec<String>,
    pub uncertainty: ProfileUncertainty,
    pub cache_eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEffect {
    pub capability: String,
    pub boundary: String,
    pub disposition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileUncertainty {
    pub kind: String,
    pub consequence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Program {
    pub schema: String,
    pub id: String,
    pub claim: AssuranceV2Claim,
    pub specification: Option<AssuranceV2Specification>,
    pub dependencies: Vec<AssuranceV2Dependency>,
    pub effects: Vec<AssuranceV2Effect>,
    pub artifacts: Vec<AssuranceV2Artifact>,
    pub evidence: AssuranceV2Evidence,
    pub uncertainties: Vec<AssuranceV2Uncertainty>,
    pub invalidation: AssuranceV2Invalidation,
    pub derivation: AssuranceV2Derivation,
    pub expected_decision: AssuranceV2Decision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Claim {
    pub id: String,
    pub subject: String,
    pub specification_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Specification {
    pub id: String,
    pub suite_identity: String,
    pub adequacy_identity: String,
    pub roles: Vec<String>,
    pub required_mutants: u64,
    pub killed_mutants: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Dependency {
    pub id: String,
    pub role: String,
    pub identity: String,
    pub declared: bool,
    pub observed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Effect {
    pub id: String,
    pub capability: String,
    pub boundary: String,
    pub disposition: String,
    pub enforcement_dependency: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Artifact {
    pub id: String,
    pub role: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub corresponds_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Evidence {
    pub id: String,
    pub family: String,
    pub outcome: String,
    pub dependency_ids: Vec<String>,
    pub effect_ids: Vec<String>,
    pub artifact_ids: Vec<String>,
    pub specification_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Uncertainty {
    pub id: String,
    pub kind: String,
    pub consequence: String,
    pub detail_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Invalidation {
    pub changed_dependencies: Vec<String>,
    pub invalidated_evidence: Vec<String>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Derivation {
    pub steps: Vec<AssuranceV2Step>,
    pub root: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Step {
    pub id: String,
    pub rule: String,
    pub inputs: Vec<String>,
    pub conclusion: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Decision {
    pub formal: String,
    pub linkage: String,
    pub assumption: String,
    pub admitted: bool,
    pub cache_eligible: bool,
    pub consumed_uncertainties: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2KernelReport {
    pub schema: String,
    pub programme: String,
    pub semantic_identity: String,
    pub dependency_identity: String,
    pub invalidation_identity: String,
    pub derivation_identity: String,
    pub decision: AssuranceV2Decision,
    pub consumed_uncertainties: Vec<String>,
    pub cache_eligible: bool,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2AttackCorpus {
    pub schema: String,
    pub attacks: Vec<AssuranceV2Attack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Attack {
    pub id: String,
    pub template: String,
    pub action: String,
    pub expected: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2Generation {
    pub schema: String,
    pub algorithm: String,
    pub seed: u64,
    pub valid_programs: usize,
    pub adversarial_programs: usize,
    pub mutation_cardinality: u64,
    pub template_selection: String,
    pub attack_selection: String,
    pub identifier_suffix: String,
    pub repetitions: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2AttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceV2ModelReport {
    pub schema: String,
    pub templates: Vec<AssuranceV2KernelReport>,
    pub valid_programs: usize,
    pub valid_corpus_identity: String,
    pub adversarial_programs: usize,
    pub adversarial_corpus_identity: String,
    pub attacks: Vec<AssuranceV2AttackResult>,
    pub constructor_coverage: Vec<String>,
    pub validation_code_coverage: Vec<String>,
    pub repetition_report_identities: Vec<String>,
    pub identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssuranceV2Error {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for AssuranceV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AssuranceV2Error {}

fn invalid(code: &'static str, message: impl Into<String>) -> AssuranceV2Error {
    AssuranceV2Error {
        code,
        message: message.into(),
    }
}

pub fn load_assurance_v2_corpus(
    root: &Path,
    corpus_dir: &Path,
) -> Result<
    (
        AssuranceV2Model,
        AssuranceV2Templates,
        AssuranceV2AttackCorpus,
        AssuranceV2Generation,
    ),
    AssuranceV2Error,
> {
    let model: AssuranceV2Model = decode_file(root, &corpus_dir.join("model.json"))?;
    let templates: AssuranceV2Templates = decode_file(root, &corpus_dir.join("templates.json"))?;
    let attacks: AssuranceV2AttackCorpus = decode_file(root, &corpus_dir.join("attacks.json"))?;
    let generation: AssuranceV2Generation = decode_file(root, &corpus_dir.join("generation.json"))?;
    validate_corpus(&model, &templates, &attacks, &generation)?;
    Ok((model, templates, attacks, generation))
}

pub fn expand_assurance_v2_profile(
    model: &AssuranceV2Model,
    profile: &AssuranceV2Profile,
    suffix: usize,
) -> Result<AssuranceV2Program, AssuranceV2Error> {
    let suffix = format!("{suffix:06}");
    let family = family(model, &profile.family)?;
    let programme_id = format!("programme:{}:{suffix}", profile.id);
    let claim_id = format!("claim:{}:{suffix}", profile.id);
    let spec_id = format!("specification:{}:{suffix}", profile.id);
    let evidence_id = format!("evidence:{}:{suffix}", profile.id);
    let uncertainty_id = format!("uncertainty:{}:{suffix}", profile.id);

    let mut dependencies = profile
        .dependency_roles
        .iter()
        .map(|role| {
            let id = format!("dependency:{}:{role}:{suffix}", profile.id);
            AssuranceV2Dependency {
                identity: sha256_bytes(id.as_bytes()),
                id,
                role: role.clone(),
                declared: true,
                observed: true,
            }
        })
        .collect::<Vec<_>>();
    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    let external_dependency = dependencies
        .iter()
        .find(|dependency| dependency.role == "external-contract")
        .map(|dependency| dependency.id.clone());

    let mut effects = profile
        .effects
        .iter()
        .map(|effect| AssuranceV2Effect {
            id: format!("effect:{}:{}:{suffix}", profile.id, effect.capability),
            capability: effect.capability.clone(),
            boundary: effect.boundary.clone(),
            disposition: effect.disposition.clone(),
            enforcement_dependency: (effect.boundary == "externally-enforced")
                .then(|| external_dependency.clone())
                .flatten(),
        })
        .collect::<Vec<_>>();
    effects.sort_by(|left, right| left.id.cmp(&right.id));

    let mut artifacts = profile
        .artifact_roles
        .iter()
        .map(|role| {
            let id = format!("artifact:{}:{role}:{suffix}", profile.id);
            AssuranceV2Artifact {
                sha256: sha256_bytes(id.as_bytes()),
                size_bytes: 64 + u64::try_from(role.len()).unwrap_or(0),
                id,
                role: role.clone(),
                corresponds_to: None,
            }
        })
        .collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    let role_ids = artifacts
        .iter()
        .map(|artifact| (artifact.role.clone(), artifact.id.clone()))
        .collect::<BTreeMap<_, _>>();
    let source_value = artifacts
        .iter()
        .find(|artifact| artifact.role == "source")
        .map(|artifact| (artifact.sha256.clone(), artifact.size_bytes));
    for artifact in &mut artifacts {
        match artifact.role.as_str() {
            "bound" => artifact.corresponds_to = role_ids.get("generated").cloned(),
            "reproduced" => {
                artifact.corresponds_to = role_ids.get("source").cloned();
                if let Some((sha256, size_bytes)) = &source_value {
                    artifact.sha256.clone_from(sha256);
                    artifact.size_bytes = *size_bytes;
                }
            }
            _ => {}
        }
    }

    let roles = model.specification_roles.clone();
    let suite_payload = json!({"profile": profile.id, "roles": roles});
    let suite_identity = hash_value("proofbound-research-specification-suite/2", &suite_payload)?;
    let adequacy_payload = json!({
        "killed_mutants": 6,
        "required_mutants": 6,
        "suite_identity": suite_identity,
    });
    let adequacy_identity = hash_value(
        "proofbound-research-specification-adequacy/2",
        &adequacy_payload,
    )?;
    let specification = AssuranceV2Specification {
        id: spec_id.clone(),
        suite_identity,
        adequacy_identity,
        roles,
        required_mutants: 6,
        killed_mutants: 6,
    };
    let uncertainty = AssuranceV2Uncertainty {
        id: uncertainty_id.clone(),
        kind: profile.uncertainty.kind.clone(),
        consequence: profile.uncertainty.consequence.clone(),
        detail_sha256: sha256_bytes(uncertainty_id.as_bytes()),
    };
    let consumed_uncertainties = if uncertainty.consequence == "informational" {
        Vec::new()
    } else {
        vec![uncertainty.id.clone()]
    };
    let decision = AssuranceV2Decision {
        formal: family.formal.clone(),
        linkage: family.linkage.clone(),
        assumption: if uncertainty.consequence == "marks-assumed" {
            "assumed".to_owned()
        } else {
            "none".to_owned()
        },
        admitted: uncertainty.consequence != "blocks-admission",
        cache_eligible: profile.cache_eligible,
        consumed_uncertainties,
    };
    let evidence = AssuranceV2Evidence {
        id: evidence_id.clone(),
        family: profile.family.clone(),
        outcome: "passed".to_owned(),
        dependency_ids: dependencies.iter().map(|item| item.id.clone()).collect(),
        effect_ids: effects.iter().map(|item| item.id.clone()).collect(),
        artifact_ids: artifacts.iter().map(|item| item.id.clone()).collect(),
        specification_id: spec_id.clone(),
    };
    let changed_dependencies = vec![
        dependencies
            .first()
            .ok_or_else(|| invalid("IR2-DEPENDENCY-INCOMPLETE", "profile has no dependency"))?
            .id
            .clone(),
    ];
    let invalidated_evidence = vec![evidence_id.clone()];
    let invalidation_payload = json!({
        "changed_dependencies": changed_dependencies,
        "invalidated_evidence": invalidated_evidence,
    });
    let invalidation = AssuranceV2Invalidation {
        changed_dependencies,
        invalidated_evidence,
        identity: hash_value(
            "proofbound-research-invalidation-set/2",
            &invalidation_payload,
        )?,
    };
    let derivation = derive_derivation(
        profile,
        &evidence_id,
        &spec_id,
        &uncertainty_id,
        &decision,
        &suffix,
    )?;
    Ok(AssuranceV2Program {
        schema: ASSURANCE_V2_PROGRAM_SCHEMA.to_owned(),
        id: programme_id,
        claim: AssuranceV2Claim {
            id: claim_id,
            subject: format!("subject:{}", profile.id),
            specification_id: spec_id,
        },
        specification: Some(specification),
        dependencies,
        effects,
        artifacts,
        evidence,
        uncertainties: vec![uncertainty],
        invalidation,
        derivation,
        expected_decision: decision,
    })
}

pub fn validate_assurance_v2_program(
    model: &AssuranceV2Model,
    bytes: &[u8],
) -> Result<AssuranceV2KernelReport, AssuranceV2Error> {
    let value =
        decode_strict_json(bytes).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    let canonical =
        canonical_json(&value).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    if canonical != bytes {
        return Err(invalid(
            "IR2-NONCANONICAL",
            "programme is not canonical JSON",
        ));
    }
    let program: AssuranceV2Program =
        serde_json::from_value(value).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    validate_program(model, &program)?;
    derive_kernel_report(&program)
}

pub fn execute_assurance_v2_corpus(
    root: &Path,
    corpus_dir: &Path,
    repetitions: usize,
) -> Result<AssuranceV2ModelReport, AssuranceV2Error> {
    let (model, templates, attacks, generation) = load_assurance_v2_corpus(root, corpus_dir)?;
    if repetitions != generation.repetitions {
        return Err(invalid(
            "IR2-SCHEMA",
            "repetition count differs from corpus",
        ));
    }
    let mut report = derive_model_report(&model, &templates, &attacks, &generation)?;
    let stable_identity = report.identity.clone();
    report.repetition_report_identities = (0..repetitions)
        .map(|_| {
            derive_model_report(&model, &templates, &attacks, &generation)
                .map(|candidate| candidate.identity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if report
        .repetition_report_identities
        .iter()
        .any(|identity| identity != &stable_identity)
    {
        return Err(invalid("IR2-DECISION-MISMATCH", "model report is unstable"));
    }
    report.identity = model_report_identity(&report)?;
    Ok(report)
}

fn derive_model_report(
    model: &AssuranceV2Model,
    templates: &AssuranceV2Templates,
    attacks: &AssuranceV2AttackCorpus,
    generation: &AssuranceV2Generation,
) -> Result<AssuranceV2ModelReport, AssuranceV2Error> {
    let profiles = templates
        .profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut template_reports = Vec::new();
    for (index, profile) in templates.profiles.iter().enumerate() {
        let program = expand_assurance_v2_profile(model, profile, index)?;
        template_reports.push(validate_typed(model, &program)?);
    }
    let mut valid_rows = Vec::with_capacity(generation.valid_programs);
    for index in 0..generation.valid_programs {
        let profile = &templates.profiles[index % templates.profiles.len()];
        let program = expand_assurance_v2_profile(model, profile, index)?;
        let report = validate_typed(model, &program)?;
        valid_rows.push(json!({
            "index": index,
            "report_identity": report.identity,
            "semantic_identity": report.semantic_identity,
        }));
    }
    let mut attack_results = Vec::with_capacity(attacks.attacks.len());
    for (index, attack) in attacks.attacks.iter().enumerate() {
        let profile = profiles
            .get(attack.template.as_str())
            .ok_or_else(|| invalid("IR2-REFERENCE", "attack template is unknown"))?;
        let program = expand_assurance_v2_profile(model, profile, 900_000 + index)?;
        let actual = run_attack(model, &program, &attack.action)?;
        attack_results.push(AssuranceV2AttackResult {
            id: attack.id.clone(),
            expected_code: attack.expected.clone(),
            exact: actual == attack.expected,
            actual_code: actual,
        });
    }
    let mut adversarial_rows = Vec::with_capacity(generation.adversarial_programs);
    for index in 0..generation.adversarial_programs {
        let attack = &attacks.attacks[index % attacks.attacks.len()];
        let profile = profiles
            .get(attack.template.as_str())
            .ok_or_else(|| invalid("IR2-REFERENCE", "attack template is unknown"))?;
        let program = expand_assurance_v2_profile(model, profile, 500_000 + index)?;
        let actual = run_attack(model, &program, &attack.action)?;
        adversarial_rows.push(json!({
            "actual_code": actual,
            "attack": attack.id,
            "index": index,
        }));
    }
    let validation_code_coverage = attack_results
        .iter()
        .map(|result| result.actual_code.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut report = AssuranceV2ModelReport {
        schema: ASSURANCE_V2_MODEL_REPORT_SCHEMA.to_owned(),
        templates: template_reports,
        valid_programs: generation.valid_programs,
        valid_corpus_identity: hash_value(
            "proofbound-research-assurance-valid-corpus/2",
            &Value::Array(valid_rows),
        )?,
        adversarial_programs: generation.adversarial_programs,
        adversarial_corpus_identity: hash_value(
            "proofbound-research-assurance-adversarial-corpus/2",
            &Value::Array(adversarial_rows),
        )?,
        attacks: attack_results,
        constructor_coverage: model.object_constructors.clone(),
        validation_code_coverage,
        repetition_report_identities: Vec::new(),
        identity: String::new(),
    };
    report.identity = model_report_identity(&report)?;
    Ok(report)
}

fn validate_program(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<(), AssuranceV2Error> {
    if program.schema != ASSURANCE_V2_PROGRAM_SCHEMA {
        return Err(invalid("IR2-SCHEMA", "unsupported programme schema"));
    }
    for identifier in [
        program.id.as_str(),
        program.claim.id.as_str(),
        program.evidence.id.as_str(),
    ] {
        validate_id(identifier)?;
    }
    let groups = [
        program
            .dependencies
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        program
            .effects
            .iter()
            .map(|item| item.id.as_str())
            .collect(),
        program
            .artifacts
            .iter()
            .map(|item| item.id.as_str())
            .collect(),
        program
            .uncertainties
            .iter()
            .map(|item| item.id.as_str())
            .collect(),
    ];
    let mut all = BTreeSet::new();
    for group in groups {
        let mut local = BTreeSet::new();
        for identifier in group {
            if !local.insert(identifier) {
                return Err(invalid("IR2-DUPLICATE", "duplicate identity"));
            }
            if !all.insert(identifier) {
                return Err(invalid("IR2-ALIAS", "typed identities alias"));
            }
        }
    }
    require_sorted_unique(&program.dependencies, |item| &item.id)?;
    require_sorted_unique(&program.effects, |item| &item.id)?;
    require_sorted_unique(&program.artifacts, |item| &item.id)?;
    require_sorted_unique(&program.uncertainties, |item| &item.id)?;
    validate_dependencies(program)?;
    validate_effects(model, program)?;
    validate_specification(model, program)?;
    validate_artifacts(model, program)?;
    validate_uncertainty(model, program)?;
    validate_family(model, program)?;
    validate_invalidation(program)?;
    validate_derivation(program)?;
    let expected = derive_decision(model, program)?;
    if program.expected_decision.linkage == "artifact-bound" && expected.linkage != "artifact-bound"
    {
        return Err(invalid(
            "IR2-DECISION-UPGRADE",
            "artifact linkage lacks correspondence evidence",
        ));
    }
    if program.expected_decision != expected {
        return Err(invalid("IR2-DECISION-MISMATCH", "decision is not derived"));
    }
    Ok(())
}

fn validate_dependencies(program: &AssuranceV2Program) -> Result<(), AssuranceV2Error> {
    let ids = program
        .dependencies
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    for dependency in &program.dependencies {
        validate_id(&dependency.id)?;
        validate_sha(&dependency.identity)?;
        if !dependency.declared || !dependency.observed {
            return Err(invalid(
                "IR2-DEPENDENCY-INCOMPLETE",
                "dependency is not both declared and observed",
            ));
        }
    }
    for reference in &program.evidence.dependency_ids {
        if !ids.contains(reference) {
            return Err(invalid(
                "IR2-DEPENDENCY-MISSING",
                "dependency reference is missing",
            ));
        }
    }
    if program.evidence.dependency_ids != ids {
        return Err(invalid(
            "IR2-DEPENDENCY-BINDING",
            "evidence does not bind the exact dependency set",
        ));
    }
    Ok(())
}

fn validate_effects(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<(), AssuranceV2Error> {
    let ids = program
        .effects
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    for reference in &program.evidence.effect_ids {
        if !ids.contains(reference) {
            return Err(invalid("IR2-EFFECT-MISSING", "effect reference is missing"));
        }
    }
    if program.evidence.effect_ids != ids {
        return Err(invalid(
            "IR2-EFFECT-MISSING",
            "evidence does not bind every effect",
        ));
    }
    for effect in &program.effects {
        if !model.effect_capabilities.contains(&effect.capability)
            || !model.effect_boundaries.contains(&effect.boundary)
        {
            return Err(invalid("IR2-SCHEMA", "unknown effect value"));
        }
        if !matches!(effect.disposition.as_str(), "observed" | "unused") {
            return Err(invalid("IR2-EFFECT-DISPOSITION", "effect is unresolved"));
        }
        if effect.boundary == "statically-denied" && effect.disposition != "unused" {
            return Err(invalid(
                "IR2-EFFECT-DISPOSITION",
                "denied effect was observed",
            ));
        }
        if effect.boundary == "externally-enforced" {
            let Some(reference) = &effect.enforcement_dependency else {
                return Err(invalid("IR2-EFFECT-ENFORCEMENT", "enforcement is absent"));
            };
            if !program
                .dependencies
                .iter()
                .any(|item| &item.id == reference && item.role == "external-contract")
            {
                return Err(invalid("IR2-EFFECT-ENFORCEMENT", "enforcement is unbound"));
            }
        } else if effect.enforcement_dependency.is_some() {
            return Err(invalid(
                "IR2-EFFECT-OPAQUE",
                "non-external effect carries enforcement",
            ));
        }
    }
    if program.effects.iter().any(|item| item.boundary == "opaque")
        && program.expected_decision.cache_eligible
    {
        return Err(invalid(
            "IR2-CACHE-INELIGIBLE",
            "opaque execution is reusable",
        ));
    }
    Ok(())
}

fn validate_specification(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<(), AssuranceV2Error> {
    let family = family(model, &program.evidence.family)?;
    let Some(specification) = &program.specification else {
        if family.requires_specification {
            return Err(invalid(
                "IR2-SPECIFICATION-MISSING",
                "specification is absent",
            ));
        }
        return Ok(());
    };
    if specification.id != program.claim.specification_id
        || specification.id != program.evidence.specification_id
    {
        return Err(invalid(
            "IR2-SPECIFICATION-MISSING",
            "specification reference differs",
        ));
    }
    if specification.roles != model.specification_roles {
        return Err(invalid("IR2-ORDER", "specification roles are noncanonical"));
    }
    if specification.required_mutants != 6
        || specification.killed_mutants != specification.required_mutants
    {
        return Err(invalid(
            "IR2-SPECIFICATION-INADEQUATE",
            "required semantic mutant survived",
        ));
    }
    let suite_payload =
        json!({"profile": profile_from_program(&program.id)?, "roles": specification.roles});
    let expected_suite = hash_value("proofbound-research-specification-suite/2", &suite_payload)?;
    let adequacy_payload = json!({
        "killed_mutants": specification.killed_mutants,
        "required_mutants": specification.required_mutants,
        "suite_identity": specification.suite_identity,
    });
    let expected_adequacy = hash_value(
        "proofbound-research-specification-adequacy/2",
        &adequacy_payload,
    )?;
    if specification.suite_identity != expected_suite
        || specification.adequacy_identity != expected_adequacy
    {
        return Err(invalid(
            "IR2-SPECIFICATION-BINDING",
            "specification identity differs",
        ));
    }
    Ok(())
}

fn validate_artifacts(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<(), AssuranceV2Error> {
    let family = family(model, &program.evidence.family)?;
    let roles = program
        .artifacts
        .iter()
        .map(|item| item.role.clone())
        .collect::<Vec<_>>();
    if roles != family.required_artifact_roles {
        return Err(invalid("IR2-ARTIFACT-ROLE", "artifact roles differ"));
    }
    let ids = program
        .artifacts
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    if program.evidence.artifact_ids != ids {
        return Err(invalid(
            "IR2-ARTIFACT-ROLE",
            "evidence artifact set differs",
        ));
    }
    let by_role = program
        .artifacts
        .iter()
        .map(|item| (item.role.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    for artifact in &program.artifacts {
        validate_sha(&artifact.sha256)?;
        match artifact.role.as_str() {
            "bound" => {
                if artifact.corresponds_to.as_deref()
                    != by_role.get("generated").map(|item| item.id.as_str())
                {
                    return Err(invalid(
                        "IR2-ARTIFACT-BINDING",
                        "bound artifact is unjoined",
                    ));
                }
            }
            "reproduced" => {
                let source = by_role.get("source").ok_or_else(|| {
                    invalid("IR2-ARTIFACT-BINDING", "reproduction source is absent")
                })?;
                if artifact.corresponds_to.as_deref() != Some(source.id.as_str())
                    || artifact.sha256 != source.sha256
                    || artifact.size_bytes != source.size_bytes
                {
                    return Err(invalid("IR2-ARTIFACT-BINDING", "reproduction differs"));
                }
            }
            _ if artifact.corresponds_to.is_some() => {
                return Err(invalid("IR2-ARTIFACT-BINDING", "unexpected correspondence"));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_uncertainty(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<(), AssuranceV2Error> {
    let Some(uncertainty) = program.uncertainties.first() else {
        return Err(invalid(
            "IR2-UNCERTAINTY-MISSING",
            "uncertainty record is absent",
        ));
    };
    if program.uncertainties.len() != 1 {
        return Err(invalid("IR2-DUPLICATE", "expected one uncertainty"));
    }
    let expected = model
        .uncertainties
        .iter()
        .find(|item| item.kind == uncertainty.kind)
        .ok_or_else(|| invalid("IR2-UNCERTAINTY-KIND", "unknown uncertainty kind"))?;
    if uncertainty.consequence != expected.consequence {
        return Err(invalid(
            "IR2-UNCERTAINTY-KIND",
            "uncertainty consequence differs",
        ));
    }
    let consumed = &program.expected_decision.consumed_uncertainties;
    if uncertainty.consequence == "informational" {
        if !consumed.is_empty() {
            return Err(invalid(
                "IR2-UNCERTAINTY-CONSEQUENCE",
                "informational uncertainty was consumed",
            ));
        }
    } else if consumed != &vec![uncertainty.id.clone()] {
        return Err(invalid(
            "IR2-UNCERTAINTY-CONSEQUENCE",
            "load-bearing uncertainty is not consumed",
        ));
    }
    Ok(())
}

fn validate_family(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<(), AssuranceV2Error> {
    let family = family(model, &program.evidence.family)?;
    if program.evidence.outcome != "passed" {
        return Err(invalid("IR2-FAMILY-COERCION", "evidence did not pass"));
    }
    if program.expected_decision.linkage == "artifact-bound" && family.linkage != "artifact-bound" {
        return Err(invalid(
            "IR2-DECISION-UPGRADE",
            "artifact linkage lacks correspondence evidence",
        ));
    }
    if program.expected_decision.formal != family.formal
        || program.expected_decision.linkage != family.linkage
    {
        return Err(invalid(
            "IR2-FAMILY-COERCION",
            "family facet was strengthened",
        ));
    }
    Ok(())
}

fn validate_invalidation(program: &AssuranceV2Program) -> Result<(), AssuranceV2Error> {
    let expected_changed = vec![
        program
            .dependencies
            .first()
            .ok_or_else(|| invalid("IR2-DEPENDENCY-INCOMPLETE", "no dependency exists"))?
            .id
            .clone(),
    ];
    let expected_evidence = vec![program.evidence.id.clone()];
    let payload = json!({
        "changed_dependencies": expected_changed,
        "invalidated_evidence": expected_evidence,
    });
    let identity = hash_value("proofbound-research-invalidation-set/2", &payload)?;
    if program.invalidation.changed_dependencies != expected_changed
        || program.invalidation.invalidated_evidence != expected_evidence
        || program.invalidation.identity != identity
    {
        return Err(invalid(
            "IR2-INVALIDATION",
            "invalidation projection differs",
        ));
    }
    Ok(())
}

fn validate_derivation(program: &AssuranceV2Program) -> Result<(), AssuranceV2Error> {
    let suffix = suffix_from_program(&program.id)?;
    let profile = profile_from_program(&program.id)?;
    let expected = derive_derivation(
        &AssuranceV2Profile {
            id: profile.to_owned(),
            family: program.evidence.family.clone(),
            dependency_roles: Vec::new(),
            effects: Vec::new(),
            artifact_roles: Vec::new(),
            uncertainty: ProfileUncertainty {
                kind: program.uncertainties[0].kind.clone(),
                consequence: program.uncertainties[0].consequence.clone(),
            },
            cache_eligible: program.expected_decision.cache_eligible,
        },
        &program.evidence.id,
        &program.evidence.specification_id,
        &program.uncertainties[0].id,
        &program.expected_decision,
        suffix,
    )?;
    if program.derivation.root != expected.root {
        return Err(invalid("IR2-DERIVATION-ROOT", "derivation root differs"));
    }
    if program.derivation.steps != expected.steps {
        return Err(invalid(
            "IR2-DERIVATION-DEPENDENCY",
            "derivation dependencies differ",
        ));
    }
    if program.derivation.identity != expected.identity {
        return Err(invalid(
            "IR2-DERIVATION-IDENTITY",
            "derivation identity differs",
        ));
    }
    Ok(())
}

fn derive_decision(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<AssuranceV2Decision, AssuranceV2Error> {
    let family = family(model, &program.evidence.family)?;
    let uncertainty = program
        .uncertainties
        .first()
        .ok_or_else(|| invalid("IR2-UNCERTAINTY-MISSING", "uncertainty is absent"))?;
    Ok(AssuranceV2Decision {
        formal: family.formal.clone(),
        linkage: family.linkage.clone(),
        assumption: if uncertainty.consequence == "marks-assumed" {
            "assumed".to_owned()
        } else {
            "none".to_owned()
        },
        admitted: uncertainty.consequence != "blocks-admission",
        cache_eligible: !program.effects.iter().any(|item| item.boundary == "opaque"),
        consumed_uncertainties: if uncertainty.consequence == "informational" {
            Vec::new()
        } else {
            vec![uncertainty.id.clone()]
        },
    })
}

fn derive_derivation(
    profile: &AssuranceV2Profile,
    evidence_id: &str,
    specification_id: &str,
    uncertainty_id: &str,
    decision: &AssuranceV2Decision,
    suffix: &str,
) -> Result<AssuranceV2Derivation, AssuranceV2Error> {
    let prefix = format!("step:{}:{suffix}", profile.id);
    let evidence_step = format!("{prefix}:01-evidence");
    let family_step = format!("{prefix}:02-family");
    let uncertainty_step = format!("{prefix}:03-uncertainty");
    let admission_step = format!("{prefix}:04-admission");
    let steps = vec![
        AssuranceV2Step {
            id: evidence_step.clone(),
            rule: "evidence-valid".to_owned(),
            inputs: vec![evidence_id.to_owned()],
            conclusion: "evidence=valid".to_owned(),
        },
        AssuranceV2Step {
            id: family_step.clone(),
            rule: "family-facet".to_owned(),
            inputs: vec![evidence_step.clone(), specification_id.to_owned()],
            conclusion: format!("formal={};linkage={}", decision.formal, decision.linkage),
        },
        AssuranceV2Step {
            id: uncertainty_step.clone(),
            rule: "uncertainty-evaluated".to_owned(),
            inputs: vec![uncertainty_id.to_owned()],
            conclusion: format!(
                "assumption={};admitted={}",
                decision.assumption, decision.admitted
            ),
        },
        AssuranceV2Step {
            id: admission_step.clone(),
            rule: "admission-decided".to_owned(),
            inputs: vec![family_step, uncertainty_step],
            conclusion: decision_text(decision),
        },
    ];
    let payload = json!({"root": admission_step, "steps": steps});
    Ok(AssuranceV2Derivation {
        steps,
        root: admission_step,
        identity: hash_value("proofbound-research-derivation-trace/2", &payload)?,
    })
}

fn derive_kernel_report(
    program: &AssuranceV2Program,
) -> Result<AssuranceV2KernelReport, AssuranceV2Error> {
    let semantic_identity = hash_value(
        "proofbound-research-assurance-program/2",
        &serde_json::to_value(program).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?,
    )?;
    let dependency_identity = hash_value(
        "proofbound-research-dependency-projection/2",
        &serde_json::to_value(&program.dependencies)
            .map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?,
    )?;
    let mut report = AssuranceV2KernelReport {
        schema: ASSURANCE_V2_REPORT_SCHEMA.to_owned(),
        programme: program.id.clone(),
        semantic_identity,
        dependency_identity,
        invalidation_identity: program.invalidation.identity.clone(),
        derivation_identity: program.derivation.identity.clone(),
        decision: program.expected_decision.clone(),
        consumed_uncertainties: program.expected_decision.consumed_uncertainties.clone(),
        cache_eligible: program.expected_decision.cache_eligible,
        identity: String::new(),
    };
    report.identity = kernel_report_identity(&report)?;
    Ok(report)
}

fn run_attack(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
    action: &str,
) -> Result<String, AssuranceV2Error> {
    let mut value =
        serde_json::to_value(program).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    mutate(&mut value, action)?;
    let mut bytes =
        canonical_json(&value).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    if action == "noncanonical-bytes" {
        bytes.push(b'\n');
    }
    Ok(match validate_assurance_v2_program(model, &bytes) {
        Ok(_) => "IR2-ACCEPTED".to_owned(),
        Err(error) => error.code.to_owned(),
    })
}

fn mutate(value: &mut Value, action: &str) -> Result<(), AssuranceV2Error> {
    let root = value
        .as_object_mut()
        .ok_or_else(|| invalid("IR2-SCHEMA", "programme root is not an object"))?;
    match action {
        "replace-schema" => root.insert(
            "schema".to_owned(),
            json!("proofbound-research-assurance-program/3"),
        ),
        "noncanonical-bytes" => None,
        "duplicate-dependency" => {
            let dependencies = array_mut(root, "dependencies")?;
            dependencies.push(dependencies[0].clone());
            None
        }
        "alias-dependency-artifact" => {
            let id = array_mut(root, "dependencies")?[0]["id"].clone();
            array_mut(root, "artifacts")?[0]["id"] = id;
            None
        }
        "remove-dependency" => {
            array_mut(root, "dependencies")?.remove(0);
            None
        }
        "substitute-dependency-reference" => {
            let dependencies = array_mut(root, "dependencies")?;
            let replacement = dependencies[1]["id"].clone();
            root.get_mut("evidence")
                .and_then(Value::as_object_mut)
                .and_then(|evidence| evidence.get_mut("dependency_ids"))
                .and_then(Value::as_array_mut)
                .ok_or_else(|| invalid("IR2-SCHEMA", "dependency references are absent"))?[0] =
                replacement;
            None
        }
        "mark-dependency-unobserved" => {
            array_mut(root, "dependencies")?[0]["observed"] = json!(false);
            None
        }
        "forge-invalidation-identity" => {
            replace_nested(root, &["invalidation", "identity"], json!(zero_sha()))?
        }
        "enable-opaque-cache" => {
            replace_nested(root, &["expected_decision", "cache_eligible"], json!(true))?
        }
        "remove-effect" => {
            array_mut(root, "effects")?.remove(0);
            None
        }
        "unresolve-effect-disposition" => {
            array_mut(root, "effects")?[0]["disposition"] = json!("unresolved");
            None
        }
        "forge-external-enforcement" => {
            let effects = array_mut(root, "effects")?;
            let effect = effects
                .iter_mut()
                .find(|item| item["boundary"] == "externally-enforced")
                .ok_or_else(|| invalid("IR2-SCHEMA", "external effect is absent"))?;
            effect["enforcement_dependency"] = json!("dependency:forged:external-contract:000000");
            None
        }
        "retain-enforcement-on-opaque" => {
            let effects = array_mut(root, "effects")?;
            let effect = effects
                .iter_mut()
                .find(|item| item["boundary"] == "externally-enforced")
                .ok_or_else(|| invalid("IR2-SCHEMA", "external effect is absent"))?;
            effect["boundary"] = json!("opaque");
            None
        }
        "remove-specification" => root.insert("specification".to_owned(), Value::Null),
        "forge-adequacy-identity" => replace_nested(
            root,
            &["specification", "adequacy_identity"],
            json!(zero_sha()),
        )?,
        "leave-mutant-alive" => {
            replace_nested(root, &["specification", "killed_mutants"], json!(5))?
        }
        "substitute-artifact-role" => {
            array_mut(root, "artifacts")?[0]["role"] = json!("sealed");
            None
        }
        "remove-artifact-correspondence" => {
            let artifacts = array_mut(root, "artifacts")?;
            let bound = artifacts
                .iter_mut()
                .find(|item| item["role"] == "bound")
                .ok_or_else(|| invalid("IR2-SCHEMA", "bound artifact is absent"))?;
            bound["corresponds_to"] = Value::Null;
            None
        }
        "remove-uncertainty" => {
            array_mut(root, "uncertainties")?.clear();
            None
        }
        "coerce-telemetry-to-assumption" => {
            array_mut(root, "uncertainties")?[0]["kind"] = json!("assumption");
            None
        }
        "omit-consumed-uncertainty" => replace_nested(
            root,
            &["expected_decision", "consumed_uncertainties"],
            json!([]),
        )?,
        "substitute-derivation-input" => {
            let steps = root
                .get_mut("derivation")
                .and_then(Value::as_object_mut)
                .and_then(|derivation| derivation.get_mut("steps"))
                .and_then(Value::as_array_mut)
                .ok_or_else(|| invalid("IR2-SCHEMA", "derivation steps are absent"))?;
            steps[1]["inputs"][0] = json!("step:substituted");
            None
        }
        "replace-derivation-root" => {
            replace_nested(root, &["derivation", "root"], json!("step:substituted"))?
        }
        "forge-derivation-identity" => {
            replace_nested(root, &["derivation", "identity"], json!(zero_sha()))?
        }
        "upgrade-formal-facet" => {
            replace_nested(root, &["expected_decision", "formal"], json!("proved"))?
        }
        "upgrade-transcription-linkage" => {
            replace_nested(root, &["expected_decision", "linkage"], json!("refined"))?
        }
        "upgrade-artifact-linkage" => replace_nested(
            root,
            &["expected_decision", "linkage"],
            json!("artifact-bound"),
        )?,
        "replace-derived-decision" => {
            replace_nested(root, &["expected_decision", "admitted"], json!(true))?
        }
        _ => {
            return Err(invalid(
                "IR2-SCHEMA",
                format!("unknown attack action {action}"),
            ));
        }
    };
    if action == "replace-derived-decision" {
        rewrite_derivation_for_decision(value)?;
    }
    Ok(())
}

fn rewrite_derivation_for_decision(value: &mut Value) -> Result<(), AssuranceV2Error> {
    let program: AssuranceV2Program = serde_json::from_value(value.clone())
        .map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    let profile = profile_from_program(&program.id)?;
    let suffix = suffix_from_program(&program.id)?;
    let derivation = derive_derivation(
        &AssuranceV2Profile {
            id: profile.to_owned(),
            family: program.evidence.family.clone(),
            dependency_roles: Vec::new(),
            effects: Vec::new(),
            artifact_roles: Vec::new(),
            uncertainty: ProfileUncertainty {
                kind: program.uncertainties[0].kind.clone(),
                consequence: program.uncertainties[0].consequence.clone(),
            },
            cache_eligible: program.expected_decision.cache_eligible,
        },
        &program.evidence.id,
        &program.evidence.specification_id,
        &program.uncertainties[0].id,
        &program.expected_decision,
        suffix,
    )?;
    value["derivation"] = serde_json::to_value(derivation)
        .map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    Ok(())
}

fn validate_corpus(
    model: &AssuranceV2Model,
    templates: &AssuranceV2Templates,
    attacks: &AssuranceV2AttackCorpus,
    generation: &AssuranceV2Generation,
) -> Result<(), AssuranceV2Error> {
    if model.schema != MODEL_SCHEMA
        || model.program_schema != ASSURANCE_V2_PROGRAM_SCHEMA
        || model.report_schema != ASSURANCE_V2_REPORT_SCHEMA
        || templates.schema != TEMPLATES_SCHEMA
        || attacks.schema != ATTACKS_SCHEMA
        || generation.schema != GENERATION_SCHEMA
        || generation.algorithm != "proofbound-exp-0015-generator/1"
    {
        return Err(invalid("IR2-SCHEMA", "corpus schema differs"));
    }
    for values in [
        &model.dependency_roles,
        &model.effect_capabilities,
        &model.effect_boundaries,
        &model.artifact_roles,
        &model.specification_roles,
        &model.derivation_rules,
        &model.object_constructors,
        &model.validation_codes,
    ] {
        require_text_sorted_unique(values)?;
    }
    require_sorted_unique(&model.families, |item| &item.id)?;
    require_sorted_unique(&model.uncertainties, |item| &item.kind)?;
    require_sorted_unique(&templates.profiles, |item| &item.id)?;
    require_sorted_unique(&attacks.attacks, |item| &item.id)?;
    if templates.profiles.len() != 6
        || attacks.attacks.len() != 28
        || generation.valid_programs != 500
        || generation.adversarial_programs != 500
        || generation.repetitions != 10
        || generation.mutation_cardinality != 1
        || generation.seed != 151_510
    {
        return Err(invalid("IR2-SCHEMA", "frozen corpus cardinality differs"));
    }
    for profile in &templates.profiles {
        family(model, &profile.family)?;
        require_text_sorted_unique(&profile.dependency_roles)?;
        require_text_sorted_unique(&profile.artifact_roles)?;
        require_sorted_unique(&profile.effects, |item| &item.capability)?;
        if !model.uncertainties.iter().any(|item| {
            item.kind == profile.uncertainty.kind
                && item.consequence == profile.uncertainty.consequence
        }) {
            return Err(invalid(
                "IR2-UNCERTAINTY-KIND",
                "profile uncertainty differs",
            ));
        }
        let has_opaque = profile.effects.iter().any(|item| item.boundary == "opaque");
        if profile.cache_eligible == has_opaque {
            return Err(invalid(
                "IR2-CACHE-INELIGIBLE",
                "profile cache policy differs",
            ));
        }
    }
    let profile_ids = templates
        .profiles
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    for attack in &attacks.attacks {
        if !profile_ids.contains(attack.template.as_str())
            || !model.validation_codes.contains(&attack.expected)
        {
            return Err(invalid("IR2-REFERENCE", "attack registration differs"));
        }
    }
    Ok(())
}

fn validate_typed(
    model: &AssuranceV2Model,
    program: &AssuranceV2Program,
) -> Result<AssuranceV2KernelReport, AssuranceV2Error> {
    let bytes =
        canonical_json(program).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?;
    validate_assurance_v2_program(model, &bytes)
}

fn family<'a>(
    model: &'a AssuranceV2Model,
    identifier: &str,
) -> Result<&'a FamilyDefinition, AssuranceV2Error> {
    model
        .families
        .iter()
        .find(|item| item.id == identifier)
        .ok_or_else(|| invalid("IR2-FAMILY-COERCION", "unknown evidence family"))
}

fn require_sorted_unique<T, F>(values: &[T], key: F) -> Result<(), AssuranceV2Error>
where
    F: Fn(&T) -> &String,
{
    let keys = values.iter().map(key).collect::<Vec<_>>();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("IR2-DUPLICATE", "duplicate identity"));
    }
    if keys.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(invalid("IR2-ORDER", "collection is not lexical"));
    }
    Ok(())
}

fn require_text_sorted_unique(values: &[String]) -> Result<(), AssuranceV2Error> {
    require_sorted_unique(values, |item| item)
}

fn validate_id(value: &str) -> Result<(), AssuranceV2Error> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":-".contains(&byte))
    {
        return Err(invalid("IR2-IDENTIFIER", "identifier is not canonical"));
    }
    Ok(())
}

fn validate_sha(value: &str) -> Result<(), AssuranceV2Error> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid("IR2-IDENTIFIER", "identity is not SHA-256"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "IR2-IDENTIFIER",
            "identity is not canonical SHA-256",
        ));
    }
    Ok(())
}

fn hash_value(domain: &str, value: &Value) -> Result<String, AssuranceV2Error> {
    canonical_json(value)
        .map(|bytes| domain_hash(domain, &bytes))
        .map_err(|error| invalid("IR2-SCHEMA", error.to_string()))
}

fn kernel_report_identity(report: &AssuranceV2KernelReport) -> Result<String, AssuranceV2Error> {
    let mut candidate = report.clone();
    candidate.identity.clear();
    hash_value(
        ASSURANCE_V2_REPORT_SCHEMA,
        &serde_json::to_value(candidate)
            .map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?,
    )
}

fn model_report_identity(report: &AssuranceV2ModelReport) -> Result<String, AssuranceV2Error> {
    let mut candidate = report.clone();
    candidate.identity.clear();
    candidate.repetition_report_identities.clear();
    hash_value(
        ASSURANCE_V2_MODEL_REPORT_SCHEMA,
        &serde_json::to_value(candidate)
            .map_err(|error| invalid("IR2-SCHEMA", error.to_string()))?,
    )
}

fn decision_text(decision: &AssuranceV2Decision) -> String {
    format!(
        "formal={};linkage={};assumption={};admitted={};cache={}",
        decision.formal,
        decision.linkage,
        decision.assumption,
        decision.admitted,
        decision.cache_eligible
    )
}

fn profile_from_program(value: &str) -> Result<&str, AssuranceV2Error> {
    let rest = value
        .strip_prefix("programme:")
        .ok_or_else(|| invalid("IR2-IDENTIFIER", "programme prefix differs"))?;
    rest.rsplit_once(':')
        .map(|(profile, _)| profile)
        .ok_or_else(|| invalid("IR2-IDENTIFIER", "programme suffix is absent"))
}

fn suffix_from_program(value: &str) -> Result<&str, AssuranceV2Error> {
    value
        .rsplit_once(':')
        .map(|(_, suffix)| suffix)
        .ok_or_else(|| invalid("IR2-IDENTIFIER", "programme suffix is absent"))
}

fn decode_file<T: for<'de> Deserialize<'de>>(
    root: &Path,
    path: &Path,
) -> Result<T, AssuranceV2Error> {
    let bytes = fs::read(root.join(path))
        .map_err(|error| invalid("IR2-SCHEMA", format!("{}: {error}", path.display())))?;
    serde_json::from_slice(&bytes).map_err(|error| invalid("IR2-SCHEMA", error.to_string()))
}

fn array_mut<'a>(
    root: &'a mut serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a mut Vec<Value>, AssuranceV2Error> {
    root.get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("IR2-SCHEMA", format!("{field} is not an array")))
}

fn replace_nested(
    root: &mut serde_json::Map<String, Value>,
    path: &[&str],
    value: Value,
) -> Result<Option<Value>, AssuranceV2Error> {
    let mut current = root
        .get_mut(path[0])
        .ok_or_else(|| invalid("IR2-SCHEMA", "nested object is absent"))?;
    for field in &path[1..path.len() - 1] {
        current = current
            .get_mut(*field)
            .ok_or_else(|| invalid("IR2-SCHEMA", "nested field is absent"))?;
    }
    current
        .as_object_mut()
        .ok_or_else(|| invalid("IR2-SCHEMA", "nested value is not an object"))
        .map(|object| object.insert(path[path.len() - 1].to_owned(), value))
}

fn zero_sha() -> &'static str {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> &'static Path {
        Path::new("../../docs/experiments/0015-assurance-ir-differential-kernel/corpus")
    }

    #[test]
    fn frozen_corpus_executes_every_case_and_attack() {
        let report = execute_assurance_v2_corpus(Path::new("."), corpus(), 10)
            .expect("frozen corpus should execute");
        assert_eq!(report.templates.len(), 6);
        assert_eq!(report.valid_programs, 500);
        assert_eq!(report.adversarial_programs, 500);
        assert_eq!(report.attacks.len(), 28);
        assert!(report.attacks.iter().all(|result| result.exact));
        assert_eq!(report.repetition_report_identities.len(), 10);
        assert_eq!(
            report
                .repetition_report_identities
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            1
        );
    }

    #[test]
    fn decision_upgrade_rejects_after_self_consistent_encoding() {
        let (model, templates, _, _) =
            load_assurance_v2_corpus(Path::new("."), corpus()).expect("corpus should load");
        let theorem = templates
            .profiles
            .iter()
            .find(|profile| profile.id == "theorem-with-assumption")
            .expect("theorem profile");
        let program = expand_assurance_v2_profile(&model, theorem, 42).expect("programme");
        assert_eq!(
            run_attack(&model, &program, "upgrade-artifact-linkage").expect("attack"),
            "IR2-DECISION-UPGRADE"
        );
    }
}
