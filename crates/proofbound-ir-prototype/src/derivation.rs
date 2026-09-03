use std::{collections::BTreeMap, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assurance::decode_strict_json;

const PROGRAM_SCHEMA: &str = "proofbound-derivation-program/1";
const FACT_SCHEMA: &str = "proofbound-derivation-fact/1";
const STEP_SCHEMA: &str = "proofbound-derivation-step/1";
const JUDGMENT_SCHEMA: &str = "proofbound-derivation-judgment/1";
const TRACE_DOMAIN: &str = "proofbound-derivation-trace/1";
const GENERATED_SCHEMA: &str = "proofbound-generated-derivation-corpus/1";
const GENERATOR_ALGORITHM: &str = "proofbound-exp-0009-generator/1";
const GENERATOR_SEED: u64 = 9009;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationError {
    pub code: &'static str,
    pub message: String,
}

impl DerivationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DerivationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DerivationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationProgram {
    schema: String,
    claim_id: String,
    facts: Vec<Fact>,
    steps: Vec<Step>,
    conclusion: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Fact {
    schema: String,
    id: String,
    authority: Authority,
    proposition: Proposition,
    sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Authority {
    Registered,
    Observed,
    Reviewed,
    Derived,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Proposition {
    EvidencePassed {
        evidence_id: String,
        family: EvidenceFamily,
    },
    BindingMatches {
        theorem_id: String,
        artifact_id: String,
    },
    AssumptionOpen {
        assumption_id: String,
    },
    PolicyRegistered {
        policy_id: String,
        required_formal: FormalFacet,
        required_linkage: LinkageFacet,
        allow_assumptions: bool,
    },
    Telemetry {
        name: String,
        value: u64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceFamily {
    SampledProperty,
    BoundedCheck,
    Theorem,
    MutationWitness,
    TrustedTranscription,
    ArtifactBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Step {
    schema: String,
    id: String,
    rule: Rule,
    inputs: Vec<String>,
    conclusion: Judgment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Rule {
    EvidenceValid,
    SampledTested,
    BoundedTested,
    TheoremProved,
    MutationTested,
    TranscriptionOpen,
    ModelLinked,
    TranscriptionLinked,
    ArtifactBound,
    AssumptionFacet,
    PolicyAdmitted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Judgment {
    EvidenceValid {
        schema: String,
        evidence_id: String,
        family: EvidenceFamily,
    },
    Formal {
        schema: String,
        value: FormalFacet,
    },
    Linkage {
        schema: String,
        value: LinkageFacet,
    },
    Assumption {
        schema: String,
        value: AssumptionFacet,
    },
    Status {
        schema: String,
        formal: FormalFacet,
        linkage: LinkageFacet,
        assumption: AssumptionFacet,
        policy: PolicyDecision,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FormalFacet {
    Open,
    Tested,
    Proved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum LinkageFacet {
    ModelOnly,
    Transcribed,
    ArtifactBound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AssumptionFacet {
    None,
    Assumed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PolicyDecision {
    Admitted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DerivationReport {
    pub schema: String,
    pub claim_id: String,
    pub conclusion: Value,
    pub trace_identity: String,
    pub alerts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateCorpus {
    schema: String,
    templates: Vec<Template>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Template {
    id: String,
    route: EvidenceFamily,
    family: EvidenceFamily,
    formal: FormalFacet,
    linkage: LinkageFacet,
    assumption: AssumptionFacet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedCorpus {
    pub schema: String,
    pub algorithm: String,
    pub seed: u64,
    pub valid: Vec<GeneratedValidCase>,
    pub adversarial: Vec<GeneratedAdversarialCase>,
    pub corpus_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedValidCase {
    pub id: String,
    pub program: Value,
    pub expected_trace_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedAdversarialCase {
    pub id: String,
    pub attack: String,
    pub encoding: String,
    pub program: Value,
    pub expected: String,
}

pub fn validate_derivation_program(bytes: &[u8]) -> Result<DerivationReport, DerivationError> {
    let value = decode_program_value(bytes)?;
    validate_derivation_value(&value)
}

pub fn generate_derivation_corpus(
    templates_path: &Path,
    count: usize,
) -> Result<GeneratedCorpus, DerivationError> {
    if count == 0 || count > 10_000 {
        return Err(DerivationError::new(
            "derivation-generation-invalid",
            "generated corpus count must be between 1 and 10000",
        ));
    }
    let bytes = fs::read(templates_path).map_err(generation_error)?;
    let templates: TemplateCorpus = serde_json::from_slice(&bytes).map_err(generation_error)?;
    validate_templates(&templates)?;

    let mut valid = Vec::with_capacity(count);
    let mut adversarial = Vec::with_capacity(count);
    for index in 0..count {
        let template = &templates.templates[index % templates.templates.len()];
        let program = build_program(template, index);
        let program_value = serde_json::to_value(&program).map_err(generation_error)?;
        let report = validate_derivation_value(&program_value)?;
        valid.push(GeneratedValidCase {
            id: format!("EXP-0009-V{index:04}"),
            program: program_value,
            expected_trace_identity: report.trace_identity,
        });

        let attack_number = index % 16 + 1;
        let attack_template = template_for_attack(&templates.templates, attack_number)?;
        let attack_program = build_program(attack_template, index + count);
        let (mutated, encoding, expected) = mutate_attack(attack_program, attack_number)?;
        verify_generated_attack(&mutated, &encoding, &expected)?;
        adversarial.push(GeneratedAdversarialCase {
            id: format!("EXP-0009-X{index:04}"),
            attack: format!("EXP-0009-A{attack_number:03}"),
            encoding,
            program: mutated,
            expected,
        });
    }
    let material = serde_json::json!({
        "adversarial": adversarial,
        "algorithm": GENERATOR_ALGORITHM,
        "schema": GENERATED_SCHEMA,
        "seed": GENERATOR_SEED,
        "valid": valid,
    });
    let corpus_identity = domain_hash(
        GENERATOR_ALGORITHM,
        &canonical_json(&material).map_err(generation_error)?,
    );
    Ok(GeneratedCorpus {
        schema: GENERATED_SCHEMA.to_owned(),
        algorithm: GENERATOR_ALGORITHM.to_owned(),
        seed: GENERATOR_SEED,
        valid,
        adversarial,
        corpus_identity,
    })
}

fn decode_program_value(bytes: &[u8]) -> Result<Value, DerivationError> {
    let document = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let value = decode_strict_json(document)
        .map_err(|error| DerivationError::new("derivation-schema-mismatch", error.message))?;
    if canonical_json(&value).map_err(generation_error)? != document {
        return Err(DerivationError::new(
            "derivation-noncanonical",
            "derivation program is not canonical JSON",
        ));
    }
    Ok(value)
}

fn validate_derivation_value(value: &Value) -> Result<DerivationReport, DerivationError> {
    if value.get("schema").and_then(Value::as_str) != Some(PROGRAM_SCHEMA) {
        return Err(DerivationError::new(
            "derivation-schema-mismatch",
            "unsupported derivation program schema",
        ));
    }
    reject_unknown_rules(value)?;
    let program: DerivationProgram = serde_json::from_value(value.clone())
        .map_err(|error| DerivationError::new("derivation-schema-mismatch", error.to_string()))?;
    require_text(&program.claim_id, "claim ID")?;

    let mut facts = BTreeMap::new();
    let mut prior_fact = None;
    for fact in &program.facts {
        if fact.schema != FACT_SCHEMA {
            return Err(DerivationError::new(
                "derivation-schema-mismatch",
                "unsupported fact schema",
            ));
        }
        require_text(&fact.id, "fact ID")?;
        if prior_fact.as_ref().is_some_and(|prior| prior >= &fact.id)
            || facts.insert(fact.id.clone(), fact).is_some()
        {
            return Err(DerivationError::new(
                "derivation-duplicate-identity",
                "fact identities must be strictly sorted and unique",
            ));
        }
        prior_fact = Some(fact.id.clone());
    }
    validate_fact_authority(&facts)?;

    let all_step_ids = program
        .steps
        .iter()
        .map(|step| step.id.as_str())
        .collect::<Vec<_>>();
    let mut judgments = BTreeMap::new();
    let mut prior_step = None;
    for step in &program.steps {
        if step.schema != STEP_SCHEMA {
            return Err(DerivationError::new(
                "derivation-schema-mismatch",
                "unsupported derivation step schema",
            ));
        }
        require_text(&step.id, "step ID")?;
        if facts.contains_key(&step.id)
            || prior_step.as_ref().is_some_and(|prior| prior >= &step.id)
            || judgments.contains_key(&step.id)
        {
            return Err(DerivationError::new(
                "derivation-duplicate-identity",
                "fact and step identities must be globally unique",
            ));
        }
        require_sorted_unique(&step.inputs, "step inputs")?;
        for input in &step.inputs {
            if all_step_ids.contains(&input.as_str()) && !judgments.contains_key(input) {
                return Err(DerivationError::new(
                    "derivation-cycle",
                    format!("step {} depends on non-prior step {input}", step.id),
                ));
            }
            if !facts.contains_key(input) && !judgments.contains_key(input) {
                return Err(DerivationError::new(
                    "derivation-dependency-mismatch",
                    format!("step {} names unknown input {input}", step.id),
                ));
            }
        }
        validate_step(step, &facts, &judgments)?;
        judgments.insert(step.id.clone(), &step.conclusion);
        prior_step = Some(step.id.clone());
    }
    let conclusion = judgments.get(&program.conclusion).ok_or_else(|| {
        DerivationError::new(
            "derivation-root-mismatch",
            "declared conclusion does not name a derived step",
        )
    })?;
    if !matches!(conclusion, Judgment::Status { .. }) {
        return Err(DerivationError::new(
            "derivation-root-mismatch",
            "declared root is not a complete status judgment",
        ));
    }
    let trace_identity = domain_hash(
        TRACE_DOMAIN,
        &canonical_json(&program).map_err(generation_error)?,
    );
    Ok(DerivationReport {
        schema: "proofbound-derivation-validation/1".to_owned(),
        claim_id: program.claim_id,
        conclusion: serde_json::to_value(conclusion).map_err(generation_error)?,
        trace_identity,
        alerts: Vec::new(),
    })
}

fn validate_fact_authority(facts: &BTreeMap<String, &Fact>) -> Result<(), DerivationError> {
    for fact in facts.values() {
        require_sorted_unique(&fact.sources, "fact sources")?;
        match fact.authority {
            Authority::Derived if fact.sources.is_empty() => {
                return Err(DerivationError::new(
                    "derivation-authority-mismatch",
                    format!("derived fact {} has no derivation sources", fact.id),
                ));
            }
            Authority::Derived => {
                for source in &fact.sources {
                    if !facts.contains_key(source) {
                        return Err(DerivationError::new(
                            "derivation-authority-mismatch",
                            format!("derived fact {} has unknown source {source}", fact.id),
                        ));
                    }
                }
            }
            _ if !fact.sources.is_empty() => {
                return Err(DerivationError::new(
                    "derivation-authority-mismatch",
                    format!("non-derived fact {} carries derivation sources", fact.id),
                ));
            }
            _ => {}
        }
        match (&fact.authority, &fact.proposition) {
            (Authority::Registered, Proposition::PolicyRegistered { .. })
            | (Authority::Reviewed, Proposition::AssumptionOpen { .. })
            | (Authority::Observed, Proposition::EvidencePassed { .. })
            | (Authority::Derived, Proposition::BindingMatches { .. })
            | (Authority::Observed, Proposition::Telemetry { .. })
            | (Authority::Unavailable, _) => {}
            _ => {
                return Err(DerivationError::new(
                    "derivation-authority-mismatch",
                    format!(
                        "fact {} has an invalid authority for its proposition",
                        fact.id
                    ),
                ));
            }
        }
    }
    for fact in facts.values() {
        if let Proposition::BindingMatches {
            theorem_id,
            artifact_id,
        } = &fact.proposition
        {
            let mut seen_theorem = false;
            let mut seen_artifact = false;
            for source in &fact.sources {
                match &facts[source].proposition {
                    Proposition::EvidencePassed {
                        evidence_id,
                        family: EvidenceFamily::Theorem,
                    } if evidence_id == theorem_id => seen_theorem = true,
                    Proposition::EvidencePassed {
                        evidence_id,
                        family: EvidenceFamily::ArtifactBinding,
                    } if evidence_id == artifact_id => seen_artifact = true,
                    _ => {}
                }
            }
            if fact.sources.len() != 2 || !seen_theorem || !seen_artifact {
                return Err(DerivationError::new(
                    "derivation-binding-mismatch",
                    format!("binding fact {} does not join its exact evidence", fact.id),
                ));
            }
        }
    }
    Ok(())
}

fn validate_step(
    step: &Step,
    facts: &BTreeMap<String, &Fact>,
    judgments: &BTreeMap<String, &Judgment>,
) -> Result<(), DerivationError> {
    match step.rule {
        Rule::EvidenceValid => validate_evidence_valid(step, facts),
        Rule::SampledTested => validate_formal_rule(
            step,
            judgments,
            EvidenceFamily::SampledProperty,
            FormalFacet::Tested,
        ),
        Rule::BoundedTested => validate_formal_rule(
            step,
            judgments,
            EvidenceFamily::BoundedCheck,
            FormalFacet::Tested,
        ),
        Rule::TheoremProved => validate_formal_rule(
            step,
            judgments,
            EvidenceFamily::Theorem,
            FormalFacet::Proved,
        ),
        Rule::MutationTested => validate_formal_rule(
            step,
            judgments,
            EvidenceFamily::MutationWitness,
            FormalFacet::Tested,
        ),
        Rule::TranscriptionOpen => validate_formal_rule(
            step,
            judgments,
            EvidenceFamily::TrustedTranscription,
            FormalFacet::Open,
        ),
        Rule::ModelLinked => validate_model_linked(step, judgments),
        Rule::TranscriptionLinked => validate_transcription_linked(step, judgments),
        Rule::ArtifactBound => validate_artifact_bound(step, facts, judgments),
        Rule::AssumptionFacet => validate_assumption_facet(step, facts),
        Rule::PolicyAdmitted => validate_policy_admitted(step, facts, judgments),
    }
}

fn validate_evidence_valid(
    step: &Step,
    facts: &BTreeMap<String, &Fact>,
) -> Result<(), DerivationError> {
    let fact = one_fact_input(step, facts)?;
    if fact.authority == Authority::Unavailable {
        return Err(DerivationError::new(
            "derivation-admission-blocked",
            format!("rule evidence-valid requires unavailable fact {}", fact.id),
        ));
    }
    let Proposition::EvidencePassed {
        evidence_id,
        family,
    } = &fact.proposition
    else {
        return rule_input_mismatch(step);
    };
    require_conclusion(
        step,
        &Judgment::EvidenceValid {
            schema: JUDGMENT_SCHEMA.to_owned(),
            evidence_id: evidence_id.clone(),
            family: *family,
        },
    )
}

fn validate_formal_rule(
    step: &Step,
    judgments: &BTreeMap<String, &Judgment>,
    expected_family: EvidenceFamily,
    formal: FormalFacet,
) -> Result<(), DerivationError> {
    let judgment = one_step_input(step, judgments)?;
    if !matches!(
        judgment,
        Judgment::EvidenceValid { family, .. } if *family == expected_family
    ) {
        return rule_input_mismatch(step);
    }
    require_conclusion(
        step,
        &Judgment::Formal {
            schema: JUDGMENT_SCHEMA.to_owned(),
            value: formal,
        },
    )
}

fn validate_model_linked(
    step: &Step,
    judgments: &BTreeMap<String, &Judgment>,
) -> Result<(), DerivationError> {
    if !matches!(one_step_input(step, judgments)?, Judgment::Formal { .. }) {
        return rule_input_mismatch(step);
    }
    require_conclusion(
        step,
        &Judgment::Linkage {
            schema: JUDGMENT_SCHEMA.to_owned(),
            value: LinkageFacet::ModelOnly,
        },
    )
}

fn validate_transcription_linked(
    step: &Step,
    judgments: &BTreeMap<String, &Judgment>,
) -> Result<(), DerivationError> {
    if !matches!(
        one_step_input(step, judgments)?,
        Judgment::EvidenceValid {
            family: EvidenceFamily::TrustedTranscription,
            ..
        }
    ) {
        return rule_input_mismatch(step);
    }
    require_conclusion(
        step,
        &Judgment::Linkage {
            schema: JUDGMENT_SCHEMA.to_owned(),
            value: LinkageFacet::Transcribed,
        },
    )
}

fn validate_artifact_bound(
    step: &Step,
    facts: &BTreeMap<String, &Fact>,
    judgments: &BTreeMap<String, &Judgment>,
) -> Result<(), DerivationError> {
    if step.inputs.len() != 3 {
        return dependency_mismatch(step, "artifact-bound requires three exact inputs");
    }
    let mut theorem = None;
    let mut artifact = None;
    let mut binding = None;
    for input in &step.inputs {
        match (facts.get(input), judgments.get(input)) {
            (
                _,
                Some(Judgment::EvidenceValid {
                    evidence_id,
                    family: EvidenceFamily::Theorem,
                    ..
                }),
            ) => theorem = Some(evidence_id),
            (
                _,
                Some(Judgment::EvidenceValid {
                    evidence_id,
                    family: EvidenceFamily::ArtifactBinding,
                    ..
                }),
            ) => artifact = Some(evidence_id),
            (Some(fact), _) => {
                if let Proposition::BindingMatches {
                    theorem_id,
                    artifact_id,
                } = &fact.proposition
                {
                    if fact.authority == Authority::Unavailable {
                        return Err(DerivationError::new(
                            "derivation-admission-blocked",
                            format!("rule artifact-bound requires unavailable fact {input}"),
                        ));
                    }
                    binding = Some((theorem_id, artifact_id));
                }
            }
            _ => {}
        }
    }
    let Some((theorem_id, artifact_id)) = binding else {
        return dependency_mismatch(step, "artifact-bound lacks a binding fact");
    };
    if theorem != Some(theorem_id) || artifact != Some(artifact_id) {
        return Err(DerivationError::new(
            "derivation-binding-mismatch",
            "artifact-bound inputs do not match the exact binding",
        ));
    }
    require_conclusion(
        step,
        &Judgment::Linkage {
            schema: JUDGMENT_SCHEMA.to_owned(),
            value: LinkageFacet::ArtifactBound,
        },
    )
}

fn validate_assumption_facet(
    step: &Step,
    facts: &BTreeMap<String, &Fact>,
) -> Result<(), DerivationError> {
    let expected = if step.inputs.is_empty() {
        AssumptionFacet::None
    } else {
        for input in &step.inputs {
            let Some(fact) = facts.get(input) else {
                return dependency_mismatch(step, "assumption rule requires fact inputs");
            };
            if fact.authority == Authority::Unavailable {
                return Err(DerivationError::new(
                    "derivation-admission-blocked",
                    format!("assumption rule requires unavailable fact {input}"),
                ));
            }
            if !matches!(fact.proposition, Proposition::AssumptionOpen { .. }) {
                return rule_input_mismatch(step);
            }
        }
        AssumptionFacet::Assumed
    };
    require_conclusion(
        step,
        &Judgment::Assumption {
            schema: JUDGMENT_SCHEMA.to_owned(),
            value: expected,
        },
    )
}

fn validate_policy_admitted(
    step: &Step,
    facts: &BTreeMap<String, &Fact>,
    judgments: &BTreeMap<String, &Judgment>,
) -> Result<(), DerivationError> {
    if step.inputs.len() != 4 {
        return dependency_mismatch(step, "policy admission requires four exact inputs");
    }
    let mut policy = None;
    let mut formal = None;
    let mut linkage = None;
    let mut assumption = None;
    for input in &step.inputs {
        match (facts.get(input), judgments.get(input)) {
            (
                Some(Fact {
                    authority: Authority::Registered,
                    proposition:
                        Proposition::PolicyRegistered {
                            required_formal,
                            required_linkage,
                            allow_assumptions,
                            ..
                        },
                    ..
                }),
                _,
            ) => policy = Some((*required_formal, *required_linkage, *allow_assumptions)),
            (_, Some(Judgment::Formal { value, .. })) => formal = Some(*value),
            (_, Some(Judgment::Linkage { value, .. })) => linkage = Some(*value),
            (_, Some(Judgment::Assumption { value, .. })) => assumption = Some(*value),
            _ => {}
        }
    }
    let Some((required_formal, required_linkage, allow_assumptions)) = policy else {
        return dependency_mismatch(step, "policy admission lacks its registered policy");
    };
    let (Some(formal), Some(linkage), Some(assumption)) = (formal, linkage, assumption) else {
        return dependency_mismatch(step, "policy admission lacks a derived facet");
    };
    if formal != required_formal
        || linkage != required_linkage
        || (!allow_assumptions && assumption == AssumptionFacet::Assumed)
    {
        return Err(DerivationError::new(
            "derivation-admission-blocked",
            format!(
                "rule {} is blocked by registered policy requirements",
                step.id
            ),
        ));
    }
    require_conclusion(
        step,
        &Judgment::Status {
            schema: JUDGMENT_SCHEMA.to_owned(),
            formal,
            linkage,
            assumption,
            policy: PolicyDecision::Admitted,
        },
    )
}

fn one_fact_input<'a>(
    step: &Step,
    facts: &'a BTreeMap<String, &Fact>,
) -> Result<&'a Fact, DerivationError> {
    if step.inputs.len() != 1 {
        return dependency_mismatch(step, "rule requires one fact input");
    }
    facts.get(&step.inputs[0]).copied().ok_or_else(|| {
        DerivationError::new("derivation-rule-input-mismatch", "expected fact input")
    })
}

fn one_step_input<'a>(
    step: &Step,
    judgments: &'a BTreeMap<String, &Judgment>,
) -> Result<&'a Judgment, DerivationError> {
    if step.inputs.len() != 1 {
        return dependency_mismatch(step, "rule requires one derived input");
    }
    judgments.get(&step.inputs[0]).copied().ok_or_else(|| {
        DerivationError::new("derivation-rule-input-mismatch", "expected derived input")
    })
}

fn require_conclusion(step: &Step, expected: &Judgment) -> Result<(), DerivationError> {
    if &step.conclusion != expected {
        return Err(DerivationError::new(
            "derivation-conclusion-mismatch",
            format!("rule {} emitted an invalid conclusion", step.id),
        ));
    }
    Ok(())
}

fn rule_input_mismatch<T>(step: &Step) -> Result<T, DerivationError> {
    Err(DerivationError::new(
        "derivation-rule-input-mismatch",
        format!("rule {} received an incompatible input", step.id),
    ))
}

fn dependency_mismatch<T>(step: &Step, message: &str) -> Result<T, DerivationError> {
    Err(DerivationError::new(
        "derivation-dependency-mismatch",
        format!("rule {}: {message}", step.id),
    ))
}

fn reject_unknown_rules(value: &Value) -> Result<(), DerivationError> {
    let known = [
        "evidence-valid",
        "sampled-tested",
        "bounded-tested",
        "theorem-proved",
        "mutation-tested",
        "transcription-open",
        "model-linked",
        "transcription-linked",
        "artifact-bound",
        "assumption-facet",
        "policy-admitted",
    ];
    if let Some(steps) = value.get("steps").and_then(Value::as_array) {
        for step in steps {
            if step
                .get("rule")
                .and_then(Value::as_str)
                .is_some_and(|rule| !known.contains(&rule))
            {
                return Err(DerivationError::new(
                    "derivation-unknown-rule",
                    "derivation uses an unknown or backend-named rule",
                ));
            }
        }
    }
    Ok(())
}

fn validate_templates(corpus: &TemplateCorpus) -> Result<(), DerivationError> {
    if corpus.schema != "proofbound-derivation-template-corpus/1" || corpus.templates.len() != 6 {
        return Err(DerivationError::new(
            "derivation-generation-invalid",
            "template corpus must contain the six registered routes",
        ));
    }
    let mut prior = None;
    for template in &corpus.templates {
        require_text(&template.id, "template ID")?;
        if prior.as_ref().is_some_and(|id| id >= &template.id) {
            return Err(DerivationError::new(
                "derivation-generation-invalid",
                "templates are not strictly sorted and unique",
            ));
        }
        if template.route != template.family
            || expected_facets(template.route)
                != (template.formal, template.linkage, template.assumption)
        {
            return Err(DerivationError::new(
                "derivation-generation-invalid",
                format!("template {} contradicts its closed route", template.id),
            ));
        }
        prior = Some(template.id.clone());
    }
    Ok(())
}

fn expected_facets(route: EvidenceFamily) -> (FormalFacet, LinkageFacet, AssumptionFacet) {
    match route {
        EvidenceFamily::SampledProperty
        | EvidenceFamily::BoundedCheck
        | EvidenceFamily::MutationWitness => (
            FormalFacet::Tested,
            LinkageFacet::ModelOnly,
            AssumptionFacet::None,
        ),
        EvidenceFamily::Theorem => (
            FormalFacet::Proved,
            LinkageFacet::ModelOnly,
            AssumptionFacet::Assumed,
        ),
        EvidenceFamily::TrustedTranscription => (
            FormalFacet::Open,
            LinkageFacet::Transcribed,
            AssumptionFacet::None,
        ),
        EvidenceFamily::ArtifactBinding => (
            FormalFacet::Proved,
            LinkageFacet::ArtifactBound,
            AssumptionFacet::None,
        ),
    }
}

fn build_program(template: &Template, index: usize) -> DerivationProgram {
    let suffix = format!("{index:04}");
    let evidence_id = format!("evidence:{}:{suffix}", template.id);
    let policy_id = format!("policy:{}:{suffix}", template.id);
    let mut facts = vec![Fact {
        schema: FACT_SCHEMA.to_owned(),
        id: "f-evidence".to_owned(),
        authority: Authority::Observed,
        proposition: Proposition::EvidencePassed {
            evidence_id: evidence_id.clone(),
            family: template.family,
        },
        sources: vec![],
    }];
    if template.route == EvidenceFamily::ArtifactBinding {
        let theorem_id = format!("evidence:theorem:{suffix}");
        facts.push(Fact {
            schema: FACT_SCHEMA.to_owned(),
            id: "f-binding".to_owned(),
            authority: Authority::Derived,
            proposition: Proposition::BindingMatches {
                theorem_id: theorem_id.clone(),
                artifact_id: evidence_id.clone(),
            },
            sources: vec!["f-evidence".to_owned(), "f-theorem".to_owned()],
        });
        facts.push(Fact {
            schema: FACT_SCHEMA.to_owned(),
            id: "f-theorem".to_owned(),
            authority: Authority::Observed,
            proposition: Proposition::EvidencePassed {
                evidence_id: theorem_id,
                family: EvidenceFamily::Theorem,
            },
            sources: vec![],
        });
    }
    if template.assumption == AssumptionFacet::Assumed {
        facts.push(Fact {
            schema: FACT_SCHEMA.to_owned(),
            id: "f-assumption".to_owned(),
            authority: Authority::Reviewed,
            proposition: Proposition::AssumptionOpen {
                assumption_id: format!("assumption:{}:{suffix}", template.id),
            },
            sources: vec![],
        });
    }
    facts.push(Fact {
        schema: FACT_SCHEMA.to_owned(),
        id: "f-policy".to_owned(),
        authority: Authority::Registered,
        proposition: Proposition::PolicyRegistered {
            policy_id,
            required_formal: template.formal,
            required_linkage: template.linkage,
            allow_assumptions: template.assumption == AssumptionFacet::Assumed,
        },
        sources: vec![],
    });
    facts.push(Fact {
        schema: FACT_SCHEMA.to_owned(),
        id: "f-telemetry".to_owned(),
        authority: Authority::Observed,
        proposition: Proposition::Telemetry {
            name: "duration-ms".to_owned(),
            value: (index % 97) as u64,
        },
        sources: vec![],
    });
    facts.sort_by(|left, right| left.id.cmp(&right.id));

    let mut steps = Vec::new();
    if template.route == EvidenceFamily::ArtifactBinding {
        steps.push(evidence_valid_step(
            "s00-artifact-valid",
            "f-evidence",
            &evidence_id,
            EvidenceFamily::ArtifactBinding,
        ));
        let theorem_id = format!("evidence:theorem:{suffix}");
        steps.push(evidence_valid_step(
            "s01-theorem-valid",
            "f-theorem",
            &theorem_id,
            EvidenceFamily::Theorem,
        ));
        steps.push(Step {
            schema: STEP_SCHEMA.to_owned(),
            id: "s02-formal".to_owned(),
            rule: Rule::TheoremProved,
            inputs: vec!["s01-theorem-valid".to_owned()],
            conclusion: Judgment::Formal {
                schema: JUDGMENT_SCHEMA.to_owned(),
                value: FormalFacet::Proved,
            },
        });
        steps.push(Step {
            schema: STEP_SCHEMA.to_owned(),
            id: "s03-linkage".to_owned(),
            rule: Rule::ArtifactBound,
            inputs: vec![
                "f-binding".to_owned(),
                "s00-artifact-valid".to_owned(),
                "s01-theorem-valid".to_owned(),
            ],
            conclusion: Judgment::Linkage {
                schema: JUDGMENT_SCHEMA.to_owned(),
                value: LinkageFacet::ArtifactBound,
            },
        });
    } else {
        steps.push(evidence_valid_step(
            "s00-evidence-valid",
            "f-evidence",
            &evidence_id,
            template.family,
        ));
        let formal_rule = match template.route {
            EvidenceFamily::SampledProperty => Rule::SampledTested,
            EvidenceFamily::BoundedCheck => Rule::BoundedTested,
            EvidenceFamily::Theorem => Rule::TheoremProved,
            EvidenceFamily::MutationWitness => Rule::MutationTested,
            EvidenceFamily::TrustedTranscription => Rule::TranscriptionOpen,
            EvidenceFamily::ArtifactBinding => unreachable!(),
        };
        steps.push(Step {
            schema: STEP_SCHEMA.to_owned(),
            id: "s01-formal".to_owned(),
            rule: formal_rule,
            inputs: vec!["s00-evidence-valid".to_owned()],
            conclusion: Judgment::Formal {
                schema: JUDGMENT_SCHEMA.to_owned(),
                value: template.formal,
            },
        });
        let (rule, inputs) = if template.route == EvidenceFamily::TrustedTranscription {
            (
                Rule::TranscriptionLinked,
                vec!["s00-evidence-valid".to_owned()],
            )
        } else {
            (Rule::ModelLinked, vec!["s01-formal".to_owned()])
        };
        steps.push(Step {
            schema: STEP_SCHEMA.to_owned(),
            id: "s02-linkage".to_owned(),
            rule,
            inputs,
            conclusion: Judgment::Linkage {
                schema: JUDGMENT_SCHEMA.to_owned(),
                value: template.linkage,
            },
        });
    }
    let assumption_inputs = if template.assumption == AssumptionFacet::Assumed {
        vec!["f-assumption".to_owned()]
    } else {
        Vec::new()
    };
    steps.push(Step {
        schema: STEP_SCHEMA.to_owned(),
        id: "s04-assumption".to_owned(),
        rule: Rule::AssumptionFacet,
        inputs: assumption_inputs,
        conclusion: Judgment::Assumption {
            schema: JUDGMENT_SCHEMA.to_owned(),
            value: template.assumption,
        },
    });
    let (formal_step, linkage_step) = if template.route == EvidenceFamily::ArtifactBinding {
        ("s02-formal", "s03-linkage")
    } else {
        ("s01-formal", "s02-linkage")
    };
    steps.push(Step {
        schema: STEP_SCHEMA.to_owned(),
        id: "s05-policy".to_owned(),
        rule: Rule::PolicyAdmitted,
        inputs: vec![
            "f-policy".to_owned(),
            formal_step.to_owned(),
            linkage_step.to_owned(),
            "s04-assumption".to_owned(),
        ],
        conclusion: Judgment::Status {
            schema: JUDGMENT_SCHEMA.to_owned(),
            formal: template.formal,
            linkage: template.linkage,
            assumption: template.assumption,
            policy: PolicyDecision::Admitted,
        },
    });
    DerivationProgram {
        schema: PROGRAM_SCHEMA.to_owned(),
        claim_id: format!("claim:{}:{suffix}", template.id),
        facts,
        steps,
        conclusion: "s05-policy".to_owned(),
    }
}

fn evidence_valid_step(
    step_id: &str,
    fact_id: &str,
    evidence_id: &str,
    family: EvidenceFamily,
) -> Step {
    Step {
        schema: STEP_SCHEMA.to_owned(),
        id: step_id.to_owned(),
        rule: Rule::EvidenceValid,
        inputs: vec![fact_id.to_owned()],
        conclusion: Judgment::EvidenceValid {
            schema: JUDGMENT_SCHEMA.to_owned(),
            evidence_id: evidence_id.to_owned(),
            family,
        },
    }
}

fn template_for_attack(
    templates: &[Template],
    attack: usize,
) -> Result<&Template, DerivationError> {
    let id = match attack {
        1 => "sampled",
        2 => "bounded",
        3 | 4 => "artifact",
        5 => "theorem",
        15 => "transcription",
        _ => "sampled",
    };
    templates
        .iter()
        .find(|template| template.id == id)
        .ok_or_else(|| {
            DerivationError::new(
                "derivation-generation-invalid",
                "required template is missing",
            )
        })
}

fn mutate_attack(
    program: DerivationProgram,
    attack: usize,
) -> Result<(Value, String, String), DerivationError> {
    let mut value = serde_json::to_value(program).map_err(generation_error)?;
    let encoding = if attack == 14 { "pretty" } else { "canonical" }.to_owned();
    let expected = match attack {
        1 | 2 => {
            value["steps"][1]["rule"] = Value::String("theorem-proved".to_owned());
            "derivation-rule-input-mismatch"
        }
        3 => {
            value["steps"][3]["inputs"] =
                serde_json::json!(["s00-artifact-valid", "s01-theorem-valid"]);
            "derivation-dependency-mismatch"
        }
        4 => {
            value["facts"][0]["proposition"]["theorem_id"] =
                Value::String("evidence:theorem:substituted".to_owned());
            "derivation-binding-mismatch"
        }
        5 => {
            value["steps"][4]["inputs"] =
                serde_json::json!(["f-policy", "s01-formal", "s02-linkage"]);
            "derivation-dependency-mismatch"
        }
        6 => {
            value["steps"][0]["inputs"] = serde_json::json!(["f-substituted"]);
            "derivation-dependency-mismatch"
        }
        7 => {
            value["steps"][1]["inputs"] = serde_json::json!(["s05-policy"]);
            "derivation-cycle"
        }
        8 => {
            value["facts"][1]["id"] = value["facts"][0]["id"].clone();
            "derivation-duplicate-identity"
        }
        9 => {
            value["steps"][1]["rule"] = Value::String("hypothesis-tested".to_owned());
            "derivation-unknown-rule"
        }
        10 => {
            let facts = value["facts"].as_array_mut().ok_or_else(|| {
                DerivationError::new("derivation-generation-invalid", "facts are not an array")
            })?;
            let telemetry = facts
                .iter_mut()
                .find(|fact| fact["id"] == "f-telemetry")
                .ok_or_else(|| {
                    DerivationError::new(
                        "derivation-generation-invalid",
                        "telemetry fact is missing",
                    )
                })?;
            telemetry["authority"] = Value::String("derived".to_owned());
            "derivation-authority-mismatch"
        }
        11 => {
            let facts = value["facts"].as_array_mut().ok_or_else(|| {
                DerivationError::new("derivation-generation-invalid", "facts are not an array")
            })?;
            let evidence = facts
                .iter_mut()
                .find(|fact| fact["id"] == "f-evidence")
                .ok_or_else(|| {
                    DerivationError::new(
                        "derivation-generation-invalid",
                        "evidence fact is missing",
                    )
                })?;
            evidence["authority"] = Value::String("unavailable".to_owned());
            "derivation-admission-blocked"
        }
        12 => {
            value["facts"]
                .as_array_mut()
                .ok_or_else(|| {
                    DerivationError::new("derivation-generation-invalid", "facts are not an array")
                })?
                .retain(|fact| fact["id"] != "f-telemetry");
            "no-admission-consequence"
        }
        13 => {
            value["conclusion"] = Value::String("s01-formal".to_owned());
            "derivation-root-mismatch"
        }
        14 => "derivation-noncanonical",
        15 => {
            value["steps"][1]["rule"] = Value::String("theorem-proved".to_owned());
            "derivation-rule-input-mismatch"
        }
        16 => {
            value["schema"] = Value::String("proofbound-layered-sampling-observation/1".to_owned());
            "derivation-schema-mismatch"
        }
        _ => {
            return Err(DerivationError::new(
                "derivation-generation-invalid",
                "unknown registered attack",
            ));
        }
    };
    Ok((value, encoding, expected.to_owned()))
}

fn verify_generated_attack(
    value: &Value,
    encoding: &str,
    expected: &str,
) -> Result<(), DerivationError> {
    let bytes = if encoding == "pretty" {
        serde_json::to_vec_pretty(value).map_err(generation_error)?
    } else {
        canonical_json(value).map_err(generation_error)?
    };
    match validate_derivation_program(&bytes) {
        Ok(_) if expected == "no-admission-consequence" => Ok(()),
        Ok(_) => Err(DerivationError::new(
            "derivation-generation-invalid",
            format!("generated attack unexpectedly passed; expected {expected}"),
        )),
        Err(error) if error.code == expected => Ok(()),
        Err(error) => Err(DerivationError::new(
            "derivation-generation-invalid",
            format!("generated attack expected {expected}, received {error}"),
        )),
    }
}

fn require_text(value: &str, label: &str) -> Result<(), DerivationError> {
    if value.trim().is_empty()
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(DerivationError::new(
            "derivation-schema-mismatch",
            format!("{label} is not bounded non-control text"),
        ));
    }
    Ok(())
}

fn require_sorted_unique(values: &[String], label: &str) -> Result<(), DerivationError> {
    for value in values {
        require_text(value, label)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DerivationError::new(
            "derivation-dependency-mismatch",
            format!("{label} are not strictly sorted and unique"),
        ));
    }
    Ok(())
}

fn generation_error(error: impl std::fmt::Display) -> DerivationError {
    DerivationError::new("derivation-generation-invalid", error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use proofbound_evidence::canonical_json;

    use super::{generate_derivation_corpus, validate_derivation_program};

    fn templates() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/experiments/0009-generated-evidence-algebra/corpus/templates.json")
    }

    #[test]
    fn generated_valid_and_adversarial_programs_match_registration() {
        let corpus = generate_derivation_corpus(&templates(), 500).unwrap();
        assert_eq!(corpus.valid.len(), 500);
        assert_eq!(corpus.adversarial.len(), 500);
        for case in &corpus.valid {
            let bytes = canonical_json(&case.program).unwrap();
            let report = validate_derivation_program(&bytes).unwrap();
            assert_eq!(report.trace_identity, case.expected_trace_identity);
        }
        let attacks = corpus
            .adversarial
            .iter()
            .map(|case| case.attack.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(attacks.len(), 16);
    }

    #[test]
    fn generated_corpus_is_deterministic() {
        let first = generate_derivation_corpus(&templates(), 500).unwrap();
        let second = generate_derivation_corpus(&templates(), 500).unwrap();
        assert_eq!(first, second);
    }
}
