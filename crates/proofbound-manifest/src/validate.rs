use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

use crate::{
    AdapterKind, AssumptionCategory, BindingMode, EvidenceKind, OperationKind, ProjectBundle,
};

const BUILTIN_PROFILES: &[&str] = &[
    "ledger",
    "kernel",
    "kernel-with-assumptions",
    "artifact-bound",
    "source-refined",
    "native-evaluated",
    "bounded",
];

#[derive(Debug, Error)]
pub enum SemanticError {
    #[error("unknown schema in {path}: expected {expected}, found {actual}")]
    Schema {
        path: PathBuf,
        expected: &'static str,
        actual: String,
    },
    #[error("duplicate stable ID {id} in {first} and {second}")]
    DuplicateId {
        id: String,
        first: PathBuf,
        second: PathBuf,
    },
    #[error("invalid stable ID {id} in {path}")]
    InvalidId { id: String, path: PathBuf },
    #[error("invalid SHA-256 identity {digest} in {path}")]
    InvalidDigest { digest: String, path: PathBuf },
    #[error("project tier must be between 0 and 3, found {0}")]
    InvalidTier(u8),
    #[error("{owner} references missing {kind} {id}")]
    MissingReference {
        owner: String,
        kind: &'static str,
        id: String,
    },
    #[error("{owner} and {target} do not reference each other bidirectionally")]
    InverseMissing { owner: String, target: String },
    #[error(
        "claim {claim} cites tier {evidence_tier} evidence above its effective tier ceiling {project_tier}"
    )]
    TierExceeded {
        claim: String,
        evidence_tier: u8,
        project_tier: u8,
    },
    #[error(
        "claim {claim} has an incomplete formal identity; declaration, encoding, and digest must occur together"
    )]
    PartialFormalIdentity { claim: String },
    #[error("claim {claim} uses unsupported statement encoding {encoding}")]
    StatementEncoding { claim: String, encoding: String },
    #[error("evidence unit {unit}: {message}")]
    EvidenceQualifier { unit: String, message: String },
    #[error("translation unit {unit}: {message}")]
    Translation { unit: String, message: String },
    #[error("custom policy {policy} weakens built-in profile {base}: {message}")]
    WeakPolicy {
        policy: String,
        base: String,
        message: String,
    },
    #[error("unsafe repository-relative path in {owner}: {path}")]
    UnsafePath { owner: String, path: String },
    #[error("demo registry contains duplicate demo {0}")]
    DuplicateDemo(String),
}

pub fn validate_bundle(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    if bundle.project.schema != "proofbound-project/1" {
        return Err(SemanticError::Schema {
            path: bundle.root.join("proofbound.toml"),
            expected: "proofbound-project/1",
            actual: bundle.project.schema.clone(),
        });
    }
    if bundle.project.tier > 3 {
        return Err(SemanticError::InvalidTier(bundle.project.tier));
    }
    validate_project_paths(bundle)?;

    let mut global_ids = BTreeSet::new();
    for (id, (path, claim)) in &bundle.claims {
        schema(path, &claim.schema, "proofbound-claim/1")?;
        stable_id(id, path)?;
        if !global_ids.insert(id.clone()) {
            return Err(SemanticError::DuplicateId {
                id: id.clone(),
                first: path.clone(),
                second: path.clone(),
            });
        }
        if claim.tier.unwrap_or(bundle.project.tier) > bundle.project.tier {
            return Err(SemanticError::TierExceeded {
                claim: id.clone(),
                evidence_tier: claim.tier.unwrap(),
                project_tier: bundle.project.tier,
            });
        }
        match (
            &claim.formal_declaration,
            &claim.statement_encoding,
            &claim.statement_sha256,
        ) {
            (None, None, None) => {}
            (Some(_), Some(encoding), Some(digest)) => {
                if encoding != "lean-expr-cbor/1" {
                    return Err(SemanticError::StatementEncoding {
                        claim: id.clone(),
                        encoding: encoding.clone(),
                    });
                }
                digest_sha256(digest, path)?;
            }
            _ => return Err(SemanticError::PartialFormalIdentity { claim: id.clone() }),
        }
        if let Some(digest) = &claim.subject_closure {
            digest_sha256(digest, path)?;
        }
        if claim
            .foundational_axioms
            .iter()
            .any(|axiom| axiom.is_empty() || axiom.len() > 1024)
            || !claim
                .foundational_axioms
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(SemanticError::EvidenceQualifier {
                unit: id.clone(),
                message: "foundational_axioms must be non-empty names in strict sorted order"
                    .to_owned(),
            });
        }
        for root in &claim.source_roots {
            relative_path(id, root)?;
        }
        if !BUILTIN_PROFILES.contains(&claim.profile.as_str())
            && !bundle.policies.contains_key(&claim.profile)
        {
            return Err(SemanticError::MissingReference {
                owner: id.clone(),
                kind: "policy",
                id: claim.profile.clone(),
            });
        }
    }

    for (id, (path, assumption)) in &bundle.assumptions {
        schema(path, &assumption.schema, "proofbound-assumption/1")?;
        stable_id(id, path)?;
        if !global_ids.insert(id.clone()) {
            let (claim_path, _) = bundle.claims.get(id).expect("ID collision must be a claim");
            return Err(SemanticError::DuplicateId {
                id: id.clone(),
                first: claim_path.clone(),
                second: path.clone(),
            });
        }
        for claim_id in &assumption.affected_claims {
            let Some((_, claim)) = bundle.claims.get(claim_id) else {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: claim_id.clone(),
                });
            };
            if !claim.assumptions.contains(id) && !claim.premises.contains(id) {
                return Err(SemanticError::InverseMissing {
                    owner: id.clone(),
                    target: claim_id.clone(),
                });
            }
        }
    }

    for (claim_id, (_, claim)) in &bundle.claims {
        for assumption_id in &claim.assumptions {
            let Some((_, assumption)) = bundle.assumptions.get(assumption_id) else {
                return Err(SemanticError::MissingReference {
                    owner: claim_id.clone(),
                    kind: "assumption",
                    id: assumption_id.clone(),
                });
            };
            if !assumption.affected_claims.contains(claim_id) {
                return Err(SemanticError::InverseMissing {
                    owner: claim_id.clone(),
                    target: assumption_id.clone(),
                });
            }
        }
        for premise_id in &claim.premises {
            let Some((_, premise)) = bundle.assumptions.get(premise_id) else {
                return Err(SemanticError::MissingReference {
                    owner: claim_id.clone(),
                    kind: "premise",
                    id: premise_id.clone(),
                });
            };
            if premise.category != AssumptionCategory::RepresentationPremise {
                return Err(SemanticError::EvidenceQualifier {
                    unit: claim_id.clone(),
                    message: format!("premise {premise_id} is not a representation-premise"),
                });
            }
            if !premise.affected_claims.contains(claim_id) {
                return Err(SemanticError::InverseMissing {
                    owner: claim_id.clone(),
                    target: premise_id.clone(),
                });
            }
        }
    }

    validate_evidence(bundle)?;
    validate_translations(bundle)?;
    validate_model_checks(bundle)?;
    validate_policies(bundle)?;
    validate_reviews(bundle)?;
    validate_demos(bundle)?;
    Ok(())
}

fn validate_evidence(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    let mut known_refs = BTreeSet::new();
    for (id, (path, unit)) in &bundle.evidence_units {
        schema(path, &unit.schema, "proofbound-evidence-unit/1")?;
        local_id(id, path)?;
        if unit.tier > bundle.project.tier {
            return Err(SemanticError::TierExceeded {
                claim: unit.claims.join(","),
                evidence_tier: unit.tier,
                project_tier: bundle.project.tier,
            });
        }
        validate_unit_qualifiers(unit)?;
        let references = evidence_references(unit.kind, id);
        known_refs.extend(references.iter().cloned());
        for claim_id in &unit.claims {
            let Some((_, claim)) = bundle.claims.get(claim_id) else {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: claim_id.clone(),
                });
            };
            let claim_tier = claim.tier.unwrap_or(bundle.project.tier);
            if unit.tier > claim_tier {
                return Err(SemanticError::TierExceeded {
                    claim: claim_id.clone(),
                    evidence_tier: unit.tier,
                    project_tier: claim_tier,
                });
            }
            if !references
                .iter()
                .any(|reference| claim.evidence.contains(reference))
            {
                return Err(SemanticError::InverseMissing {
                    owner: id.clone(),
                    target: claim_id.clone(),
                });
            }
        }
        for path_value in unit
            .inputs
            .iter()
            .chain(unit.outputs.iter())
            .chain(unit.operation.paths.iter())
        {
            relative_path(id, path_value)?;
        }
        if let Some(path_value) = &unit.operation.manifest {
            relative_path(id, path_value)?;
        }
        if let Some(path_value) = &unit.operation.inventory {
            relative_path(id, path_value)?;
        }
        if let Some(path_value) = &unit.operation.checker {
            relative_path(id, path_value)?;
        }
    }
    for (id, (_, unit)) in &bundle.translation_units {
        let reference = format!("translation:{id}");
        known_refs.insert(reference.clone());
        for claim_id in &unit.claims {
            if !bundle.claims.contains_key(claim_id) {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: claim_id.clone(),
                });
            }
        }
    }
    for (id, (_, unit)) in &bundle.model_check_units {
        let references = [format!("kani:{id}"), format!("bounded-check:{id}")];
        known_refs.extend(references);
        for claim_id in &unit.claims {
            if !bundle.claims.contains_key(claim_id) {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: claim_id.clone(),
                });
            }
        }
    }
    for (claim_id, (_, claim)) in &bundle.claims {
        for reference in &claim.evidence {
            if !known_refs.contains(reference) {
                return Err(SemanticError::MissingReference {
                    owner: claim_id.clone(),
                    kind: "evidence",
                    id: reference.clone(),
                });
            }
        }
    }
    Ok(())
}

fn evidence_references(kind: EvidenceKind, id: &str) -> Vec<String> {
    let prefixes: &[&str] = match kind {
        EvidenceKind::Theorem => &["theorem"],
        EvidenceKind::ArtifactSoundness => &["artifact", "artifact-soundness"],
        EvidenceKind::TrustedTranscription => &["transcription", "trusted-transcription"],
        EvidenceKind::SourceRefinement => &["refinement", "source-refinement"],
        EvidenceKind::BoundedCheck => &["kani", "bounded-check"],
        EvidenceKind::IndependentCheck => &["independent", "independent-check"],
        EvidenceKind::ExhaustiveCheck => &["exhaustive", "exhaustive-check"],
        EvidenceKind::PropertyTest => &["property-test"],
        EvidenceKind::ExampleTest => &["test", "example-test"],
        EvidenceKind::MutationWitness => &["mutation", "mutation-witness"],
        EvidenceKind::Review => &["review"],
        EvidenceKind::Assumption => &["assumption"],
        EvidenceKind::Open => &["open"],
    };
    prefixes
        .iter()
        .map(|prefix| format!("{prefix}:{id}"))
        .collect()
}

fn validate_unit_qualifiers(unit: &crate::EvidenceUnitManifest) -> Result<(), SemanticError> {
    if unit.resource_budget.time_seconds == 0
        || unit.resource_budget.disk_bytes == 0
        || unit.resource_budget.memory_bytes == 0
    {
        return Err(SemanticError::EvidenceQualifier {
            unit: unit.id.clone(),
            message: "resource budgets must be nonzero".to_owned(),
        });
    }
    match unit.kind {
        EvidenceKind::Theorem | EvidenceKind::ArtifactSoundness
            if unit.evaluation_mode.is_none() =>
        {
            return Err(SemanticError::EvidenceQualifier {
                unit: unit.id.clone(),
                message: "theorem evidence requires evaluation_mode".to_owned(),
            });
        }
        _ => {}
    }
    if matches!(
        unit.kind,
        EvidenceKind::Theorem | EvidenceKind::ArtifactSoundness
    ) && unit.theorem.is_none()
    {
        return Err(SemanticError::EvidenceQualifier {
            unit: unit.id.clone(),
            message: "theorem evidence requires a declaration".to_owned(),
        });
    }
    match (unit.kind, unit.binding_mode) {
        (
            EvidenceKind::ArtifactSoundness,
            Some(BindingMode::BytesInTheorem | BindingMode::DigestTheorem),
        ) => {}
        (EvidenceKind::ArtifactSoundness, _) => {
            return Err(SemanticError::EvidenceQualifier {
                unit: unit.id.clone(),
                message: "artifact-soundness requires bytes-in-theorem or digest-theorem"
                    .to_owned(),
            });
        }
        (EvidenceKind::TrustedTranscription, Some(BindingMode::ExternalRoundTrip)) => {}
        (EvidenceKind::TrustedTranscription, _) => {
            return Err(SemanticError::EvidenceQualifier {
                unit: unit.id.clone(),
                message: "trusted-transcription requires external-round-trip".to_owned(),
            });
        }
        (_, Some(_)) => {
            return Err(SemanticError::EvidenceQualifier {
                unit: unit.id.clone(),
                message: "binding mode is not valid for this evidence kind".to_owned(),
            });
        }
        _ => {}
    }
    if unit.kind == EvidenceKind::SourceRefinement
        && (unit.refinement_theorem.is_none() || unit.premises.is_empty())
    {
        return Err(SemanticError::EvidenceQualifier {
            unit: unit.id.clone(),
            message: "source-refinement requires a named theorem and registered premises"
                .to_owned(),
        });
    }
    if matches!(
        unit.kind,
        EvidenceKind::BoundedCheck | EvidenceKind::ExhaustiveCheck
    ) && unit.bounded_domain.is_none()
    {
        return Err(SemanticError::EvidenceQualifier {
            unit: unit.id.clone(),
            message: "bounded evidence requires a finite domain".to_owned(),
        });
    }
    let operation_ok = matches!(
        (unit.adapter, unit.operation.kind),
        (AdapterKind::RustTest, OperationKind::CargoTest)
            | (AdapterKind::PythonTest, OperationKind::Pytest)
            | (AdapterKind::PythonTest, OperationKind::Generator)
            | (AdapterKind::Lean, OperationKind::LeanAudit)
            | (AdapterKind::Kani, OperationKind::Kani)
            | (AdapterKind::CharonAeneas, OperationKind::Translation)
            | (AdapterKind::CanonicalArtifact, OperationKind::ArtifactCheck)
            | (
                AdapterKind::IndependentCheck,
                OperationKind::IndependentCheck
            )
            | (AdapterKind::HumanReview, OperationKind::Review)
            | (AdapterKind::SourceClosure, OperationKind::Closure)
    );
    if !operation_ok {
        return Err(SemanticError::EvidenceQualifier {
            unit: unit.id.clone(),
            message: "adapter and typed operation do not match".to_owned(),
        });
    }
    Ok(())
}

fn validate_translations(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    for (id, (path, unit)) in &bundle.translation_units {
        schema(path, &unit.schema, "proofbound-translation-unit/1")?;
        local_id(id, path)?;
        if unit.adapter != "charon-aeneas"
            || unit.determinism_runs != 2
            || !unit.forbid_generated_axioms
        {
            return Err(SemanticError::Translation { unit: id.clone(), message: "adapter must be charon-aeneas, determinism_runs must be 2, and generated axioms must be forbidden".to_owned() });
        }
        relative_path(id, &unit.generated_dir)?;
        relative_path(id, &unit.handwritten_refinement)?;
        if overlaps(&unit.generated_dir, &unit.handwritten_refinement) {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "handwritten refinement overlaps generator-owned directory".to_owned(),
            });
        }
        for bridge in &unit.external_bridges {
            relative_path(id, &bridge.file)?;
            digest_sha256(&bridge.reviewed_sha256, path)?;
            if overlaps(&unit.generated_dir, &bridge.file) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "external bridge {} overlaps generator-owned directory",
                        bridge.file
                    ),
                });
            }
        }
        for template in &unit.template_axioms {
            relative_path(id, &template.file)?;
            if template.compiled {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!("template {} is marked compiled", template.file),
                });
            }
            if !overlaps(&unit.generated_dir, &template.file) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!("template {} is outside generated_dir", template.file),
                });
            }
        }
        for claim in &unit.claims {
            if !bundle.claims.contains_key(claim) {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: claim.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_model_checks(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    for (id, (path, unit)) in &bundle.model_check_units {
        schema(path, &unit.schema, "proofbound-model-check-unit/1")?;
        local_id(id, path)?;
        if unit.adapter != "kani"
            || unit.harnesses.is_empty()
            || unit.unwind == 0
            || unit.domain.cardinality == 0
        {
            return Err(SemanticError::EvidenceQualifier {
                unit: id.clone(),
                message: "invalid Kani inventory, domain, or unwind bound".to_owned(),
            });
        }
        for claim in &unit.claims {
            if !bundle.claims.contains_key(claim) {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: claim.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_policies(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    for (id, (path, policy)) in &bundle.policies {
        schema(path, &policy.schema, "proofbound-policy/1")?;
        local_id(id, path)?;
        if BUILTIN_PROFILES.contains(&id.as_str())
            || !BUILTIN_PROFILES.contains(&policy.extends.as_str())
        {
            return Err(SemanticError::WeakPolicy {
                policy: id.clone(),
                base: policy.extends.clone(),
                message: "built-in profiles cannot be replaced and custom profiles must extend one"
                    .to_owned(),
            });
        }
        match policy.extends.as_str() {
            "kernel"
                if policy.allow_project_axioms
                    || policy.allow_native
                    || policy.allow_exhaustive_as_proved =>
            {
                return Err(weak(
                    id,
                    &policy.extends,
                    "kernel extensions cannot admit project axioms, native evaluation, or exhaustive-as-proof",
                ));
            }
            "artifact-bound" if policy.required_binding != "artifact-bound" => {
                return Err(weak(
                    id,
                    &policy.extends,
                    "artifact-bound extension must retain artifact binding",
                ));
            }
            "source-refined"
                if policy.required_binding != "source-refined"
                    || !policy.require_registered_premises =>
            {
                return Err(weak(
                    id,
                    &policy.extends,
                    "source-refined extension must retain source binding and premise registration",
                ));
            }
            "bounded" if policy.allow_native || policy.allow_project_axioms => {
                return Err(weak(
                    id,
                    &policy.extends,
                    "bounded extension cannot add theorem trust",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_reviews(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    for (id, (path, review)) in &bundle.reviews {
        schema(path, &review.schema, "proofbound-review/1")?;
        stable_id(id, path)?;
        digest_sha256(&review.base_revision, path)?;
        digest_sha256(&review.head_revision, path)?;
        let mut regression_ids = BTreeSet::new();
        for regression in &review.regressions {
            digest_sha256(&regression.id, path)?;
            if !regression_ids.insert(&regression.id) {
                return Err(SemanticError::DuplicateId {
                    id: regression.id.clone(),
                    first: path.clone(),
                    second: path.clone(),
                });
            }
            if !bundle.claims.contains_key(&regression.claim_id) {
                return Err(SemanticError::MissingReference {
                    owner: id.clone(),
                    kind: "claim",
                    id: regression.claim_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_demos(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    let Some((path, registry)) = &bundle.demos else {
        return Ok(());
    };
    schema(path, &registry.schema, "proofbound-demo-registry/1")?;
    let mut names = BTreeSet::new();
    for demo in &registry.demos {
        if !names.insert(&demo.name) {
            return Err(SemanticError::DuplicateDemo(demo.name.clone()));
        }
        for claim in &demo.claims {
            if !bundle.claims.contains_key(claim) {
                return Err(SemanticError::MissingReference {
                    owner: demo.name.clone(),
                    kind: "claim",
                    id: claim.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_project_paths(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    let p = &bundle.project;
    for value in p
        .source
        .semantic
        .iter()
        .chain(&p.source.runner)
        .chain(&p.source.presentation)
        .chain(&p.source.external_evidence)
        .chain(&p.claim_manifests)
        .chain(&p.assumption_manifests)
        .chain(&p.evidence_units)
        .chain(&p.translation_units)
        .chain(&p.model_check_units)
        .chain(&p.policy_manifests)
        .chain(&p.review_manifests)
    {
        relative_path(&p.project, value)?;
    }
    for value in [
        &p.toolchains.rust,
        &p.toolchains.lean,
        &p.toolchains.python,
        &p.toolchains.translation,
    ]
    .into_iter()
    .flatten()
    {
        relative_path(&p.project, value)?;
    }
    if let Some(value) = &p.demo_registry {
        relative_path(&p.project, value)?;
    }
    Ok(())
}

fn schema(path: &Path, actual: &str, expected: &'static str) -> Result<(), SemanticError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SemanticError::Schema {
            path: path.to_owned(),
            expected,
            actual: actual.to_owned(),
        })
    }
}

fn stable_id(id: &str, path: &Path) -> Result<(), SemanticError> {
    let valid = id.len() <= 160
        && id.split('-').count() >= 2
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        && id.as_bytes().first().is_some_and(u8::is_ascii_uppercase);
    if valid {
        Ok(())
    } else {
        Err(SemanticError::InvalidId {
            id: id.to_owned(),
            path: path.to_owned(),
        })
    }
}

fn local_id(id: &str, path: &Path) -> Result<(), SemanticError> {
    let valid = id.len() <= 128
        && !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase);
    if valid {
        Ok(())
    } else {
        Err(SemanticError::InvalidId {
            id: id.to_owned(),
            path: path.to_owned(),
        })
    }
}

fn digest_sha256(digest: &str, path: &Path) -> Result<(), SemanticError> {
    let valid = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        Err(SemanticError::InvalidDigest {
            digest: digest.to_owned(),
            path: path.to_owned(),
        })
    }
}

fn relative_path(owner: &str, value: &str) -> Result<(), SemanticError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        Err(SemanticError::UnsafePath {
            owner: owner.to_owned(),
            path: value.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn overlaps(left: &str, right: &str) -> bool {
    let left = Path::new(left);
    let right = Path::new(right);
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn weak(policy: &str, base: &str, message: &str) -> SemanticError {
    SemanticError::WeakPolicy {
        policy: policy.to_owned(),
        base: base.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules_reject_parent_and_absolute() {
        assert!(relative_path("x", "../secret").is_err());
        assert!(relative_path("x", "/secret").is_err());
        assert!(relative_path("x", "claims/*.toml").is_ok());
    }

    #[test]
    fn transcription_cannot_claim_strong_binding() {
        let unit = crate::EvidenceUnitManifest {
            schema: "proofbound-evidence-unit/1".into(),
            id: "x".into(),
            adapter: AdapterKind::IndependentCheck,
            kind: EvidenceKind::TrustedTranscription,
            claims: vec!["TEST-X-001".into()],
            tier: 3,
            operation: crate::AdapterOperation {
                kind: OperationKind::IndependentCheck,
                package: None,
                targets: vec![],
                paths: vec![],
                manifest: None,
                inventory: None,
                checker: None,
                arguments: vec![],
            },
            evaluation_mode: None,
            binding_mode: Some(BindingMode::DigestTheorem),
            theorem: None,
            refinement_theorem: None,
            premises: vec![],
            assumptions: vec![],
            expected_inventory: vec![],
            inputs: vec![],
            outputs: vec![],
            environment_allowlist: vec![],
            bounded_domain: None,
            resource_budget: crate::ResourceBudget {
                time_seconds: 1,
                disk_bytes: 1,
                memory_bytes: 1,
            },
        };
        assert!(validate_unit_qualifiers(&unit).is_err());
    }

    #[test]
    fn primary_linkage_names_are_deserializable() {
        let value: crate::PrimaryLinkage = toml::from_str("value = \"artifact-bound\"")
            .map(|wrapper: LinkageWrapper| wrapper.value)
            .unwrap();
        assert_eq!(value, crate::PrimaryLinkage::ArtifactBound);
    }

    #[test]
    fn ci_workflow_registers_every_verify_only_stage_and_final_verifier() {
        let workflow = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.github/workflows/ci.yml"
        ));
        let xtask = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../xtask/src/main.rs"));
        let justfile = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../justfile"));
        let cargo_config = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.cargo/config.toml"
        ));

        for event in ["pull_request:", "push:", "schedule:", "release:"] {
            assert!(workflow.contains(event), "missing CI event {event}");
        }
        for stage in 1..=12 {
            let marker = format!("stage {stage}/12");
            assert!(xtask.contains(&marker), "missing typed CI stage {stage}");
        }
        assert!(
            !workflow.contains("proofbound update") && !xtask.contains("proofbound update"),
            "verify-only CI must never invoke proofbound update"
        );
        let preflight = workflow
            .find("cargo xtask preflight")
            .expect("hosted CI must run cheap preflight first");
        let smoke = workflow
            .find("cargo xtask release-smoke")
            .expect("hosted CI must smoke-test releases before proof tools");
        let kani = workflow
            .find("Install pinned Kani verifier after cheap gates")
            .expect("hosted CI must install Kani only after cheap gates");
        let full = workflow
            .find("cargo xtask ci")
            .expect("hosted CI must delegate the full typed plan to xtask");
        assert!(preflight < smoke && smoke < kani && kani < full);
        assert!(workflow.contains(
            "--diff \"${{ steps.revisions.outputs.base }}..${{ steps.revisions.outputs.head }}\""
        ));
        assert!(xtask.contains("OsString::from(\"check\"), OsString::from(\"--fresh\")"));
        assert!(xtask.contains("Role::FinalVerifier"));
        assert!(xtask.contains("workspace_binary(root, \"proofbound-verify\")"));
        assert!(
            justfile.contains("ci:\n    cargo xtask ci"),
            "the local gate must be a thin typed-xtask entry point"
        );
        assert!(
            cargo_config.contains("xtask = \"run --locked --package xtask --\""),
            "the xtask alias must not be allowed to rewrite Cargo.lock"
        );
    }

    #[derive(serde::Deserialize)]
    struct LinkageWrapper {
        value: crate::PrimaryLinkage,
    }
}
