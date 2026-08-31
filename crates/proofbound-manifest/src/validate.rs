use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;

use crate::{
    AdapterKind, AssumptionCategory, BindingMode, EvidenceKind, ImportMappingMode,
    MAX_TRANSLATION_CLAIMS, MAX_TRANSLATION_EXTERNAL_BRIDGES, MAX_TRANSLATION_INVOCATIONS,
    MAX_TRANSLATION_MAPPED_OUTPUTS, MAX_TRANSLATION_PATH_BYTES, MAX_TRANSLATION_SOURCE_ROOTS,
    MAX_TRANSLATION_SYMBOLS, MAX_TRANSLATION_TEMPLATE_AXIOMS, MAX_TRANSLATION_WARNINGS,
    OperationKind, ProjectBundle, TRANSLATION_RESERVED_PATH_COMPONENTS, TranslationOutputKind,
    TranslationPipeline,
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
    let mut generated_directories = Vec::<String>::new();
    for (id, (_, unit)) in &bundle.translation_units {
        translation_path(id, &unit.generated_dir)?;
        if Path::new(&unit.generated_dir).components().count() < 2 {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "generated_dir must have at least two path components".to_owned(),
            });
        }
        if generated_directories
            .iter()
            .any(|existing| overlaps(existing, &unit.generated_dir))
        {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "generated_dir overlaps another translation unit's ownership boundary"
                    .to_owned(),
            });
        }
        generated_directories.push(unit.generated_dir.clone());
    }
    let mut destinations = BTreeSet::<String>::new();
    let mut llbc_files = BTreeSet::new();
    for (id, (path, unit)) in &bundle.translation_units {
        schema(path, &unit.schema, "proofbound-translation-unit/2")?;
        local_id(id, path)?;
        if unit.pipeline != TranslationPipeline::CharonAeneas
            || unit.determinism_runs != 2
            || unit.determinism_normalization != "pretty-printed-llbc/1"
            || !unit.forbid_generated_axioms
            || unit.resource_budget.time_seconds == 0
            || unit.resource_budget.disk_bytes == 0
            || unit.resource_budget.memory_bytes == 0
        {
            return Err(SemanticError::Translation { unit: id.clone(), message: "pipeline must be charon-aeneas, determinism_runs must be 2, normalization must be pretty-printed-llbc/1, generated axioms must be forbidden, and every budget must be nonzero".to_owned() });
        }
        translation_path(id, &unit.handwritten_refinement)?;
        if generated_directories
            .iter()
            .any(|generated| overlaps(generated, &unit.handwritten_refinement))
        {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "handwritten refinement overlaps a generator-owned directory".to_owned(),
            });
        }
        if unit.invocations.is_empty() || unit.invocations.len() > MAX_TRANSLATION_INVOCATIONS {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: format!(
                    "invocations must contain between 1 and {MAX_TRANSLATION_INVOCATIONS} entries"
                ),
            });
        }
        if !unit
            .invocations
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
        {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "invocations must be in strict lexical id order".to_owned(),
            });
        }
        let generated_dir = Path::new(&unit.generated_dir);
        let mut lean_destinations = BTreeSet::<String>::new();
        let mut start_symbols = BTreeSet::<String>::new();
        for invocation in &unit.invocations {
            local_id(&invocation.id, path)?;
            if !valid_cargo_package(&invocation.cargo_package) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!("invocation {} has an invalid cargo_package", invocation.id),
                });
            }
            translation_path(id, &invocation.cargo_manifest)?;
            if Path::new(&invocation.cargo_manifest)
                .file_name()
                .and_then(|value| value.to_str())
                != Some("Cargo.toml")
            {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} cargo_manifest must name Cargo.toml",
                        invocation.id
                    ),
                });
            }
            if generated_directories
                .iter()
                .any(|generated| overlaps(generated, &invocation.cargo_manifest))
            {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} cargo_manifest overlaps generated_dir",
                        invocation.id
                    ),
                });
            }
            validate_exact_package_manifest(
                &bundle.root,
                id,
                &invocation.cargo_manifest,
                &invocation.cargo_package,
                bundle.project.limits.max_manifest_bytes,
            )?;
            if !valid_rust_identifier(&invocation.crate_name) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} has an invalid Rust crate_name",
                        invocation.id
                    ),
                });
            }
            translation_path(id, &invocation.llbc_file)?;
            if Path::new(&invocation.llbc_file)
                .extension()
                .and_then(|value| value.to_str())
                != Some("llbc")
            {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} llbc_file must have the .llbc extension",
                        invocation.id
                    ),
                });
            }
            if !llbc_files.insert(&invocation.llbc_file) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} repeats llbc_file {}",
                        invocation.id, invocation.llbc_file
                    ),
                });
            }
            if let Some(subdir) = &invocation.aeneas_subdir {
                translation_path(id, subdir)?;
            }
            for (name, values, allow_empty) in [
                ("start_from", &invocation.start_from, false),
                ("opaque", &invocation.opaque, true),
                ("include", &invocation.include, true),
            ] {
                if (!allow_empty && values.is_empty())
                    || values.len() > MAX_TRANSLATION_SYMBOLS
                    || values
                        .iter()
                        .any(|value| value.len() > 1024 || !valid_rust_path(value))
                    || !values.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: format!(
                            "invocation {} {name} must be in strict lexical order",
                            invocation.id
                        ),
                    });
                }
            }
            for symbol in &invocation.start_from {
                if !start_symbols.insert(symbol.clone()) {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: format!(
                            "start_from symbol {symbol} is repeated across invocations"
                        ),
                    });
                }
            }
            let symbol_count =
                invocation.start_from.len() + invocation.opaque.len() + invocation.include.len();
            let distinct_symbols = invocation
                .start_from
                .iter()
                .chain(&invocation.opaque)
                .chain(&invocation.include)
                .collect::<BTreeSet<_>>()
                .len();
            if distinct_symbols != symbol_count {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} repeats a symbol across start_from, opaque, and include",
                        invocation.id
                    ),
                });
            }
            if invocation.outputs.is_empty()
                || invocation.outputs.len() > MAX_TRANSLATION_MAPPED_OUTPUTS
            {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} outputs must contain between 1 and {MAX_TRANSLATION_MAPPED_OUTPUTS} entries",
                        invocation.id,
                    ),
                });
            }
            if !invocation.outputs.windows(2).all(|pair| {
                (&pair[0].produced, &pair[0].destination, pair[0].kind)
                    < (&pair[1].produced, &pair[1].destination, pair[1].kind)
            }) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} outputs must be in strict produced/destination/kind order",
                        invocation.id
                    ),
                });
            }
            let mut produced = BTreeSet::<String>::new();
            let mut lean_sources = 0_usize;
            let mut translation_reports = 0_usize;
            for output in &invocation.outputs {
                translation_path(id, &output.produced)?;
                translation_path(id, &output.destination)?;
                if produced
                    .iter()
                    .any(|existing| overlaps(existing, &output.produced))
                {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: format!(
                            "invocation {} has duplicate or prefix-overlapping produced output {}",
                            invocation.id, output.produced
                        ),
                    });
                }
                produced.insert(output.produced.clone());
                if destinations
                    .iter()
                    .any(|existing| overlaps(existing, &output.destination))
                {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: format!(
                            "destination {} is duplicate or prefix-overlaps another destination",
                            output.destination
                        ),
                    });
                }
                destinations.insert(output.destination.clone());
                let destination = Path::new(&output.destination);
                if destination == generated_dir || !destination.starts_with(generated_dir) {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: format!(
                            "destination {} is not strictly beneath generated_dir",
                            output.destination
                        ),
                    });
                }
                let expected_extension = match output.kind {
                    TranslationOutputKind::LeanSource => {
                        if let Some(subdir) = invocation.aeneas_subdir.as_deref() {
                            let produced = Path::new(&output.produced);
                            let subdir = Path::new(subdir);
                            if produced == subdir || !produced.starts_with(subdir) {
                                return Err(SemanticError::Translation {
                                    unit: id.clone(),
                                    message: format!(
                                        "invocation {} lean-source {} must be strictly inside aeneas_subdir {}",
                                        invocation.id,
                                        output.produced,
                                        subdir.display()
                                    ),
                                });
                            }
                        }
                        lean_sources += 1;
                        lean_destinations.insert(output.destination.clone());
                        "lean"
                    }
                    TranslationOutputKind::TranslationReport => {
                        if output.produced != "translation.json" {
                            return Err(SemanticError::Translation {
                                unit: id.clone(),
                                message: format!(
                                    "invocation {} translation report must be the root-level Aeneas output translation.json",
                                    invocation.id
                                ),
                            });
                        }
                        translation_reports += 1;
                        "json"
                    }
                };
                if [output.produced.as_str(), output.destination.as_str()]
                    .into_iter()
                    .any(|value| {
                        Path::new(value)
                            .extension()
                            .and_then(|extension| extension.to_str())
                            != Some(expected_extension)
                    })
                {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: format!(
                            "{} output {} must use the .{expected_extension} extension",
                            match output.kind {
                                TranslationOutputKind::LeanSource => "lean-source",
                                TranslationOutputKind::TranslationReport => "translation-report",
                            },
                            output.produced
                        ),
                    });
                }
            }
            if lean_sources == 0 || translation_reports != 1 {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "invocation {} must map at least one lean-source and exactly one translation-report",
                        invocation.id
                    ),
                });
            }
        }
        let mapped_output_limit = bundle
            .project
            .limits
            .max_files
            .min(MAX_TRANSLATION_MAPPED_OUTPUTS);
        if destinations.len() > mapped_output_limit {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: format!(
                    "{} mapped outputs exceed the effective limit {} (project max_files {}, fixed translation maximum {})",
                    destinations.len(),
                    mapped_output_limit,
                    bundle.project.limits.max_files,
                    MAX_TRANSLATION_MAPPED_OUTPUTS,
                ),
            });
        }
        match unit.import_mapping.mode {
            ImportMappingMode::ExternalSourceRoot => {
                if unit.import_mapping.source_roots.is_empty()
                    || unit.import_mapping.source_roots.len() > MAX_TRANSLATION_SOURCE_ROOTS
                    || !unit
                        .import_mapping
                        .source_roots
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
                    || unit.import_mapping.rewrite_digest.is_some()
                {
                    return Err(SemanticError::Translation {
                        unit: id.clone(),
                        message: "external-source-root requires nonempty, strictly sorted source_roots and forbids rewrite_digest".to_owned(),
                    });
                }
                for root in &unit.import_mapping.source_roots {
                    translation_path(id, root)?;
                    let root_path = Path::new(root);
                    if generated_directories.iter().any(|generated| {
                        root_path == Path::new(generated)
                            || root_path.starts_with(Path::new(generated))
                    }) {
                        return Err(SemanticError::Translation {
                            unit: id.clone(),
                            message: format!(
                                "external source root {root} must not be inside generated_dir"
                            ),
                        });
                    }
                }
            }
            ImportMappingMode::AuditedRewrite => {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: "audited-rewrite is reserved but unsupported until a typed rewrite implementation exists".to_owned(),
                });
            }
        }
        if unit.claims.is_empty()
            || unit.claims.len() > MAX_TRANSLATION_CLAIMS
            || !unit.claims.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "claims must be in strict lexical order".to_owned(),
            });
        }
        if unit.external_bridges.len() > MAX_TRANSLATION_EXTERNAL_BRIDGES {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: format!(
                    "external_bridges exceeds {MAX_TRANSLATION_EXTERNAL_BRIDGES} entries"
                ),
            });
        }
        if !unit
            .external_bridges
            .windows(2)
            .all(|pair| pair[0].file < pair[1].file)
        {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "external_bridges must be in strict file order".to_owned(),
            });
        }
        let mut bridge_modules = BTreeSet::<String>::new();
        for bridge in &unit.external_bridges {
            translation_path(id, &bridge.file)?;
            digest_sha256(&bridge.reviewed_sha256, path)?;
            let Some(module) = bridge.module.as_deref() else {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "external bridge {} requires a valid module for external-source-root resolution",
                        bridge.file
                    ),
                });
            };
            if module.len() > 1024 || !valid_lean_module(module) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "external bridge {} requires a valid module for external-source-root resolution",
                        bridge.file
                    ),
                });
            }
            if !bridge_modules.insert(module.to_owned()) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!("external bridge module {module} is declared more than once"),
                });
            }
            if generated_directories
                .iter()
                .any(|generated| overlaps(generated, &bridge.file))
            {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "external bridge {} overlaps generator-owned directory",
                        bridge.file
                    ),
                });
            }
            let module_path = format!("{}.lean", module.replace('.', "/"));
            let matching_roots = unit
                .import_mapping
                .source_roots
                .iter()
                .filter(|root| {
                    Path::new(root.as_str()).join(&module_path) == Path::new(&bridge.file)
                })
                .count();
            if matching_roots != 1 {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "external bridge {} must resolve from exactly one declared source root",
                        bridge.file
                    ),
                });
            }
        }
        if unit.template_axioms.len() > MAX_TRANSLATION_TEMPLATE_AXIOMS {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: format!(
                    "template_axioms exceeds {MAX_TRANSLATION_TEMPLATE_AXIOMS} entries"
                ),
            });
        }
        if !unit
            .template_axioms
            .windows(2)
            .all(|pair| pair[0].file < pair[1].file)
        {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "template_axioms must be in strict file order".to_owned(),
            });
        }
        for template in &unit.template_axioms {
            translation_path(id, &template.file)?;
            if template.compiled {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!("template {} is marked compiled", template.file),
                });
            }
            let template_path = Path::new(&template.file);
            if template_path == generated_dir || !template_path.starts_with(generated_dir) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!("template {} is outside generated_dir", template.file),
                });
            }
            if !lean_destinations.contains(&template.file) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "template {} is not a declared lean-source destination",
                        template.file
                    ),
                });
            }
        }
        if unit.warning_inventory.len() > MAX_TRANSLATION_WARNINGS {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: format!("warning_inventory exceeds {MAX_TRANSLATION_WARNINGS} entries"),
            });
        }
        if !unit.warning_inventory.windows(2).all(|pair| {
            (&pair[0].artifact, pair[0].line, &pair[0].kind)
                < (&pair[1].artifact, pair[1].line, &pair[1].kind)
        }) {
            return Err(SemanticError::Translation {
                unit: id.clone(),
                message: "warning_inventory must be in strict artifact/line/kind order".to_owned(),
            });
        }
        for warning in &unit.warning_inventory {
            translation_path(id, &warning.artifact)?;
            if warning.line == 0 {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "warning artifact {} requires a positive line",
                        warning.artifact
                    ),
                });
            }
            let warning_path = Path::new(&warning.artifact);
            if warning_path == generated_dir || !warning_path.starts_with(generated_dir) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "warning artifact {} is outside generated_dir",
                        warning.artifact
                    ),
                });
            }
            if !lean_destinations.contains(&warning.artifact) {
                return Err(SemanticError::Translation {
                    unit: id.clone(),
                    message: format!(
                        "warning artifact {} is not a declared lean-source destination",
                        warning.artifact
                    ),
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
    validate_translation_evidence(bundle)?;
    Ok(())
}

fn validate_translation_evidence(bundle: &ProjectBundle) -> Result<(), SemanticError> {
    for (evidence_id, (_, evidence)) in &bundle.evidence_units {
        if evidence.adapter != AdapterKind::CharonAeneas
            || evidence.operation.kind != OperationKind::Translation
        {
            continue;
        }
        let Some(manifest) = evidence.operation.manifest.as_deref() else {
            return Err(SemanticError::Translation {
                unit: evidence_id.clone(),
                message: "translation evidence requires operation.manifest".to_owned(),
            });
        };
        let manifest_path = bundle.root.join(manifest);
        let Some((_, translation)) = bundle
            .translation_units
            .values()
            .find(|(path, _)| path == &manifest_path)
        else {
            return Err(SemanticError::Translation {
                unit: evidence_id.clone(),
                message: format!(
                    "operation.manifest {manifest} is not a registered translation unit"
                ),
            });
        };
        let targets = translation
            .invocations
            .iter()
            .flat_map(|invocation| invocation.start_from.iter().cloned())
            .collect::<Vec<_>>();
        if !evidence.outputs.is_empty()
            || !evidence.expected_inventory.is_empty()
            || evidence.operation.targets != targets
            || evidence.claims != translation.claims
            || evidence.resource_budget != translation.resource_budget
            || !evidence.inputs.iter().any(|input| input == manifest)
        {
            return Err(SemanticError::Translation {
                unit: evidence_id.clone(),
                message: "translation evidence must have no committed outputs or secondary expected_inventory and must exactly match the registered manifest, flattened start inventory, claims, and budget".to_owned(),
            });
        }
    }
    Ok(())
}

fn valid_rust_identifier(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn valid_rust_path(value: &str) -> bool {
    value.split("::").all(valid_rust_identifier)
}

fn valid_lean_module(value: &str) -> bool {
    value.split('.').all(|part| {
        part.bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
            && part
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    })
}

fn valid_cargo_package(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte == b'_' || byte == b'.' || byte == b'-' || byte.is_ascii_alphanumeric()
        })
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
        && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && id.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
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

fn translation_path(owner: &str, value: &str) -> Result<(), SemanticError> {
    if value.len() > MAX_TRANSLATION_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || value.bytes().any(|byte| !(b' '..=b'~').contains(&byte))
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || value
            .split('/')
            .any(|component| TRANSLATION_RESERVED_PATH_COMPONENTS.contains(&component))
    {
        return Err(SemanticError::UnsafePath {
            owner: owner.to_owned(),
            path: value.to_owned(),
        });
    }
    relative_path(owner, value)
}

fn validate_exact_package_manifest(
    root: &Path,
    unit: &str,
    relative: &str,
    expected_package: &str,
    max_bytes: u64,
) -> Result<(), SemanticError> {
    let mut candidate = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            return Err(SemanticError::UnsafePath {
                owner: unit.to_owned(),
                path: relative.to_owned(),
            });
        };
        candidate.push(component);
        let metadata =
            fs::symlink_metadata(&candidate).map_err(|error| SemanticError::Translation {
                unit: unit.to_owned(),
                message: format!("cannot read package manifest {relative}: {error}"),
            })?;
        if metadata.file_type().is_symlink() {
            return Err(SemanticError::Translation {
                unit: unit.to_owned(),
                message: format!("package manifest {relative} crosses a symlink"),
            });
        }
    }
    let metadata =
        fs::symlink_metadata(&candidate).map_err(|error| SemanticError::Translation {
            unit: unit.to_owned(),
            message: format!("cannot read package manifest {relative}: {error}"),
        })?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(SemanticError::Translation {
            unit: unit.to_owned(),
            message: format!(
                "package manifest {relative} must be a regular file no larger than project max_manifest_bytes {max_bytes}"
            ),
        });
    }
    let bytes = fs::read(&candidate).map_err(|error| SemanticError::Translation {
        unit: unit.to_owned(),
        message: format!("cannot read package manifest {relative}: {error}"),
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|error| SemanticError::Translation {
        unit: unit.to_owned(),
        message: format!("package manifest {relative} is not UTF-8: {error}"),
    })?;
    let manifest: toml::Value =
        toml::from_str(text).map_err(|error| SemanticError::Translation {
            unit: unit.to_owned(),
            message: format!("package manifest {relative} is invalid TOML: {error}"),
        })?;
    let actual = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str);
    if actual != Some(expected_package) {
        return Err(SemanticError::Translation {
            unit: unit.to_owned(),
            message: format!(
                "package manifest {relative} must contain literal [package].name = {expected_package:?}"
            ),
        });
    }
    Ok(())
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

    fn repository_bundle() -> crate::ProjectBundle {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = crate_dir.parent().and_then(|path| path.parent()).unwrap();
        crate::ProjectBundle::load(root).unwrap()
    }

    #[test]
    fn path_rules_are_portable_component_normal_and_byte_bounded() {
        for invalid in [
            "../secret",
            "/secret",
            "./secret",
            "claims//one.toml",
            "claims/",
            "claims\\one.toml",
            "claims/one\n.toml",
            "claims/café.toml",
            ".git/objects",
            "lean/target/Funs.lean",
        ] {
            assert!(
                translation_path("x", invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(translation_path("x", &"a".repeat(MAX_TRANSLATION_PATH_BYTES + 1)).is_err());
        assert!(translation_path("x", &"a".repeat(MAX_TRANSLATION_PATH_BYTES)).is_ok());
        assert!(translation_path("x", "claims/*.toml").is_ok());
    }

    #[test]
    fn local_ids_use_the_public_segmented_grammar() {
        let path = Path::new("translation.toml");
        for invalid in ["", "A", "a--b", "a-", "a_b", "a.b"] {
            assert!(local_id(invalid, path).is_err(), "accepted {invalid:?}");
        }
        for valid in ["a", "a-b", "a1-b2"] {
            assert!(local_id(valid, path).is_ok(), "rejected {valid:?}");
        }
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
    fn translation_v2_rejects_reserved_rewrite_and_selector_injection() {
        let mut bundle = repository_bundle();
        let (_, translation) = bundle.translation_units.get_mut("transfer-kernel").unwrap();
        translation.import_mapping.mode = ImportMappingMode::AuditedRewrite;
        translation.import_mapping.source_roots.clear();
        translation.import_mapping.rewrite_digest = Some(format!("sha256:{}", "01".repeat(32)));
        assert!(validate_translations(&bundle).is_err());

        let mut bundle = repository_bundle();
        bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .invocations[0]
            .start_from = vec!["allowance_kernel::decide_transfer,--include".to_owned()];
        assert!(validate_translations(&bundle).is_err());
    }

    #[test]
    fn translation_v2_rejects_prefix_collisions_and_reused_llbc_paths() {
        let mut bundle = repository_bundle();
        let invocation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .invocations[0];
        invocation.outputs.insert(
            1,
            crate::TranslationOutputMapping {
                kind: TranslationOutputKind::LeanSource,
                produced: "Funs.lean/Nested.lean".to_owned(),
                destination: "demo/allowance/lean/Generated/Allowance/Funs.lean/Nested.lean"
                    .to_owned(),
            },
        );
        assert!(validate_translations(&bundle).is_err());

        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        let mut duplicate = translation.invocations[0].clone();
        duplicate.id = "second-kernel".to_owned();
        translation.invocations.push(duplicate);
        assert!(validate_translations(&bundle).is_err());
    }

    #[test]
    fn translation_v2_rejects_repeated_starts_across_invocations() {
        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        let mut duplicate = translation.invocations[0].clone();
        duplicate.id = "second-kernel".to_owned();
        duplicate.llbc_file = "second_kernel.llbc".to_owned();
        for output in &mut duplicate.outputs {
            output.destination = output
                .destination
                .replace("Generated/Allowance/", "Generated/Allowance/Second/");
        }
        translation.invocations.push(duplicate);
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("repeated across invocations"), "{error}");
    }

    #[test]
    fn translation_v2_subdir_layout_keeps_lean_below_it_and_report_at_root() {
        let mut bundle = repository_bundle();
        let invocation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .invocations[0];
        invocation.aeneas_subdir = Some("Transfer".to_owned());
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("strictly inside aeneas_subdir"), "{error}");

        let mut bundle = repository_bundle();
        let invocation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .invocations[0];
        invocation.aeneas_subdir = Some("Transfer".to_owned());
        for output in &mut invocation.outputs {
            if output.kind == TranslationOutputKind::LeanSource {
                output.produced = format!("Transfer/{}", output.produced);
            }
        }
        let _ = invocation;
        assert!(validate_translations(&bundle).is_ok());

        let report = bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .invocations[0]
            .outputs
            .iter_mut()
            .find(|output| output.kind == TranslationOutputKind::TranslationReport)
            .unwrap();
        report.produced = "Transfer/translation.json".to_owned();
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("root-level"), "{error}");
    }

    #[test]
    fn translation_v2_rejects_duplicate_external_bridge_modules() {
        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        translation
            .import_mapping
            .source_roots
            .push("z-external-root".to_owned());
        let mut duplicate = translation.external_bridges[0].clone();
        duplicate.file = "z-external-root/ProofboundDemo/Bridges/Kernel.lean".to_owned();
        translation.external_bridges.push(duplicate);
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(
            error.contains("module") && error.contains("more than once"),
            "{error}"
        );
    }

    #[test]
    fn translation_v2_requires_a_literal_matching_package_manifest() {
        let mut bundle = repository_bundle();
        bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .invocations[0]
            .cargo_package = "different-package".to_owned();
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("literal [package].name"), "{error}");
    }

    #[test]
    fn translation_side_inventories_must_name_mapped_lean_outputs() {
        let mut bundle = repository_bundle();
        bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .warning_inventory
            .push(crate::WarningInventory {
                artifact: "demo/allowance/lean/Generated/Allowance/Undeclared.lean".to_owned(),
                line: 1,
                kind: crate::TranslationWarningKind::UpstreamSorry,
            });
        assert!(validate_translations(&bundle).is_err());

        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        translation.warning_inventory.push(crate::WarningInventory {
            artifact: translation.invocations[0].outputs[0].destination.clone(),
            line: 0,
            kind: crate::TranslationWarningKind::UpstreamSorry,
        });
        assert!(validate_translations(&bundle).is_err());
    }

    #[test]
    fn translation_roots_and_output_counts_are_fail_closed() {
        let mut bundle = repository_bundle();
        bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1
            .import_mapping
            .source_roots = vec!["demo/allowance/lean/ProofboundDemo".to_owned()];
        assert!(validate_translations(&bundle).is_err());

        let mut bundle = repository_bundle();
        bundle.project.limits.max_files = 2;
        assert!(validate_translations(&bundle).is_err());
    }

    #[test]
    fn translation_inventory_ceilings_are_fail_closed() {
        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        let invocation = translation.invocations[0].clone();
        translation
            .invocations
            .resize(MAX_TRANSLATION_INVOCATIONS + 1, invocation);
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("invocations must contain"), "{error}");

        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        let bridge = translation.external_bridges[0].clone();
        translation
            .external_bridges
            .resize(MAX_TRANSLATION_EXTERNAL_BRIDGES + 1, bridge);
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("external_bridges exceeds"), "{error}");

        let mut bundle = repository_bundle();
        let translation = &mut bundle
            .translation_units
            .get_mut("transfer-kernel")
            .unwrap()
            .1;
        let warning = crate::WarningInventory {
            artifact: translation.invocations[0].outputs[0].destination.clone(),
            line: 1,
            kind: crate::TranslationWarningKind::UpstreamSorry,
        };
        translation
            .warning_inventory
            .resize(MAX_TRANSLATION_WARNINGS + 1, warning);
        let error = validate_translations(&bundle).unwrap_err().to_string();
        assert!(error.contains("warning_inventory exceeds"), "{error}");
    }

    #[test]
    fn translation_evidence_is_an_exact_manifest_cross_check() {
        let mut bundle = repository_bundle();
        let translation = &bundle.translation_units["transfer-kernel"].1;
        let manifest = "demo/allowance/proofbound/translations/transfer-kernel.toml";
        let targets = translation
            .invocations
            .iter()
            .flat_map(|invocation| invocation.start_from.iter().cloned())
            .collect::<Vec<_>>();
        let mut evidence = bundle.evidence_units.values().next().unwrap().1.clone();
        evidence.id = "translation-cross-check".to_owned();
        evidence.adapter = AdapterKind::CharonAeneas;
        evidence.operation.kind = OperationKind::Translation;
        evidence.operation.manifest = Some(manifest.to_owned());
        evidence.operation.targets = targets;
        evidence.claims = translation.claims.clone();
        evidence.resource_budget = translation.resource_budget;
        evidence.outputs.clear();
        evidence.inputs.push(manifest.to_owned());
        bundle.evidence_units.insert(
            evidence.id.clone(),
            (bundle.root.join("translation-cross-check.toml"), evidence),
        );
        assert!(validate_translation_evidence(&bundle).is_ok());

        bundle
            .evidence_units
            .get_mut("translation-cross-check")
            .unwrap()
            .1
            .expected_inventory
            .push("duplicated-authority".to_owned());
        assert!(validate_translation_evidence(&bundle).is_err());
        bundle
            .evidence_units
            .get_mut("translation-cross-check")
            .unwrap()
            .1
            .expected_inventory
            .clear();

        bundle
            .evidence_units
            .get_mut("translation-cross-check")
            .unwrap()
            .1
            .outputs
            .push("demo/allowance/lean/Generated/Allowance".to_owned());
        assert!(validate_translation_evidence(&bundle).is_err());
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
