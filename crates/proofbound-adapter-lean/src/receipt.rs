use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
    str::FromStr,
};

use proofbound_core::{
    ArtifactIdentity, ArtifactLogicalName, AssumptionId, CacheOrigin, ClaimId, CommandSpec,
    EVIDENCE_SCHEMA_V3, EvaluationMode, EvidenceId, EvidenceKind, EvidenceProvenance,
    EvidenceRecord, EvidenceStatus, ExecutionKind, NodeId, PremiseId, ResourceBudget, Sha256Digest,
    TheoremEvidence, TreeState, UnitId,
};
use proofbound_evidence::{
    ClosureKind, ClosureLimits, build_closure, canonical_json, git_identity,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    error::{AdapterError, CONFIGURATION, PROVENANCE, RESOURCE},
    model::{AuditSource, CapturedExecution, LeanAdapterUnit, VerifiedAudit},
    runtime::adapter_identity,
};

#[derive(Serialize)]
struct ConfigurationIdentity<'a> {
    schema: &'static str,
    evidence_unit: &'a proofbound_manifest::EvidenceUnitManifest,
    environment_id: &'a proofbound_core::EnvironmentId,
    claim_inventory: &'a [crate::model::ExpectedClaim],
    audit_mode: &'static str,
}

#[derive(Serialize)]
struct ResultIdentity<'a> {
    schema: &'static str,
    audit_identity: Sha256Digest,
    claim_id: &'a str,
    declaration: &'a str,
    declaration_kind: crate::model::DeclarationKind,
    statement_encoding: &'static str,
    statement_sha256: Sha256Digest,
    foundational_axioms: &'a BTreeSet<String>,
    project_axioms: &'a BTreeSet<AssumptionId>,
    evaluation_mode: EvaluationMode,
}

pub fn build_theorem_evidence(
    root: &Path,
    unit: &LeanAdapterUnit,
    verified: &VerifiedAudit,
    execution: &CapturedExecution,
    status: EvidenceStatus,
) -> Result<EvidenceRecord, AdapterError> {
    let evidence_unit = &unit.evidence_unit;
    let claim_id = ClaimId::new(
        evidence_unit
            .claims
            .first()
            .expect("audit validation establishes one claim")
            .clone(),
    )
    .map_err(|error| {
        AdapterError::new(CONFIGURATION, format!("invalid target claim ID: {error}"))
    })?;
    let unit_id = UnitId::new(format!("unit:{}", evidence_unit.id)).map_err(|error| {
        AdapterError::new(CONFIGURATION, format!("invalid evidence unit ID: {error}"))
    })?;
    let assumptions = parse_ids::<AssumptionId>(&evidence_unit.assumptions, "assumption")?;
    let premises = parse_ids::<PremiseId>(&evidence_unit.premises, "premise")?;
    let evaluation_mode = match evidence_unit
        .evaluation_mode
        .expect("audit validation establishes evaluation mode")
    {
        proofbound_manifest::EvaluationMode::Kernel => EvaluationMode::Kernel,
        proofbound_manifest::EvaluationMode::Native => EvaluationMode::Native,
    };

    let budget_ms = evidence_unit
        .resource_budget
        .time_seconds
        .checked_mul(1_000)
        .ok_or_else(|| AdapterError::new(RESOURCE, "time budget overflows milliseconds"))?;
    if execution.resource_usage.time_ms > budget_ms
        || execution.resource_usage.peak_disk_bytes > evidence_unit.resource_budget.disk_bytes
        || execution
            .resource_usage
            .peak_memory_bytes
            .is_some_and(|actual| actual > evidence_unit.resource_budget.memory_bytes)
    {
        return Err(AdapterError::new(
            RESOURCE,
            "Lean audit exceeded its declared time, disk, or memory budget",
        ));
    }

    let closure = exact_closure(
        root,
        &evidence_unit.inputs,
        evidence_unit.resource_budget.disk_bytes,
    )?;
    let semantic_source_closure = parse_prefixed_digest(&closure.id, "semantic closure")?;
    let input_artifacts = closure
        .members
        .iter()
        .map(|member| {
            Ok(ArtifactIdentity {
                logical_name: ArtifactLogicalName::new(member.path.clone()).map_err(|error| {
                    AdapterError::new(PROVENANCE, format!("invalid input artifact name: {error}"))
                })?,
                sha256: parse_prefixed_digest(&member.sha256, "input artifact")?,
                size_bytes: member.bytes,
            })
        })
        .collect::<Result<_, AdapterError>>()?;
    let generated_artifacts = exact_artifacts(root, &evidence_unit.outputs)?;

    let git = git_identity(root).map_err(|error| {
        AdapterError::new(
            PROVENANCE,
            format!("cannot bind project revision and tree state: {error}"),
        )
    })?;
    let tree_state = match git.tree_state.as_str() {
        "clean" => TreeState::Clean,
        "dirty" => TreeState::Dirty,
        other => {
            return Err(AdapterError::new(
                PROVENANCE,
                format!("unsupported git tree state '{other}'"),
            ));
        }
    };

    let configuration = ConfigurationIdentity {
        schema: "proofbound-lean-unit-configuration/1",
        evidence_unit,
        environment_id: &unit.environment_id,
        claim_inventory: &unit.claim_inventory,
        audit_mode: match unit.audit {
            AuditSource::Execute => "execute",
            AuditSource::Captured { .. } => "captured",
        },
    };
    let unit_configuration_sha256 = domain_digest(
        b"proofbound:lean-unit-configuration/1\0",
        &canonical_json(&configuration).map_err(|error| {
            AdapterError::new(
                PROVENANCE,
                format!("cannot canonicalize Lean unit configuration: {error}"),
            )
        })?,
    );
    let result = ResultIdentity {
        schema: "proofbound-lean-result/1",
        audit_identity: verified.audit_identity,
        claim_id: claim_id.as_str(),
        declaration: &verified.target.declaration,
        declaration_kind: verified.target.kind,
        statement_encoding: crate::wire::STATEMENT_ENCODING,
        statement_sha256: verified.statement_sha256,
        foundational_axioms: &verified.foundational_axioms,
        project_axioms: &verified.project_axioms,
        evaluation_mode,
    };
    let deterministic_result_identity = domain_digest(
        b"proofbound:lean-result/1\0",
        &canonical_json(&result).map_err(|error| {
            AdapterError::new(
                PROVENANCE,
                format!("cannot canonicalize Lean result identity: {error}"),
            )
        })?,
    );
    let evidence_id =
        EvidenceId::new(format!("theorem:{}", evidence_unit.id)).map_err(|error| {
            AdapterError::new(CONFIGURATION, format!("invalid evidence ID: {error}"))
        })?;
    let node_id = NodeId::new(format!("evidence:{evidence_id}"))
        .map_err(|error| AdapterError::new(CONFIGURATION, format!("invalid node ID: {error}")))?;

    let record = EvidenceRecord {
        schema: EVIDENCE_SCHEMA_V3.to_owned(),
        id: evidence_id,
        node_id,
        unit_id,
        kind: EvidenceKind::Theorem,
        status,
        claims: BTreeSet::from([claim_id.clone()]),
        evaluation_mode: Some(evaluation_mode),
        binding_mode: None,
        theorem: Some(TheoremEvidence {
            declaration: verified.target.declaration.clone(),
            statement_encoding: crate::wire::STATEMENT_ENCODING.to_owned(),
            statement_wire: verified.target.expr_wire.clone(),
            statement_sha256: verified.statement_sha256,
            attributed_claim: claim_id.clone(),
            environment: unit.environment_id.clone(),
            axiom_audit_passed: true,
            contains_sorry_ax: false,
            foundational_axioms: verified.foundational_axioms.clone(),
            project_axioms: verified.project_axioms.clone(),
        }),
        artifact_binding: None,
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: verified.inventory.clone(),
        assumptions,
        premises,
        open_obligation: None,
        provenance: EvidenceProvenance {
            project_revision: git.revision,
            tree_state,
            semantic_source_closure,
            additional_closures: Vec::new(),
            input_artifacts,
            generated_artifacts,
            tool: execution.tool.clone(),
            adapter: adapter_identity()?,
            execution_kind: ExecutionKind::ObservedProcesses,
            commands: execution.commands.clone(),
            runs: execution.runs.clone(),
            normalization: execution.normalization.clone(),
            reproduction_command: CommandSpec {
                program: "proofbound".to_owned(),
                args: vec!["reproduce".to_owned(), evidence_unit.id.clone()],
                environment_allowlist: Vec::new(),
            },
            started_unix_ms: execution.started_unix_ms,
            completed_unix_ms: execution.completed_unix_ms,
            deterministic_result_identity,
            unit_configuration_sha256,
            resource_budget: ResourceBudget {
                time_ms: budget_ms,
                disk_bytes: evidence_unit.resource_budget.disk_bytes,
                memory_bytes: evidence_unit.resource_budget.memory_bytes,
            },
            resource_usage: execution.resource_usage.clone(),
            cache_origin: CacheOrigin::Executed,
            prior_receipt_sha256: None,
        },
    };
    record.validate(&claim_id).map_err(|errors| {
        AdapterError::new(
            PROVENANCE,
            format!("constructed theorem evidence failed core validation: {errors}"),
        )
    })?;
    Ok(record)
}

fn exact_closure(
    root: &Path,
    inputs: &[String],
    max_total_bytes: u64,
) -> Result<proofbound_evidence::ClosureRecord, AdapterError> {
    if inputs.is_empty() {
        return Err(AdapterError::new(
            PROVENANCE,
            "Lean theorem unit must declare at least one semantic input",
        ));
    }
    let expected = validate_exact_paths(root, inputs)?;
    let closure = build_closure(
        root,
        ClosureKind::Semantic,
        inputs,
        None,
        "evidence-unit-inputs/1",
        ClosureLimits {
            max_files: inputs.len(),
            max_total_bytes,
            max_file_bytes: max_total_bytes,
        },
    )
    .map_err(|error| {
        AdapterError::new(
            PROVENANCE,
            format!("cannot build semantic source closure: {error}"),
        )
    })?;
    let actual: BTreeSet<_> = closure
        .members
        .iter()
        .map(|member| member.path.clone())
        .collect();
    if actual != expected {
        return Err(AdapterError::new(
            PROVENANCE,
            format!(
                "semantic closure skipped or added configured inputs: expected={expected:?}, actual={actual:?}"
            ),
        ));
    }
    Ok(closure)
}

fn exact_artifacts(root: &Path, outputs: &[String]) -> Result<Vec<ArtifactIdentity>, AdapterError> {
    let paths = validate_exact_paths(root, outputs)?;
    let mut artifacts = Vec::with_capacity(paths.len());
    for logical_name in paths {
        let bytes = fs::read(root.join(&logical_name)).map_err(|error| {
            AdapterError::new(
                PROVENANCE,
                format!("cannot read generated artifact '{logical_name}': {error}"),
            )
        })?;
        artifacts.push(ArtifactIdentity {
            logical_name: ArtifactLogicalName::new(logical_name).map_err(|error| {
                AdapterError::new(
                    PROVENANCE,
                    format!("invalid generated artifact name: {error}"),
                )
            })?,
            sha256: Sha256Digest::of_bytes(&bytes),
            size_bytes: u64::try_from(bytes.len()).map_err(|_| {
                AdapterError::new(PROVENANCE, "generated artifact length exceeds u64")
            })?,
        });
    }
    Ok(artifacts)
}

fn validate_exact_paths(root: &Path, paths: &[String]) -> Result<BTreeSet<String>, AdapterError> {
    let mut validated = BTreeSet::new();
    for path in paths {
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || path
                .bytes()
                .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{'))
        {
            return Err(AdapterError::new(
                PROVENANCE,
                format!("Lean evidence path must be an exact canonical relative file: '{path}'"),
            ));
        }
        let metadata = fs::symlink_metadata(root.join(relative)).map_err(|error| {
            AdapterError::new(
                PROVENANCE,
                format!("cannot stat evidence path '{path}': {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(AdapterError::new(
                PROVENANCE,
                format!("evidence path '{path}' is not a regular non-symlink file"),
            ));
        }
        if !validated.insert(path.replace('\\', "/")) {
            return Err(AdapterError::new(
                PROVENANCE,
                format!("duplicate evidence path '{path}'"),
            ));
        }
    }
    Ok(validated)
}

fn parse_prefixed_digest(value: &str, kind: &str) -> Result<Sha256Digest, AdapterError> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        AdapterError::new(
            PROVENANCE,
            format!("{kind} has non-canonical digest '{value}'"),
        )
    })?;
    Sha256Digest::from_str(hex)
        .map_err(|error| AdapterError::new(PROVENANCE, format!("invalid {kind} digest: {error}")))
}

fn domain_digest(domain_with_nul: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain_with_nul);
    hasher.update(bytes);
    Sha256Digest::from_str(&hex::encode(hasher.finalize()))
        .expect("SHA-256 always renders canonical hex")
}

fn parse_ids<T>(values: &[String], kind: &str) -> Result<BTreeSet<T>, AdapterError>
where
    T: FromStr + Ord,
    <T as FromStr>::Err: std::fmt::Display,
{
    values
        .iter()
        .map(|value| {
            value.parse().map_err(|error| {
                AdapterError::new(
                    CONFIGURATION,
                    format!("invalid {kind} ID '{value}': {error}"),
                )
            })
        })
        .collect()
}
