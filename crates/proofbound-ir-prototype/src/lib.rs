//! Research-only producer projection for Experiment 0005.
//!
//! This crate does not define a production Proofbound wire. It projects the
//! preregistered corpus into a small typed record so an independently written
//! checker can test canonical identity and source-to-projection agreement.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod artifact_roles;
mod assurance;
mod assurance_v2;
mod derivation;
mod effects;
mod enforced;
mod enforced_batch;
mod frontend;
mod invalidation;
mod layered_sampling;
mod linux_enforcement;
mod linux_loader_enforcement;
mod migration;
mod native;
mod notifications;
mod portable;
mod sampling;
mod specifications;
mod windows_enforcement;

pub use artifact_roles::{
    ArtifactRoleReport, ArtifactUnitRoles, BoundArtifactRole, audit_artifact_roles,
};
pub use assurance::{
    Artifact, CacheInput, CaseProgram, IrAssumption, IrAssumptionDerivation, IrBackend,
    IrBoundedDomain, IrBudget, IrCache, IrCacheProvenance, IrClaim, IrClaimAdmission,
    IrClaimMeaning, IrClaimPresentation, IrClosure, IrClosureReference, IrCommand,
    IrDerivationTrace, IrDistributionRegistration, IrEnvironment, IrEvidence, IrEvidenceRequest,
    IrFacetDerivation, IrFamily, IrFamilyDetail, IrFlowScope, IrGraph, IrGraphEdge, IrGraphNode,
    IrMutationRegistration, IrMutualTheoremGroup, IrNativePremiseRule, IrPolicy, IrPolicyRecord,
    IrPremise, IrPremiseDischarge, IrProgrammeContext, IrProject, IrPropertyRegistration,
    IrProvenance, IrPublicationTrace, IrPythonPlugin, IrReportedStatus, IrRetainedFactValue, IrRun,
    IrSubjectClosure, IrTcbComponent, IrTool, IrUsage, IrValidationError, RetainedFact,
    family_kind, family_schema, validate_case_program,
};
pub use assurance_v2::{
    ASSURANCE_V2_MODEL_REPORT_SCHEMA, ASSURANCE_V2_PROGRAM_SCHEMA, ASSURANCE_V2_REPORT_SCHEMA,
    AssuranceV2Attack, AssuranceV2AttackCorpus, AssuranceV2AttackResult, AssuranceV2Decision,
    AssuranceV2Error, AssuranceV2Generation, AssuranceV2KernelReport, AssuranceV2Model,
    AssuranceV2ModelReport, AssuranceV2Profile, AssuranceV2Program, AssuranceV2Templates,
    execute_assurance_v2_corpus, expand_assurance_v2_profile, load_assurance_v2_corpus,
    validate_assurance_v2_program,
};
pub use derivation::{
    DerivationError, DerivationProgram, DerivationReport, GeneratedAdversarialCase,
    GeneratedCorpus, GeneratedValidCase, generate_derivation_corpus, validate_derivation_program,
};
pub use effects::{
    ArtifactIdentity, DeniedMode, EFFECT_ENFORCEMENT_SCHEMA, EFFECT_INVALIDATION_SCHEMA,
    EFFECT_MODEL_REPORT_SCHEMA, EFFECT_PLAN_SCHEMA, EFFECT_TRACE_SCHEMA, Effect, EffectAttack,
    EffectAttackAction, EffectAttackCorpus, EffectAttackResult, EffectCorpus, EffectDisposition,
    EffectError, EffectExpected, EffectInvalidation, EffectInvalidationResult, EffectModelReport,
    EffectObservation, EffectOutput, EffectPlan, EffectPlanResult, EffectTrace, EffectWorkload,
    EnforcementMechanism, EnforcementReceipt, ExecutionBoundary, ExpectedEffectPlan, ObservedValue,
    derive_effect_invalidation, execute_effect_corpus, execute_effect_plan, load_effect_corpus,
    validate_effect_plan, validate_effect_trace,
};
pub use enforced::{
    ENFORCED_CAPTURE_SCHEMA, ENFORCED_MODEL_REPORT_SCHEMA, ENFORCED_PLAN_SCHEMA,
    ENFORCEMENT_RECEIPT_SCHEMA, EnforcedAbsence, EnforcedArtifact, EnforcedAttackResult,
    EnforcedCapture, EnforcedCommand, EnforcedEnvironment, EnforcedError,
    EnforcedInvalidationResult, EnforcedMechanism, EnforcedMetrics, EnforcedMode,
    EnforcedModelReport, EnforcedOutcome, EnforcedPlan, EnforcedPlatform, EnforcedProbe,
    EnforcedProbeResult, EnforcedReceipt, EnforcedRun, EnforcedSubjectResult,
    capture_enforced_effects, render_seatbelt_policy, validate_enforced_capture,
    validate_enforced_capture_bytes, validate_enforced_model_report, validate_enforced_plan,
    validate_enforcement_receipt,
};
pub use enforced_batch::{
    BATCHED_CAPTURE_SCHEMA, BATCHED_REPORT_SCHEMA, BatchedCapture, BatchedError, BatchedMetrics,
    BatchedReport, BatchedSlot, BatchedSlotKind, capture_batched_enforcement,
    validate_batched_capture, validate_batched_capture_bytes, validate_batched_report,
};
pub use frontend::{
    EFFECTIVE_PROGRAMME_SCHEMA, EffectiveProgramme, FRONTEND_COMPILATION_SCHEMA,
    FRONTEND_PROGRAMME_SCHEMA, FRONTEND_RECEIPT_SCHEMA, FrontendBoundedDomain, FrontendBudget,
    FrontendCompilation, FrontendDependency, FrontendError, FrontendEvidence, FrontendMutation,
    FrontendOperation, FrontendProgramme, FrontendProgrammeControl, FrontendProject,
    FrontendPythonProperty, FrontendReceipt, FrontendSourceMap, FrontendSourceMapEntry,
    FrontendSourceSpan, SOURCE_MAP_SCHEMA, compare_frontend_programme_control,
    compile_dsl_frontend, compile_pkl_frontend, compile_pkl_frontend_with_identity,
    compile_toml_frontend, format_dsl_frontend, validate_effective_programme_bytes,
    validate_frontend_compilation, validate_frontend_compilation_bytes,
    validate_pkl_frontend_source,
};
pub use invalidation::{
    CacheDependencyEvidence, ChangedNode, ChangedNodeKind, DEPENDENCY_PROJECTION_DOMAIN,
    DEPENDENCY_PROJECTION_SCHEMA, DependencyNode, DependencyProjection, DependencyRole,
    DependencyUse, EnvironmentState, ExactRatio, INVALIDATION_TRACE_DOMAIN,
    INVALIDATION_TRACE_SCHEMA, InvalidationExecutionReport, InvalidationMetrics, InvalidationPath,
    InvalidationScenarioResult, InvalidationTrace, PathState, PermissionModel, ResolutionCandidate,
    dependency_node_id, derive_invalidation_trace, validate_cache_dependency_evidence,
    validate_dependency_projection, validate_invalidation_execution_report,
    validate_invalidation_trace, validate_projection_against_source,
};
pub use layered_sampling::{
    LayeredSamplingCase, LayeredSamplingError, LayeredSamplingReport,
    validate_layered_sampling_case,
};
pub use linux_enforcement::{
    LINUX_CAPTURE_SCHEMA, LINUX_POLICY_SCHEMA, LINUX_REPORT_SCHEMA, LinuxAttackResult,
    LinuxCapture, LinuxEnforcementError, LinuxMetrics, LinuxOutput, LinuxPlatform, LinuxPolicy,
    LinuxPolicyPlatform, LinuxPortabilityDelta, LinuxReport, LinuxSlot, validate_linux_capture,
    validate_linux_capture_bytes, validate_linux_report,
};
pub use linux_loader_enforcement::{
    LINUX_LOADER_CAPTURE_SCHEMA, LINUX_LOADER_POLICY_SCHEMA, LINUX_LOADER_REPORT_SCHEMA,
    LinuxLoaderError, LinuxLoaderIdentity, LinuxLoaderReport, validate_linux_loader_capture,
    validate_linux_loader_capture_bytes,
};
pub use migration::{
    FOREIGN_CALL_SCHEMA, FOREIGN_CONTRACT_SCHEMA, FOREIGN_OBSERVATIONS_SCHEMA, ForeignCall,
    ForeignContract, ForeignObservationEnvelope, ForeignObservationSet, MIXED_GRAPH_SCHEMA,
    MIXED_MODEL_REPORT_SCHEMA, MigrationError, MixedModelReport, encode_observation_envelope,
    execute_migration_corpus,
};
pub use native::{
    NATIVE_AST_SCHEMA, NATIVE_CERTIFICATE_SCHEMA, NATIVE_REPORT_SCHEMA, NativeAssuranceSummary,
    NativeAst, NativeAttack, NativeAttackCorpus, NativeAttackResult, NativeCertificate,
    NativeError, NativeInputRow, NativeMutantResult, NativeReport, NativeScope,
    NativeSolverReceipt, NativeValueRow, compile_native_artifact, derive_native_certificate,
    execute_native_corpus, generate_native_smt, parse_native_source, validate_native_artifact,
    validate_native_certificate, validate_native_report,
};
pub use notifications::{
    BaselineAlert, DecisionNotification, FactConsequence, FindingSeverity, GraphUpdate,
    NOTIFICATION_CORPUS_SCHEMA, NOTIFICATION_MODEL_REPORT_SCHEMA, NOTIFICATION_REPORT_SCHEMA,
    NotificationAttack, NotificationAttackAction, NotificationAttackCorpus,
    NotificationAttackResult, NotificationClaim, NotificationCorpus, NotificationDecisionReport,
    NotificationError, NotificationImpactPath, NotificationModelReport, NotificationScenario,
    PublicationConsequence, ScenarioIdentity, ToolFinding, UncertaintyFact, UncertaintyKind,
    derive_notification_report, execute_notification_corpus, load_notification_corpus,
    validate_notification_corpus, validate_notification_report,
};
pub use portable::{
    PORTABLE_FAMILY_PROJECTION_SCHEMA, PORTABLE_FAMILY_PROJECTION_V2_SCHEMA, PortableFamily,
    PortableFamilyProjection, PortableFamilyRecord, SamplingDetail, project_portable_families,
    project_portable_families_with_sampling,
};
pub use sampling::{
    SamplingContract, SamplingObservation, SamplingValidationError, SamplingValidationReport,
    validate_sampling_observation,
};
pub use specifications::{
    SPECIFICATION_EXECUTIONS_SCHEMA, SPECIFICATION_MODEL_REPORT_SCHEMA,
    SPECIFICATION_REPORT_SCHEMA, SPECIFICATION_SUITE_SCHEMA, SPECIFICATION_UNIVERSE_SCHEMA,
    SpecificationAttack, SpecificationAttackAction, SpecificationAttackCorpus,
    SpecificationAttackResult, SpecificationCarrier, SpecificationCase, SpecificationContract,
    SpecificationContractResult, SpecificationCounterexample, SpecificationError,
    SpecificationExecutions, SpecificationExpression, SpecificationImplementation,
    SpecificationModelReport, SpecificationMutantResult, SpecificationReplacement,
    SpecificationReport, SpecificationSuite, SpecificationType, SpecificationUniverse,
    SpecificationValue, SpecificationVariable, SpecificationVariableRole,
    derive_specification_report, execute_specification_corpus, load_specification_corpus,
    validate_specification_report,
};
pub use windows_enforcement::{
    WINDOWS_CAPTURE_SCHEMA, WINDOWS_POLICY_SCHEMA, WINDOWS_REPORT_SCHEMA, WindowsAppContainer,
    WindowsAttackResult, WindowsCapture, WindowsEnforcementError, WindowsHost, WindowsJobObject,
    WindowsMetrics, WindowsPolicy, WindowsPortabilityDelta, WindowsReport, WindowsRestrictedToken,
    WindowsTarget, compile_windows_policy, validate_windows_capture,
    validate_windows_capture_bytes, validate_windows_policy, validate_windows_report,
};

pub const CORPUS_SCHEMA: &str = "proofbound-research-projection-corpus/1";
pub const PROJECTION_SCHEMA: &str = "proofbound-assurance-ir-projection/1";
pub const PROJECTION_DOMAIN: &str = "proofbound-assurance-ir-projection/1";
const SUBJECT_CLOSURE_SCHEMA: &str = "proofbound-ir-subject-closure/1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    experiment: String,
    baseline: String,
    revision: u64,
    status: String,
    source_identity: String,
    projection_profiles: BTreeMap<String, Vec<String>>,
    supporting_sources: Vec<SupportingSource>,
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportingSource {
    path: String,
    sha256: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    role: String,
    evidence_family: String,
    source: Source,
    #[serde(default)]
    claim_sources: Vec<ClaimSource>,
    #[serde(default)]
    unit_id: Option<String>,
    claim_ids: Vec<String>,
    expected_claim: ExpectedClaim,
    projection_profiles: Vec<String>,
    toolchain_required_to_regenerate: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimSource {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: String,
    sha256: String,
    #[serde(default)]
    json_pointer: Option<String>,
    #[serde(default)]
    envelope_path: Option<String>,
    #[serde(default)]
    envelope_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedClaim {
    pub formal: String,
    pub linkage: String,
    pub assumption: String,
    pub policy_admitted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTraceBundle {
    pub schema: String,
    pub project: String,
    pub receipt_sha256: String,
    pub traces: Vec<IrDerivationTrace>,
    pub publication: IrPublicationTrace,
}

/// Derive a canonical, backend-neutral admission trace from a portable receipt.
pub fn derive_release_trace_bundle(receipt_bytes: &[u8]) -> Result<ReleaseTraceBundle> {
    let receipt = assurance::decode_strict_json(receipt_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (traces, publication) = release_derivation_traces(&receipt)?;
    Ok(ReleaseTraceBundle {
        schema: "proofbound-ir-release-trace-bundle/1".to_owned(),
        project: required_value_text(&receipt, "project")?.to_owned(),
        receipt_sha256: sha256_bytes(receipt_bytes),
        traces,
        publication,
    })
}

/// Check a claimed trace against an independent derivation from receipt inputs.
pub fn validate_release_trace_bundle(
    receipt_bytes: &[u8],
    trace_bytes: &[u8],
) -> std::result::Result<(), IrValidationError> {
    let value = assurance::decode_strict_json(trace_bytes)?;
    let canonical = canonical_json(&value)
        .map_err(|error| IrValidationError::new("IR-DECODE-INVALID", error.to_string()))?;
    if canonical != trace_bytes {
        return Err(IrValidationError::new(
            "IR-DECODE-NONCANONICAL",
            "trace bundle is not canonical JSON",
        ));
    }
    let actual: ReleaseTraceBundle = serde_json::from_value(value).map_err(|error| {
        IrValidationError::new("IR-DERIVATION-TRACE-MISMATCH", error.to_string())
    })?;
    let expected = derive_release_trace_bundle(receipt_bytes).map_err(|error| {
        IrValidationError::new("IR-DERIVATION-TRACE-MISMATCH", error.to_string())
    })?;
    if actual != expected {
        return Err(IrValidationError::new(
            "IR-DERIVATION-TRACE-MISMATCH",
            "trace bundle differs from independently derived receipt semantics",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionBatch {
    pub schema: String,
    pub experiment: String,
    pub baseline: String,
    pub corpus_sha256: String,
    pub cases: Vec<ProjectionCase>,
    pub projection_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCase {
    pub id: String,
    pub role: String,
    pub source: ProjectedSource,
    pub evidence_family: String,
    pub unit_id: Option<String>,
    pub claim_ids: Vec<String>,
    pub expected_claim: ExpectedClaim,
    pub registration: Option<RegistrationProjection>,
    pub semantic_case_id: Option<String>,
    pub projection_profiles: Vec<String>,
    pub program: CaseProgram,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedSource {
    pub path: String,
    pub sha256: String,
    pub json_pointer: Option<String>,
    pub envelope_path: Option<String>,
    pub envelope_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProjection {
    pub schema: String,
    pub unit_id: String,
    pub declared_kind: String,
    pub adapter: String,
    pub operation: String,
    pub claims: Vec<String>,
    pub assumptions: Vec<String>,
    pub premises: Vec<String>,
    pub open_obligation: Option<String>,
    pub evaluation_mode: Option<String>,
    pub binding_mode: Option<String>,
    pub inventory: Vec<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub tier: u64,
    pub environment_allowlist: Vec<String>,
    pub resource_budget: Value,
    pub operation_configuration: Value,
    pub family_configuration: Value,
    pub family_configuration_sha256: String,
}

/// Project the frozen corpus without executing any evidence backend.
pub fn project_corpus(root: &Path, corpus_path: &Path) -> Result<ProjectionBatch> {
    let corpus_bytes =
        fs::read(corpus_path).with_context(|| format!("read corpus {}", corpus_path.display()))?;
    let corpus: Corpus = serde_json::from_slice(&corpus_bytes).context("decode corpus")?;
    validate_corpus_header(&corpus)?;

    for source in &corpus.supporting_sources {
        let _ = &source.role;
        verify_source(root, &source.path, &source.sha256)?;
    }

    let mut projected = Vec::with_capacity(corpus.cases.len());
    for case in &corpus.cases {
        ensure!(
            !case
                .toolchain_required_to_regenerate
                .iter()
                .any(String::is_empty)
        );
        for profile in &case.projection_profiles {
            ensure!(
                corpus.projection_profiles.contains_key(profile),
                "case {} names unknown projection profile {profile}",
                case.id
            );
        }
        projected.push(project_case(root, case)?);
    }
    projected.sort_by(|left, right| left.id.cmp(&right.id));
    for pair in projected.windows(2) {
        ensure!(pair[0].id != pair[1].id, "duplicate case {}", pair[0].id);
    }

    let material = serde_json::json!({
        "baseline": corpus.baseline,
        "cases": projected,
        "corpus_sha256": sha256_bytes(&corpus_bytes),
        "experiment": corpus.experiment,
        "schema": PROJECTION_SCHEMA,
    });
    let projection_sha256 = domain_hash(PROJECTION_DOMAIN, &canonical_json(&material)?);

    Ok(ProjectionBatch {
        schema: PROJECTION_SCHEMA.to_owned(),
        experiment: corpus.experiment,
        baseline: corpus.baseline,
        corpus_sha256: sha256_bytes(&corpus_bytes),
        cases: projected,
        projection_sha256,
    })
}

fn validate_corpus_header(corpus: &Corpus) -> Result<()> {
    ensure!(corpus.schema == CORPUS_SCHEMA, "unsupported corpus schema");
    ensure!(corpus.experiment == "EXP-0005", "unexpected experiment");
    ensure!(corpus.revision == 3, "unsupported corpus revision");
    ensure!(
        corpus.status == "frozen-positive-after-preregistered-rust-classification-correction",
        "corpus is not frozen"
    );
    ensure!(
        corpus.source_identity == "sha256-of-exact-git-blob-bytes-at-baseline",
        "unsupported source identity contract"
    );
    ensure!(
        corpus.baseline.starts_with("git:"),
        "baseline must be Git-bound"
    );
    Ok(())
}

fn project_case(root: &Path, case: &CorpusCase) -> Result<ProjectionCase> {
    let source_bytes = verify_source(root, &case.source.path, &case.source.sha256)?;
    let registered_claims = project_claim_sources(root, case)?;
    let (registration, semantic_case_id, program) = match case.role.as_str() {
        "positive-registration" => {
            let registration = project_registration(case, &source_bytes)?;
            let program = registration_program(
                root,
                case,
                source_bytes.len() as u64,
                &registration,
                registered_claims,
            )?;
            (Some(registration), None, program)
        }
        "positive-semantic-status" => {
            let (semantic_case_id, selected) = project_semantic_case(case, &source_bytes)?;
            let program = semantic_program(case, source_bytes.len() as u64, &selected)?;
            (None, Some(semantic_case_id), program)
        }
        "positive-portable-release" => {
            verify_release_case(root, case, &source_bytes)?;
            (
                None,
                None,
                release_program(root, case, source_bytes.len() as u64, &source_bytes)?,
            )
        }
        role => bail!("case {} has unsupported role {role}", case.id),
    };

    validate_case_program(&canonical_json(&program)?).map_err(anyhow::Error::from)?;

    Ok(ProjectionCase {
        id: case.id.clone(),
        role: case.role.clone(),
        source: ProjectedSource {
            path: case.source.path.clone(),
            sha256: case.source.sha256.clone(),
            json_pointer: case.source.json_pointer.clone(),
            envelope_path: case.source.envelope_path.clone(),
            envelope_sha256: case.source.envelope_sha256.clone(),
        },
        evidence_family: case.evidence_family.clone(),
        unit_id: case.unit_id.clone(),
        claim_ids: case.claim_ids.clone(),
        expected_claim: case.expected_claim.clone(),
        registration,
        semantic_case_id,
        projection_profiles: case.projection_profiles.clone(),
        program,
    })
}

fn project_registration(case: &CorpusCase, bytes: &[u8]) -> Result<RegistrationProjection> {
    let text = std::str::from_utf8(bytes).context("registration is not UTF-8")?;
    let value: toml::Value = toml::from_str(text).context("decode registration TOML")?;
    let table = value
        .as_table()
        .context("registration root is not a table")?;
    let unit_id = required_text(table, "id")?;
    let schema = required_text(table, "schema")?;
    let declared_kind = required_text(table, "kind")?;
    let adapter = required_text(table, "adapter")?;
    let claims = text_array(table, "claims")?;
    ensure!(
        case.unit_id.as_deref() == Some(unit_id.as_str()),
        "unit ID mismatch"
    );
    ensure!(
        case.claim_ids == claims,
        "claim attribution mismatch for {}",
        case.id
    );

    let operation_table = table
        .get("operation")
        .and_then(toml::Value::as_table)
        .context("registration has no operation table")?;
    let operation = required_text(operation_table, "type")?;
    let assumptions = optional_text_array(table, "assumptions")?;
    let premises = optional_text_array(table, "premises")?;
    let open_obligation = optional_text(table, "open_obligation")?;
    let evaluation_mode = optional_text(table, "evaluation_mode")?;
    let binding_mode = optional_text(table, "binding_mode")?;
    let inventory = optional_text_array(table, "expected_inventory")?;
    let inputs = optional_text_array(table, "inputs")?;
    let outputs = optional_text_array(table, "outputs")?;
    let tier = table
        .get("tier")
        .and_then(toml::Value::as_integer)
        .context("tier must be an integer")? as u64;
    let environment_allowlist = optional_text_array(table, "environment_allowlist")?;
    let resource_budget = table
        .get("resource_budget")
        .map(serde_json::to_value)
        .transpose()
        .context("convert resource budget")?
        .context("resource_budget is required")?;
    let operation_configuration = serde_json::to_value(
        table
            .get("operation")
            .context("operation configuration is required")?,
    )
    .context("convert operation configuration")?;

    let projected_family = if table.contains_key("distribution") {
        "distribution-reproduction"
    } else {
        declared_kind.as_str()
    };
    ensure!(
        projected_family == case.evidence_family,
        "evidence family mismatch for {}",
        case.id
    );

    let family_configuration = registration_family_configuration(table)?;
    let family_configuration_sha256 = domain_hash(
        PROJECTION_DOMAIN,
        &canonical_json(&family_configuration).context("canonicalize family configuration")?,
    );

    let projected = RegistrationProjection {
        schema,
        unit_id,
        declared_kind,
        adapter,
        operation,
        claims,
        assumptions,
        premises,
        open_obligation,
        evaluation_mode,
        binding_mode,
        inventory,
        inputs,
        outputs,
        tier,
        environment_allowlist,
        resource_budget,
        operation_configuration,
        family_configuration: family_configuration.clone(),
        family_configuration_sha256,
    };
    ensure!(
        registration_source_projection(table)? == registration_ir_projection(&projected),
        "registration {} is not lossless under the registered semantic projection",
        projected.unit_id
    );
    Ok(projected)
}

fn registration_family_configuration(table: &toml::value::Table) -> Result<Value> {
    const COMMON_FIELDS: &[&str] = &[
        "schema",
        "id",
        "adapter",
        "kind",
        "claims",
        "tier",
        "assumptions",
        "premises",
        "open_obligation",
        "evaluation_mode",
        "binding_mode",
        "expected_inventory",
        "inputs",
        "outputs",
        "environment_allowlist",
        "resource_budget",
        "operation",
    ];
    let mut projected = serde_json::Map::new();
    for (field, value) in table {
        if !COMMON_FIELDS.contains(&field.as_str()) {
            projected.insert(
                field.clone(),
                serde_json::to_value(value)
                    .with_context(|| format!("convert family field {field}"))?,
            );
        }
    }
    Ok(Value::Object(projected))
}

fn registration_source_projection(table: &toml::value::Table) -> Result<Value> {
    Ok(serde_json::json!({
        "schema": required_text(table, "schema")?,
        "unit": required_text(table, "id")?,
        "adapter": required_text(table, "adapter")?,
        "kind": required_text(table, "kind")?,
        "claims": optional_text_array(table, "claims")?,
        "tier": table.get("tier").and_then(toml::Value::as_integer).map(|value| value as u64),
        "assumptions": optional_text_array(table, "assumptions")?,
        "premises": optional_text_array(table, "premises")?,
        "open_obligation": optional_text(table, "open_obligation")?,
        "evaluation_mode": optional_text(table, "evaluation_mode")?,
        "binding_mode": optional_text(table, "binding_mode")?,
        "inventory": optional_text_array(table, "expected_inventory")?,
        "inputs": optional_text_array(table, "inputs")?,
        "outputs": optional_text_array(table, "outputs")?,
        "environment_allowlist": optional_text_array(table, "environment_allowlist")?,
        "resource_budget": table.get("resource_budget").map(serde_json::to_value).transpose()?,
        "operation": table.get("operation").map(serde_json::to_value).transpose()?,
        "family_configuration": registration_family_configuration(table)?,
    }))
}

fn registration_ir_projection(registration: &RegistrationProjection) -> Value {
    serde_json::json!({
        "schema": registration.schema,
        "unit": registration.unit_id,
        "adapter": registration.adapter,
        "kind": registration.declared_kind,
        "claims": registration.claims,
        "tier": registration.tier,
        "assumptions": registration.assumptions,
        "premises": registration.premises,
        "open_obligation": registration.open_obligation,
        "evaluation_mode": registration.evaluation_mode,
        "binding_mode": registration.binding_mode,
        "inventory": registration.inventory,
        "inputs": registration.inputs,
        "outputs": registration.outputs,
        "environment_allowlist": registration.environment_allowlist,
        "resource_budget": registration.resource_budget,
        "operation": registration.operation_configuration,
        "family_configuration": registration.family_configuration,
    })
}

fn project_semantic_case(case: &CorpusCase, bytes: &[u8]) -> Result<(String, Value)> {
    let pointer = case
        .source
        .json_pointer
        .as_deref()
        .context("semantic case has no JSON pointer")?;
    let root: Value = serde_json::from_slice(bytes).context("decode semantic corpus")?;
    let selected = root
        .pointer(pointer)
        .context("semantic JSON pointer is missing")?;
    let selected_id = selected
        .get("id")
        .and_then(Value::as_str)
        .context("semantic case has no ID")?;
    let expected = expected_from_value(
        selected
            .get("expected")
            .context("semantic case has no expected result")?,
    )?;
    ensure!(expected == case.expected_claim, "semantic status mismatch");
    Ok((selected_id.to_owned(), selected.clone()))
}

fn expected_from_value(value: &Value) -> Result<ExpectedClaim> {
    Ok(ExpectedClaim {
        formal: value
            .get("formal")
            .and_then(Value::as_str)
            .context("expected formal status is missing")?
            .to_owned(),
        linkage: value
            .get("linkage")
            .and_then(Value::as_str)
            .context("expected linkage is missing")?
            .to_owned(),
        assumption: value
            .get("assumption")
            .and_then(Value::as_str)
            .context("expected assumption status is missing")?
            .to_owned(),
        policy_admitted: value
            .get("policy_admitted")
            .and_then(Value::as_bool)
            .context("expected policy status is missing")?,
    })
}

fn project_claim_sources(root: &Path, case: &CorpusCase) -> Result<Vec<IrClaim>> {
    let mut claims = case
        .claim_sources
        .iter()
        .map(|source| {
            let bytes = verify_source(root, &source.path, &source.sha256)?;
            let text = std::str::from_utf8(&bytes).context("claim source is not UTF-8")?;
            let value: toml::Value = toml::from_str(text).context("decode claim TOML")?;
            let table = value.as_table().context("claim root is not a table")?;
            let id = required_text(table, "id")?;
            let mut cited_evidence = optional_text_array(table, "evidence")?;
            let mut assumptions = optional_text_array(table, "assumptions")?;
            let mut premises = optional_text_array(table, "premises")?;
            let mut open_obligations = optional_text_array(table, "open_obligations")?;
            let mut out_of_scope = optional_text_array(table, "out_of_scope")?;
            let mut registered_inputs = optional_text_array(table, "source_roots")?;
            let mut foundational_axioms = optional_text_array(table, "foundational_axioms")?;
            for values in [
                &mut cited_evidence,
                &mut assumptions,
                &mut premises,
                &mut open_obligations,
                &mut out_of_scope,
                &mut registered_inputs,
                &mut foundational_axioms,
            ] {
                values.sort();
            }
            let subject_closure = subject_closure(root, &source.path, &registered_inputs)?;
            let claim = IrClaim {
                id,
                subject: required_text(table, "subject")?,
                subject_closure: Some(subject_closure.clone()),
                source: Some(Artifact {
                    logical_name: source.path.clone(),
                    sha256: source.sha256.clone(),
                    size_bytes: bytes.len() as u64,
                }),
                node: None,
                meaning: Some(IrClaimMeaning {
                    schema: required_text(table, "schema")?,
                    statement: required_text(table, "statement")?,
                    formal_declaration: optional_text(table, "formal_declaration")?,
                    statement_encoding: optional_text(table, "statement_encoding")?,
                    statement_sha256: optional_text(table, "statement_sha256")?,
                    foundational_axioms,
                    bounded_domain: table
                        .get("bounded_domain")
                        .map(serde_json::to_value)
                        .transpose()
                        .context("convert bounded domain")?,
                    registered_domain_language: optional_text(table, "registered_domain_language")?,
                }),
                presentation: Some(IrClaimPresentation {
                    title: required_text(table, "title")?,
                    public_language: optional_text(table, "public_language")?,
                    public_statement: None,
                }),
                cited_evidence,
                assumptions,
                premises,
                open_obligations,
                out_of_scope,
                registered_inputs,
                admission: Some(IrClaimAdmission {
                    policy: required_text(table, "profile")?,
                    tier: table
                        .get("tier")
                        .and_then(toml::Value::as_integer)
                        .map(|value| value as u64),
                    primary_linkage: optional_text(table, "primary_linkage")?,
                }),
            };
            ensure!(
                claim_source_projection(table, Some(&subject_closure))?
                    == claim_ir_projection(&claim)?,
                "claim {} is not lossless under the registered semantic projection",
                claim.id
            );
            Ok(claim)
        })
        .collect::<Result<Vec<_>>>()?;
    claims.sort_by(|left, right| left.id.cmp(&right.id));
    let projected_ids = claims
        .iter()
        .map(|claim| claim.id.clone())
        .collect::<Vec<_>>();
    let mut expected_ids = case.claim_ids.clone();
    expected_ids.sort();
    ensure!(
        claims.is_empty() || projected_ids == expected_ids,
        "claim source attribution differs for {}",
        case.id
    );
    Ok(claims)
}

fn claim_source_projection(
    table: &toml::value::Table,
    subject_closure: Option<&IrSubjectClosure>,
) -> Result<Value> {
    let sorted = |field| {
        let mut values = optional_text_array(table, field)?;
        values.sort();
        Ok::<_, anyhow::Error>(values)
    };
    Ok(serde_json::json!({
        "schema": required_text(table, "schema")?,
        "id": required_text(table, "id")?,
        "title": required_text(table, "title")?,
        "statement": required_text(table, "statement")?,
        "public_language": optional_text(table, "public_language")?,
        "public_statement": Value::Null,
        "subject": required_text(table, "subject")?,
        "subject_closure": subject_closure,
        "formal_declaration": optional_text(table, "formal_declaration")?,
        "statement_encoding": optional_text(table, "statement_encoding")?,
        "statement_sha256": optional_text(table, "statement_sha256")?,
        "foundational_axioms": sorted("foundational_axioms")?,
        "policy": required_text(table, "profile")?,
        "tier": table.get("tier").and_then(toml::Value::as_integer).map(|value| value as u64),
        "primary_linkage": optional_text(table, "primary_linkage")?,
        "cited_evidence": sorted("evidence")?,
        "assumptions": sorted("assumptions")?,
        "premises": sorted("premises")?,
        "open_obligations": sorted("open_obligations")?,
        "out_of_scope": sorted("out_of_scope")?,
        "registered_inputs": sorted("source_roots")?,
        "bounded_domain": table.get("bounded_domain").map(serde_json::to_value).transpose()?,
        "registered_domain_language": optional_text(table, "registered_domain_language")?,
    }))
}

fn claim_ir_projection(claim: &IrClaim) -> Result<Value> {
    let meaning = claim.meaning.as_ref().context("claim meaning is missing")?;
    let presentation = claim
        .presentation
        .as_ref()
        .context("claim presentation is missing")?;
    let admission = claim
        .admission
        .as_ref()
        .context("claim admission is missing")?;
    Ok(serde_json::json!({
        "schema": meaning.schema,
        "id": claim.id,
        "title": presentation.title,
        "statement": meaning.statement,
        "public_language": presentation.public_language,
        "public_statement": presentation.public_statement,
        "subject": claim.subject,
        "subject_closure": claim.subject_closure,
        "formal_declaration": meaning.formal_declaration,
        "statement_encoding": meaning.statement_encoding,
        "statement_sha256": meaning.statement_sha256,
        "foundational_axioms": meaning.foundational_axioms,
        "policy": admission.policy,
        "tier": admission.tier,
        "primary_linkage": admission.primary_linkage,
        "cited_evidence": claim.cited_evidence,
        "assumptions": claim.assumptions,
        "premises": claim.premises,
        "open_obligations": claim.open_obligations,
        "out_of_scope": claim.out_of_scope,
        "registered_inputs": claim.registered_inputs,
        "bounded_domain": meaning.bounded_domain,
        "registered_domain_language": meaning.registered_domain_language,
    }))
}

fn registration_program(
    root: &Path,
    case: &CorpusCase,
    source_size: u64,
    registration: &RegistrationProjection,
    claims: Vec<IrClaim>,
) -> Result<CaseProgram> {
    let mut claim_ids = registration.claims.clone();
    claim_ids.sort();
    let mut assumptions = registration.assumptions.clone();
    assumptions.sort();
    let kind = family_kind(&case.evidence_family)
        .expect("frozen registration family must have an IR mapping");
    let detail = family_detail(
        kind,
        claims.first().map(|claim| claim.subject.as_str()),
        &case.source,
        source_size,
        Some(&registration.family_configuration),
    )?;
    let retained_facts = if kind == "sampled-property"
        && registration.family_configuration.get("property").is_some()
    {
        vec![RetainedFact {
            schema: "proofbound-python-property/1".to_owned(),
            required: true,
            value: Some(IrRetainedFactValue {
                configuration_sha256: registration.family_configuration_sha256.clone(),
            }),
            payload_sha256: None,
        }]
    } else {
        Vec::new()
    };
    let cache = registration_cache(root, case, registration)?;
    let evidence = vec![IrEvidence {
        authority: "registered".to_owned(),
        schema: None,
        unit: registration.unit_id.clone(),
        content_sha256: None,
        node: None,
        claims: claim_ids,
        outcome: None,
        evaluation: registration.evaluation_mode.clone(),
        binding: registration.binding_mode.clone(),
        inventory: registration.inventory.clone(),
        assumptions,
        premises: registration.premises.clone(),
        open_obligation: registration.open_obligation.clone(),
        request: Some(IrEvidenceRequest {
            schema: registration.schema.clone(),
            adapter: registration.adapter.clone(),
            tier: registration.tier,
            input_names: registration.inputs.clone(),
            output_names: registration.outputs.clone(),
            environment_allowlist: registration.environment_allowlist.clone(),
            resource_budget: registration.resource_budget.clone(),
            operation: registration.operation_configuration.clone(),
            family_configuration: registration.family_configuration.clone(),
        }),
        family: IrFamily {
            kind: kind.to_owned(),
            detail,
        },
        backend: IrBackend { retained_facts },
        provenance: empty_provenance(&registration.unit_id),
    }];
    Ok(CaseProgram {
        schema: assurance::CASE_SCHEMA.to_owned(),
        case_id: case.id.clone(),
        evidence_family: case.evidence_family.clone(),
        source: source_artifact(&case.source, source_size),
        claims,
        evidence,
        cache,
        policy: IrPolicy {
            required_components: vec!["registered-aggregate".to_owned()],
        },
        programme: empty_programme(),
        reported: case.expected_claim.clone(),
        exact_status: false,
    })
}

fn semantic_program(case: &CorpusCase, source_size: u64, selected: &Value) -> Result<CaseProgram> {
    let expected = selected
        .get("expected")
        .and_then(Value::as_object)
        .context("semantic expected result is not an object")?;
    let assumptions = json_text_array(expected, "assumptions")?;
    let obligations = json_text_array(expected, "undischarged_premises")?;
    let mut claim_ids = case.claim_ids.clone();
    claim_ids.sort();
    let claims = claim_ids
        .iter()
        .map(|claim_id| IrClaim {
            id: claim_id.clone(),
            subject: format!("subject:{claim_id}"),
            subject_closure: None,
            source: None,
            node: None,
            meaning: None,
            presentation: None,
            cited_evidence: Vec::new(),
            assumptions: assumptions.clone(),
            premises: Vec::new(),
            open_obligations: obligations.clone(),
            out_of_scope: Vec::new(),
            registered_inputs: Vec::new(),
            admission: None,
        })
        .collect::<Vec<_>>();
    let source = source_artifact(&case.source, source_size);
    let evidence_values = selected
        .get("evidence")
        .and_then(Value::as_array)
        .context("semantic case has no evidence")?;
    let evidence = evidence_values
        .iter()
        .map(|item| {
            let source_kind = item
                .get("kind")
                .and_then(Value::as_str)
                .context("semantic evidence kind is missing")?;
            let kind = family_kind(source_kind).context("unsupported semantic evidence kind")?;
            let unit = item
                .get("id")
                .and_then(Value::as_str)
                .context("semantic evidence ID is missing")?;
            Ok(IrEvidence {
                authority: "derived-conformance".to_owned(),
                schema: None,
                unit: unit.to_owned(),
                content_sha256: None,
                node: None,
                claims: claim_ids.clone(),
                outcome: Some("passed".to_owned()),
                evaluation: item
                    .get("evaluation")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                binding: None,
                inventory: Vec::new(),
                assumptions: assumptions.clone(),
                premises: item
                    .get("premises")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                open_obligation: None,
                request: None,
                family: IrFamily {
                    kind: kind.to_owned(),
                    detail: family_detail(
                        kind,
                        claims.first().map(|claim| claim.subject.as_str()),
                        &case.source,
                        source_size,
                        None,
                    )?,
                },
                backend: IrBackend {
                    retained_facts: Vec::new(),
                },
                provenance: empty_provenance(unit),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let policy = selected
        .get("policy")
        .and_then(Value::as_object)
        .context("semantic policy is missing")?;
    Ok(CaseProgram {
        schema: assurance::CASE_SCHEMA.to_owned(),
        case_id: case.id.clone(),
        evidence_family: case.evidence_family.clone(),
        source,
        claims,
        evidence,
        cache: IrCache {
            registered_inputs: Vec::new(),
            execution_inputs: Vec::new(),
        },
        policy: IrPolicy {
            required_components: json_text_array(policy, "components")?,
        },
        programme: empty_programme(),
        reported: case.expected_claim.clone(),
        exact_status: true,
    })
}

fn release_program(
    root: &Path,
    case: &CorpusCase,
    source_size: u64,
    bytes: &[u8],
) -> Result<CaseProgram> {
    let receipt: Value = serde_json::from_slice(bytes).context("decode release receipt")?;
    let tcb_components = release_tcb_components(root, case, &receipt)?;
    let records = receipt
        .get("evidence")
        .and_then(Value::as_array)
        .context("release evidence is missing")?;
    let mut evidence = Vec::with_capacity(records.len());
    for wrapped in records {
        let record = wrapped.get("record").context("release record is missing")?;
        let source_kind = record
            .get("kind")
            .and_then(Value::as_str)
            .context("release evidence kind is missing")?;
        let kind = family_kind(source_kind).context("unsupported release evidence kind")?;
        let unit = record
            .get("unit_id")
            .and_then(Value::as_str)
            .context("release evidence unit is missing")?;
        let assumptions = json_text_array_value(record, "assumptions")?;
        let provenance = record
            .get("provenance")
            .and_then(Value::as_object)
            .context("release provenance is missing")?;
        let runs = provenance
            .get("runs")
            .and_then(Value::as_array)
            .context("release runs are missing")?
            .iter()
            .map(|run| {
                Ok(IrRun {
                    command_index: run
                        .get("command_index")
                        .and_then(Value::as_u64)
                        .context("release run index is missing")?,
                    exit_code: run.get("exit_code").and_then(Value::as_i64),
                    stdout_sha256: value_optional_text(
                        run.as_object().context("release run must be an object")?,
                        "stdout_sha256",
                    )?,
                    stderr_sha256: value_optional_text(
                        run.as_object().context("release run must be an object")?,
                        "stderr_sha256",
                    )?,
                    normalized_output_sha256: value_optional_text(
                        run.as_object().context("release run must be an object")?,
                        "normalized_output_sha256",
                    )?,
                    output_truncated: run.get("output_truncated").and_then(Value::as_bool),
                    duration_ms: run.get("duration_ms").and_then(Value::as_u64),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let peak_memory = provenance
            .get("actual_cost")
            .and_then(|usage| usage.get("memory_bytes"))
            .and_then(Value::as_u64);
        let prior_receipt = provenance.get("reused_from").and_then(Value::as_str);
        evidence.push(IrEvidence {
            authority: "portable-receipt".to_owned(),
            schema: value_optional_text(
                record
                    .as_object()
                    .context("release record must be an object")?,
                "schema",
            )?,
            unit: unit.to_owned(),
            content_sha256: wrapped
                .get("sha256")
                .and_then(Value::as_str)
                .map(str::to_owned),
            node: record
                .get("node_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            claims: json_text_array_value(record, "claim_ids")?,
            outcome: record
                .get("outcome")
                .and_then(Value::as_str)
                .map(str::to_owned),
            evaluation: record
                .get("evaluation_mode")
                .and_then(Value::as_str)
                .map(str::to_owned),
            binding: record
                .get("binding_mode")
                .and_then(Value::as_str)
                .map(str::to_owned),
            inventory: json_text_array_value(record, "inventoried_targets")?,
            assumptions,
            premises: json_text_array_optional(
                record
                    .as_object()
                    .context("release record must be an object")?,
                "premises",
            )?,
            open_obligation: record
                .get("open_obligation")
                .and_then(Value::as_str)
                .map(str::to_owned),
            request: None,
            family: IrFamily {
                kind: kind.to_owned(),
                detail: family_detail(kind, Some("subject:c"), &case.source, source_size, None)?,
            },
            backend: IrBackend {
                retained_facts: Vec::new(),
            },
            provenance: IrProvenance {
                revision: value_optional_text(provenance, "project_revision")?,
                tree_state: value_optional_text(provenance, "tree_state")?,
                semantic_closure: value_optional_text(provenance, "semantic_closure")?,
                additional_closures: provenance
                    .get("additional_closures")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .map(closure_reference_from_value)
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?
                    .unwrap_or_default(),
                input_artifacts: provenance
                    .get("input_artifacts")
                    .and_then(Value::as_array)
                    .context("release input artifacts are missing")?
                    .iter()
                    .map(artifact_from_value)
                    .collect::<Result<Vec<_>>>()?,
                generated_artifacts: provenance
                    .get("generated_artifacts")
                    .and_then(Value::as_array)
                    .context("release generated artifacts are missing")?
                    .iter()
                    .map(artifact_from_value)
                    .collect::<Result<Vec<_>>>()?,
                tool: provenance.get("tool").map(tool_from_value).transpose()?,
                adapter: provenance.get("adapter").map(tool_from_value).transpose()?,
                execution_kind: value_optional_text(provenance, "execution_kind")?,
                commands: provenance
                    .get("commands")
                    .and_then(Value::as_array)
                    .context("release commands are missing")?
                    .iter()
                    .map(command_from_value)
                    .collect::<Result<Vec<_>>>()?,
                runs,
                normalization: value_optional_text(provenance, "normalization")?,
                reproduction: provenance
                    .get("reproduction_command")
                    .map(command_from_value)
                    .transpose()?,
                started_unix_ms: provenance.get("started_unix_ms").and_then(Value::as_u64),
                completed_unix_ms: provenance.get("completed_unix_ms").and_then(Value::as_u64),
                result_sha256: value_optional_text(provenance, "deterministic_result_sha256")?,
                unit_configuration_sha256: value_optional_text(
                    provenance,
                    "unit_configuration_sha256",
                )?,
                budget: provenance
                    .get("resource_budget")
                    .map(budget_from_value)
                    .transpose()?,
                usage: IrUsage {
                    time_ms: provenance
                        .get("actual_cost")
                        .and_then(|usage| usage.get("time_ms"))
                        .and_then(Value::as_u64),
                    disk_bytes: provenance
                        .get("actual_cost")
                        .and_then(|usage| usage.get("disk_bytes"))
                        .and_then(Value::as_u64),
                    peak_memory,
                },
                python_plugins: provenance
                    .get("python_plugins")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .map(python_plugin_from_value)
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?
                    .unwrap_or_default(),
                cache: match prior_receipt {
                    Some(prior_receipt) => IrCacheProvenance::ReusedExactPrior {
                        key: provenance
                            .get("cache_key")
                            .and_then(Value::as_str)
                            .context("release cache key is missing")?
                            .to_owned(),
                        prior_receipt: prior_receipt.to_owned(),
                    },
                    None => IrCacheProvenance::Executed {
                        key: provenance
                            .get("cache_key")
                            .and_then(Value::as_str)
                            .context("release cache key is missing")?
                            .to_owned(),
                    },
                },
            },
        });
    }
    let receipt_claims = receipt
        .get("claims")
        .and_then(Value::as_array)
        .context("release claims are missing")?;
    let claims = receipt_claims
        .iter()
        .map(|claim| release_claim(claim, &receipt))
        .collect::<Result<Vec<_>>>()?;
    let program = CaseProgram {
        schema: assurance::CASE_SCHEMA.to_owned(),
        case_id: case.id.clone(),
        evidence_family: case.evidence_family.clone(),
        source: source_artifact(&case.source, source_size),
        claims,
        evidence,
        cache: IrCache {
            registered_inputs: Vec::new(),
            execution_inputs: Vec::new(),
        },
        policy: IrPolicy {
            required_components: vec!["ledger".to_owned()],
        },
        programme: release_programme(&receipt, tcb_components.clone())?,
        reported: case.expected_claim.clone(),
        exact_status: true,
    };
    let source_semantics = release_source_semantics(&receipt, case, source_size, &tcb_components)?;
    let ir_semantics = release_ir_semantics(&program)?;
    if source_semantics != ir_semantics {
        bail!(
            "portable release is not lossless at {}",
            first_json_difference(&source_semantics, &ir_semantics, "$")
        );
    }
    Ok(program)
}

fn empty_programme() -> IrProgrammeContext {
    IrProgrammeContext {
        release_schema: None,
        project: None,
        graph: None,
        graph_sha256: None,
        assumptions: Vec::new(),
        premises: Vec::new(),
        policies: Vec::new(),
        closures: Vec::new(),
        sealed_artifacts: Vec::new(),
        tcb_components: Vec::new(),
        publication_blockers: Vec::new(),
        reported_statuses: Vec::new(),
        derivation_traces: Vec::new(),
        publication_trace: None,
    }
}

fn release_tcb_components(
    root: &Path,
    case: &CorpusCase,
    receipt: &Value,
) -> Result<Vec<IrTcbComponent>> {
    let sealed = required_value_array(receipt, "sealed_files")?
        .iter()
        .find(|artifact| {
            artifact
                .get("path")
                .or_else(|| artifact.get("logical_name"))
                .and_then(Value::as_str)
                == Some("tcb-ledger.json")
        })
        .context("portable release does not seal tcb-ledger.json")?;
    let release_root = root
        .join(&case.source.path)
        .parent()
        .context("portable receipt has no release directory")?
        .to_path_buf();
    let bytes = fs::read(release_root.join("tcb-ledger.json")).context("read sealed TCB ledger")?;
    ensure!(
        sha256_bytes(&bytes) == required_value_text(sealed, "sha256")?
            && bytes.len() as u64
                == sealed
                    .get("size_bytes")
                    .and_then(Value::as_u64)
                    .context("sealed TCB ledger size is missing")?,
        "sealed TCB ledger identity differs from its bytes"
    );
    let ledger = assurance::decode_strict_json(&bytes).context("decode sealed TCB ledger")?;
    ensure!(
        required_value_text(&ledger, "schema")? == "proofbound-tcb-ledger/1",
        "unsupported TCB ledger schema"
    );
    let components = required_value_array(&ledger, "components")?
        .iter()
        .map(|component| {
            Ok(IrTcbComponent {
                name: required_value_text(component, "name")?.to_owned(),
                version: required_value_text(component, "version")?.to_owned(),
                identity_sha256: required_value_text(component, "identity_sha256")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut canonical = components.clone();
    canonical.sort();
    canonical.dedup();
    ensure!(
        !components.is_empty() && components == canonical,
        "TCB components must be sorted and unique"
    );
    Ok(components)
}

fn release_programme(
    receipt: &Value,
    tcb_components: Vec<IrTcbComponent>,
) -> Result<IrProgrammeContext> {
    let project = IrProject {
        id: required_value_text(receipt, "project")?.to_owned(),
        revision: required_value_text(receipt, "project_revision")?.to_owned(),
        tier: receipt
            .get("project_tier")
            .and_then(Value::as_u64)
            .context("release project tier is missing")?,
        tree_state: required_value_text(receipt, "tree_state")?.to_owned(),
    };
    let closures = receipt
        .get("closures")
        .and_then(Value::as_array)
        .context("release closures are missing")?
        .iter()
        .map(|closure| {
            let record = closure
                .get("record")
                .context("release closure record is missing")?;
            Ok(IrClosure {
                schema: required_value_text(record, "schema")?.to_owned(),
                sha256: required_value_text(closure, "sha256")?.to_owned(),
                kind: required_value_text(record, "kind")?.to_owned(),
                members: record
                    .get("members")
                    .and_then(Value::as_array)
                    .context("release closure members are missing")?
                    .iter()
                    .map(artifact_from_value)
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let sealed_artifacts = receipt
        .get("sealed_files")
        .and_then(Value::as_array)
        .context("release sealed files are missing")?
        .iter()
        .map(artifact_from_value)
        .collect::<Result<Vec<_>>>()?;
    let publication_blockers = receipt
        .get("reported_statuses")
        .and_then(Value::as_array)
        .context("release statuses are missing")?
        .iter()
        .filter(|status| status.get("policy_admitted").and_then(Value::as_bool) == Some(false))
        .map(|status| {
            required_value_text(status, "claim_id")
                .map(str::to_owned)
                .context("blocked release status has no claim ID")
        })
        .collect::<Result<Vec<_>>>()?;
    let reported_statuses = receipt
        .get("reported_statuses")
        .and_then(Value::as_array)
        .context("release statuses are missing")?
        .iter()
        .map(reported_status_from_value)
        .collect::<Result<Vec<_>>>()?;
    let (derivation_traces, publication_trace) = release_derivation_traces(receipt)?;
    Ok(IrProgrammeContext {
        release_schema: Some(required_value_text(receipt, "schema")?.to_owned()),
        project: Some(project),
        graph: Some(graph_from_value(
            receipt.get("graph").context("release graph is missing")?,
        )?),
        graph_sha256: Some(required_value_text(receipt, "graph_sha256")?.to_owned()),
        assumptions: required_value_array(receipt, "assumptions")?
            .iter()
            .map(assumption_from_value)
            .collect::<Result<Vec<_>>>()?,
        premises: required_value_array(receipt, "premises")?
            .iter()
            .map(premise_from_value)
            .collect::<Result<Vec<_>>>()?,
        policies: required_value_array(receipt, "policies")?
            .iter()
            .map(policy_from_value)
            .collect::<Result<Vec<_>>>()?,
        closures,
        sealed_artifacts,
        tcb_components,
        publication_blockers,
        reported_statuses,
        derivation_traces,
        publication_trace: Some(publication_trace),
    })
}

fn release_derivation_traces(
    receipt: &Value,
) -> Result<(Vec<IrDerivationTrace>, IrPublicationTrace)> {
    let project_tier = receipt
        .get("project_tier")
        .and_then(Value::as_u64)
        .context("release project tier is missing")?;
    let evidence = required_value_array(receipt, "evidence")?;
    let policies = required_value_array(receipt, "policies")?;
    let mut traces = Vec::new();
    for claim in required_value_array(receipt, "claims")? {
        let claim_id = required_value_text(claim, "id")?;
        let mut cited = json_text_array_optional(
            claim
                .as_object()
                .context("release claim must be an object")?,
            "cited_evidence",
        )?;
        cited.sort();
        let cited_records = cited
            .iter()
            .filter_map(|identity| {
                evidence.iter().find(|wrapped| {
                    wrapped.get("sha256").and_then(Value::as_str) == Some(identity.as_str())
                })
            })
            .collect::<Vec<_>>();
        let passed_kinds = cited_records
            .iter()
            .filter_map(|wrapped| {
                let record = wrapped.get("record")?;
                (record.get("outcome").and_then(Value::as_str) == Some("passed"))
                    .then(|| record.get("kind")?.as_str().map(str::to_owned))
                    .flatten()
            })
            .collect::<Vec<_>>();
        let (formal, formal_rule) = derive_formal_facet(&passed_kinds);
        let (linkage, linkage_rule) = derive_linkage_facet(&passed_kinds);
        let mut assumption_inputs = json_text_array_optional(
            claim
                .as_object()
                .context("release claim must be an object")?,
            "assumptions",
        )?;
        assumption_inputs.extend(json_text_array_optional(
            claim
                .as_object()
                .context("release claim must be an object")?,
            "premises",
        )?);
        assumption_inputs.extend(obligation_ids(claim)?);
        assumption_inputs.sort();
        assumption_inputs.dedup();
        let policy_id = required_value_text(claim, "policy")?;
        let policy = policies
            .iter()
            .find(|policy| policy.get("id").and_then(Value::as_str) == Some(policy_id))
            .with_context(|| format!("claim {claim_id} has no effective policy"))?;
        let policy = policy
            .as_object()
            .context("release policy must be an object")?;
        let required_policy_components = json_text_array(policy, "components")?;
        let native = cited_records.iter().any(|wrapped| {
            wrapped
                .get("record")
                .and_then(|record| record.get("evaluation_mode"))
                .and_then(Value::as_str)
                == Some("native")
        });
        let satisfied_policy_components = required_policy_components
            .iter()
            .filter(|component| {
                policy_component_satisfied(component, formal, linkage, native, &cited_records)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut blockers = Vec::new();
        if cited_records.len() != cited.len() {
            blockers.push("cited-evidence-missing".to_owned());
        }
        if cited_records.iter().any(|wrapped| {
            wrapped
                .get("record")
                .and_then(|record| record.get("outcome"))
                .and_then(Value::as_str)
                != Some("passed")
        }) {
            blockers.push("cited-evidence-not-passed".to_owned());
        }
        blockers.extend(
            required_policy_components
                .iter()
                .filter(|component| !satisfied_policy_components.contains(component))
                .map(|component| format!("policy-component:{component}")),
        );
        if policy
            .get("require_no_assumptions")
            .and_then(Value::as_bool)
            == Some(true)
            && !assumption_inputs.is_empty()
        {
            blockers.push("assumptions-forbidden".to_owned());
        }
        for required in json_text_array(policy, "additional_required_evidence")? {
            if !cited.contains(&required) {
                blockers.push(format!("required-evidence:{required}"));
            }
        }
        blockers.sort();
        blockers.dedup();
        let open_obligations = obligation_ids(claim)?;
        traces.push(IrDerivationTrace {
            schema: "proofbound-ir-derivation-trace/1".to_owned(),
            claim_id: claim_id.to_owned(),
            formal_value_and_rule: IrFacetDerivation {
                value: formal.to_owned(),
                rule: formal_rule.to_owned(),
            },
            linkage_value_and_rule: IrFacetDerivation {
                value: linkage.to_owned(),
                rule: linkage_rule.to_owned(),
            },
            assumption_value_and_inputs: IrAssumptionDerivation {
                value: if assumption_inputs.is_empty() {
                    "NONE".to_owned()
                } else {
                    "ASSUMED".to_owned()
                },
                inputs: assumption_inputs,
            },
            policy_id: policy_id.to_owned(),
            effective_tier: claim
                .get("tier")
                .and_then(Value::as_u64)
                .unwrap_or(project_tier),
            required_policy_components,
            satisfied_policy_components,
            load_bearing_evidence: cited,
            open_obligations,
            blockers,
        });
    }
    traces.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    let admitted_claims = traces
        .iter()
        .filter(|trace| trace.blockers.is_empty())
        .map(|trace| trace.claim_id.clone())
        .collect::<Vec<_>>();
    let blocked_claims = traces
        .iter()
        .filter(|trace| !trace.blockers.is_empty())
        .map(|trace| trace.claim_id.clone())
        .collect::<Vec<_>>();
    let blockers = traces
        .iter()
        .flat_map(|trace| {
            trace
                .blockers
                .iter()
                .map(|blocker| format!("{}:{blocker}", trace.claim_id))
        })
        .collect::<Vec<_>>();
    Ok((
        traces,
        IrPublicationTrace {
            admitted_claims,
            blocked_claims,
            blockers,
        },
    ))
}

fn obligation_ids(claim: &Value) -> Result<Vec<String>> {
    let mut obligations = claim
        .get("open_obligations")
        .and_then(Value::as_array)
        .context("open_obligations must be an array")?
        .iter()
        .map(|item| {
            item.as_str()
                .or_else(|| item.get("id").and_then(Value::as_str))
                .map(str::to_owned)
                .context("open obligation must be an identity or typed record")
        })
        .collect::<Result<Vec<_>>>()?;
    obligations.sort();
    obligations.dedup();
    Ok(obligations)
}

fn derive_formal_facet(kinds: &[String]) -> (&'static str, &'static str) {
    if kinds.iter().any(|kind| kind == "theorem") {
        ("PROVED", "universal-source-proof")
    } else if kinds.iter().any(|kind| kind == "bounded-check") {
        ("BOUNDED_CHECKED", "bounded-model-check")
    } else if !kinds.is_empty() && kinds.iter().all(|kind| kind == "trusted-transcription") {
        ("OPEN", "no-functional-evidence")
    } else {
        ("TESTED", "empirical-evidence")
    }
}

fn derive_linkage_facet(kinds: &[String]) -> (&'static str, &'static str) {
    if kinds.iter().any(|kind| kind == "artifact-soundness") {
        ("ARTIFACT_BOUND", "artifact-correspondence")
    } else if kinds.iter().any(|kind| kind == "source-refinement") {
        ("REFINED", "source-correspondence")
    } else if kinds.iter().any(|kind| kind == "trusted-transcription") {
        ("TRANSCRIBED", "trusted-transcription")
    } else {
        ("MODEL_ONLY", "no-artifact-binding")
    }
}

fn policy_component_satisfied(
    component: &str,
    formal: &str,
    linkage: &str,
    native: bool,
    cited_records: &[&Value],
) -> bool {
    match component {
        "ledger" => !cited_records.is_empty(),
        "kernel" | "kernel-with-assumptions" => formal == "PROVED",
        "artifact-bound" => linkage == "ARTIFACT_BOUND",
        "native-evaluated" => native,
        "transcribed" => linkage == "TRANSCRIBED",
        _ => false,
    }
}

fn release_source_semantics(
    receipt: &Value,
    case: &CorpusCase,
    source_size: u64,
    tcb_components: &[IrTcbComponent],
) -> Result<Value> {
    let claims = required_value_array(receipt, "claims")?
        .iter()
        .map(|claim| release_claim_source_projection(claim, receipt))
        .collect::<Result<Vec<_>>>()?;
    let evidence = required_value_array(receipt, "evidence")?
        .iter()
        .map(|wrapped| release_evidence_source_projection(wrapped, case, source_size))
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "claims": claims,
        "evidence": evidence,
        "programme": release_programme_source_projection(receipt, tcb_components)?,
    }))
}

fn release_ir_semantics(program: &CaseProgram) -> Result<Value> {
    let claims = program
        .claims
        .iter()
        .map(claim_ir_projection)
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "claims": claims,
        "evidence": program.evidence,
        "programme": program.programme,
    }))
}

fn release_claim_source_projection(claim: &Value, receipt: &Value) -> Result<Value> {
    let claim_id = required_value_text(claim, "id")?;
    let status = required_value_array(receipt, "reported_statuses")?
        .iter()
        .find(|status| status.get("claim_id").and_then(Value::as_str) == Some(claim_id))
        .context("release claim has no reported status")?;
    let mut projection = Map::new();
    projection.insert("schema".to_owned(), claim["schema"].clone());
    projection.insert("id".to_owned(), claim["id"].clone());
    projection.insert("title".to_owned(), claim["title"].clone());
    projection.insert("statement".to_owned(), claim["statement"].clone());
    projection.insert(
        "public_language".to_owned(),
        claim.get("public_language").cloned().unwrap_or(Value::Null),
    );
    projection.insert("subject".to_owned(), claim["subject"].clone());
    projection.insert("subject_closure".to_owned(), Value::Null);
    for field in [
        "formal_declaration",
        "statement_encoding",
        "statement_sha256",
        "bounded_domain",
        "registered_domain_language",
    ] {
        projection.insert(
            field.to_owned(),
            claim.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    projection.insert(
        "foundational_axioms".to_owned(),
        sorted_value_text_array(claim, "foundational_axioms")?,
    );
    projection.insert("policy".to_owned(), claim["policy"].clone());
    projection.insert(
        "tier".to_owned(),
        claim.get("tier").cloned().unwrap_or(Value::Null),
    );
    projection.insert(
        "primary_linkage".to_owned(),
        claim.get("primary_linkage").cloned().unwrap_or(Value::Null),
    );
    for field in [
        "cited_evidence",
        "assumptions",
        "premises",
        "open_obligations",
        "out_of_scope",
        "registered_inputs",
    ] {
        projection.insert(field.to_owned(), sorted_value_text_array(claim, field)?);
    }
    projection.insert(
        "public_statement".to_owned(),
        status["public_statement"].clone(),
    );
    Ok(Value::Object(projection))
}

fn release_evidence_source_projection(
    wrapped: &Value,
    case: &CorpusCase,
    source_size: u64,
) -> Result<Value> {
    let record = wrapped.get("record").context("release record is missing")?;
    let kind = family_kind(required_value_text(record, "kind")?)
        .context("unsupported release evidence kind")?;
    let unit = required_value_text(record, "unit_id")?;
    let provenance = record
        .get("provenance")
        .context("release provenance is missing")?;
    Ok(serde_json::json!({
        "authority": "portable-receipt",
        "schema": record.get("schema").cloned().unwrap_or(Value::Null),
        "unit": unit,
        "content_sha256": wrapped.get("sha256").cloned().unwrap_or(Value::Null),
        "node": record.get("node_id").cloned().unwrap_or(Value::Null),
        "claims": record.get("claim_ids").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "outcome": record.get("outcome").cloned().unwrap_or(Value::Null),
        "evaluation": record.get("evaluation_mode").cloned().unwrap_or(Value::Null),
        "binding": record.get("binding_mode").cloned().unwrap_or(Value::Null),
        "inventory": record.get("inventoried_targets").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "assumptions": record.get("assumptions").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "premises": record.get("premises").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "open_obligation": record.get("open_obligation").cloned().unwrap_or(Value::Null),
        "request": Value::Null,
        "family": {
            "kind": kind,
            "detail": family_detail(kind, Some("subject:c"), &case.source, source_size, None)?,
        },
        "backend": {"retained_facts": []},
        "provenance": release_provenance_source_projection(unit, provenance)?,
    }))
}

fn release_provenance_source_projection(_unit: &str, provenance: &Value) -> Result<Value> {
    let prior = provenance.get("reused_from").and_then(Value::as_str);
    let cache = match prior {
        Some(prior_receipt) => serde_json::json!({
            "state": "reused-exact-prior",
            "key": required_value_text(provenance, "cache_key")?,
            "prior_receipt": prior_receipt,
        }),
        None => serde_json::json!({
            "state": "executed",
            "key": required_value_text(provenance, "cache_key")?,
        }),
    };
    Ok(serde_json::json!({
        "revision": provenance.get("project_revision").cloned().unwrap_or(Value::Null),
        "tree_state": provenance.get("tree_state").cloned().unwrap_or(Value::Null),
        "semantic_closure": provenance.get("semantic_closure").cloned().unwrap_or(Value::Null),
        "additional_closures": provenance.get("additional_closures").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "input_artifacts": artifact_array_source_projection(provenance, "input_artifacts")?,
        "generated_artifacts": artifact_array_source_projection(provenance, "generated_artifacts")?,
        "tool": provenance.get("tool").cloned().unwrap_or(Value::Null),
        "adapter": provenance.get("adapter").cloned().unwrap_or(Value::Null),
        "execution_kind": provenance.get("execution_kind").cloned().unwrap_or(Value::Null),
        "commands": command_array_source_projection(provenance, "commands")?,
        "runs": provenance.get("runs").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "normalization": provenance.get("normalization").cloned().unwrap_or(Value::Null),
        "reproduction": command_source_projection(provenance.get("reproduction_command").context("release reproduction command is missing")?)?,
        "started_unix_ms": provenance.get("started_unix_ms").cloned().unwrap_or(Value::Null),
        "completed_unix_ms": provenance.get("completed_unix_ms").cloned().unwrap_or(Value::Null),
        "result_sha256": provenance.get("deterministic_result_sha256").cloned().unwrap_or(Value::Null),
        "unit_configuration_sha256": provenance.get("unit_configuration_sha256").cloned().unwrap_or(Value::Null),
        "budget": provenance.get("resource_budget").cloned().unwrap_or(Value::Null),
        "usage": {
            "time_ms": provenance.pointer("/actual_cost/time_ms").cloned().unwrap_or(Value::Null),
            "disk_bytes": provenance.pointer("/actual_cost/disk_bytes").cloned().unwrap_or(Value::Null),
            "peak_memory": provenance.pointer("/actual_cost/memory_bytes").cloned().unwrap_or(Value::Null),
        },
        "python_plugins": provenance.get("python_plugins").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "cache": cache,
    }))
}

fn release_programme_source_projection(
    receipt: &Value,
    tcb_components: &[IrTcbComponent],
) -> Result<Value> {
    let closures = required_value_array(receipt, "closures")?
        .iter()
        .map(|closure| {
            let record = closure
                .get("record")
                .context("release closure record is missing")?;
            Ok(serde_json::json!({
                "schema": record["schema"],
                "sha256": closure["sha256"],
                "kind": record["kind"],
                "members": artifact_array_source_projection(record, "members")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let statuses = required_value_array(receipt, "reported_statuses")?
        .iter()
        .map(|status| serde_json::to_value(reported_status_from_value(status)?).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;
    let blockers = required_value_array(receipt, "reported_statuses")?
        .iter()
        .filter(|status| status.get("policy_admitted").and_then(Value::as_bool) == Some(false))
        .map(|status| required_value_text(status, "claim_id").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    let (derivation_traces, publication_trace) = release_derivation_traces(receipt)?;
    Ok(serde_json::json!({
        "release_schema": receipt.get("schema").cloned().unwrap_or(Value::Null),
        "project": {
            "id": receipt["project"],
            "revision": receipt["project_revision"],
            "tier": receipt["project_tier"],
            "tree_state": receipt["tree_state"],
        },
        "graph": receipt.get("graph").cloned().unwrap_or(Value::Null),
        "graph_sha256": receipt.get("graph_sha256").cloned().unwrap_or(Value::Null),
        "assumptions": receipt.get("assumptions").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "premises": receipt.get("premises").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "policies": receipt.get("policies").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "closures": closures,
        "sealed_artifacts": artifact_array_source_projection(receipt, "sealed_files")?,
        "tcb_components": tcb_components,
        "publication_blockers": blockers,
        "reported_statuses": statuses,
        "derivation_traces": derivation_traces,
        "publication_trace": publication_trace,
    }))
}

fn artifact_array_source_projection(value: &Value, field: &str) -> Result<Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(|artifact| {
            Ok(serde_json::json!({
                "logical_name": artifact.get("logical_name").or_else(|| artifact.get("path")).context("artifact logical name is missing")?,
                "sha256": artifact.get("sha256").context("artifact digest is missing")?,
                "size_bytes": artifact.get("size_bytes").context("artifact size is missing")?,
            }))
        })
        .collect()
}

fn command_array_source_projection(value: &Value, field: &str) -> Result<Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(command_source_projection)
        .collect()
}

fn command_source_projection(command: &Value) -> Result<Value> {
    Ok(serde_json::json!({
        "program": command.get("program").context("command program is missing")?,
        "args": command.get("args").context("command args are missing")?,
        "environment_allowlist": command.get("environment_allowlist").context("command environment is missing")?,
    }))
}

fn sorted_value_text_array(value: &Value, field: &str) -> Result<Value> {
    let mut values = json_text_array_optional(
        value
            .as_object()
            .context("projection source must be an object")?,
        field,
    )?;
    values.sort();
    Ok(serde_json::to_value(values)?)
}

fn first_json_difference(left: &Value, right: &Value, path: &str) -> String {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            for key in left.keys().chain(right.keys()) {
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) if left != right => {
                        return first_json_difference(left, right, &format!("{path}.{key}"));
                    }
                    (None, Some(_)) | (Some(_), None) => return format!("{path}.{key}"),
                    _ => {}
                }
            }
            path.to_owned()
        }
        (Value::Array(left), Value::Array(right)) => {
            let length = left.len().max(right.len());
            for index in 0..length {
                match (left.get(index), right.get(index)) {
                    (Some(left), Some(right)) if left != right => {
                        return first_json_difference(left, right, &format!("{path}[{index}]"));
                    }
                    (None, Some(_)) | (Some(_), None) => return format!("{path}[{index}]"),
                    _ => {}
                }
            }
            path.to_owned()
        }
        _ => path.to_owned(),
    }
}

fn release_claim(claim: &Value, receipt: &Value) -> Result<IrClaim> {
    let object = claim
        .as_object()
        .context("release claim is not an object")?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .context("release claim ID is missing")?;
    let mut cited_evidence = json_text_array_optional(object, "cited_evidence")?;
    let mut assumptions = json_text_array_optional(object, "assumptions")?;
    let mut premises = json_text_array_optional(object, "premises")?;
    let mut open_obligations = json_text_array_optional(object, "open_obligations")?;
    let mut out_of_scope = json_text_array_optional(object, "out_of_scope")?;
    let mut registered_inputs = json_text_array_optional(object, "registered_inputs")?;
    for values in [
        &mut cited_evidence,
        &mut assumptions,
        &mut premises,
        &mut open_obligations,
        &mut out_of_scope,
        &mut registered_inputs,
    ] {
        values.sort();
    }
    let public_statement = receipt
        .get("reported_statuses")
        .and_then(Value::as_array)
        .and_then(|statuses| {
            statuses
                .iter()
                .find(|status| status.get("claim_id").and_then(Value::as_str) == Some(id))
        })
        .and_then(|status| status.get("public_statement"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(IrClaim {
        id: id.to_owned(),
        subject: object
            .get("subject")
            .and_then(Value::as_str)
            .context("release claim subject is missing")?
            .to_owned(),
        subject_closure: None,
        source: None,
        node: object
            .get("node_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        meaning: Some(IrClaimMeaning {
            schema: object
                .get("schema")
                .and_then(Value::as_str)
                .context("release claim schema is missing")?
                .to_owned(),
            statement: object
                .get("statement")
                .and_then(Value::as_str)
                .context("release claim statement is missing")?
                .to_owned(),
            formal_declaration: value_optional_text(object, "formal_declaration")?,
            statement_encoding: value_optional_text(object, "statement_encoding")?,
            statement_sha256: value_optional_text(object, "statement_sha256")?,
            foundational_axioms: json_text_array_optional(object, "foundational_axioms")?,
            bounded_domain: object.get("bounded_domain").cloned(),
            registered_domain_language: value_optional_text(object, "registered_domain_language")?,
        }),
        presentation: Some(IrClaimPresentation {
            title: object
                .get("title")
                .and_then(Value::as_str)
                .context("release claim title is missing")?
                .to_owned(),
            public_language: value_optional_text(object, "public_language")?,
            public_statement,
        }),
        cited_evidence,
        assumptions,
        premises,
        open_obligations,
        out_of_scope,
        registered_inputs,
        admission: Some(IrClaimAdmission {
            policy: object
                .get("policy")
                .and_then(Value::as_str)
                .context("release claim policy is missing")?
                .to_owned(),
            tier: object.get("tier").and_then(Value::as_u64),
            primary_linkage: value_optional_text(object, "primary_linkage")?,
        }),
    })
}

fn artifact_from_value(value: &Value) -> Result<Artifact> {
    let object = value.as_object().context("artifact must be an object")?;
    let logical_name = object
        .get("logical_name")
        .or_else(|| object.get("path"))
        .and_then(Value::as_str)
        .context("artifact logical name is missing")?;
    Ok(Artifact {
        logical_name: logical_name.to_owned(),
        sha256: object
            .get("sha256")
            .and_then(Value::as_str)
            .context("artifact digest is missing")?
            .to_owned(),
        size_bytes: object
            .get("size_bytes")
            .and_then(Value::as_u64)
            .context("artifact size is missing")?,
    })
}

fn closure_reference_from_value(value: &Value) -> Result<IrClosureReference> {
    Ok(IrClosureReference {
        kind: required_value_text(value, "kind")?.to_owned(),
        sha256: required_value_text(value, "sha256")?.to_owned(),
    })
}

fn python_plugin_from_value(value: &Value) -> Result<IrPythonPlugin> {
    Ok(IrPythonPlugin {
        module: required_value_text(value, "module")?.to_owned(),
        distribution: required_value_text(value, "distribution")?.to_owned(),
        version: required_value_text(value, "version")?.to_owned(),
        origin_sha256: required_value_text(value, "origin_sha256")?.to_owned(),
    })
}

fn reported_status_from_value(value: &Value) -> Result<IrReportedStatus> {
    Ok(IrReportedStatus {
        claim_id: required_value_text(value, "claim_id")?.to_owned(),
        formal: required_value_text(value, "formal")?.to_owned(),
        linkage: required_value_text(value, "linkage")?.to_owned(),
        assumption: required_value_text(value, "assumption")?.to_owned(),
        policy_admitted: value
            .get("policy_admitted")
            .and_then(Value::as_bool)
            .context("reported policy decision is missing")?,
        public_statement: required_value_text(value, "public_statement")?.to_owned(),
        assumptions: json_text_array_value(value, "assumptions")?,
        undischarged_premises: json_text_array_value(value, "undischarged_premises")?,
    })
}

fn graph_from_value(value: &Value) -> Result<IrGraph> {
    Ok(IrGraph {
        schema: required_value_text(value, "schema")?.to_owned(),
        nodes: required_value_array(value, "nodes")?
            .iter()
            .map(|node| {
                Ok(IrGraphNode {
                    id: required_value_text(node, "id")?.to_owned(),
                    kind: required_value_text(node, "kind")?.to_owned(),
                    proof_environment: node
                        .get("proof_environment")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        edges: required_value_array(value, "edges")?
            .iter()
            .map(|edge| {
                Ok(IrGraphEdge {
                    from: required_value_text(edge, "from")?.to_owned(),
                    to: required_value_text(edge, "to")?.to_owned(),
                    kind: required_value_text(edge, "kind")?.to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        mutual_theorem_groups: required_value_array(value, "mutual_theorem_groups")?
            .iter()
            .map(|group| {
                Ok(IrMutualTheoremGroup {
                    id: required_value_text(group, "id")?.to_owned(),
                    proof_environment: required_value_text(group, "proof_environment")?.to_owned(),
                    members: json_text_array_value(group, "members")?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn assumption_from_value(value: &Value) -> Result<IrAssumption> {
    Ok(IrAssumption {
        schema: required_value_text(value, "schema")?.to_owned(),
        id: required_value_text(value, "id")?.to_owned(),
        node_id: required_value_text(value, "node_id")?.to_owned(),
        statement: required_value_text(value, "statement")?.to_owned(),
        category: required_value_text(value, "category")?.to_owned(),
        owner: required_value_text(value, "owner")?.to_owned(),
        rationale: required_value_text(value, "rationale")?.to_owned(),
        scope: required_value_text(value, "scope")?.to_owned(),
        affected_claims: json_text_array_value(value, "affected_claims")?,
        review_evidence: json_text_array_value(value, "review_evidence")?,
        falsification_or_discharge_plan: required_value_text(
            value,
            "falsification_or_discharge_plan",
        )?
        .to_owned(),
        source_citation: value
            .get("source_citation")
            .and_then(Value::as_str)
            .map(str::to_owned),
        state: required_value_text(value, "state")?.to_owned(),
        depends_on: value
            .get("depends_on")
            .map(|_| json_text_array_value(value, "depends_on"))
            .transpose()?
            .unwrap_or_default(),
    })
}

fn premise_from_value(value: &Value) -> Result<IrPremise> {
    Ok(IrPremise {
        id: required_value_text(value, "id")?.to_owned(),
        node_id: required_value_text(value, "node_id")?.to_owned(),
        statement: required_value_text(value, "statement")?.to_owned(),
        category: required_value_text(value, "category")?.to_owned(),
        theorem_evidence: value
            .get("theorem_evidence")
            .and_then(Value::as_str)
            .map(str::to_owned),
        scope: flow_scope_from_value(value.get("scope").context("premise scope is missing")?)?,
        discharge: value
            .get("discharge")
            .map(|discharge| -> Result<IrPremiseDischarge> {
                Ok(IrPremiseDischarge {
                    theorem_evidence: required_value_text(discharge, "theorem_evidence")?
                        .to_owned(),
                    scope: flow_scope_from_value(
                        discharge
                            .get("scope")
                            .context("premise discharge scope is missing")?,
                    )?,
                })
            })
            .transpose()?,
    })
}

fn flow_scope_from_value(value: &Value) -> Result<IrFlowScope> {
    Ok(IrFlowScope {
        kind: required_value_text(value, "kind")?.to_owned(),
        flows: value
            .get("flows")
            .map(|_| json_text_array_value(value, "flows"))
            .transpose()?
            .unwrap_or_default(),
    })
}

fn policy_from_value(value: &Value) -> Result<IrPolicyRecord> {
    Ok(IrPolicyRecord {
        schema: required_value_text(value, "schema")?.to_owned(),
        id: required_value_text(value, "id")?.to_owned(),
        node_id: required_value_text(value, "node_id")?.to_owned(),
        components: json_text_array_value(value, "components")?,
        allowed_foundational_axioms: json_text_array_value(value, "allowed_foundational_axioms")?,
        allowed_project_axioms: json_text_array_value(value, "allowed_project_axioms")?,
        admit_exhaustive_as_proved: required_value_bool(value, "admit_exhaustive_as_proved")?,
        require_no_assumptions: required_value_bool(value, "require_no_assumptions")?,
        native_premise_rule: value
            .get("native_premise_rule")
            .map(|rule| -> Result<IrNativePremiseRule> {
                Ok(IrNativePremiseRule {
                    kind: required_value_text(rule, "kind")?.to_owned(),
                    count: rule.get("count").and_then(Value::as_u64),
                })
            })
            .transpose()?,
        additional_required_evidence: json_text_array_value(value, "additional_required_evidence")?,
    })
}

fn tool_from_value(value: &Value) -> Result<IrTool> {
    let object = value.as_object().context("tool must be an object")?;
    Ok(IrTool {
        name: object
            .get("name")
            .and_then(Value::as_str)
            .context("tool name is missing")?
            .to_owned(),
        version: object
            .get("version")
            .and_then(Value::as_str)
            .context("tool version is missing")?
            .to_owned(),
        identity_sha256: object
            .get("identity_sha256")
            .and_then(Value::as_str)
            .context("tool identity is missing")?
            .to_owned(),
    })
}

fn command_from_value(value: &Value) -> Result<IrCommand> {
    let object = value.as_object().context("command must be an object")?;
    let environment_allowlist = object
        .get("environment_allowlist")
        .and_then(Value::as_array)
        .context("command environment is missing")?
        .iter()
        .map(|environment| {
            let environment = environment
                .as_object()
                .context("environment entry must be an object")?;
            Ok(IrEnvironment {
                name: environment
                    .get("name")
                    .and_then(Value::as_str)
                    .context("environment name is missing")?
                    .to_owned(),
                value_sha256: value_optional_text(environment, "value_sha256")?,
                secret: environment
                    .get("secret")
                    .and_then(Value::as_bool)
                    .context("environment secret flag is missing")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(IrCommand {
        program: object
            .get("program")
            .and_then(Value::as_str)
            .context("command program is missing")?
            .to_owned(),
        args: json_text_array(object, "args")?,
        environment_allowlist,
    })
}

fn budget_from_value(value: &Value) -> Result<IrBudget> {
    let object = value.as_object().context("budget must be an object")?;
    Ok(IrBudget {
        time_ms: object
            .get("time_ms")
            .and_then(Value::as_u64)
            .context("budget time is missing")?,
        disk_bytes: object
            .get("disk_bytes")
            .and_then(Value::as_u64)
            .context("budget disk is missing")?,
        memory_bytes: object
            .get("memory_bytes")
            .and_then(Value::as_u64)
            .context("budget memory is missing")?,
    })
}

fn registration_cache(
    root: &Path,
    case: &CorpusCase,
    registration: &RegistrationProjection,
) -> Result<IrCache> {
    let project_root = registration_project_root(root, case, &registration.inputs)?;
    let mutation_target = (registration.declared_kind == "mutation-witness")
        .then(|| {
            registration
                .inputs
                .iter()
                .find(|path| path.starts_with("src/") || path.contains("/src/"))
        })
        .flatten();
    let mut inputs = registration
        .inputs
        .iter()
        .map(|path| {
            let bytes = fs::read(project_root.join(path))
                .with_context(|| format!("read registered cache input {path}"))?;
            Ok(CacheInput {
                selector: if mutation_target == Some(path) {
                    "target-preimage".to_owned()
                } else {
                    path.clone()
                },
                identity: sha256_bytes(&bytes),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    inputs.sort();
    Ok(IrCache {
        registered_inputs: inputs.clone(),
        execution_inputs: inputs,
    })
}

fn registration_project_root(
    root: &Path,
    case: &CorpusCase,
    inputs: &[String],
) -> Result<std::path::PathBuf> {
    source_project_root(root, &case.source.path, inputs)
}

fn source_project_root(
    root: &Path,
    source_path: &str,
    inputs: &[String],
) -> Result<std::path::PathBuf> {
    let source = root.join(source_path);
    let mut candidates = source
        .parent()
        .context("registration source has no parent")?
        .ancestors()
        .take_while(|candidate| candidate.starts_with(root))
        .filter(|candidate| inputs.iter().all(|path| candidate.join(path).is_file()));
    let project_root = candidates
        .next()
        .context("registration inputs do not resolve from a project root")?;
    ensure!(
        candidates.next().is_none(),
        "registration inputs resolve from more than one project root"
    );
    Ok(project_root.to_path_buf())
}

fn subject_closure(
    root: &Path,
    source_path: &str,
    selectors: &[String],
) -> Result<IrSubjectClosure> {
    ensure!(!selectors.is_empty(), "claim subject closure is empty");
    let project_root = source_project_root(root, source_path, selectors)?;
    let members = selectors
        .iter()
        .map(|selector| {
            let path = Path::new(selector);
            ensure!(
                !path.is_absolute()
                    && path
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "claim source selector is not a normalized relative path"
            );
            let absolute = project_root.join(path);
            let metadata = fs::symlink_metadata(&absolute)
                .with_context(|| format!("inspect claim source {selector}"))?;
            ensure!(metadata.is_file() && !metadata.file_type().is_symlink());
            let bytes =
                fs::read(&absolute).with_context(|| format!("read claim source {selector}"))?;
            Ok(Artifact {
                logical_name: selector.clone(),
                sha256: sha256_bytes(&bytes),
                size_bytes: bytes.len() as u64,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let material = serde_json::json!({
        "schema": SUBJECT_CLOSURE_SCHEMA,
        "selectors": selectors,
        "members": members,
    });
    let sha256 = domain_hash(SUBJECT_CLOSURE_SCHEMA, &canonical_json(&material)?);
    Ok(IrSubjectClosure {
        schema: SUBJECT_CLOSURE_SCHEMA.to_owned(),
        sha256,
        selectors: selectors.to_vec(),
        members,
    })
}

fn family_detail(
    kind: &str,
    subject: Option<&str>,
    source: &Source,
    source_size: u64,
    configuration: Option<&Value>,
) -> Result<IrFamilyDetail> {
    let schema = family_schema(kind).expect("mapped family kind must have a detail schema");
    let configuration = configuration
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut detail = IrFamilyDetail {
        schema: schema.to_owned(),
        subject: None,
        artifact: None,
        property: None,
        mutation: None,
        distribution: None,
        bounded_domain: None,
        theorem: None,
        required_fact_schemas: Vec::new(),
    };
    match kind {
        "mutation-witness" => {
            ensure_family_configuration_fields(&configuration, &["mutation"])?;
            detail.subject = Some(subject.unwrap_or("subject:unknown").to_owned());
            if let Some(value) = configuration.get("mutation") {
                detail.mutation = Some(IrMutationRegistration {
                    schema: required_value_text(value, "schema")?.to_owned(),
                    registry: required_value_text(value, "registry")?.to_owned(),
                });
            }
        }
        "artifact-correspondence" => {
            ensure_family_configuration_fields(&configuration, &[])?;
            detail.artifact = Some(source_artifact(source, source_size));
        }
        "sampled-property" => {}
        "distribution-reproduction" => {
            ensure_family_configuration_fields(&configuration, &["distribution"])?;
            if let Some(value) = configuration.get("distribution") {
                detail.distribution = Some(IrDistributionRegistration {
                    schema: required_value_text(value, "schema")?.to_owned(),
                    format: required_value_text(value, "format")?.to_owned(),
                    artifact_name: required_value_text(value, "artifact_name")?.to_owned(),
                    artifact_sha256: required_value_text(value, "artifact_sha256")?.to_owned(),
                    source_date_epoch: value
                        .get("source_date_epoch")
                        .and_then(Value::as_u64)
                        .context("distribution source_date_epoch is missing")?,
                });
            }
        }
        "bounded-model-check" => {
            ensure_family_configuration_fields(&configuration, &["bounded_domain"])?;
            if let Some(value) = configuration.get("bounded_domain") {
                detail.bounded_domain = Some(IrBoundedDomain {
                    id: required_value_text(value, "id")?.to_owned(),
                    description: required_value_text(value, "description")?.to_owned(),
                    cardinality: value
                        .get("cardinality")
                        .and_then(Value::as_u64)
                        .context("bounded-domain cardinality is missing")?,
                    ordering_key: value
                        .get("ordering_key")
                        .and_then(Value::as_array)
                        .context("bounded-domain ordering key is missing")?
                        .iter()
                        .map(|item| item.as_u64().context("ordering key must be unsigned"))
                        .collect::<Result<Vec<_>>>()?,
                });
            }
        }
        "universal-source-proof" => {
            ensure_family_configuration_fields(&configuration, &["theorem"])?;
            detail.theorem = configuration
                .get("theorem")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        _ => ensure_family_configuration_fields(&configuration, &[])?,
    }
    if kind == "sampled-property" {
        ensure_family_configuration_fields(&configuration, &["property"])?;
        if let Some(value) = configuration.get("property") {
            let property = IrPropertyRegistration {
                schema: required_value_text(value, "schema")?.to_owned(),
                framework: required_value_text(value, "framework")?.to_owned(),
                seed: value
                    .get("seed")
                    .and_then(Value::as_u64)
                    .context("property seed is missing")?,
            };
            detail.required_fact_schemas.push(property.schema.clone());
            detail.property = Some(property);
        }
    }
    Ok(detail)
}

fn ensure_family_configuration_fields(
    configuration: &Map<String, Value>,
    allowed: &[&str],
) -> Result<()> {
    ensure!(
        configuration
            .keys()
            .all(|field| allowed.contains(&field.as_str())),
        "family configuration contains fields outside its typed IR variant"
    );
    Ok(())
}

fn empty_provenance(_unit: &str) -> IrProvenance {
    IrProvenance {
        revision: None,
        tree_state: None,
        semantic_closure: None,
        additional_closures: Vec::new(),
        input_artifacts: Vec::new(),
        generated_artifacts: Vec::new(),
        tool: None,
        adapter: None,
        execution_kind: None,
        commands: Vec::new(),
        runs: Vec::new(),
        normalization: None,
        reproduction: None,
        started_unix_ms: None,
        completed_unix_ms: None,
        result_sha256: None,
        unit_configuration_sha256: None,
        budget: None,
        usage: IrUsage {
            time_ms: None,
            disk_bytes: None,
            peak_memory: None,
        },
        python_plugins: Vec::new(),
        cache: IrCacheProvenance::NotExecuted,
    }
}

fn source_artifact(source: &Source, size_bytes: u64) -> Artifact {
    Artifact {
        logical_name: source.path.clone(),
        sha256: source.sha256.clone(),
        size_bytes,
    }
}

fn required_value_text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("{field} must be text"))
}

fn required_value_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be an array"))
}

fn required_value_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .with_context(|| format!("{field} must be a Boolean"))
}

fn json_text_array(object: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<String>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .with_context(|| format!("{field} entries must be text"))
        })
        .collect()
}

fn json_text_array_value(value: &Value, field: &str) -> Result<Vec<String>> {
    json_text_array(
        value
            .as_object()
            .with_context(|| format!("parent of {field} must be an object"))?,
        field,
    )
}

fn json_text_array_optional(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<String>> {
    match object.get(field) {
        Some(Value::Array(_)) => json_text_array(object, field),
        Some(_) => bail!("{field} must be an array"),
        None => Ok(Vec::new()),
    }
}

fn value_optional_text(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => bail!("{field} must be text or null"),
    }
}

fn verify_release_case(root: &Path, case: &CorpusCase, bytes: &[u8]) -> Result<()> {
    let receipt: Value = serde_json::from_slice(bytes).context("decode release receipt")?;
    let statuses = receipt
        .get("reported_statuses")
        .and_then(Value::as_array)
        .context("release has no reported statuses")?;
    for claim_id in &case.claim_ids {
        let status = statuses
            .iter()
            .find(|status| status.get("claim_id").and_then(Value::as_str) == Some(claim_id))
            .with_context(|| format!("release has no status for {claim_id}"))?;
        ensure!(
            status.get("formal").and_then(Value::as_str) == Some(&case.expected_claim.formal),
            "release formal status mismatch"
        );
        ensure!(
            status.get("linkage").and_then(Value::as_str) == Some(&case.expected_claim.linkage),
            "release linkage mismatch"
        );
        ensure!(
            status.get("assumption").and_then(Value::as_str)
                == Some(&case.expected_claim.assumption),
            "release assumption mismatch"
        );
        ensure!(
            status.get("policy_admitted").and_then(Value::as_bool)
                == Some(case.expected_claim.policy_admitted),
            "release policy mismatch"
        );
    }

    let envelope_path = case
        .source
        .envelope_path
        .as_deref()
        .context("release case has no envelope path")?;
    let envelope_sha256 = case
        .source
        .envelope_sha256
        .as_deref()
        .context("release case has no envelope digest")?;
    verify_source(root, envelope_path, envelope_sha256)?;
    Ok(())
}

fn verify_source(root: &Path, path: &str, expected: &str) -> Result<Vec<u8>> {
    let full = root.join(path);
    let bytes = fs::read(&full).with_context(|| format!("read source {}", full.display()))?;
    ensure!(
        sha256_bytes(&bytes) == expected,
        "source identity mismatch for {path}"
    );
    Ok(bytes)
}

fn required_text(table: &toml::value::Table, field: &str) -> Result<String> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{field} must be text"))
}

fn optional_text(table: &toml::value::Table, field: &str) -> Result<Option<String>> {
    match table.get(field) {
        Some(toml::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("{field} must be text"),
        None => Ok(None),
    }
}

fn text_array(table: &toml::value::Table, field: &str) -> Result<Vec<String>> {
    let values = table
        .get(field)
        .and_then(toml::Value::as_array)
        .with_context(|| format!("{field} must be an array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("{field} entries must be text"))
        })
        .collect()
}

fn optional_text_array(table: &toml::value::Table, field: &str) -> Result<Vec<String>> {
    match table.get(field) {
        Some(_) => text_array(table, field),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn projects_all_frozen_cases_deterministically() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let first = project_corpus(&root, &corpus).unwrap();
        let second = project_corpus(&root, &corpus).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.cases.len(), 20);
        assert!(first.projection_sha256.starts_with("sha256:"));
    }

    #[test]
    fn portable_family_projection_covers_completion_captures() {
        let root = root();
        let index = root.join(
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1/index.json",
        );
        let first = project_portable_families(&root, &index).unwrap();
        let second = project_portable_families(&root, &index).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.records.len(), 45);
        assert_eq!(
            first
                .records
                .iter()
                .filter(|record| matches!(
                    &record.family,
                    PortableFamily::SampledProperty(detail)
                        if matches!(detail.sampling, SamplingDetail::LegacyBackend { .. })
                ))
                .count(),
            2
        );
        assert!(
            first
                .records
                .iter()
                .any(|record| matches!(record.family, PortableFamily::HumanReview(_)))
        );
    }

    #[test]
    fn completion_receipts_have_independent_exact_derivation_traces() {
        let root = root();
        for language in ["python", "typescript", "rust"] {
            let receipt = fs::read(root.join(format!(
                "docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1/{language}/compiled-receipt.json"
            )))
            .unwrap();
            let bundle = derive_release_trace_bundle(&receipt).unwrap();
            let encoded = canonical_json(&bundle).unwrap();
            validate_release_trace_bundle(&receipt, &encoded).unwrap();
            assert!(!bundle.traces.is_empty());
            assert!(bundle.publication.blocked_claims.is_empty());
            assert!(bundle.publication.blockers.is_empty());
        }
    }

    #[test]
    fn completion_receipts_bind_registered_and_observed_artifact_roles() {
        let root = root();
        for (language, project_root) in [
            ("python", "demo/python-inventory-service"),
            ("typescript", "demo/typescript-codec"),
            ("rust", ""),
        ] {
            let receipt = fs::read(root.join(format!(
                "docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1/{language}/compiled-receipt.json"
            )))
            .unwrap();
            let report = audit_artifact_roles(&root, Path::new(project_root), &receipt).unwrap();
            assert!(!report.units.is_empty());
            assert!(
                report
                    .units
                    .iter()
                    .all(|unit| !unit.registered_inputs.is_empty())
            );
        }
    }

    #[test]
    fn rejects_all_preregistered_derivation_trace_attacks() {
        let root = root();
        let receipt = fs::read(root.join(
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1/python/compiled-receipt.json",
        ))
        .unwrap();
        let bundle = derive_release_trace_bundle(&receipt).unwrap();
        let original = serde_json::to_value(&bundle).unwrap();
        let mut attacks = Vec::new();

        let mut missing_evidence = original.clone();
        missing_evidence["traces"][0]["load_bearing_evidence"]
            .as_array_mut()
            .unwrap()
            .pop();
        attacks.push(missing_evidence);

        let mut stronger_rule = original.clone();
        stronger_rule["traces"][0]["formal_value_and_rule"]["rule"] =
            Value::String("universal-source-proof".to_owned());
        attacks.push(stronger_rule);

        let mut forged_component = original.clone();
        forged_component["traces"][0]["satisfied_policy_components"] =
            serde_json::json!(["forged-component", "ledger"]);
        attacks.push(forged_component);

        let mut publication_skew = original.clone();
        publication_skew["publication"]["admitted_claims"]
            .as_array_mut()
            .unwrap()
            .pop();
        attacks.push(publication_skew);

        let mut moved_claim = original.clone();
        moved_claim["traces"][0]["claim_id"] = Value::String("PY-WHEEL-001".to_owned());
        attacks.push(moved_claim);

        let mut reported_receipt: Value = serde_json::from_slice(&receipt).unwrap();
        reported_receipt["reported_statuses"][0]["policy_admitted"] = Value::Bool(false);
        let reported_receipt = canonical_json(&reported_receipt).unwrap();
        let mut reported_authored =
            serde_json::to_value(derive_release_trace_bundle(&reported_receipt).unwrap()).unwrap();
        reported_authored["traces"][0]["blockers"] = serde_json::json!(["reported-policy-blocked"]);
        reported_authored["publication"]["admitted_claims"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        reported_authored["publication"]["blocked_claims"] =
            serde_json::json!(["PY-RESERVATION-001"]);
        reported_authored["publication"]["blockers"] =
            serde_json::json!(["PY-RESERVATION-001:reported-policy-blocked"]);

        for attack in attacks {
            let error = validate_release_trace_bundle(&receipt, &canonical_json(&attack).unwrap())
                .unwrap_err();
            assert_eq!(error.code, "IR-DERIVATION-TRACE-MISMATCH");
        }
        let error = validate_release_trace_bundle(
            &reported_receipt,
            &canonical_json(&reported_authored).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code, "IR-DERIVATION-TRACE-MISMATCH");
    }

    #[test]
    fn registration_projection_retains_claim_and_request_meaning() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let case = projection
            .cases
            .iter()
            .find(|case| case.id == "IR-PY-001")
            .unwrap();
        let claim = &case.program.claims[0];
        assert_eq!(
            claim.subject,
            "python:proofbound-python-inventory::inventory_service.reservations.reserve"
        );
        assert!(
            claim
                .meaning
                .as_ref()
                .unwrap()
                .statement
                .starts_with("For the registered examples")
        );
        assert_eq!(claim.assumptions, ["PY-RUNTIME-001"]);
        assert!(claim.source.as_ref().unwrap().size_bytes > 0);

        let evidence = &case.program.evidence[0];
        assert_eq!(
            evidence.inventory,
            ["test_reservations::test_rejects_request_beyond_remaining_capacity"]
        );
        let request = evidence.request.as_ref().unwrap();
        assert_eq!(request.schema, "proofbound-evidence-unit/1");
        assert_eq!(request.environment_allowlist, ["PATH"]);
        assert_eq!(request.operation["type"], "pytest");
        let pyproject =
            fs::read(root.join("demo/python-inventory-service/pyproject.toml")).unwrap();
        let cache_input = case
            .program
            .cache
            .registered_inputs
            .iter()
            .find(|input| input.selector == "pyproject.toml")
            .unwrap();
        assert_eq!(cache_input.identity, sha256_bytes(&pyproject));
    }

    #[test]
    fn portable_projection_retains_programme_and_execution_meaning() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let program = &projection
            .cases
            .iter()
            .find(|case| case.id == "IR-REL-001")
            .unwrap()
            .program;
        let project = program.programme.project.as_ref().unwrap();
        assert_eq!(project.id, "synthetic");
        assert_eq!(project.revision, "rev-1");
        assert_eq!(program.programme.closures.len(), 1);
        assert_eq!(
            program.programme.graph.as_ref().unwrap().nodes[0].kind,
            "claim"
        );
        assert_eq!(program.programme.policies[0].id, "ledger-ci");
        assert_eq!(
            program.programme.closures[0].members[0].logical_name,
            "src/model.rs"
        );
        assert_eq!(
            program.programme.sealed_artifacts[0].logical_name,
            "tcb-ledger.json"
        );
        assert_eq!(program.programme.tcb_components.len(), 2);

        let evidence = &program.evidence[0];
        assert_eq!(
            evidence.content_sha256.as_deref(),
            Some("sha256:0472956f8429866d293913903a3b1ac9ae42764e658078953dae8015939b44d4")
        );
        assert_eq!(evidence.provenance.commands[0].program, "synthetic-runner");
        assert_eq!(evidence.provenance.runs[0].exit_code, Some(0));
        assert_eq!(evidence.provenance.usage.disk_bytes, Some(1));
        assert_eq!(
            evidence.provenance.cache,
            IrCacheProvenance::Executed {
                key: "sha256:3a3aa7839045a3bb80eae26b9bd31e629947c5354d2eb3ff919d640e944556c9"
                    .to_owned(),
            }
        );

        let mut inconsistent_cache = serde_json::to_value(program.clone()).unwrap();
        inconsistent_cache["evidence"][0]["provenance"]["cache"] = serde_json::json!({
            "state": "reused-exact-prior",
            "key": "sha256:3a3aa7839045a3bb80eae26b9bd31e629947c5354d2eb3ff919d640e944556c9"
        });
        let error =
            validate_case_program(&canonical_json(&inconsistent_cache).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-TYPED-RECORD");

        let mut invented_eligibility = serde_json::to_value(program.clone()).unwrap();
        invented_eligibility["evidence"][0]["provenance"]["cache"]["reuse_eligible"] =
            Value::Bool(true);
        let error =
            validate_case_program(&canonical_json(&invented_eligibility).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-TYPED-RECORD");

        let mut missing_policy = serde_json::to_value(program).unwrap();
        missing_policy["programme"]["policies"] = Value::Array(Vec::new());
        let error = validate_case_program(&canonical_json(&missing_policy).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-POLICY-OMITTED");

        let mut wrong_revision = serde_json::to_value(program).unwrap();
        wrong_revision["evidence"][0]["provenance"]["revision"] =
            Value::String("rev-substituted".to_owned());
        let error = validate_case_program(&canonical_json(&wrong_revision).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-PROVENANCE-MISMATCH");

        let mut wrong_graph = serde_json::to_value(program).unwrap();
        wrong_graph["programme"]["graph"]["nodes"][0]["kind"] = Value::String("subject".to_owned());
        let error = validate_case_program(&canonical_json(&wrong_graph).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-GRAPH-IDENTITY");

        let mut wrong_closure = serde_json::to_value(program).unwrap();
        wrong_closure["programme"]["closures"][0]["members"][0]["size_bytes"] = Value::from(13);
        let error = validate_case_program(&canonical_json(&wrong_closure).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-CLOSURE-IDENTITY");

        let mut missing_status = serde_json::to_value(program).unwrap();
        missing_status["programme"]["reported_statuses"] = Value::Array(Vec::new());
        let error = validate_case_program(&canonical_json(&missing_status).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-STATUS-MISMATCH");

        let mut false_blocker = serde_json::to_value(program).unwrap();
        false_blocker["programme"]["publication_blockers"] = serde_json::json!(["c"]);
        let error = validate_case_program(&canonical_json(&false_blocker).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-BLOCKER-MISMATCH");

        let mut unknown_policy_field = serde_json::to_value(program).unwrap();
        unknown_policy_field["programme"]["policies"][0]["backend_hint"] =
            Value::String("hidden".to_owned());
        let error =
            validate_case_program(&canonical_json(&unknown_policy_field).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-TYPED-RECORD");

        let mut substituted_tcb = serde_json::to_value(program).unwrap();
        substituted_tcb["programme"]["tcb_components"][0]["identity_sha256"] =
            Value::String(format!("sha256:{}", "2".repeat(64)));
        let ledger = serde_json::json!({
            "components": substituted_tcb["programme"]["tcb_components"],
            "schema": "proofbound-tcb-ledger/1",
        });
        let ledger_bytes = canonical_json(&ledger).unwrap();
        substituted_tcb["programme"]["sealed_artifacts"][0]["sha256"] =
            Value::String(sha256_bytes(&ledger_bytes));
        substituted_tcb["programme"]["sealed_artifacts"][0]["size_bytes"] =
            Value::from(ledger_bytes.len() as u64);
        let error = validate_case_program(&canonical_json(&substituted_tcb).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-PROGRAMME-TCB-MISMATCH");
    }

    #[test]
    fn typed_ledger_records_round_trip_without_opaque_values() {
        let assumption = serde_json::json!({
            "schema": "proofbound-assumption/1",
            "id": "ASSUMPTION-1",
            "node_id": "assumption:one",
            "statement": "The runtime preserves integer addition.",
            "category": "runtime-environment",
            "owner": "runtime team",
            "rationale": "Execution is outside the proof kernel.",
            "scope": "registered runtime calls",
            "affected_claims": ["CLAIM-1"],
            "review_evidence": [],
            "falsification_or_discharge_plan": "Replace with a verified runtime.",
            "state": "active",
            "depends_on": [],
        });
        let premise = serde_json::json!({
            "id": "PREMISE-1",
            "node_id": "premise:one",
            "statement": "Inputs use the registered representation.",
            "category": "representation-premise",
            "scope": {"kind": "flows", "flows": ["input:one"]},
        });
        assert_eq!(
            serde_json::to_value(assumption_from_value(&assumption).unwrap()).unwrap(),
            assumption
        );
        assert_eq!(
            serde_json::to_value(premise_from_value(&premise).unwrap()).unwrap(),
            premise
        );
    }

    #[test]
    fn typed_family_details_bind_registration_and_artifact_roles() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let property = &projection
            .cases
            .iter()
            .find(|case| case.id == "IR-PY-002")
            .unwrap()
            .program;
        assert_eq!(
            property.evidence[0]
                .family
                .detail
                .property
                .as_ref()
                .unwrap()
                .seed,
            4_025_493_768
        );

        let mut substituted_property = serde_json::to_value(property).unwrap();
        substituted_property["evidence"][0]["family"]["detail"]["property"]["seed"] =
            Value::from(1);
        let error =
            validate_case_program(&canonical_json(&substituted_property).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-EVIDENCE-FAMILY-DETAIL");

        let mut substituted_fact = serde_json::to_value(property).unwrap();
        substituted_fact["evidence"][0]["backend"]["retained_facts"][0]["value"]["configuration_sha256"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        let error = validate_case_program(&canonical_json(&substituted_fact).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-BACKEND-FACT-MISMATCH");

        let mut optional_extension = serde_json::to_value(property).unwrap();
        let fact = optional_extension["evidence"][0]["backend"]["retained_facts"][0]
            .as_object_mut()
            .unwrap();
        fact.insert(
            "schema".to_owned(),
            Value::String("extension-observation/1".to_owned()),
        );
        fact.insert("required".to_owned(), Value::Bool(false));
        fact.remove("value");
        fact.insert(
            "payload_sha256".to_owned(),
            Value::String(format!("sha256:{}", "1".repeat(64))),
        );
        validate_case_program(&canonical_json(&optional_extension).unwrap()).unwrap();

        let artifact = &projection
            .cases
            .iter()
            .find(|case| case.id == "IR-SEM-004")
            .unwrap()
            .program;
        let mut substituted_role = serde_json::to_value(artifact).unwrap();
        substituted_role["evidence"][1]["family"]["detail"]["artifact"]["logical_name"] =
            Value::String("substituted-artifact".to_owned());
        let error = validate_case_program(&canonical_json(&substituted_role).unwrap()).unwrap_err();
        assert_eq!(
            error.code, "IR-ARTIFACT-IDENTITY-MISMATCH",
            "{}",
            error.message
        );
    }

    #[test]
    fn subject_closure_binds_registered_paths_and_bytes() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let program = &projection
            .cases
            .iter()
            .find(|case| case.id == "IR-PY-001")
            .unwrap()
            .program;
        let closure = program.claims[0].subject_closure.as_ref().unwrap();
        assert_eq!(closure.selectors, ["src/inventory_service/reservations.py"]);
        assert_eq!(closure.members[0].logical_name, closure.selectors[0]);

        let mut substituted = serde_json::to_value(program).unwrap();
        substituted["claims"][0]["subject_closure"]["selectors"][0] =
            Value::String("src/inventory_service/substituted.py".to_owned());
        substituted["claims"][0]["subject_closure"]["members"][0]["logical_name"] =
            Value::String("src/inventory_service/substituted.py".to_owned());
        let closure = substituted["claims"][0]["subject_closure"]
            .as_object()
            .unwrap();
        let material = serde_json::json!({
            "schema": closure["schema"],
            "selectors": closure["selectors"],
            "members": closure["members"],
        });
        substituted["claims"][0]["subject_closure"]["sha256"] = Value::String(domain_hash(
            SUBJECT_CLOSURE_SCHEMA,
            &canonical_json(&material).unwrap(),
        ));
        let error = validate_case_program(&canonical_json(&substituted).unwrap()).unwrap_err();
        assert_eq!(error.code, "IR-CLAIM-SUBJECT-CLOSURE");
    }

    #[test]
    fn source_drift_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let error = verify_source(temporary.path(), "missing", "sha256:00").unwrap_err();
        assert!(error.to_string().contains("read source"));
    }

    #[test]
    fn rejects_every_preregistered_adversarial_case() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let bases = projection
            .cases
            .iter()
            .map(|case| (case.id.as_str(), &case.program))
            .collect::<BTreeMap<_, _>>();
        let adversarial_path = root
            .join("docs/experiments/0005-assurance-ir-extraction/corpus/adversarial-cases.json");
        let adversarial: Value =
            serde_json::from_slice(&fs::read(adversarial_path).unwrap()).unwrap();
        assert_eq!(adversarial.get("revision").and_then(Value::as_u64), Some(2));
        let attacks = adversarial.get("cases").and_then(Value::as_array).unwrap();
        assert_eq!(attacks.len(), 20);

        for attack in attacks {
            let base_id = attack.get("base_case").and_then(Value::as_str).unwrap();
            let base = bases[base_id];
            let bytes = mutate_case(base, attack);
            let expected = attack
                .pointer("/expected/code")
                .and_then(Value::as_str)
                .unwrap();
            let error = validate_case_program(&bytes).unwrap_err();
            assert_eq!(error.code, expected, "attack {}", attack["id"]);
        }
    }

    #[test]
    fn rejects_every_preregistered_q1_adversarial_case() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let base = &projection
            .cases
            .iter()
            .find(|case| case.id == "IR-REL-001")
            .unwrap()
            .program;
        let path = root
            .join("docs/experiments/0005-assurance-ir-extraction/corpus/q1-adversarial-cases.json");
        let adversarial: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(adversarial.get("revision").and_then(Value::as_u64), Some(1));
        assert_eq!(
            adversarial.get("status").and_then(Value::as_str),
            Some("preregistered-not-executed")
        );
        let attacks = adversarial.get("cases").and_then(Value::as_array).unwrap();
        assert_eq!(attacks.len(), 12);

        for attack in attacks {
            let bytes = mutate_case(base, attack);
            let expected = attack
                .pointer("/expected/code")
                .and_then(Value::as_str)
                .unwrap();
            let error = validate_case_program(&bytes).unwrap_err();
            assert_eq!(error.code, expected, "attack {}", attack["id"]);
        }
    }

    fn mutate_case(base: &CaseProgram, attack: &Value) -> Vec<u8> {
        let mutation = attack.get("mutation").unwrap();
        let operation = mutation.get("operation").and_then(Value::as_str).unwrap();
        let mut value = serde_json::to_value(base).unwrap();
        match operation {
            "delete" => delete_pointer(
                &mut value,
                mutation.get("path").and_then(Value::as_str).unwrap(),
            ),
            "replace" | "replace-reported-status" => {
                let path = mutation.get("path").and_then(Value::as_str).unwrap();
                if let Some(target) = value.pointer_mut(path) {
                    *target = mutation.get("value").unwrap().clone();
                } else if path.ends_with("/cache/prior_receipt") {
                    let (parent, field) = path.rsplit_once('/').unwrap();
                    value
                        .pointer_mut(parent)
                        .and_then(Value::as_object_mut)
                        .unwrap()
                        .insert(field.to_owned(), mutation.get("value").unwrap().clone());
                } else {
                    panic!("missing adversarial replacement path {path}");
                }
            }
            "duplicate-set-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let index = mutation.get("index").and_then(Value::as_u64).unwrap() as usize;
                array.insert(index, array[index].clone());
            }
            "replace-family" => {
                let from = mutation.get("from").and_then(Value::as_str).unwrap();
                let to = mutation.get("to").and_then(Value::as_str).unwrap();
                let evidence = value
                    .get_mut("evidence")
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let family = evidence
                    .iter_mut()
                    .find_map(|item| {
                        let family = item.get_mut("family")?;
                        (family.get("kind").and_then(Value::as_str) == Some(from)).then_some(family)
                    })
                    .unwrap();
                family["kind"] = Value::String(to.to_owned());
            }
            "remove-set-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let position = if let Some(expected) = mutation.get("value") {
                    array.iter().position(|item| item == expected).unwrap()
                } else {
                    let selector = mutation.get("selector").and_then(Value::as_str).unwrap();
                    array
                        .iter()
                        .position(|item| {
                            item.get("selector").and_then(Value::as_str) == Some(selector)
                        })
                        .unwrap()
                };
                array.remove(position);
            }
            "add-set-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                array.push(mutation.get("value").unwrap().clone());
                array.sort_by_key(|item| item.as_str().unwrap().to_owned());
            }
            "add-object-field" => {
                let object = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_object_mut)
                    .unwrap();
                let field = mutation.get("field").and_then(Value::as_str).unwrap();
                object.insert(field.to_owned(), mutation.get("value").unwrap().clone());
            }
            "add-array-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                array.push(mutation.get("value").unwrap().clone());
            }
            "delete-array-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let index = mutation.get("index").and_then(Value::as_u64).unwrap() as usize;
                array.remove(index);
            }
            "duplicate-array-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let index = mutation.get("index").and_then(Value::as_u64).unwrap() as usize;
                array.insert(index, array[index].clone());
            }
            "add-graph-edge-and-rehash" => {
                let graph = value.pointer_mut("/programme/graph").unwrap();
                graph
                    .get_mut("edges")
                    .and_then(Value::as_array_mut)
                    .unwrap()
                    .push(mutation.get("value").unwrap().clone());
                rehash_programme_graph(&mut value);
            }
            "replace-and-rehash-graph" => {
                let path = mutation.get("path").and_then(Value::as_str).unwrap();
                *value.pointer_mut(path).unwrap() = mutation.get("value").unwrap().clone();
                rehash_programme_graph(&mut value);
            }
            "encode-noncanonical" => {
                let mut bytes = canonical_json(&value).unwrap();
                bytes.push(b'\n');
                return bytes;
            }
            "encode-duplicate-object-key" => {
                let bytes = canonical_json(&value).unwrap();
                let unit = base.evidence[0].unit.as_str();
                let needle = format!("\"unit\":\"{unit}\"");
                let replacement = format!("{needle},{needle}");
                return String::from_utf8(bytes)
                    .unwrap()
                    .replacen(&needle, &replacement, 1)
                    .into_bytes();
            }
            other => panic!("unsupported adversarial operation {other}"),
        }
        canonical_json(&value).unwrap()
    }

    fn rehash_programme_graph(value: &mut Value) {
        let graph = value.pointer("/programme/graph").unwrap();
        let schema = graph.get("schema").and_then(Value::as_str).unwrap();
        let digest = domain_hash(schema, &canonical_json(graph).unwrap());
        value["programme"]["graph_sha256"] = Value::String(digest);
    }

    fn delete_pointer(value: &mut Value, pointer: &str) {
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove(field)
            .unwrap();
    }
}
