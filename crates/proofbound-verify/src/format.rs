//! Closed `proofbound-compiled-release/3` receipt format.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const RELEASE_ENVELOPE_SCHEMA_V3: &str = "proofbound-release-envelope/3";
pub const COMPILED_RELEASE_SCHEMA_V3: &str = "proofbound-compiled-release/3";
pub const GRAPH_SCHEMA_V1: &str = "proofbound-graph/1";
pub const CLAIM_SCHEMA_V1: &str = "proofbound-claim/1";
pub const EVIDENCE_SCHEMA_V3: &str = "proofbound-evidence/3";
pub const ASSUMPTION_SCHEMA_V1: &str = "proofbound-assumption/1";
pub const CLOSURE_SCHEMA_V1: &str = "proofbound-source-closure/1";
pub const POLICY_SCHEMA_V1: &str = "proofbound-policy/1";
pub const TRUSTED_TRANSCRIPTION_SCHEMA_V1: &str = "proofbound-trusted-transcription/1";
pub const TRANSCRIPTION_DRIVER_ABI_V1: &str = "proofbound-transcription-driver/1";
pub const TRANSCRIPTION_TCB_ROLE_DOMAIN_V1: &str = "proofbound-transcription-tcb-role/1";
pub const MUTATION_WITNESS_SCHEMA_V2: &str = "proofbound-mutation-witness/2";
pub const MUTATION_IDENTITY_DOMAIN_V2: &str = "proofbound-mutation/2";
pub const PYTHON_PROPERTY_SCHEMA_V1: &str = "proofbound-python-property/1";
pub const STATIC_CHECK_SCHEMA_V1: &str = "proofbound-static-check/1";
pub const DISTRIBUTION_REPRODUCTION_SCHEMA_V1: &str = "proofbound-distribution-reproduction/1";

/// Small canonical index stored as `<release>/release.json`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEnvelope {
    pub schema: String,
    pub payload: String,
    pub payload_sha256: String,
}

/// Complete closed receipt payload. It references no unsealed external state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledRelease {
    pub schema: String,
    pub project: String,
    pub project_revision: String,
    pub project_tier: Tier,
    pub tree_state: TreeState,
    pub graph: AssuranceGraph,
    pub graph_sha256: String,
    pub claims: Vec<ClaimReceipt>,
    pub evidence: Vec<HashedRecord<EvidenceReceipt>>,
    pub assumptions: Vec<AssumptionReceipt>,
    pub premises: Vec<PremiseReceipt>,
    pub policies: Vec<PolicyReceipt>,
    pub closures: Vec<HashedRecord<SourceClosureReceipt>>,
    #[serde(default)]
    pub sealed_files: Vec<SealedFile>,
    pub reported_statuses: Vec<ReportedClaimStatus>,
}

/// Digest envelope avoids self-referential IDs inside content-addressed data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HashedRecord<T> {
    pub sha256: String,
    pub record: T,
}

/// One physical file included in the portable release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedFile {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TreeState {
    Clean,
    Dirty,
}

/// Numeric adoption tier, encoded as an integer from zero through three.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Tier {
    Ledger,
    Bounded,
    Model,
    Bound,
}

impl Tier {
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Ledger => 0,
            Self::Bounded => 1,
            Self::Model => 2,
            Self::Bound => 3,
        }
    }

    #[must_use]
    pub const fn admits(self, required: Self) -> bool {
        self.number() >= required.number()
    }
}

impl Serialize for Tier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.number())
    }
}

impl<'de> Deserialize<'de> for Tier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::Ledger),
            1 => Ok(Self::Bounded),
            2 => Ok(Self::Model),
            3 => Ok(Self::Bound),
            _ => Err(serde::de::Error::custom("tier must be 0, 1, 2, or 3")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    Claim,
    Theorem,
    Subject,
    Artifact,
    SourceClosure,
    TranslationUnit,
    ModelCheckUnit,
    TestSuite,
    Assumption,
    Premise,
    Toolchain,
    TcbComponent,
    Review,
    Policy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    Proves,
    Refines,
    Decodes,
    Checks,
    GeneratedFrom,
    DependsOn,
    Assumes,
    DischargedBy,
    CrossChecks,
    CoversBoundedDomain,
    BindsDigest,
    ReviewedBy,
    AdmittedByPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub id: String,
    pub kind: NodeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_environment: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutualTheoremGroup {
    pub id: String,
    pub proof_environment: String,
    pub members: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceGraph {
    pub schema: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(default)]
    pub mutual_theorem_groups: Vec<MutualTheoremGroup>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenObligation {
    pub id: String,
    pub statement: String,
    pub remediation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub id: String,
    pub statement: String,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReceipt {
    pub schema: String,
    pub id: String,
    pub node_id: String,
    pub title: String,
    /// Exact internal property registered for theorem and evidence matching.
    pub statement: String,
    /// Optional reader-facing property language; never replaces `statement`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_language: Option<String>,
    pub subject: String,
    pub policy: String,
    /// Optional per-claim tier ceiling; absence inherits `project_tier`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    pub cited_evidence: BTreeSet<String>,
    #[serde(default)]
    pub assumptions: BTreeSet<String>,
    #[serde(default)]
    pub open_obligations: BTreeSet<OpenObligation>,
    #[serde(default)]
    pub out_of_scope: BTreeSet<Exclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_linkage: Option<LinkageFacet>,
    #[serde(default)]
    pub registered_inputs: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_domain_language: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Theorem,
    ArtifactSoundness,
    TrustedTranscription,
    SourceRefinement,
    BoundedCheck,
    IndependentCheck,
    ExhaustiveCheck,
    PropertyTest,
    ExampleTest,
    MutationWitness,
    StaticCheck,
    Review,
    Assumption,
    Open,
}

impl EvidenceKind {
    #[must_use]
    pub const fn minimum_tier(self) -> Tier {
        match self {
            Self::Theorem => Tier::Model,
            Self::ArtifactSoundness | Self::SourceRefinement => Tier::Bound,
            Self::TrustedTranscription => Tier::Bounded,
            Self::BoundedCheck | Self::IndependentCheck | Self::ExhaustiveCheck => Tier::Bounded,
            _ => Tier::Ledger,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOutcome {
    Passed,
    Failed,
    Missing,
    Drifted,
    Unregistered,
    Ambiguous,
    Corrupt,
    Skipped,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationMode {
    Kernel,
    Native,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    BytesInTheorem,
    DigestTheorem,
    ExternalRoundTrip,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TheoremReceipt {
    pub declaration: String,
    pub statement_encoding: String,
    pub statement_wire: serde_json::Value,
    pub statement_sha256: String,
    pub attributed_claim: String,
    pub proof_environment: String,
    pub axiom_audit_passed: bool,
    pub contains_sorry_ax: bool,
    #[serde(default)]
    pub foundational_axioms: BTreeSet<String>,
    #[serde(default)]
    pub project_axioms: BTreeSet<String>,
}

/// Exact identity of an artifact checked by a binding evidence unit.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentityReceipt {
    pub logical_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBindingReceipt {
    pub theorem_evidence: String,
    pub artifact: ArtifactIdentityReceipt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranscriptionRole {
    Transcriber,
    Reencoder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptionTcbRoleReceipt {
    pub tcb_node: String,
    pub role_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTranscriptionReceipt {
    pub schema: String,
    pub source: ArtifactIdentityReceipt,
    pub committed_transcription: ArtifactIdentityReceipt,
    pub transcribed_candidate: ArtifactIdentityReceipt,
    pub reencoded_source: ArtifactIdentityReceipt,
    pub driver: ArtifactIdentityReceipt,
    pub transcriber: TranscriptionTcbRoleReceipt,
    pub reencoder: TranscriptionTcbRoleReceipt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefinementStrength {
    FieldForField,
    DecisionAdequate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRefinementReceipt {
    pub refinement_theorem_evidence: String,
    pub representation_premises: BTreeSet<String>,
    pub deterministic_translation: bool,
    pub pinned_toolchain: bool,
    pub generated_axioms_clean: bool,
    pub strength: RefinementStrength,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedDomain {
    pub id: String,
    pub description: String,
    pub registration_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedCheckReceipt {
    pub domain: BoundedDomain,
    pub solver: String,
    pub harnesses: BTreeSet<String>,
    #[serde(default)]
    pub unwind_bounds: BTreeMap<String, u64>,
    /// Exact solver assumptions reported for this bounded execution.
    pub assumptions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExhaustiveCheckReceipt {
    pub domain: BoundedDomain,
    pub evaluated_members: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationWitnessReceipt {
    pub schema: String,
    pub mutation_id: String,
    pub subject: String,
    pub guard: String,
    pub mutation_sha256: String,
    pub registry: ArtifactIdentityReceipt,
    pub target_preimage: ArtifactIdentityReceipt,
    pub mutant_artifact: ArtifactIdentityReceipt,
    pub target_postimage: ArtifactIdentityReceipt,
    pub witness_source: ArtifactIdentityReceipt,
    pub check_id: String,
    pub baseline_run_index: usize,
    pub expected_failure: ExpectedFailureReceipt,
    pub proof_term_witness: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFailureReceipt {
    pub run_index: usize,
    pub allowed_exit_codes: BTreeSet<i32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndependenceMode {
    Independent,
    CommonOrigin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceMeasure {
    pub time_ms: u64,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub name: String,
    pub version: String,
    pub identity_sha256: String,
}

/// One environment variable admitted to a typed command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentReceipt {
    pub name: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub value_sha256: Option<String>,
    pub secret: bool,
}

/// One exact process invocation in adapter execution order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReceipt {
    pub program: String,
    pub args: Vec<String>,
    pub environment_allowlist: Vec<EnvironmentReceipt>,
}

/// Captured outcome for exactly one indexed command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRunReceipt {
    pub command_index: usize,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub normalized_output_sha256: String,
    pub output_truncated: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionKind {
    ObservedProcesses,
    CompilerInternal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheKeyMaterial {
    pub semantic_closure: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_closures: Vec<ClosureReference>,
    pub input_artifacts: Vec<ArtifactIdentityReceipt>,
    pub tool: ToolIdentity,
    pub adapter: ToolIdentity,
    pub unit_configuration_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub project_revision: String,
    pub tree_state: TreeState,
    pub semantic_closure: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_closures: Vec<ClosureReference>,
    #[serde(default)]
    pub input_artifacts: Vec<ArtifactIdentityReceipt>,
    #[serde(default)]
    pub generated_artifacts: Vec<ArtifactIdentityReceipt>,
    pub tool: ToolIdentity,
    pub adapter: ToolIdentity,
    pub execution_kind: ExecutionKind,
    pub commands: Vec<CommandReceipt>,
    pub runs: Vec<ExecutionRunReceipt>,
    pub normalization: String,
    pub reproduction_command: CommandReceipt,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub deterministic_result_sha256: String,
    pub unit_configuration_sha256: String,
    pub cache_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused_from: Option<String>,
    pub resource_budget: ResourceMeasure,
    pub actual_cost: ActualCostReceipt,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub python_plugins: Vec<PythonPluginReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PythonPluginReceipt {
    pub module: String,
    pub distribution: String,
    pub version: String,
    pub origin_sha256: String,
}

/// Measured adapter cost; `None` means peak memory was not measured.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActualCostReceipt {
    pub time_ms: u64,
    pub disk_bytes: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub memory_bytes: Option<u64>,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl EvidenceProvenance {
    #[must_use]
    pub fn cache_material(&self) -> CacheKeyMaterial {
        CacheKeyMaterial {
            semantic_closure: self.semantic_closure.clone(),
            additional_closures: self.additional_closures.clone(),
            input_artifacts: self.input_artifacts.clone(),
            tool: self.tool.clone(),
            adapter: self.adapter.clone(),
            unit_configuration_sha256: self.unit_configuration_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureReference {
    pub kind: ClosureKind,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReceipt {
    pub schema: String,
    pub unit_id: String,
    pub node_id: String,
    pub kind: EvidenceKind,
    pub claim_ids: BTreeSet<String>,
    pub outcome: EvidenceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_mode: Option<EvaluationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_mode: Option<BindingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem: Option<TheoremReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_binding: Option<ArtifactBindingReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_transcription: Option<TrustedTranscriptionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_refinement: Option<SourceRefinementReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_check: Option<BoundedCheckReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exhaustive_check: Option<ExhaustiveCheckReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_witness: Option<MutationWitnessReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_property: Option<PythonPropertyReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_check: Option<StaticCheckReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_reproduction: Option<DistributionReproductionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence: Option<IndependenceMode>,
    #[serde(default)]
    pub inventoried_targets: BTreeSet<String>,
    #[serde(default)]
    pub assumptions: BTreeSet<String>,
    #[serde(default)]
    pub premises: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_obligation: Option<OpenObligation>,
    pub provenance: EvidenceProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PythonPropertyReceipt {
    pub schema: String,
    pub framework: String,
    pub seed: u64,
    pub framework_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCheckReceipt {
    pub schema: String,
    pub tool: String,
    pub tool_version: String,
    pub configuration_sha256: String,
    pub targets: BTreeSet<String>,
    pub diagnostics: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionReproductionReceipt {
    pub schema: String,
    pub format: String,
    pub run_digests: Vec<String>,
    pub registered_digest: String,
    pub source_date_epoch: u64,
    pub build_backend_name: String,
    pub build_backend_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_integrity: Option<String>,
    #[serde(default)]
    pub member_inventory: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssumptionCategory {
    MathematicalHypothesis,
    RepresentationPremise,
    TranslatorTcb,
    CompilerTcb,
    RuntimeEnvironment,
    ExternalProvider,
    CryptographicLibrary,
    HumanAttestation,
    NativeEvaluation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssumptionState {
    Active,
    Discharged,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssumptionReceipt {
    pub schema: String,
    pub id: String,
    pub node_id: String,
    pub statement: String,
    pub category: AssumptionCategory,
    pub owner: String,
    pub rationale: String,
    pub scope: String,
    pub affected_claims: BTreeSet<String>,
    pub review_evidence: BTreeSet<String>,
    pub falsification_or_discharge_plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_citation: Option<String>,
    pub state: AssumptionState,
    #[serde(default)]
    pub depends_on: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FlowScope {
    AllRegisteredInputs,
    Flows { flows: BTreeSet<String> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PremiseDischarge {
    pub theorem_evidence: String,
    pub scope: FlowScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PremiseReceipt {
    pub id: String,
    pub node_id: String,
    pub statement: String,
    pub category: AssumptionCategory,
    /// Present for a theorem hypothesis. Direct claim-level premises omit it
    /// and are bound by an exact claim-to-premise `assumes` graph edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem_evidence: Option<String>,
    pub scope: FlowScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discharge: Option<PremiseDischarge>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuiltInProfile {
    Ledger,
    Transcribed,
    Kernel,
    KernelWithAssumptions,
    ArtifactBound,
    SourceRefined,
    NativeEvaluated,
    Bounded,
}

impl BuiltInProfile {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Transcribed => "transcribed",
            Self::Kernel => "kernel",
            Self::KernelWithAssumptions => "kernel-with-assumptions",
            Self::ArtifactBound => "artifact-bound",
            Self::SourceRefined => "source-refined",
            Self::NativeEvaluated => "native-evaluated",
            Self::Bounded => "bounded",
        }
    }

    #[must_use]
    pub const fn minimum_tier(self) -> Tier {
        match self {
            Self::Ledger => Tier::Ledger,
            Self::Bounded | Self::Transcribed => Tier::Bounded,
            Self::Kernel | Self::KernelWithAssumptions | Self::NativeEvaluated => Tier::Model,
            Self::ArtifactBound | Self::SourceRefined => Tier::Bound,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativePremiseRule {
    AtLeastOne,
    Exactly { count: usize },
}

impl NativePremiseRule {
    #[must_use]
    pub const fn accepts(&self, actual: usize) -> bool {
        match self {
            Self::AtLeastOne => actual >= 1,
            Self::Exactly { count } => actual == *count,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReceipt {
    pub schema: String,
    pub id: String,
    pub node_id: String,
    #[serde(default)]
    pub components: BTreeSet<BuiltInProfile>,
    #[serde(default)]
    pub allowed_foundational_axioms: BTreeSet<String>,
    #[serde(default)]
    pub allowed_project_axioms: BTreeSet<String>,
    pub admit_exhaustive_as_proved: bool,
    pub require_no_assumptions: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_premise_rule: Option<NativePremiseRule>,
    #[serde(default)]
    pub additional_required_evidence: BTreeSet<EvidenceKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureMember {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceClosureReceipt {
    pub schema: String,
    pub kind: ClosureKind,
    pub members: Vec<ClosureMember>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClosureKind {
    Semantic,
    Runner,
    Presentation,
    ExternalEvidence,
    Toolchain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FormalFacet {
    Proved,
    BoundedChecked,
    Tested,
    Open,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinkageFacet {
    Refined,
    ArtifactBound,
    Transcribed,
    ModelOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssumptionFacet {
    None,
    Assumed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedClaimStatus {
    pub claim_id: String,
    pub public_statement: String,
    pub formal: FormalFacet,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkage: Option<LinkageFacet>,
    pub assumption: AssumptionFacet,
    #[serde(default)]
    pub assumptions: BTreeSet<String>,
    #[serde(default)]
    pub undischarged_premises: BTreeSet<String>,
    pub policy_admitted: bool,
}
