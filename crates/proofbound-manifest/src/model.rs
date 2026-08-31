use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectManifest {
    pub schema: String,
    pub project: String,
    pub tier: u8,
    pub source: SourceSets,
    #[serde(default)]
    pub toolchains: ToolchainFiles,
    pub claim_manifests: Vec<String>,
    #[serde(default)]
    pub assumption_manifests: Vec<String>,
    #[serde(default)]
    pub evidence_units: Vec<String>,
    #[serde(default)]
    pub translation_units: Vec<String>,
    #[serde(default)]
    pub model_check_units: Vec<String>,
    #[serde(default)]
    pub policy_manifests: Vec<String>,
    #[serde(default)]
    pub review_manifests: Vec<String>,
    pub demo_registry: Option<String>,
    #[serde(default)]
    pub limits: ProjectLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSets {
    pub semantic: Vec<String>,
    pub runner: Vec<String>,
    pub presentation: Vec<String>,
    #[serde(default)]
    pub external_evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainFiles {
    pub rust: Option<String>,
    pub lean: Option<String>,
    pub python: Option<String>,
    pub translation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectLimits {
    #[serde(default = "default_manifest_bytes")]
    pub max_manifest_bytes: u64,
    #[serde(default = "default_files")]
    pub max_files: usize,
    #[serde(default = "default_total_bytes")]
    pub max_total_bytes: u64,
}

impl Default for ProjectLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: default_manifest_bytes(),
            max_files: default_files(),
            max_total_bytes: default_total_bytes(),
        }
    }
}

const fn default_manifest_bytes() -> u64 {
    2 << 20
}
const fn default_files() -> usize {
    100_000
}
const fn default_total_bytes() -> u64 {
    4 << 30
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimManifest {
    pub schema: String,
    pub id: String,
    pub title: String,
    pub statement: String,
    pub public_language: Option<String>,
    pub formal_declaration: Option<String>,
    pub statement_encoding: Option<String>,
    pub statement_sha256: Option<String>,
    #[serde(default)]
    pub foundational_axioms: Vec<String>,
    pub subject: String,
    pub subject_closure: Option<String>,
    pub profile: String,
    pub tier: Option<u8>,
    pub primary_linkage: Option<PrimaryLinkage>,
    pub evidence: Vec<String>,
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub premises: Vec<String>,
    pub open_obligations: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub bounded_domain: Option<BoundedDomain>,
    #[serde(default)]
    pub source_roots: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrimaryLinkage {
    Refined,
    ArtifactBound,
    Transcribed,
    ModelOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedDomain {
    pub id: String,
    pub description: String,
    pub cardinality: u64,
    pub ordering_key: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssumptionManifest {
    pub schema: String,
    pub id: String,
    pub statement: String,
    pub category: AssumptionCategory,
    pub owner: String,
    pub rationale: String,
    pub scope: String,
    pub affected_claims: Vec<String>,
    pub review_evidence: Vec<String>,
    pub discharge_plan: String,
    pub source_citation: Option<String>,
    pub status: AssumptionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssumptionStatus {
    Active,
    Discharged,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceUnitManifest {
    pub schema: String,
    pub id: String,
    pub adapter: AdapterKind,
    pub kind: EvidenceKind,
    pub claims: Vec<String>,
    pub tier: u8,
    pub operation: AdapterOperation,
    pub evaluation_mode: Option<EvaluationMode>,
    pub binding_mode: Option<BindingMode>,
    pub theorem: Option<String>,
    pub refinement_theorem: Option<String>,
    #[serde(default)]
    pub premises: Vec<String>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub expected_inventory: Vec<String>,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub environment_allowlist: Vec<String>,
    pub bounded_domain: Option<BoundedDomain>,
    #[serde(default)]
    pub transcription: Option<TrustedTranscriptionConfig>,
    pub resource_budget: ResourceBudget,
}

/// Manifest-owned inputs for the executable trusted-transcription route.
///
/// The adapter derives the two trusted roles from the registered driver and
/// this typed configuration. Manifests never author TCB node identities or a
/// Boolean assertion that the round trip passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTranscriptionConfig {
    pub schema: TrustedTranscriptionSchema,
    pub source: String,
    pub committed_transcription: String,
    pub driver: String,
    pub source_format: String,
    pub transcribed_format: String,
    pub driver_abi: TranscriptionDriverAbi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustedTranscriptionSchema {
    #[serde(rename = "proofbound-trusted-transcription/1")]
    Version1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TranscriptionDriverAbi {
    #[serde(rename = "proofbound-transcription-driver/1")]
    Version1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterKind {
    Lean,
    CharonAeneas,
    Kani,
    RustTest,
    PythonTest,
    CanonicalArtifact,
    SourceClosure,
    IndependentCheck,
    HumanReview,
    TrustedTranscription,
}

impl AdapterKind {
    pub const fn executable(self) -> &'static str {
        match self {
            Self::Lean => "proofbound-adapter-lean",
            Self::CharonAeneas => "proofbound-adapter-aeneas",
            Self::Kani => "proofbound-adapter-kani",
            Self::RustTest | Self::PythonTest => "proofbound-adapter-test",
            Self::CanonicalArtifact
            | Self::IndependentCheck
            | Self::SourceClosure
            | Self::HumanReview
            | Self::TrustedTranscription => "proofbound-adapter-test",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    Review,
    Assumption,
    Open,
}

impl EvidenceKind {
    pub const fn reference_prefix(self) -> &'static str {
        match self {
            Self::Theorem => "theorem",
            Self::ArtifactSoundness => "artifact",
            Self::TrustedTranscription => "transcription",
            Self::SourceRefinement => "refinement",
            Self::BoundedCheck => "kani",
            Self::IndependentCheck => "independent",
            Self::ExhaustiveCheck => "exhaustive",
            Self::PropertyTest => "property-test",
            Self::ExampleTest => "test",
            Self::MutationWitness => "mutation",
            Self::Review => "review",
            Self::Assumption => "assumption",
            Self::Open => "open",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationMode {
    Kernel,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    BytesInTheorem,
    DigestTheorem,
    ExternalRoundTrip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterOperation {
    #[serde(rename = "type")]
    pub kind: OperationKind,
    pub package: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub manifest: Option<String>,
    pub inventory: Option<String>,
    pub checker: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    CargoTest,
    Pytest,
    Generator,
    LeanAudit,
    Kani,
    Translation,
    ArtifactCheck,
    IndependentCheck,
    Review,
    Closure,
    Transcription,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub time_seconds: u64,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
}

pub const MAX_TRANSLATION_PATH_BYTES: usize = 4096;
pub const MAX_TRANSLATION_INVOCATIONS: usize = 4096;
pub const MAX_TRANSLATION_SYMBOLS: usize = 4096;
pub const MAX_TRANSLATION_CLAIMS: usize = 4096;
pub const MAX_TRANSLATION_SOURCE_ROOTS: usize = 1024;
pub const MAX_TRANSLATION_EXTERNAL_BRIDGES: usize = 1024;
pub const MAX_TRANSLATION_TEMPLATE_AXIOMS: usize = 1024;
pub const MAX_TRANSLATION_WARNINGS: usize = 4096;
pub const MAX_TRANSLATION_MAPPED_OUTPUTS: usize = 100_000;
pub const TRANSLATION_RESERVED_PATH_COMPONENTS: &[&str] = &[
    ".git",
    "target",
    ".lake",
    ".proofbound",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationUnitManifest {
    pub schema: String,
    pub id: String,
    pub pipeline: TranslationPipeline,
    pub invocations: Vec<TranslationInvocation>,
    pub generated_dir: String,
    pub handwritten_refinement: String,
    pub determinism_runs: u8,
    pub determinism_normalization: String,
    pub forbid_generated_axioms: bool,
    #[serde(default)]
    pub external_bridges: Vec<ExternalBridge>,
    #[serde(default)]
    pub template_axioms: Vec<TemplateAxiom>,
    #[serde(default)]
    pub warning_inventory: Vec<WarningInventory>,
    pub import_mapping: ImportMapping,
    pub resource_budget: ResourceBudget,
    pub claims: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranslationPipeline {
    CharonAeneas,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationInvocation {
    pub id: String,
    pub cargo_package: String,
    pub cargo_manifest: String,
    pub crate_name: String,
    pub llbc_file: String,
    pub start_from: Vec<String>,
    pub opaque: Vec<String>,
    pub include: Vec<String>,
    pub aeneas_subdir: Option<String>,
    pub outputs: Vec<TranslationOutputMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationOutputMapping {
    pub kind: TranslationOutputKind,
    pub produced: String,
    pub destination: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranslationOutputKind {
    LeanSource,
    TranslationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalBridge {
    pub file: String,
    pub module: Option<String>,
    pub reviewed_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateAxiom {
    pub file: String,
    pub count: usize,
    pub compiled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarningInventory {
    pub artifact: String,
    pub line: usize,
    pub kind: TranslationWarningKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranslationWarningKind {
    UpstreamSorry,
    UpstreamSorryAx,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportMapping {
    pub mode: ImportMappingMode,
    #[serde(default)]
    pub source_roots: Vec<String>,
    pub rewrite_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportMappingMode {
    ExternalSourceRoot,
    AuditedRewrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCheckUnitManifest {
    pub schema: String,
    pub id: String,
    pub adapter: String,
    pub package: String,
    pub harnesses: Vec<String>,
    pub claims: Vec<String>,
    pub domain: BoundedDomain,
    pub solver: String,
    pub unwind: u32,
    #[serde(default)]
    pub assumptions: Vec<String>,
    pub resource_budget: ResourceBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifest {
    pub schema: String,
    pub id: String,
    pub extends: String,
    pub allow_project_axioms: bool,
    #[serde(default)]
    pub allowed_project_axioms: Vec<String>,
    pub allowed_foundational_axioms: Vec<String>,
    pub allow_native: bool,
    pub native_premise_count: Option<u8>,
    pub allow_exhaustive_as_proved: bool,
    pub required_binding: String,
    pub require_registered_premises: bool,
    #[serde(default)]
    pub publication_allows_open: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewManifest {
    pub schema: String,
    pub id: String,
    pub reviewer: String,
    pub statement: String,
    pub scope: String,
    pub reviewed_at: String,
    pub base_revision: String,
    pub head_revision: String,
    pub regressions: Vec<ApprovedRegression>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRegression {
    pub id: String,
    pub claim_id: String,
    pub kind: RegressionKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegressionKind {
    NewAssumption,
    UndischargedPremise,
    EnlargedTcb,
    LinkageDowngrade,
    EvaluationDowngrade,
    FormalDowngrade,
    BoundedDomainNarrowed,
    BoundedDomainIncomparable,
    MutationCoverageRemoved,
    SourceClosureWeakened,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoRegistry {
    pub schema: String,
    pub demos: Vec<DemoEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoEntry {
    pub name: String,
    pub description: String,
    pub runner: DemoRunner,
    pub claims: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DemoRunner {
    AllowancePython,
    ArtifactRust,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRequest {
    pub schema: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub adapter: String,
    pub operation: String,
    pub project_root: String,
    pub unit: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterResponse {
    pub schema: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub adapter: String,
    pub success: bool,
    pub evidence: Option<serde_json::Value>,
    #[serde(default)]
    pub inventory: Vec<String>,
    pub diagnostics: Vec<AdapterDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

pub type StringMap = BTreeMap<String, String>;
