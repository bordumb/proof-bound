//! Strict claim, evidence, assumption, premise, and provenance records.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::{
    AdapterStrength, AssumptionCategory, AssumptionId, AssumptionStatus, BindingMode, CacheOrigin,
    ClaimId, ClosureKind, EnvironmentId, ErrorCode, EvaluationMode, EvidenceId, EvidenceKind,
    EvidenceStatus, IndependenceMode, LinkageFacet, NodeId, ObligationId, PolicyId, PremiseId,
    Sha256Digest, StableIdError, StructuredError, Tier, TreeState, UnitId, ValidationErrors,
    lean_statement_wire_digest,
};

pub const CLAIM_SCHEMA_V1: &str = "proofbound-claim/1";
/// Superseded evidence schema retained so migrations can identify old records.
pub const EVIDENCE_SCHEMA_V1: &str = "proofbound-evidence/1";
/// Superseded version-2 evidence schema retained for explicit migration errors.
pub const EVIDENCE_SCHEMA_V2: &str = "proofbound-evidence/2";
pub const EVIDENCE_SCHEMA_V3: &str = "proofbound-evidence/3";
pub const ASSUMPTION_SCHEMA_V1: &str = "proofbound-assumption/1";
pub const TRUSTED_TRANSCRIPTION_SCHEMA_V1: &str = "proofbound-trusted-transcription/1";
pub const TRANSCRIPTION_DRIVER_ABI_V1: &str = "proofbound-transcription-driver/1";
pub const TRANSCRIPTION_TCB_ROLE_DOMAIN_V1: &str = "proofbound-transcription-tcb-role/1";
pub const MUTATION_WITNESS_SCHEMA_V2: &str = "proofbound-mutation-witness/2";
pub const MUTATION_IDENTITY_DOMAIN_V2: &str = "proofbound-mutation/2";

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Why a machine-matched name inside an evidence record was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EvidenceNameError {
    #[error("an artifact logical name must not be empty")]
    EmptyArtifactLogicalName,
    #[error("an artifact logical name must be at most 4096 characters")]
    ArtifactLogicalNameTooLong,
    #[error("an environment variable name must not be empty")]
    EmptyEnvironmentVariableName,
    #[error("an environment variable name must be at most 256 bytes")]
    EnvironmentVariableNameTooLong,
    #[error("an environment variable name must start with an ASCII letter or underscore")]
    InvalidEnvironmentVariableNameStart,
    #[error("environment variable name contains an invalid character at byte {0}")]
    InvalidEnvironmentVariableNameCharacter(usize),
}

/// A stable, machine-matched name for an artifact in a provenance record.
///
/// This is intentionally distinct from paths, theorem declarations, and
/// free-text labels even though all of them serialize as JSON strings.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactLogicalName(String);

impl ArtifactLogicalName {
    /// Constructs a logical name accepted by the public evidence schema.
    pub fn new(value: impl Into<String>) -> Result<Self, EvidenceNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EvidenceNameError::EmptyArtifactLogicalName);
        }
        if value.chars().count() > 4096 {
            return Err(EvidenceNameError::ArtifactLogicalNameTooLong);
        }
        Ok(Self(value))
    }

    /// Borrows the exact name used for artifact matching.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactLogicalName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ArtifactLogicalName {
    type Err = EvidenceNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ArtifactLogicalName {
    type Error = EvidenceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for ArtifactLogicalName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ArtifactLogicalName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A validated environment-variable name used by a typed command.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentVariableName(String);

impl EnvironmentVariableName {
    /// Constructs a name matching the public evidence schema's portable form.
    pub fn new(value: impl Into<String>) -> Result<Self, EvidenceNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EvidenceNameError::EmptyEnvironmentVariableName);
        }
        if value.len() > 256 {
            return Err(EvidenceNameError::EnvironmentVariableNameTooLong);
        }
        let mut bytes = value.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        {
            return Err(EvidenceNameError::InvalidEnvironmentVariableNameStart);
        }
        if let Some((offset, _)) = value
            .bytes()
            .enumerate()
            .find(|(_, byte)| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        {
            return Err(EvidenceNameError::InvalidEnvironmentVariableNameCharacter(
                offset,
            ));
        }
        Ok(Self(value))
    }

    /// Borrows the exact name used for environment lookup.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentVariableName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EnvironmentVariableName {
    type Err = EvidenceNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for EnvironmentVariableName {
    type Error = EvidenceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for EnvironmentVariableName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EnvironmentVariableName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod evidence_name_tests {
    use super::*;

    #[test]
    fn artifact_logical_names_are_validated_and_serialize_as_strings() {
        let name = ArtifactLogicalName::new("generated/report.json").unwrap();
        assert_eq!(name.as_str(), "generated/report.json");
        assert_eq!(
            serde_json::to_string(&name).unwrap(),
            "\"generated/report.json\""
        );
        assert_eq!(
            serde_json::from_str::<ArtifactLogicalName>("\"generated/report.json\"").unwrap(),
            name
        );
        assert!(ArtifactLogicalName::new("").is_err());
        assert!(ArtifactLogicalName::new("x".repeat(4097)).is_err());
        assert!(serde_json::from_str::<ArtifactLogicalName>("\"\"").is_err());
    }

    #[test]
    fn environment_variable_names_are_validated_and_serialize_as_strings() {
        let name = EnvironmentVariableName::new("PROOFBOUND_TOKEN_2").unwrap();
        assert_eq!(name.as_str(), "PROOFBOUND_TOKEN_2");
        assert_eq!(
            serde_json::to_string(&name).unwrap(),
            "\"PROOFBOUND_TOKEN_2\""
        );
        assert_eq!(
            serde_json::from_str::<EnvironmentVariableName>("\"PROOFBOUND_TOKEN_2\"").unwrap(),
            name
        );
        for invalid in ["", "2TOKEN", "TOKEN-VALUE", "TOKEN=VALUE", "TOKEN VALUE"] {
            assert!(
                EnvironmentVariableName::new(invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(serde_json::from_str::<EnvironmentVariableName>("\"BAD=VALUE\"").is_err());
    }
}

/// A named content identity used in provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub logical_name: ArtifactLogicalName,
    pub sha256: Sha256Digest,
    pub size_bytes: u64,
}

/// A source or toolchain closure referenced by digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureIdentity {
    pub kind: ClosureKind,
    pub sha256: Sha256Digest,
}

/// Complete identity of an external tool or adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub name: String,
    pub version: String,
    pub identity_sha256: Sha256Digest,
}

/// Environment metadata records names and identities, never raw values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVariable {
    pub name: EnvironmentVariableName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sha256: Option<Sha256Digest>,
    pub secret: bool,
}

/// A typed process invocation. It is data for an adapter, not a shell string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub environment_allowlist: Vec<EnvironmentVariable>,
}

/// One observed execution of a typed command in a deterministic evidence run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRun {
    pub command_index: usize,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub exit_code: Option<i32>,
    pub stdout_sha256: Sha256Digest,
    pub stderr_sha256: Sha256Digest,
    pub normalized_output_sha256: Sha256Digest,
    pub output_truncated: bool,
    pub duration_ms: u64,
}

/// Declared upper resource limits.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub time_ms: u64,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
}

/// Actual adapter cost recorded after execution.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    pub time_ms: u64,
    pub peak_disk_bytes: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub peak_memory_bytes: Option<u64>,
}

/// Whether provenance records external processes or an in-process compiler derivation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionKind {
    ObservedProcesses,
    CompilerInternal,
}

#[cfg(test)]
mod required_nullable_tests {
    use super::*;

    #[test]
    fn execution_exit_code_is_required_but_nullable() {
        let run = ExecutionRun {
            command_index: 0,
            exit_code: None,
            stdout_sha256: Sha256Digest::of_bytes(b"stdout"),
            stderr_sha256: Sha256Digest::of_bytes(b"stderr"),
            normalized_output_sha256: Sha256Digest::of_bytes(b"normalized"),
            output_truncated: false,
            duration_ms: 1,
        };
        let mut encoded = serde_json::to_value(&run).unwrap();
        assert!(encoded["exit_code"].is_null());
        assert!(serde_json::from_value::<ExecutionRun>(encoded.clone()).is_ok());
        encoded.as_object_mut().unwrap().remove("exit_code");
        assert!(serde_json::from_value::<ExecutionRun>(encoded).is_err());
    }

    #[test]
    fn peak_memory_is_required_but_nullable() {
        let usage = ResourceUsage {
            time_ms: 1,
            peak_disk_bytes: 2,
            peak_memory_bytes: None,
        };
        let mut encoded = serde_json::to_value(&usage).unwrap();
        assert!(encoded["peak_memory_bytes"].is_null());
        assert!(serde_json::from_value::<ResourceUsage>(encoded.clone()).is_ok());
        encoded.as_object_mut().unwrap().remove("peak_memory_bytes");
        assert!(serde_json::from_value::<ResourceUsage>(encoded).is_err());
    }
}

/// Provenance every evidence record must bind.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub project_revision: String,
    pub tree_state: TreeState,
    pub semantic_source_closure: Sha256Digest,
    #[serde(default)]
    pub additional_closures: Vec<ClosureIdentity>,
    #[serde(default)]
    pub input_artifacts: Vec<ArtifactIdentity>,
    #[serde(default)]
    pub generated_artifacts: Vec<ArtifactIdentity>,
    pub tool: ToolIdentity,
    pub adapter: ToolIdentity,
    pub execution_kind: ExecutionKind,
    pub commands: Vec<CommandSpec>,
    pub runs: Vec<ExecutionRun>,
    pub normalization: String,
    pub reproduction_command: CommandSpec,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub deterministic_result_identity: Sha256Digest,
    pub unit_configuration_sha256: Sha256Digest,
    pub resource_budget: ResourceBudget,
    pub resource_usage: ResourceUsage,
    pub cache_origin: CacheOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_receipt_sha256: Option<Sha256Digest>,
}

impl EvidenceProvenance {
    fn validate(
        &self,
        claim_id: &ClaimId,
        unit_id: &UnitId,
        status: EvidenceStatus,
        expected_failure: Option<&ExpectedFailure>,
    ) -> Vec<StructuredError> {
        let mut errors = Vec::new();
        let contextual =
            |error: StructuredError| error.for_claim(claim_id.clone()).for_unit(unit_id.clone());
        if self.project_revision.trim().is_empty() {
            errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "evidence has an empty project revision",
                "record the exact source-control revision or another stable project revision identity",
            )));
        }
        if self.tool.name.trim().is_empty()
            || self.tool.version.trim().is_empty()
            || self.adapter.name.trim().is_empty()
            || self.adapter.version.trim().is_empty()
        {
            errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "tool and adapter identities require non-empty names and versions",
                "record the complete tool and adapter identities",
            )));
        }
        match self.execution_kind {
            ExecutionKind::ObservedProcesses
                if self.commands.is_empty()
                    || self.commands.len() > 4096
                    || self.runs.is_empty()
                    || self.runs.len() > 4096
                    || self.commands.len() != self.runs.len() =>
            {
                errors.push(contextual(StructuredError::new(
                    ErrorCode::PbCoreInvalidEvidence,
                    "observed-process provenance requires one to 4096 commands and one matching run per command",
                    "record every typed process command and its corresponding execution observation in order",
                )));
            }
            ExecutionKind::CompilerInternal
                if !self.commands.is_empty() || !self.runs.is_empty() =>
            {
                errors.push(contextual(StructuredError::new(
                    ErrorCode::PbCoreInvalidEvidence,
                    "compiler-internal provenance must not fabricate process commands or runs",
                    "leave commands and runs empty for an in-process compiler derivation",
                )));
            }
            _ => {}
        }
        if self.normalization.trim().is_empty() || self.normalization.chars().count() > 1024 {
            errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "evidence provenance normalization must contain 1 through 1024 characters",
                "name the bounded exact normalization applied before deterministic output hashing",
            )));
        }
        for (index, command) in self.commands.iter().enumerate() {
            validate_command(
                command,
                &format!("command {index}"),
                &contextual,
                &mut errors,
            );
        }
        validate_command(
            &self.reproduction_command,
            "reproduction command",
            &contextual,
            &mut errors,
        );
        for (index, run) in self.runs.iter().enumerate() {
            if run.command_index != index {
                errors.push(contextual(StructuredError::new(
                    ErrorCode::PbCoreInvalidEvidence,
                    format!(
                        "execution run {index} names command index {} instead of {index}",
                        run.command_index
                    ),
                    "record execution runs in command order with exact positional indices",
                )));
            }
            if run.output_truncated {
                errors.push(contextual(StructuredError::new(
                    ErrorCode::PbCoreInvalidEvidence,
                    format!("execution run {index} used truncated output"),
                    "capture and hash the complete stdout, stderr, and normalized output",
                )));
            }
            if status == EvidenceStatus::Passed {
                let accepted = expected_failure.is_some_and(|expected| {
                    expected.run_index == index
                        && run
                            .exit_code
                            .is_some_and(|code| expected.allowed_exit_codes.contains(&code))
                }) || (expected_failure
                    .is_none_or(|expected| expected.run_index != index)
                    && run.exit_code == Some(0));
                if !accepted {
                    errors.push(contextual(StructuredError::new(
                        ErrorCode::PbCoreInvalidEvidence,
                        format!(
                            "passing evidence run {index} did not match its registered exit expectation"
                        ),
                        "require ordinary runs to exit zero and preserve the one typed mutation-witness failure exactly",
                    )));
                }
            }
        }
        if self.completed_unix_ms < self.started_unix_ms {
            errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "evidence completion precedes its start timestamp",
                "regenerate the evidence with monotonic diagnostic timestamps",
            )));
        }
        match (self.cache_origin, self.prior_receipt_sha256) {
            (CacheOrigin::Reused, None) => errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "cached evidence does not identify its prior receipt",
                "bind the reused receipt digest into the receipt chain",
            ))),
            (CacheOrigin::Executed, Some(_)) => errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "newly executed evidence unexpectedly names a prior cached receipt",
                "mark the receipt as reused or remove the prior-receipt identity",
            ))),
            _ => {}
        }
        errors
    }

    /// Whether actual use exceeded any declared resource budget.
    #[must_use]
    pub const fn exceeded_budget(&self) -> bool {
        self.resource_usage.time_ms > self.resource_budget.time_ms
            || self.resource_usage.peak_disk_bytes > self.resource_budget.disk_bytes
            || match self.resource_usage.peak_memory_bytes {
                Some(actual) => actual > self.resource_budget.memory_bytes,
                None => false,
            }
    }
}

fn validate_command<F>(
    command: &CommandSpec,
    label: &str,
    contextual: &F,
    errors: &mut Vec<StructuredError>,
) where
    F: Fn(StructuredError) -> StructuredError,
{
    let program = command.program.trim();
    let executable = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    let is_shell = matches!(
        executable.as_str(),
        "sh" | "bash" | "dash" | "zsh" | "fish" | "cmd" | "cmd.exe" | "powershell" | "pwsh"
    );
    if program.is_empty()
        || command.program.chars().count() > 4096
        || command.program.contains('\0')
        || is_shell
        || command.args.len() > 4096
        || command
            .args
            .iter()
            .any(|argument| argument.chars().count() > 4096 || argument.contains('\0'))
    {
        errors.push(contextual(StructuredError::new(
            ErrorCode::PbCoreInvalidEvidence,
            format!("{label} is not a bounded typed non-shell command"),
            "record a direct program and bounded argument vector without a shell interpreter",
        )));
    }
    if command.environment_allowlist.len() > 256 {
        errors.push(contextual(StructuredError::new(
            ErrorCode::PbCoreInvalidEvidence,
            format!("{label} has more than 256 environment entries"),
            "record only the bounded environment allowlist required by the command",
        )));
    }
    let mut names = BTreeSet::new();
    for variable in &command.environment_allowlist {
        if !names.insert(variable.name.as_str()) {
            errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                format!("{label} repeats environment variable '{}'", variable.name),
                "record each environment variable at most once per command",
            )));
        }
    }
}

/// Compiled theorem and axiom-audit facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TheoremEvidence {
    pub declaration: String,
    pub statement_encoding: String,
    pub statement_wire: serde_json::Value,
    pub statement_sha256: Sha256Digest,
    pub attributed_claim: ClaimId,
    pub environment: EnvironmentId,
    pub axiom_audit_passed: bool,
    pub contains_sorry_ax: bool,
    #[serde(default)]
    pub foundational_axioms: BTreeSet<String>,
    #[serde(default)]
    pub project_axioms: BTreeSet<AssumptionId>,
}

/// Facts required for the strong artifact boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBindingEvidence {
    pub theorem: EvidenceId,
    pub artifact: ArtifactIdentity,
}

/// One of the two domain-separated trusted roles in a transcription boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TranscriptionRole {
    Transcriber,
    Reencoder,
}

/// A graph reference paired with the independently derived identity of its
/// trusted role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptionTcbRole {
    pub tcb_node: NodeId,
    pub role_identity: Sha256Digest,
}

#[derive(Serialize)]
struct TranscriptionRoleIdentityMaterial<'a> {
    abi: &'static str,
    driver: &'a ArtifactIdentity,
    role: TranscriptionRole,
}

/// Derives a trusted-role identity from the complete driver identity and its
/// fixed ABI. The domain and role keep a single two-mode driver from collapsing
/// the transcriber and re-encoder into one TCB identity.
#[must_use]
pub fn transcription_role_identity(
    role: TranscriptionRole,
    driver: &ArtifactIdentity,
) -> Sha256Digest {
    let material = serde_json::to_vec(&TranscriptionRoleIdentityMaterial {
        abi: TRANSCRIPTION_DRIVER_ABI_V1,
        driver,
        role,
    })
    .expect("trusted-transcription role material is infallibly serializable");
    let mut framed =
        Vec::with_capacity(TRANSCRIPTION_TCB_ROLE_DOMAIN_V1.len() + 1 + material.len());
    framed.extend_from_slice(TRANSCRIPTION_TCB_ROLE_DOMAIN_V1.as_bytes());
    framed.push(0);
    framed.extend_from_slice(&material);
    Sha256Digest::of_bytes(framed)
}

/// Derives the only graph node identity accepted for one transcription TCB
/// role. Unit scoping allows different registered drivers to coexist without
/// giving a producer freedom to redirect a receipt to an arbitrary TCB node.
pub fn transcription_tcb_node_id(
    unit_id: &UnitId,
    role: TranscriptionRole,
) -> Result<NodeId, StableIdError> {
    let unit_name = unit_id
        .as_str()
        .strip_prefix("unit:")
        .unwrap_or(unit_id.as_str());
    let role_name = match role {
        TranscriptionRole::Transcriber => "transcriber",
        TranscriptionRole::Reencoder => "reencoder",
    };
    NodeId::new(format!("tcb:trusted-transcription:{unit_name}:{role_name}"))
}

/// Exact inputs, independently observed outputs, and trusted role identities
/// for the degraded transcription form. Equality of the two byte-identity
/// pairs derives the round trip; no checker-authored success bit is accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTranscriptionEvidence {
    pub schema: String,
    pub source: ArtifactIdentity,
    pub committed_transcription: ArtifactIdentity,
    pub transcribed_candidate: ArtifactIdentity,
    pub reencoded_source: ArtifactIdentity,
    pub driver: ArtifactIdentity,
    pub transcriber: TranscriptionTcbRole,
    pub reencoder: TranscriptionTcbRole,
}

fn same_artifact_bytes(left: &ArtifactIdentity, right: &ArtifactIdentity) -> bool {
    left.sha256 == right.sha256 && left.size_bytes == right.size_bytes
}

/// Facts required to connect translated production code to a semantic model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRefinementEvidence {
    pub refinement_theorem: EvidenceId,
    pub representation_premises: BTreeSet<PremiseId>,
    pub deterministic_translation: bool,
    pub pinned_toolchain: bool,
    pub generated_axioms_clean: bool,
    pub adapter_strength: AdapterStrength,
}

/// An explicitly finite domain. Its registration digest is part of closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedDomain {
    pub id: UnitId,
    pub description: String,
    pub registration_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<u64>,
    #[serde(default)]
    pub constraints: Vec<String>,
}

/// Bounded model-checker facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedCheckEvidence {
    pub domain: BoundedDomain,
    pub solver: String,
    pub harnesses: BTreeSet<String>,
    #[serde(default)]
    pub unwind_bounds: BTreeMap<String, u64>,
    pub assumptions: Vec<String>,
}

/// Exhaustive enumeration facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExhaustiveCheckEvidence {
    pub domain: BoundedDomain,
    pub evaluated_members: u64,
}

/// Deliberately broken subject and the check that detected it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationWitnessEvidence {
    pub schema: String,
    pub mutation_id: String,
    pub subject: String,
    pub guard: String,
    pub mutation_sha256: Sha256Digest,
    pub registry: ArtifactIdentity,
    pub target_preimage: ArtifactIdentity,
    pub mutant_artifact: ArtifactIdentity,
    pub target_postimage: ArtifactIdentity,
    pub witness_source: ArtifactIdentity,
    pub check_id: String,
    pub baseline_run_index: usize,
    pub expected_failure: ExpectedFailure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_term_theorem: Option<EvidenceId>,
}

/// The one deliberately failing subprocess that constitutes mutation detection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFailure {
    pub run_index: usize,
    pub allowed_exit_codes: BTreeSet<i32>,
}

impl MutationWitnessEvidence {
    /// Recomputes the canonical identity of the registered mutation semantics.
    ///
    /// Execution indices are deliberately excluded: they bind provenance, not
    /// the mutation registration. The outer claim set is included so the same
    /// mutant cannot be replayed under a broader claim attribution.
    pub fn derived_mutation_sha256(
        &self,
        claims: &BTreeSet<ClaimId>,
    ) -> Result<Sha256Digest, serde_json::Error> {
        let value = serde_json::json!({
            "check_id": self.check_id,
            "claims": claims,
            "guard": self.guard,
            "mutant_artifact": self.mutant_artifact,
            "mutation_id": self.mutation_id,
            "registry": self.registry,
            "subject": self.subject,
            "target_postimage": self.target_postimage,
            "target_preimage": self.target_preimage,
            "witness_source": self.witness_source,
        });
        let canonical = canonical_json_value(value)?;
        let mut material =
            Vec::with_capacity(MUTATION_IDENTITY_DOMAIN_V2.len() + 1 + canonical.len());
        material.extend_from_slice(MUTATION_IDENTITY_DOMAIN_V2.as_bytes());
        material.push(0);
        material.extend_from_slice(&canonical);
        Ok(Sha256Digest::of_bytes(material))
    }
}

fn canonical_json_value(value: serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    fn sort(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sort).collect())
            }
            serde_json::Value::Object(values) => {
                let sorted = values
                    .into_iter()
                    .map(|(key, value)| (key, sort(value)))
                    .collect::<BTreeMap<_, _>>();
                serde_json::to_value(sorted).expect("JSON values serialize")
            }
            scalar => scalar,
        }
    }

    serde_json::to_vec(&sort(value))
}

/// Registered open work, distinct from an adopted assumption.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenObligation {
    pub id: ObligationId,
    pub statement: String,
    pub remediation: String,
}

/// A boundary intentionally excluded from the public claim.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutOfScope {
    pub id: ObligationId,
    pub statement: String,
    pub rationale: String,
}

/// Scope of a theorem premise or its discharge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FlowScope {
    AllRegisteredInputs,
    Flows { flows: BTreeSet<String> },
}

impl FlowScope {
    fn covers(&self, required: &Self, registered_inputs: &BTreeSet<String>) -> bool {
        let required_flows = match required {
            Self::AllRegisteredInputs => registered_inputs,
            Self::Flows { flows } => flows,
        };
        match self {
            Self::AllRegisteredInputs => true,
            Self::Flows { flows } => {
                !required_flows.is_empty() && flows.is_superset(required_flows)
            }
        }
    }
}

/// A proposed, explicit premise discharge. It counts only with the corresponding
/// graph edge and a policy-admitted theorem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PremiseDischarge {
    pub theorem_evidence: EvidenceId,
    pub scope: FlowScope,
}

/// One first-class theorem hypothesis.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PremiseRecord {
    pub id: PremiseId,
    pub node_id: NodeId,
    pub statement: String,
    pub category: AssumptionCategory,
    /// The theorem whose hypothesis this premise records. A direct
    /// claim-level premise has no owning theorem and must instead be attached
    /// to the claim by an exact `assumes` graph edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem_evidence: Option<EvidenceId>,
    pub scope: FlowScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discharge: Option<PremiseDischarge>,
}

impl PremiseRecord {
    pub(crate) fn discharge_covers(
        &self,
        discharge: &PremiseDischarge,
        registered_inputs: &BTreeSet<String>,
    ) -> bool {
        discharge.scope.covers(&self.scope, registered_inputs)
    }
}

/// A first-class explicit assumption ledger record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssumptionRecord {
    pub schema: String,
    pub id: AssumptionId,
    pub node_id: NodeId,
    pub statement: String,
    pub category: AssumptionCategory,
    pub owner: String,
    pub rationale: String,
    pub scope: String,
    pub affected_claims: BTreeSet<ClaimId>,
    pub review_evidence: BTreeSet<EvidenceId>,
    pub falsification_or_discharge_plan: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_citation: Option<String>,
    pub status: AssumptionStatus,
    #[serde(default)]
    pub depends_on: BTreeSet<AssumptionId>,
}

/// A canonical evidence record. Optional detail blocks are conditionally
/// required and checked by [`EvidenceRecord::validate`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub schema: String,
    pub id: EvidenceId,
    pub node_id: NodeId,
    pub unit_id: UnitId,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub claims: BTreeSet<ClaimId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_mode: Option<EvaluationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_mode: Option<BindingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem: Option<TheoremEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_binding: Option<ArtifactBindingEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_transcription: Option<TrustedTranscriptionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_refinement: Option<SourceRefinementEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_check: Option<BoundedCheckEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exhaustive_check: Option<ExhaustiveCheckEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_witness: Option<MutationWitnessEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence: Option<IndependenceMode>,
    #[serde(default)]
    pub inventoried_targets: BTreeSet<String>,
    #[serde(default)]
    pub assumptions: BTreeSet<AssumptionId>,
    #[serde(default)]
    pub premises: BTreeSet<PremiseId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_obligation: Option<OpenObligation>,
    pub provenance: EvidenceProvenance,
}

impl EvidenceRecord {
    /// Validates conditional evidence-kind invariants and complete provenance.
    pub fn validate(&self, claim_id: &ClaimId) -> Result<(), ValidationErrors> {
        let expected_failure = (self.kind == EvidenceKind::MutationWitness)
            .then(|| {
                self.mutation_witness
                    .as_ref()
                    .map(|witness| &witness.expected_failure)
            })
            .flatten();
        let mut errors =
            self.provenance
                .validate(claim_id, &self.unit_id, self.status, expected_failure);
        let error = |message: String, remediation: &'static str| {
            StructuredError::new(ErrorCode::PbCoreInvalidEvidence, message, remediation)
                .for_claim(claim_id.clone())
                .for_unit(self.unit_id.clone())
        };

        if self.schema != EVIDENCE_SCHEMA_V3 {
            errors.push(
                StructuredError::new(
                    ErrorCode::PbCoreUnsupportedSchema,
                    format!("unsupported evidence schema '{}'", self.schema),
                    "migrate the evidence record to proofbound-evidence/3",
                )
                .for_claim(claim_id.clone())
                .for_unit(self.unit_id.clone())
                .identities(EVIDENCE_SCHEMA_V3, &self.schema),
            );
        }
        if !self.claims.contains(claim_id) {
            errors.push(error(
                format!("evidence '{}' is not bound to claim '{claim_id}'", self.id),
                "add the claim to the evidence record or remove the claim's citation",
            ));
        }

        let inventory_valid = self.inventoried_targets.len() <= 100_000
            && self.inventoried_targets.iter().all(|target| {
                !target.trim().is_empty()
                    && target.chars().count() <= 4096
                    && !target.chars().any(char::is_control)
            });
        if !inventory_valid
            || (self.status == EvidenceStatus::Passed
                && self.provenance.execution_kind == ExecutionKind::ObservedProcesses
                && self.inventoried_targets.is_empty())
        {
            errors.push(error(
                "observed evidence lacks a nonempty bounded exact target inventory".into(),
                "record 1 through 100000 unique nonblank control-free target identities of at most 4096 characters for every passed observed-process evidence record",
            ));
        }

        match self.kind {
            EvidenceKind::Theorem => {
                if self.evaluation_mode.is_none() || self.theorem.is_none() {
                    errors.push(error(
                        "theorem evidence requires an evaluation mode and compiled theorem audit".into(),
                        "record kernel/native evaluation and the compiled axiom audit",
                    ));
                }
                if self.binding_mode.is_some() {
                    errors.push(error(
                        "plain theorem evidence cannot assert an artifact binding mode".into(),
                        "move the binding to a separate artifact-soundness evidence record",
                    ));
                }
                if let Some(theorem) = &self.theorem {
                    let wire_identity_valid = theorem.statement_encoding == "lean-expr-cbor/1"
                        && lean_statement_wire_digest(&theorem.statement_wire)
                            .is_ok_and(|digest| digest == theorem.statement_sha256);
                    if theorem.attributed_claim != *claim_id
                        || theorem.declaration.trim().is_empty()
                        || !self.inventoried_targets.contains(&theorem.declaration)
                        || !wire_identity_valid
                        || !theorem.axiom_audit_passed
                        || theorem.contains_sorry_ax
                    {
                        errors.push(error(
                            "the compiled theorem identity, statement wire, or axiom audit is invalid"
                                .into(),
                            "regenerate the compiled attribute inventory, canonical statement wire, and axiom audit",
                        ));
                    }
                }
            }
            EvidenceKind::ArtifactSoundness => {
                if self.evaluation_mode.is_none()
                    || !matches!(
                        self.binding_mode,
                        Some(BindingMode::BytesInTheorem | BindingMode::DigestTheorem)
                    )
                {
                    errors.push(error(
                        "artifact-soundness requires kernel/native evaluation and a strong byte or digest binding".into(),
                        "record bytes-in-theorem or digest-theorem binding explicitly",
                    ));
                }
                match &self.artifact_binding {
                    Some(binding)
                        if self
                            .provenance
                            .input_artifacts
                            .iter()
                            .filter(|artifact| *artifact == &binding.artifact)
                            .count()
                            == 1 => {}
                    Some(_) => errors.push(error(
                        "artifact-soundness identity does not match exactly one provenance input artifact".into(),
                        "record the checked artifact exactly once in provenance and bind that exact identity",
                    )),
                    None => errors.push(error(
                        "artifact-soundness is missing its checked artifact identity".into(),
                        "record the referenced theorem and exact checked artifact identity",
                    )),
                }
            }
            EvidenceKind::TrustedTranscription => {
                if self.binding_mode != Some(BindingMode::ExternalRoundTrip) {
                    errors.push(error(
                        "trusted transcription requires external-round-trip binding".into(),
                        "record external-round-trip and the complete derived transcription record",
                    ));
                }
                if let Some(record) = &self.trusted_transcription {
                    if record.schema != TRUSTED_TRANSCRIPTION_SCHEMA_V1 {
                        errors.push(error(
                            format!(
                                "trusted transcription uses unsupported nested schema '{}'",
                                record.schema
                            ),
                            "regenerate proofbound-trusted-transcription/1 evidence",
                        ));
                    }
                    let artifact_names = [
                        record.source.logical_name.as_str(),
                        record.committed_transcription.logical_name.as_str(),
                        record.transcribed_candidate.logical_name.as_str(),
                        record.reencoded_source.logical_name.as_str(),
                        record.driver.logical_name.as_str(),
                    ];
                    if artifact_names.into_iter().collect::<BTreeSet<_>>().len()
                        != artifact_names.len()
                    {
                        errors.push(error(
                            "trusted transcription aliases two artifact roles to one logical name"
                                .into(),
                            "give source, committed transcription, candidate, re-encoded source, and driver distinct logical names",
                        ));
                    }
                    let expected_inventory = BTreeSet::from([
                        record.source.logical_name.as_str().to_owned(),
                        record
                            .committed_transcription
                            .logical_name
                            .as_str()
                            .to_owned(),
                    ]);
                    if self.inventoried_targets != expected_inventory {
                        errors.push(error(
                            "trusted transcription target inventory does not exactly name its source and committed transcription"
                                .into(),
                            "derive the exact two-entry inventory from the typed trusted-transcription record",
                        ));
                    }
                    if self.provenance.input_artifacts.len() != 3 {
                        errors.push(error(
                            "trusted transcription provenance input inventory is not the exact three registered artifacts"
                                .into(),
                            "record only the source, committed transcription, and driver as inputs",
                        ));
                    }
                    if self.provenance.generated_artifacts.len() != 2 {
                        errors.push(error(
                            "trusted transcription provenance generated inventory is not the exact two observed outputs"
                                .into(),
                            "record only the transcribed candidate and re-encoded source as generated artifacts",
                        ));
                    }
                    for (label, artifact) in [
                        ("source", &record.source),
                        ("committed transcription", &record.committed_transcription),
                        ("driver", &record.driver),
                    ] {
                        if self
                            .provenance
                            .input_artifacts
                            .iter()
                            .filter(|candidate| *candidate == artifact)
                            .count()
                            != 1
                        {
                            errors.push(error(
                                format!(
                                    "trusted transcription {label} identity does not match exactly one provenance input artifact"
                                ),
                                "bind every trusted-transcription input by its complete logical name, digest, and size",
                            ));
                        }
                    }
                    for (label, artifact) in [
                        ("transcribed candidate", &record.transcribed_candidate),
                        ("re-encoded source", &record.reencoded_source),
                    ] {
                        if self
                            .provenance
                            .generated_artifacts
                            .iter()
                            .filter(|candidate| *candidate == artifact)
                            .count()
                            != 1
                        {
                            errors.push(error(
                                format!(
                                    "trusted transcription {label} identity does not match exactly one provenance generated artifact"
                                ),
                                "bind both independently observed outputs by their complete logical name, digest, and size",
                            ));
                        }
                    }
                    if !same_artifact_bytes(
                        &record.committed_transcription,
                        &record.transcribed_candidate,
                    ) {
                        errors.push(error(
                            "transcribed candidate bytes do not match the committed transcription"
                                .into(),
                            "regenerate the transcription and require identical digest and byte size before recording evidence",
                        ));
                    }
                    if !same_artifact_bytes(&record.source, &record.reencoded_source) {
                        errors.push(error(
                            "re-encoded source bytes do not match the registered source".into(),
                            "run the external round trip and require identical digest and byte size before recording evidence",
                        ));
                    }
                    let expected_transcriber = transcription_role_identity(
                        TranscriptionRole::Transcriber,
                        &record.driver,
                    );
                    let expected_reencoder = transcription_role_identity(
                        TranscriptionRole::Reencoder,
                        &record.driver,
                    );
                    if record.transcriber.role_identity != expected_transcriber
                        || record.reencoder.role_identity != expected_reencoder
                    {
                        errors.push(error(
                            "trusted transcription TCB role identity is not derived from the exact registered driver and ABI"
                                .into(),
                            "derive each role identity with proofbound-transcription-tcb-role/1 from the complete driver identity",
                        ));
                    }
                    let expected_transcriber_node =
                        transcription_tcb_node_id(&self.unit_id, TranscriptionRole::Transcriber);
                    let expected_reencoder_node =
                        transcription_tcb_node_id(&self.unit_id, TranscriptionRole::Reencoder);
                    if expected_transcriber_node.as_ref() != Ok(&record.transcriber.tcb_node)
                        || expected_reencoder_node.as_ref() != Ok(&record.reencoder.tcb_node)
                    {
                        errors.push(error(
                            "trusted transcription TCB node identity is not derived from the evidence unit and role"
                                .into(),
                            "use tcb:trusted-transcription:<unit>:transcriber and the corresponding reencoder node",
                        ));
                    }
                    if record.transcriber.tcb_node == record.reencoder.tcb_node
                        || record.transcriber.role_identity == record.reencoder.role_identity
                    {
                        errors.push(error(
                            "trusted transcription collapses the transcriber and re-encoder TCB roles"
                                .into(),
                            "record two distinct TCB nodes with domain-separated role identities",
                        ));
                    }
                } else {
                    errors.push(error(
                        "trusted transcription is missing its derived external round-trip record"
                            .into(),
                        "record both exact inputs, both observed outputs, the driver, and both TCB roles",
                    ));
                }
            }
            EvidenceKind::SourceRefinement => match &self.source_refinement {
                Some(refinement)
                    if refinement.deterministic_translation
                        && refinement.pinned_toolchain
                        && refinement.generated_axioms_clean
                        && !refinement.representation_premises.is_empty()
                        && refinement.representation_premises.is_subset(&self.premises) => {}
                _ => errors.push(error(
                    "source refinement lacks deterministic pinned translation, clean generated code, or registered premises".into(),
                    "record the refinement theorem and every representation premise",
                )),
            },
            EvidenceKind::BoundedCheck => match &self.bounded_check {
                Some(check)
                    if !check.domain.description.trim().is_empty()
                        && !check.solver.trim().is_empty()
                        && !check.harnesses.is_empty()
                        && check.harnesses == self.inventoried_targets
                        && check.unwind_bounds.keys().eq(check.harnesses.iter())
                        && check.unwind_bounds.values().all(|bound| *bound > 0)
                        && check.assumptions.len() <= 4096
                        && check
                            .assumptions
                            .iter()
                            .all(|assumption| {
                                !assumption.trim().is_empty()
                                    && assumption.chars().count() <= 4096
                            })
                        && check.assumptions.iter().collect::<BTreeSet<_>>().len()
                            == check.assumptions.len() => {}
                _ => errors.push(error(
                    "bounded evidence lacks an explicit finite domain, solver, exact nonzero per-harness unwind bounds, or a valid assumption inventory".into(),
                    "register the finite domain, every bounded harness and its unwind bound, and at most 4096 unique nonblank model-check assumptions of at most 4096 characters each",
                )),
            },
            EvidenceKind::ExhaustiveCheck => match &self.exhaustive_check {
                Some(check)
                    if !check.domain.description.trim().is_empty()
                        && check.domain.cardinality == Some(check.evaluated_members) => {}
                _ => errors.push(error(
                    "exhaustive evidence does not match the registered finite-domain cardinality".into(),
                    "record a finite cardinality equal to the evaluated member count",
                )),
            },
            EvidenceKind::IndependentCheck => {
                if self.independence != Some(IndependenceMode::Independent)
                    || self.inventoried_targets.is_empty()
                {
                    errors.push(error(
                        "independent-check evidence is common-origin or has no inventoried targets".into(),
                        "use common-origin evidence honestly or register independently implemented targets",
                    ));
                }
            }
            EvidenceKind::PropertyTest | EvidenceKind::ExampleTest => {
                if self.inventoried_targets.is_empty() {
                    errors.push(error(
                        "test evidence has no inventoried target".into(),
                        "record every collected test target and fail if collection skips one",
                    ));
                }
            }
            EvidenceKind::MutationWitness => {
                match &self.mutation_witness {
                    Some(witness) if mutation_witness_valid(self, witness) => {}
                    Some(_) => errors.push(error(
                        "mutation-witness evidence does not bind one exact registered mutant, clean baseline, and truthful expected failing run".into(),
                        "record the singleton mutation registration and artifact identities, require the exact witness to pass cleanly and fail with exit 101 after sealed replay, and recompute proofbound-mutation/2",
                    )),
                    None => errors.push(error(
                        "mutation-witness evidence lacks the version-2 mutation replay record".into(),
                        "record the singleton mutation, its exact artifacts, clean baseline, and typed expected failure",
                    )),
                }
            }
            EvidenceKind::Open => {
                if self.open_obligation.is_none() {
                    errors.push(error(
                        "open evidence lacks a registered open obligation".into(),
                        "register the exact open statement and remediation",
                    ));
                }
            }
            EvidenceKind::Review | EvidenceKind::Assumption => {}
        }

        let detail_allowed = match self.kind {
            EvidenceKind::Theorem => {
                self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
            }
            EvidenceKind::ArtifactSoundness => {
                self.theorem.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
            }
            EvidenceKind::TrustedTranscription => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
            }
            EvidenceKind::SourceRefinement => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
            EvidenceKind::BoundedCheck => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
            EvidenceKind::ExhaustiveCheck => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
            EvidenceKind::IndependentCheck => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
            EvidenceKind::MutationWitness => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
            EvidenceKind::Open => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
            EvidenceKind::PropertyTest
            | EvidenceKind::ExampleTest
            | EvidenceKind::Review
            | EvidenceKind::Assumption => {
                self.theorem.is_none()
                    && self.artifact_binding.is_none()
                    && self.trusted_transcription.is_none()
                    && self.source_refinement.is_none()
                    && self.bounded_check.is_none()
                    && self.exhaustive_check.is_none()
                    && self.mutation_witness.is_none()
                    && self.independence.is_none()
                    && self.open_obligation.is_none()
                    && self.evaluation_mode.is_none()
                    && self.binding_mode.is_none()
            }
        };
        if !detail_allowed {
            errors.push(error(
                format!(
                    "evidence '{}' contains qualifier or detail blocks belonging to another evidence kind",
                    self.id
                ),
                "split distinct evidence meanings into separate records",
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::new(errors))
        }
    }

    /// Returns the finite domain carried by this evidence, if any.
    #[must_use]
    pub fn bounded_domain(&self) -> Option<&BoundedDomain> {
        self.bounded_check
            .as_ref()
            .map(|check| &check.domain)
            .or_else(|| self.exhaustive_check.as_ref().map(|check| &check.domain))
    }
}

fn mutation_witness_valid(record: &EvidenceRecord, witness: &MutationWitnessEvidence) -> bool {
    let expected_exit_codes = BTreeSet::from([101]);
    let input_roles = [
        &witness.registry,
        &witness.target_preimage,
        &witness.mutant_artifact,
        &witness.witness_source,
    ];
    let input_role_names = input_roles
        .iter()
        .map(|artifact| artifact.logical_name.as_str())
        .collect::<BTreeSet<_>>();
    let input_roles_are_exact = record.provenance.input_artifacts.len() == input_roles.len()
        && input_role_names.len() == input_roles.len()
        && input_roles.iter().all(|artifact| {
            record
                .provenance
                .input_artifacts
                .iter()
                .filter(|observed| *observed == *artifact)
                .count()
                == 1
        });
    let postimage_is_exact = record.provenance.generated_artifacts.len() == 1
        && record.provenance.generated_artifacts[0] == witness.target_postimage;
    let replacement_is_exact = witness.target_preimage.logical_name
        == witness.target_postimage.logical_name
        && witness.target_preimage.sha256 != witness.target_postimage.sha256
        && witness.target_postimage.logical_name != witness.mutant_artifact.logical_name
        && same_artifact_bytes(&witness.target_postimage, &witness.mutant_artifact);
    let singleton_inventory =
        record.inventoried_targets == BTreeSet::from([witness.mutation_id.clone()]);
    let singleton_unit =
        record.unit_id.as_str().strip_prefix("unit:") == Some(witness.mutation_id.as_str());
    let expected_failure_is_exact = witness.expected_failure.allowed_exit_codes
        == expected_exit_codes
        && witness.baseline_run_index < witness.expected_failure.run_index;
    let baseline_run = record.provenance.runs.get(witness.baseline_run_index);
    let mutant_run = record
        .provenance
        .runs
        .get(witness.expected_failure.run_index);
    let baseline_command = record.provenance.commands.get(witness.baseline_run_index);
    let mutant_command = record
        .provenance
        .commands
        .get(witness.expected_failure.run_index);
    let commands_bind_same_check =
        baseline_command
            .zip(mutant_command)
            .is_some_and(|(baseline, mutant)| {
                baseline.program != mutant.program
                    && baseline.environment_allowlist == mutant.environment_allowlist
                    && command_runs_exact_check(baseline, &witness.check_id)
                    && command_runs_exact_check(mutant, &witness.check_id)
            });
    let passed_run_shape = record.status != EvidenceStatus::Passed
        || (baseline_run.is_some_and(|run| run.exit_code == Some(0))
            && mutant_run.is_some_and(|run| run.exit_code == Some(101))
            && record
                .provenance
                .runs
                .iter()
                .filter(|run| run.exit_code != Some(0))
                .count()
                == 1);
    let strings_are_valid = witness.schema == MUTATION_WITNESS_SCHEMA_V2
        && valid_mutation_id(&witness.mutation_id)
        && bounded_text(&witness.subject, 4096)
        && bounded_text(&witness.guard, 8192)
        && bounded_text(&witness.check_id, 4096);
    let identity_is_exact = witness
        .derived_mutation_sha256(&record.claims)
        .is_ok_and(|identity| identity == witness.mutation_sha256);

    strings_are_valid
        && input_roles_are_exact
        && postimage_is_exact
        && replacement_is_exact
        && singleton_inventory
        && singleton_unit
        && expected_failure_is_exact
        && commands_bind_same_check
        && passed_run_shape
        && identity_is_exact
}

fn command_runs_exact_check(command: &CommandSpec, check_id: &str) -> bool {
    let selector = check_id
        .split_once("::")
        .map_or(check_id, |(_, selector)| selector);
    command.args == [selector, "--exact"]
}

fn bounded_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

fn valid_mutation_id(value: &str) -> bool {
    value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Claim input consumed by status derivation after manifest resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub schema: String,
    pub id: ClaimId,
    pub node_id: NodeId,
    pub title: String,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_language: Option<String>,
    pub subject: NodeId,
    pub policy: PolicyId,
    /// Optional per-claim ceiling. When absent, the project tier is the
    /// effective ceiling; it can never raise the project tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    pub cited_evidence: BTreeSet<EvidenceId>,
    #[serde(default)]
    pub assumptions: BTreeSet<AssumptionId>,
    #[serde(default)]
    pub open_obligations: BTreeSet<OpenObligation>,
    #[serde(default)]
    pub out_of_scope: BTreeSet<OutOfScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_linkage: Option<LinkageFacet>,
    #[serde(default)]
    pub registered_inputs: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_domain_language: Option<String>,
}

impl AssumptionRecord {
    pub(crate) fn validate_for_claim(&self, claim_id: &ClaimId) -> Vec<StructuredError> {
        let mut errors = Vec::new();
        if self.schema != ASSUMPTION_SCHEMA_V1 {
            errors.push(
                StructuredError::new(
                    ErrorCode::PbCoreUnsupportedSchema,
                    format!("unsupported assumption schema '{}'", self.schema),
                    "migrate the assumption record to proofbound-assumption/1",
                )
                .for_claim(claim_id.clone())
                .identities(ASSUMPTION_SCHEMA_V1, &self.schema),
            );
        }
        if !self.affected_claims.contains(claim_id)
            || self.statement.trim().is_empty()
            || self.owner.trim().is_empty()
            || self.rationale.trim().is_empty()
            || self.scope.trim().is_empty()
            || self.review_evidence.is_empty()
            || self.falsification_or_discharge_plan.trim().is_empty()
        {
            errors.push(
                StructuredError::new(
                    ErrorCode::PbCoreInvalidEvidence,
                    format!(
                        "assumption '{}' is incomplete or is not scoped to claim '{claim_id}'",
                        self.id
                    ),
                    "complete every assumption field and bind it to the affected claim",
                )
                .for_claim(claim_id.clone()),
            );
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_evidence_rejects_unknown_fields() {
        let value = serde_json::json!({
            "schema": EVIDENCE_SCHEMA_V3,
            "id": "test:e",
            "node_id": "node:e",
            "unit_id": "unit:e",
            "kind": "example-test",
            "status": "passed",
            "claims": ["CLAIM-1"],
            "inventoried_targets": ["test_one"],
            "provenance": {},
            "manual_status": "PROVED"
        });
        assert!(serde_json::from_value::<EvidenceRecord>(value).is_err());
    }

    #[test]
    fn trusted_transcription_rejects_legacy_or_forged_success_booleans() {
        let legacy = serde_json::json!({
            "transcriber_tcb": "tcb:transcriber",
            "reencoder_tcb": "tcb:reencoder",
            "round_trip_passed": true
        });
        assert!(serde_json::from_value::<TrustedTranscriptionEvidence>(legacy).is_err());

        let artifact = serde_json::json!({
            "logical_name": "artifact.bin",
            "sha256": format!("sha256:{}", Sha256Digest::of_bytes(b"artifact")),
            "size_bytes": 8
        });
        let forged = serde_json::json!({
            "schema": TRUSTED_TRANSCRIPTION_SCHEMA_V1,
            "source": artifact,
            "committed_transcription": artifact,
            "transcribed_candidate": artifact,
            "reencoded_source": artifact,
            "driver": artifact,
            "transcriber": {
                "tcb_node": "tcb:transcriber",
                "role_identity": format!("sha256:{}", Sha256Digest::of_bytes(b"transcriber"))
            },
            "reencoder": {
                "tcb_node": "tcb:reencoder",
                "role_identity": format!("sha256:{}", Sha256Digest::of_bytes(b"reencoder"))
            },
            "round_trip_passed": true
        });
        assert!(serde_json::from_value::<TrustedTranscriptionEvidence>(forged).is_err());
    }

    #[test]
    fn scoped_discharge_must_cover_required_flows() {
        let registered = BTreeSet::from(["api".to_owned(), "batch".to_owned()]);
        let required = FlowScope::AllRegisteredInputs;
        let partial = FlowScope::Flows {
            flows: BTreeSet::from(["api".to_owned()]),
        };
        assert!(!partial.covers(&required, &registered));
        assert!(FlowScope::AllRegisteredInputs.covers(&required, &registered));
    }
}
