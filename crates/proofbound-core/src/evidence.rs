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
    Sha256Digest, StructuredError, Tier, TreeState, UnitId, ValidationErrors,
    lean_statement_wire_digest,
};

pub const CLAIM_SCHEMA_V1: &str = "proofbound-claim/1";
/// Superseded evidence schema retained so migrations can identify old records.
pub const EVIDENCE_SCHEMA_V1: &str = "proofbound-evidence/1";
pub const EVIDENCE_SCHEMA_BINDING_PREVIEW: &str = "proofbound-evidence/2-binding-preview";
pub const ASSUMPTION_SCHEMA_V1: &str = "proofbound-assumption/1";

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
    pub peak_memory_bytes: u64,
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
    pub command: CommandSpec,
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
    fn validate(&self, claim_id: &ClaimId, unit_id: &UnitId) -> Vec<StructuredError> {
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
        if self.command.program.trim().is_empty()
            || self.reproduction_command.program.trim().is_empty()
        {
            errors.push(contextual(StructuredError::new(
                ErrorCode::PbCoreInvalidEvidence,
                "typed command records require a program",
                "record argv as a program and argument vector rather than a shell string",
            )));
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
        let mut names = BTreeSet::new();
        for variable in self
            .command
            .environment_allowlist
            .iter()
            .chain(&self.reproduction_command.environment_allowlist)
        {
            if variable.name.as_str().trim().is_empty() || variable.name.as_str().contains('=') {
                errors.push(contextual(StructuredError::new(
                    ErrorCode::PbCoreInvalidEvidence,
                    "environment allowlist contains an invalid variable name",
                    "record only an environment variable name and an optional value digest",
                )));
            }
            if variable.secret && variable.value_sha256.is_none() {
                // A secret may intentionally be omitted completely. Its name is sufficient.
                continue;
            }
            names.insert(variable.name.as_str());
        }
        errors
    }

    /// Whether actual use exceeded any declared resource budget.
    #[must_use]
    pub const fn exceeded_budget(&self) -> bool {
        self.resource_usage.time_ms > self.resource_budget.time_ms
            || self.resource_usage.peak_disk_bytes > self.resource_budget.disk_bytes
            || self.resource_usage.peak_memory_bytes > self.resource_budget.memory_bytes
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

/// Trusted components and round-trip check for the degraded transcription form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTranscriptionEvidence {
    pub transcriber_tcb: NodeId,
    pub reencoder_tcb: NodeId,
    pub round_trip_passed: bool,
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
    pub mutation_sha256: Sha256Digest,
    pub check_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_term_theorem: Option<EvidenceId>,
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
        let mut errors = self.provenance.validate(claim_id, &self.unit_id);
        let error = |message: String, remediation: &'static str| {
            StructuredError::new(ErrorCode::PbCoreInvalidEvidence, message, remediation)
                .for_claim(claim_id.clone())
                .for_unit(self.unit_id.clone())
        };

        if self.schema != EVIDENCE_SCHEMA_BINDING_PREVIEW {
            errors.push(
                StructuredError::new(
                    ErrorCode::PbCoreUnsupportedSchema,
                    format!("unsupported evidence schema '{}'", self.schema),
                    "migrate the evidence record to proofbound-evidence/2-binding-preview",
                )
                .for_claim(claim_id.clone())
                .for_unit(self.unit_id.clone())
                .identities(EVIDENCE_SCHEMA_BINDING_PREVIEW, &self.schema),
            );
        }
        if !self.claims.contains(claim_id) {
            errors.push(error(
                format!("evidence '{}' is not bound to claim '{claim_id}'", self.id),
                "add the claim to the evidence record or remove the claim's citation",
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
                if self.binding_mode != Some(BindingMode::ExternalRoundTrip)
                    || self
                        .trusted_transcription
                        .as_ref()
                        .is_none_or(|record| !record.round_trip_passed)
                {
                    errors.push(error(
                        "trusted transcription requires a passing external round-trip binding".into(),
                        "record external-round-trip and both trusted components",
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
                        && check.unwind_bounds.keys().eq(check.harnesses.iter())
                        && check.unwind_bounds.values().all(|bound| *bound > 0) => {}
                _ => errors.push(error(
                    "bounded evidence lacks an explicit finite domain, solver, or exact nonzero per-harness unwind bounds".into(),
                    "register the finite domain, every bounded harness, and its unwind bound",
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
                if self.mutation_witness.is_none() {
                    errors.push(error(
                        "mutation-witness evidence lacks mutation and detecting-check identities".into(),
                        "record the mutation digest and registered check",
                    ));
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

/// Claim input consumed by status derivation after manifest resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub schema: String,
    pub id: ClaimId,
    pub node_id: NodeId,
    pub title: String,
    pub statement: String,
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
            "schema": EVIDENCE_SCHEMA_BINDING_PREVIEW,
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
