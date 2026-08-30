use std::collections::BTreeMap;

use proofbound_core::{ClaimEvaluationInput, ClaimStatus, EvidenceRecord};
use proofbound_evidence::ClosureRecord;
use proofbound_manifest::AdapterDiagnostic;
use serde::{Deserialize, Serialize};

/// Diagnostic record for one adapter invocation, successful or otherwise.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnitRun {
    pub unit_id: String,
    pub adapter: String,
    pub cache_key: String,
    pub outcome: String,
    pub evidence_sha256: Option<String>,
    #[serde(default)]
    pub inventory: Vec<String>,
    #[serde(default)]
    pub diagnostics: Vec<AdapterDiagnostic>,
}

/// Self-contained orchestrator output. The independent release format is
/// deliberately compiled from this rather than treating this file as signed
/// truth.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProject {
    pub schema: String,
    pub project: String,
    pub project_revision: String,
    pub tree_state: String,
    /// Digest of every reviewed tracked or non-ignored untracked byte at the
    /// instant this compilation began. Reports may be loaded only while this
    /// exact snapshot is still current.
    pub reviewed_tree_sha256: String,
    pub generated_at: String,
    pub inputs: Vec<ClaimEvaluationInput>,
    pub statuses: Vec<ClaimStatus>,
    pub evidence: Vec<EvidenceRecord>,
    pub closures: Vec<ClosureRecord>,
    pub unit_runs: Vec<UnitRun>,
    /// Claim ID to the content digest of its serialized derivation input.
    pub claim_input_identities: BTreeMap<String, String>,
}
