use std::collections::{BTreeMap, BTreeSet};

use proofbound_core::{
    CommandSpec, EnvironmentId, ExecutionRun, ResourceUsage, Sha256Digest, ToolIdentity,
};
use proofbound_manifest::EvidenceUnitManifest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const LEAN_ADAPTER_UNIT_SCHEMA: &str = "proofbound-lean-adapter-unit/1";
pub const LEAN_AUDIT_SCHEMA: &str = "proofbound-lean-audit/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeanAdapterUnit {
    pub schema: String,
    pub evidence_unit: EvidenceUnitManifest,
    pub environment_id: EnvironmentId,
    pub claim_inventory: Vec<ExpectedClaim>,
    pub audit: AuditSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedClaim {
    pub claim_id: String,
    pub declaration: String,
    pub declaration_kind: DeclarationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_sha256: Option<String>,
    #[serde(default)]
    pub foundational_axioms: Vec<String>,
    #[serde(default)]
    pub project_axioms: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AuditSource {
    Execute,
    Captured {
        output: Box<AuditOutput>,
        execution: Box<CapturedExecution>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedExecution {
    pub tool: ToolIdentity,
    pub commands: Vec<CommandSpec>,
    pub runs: Vec<ExecutionRun>,
    pub normalization: String,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub resource_usage: ResourceUsage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOutput {
    pub schema: String,
    pub statement_encoding: String,
    pub claims: Vec<AuditClaim>,
    pub exemptions: Vec<AuditExemption>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditClaim {
    pub axioms: Vec<String>,
    pub claim_id: String,
    pub declaration: String,
    pub expr_wire: Value,
    pub kind: DeclarationKind,
    pub module: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExemption {
    pub declaration: String,
    pub module: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclarationKind {
    Axiom,
    Definition,
    Theorem,
    Opaque,
    Quotient,
    Inductive,
    Constructor,
    Recursor,
}

#[derive(Clone, Debug)]
pub struct VerifiedAudit {
    pub target: AuditClaim,
    pub statement_sha256: Sha256Digest,
    pub foundational_axioms: BTreeSet<String>,
    pub project_axioms: BTreeSet<proofbound_core::AssumptionId>,
    pub inventory: BTreeSet<String>,
    pub audit_identity: Sha256Digest,
}
