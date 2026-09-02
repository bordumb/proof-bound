use std::collections::BTreeSet;

use proofbound_evidence::{canonical_json, domain_hash};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Number, Value};

pub const CASE_SCHEMA: &str = "proofbound-assurance-ir-case/1";
const CACHE_DOMAIN: &str = "proofbound-assurance-ir-cache/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaseProgram {
    pub schema: String,
    pub case_id: String,
    pub evidence_family: String,
    pub source: Artifact,
    pub claims: Vec<IrClaim>,
    pub evidence: Vec<IrEvidence>,
    pub cache: IrCache,
    pub policy: IrPolicy,
    pub programme: IrProgrammeContext,
    pub reported: super::ExpectedClaim,
    pub exact_status: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrProgrammeContext {
    pub release_schema: Option<String>,
    pub project: Option<IrProject>,
    pub graph: Option<IrGraph>,
    pub graph_sha256: Option<String>,
    pub assumptions: Vec<IrAssumption>,
    pub premises: Vec<IrPremise>,
    pub policies: Vec<IrPolicyRecord>,
    pub closures: Vec<IrClosure>,
    pub sealed_artifacts: Vec<Artifact>,
    pub publication_blockers: Vec<String>,
    pub reported_statuses: Vec<IrReportedStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrGraph {
    pub schema: String,
    pub nodes: Vec<IrGraphNode>,
    pub edges: Vec<IrGraphEdge>,
    pub mutual_theorem_groups: Vec<IrMutualTheoremGroup>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrGraphNode {
    pub id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_environment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrMutualTheoremGroup {
    pub id: String,
    pub proof_environment: String,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrAssumption {
    pub schema: String,
    pub id: String,
    pub node_id: String,
    pub statement: String,
    pub category: String,
    pub owner: String,
    pub rationale: String,
    pub scope: String,
    pub affected_claims: Vec<String>,
    pub review_evidence: Vec<String>,
    pub falsification_or_discharge_plan: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_citation: Option<String>,
    pub state: String,
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrPremise {
    pub id: String,
    pub node_id: String,
    pub statement: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theorem_evidence: Option<String>,
    pub scope: IrFlowScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discharge: Option<IrPremiseDischarge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrFlowScope {
    pub kind: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flows: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrPremiseDischarge {
    pub theorem_evidence: String,
    pub scope: IrFlowScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrPolicyRecord {
    pub schema: String,
    pub id: String,
    pub node_id: String,
    pub components: Vec<String>,
    pub allowed_foundational_axioms: Vec<String>,
    pub allowed_project_axioms: Vec<String>,
    pub admit_exhaustive_as_proved: bool,
    pub require_no_assumptions: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_premise_rule: Option<IrNativePremiseRule>,
    pub additional_required_evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrNativePremiseRule {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrReportedStatus {
    pub claim_id: String,
    pub formal: String,
    pub linkage: String,
    pub assumption: String,
    pub policy_admitted: bool,
    pub public_statement: String,
    pub assumptions: Vec<String>,
    pub undischarged_premises: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrProject {
    pub id: String,
    pub revision: String,
    pub tier: u64,
    pub tree_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClosure {
    pub schema: String,
    pub sha256: String,
    pub kind: String,
    pub members: Vec<Artifact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Artifact {
    pub logical_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClaim {
    pub id: String,
    pub subject: String,
    pub subject_closure: Option<IrSubjectClosure>,
    pub source: Option<Artifact>,
    pub node: Option<String>,
    pub meaning: Option<IrClaimMeaning>,
    pub presentation: Option<IrClaimPresentation>,
    pub cited_evidence: Vec<String>,
    pub assumptions: Vec<String>,
    pub premises: Vec<String>,
    pub open_obligations: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub registered_inputs: Vec<String>,
    pub admission: Option<IrClaimAdmission>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrSubjectClosure {
    pub schema: String,
    pub sha256: String,
    pub selectors: Vec<String>,
    pub members: Vec<Artifact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClaimMeaning {
    pub schema: String,
    pub statement: String,
    pub formal_declaration: Option<String>,
    pub statement_encoding: Option<String>,
    pub statement_sha256: Option<String>,
    pub foundational_axioms: Vec<String>,
    pub bounded_domain: Option<Value>,
    pub registered_domain_language: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClaimPresentation {
    pub title: String,
    pub public_language: Option<String>,
    pub public_statement: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClaimAdmission {
    pub policy: String,
    pub tier: Option<u64>,
    pub primary_linkage: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrEvidence {
    pub authority: String,
    pub schema: Option<String>,
    pub unit: String,
    pub content_sha256: Option<String>,
    pub node: Option<String>,
    pub claims: Vec<String>,
    pub outcome: Option<String>,
    pub evaluation: Option<String>,
    pub binding: Option<String>,
    pub inventory: Vec<String>,
    pub assumptions: Vec<String>,
    pub premises: Vec<String>,
    pub open_obligation: Option<String>,
    pub request: Option<IrEvidenceRequest>,
    pub family: IrFamily,
    pub backend: IrBackend,
    pub provenance: IrProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrEvidenceRequest {
    pub schema: String,
    pub adapter: String,
    pub tier: u64,
    pub input_names: Vec<String>,
    pub output_names: Vec<String>,
    pub environment_allowlist: Vec<String>,
    pub resource_budget: Value,
    pub operation: Value,
    pub family_configuration: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrFamily {
    pub kind: String,
    pub detail: IrFamilyDetail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrFamilyDetail {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<Artifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property: Option<IrPropertyRegistration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation: Option<IrMutationRegistration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<IrDistributionRegistration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounded_domain: Option<IrBoundedDomain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theorem: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_fact_schemas: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrPropertyRegistration {
    pub schema: String,
    pub framework: String,
    pub seed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrMutationRegistration {
    pub schema: String,
    pub registry: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrDistributionRegistration {
    pub schema: String,
    pub format: String,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub source_date_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrBoundedDomain {
    pub id: String,
    pub description: String,
    pub cardinality: u64,
    pub ordering_key: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrBackend {
    pub retained_facts: Vec<RetainedFact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetainedFact {
    pub schema: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<IrRetainedFactValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrRetainedFactValue {
    pub configuration_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrProvenance {
    pub revision: Option<String>,
    pub tree_state: Option<String>,
    pub semantic_closure: Option<String>,
    pub additional_closures: Vec<IrClosureReference>,
    pub input_artifacts: Vec<Artifact>,
    pub generated_artifacts: Vec<Artifact>,
    pub tool: Option<IrTool>,
    pub adapter: Option<IrTool>,
    pub execution_kind: Option<String>,
    pub commands: Vec<IrCommand>,
    pub runs: Vec<IrRun>,
    pub normalization: Option<String>,
    pub reproduction: Option<IrCommand>,
    pub started_unix_ms: Option<u64>,
    pub completed_unix_ms: Option<u64>,
    pub result_sha256: Option<String>,
    pub unit_configuration_sha256: Option<String>,
    pub budget: Option<IrBudget>,
    pub usage: IrUsage,
    pub python_plugins: Vec<IrPythonPlugin>,
    pub cache: IrCacheProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClosureReference {
    pub kind: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrPythonPlugin {
    pub module: String,
    pub distribution: String,
    pub version: String,
    pub origin_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrTool {
    pub name: String,
    pub version: String,
    pub identity_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrCommand {
    pub program: String,
    pub args: Vec<String>,
    pub environment_allowlist: Vec<IrEnvironment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrEnvironment {
    pub name: String,
    pub value_sha256: Option<String>,
    pub secret: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrRun {
    pub command_index: u64,
    pub exit_code: Option<i64>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub normalized_output_sha256: Option<String>,
    pub output_truncated: Option<bool>,
    pub duration_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrUsage {
    pub time_ms: Option<u64>,
    pub disk_bytes: Option<u64>,
    pub peak_memory: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrBudget {
    pub time_ms: u64,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrCacheProvenance {
    pub prior_receipt: Option<String>,
    pub key: String,
    pub source_key: Option<String>,
    pub origin: String,
    pub reuse_eligible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrCache {
    pub registered_inputs: Vec<CacheInput>,
    pub execution_inputs: Vec<CacheInput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct CacheInput {
    pub selector: String,
    pub identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrPolicy {
    pub required_components: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrValidationError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for IrValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for IrValidationError {}

impl IrValidationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn family_kind(source_kind: &str) -> Option<&'static str> {
    match source_kind {
        "example-test" => Some("example"),
        "property-test" => Some("sampled-property"),
        "static-check" => Some("static-consistency"),
        "mutation-witness" => Some("mutation-witness"),
        "distribution-reproduction" => Some("distribution-reproduction"),
        "bounded-check" => Some("bounded-model-check"),
        "theorem" => Some("universal-source-proof"),
        "exhaustive-check" => Some("finite-exhaustive"),
        "artifact-soundness" => Some("artifact-correspondence"),
        "trusted-transcription" => Some("trusted-transcription"),
        "source-refinement" => Some("source-correspondence"),
        _ => None,
    }
}

pub fn family_schema(kind: &str) -> Option<&'static str> {
    match kind {
        "example" => Some("proofbound-ir-example/1"),
        "sampled-property" => Some("proofbound-ir-sampled-property/1"),
        "static-consistency" => Some("proofbound-ir-static-consistency/1"),
        "mutation-witness" => Some("proofbound-ir-mutation-witness/1"),
        "distribution-reproduction" => Some("proofbound-ir-distribution/1"),
        "bounded-model-check" => Some("proofbound-ir-bounded-model/1"),
        "universal-source-proof" => Some("proofbound-ir-source-proof/1"),
        "finite-exhaustive" => Some("proofbound-ir-finite-exhaustive/1"),
        "artifact-correspondence" => Some("proofbound-ir-artifact/1"),
        "trusted-transcription" => Some("proofbound-ir-transcription/1"),
        "source-correspondence" => Some("proofbound-ir-source-correspondence/1"),
        _ => None,
    }
}

pub fn cache_key(unit: &str, prior_receipt: Option<&str>) -> String {
    let material = serde_json::json!({
        "prior_receipt": prior_receipt,
        "unit": unit,
    });
    domain_hash(
        CACHE_DOMAIN,
        &canonical_json(&material).expect("bounded cache material must canonicalize"),
    )
}

pub fn validate_case_program(bytes: &[u8]) -> Result<(), IrValidationError> {
    let StrictValue(value) = serde_json::from_slice(bytes).map_err(|error| {
        let message = error.to_string();
        let code = if message.contains("duplicate object key") {
            "IR-DECODE-DUPLICATE-KEY"
        } else {
            "IR-DECODE-INVALID"
        };
        IrValidationError::new(code, message)
    })?;
    let canonical = canonical_json(&value)
        .map_err(|error| IrValidationError::new("IR-DECODE-INVALID", error.to_string()))?;
    if canonical != bytes {
        return Err(IrValidationError::new(
            "IR-DECODE-NONCANONICAL",
            "case document is not canonical JSON",
        ));
    }
    validate_value(&value)
}

fn validate_value(root: &Value) -> Result<(), IrValidationError> {
    let object = root.as_object().ok_or_else(|| {
        IrValidationError::new("IR-DECODE-INVALID", "case root must be an object")
    })?;
    if text(object, "schema")? != CASE_SCHEMA {
        return Err(IrValidationError::new(
            "IR-DECODE-SCHEMA",
            "unsupported case schema",
        ));
    }
    let source = object_field(object, "source")?;
    text(source, "sha256")?;
    let claims = array_field(object, "claims")?;
    let evidence = array_field(object, "evidence")?;
    let programme = object_field(object, "programme")?;
    let claim_ids = claims
        .iter()
        .map(|claim| text(value_object(claim)?, "id").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    require_sorted_unique(&claim_ids)?;

    let mut claim_assumptions = Vec::with_capacity(claims.len());
    let mut obligations = false;
    for claim in claims {
        let claim = value_object(claim)?;
        text(claim, "subject")?;
        let assumptions = text_array(claim, "assumptions")?;
        require_sorted_unique(&assumptions)?;
        for field in [
            "cited_evidence",
            "premises",
            "open_obligations",
            "out_of_scope",
        ] {
            require_sorted_unique(&text_array(claim, field)?)?;
        }
        let registered_inputs = text_array(claim, "registered_inputs")?;
        require_sorted_unique(&registered_inputs)?;
        if !matches!(claim.get("source"), None | Some(Value::Null)) {
            let source = object_field(claim, "source")?;
            text(source, "logical_name")?;
            text(source, "sha256")?;
            if source.get("size_bytes").and_then(Value::as_u64).is_none() {
                return Err(IrValidationError::new(
                    "IR-DECODE-INVALID",
                    "claim source size is required",
                ));
            }
            let meaning = object_field(claim, "meaning")?;
            text(meaning, "schema")?;
            text(meaning, "statement")?;
            let presentation = object_field(claim, "presentation")?;
            text(presentation, "title")?;
            let admission = object_field(claim, "admission")?;
            text(admission, "policy")?;
            validate_subject_closure(object_field(claim, "subject_closure")?, &registered_inputs)?;
        }
        obligations |= !array_field(claim, "open_obligations")?.is_empty();
        claim_assumptions.push(assumptions);
    }

    let mut kinds = Vec::with_capacity(evidence.len());
    let mut portable_receipt = false;
    for item in evidence {
        let item = value_object(item)?;
        if !item.contains_key("authority") {
            return Err(IrValidationError::new(
                "IR-DECODE-REQUIRED-AUTHORITY",
                "evidence authority is required",
            ));
        }
        let item_claims = text_array(item, "claims")?;
        require_sorted_unique(&item_claims)?;
        if item_claims != claim_ids {
            return Err(IrValidationError::new(
                "IR-EVIDENCE-CLAIM-ATTRIBUTION",
                "evidence claim attribution differs from the case",
            ));
        }
        let assumptions = text_array(item, "assumptions")?;
        require_sorted_unique(&assumptions)?;
        let inventory = text_array(item, "inventory")?;
        require_sorted_unique(&inventory)?;
        let authority = text(item, "authority")?;
        let request = (authority == "registered")
            .then(|| object_field(item, "request"))
            .transpose()?;
        if authority == "portable-receipt" {
            portable_receipt = true;
            if item.get("schema").and_then(Value::as_str) != Some("proofbound-evidence/3") {
                return Err(IrValidationError::new(
                    "IR-PORTABLE-EVIDENCE-SCHEMA",
                    "portable evidence schema is missing or unsupported",
                ));
            }
            text(item, "content_sha256")?;
        }
        if claim_assumptions.iter().any(|registered| {
            assumptions
                .iter()
                .any(|assumption| !registered.contains(assumption))
        }) {
            return Err(IrValidationError::new(
                "IR-ASSUMPTION-JOIN",
                "claim and evidence assumptions differ",
            ));
        }

        let family = object_field(item, "family")?;
        let kind = text(family, "kind")?;
        let detail = object_field(family, "detail")?;
        if family_schema(kind) != detail.get("schema").and_then(Value::as_str) {
            return Err(IrValidationError::new(
                "IR-EVIDENCE-FAMILY-DETAIL",
                "family discriminant and detail schema differ",
            ));
        }
        validate_family_detail(kind, detail)?;
        if let Some(request) = request {
            validate_registered_family_join(kind, detail, request)?;
        }
        kinds.push(kind.to_owned());

        let declared_fact_schemas = match detail.get("required_fact_schemas") {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>(),
            Some(_) => {
                return Err(IrValidationError::new(
                    "IR-DECODE-INVALID",
                    "required_fact_schemas must be an array",
                ));
            }
            None => BTreeSet::new(),
        };

        let backend = object_field(item, "backend")?;
        for fact in array_field(backend, "retained_facts")? {
            let fact = value_object(fact)?;
            exact_fields(fact, &["schema", "required"], &["value", "payload_sha256"])?;
            let required = fact
                .get("required")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    IrValidationError::new(
                        "IR-DECODE-INVALID",
                        "retained fact disposition is required",
                    )
                })?;
            let schema = text(fact, "schema")?;
            if required && !declared_fact_schemas.contains(schema) {
                return Err(IrValidationError::new(
                    "IR-BACKEND-UNKNOWN-REQUIRED",
                    "unknown required retained fact",
                ));
            }
            if schema != "proofbound-python-property/1" {
                if required
                    || fact.contains_key("value")
                    || !matches!(fact.get("payload_sha256"), Some(Value::String(_)))
                {
                    return Err(IrValidationError::new(
                        "IR-BACKEND-UNKNOWN-OPTIONAL",
                        "unknown optional fact must retain only its canonical payload identity",
                    ));
                }
                continue;
            }
            if fact.contains_key("payload_sha256") {
                return Err(IrValidationError::new(
                    "IR-BACKEND-FACT-MISMATCH",
                    "known retained fact must use its typed value",
                ));
            }
            let value = object_field(fact, "value")?;
            exact_fields(value, &["configuration_sha256"], &[])?;
            let configuration_sha256 = text(value, "configuration_sha256")?;
            let registered_configuration = request
                .and_then(|request| request.get("family_configuration"))
                .ok_or_else(|| {
                    IrValidationError::new(
                        "IR-BACKEND-FACT-MISMATCH",
                        "retained fact has no registered family configuration",
                    )
                })?;
            let bytes = canonical_json(registered_configuration)
                .map_err(|error| IrValidationError::new("IR-DECODE-INVALID", error.to_string()))?;
            if domain_hash(super::PROJECTION_DOMAIN, &bytes) != configuration_sha256 {
                return Err(IrValidationError::new(
                    "IR-BACKEND-FACT-MISMATCH",
                    "retained fact identity differs from the registered family configuration",
                ));
            }
        }

        if kind == "mutation-witness" {
            let subject = text(detail, "subject")?;
            let expected = claims
                .first()
                .and_then(Value::as_object)
                .and_then(|claim| claim.get("subject"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if subject != expected {
                return Err(IrValidationError::new(
                    "IR-EVIDENCE-SUBJECT-MISMATCH",
                    "mutation subject differs from the claim subject",
                ));
            }
        }
        if kind == "artifact-correspondence" {
            let artifact = object_field(detail, "artifact")?;
            if artifact != source {
                return Err(IrValidationError::new(
                    "IR-ARTIFACT-IDENTITY-MISMATCH",
                    "artifact identity differs from the registered source",
                ));
            }
        }

        let provenance = object_field(item, "provenance")?;
        for (index, run) in array_field(provenance, "runs")?.iter().enumerate() {
            let run = value_object(run)?;
            if run.get("command_index").and_then(Value::as_u64) != Some(index as u64) {
                return Err(IrValidationError::new(
                    "IR-PROVENANCE-RUN-ORDER",
                    "run index differs from its registered position",
                ));
            }
        }
        let usage = object_field(provenance, "usage")?;
        if !usage.contains_key("peak_memory") {
            return Err(IrValidationError::new(
                "IR-DECODE-REQUIRED-UNKNOWN",
                "required nullable peak_memory is missing",
            ));
        }
        let cache = object_field(provenance, "cache")?;
        let prior = cache.get("prior_receipt").and_then(Value::as_str);
        let unit = text(item, "unit")?;
        if text(cache, "key")? != cache_key(unit, prior) {
            return Err(IrValidationError::new(
                "IR-CACHE-REUSE-MISMATCH",
                "cache key does not bind the prior receipt",
            ));
        }
    }

    validate_programme(programme, portable_receipt)?;
    let reported = object_field(object, "reported")?;
    if portable_receipt {
        validate_portable_joins(
            programme,
            claims,
            evidence,
            reported,
            object_field(object, "policy")?,
        )?;
    }

    let cache = object_field(object, "cache")?;
    let registered = cache_inputs(cache, "registered_inputs")?;
    let execution = cache_inputs(cache, "execution_inputs")?;
    if registered != execution {
        return Err(IrValidationError::new(
            "IR-CACHE-DEPENDENCY-OMITTED",
            "execution cache inputs differ from registration",
        ));
    }

    let exact_status = object
        .get("exact_status")
        .and_then(Value::as_bool)
        .ok_or_else(|| IrValidationError::new("IR-DECODE-INVALID", "missing exact_status"))?;
    validate_reported(
        reported,
        &kinds,
        !claim_assumptions.iter().all(Vec::is_empty) || obligations,
        exact_status,
    )
}

fn validate_portable_joins(
    programme: &Map<String, Value>,
    claims: &[Value],
    evidence: &[Value],
    reported: &Map<String, Value>,
    derived_policy: &Map<String, Value>,
) -> Result<(), IrValidationError> {
    let project = object_field(programme, "project")?;
    let revision = text(project, "revision")?;
    let tree_state = text(project, "tree_state")?;
    let closure_ids = array_field(programme, "closures")?
        .iter()
        .map(|closure| text(value_object(closure)?, "sha256"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let claim_ids = claims
        .iter()
        .map(|claim| text(value_object(claim)?, "id"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let statuses = array_field(programme, "reported_statuses")?;
    let status_claims = statuses
        .iter()
        .map(|status| text(value_object(status)?, "claim_id"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if status_claims.len() != statuses.len() {
        return Err(IrValidationError::new(
            "IR-DECODE-DUPLICATE",
            "portable reported statuses contain duplicate claim ownership",
        ));
    }
    if claim_ids != status_claims {
        return Err(IrValidationError::new(
            "IR-PROGRAMME-STATUS-MISMATCH",
            "portable reported statuses do not cover the exact claim set",
        ));
    }
    for status in statuses {
        let status = value_object(status)?;
        let claim_id = text(status, "claim_id")?;
        let claim = claims
            .iter()
            .find(|claim| claim.get("id").and_then(Value::as_str) == Some(claim_id))
            .and_then(Value::as_object)
            .expect("status coverage proves claim exists");
        let public_statement = object_field(claim, "presentation")?
            .get("public_statement")
            .and_then(Value::as_str);
        if status.get("public_statement").and_then(Value::as_str) != public_statement {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-PRESENTATION-MISMATCH",
                "reported public statement differs from the claim presentation",
            ));
        }
        for field in ["formal", "linkage", "assumption"] {
            if status.get(field) != reported.get(field) {
                return Err(IrValidationError::new(
                    "IR-PROGRAMME-STATUS-MISMATCH",
                    "portable reported status differs from independent derivation",
                ));
            }
        }
        if status.get("policy_admitted") != reported.get("policy_admitted") {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-STATUS-MISMATCH",
                "portable policy decision differs from independent derivation",
            ));
        }
    }

    let policies = array_field(programme, "policies")?;
    let required_components = text_array(derived_policy, "required_components")?;
    for claim in claims {
        let claim = value_object(claim)?;
        let policy_id = text(object_field(claim, "admission")?, "policy")?;
        let policy = policies
            .iter()
            .find(|policy| policy.get("id").and_then(Value::as_str) == Some(policy_id))
            .and_then(Value::as_object)
            .ok_or_else(|| {
                IrValidationError::new(
                    "IR-PROGRAMME-POLICY-MISMATCH",
                    "claim policy is absent from the effective policy set",
                )
            })?;
        if text_array(policy, "components")? != required_components {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-POLICY-MISMATCH",
                "effective policy differs from the policy used by status derivation",
            ));
        }
    }
    let blockers = statuses
        .iter()
        .filter_map(|status| {
            let status = status.as_object()?;
            (status.get("policy_admitted").and_then(Value::as_bool) == Some(false))
                .then(|| status.get("claim_id")?.as_str())
                .flatten()
        })
        .collect::<Vec<_>>();
    if text_array(programme, "publication_blockers")? != blockers {
        return Err(IrValidationError::new(
            "IR-PROGRAMME-BLOCKER-MISMATCH",
            "publication blockers differ from non-admitted statuses",
        ));
    }

    validate_ledger_joins(programme, &claim_ids, evidence)?;
    for item in evidence {
        let item = value_object(item)?;
        if text(item, "authority")? != "portable-receipt" {
            continue;
        }
        let provenance = object_field(item, "provenance")?;
        if provenance.get("revision").and_then(Value::as_str) != Some(revision)
            || provenance.get("tree_state").and_then(Value::as_str) != Some(tree_state)
        {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-PROVENANCE-MISMATCH",
                "portable provenance differs from project identity",
            ));
        }
        let closure = text(provenance, "semantic_closure")?;
        if !closure_ids.contains(closure) {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-CLOSURE-MISSING",
                "portable evidence names an unregistered semantic closure",
            ));
        }
    }
    Ok(())
}

fn validate_ledger_joins(
    programme: &Map<String, Value>,
    claim_ids: &BTreeSet<&str>,
    evidence: &[Value],
) -> Result<(), IrValidationError> {
    let graph = object_field(programme, "graph")?;
    let nodes = array_field(graph, "nodes")?
        .iter()
        .map(|node| {
            let node = value_object(node)?;
            Ok((text(node, "id")?, text(node, "kind")?))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, IrValidationError>>()?;
    let evidence_ids = evidence
        .iter()
        .filter_map(|item| item.get("content_sha256").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for assumption in array_field(programme, "assumptions")? {
        let assumption = value_object(assumption)?;
        let node_id = text(assumption, "node_id")?;
        let affected = text_array(assumption, "affected_claims")?;
        let reviews = text_array(assumption, "review_evidence")?;
        if nodes.get(node_id) != Some(&"assumption")
            || affected
                .iter()
                .any(|claim| !claim_ids.contains(claim.as_str()))
            || reviews
                .iter()
                .any(|review| !evidence_ids.contains(review.as_str()))
        {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-LEDGER-JOIN",
                "assumption ledger references absent programme identities",
            ));
        }
    }
    for premise in array_field(programme, "premises")? {
        let premise = value_object(premise)?;
        let node_id = text(premise, "node_id")?;
        let theorem = premise.get("theorem_evidence").and_then(Value::as_str);
        let discharge = premise
            .get("discharge")
            .and_then(Value::as_object)
            .and_then(|value| value.get("theorem_evidence"))
            .and_then(Value::as_str);
        if nodes.get(node_id) != Some(&"premise")
            || theorem.is_some_and(|id| !evidence_ids.contains(id))
            || discharge.is_some_and(|id| !evidence_ids.contains(id))
        {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-LEDGER-JOIN",
                "premise ledger references absent programme identities",
            ));
        }
    }
    Ok(())
}

fn validate_subject_closure(
    closure: &Map<String, Value>,
    registered_inputs: &[String],
) -> Result<(), IrValidationError> {
    exact_fields(closure, &["schema", "sha256", "selectors", "members"], &[])?;
    let schema = text(closure, "schema")?;
    if schema != "proofbound-ir-subject-closure/1" {
        return Err(IrValidationError::new(
            "IR-CLAIM-SUBJECT-CLOSURE",
            "unsupported subject-closure schema",
        ));
    }
    let selectors = text_array(closure, "selectors")?;
    require_sorted_unique(&selectors)?;
    let members = array_field(closure, "members")?;
    for member in members {
        validate_artifact(value_object(member)?)?;
    }
    let member_names = members
        .iter()
        .map(|member| text(value_object(member)?, "logical_name").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if selectors != registered_inputs || member_names != selectors {
        return Err(IrValidationError::new(
            "IR-CLAIM-SUBJECT-CLOSURE",
            "subject closure differs from the registered source selectors",
        ));
    }
    let material = serde_json::json!({
        "schema": schema,
        "selectors": selectors,
        "members": members,
    });
    let bytes = canonical_json(&material)
        .map_err(|error| IrValidationError::new("IR-DECODE-INVALID", error.to_string()))?;
    if domain_hash(schema, &bytes) != text(closure, "sha256")? {
        return Err(IrValidationError::new(
            "IR-CLAIM-SUBJECT-CLOSURE",
            "subject closure identity differs from its typed members",
        ));
    }
    Ok(())
}

fn validate_programme(
    programme: &Map<String, Value>,
    portable_receipt: bool,
) -> Result<(), IrValidationError> {
    if portable_receipt {
        text(programme, "release_schema")?;
        let project = object_field(programme, "project")?;
        for field in ["id", "revision", "tree_state"] {
            text(project, field)?;
        }
        if project.get("tier").and_then(Value::as_u64).is_none() {
            return Err(IrValidationError::new(
                "IR-DECODE-INVALID",
                "portable project tier is required",
            ));
        }
        let graph = object_field(programme, "graph")?;
        validate_graph(graph)?;
        let graph_schema = text(graph, "schema")?;
        let graph_sha256 = text(programme, "graph_sha256")?;
        let graph_bytes = canonical_json(&Value::Object(graph.clone()))
            .map_err(|error| IrValidationError::new("IR-DECODE-INVALID", error.to_string()))?;
        if domain_hash(graph_schema, &graph_bytes) != graph_sha256 {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-GRAPH-IDENTITY",
                "portable graph identity does not match its typed content",
            ));
        }
        if array_field(programme, "policies")?.is_empty() {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-POLICY-OMITTED",
                "portable programme must retain its policies",
            ));
        }
    }

    for assumption in array_field(programme, "assumptions")? {
        validate_assumption(value_object(assumption)?)?;
    }
    for premise in array_field(programme, "premises")? {
        validate_premise(value_object(premise)?)?;
    }
    for policy in array_field(programme, "policies")? {
        validate_policy_record(value_object(policy)?)?;
    }

    for closure in array_field(programme, "closures")? {
        let closure = value_object(closure)?;
        let schema = text(closure, "schema")?;
        let kind = text(closure, "kind")?;
        let mut source_members = Vec::new();
        for member in array_field(closure, "members")? {
            let member = value_object(member)?;
            validate_artifact(member)?;
            source_members.push(serde_json::json!({
                "path": text(member, "logical_name")?,
                "sha256": text(member, "sha256")?,
                "size_bytes": member.get("size_bytes").and_then(Value::as_u64).expect("validated artifact size"),
            }));
        }
        let source_record = serde_json::json!({
            "schema": schema,
            "kind": kind,
            "members": source_members,
        });
        let closure_bytes = canonical_json(&source_record)
            .map_err(|error| IrValidationError::new("IR-DECODE-INVALID", error.to_string()))?;
        if domain_hash(schema, &closure_bytes) != text(closure, "sha256")? {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-CLOSURE-IDENTITY",
                "portable closure identity does not match its typed content",
            ));
        }
    }
    for artifact in array_field(programme, "sealed_artifacts")? {
        validate_artifact(value_object(artifact)?)?;
    }
    for field in ["assumptions", "premises", "publication_blockers"] {
        array_field(programme, field)?;
    }
    Ok(())
}

fn validate_family_detail(
    kind: &str,
    detail: &Map<String, Value>,
) -> Result<(), IrValidationError> {
    match kind {
        "mutation-witness" => {
            exact_fields(detail, &["schema", "subject"], &["mutation"])?;
            text(detail, "subject")?;
            if let Some(value) = detail.get("mutation") {
                let value = value_object(value)?;
                exact_fields(value, &["schema", "registry"], &[])?;
                text(value, "schema")?;
                text(value, "registry")?;
            }
        }
        "artifact-correspondence" => {
            exact_fields(detail, &["schema", "artifact"], &[])?;
            validate_artifact(object_field(detail, "artifact")?)?;
        }
        "sampled-property" => {
            exact_fields(detail, &["schema"], &["property", "required_fact_schemas"])?;
            if let Some(value) = detail.get("property") {
                let value = value_object(value)?;
                exact_fields(value, &["schema", "framework", "seed"], &[])?;
                let schema = text(value, "schema")?;
                text(value, "framework")?;
                if value.get("seed").and_then(Value::as_u64).is_none() {
                    return Err(IrValidationError::new(
                        "IR-PROGRAMME-TYPED-RECORD",
                        "sampled-property seed must be an unsigned integer",
                    ));
                }
                if text_array(detail, "required_fact_schemas")? != [schema.to_owned()] {
                    return Err(IrValidationError::new(
                        "IR-PROGRAMME-TYPED-RECORD",
                        "sampled-property fact declaration differs from its typed property",
                    ));
                }
            } else if detail.contains_key("required_fact_schemas") {
                return Err(IrValidationError::new(
                    "IR-PROGRAMME-TYPED-RECORD",
                    "sampled-property facts require a typed property registration",
                ));
            }
        }
        "distribution-reproduction" => {
            exact_fields(detail, &["schema"], &["distribution"])?;
            if let Some(value) = detail.get("distribution") {
                let value = value_object(value)?;
                exact_fields(
                    value,
                    &[
                        "schema",
                        "format",
                        "artifact_name",
                        "artifact_sha256",
                        "source_date_epoch",
                    ],
                    &[],
                )?;
                for field in ["schema", "format", "artifact_name", "artifact_sha256"] {
                    text(value, field)?;
                }
                if value
                    .get("source_date_epoch")
                    .and_then(Value::as_u64)
                    .is_none()
                {
                    return Err(IrValidationError::new(
                        "IR-PROGRAMME-TYPED-RECORD",
                        "distribution epoch must be an unsigned integer",
                    ));
                }
            }
        }
        "bounded-model-check" => {
            exact_fields(detail, &["schema"], &["bounded_domain"])?;
            if let Some(value) = detail.get("bounded_domain") {
                let value = value_object(value)?;
                exact_fields(
                    value,
                    &["id", "description", "cardinality", "ordering_key"],
                    &[],
                )?;
                text(value, "id")?;
                text(value, "description")?;
                if value.get("cardinality").and_then(Value::as_u64).is_none()
                    || array_field(value, "ordering_key")?
                        .iter()
                        .any(|item| item.as_u64().is_none())
                {
                    return Err(IrValidationError::new(
                        "IR-PROGRAMME-TYPED-RECORD",
                        "bounded-domain cardinality and ordering key must be unsigned",
                    ));
                }
            }
        }
        "universal-source-proof" => {
            exact_fields(detail, &["schema"], &["theorem"])?;
            optional_text_value(detail, "theorem")?;
        }
        "example"
        | "static-consistency"
        | "finite-exhaustive"
        | "trusted-transcription"
        | "source-correspondence" => exact_fields(detail, &["schema"], &[])?,
        _ => {
            return Err(IrValidationError::new(
                "IR-EVIDENCE-FAMILY-DETAIL",
                "unknown evidence family detail",
            ));
        }
    }
    Ok(())
}

fn validate_registered_family_join(
    kind: &str,
    detail: &Map<String, Value>,
    request: &Map<String, Value>,
) -> Result<(), IrValidationError> {
    let mut projected = Map::new();
    let field = match kind {
        "sampled-property" => Some("property"),
        "mutation-witness" => Some("mutation"),
        "distribution-reproduction" => Some("distribution"),
        "bounded-model-check" => Some("bounded_domain"),
        "universal-source-proof" => Some("theorem"),
        _ => None,
    };
    if let Some(field) = field
        && let Some(value) = detail.get(field)
    {
        projected.insert(field.to_owned(), value.clone());
    }
    if request.get("family_configuration") != Some(&Value::Object(projected)) {
        return Err(IrValidationError::new(
            "IR-EVIDENCE-FAMILY-DETAIL",
            "typed family detail differs from the registered family configuration",
        ));
    }
    Ok(())
}

fn validate_graph(graph: &Map<String, Value>) -> Result<(), IrValidationError> {
    const NODE_KINDS: &[&str] = &[
        "claim",
        "theorem",
        "subject",
        "artifact",
        "source-closure",
        "translation-unit",
        "model-check-unit",
        "test-suite",
        "assumption",
        "premise",
        "toolchain",
        "tcb-component",
        "review",
        "policy",
    ];
    const EDGE_KINDS: &[&str] = &[
        "proves",
        "refines",
        "decodes",
        "checks",
        "generated-from",
        "depends-on",
        "assumes",
        "discharged-by",
        "cross-checks",
        "covers-bounded-domain",
        "binds-digest",
        "reviewed-by",
        "admitted-by-policy",
    ];
    exact_fields(
        graph,
        &["schema", "nodes", "edges", "mutual_theorem_groups"],
        &[],
    )?;
    let mut node_ids = BTreeSet::new();
    for node in array_field(graph, "nodes")? {
        let node = value_object(node)?;
        exact_fields(node, &["id", "kind"], &["proof_environment"])?;
        let id = text(node, "id")?;
        let kind = text(node, "kind")?;
        if !node_ids.insert(id) || !NODE_KINDS.contains(&kind) {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-GRAPH-SEMANTICS",
                "graph contains a duplicate node or unknown node kind",
            ));
        }
        optional_text_value(node, "proof_environment")?;
    }
    for edge in array_field(graph, "edges")? {
        let edge = value_object(edge)?;
        exact_fields(edge, &["from", "to", "kind"], &[])?;
        for field in ["from", "to", "kind"] {
            text(edge, field)?;
        }
        if !node_ids.contains(text(edge, "from")?)
            || !node_ids.contains(text(edge, "to")?)
            || !EDGE_KINDS.contains(&text(edge, "kind")?)
        {
            return Err(IrValidationError::new(
                "IR-PROGRAMME-GRAPH-SEMANTICS",
                "graph edge has an absent endpoint or unknown kind",
            ));
        }
    }
    for group in array_field(graph, "mutual_theorem_groups")? {
        let group = value_object(group)?;
        exact_fields(group, &["id", "proof_environment", "members"], &[])?;
        text(group, "id")?;
        text(group, "proof_environment")?;
        require_sorted_unique(&text_array(group, "members")?)?;
    }
    Ok(())
}

fn validate_assumption(value: &Map<String, Value>) -> Result<(), IrValidationError> {
    exact_fields(
        value,
        &[
            "schema",
            "id",
            "node_id",
            "statement",
            "category",
            "owner",
            "rationale",
            "scope",
            "affected_claims",
            "review_evidence",
            "falsification_or_discharge_plan",
            "state",
            "depends_on",
        ],
        &["source_citation"],
    )?;
    for field in [
        "schema",
        "id",
        "node_id",
        "statement",
        "category",
        "owner",
        "rationale",
        "scope",
        "falsification_or_discharge_plan",
        "state",
    ] {
        text(value, field)?;
    }
    optional_text_value(value, "source_citation")?;
    for field in ["affected_claims", "review_evidence", "depends_on"] {
        require_sorted_unique(&text_array(value, field)?)?;
    }
    Ok(())
}

fn validate_premise(value: &Map<String, Value>) -> Result<(), IrValidationError> {
    exact_fields(
        value,
        &["id", "node_id", "statement", "category", "scope"],
        &["theorem_evidence", "discharge"],
    )?;
    for field in ["id", "node_id", "statement", "category"] {
        text(value, field)?;
    }
    optional_text_value(value, "theorem_evidence")?;
    validate_flow_scope(object_field(value, "scope")?)?;
    if let Some(discharge) = value.get("discharge") {
        let discharge = value_object(discharge)?;
        exact_fields(discharge, &["theorem_evidence", "scope"], &[])?;
        text(discharge, "theorem_evidence")?;
        validate_flow_scope(object_field(discharge, "scope")?)?;
    }
    Ok(())
}

fn validate_flow_scope(value: &Map<String, Value>) -> Result<(), IrValidationError> {
    exact_fields(value, &["kind"], &["flows"])?;
    text(value, "kind")?;
    if value.contains_key("flows") {
        require_sorted_unique(&text_array(value, "flows")?)?;
    }
    Ok(())
}

fn validate_policy_record(value: &Map<String, Value>) -> Result<(), IrValidationError> {
    exact_fields(
        value,
        &[
            "schema",
            "id",
            "node_id",
            "components",
            "allowed_foundational_axioms",
            "allowed_project_axioms",
            "admit_exhaustive_as_proved",
            "require_no_assumptions",
            "additional_required_evidence",
        ],
        &["native_premise_rule"],
    )?;
    for field in ["schema", "id", "node_id"] {
        text(value, field)?;
    }
    for field in [
        "components",
        "allowed_foundational_axioms",
        "allowed_project_axioms",
        "additional_required_evidence",
    ] {
        require_sorted_unique(&text_array(value, field)?)?;
    }
    for field in ["admit_exhaustive_as_proved", "require_no_assumptions"] {
        if value.get(field).and_then(Value::as_bool).is_none() {
            return Err(IrValidationError::new(
                "IR-DECODE-INVALID",
                format!("{field} must be a Boolean"),
            ));
        }
    }
    if let Some(rule) = value.get("native_premise_rule") {
        let rule = value_object(rule)?;
        exact_fields(rule, &["kind"], &["count"])?;
        text(rule, "kind")?;
        if rule.contains_key("count") && rule.get("count").and_then(Value::as_u64).is_none() {
            return Err(IrValidationError::new(
                "IR-DECODE-INVALID",
                "native premise count must be an unsigned integer",
            ));
        }
    }
    Ok(())
}

fn exact_fields(
    value: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), IrValidationError> {
    let allowed = required
        .iter()
        .chain(optional)
        .copied()
        .collect::<BTreeSet<_>>();
    if required.iter().any(|field| !value.contains_key(*field))
        || value.keys().any(|field| !allowed.contains(field.as_str()))
    {
        let missing = required
            .iter()
            .filter(|field| !value.contains_key(**field))
            .copied()
            .collect::<Vec<_>>();
        let unknown = value
            .keys()
            .filter(|field| !allowed.contains(field.as_str()))
            .collect::<Vec<_>>();
        return Err(IrValidationError::new(
            "IR-PROGRAMME-TYPED-RECORD",
            format!("typed programme record has missing {missing:?} or unknown {unknown:?} fields"),
        ));
    }
    Ok(())
}

fn optional_text_value(value: &Map<String, Value>, field: &str) -> Result<(), IrValidationError> {
    if matches!(
        value.get(field),
        None | Some(Value::Null | Value::String(_))
    ) {
        Ok(())
    } else {
        Err(IrValidationError::new(
            "IR-DECODE-INVALID",
            format!("{field} must be text or null"),
        ))
    }
}

fn validate_artifact(artifact: &Map<String, Value>) -> Result<(), IrValidationError> {
    text(artifact, "logical_name")?;
    text(artifact, "sha256")?;
    if artifact.get("size_bytes").and_then(Value::as_u64).is_none() {
        return Err(IrValidationError::new(
            "IR-DECODE-INVALID",
            "artifact size is required",
        ));
    }
    Ok(())
}

fn validate_reported(
    reported: &Map<String, Value>,
    kinds: &[String],
    assumed: bool,
    exact: bool,
) -> Result<(), IrValidationError> {
    let formal = if kinds.iter().any(|kind| kind == "universal-source-proof") {
        "PROVED"
    } else if kinds.iter().any(|kind| kind == "bounded-model-check") {
        "BOUNDED_CHECKED"
    } else if kinds.iter().all(|kind| kind == "trusted-transcription") {
        "OPEN"
    } else {
        "TESTED"
    };
    let linkage = if kinds.iter().any(|kind| kind == "artifact-correspondence") {
        "ARTIFACT_BOUND"
    } else if kinds.iter().any(|kind| kind == "source-correspondence") {
        "REFINED"
    } else if kinds.iter().any(|kind| kind == "trusted-transcription") {
        "TRANSCRIBED"
    } else {
        "MODEL_ONLY"
    };
    let reported_formal = text(reported, "formal")?;
    let formal_matches = if exact {
        reported_formal == formal
    } else {
        match formal {
            "PROVED" => reported_formal == "PROVED",
            "BOUNDED_CHECKED" => matches!(
                reported_formal,
                "BOUNDED_CHECKED" | "BOUNDED_CHECKED_OR_STRONGER_PER_CLAIM"
            ),
            "OPEN" => reported_formal == "OPEN",
            _ => matches!(reported_formal, "TESTED" | "TESTED_OR_STRONGER_PER_CLAIM"),
        }
    };
    let assumption_matches =
        !exact || text(reported, "assumption")? == if assumed { "ASSUMED" } else { "NONE" };
    if !formal_matches || text(reported, "linkage")? != linkage || !assumption_matches {
        return Err(IrValidationError::new(
            "IR-STATUS-MISMATCH",
            "reported status differs from independent derivation",
        ));
    }
    Ok(())
}

fn cache_inputs(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Vec<CacheInput>, IrValidationError> {
    let mut inputs = array_field(object, field)?
        .iter()
        .map(|value| {
            let value = value_object(value)?;
            Ok(CacheInput {
                selector: text(value, "selector")?.to_owned(),
                identity: text(value, "identity")?.to_owned(),
            })
        })
        .collect::<Result<Vec<_>, IrValidationError>>()?;
    let original = inputs.clone();
    inputs.sort();
    inputs.dedup();
    if inputs != original {
        return Err(IrValidationError::new(
            "IR-DECODE-DUPLICATE",
            "cache inputs must be a canonical set",
        ));
    }
    Ok(inputs)
}

fn require_sorted_unique(values: &[String]) -> Result<(), IrValidationError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(IrValidationError::new(
            "IR-DECODE-DUPLICATE",
            "set-like text arrays must be sorted and unique",
        ));
    }
    Ok(())
}

fn value_object(value: &Value) -> Result<&Map<String, Value>, IrValidationError> {
    value
        .as_object()
        .ok_or_else(|| IrValidationError::new("IR-DECODE-INVALID", "expected an object"))
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, IrValidationError> {
    object.get(field).and_then(Value::as_object).ok_or_else(|| {
        IrValidationError::new("IR-DECODE-INVALID", format!("{field} must be an object"))
    })
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Vec<Value>, IrValidationError> {
    object.get(field).and_then(Value::as_array).ok_or_else(|| {
        IrValidationError::new("IR-DECODE-INVALID", format!("{field} must be an array"))
    })
}

fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, IrValidationError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            IrValidationError::new(
                "IR-DECODE-INVALID",
                format!("{field} must be non-empty text"),
            )
        })
}

fn text_array(object: &Map<String, Value>, field: &str) -> Result<Vec<String>, IrValidationError> {
    array_field(object, field)?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                IrValidationError::new("IR-DECODE-INVALID", format!("{field} entries must be text"))
            })
        })
        .collect()
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> de::Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point JSON values are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let StrictValue(value) = map.next_value()?;
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format!("duplicate object key {key}")));
            }
        }
        Ok(StrictValue(Value::Object(values)))
    }
}
