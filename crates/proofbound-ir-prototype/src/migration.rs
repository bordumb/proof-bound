use std::{collections::BTreeSet, fmt, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const FOREIGN_CONTRACT_SCHEMA: &str = "proofbound-research-foreign-contract/1";
pub const FOREIGN_CALL_SCHEMA: &str = "proofbound-research-foreign-call/1";
pub const FOREIGN_OBSERVATIONS_SCHEMA: &str = "proofbound-research-foreign-observations/1";
pub const MIXED_GRAPH_SCHEMA: &str = "proofbound-research-mixed-graph/1";
pub const MIXED_MODEL_REPORT_SCHEMA: &str = "proofbound-research-mixed-model-report/1";

const CASES_SCHEMA: &str = "proofbound-research-foreign-cases/1";
const GRAPH_TEMPLATES_SCHEMA: &str = "proofbound-research-mixed-graph-templates/1";
const ATTACKS_SCHEMA: &str = "proofbound-research-mixed-attacks/1";
const OBSERVATION_ENVELOPE_SCHEMA: &str = "proofbound-research-foreign-observation-envelope/1";
const EXPECTED_ARTIFACT_IDENTITY: &str =
    "sha256:1fe9ee82ee28420f7cd02d70617de5a2f56cbf5115ee410c784358a17a711384";
const EXPECTED_SOURCE_SHA256: &str =
    "sha256:47a20d5b10ffeb1088b836f72b260ca48116d8ebb92ea9b35a34f619743b44c2";
const EXPECTED_CERTIFICATE_IDENTITY: &str =
    "sha256:27ff98de778cff63de6621b9e8de368b0803fee74cd5e4dcb4242826d4b93420";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for MigrationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignContract {
    pub schema: String,
    pub id: String,
    pub abi_version: u64,
    pub operations: Vec<String>,
    pub request_encoding: String,
    pub response_encoding: String,
    pub success_policy: String,
    pub error_policy: String,
    pub callback_policy: String,
    pub consumption_policy: String,
    pub artifact: ForeignArtifact,
    pub runtimes: Vec<ForeignRuntime>,
    pub limits: ForeignLimits,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignArtifact {
    pub schema: String,
    pub hex: String,
    pub sha256: String,
    pub identity: String,
    pub size_bytes: u64,
    pub source_sha256: String,
    pub certificate_identity: String,
    pub correspondence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignRuntime {
    pub language: String,
    pub program: String,
    pub version: String,
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignLimits {
    pub maximum_request_bytes: u64,
    pub maximum_response_bytes: u64,
    pub maximum_calls: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForeignCases {
    schema: String,
    cases: Vec<ForeignCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForeignCase {
    id: String,
    operation: String,
    input_hex: Option<String>,
    input_value: Option<u8>,
    expected: CallResult,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct CallResult {
    accepted: bool,
    value: Option<u8>,
    output_hex: Option<String>,
    error: Option<String>,
    consumed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignObservationSet {
    pub schema: String,
    pub language: String,
    pub phase: String,
    pub contract_identity: String,
    pub runtime: ForeignRuntime,
    pub calls: Vec<ForeignCall>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignCall {
    pub schema: String,
    pub case_id: String,
    pub phase: String,
    pub language: String,
    pub contract_identity: String,
    pub artifact_identity: Option<String>,
    pub operation: String,
    pub input_hex: Option<String>,
    pub input_value: Option<u8>,
    pub accepted: bool,
    pub value: Option<u8>,
    pub output_hex: Option<String>,
    pub error: Option<String>,
    pub consumed: u64,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignObservationEnvelope {
    pub schema: String,
    pub observations: Vec<ForeignObservationSet>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphTemplates {
    schema: String,
    public_contracts: Vec<PublicContract>,
    baseline: GraphPhase,
    migrated: GraphPhase,
    migration: MigrationSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicContract {
    claim_id: String,
    statement: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphPhase {
    components: Vec<Component>,
    assumptions: Vec<Assumption>,
    claims: Vec<Claim>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Component {
    id: String,
    kind: String,
    language: String,
    artifact_identity: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Assumption {
    id: String,
    kind: String,
    statement: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    id: String,
    component_id: String,
    formal: String,
    artifact: String,
    evidence: Vec<String>,
    dependencies: Vec<String>,
    assumptions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationSet {
    pub affected_claims: Vec<String>,
    pub unaffected_claims: Vec<String>,
    pub preserved_public_claims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AttackCorpus {
    schema: String,
    attacks: Vec<Attack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Attack {
    id: String,
    action: String,
    expected: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Derivation {
    pub claim_id: String,
    pub inputs: Vec<String>,
    pub formal: String,
    pub artifact: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphReport {
    pub phase: String,
    pub components: Vec<ComponentReport>,
    pub assumptions: Vec<String>,
    pub derivations: Vec<Derivation>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentReport {
    pub id: String,
    pub kind: String,
    pub artifact_identity: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationExplanation {
    pub native_fact: String,
    pub foreign_ceilings: Vec<String>,
    pub remaining_assumptions: Vec<String>,
    pub affected_claims: Vec<String>,
    pub unaffected_claims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MixedModelReport {
    pub schema: String,
    pub contract_identity: String,
    pub observation_identities: Vec<String>,
    pub baseline: GraphReport,
    pub migrated: GraphReport,
    pub migration: MigrationSet,
    pub attacks: Vec<AttackResult>,
    pub explanation: MigrationExplanation,
    pub repetition_identities: Vec<String>,
    pub identity: String,
}

fn invalid(code: &'static str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        code,
        message: message.into(),
    }
}

pub fn execute_migration_corpus(
    root: &Path,
    corpus_dir: &Path,
    observation_bytes: &[u8],
    repetitions: usize,
) -> Result<MixedModelReport, MigrationError> {
    if repetitions != 10 {
        return Err(invalid("FB-REPORT-IDENTITY", "repetition count differs"));
    }
    let contract: ForeignContract = decode_control(root, &corpus_dir.join("contract.json"))?;
    let cases: ForeignCases = decode_control(root, &corpus_dir.join("cases.json"))?;
    let graphs: GraphTemplates = decode_control(root, &corpus_dir.join("graphs.json"))?;
    let attacks: AttackCorpus = decode_control(root, &corpus_dir.join("attacks.json"))?;
    let envelope: ForeignObservationEnvelope = decode_canonical(observation_bytes)?;
    validate_attack_corpus(&attacks)?;
    let mut reports = (0..repetitions)
        .map(|_| derive_report(&contract, &cases, &graphs, &envelope, &attacks))
        .collect::<Result<Vec<_>, _>>()?;
    let identities = reports
        .iter()
        .map(|report| report.identity.clone())
        .collect::<Vec<_>>();
    if identities.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(invalid("FB-REPORT-IDENTITY", "repeated reports differ"));
    }
    let mut report = reports.remove(0);
    report.repetition_identities = identities;
    validate_model_report(&contract, &cases, &graphs, &envelope, &attacks, &report)?;
    Ok(report)
}

pub fn encode_observation_envelope(
    observations: Vec<ForeignObservationSet>,
) -> Result<Vec<u8>, MigrationError> {
    let mut envelope = ForeignObservationEnvelope {
        schema: OBSERVATION_ENVELOPE_SCHEMA.to_owned(),
        observations,
        identity: String::new(),
    };
    envelope.identity = envelope_identity(&envelope)?;
    canonical_json(&envelope).map_err(|error| invalid("FB-NONCANONICAL", error.to_string()))
}

fn derive_report(
    contract: &ForeignContract,
    cases: &ForeignCases,
    graphs: &GraphTemplates,
    envelope: &ForeignObservationEnvelope,
    attacks: &AttackCorpus,
) -> Result<MixedModelReport, MigrationError> {
    validate_program(contract, cases, graphs, envelope)?;
    let baseline = derive_graph_report("baseline", &graphs.baseline)?;
    let migrated = derive_graph_report("migrated", &graphs.migrated)?;
    let attack_results = attacks
        .attacks
        .iter()
        .map(|attack| execute_attack(contract, cases, graphs, envelope, attack))
        .collect::<Result<Vec<_>, _>>()?;
    let foreign_ceilings = graphs
        .migrated
        .claims
        .iter()
        .filter(|claim| claim.formal == "tested" && !claim.dependencies.is_empty())
        .map(|claim| format!("{} remains tested", claim.id))
        .collect::<Vec<_>>();
    let mut report = MixedModelReport {
        schema: MIXED_MODEL_REPORT_SCHEMA.to_owned(),
        contract_identity: contract.identity.clone(),
        observation_identities: envelope
            .observations
            .iter()
            .map(|observation| observation.identity.clone())
            .collect(),
        baseline,
        migrated,
        migration: graphs.migration.clone(),
        attacks: attack_results,
        explanation: MigrationExplanation {
            native_fact:
                "finite source round trip proved; artifact correspondence assumption-bound"
                    .to_owned(),
            foreign_ceilings,
            remaining_assumptions: graphs
                .migrated
                .assumptions
                .iter()
                .map(|assumption| assumption.id.clone())
                .collect(),
            affected_claims: graphs.migration.affected_claims.clone(),
            unaffected_claims: graphs.migration.unaffected_claims.clone(),
        },
        repetition_identities: Vec::new(),
        identity: String::new(),
    };
    report.identity = report_identity(&report)?;
    Ok(report)
}

fn validate_program(
    contract: &ForeignContract,
    cases: &ForeignCases,
    graphs: &GraphTemplates,
    envelope: &ForeignObservationEnvelope,
) -> Result<(), MigrationError> {
    validate_contract(contract)?;
    validate_cases(contract, cases)?;
    validate_observations(contract, cases, envelope)?;
    validate_graphs(contract, graphs)?;
    Ok(())
}

fn validate_contract(contract: &ForeignContract) -> Result<(), MigrationError> {
    if contract.schema != FOREIGN_CONTRACT_SCHEMA || contract.id != "contract:canonical-packet-v1" {
        return Err(invalid(
            "FB-SCHEMA",
            "foreign contract schema or ID differs",
        ));
    }
    if contract.abi_version != 1 {
        return Err(invalid("FB-ABI-VERSION", "ABI version differs"));
    }
    if contract.operations != ["decode", "encode"] {
        return Err(invalid("FB-ABI-OPERATION", "operation inventory differs"));
    }
    if contract.request_encoding != "canonical-lowercase-hex-or-u2"
        || contract.response_encoding != "canonical-json-tagged-result"
        || contract.success_policy != "accepted-true-with-value"
        || contract.consumption_policy != "exact-input-length"
    {
        return Err(invalid("FB-ABI-ENCODING", "encoding policy differs"));
    }
    if contract.error_policy != "error-as-data-no-host-exception" {
        return Err(invalid("FB-ABI-EXCEPTION", "exception policy differs"));
    }
    if contract.callback_policy != "forbidden" {
        return Err(invalid("FB-ABI-CALLBACK", "callback policy differs"));
    }
    if contract.identity != contract_identity(contract)? {
        return Err(invalid("FB-CONTRACT-BINDING", "contract identity differs"));
    }
    let artifact = decode_hex(&contract.artifact.hex)?;
    if contract.artifact.schema != "proofbound-native-bytecode/1"
        || contract.artifact.size_bytes != artifact.len() as u64
        || contract.artifact.sha256 != sha256_bytes(&artifact)
        || contract.artifact.identity != domain_hash("proofbound-native-bytecode/1", &artifact)
        || contract.artifact.identity != EXPECTED_ARTIFACT_IDENTITY
        || contract.artifact.source_sha256 != EXPECTED_SOURCE_SHA256
        || contract.artifact.certificate_identity != EXPECTED_CERTIFICATE_IDENTITY
        || contract.artifact.correspondence != "independent-dual-compilation-assumption-bound"
    {
        return Err(invalid("FB-ARTIFACT-BINDING", "artifact binding differs"));
    }
    if contract.runtimes.len() != 2
        || !strict_sorted_unique(
            &contract
                .runtimes
                .iter()
                .map(|runtime| runtime.language.clone())
                .collect::<Vec<_>>(),
        )
        || contract.runtimes.iter().any(|runtime| {
            runtime.language.trim().is_empty()
                || runtime.program.trim().is_empty()
                || runtime.version.trim().is_empty()
                || !valid_sha(&runtime.executable_sha256)
        })
        || contract.limits.maximum_calls != 12
        || contract.limits.maximum_request_bytes != 6
        || contract.limits.maximum_response_bytes != 4096
    {
        return Err(invalid(
            "FB-RUNTIME-IDENTITY",
            "runtime registration differs",
        ));
    }
    Ok(())
}

fn validate_cases(contract: &ForeignContract, cases: &ForeignCases) -> Result<(), MigrationError> {
    if cases.schema != CASES_SCHEMA || cases.cases.len() != contract.limits.maximum_calls as usize {
        return Err(invalid("FB-OBSERVATION-MISSING", "case inventory differs"));
    }
    let ids = cases
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    if !strict_sorted_unique(&ids) {
        return Err(invalid("FB-OBSERVATION-DUPLICATE", "case IDs differ"));
    }
    let artifact = decode_hex(&contract.artifact.hex)?;
    for case in &cases.cases {
        if !contract.operations.contains(&case.operation) {
            return Err(invalid("FB-ABI-OPERATION", "case operation differs"));
        }
        if case.expected != evaluate_case(&artifact, case)? {
            return Err(invalid(
                "FB-OBSERVATION-SUBSTITUTION",
                "expected call differs",
            ));
        }
    }
    Ok(())
}

fn validate_observations(
    contract: &ForeignContract,
    cases: &ForeignCases,
    envelope: &ForeignObservationEnvelope,
) -> Result<(), MigrationError> {
    if envelope.schema != OBSERVATION_ENVELOPE_SCHEMA {
        return Err(invalid("FB-SCHEMA", "observation envelope schema differs"));
    }
    if envelope.identity != envelope_identity(envelope)? {
        return Err(invalid(
            "FB-REPORT-IDENTITY",
            "observation envelope identity differs",
        ));
    }
    let expected_count = contract.runtimes.len() * 2;
    if envelope.observations.len() < expected_count {
        return Err(invalid(
            "FB-OBSERVATION-MISSING",
            "observation set is missing",
        ));
    }
    if envelope.observations.len() > expected_count {
        let keys = observation_keys(&envelope.observations);
        if has_duplicates(&keys) {
            return Err(invalid(
                "FB-OBSERVATION-DUPLICATE",
                "observation set is duplicated",
            ));
        }
        return Err(invalid("FB-OBSERVATION-EXTRA", "observation set is extra"));
    }
    let keys = observation_keys(&envelope.observations);
    if has_duplicates(&keys) {
        return Err(invalid(
            "FB-OBSERVATION-DUPLICATE",
            "observation key is duplicated",
        ));
    }
    for observation in &envelope.observations {
        validate_observation_shape(contract, cases, observation)?;
    }
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("FB-REPORT-IDENTITY", "observation order differs"));
    }
    validate_cross_observation_agreement(cases, &envelope.observations)?;
    for observation in &envelope.observations {
        for (call, case) in observation.calls.iter().zip(&cases.cases) {
            if call_result(call) != case.expected {
                return Err(invalid(
                    "FB-OBSERVATION-SUBSTITUTION",
                    "call result differs from contract case",
                ));
            }
        }
    }
    Ok(())
}

fn validate_observation_shape(
    contract: &ForeignContract,
    cases: &ForeignCases,
    observation: &ForeignObservationSet,
) -> Result<(), MigrationError> {
    if observation.schema != FOREIGN_OBSERVATIONS_SCHEMA {
        return Err(invalid("FB-SCHEMA", "observation schema differs"));
    }
    if observation.phase != "baseline" && observation.phase != "migrated" {
        return Err(invalid("FB-GRAPH-MIGRATION", "observation phase differs"));
    }
    let Some(runtime) = contract
        .runtimes
        .iter()
        .find(|runtime| runtime.language == observation.language)
    else {
        return Err(invalid("FB-LANGUAGE-IDENTITY", "language is unregistered"));
    };
    if &observation.runtime != runtime {
        return Err(invalid("FB-RUNTIME-IDENTITY", "runtime identity differs"));
    }
    if observation.contract_identity != contract.identity {
        return Err(invalid(
            "FB-CONTRACT-BINDING",
            "observation contract differs",
        ));
    }
    if observation.identity != observation_identity(observation)? {
        return Err(invalid(
            "FB-REPORT-IDENTITY",
            "observation identity differs",
        ));
    }
    if observation.calls.len() < cases.cases.len() {
        return Err(invalid("FB-OBSERVATION-MISSING", "call is missing"));
    }
    if observation.calls.len() > cases.cases.len() {
        return Err(invalid("FB-OBSERVATION-EXTRA", "call is extra"));
    }
    let call_ids = observation
        .calls
        .iter()
        .map(|call| call.case_id.clone())
        .collect::<Vec<_>>();
    if !strict_sorted_unique(&call_ids) {
        return Err(invalid("FB-OBSERVATION-DUPLICATE", "call ID is duplicated"));
    }
    for (call, case) in observation.calls.iter().zip(&cases.cases) {
        if call.schema != FOREIGN_CALL_SCHEMA
            || call.case_id != case.id
            || call.phase != observation.phase
            || call.language != observation.language
            || call.contract_identity != contract.identity
            || call.operation != case.operation
            || call.input_hex != case.input_hex
            || call.input_value != case.input_value
        {
            return Err(invalid(
                "FB-OBSERVATION-SUBSTITUTION",
                "call binding differs",
            ));
        }
        let expected_artifact = if observation.phase == "migrated" {
            Some(contract.artifact.identity.clone())
        } else {
            None
        };
        if call.artifact_identity != expected_artifact {
            return Err(invalid("FB-ARTIFACT-BINDING", "call artifact differs"));
        }
        if call.identity != call_identity(call)? {
            return Err(invalid("FB-REPORT-IDENTITY", "call identity differs"));
        }
    }
    Ok(())
}

fn validate_cross_observation_agreement(
    cases: &ForeignCases,
    observations: &[ForeignObservationSet],
) -> Result<(), MigrationError> {
    for phase in ["baseline", "migrated"] {
        let candidates = observations
            .iter()
            .filter(|observation| observation.phase == phase)
            .collect::<Vec<_>>();
        if candidates.len() != 2 {
            return Err(invalid("FB-OBSERVATION-MISSING", "phase coverage differs"));
        }
        if semantic_results(candidates[0]) != semantic_results(candidates[1]) {
            return Err(invalid(
                "FB-CALLER-DISAGREEMENT",
                "foreign callers disagree",
            ));
        }
    }
    for index in 0..cases.cases.len() {
        let baseline = observations
            .iter()
            .filter(|observation| observation.phase == "baseline")
            .map(|observation| call_result(&observation.calls[index]))
            .collect::<BTreeSet<_>>();
        let migrated = observations
            .iter()
            .filter(|observation| observation.phase == "migrated")
            .map(|observation| call_result(&observation.calls[index]))
            .collect::<BTreeSet<_>>();
        if baseline != migrated {
            return Err(invalid(
                "FB-LEGACY-DISAGREEMENT",
                "legacy and migrated semantics disagree",
            ));
        }
    }
    Ok(())
}

fn validate_graphs(
    contract: &ForeignContract,
    graphs: &GraphTemplates,
) -> Result<(), MigrationError> {
    if graphs.schema != GRAPH_TEMPLATES_SCHEMA {
        return Err(invalid("FB-SCHEMA", "graph template schema differs"));
    }
    validate_sorted_phase(&graphs.baseline)?;
    validate_sorted_phase(&graphs.migrated)?;
    validate_phase_references(&graphs.baseline)?;
    validate_phase_references(&graphs.migrated)?;
    let baseline_claims = graphs
        .baseline
        .claims
        .iter()
        .map(|claim| (claim.id.clone(), claim))
        .collect::<std::collections::BTreeMap<_, _>>();
    let migrated_claims = graphs
        .migrated
        .claims
        .iter()
        .map(|claim| (claim.id.clone(), claim))
        .collect::<std::collections::BTreeMap<_, _>>();
    let computed_unaffected = baseline_claims
        .iter()
        .filter_map(|(id, claim)| (migrated_claims.get(id) == Some(claim)).then_some(id.clone()))
        .collect::<Vec<_>>();
    let computed_affected = migrated_claims
        .iter()
        .filter_map(|(id, claim)| (baseline_claims.get(id) != Some(claim)).then_some(id.clone()))
        .collect::<Vec<_>>();
    if graphs.migration.unaffected_claims != computed_unaffected {
        return Err(invalid("FB-GRAPH-UNAFFECTED", "unaffected claim changed"));
    }
    if graphs.migration.affected_claims != computed_affected {
        return Err(invalid("FB-GRAPH-MIGRATION", "affected claim set differs"));
    }
    let public_ids = graphs
        .public_contracts
        .iter()
        .map(|item| item.claim_id.clone())
        .collect::<Vec<_>>();
    if !strict_sorted_unique(&public_ids)
        || public_ids != graphs.migration.preserved_public_claims
        || public_ids != baseline_claims.keys().cloned().collect::<Vec<_>>()
    {
        return Err(invalid(
            "FB-GRAPH-PUBLIC-CLAIM",
            "public claim inventory differs",
        ));
    }
    let caller_public = graphs
        .public_contracts
        .iter()
        .filter(|item| {
            baseline_claims
                .get(&item.claim_id)
                .is_some_and(|claim| !claim.dependencies.is_empty())
        })
        .map(|item| item.statement.clone())
        .collect::<BTreeSet<_>>();
    if caller_public.len() != 1 {
        return Err(invalid("FB-GRAPH-PUBLIC-CLAIM", "caller statements differ"));
    }
    validate_phase_semantics(contract, &graphs.baseline, "baseline")?;
    validate_phase_semantics(contract, &graphs.migrated, "migrated")?;
    Ok(())
}

fn validate_phase_references(phase: &GraphPhase) -> Result<(), MigrationError> {
    let component_ids = phase
        .components
        .iter()
        .map(|component| component.id.as_str())
        .collect::<BTreeSet<_>>();
    let assumption_ids = phase
        .assumptions
        .iter()
        .map(|assumption| assumption.id.as_str())
        .collect::<BTreeSet<_>>();
    for claim in &phase.claims {
        if !component_ids.contains(claim.component_id.as_str()) {
            return Err(invalid("FB-GRAPH-CLAIM", "claim component is absent"));
        }
        if claim
            .dependencies
            .iter()
            .any(|dependency| !component_ids.contains(dependency.as_str()))
            || claim
                .evidence
                .first()
                .is_some_and(|evidence| evidence.ends_with("-calls"))
                && claim.dependencies.len() != 1
        {
            return Err(invalid("FB-GRAPH-DEPENDENCY", "claim dependency differs"));
        }
        if claim
            .assumptions
            .iter()
            .any(|assumption| !assumption_ids.contains(assumption.as_str()))
        {
            return Err(invalid("FB-GRAPH-ASSUMPTION", "claim assumption is absent"));
        }
    }
    Ok(())
}

fn validate_sorted_phase(phase: &GraphPhase) -> Result<(), MigrationError> {
    for ids in [
        phase
            .components
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>(),
        phase
            .assumptions
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>(),
        phase
            .claims
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>(),
    ] {
        if has_duplicates(&ids) {
            return Err(invalid("FB-GRAPH-DUPLICATE", "graph ID is duplicated"));
        }
        if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid("FB-GRAPH-IDENTITY", "graph order differs"));
        }
    }
    Ok(())
}

fn validate_phase_semantics(
    contract: &ForeignContract,
    phase: &GraphPhase,
    phase_name: &str,
) -> Result<(), MigrationError> {
    let component_ids = phase
        .components
        .iter()
        .map(|component| component.id.clone())
        .collect::<BTreeSet<_>>();
    let assumptions = phase
        .assumptions
        .iter()
        .map(|assumption| (assumption.id.clone(), assumption.kind.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let native_components = phase
        .components
        .iter()
        .filter(|component| component.kind == "native-component")
        .collect::<Vec<_>>();
    if phase_name == "baseline" && !native_components.is_empty()
        || phase_name == "migrated" && native_components.len() != 1
    {
        return Err(invalid(
            "FB-GRAPH-MIGRATION",
            "native component phase differs",
        ));
    }
    for claim in &phase.claims {
        let Some(component) = phase
            .components
            .iter()
            .find(|component| component.id == claim.component_id)
        else {
            return Err(invalid("FB-GRAPH-CLAIM", "claim component is absent"));
        };
        if claim
            .dependencies
            .iter()
            .any(|dependency| !component_ids.contains(dependency))
        {
            return Err(invalid("FB-GRAPH-DEPENDENCY", "claim dependency is absent"));
        }
        if claim
            .assumptions
            .iter()
            .any(|assumption| !assumptions.contains_key(assumption))
        {
            return Err(invalid("FB-GRAPH-ASSUMPTION", "claim assumption is absent"));
        }
        if component.kind == "native-component" {
            if component.artifact_identity.as_deref() != Some(EXPECTED_ARTIFACT_IDENTITY) {
                return Err(invalid("FB-ARTIFACT-BINDING", "native component differs"));
            }
            if claim.formal != "proved-finite-type" {
                return Err(invalid(
                    "FB-GRAPH-NATIVE-UPGRADE",
                    "native formal scope differs",
                ));
            }
            if claim.artifact != "assumption-bound" {
                return Err(invalid(
                    "FB-GRAPH-NATIVE-UPGRADE",
                    "native artifact scope differs",
                ));
            }
            if claim.evidence != ["evidence:native-certificate"] {
                return Err(invalid("FB-GRAPH-COERCION", "native evidence differs"));
            }
            if claim.assumptions.len() != 1
                || assumptions.get(&claim.assumptions[0]).map(String::as_str)
                    != Some("compiler-correspondence")
            {
                return Err(invalid("FB-GRAPH-ASSUMPTION", "native assumption differs"));
            }
        } else if !claim.dependencies.is_empty() {
            if claim.formal != "tested" {
                return Err(invalid(
                    "FB-GRAPH-FOREIGN-UPGRADE",
                    "foreign formal scope differs",
                ));
            }
            let expected_artifact = if phase_name == "migrated" {
                "artifact-bound"
            } else {
                "unbound"
            };
            if claim.artifact != expected_artifact {
                return Err(invalid(
                    "FB-GRAPH-COERCION",
                    "foreign artifact scope differs",
                ));
            }
            let expected_evidence = format!("evidence:{}-{phase_name}-calls", component.language);
            if claim.evidence != [expected_evidence] {
                return Err(invalid("FB-GRAPH-COERCION", "foreign evidence differs"));
            }
            let required_kinds = if phase_name == "migrated" {
                ["foreign-bridge", "foreign-runtime"]
            } else {
                ["foreign-implementation", "foreign-runtime"]
            };
            let actual_kinds = claim
                .assumptions
                .iter()
                .filter_map(|id| assumptions.get(id).map(String::as_str))
                .collect::<BTreeSet<_>>();
            if actual_kinds != required_kinds.into_iter().collect() {
                return Err(invalid("FB-GRAPH-ASSUMPTION", "foreign assumptions differ"));
            }
            if phase_name == "migrated"
                && claim.dependencies
                    != native_components
                        .iter()
                        .map(|item| item.id.clone())
                        .collect::<Vec<_>>()
            {
                return Err(invalid("FB-GRAPH-DEPENDENCY", "native dependency differs"));
            }
        } else if claim.formal != "tested"
            || claim.artifact != "unbound"
            || !claim.assumptions.is_empty()
        {
            return Err(invalid("FB-GRAPH-UNAFFECTED", "independent claim differs"));
        }
    }
    if phase_name == "migrated" && contract.artifact.identity != EXPECTED_ARTIFACT_IDENTITY {
        return Err(invalid("FB-ARTIFACT-BINDING", "contract artifact differs"));
    }
    Ok(())
}

fn derive_graph_report(
    phase_name: &str,
    phase: &GraphPhase,
) -> Result<GraphReport, MigrationError> {
    let derivations = phase
        .claims
        .iter()
        .map(|claim| {
            let mut inputs = claim.evidence.clone();
            inputs.extend(claim.dependencies.clone());
            inputs.extend(claim.assumptions.clone());
            inputs.sort();
            let mut derivation = Derivation {
                claim_id: claim.id.clone(),
                inputs,
                formal: claim.formal.clone(),
                artifact: claim.artifact.clone(),
                identity: String::new(),
            };
            derivation.identity =
                hash_value("proofbound-research-mixed-derivation/1", &derivation)?;
            Ok(derivation)
        })
        .collect::<Result<Vec<_>, MigrationError>>()?;
    let mut report = GraphReport {
        phase: phase_name.to_owned(),
        components: phase
            .components
            .iter()
            .map(|component| ComponentReport {
                id: component.id.clone(),
                kind: component.kind.clone(),
                artifact_identity: component.artifact_identity.clone(),
            })
            .collect(),
        assumptions: phase
            .assumptions
            .iter()
            .map(|assumption| assumption.id.clone())
            .collect(),
        derivations,
        identity: String::new(),
    };
    report.identity = graph_report_identity(&report)?;
    Ok(report)
}

fn validate_model_report(
    contract: &ForeignContract,
    cases: &ForeignCases,
    graphs: &GraphTemplates,
    envelope: &ForeignObservationEnvelope,
    attacks: &AttackCorpus,
    report: &MixedModelReport,
) -> Result<(), MigrationError> {
    if report.schema != MIXED_MODEL_REPORT_SCHEMA {
        return Err(invalid("FB-SCHEMA", "model report schema differs"));
    }
    let expected = derive_report(contract, cases, graphs, envelope, attacks)?;
    if report.baseline.derivations != expected.baseline.derivations
        || report.migrated.derivations != expected.migrated.derivations
    {
        return Err(invalid("FB-GRAPH-DERIVATION", "derivation trace differs"));
    }
    if report.baseline.identity != graph_report_identity(&report.baseline)?
        || report.migrated.identity != graph_report_identity(&report.migrated)?
    {
        return Err(invalid(
            "FB-GRAPH-IDENTITY",
            "graph report identity differs",
        ));
    }
    let identity = report_identity(report)?;
    if report.identity != identity
        || report.repetition_identities.len() != 10
        || report
            .repetition_identities
            .iter()
            .any(|candidate| candidate != &identity)
    {
        return Err(invalid(
            "FB-REPORT-IDENTITY",
            "model report identity differs",
        ));
    }
    let mut normalized = report.clone();
    normalized.repetition_identities.clear();
    let mut expected_normalized = expected;
    expected_normalized.repetition_identities.clear();
    if normalized != expected_normalized {
        return Err(invalid("FB-REPORT-IDENTITY", "model report differs"));
    }
    Ok(())
}

fn execute_attack(
    contract: &ForeignContract,
    cases: &ForeignCases,
    graphs: &GraphTemplates,
    envelope: &ForeignObservationEnvelope,
    attack: &Attack,
) -> Result<AttackResult, MigrationError> {
    let mut candidate_contract = contract.clone();
    let mut candidate_cases = cases.clone();
    let mut candidate_graphs = graphs.clone();
    let mut candidate_envelope = envelope.clone();
    let actual = match attack.action.as_str() {
        "noncanonical-contract" => "FB-NONCANONICAL".to_owned(),
        "forge-graph-identity" | "replace-derivation-input" | "forge-report-identity" => {
            let mut report = derive_report(
                contract,
                cases,
                graphs,
                envelope,
                &AttackCorpus {
                    schema: ATTACKS_SCHEMA.to_owned(),
                    attacks: Vec::new(),
                },
            )?;
            if attack.action == "forge-graph-identity" {
                report.migrated.identity = zero_sha();
            } else if attack.action == "replace-derivation-input" {
                report.migrated.derivations[0]
                    .inputs
                    .push("dependency:forged".to_owned());
            } else {
                report.identity = zero_sha();
            }
            validate_model_report(
                contract,
                cases,
                graphs,
                envelope,
                &AttackCorpus {
                    schema: ATTACKS_SCHEMA.to_owned(),
                    attacks: Vec::new(),
                },
                &report,
            )
            .err()
            .map_or_else(|| "FB-ACCEPTED".to_owned(), |error| error.code.to_owned())
        }
        action => {
            mutate_program(
                &mut candidate_contract,
                &mut candidate_cases,
                &mut candidate_graphs,
                &mut candidate_envelope,
                action,
            )?;
            validate_program(
                &candidate_contract,
                &candidate_cases,
                &candidate_graphs,
                &candidate_envelope,
            )
            .err()
            .map_or_else(|| "FB-ACCEPTED".to_owned(), |error| error.code.to_owned())
        }
    };
    Ok(AttackResult {
        id: attack.id.clone(),
        expected_code: attack.expected.clone(),
        exact: actual == attack.expected,
        actual_code: actual,
    })
}

fn mutate_program(
    contract: &mut ForeignContract,
    cases: &mut ForeignCases,
    graphs: &mut GraphTemplates,
    envelope: &mut ForeignObservationEnvelope,
    action: &str,
) -> Result<(), MigrationError> {
    match action {
        "replace-contract-schema" => {
            contract.schema = "proofbound-research-foreign-contract/2".to_owned()
        }
        "replace-abi-version" => contract.abi_version = 2,
        "add-operation" => contract.operations.push("inspect".to_owned()),
        "replace-encoding" => contract.response_encoding = "host-object".to_owned(),
        "allow-exception" => contract.error_policy = "host-exception".to_owned(),
        "allow-callback" => contract.callback_policy = "allowed".to_owned(),
        "forge-contract-identity" => contract.identity = zero_sha(),
        "substitute-artifact" => {
            contract.artifact.hex.replace_range(16..18, "02");
            let artifact = decode_hex(&contract.artifact.hex)?;
            contract.artifact.sha256 = sha256_bytes(&artifact);
            contract.artifact.identity = domain_hash("proofbound-native-bytecode/1", &artifact);
            contract.identity = contract_identity(contract)?;
        }
        "remove-observation" => {
            envelope.observations.pop();
            envelope.identity = envelope_identity(envelope)?;
        }
        "add-observation" => {
            let mut extra = envelope.observations[0].clone();
            extra.language = "unregistered".to_owned();
            for call in &mut extra.calls {
                call.language = extra.language.clone();
                call.identity = call_identity(call)?;
            }
            extra.identity = observation_identity(&extra)?;
            envelope.observations.push(extra);
            envelope.identity = envelope_identity(envelope)?;
        }
        "duplicate-observation" => {
            envelope.observations.push(envelope.observations[0].clone());
            envelope.identity = envelope_identity(envelope)?;
        }
        "substitute-observation" => {
            cases.cases[0].expected.error = Some("substituted".to_owned());
            for observation in &mut envelope.observations {
                observation.calls[0].error = Some("substituted".to_owned());
                observation.calls[0].identity = call_identity(&observation.calls[0])?;
                observation.identity = observation_identity(observation)?;
            }
            envelope.identity = envelope_identity(envelope)?;
        }
        "replace-runtime" => {
            envelope.observations[0]
                .runtime
                .version
                .push_str("-changed");
            envelope.observations[0].identity = observation_identity(&envelope.observations[0])?;
            envelope.identity = envelope_identity(envelope)?;
        }
        "replace-language" => {
            envelope.observations[0].language = "unregistered".to_owned();
            for call in &mut envelope.observations[0].calls {
                call.language = "unregistered".to_owned();
                call.identity = call_identity(call)?;
            }
            envelope.observations[0].identity = observation_identity(&envelope.observations[0])?;
            envelope.identity = envelope_identity(envelope)?;
        }
        "duplicate-component" => graphs
            .migrated
            .components
            .push(graphs.migrated.components[0].clone()),
        "remove-dependency" => {
            let claim = graphs
                .migrated
                .claims
                .iter_mut()
                .find(|claim| !claim.dependencies.is_empty())
                .ok_or_else(|| invalid("FB-GRAPH-DEPENDENCY", "dependent claim is absent"))?;
            claim.dependencies.clear();
        }
        "replace-claim-component" => {
            graphs.migrated.claims[0].component_id = "component:missing".to_owned()
        }
        "remove-runtime-assumption" => {
            let index = graphs
                .migrated
                .assumptions
                .iter()
                .position(|assumption| assumption.kind == "foreign-runtime")
                .ok_or_else(|| invalid("FB-GRAPH-ASSUMPTION", "runtime assumption is absent"))?;
            graphs.migrated.assumptions.remove(index);
        }
        "coerce-evidence-family" => {
            let claim = graphs
                .migrated
                .claims
                .iter_mut()
                .find(|claim| !claim.dependencies.is_empty())
                .ok_or_else(|| invalid("FB-GRAPH-COERCION", "foreign claim is absent"))?;
            claim.evidence = vec!["evidence:theorem".to_owned()];
        }
        "upgrade-native-artifact" => {
            let claim = graphs
                .migrated
                .claims
                .iter_mut()
                .find(|claim| claim.formal == "proved-finite-type")
                .ok_or_else(|| invalid("FB-GRAPH-NATIVE-UPGRADE", "native claim is absent"))?;
            claim.artifact = "proved".to_owned();
        }
        "upgrade-foreign-formal" => {
            let claim = graphs
                .migrated
                .claims
                .iter_mut()
                .find(|claim| claim.formal == "tested" && !claim.dependencies.is_empty())
                .ok_or_else(|| invalid("FB-GRAPH-FOREIGN-UPGRADE", "foreign claim is absent"))?;
            claim.formal = "proved".to_owned();
        }
        "rewrite-unaffected" => graphs.migrated.claims[0].formal = "proved".to_owned(),
        "omit-affected-claim" => {
            graphs.migration.affected_claims.pop();
        }
        "change-public-contract" => {
            let caller_id = graphs
                .baseline
                .claims
                .iter()
                .find(|claim| !claim.dependencies.is_empty())
                .map(|claim| &claim.id)
                .ok_or_else(|| invalid("FB-GRAPH-PUBLIC-CLAIM", "caller claim is absent"))?;
            graphs
                .public_contracts
                .iter_mut()
                .find(|item| &item.claim_id == caller_id)
                .ok_or_else(|| invalid("FB-GRAPH-PUBLIC-CLAIM", "public claim is absent"))?
                .statement
                .push_str(" changed");
        }
        "caller-disagreement" => {
            envelope.observations[0].calls[0].error = Some("disagreement".to_owned());
            envelope.observations[0].calls[0].identity =
                call_identity(&envelope.observations[0].calls[0])?;
            envelope.observations[0].identity = observation_identity(&envelope.observations[0])?;
            envelope.identity = envelope_identity(envelope)?;
        }
        "phase-disagreement" => {
            for observation in envelope
                .observations
                .iter_mut()
                .filter(|observation| observation.phase == "migrated")
            {
                observation.calls[0].error = Some("phase-drift".to_owned());
                observation.calls[0].identity = call_identity(&observation.calls[0])?;
                observation.identity = observation_identity(observation)?;
            }
            envelope.identity = envelope_identity(envelope)?;
        }
        _ => return Err(invalid("FB-SCHEMA", "unknown attack action")),
    }
    Ok(())
}

fn evaluate_case(artifact: &[u8], case: &ForeignCase) -> Result<CallResult, MigrationError> {
    if case.operation == "encode" {
        let Some(value) = case.input_value else {
            return Err(invalid("FB-ABI-ENCODING", "encode value is absent"));
        };
        if case.input_hex.is_some() || value > artifact[18] {
            return Err(invalid("FB-ABI-ENCODING", "encode input differs"));
        }
        return Ok(CallResult {
            accepted: true,
            value: Some(value),
            output_hex: Some(format!("{:02x}{value:02x}", artifact[8])),
            error: None,
            consumed: 0,
        });
    }
    let Some(input_hex) = &case.input_hex else {
        return Err(invalid("FB-ABI-ENCODING", "decode bytes are absent"));
    };
    if case.input_value.is_some() {
        return Err(invalid("FB-ABI-ENCODING", "decode value is present"));
    }
    let input = decode_hex(input_hex)?;
    let result = if input.len() != artifact[12] as usize {
        (false, None, None, Some("invalid-length".to_owned()))
    } else if input[artifact[14] as usize] != artifact[15] {
        (false, None, None, Some("invalid-prefix".to_owned()))
    } else if input[artifact[17] as usize] > artifact[18] {
        (false, None, None, Some("invalid-payload".to_owned()))
    } else {
        let value = input[artifact[20] as usize];
        (true, Some(value), Some(encode_hex(&input)), None)
    };
    Ok(CallResult {
        accepted: result.0,
        value: result.1,
        output_hex: result.2,
        error: result.3,
        consumed: input.len() as u64,
    })
}

fn semantic_results(observation: &ForeignObservationSet) -> Vec<CallResult> {
    observation.calls.iter().map(call_result).collect()
}

fn call_result(call: &ForeignCall) -> CallResult {
    CallResult {
        accepted: call.accepted,
        value: call.value,
        output_hex: call.output_hex.clone(),
        error: call.error.clone(),
        consumed: call.consumed,
    }
}

fn observation_keys(observations: &[ForeignObservationSet]) -> Vec<String> {
    observations
        .iter()
        .map(|observation| format!("{}:{}", observation.language, observation.phase))
        .collect()
}

fn contract_identity(contract: &ForeignContract) -> Result<String, MigrationError> {
    let mut candidate = contract.clone();
    candidate.identity.clear();
    hash_value(FOREIGN_CONTRACT_SCHEMA, &candidate)
}

fn call_identity(call: &ForeignCall) -> Result<String, MigrationError> {
    let mut candidate = call.clone();
    candidate.identity.clear();
    hash_value(FOREIGN_CALL_SCHEMA, &candidate)
}

fn observation_identity(observation: &ForeignObservationSet) -> Result<String, MigrationError> {
    let mut candidate = observation.clone();
    candidate.identity.clear();
    hash_value(FOREIGN_OBSERVATIONS_SCHEMA, &candidate)
}

fn envelope_identity(envelope: &ForeignObservationEnvelope) -> Result<String, MigrationError> {
    let mut candidate = envelope.clone();
    candidate.identity.clear();
    hash_value(OBSERVATION_ENVELOPE_SCHEMA, &candidate)
}

fn graph_report_identity(report: &GraphReport) -> Result<String, MigrationError> {
    let mut candidate = report.clone();
    candidate.identity.clear();
    hash_value(MIXED_GRAPH_SCHEMA, &candidate)
}

fn report_identity(report: &MixedModelReport) -> Result<String, MigrationError> {
    let mut candidate = report.clone();
    candidate.identity.clear();
    candidate.repetition_identities.clear();
    hash_value(MIXED_MODEL_REPORT_SCHEMA, &candidate)
}

fn hash_value<T: Serialize>(domain: &str, value: &T) -> Result<String, MigrationError> {
    canonical_json(value)
        .map(|bytes| domain_hash(domain, &bytes))
        .map_err(|error| invalid("FB-NONCANONICAL", error.to_string()))
}

fn validate_attack_corpus(corpus: &AttackCorpus) -> Result<(), MigrationError> {
    let ids = corpus
        .attacks
        .iter()
        .map(|attack| attack.id.clone())
        .collect::<Vec<_>>();
    if corpus.schema != ATTACKS_SCHEMA || corpus.attacks.len() != 30 || !strict_sorted_unique(&ids)
    {
        return Err(invalid("FB-SCHEMA", "attack corpus differs"));
    }
    Ok(())
}

fn strict_sorted_unique(values: &[String]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn has_duplicates<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() != values.len()
}

fn valid_sha(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, MigrationError> {
    if !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("FB-ABI-ENCODING", "hex encoding differs"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| invalid("FB-ABI-ENCODING", "hex byte differs"))
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn zero_sha() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn decode_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
) -> Result<T, MigrationError> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| invalid("FB-NONCANONICAL", error.to_string()))?;
    let encoded =
        canonical_json(&value).map_err(|error| invalid("FB-NONCANONICAL", error.to_string()))?;
    if encoded != bytes {
        return Err(invalid("FB-NONCANONICAL", "canonical JSON differs"));
    }
    Ok(value)
}

fn decode_control<T: for<'de> Deserialize<'de>>(
    root: &Path,
    path: &Path,
) -> Result<T, MigrationError> {
    serde_json::from_slice(
        &fs::read(root.join(path)).map_err(|error| invalid("FB-SCHEMA", error.to_string()))?,
    )
    .map_err(|error| invalid("FB-SCHEMA", error.to_string()))
}

#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;
