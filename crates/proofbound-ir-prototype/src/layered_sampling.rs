use std::{collections::BTreeSet, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assurance::decode_strict_json;

const CASE_SCHEMA: &str = "proofbound-layered-sampling-case/1";
const INTENT_SCHEMA: &str = "proofbound-sampling-intent/1";
const PLAN_SCHEMA: &str = "proofbound-backend-sampling-plan/1";
const OBSERVATION_SCHEMA: &str = "proofbound-layered-sampling-observation/1";
const RULE_SCHEMA: &str = "proofbound-sampling-admission-rule/1";
const INTENT_DOMAIN: &str = "proofbound-sampling-intent/1";
const PLAN_DOMAIN: &str = "proofbound-backend-sampling-plan/1";
const GENERATOR_DOMAIN: &str = "proofbound-generator-closure/1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayeredSamplingError {
    pub code: &'static str,
    pub message: String,
}

impl LayeredSamplingError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for LayeredSamplingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LayeredSamplingError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayeredSamplingCase {
    schema: String,
    intent: SamplingIntent,
    intent_identity: String,
    plan: BackendSamplingPlan,
    plan_identity: String,
    observation: LayeredSamplingObservation,
    admission_rule: AdmissionRule,
}

impl LayeredSamplingCase {
    pub fn targets(&self) -> &[String] {
        &self.intent.targets
    }

    pub fn intent_identity(&self) -> &str {
        &self.intent_identity
    }

    pub fn plan_identity(&self) -> &str {
        &self.plan_identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SamplingIntent {
    schema: String,
    seed: Seed,
    successful_cases: u64,
    generator: Generator,
    targets: Vec<String>,
    persistence: Persistence,
    ceiling: AssuranceCeiling,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    encoding: SeedEncoding,
    value: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SeedEncoding {
    DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Generator {
    entrypoint: String,
    closure: Vec<ArtifactIdentity>,
    identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    logical_name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
enum Persistence {
    Disabled,
    ReadOnlyBound { artifact: ArtifactIdentity },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AssuranceCeiling {
    EmpiricalSample,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "backend", rename_all = "kebab-case")]
enum BackendSamplingPlan {
    Hypothesis {
        schema: String,
        version: String,
        phases: Vec<String>,
        database: String,
        shrinking: String,
        capabilities: FactCapabilities,
    },
    FastCheck {
        schema: String,
        version: String,
        random_type: String,
        examples: Vec<Value>,
        skip_limit: u64,
        shrinking: String,
        capabilities: FactCapabilities,
    },
    Proptest {
        schema: String,
        version: String,
        rng_algorithm: String,
        max_local_rejects: u64,
        max_global_rejects: u64,
        max_shrink_iters: u64,
        capabilities: FactCapabilities,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FactCapabilities {
    attempted: FactAuthority,
    completed: FactAuthority,
    skipped: FactAuthority,
    shrinks: FactAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FactAuthority {
    Observed,
    Derived,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LayeredSamplingObservation {
    schema: String,
    intent_identity: String,
    plan_identity: String,
    targets: Vec<String>,
    attempted: Option<Fact>,
    completed: Option<Fact>,
    skipped: Option<Fact>,
    shrinks: Option<Fact>,
    result: SamplingResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "authority", rename_all = "kebab-case")]
enum Fact {
    Observed {
        value: u64,
        source: String,
    },
    Derived {
        value: u64,
        rule: DerivationRule,
        dependencies: Vec<String>,
    },
    Unavailable {
        reason: String,
    },
}

impl Fact {
    fn authority(&self) -> FactAuthority {
        match self {
            Self::Observed { .. } => FactAuthority::Observed,
            Self::Derived { .. } => FactAuthority::Derived,
            Self::Unavailable { .. } => FactAuthority::Unavailable,
        }
    }

    fn value(&self) -> Option<u64> {
        match self {
            Self::Observed { value, .. } | Self::Derived { value, .. } => Some(*value),
            Self::Unavailable { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DerivationRule {
    RunnerSuccessContract,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum SamplingResult {
    Passed,
    Counterexample { counterexample: Value },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRule {
    schema: String,
    id: String,
    required_facts: Vec<FactName>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FactName {
    Attempted,
    Completed,
    Skipped,
    Shrinks,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LayeredSamplingReport {
    pub schema: String,
    pub intent_identity: String,
    pub plan_identity: String,
    pub result: String,
    pub admitted: bool,
    pub alerts: Vec<String>,
}

pub fn validate_layered_sampling_case(
    root: &Path,
    bytes: &[u8],
) -> Result<LayeredSamplingReport, LayeredSamplingError> {
    let value = decode_canonical_value(bytes)?;
    if value.get("schema").and_then(Value::as_str) != Some(CASE_SCHEMA) {
        return Err(LayeredSamplingError::new(
            "sampling-schema-mismatch",
            "unsupported layered sampling case schema",
        ));
    }
    if value
        .get("intent")
        .and_then(Value::as_object)
        .is_some_and(|intent| {
            [
                "rng_algorithm",
                "phases",
                "database",
                "random_type",
                "skip_limit",
                "max_local_rejects",
                "max_global_rejects",
                "max_shrink_iters",
            ]
            .iter()
            .any(|field| intent.contains_key(*field))
        })
    {
        return Err(LayeredSamplingError::new(
            "sampling-layer-violation",
            "backend execution control appears in the common sampling intent",
        ));
    }
    let case: LayeredSamplingCase = serde_json::from_value(value)
        .map_err(|error| LayeredSamplingError::new("sampling-plan-invalid", error.to_string()))?;
    if case.schema != CASE_SCHEMA
        || case.intent.schema != INTENT_SCHEMA
        || case.observation.schema != OBSERVATION_SCHEMA
    {
        return Err(LayeredSamplingError::new(
            "sampling-schema-mismatch",
            "unsupported layered sampling schema",
        ));
    }
    validate_intent(root, &case.intent)?;
    let intent_identity = identity(INTENT_DOMAIN, &case.intent)?;
    if case.intent_identity != intent_identity
        || case.observation.intent_identity != intent_identity
    {
        return Err(LayeredSamplingError::new(
            "sampling-intent-identity-mismatch",
            "sampling intent identity differs",
        ));
    }

    let capabilities = validate_plan(&case.plan)?;
    let plan_identity = identity(PLAN_DOMAIN, &case.plan)?;
    if case.plan_identity != plan_identity || case.observation.plan_identity != plan_identity {
        return Err(LayeredSamplingError::new(
            "sampling-plan-identity-mismatch",
            "backend sampling plan identity differs",
        ));
    }
    if case.observation.targets != case.intent.targets {
        return Err(LayeredSamplingError::new(
            "sampling-inventory-mismatch",
            "observed targets differ from common intent",
        ));
    }
    validate_fact(
        case.observation.attempted.as_ref(),
        capabilities.attempted,
        FactName::Attempted,
    )?;
    validate_fact(
        case.observation.completed.as_ref(),
        capabilities.completed,
        FactName::Completed,
    )?;
    validate_fact(
        case.observation.skipped.as_ref(),
        capabilities.skipped,
        FactName::Skipped,
    )?;
    validate_fact(
        case.observation.shrinks.as_ref(),
        capabilities.shrinks,
        FactName::Shrinks,
    )?;
    validate_rule(&case.admission_rule)?;

    let result = match case.observation.result {
        SamplingResult::Passed => "passed",
        SamplingResult::Counterexample { .. } => "counterexample",
    };
    if matches!(
        case.observation.completed,
        Some(Fact::Derived {
            rule: DerivationRule::RunnerSuccessContract,
            ..
        })
    ) && result != "passed"
    {
        return Err(LayeredSamplingError::new(
            "sampling-derivation-incomplete",
            "runner-success derivation requires a passed typed result",
        ));
    }
    let mut alerts = Vec::new();
    for required in &case.admission_rule.required_facts {
        let fact = fact_by_name(&case.observation, required);
        if fact.and_then(Fact::value).is_none() {
            alerts.push(format!("required-fact-unavailable:{required:?}").to_lowercase());
        }
    }
    if result == "passed"
        && case.observation.completed.as_ref().and_then(Fact::value)
            != Some(case.intent.successful_cases)
    {
        alerts.push("completed-budget-not-established".to_owned());
    }
    if !alerts.is_empty() {
        return Err(LayeredSamplingError::new(
            "sampling-admission-blocked",
            alerts.join(","),
        ));
    }

    Ok(LayeredSamplingReport {
        schema: "proofbound-layered-sampling-validation/1".to_owned(),
        intent_identity,
        plan_identity,
        result: result.to_owned(),
        admitted: result == "passed",
        alerts,
    })
}

fn decode_canonical_value(bytes: &[u8]) -> Result<Value, LayeredSamplingError> {
    let document = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let value = decode_strict_json(document)
        .map_err(|error| LayeredSamplingError::new("sampling-schema-mismatch", error.message))?;
    let canonical = canonical_json(&value).map_err(invalid)?;
    if canonical != document {
        return Err(LayeredSamplingError::new(
            "sampling-schema-mismatch",
            "layered sampling case is not canonical JSON",
        ));
    }
    Ok(value)
}

fn validate_intent(root: &Path, intent: &SamplingIntent) -> Result<(), LayeredSamplingError> {
    if intent.successful_cases == 0 || intent.successful_cases > 1_000_000 {
        return Err(LayeredSamplingError::new(
            "sampling-intent-invalid",
            "successful-case budget is outside the bounded domain",
        ));
    }
    require_sorted_text(&intent.targets, "sampling targets")?;
    if intent.targets.is_empty() || intent.generator.closure.is_empty() {
        return Err(LayeredSamplingError::new(
            "sampling-intent-invalid",
            "targets and generator closure must be nonempty",
        ));
    }
    require_text(&intent.generator.entrypoint, "generator entrypoint")?;
    let mut names = Vec::new();
    for artifact in &intent.generator.closure {
        validate_artifact(root, artifact)?;
        names.push(artifact.logical_name.clone());
    }
    require_sorted_text(&names, "generator closure")?;
    let material = serde_json::json!({
        "closure": intent.generator.closure,
        "entrypoint": intent.generator.entrypoint,
    });
    let generator_identity = domain_hash(
        GENERATOR_DOMAIN,
        &canonical_json(&material).map_err(invalid)?,
    );
    if intent.generator.identity_sha256 != generator_identity {
        return Err(LayeredSamplingError::new(
            "generator-identity-mismatch",
            "generator identity differs",
        ));
    }
    if let Persistence::ReadOnlyBound { artifact } = &intent.persistence {
        validate_artifact(root, artifact)?;
    }
    Ok(())
}

fn validate_plan(plan: &BackendSamplingPlan) -> Result<&FactCapabilities, LayeredSamplingError> {
    match plan {
        BackendSamplingPlan::Hypothesis {
            schema,
            version,
            phases,
            database,
            shrinking,
            capabilities,
        } => {
            require_plan_schema(schema)?;
            require_text(version, "Hypothesis version")?;
            require_sorted_text(phases, "Hypothesis phases")?;
            require_text(database, "Hypothesis database policy")?;
            require_text(shrinking, "Hypothesis shrinking policy")?;
            Ok(capabilities)
        }
        BackendSamplingPlan::FastCheck {
            schema,
            version,
            random_type,
            skip_limit,
            shrinking,
            capabilities,
            ..
        } => {
            require_plan_schema(schema)?;
            require_text(version, "fast-check version")?;
            require_text(random_type, "fast-check random type")?;
            require_text(shrinking, "fast-check shrinking policy")?;
            if *skip_limit > 1_000_000 {
                return Err(LayeredSamplingError::new(
                    "sampling-plan-invalid",
                    "fast-check skip limit is outside the bounded domain",
                ));
            }
            Ok(capabilities)
        }
        BackendSamplingPlan::Proptest {
            schema,
            version,
            rng_algorithm,
            max_local_rejects,
            max_global_rejects,
            max_shrink_iters,
            capabilities,
        } => {
            require_plan_schema(schema)?;
            require_text(version, "proptest version")?;
            require_text(rng_algorithm, "proptest RNG algorithm")?;
            if *max_local_rejects == 0 || *max_global_rejects == 0 || *max_shrink_iters == 0 {
                return Err(LayeredSamplingError::new(
                    "sampling-plan-invalid",
                    "proptest rejection and shrink limits must be nonzero",
                ));
            }
            Ok(capabilities)
        }
    }
}

fn validate_fact(
    fact: Option<&Fact>,
    expected: FactAuthority,
    name: FactName,
) -> Result<(), LayeredSamplingError> {
    let Some(fact) = fact else {
        return Ok(());
    };
    if fact.authority() != expected {
        return Err(LayeredSamplingError::new(
            "sampling-authority-mismatch",
            format!("{name:?} fact authority differs from backend capability"),
        ));
    }
    match fact {
        Fact::Observed { source, .. } => require_text(source, "observation source"),
        Fact::Unavailable { reason } => require_text(reason, "unavailable reason"),
        Fact::Derived {
            rule, dependencies, ..
        } => {
            let expected_dependencies = match rule {
                DerivationRule::RunnerSuccessContract => [
                    "intent.successful-cases".to_owned(),
                    "result.passed".to_owned(),
                ],
            };
            if dependencies.as_slice() != expected_dependencies {
                return Err(LayeredSamplingError::new(
                    "sampling-derivation-incomplete",
                    "derived fact dependencies differ from the closed derivation rule",
                ));
            }
            Ok(())
        }
    }
}

fn validate_rule(rule: &AdmissionRule) -> Result<(), LayeredSamplingError> {
    if rule.schema != RULE_SCHEMA || rule.id != "empirical-sample-pass" {
        return Err(LayeredSamplingError::new(
            "sampling-rule-overreach",
            "unsupported sampling admission rule",
        ));
    }
    if rule.required_facts != [FactName::Completed] {
        return Err(LayeredSamplingError::new(
            "sampling-rule-overreach",
            "empirical sample admission consumes only the completed-case fact",
        ));
    }
    Ok(())
}

fn fact_by_name<'a>(
    observation: &'a LayeredSamplingObservation,
    name: &FactName,
) -> Option<&'a Fact> {
    match name {
        FactName::Attempted => observation.attempted.as_ref(),
        FactName::Completed => observation.completed.as_ref(),
        FactName::Skipped => observation.skipped.as_ref(),
        FactName::Shrinks => observation.shrinks.as_ref(),
    }
}

fn require_plan_schema(schema: &str) -> Result<(), LayeredSamplingError> {
    if schema != PLAN_SCHEMA {
        return Err(LayeredSamplingError::new(
            "sampling-schema-mismatch",
            "unsupported backend sampling plan schema",
        ));
    }
    Ok(())
}

fn validate_artifact(root: &Path, artifact: &ArtifactIdentity) -> Result<(), LayeredSamplingError> {
    require_text(&artifact.logical_name, "artifact path")?;
    let relative = Path::new(&artifact.logical_name);
    if relative.is_absolute()
        || artifact.logical_name.contains('\\')
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(LayeredSamplingError::new(
            "generator-identity-mismatch",
            "artifact path is not normalized",
        ));
    }
    let canonical_root = root.canonicalize().map_err(generator_io)?;
    let resolved = root.join(relative).canonicalize().map_err(generator_io)?;
    if !resolved.starts_with(canonical_root) {
        return Err(LayeredSamplingError::new(
            "generator-identity-mismatch",
            "artifact path escapes the repository",
        ));
    }
    let bytes = fs::read(resolved).map_err(generator_io)?;
    if artifact.sha256 != sha256_bytes(&bytes) || artifact.size_bytes != bytes.len() as u64 {
        return Err(LayeredSamplingError::new(
            "generator-identity-mismatch",
            format!("artifact bytes differ at {}", artifact.logical_name),
        ));
    }
    Ok(())
}

fn require_text(value: &str, label: &str) -> Result<(), LayeredSamplingError> {
    if value.trim().is_empty()
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(LayeredSamplingError::new(
            "sampling-plan-invalid",
            format!("{label} is not bounded non-control text"),
        ));
    }
    Ok(())
}

fn require_sorted_text(values: &[String], label: &str) -> Result<(), LayeredSamplingError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_text(value, label)?;
        if !seen.insert(value) {
            return Err(LayeredSamplingError::new(
                "sampling-plan-invalid",
                format!("{label} contains a duplicate"),
            ));
        }
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(LayeredSamplingError::new(
            "sampling-plan-invalid",
            format!("{label} is not strictly sorted"),
        ));
    }
    Ok(())
}

fn identity<T: Serialize>(domain: &str, value: &T) -> Result<String, LayeredSamplingError> {
    Ok(domain_hash(
        domain,
        &canonical_json(value).map_err(invalid)?,
    ))
}

fn invalid(error: impl std::fmt::Display) -> LayeredSamplingError {
    LayeredSamplingError::new("sampling-schema-mismatch", error.to_string())
}

fn generator_io(error: impl std::fmt::Display) -> LayeredSamplingError {
    LayeredSamplingError::new("generator-identity-mismatch", error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use proofbound_evidence::{canonical_json, domain_hash};
    use serde_json::{Value, json};

    use super::{PLAN_DOMAIN, validate_layered_sampling_case};

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    fn base_case(backend: &str) -> Value {
        let path = root().join(format!(
            "docs/experiments/0008-layered-sampling-model/corpus/{backend}.json"
        ));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn validate(
        value: &Value,
    ) -> Result<super::LayeredSamplingReport, super::LayeredSamplingError> {
        validate_layered_sampling_case(&root(), &canonical_json(value).unwrap())
    }

    fn rehash_plan(case: &mut Value) {
        let identity = domain_hash(PLAN_DOMAIN, &canonical_json(&case["plan"]).unwrap());
        case["plan_identity"] = Value::String(identity.clone());
        case["observation"]["plan_identity"] = Value::String(identity);
    }

    #[test]
    fn admits_three_frameworks_without_inventing_unavailable_facts() {
        for backend in ["hypothesis", "fast-check", "proptest"] {
            let report = validate(&base_case(backend)).unwrap();
            assert!(report.admitted);
            assert!(report.alerts.is_empty());
        }
    }

    #[test]
    fn rejects_preregistered_layer_and_plan_attacks() {
        let attacks = [
            ("EXP-0008-A001", "sampling-layer-violation"),
            ("EXP-0008-A002", "sampling-plan-invalid"),
            ("EXP-0008-A003", "sampling-plan-identity-mismatch"),
            ("EXP-0008-A004", "sampling-authority-mismatch"),
            ("EXP-0008-A005", "sampling-authority-mismatch"),
            ("EXP-0008-A006", "sampling-derivation-incomplete"),
            ("EXP-0008-A007", "sampling-admission-blocked"),
            ("EXP-0008-A008", "sampling-rule-overreach"),
            ("EXP-0008-A010", "sampling-inventory-mismatch"),
            ("EXP-0008-A011", "sampling-schema-mismatch"),
            ("EXP-0008-A012", "sampling-schema-mismatch"),
        ];
        for (id, expected) in attacks {
            let mut case = base_case("proptest");
            match id {
                "EXP-0008-A001" => case["intent"]["rng_algorithm"] = json!("chacha"),
                "EXP-0008-A002" => {
                    case["plan"]
                        .as_object_mut()
                        .unwrap()
                        .remove("rng_algorithm");
                    rehash_plan(&mut case);
                }
                "EXP-0008-A003" => case["plan"]["rng_algorithm"] = json!("xorshift"),
                "EXP-0008-A004" => {
                    case["observation"]["completed"] = json!({
                        "authority": "observed", "value": 100, "source": "runner-success"
                    });
                }
                "EXP-0008-A005" => {
                    case["observation"]["shrinks"] = json!({
                        "authority": "observed", "value": 0, "source": "invented-zero"
                    });
                }
                "EXP-0008-A006" => {
                    case["observation"]["completed"]["dependencies"] = json!(["result.passed"]);
                }
                "EXP-0008-A007" => {
                    case["plan"]["capabilities"]["completed"] = json!("unavailable");
                    rehash_plan(&mut case);
                    case["observation"]["completed"] = json!({
                        "authority": "unavailable",
                        "reason": "runner completion could not be established"
                    });
                }
                "EXP-0008-A008" => {
                    case["admission_rule"]["required_facts"] = json!(["completed", "shrinks"]);
                }
                "EXP-0008-A010" => {
                    case["observation"]["targets"] = json!(["proptest::substituted"]);
                }
                "EXP-0008-A011" => {
                    case["schema"] = json!("proofbound-sampling-observation/1");
                }
                "EXP-0008-A012" => case["schema"] = json!("legacy-backend-sampling/1"),
                _ => unreachable!(),
            }
            let error = validate(&case).unwrap_err();
            assert_eq!(error.code, expected, "{id}: {}", error.message);
        }
    }

    #[test]
    fn unused_shrink_telemetry_has_no_admission_consequence() {
        let mut case = base_case("proptest");
        case["observation"]
            .as_object_mut()
            .unwrap()
            .remove("shrinks");
        let report = validate(&case).unwrap();
        assert!(report.admitted);
        assert!(report.alerts.is_empty());
    }
}
