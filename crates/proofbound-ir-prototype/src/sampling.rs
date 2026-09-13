use std::{collections::BTreeSet, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assurance::decode_strict_json;

const CONTRACT_SCHEMA: &str = "proofbound-sampling-contract/1";
const OBSERVATION_SCHEMA: &str = "proofbound-sampling-observation/1";
const GENERATOR_DOMAIN: &str = "proofbound-generator-closure/1";
const CONTRACT_DOMAIN: &str = "proofbound-sampling-contract/1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SamplingValidationError {
    pub code: &'static str,
    pub message: String,
}

impl SamplingValidationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SamplingValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SamplingValidationError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingContract {
    schema: String,
    framework: Framework,
    seed: Seed,
    successful_cases: u64,
    generator: Generator,
    targets: Vec<String>,
    replay: ReplayPolicy,
    persistence: PersistencePolicy,
    shrinking: ShrinkingPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Framework {
    name: String,
    version: String,
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
#[serde(rename_all = "kebab-case")]
enum ReplayPolicy {
    FreshOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PersistencePolicy {
    Disabled,
    AmbientWritableDatabase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ShrinkingPolicy {
    Disabled,
    Enabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingObservation {
    schema: String,
    contract: SamplingContract,
    contract_identity: String,
    actual_seed: Seed,
    attempted_cases: u64,
    completed_cases: u64,
    skipped_cases: u64,
    shrink_count: u64,
    targets: Vec<String>,
    result: SamplingResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum SamplingResult {
    Passed,
    Counterexample {
        counterexample: Value,
        failure_kind: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamplingValidationReport {
    pub schema: String,
    pub framework: String,
    pub framework_version: String,
    pub contract_identity: String,
    pub generator_identity: String,
    pub result: String,
}

pub fn validate_sampling_observation(
    root: &Path,
    contract_bytes: &[u8],
    observation_bytes: &[u8],
) -> Result<SamplingValidationReport, SamplingValidationError> {
    let contract: SamplingContract = decode_canonical(contract_bytes, "sampling contract", true)?;
    let observation: SamplingObservation =
        decode_canonical(observation_bytes, "sampling observation", false)?;
    validate_contract(root, &contract)?;
    if contract.schema != CONTRACT_SCHEMA || observation.schema != OBSERVATION_SCHEMA {
        return Err(SamplingValidationError::new(
            "sampling-schema-mismatch",
            "unsupported sampling contract or observation schema",
        ));
    }
    if observation.contract.framework != contract.framework {
        return Err(SamplingValidationError::new(
            "sampling-tool-mismatch",
            "observed framework differs from registration",
        ));
    }
    if observation.contract.generator != contract.generator {
        return Err(SamplingValidationError::new(
            "generator-identity-mismatch",
            "observed generator differs from registration",
        ));
    }
    if observation.contract.targets != contract.targets || observation.targets != contract.targets {
        return Err(SamplingValidationError::new(
            "sampling-inventory-mismatch",
            "observed targets differ from registration",
        ));
    }
    if observation.contract != contract {
        return Err(SamplingValidationError::new(
            "sampling-contract-mismatch",
            "observed sampling contract differs from registration",
        ));
    }
    let contract_identity = domain_hash(
        CONTRACT_DOMAIN,
        &canonical_json(&contract).map_err(report_invalid)?,
    );
    if observation.contract_identity != contract_identity
        || observation.actual_seed != contract.seed
    {
        return Err(SamplingValidationError::new(
            "sampling-contract-mismatch",
            "observed contract identity or actual seed differs",
        ));
    }
    if matches!(contract.shrinking, ShrinkingPolicy::Disabled) && observation.shrink_count != 0 {
        return Err(SamplingValidationError::new(
            "sampling-contract-mismatch",
            "disabled shrinking produced a shrink count",
        ));
    }
    let result = match observation.result {
        SamplingResult::Passed => {
            if observation.completed_cases != contract.successful_cases
                || observation.attempted_cases
                    != observation.completed_cases + observation.skipped_cases
            {
                return Err(SamplingValidationError::new(
                    "sampling-contract-mismatch",
                    "completed successful cases differ from registration",
                ));
            }
            "passed"
        }
        SamplingResult::Counterexample {
            ref failure_kind, ..
        } => {
            if observation.completed_cases >= contract.successful_cases
                || observation.attempted_cases
                    <= observation.completed_cases + observation.skipped_cases
            {
                return Err(SamplingValidationError::new(
                    "sampling-report-invalid",
                    "counterexample appears after the successful budget completed",
                ));
            }
            require_text(failure_kind, "counterexample failure kind")?;
            "counterexample"
        }
    };
    Ok(SamplingValidationReport {
        schema: "proofbound-sampling-validation/1".to_owned(),
        framework: contract.framework.name,
        framework_version: contract.framework.version,
        contract_identity,
        generator_identity: contract.generator.identity_sha256,
        result: result.to_owned(),
    })
}

fn decode_canonical<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    label: &str,
    allow_final_newline: bool,
) -> Result<T, SamplingValidationError> {
    let document = if allow_final_newline {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    } else {
        bytes
    };
    let value = decode_strict_json(document)
        .map_err(|error| SamplingValidationError::new("sampling-report-invalid", error.message))?;
    let canonical = canonical_json(&value).map_err(report_invalid)?;
    if canonical != document {
        return Err(SamplingValidationError::new(
            "sampling-report-invalid",
            format!("{label} is not canonical JSON"),
        ));
    }
    serde_json::from_value(value).map_err(|error| {
        SamplingValidationError::new(
            "sampling-report-invalid",
            format!("invalid {label}: {error}"),
        )
    })
}

fn validate_contract(
    root: &Path,
    contract: &SamplingContract,
) -> Result<(), SamplingValidationError> {
    if contract.schema != CONTRACT_SCHEMA {
        return Err(SamplingValidationError::new(
            "sampling-schema-mismatch",
            "unsupported sampling contract schema",
        ));
    }
    require_text(&contract.framework.name, "framework name")?;
    require_text(&contract.framework.version, "framework version")?;
    if !matches!(contract.persistence, PersistencePolicy::Disabled) {
        return Err(SamplingValidationError::new(
            "sampling-contract-mismatch",
            "ambient sampling persistence is forbidden",
        ));
    }
    require_text(&contract.generator.entrypoint, "generator entrypoint")?;
    if contract.successful_cases == 0 || contract.successful_cases > 1_000_000 {
        return Err(SamplingValidationError::new(
            "sampling-contract-mismatch",
            "successful case budget is outside the bounded domain",
        ));
    }
    require_sorted_unique(&contract.targets, "sampling targets")?;
    if contract.targets.is_empty() || contract.generator.closure.is_empty() {
        return Err(SamplingValidationError::new(
            "sampling-contract-mismatch",
            "targets and generator closure must be nonempty",
        ));
    }
    let mut prior = None;
    for artifact in &contract.generator.closure {
        validate_artifact(root, artifact)?;
        if prior
            .as_ref()
            .is_some_and(|name| name >= &artifact.logical_name)
        {
            return Err(SamplingValidationError::new(
                "generator-identity-mismatch",
                "generator closure is not strictly sorted and unique",
            ));
        }
        prior = Some(artifact.logical_name.clone());
    }
    let material = serde_json::json!({
        "entrypoint": contract.generator.entrypoint,
        "closure": contract.generator.closure,
    });
    let identity = domain_hash(
        GENERATOR_DOMAIN,
        &canonical_json(&material).map_err(report_invalid)?,
    );
    if contract.generator.identity_sha256 != identity {
        return Err(SamplingValidationError::new(
            "generator-identity-mismatch",
            "generator closure identity differs",
        ));
    }
    Ok(())
}

fn validate_artifact(
    root: &Path,
    artifact: &ArtifactIdentity,
) -> Result<(), SamplingValidationError> {
    let path = Path::new(&artifact.logical_name);
    if path.is_absolute()
        || artifact.logical_name.contains('\\')
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(SamplingValidationError::new(
            "generator-identity-mismatch",
            "generator closure path is not normalized",
        ));
    }
    let canonical_root = root.canonicalize().map_err(generator_io)?;
    let resolved = root.join(path).canonicalize().map_err(generator_io)?;
    if !resolved.starts_with(&canonical_root) {
        return Err(SamplingValidationError::new(
            "generator-identity-mismatch",
            "generator closure path escapes the repository",
        ));
    }
    let bytes = fs::read(resolved).map_err(generator_io)?;
    if artifact.sha256 != sha256_bytes(&bytes) || artifact.size_bytes != bytes.len() as u64 {
        return Err(SamplingValidationError::new(
            "generator-identity-mismatch",
            format!(
                "generator closure bytes differ at {}",
                artifact.logical_name
            ),
        ));
    }
    Ok(())
}

fn require_text(value: &str, label: &str) -> Result<(), SamplingValidationError> {
    if value.trim().is_empty()
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(SamplingValidationError::new(
            "sampling-report-invalid",
            format!("{label} is not bounded non-control text"),
        ));
    }
    Ok(())
}

fn require_sorted_unique(values: &[String], label: &str) -> Result<(), SamplingValidationError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_text(value, label)?;
        if !seen.insert(value) {
            return Err(SamplingValidationError::new(
                "sampling-report-invalid",
                format!("{label} contains a duplicate"),
            ));
        }
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SamplingValidationError::new(
            "sampling-report-invalid",
            format!("{label} is not strictly sorted"),
        ));
    }
    Ok(())
}

fn report_invalid(error: impl std::fmt::Display) -> SamplingValidationError {
    SamplingValidationError::new("sampling-report-invalid", error.to_string())
}

fn generator_io(error: impl std::fmt::Display) -> SamplingValidationError {
    SamplingValidationError::new("generator-identity-mismatch", error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use proofbound_evidence::{canonical_json, domain_hash};
    use serde_json::Value;

    use super::{GENERATOR_DOMAIN, validate_sampling_observation};

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    fn fixture(path: &str) -> Vec<u8> {
        let mut bytes = fs::read(root().join(path)).unwrap();
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        bytes
    }

    fn hypothesis() -> (Vec<u8>, Vec<u8>) {
        (
            fixture(
                "docs/experiments/0006-explicit-sampling-contract/corpus/contracts/hypothesis.json",
            ),
            fixture(
                "docs/experiments/0006-explicit-sampling-contract/corpus/observations/hypothesis-passed.json",
            ),
        )
    }

    #[test]
    fn validates_both_backend_neutral_observations() {
        for backend in ["hypothesis", "fast-check"] {
            let contract = fixture(&format!(
                "docs/experiments/0006-explicit-sampling-contract/corpus/contracts/{backend}.json"
            ));
            let observation = fixture(&format!(
                "docs/experiments/0006-explicit-sampling-contract/corpus/observations/{backend}-passed.json"
            ));
            let report = validate_sampling_observation(&root(), &contract, &observation).unwrap();
            assert_eq!(report.result, "passed");
            assert_eq!(report.framework, backend);
        }
    }

    #[test]
    fn accepts_a_typed_counterexample_without_treating_it_as_a_pass() {
        let (contract, observation) = hypothesis();
        let mut value: Value = serde_json::from_slice(&observation).unwrap();
        value["completed_cases"] = Value::from(0_u64);
        value["result"] = serde_json::json!({
            "status": "counterexample",
            "counterexample": [11, 10],
            "failure_kind": "AssertionError",
        });
        let report =
            validate_sampling_observation(&root(), &contract, &canonical_json(&value).unwrap())
                .unwrap();
        assert_eq!(report.result, "counterexample");
    }

    #[test]
    fn rejects_every_preregistered_sampling_attack() {
        let (contract_bytes, observation_bytes) = hypothesis();
        let base_contract: Value = serde_json::from_slice(&contract_bytes).unwrap();
        let base_observation: Value = serde_json::from_slice(&observation_bytes).unwrap();
        let attacks = [
            ("EXP-0006-A001", "sampling-contract-mismatch"),
            ("EXP-0006-A002", "sampling-contract-mismatch"),
            ("EXP-0006-A003", "generator-identity-mismatch"),
            ("EXP-0006-A004", "generator-identity-mismatch"),
            ("EXP-0006-A005", "sampling-inventory-mismatch"),
            ("EXP-0006-A006", "sampling-report-invalid"),
            ("EXP-0006-A007", "sampling-contract-mismatch"),
            ("EXP-0006-A008", "sampling-schema-mismatch"),
            ("EXP-0006-A009", "sampling-contract-mismatch"),
            ("EXP-0006-A010", "sampling-tool-mismatch"),
        ];
        for (id, expected) in attacks {
            let (contract, observation) = mutate_attack(id, &base_contract, &base_observation);
            let error =
                validate_sampling_observation(&root(), &contract, &observation).unwrap_err();
            assert_eq!(error.code, expected, "attack {id}: {}", error.message);
        }
    }

    fn mutate_attack(
        id: &str,
        base_contract: &Value,
        base_observation: &Value,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut contract = base_contract.clone();
        let mut observation = base_observation.clone();
        match id {
            "EXP-0006-A001" => contract["seed"]["value"] = Value::from(1_u64),
            "EXP-0006-A002" => contract["successful_cases"] = Value::from(101_u64),
            "EXP-0006-A003" => {
                contract["generator"]["entrypoint"] =
                    Value::String("substituted::property".to_owned());
                rehash_generator(&mut contract);
            }
            "EXP-0006-A004" => {
                contract["generator"]["closure"][0]["sha256"] =
                    Value::String(format!("sha256:{}", "0".repeat(64)));
            }
            "EXP-0006-A005" => {
                let targets = serde_json::json!(["substituted::target"]);
                observation["contract"]["targets"] = targets.clone();
                observation["targets"] = targets;
            }
            "EXP-0006-A006" => {
                let bytes = canonical_json(&observation).unwrap();
                let needle = b"\"completed_cases\":100";
                let position = bytes
                    .windows(needle.len())
                    .position(|item| item == needle)
                    .unwrap();
                let mut duplicate = bytes.clone();
                duplicate.splice(
                    position..position + needle.len(),
                    b"\"completed_cases\":100,\"completed_cases\":100"
                        .iter()
                        .copied(),
                );
                return (canonical_json(&contract).unwrap(), duplicate);
            }
            "EXP-0006-A007" => observation["actual_seed"]["value"] = Value::from(1_u64),
            "EXP-0006-A008" => {
                observation["schema"] = Value::String("legacy-backend-sampling/1".to_owned())
            }
            "EXP-0006-A009" => {
                observation["contract"]["persistence"] =
                    Value::String("ambient-writable-database".to_owned())
            }
            "EXP-0006-A010" => {
                observation["contract"]["framework"]["version"] =
                    Value::String("6.113.0".to_owned())
            }
            _ => unreachable!(),
        }
        (
            canonical_json(&contract).unwrap(),
            canonical_json(&observation).unwrap(),
        )
    }

    fn rehash_generator(contract: &mut Value) {
        let material = serde_json::json!({
            "entrypoint": contract["generator"]["entrypoint"],
            "closure": contract["generator"]["closure"],
        });
        contract["generator"]["identity_sha256"] = Value::String(domain_hash(
            GENERATOR_DOMAIN,
            &canonical_json(&material).unwrap(),
        ));
    }
}
