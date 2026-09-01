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
    pub reported: super::ExpectedClaim,
    pub exact_status: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Artifact {
    pub logical_name: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrClaim {
    pub id: String,
    pub subject: String,
    pub assumptions: Vec<String>,
    pub open_obligations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrEvidence {
    pub authority: String,
    pub unit: String,
    pub claims: Vec<String>,
    pub assumptions: Vec<String>,
    pub family: IrFamily,
    pub backend: IrBackend,
    pub provenance: IrProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrFamily {
    pub kind: String,
    pub detail: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrBackend {
    pub retained_facts: Vec<RetainedFact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetainedFact {
    pub schema: String,
    pub required: bool,
    pub value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrProvenance {
    pub runs: Vec<IrRun>,
    pub usage: IrUsage,
    pub cache: IrCacheProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrRun {
    pub command_index: u64,
    pub exit_code: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrUsage {
    pub peak_memory: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IrCacheProvenance {
    pub prior_receipt: Option<String>,
    pub key: String,
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
    let source_sha256 = text(source, "sha256")?;
    let claims = array_field(object, "claims")?;
    let evidence = array_field(object, "evidence")?;
    let claim_ids = claims
        .iter()
        .map(|claim| text(value_object(claim)?, "id").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    require_sorted_unique(&claim_ids)?;

    let mut claim_assumptions = Vec::with_capacity(claims.len());
    let mut obligations = false;
    for claim in claims {
        let claim = value_object(claim)?;
        let assumptions = text_array(claim, "assumptions")?;
        require_sorted_unique(&assumptions)?;
        obligations |= !array_field(claim, "open_obligations")?.is_empty();
        claim_assumptions.push(assumptions);
    }

    let mut kinds = Vec::with_capacity(evidence.len());
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
        if claim_assumptions
            .iter()
            .any(|expected| expected != &assumptions)
        {
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
        kinds.push(kind.to_owned());

        let backend = object_field(item, "backend")?;
        for fact in array_field(backend, "retained_facts")? {
            let fact = value_object(fact)?;
            let required = fact
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let schema = text(fact, "schema")?;
            if required && schema != "proofbound-python-property/1" {
                return Err(IrValidationError::new(
                    "IR-BACKEND-UNKNOWN-REQUIRED",
                    "unknown required retained fact",
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
            if text(artifact, "sha256")? != source_sha256 {
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

    let cache = object_field(object, "cache")?;
    let registered = cache_inputs(cache, "registered_inputs")?;
    let execution = cache_inputs(cache, "execution_inputs")?;
    if registered != execution {
        return Err(IrValidationError::new(
            "IR-CACHE-DEPENDENCY-OMITTED",
            "execution cache inputs differ from registration",
        ));
    }

    let reported = object_field(object, "reported")?;
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
