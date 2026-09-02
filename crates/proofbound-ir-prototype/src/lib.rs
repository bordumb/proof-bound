//! Research-only producer projection for Experiment 0005.
//!
//! This crate does not define a production Proofbound wire. It projects the
//! preregistered corpus into a small typed record so an independently written
//! checker can test canonical identity and source-to-projection agreement.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod assurance;

pub use assurance::{
    Artifact, CacheInput, CaseProgram, IrBackend, IrCache, IrCacheProvenance, IrClaim, IrEvidence,
    IrFamily, IrPolicy, IrProvenance, IrRun, IrUsage, IrValidationError, RetainedFact, cache_key,
    family_kind, family_schema, validate_case_program,
};

pub const CORPUS_SCHEMA: &str = "proofbound-research-projection-corpus/1";
pub const PROJECTION_SCHEMA: &str = "proofbound-assurance-ir-projection/1";
pub const PROJECTION_DOMAIN: &str = "proofbound-assurance-ir-projection/1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    experiment: String,
    baseline: String,
    revision: u64,
    status: String,
    source_identity: String,
    projection_profiles: BTreeMap<String, Vec<String>>,
    supporting_sources: Vec<SupportingSource>,
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportingSource {
    path: String,
    sha256: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    role: String,
    evidence_family: String,
    source: Source,
    #[serde(default)]
    claim_sources: Vec<ClaimSource>,
    #[serde(default)]
    unit_id: Option<String>,
    claim_ids: Vec<String>,
    expected_claim: ExpectedClaim,
    projection_profiles: Vec<String>,
    toolchain_required_to_regenerate: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimSource {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: String,
    sha256: String,
    #[serde(default)]
    json_pointer: Option<String>,
    #[serde(default)]
    envelope_path: Option<String>,
    #[serde(default)]
    envelope_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedClaim {
    pub formal: String,
    pub linkage: String,
    pub assumption: String,
    pub policy_admitted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionBatch {
    pub schema: String,
    pub experiment: String,
    pub baseline: String,
    pub corpus_sha256: String,
    pub cases: Vec<ProjectionCase>,
    pub projection_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCase {
    pub id: String,
    pub role: String,
    pub source: ProjectedSource,
    pub evidence_family: String,
    pub unit_id: Option<String>,
    pub claim_ids: Vec<String>,
    pub expected_claim: ExpectedClaim,
    pub registration: Option<RegistrationProjection>,
    pub semantic_case_id: Option<String>,
    pub projection_profiles: Vec<String>,
    pub program: CaseProgram,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedSource {
    pub path: String,
    pub sha256: String,
    pub json_pointer: Option<String>,
    pub envelope_path: Option<String>,
    pub envelope_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProjection {
    pub schema: String,
    pub unit_id: String,
    pub declared_kind: String,
    pub adapter: String,
    pub operation: String,
    pub claims: Vec<String>,
    pub assumptions: Vec<String>,
    pub inventory: Vec<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub family_configuration_sha256: String,
}

/// Project the frozen corpus without executing any evidence backend.
pub fn project_corpus(root: &Path, corpus_path: &Path) -> Result<ProjectionBatch> {
    let corpus_bytes =
        fs::read(corpus_path).with_context(|| format!("read corpus {}", corpus_path.display()))?;
    let corpus: Corpus = serde_json::from_slice(&corpus_bytes).context("decode corpus")?;
    validate_corpus_header(&corpus)?;

    for source in &corpus.supporting_sources {
        let _ = &source.role;
        verify_source(root, &source.path, &source.sha256)?;
    }

    let mut projected = Vec::with_capacity(corpus.cases.len());
    for case in &corpus.cases {
        ensure!(
            !case
                .toolchain_required_to_regenerate
                .iter()
                .any(String::is_empty)
        );
        for profile in &case.projection_profiles {
            ensure!(
                corpus.projection_profiles.contains_key(profile),
                "case {} names unknown projection profile {profile}",
                case.id
            );
        }
        projected.push(project_case(root, case)?);
    }
    projected.sort_by(|left, right| left.id.cmp(&right.id));
    for pair in projected.windows(2) {
        ensure!(pair[0].id != pair[1].id, "duplicate case {}", pair[0].id);
    }

    let material = serde_json::json!({
        "baseline": corpus.baseline,
        "cases": projected,
        "corpus_sha256": sha256_bytes(&corpus_bytes),
        "experiment": corpus.experiment,
        "schema": PROJECTION_SCHEMA,
    });
    let projection_sha256 = domain_hash(PROJECTION_DOMAIN, &canonical_json(&material)?);

    Ok(ProjectionBatch {
        schema: PROJECTION_SCHEMA.to_owned(),
        experiment: corpus.experiment,
        baseline: corpus.baseline,
        corpus_sha256: sha256_bytes(&corpus_bytes),
        cases: projected,
        projection_sha256,
    })
}

fn validate_corpus_header(corpus: &Corpus) -> Result<()> {
    ensure!(corpus.schema == CORPUS_SCHEMA, "unsupported corpus schema");
    ensure!(corpus.experiment == "EXP-0005", "unexpected experiment");
    ensure!(corpus.revision == 2, "unsupported corpus revision");
    ensure!(
        corpus.status == "frozen-positive-expanded-for-q1",
        "corpus is not frozen"
    );
    ensure!(
        corpus.source_identity == "sha256-of-exact-git-blob-bytes-at-baseline",
        "unsupported source identity contract"
    );
    ensure!(
        corpus.baseline.starts_with("git:"),
        "baseline must be Git-bound"
    );
    Ok(())
}

fn project_case(root: &Path, case: &CorpusCase) -> Result<ProjectionCase> {
    let source_bytes = verify_source(root, &case.source.path, &case.source.sha256)?;
    for claim_source in &case.claim_sources {
        verify_source(root, &claim_source.path, &claim_source.sha256)?;
    }
    let (registration, semantic_case_id, program) = match case.role.as_str() {
        "positive-registration" => {
            let registration = project_registration(case, &source_bytes)?;
            let program = registration_program(case, &registration);
            (Some(registration), None, program)
        }
        "positive-semantic-status" => {
            let (semantic_case_id, selected) = project_semantic_case(case, &source_bytes)?;
            let program = semantic_program(case, &selected)?;
            (None, Some(semantic_case_id), program)
        }
        "positive-portable-release" => {
            verify_release_case(root, case, &source_bytes)?;
            (None, None, release_program(case, &source_bytes)?)
        }
        role => bail!("case {} has unsupported role {role}", case.id),
    };

    validate_case_program(&canonical_json(&program)?).map_err(anyhow::Error::from)?;

    Ok(ProjectionCase {
        id: case.id.clone(),
        role: case.role.clone(),
        source: ProjectedSource {
            path: case.source.path.clone(),
            sha256: case.source.sha256.clone(),
            json_pointer: case.source.json_pointer.clone(),
            envelope_path: case.source.envelope_path.clone(),
            envelope_sha256: case.source.envelope_sha256.clone(),
        },
        evidence_family: case.evidence_family.clone(),
        unit_id: case.unit_id.clone(),
        claim_ids: case.claim_ids.clone(),
        expected_claim: case.expected_claim.clone(),
        registration,
        semantic_case_id,
        projection_profiles: case.projection_profiles.clone(),
        program,
    })
}

fn project_registration(case: &CorpusCase, bytes: &[u8]) -> Result<RegistrationProjection> {
    let text = std::str::from_utf8(bytes).context("registration is not UTF-8")?;
    let value: toml::Value = toml::from_str(text).context("decode registration TOML")?;
    let table = value
        .as_table()
        .context("registration root is not a table")?;
    let unit_id = required_text(table, "id")?;
    let schema = required_text(table, "schema")?;
    let declared_kind = required_text(table, "kind")?;
    let adapter = required_text(table, "adapter")?;
    let claims = text_array(table, "claims")?;
    ensure!(
        case.unit_id.as_deref() == Some(unit_id.as_str()),
        "unit ID mismatch"
    );
    ensure!(
        case.claim_ids == claims,
        "claim attribution mismatch for {}",
        case.id
    );

    let operation_table = table
        .get("operation")
        .and_then(toml::Value::as_table)
        .context("registration has no operation table")?;
    let operation = required_text(operation_table, "type")?;
    let assumptions = optional_text_array(table, "assumptions")?;
    let inventory = optional_text_array(table, "expected_inventory")?;
    let inputs = optional_text_array(table, "inputs")?;
    let outputs = optional_text_array(table, "outputs")?;

    let projected_family = if table.contains_key("distribution") {
        "distribution-reproduction"
    } else {
        declared_kind.as_str()
    };
    ensure!(
        projected_family == case.evidence_family,
        "evidence family mismatch for {}",
        case.id
    );

    let family_configuration = serde_json::json!({
        "bounded_domain": table.get("bounded_domain"),
        "distribution": table.get("distribution"),
        "mutation": table.get("mutation"),
        "operation": table.get("operation"),
        "property": table.get("property"),
        "transcription": table.get("transcription"),
    });
    let family_configuration_sha256 = domain_hash(
        PROJECTION_DOMAIN,
        &canonical_json(&family_configuration).context("canonicalize family configuration")?,
    );

    Ok(RegistrationProjection {
        schema,
        unit_id,
        declared_kind,
        adapter,
        operation,
        claims,
        assumptions,
        inventory,
        inputs,
        outputs,
        family_configuration_sha256,
    })
}

fn project_semantic_case(case: &CorpusCase, bytes: &[u8]) -> Result<(String, Value)> {
    let pointer = case
        .source
        .json_pointer
        .as_deref()
        .context("semantic case has no JSON pointer")?;
    let root: Value = serde_json::from_slice(bytes).context("decode semantic corpus")?;
    let selected = root
        .pointer(pointer)
        .context("semantic JSON pointer is missing")?;
    let selected_id = selected
        .get("id")
        .and_then(Value::as_str)
        .context("semantic case has no ID")?;
    let expected = expected_from_value(
        selected
            .get("expected")
            .context("semantic case has no expected result")?,
    )?;
    ensure!(expected == case.expected_claim, "semantic status mismatch");
    Ok((selected_id.to_owned(), selected.clone()))
}

fn expected_from_value(value: &Value) -> Result<ExpectedClaim> {
    Ok(ExpectedClaim {
        formal: value
            .get("formal")
            .and_then(Value::as_str)
            .context("expected formal status is missing")?
            .to_owned(),
        linkage: value
            .get("linkage")
            .and_then(Value::as_str)
            .context("expected linkage is missing")?
            .to_owned(),
        assumption: value
            .get("assumption")
            .and_then(Value::as_str)
            .context("expected assumption status is missing")?
            .to_owned(),
        policy_admitted: value
            .get("policy_admitted")
            .and_then(Value::as_bool)
            .context("expected policy status is missing")?,
    })
}

fn registration_program(case: &CorpusCase, registration: &RegistrationProjection) -> CaseProgram {
    let mut claim_ids = registration.claims.clone();
    claim_ids.sort();
    let mut assumptions = registration.assumptions.clone();
    assumptions.sort();
    let claims = claim_ids
        .iter()
        .map(|claim_id| IrClaim {
            id: claim_id.clone(),
            subject: format!("subject:{claim_id}"),
            assumptions: assumptions.clone(),
            open_obligations: Vec::new(),
        })
        .collect::<Vec<_>>();
    let kind = family_kind(&case.evidence_family)
        .expect("frozen registration family must have an IR mapping");
    let detail = family_detail(
        kind,
        claims.first().map(|claim| claim.subject.as_str()),
        &case.source,
        Some(&registration.family_configuration_sha256),
    );
    let retained_facts = if kind == "sampled-property" {
        vec![RetainedFact {
            schema: "proofbound-python-property/1".to_owned(),
            required: true,
            value: serde_json::json!({"configuration_sha256": registration.family_configuration_sha256}),
        }]
    } else {
        Vec::new()
    };
    let cache = registration_cache(registration);
    let prior_receipt = None;
    let evidence = vec![IrEvidence {
        authority: "registered".to_owned(),
        unit: registration.unit_id.clone(),
        claims: claim_ids,
        assumptions,
        family: IrFamily {
            kind: kind.to_owned(),
            detail,
        },
        backend: IrBackend { retained_facts },
        provenance: IrProvenance {
            runs: Vec::new(),
            usage: IrUsage { peak_memory: None },
            cache: IrCacheProvenance {
                prior_receipt: prior_receipt.map(str::to_owned),
                key: cache_key(&registration.unit_id, prior_receipt),
            },
        },
    }];
    CaseProgram {
        schema: assurance::CASE_SCHEMA.to_owned(),
        case_id: case.id.clone(),
        evidence_family: case.evidence_family.clone(),
        source: source_artifact(&case.source),
        claims,
        evidence,
        cache,
        policy: IrPolicy {
            required_components: vec!["registered-aggregate".to_owned()],
        },
        reported: case.expected_claim.clone(),
        exact_status: false,
    }
}

fn semantic_program(case: &CorpusCase, selected: &Value) -> Result<CaseProgram> {
    let expected = selected
        .get("expected")
        .and_then(Value::as_object)
        .context("semantic expected result is not an object")?;
    let assumptions = json_text_array(expected, "assumptions")?;
    let obligations = json_text_array(expected, "undischarged_premises")?;
    let mut claim_ids = case.claim_ids.clone();
    claim_ids.sort();
    let claims = claim_ids
        .iter()
        .map(|claim_id| IrClaim {
            id: claim_id.clone(),
            subject: format!("subject:{claim_id}"),
            assumptions: assumptions.clone(),
            open_obligations: obligations.clone(),
        })
        .collect::<Vec<_>>();
    let source = source_artifact(&case.source);
    let evidence_values = selected
        .get("evidence")
        .and_then(Value::as_array)
        .context("semantic case has no evidence")?;
    let evidence = evidence_values
        .iter()
        .map(|item| {
            let source_kind = item
                .get("kind")
                .and_then(Value::as_str)
                .context("semantic evidence kind is missing")?;
            let kind = family_kind(source_kind).context("unsupported semantic evidence kind")?;
            let unit = item
                .get("id")
                .and_then(Value::as_str)
                .context("semantic evidence ID is missing")?;
            Ok(IrEvidence {
                authority: "derived-conformance".to_owned(),
                unit: unit.to_owned(),
                claims: claim_ids.clone(),
                assumptions: assumptions.clone(),
                family: IrFamily {
                    kind: kind.to_owned(),
                    detail: family_detail(
                        kind,
                        claims.first().map(|claim| claim.subject.as_str()),
                        &case.source,
                        None,
                    ),
                },
                backend: IrBackend {
                    retained_facts: Vec::new(),
                },
                provenance: empty_provenance(unit),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let policy = selected
        .get("policy")
        .and_then(Value::as_object)
        .context("semantic policy is missing")?;
    Ok(CaseProgram {
        schema: assurance::CASE_SCHEMA.to_owned(),
        case_id: case.id.clone(),
        evidence_family: case.evidence_family.clone(),
        source,
        claims,
        evidence,
        cache: IrCache {
            registered_inputs: Vec::new(),
            execution_inputs: Vec::new(),
        },
        policy: IrPolicy {
            required_components: json_text_array(policy, "components")?,
        },
        reported: case.expected_claim.clone(),
        exact_status: true,
    })
}

fn release_program(case: &CorpusCase, bytes: &[u8]) -> Result<CaseProgram> {
    let receipt: Value = serde_json::from_slice(bytes).context("decode release receipt")?;
    let records = receipt
        .get("evidence")
        .and_then(Value::as_array)
        .context("release evidence is missing")?;
    let mut evidence = Vec::with_capacity(records.len());
    let mut all_assumptions = Vec::new();
    for wrapped in records {
        let record = wrapped.get("record").context("release record is missing")?;
        let source_kind = record
            .get("kind")
            .and_then(Value::as_str)
            .context("release evidence kind is missing")?;
        let kind = family_kind(source_kind).context("unsupported release evidence kind")?;
        let unit = record
            .get("unit_id")
            .and_then(Value::as_str)
            .context("release evidence unit is missing")?;
        let assumptions = json_text_array_value(record, "assumptions")?;
        all_assumptions.extend(assumptions.iter().cloned());
        let provenance = record
            .get("provenance")
            .and_then(Value::as_object)
            .context("release provenance is missing")?;
        let runs = provenance
            .get("runs")
            .and_then(Value::as_array)
            .context("release runs are missing")?
            .iter()
            .map(|run| {
                Ok(IrRun {
                    command_index: run
                        .get("command_index")
                        .and_then(Value::as_u64)
                        .context("release run index is missing")?,
                    exit_code: run.get("exit_code").and_then(Value::as_i64),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let peak_memory = provenance
            .get("actual_cost")
            .and_then(|usage| usage.get("memory_bytes"))
            .and_then(Value::as_u64);
        let prior_receipt = provenance.get("reused_from").and_then(Value::as_str);
        evidence.push(IrEvidence {
            authority: "portable-receipt".to_owned(),
            unit: unit.to_owned(),
            claims: case.claim_ids.clone(),
            assumptions,
            family: IrFamily {
                kind: kind.to_owned(),
                detail: family_detail(kind, Some("subject:c"), &case.source, None),
            },
            backend: IrBackend {
                retained_facts: Vec::new(),
            },
            provenance: IrProvenance {
                runs,
                usage: IrUsage { peak_memory },
                cache: IrCacheProvenance {
                    prior_receipt: prior_receipt.map(str::to_owned),
                    key: cache_key(unit, prior_receipt),
                },
            },
        });
    }
    all_assumptions.sort();
    all_assumptions.dedup();
    let claims = case
        .claim_ids
        .iter()
        .map(|claim_id| IrClaim {
            id: claim_id.clone(),
            subject: format!("subject:{claim_id}"),
            assumptions: all_assumptions.clone(),
            open_obligations: Vec::new(),
        })
        .collect();
    Ok(CaseProgram {
        schema: assurance::CASE_SCHEMA.to_owned(),
        case_id: case.id.clone(),
        evidence_family: case.evidence_family.clone(),
        source: source_artifact(&case.source),
        claims,
        evidence,
        cache: IrCache {
            registered_inputs: Vec::new(),
            execution_inputs: Vec::new(),
        },
        policy: IrPolicy {
            required_components: vec!["ledger".to_owned()],
        },
        reported: case.expected_claim.clone(),
        exact_status: true,
    })
}

fn registration_cache(registration: &RegistrationProjection) -> IrCache {
    let mutation_target = (registration.declared_kind == "mutation-witness")
        .then(|| {
            registration
                .inputs
                .iter()
                .find(|path| path.starts_with("src/") || path.contains("/src/"))
        })
        .flatten();
    let mut inputs = registration
        .inputs
        .iter()
        .map(|path| CacheInput {
            selector: if mutation_target == Some(path) {
                "target-preimage".to_owned()
            } else {
                path.clone()
            },
            identity: sha256_bytes(path.as_bytes()),
        })
        .collect::<Vec<_>>();
    inputs.sort();
    IrCache {
        registered_inputs: inputs.clone(),
        execution_inputs: inputs,
    }
}

fn family_detail(
    kind: &str,
    subject: Option<&str>,
    source: &Source,
    configuration_sha256: Option<&str>,
) -> Value {
    let schema = family_schema(kind).expect("mapped family kind must have a detail schema");
    match kind {
        "mutation-witness" => serde_json::json!({
            "schema": schema,
            "subject": subject.unwrap_or("subject:unknown"),
        }),
        "artifact-correspondence" => serde_json::json!({
            "schema": schema,
            "artifact": source_artifact(source),
        }),
        "sampled-property" => serde_json::json!({
            "schema": schema,
            "configuration_sha256": configuration_sha256,
            "required_fact_schemas": ["proofbound-python-property/1"],
        }),
        _ => serde_json::json!({
            "schema": schema,
            "configuration_sha256": configuration_sha256,
        }),
    }
}

fn empty_provenance(unit: &str) -> IrProvenance {
    IrProvenance {
        runs: Vec::new(),
        usage: IrUsage { peak_memory: None },
        cache: IrCacheProvenance {
            prior_receipt: None,
            key: cache_key(unit, None),
        },
    }
}

fn source_artifact(source: &Source) -> Artifact {
    Artifact {
        logical_name: source.path.clone(),
        sha256: source.sha256.clone(),
    }
}

fn json_text_array(object: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<String>> {
    object
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .with_context(|| format!("{field} entries must be text"))
        })
        .collect()
}

fn json_text_array_value(value: &Value, field: &str) -> Result<Vec<String>> {
    json_text_array(
        value
            .as_object()
            .with_context(|| format!("parent of {field} must be an object"))?,
        field,
    )
}

fn verify_release_case(root: &Path, case: &CorpusCase, bytes: &[u8]) -> Result<()> {
    let receipt: Value = serde_json::from_slice(bytes).context("decode release receipt")?;
    let statuses = receipt
        .get("reported_statuses")
        .and_then(Value::as_array)
        .context("release has no reported statuses")?;
    for claim_id in &case.claim_ids {
        let status = statuses
            .iter()
            .find(|status| status.get("claim_id").and_then(Value::as_str) == Some(claim_id))
            .with_context(|| format!("release has no status for {claim_id}"))?;
        ensure!(
            status.get("formal").and_then(Value::as_str) == Some(&case.expected_claim.formal),
            "release formal status mismatch"
        );
        ensure!(
            status.get("linkage").and_then(Value::as_str) == Some(&case.expected_claim.linkage),
            "release linkage mismatch"
        );
        ensure!(
            status.get("assumption").and_then(Value::as_str)
                == Some(&case.expected_claim.assumption),
            "release assumption mismatch"
        );
        ensure!(
            status.get("policy_admitted").and_then(Value::as_bool)
                == Some(case.expected_claim.policy_admitted),
            "release policy mismatch"
        );
    }

    let envelope_path = case
        .source
        .envelope_path
        .as_deref()
        .context("release case has no envelope path")?;
    let envelope_sha256 = case
        .source
        .envelope_sha256
        .as_deref()
        .context("release case has no envelope digest")?;
    verify_source(root, envelope_path, envelope_sha256)?;
    Ok(())
}

fn verify_source(root: &Path, path: &str, expected: &str) -> Result<Vec<u8>> {
    let full = root.join(path);
    let bytes = fs::read(&full).with_context(|| format!("read source {}", full.display()))?;
    ensure!(
        sha256_bytes(&bytes) == expected,
        "source identity mismatch for {path}"
    );
    Ok(bytes)
}

fn required_text(table: &toml::value::Table, field: &str) -> Result<String> {
    table
        .get(field)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{field} must be text"))
}

fn text_array(table: &toml::value::Table, field: &str) -> Result<Vec<String>> {
    let values = table
        .get(field)
        .and_then(toml::Value::as_array)
        .with_context(|| format!("{field} must be an array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("{field} entries must be text"))
        })
        .collect()
}

fn optional_text_array(table: &toml::value::Table, field: &str) -> Result<Vec<String>> {
    match table.get(field) {
        Some(_) => text_array(table, field),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn projects_all_frozen_cases_deterministically() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let first = project_corpus(&root, &corpus).unwrap();
        let second = project_corpus(&root, &corpus).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.cases.len(), 20);
        assert!(first.projection_sha256.starts_with("sha256:"));
    }

    #[test]
    fn source_drift_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let error = verify_source(temporary.path(), "missing", "sha256:00").unwrap_err();
        assert!(error.to_string().contains("read source"));
    }

    #[test]
    fn rejects_every_preregistered_adversarial_case() {
        let root = root();
        let corpus = root.join("docs/experiments/0005-assurance-ir-extraction/corpus/cases.json");
        let projection = project_corpus(&root, &corpus).unwrap();
        let bases = projection
            .cases
            .iter()
            .map(|case| (case.id.as_str(), &case.program))
            .collect::<BTreeMap<_, _>>();
        let adversarial_path = root
            .join("docs/experiments/0005-assurance-ir-extraction/corpus/adversarial-cases.json");
        let adversarial: Value =
            serde_json::from_slice(&fs::read(adversarial_path).unwrap()).unwrap();
        assert_eq!(adversarial.get("revision").and_then(Value::as_u64), Some(2));
        let attacks = adversarial.get("cases").and_then(Value::as_array).unwrap();
        assert_eq!(attacks.len(), 20);

        for attack in attacks {
            let base_id = attack.get("base_case").and_then(Value::as_str).unwrap();
            let base = bases[base_id];
            let bytes = mutate_case(base, attack);
            let expected = attack
                .pointer("/expected/code")
                .and_then(Value::as_str)
                .unwrap();
            let error = validate_case_program(&bytes).unwrap_err();
            assert_eq!(error.code, expected, "attack {}", attack["id"]);
        }
    }

    fn mutate_case(base: &CaseProgram, attack: &Value) -> Vec<u8> {
        let mutation = attack.get("mutation").unwrap();
        let operation = mutation.get("operation").and_then(Value::as_str).unwrap();
        let mut value = serde_json::to_value(base).unwrap();
        match operation {
            "delete" => delete_pointer(
                &mut value,
                mutation.get("path").and_then(Value::as_str).unwrap(),
            ),
            "replace" | "replace-reported-status" => {
                let path = mutation.get("path").and_then(Value::as_str).unwrap();
                *value.pointer_mut(path).unwrap() = mutation.get("value").unwrap().clone();
            }
            "duplicate-set-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let index = mutation.get("index").and_then(Value::as_u64).unwrap() as usize;
                array.insert(index, array[index].clone());
            }
            "replace-family" => {
                let from = mutation.get("from").and_then(Value::as_str).unwrap();
                let to = mutation.get("to").and_then(Value::as_str).unwrap();
                let evidence = value
                    .get_mut("evidence")
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let family = evidence
                    .iter_mut()
                    .find_map(|item| {
                        let family = item.get_mut("family")?;
                        (family.get("kind").and_then(Value::as_str) == Some(from)).then_some(family)
                    })
                    .unwrap();
                family["kind"] = Value::String(to.to_owned());
            }
            "remove-set-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                let position = if let Some(expected) = mutation.get("value") {
                    array.iter().position(|item| item == expected).unwrap()
                } else {
                    let selector = mutation.get("selector").and_then(Value::as_str).unwrap();
                    array
                        .iter()
                        .position(|item| {
                            item.get("selector").and_then(Value::as_str) == Some(selector)
                        })
                        .unwrap()
                };
                array.remove(position);
            }
            "add-set-member" => {
                let array = value
                    .pointer_mut(mutation.get("path").and_then(Value::as_str).unwrap())
                    .and_then(Value::as_array_mut)
                    .unwrap();
                array.push(mutation.get("value").unwrap().clone());
                array.sort_by_key(|item| item.as_str().unwrap().to_owned());
            }
            "encode-noncanonical" => {
                let mut bytes = canonical_json(&value).unwrap();
                bytes.push(b'\n');
                return bytes;
            }
            "encode-duplicate-object-key" => {
                let bytes = canonical_json(&value).unwrap();
                let unit = base.evidence[0].unit.as_str();
                let needle = format!("\"unit\":\"{unit}\"");
                let replacement = format!("{needle},{needle}");
                return String::from_utf8(bytes)
                    .unwrap()
                    .replacen(&needle, &replacement, 1)
                    .into_bytes();
            }
            other => panic!("unsupported adversarial operation {other}"),
        }
        canonical_json(&value).unwrap()
    }

    fn delete_pointer(value: &mut Value, pointer: &str) {
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove(field)
            .unwrap();
    }
}
