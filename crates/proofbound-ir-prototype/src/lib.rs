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
    unit_id: Option<String>,
    claim_ids: Vec<String>,
    expected_claim: ExpectedClaim,
    projection_profiles: Vec<String>,
    toolchain_required_to_regenerate: Vec<String>,
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
    ensure!(corpus.revision == 1, "unsupported corpus revision");
    ensure!(
        corpus.status == "frozen-positive-unexecuted",
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
    let (registration, semantic_case_id) = match case.role.as_str() {
        "positive-registration" => (Some(project_registration(case, &source_bytes)?), None),
        "positive-semantic-status" => (None, Some(project_semantic_case(case, &source_bytes)?)),
        "positive-portable-release" => {
            verify_release_case(root, case, &source_bytes)?;
            (None, None)
        }
        role => bail!("case {} has unsupported role {role}", case.id),
    };

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

fn project_semantic_case(case: &CorpusCase, bytes: &[u8]) -> Result<String> {
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
    Ok(selected_id.to_owned())
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
}
