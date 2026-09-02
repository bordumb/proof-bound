use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PORTABLE_FAMILY_PROJECTION_SCHEMA: &str = "proofbound-ir-portable-family-projection/1";
const PORTABLE_FAMILY_PROJECTION_DOMAIN: &str = "proofbound-ir-portable-family-projection/1";
const LEGACY_SAMPLING_REASON: &str = "sampling-detail-not-yet-portable";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PortableFamilyProjection {
    pub schema: String,
    pub capture_sha256: String,
    pub records: Vec<PortableFamilyRecord>,
    pub projection_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PortableFamilyRecord {
    pub content_sha256: String,
    pub unit_id: String,
    pub claims: Vec<String>,
    pub inventory: Vec<String>,
    pub family: PortableFamily,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
pub enum PortableFamily {
    Example(EmptyDetail),
    SampledProperty(SampledPropertyDetail),
    StaticConsistency(StaticCheckDetail),
    IndependentObservation(IndependentObservationDetail),
    MutationWitness(MutationWitnessDetail),
    ReproducibleArtifact(DistributionReproductionDetail),
    UniversalSourceProof(TheoremDetail),
    BoundedModelCheck(BoundedCheckDetail),
    ArtifactCorrespondence(ArtifactBindingDetail),
    TrustedTranscription(TrustedTranscriptionDetail),
    HumanReview(EmptyDetail),
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EmptyDetail {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SampledPropertyDetail {
    pub sampling: SamplingDetail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum SamplingDetail {
    Explicit {
        schema: String,
        framework: String,
        framework_version: String,
        seed: u64,
    },
    LegacyBackend {
        contract_identity: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCheckDetail {
    pub schema: String,
    pub tool: String,
    pub tool_version: String,
    pub configuration_sha256: String,
    pub targets: BTreeSet<String>,
    pub diagnostics: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndependenceMode {
    Independent,
    CommonOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IndependentObservationDetail {
    pub independence: IndependenceMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub logical_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFailureDetail {
    pub run_index: usize,
    pub allowed_exit_codes: BTreeSet<i32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationWitnessDetail {
    pub schema: String,
    pub mutation_id: String,
    pub subject: String,
    pub guard: String,
    pub mutation_sha256: String,
    pub registry: ArtifactIdentity,
    pub target_preimage: ArtifactIdentity,
    pub mutant_artifact: ArtifactIdentity,
    pub target_postimage: ArtifactIdentity,
    pub witness_source: ArtifactIdentity,
    pub check_id: String,
    pub baseline_run_index: usize,
    pub expected_failure: ExpectedFailureDetail,
    pub proof_term_witness: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionReproductionDetail {
    pub schema: String,
    pub format: String,
    pub run_digests: Vec<String>,
    pub registered_digest: String,
    pub source_date_epoch: u64,
    pub build_backend_name: String,
    pub build_backend_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_integrity: Option<String>,
    #[serde(default)]
    pub member_inventory: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TheoremDetail {
    pub declaration: String,
    pub statement_encoding: String,
    pub statement_wire: Value,
    pub statement_sha256: String,
    pub attributed_claim: String,
    pub proof_environment: String,
    pub axiom_audit_passed: bool,
    pub contains_sorry_ax: bool,
    #[serde(default)]
    pub foundational_axioms: BTreeSet<String>,
    #[serde(default)]
    pub project_axioms: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedDomainDetail {
    pub id: String,
    pub description: String,
    pub registration_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedCheckDetail {
    pub domain: BoundedDomainDetail,
    pub solver: String,
    pub harnesses: BTreeSet<String>,
    #[serde(default)]
    pub unwind_bounds: BTreeMap<String, u64>,
    pub assumptions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBindingDetail {
    pub theorem_evidence: String,
    pub artifact: ArtifactIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptionTcbRole {
    pub tcb_node: String,
    pub role_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTranscriptionDetail {
    pub schema: String,
    pub source: ArtifactIdentity,
    pub committed_transcription: ArtifactIdentity,
    pub transcribed_candidate: ArtifactIdentity,
    pub reencoded_source: ArtifactIdentity,
    pub driver: ArtifactIdentity,
    pub transcriber: TranscriptionTcbRole,
    pub reencoder: TranscriptionTcbRole,
}

#[derive(Debug, Deserialize)]
struct CaptureIndex {
    schema: String,
    revision: u64,
    cases: Vec<CaptureCase>,
}

#[derive(Debug, Deserialize)]
struct CaptureCase {
    evidence_records: usize,
    files: Vec<CaptureFile>,
}

#[derive(Debug, Deserialize)]
struct CaptureFile {
    path: String,
    sha256: String,
    size_bytes: u64,
}

pub fn project_portable_families(
    repository_root: &Path,
    capture_index_path: &Path,
) -> Result<PortableFamilyProjection> {
    let index_bytes = fs::read(capture_index_path)
        .with_context(|| format!("read capture index {}", capture_index_path.display()))?;
    let index: CaptureIndex =
        serde_json::from_slice(&index_bytes).context("decode capture index")?;
    ensure!(
        index.schema == "proofbound-research-q1-completion-capture/1" && index.revision == 1,
        "unsupported completion capture"
    );
    let capture_root = capture_index_path
        .parent()
        .context("capture index has no parent")?;
    let mut records = Vec::new();
    for case in index.cases {
        let compiled = case
            .files
            .iter()
            .find(|file| file.path.ends_with("/compiled-receipt.json"))
            .context("capture case has no compiled receipt")?;
        let path = capture_path(repository_root, capture_root, &compiled.path)?;
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        ensure!(
            sha256_bytes(&bytes) == compiled.sha256 && bytes.len() as u64 == compiled.size_bytes,
            "captured compiled receipt identity differs"
        );
        let receipt: Value = serde_json::from_slice(&bytes).context("decode compiled receipt")?;
        let evidence = receipt
            .get("evidence")
            .and_then(Value::as_array)
            .context("compiled receipt evidence is missing")?;
        ensure!(
            evidence.len() == case.evidence_records,
            "capture evidence count differs"
        );
        for wrapped in evidence {
            records.push(project_record(wrapped)?);
        }
    }
    records.sort_by(|left, right| left.content_sha256.cmp(&right.content_sha256));
    for pair in records.windows(2) {
        ensure!(
            pair[0].content_sha256 != pair[1].content_sha256,
            "duplicate portable evidence identity"
        );
    }
    let capture_sha256 = sha256_bytes(&index_bytes);
    let material = serde_json::json!({
        "capture_sha256": capture_sha256,
        "records": records,
        "schema": PORTABLE_FAMILY_PROJECTION_SCHEMA,
    });
    let projection_sha256 = domain_hash(
        PORTABLE_FAMILY_PROJECTION_DOMAIN,
        &canonical_json(&material)?,
    );
    Ok(PortableFamilyProjection {
        schema: PORTABLE_FAMILY_PROJECTION_SCHEMA.to_owned(),
        capture_sha256,
        records,
        projection_sha256,
    })
}

fn capture_path(repository_root: &Path, capture_root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    ensure!(
        relative.is_relative()
            && relative
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
        "capture path is not normalized"
    );
    let path = capture_root.join(relative);
    ensure!(
        path.starts_with(repository_root),
        "capture path escapes repository"
    );
    Ok(path)
}

fn project_record(wrapped: &Value) -> Result<PortableFamilyRecord> {
    let content_sha256 = text(wrapped, "sha256")?.to_owned();
    let record = wrapped
        .get("record")
        .and_then(Value::as_object)
        .context("portable evidence record is missing")?;
    let source_kind = record
        .get("kind")
        .and_then(Value::as_str)
        .context("portable evidence kind is missing")?;
    validate_detail_exclusivity(record, source_kind)?;
    let family = match source_kind {
        "example-test" if record.contains_key("distribution_reproduction") => {
            PortableFamily::ReproducibleArtifact(detail(record, "distribution_reproduction")?)
        }
        "example-test" => PortableFamily::Example(EmptyDetail::default()),
        "property-test" => {
            let sampling = if let Some(value) = record.get("python_property") {
                let property: PythonPropertySource = serde_json::from_value(value.clone())
                    .context("decode explicit property detail")?;
                SamplingDetail::Explicit {
                    schema: property.schema,
                    framework: property.framework,
                    framework_version: property.framework_version,
                    seed: property.seed,
                }
            } else {
                let provenance = record
                    .get("provenance")
                    .and_then(Value::as_object)
                    .context("legacy property provenance is missing")?;
                SamplingDetail::LegacyBackend {
                    contract_identity: provenance
                        .get("unit_configuration_sha256")
                        .and_then(Value::as_str)
                        .context("legacy property contract identity is missing")?
                        .to_owned(),
                    reason: LEGACY_SAMPLING_REASON.to_owned(),
                }
            };
            PortableFamily::SampledProperty(SampledPropertyDetail { sampling })
        }
        "static-check" => PortableFamily::StaticConsistency(detail(record, "static_check")?),
        "independent-check" => {
            PortableFamily::IndependentObservation(IndependentObservationDetail {
                independence: serde_json::from_value(
                    record
                        .get("independence")
                        .cloned()
                        .context("independence detail is missing")?,
                )
                .context("decode independence detail")?,
            })
        }
        "mutation-witness" => PortableFamily::MutationWitness(detail(record, "mutation_witness")?),
        "theorem" => PortableFamily::UniversalSourceProof(detail(record, "theorem")?),
        "bounded-check" => PortableFamily::BoundedModelCheck(detail(record, "bounded_check")?),
        "artifact-soundness" => {
            PortableFamily::ArtifactCorrespondence(detail(record, "artifact_binding")?)
        }
        "trusted-transcription" => {
            PortableFamily::TrustedTranscription(detail(record, "trusted_transcription")?)
        }
        "review" => PortableFamily::HumanReview(EmptyDetail::default()),
        other => bail!("unsupported portable evidence family {other}"),
    };
    Ok(PortableFamilyRecord {
        content_sha256,
        unit_id: record
            .get("unit_id")
            .and_then(Value::as_str)
            .context("portable unit ID is missing")?
            .to_owned(),
        claims: text_array(record, "claim_ids")?,
        inventory: text_array(record, "inventoried_targets")?,
        family,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonPropertySource {
    schema: String,
    framework: String,
    seed: u64,
    framework_version: String,
}

fn detail<T: for<'de> Deserialize<'de>>(
    record: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<T> {
    serde_json::from_value(
        record
            .get(field)
            .cloned()
            .with_context(|| format!("portable {field} detail is missing"))?,
    )
    .with_context(|| format!("decode portable {field} detail"))
}

fn validate_detail_exclusivity(
    record: &serde_json::Map<String, Value>,
    source_kind: &str,
) -> Result<()> {
    const DETAIL_FIELDS: &[&str] = &[
        "artifact_binding",
        "bounded_check",
        "distribution_reproduction",
        "independence",
        "mutation_witness",
        "python_property",
        "static_check",
        "theorem",
        "trusted_transcription",
    ];
    let present = DETAIL_FIELDS
        .iter()
        .filter(|field| record.contains_key(**field))
        .copied()
        .collect::<Vec<_>>();
    let allowed = match source_kind {
        "artifact-soundness" => &["artifact_binding"][..],
        "bounded-check" => &["bounded_check"][..],
        "example-test" => &["distribution_reproduction"][..],
        "independent-check" => &["independence"][..],
        "mutation-witness" => &["mutation_witness"][..],
        "property-test" => &["python_property"][..],
        "review" => &[][..],
        "static-check" => &["static_check"][..],
        "theorem" => &["theorem"][..],
        "trusted-transcription" => &["trusted_transcription"][..],
        _ => &[][..],
    };
    ensure!(
        present.iter().all(|field| allowed.contains(field)) && present.len() <= 1,
        "portable evidence contains conflicting family detail"
    );
    Ok(())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("{field} is missing"))
}

fn text_array(record: &serde_json::Map<String, Value>, field: &str) -> Result<Vec<String>> {
    record
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{field} is missing"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("{field} entry is not text"))
        })
        .collect()
}
