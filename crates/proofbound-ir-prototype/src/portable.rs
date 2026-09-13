use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::layered_sampling::{LayeredSamplingCase, validate_layered_sampling_case};

pub const PORTABLE_FAMILY_PROJECTION_SCHEMA: &str = "proofbound-ir-portable-family-projection/1";
const PORTABLE_FAMILY_PROJECTION_DOMAIN: &str = "proofbound-ir-portable-family-projection/1";
pub const PORTABLE_FAMILY_PROJECTION_V2_SCHEMA: &str = "proofbound-ir-portable-family-projection/2";
const PORTABLE_FAMILY_PROJECTION_V2_DOMAIN: &str = "proofbound-ir-portable-family-projection/2";
const SAMPLING_EXTENSION_SCHEMA: &str = "proofbound-ir-sampling-extension/1";
const SAMPLING_EXTENSION_DOMAIN: &str = "proofbound-ir-sampling-extension/1";
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
    LayeredExtension {
        source_contract_identity: String,
        extension_identity: String,
        case_sha256: String,
        case: Box<LayeredSamplingCase>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SamplingExtensionIndex {
    schema: String,
    registered_units: Vec<String>,
    extensions: Vec<SamplingExtension>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SamplingExtension {
    record_sha256: String,
    unit_id: String,
    claims: Vec<String>,
    inventory: Vec<String>,
    case_path: String,
    case_sha256: String,
    extension_sha256: String,
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

pub fn project_portable_families_with_sampling(
    repository_root: &Path,
    capture_index_path: &Path,
    sampling_extension_path: &Path,
) -> Result<PortableFamilyProjection> {
    let mut projection = project_portable_families(repository_root, capture_index_path)?;
    let bytes = fs::read(sampling_extension_path).with_context(|| {
        format!(
            "read sampling extension index {}",
            sampling_extension_path.display()
        )
    })?;
    let value = crate::assurance::decode_strict_json(&bytes)
        .map_err(|error| anyhow!("IR-SAMPLING-EXTENSION-SCHEMA: {}", error.message))?;
    let index: SamplingExtensionIndex = serde_json::from_value(value)
        .context("IR-SAMPLING-EXTENSION-SCHEMA: decode sampling extension index")?;
    if index.schema != SAMPLING_EXTENSION_SCHEMA {
        bail!("IR-SAMPLING-EXTENSION-SCHEMA: unsupported sampling extension schema");
    }
    if index.registered_units != ["unit:bounded-roundtrip"] {
        bail!("IR-SAMPLING-EXTENSION-UNREGISTERED: sampling extension registration differs");
    }

    let mut seen_records = BTreeSet::new();
    let mut extended_units = BTreeSet::new();
    for extension in index.extensions {
        if !seen_records.insert(extension.record_sha256.clone()) {
            bail!("IR-SAMPLING-EXTENSION-DUPLICATE: portable record has two extensions");
        }
        let material = serde_json::json!({
            "case_path": &extension.case_path,
            "case_sha256": &extension.case_sha256,
            "claims": &extension.claims,
            "inventory": &extension.inventory,
            "record_sha256": &extension.record_sha256,
            "unit_id": &extension.unit_id,
        });
        let expected_extension_identity =
            domain_hash(SAMPLING_EXTENSION_DOMAIN, &canonical_json(&material)?);
        if extension.extension_sha256 != expected_extension_identity {
            bail!("IR-SAMPLING-EXTENSION-IDENTITY-MISMATCH: extension identity differs");
        }

        let Some(record) = projection
            .records
            .iter_mut()
            .find(|record| record.content_sha256 == extension.record_sha256)
        else {
            bail!("IR-SAMPLING-EXTENSION-RECORD-MISMATCH: portable record is absent");
        };
        if record.unit_id != extension.unit_id {
            bail!("IR-SAMPLING-EXTENSION-UNIT-MISMATCH: unit ID differs");
        }
        if !index.registered_units.contains(&extension.unit_id) {
            bail!("IR-SAMPLING-EXTENSION-UNREGISTERED: unit is not registered for extension");
        }
        if record.claims != extension.claims {
            bail!("IR-SAMPLING-EXTENSION-CLAIM-MISMATCH: claim IDs differ");
        }
        if record.inventory != extension.inventory {
            bail!("IR-SAMPLING-EXTENSION-INVENTORY-MISMATCH: target inventory differs");
        }
        let source_contract_identity = match &record.family {
            PortableFamily::SampledProperty(SampledPropertyDetail {
                sampling:
                    SamplingDetail::LegacyBackend {
                        contract_identity, ..
                    },
            }) => contract_identity.clone(),
            _ => bail!("IR-SAMPLING-EXTENSION-UNREGISTERED: record is not legacy sampled evidence"),
        };

        let case_path = capture_path(repository_root, repository_root, &extension.case_path)?;
        let case_bytes = fs::read(&case_path)
            .with_context(|| format!("read layered sampling case {}", case_path.display()))?;
        if sha256_bytes(&case_bytes) != extension.case_sha256 {
            bail!("generator-identity-mismatch: layered sampling case bytes differ");
        }
        validate_layered_sampling_case(repository_root, &case_bytes)
            .map_err(|error| anyhow!("{}: {}", error.code, error.message))?;
        let document = case_bytes.strip_suffix(b"\n").unwrap_or(&case_bytes);
        let case: LayeredSamplingCase = serde_json::from_slice(document)
            .context("IR-SAMPLING-EXTENSION-SCHEMA: decode layered sampling case")?;
        if case.targets() != extension.inventory {
            bail!("IR-SAMPLING-EXTENSION-INVENTORY-MISMATCH: case targets differ");
        }
        record.family = PortableFamily::SampledProperty(SampledPropertyDetail {
            sampling: SamplingDetail::LayeredExtension {
                source_contract_identity,
                extension_identity: extension.extension_sha256,
                case_sha256: extension.case_sha256,
                case: Box::new(case),
            },
        });
        extended_units.insert(extension.unit_id);
    }

    if extended_units != index.registered_units.into_iter().collect() {
        bail!("IR-SAMPLING-EXTENSION-UNREGISTERED: registered extension is missing");
    }
    if projection.records.iter().any(|record| {
        matches!(
            &record.family,
            PortableFamily::SampledProperty(SampledPropertyDetail {
                sampling: SamplingDetail::LegacyBackend { .. }
            })
        )
    }) {
        bail!("IR-SAMPLING-EXTENSION-UNREGISTERED: legacy sampling remains");
    }

    projection.schema = PORTABLE_FAMILY_PROJECTION_V2_SCHEMA.to_owned();
    let material = serde_json::json!({
        "capture_sha256": &projection.capture_sha256,
        "records": &projection.records,
        "schema": &projection.schema,
    });
    projection.projection_sha256 = domain_hash(
        PORTABLE_FAMILY_PROJECTION_V2_DOMAIN,
        &canonical_json(&material)?,
    );
    Ok(projection)
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

#[cfg(test)]
mod tests {
    use std::{io::Write as _, path::PathBuf};

    use proofbound_evidence::{canonical_json, domain_hash};
    use serde_json::{Value, json};
    use tempfile::{NamedTempFile, TempDir, tempdir};

    use super::{
        PORTABLE_FAMILY_PROJECTION_V2_SCHEMA, PortableFamily, SampledPropertyDetail,
        SamplingDetail, project_portable_families, project_portable_families_with_sampling,
    };

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    fn capture() -> PathBuf {
        root().join(
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/index.json",
        )
    }

    fn extensions() -> PathBuf {
        capture().parent().unwrap().join("sampling-extensions.json")
    }

    fn extension_value() -> Value {
        serde_json::from_slice(&std::fs::read(extensions()).unwrap()).unwrap()
    }

    fn rehash_extension(value: &mut Value) {
        let extension = &mut value["extensions"][0];
        let material = json!({
            "case_path": extension["case_path"],
            "case_sha256": extension["case_sha256"],
            "claims": extension["claims"],
            "inventory": extension["inventory"],
            "record_sha256": extension["record_sha256"],
            "unit_id": extension["unit_id"],
        });
        extension["extension_sha256"] = Value::String(domain_hash(
            "proofbound-ir-sampling-extension/1",
            &canonical_json(&material).unwrap(),
        ));
    }

    fn reject_extension(value: &Value, expected: &str) {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&canonical_json(value).unwrap()).unwrap();
        let error = project_portable_families_with_sampling(&root(), &capture(), file.path())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(expected),
            "expected {expected}, received {error}"
        );
    }

    fn temporary_repository() -> TempDir {
        let temp = tempdir().unwrap();
        for relative in [
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/index.json",
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/sampling-extensions.json",
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/python/compiled-receipt.json",
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/typescript/compiled-receipt.json",
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/typescript/bounded-roundtrip-sampling.json",
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/rust/compiled-receipt.json",
            "demo/typescript-codec/src/base64url.ts",
            "demo/typescript-codec/src/roundtrip.test.ts",
        ] {
            let destination = temp.path().join(relative);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(root().join(relative), destination).unwrap();
        }
        temp
    }

    fn temporary_paths(root: &std::path::Path) -> (PathBuf, PathBuf) {
        let capture = root.join(
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/index.json",
        );
        let extensions = capture.parent().unwrap().join("sampling-extensions.json");
        (capture, extensions)
    }

    #[test]
    fn finalization_replaces_only_the_registered_legacy_sampling_record() {
        let projection =
            project_portable_families_with_sampling(&root(), &capture(), &extensions()).unwrap();
        assert_eq!(projection.schema, PORTABLE_FAMILY_PROJECTION_V2_SCHEMA);
        assert_eq!(projection.records.len(), 45);
        assert!(!projection.records.iter().any(|record| matches!(
            &record.family,
            PortableFamily::SampledProperty(SampledPropertyDetail {
                sampling: SamplingDetail::LegacyBackend { .. }
            })
        )));
        assert!(projection.records.iter().any(|record| {
            record.unit_id == "unit:bounded-roundtrip"
                && matches!(
                    &record.family,
                    PortableFamily::SampledProperty(SampledPropertyDetail {
                        sampling: SamplingDetail::LayeredExtension { case, .. }
                    }) if case.targets()
                        == ["src/roundtrip.test.ts::base64url codec > round trips bounded byte arrays"]
                )
        }));
        assert!(projection.records.iter().any(|record| {
            record.unit_id == "unit:rust-kernel-tests"
                && matches!(record.family, PortableFamily::Example(_))
        }));
    }

    #[test]
    fn rejects_preregistered_sampling_extension_join_attacks() {
        let mut missing_record = extension_value();
        missing_record["extensions"][0]["record_sha256"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        rehash_extension(&mut missing_record);
        reject_extension(&missing_record, "IR-SAMPLING-EXTENSION-RECORD-MISMATCH");

        let mut wrong_unit = extension_value();
        wrong_unit["extensions"][0]["unit_id"] = Value::String("unit:other".to_owned());
        rehash_extension(&mut wrong_unit);
        reject_extension(&wrong_unit, "IR-SAMPLING-EXTENSION-UNIT-MISMATCH");

        let mut wrong_claim = extension_value();
        wrong_claim["extensions"][0]["claims"] = json!(["TS-PACKAGE-001"]);
        rehash_extension(&mut wrong_claim);
        reject_extension(&wrong_claim, "IR-SAMPLING-EXTENSION-CLAIM-MISMATCH");

        let mut wrong_inventory = extension_value();
        wrong_inventory["extensions"][0]["inventory"] = json!(["same-count-substitute"]);
        rehash_extension(&mut wrong_inventory);
        reject_extension(&wrong_inventory, "IR-SAMPLING-EXTENSION-INVENTORY-MISMATCH");

        let mut duplicate = extension_value();
        let second = duplicate["extensions"][0].clone();
        duplicate["extensions"].as_array_mut().unwrap().push(second);
        reject_extension(&duplicate, "IR-SAMPLING-EXTENSION-DUPLICATE");

        let base = project_portable_families(&root(), &capture()).unwrap();
        let rust = base
            .records
            .iter()
            .find(|record| record.unit_id == "unit:rust-kernel-tests")
            .unwrap();
        let mut reinterpret_rust = extension_value();
        reinterpret_rust["extensions"][0]["record_sha256"] =
            Value::String(rust.content_sha256.clone());
        reinterpret_rust["extensions"][0]["unit_id"] = Value::String(rust.unit_id.clone());
        reinterpret_rust["extensions"][0]["claims"] = json!(rust.claims);
        reinterpret_rust["extensions"][0]["inventory"] = json!(rust.inventory);
        rehash_extension(&mut reinterpret_rust);
        reject_extension(&reinterpret_rust, "IR-SAMPLING-EXTENSION-UNREGISTERED");
    }

    #[test]
    fn rejects_preregistered_sampling_extension_content_attacks() {
        let changed_generator = temporary_repository();
        let generator_path = changed_generator
            .path()
            .join("demo/typescript-codec/src/base64url.ts");
        std::fs::OpenOptions::new()
            .append(true)
            .open(generator_path)
            .unwrap()
            .write_all(b" ")
            .unwrap();
        let (capture, extensions) = temporary_paths(changed_generator.path());
        let error = project_portable_families_with_sampling(
            changed_generator.path(),
            &capture,
            &extensions,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("generator-identity-mismatch"), "{error}");

        let changed_plan = temporary_repository();
        let (capture, extensions_path) = temporary_paths(changed_plan.path());
        let mut extensions: Value =
            serde_json::from_slice(&std::fs::read(&extensions_path).unwrap()).unwrap();
        let case_path = changed_plan.path().join(
            "docs/experiments/0005-assurance-ir-extraction/captures/q1-finalization-r1/typescript/bounded-roundtrip-sampling.json",
        );
        let mut case: Value = serde_json::from_slice(&std::fs::read(&case_path).unwrap()).unwrap();
        case["plan"]["random_type"] = Value::String("substituted".to_owned());
        let mut case_bytes = canonical_json(&case).unwrap();
        case_bytes.push(b'\n');
        std::fs::write(&case_path, &case_bytes).unwrap();
        extensions["extensions"][0]["case_sha256"] =
            Value::String(proofbound_evidence::sha256_bytes(&case_bytes));
        rehash_extension(&mut extensions);
        std::fs::write(&extensions_path, canonical_json(&extensions).unwrap()).unwrap();
        let error = project_portable_families_with_sampling(
            changed_plan.path(),
            &capture,
            &extensions_path,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("sampling-plan-identity-mismatch"), "{error}");
    }
}
