use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use proofbound_evidence::sha256_bytes;
use serde::Serialize;
use serde_json::Value;

use crate::{Artifact, required_value_array, required_value_text};

const REPORT_SCHEMA: &str = "proofbound-ir-artifact-role-report/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactRoleReport {
    pub schema: String,
    pub project: String,
    pub receipt_sha256: String,
    pub units: Vec<ArtifactUnitRoles>,
    pub sealed_tcb_ledger: Artifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactUnitRoles {
    pub unit_id: String,
    pub manifest: Artifact,
    pub registered_inputs: Vec<Artifact>,
    pub supplemental_inputs: Vec<Artifact>,
    pub generated_artifacts: Vec<Artifact>,
    pub bound_roles: Vec<BoundArtifactRole>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundArtifactRole {
    pub role: String,
    pub artifact: Artifact,
}

#[derive(Debug)]
struct RegisteredUnit {
    manifest: Artifact,
    inputs: Vec<String>,
}

pub fn audit_artifact_roles(
    repository_root: &Path,
    project_root: &Path,
    receipt_bytes: &[u8],
) -> Result<ArtifactRoleReport> {
    let receipt: Value = serde_json::from_slice(receipt_bytes).context("decode receipt")?;
    let registered = discover_registered_units(repository_root, project_root)?;
    let mut units = Vec::new();
    for wrapped in required_value_array(&receipt, "evidence")? {
        let record = wrapped
            .get("record")
            .context("evidence record is missing")?;
        let unit_id = required_value_text(record, "unit_id")?;
        let Some(local_id) = unit_id.strip_prefix("unit:") else {
            continue;
        };
        let candidates = registered
            .get(local_id)
            .with_context(|| format!("no registered manifest for {unit_id}"))?;
        let provenance = record
            .get("provenance")
            .context("evidence provenance is missing")?;
        let observed_inputs = artifacts(provenance, "input_artifacts")?;
        let generated_artifacts = artifacts(provenance, "generated_artifacts")?;
        require_unique_artifacts(&observed_inputs, "input")?;
        require_unique_artifacts(&generated_artifacts, "generated")?;
        let observed_by_name = observed_inputs
            .iter()
            .map(|artifact| (artifact.logical_name.as_str(), artifact))
            .collect::<BTreeMap<_, _>>();
        let matching = candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .inputs
                    .iter()
                    .all(|selector| observed_by_name.contains_key(selector.as_str()))
            })
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "{unit_id} does not resolve to exactly one registered manifest"
        );
        let unit = matching[0];
        let mut registered_inputs = Vec::new();
        for selector in &unit.inputs {
            let artifact = observed_by_name
                .get(selector.as_str())
                .with_context(|| format!("{unit_id} omits registered input role {selector}"))?;
            verify_project_artifact(repository_root, project_root, artifact)?;
            registered_inputs.push((*artifact).clone());
        }
        registered_inputs.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
        let registered_names = unit
            .inputs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let supplemental_inputs = observed_inputs
            .iter()
            .filter(|artifact| !registered_names.contains(artifact.logical_name.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for artifact in &supplemental_inputs {
            verify_project_artifact(repository_root, project_root, artifact)?;
        }
        let mut bound_roles = Vec::new();
        collect_bound_roles(record, "record", &mut bound_roles)?;
        bound_roles.sort_by(|left, right| left.role.cmp(&right.role));
        for pair in bound_roles.windows(2) {
            ensure!(
                pair[0].role != pair[1].role,
                "duplicate bound artifact role"
            );
        }
        let available = observed_inputs
            .iter()
            .chain(generated_artifacts.iter())
            .collect::<Vec<_>>();
        for binding in &bound_roles {
            ensure!(
                available.contains(&&binding.artifact),
                "{} binds an artifact absent from observed input/generated roles",
                binding.role
            );
        }
        units.push(ArtifactUnitRoles {
            unit_id: unit_id.to_owned(),
            manifest: unit.manifest.clone(),
            registered_inputs,
            supplemental_inputs,
            generated_artifacts,
            bound_roles,
        });
    }
    units.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    ensure!(
        !units.is_empty(),
        "receipt has no registered executable evidence units"
    );
    let sealed_tcb_ledger = verify_sealed_tcb_ledger(repository_root, project_root, &receipt)?;
    Ok(ArtifactRoleReport {
        schema: REPORT_SCHEMA.to_owned(),
        project: required_value_text(&receipt, "project")?.to_owned(),
        receipt_sha256: sha256_bytes(receipt_bytes),
        units,
        sealed_tcb_ledger,
    })
}

fn discover_registered_units(
    repository_root: &Path,
    project_root: &Path,
) -> Result<BTreeMap<String, Vec<RegisteredUnit>>> {
    let absolute_root = repository_root.join(project_root);
    let mut paths = Vec::new();
    collect_toml_paths(&absolute_root, &absolute_root, &mut paths)?;
    let mut units = BTreeMap::new();
    for path in paths {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        ensure!(bytes.len() <= 1_048_576, "research manifest exceeds 1 MiB");
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let Ok(value) = toml::from_str::<toml::Value>(text) else {
            continue;
        };
        let Some(table) = value.as_table() else {
            continue;
        };
        let Some(schema) = table.get("schema").and_then(toml::Value::as_str) else {
            continue;
        };
        if !schema.starts_with("proofbound-evidence-unit/") {
            continue;
        }
        let id = table
            .get("id")
            .and_then(toml::Value::as_str)
            .context("evidence unit ID is missing")?;
        let inputs = table
            .get("inputs")
            .and_then(toml::Value::as_array)
            .context("evidence inputs are missing")?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .context("evidence input is not text")
            })
            .collect::<Result<Vec<_>>>()?;
        let relative = path
            .strip_prefix(&absolute_root)
            .context("manifest escaped project root")?
            .to_string_lossy()
            .replace('\\', "/");
        let manifest = Artifact {
            logical_name: relative,
            sha256: sha256_bytes(&bytes),
            size_bytes: bytes.len() as u64,
        };
        units
            .entry(id.to_owned())
            .or_insert_with(Vec::new)
            .push(RegisteredUnit { manifest, inputs });
    }
    Ok(units)
}

fn collect_toml_paths(root: &Path, current: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current).with_context(|| format!("read {}", current.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if [".git", ".proofbound", "node_modules", "target"]
            .contains(&name.to_string_lossy().as_ref())
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_toml_paths(root, &path, paths)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            ensure!(path.starts_with(root), "manifest escaped project root");
            paths.push(path);
        }
    }
    paths.sort();
    Ok(())
}

fn artifacts(value: &Value, field: &str) -> Result<Vec<Artifact>> {
    required_value_array(value, field)?
        .iter()
        .map(artifact)
        .collect()
}

fn artifact(value: &Value) -> Result<Artifact> {
    Ok(Artifact {
        logical_name: required_value_text(value, "logical_name")?.to_owned(),
        sha256: required_value_text(value, "sha256")?.to_owned(),
        size_bytes: value
            .get("size_bytes")
            .and_then(Value::as_u64)
            .context("artifact size is missing")?,
    })
}

fn require_unique_artifacts(artifacts: &[Artifact], role: &str) -> Result<()> {
    let names = artifacts
        .iter()
        .map(|artifact| artifact.logical_name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        names.len() == artifacts.len(),
        "duplicate {role} artifact role"
    );
    Ok(())
}

fn verify_project_artifact(
    repository_root: &Path,
    project_root: &Path,
    artifact: &Artifact,
) -> Result<()> {
    let path = repository_root
        .join(project_root)
        .join(&artifact.logical_name);
    let bytes =
        fs::read(&path).with_context(|| format!("read registered artifact {}", path.display()))?;
    ensure!(
        sha256_bytes(&bytes) == artifact.sha256 && bytes.len() as u64 == artifact.size_bytes,
        "registered artifact identity differs at {}",
        artifact.logical_name
    );
    Ok(())
}

fn collect_bound_roles(
    value: &Value,
    path: &str,
    roles: &mut Vec<BoundArtifactRole>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.contains_key("logical_name")
                && object.contains_key("sha256")
                && object.contains_key("size_bytes")
            {
                if !path.contains("provenance.input_artifacts")
                    && !path.contains("provenance.generated_artifacts")
                {
                    roles.push(BoundArtifactRole {
                        role: path.to_owned(),
                        artifact: artifact(value)?,
                    });
                }
                return Ok(());
            }
            for (name, child) in object {
                collect_bound_roles(child, &format!("{path}.{name}"), roles)?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_bound_roles(child, &format!("{path}[{index}]"), roles)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn verify_sealed_tcb_ledger(
    repository_root: &Path,
    project_root: &Path,
    receipt: &Value,
) -> Result<Artifact> {
    let sealed = required_value_array(receipt, "sealed_files")?
        .iter()
        .find(|item| {
            item.get("path")
                .or_else(|| item.get("logical_name"))
                .and_then(Value::as_str)
                == Some("tcb-ledger.json")
        })
        .context("receipt does not seal tcb-ledger.json")?;
    let expected = Artifact {
        logical_name: "tcb-ledger.json".to_owned(),
        sha256: required_value_text(sealed, "sha256")?.to_owned(),
        size_bytes: sealed
            .get("size_bytes")
            .and_then(Value::as_u64)
            .context("sealed ledger size is missing")?,
    };
    let language = match required_value_text(receipt, "project")? {
        "proofbound-python-inventory" => "python",
        "proofbound-typescript-codec" => "typescript",
        "proofbound" => "rust",
        project => bail!("unknown completion project {project}"),
    };
    let path = repository_root
        .join("docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1");
    let bytes = fs::read(path.join(language).join("tcb-ledger.json"))?;
    ensure!(
        sha256_bytes(&bytes) == expected.sha256 && bytes.len() as u64 == expected.size_bytes,
        "sealed TCB ledger bytes differ from their receipt identity"
    );
    let _ = project_root;
    Ok(expected)
}
