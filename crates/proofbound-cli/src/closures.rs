use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use proofbound_core::{ClosureIdentity, ClosureKind as CoreClosureKind, Sha256Digest};
use proofbound_evidence::{ClosureKind, ClosureLimits, ClosureRecord, build_closure};
use proofbound_manifest::{ClaimManifest, ProjectBundle};
use serde::Deserialize;

const MAX_DISCOVERY_OUTPUT: usize = 64 << 20;

pub(crate) fn limits(bundle: &ProjectBundle) -> ClosureLimits {
    ClosureLimits {
        max_files: bundle.project.limits.max_files,
        max_total_bytes: bundle.project.limits.max_total_bytes,
        max_file_bytes: bundle.project.limits.max_manifest_bytes.max(64 << 20),
    }
}

pub(crate) fn claim_closure(
    root: &Path,
    bundle: &ProjectBundle,
    claim_id: &str,
    claim: &ClaimManifest,
) -> Result<ClosureRecord> {
    let configured = if claim.source_roots.is_empty() {
        &bundle.project.source.semantic
    } else {
        &claim.source_roots
    };
    let mut patterns = configured.iter().cloned().collect::<BTreeSet<_>>();
    // A semantic closure binds not only implementation sources but also the
    // exact declarative bytes from which the claim, its assumptions/premises,
    // and any custom policy are compiled.  A narrow `source_roots` override
    // must never make those meaning-bearing manifests disappear from the
    // closure (and therefore from the evidence cache key).
    patterns.extend(claim_manifest_dependencies(root, bundle, claim_id, claim)?);
    patterns.extend(lean_dependencies(root, configured)?);
    patterns.extend(rust_package_dependencies(root, configured)?);
    let closure = build_closure(
        root,
        ClosureKind::Semantic,
        &patterns.into_iter().collect::<Vec<_>>(),
        Some(claim_id.to_owned()),
        "build-tool-transitive/1",
        limits(bundle),
    )
    .with_context(|| format!("PB-CLOSURE-0001: could not close claim {claim_id}"))?;
    if let Some(expected) = claim.subject_closure.as_deref()
        && expected != closure.id
    {
        bail!(
            "PB-CLOSURE-0002: claim {claim_id} pins subject closure {expected}, computed {}",
            closure.id
        );
    }
    Ok(closure)
}

fn claim_manifest_dependencies(
    root: &Path,
    bundle: &ProjectBundle,
    claim_id: &str,
    claim: &ClaimManifest,
) -> Result<BTreeSet<String>> {
    let canonical_root = root
        .canonicalize()
        .context("PB-CLOSURE-0007: project root cannot be canonicalized")?;
    let mut paths = BTreeSet::new();
    let (claim_path, _) = bundle
        .claims
        .get(claim_id)
        .with_context(|| format!("PB-CLOSURE-0007: claim manifest is missing for {claim_id}"))?;
    paths.insert(normalized_relative(&canonical_root, claim_path)?);

    for assumption_id in claim.assumptions.iter().chain(&claim.premises) {
        let (path, _) = bundle.assumptions.get(assumption_id).with_context(|| {
            format!(
                "PB-CLOSURE-0007: claim {claim_id} references missing assumption manifest {assumption_id}"
            )
        })?;
        paths.insert(normalized_relative(&canonical_root, path)?);
    }

    if let Some((path, _)) = bundle.policies.get(&claim.profile) {
        paths.insert(normalized_relative(&canonical_root, path)?);
    }
    Ok(paths)
}

pub(crate) fn shared_closures(root: &Path, bundle: &ProjectBundle) -> Result<Vec<ClosureRecord>> {
    let toolchains = [
        bundle.project.toolchains.rust.as_ref(),
        bundle.project.toolchains.lean.as_ref(),
        bundle.project.toolchains.python.as_ref(),
        bundle.project.toolchains.translation.as_ref(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<Vec<_>>();
    let registrations = [
        (
            ClosureKind::Runner,
            bundle.project.source.runner.as_slice(),
            "project-runner/1",
        ),
        (
            ClosureKind::Presentation,
            bundle.project.source.presentation.as_slice(),
            "project-presentation/1",
        ),
        (
            ClosureKind::ExternalEvidence,
            bundle.project.source.external_evidence.as_slice(),
            "external-evidence/1",
        ),
        (
            ClosureKind::Toolchain,
            toolchains.as_slice(),
            "toolchains/1",
        ),
    ];
    registrations
        .into_iter()
        .filter(|(_, patterns, _)| !patterns.is_empty())
        .map(|(kind, patterns, discovery)| {
            build_closure(root, kind, patterns, None, discovery, limits(bundle))
                .with_context(|| format!("PB-CLOSURE-0003: could not build {kind:?} closure"))
        })
        .collect()
}

pub(crate) fn core_identity(record: &ClosureRecord) -> Result<ClosureIdentity> {
    let kind = match record.kind {
        ClosureKind::Semantic => CoreClosureKind::Semantic,
        ClosureKind::Runner => CoreClosureKind::Runner,
        ClosureKind::Presentation => CoreClosureKind::Presentation,
        ClosureKind::ExternalEvidence => CoreClosureKind::ExternalEvidence,
        ClosureKind::Toolchain => CoreClosureKind::Toolchain,
    };
    let digest = record.id.strip_prefix("sha256:").unwrap_or(&record.id);
    Ok(ClosureIdentity {
        kind,
        sha256: digest.parse::<Sha256Digest>()?,
    })
}

fn lean_dependencies(root: &Path, patterns: &[String]) -> Result<BTreeSet<String>> {
    let mut dependencies = BTreeSet::new();
    for relative in patterns {
        if has_glob(relative)
            || Path::new(relative)
                .extension()
                .and_then(|value| value.to_str())
                != Some("lean")
        {
            continue;
        }
        let source = safe_existing_file(root, relative)?;
        dependencies.insert(normalized_relative(root, &source)?);
        let output = Command::new("lake")
            .args(["env", "lean", "--src-deps", relative])
            .current_dir(root)
            .output()
            .with_context(|| {
                format!("PB-CLOSURE-0004: could not query Lean dependencies for {relative}")
            })?;
        if !output.status.success() || output.stdout.len() > MAX_DISCOVERY_OUTPUT {
            bail!(
                "PB-CLOSURE-0004: Lean dependency discovery failed for {relative}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let text = std::str::from_utf8(&output.stdout)
            .context("PB-CLOSURE-0004: Lean dependency output is not UTF-8")?;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let path = PathBuf::from(line.trim());
            let canonical = path.canonicalize().with_context(|| {
                format!("PB-CLOSURE-0004: Lean reported missing dependency {line}")
            })?;
            if canonical.starts_with(root) {
                dependencies.insert(normalized_relative(root, &canonical)?);
            }
        }
    }
    Ok(dependencies)
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    resolve: Option<CargoResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    manifest_path: PathBuf,
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}

#[derive(Debug, Deserialize)]
struct CargoNode {
    id: String,
    dependencies: Vec<String>,
}

fn rust_package_dependencies(root: &Path, patterns: &[String]) -> Result<BTreeSet<String>> {
    let probes = patterns
        .iter()
        .filter_map(|pattern| package_probe(root, pattern))
        .collect::<BTreeSet<_>>();
    if probes.is_empty() {
        return Ok(BTreeSet::new());
    }
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--offline", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("PB-CLOSURE-0005: cargo metadata could not discover Rust dependencies")?;
    if !output.status.success() || output.stdout.len() > MAX_DISCOVERY_OUTPUT {
        bail!(
            "PB-CLOSURE-0005: cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .context("PB-CLOSURE-0005: cargo metadata output is malformed")?;
    let packages = metadata
        .packages
        .into_iter()
        .filter_map(|package| {
            let manifest = package.manifest_path.canonicalize().ok()?;
            (package.source.is_none() && manifest.starts_with(root))
                .then_some((package.id, manifest))
        })
        .collect::<BTreeMap<_, _>>();
    let mut roots = BTreeSet::new();
    for probe in probes {
        let canonical = probe.canonicalize().with_context(|| {
            format!(
                "PB-CLOSURE-0005: source root does not exist: {}",
                probe.display()
            )
        })?;
        let owner = packages
            .iter()
            .filter(|(_, manifest)| {
                manifest
                    .parent()
                    .is_some_and(|directory| canonical.starts_with(directory))
            })
            .max_by_key(|(_, manifest)| manifest.components().count())
            .map(|(id, _)| id.clone());
        if let Some(owner) = owner {
            roots.insert(owner);
        }
    }
    let dependencies = metadata
        .resolve
        .into_iter()
        .flat_map(|resolve| resolve.nodes)
        .map(|node| (node.id, node.dependencies))
        .collect::<BTreeMap<_, _>>();
    let mut closed = roots.clone();
    let mut queue = VecDeque::from_iter(roots);
    while let Some(package) = queue.pop_front() {
        for dependency in dependencies.get(&package).into_iter().flatten() {
            if packages.contains_key(dependency) && closed.insert(dependency.clone()) {
                queue.push_back(dependency.clone());
            }
        }
    }
    closed
        .into_iter()
        .map(|id| {
            let manifest = packages
                .get(&id)
                .expect("closed package IDs originate in package map");
            let directory = manifest.parent().context("Cargo.toml has no parent")?;
            Ok(format!("{}/**", normalized_relative(root, directory)?))
        })
        .collect()
}

fn package_probe(root: &Path, pattern: &str) -> Option<PathBuf> {
    if !(pattern.ends_with(".rs")
        || pattern.contains("/src/")
        || pattern.starts_with("crates/")
        || pattern.contains("/rust/"))
    {
        return None;
    }
    let prefix = literal_prefix(pattern);
    if prefix.as_os_str().is_empty() {
        return None;
    }
    let mut candidate = root.join(prefix);
    if candidate.is_file() {
        candidate.pop();
    }
    while candidate.starts_with(root) {
        if candidate.join("Cargo.toml").is_file() {
            return Some(candidate);
        }
        if !candidate.pop() {
            break;
        }
    }
    None
}

fn literal_prefix(pattern: &str) -> PathBuf {
    let mut result = PathBuf::new();
    for component in Path::new(pattern).components() {
        let Component::Normal(value) = component else {
            break;
        };
        let text = value.to_string_lossy();
        if text.contains(['*', '?', '[', ']']) {
            break;
        }
        result.push(value);
    }
    result
}

fn has_glob(value: &str) -> bool {
    value.contains(['*', '?', '[', ']'])
}

fn safe_existing_file(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("PB-CLOSURE-0006: source root is missing: {relative}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("PB-CLOSURE-0006: source root is not a regular file: {relative}");
    }
    path.canonicalize().map_err(Into::into)
}

fn normalized_relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("path escapes project: {}", path.display()))?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("path is not normalized: {}", relative.display());
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::cache_key_identity;
    use proofbound_manifest::EvidenceUnitManifest;
    use serde_json::json;

    fn write_manifest_fixture(root: &Path) {
        for directory in ["src", "claims", "assumptions", "policies"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("src/meaning.txt"), "meaning-v1\n").unwrap();
        fs::write(
            root.join("proofbound.toml"),
            r#"schema = "proofbound-project/1"
project = "closure-regression"
tier = 0
claim_manifests = ["claims/*.toml"]
assumption_manifests = ["assumptions/*.toml"]
evidence_units = []
translation_units = []
model_check_units = []
policy_manifests = ["policies/*.toml"]
review_manifests = []

[source]
semantic = ["src/**"]
runner = []
presentation = []
external_evidence = []
"#,
        )
        .unwrap();
        write_claim(root, "Claim statement v1.");
        write_assumption(root, "Assumption statement v1.");
        write_policy(root, false);
    }

    fn write_claim(root: &Path, statement: &str) {
        fs::write(
            root.join("claims/TEST-CLAIM-001.toml"),
            format!(
                r#"schema = "proofbound-claim/1"
id = "TEST-CLAIM-001"
title = "Closure regression"
statement = {statement:?}
subject = "fixture:meaning"
profile = "strict-profile"
tier = 0
evidence = []
assumptions = ["TEST-ASSUMPTION-001"]
premises = []
open_obligations = []
out_of_scope = []
source_roots = ["src/**"]
"#
            ),
        )
        .unwrap();
    }

    fn write_assumption(root: &Path, statement: &str) {
        fs::write(
            root.join("assumptions/TEST-ASSUMPTION-001.toml"),
            format!(
                r#"schema = "proofbound-assumption/1"
id = "TEST-ASSUMPTION-001"
statement = {statement:?}
category = "human-attestation"
owner = "Fixture owner"
rationale = "Regression coverage."
scope = "This fixture claim."
affected_claims = ["TEST-CLAIM-001"]
review_evidence = []
discharge_plan = "Revise the fixture."
status = "active"
"#
            ),
        )
        .unwrap();
    }

    fn write_policy(root: &Path, allow_classical_choice: bool) {
        let foundational_axioms = if allow_classical_choice {
            r#"["Classical.choice"]"#
        } else {
            "[]"
        };
        fs::write(
            root.join("policies/strict-profile.toml"),
            format!(
                r#"schema = "proofbound-policy/1"
id = "strict-profile"
extends = "kernel-with-assumptions"
allow_project_axioms = true
allowed_project_axioms = ["TEST-ASSUMPTION-001"]
allowed_foundational_axioms = {foundational_axioms}
allow_native = false
allow_exhaustive_as_proved = false
required_binding = "none"
require_registered_premises = false
publication_allows_open = false
"#
            ),
        )
        .unwrap();
    }

    fn fixture_closure(root: &Path) -> ClosureRecord {
        let bundle = ProjectBundle::load(root).unwrap();
        let (_, claim) = &bundle.claims["TEST-CLAIM-001"];
        claim_closure(root, &bundle, "TEST-CLAIM-001", claim).unwrap()
    }

    fn fixture_unit() -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "closure-regression",
            "adapter": "source-closure",
            "kind": "example-test",
            "claims": ["TEST-CLAIM-001"],
            "tier": 0,
            "operation": {"type": "closure"},
            "inputs": [],
            "outputs": [],
            "environment_allowlist": [],
            "resource_budget": {
                "time_seconds": 1,
                "disk_bytes": 1,
                "memory_bytes": 1
            }
        }))
        .unwrap()
    }

    fn fixture_cache_key(closure: &ClosureRecord) -> String {
        cache_key_identity(
            &fixture_unit(),
            std::slice::from_ref(&closure.id),
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::from([("adapter:fixture".to_owned(), "sha256:fixture".to_owned())]),
        )
        .unwrap()
    }

    #[test]
    fn literal_prefix_stops_before_glob_component() {
        assert_eq!(literal_prefix("demo/*/rust/**"), PathBuf::from("demo"));
        assert_eq!(
            literal_prefix("crates/proofbound-core/src/lib.rs"),
            PathBuf::from("crates/proofbound-core/src/lib.rs")
        );
    }

    #[test]
    fn meaning_manifests_are_exact_members_of_every_claim_closure() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest_fixture(temp.path());
        let closure = fixture_closure(temp.path());
        let members = closure
            .members
            .iter()
            .map(|member| member.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            members,
            BTreeSet::from([
                "assumptions/TEST-ASSUMPTION-001.toml",
                "claims/TEST-CLAIM-001.toml",
                "policies/strict-profile.toml",
                "src/meaning.txt",
            ])
        );
    }

    #[test]
    fn claim_assumption_and_policy_drift_change_closure_and_cache_identity() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest_fixture(temp.path());
        let initial = fixture_closure(temp.path());
        let initial_cache = fixture_cache_key(&initial);

        write_claim(temp.path(), "Claim statement v2.");
        let claim_drift = fixture_closure(temp.path());
        assert_ne!(claim_drift.id, initial.id);
        assert_ne!(fixture_cache_key(&claim_drift), initial_cache);

        write_claim(temp.path(), "Claim statement v1.");
        write_assumption(temp.path(), "Assumption statement v2.");
        let assumption_drift = fixture_closure(temp.path());
        assert_ne!(assumption_drift.id, initial.id);
        assert_ne!(fixture_cache_key(&assumption_drift), initial_cache);

        write_assumption(temp.path(), "Assumption statement v1.");
        write_policy(temp.path(), true);
        let policy_drift = fixture_closure(temp.path());
        assert_ne!(policy_drift.id, initial.id);
        assert_ne!(fixture_cache_key(&policy_drift), initial_cache);
    }
}
