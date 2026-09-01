use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    str::FromStr,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use proofbound_core::{
    AdapterStrength, ArtifactBindingEvidence, ArtifactIdentity, ArtifactLogicalName,
    AssumptionCategory, AssumptionId, AssumptionRecord, AssumptionStatus, AssuranceGraph,
    BoundedCheckEvidence, BoundedDomain, BuiltInProfile, CacheOrigin, ClaimDefinition,
    ClaimEvaluationInput, ClaimId, ClosureIdentity, CommandSpec, DistributionReproductionEvidence,
    EdgeKind, EnvironmentVariable, EnvironmentVariableName, EvidenceId, EvidenceKind,
    EvidenceProvenance, EvidenceRecord, EvidenceStatus, ExecutionKind, ExecutionRun,
    ExpectedFailure, FlowScope, GraphEdge, GraphNode, IndependenceMode, LinkageFacet,
    MutationWitnessEvidence, NativePremiseRule, NodeId, NodeKind, ObligationId, OpenObligation,
    OutOfScope, PolicyDefinition, PolicyId, PremiseId, PremiseRecord, PythonPluginEvidence,
    PythonPropertyEvidence, ResourceBudget, ResourceUsage, Sha256Digest, SourceRefinementEvidence,
    StaticCheckEvidence, TRANSCRIPTION_DRIVER_ABI_V1, Tier, ToolIdentity, TranscriptionRole,
    TranscriptionTcbRole, TreeState, TrustedTranscriptionEvidence, UnitId, derive_claim_status,
    transcription_role_identity,
};
use proofbound_evidence::{
    ClosureMember, ClosureRecord, ContentAddressedStore, canonical_json, domain_hash, git_identity,
    merge_closures, sha256_bytes,
};
use proofbound_manifest::{
    AdapterDiagnostic, AdapterKind, AdapterResponse,
    AssumptionCategory as ManifestAssumptionCategory, AssumptionStatus as ManifestAssumptionStatus,
    ClaimManifest, EvidenceKind as ManifestEvidenceKind, EvidenceUnitManifest, ManifestLimits,
    ModelCheckUnitManifest, MutationRegistry, OperationKind, PolicyManifest, PrimaryLinkage,
    ProjectBundle, TranslationUnitManifest, load_toml,
};
use serde::{Deserialize, Serialize};

use crate::{adapter, closures, model::CompiledProject, model::UnitRun, safe_component};

const COMPILED_SCHEMA: &str = "proofbound-compiled-project/3";
const CLAIM_INPUT_DOMAIN: &str = "proofbound-claim-input/3";
const EVIDENCE_DOMAIN: &str = "proofbound-evidence/3";
const OBSERVATION_SCHEMA: &str = "proofbound-adapter-observation/2";
const MAX_CARGO_METADATA_OUTPUT: usize = 64 << 20;

#[derive(Clone, Debug, Default)]
pub struct CheckOptions {
    pub claim: Option<String>,
    pub profile: Option<String>,
    pub fresh: bool,
    pub reproduce_unit: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheReference {
    schema: String,
    cache_key: String,
    evidence_sha256: String,
}

struct ExecutionContext<'a> {
    root: &'a Path,
    state_root: &'a Path,
    store: &'a ContentAddressedStore,
    bundle: &'a ProjectBundle,
}

pub fn check_project(root: &Path, options: &CheckOptions) -> Result<CompiledProject> {
    let before = worktree_snapshot(root)?;
    let reviewed_tree_sha256 = sha256_bytes(&before);
    let bundle =
        ProjectBundle::load(root).context("PB-MANIFEST-0001: manifest validation failed")?;
    let identity = git_identity(root).context("PB-PROVENANCE-0001: git identity unavailable")?;
    let tier = Tier::try_from(bundle.project.tier).map_err(anyhow::Error::msg)?;
    let selected = select_claims(&bundle, options)?;
    let state_root = root.join(".proofbound");
    create_sealed_directories(&state_root)?;
    let store = ContentAddressedStore::new(state_root.join("evidence"));

    let selected_units = select_units(&bundle, &selected, options)?;
    let mut required_closure_claims = selected.iter().cloned().collect::<BTreeSet<_>>();
    for unit_id in &selected_units {
        required_closure_claims.extend(bundle.evidence_units[unit_id].1.claims.iter().cloned());
    }
    for (_, assumption) in bundle.assumptions.values() {
        if assumption
            .affected_claims
            .iter()
            .any(|claim| required_closure_claims.contains(claim))
        {
            required_closure_claims.extend(assumption.affected_claims.iter().cloned());
        }
    }

    let mut closures = closures::shared_closures(root, &bundle)?;
    let cache_context = closures
        .iter()
        .filter(|closure| {
            matches!(
                closure.kind,
                proofbound_evidence::ClosureKind::Runner
                    | proofbound_evidence::ClosureKind::ExternalEvidence
                    | proofbound_evidence::ClosureKind::Toolchain
            )
        })
        .map(|closure| closure.id.clone())
        .collect::<Vec<_>>();
    let shared_evidence_closures = closures
        .iter()
        .filter(|closure| {
            matches!(
                closure.kind,
                proofbound_evidence::ClosureKind::Runner
                    | proofbound_evidence::ClosureKind::ExternalEvidence
                    | proofbound_evidence::ClosureKind::Toolchain
            )
        })
        .map(closures::core_identity)
        .collect::<Result<Vec<_>>>()?;
    for closure in &closures {
        let kind = serde_json::to_value(closure.kind)?
            .as_str()
            .expect("closure kind serializes as text")
            .to_owned();
        write_canonical(
            &state_root
                .join("closures")
                .join(format!("project.{kind}.json")),
            closure,
        )?;
    }
    let mut closure_by_claim = BTreeMap::new();
    for claim in &required_closure_claims {
        let (_, manifest) = &bundle.claims[claim];
        let closure = closures::claim_closure(root, &bundle, claim, manifest)?;
        write_canonical(
            &state_root
                .join("closures")
                .join(format!("{}.semantic.json", safe_component(claim))),
            &closure,
        )?;
        closure_by_claim.insert(claim.clone(), closure.clone());
        closures.push(closure);
    }

    let execution = ExecutionContext {
        root,
        state_root: &state_root,
        store: &store,
        bundle: &bundle,
    };
    let mut records = Vec::new();
    let mut runs = Vec::new();
    for unit_id in selected_units {
        let (_, unit) = &bundle.evidence_units[&unit_id];
        let unit_claim_closures = unit
            .claims
            .iter()
            .map(|claim| {
                closure_by_claim
                    .get(claim)
                    .cloned()
                    .with_context(|| format!("PB-CLOSURE-0007: no closure for claim {claim}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let unit_closure = if unit_claim_closures.len() == 1 {
            unit_claim_closures[0].clone()
        } else {
            merge_closures(
                &unit_claim_closures,
                "unit-claim-union/1",
                closures::limits(&bundle),
            )?
        };
        if !closures.iter().any(|closure| closure.id == unit_closure.id) {
            write_canonical(
                &state_root
                    .join("closures")
                    .join(format!("{}.semantic.json", safe_component(&unit.id))),
                &unit_closure,
            )?;
            closures.push(unit_closure.clone());
        }
        let closure_ids = vec![unit_closure.id.clone()];
        let cache_key = cache_key(root, &bundle, unit, &closure_ids, &cache_context)?;
        match execute_or_reuse(
            &execution,
            unit,
            &unit_closure,
            &closure_ids,
            &shared_evidence_closures,
            &cache_key,
            options.fresh
                || options
                    .reproduce_unit
                    .as_ref()
                    .is_some_and(|selected| selected == &unit.id),
        ) {
            Ok((record, run)) => {
                records.push(record);
                runs.push(run);
            }
            Err(error) => runs.push(UnitRun {
                unit_id: unit.id.clone(),
                adapter: format!("{:?}", unit.adapter),
                cache_key,
                outcome: "unavailable-or-failed".into(),
                evidence_sha256: None,
                inventory: Vec::new(),
                diagnostics: vec![AdapterDiagnostic {
                    code: "PB-ADAPTER-0900".into(),
                    message: error.to_string(),
                    path: None,
                    remediation: Some(
                        "install the pinned tool/adapter and reproduce this exact unit".into(),
                    ),
                }],
            }),
        }
    }

    records.extend(synthesize_review_records(
        root,
        &bundle,
        &identity,
        &closure_by_claim,
        &mut closures,
        &shared_evidence_closures,
    )?);
    normalize_and_check_records(&bundle, &mut records)?;

    let mut inputs = Vec::new();
    let mut statuses = Vec::new();
    let mut identities = BTreeMap::new();
    for claim_id in selected {
        let input = compile_claim(&bundle, &claim_id, tier, &records, &closure_by_claim)?;
        let status = derive_claim_status(&input);
        let input_bytes = canonical_json(&input)?;
        let input_identity = domain_hash(CLAIM_INPUT_DOMAIN, &input_bytes);
        let input_path = state_root
            .join("compiled/claims")
            .join(format!("{}.json", safe_component(&claim_id)));
        write_bytes(&input_path, &input_bytes)?;
        identities.insert(claim_id, input_identity);
        inputs.push(input);
        statuses.push(status);
    }
    inputs.sort_by(|left, right| left.claim.id.cmp(&right.claim.id));
    statuses.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    records.sort_by(|left, right| left.id.cmp(&right.id));
    closures.sort_by(|left, right| left.id.cmp(&right.id));
    runs.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));

    let compiled = CompiledProject {
        schema: COMPILED_SCHEMA.into(),
        project: bundle.project.project,
        project_revision: identity.revision,
        tree_state: identity.tree_state,
        reviewed_tree_sha256,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        inputs,
        statuses,
        evidence: records,
        closures,
        unit_runs: runs,
        claim_input_identities: identities,
    };
    write_canonical(&state_root.join("compiled/project.json"), &compiled)?;
    let after = worktree_snapshot(root)?;
    if before != after {
        bail!("PB-CHECK-0001: check modified the reviewed tree; only .proofbound state may change");
    }
    Ok(compiled)
}

pub fn load_compiled(root: &Path) -> Result<CompiledProject> {
    let path = root.join(".proofbound/compiled/project.json");
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| "no compiled result exists; run proofbound check first")?;
    if metadata.file_type().is_symlink() || metadata.len() > 256 << 20 {
        bail!("PB-RECEIPT-0001: compiled result crosses an unsafe boundary");
    }
    let compiled: CompiledProject = serde_json::from_slice(&fs::read(&path)?)?;
    if compiled.schema != COMPILED_SCHEMA {
        bail!("PB-RECEIPT-0002: unsupported compiled-project schema");
    }
    validate_reviewed_tree_snapshot(root, &compiled.reviewed_tree_sha256)?;
    if compiled.inputs.len() != compiled.statuses.len() {
        bail!("PB-RECEIPT-0003: claim input/status cardinality mismatch");
    }
    for input in &compiled.inputs {
        let recomputed = derive_claim_status(input);
        let Some(reported) = compiled
            .statuses
            .iter()
            .find(|status| status.claim_id == input.claim.id)
        else {
            bail!(
                "PB-RECEIPT-0004: missing reported status for {}",
                input.claim.id
            );
        };
        if &recomputed != reported {
            bail!(
                "PB-RECEIPT-0005: stored status for {} differs from recomputation",
                input.claim.id
            );
        }
        let bytes = canonical_json(input)?;
        let actual = domain_hash(CLAIM_INPUT_DOMAIN, &bytes);
        if compiled.claim_input_identities.get(input.claim.id.as_str()) != Some(&actual) {
            bail!(
                "PB-RECEIPT-0006: claim input identity drift for {}",
                input.claim.id
            );
        }
    }
    Ok(compiled)
}

pub fn release_project(root: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let identity = git_identity(root)?;
    if identity.tree_state != "clean" {
        bail!("PB-RELEASE-0001: releases require a clean reviewed tree");
    }
    let compiled = load_compiled(root)?;
    if compiled.project_revision != identity.revision || compiled.tree_state != "clean" {
        bail!("PB-RELEASE-0002: compiled receipts do not match the clean release revision");
    }
    if compiled
        .statuses
        .iter()
        .any(proofbound_core::ClaimStatus::is_build_failure)
    {
        bail!("PB-RELEASE-0003: publication is blocked by invalid or inadmissible claims");
    }
    let bundle = ProjectBundle::load(root)?;
    if compiled.inputs.len() != bundle.claims.len() {
        bail!("PB-RELEASE-0006: a release requires a full-project check, not a filtered check");
    }
    let destination = output
        .map(Path::to_owned)
        .unwrap_or_else(|| root.join(".proofbound/release"));
    if destination.exists() {
        bail!("PB-RELEASE-0004: refusing to overwrite an existing release directory");
    }
    fs::create_dir_all(destination.join("schemas"))?;
    fs::create_dir_all(destination.join("bin"))?;
    write_release_schemas(&destination.join("schemas"))?;
    copy_release_binaries(&destination)?;
    let assumptions = compiled
        .inputs
        .iter()
        .flat_map(|input| input.assumptions.iter())
        .map(|item| (item.id.to_string(), item))
        .collect::<BTreeMap<_, _>>();
    write_canonical(
        &destination.join("assumptions-ledger.json"),
        &serde_json::json!({
            "schema": "proofbound-assumptions-ledger/1",
            "assumptions": assumptions.values().collect::<Vec<_>>(),
        }),
    )?;
    let tcb = tcb_projection(&compiled)?;
    write_canonical(&destination.join("tcb-ledger.json"), &tcb)?;
    write_canonical(
        &destination.join("demo-receipts.json"),
        &serde_json::json!({
            "schema": "proofbound-demo-receipts/1",
            "claims": compiled.statuses.iter().filter(|status| {
                status.claim_id.as_str().starts_with("DEMO-")
                    || status.claim_id.as_str().starts_with("PBAC-")
            }).collect::<Vec<_>>(),
        }),
    )?;
    write_canonical(
        &destination.join("build-provenance.json"),
        &serde_json::json!({
            "schema": "proofbound-build-provenance/1",
            "project_revision": compiled.project_revision,
            "tree_state": compiled.tree_state,
            "builder": format!("proofbound {}", env!("CARGO_PKG_VERSION")),
            "signature": null,
        }),
    )?;
    let graph = merged_release_graph(&compiled)?;
    write_canonical(&destination.join("assurance-graph.json"), &graph)?;
    let sealed_files = release_sealed_files(&destination)?;
    let payload = compiled_release_value(&compiled, bundle.project.tier, graph, sealed_files)?;
    let payload_bytes = canonical_json(&payload)?;
    write_bytes(&destination.join("compiled-receipt.json"), &payload_bytes)?;
    let payload_sha256 = domain_hash("proofbound-compiled-release/3", &payload_bytes);
    write_canonical(
        &destination.join("release.json"),
        &serde_json::json!({
            "schema": "proofbound-release-envelope/3",
            "payload": "compiled-receipt.json",
            "payload_sha256": payload_sha256,
        }),
    )?;
    Ok(destination)
}

/// Construct a deterministic, proof-free release through the same graph and
/// receipt serializer used by `release_project`. This development-only smoke
/// path exists so cheap CI can exercise the independent verifier boundary
/// before invoking any proof or model-checking tool.
pub fn release_smoke(output: &Path) -> Result<PathBuf> {
    if output.exists() {
        bail!("PB-RELEASE-0004: refusing to overwrite an existing release directory");
    }

    let claim_id = ClaimId::new("PB-SMOKE-LEDGER-001")?;
    let policy = scope_built_in_policy(
        PolicyDefinition::ledger(PolicyId::new("ledger")?),
        claim_id.as_str(),
    )?;
    let semantic_closure = Sha256Digest::of_bytes(b"proofbound-release-smoke-semantic-v1");
    let evidence = EvidenceRecord {
        schema: EVIDENCE_DOMAIN.into(),
        id: EvidenceId::new("review:release-smoke")?,
        node_id: NodeId::new("review:release-smoke")?,
        unit_id: UnitId::new("unit:release-smoke")?,
        kind: EvidenceKind::Review,
        status: EvidenceStatus::Passed,
        claims: BTreeSet::from([claim_id.clone()]),
        evaluation_mode: None,
        binding_mode: None,
        theorem: None,
        artifact_binding: None,
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        python_property: None,
        static_check: None,
        distribution_reproduction: None,
        independence: None,
        inventoried_targets: BTreeSet::new(),
        assumptions: BTreeSet::new(),
        premises: BTreeSet::new(),
        open_obligation: None,
        provenance: EvidenceProvenance {
            project_revision: "proofbound-release-smoke-v1".into(),
            tree_state: TreeState::Clean,
            semantic_source_closure: semantic_closure,
            additional_closures: Vec::new(),
            input_artifacts: Vec::new(),
            generated_artifacts: Vec::new(),
            tool: ToolIdentity {
                name: "proofbound-release-smoke".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                identity_sha256: Sha256Digest::of_bytes(b"proofbound-release-smoke-tool-v1"),
            },
            adapter: ToolIdentity {
                name: "proofbound-cli".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                identity_sha256: Sha256Digest::of_bytes(b"proofbound-release-smoke-adapter-v1"),
            },
            execution_kind: ExecutionKind::CompilerInternal,
            commands: Vec::new(),
            runs: Vec::new(),
            normalization: "proofbound-release-smoke/1".into(),
            reproduction_command: CommandSpec {
                program: "proofbound".into(),
                args: vec!["release-smoke".into()],
                environment_allowlist: Vec::new(),
            },
            started_unix_ms: 0,
            completed_unix_ms: 0,
            deterministic_result_identity: Sha256Digest::of_bytes(
                b"proofbound-release-smoke-result-v1",
            ),
            unit_configuration_sha256: Sha256Digest::of_bytes(
                b"proofbound-release-smoke-configuration-v1",
            ),
            resource_budget: ResourceBudget::default(),
            resource_usage: ResourceUsage::default(),
            cache_origin: CacheOrigin::Executed,
            prior_receipt_sha256: None,
            python_plugins: Vec::new(),
        },
    };
    let closure = ClosureRecord {
        schema: "proofbound-source-closure/1".into(),
        id: format!("sha256:{}", semantic_closure.to_hex()),
        kind: proofbound_evidence::ClosureKind::Semantic,
        root: ".".into(),
        claim_id: Some(claim_id.to_string()),
        members: vec![ClosureMember {
            path: "release-smoke.synthetic".into(),
            sha256: sha256_bytes(b"proofbound release smoke synthetic member"),
            bytes: 41,
        }],
        total_bytes: 41,
        discovery: "unit-claim-union/1".into(),
        tool_identity: None,
    };
    let claim = ClaimDefinition {
        schema: "proofbound-claim/1".into(),
        id: claim_id.clone(),
        node_id: NodeId::new(format!("claim:{claim_id}"))?,
        title: "Deterministic release construction smoke claim".into(),
        statement: "The release serializer preserves a Tier-0 assurance ledger.".into(),
        public_language: Some(
            "The portable release smoke remains an open Tier-0 ledger entry.".into(),
        ),
        subject: NodeId::new("subject:release-smoke")?,
        policy: policy.id.clone(),
        tier: Some(Tier::Ledger),
        cited_evidence: BTreeSet::from([evidence.id.clone()]),
        assumptions: BTreeSet::new(),
        open_obligations: BTreeSet::from([OpenObligation {
            id: ObligationId::new("open:PB-SMOKE-LEDGER-001:0")?,
            statement: "No formal proof is claimed by this smoke fixture.".into(),
            remediation: "Run the registered project proof units for formal assurance.".into(),
        }]),
        out_of_scope: BTreeSet::new(),
        primary_linkage: Some(LinkageFacet::ModelOnly),
        registered_inputs: BTreeSet::new(),
        registered_domain_language: None,
    };
    let graph = graph_for_claim(&claim, &policy, std::slice::from_ref(&evidence), &[], &[])?;
    let input = ClaimEvaluationInput {
        project_tier: Tier::Ledger,
        claim,
        policy,
        graph,
        evidence: vec![evidence.clone()],
        assumptions: Vec::new(),
        premises: Vec::new(),
    };
    let status = derive_claim_status(&input);
    if status.is_build_failure() {
        bail!("PB-RELEASE-0019: internal release-smoke claim is inadmissible");
    }
    let compiled = CompiledProject {
        schema: COMPILED_SCHEMA.into(),
        project: "proofbound-release-smoke".into(),
        project_revision: "proofbound-release-smoke-v1".into(),
        tree_state: "clean".into(),
        reviewed_tree_sha256: sha256_bytes(b"proofbound-release-smoke-v1"),
        generated_at: "1970-01-01T00:00:00.000Z".into(),
        inputs: vec![input],
        statuses: vec![status],
        evidence: vec![evidence],
        closures: vec![closure],
        unit_runs: Vec::new(),
        claim_input_identities: BTreeMap::new(),
    };
    let graph = merged_release_graph(&compiled)?;
    let tcb = tcb_projection(&compiled)?;
    write_canonical(&output.join("tcb-ledger.json"), &tcb)?;
    let sealed_files = release_sealed_files(output)?;
    let payload = compiled_release_value(&compiled, 0, graph, sealed_files)?;
    let payload_bytes = canonical_json(&payload)?;
    write_bytes(&output.join("compiled-receipt.json"), &payload_bytes)?;
    write_canonical(
        &output.join("release.json"),
        &serde_json::json!({
            "schema": "proofbound-release-envelope/3",
            "payload": "compiled-receipt.json",
            "payload_sha256": domain_hash("proofbound-compiled-release/3", &payload_bytes),
        }),
    )?;
    Ok(output.to_owned())
}

fn write_release_schemas(destination: &Path) -> Result<()> {
    const SCHEMAS: &[(&str, &[u8])] = &[
        ("README.md", include_bytes!("../../../schemas/README.md")),
        (
            "adapter-observation.schema.json",
            include_bytes!("../../../schemas/adapter-observation.schema.json"),
        ),
        (
            "adapter-protocol.schema.json",
            include_bytes!("../../../schemas/adapter-protocol.schema.json"),
        ),
        (
            "assumption.schema.json",
            include_bytes!("../../../schemas/assumption.schema.json"),
        ),
        (
            "checker-result.schema.json",
            include_bytes!("../../../schemas/checker-result.schema.json"),
        ),
        (
            "claim.schema.json",
            include_bytes!("../../../schemas/claim.schema.json"),
        ),
        (
            "closure.schema.json",
            include_bytes!("../../../schemas/closure.schema.json"),
        ),
        (
            "demo-registry.schema.json",
            include_bytes!("../../../schemas/demo-registry.schema.json"),
        ),
        (
            "error.schema.json",
            include_bytes!("../../../schemas/error.schema.json"),
        ),
        (
            "evidence-unit.schema.json",
            include_bytes!("../../../schemas/evidence-unit.schema.json"),
        ),
        (
            "evidence.schema.json",
            include_bytes!("../../../schemas/evidence.schema.json"),
        ),
        (
            "graph.schema.json",
            include_bytes!("../../../schemas/graph.schema.json"),
        ),
        (
            "lean-expr-v1.cddl",
            include_bytes!("../../../schemas/lean-expr-v1.cddl"),
        ),
        (
            "model-check-unit.schema.json",
            include_bytes!("../../../schemas/model-check-unit.schema.json"),
        ),
        (
            "mutation-registry.schema.json",
            include_bytes!("../../../schemas/mutation-registry.schema.json"),
        ),
        (
            "policy.schema.json",
            include_bytes!("../../../schemas/policy.schema.json"),
        ),
        (
            "project.schema.json",
            include_bytes!("../../../schemas/project.schema.json"),
        ),
        (
            "receipt.schema.json",
            include_bytes!("../../../schemas/receipt.schema.json"),
        ),
        (
            "report.schema.json",
            include_bytes!("../../../schemas/report.schema.json"),
        ),
        (
            "review.schema.json",
            include_bytes!("../../../schemas/review.schema.json"),
        ),
        (
            "tcb.schema.json",
            include_bytes!("../../../schemas/tcb.schema.json"),
        ),
        (
            "translation-toolchain-lock.schema.json",
            include_bytes!("../../../schemas/translation-toolchain-lock.schema.json"),
        ),
        (
            "translation-unit.schema.json",
            include_bytes!("../../../schemas/translation-unit.schema.json"),
        ),
    ];

    for (name, bytes) in SCHEMAS {
        write_bytes(&destination.join(name), bytes)?;
    }
    Ok(())
}

pub fn update_unit(root: &Path, unit_id: &str) -> Result<()> {
    let identity = git_identity(root)?;
    if identity.tree_state != "clean" {
        bail!("PB-UPDATE-0001: update requires a clean tree before regeneration");
    }
    let bundle = ProjectBundle::load(root)?;
    let requested_translation = bundle.translation_units.get(unit_id);
    let (_, unit) = if let Some(unit) = bundle.evidence_units.get(unit_id) {
        unit
    } else if let Some((path, _)) = requested_translation {
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        bundle
            .evidence_units
            .values()
            .find(|(_, candidate)| {
                candidate.adapter == AdapterKind::CharonAeneas
                    && candidate.operation.manifest.as_deref() == Some(relative.as_str())
            })
            .with_context(|| {
                format!(
                    "PB-UPDATE-0002: translation unit {unit_id} has no registered evidence adapter"
                )
            })?
    } else {
        bail!("PB-UPDATE-0003: unknown update unit {unit_id}");
    };
    let translation = if unit.operation.kind == OperationKind::Translation {
        let manifest = unit.operation.manifest.as_deref().with_context(|| {
            format!(
                "PB-UPDATE-0002: translation evidence {} has no manifest",
                unit.id
            )
        })?;
        let found = bundle
            .translation_units
            .values()
            .find(|(path, _)| {
                path.strip_prefix(root)
                    .ok()
                    .map(|path| path.to_string_lossy().replace('\\', "/"))
                    .as_deref()
                    == Some(manifest)
            })
            .with_context(|| {
                format!(
                    "PB-UPDATE-0002: translation evidence {} references unregistered manifest {manifest}",
                    unit.id
                )
            })?;
        if requested_translation.is_some_and(|requested| requested.1.id != found.1.id) {
            bail!(
                "PB-UPDATE-0002: update target {unit_id} resolved to mismatched translation {}",
                found.1.id
            );
        }
        Some(&found.1)
    } else {
        None
    };
    let output_boundaries = translation.is_none().then(|| {
        vec![UpdateBoundaryGroup {
            paths: unit.outputs.clone(),
            recursive: false,
        }]
    });
    if let Some(boundaries) = &output_boundaries {
        validate_output_boundaries(boundaries)?;
    }

    let request = adapter_unit(root, &bundle, unit)?;
    let shadow = sealed_update_shadow(
        root,
        unit.resource_budget
            .disk_bytes
            .min(bundle.project.limits.max_total_bytes),
        bundle.project.limits.max_files,
    )?;
    let response = adapter::invoke(shadow.path(), unit, "update", request)?;
    if !response.success {
        bail!(
            "PB-UPDATE-0004: update failed: {}",
            response
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let changes = classify_update_changes(root, shadow.path(), unit.resource_budget.disk_bytes)?;
    let changed = changes.all();
    let mut owned_replacement = None;
    if let Some(translation) = translation {
        let destinations = translation_destinations(translation)?;
        let observed = response.inventory.iter().cloned().collect::<BTreeSet<_>>();
        if observed.len() != response.inventory.len() || observed != destinations {
            bail!(
                "PB-UPDATE-0005: translation adapter output inventory differs from the manifest; expected={}, observed={}",
                destinations.iter().cloned().collect::<Vec<_>>().join(", "),
                observed.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        validate_translation_update(
            unit_id,
            root,
            shadow.path(),
            translation,
            &destinations,
            &changes,
            bundle.project.limits.max_files,
            unit.resource_budget.disk_bytes,
        )?;
        owned_replacement = Some(begin_owned_tree_replacement(
            root,
            shadow.path(),
            &translation.generated_dir,
        )?);
    } else {
        let boundaries = output_boundaries
            .as_ref()
            .expect("non-translation updates have evidence-owned boundaries");
        enforce_update_output_postcondition(unit_id, &changed, boundaries)?;
        apply_update_changes(root, shadow.path(), &changed)?;
    }
    let reviewed = changed_reviewed_paths(root)?;
    if let Some(boundaries) = &output_boundaries {
        enforce_update_output_postcondition(unit_id, &reviewed, boundaries)?;
    }
    if reviewed != changed {
        bail!(
            "PB-UPDATE-0005: imported update paths differ from Git's reviewed diff; changed={}, reviewed={}",
            changed.into_iter().collect::<Vec<_>>().join(", "),
            reviewed.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    if let Some(replacement) = owned_replacement {
        replacement.commit()?;
    }
    println!("updated {} through {}", unit_id, unit.adapter.executable());
    println!("Review the resulting diff, then run the same verify-only gates.");
    Ok(())
}

struct UpdateShadow {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl UpdateShadow {
    fn path(&self) -> &Path {
        &self.root
    }
}

fn sealed_update_shadow(root: &Path, byte_limit: u64, file_limit: usize) -> Result<UpdateShadow> {
    let temporary = tempfile::Builder::new()
        .prefix("proofbound-update-")
        .tempdir()?;
    let shadow_root = temporary.path().join("project");
    fs::create_dir_all(&shadow_root)?;
    let paths = git_nul_paths(root, &["ls-files", "--cached", "-z"])?;
    if paths.len() > file_limit {
        bail!(
            "PB-UPDATE-0005: reviewed tree has {} files, above the configured limit {file_limit}",
            paths.len()
        );
    }
    let mut copied = 0_u64;
    for relative in paths {
        validate_update_relative_path(&relative)?;
        let source = root.join(&relative);
        let metadata = fs::symlink_metadata(&source)
            .with_context(|| format!("PB-UPDATE-0005: tracked input {relative:?} is missing"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("PB-UPDATE-0005: tracked input {relative:?} must be a regular non-symlink file");
        }
        copied = copied
            .checked_add(metadata.len())
            .context("PB-UPDATE-0005: shadow byte count overflowed")?;
        if copied > byte_limit {
            bail!("PB-UPDATE-0005: update shadow exceeds its {byte_limit}-byte input budget");
        }
        let target = shadow_root.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, target)?;
    }
    Ok(UpdateShadow {
        _temporary: temporary,
        root: shadow_root,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct UpdateChanges {
    writes: BTreeSet<String>,
    deletions: BTreeSet<String>,
}

impl UpdateChanges {
    fn all(&self) -> BTreeSet<String> {
        self.writes.union(&self.deletions).cloned().collect()
    }
}

fn classify_update_changes(root: &Path, shadow: &Path, byte_limit: u64) -> Result<UpdateChanges> {
    let original = update_file_inventory(root, byte_limit)?;
    let updated = update_file_inventory(shadow, byte_limit)?;
    let writes = updated
        .iter()
        .filter(|(path, digest)| original.get(*path) != Some(*digest))
        .map(|(path, _)| path.clone())
        .collect();
    let deletions = original
        .keys()
        .filter(|path| !updated.contains_key(*path))
        .cloned()
        .collect();
    Ok(UpdateChanges { writes, deletions })
}

#[cfg(test)]
fn changed_update_paths(root: &Path, shadow: &Path, byte_limit: u64) -> Result<BTreeSet<String>> {
    Ok(classify_update_changes(root, shadow, byte_limit)?.all())
}

fn update_file_inventory(root: &Path, byte_limit: u64) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    let mut bytes = 0_u64;
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .ok()
                .is_none_or(|relative| !excluded_update_path(relative))
        });
    for entry in walker {
        let entry = entry?;
        let relative = entry.path().strip_prefix(root)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "PB-UPDATE-0005: update shadow contains symlink {}",
                relative.display()
            );
        }
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            bail!(
                "PB-UPDATE-0005: update shadow contains special file {}",
                relative.display()
            );
        }
        let relative = relative.to_string_lossy().replace('\\', "/");
        validate_update_relative_path(&relative)?;
        let content = fs::read(entry.path())?;
        bytes = bytes
            .checked_add(content.len() as u64)
            .context("PB-UPDATE-0005: update output byte count overflowed")?;
        if bytes > byte_limit {
            bail!("PB-UPDATE-0005: update shadow exceeds its {byte_limit}-byte disk budget");
        }
        files.insert(relative, sha256_bytes(&content));
    }
    Ok(files)
}

fn excluded_update_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                ".git"
                    | "target"
                    | ".lake"
                    | ".proofbound"
                    | ".venv"
                    | "node_modules"
                    | "__pycache__"
                    | ".pytest_cache"
                    | ".mypy_cache"
                    | ".ruff_cache"
            )
        )
    })
}

fn validate_update_relative_path(relative: &str) -> Result<()> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("PB-UPDATE-0005: unsafe update path {relative:?}");
    }
    Ok(())
}

fn validate_owned_update_path(relative: &str) -> Result<()> {
    validate_update_relative_path(relative)?;
    if excluded_update_path(Path::new(relative)) {
        bail!(
            "PB-UPDATE-0005: generated ownership path {relative:?} contains a reserved project-control component"
        );
    }
    Ok(())
}

fn translation_destinations(translation: &TranslationUnitManifest) -> Result<BTreeSet<String>> {
    validate_owned_update_path(&translation.generated_dir)?;
    let destinations = translation
        .invocations
        .iter()
        .flat_map(|invocation| invocation.outputs.iter())
        .map(|output| output.destination.clone())
        .collect::<BTreeSet<_>>();
    let declared_count = translation
        .invocations
        .iter()
        .map(|invocation| invocation.outputs.len())
        .sum::<usize>();
    if destinations.len() != declared_count || destinations.is_empty() {
        bail!(
            "PB-UPDATE-0005: translation manifest has an empty or duplicate output destination inventory"
        );
    }
    for destination in &destinations {
        validate_owned_update_path(destination)?;
        if !path_matches_boundary(destination, &translation.generated_dir, true)
            || destination == &translation.generated_dir
        {
            bail!(
                "PB-UPDATE-0005: translation destination {destination:?} is not strictly beneath its generated directory"
            );
        }
    }
    Ok(destinations)
}

#[allow(clippy::too_many_arguments)]
fn validate_translation_update(
    unit_id: &str,
    root: &Path,
    shadow: &Path,
    translation: &TranslationUnitManifest,
    destinations: &BTreeSet<String>,
    changes: &UpdateChanges,
    max_files: usize,
    max_bytes: u64,
) -> Result<()> {
    let generated = owned_tree_inventory(shadow, &translation.generated_dir, max_files, max_bytes)?;
    let actual = generated.keys().cloned().collect::<BTreeSet<_>>();
    if &actual != destinations {
        let missing = destinations
            .difference(&actual)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual.difference(destinations).cloned().collect::<Vec<_>>();
        bail!(
            "PB-UPDATE-0005: translation {unit_id} shadow tree does not match its exact output map; missing={missing:?}, extra={extra:?}"
        );
    }
    let unauthorized_writes = changes
        .writes
        .difference(destinations)
        .cloned()
        .collect::<Vec<_>>();
    let unauthorized_deletions = changes
        .deletions
        .iter()
        .filter(|path| !path_matches_boundary(path, &translation.generated_dir, true))
        .cloned()
        .collect::<Vec<_>>();
    if !unauthorized_writes.is_empty() || !unauthorized_deletions.is_empty() {
        bail!(
            "PB-UPDATE-0005: translation {unit_id} escaped its ownership boundary; unauthorized writes={unauthorized_writes:?}, unauthorized deletions={unauthorized_deletions:?}"
        );
    }
    // Observe the original owned tree as well. This rejects a pre-existing
    // symlink or special file before any committed bytes are touched.
    if root.join(&translation.generated_dir).exists() {
        owned_tree_inventory(root, &translation.generated_dir, max_files, max_bytes)?;
    }
    Ok(())
}

fn owned_tree_inventory(
    root: &Path,
    relative: &str,
    max_files: usize,
    max_bytes: u64,
) -> Result<BTreeMap<String, String>> {
    validate_owned_update_path(relative)?;
    let canonical_root = root
        .canonicalize()
        .context("PB-UPDATE-0005: project root cannot be resolved")?;
    let candidate = canonical_root.join(relative);
    reject_update_target_symlinks(&canonical_root, &candidate)?;
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("PB-UPDATE-0005: generated directory {relative:?} is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("PB-UPDATE-0005: generated boundary {relative:?} is not a regular directory");
    }
    let mut files = BTreeMap::new();
    let mut bytes = 0_u64;
    for entry in walkdir::WalkDir::new(&candidate)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "PB-UPDATE-0005: generated tree contains symlink {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            bail!(
                "PB-UPDATE-0005: generated tree contains special file {}",
                entry.path().display()
            );
        }
        if files.len() >= max_files {
            bail!("PB-UPDATE-0005: generated tree exceeds its {max_files}-file limit");
        }
        let path = repository_relative(&canonical_root, entry.path()).with_context(|| {
            format!(
                "PB-UPDATE-0005: generated path escaped the project: {}",
                entry.path().display()
            )
        })?;
        let content = fs::read(entry.path())?;
        bytes = bytes
            .checked_add(content.len() as u64)
            .context("PB-UPDATE-0005: generated byte count overflowed")?;
        if bytes > max_bytes {
            bail!("PB-UPDATE-0005: generated tree exceeds its {max_bytes}-byte limit");
        }
        files.insert(path, sha256_bytes(&content));
    }
    Ok(files)
}

struct OwnedTreeReplacement {
    target: PathBuf,
    backup: Option<PathBuf>,
    rejected: PathBuf,
    active: bool,
}

impl OwnedTreeReplacement {
    fn rollback(&mut self) -> std::io::Result<()> {
        if !self.active {
            return Ok(());
        }
        if self.target.exists() {
            fs::rename(&self.target, &self.rejected)?;
        }
        if let Some(backup) = &self.backup {
            fs::rename(backup, &self.target)?;
        }
        if self.rejected.exists() {
            fs::remove_dir_all(&self.rejected)?;
        }
        self.active = false;
        Ok(())
    }

    fn commit(self) -> Result<()> {
        self.commit_with_cleanup(|path| fs::remove_dir_all(path))
    }

    fn commit_with_cleanup<F>(mut self, cleanup: F) -> Result<()>
    where
        F: FnOnce(&Path) -> std::io::Result<()>,
    {
        if let Some(backup) = &self.backup
            && let Err(cleanup_error) = cleanup(backup)
        {
            let target_display = self.target.display().to_string();
            let backup_display = backup.display().to_string();
            // remove_dir_all is allowed to make partial progress before it
            // returns an error. Never try to restore from a backup after its
            // cleanup has started: the reviewed installed tree is the only
            // complete copy we can still guarantee.
            self.active = false;
            bail!(
                "PB-UPDATE-0005: generated-tree backup cleanup failed ({cleanup_error}); the installed tree remains at {target_display}, and any residual backup remains at {backup_display}"
            );
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for OwnedTreeReplacement {
    fn drop(&mut self) {
        if self.active {
            let _ = self.rollback();
        }
    }
}

fn begin_owned_tree_replacement(
    root: &Path,
    shadow: &Path,
    relative: &str,
) -> Result<OwnedTreeReplacement> {
    validate_owned_update_path(relative)?;
    let source = shadow.join(relative);
    let source_metadata = fs::symlink_metadata(&source).with_context(|| {
        format!("PB-UPDATE-0005: generated shadow tree {relative:?} is missing")
    })?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        bail!("PB-UPDATE-0005: generated shadow tree {relative:?} is not a directory");
    }
    let target = root.join(relative);
    reject_update_target_symlinks(root, &target)?;
    let parent = target
        .parent()
        .context("PB-UPDATE-0005: generated directory has no parent")?;
    fs::create_dir_all(parent)?;
    reject_update_target_symlinks(root, parent)?;
    let transaction_root = root.join(".proofbound/update-transactions");
    reject_update_target_symlinks(root, &transaction_root)?;
    fs::create_dir_all(&transaction_root)?;
    reject_update_target_symlinks(root, &transaction_root)?;

    let staging = tempfile::Builder::new()
        .prefix("staging-")
        .tempdir_in(&transaction_root)?;
    copy_regular_tree(&source, staging.path())?;

    let target_existed = match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("PB-UPDATE-0005: generated target {relative:?} is not a regular directory");
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let backup_path = if target_existed {
        let reservation = tempfile::Builder::new()
            .prefix("backup-")
            .tempdir_in(&transaction_root)?;
        let path = reservation.keep();
        fs::remove_dir(&path)?;
        Some(path)
    } else {
        None
    };
    let rejected_reservation = tempfile::Builder::new()
        .prefix("rejected-")
        .tempdir_in(&transaction_root)?;
    let rejected = rejected_reservation.keep();
    fs::remove_dir(&rejected)?;
    let staging_path = staging.keep();

    if let Some(backup) = &backup_path
        && let Err(error) = fs::rename(&target, backup)
    {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(error.into());
    }

    if let Err(install_error) = fs::rename(&staging_path, &target) {
        let rollback = backup_path
            .as_ref()
            .map_or(Ok(()), |backup| fs::rename(backup, &target));
        let _ = fs::remove_dir_all(&staging_path);
        if let Err(rollback_error) = rollback {
            bail!(
                "PB-UPDATE-0005: atomic generated-tree install failed ({install_error}) and rollback failed ({rollback_error}); backup remains at {}",
                backup_path.expect("rollback requires a backup").display()
            );
        }
        return Err(install_error.into());
    }
    Ok(OwnedTreeReplacement {
        target,
        backup: backup_path,
        rejected,
        active: true,
    })
}

#[cfg(test)]
fn replace_owned_tree_atomically(root: &Path, shadow: &Path, relative: &str) -> Result<()> {
    begin_owned_tree_replacement(root, shadow, relative)?.commit()
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "PB-UPDATE-0005: generated shadow tree contains symlink {}",
                entry.path().display()
            );
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), target)?;
        } else {
            bail!(
                "PB-UPDATE-0005: generated shadow tree contains special file {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn apply_update_changes(root: &Path, shadow: &Path, changed: &BTreeSet<String>) -> Result<()> {
    for relative in changed {
        validate_update_relative_path(relative)?;
        let source = shadow.join(relative);
        let target = root.join(relative);
        match fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("PB-UPDATE-0005: generated output {relative:?} is not a regular file")
            }
            Ok(_) => {
                reject_update_target_symlinks(root, &target)?;
                let content = fs::read(&source)?;
                write_bytes(&target, &content)?;
                fs::set_permissions(&target, fs::metadata(&source)?.permissions())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                reject_update_target_symlinks(root, &target)?;
                match fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                        fs::remove_file(&target)?;
                    }
                    Ok(_) => {
                        bail!("PB-UPDATE-0005: refusing to delete non-file output {relative:?}")
                    }
                    Err(target_error) if target_error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(target_error) => return Err(target_error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reject_update_target_symlinks(root: &Path, target: &Path) -> Result<()> {
    let relative = target
        .strip_prefix(root)
        .context("PB-UPDATE-0005: output target escaped the project")?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!(
                "PB-UPDATE-0005: output target traverses symlink {}",
                current.display()
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpdateBoundaryGroup {
    paths: Vec<String>,
    recursive: bool,
}

fn validate_output_boundaries(groups: &[UpdateBoundaryGroup]) -> Result<()> {
    for group in groups {
        if group.paths.is_empty() {
            bail!("PB-UPDATE-0005: update unit has no explicit output boundary");
        }
        for boundary in &group.paths {
            let path = Path::new(boundary);
            if boundary.is_empty()
                || boundary.contains(['\\', '*', '?', '[', ']'])
                || path.is_absolute()
                || path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                bail!(
                    "PB-UPDATE-0005: output boundary {boundary:?} is not a literal normalized repository-relative path"
                );
            }
        }
    }
    Ok(())
}

fn changed_reviewed_paths(root: &Path) -> Result<BTreeSet<String>> {
    let tracked = git_nul_paths(
        root,
        &["diff", "--name-only", "--no-renames", "-z", "HEAD", "--"],
    )?;
    let untracked = git_nul_paths(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    tracked
        .into_iter()
        .chain(untracked)
        .filter(|path| path != ".proofbound" && !path.starts_with(".proofbound/"))
        .map(|path| {
            if path.contains('\\')
                || Path::new(&path).is_absolute()
                || Path::new(&path)
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                bail!("PB-UPDATE-0005: Git reported unsafe changed path {path:?}");
            }
            Ok(path)
        })
        .collect()
}

fn git_nul_paths(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        bail!(
            "PB-UPDATE-0005: Git could not enumerate update changes: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| {
            std::str::from_utf8(path)
                .map(str::to_owned)
                .context("PB-UPDATE-0005: Git returned a non-UTF-8 changed path")
        })
        .collect()
}

fn enforce_update_output_postcondition(
    unit_id: &str,
    changed: &BTreeSet<String>,
    boundary_groups: &[UpdateBoundaryGroup],
) -> Result<()> {
    let unauthorized = changed
        .iter()
        .filter(|changed| {
            boundary_groups.iter().any(|group| {
                !group
                    .paths
                    .iter()
                    .any(|boundary| path_matches_boundary(changed, boundary, group.recursive))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    if !unauthorized.is_empty() {
        bail!(
            "PB-UPDATE-0005: update {unit_id} changed reviewed paths outside its explicit output boundary: {}; inspect and restore these changes before retrying",
            unauthorized.join(", ")
        );
    }
    Ok(())
}

fn path_matches_boundary(path: &str, boundary: &str, recursive: bool) -> bool {
    let path = Path::new(path);
    let boundary = Path::new(boundary);
    path == boundary || (recursive && path.starts_with(boundary))
}

fn select_claims(bundle: &ProjectBundle, options: &CheckOptions) -> Result<Vec<String>> {
    if let Some(unit_id) = &options.reproduce_unit {
        let (_, unit) = bundle
            .evidence_units
            .get(unit_id)
            .with_context(|| format!("PB-UNIT-0001: unknown evidence unit {unit_id}"))?;
        let mut claims = unit.claims.clone();
        claims.sort();
        return Ok(claims);
    }
    let mut claims = bundle
        .claims
        .iter()
        .filter(|(id, (_, claim))| {
            options
                .claim
                .as_ref()
                .is_none_or(|selected| selected == *id)
                && options
                    .profile
                    .as_ref()
                    .is_none_or(|profile| profile == &claim.profile)
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    if let Some(id) = &options.claim
        && !bundle.claims.contains_key(id)
    {
        bail!("PB-CLAIM-0001: unknown claim {id}");
    }
    claims.sort();
    if claims.is_empty() {
        bail!("PB-CLAIM-0002: no claims match the requested selection");
    }
    Ok(claims)
}

fn select_units(
    bundle: &ProjectBundle,
    claims: &[String],
    options: &CheckOptions,
) -> Result<Vec<String>> {
    if let Some(unit) = &options.reproduce_unit {
        if !bundle.evidence_units.contains_key(unit) {
            bail!("PB-UNIT-0001: unknown evidence unit {unit}");
        }
        return Ok(vec![unit.clone()]);
    }
    let selected = claims.iter().cloned().collect::<BTreeSet<_>>();
    let mut units = bundle
        .evidence_units
        .iter()
        .filter(|(_, (_, unit))| unit.claims.iter().any(|claim| selected.contains(claim)))
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    units.sort();
    Ok(units)
}

fn registered_model_check<'a>(
    bundle: &'a ProjectBundle,
    unit: &EvidenceUnitManifest,
) -> Result<Option<&'a ModelCheckUnitManifest>> {
    if unit.adapter != AdapterKind::Kani {
        return Ok(None);
    }
    if unit.kind != ManifestEvidenceKind::BoundedCheck {
        bail!("PB-ADAPTER-0017: Kani evidence must be registered as bounded-check");
    }
    let relative = unit
        .operation
        .manifest
        .as_deref()
        .context("PB-ADAPTER-0017: Kani evidence has no model-check manifest")?;
    let (registered_path, model) = bundle.model_check_units.get(&unit.id).with_context(|| {
        format!(
            "PB-ADAPTER-0017: Kani evidence {} has no registered model-check unit",
            unit.id
        )
    })?;
    if registered_path != &bundle.root.join(relative) {
        bail!(
            "PB-ADAPTER-0017: Kani evidence {} does not reference its registered model-check manifest",
            unit.id
        );
    }
    // Validate every duplicated execution field here as well as in the adapter.
    // The adapter establishes what ran; this independent producer-side check
    // establishes that the receipt projects the same registered semantics.
    let _ = bounded_check_from_registered_model(unit, model, &model.harnesses)?;
    Ok(Some(model))
}

fn bounded_check_from_registered_model(
    unit: &EvidenceUnitManifest,
    model: &ModelCheckUnitManifest,
    observed_inventory: &[String],
) -> Result<BoundedCheckEvidence> {
    let registered_assumptions = model
        .assumptions
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if model.schema != "proofbound-model-check-unit/1"
        || model.adapter != "kani"
        || model.id != unit.id
        || unit.operation.package.as_deref() != Some(model.package.as_str())
        || unit.operation.targets != model.harnesses
        || unit.expected_inventory != model.harnesses
        || unit.claims != model.claims
        || unit.bounded_domain.as_ref() != Some(&model.domain)
        || unit.resource_budget != model.resource_budget
        || model.solver.trim().is_empty()
        || model.unwind == 0
        || model.assumptions.len() > 4096
        || registered_assumptions.len() != model.assumptions.len()
        || model
            .assumptions
            .iter()
            .any(|assumption| assumption.trim().is_empty() || assumption.chars().count() > 4096)
    {
        bail!("PB-ADAPTER-0017: Kani evidence and registered model-check semantics disagree");
    }

    let harnesses = model.harnesses.iter().cloned().collect::<BTreeSet<_>>();
    let observed = observed_inventory.iter().cloned().collect::<BTreeSet<_>>();
    if harnesses.len() != model.harnesses.len()
        || observed.len() != observed_inventory.len()
        || observed != harnesses
    {
        bail!("PB-ADAPTER-0016: exact Kani harness inventory does not match the registration");
    }

    let unwind = u64::from(model.unwind);
    Ok(BoundedCheckEvidence {
        domain: BoundedDomain {
            id: UnitId::new(model.domain.id.clone())?,
            description: model.domain.description.clone(),
            registration_sha256: Sha256Digest::of_bytes(canonical_json(&model.domain)?),
            cardinality: Some(model.domain.cardinality),
            constraints: model
                .domain
                .ordering_key
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
        solver: model.solver.clone(),
        assumptions: model.assumptions.clone(),
        harnesses: harnesses.clone(),
        unwind_bounds: harnesses
            .into_iter()
            .map(|harness| (harness, unwind))
            .collect(),
    })
}

/// Return the one manifest-owned target inventory an adapter must establish.
///
/// Translation units own their complete typed closure in the registered
/// translation manifest; `operation.targets` remains the separately checked
/// ordered start-root list. Every other adapter uses `expected_inventory`. An
/// empty registration is never evidence, regardless of subprocess exit
/// status.
fn registered_adapter_inventory(
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
) -> Result<Vec<String>> {
    let inventory = if unit.adapter == AdapterKind::CharonAeneas {
        let manifest = unit.operation.manifest.as_deref().with_context(|| {
            format!(
                "PB-ADAPTER-0016: translation unit {} has no registered manifest",
                unit.id
            )
        })?;
        let manifest_path = bundle.root.join(manifest);
        let translation = bundle
            .translation_units
            .values()
            .find(|(path, _)| path == &manifest_path)
            .map(|(_, translation)| translation)
            .with_context(|| {
                format!("PB-ADAPTER-0016: translation manifest {manifest:?} is not registered")
            })?;
        translation.canonical_translated_closure_inventory()
    } else {
        unit.canonical_expected_inventory()
    };
    let unique = inventory.iter().collect::<BTreeSet<_>>();
    if inventory.is_empty()
        || inventory.len() > 100_000
        || unique.len() != inventory.len()
        || inventory.iter().any(|item| {
            item.trim().is_empty()
                || item.chars().count() > 4096
                || item.chars().any(char::is_control)
        })
    {
        bail!(
            "PB-ADAPTER-0016: adapter unit {} has no exact nonempty bounded unique inventory registration",
            unit.id
        );
    }
    Ok(inventory)
}

fn execute_or_reuse(
    context: &ExecutionContext<'_>,
    unit: &EvidenceUnitManifest,
    semantic_closure: &ClosureRecord,
    closure_ids: &[String],
    additional_closures: &[ClosureIdentity],
    cache_key: &str,
    fresh: bool,
) -> Result<(EvidenceRecord, UnitRun)> {
    // Mutation evidence is only meaningful when the compiler can join the
    // registered preimage to the exact source closure under review. Perform
    // this check before either execution or cache lookup so a stale receipt
    // cannot bypass a changed registry or closure.
    registered_mutation(context.root, context.bundle, unit, Some(semantic_closure))?;
    let cache_path = context
        .state_root
        .join("cache")
        .join(format!("{}.json", cache_key.trim_start_matches("sha256:")));
    if !fresh
        && let Some((record, prior_digest)) = reusable_cached_record(
            context,
            unit,
            semantic_closure,
            closure_ids,
            additional_closures,
            cache_key,
            &cache_path,
        )
    {
        let digest = context.store.put(EVIDENCE_DOMAIN, &record)?;
        return Ok((
            record,
            UnitRun {
                unit_id: unit.id.clone(),
                adapter: format!("{:?}", unit.adapter),
                cache_key: cache_key.into(),
                outcome: "verified-from-cache".into(),
                evidence_sha256: Some(digest),
                inventory: registered_adapter_inventory(context.bundle, unit)?,
                diagnostics: vec![AdapterDiagnostic {
                    code: "PB-CACHE-0002".into(),
                    message: format!("reused exact prior receipt {prior_digest}"),
                    path: None,
                    remediation: None,
                }],
            },
        ));
    }

    let registered_model = registered_model_check(context.bundle, unit)?;
    let request_unit = adapter_unit(context.root, context.bundle, unit)?;
    let response = adapter::invoke(context.root, unit, "check", request_unit)?;
    let record = response_to_record(
        context.root,
        context.bundle,
        unit,
        registered_model,
        closure_ids,
        additional_closures,
        &response,
    )?;
    let digest = context.store.put(EVIDENCE_DOMAIN, &record)?;
    write_canonical(
        &cache_path,
        &CacheReference {
            schema: "proofbound-cache-ref/1".into(),
            cache_key: cache_key.into(),
            evidence_sha256: digest.clone(),
        },
    )?;
    Ok((
        record,
        UnitRun {
            unit_id: unit.id.clone(),
            adapter: response.adapter,
            cache_key: cache_key.into(),
            outcome: if response.success {
                "verified-now".into()
            } else {
                "failed".into()
            },
            evidence_sha256: Some(digest),
            inventory: response.inventory,
            diagnostics: response.diagnostics,
        },
    ))
}

/// Invalid cache state is deliberately collapsed to a miss. A corrupt index,
/// missing CAS object, digest mismatch, stale closure, or wrong unit identity
/// must trigger execution rather than either acceptance or an unavailable
/// result.
fn reusable_cached_record(
    context: &ExecutionContext<'_>,
    unit: &EvidenceUnitManifest,
    semantic_closure: &ClosureRecord,
    closure_ids: &[String],
    additional_closures: &[ClosureIdentity],
    cache_key: &str,
    cache_path: &Path,
) -> Option<(EvidenceRecord, String)> {
    let reference: CacheReference = serde_json::from_slice(&fs::read(cache_path).ok()?).ok()?;
    if reference.schema != "proofbound-cache-ref/1" || reference.cache_key != cache_key {
        return None;
    }
    let mut record: EvidenceRecord = context
        .store
        .get(EVIDENCE_DOMAIN, &reference.evidence_sha256)
        .ok()?;
    let [semantic_closure_id] = closure_ids else {
        return None;
    };
    let expected_id = EvidenceId::new(canonical_reference(unit.kind, &unit.id)).ok()?;
    let expected_node = NodeId::new(format!("evidence:{expected_id}")).ok()?;
    let expected_unit = UnitId::new(format!("unit:{}", unit.id)).ok()?;
    let expected_claims = unit
        .claims
        .iter()
        .map(|id| ClaimId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()
        .ok()?;
    let expected_assumptions = unit
        .assumptions
        .iter()
        .map(|id| AssumptionId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()
        .ok()?;
    let expected_premises = unit
        .premises
        .iter()
        .map(|id| PremiseId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()
        .ok()?;
    let expected_inventory = registered_adapter_inventory(context.bundle, unit)
        .ok()?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected_evaluation = unit
        .evaluation_mode
        .and_then(|mode| serde_json::from_value(serde_json::to_value(mode).ok()?).ok());
    let expected_binding = unit
        .binding_mode
        .and_then(|mode| serde_json::from_value(serde_json::to_value(mode).ok()?).ok());
    let expected_bounded_check = match registered_model_check(context.bundle, unit).ok()? {
        Some(model) => {
            Some(bounded_check_from_registered_model(unit, model, &unit.expected_inventory).ok()?)
        }
        None => None,
    };
    if record.schema != EVIDENCE_DOMAIN
        || record.id != expected_id
        || record.node_id != expected_node
        || record.unit_id != expected_unit
        || record.kind != manifest_evidence_kind(unit.kind)
        || record.status != EvidenceStatus::Passed
        || record.claims != expected_claims
        || record.assumptions != expected_assumptions
        || record.premises != expected_premises
        || record.evaluation_mode != expected_evaluation
        || record.binding_mode != expected_binding
        || record.bounded_check.as_ref() != expected_bounded_check.as_ref()
        || trusted_transcription_record_matches_unit(unit, &record).is_err()
        || mutation_record_matches_registration(
            context.root,
            context.bundle,
            unit,
            semantic_closure,
            &record,
        )
        .is_err()
        || !has_observed_adapter_execution(&record)
        || record.inventoried_targets != expected_inventory
        || record.provenance.semantic_source_closure != parse_digest(semantic_closure_id).ok()?
        || record.provenance.additional_closures != additional_closures
        || expected_claims
            .iter()
            .any(|claim| record.validate(claim).is_err())
    {
        return None;
    }
    let identity = git_identity(context.root).ok()?;
    record.provenance.project_revision = identity.revision;
    record.provenance.tree_state = match identity.tree_state.as_str() {
        "clean" => TreeState::Clean,
        "dirty" => TreeState::Dirty,
        _ => return None,
    };
    record.provenance.cache_origin = CacheOrigin::Reused;
    record.provenance.prior_receipt_sha256 = parse_digest(&reference.evidence_sha256).ok();
    Some((record, reference.evidence_sha256))
}

/// Parse adapter-authored core evidence without allowing typed collection
/// normalization to change what the adapter actually signed. In particular,
/// `BTreeSet` deserialization must not hide duplicate or reordered inventory
/// entries present in the wire value.
fn canonical_direct_evidence_record(value: &serde_json::Value) -> Result<Option<EvidenceRecord>> {
    let Ok(record) = serde_json::from_value::<EvidenceRecord>(value.clone()) else {
        return Ok(None);
    };
    if canonical_json(&record)? != canonical_json(value)? {
        bail!(
            "PB-ADAPTER-0027: direct evidence wire value differs from its canonical typed encoding"
        );
    }
    Ok(Some(record))
}

fn response_to_record(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    registered_model: Option<&ModelCheckUnitManifest>,
    closure_ids: &[String],
    additional_closures: &[ClosureIdentity],
    response: &AdapterResponse,
) -> Result<EvidenceRecord> {
    if !response.success {
        bail!(
            "PB-ADAPTER-0010: adapter rejected unit {}: {}",
            unit.id,
            response
                .diagnostics
                .iter()
                .map(|item| item.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let expected_inventory = registered_adapter_inventory(bundle, unit)?;
    if response.inventory != expected_inventory {
        bail!(
            "PB-ADAPTER-0016: adapter response inventory differs from the exact nonempty registration for {}",
            unit.id
        );
    }
    let value = response
        .evidence
        .clone()
        .context("PB-ADAPTER-0011: successful response omitted evidence")?;
    // Artifact identity must come through the checker-observation protocol.
    // Accepting an adapter-authored core record here would let a checker
    // manufacture a theorem link instead of joining independently checked
    // bytes to the audited theorem statement.
    let mut record = if matches!(
        unit.kind,
        ManifestEvidenceKind::ArtifactSoundness
            | ManifestEvidenceKind::TrustedTranscription
            | ManifestEvidenceKind::MutationWitness
    ) || unit.adapter == AdapterKind::Kani
    {
        observation_to_record(root, bundle, unit, registered_model, closure_ids, &value)?
    } else if let Some(record) = canonical_direct_evidence_record(&value)? {
        record
    } else {
        observation_to_record(root, bundle, unit, registered_model, closure_ids, &value)?
    };
    bind_record_to_execution(
        root,
        bundle,
        unit,
        closure_ids,
        additional_closures,
        &mut record,
    )?;
    Ok(record)
}

fn bind_record_to_execution(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    closure_ids: &[String],
    additional_closures: &[ClosureIdentity],
    record: &mut EvidenceRecord,
) -> Result<()> {
    let expected_id = EvidenceId::new(canonical_reference(unit.kind, &unit.id))?;
    let expected_node = NodeId::new(format!("evidence:{expected_id}"))?;
    let expected_unit = UnitId::new(format!("unit:{}", unit.id))?;
    let expected_kind = manifest_evidence_kind(unit.kind);
    let expected_claims = unit
        .claims
        .iter()
        .map(|id| ClaimId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_assumptions = unit
        .assumptions
        .iter()
        .map(|id| AssumptionId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_premises = unit
        .premises
        .iter()
        .map(|id| PremiseId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_evaluation = unit.evaluation_mode.map(|mode| {
        serde_json::from_value(serde_json::to_value(mode).expect("enum serializes"))
            .expect("evaluation vocabularies agree")
    });
    let expected_binding = unit.binding_mode.map(|mode| {
        serde_json::from_value(serde_json::to_value(mode).expect("enum serializes"))
            .expect("binding vocabularies agree")
    });
    if record.id != expected_id
        || record.node_id != expected_node
        || record.unit_id != expected_unit
        || record.kind != expected_kind
        || record.claims != expected_claims
        || record.assumptions != expected_assumptions
        || record.premises != expected_premises
        || record.evaluation_mode != expected_evaluation
        || record.binding_mode != expected_binding
    {
        bail!(
            "PB-ADAPTER-0021: evidence identity or configured qualifiers differ from unit {}",
            unit.id
        );
    }
    let expected_inventory = registered_adapter_inventory(bundle, unit)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if record.inventoried_targets != expected_inventory {
        bail!(
            "PB-ADAPTER-0022: evidence inventory differs from configured unit {}",
            unit.id
        );
    }
    if record.provenance.cache_origin != CacheOrigin::Executed
        || record.provenance.prior_receipt_sha256.is_some()
    {
        bail!("PB-ADAPTER-0023: fresh adapter evidence claims a cache origin");
    }
    if !has_observed_adapter_execution(record) {
        bail!("PB-ADAPTER-0026: adapter evidence must use observed-processes provenance");
    }

    let identity = git_identity(root)?;
    let expected_tree_state = match identity.tree_state.as_str() {
        "clean" => TreeState::Clean,
        "dirty" => TreeState::Dirty,
        other => bail!("PB-PROVENANCE-0002: unsupported tree state {other:?}"),
    };
    if record.provenance.project_revision != identity.revision
        || record.provenance.tree_state != expected_tree_state
    {
        bail!(
            "PB-ADAPTER-0024: evidence revision or tree state does not match the current execution"
        );
    }

    if record.provenance.adapter.name != unit.adapter.executable() {
        bail!(
            "PB-ADAPTER-0024: evidence names adapter {:?}, expected {:?}",
            record.provenance.adapter.name,
            unit.adapter.executable()
        );
    }
    // The compiler observes the executable boundary itself. Adapter-authored
    // version strings remain useful labels, but neither an adapter nor a tool
    // may choose its own content identity. The tool identity is a canonical
    // composite of every executable used by this adapter kind (for example,
    // cargo + rustc or cargo + cargo-kani), while the adapter identity is the
    // exact binary that spoke the protocol.
    let execution_identities = adapter::cache_identities(root, unit.adapter)?;
    let adapter_key = format!("adapter:{}", unit.adapter.executable());
    record.provenance.adapter.identity_sha256 = parse_digest(
        execution_identities
            .get(&adapter_key)
            .with_context(|| format!("PB-ADAPTER-0024: missing {adapter_key} identity"))?,
    )?;
    let tool_identities = execution_identities
        .iter()
        .filter(|(name, _)| name.starts_with("tool:"))
        .collect::<BTreeMap<_, _>>();
    record.provenance.tool.identity_sha256 =
        Sha256Digest::of_bytes(canonical_json(&tool_identities)?);

    // Claim closures are compiler-owned facts.  An adapter can report its
    // more specific input artifacts, but it cannot choose which reviewed
    // claim closure its evidence is attached to.
    let [semantic_closure] = closure_ids else {
        bail!("PB-CLOSURE-0008: an evidence unit must bind one exact semantic closure");
    };
    record.provenance.semantic_source_closure = parse_digest(semantic_closure)?;
    record.provenance.additional_closures = additional_closures.to_vec();
    trusted_transcription_record_matches_unit(unit, record)?;

    for claim in &expected_claims {
        record.validate(claim).map_err(|errors| {
            anyhow!(
                "PB-ADAPTER-0025: evidence for unit {} violates the evidence schema: {errors}",
                unit.id
            )
        })?;
    }
    Ok(())
}

fn has_observed_adapter_execution(record: &EvidenceRecord) -> bool {
    record.provenance.execution_kind == ExecutionKind::ObservedProcesses
}

#[derive(Clone, Debug)]
struct RegisteredMutationBinding {
    mutation_id: String,
    subject: String,
    guard: String,
    registry: ArtifactIdentity,
    target_preimage: ArtifactIdentity,
    mutant_artifact: ArtifactIdentity,
    target_postimage: ArtifactIdentity,
    witness_source: ArtifactIdentity,
    check_id: String,
    affected_claims: Vec<String>,
}

fn registered_mutation(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    semantic_closure: Option<&ClosureRecord>,
) -> Result<Option<RegisteredMutationBinding>> {
    let is_mutation = unit.kind == ManifestEvidenceKind::MutationWitness;
    let Some(config) = unit.mutation.as_ref() else {
        if is_mutation {
            bail!("PB-MUTATION-0001: mutation-witness unit omitted its replay registration");
        }
        return Ok(None);
    };
    if !is_mutation {
        bail!("PB-MUTATION-0001: non-mutation unit declared a replay registration");
    }

    let registry_artifact = registered_file_artifact(root, bundle, &config.registry)?;
    let registry_path = root.join(&config.registry);
    let registry: MutationRegistry = load_toml(
        &registry_path,
        ManifestLimits {
            max_bytes: bundle.project.limits.max_manifest_bytes,
            max_files: bundle.project.limits.max_files,
        },
    )
    .with_context(|| {
        format!(
            "PB-MUTATION-0001: cannot load registered mutation {}",
            config.registry
        )
    })?;
    let mutation = &registry.mutation;
    let target_preimage = registered_file_artifact(root, bundle, &mutation.target_path)?;
    let mutant_artifact = registered_file_artifact(root, bundle, &mutation.mutant_path)?;
    let witness_source = registered_file_artifact(root, bundle, &mutation.witness_path)?;
    let target_postimage = ArtifactIdentity {
        logical_name: target_preimage.logical_name.clone(),
        sha256: mutant_artifact.sha256,
        size_bytes: mutant_artifact.size_bytes,
    };

    if target_preimage.sha256 != parse_digest(&mutation.target_preimage_sha256)?
        || mutant_artifact.sha256 != parse_digest(&mutation.mutant_sha256)?
        || witness_source.sha256 != parse_digest(&mutation.witness_sha256)?
    {
        bail!(
            "PB-MUTATION-0002: registered mutation {} does not match its sealed source, mutant, or witness bytes",
            mutation.id
        );
    }
    let input_paths = unit.inputs.iter().cloned().collect::<BTreeSet<_>>();
    let mut expected_inputs = BTreeSet::from([
        config.registry.clone(),
        mutation.target_path.clone(),
        mutation.mutant_path.clone(),
        mutation.witness_path.clone(),
    ]);
    if unit.adapter == AdapterKind::NodeTest {
        expected_inputs.extend(["package-lock.json".to_owned(), "package.json".to_owned()]);
    }
    if input_paths.len() != unit.inputs.len() || input_paths != expected_inputs {
        bail!(
            "PB-MUTATION-0003: mutation unit {} must register exactly its registry, target, mutant, and witness inputs",
            unit.id
        );
    }
    let unit_claims = unit.claims.iter().cloned().collect::<BTreeSet<_>>();
    let affected_claims = mutation
        .affected_claims
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if unit_claims.len() != unit.claims.len()
        || affected_claims.len() != mutation.affected_claims.len()
        || unit_claims != affected_claims
        || unit.expected_inventory != [mutation.id.clone()]
    {
        bail!(
            "PB-MUTATION-0003: mutation unit {} does not exactly match its singleton registry inventory and affected claims",
            unit.id
        );
    }
    for claim_id in &mutation.affected_claims {
        let (_, claim) = bundle.claims.get(claim_id).with_context(|| {
            format!("PB-MUTATION-0003: mutation references missing claim {claim_id}")
        })?;
        if claim.subject != registry.subject {
            bail!("PB-MUTATION-0003: mutation subject disagrees with affected claim {claim_id}");
        }
    }
    if let Some(closure) = semantic_closure
        && !closure_binds_artifact(closure, &target_preimage)
    {
        bail!(
            "PB-MUTATION-0004: mutation target {} and its exact preimage bytes are not bound by the reviewed semantic source closure",
            mutation.target_path
        );
    }

    Ok(Some(RegisteredMutationBinding {
        mutation_id: mutation.id.clone(),
        subject: registry.subject,
        guard: mutation.guard.clone(),
        registry: registry_artifact,
        target_preimage,
        mutant_artifact,
        target_postimage,
        witness_source,
        check_id: mutation.witness.clone(),
        affected_claims: mutation.affected_claims.clone(),
    }))
}

fn closure_binds_artifact(closure: &ClosureRecord, artifact: &ArtifactIdentity) -> bool {
    let mut matches = closure.members.iter().filter(|member| {
        member.path == artifact.logical_name.as_str()
            && member.sha256 == format!("sha256:{}", artifact.sha256.to_hex())
            && member.bytes == artifact.size_bytes
    });
    matches.next().is_some() && matches.next().is_none()
}

fn registered_file_artifact(
    root: &Path,
    bundle: &ProjectBundle,
    relative: &str,
) -> Result<ArtifactIdentity> {
    validate_cache_relative_path(relative)?;
    let canonical_root = root
        .canonicalize()
        .context("PB-MUTATION-0002: project root cannot be resolved")?;
    let candidate = canonical_root.join(relative);
    reject_cache_symlink_components(&canonical_root, &candidate)?;
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("PB-MUTATION-0002: registered file is missing: {relative}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("PB-MUTATION-0002: registered path is not a regular file: {relative}");
    }
    if metadata.len() > bundle.project.limits.max_total_bytes {
        bail!("PB-MUTATION-0002: registered file exceeds the project byte limit: {relative}");
    }
    let bytes = fs::read(&candidate)
        .with_context(|| format!("PB-MUTATION-0002: cannot read registered file: {relative}"))?;
    Ok(ArtifactIdentity {
        logical_name: ArtifactLogicalName::new(relative.to_owned())?,
        sha256: Sha256Digest::of_bytes(&bytes),
        size_bytes: bytes.len() as u64,
    })
}

fn mutation_record_matches_registration(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    semantic_closure: &ClosureRecord,
    record: &EvidenceRecord,
) -> Result<()> {
    let registered = registered_mutation(root, bundle, unit, Some(semantic_closure))?;
    let Some(registered) = registered else {
        if record.mutation_witness.is_some() {
            bail!("PB-MUTATION-0005: non-mutation cache record carries mutation facts");
        }
        return Ok(());
    };
    let witness = record
        .mutation_witness
        .as_ref()
        .context("PB-MUTATION-0005: cached mutation evidence omitted replay facts")?;
    let expected = MutationWitnessEvidence {
        schema: "proofbound-mutation-witness/2".into(),
        mutation_id: registered.mutation_id,
        subject: registered.subject,
        guard: registered.guard,
        mutation_sha256: witness.mutation_sha256,
        registry: registered.registry,
        target_preimage: registered.target_preimage,
        mutant_artifact: registered.mutant_artifact,
        target_postimage: registered.target_postimage,
        witness_source: registered.witness_source,
        check_id: registered.check_id,
        baseline_run_index: witness.baseline_run_index,
        expected_failure: ExpectedFailure {
            run_index: witness.expected_failure.run_index,
            allowed_exit_codes: BTreeSet::from([if unit.adapter == AdapterKind::NodeTest {
                1
            } else {
                101
            }]),
        },
        proof_term_theorem: None,
    };
    let mut expected = expected;
    expected.mutation_sha256 = expected.derived_mutation_sha256(&record.claims)?;
    if witness != &expected {
        bail!("PB-MUTATION-0005: cached mutation evidence differs from its sealed registration");
    }
    Ok(())
}

fn deserialize_required_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterObservation {
    schema: String,
    unit_id: String,
    evidence_kind: String,
    outcome: ObservationOutcome,
    input_artifacts: Vec<ArtifactObservation>,
    generated_artifacts: Vec<ArtifactObservation>,
    tool: ToolObservation,
    adapter: ToolObservation,
    commands: Vec<CommandObservation>,
    runs: Vec<RunObservation>,
    started_unix_ms: u64,
    completed_unix_ms: u64,
    deterministic_result_sha256: String,
    unit_configuration_sha256: String,
    resource_budget: BudgetObservation,
    resource_usage: UsageObservation,
    inventory: Vec<String>,
    normalization: String,
    #[serde(default)]
    artifact_binding: Option<ArtifactBindingObservation>,
    #[serde(default)]
    trusted_transcription: Option<TrustedTranscriptionObservation>,
    #[serde(default)]
    mutation_replay: Option<MutationReplayObservation>,
    #[serde(default)]
    python_plugins: Vec<PythonPluginObservation>,
    #[serde(default)]
    python_property: Option<PythonPropertyObservation>,
    #[serde(default)]
    static_check: Option<StaticCheckObservation>,
    #[serde(default)]
    distribution_reproduction: Option<DistributionReproductionObservation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonPluginObservation {
    module: String,
    distribution: String,
    version: String,
    origin_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonPropertyObservation {
    schema: String,
    framework: String,
    seed: u64,
    framework_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticCheckObservation {
    schema: String,
    tool: String,
    tool_version: String,
    configuration_sha256: String,
    targets: Vec<String>,
    diagnostics: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DistributionReproductionObservation {
    schema: String,
    format: String,
    run_digests: Vec<String>,
    registered_digest: String,
    source_date_epoch: u64,
    build_backend_name: String,
    build_backend_version: String,
    #[serde(default)]
    npm_integrity: Option<String>,
    #[serde(default)]
    member_inventory: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactBindingObservation {
    artifact_logical_name: String,
    artifact_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedTranscriptionObservation {
    schema: String,
    source: ArtifactObservation,
    committed_transcription: ArtifactObservation,
    transcribed_candidate: ArtifactObservation,
    reencoded_source: ArtifactObservation,
    driver: ArtifactObservation,
    driver_abi: String,
    source_format: String,
    transcribed_format: String,
    transcriber_role_identity: String,
    reencoder_role_identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationReplayObservation {
    schema: String,
    mutation_id: String,
    registry: ArtifactObservation,
    target_preimage: ArtifactObservation,
    mutant_artifact: ArtifactObservation,
    target_postimage: ArtifactObservation,
    witness_source: ArtifactObservation,
    check_id: String,
    affected_claims: Vec<String>,
    baseline_run_index: usize,
    expected_failure: ExpectedFailureObservation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFailureObservation {
    run_index: usize,
    allowed_exit_codes: Vec<i32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ObservationOutcome {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ArtifactObservation {
    logical_name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolObservation {
    name: String,
    version: String,
    identity_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandObservation {
    program: String,
    args: Vec<String>,
    environment_allowlist: Vec<EnvironmentObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct EnvironmentObservation {
    name: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    value_sha256: Option<String>,
    secret: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunObservation {
    command_index: usize,
    #[serde(deserialize_with = "deserialize_required_option")]
    exit_code: Option<i32>,
    stdout_sha256: String,
    stderr_sha256: String,
    normalized_output_sha256: String,
    output_truncated: bool,
    duration_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetObservation {
    time_ms: u64,
    disk_bytes: u64,
    memory_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageObservation {
    time_ms: u64,
    peak_disk_bytes: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    peak_memory_bytes: Option<u64>,
}

fn observation_to_record(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    registered_model: Option<&ModelCheckUnitManifest>,
    closure_ids: &[String],
    value: &serde_json::Value,
) -> Result<EvidenceRecord> {
    let observation: AdapterObservation = serde_json::from_value(value.clone())
        .context("PB-ADAPTER-0012: unsupported evidence observation")?;
    if observation.schema != OBSERVATION_SCHEMA
        || observation.unit_id != unit.id
        || observation.evidence_kind
            != serde_json::to_value(unit.kind)?
                .as_str()
                .expect("evidence kind serializes as text")
    {
        bail!("PB-ADAPTER-0013: observation identity does not match the configured unit");
    }
    if observation.commands.is_empty()
        || observation.normalization.trim().is_empty()
        || observation.normalization.chars().count() > 1024
    {
        bail!("PB-ADAPTER-0014: observation omitted its typed command or normalization");
    }
    let kind = manifest_evidence_kind(unit.kind);
    let passed = observation.outcome == ObservationOutcome::Passed;
    let registered_expected_failure = (kind == EvidenceKind::MutationWitness)
        .then_some(observation.mutation_replay.as_ref())
        .flatten()
        .map(|replay| &replay.expected_failure);
    if observation.runs.len() != observation.commands.len()
        || observation.runs.iter().enumerate().any(|(index, run)| {
            let expected_nonzero = registered_expected_failure.is_some_and(|expected| {
                expected.run_index == index
                    && run
                        .exit_code
                        .is_some_and(|code| expected.allowed_exit_codes.contains(&code))
            });
            run.command_index != index
                || run.output_truncated
                || (passed && run.exit_code != Some(0) && !expected_nonzero)
                || parse_digest(&run.stdout_sha256).is_err()
                || parse_digest(&run.stderr_sha256).is_err()
                || parse_digest(&run.normalized_output_sha256).is_err()
        })
    {
        bail!("PB-ADAPTER-0015: observation run metadata is incomplete or truncated");
    }
    let expected_inventory = registered_adapter_inventory(bundle, unit)?;
    if observation.inventory != expected_inventory {
        bail!("PB-ADAPTER-0016: exact inventory mismatch for {}", unit.id);
    }
    let evidence_id = EvidenceId::new(canonical_reference(unit.kind, &unit.id))?;
    let premises = unit
        .premises
        .iter()
        .map(|id| PremiseId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let claims = unit
        .claims
        .iter()
        .map(|id| ClaimId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let assumptions = unit
        .assumptions
        .iter()
        .map(|id| AssumptionId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;

    let artifact_binding = match (kind, observation.artifact_binding.as_ref()) {
        (EvidenceKind::ArtifactSoundness, Some(binding)) => {
            unit.theorem.as_deref().context(
                "PB-ADAPTER-0018: artifact unit omitted its exact audited theorem declaration",
            )?;
            let mut matching_artifacts = observation.input_artifacts.iter().filter(|artifact| {
                artifact.logical_name.as_str() == binding.artifact_logical_name
                    && artifact.sha256 == binding.artifact_sha256
            });
            let artifact = matching_artifacts
                .next()
                .context("PB-ADAPTER-0018: artifact observation is not present in bound inputs")?;
            if matching_artifacts.next().is_some() {
                bail!(
                    "PB-ADAPTER-0018: artifact observation must identify exactly one bound input"
                );
            }
            Some(ArtifactBindingEvidence {
                theorem: exact_audited_theorem(root, unit)?,
                artifact: ArtifactIdentity {
                    logical_name: ArtifactLogicalName::new(artifact.logical_name.clone())?,
                    sha256: parse_digest(&artifact.sha256)?,
                    size_bytes: artifact.size_bytes,
                },
            })
        }
        (EvidenceKind::ArtifactSoundness, None) => {
            bail!("PB-ADAPTER-0018: artifact observation omitted checked binding facts")
        }
        (_, Some(_)) => {
            bail!("PB-ADAPTER-0018: non-artifact observation asserted artifact binding facts")
        }
        (_, None) => None,
    };
    let trusted_transcription = trusted_transcription_from_observation(unit, kind, &observation)?;
    let source_refinement = if kind == EvidenceKind::SourceRefinement {
        Some(SourceRefinementEvidence {
            refinement_theorem: EvidenceId::new(format!("theorem:{}-theorem", unit.id))?,
            representation_premises: premises.clone(),
            deterministic_translation: observation.runs.len() >= 2,
            pinned_toolchain: true,
            generated_axioms_clean: true,
            adapter_strength: AdapterStrength::DecisionAdequate,
        })
    } else {
        None
    };
    let bounded_check = if kind == EvidenceKind::BoundedCheck {
        let model = registered_model
            .context("PB-ADAPTER-0017: bounded observation has no registered model-check unit")?;
        Some(bounded_check_from_registered_model(
            unit,
            model,
            &observation.inventory,
        )?)
    } else {
        None
    };
    let mutation_witness =
        mutation_witness_from_observation(root, bundle, unit, kind, &claims, &observation)?;
    let observed_plugin_modules = observation
        .python_plugins
        .iter()
        .map(|plugin| plugin.module.as_str())
        .collect::<Vec<_>>();
    if observed_plugin_modules
        != unit
            .operation
            .plugins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        bail!("PB-ADAPTER-0027: Python plugin observation does not match registered plugins");
    }
    let python_plugins = observation
        .python_plugins
        .iter()
        .map(|plugin| {
            Ok(PythonPluginEvidence {
                module: plugin.module.clone(),
                distribution: plugin.distribution.clone(),
                version: plugin.version.clone(),
                origin_sha256: parse_digest(&plugin.origin_sha256)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let python_property = match (&unit.property, &observation.python_property) {
        (Some(registered), Some(observed))
            if kind == EvidenceKind::PropertyTest
                && observed.schema == "proofbound-python-property/1"
                && observed.framework
                    == serde_json::to_value(registered.framework)?
                        .as_str()
                        .expect("framework serializes as text")
                && observed.seed == registered.seed
                && python_plugins.iter().any(|plugin| {
                    plugin.module == "_hypothesis_pytestplugin"
                        && plugin.distribution == "hypothesis"
                        && plugin.version == observed.framework_version
                }) =>
        {
            Some(PythonPropertyEvidence {
                schema: observed.schema.clone(),
                framework: observed.framework.clone(),
                seed: observed.seed,
                framework_version: observed.framework_version.clone(),
            })
        }
        (None, None) => None,
        _ => bail!("PB-ADAPTER-0028: Python property observation does not match its registration"),
    };
    let static_check = match (kind, &observation.static_check) {
        (EvidenceKind::StaticCheck, Some(observed)) => {
            let configuration = unit
                .operation
                .configuration
                .as_deref()
                .context("PB-ADAPTER-0029: static-check registration omitted configuration")?;
            let matching_configuration = observation.input_artifacts.iter().filter(|artifact| {
                artifact.logical_name == configuration
                    && artifact.sha256 == observed.configuration_sha256
            });
            if observed.schema != "proofbound-static-check/1"
                || observed.diagnostics != 0
                || observed.targets
                    != if unit.adapter == AdapterKind::NodeTest {
                        unit.expected_inventory.as_slice()
                    } else {
                        unit.operation.targets.as_slice()
                    }
                || matching_configuration.count() != 1
            {
                bail!("PB-ADAPTER-0029: static-check observation disagrees with registration");
            }
            Some(StaticCheckEvidence {
                schema: observed.schema.clone(),
                tool: observed.tool.clone(),
                tool_version: observed.tool_version.clone(),
                configuration_sha256: parse_digest(&observed.configuration_sha256)?,
                targets: observed.targets.iter().cloned().collect(),
                diagnostics: observed.diagnostics,
            })
        }
        (EvidenceKind::StaticCheck, None) => {
            bail!("PB-ADAPTER-0029: static-check observation omitted its typed record")
        }
        (_, Some(_)) => bail!("PB-ADAPTER-0029: static-check record appears on another kind"),
        (_, None) => None,
    };
    let distribution_reproduction = match (
        unit.distribution.as_ref(),
        observation.distribution_reproduction.as_ref(),
    ) {
        (Some(registered), Some(observed))
            if kind == EvidenceKind::ExampleTest
                && observed.schema == "proofbound-distribution-reproduction/1"
                && observed.format
                    == serde_json::to_value(registered.format)?
                        .as_str()
                        .expect("format serializes as text")
                && observed.registered_digest == registered.artifact_sha256
                && observed.source_date_epoch == registered.source_date_epoch =>
        {
            let npm_fields_valid = if observed.format == "npm-package" {
                observed
                    .npm_integrity
                    .as_deref()
                    .is_some_and(|value| value.starts_with("sha512-") && value.len() <= 512)
                    && !observed.member_inventory.is_empty()
                    && observed.source_date_epoch == 0
                    && observed.build_backend_name == "npm"
            } else {
                observed.npm_integrity.is_none()
            };
            if observed.run_digests.len() != 2
                || observation.generated_artifacts.len() != 2
                || !npm_fields_valid
                || observed
                    .run_digests
                    .iter()
                    .enumerate()
                    .any(|(index, digest)| {
                        digest != &registered.artifact_sha256
                            || observation.generated_artifacts[index].sha256 != *digest
                    })
            {
                bail!("PB-ADAPTER-0030: distribution candidates do not match registered bytes");
            }
            Some(DistributionReproductionEvidence {
                schema: observed.schema.clone(),
                format: observed.format.clone(),
                run_digests: observed
                    .run_digests
                    .iter()
                    .map(|digest| parse_digest(digest))
                    .collect::<Result<_>>()?,
                registered_digest: parse_digest(&observed.registered_digest)?,
                source_date_epoch: observed.source_date_epoch,
                build_backend_name: observed.build_backend_name.clone(),
                build_backend_version: observed.build_backend_version.clone(),
                npm_integrity: observed.npm_integrity.clone(),
                member_inventory: observed.member_inventory.clone(),
            })
        }
        (None, None) => None,
        _ => bail!(
            "PB-ADAPTER-0030: distribution reproduction observation does not match registration"
        ),
    };
    let commands = observation
        .commands
        .iter()
        .map(core_command)
        .collect::<Result<Vec<_>>>()?;
    let runs = observation
        .runs
        .iter()
        .map(core_run)
        .collect::<Result<Vec<_>>>()?;
    let reproduction_command = CommandSpec {
        program: "proofbound".into(),
        args: vec!["reproduce".into(), unit.id.clone()],
        environment_allowlist: Vec::new(),
    };
    let additional_closures = closure_ids
        .iter()
        .map(|digest| {
            Ok(ClosureIdentity {
                kind: proofbound_core::ClosureKind::Semantic,
                sha256: parse_digest(digest)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let semantic_source_closure = Sha256Digest::of_bytes(canonical_json(
        &closure_ids.iter().collect::<BTreeSet<_>>(),
    )?);
    let execution_identity = git_identity(root)?;
    let provenance = EvidenceProvenance {
        project_revision: execution_identity.revision,
        tree_state: match execution_identity.tree_state.as_str() {
            "clean" => TreeState::Clean,
            "dirty" => TreeState::Dirty,
            other => bail!("PB-PROVENANCE-0002: unsupported tree state {other:?}"),
        },
        semantic_source_closure,
        additional_closures,
        input_artifacts: observation
            .input_artifacts
            .into_iter()
            .map(core_artifact)
            .collect::<Result<_>>()?,
        generated_artifacts: observation
            .generated_artifacts
            .into_iter()
            .map(core_artifact)
            .collect::<Result<_>>()?,
        tool: core_tool(observation.tool)?,
        adapter: core_tool(observation.adapter)?,
        execution_kind: ExecutionKind::ObservedProcesses,
        commands,
        runs,
        normalization: observation.normalization,
        reproduction_command,
        started_unix_ms: observation.started_unix_ms,
        completed_unix_ms: observation.completed_unix_ms,
        deterministic_result_identity: parse_digest(&observation.deterministic_result_sha256)?,
        unit_configuration_sha256: parse_digest(&observation.unit_configuration_sha256)?,
        resource_budget: ResourceBudget {
            time_ms: observation.resource_budget.time_ms,
            disk_bytes: observation.resource_budget.disk_bytes,
            memory_bytes: observation.resource_budget.memory_bytes,
        },
        resource_usage: ResourceUsage {
            time_ms: observation.resource_usage.time_ms,
            peak_disk_bytes: observation.resource_usage.peak_disk_bytes,
            peak_memory_bytes: observation.resource_usage.peak_memory_bytes,
        },
        cache_origin: CacheOrigin::Executed,
        prior_receipt_sha256: None,
        python_plugins,
    };
    Ok(EvidenceRecord {
        schema: EVIDENCE_DOMAIN.into(),
        id: evidence_id.clone(),
        node_id: NodeId::new(format!("evidence:{evidence_id}"))?,
        unit_id: UnitId::new(format!("unit:{}", unit.id))?,
        kind,
        status: match observation.outcome {
            ObservationOutcome::Passed => EvidenceStatus::Passed,
            ObservationOutcome::Failed => EvidenceStatus::Failed,
        },
        claims,
        evaluation_mode: unit.evaluation_mode.map(|mode| {
            serde_json::from_value(serde_json::to_value(mode).expect("enum serializes"))
                .expect("evaluation vocabularies agree")
        }),
        binding_mode: unit.binding_mode.map(|mode| {
            serde_json::from_value(serde_json::to_value(mode).expect("enum serializes"))
                .expect("binding vocabularies agree")
        }),
        theorem: None,
        artifact_binding,
        trusted_transcription,
        source_refinement,
        bounded_check,
        exhaustive_check: None,
        mutation_witness,
        python_property,
        static_check,
        distribution_reproduction,
        independence: (kind == EvidenceKind::IndependentCheck)
            .then_some(IndependenceMode::Independent),
        inventoried_targets: observation.inventory.into_iter().collect(),
        assumptions,
        premises,
        open_obligation: None,
        provenance,
    })
}

fn core_artifact(value: ArtifactObservation) -> Result<ArtifactIdentity> {
    core_artifact_ref(&value)
}

fn core_artifact_ref(value: &ArtifactObservation) -> Result<ArtifactIdentity> {
    Ok(ArtifactIdentity {
        logical_name: ArtifactLogicalName::new(value.logical_name.clone())?,
        sha256: parse_digest(&value.sha256)?,
        size_bytes: value.size_bytes,
    })
}

fn mutation_witness_from_observation(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    kind: EvidenceKind,
    claims: &BTreeSet<ClaimId>,
    observation: &AdapterObservation,
) -> Result<Option<MutationWitnessEvidence>> {
    let observed = observation.mutation_replay.as_ref();
    if kind != EvidenceKind::MutationWitness {
        if observed.is_some() {
            bail!("PB-MUTATION-0006: non-mutation observation asserted replay facts");
        }
        return Ok(None);
    }
    let observed = observed
        .context("PB-MUTATION-0006: mutation observation omitted its exact replay facts")?;
    let registered = registered_mutation(root, bundle, unit, None)?
        .context("PB-MUTATION-0006: mutation unit has no sealed registration")?;
    let observed_registry = core_artifact_ref(&observed.registry)?;
    let observed_target_preimage = core_artifact_ref(&observed.target_preimage)?;
    let observed_mutant = core_artifact_ref(&observed.mutant_artifact)?;
    let observed_target_postimage = core_artifact_ref(&observed.target_postimage)?;
    let observed_witness = core_artifact_ref(&observed.witness_source)?;
    let expected_exit = mutation_expected_exit(unit.adapter)?;
    if observation.outcome != ObservationOutcome::Passed
        || observed.schema != "proofbound-mutation-replay-observation/1"
        || observed.mutation_id != registered.mutation_id
        || observed.check_id != registered.check_id
        || observed.affected_claims != registered.affected_claims
        || observed_registry != registered.registry
        || observed_target_preimage != registered.target_preimage
        || observed_mutant != registered.mutant_artifact
        || observed_target_postimage != registered.target_postimage
        || observed_witness != registered.witness_source
        || observed.expected_failure.allowed_exit_codes != [expected_exit]
        || observed.baseline_run_index >= observed.expected_failure.run_index
    {
        bail!(
            "PB-MUTATION-0006: mutation observation disagrees with its sealed registry or exact expected-failure contract"
        );
    }
    let mut expected_inputs = vec![
        registered.registry.clone(),
        registered.target_preimage.clone(),
        registered.mutant_artifact.clone(),
        registered.witness_source.clone(),
    ];
    if unit.adapter == AdapterKind::NodeTest {
        expected_inputs.extend([
            registered_file_artifact(root, bundle, "package-lock.json")?,
            registered_file_artifact(root, bundle, "package.json")?,
        ]);
    }
    if observation.input_artifacts.len() != expected_inputs.len()
        || expected_inputs.iter().any(|expected| {
            observation
                .input_artifacts
                .iter()
                .filter_map(|artifact| core_artifact_ref(artifact).ok())
                .filter(|artifact| artifact == expected)
                .count()
                != 1
        })
        || observation.generated_artifacts.len() != 1
        || core_artifact_ref(&observation.generated_artifacts[0])? != registered.target_postimage
    {
        bail!(
            "PB-MUTATION-0007: mutation replay provenance is not the exact four-input, one-postimage boundary"
        );
    }
    let baseline = observation
        .runs
        .get(observed.baseline_run_index)
        .context("PB-MUTATION-0008: mutation baseline run index is out of bounds")?;
    let mutant = observation
        .runs
        .get(observed.expected_failure.run_index)
        .context("PB-MUTATION-0008: mutation failure run index is out of bounds")?;
    let baseline_command = observation
        .commands
        .get(observed.baseline_run_index)
        .context("PB-MUTATION-0008: mutation baseline command index is out of bounds")?;
    let mutant_command = observation
        .commands
        .get(observed.expected_failure.run_index)
        .context("PB-MUTATION-0008: mutation failure command index is out of bounds")?;
    let command_shape_valid = mutation_command_shape_valid(
        unit.adapter,
        baseline_command,
        mutant_command,
        &registered.check_id,
    );
    if baseline.exit_code != Some(0)
        || mutant.exit_code != Some(expected_exit)
        || observation
            .runs
            .iter()
            .filter(|run| run.exit_code != Some(0))
            .count()
            != 1
        || !command_shape_valid
        || baseline_command.environment_allowlist != mutant_command.environment_allowlist
    {
        bail!(
            "PB-MUTATION-0008: mutation replay did not run the same exact witness on distinct fresh baseline and mutant executables"
        );
    }

    let mut witness = MutationWitnessEvidence {
        schema: "proofbound-mutation-witness/2".into(),
        mutation_id: registered.mutation_id,
        subject: registered.subject,
        guard: registered.guard,
        mutation_sha256: Sha256Digest::of_bytes([]),
        registry: registered.registry,
        target_preimage: registered.target_preimage,
        mutant_artifact: registered.mutant_artifact,
        target_postimage: registered.target_postimage,
        witness_source: registered.witness_source,
        check_id: registered.check_id,
        baseline_run_index: observed.baseline_run_index,
        expected_failure: ExpectedFailure {
            run_index: observed.expected_failure.run_index,
            allowed_exit_codes: BTreeSet::from([expected_exit]),
        },
        proof_term_theorem: None,
    };
    witness.mutation_sha256 = witness.derived_mutation_sha256(claims)?;
    Ok(Some(witness))
}

fn mutation_expected_exit(adapter: AdapterKind) -> Result<i32> {
    match adapter {
        AdapterKind::RustTest => Ok(101),
        AdapterKind::PythonTest | AdapterKind::NodeTest => Ok(1),
        _ => bail!("PB-MUTATION-0006: unsupported mutation adapter"),
    }
}

fn mutation_command_shape_valid(
    adapter: AdapterKind,
    baseline: &CommandObservation,
    mutant: &CommandObservation,
    check_id: &str,
) -> bool {
    match adapter {
        AdapterKind::NodeTest => {
            baseline.program == mutant.program
                && baseline.args == mutant.args
                && baseline.args.len() >= 5
                && baseline.args.first().map(String::as_str) == Some("run")
                && baseline.args.get(1).map(String::as_str)
                    == check_id.split_once("::").map(|(file, _)| file)
                && baseline
                    .args
                    .iter()
                    .any(|argument| argument == "--reporter=json")
                && baseline
                    .args
                    .iter()
                    .any(|argument| argument == "--testNamePattern")
        }
        AdapterKind::PythonTest => {
            let expected_args = |root: &str| {
                vec![
                    "-m".to_owned(),
                    "pytest".to_owned(),
                    "-p".to_owned(),
                    "no:cacheprovider".to_owned(),
                    "--rootdir".to_owned(),
                    root.to_owned(),
                    "-q".to_owned(),
                    format!("{root}/{check_id}"),
                ]
            };
            baseline.program == "python3"
                && mutant.program == "python3"
                && baseline.args == expected_args("$BASELINE")
                && mutant.args == expected_args("$MUTANT")
        }
        AdapterKind::RustTest => {
            let selector = check_id
                .split_once("::")
                .map_or(check_id, |(_, selector)| selector);
            baseline.program != mutant.program
                && baseline.args == [selector, "--exact"]
                && mutant.args == [selector, "--exact"]
        }
        _ => false,
    }
}

fn trusted_transcription_from_observation(
    unit: &EvidenceUnitManifest,
    kind: EvidenceKind,
    observation: &AdapterObservation,
) -> Result<Option<TrustedTranscriptionEvidence>> {
    let Some(observed) = observation.trusted_transcription.as_ref() else {
        if kind == EvidenceKind::TrustedTranscription {
            bail!(
                "PB-ADAPTER-0026: trusted-transcription observation omitted its exact round-trip identities"
            );
        }
        return Ok(None);
    };
    if kind != EvidenceKind::TrustedTranscription {
        bail!(
            "PB-ADAPTER-0026: non-transcription observation asserted trusted-transcription facts"
        );
    }
    let config = unit.transcription.as_ref().context(
        "PB-ADAPTER-0026: trusted-transcription evidence omitted its registered transcription configuration",
    )?;
    let config_schema = serde_json::to_value(config.schema)?;
    let driver_abi = serde_json::to_value(config.driver_abi)?;
    if observed.schema != config_schema.as_str().unwrap_or_default()
        || observed.driver_abi != driver_abi.as_str().unwrap_or_default()
        || observed.source_format != config.source_format
        || observed.transcribed_format != config.transcribed_format
    {
        bail!(
            "PB-ADAPTER-0026: trusted-transcription observation disagrees with its registered schema, ABI, or formats"
        );
    }
    let mut expected_environment = unit
        .environment_allowlist
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    expected_environment.extend(["PYTHONDONTWRITEBYTECODE", "TERM"]);
    if observation.commands.iter().any(|command| {
        let actual = command
            .environment_allowlist
            .iter()
            .map(|variable| variable.name.as_str())
            .collect::<BTreeSet<_>>();
        actual.len() != command.environment_allowlist.len() || actual != expected_environment
    }) {
        bail!(
            "PB-ADAPTER-0026: trusted-transcription command environments do not exactly match the registered allowlist"
        );
    }

    let source = core_artifact_ref(&observed.source)?;
    let committed_transcription = core_artifact_ref(&observed.committed_transcription)?;
    let transcribed_candidate = core_artifact_ref(&observed.transcribed_candidate)?;
    let reencoded_source = core_artifact_ref(&observed.reencoded_source)?;
    let driver = core_artifact_ref(&observed.driver)?;
    if observation.input_artifacts.len() != 3 || observation.generated_artifacts.len() != 2 {
        bail!(
            "PB-ADAPTER-0026: trusted-transcription provenance must contain exactly three registered inputs and two observed outputs"
        );
    }
    let expected_candidate_name =
        format!("trusted-transcription/{}/transcribed-candidate", unit.id);
    let expected_reencoded_name = format!("trusted-transcription/{}/reencoded-source", unit.id);
    if source.logical_name.as_str() != config.source
        || committed_transcription.logical_name.as_str() != config.committed_transcription
        || driver.logical_name.as_str() != config.driver
        || transcribed_candidate.logical_name.as_str() != expected_candidate_name
        || reencoded_source.logical_name.as_str() != expected_reencoded_name
    {
        bail!(
            "PB-ADAPTER-0026: trusted-transcription artifact names disagree with the registered inputs or derived output names"
        );
    }
    for (label, expected) in [
        ("source", &source),
        ("committed transcription", &committed_transcription),
        ("driver", &driver),
    ] {
        let matches = observation
            .input_artifacts
            .iter()
            .filter_map(|artifact| core_artifact_ref(artifact).ok())
            .filter(|artifact| artifact == expected)
            .count();
        if matches != 1 {
            bail!(
                "PB-ADAPTER-0026: trusted-transcription {label} is not present exactly once in observed inputs"
            );
        }
    }
    for (label, expected) in [
        ("transcribed candidate", &transcribed_candidate),
        ("re-encoded source", &reencoded_source),
    ] {
        let matches = observation
            .generated_artifacts
            .iter()
            .filter_map(|artifact| core_artifact_ref(artifact).ok())
            .filter(|artifact| artifact == expected)
            .count();
        if matches != 1 {
            bail!(
                "PB-ADAPTER-0026: trusted-transcription {label} is not present exactly once in observed outputs"
            );
        }
    }

    let expected_transcriber = transcription_role_identity(TranscriptionRole::Transcriber, &driver);
    let expected_reencoder = transcription_role_identity(TranscriptionRole::Reencoder, &driver);
    if parse_digest(&observed.transcriber_role_identity)? != expected_transcriber
        || parse_digest(&observed.reencoder_role_identity)? != expected_reencoder
    {
        bail!(
            "PB-ADAPTER-0026: trusted-transcription role identities are not derived from the exact driver and fixed ABI"
        );
    }
    Ok(Some(TrustedTranscriptionEvidence {
        schema: observed.schema.clone(),
        source,
        committed_transcription,
        transcribed_candidate,
        reencoded_source,
        driver,
        transcriber: TranscriptionTcbRole {
            tcb_node: transcription_tcb_node(&unit.id, TranscriptionRole::Transcriber)?,
            role_identity: expected_transcriber,
        },
        reencoder: TranscriptionTcbRole {
            tcb_node: transcription_tcb_node(&unit.id, TranscriptionRole::Reencoder)?,
            role_identity: expected_reencoder,
        },
    }))
}

fn transcription_tcb_node(unit_id: &str, role: TranscriptionRole) -> Result<NodeId> {
    let role = match role {
        TranscriptionRole::Transcriber => "transcriber",
        TranscriptionRole::Reencoder => "reencoder",
    };
    Ok(NodeId::new(format!(
        "tcb:trusted-transcription:{unit_id}:{role}"
    ))?)
}

fn trusted_transcription_record_matches_unit(
    unit: &EvidenceUnitManifest,
    record: &EvidenceRecord,
) -> Result<()> {
    let (Some(config), Some(transcription)) = (
        unit.transcription.as_ref(),
        record.trusted_transcription.as_ref(),
    ) else {
        if unit.kind == ManifestEvidenceKind::TrustedTranscription
            || record.kind == EvidenceKind::TrustedTranscription
            || unit.transcription.is_some()
            || record.trusted_transcription.is_some()
        {
            bail!(
                "PB-CACHE-0004: trusted-transcription cache record is missing its registered typed detail"
            );
        }
        return Ok(());
    };
    if unit.kind != ManifestEvidenceKind::TrustedTranscription
        || record.kind != EvidenceKind::TrustedTranscription
        || transcription.schema
            != serde_json::to_value(config.schema)?
                .as_str()
                .unwrap_or_default()
        || transcription.source.logical_name.as_str() != config.source
        || transcription.committed_transcription.logical_name.as_str()
            != config.committed_transcription
        || transcription.driver.logical_name.as_str() != config.driver
        || transcription.transcribed_candidate.logical_name.as_str()
            != format!("trusted-transcription/{}/transcribed-candidate", unit.id)
        || transcription.reencoded_source.logical_name.as_str()
            != format!("trusted-transcription/{}/reencoded-source", unit.id)
        || transcription.transcriber.tcb_node
            != transcription_tcb_node(&unit.id, TranscriptionRole::Transcriber)?
        || transcription.reencoder.tcb_node
            != transcription_tcb_node(&unit.id, TranscriptionRole::Reencoder)?
        || transcription.transcriber.role_identity
            != transcription_role_identity(TranscriptionRole::Transcriber, &transcription.driver)
        || transcription.reencoder.role_identity
            != transcription_role_identity(TranscriptionRole::Reencoder, &transcription.driver)
    {
        bail!(
            "PB-CACHE-0004: trusted-transcription cache record disagrees with its current registration or derived identities"
        );
    }
    Ok(())
}

fn core_tool(value: ToolObservation) -> Result<ToolIdentity> {
    Ok(ToolIdentity {
        name: value.name,
        version: value.version,
        identity_sha256: parse_digest(&value.identity_sha256)?,
    })
}

fn core_command(value: &CommandObservation) -> Result<CommandSpec> {
    Ok(CommandSpec {
        program: value.program.clone(),
        args: value.args.clone(),
        environment_allowlist: value
            .environment_allowlist
            .iter()
            .map(|item| {
                Ok(EnvironmentVariable {
                    name: EnvironmentVariableName::new(item.name.clone())?,
                    value_sha256: item.value_sha256.as_deref().map(parse_digest).transpose()?,
                    secret: item.secret,
                })
            })
            .collect::<Result<_>>()?,
    })
}

fn core_run(value: &RunObservation) -> Result<ExecutionRun> {
    Ok(ExecutionRun {
        command_index: value.command_index,
        exit_code: value.exit_code,
        stdout_sha256: parse_digest(&value.stdout_sha256)?,
        stderr_sha256: parse_digest(&value.stderr_sha256)?,
        normalized_output_sha256: parse_digest(&value.normalized_output_sha256)?,
        output_truncated: value.output_truncated,
        duration_ms: value.duration_ms,
    })
}

fn exact_audited_theorem(root: &Path, unit: &EvidenceUnitManifest) -> Result<EvidenceId> {
    let bundle = ProjectBundle::load(root)?;
    let declaration = unit
        .theorem
        .as_deref()
        .context("PB-ADAPTER-0018: artifact unit omitted its exact audited theorem declaration")?;
    let theorem_unit = select_exact_theorem_unit(
        bundle
            .evidence_units
            .values()
            .map(|(_, candidate)| candidate),
        declaration,
        &unit.claims,
        &unit.id,
    )?;
    let reference = canonical_reference(theorem_unit.kind, &theorem_unit.id);
    for claim_id in &unit.claims {
        let (_, claim) = &bundle.claims[claim_id];
        if !claim
            .evidence
            .iter()
            .any(|cited| normalize_evidence_reference(cited) == reference)
        {
            bail!(
                "PB-ADAPTER-0018: claim {} does not cite exact theorem evidence {} for artifact unit {}",
                claim_id,
                reference,
                unit.id
            );
        }
    }
    EvidenceId::new(reference).map_err(Into::into)
}

fn select_exact_theorem_unit<'a>(
    candidates: impl Iterator<Item = &'a EvidenceUnitManifest>,
    declaration: &str,
    claims: &[String],
    artifact_unit_id: &str,
) -> Result<&'a EvidenceUnitManifest> {
    let matches = candidates
        .filter(|candidate| {
            candidate.kind == ManifestEvidenceKind::Theorem
                && candidate.theorem.as_deref() == Some(declaration)
                && claims.iter().all(|claim| candidate.claims.contains(claim))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!(
            "PB-ADAPTER-0018: artifact unit {} resolved unit.theorem `{}` to {} theorem evidence units (expected exactly one)",
            artifact_unit_id,
            declaration,
            matches.len()
        );
    }
    Ok(matches[0])
}

fn adapter_unit(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
) -> Result<serde_json::Value> {
    if unit.adapter != AdapterKind::Lean {
        return Ok(serde_json::to_value(unit)?);
    }
    let theorem = unit
        .theorem
        .as_deref()
        .context("PB-LEAN-0001: Lean theorem unit has no declaration")?;
    let target = unit
        .operation
        .targets
        .first()
        .context("PB-LEAN-0002: Lean theorem unit has no target")?;
    let surface = if target == theorem {
        theorem
            .rsplit_once('.')
            .map(|(module, _)| module)
            .context("PB-LEAN-0003: Lean theorem has no declaring module")?
    } else {
        target.as_str()
    };
    let mut inventory = BTreeMap::<String, serde_json::Value>::new();
    for (claim_id, (_, claim)) in &bundle.claims {
        let Some(declaration) = claim.formal_declaration.as_ref() else {
            continue;
        };
        if declaration.rsplit_once('.').map(|(module, _)| module) != Some(surface) {
            continue;
        }
        let mut project_axioms = BTreeMap::new();
        for assumption_id in &claim.assumptions {
            if let Some((_, assumption)) = bundle.assumptions.get(assumption_id)
                && let Some(citation) = &assumption.source_citation
            {
                let name = citation.split_whitespace().next().unwrap_or_default();
                if name.starts_with(surface) && name.contains('.') {
                    project_axioms.insert(name.to_owned(), assumption_id.clone());
                }
            }
        }
        inventory.insert(
            claim_id.clone(),
            serde_json::json!({
                "claim_id": claim_id,
                "declaration": declaration,
                "declaration_kind": "theorem",
                "statement_sha256": claim.statement_sha256,
                "foundational_axioms": claim.foundational_axioms,
                "project_axioms": project_axioms,
            }),
        );
    }
    let toolchain = fs::read(root.join("lean-toolchain")).unwrap_or_default();
    let environment = Sha256Digest::of_bytes(&toolchain).to_hex();
    Ok(serde_json::json!({
        "schema": "proofbound-lean-adapter-unit/1",
        "evidence_unit": unit,
        "environment_id": format!("lean:{}", &environment[..32]),
        "claim_inventory": inventory.into_values().collect::<Vec<_>>(),
        "audit": {"mode": "execute"},
    }))
}

fn compile_claim(
    bundle: &ProjectBundle,
    claim_id: &str,
    tier: Tier,
    all_records: &[EvidenceRecord],
    closures: &BTreeMap<String, ClosureRecord>,
) -> Result<ClaimEvaluationInput> {
    let (_, manifest) = &bundle.claims[claim_id];
    let claim_id_typed = ClaimId::new(claim_id)?;
    let policy = resolve_policy(bundle, manifest)?;
    let cited = cited_evidence_ids(manifest)?;
    let assumption_ids = manifest
        .assumptions
        .iter()
        .map(|id| AssumptionId::new(id.clone()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let subject = subject_node(&manifest.subject);
    let claim_tier = manifest
        .tier
        .map(Tier::try_from)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let claim = ClaimDefinition {
        schema: "proofbound-claim/1".into(),
        id: claim_id_typed,
        node_id: NodeId::new(format!("claim:{claim_id}"))?,
        title: manifest.title.clone(),
        statement: manifest.statement.clone(),
        public_language: manifest.public_language.clone(),
        subject,
        policy: policy.id.clone(),
        tier: claim_tier,
        cited_evidence: cited.clone(),
        assumptions: assumption_ids,
        open_obligations: manifest
            .open_obligations
            .iter()
            .enumerate()
            .map(|(index, statement)| OpenObligation {
                id: ObligationId::new(format!("open:{claim_id}:{index}"))
                    .expect("generated obligation ID is valid"),
                statement: statement.clone(),
                remediation: statement.clone(),
            })
            .collect(),
        out_of_scope: manifest
            .out_of_scope
            .iter()
            .enumerate()
            .map(|(index, statement)| OutOfScope {
                id: ObligationId::new(format!("scope:{claim_id}:{index}"))
                    .expect("generated scope ID is valid"),
                statement: statement.clone(),
                rationale: "registered exclusion in the claim manifest".into(),
            })
            .collect(),
        primary_linkage: manifest.primary_linkage.map(primary_linkage),
        registered_inputs: manifest
            .bounded_domain
            .as_ref()
            .map(|domain| {
                domain
                    .ordering_key
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        registered_domain_language: manifest
            .bounded_domain
            .as_ref()
            .map(|domain| domain.description.clone()),
    };

    let mut assumptions = Vec::new();
    let mut premises = Vec::new();
    for id in manifest.assumptions.iter().chain(&manifest.premises) {
        let (_, item) = &bundle.assumptions[id];
        if manifest.premises.contains(id) {
            let theorem_evidence = find_premise_owner(bundle, id)
                .map(EvidenceId::new)
                .transpose()?;
            premises.push(PremiseRecord {
                id: PremiseId::new(id.clone())?,
                node_id: NodeId::new(format!("premise:{id}"))?,
                statement: item.statement.clone(),
                category: assumption_category(item.category),
                theorem_evidence,
                scope: FlowScope::AllRegisteredInputs,
                discharge: None,
            });
        } else {
            assumptions.push(assumption_record(item)?);
        }
    }

    let review_ids = assumptions
        .iter()
        .flat_map(|item| item.review_evidence.iter().cloned())
        .collect::<BTreeSet<_>>();
    let evidence = all_records
        .iter()
        .filter(|record| cited.contains(&record.id) || review_ids.contains(&record.id))
        .cloned()
        .collect::<Vec<_>>();
    let graph = graph_for_claim(&claim, &policy, &evidence, &assumptions, &premises)?;
    if !closures.contains_key(claim_id) {
        bail!("PB-CLOSURE-0002: no semantic closure for {claim_id}");
    }
    Ok(ClaimEvaluationInput {
        project_tier: tier,
        claim,
        policy,
        graph,
        evidence,
        assumptions,
        premises,
    })
}

fn cited_evidence_ids(manifest: &ClaimManifest) -> Result<BTreeSet<EvidenceId>> {
    let mut cited = manifest
        .evidence
        .iter()
        .map(|reference| EvidenceId::new(normalize_evidence_reference(reference)))
        .collect::<Result<BTreeSet<_>, _>>()?;
    // A registered premise carries reviewed representation/runtime meaning even
    // when its eventual theorem owner is intentionally absent at Tier 0. The
    // compiler synthesizes that review receipt, so it must also make the receipt
    // part of the claim's explicit evidence closure. Otherwise a portable
    // release contains globally targeted review evidence that neither the graph
    // nor the claim cites, which the independent verifier correctly rejects.
    for premise in &manifest.premises {
        cited.insert(EvidenceId::new(format!("review:{premise}"))?);
    }
    Ok(cited)
}

fn graph_for_claim(
    claim: &ClaimDefinition,
    policy: &PolicyDefinition,
    evidence: &[EvidenceRecord],
    assumptions: &[AssumptionRecord],
    premises: &[PremiseRecord],
) -> Result<AssuranceGraph> {
    let mut nodes = BTreeMap::new();
    insert_node(
        &mut nodes,
        GraphNode {
            id: claim.node_id.clone(),
            kind: NodeKind::Claim,
            proof_environment: None,
        },
    )?;
    insert_node(
        &mut nodes,
        GraphNode {
            id: claim.subject.clone(),
            kind: NodeKind::Subject,
            proof_environment: None,
        },
    )?;
    insert_node(
        &mut nodes,
        GraphNode {
            id: policy.node_id.clone(),
            kind: NodeKind::Policy,
            proof_environment: None,
        },
    )?;
    let mut edge_specs = vec![
        (
            claim.node_id.clone(),
            claim.subject.clone(),
            EdgeKind::DependsOn,
        ),
        (
            claim.node_id.clone(),
            policy.node_id.clone(),
            EdgeKind::AdmittedByPolicy,
        ),
    ];
    for record in evidence {
        insert_node(
            &mut nodes,
            GraphNode {
                id: record.node_id.clone(),
                kind: evidence_node_kind(record.kind),
                proof_environment: record.theorem.as_ref().map(|item| item.environment.clone()),
            },
        )?;
        if let Some(transcription) = &record.trusted_transcription {
            for role in [&transcription.transcriber, &transcription.reencoder] {
                insert_node(
                    &mut nodes,
                    GraphNode {
                        id: role.tcb_node.clone(),
                        kind: NodeKind::TcbComponent,
                        proof_environment: None,
                    },
                )?;
            }
        }
        let reviews_assumption = record.kind == EvidenceKind::Review
            && assumptions
                .iter()
                .any(|assumption| assumption.review_evidence.contains(&record.id));
        if !reviews_assumption {
            edge_specs.push((
                record.node_id.clone(),
                claim.node_id.clone(),
                evidence_edge_kind(record.kind),
            ));
        }
    }
    for assumption in assumptions {
        insert_node(
            &mut nodes,
            GraphNode {
                id: assumption.node_id.clone(),
                kind: NodeKind::Assumption,
                proof_environment: None,
            },
        )?;
        edge_specs.push((
            claim.node_id.clone(),
            assumption.node_id.clone(),
            EdgeKind::Assumes,
        ));
        for review in &assumption.review_evidence {
            if let Some(record) = evidence.iter().find(|record| &record.id == review) {
                edge_specs.push((
                    assumption.node_id.clone(),
                    record.node_id.clone(),
                    EdgeKind::ReviewedBy,
                ));
            }
        }
    }
    for premise in premises {
        insert_node(
            &mut nodes,
            GraphNode {
                id: premise.node_id.clone(),
                kind: NodeKind::Premise,
                proof_environment: None,
            },
        )?;
        edge_specs.push((
            claim.node_id.clone(),
            premise.node_id.clone(),
            EdgeKind::Assumes,
        ));
        if let Some(record) = premise
            .theorem_evidence
            .as_ref()
            .and_then(|owner| evidence.iter().find(|record| record.id == *owner))
        {
            edge_specs.push((
                record.node_id.clone(),
                premise.node_id.clone(),
                EdgeKind::Assumes,
            ));
        }
    }
    let mut edges = edge_specs
        .into_iter()
        .map(|(from, to, kind)| {
            GraphEdge::checked(
                nodes
                    .get(&from)
                    .with_context(|| format!("PB-GRAPH-0002: missing edge source {from}"))?,
                nodes
                    .get(&to)
                    .with_context(|| format!("PB-GRAPH-0003: missing edge target {to}"))?,
                kind,
            )
            .with_context(|| format!("PB-GRAPH-0004: illegal {kind:?} edge {from} -> {to}"))
        })
        .collect::<Result<Vec<_>>>()?;
    edges.sort_by(|left, right| {
        (left.from(), left.to(), left.kind()).cmp(&(right.from(), right.to(), right.kind()))
    });
    edges.dedup_by(|left, right| {
        left.from() == right.from() && left.to() == right.to() && left.kind() == right.kind()
    });
    Ok(AssuranceGraph {
        schema: "proofbound-graph/1".into(),
        nodes: nodes.into_values().collect(),
        edges,
        mutual_theorem_groups: Vec::new(),
    })
}

fn insert_node(nodes: &mut BTreeMap<NodeId, GraphNode>, node: GraphNode) -> Result<()> {
    if let Some(existing) = nodes.get(&node.id)
        && existing != &node
    {
        bail!("PB-GRAPH-0001: node {} has conflicting kinds", node.id);
    }
    nodes.insert(node.id.clone(), node);
    Ok(())
}

fn evidence_node_kind(kind: EvidenceKind) -> NodeKind {
    match kind {
        EvidenceKind::Theorem => NodeKind::Theorem,
        EvidenceKind::ArtifactSoundness | EvidenceKind::TrustedTranscription => NodeKind::Artifact,
        EvidenceKind::SourceRefinement => NodeKind::TranslationUnit,
        EvidenceKind::BoundedCheck | EvidenceKind::ExhaustiveCheck => NodeKind::ModelCheckUnit,
        EvidenceKind::IndependentCheck
        | EvidenceKind::PropertyTest
        | EvidenceKind::ExampleTest
        | EvidenceKind::MutationWitness
        | EvidenceKind::StaticCheck => NodeKind::TestSuite,
        EvidenceKind::Review => NodeKind::Review,
        EvidenceKind::Assumption => NodeKind::Assumption,
        EvidenceKind::Open => NodeKind::Claim,
    }
}

fn evidence_edge_kind(kind: EvidenceKind) -> EdgeKind {
    match kind {
        EvidenceKind::Theorem => EdgeKind::Proves,
        EvidenceKind::ArtifactSoundness => EdgeKind::BindsDigest,
        EvidenceKind::TrustedTranscription => EdgeKind::Decodes,
        EvidenceKind::SourceRefinement => EdgeKind::Refines,
        EvidenceKind::BoundedCheck | EvidenceKind::ExhaustiveCheck => EdgeKind::CoversBoundedDomain,
        EvidenceKind::IndependentCheck => EdgeKind::CrossChecks,
        EvidenceKind::PropertyTest
        | EvidenceKind::ExampleTest
        | EvidenceKind::MutationWitness
        | EvidenceKind::StaticCheck => EdgeKind::Checks,
        EvidenceKind::Review => EdgeKind::ReviewedBy,
        EvidenceKind::Assumption | EvidenceKind::Open => EdgeKind::Assumes,
    }
}

fn resolve_policy(bundle: &ProjectBundle, claim: &ClaimManifest) -> Result<PolicyDefinition> {
    if claim.profile == "ledger" {
        return scope_built_in_policy(
            PolicyDefinition::ledger(PolicyId::new("ledger")?),
            &claim.id,
        );
    }
    if let Some((_, manifest)) = bundle.policies.get(&claim.profile) {
        let registered_assumptions = bundle.assumptions.keys().cloned().collect();
        return compile_custom_policy(manifest, &registered_assumptions);
    }
    let profile = match claim.profile.as_str() {
        "transcribed" => BuiltInProfile::Transcribed,
        "kernel" => BuiltInProfile::Kernel,
        "kernel-with-assumptions" => BuiltInProfile::KernelWithAssumptions,
        "artifact-bound" => BuiltInProfile::ArtifactBound,
        "source-refined" => BuiltInProfile::SourceRefined,
        "native-evaluated" => BuiltInProfile::NativeEvaluated,
        "bounded" => BuiltInProfile::Bounded,
        other => bail!("PB-POLICY-0002: unknown policy {other}"),
    };
    let foundational = if profile == BuiltInProfile::Transcribed {
        BTreeSet::new()
    } else {
        ["Classical.choice", "propext", "Quot.sound"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    };
    let project_axioms = if matches!(
        profile,
        BuiltInProfile::Transcribed | BuiltInProfile::Kernel
    ) {
        BTreeSet::new()
    } else {
        claim
            .assumptions
            .iter()
            .map(|id| AssumptionId::new(id.clone()))
            .collect::<Result<BTreeSet<_>, _>>()?
    };
    let policy = PolicyDefinition::built_in(profile, foundational, project_axioms)
        .map_err(|errors| anyhow!(errors.to_string()))?;
    scope_built_in_policy(policy, &claim.id)
}

fn scope_built_in_policy(mut policy: PolicyDefinition, claim_id: &str) -> Result<PolicyDefinition> {
    let profile = policy
        .components
        .iter()
        .next()
        .context("PB-POLICY-0003: built-in policy has no profile component")?;
    if policy.components.len() != 1 {
        bail!("PB-POLICY-0003: built-in policy has multiple profile components");
    }
    policy.id = PolicyId::new(format!("{}:{claim_id}", profile.as_str()))?;
    policy.node_id = NodeId::new(format!("policy:{}", policy.id))?;
    policy
        .validate()
        .map_err(|errors| anyhow!(errors.to_string()))?;
    Ok(policy)
}

fn compile_custom_policy(
    manifest: &PolicyManifest,
    registered_assumptions: &BTreeSet<String>,
) -> Result<PolicyDefinition> {
    let base = built_in_profile(&manifest.extends)?;
    let mut components = BTreeSet::from([base]);

    let binding = match manifest.required_binding.as_str() {
        "none" => None,
        "transcribed" => Some(BuiltInProfile::Transcribed),
        "artifact-bound" => Some(BuiltInProfile::ArtifactBound),
        "source-refined" => Some(BuiltInProfile::SourceRefined),
        other => bail!(
            "PB-POLICY-0001: policy {} has unknown required_binding {other:?}",
            manifest.id
        ),
    };
    match base {
        BuiltInProfile::Transcribed if binding != Some(BuiltInProfile::Transcribed) => {
            bail!(
                "PB-POLICY-0001: policy {} weakens transcribed to {}",
                manifest.id,
                manifest.required_binding
            );
        }
        BuiltInProfile::ArtifactBound if binding != Some(BuiltInProfile::ArtifactBound) => {
            bail!(
                "PB-POLICY-0001: policy {} weakens artifact-bound to {}",
                manifest.id,
                manifest.required_binding
            );
        }
        BuiltInProfile::SourceRefined if binding != Some(BuiltInProfile::SourceRefined) => {
            bail!(
                "PB-POLICY-0001: policy {} weakens source-refined to {}",
                manifest.id,
                manifest.required_binding
            );
        }
        _ => {}
    }
    if let Some(binding) = binding {
        components.insert(binding);
    }

    let native_base = base == BuiltInProfile::NativeEvaluated;
    if native_base && !manifest.allow_native {
        bail!(
            "PB-POLICY-0001: policy {} disables the native evaluation required by its base",
            manifest.id
        );
    }
    let native_premise_rule = match (manifest.allow_native, manifest.native_premise_count) {
        (true, Some(count)) if count > 0 => {
            components.insert(BuiltInProfile::NativeEvaluated);
            Some(NativePremiseRule::Exactly {
                count: usize::from(count),
            })
        }
        (true, _) => bail!(
            "PB-POLICY-0001: policy {} allows native evaluation without a positive exact premise count",
            manifest.id
        ),
        (false, Some(_)) => bail!(
            "PB-POLICY-0001: policy {} declares native_premise_count while native evaluation is disabled",
            manifest.id
        ),
        (false, None) => None,
    };

    if !manifest.allow_project_axioms && !manifest.allowed_project_axioms.is_empty() {
        bail!(
            "PB-POLICY-0001: policy {} lists project axioms while allow_project_axioms is false",
            manifest.id
        );
    }
    if manifest.allow_project_axioms && components.contains(&BuiltInProfile::Kernel) {
        bail!(
            "PB-POLICY-0001: policy {} cannot allow project axioms while retaining the kernel component",
            manifest.id
        );
    }
    let allowed_project_axioms = if manifest.allow_project_axioms {
        manifest
            .allowed_project_axioms
            .iter()
            .map(|id| {
                if !registered_assumptions.contains(id) {
                    bail!(
                        "PB-POLICY-0001: policy {} allowlists unregistered assumption {id}",
                        manifest.id
                    );
                }
                AssumptionId::new(id.clone()).map_err(anyhow::Error::msg)
            })
            .collect::<Result<BTreeSet<_>>>()?
    } else {
        BTreeSet::new()
    };

    let has_theorem_component = components.iter().any(|profile| {
        matches!(
            profile,
            BuiltInProfile::Kernel
                | BuiltInProfile::KernelWithAssumptions
                | BuiltInProfile::ArtifactBound
                | BuiltInProfile::SourceRefined
                | BuiltInProfile::NativeEvaluated
        )
    });
    if !has_theorem_component && !manifest.allowed_foundational_axioms.is_empty() {
        bail!(
            "PB-POLICY-0001: policy {} allowlists theorem axioms without a theorem profile",
            manifest.id
        );
    }
    if manifest.allow_exhaustive_as_proved
        && (has_theorem_component || !components.contains(&BuiltInProfile::Bounded))
    {
        bail!(
            "PB-POLICY-0001: policy {} could use exhaustive evidence to bypass its required theorem or non-bounded base",
            manifest.id
        );
    }

    let source_refined = components.contains(&BuiltInProfile::SourceRefined);
    if manifest.require_registered_premises != source_refined {
        bail!(
            "PB-POLICY-0001: policy {} must require registered premises exactly when source-refined binding is required",
            manifest.id
        );
    }
    if manifest.publication_allows_open {
        bail!(
            "PB-POLICY-0001: policy {} weakens publication by allowing OPEN claims",
            manifest.id
        );
    }
    let additional_required_evidence = if components.contains(&BuiltInProfile::Ledger) {
        // Core supports conjunctive evidence requirements, not an empirical
        // kind disjunction. Requiring an example test is the conservative
        // executable interpretation of `publication_allows_open = false`.
        BTreeSet::from([EvidenceKind::ExampleTest])
    } else {
        BTreeSet::new()
    };

    let policy = PolicyDefinition {
        schema: "proofbound-policy/1".into(),
        id: PolicyId::new(manifest.id.clone())?,
        node_id: NodeId::new(format!("policy:{}", manifest.id))?,
        components,
        allowed_foundational_axioms: manifest
            .allowed_foundational_axioms
            .iter()
            .cloned()
            .collect(),
        allowed_project_axioms,
        admit_exhaustive_as_proved: manifest.allow_exhaustive_as_proved,
        require_no_assumptions: false,
        native_premise_rule,
        additional_required_evidence,
    };
    policy
        .validate()
        .map_err(|errors| anyhow!("PB-POLICY-0001: {errors}"))?;
    Ok(policy)
}

fn built_in_profile(value: &str) -> Result<BuiltInProfile> {
    match value {
        "ledger" => Ok(BuiltInProfile::Ledger),
        "transcribed" => Ok(BuiltInProfile::Transcribed),
        "kernel" => Ok(BuiltInProfile::Kernel),
        "kernel-with-assumptions" => Ok(BuiltInProfile::KernelWithAssumptions),
        "artifact-bound" => Ok(BuiltInProfile::ArtifactBound),
        "source-refined" => Ok(BuiltInProfile::SourceRefined),
        "native-evaluated" => Ok(BuiltInProfile::NativeEvaluated),
        "bounded" => Ok(BuiltInProfile::Bounded),
        other => bail!("PB-POLICY-0001: custom policy extends unknown built-in {other}"),
    }
}

fn assumption_record(item: &proofbound_manifest::AssumptionManifest) -> Result<AssumptionRecord> {
    let id = AssumptionId::new(item.id.clone())?;
    Ok(AssumptionRecord {
        schema: "proofbound-assumption/1".into(),
        id: id.clone(),
        node_id: NodeId::new(format!("assumption:{id}"))?,
        statement: item.statement.clone(),
        category: assumption_category(item.category),
        owner: item.owner.clone(),
        rationale: item.rationale.clone(),
        scope: item.scope.clone(),
        affected_claims: item
            .affected_claims
            .iter()
            .map(|claim| ClaimId::new(claim.clone()))
            .collect::<Result<_, _>>()?,
        review_evidence: BTreeSet::from([EvidenceId::new(format!("review:{id}"))?]),
        falsification_or_discharge_plan: item.discharge_plan.clone(),
        source_citation: item.source_citation.clone(),
        status: assumption_status(item.status),
        depends_on: BTreeSet::new(),
    })
}

fn synthesize_review_records(
    root: &Path,
    bundle: &ProjectBundle,
    identity: &proofbound_evidence::GitIdentity,
    closure_by_claim: &BTreeMap<String, ClosureRecord>,
    all_closures: &mut Vec<ClosureRecord>,
    shared_closures: &[ClosureIdentity],
) -> Result<Vec<EvidenceRecord>> {
    let mut records = Vec::new();
    for (_, item) in bundle.assumptions.values() {
        let id = EvidenceId::new(format!("review:{}", item.id))?;
        let claims = item
            .affected_claims
            .iter()
            .map(|claim| ClaimId::new(claim.clone()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let claim_closures = item
            .affected_claims
            .iter()
            .filter_map(|claim| closure_by_claim.get(claim).cloned())
            .collect::<Vec<_>>();
        if claim_closures.is_empty() {
            continue;
        }
        let closure = if claim_closures.len() == 1 {
            claim_closures[0].clone()
        } else {
            merge_closures(
                &claim_closures,
                "assumption-review-claim-union/1",
                closures::limits(bundle),
            )?
        };
        if !all_closures
            .iter()
            .any(|existing| existing.id == closure.id)
        {
            all_closures.push(closure.clone());
        }
        let closure = parse_digest(&closure.id)?;
        let artifacts = validated_review_artifacts(root, &item.id, &item.review_evidence)?;
        let result = Sha256Digest::of_bytes(canonical_json(&item.review_evidence)?);
        records.push(EvidenceRecord {
            schema: EVIDENCE_DOMAIN.into(),
            id: id.clone(),
            node_id: NodeId::new(format!("review:{}", item.id))?,
            unit_id: UnitId::new(format!("assumption-review:{}", item.id))?,
            kind: EvidenceKind::Review,
            status: EvidenceStatus::Passed,
            claims,
            evaluation_mode: None,
            binding_mode: None,
            theorem: None,
            artifact_binding: None,
            trusted_transcription: None,
            source_refinement: None,
            bounded_check: None,
            exhaustive_check: None,
            mutation_witness: None,
            python_property: None,
            static_check: None,
            distribution_reproduction: None,
            independence: None,
            inventoried_targets: item.review_evidence.iter().cloned().collect(),
            assumptions: BTreeSet::new(),
            premises: BTreeSet::new(),
            open_obligation: None,
            provenance: EvidenceProvenance {
                project_revision: identity.revision.clone(),
                tree_state: if identity.tree_state == "clean" {
                    TreeState::Clean
                } else {
                    TreeState::Dirty
                },
                semantic_source_closure: closure,
                additional_closures: shared_closures.to_vec(),
                input_artifacts: artifacts,
                generated_artifacts: Vec::new(),
                tool: identity_for("human-review", "manifest-citation/1"),
                adapter: identity_for("proofbound-cli", env!("CARGO_PKG_VERSION")),
                execution_kind: ExecutionKind::CompilerInternal,
                commands: Vec::new(),
                runs: Vec::new(),
                normalization: "proofbound-reviewed-citations/1".into(),
                reproduction_command: CommandSpec {
                    program: "proofbound".into(),
                    args: vec![
                        "assumptions".into(),
                        "--claim".into(),
                        item.affected_claims[0].clone(),
                    ],
                    environment_allowlist: Vec::new(),
                },
                started_unix_ms: 0,
                completed_unix_ms: 0,
                deterministic_result_identity: result,
                unit_configuration_sha256: result,
                resource_budget: ResourceBudget {
                    time_ms: 1,
                    disk_bytes: 1,
                    memory_bytes: 1,
                },
                resource_usage: ResourceUsage::default(),
                cache_origin: CacheOrigin::Executed,
                prior_receipt_sha256: None,
                python_plugins: Vec::new(),
            },
        });
    }
    Ok(records)
}

/// Resolve every human-review citation before constructing passed evidence.
/// A review is synthetic only in the sense that it records committed human
/// evidence; missing or dangling citations must therefore fail closed.
fn validated_review_artifacts(
    root: &Path,
    assumption_id: &str,
    citations: &[String],
) -> Result<Vec<ArtifactIdentity>> {
    if citations.is_empty() {
        bail!(
            "PB-ASSUMPTION-0001: assumption {assumption_id} has no review_evidence; add a repository-relative review citation"
        );
    }

    let canonical_root = root.canonicalize().with_context(|| {
        format!(
            "PB-ASSUMPTION-0001: cannot resolve project root while validating review evidence for {assumption_id}"
        )
    })?;
    let mut artifacts = Vec::with_capacity(citations.len());
    for citation in citations {
        let (relative, anchor) = match citation.split_once('#') {
            Some((relative, anchor)) if !anchor.is_empty() && !anchor.contains('#') => {
                (relative, Some(anchor))
            }
            Some(_) => {
                bail!(
                    "PB-ASSUMPTION-0001: assumption {assumption_id} has malformed review citation {citation:?}; use path/to/file#anchor"
                )
            }
            None => (citation.as_str(), None),
        };
        let relative_path = Path::new(relative);
        if relative.is_empty()
            || relative.contains('\\')
            || relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!(
                "PB-ASSUMPTION-0001: assumption {assumption_id} review citation {citation:?} is not a normalized repository-relative path"
            );
        }

        let candidate = canonical_root.join(relative_path);
        reject_symlinked_review_path(&canonical_root, &candidate, assumption_id, citation)?;
        let canonical = candidate.canonicalize().with_context(|| {
            format!(
                "PB-ASSUMPTION-0001: assumption {assumption_id} review citation {citation:?} names a missing path"
            )
        })?;
        if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
            bail!(
                "PB-ASSUMPTION-0001: assumption {assumption_id} review citation {citation:?} must name a regular file inside the project"
            );
        }
        let bytes = fs::read(&canonical).with_context(|| {
            format!(
                "PB-ASSUMPTION-0001: cannot read review citation {citation:?} for assumption {assumption_id}"
            )
        })?;
        if let Some(anchor) = anchor
            && !review_anchor_exists(&bytes, anchor)
        {
            bail!(
                "PB-ASSUMPTION-0001: assumption {assumption_id} review citation {citation:?} names a missing anchor"
            );
        }
        artifacts.push(ArtifactIdentity {
            logical_name: ArtifactLogicalName::new(citation.clone())?,
            sha256: Sha256Digest::of_bytes(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }
    Ok(artifacts)
}

fn reject_symlinked_review_path(
    root: &Path,
    candidate: &Path,
    assumption_id: &str,
    citation: &str,
) -> Result<()> {
    let relative = candidate.strip_prefix(root).map_err(|_| {
        anyhow!(
            "PB-ASSUMPTION-0001: assumption {assumption_id} review citation {citation:?} escapes the project"
        )
    })?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!(
                "PB-ASSUMPTION-0001: assumption {assumption_id} review citation {citation:?} traverses a symlink"
            );
        }
    }
    Ok(())
}

fn review_anchor_exists(bytes: &[u8], anchor: &str) -> bool {
    if anchor.is_empty()
        || anchor.len() > 512
        || !anchor.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };

    // Line fragments are useful for code review citations that do not have
    // document headings. Both `L12` and `L12-L19` must lie in the file.
    if let Some((start, end)) = parse_line_anchor(anchor) {
        let line_count = text.lines().count();
        return start > 0 && start <= end && end <= line_count;
    }

    let html_ids = [
        format!("id=\"{anchor}\""),
        format!("id='{anchor}'"),
        format!("name=\"{anchor}\""),
        format!("name='{anchor}'"),
    ];
    if html_ids.iter().any(|marker| text.contains(marker)) {
        return true;
    }

    let mut slug_counts = BTreeMap::<String, usize>::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let hashes = trimmed
            .chars()
            .take_while(|character| *character == '#')
            .count();
        if !(1..=6).contains(&hashes)
            || !trimmed
                .as_bytes()
                .get(hashes)
                .is_some_and(u8::is_ascii_whitespace)
        {
            continue;
        }
        let mut heading = trimmed[hashes..].trim();
        heading = heading.trim_end_matches('#').trim_end();
        if let Some(explicit) = heading
            .strip_suffix('}')
            .and_then(|value| value.rsplit_once("{#"))
            .map(|(_, explicit)| explicit)
            && explicit == anchor
        {
            return true;
        }
        let base = markdown_heading_slug(heading);
        if base.is_empty() {
            continue;
        }
        let count = slug_counts.entry(base.clone()).or_default();
        let slug = if *count == 0 {
            base
        } else {
            format!("{base}-{count}")
        };
        *count += 1;
        if slug == anchor {
            return true;
        }
    }
    false
}

fn parse_line_anchor(anchor: &str) -> Option<(usize, usize)> {
    let tail = anchor.strip_prefix('L')?;
    let (start, end) = match tail.split_once("-L") {
        Some((start, end)) => (start.parse().ok()?, end.parse().ok()?),
        None => {
            let line = tail.parse().ok()?;
            (line, line)
        }
    };
    Some((start, end))
}

fn markdown_heading_slug(heading: &str) -> String {
    let mut slug = String::new();
    for character in heading.chars() {
        if character.is_alphanumeric() || matches!(character, '-' | '_') {
            slug.extend(character.to_lowercase());
        } else if character.is_whitespace() {
            slug.push('-');
        }
    }
    slug
}

fn normalize_and_check_records(
    bundle: &ProjectBundle,
    records: &mut [EvidenceRecord],
) -> Result<()> {
    let unit_kinds = bundle
        .evidence_units
        .iter()
        .map(|(id, (_, unit))| (id.as_str(), unit.kind))
        .collect::<BTreeMap<_, _>>();
    for record in records {
        if record.kind != EvidenceKind::Review {
            let unit_key = record
                .unit_id
                .as_str()
                .strip_prefix("unit:")
                .unwrap_or(record.unit_id.as_str());
            let expected = unit_kinds
                .get(unit_key)
                .context("PB-ADAPTER-0019: evidence names an unknown unit")?;
            if manifest_evidence_kind(*expected) != record.kind {
                bail!("PB-ADAPTER-0020: adapter changed evidence kind for {unit_key}");
            }
        }
        let canonical_id = normalize_evidence_reference(record.id.as_str());
        if canonical_id != record.id.as_str() {
            record.id = EvidenceId::new(canonical_id)?;
        }
        if let Some(theorem) = &record.theorem
            && let Some((_, claim)) = bundle.claims.get(theorem.attributed_claim.as_str())
            && let (Some(declaration), Some(encoding), Some(digest)) = (
                &claim.formal_declaration,
                &claim.statement_encoding,
                &claim.statement_sha256,
            )
            && (declaration != &theorem.declaration
                || encoding != &theorem.statement_encoding
                || strip_digest(digest) != theorem.statement_sha256.to_hex())
        {
            record.status = EvidenceStatus::Drifted;
        }
    }
    Ok(())
}

fn cache_key(
    root: &Path,
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
    closures: &[String],
    cache_context: &[String],
) -> Result<String> {
    let inputs = cache_input_identities(bundle, unit)?;
    let mut environment = BTreeMap::new();
    for name in &unit.environment_allowlist {
        let secret = ["SECRET", "TOKEN", "PASSWORD", "KEY"]
            .iter()
            .any(|marker| name.contains(marker));
        if secret && std::env::var_os(name).is_some() {
            bail!(
                "PB-CACHE-0003: verification unit {} cannot reuse evidence across a secret environment input {name}",
                unit.id
            );
        }
        environment.insert(
            name.clone(),
            std::env::var_os(name).map(|value| sha256_bytes(value.to_string_lossy().as_bytes())),
        );
    }
    let tool_identities = adapter::cache_identities(root, unit.adapter)?;
    cache_key_identity(
        unit,
        closures,
        cache_context,
        &inputs,
        &environment,
        &tool_identities,
    )
}

#[derive(Debug, Deserialize)]
struct CacheCargoMetadata {
    packages: Vec<CacheCargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
    resolve: Option<CacheCargoResolve>,
}

#[derive(Debug, Deserialize)]
struct CacheCargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CacheCargoResolve {
    nodes: Vec<CacheCargoNode>,
}

#[derive(Debug, Deserialize)]
struct CacheCargoNode {
    id: String,
    dependencies: Vec<String>,
}

fn cache_input_identities(
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
) -> Result<BTreeMap<String, String>> {
    let root = &bundle.root;
    let mut roots = unit.inputs.iter().cloned().collect::<BTreeSet<_>>();
    roots.extend(cargo_execution_input_paths(bundle, unit)?);
    if unit.operation.kind == OperationKind::Translation {
        let manifest = unit.operation.manifest.as_deref().with_context(|| {
            format!(
                "PB-CACHE-0001: translation unit {} has no registered manifest",
                unit.id
            )
        })?;
        let (manifest_path, translation) = bundle
            .translation_units
            .values()
            .find(|(path, _)| repository_relative(root, path).as_deref() == Some(manifest))
            .with_context(|| {
                format!(
                    "PB-CACHE-0001: translation unit {} references unregistered manifest {manifest}",
                    unit.id
                )
            })?;
        roots.insert(repository_relative(root, manifest_path).with_context(|| {
            format!(
                "PB-CACHE-0001: translation manifest {} escaped the project",
                manifest_path.display()
            )
        })?);
        roots.insert(translation.generated_dir.clone());
        roots.insert(translation.handwritten_refinement.clone());
        roots.extend(
            translation
                .external_bridges
                .iter()
                .map(|bridge| bridge.file.clone()),
        );
        roots.extend(translation.import_mapping.source_roots.iter().cloned());
        roots.extend(
            translation
                .invocations
                .iter()
                .map(|invocation| invocation.cargo_manifest.clone()),
        );
    }
    if let Some(config) = unit.mutation.as_ref() {
        roots.insert(config.registry.clone());
        let registry: MutationRegistry = load_toml(
            &root.join(&config.registry),
            ManifestLimits {
                max_bytes: bundle.project.limits.max_manifest_bytes,
                max_files: bundle.project.limits.max_files,
            },
        )
        .with_context(|| {
            format!(
                "PB-CACHE-0001: cannot load registered mutation {}",
                config.registry
            )
        })?;
        roots.extend([
            registry.mutation.target_path,
            registry.mutation.mutant_path,
            registry.mutation.witness_path,
        ]);
    }
    let mut identities = collect_cache_path_identities(
        root,
        &roots,
        bundle.project.limits.max_files,
        bundle.project.limits.max_total_bytes,
    )?;
    if unit.operation.kind == OperationKind::CargoTest {
        bind_cargo_file_permissions(root, &mut identities)?;
    }
    Ok(identities)
}

/// Return the complete repository-owned input boundary selected by a Cargo
/// operation.
///
/// A mutation unit's four sealed registration inputs are deliberately exact,
/// but they are not the whole program Cargo executes. In particular, a
/// workspace `Cargo.toml` can remove or redirect the selected package without
/// changing those four files. Bind the operation manifest itself and use
/// locked, offline Cargo metadata to validate the selected workspace package
/// and its repository-local dependency packages. Rust can nevertheless read
/// files outside those package directories through `include!`, `#[path]`, or a
/// build script, so the cache binds the complete reviewed project tree copied
/// into the adapter shadow. The tree is enumerated through the same
/// state-excluding, bounded closure builder as semantic source closures, then
/// fed back into the ordinary bounded cache inventory.
fn cargo_execution_input_paths(
    bundle: &ProjectBundle,
    unit: &EvidenceUnitManifest,
) -> Result<BTreeSet<String>> {
    if unit.operation.kind != OperationKind::CargoTest {
        return Ok(BTreeSet::new());
    }

    let root = &bundle.root;
    let manifest = unit.operation.manifest.as_deref().with_context(|| {
        format!(
            "PB-CACHE-0001: Cargo unit {} has no operation manifest",
            unit.id
        )
    })?;
    let package = unit.operation.package.as_deref().with_context(|| {
        format!(
            "PB-CACHE-0001: Cargo unit {} has no selected package",
            unit.id
        )
    })?;
    validate_cache_relative_path(manifest)?;

    // Validate the exact manifest boundary before asking Cargo to parse it.
    // This rejects a missing, directory, symlinked, or oversized manifest
    // without permitting metadata discovery to normalize the path for us.
    let canonical_root = root
        .canonicalize()
        .context("PB-CACHE-0001: project root cannot be resolved")?;
    let manifest_path = canonical_root.join(manifest);
    reject_cache_symlink_components(&canonical_root, &manifest_path)?;
    let manifest_metadata = fs::symlink_metadata(&manifest_path).with_context(|| {
        format!("PB-CACHE-0001: Cargo operation manifest is missing: {manifest}")
    })?;
    if manifest_metadata.file_type().is_symlink()
        || !manifest_metadata.is_file()
        || manifest_metadata.len() > bundle.project.limits.max_manifest_bytes
    {
        bail!(
            "PB-CACHE-0001: Cargo operation manifest {manifest:?} must be a regular file no larger than {} bytes",
            bundle.project.limits.max_manifest_bytes
        );
    }

    let output = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
            manifest,
        ])
        .current_dir(root)
        .output()
        .with_context(|| {
            format!(
                "PB-CACHE-0001: Cargo metadata could not close unit {}",
                unit.id
            )
        })?;
    if !output.status.success() || output.stdout.len() > MAX_CARGO_METADATA_OUTPUT {
        bail!(
            "PB-CACHE-0001: locked offline Cargo metadata failed for unit {}: {}",
            unit.id,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let metadata: CacheCargoMetadata =
        serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "PB-CACHE-0001: Cargo metadata for unit {} is malformed",
                unit.id
            )
        })?;
    let workspace_root = metadata.workspace_root.canonicalize().with_context(|| {
        format!(
            "PB-CACHE-0001: Cargo workspace root for unit {} cannot be resolved",
            unit.id
        )
    })?;
    if !workspace_root.starts_with(&canonical_root) {
        bail!(
            "PB-CACHE-0001: Cargo workspace for unit {} escapes the project",
            unit.id
        );
    }

    let workspace_members = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();
    let selected = metadata
        .packages
        .iter()
        .filter(|candidate| candidate.name == package && workspace_members.contains(&candidate.id))
        .collect::<Vec<_>>();
    let [selected] = selected.as_slice() else {
        bail!(
            "PB-CACHE-0001: Cargo unit {} must select exactly one workspace package named {package:?}",
            unit.id
        );
    };

    let packages = metadata
        .packages
        .iter()
        .map(|candidate| (candidate.id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let resolve = metadata.resolve.with_context(|| {
        format!(
            "PB-CACHE-0001: Cargo metadata for unit {} omitted its dependency graph",
            unit.id
        )
    })?;
    let dependencies = resolve
        .nodes
        .into_iter()
        .map(|node| (node.id, node.dependencies))
        .collect::<BTreeMap<_, _>>();
    let mut pending = vec![selected.id.clone()];
    let mut closed = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !closed.insert(id.clone()) {
            continue;
        }
        pending.extend(dependencies.get(&id).into_iter().flatten().cloned());
    }

    let mut local_package_count = 0_usize;
    for id in closed {
        let package = packages.get(id.as_str()).with_context(|| {
            format!(
                "PB-CACHE-0001: Cargo dependency {id:?} for unit {} has no package record",
                unit.id
            )
        })?;
        if package.source.is_some() {
            continue;
        }
        let manifest_path = package.manifest_path.canonicalize().with_context(|| {
            format!(
                "PB-CACHE-0001: local Cargo package manifest {} cannot be resolved",
                package.manifest_path.display()
            )
        })?;
        if !manifest_path.starts_with(&canonical_root) {
            bail!(
                "PB-CACHE-0001: local Cargo dependency {} for unit {} escapes the project",
                package.name,
                unit.id
            );
        }
        local_package_count += 1;
    }
    if local_package_count == 0 {
        bail!(
            "PB-CACHE-0001: Cargo unit {} selected no repository-owned package sources",
            unit.id
        );
    }

    // This is intentionally the whole reviewed tree rather than merely the
    // selected package directories. It exactly tracks what `shadow_project`
    // makes available to Cargo, including repo-root files reachable via
    // `include!`, `#[path]`, and build scripts, while excluding only the same
    // generated/state directories (`.git`, `.proofbound`, `target`, and the
    // registered language caches).
    let shadow_input_closure = proofbound_evidence::build_closure(
        &canonical_root,
        proofbound_evidence::ClosureKind::Semantic,
        &["**".to_owned()],
        None,
        "build-tool-transitive/1",
        closures::limits(bundle),
    )
    .with_context(|| {
        format!(
            "PB-CACHE-0001: could not close the reviewed Cargo shadow inputs for unit {}",
            unit.id
        )
    })?;

    let mut paths = shadow_input_closure
        .members
        .into_iter()
        .map(|member| member.path)
        .collect::<BTreeSet<_>>();
    // The operation manifest can be a virtual workspace manifest outside all
    // selected package directories, so it is always an explicit cache input.
    paths.insert(manifest.to_owned());
    let workspace_manifest =
        repository_relative(&canonical_root, &workspace_root.join("Cargo.toml"))
            .context("PB-CACHE-0001: Cargo workspace manifest escapes the project")?;
    paths.insert(workspace_manifest);
    let lockfile = workspace_root.join("Cargo.lock");
    if lockfile.exists() {
        paths.insert(
            repository_relative(&canonical_root, &lockfile)
                .context("PB-CACHE-0001: Cargo lockfile escapes the project")?,
        );
    }
    for config in [".cargo/config.toml", ".cargo/config"] {
        if canonical_root.join(config).exists() {
            paths.insert(config.to_owned());
        }
    }
    Ok(paths)
}

fn collect_cache_path_identities(
    root: &Path,
    roots: &BTreeSet<String>,
    max_files: usize,
    max_bytes: u64,
) -> Result<BTreeMap<String, String>> {
    let canonical_root = root
        .canonicalize()
        .context("PB-CACHE-0001: project root cannot be resolved")?;
    let mut inputs = BTreeMap::new();
    let mut total_bytes = 0_u64;
    for relative in roots {
        validate_cache_relative_path(relative)?;
        let candidate = canonical_root.join(relative);
        reject_cache_symlink_components(&canonical_root, &candidate)?;
        let metadata = fs::symlink_metadata(&candidate)
            .with_context(|| format!("PB-CACHE-0001: registered input is missing: {relative}"))?;
        if metadata.file_type().is_symlink() {
            bail!("PB-CACHE-0001: input is a symlink: {relative}");
        }
        if metadata.is_file() {
            insert_cache_file(
                &canonical_root,
                &candidate,
                &mut inputs,
                &mut total_bytes,
                max_files,
                max_bytes,
            )?;
            continue;
        }
        if !metadata.is_dir() {
            bail!("PB-CACHE-0001: input is not a regular file or directory: {relative}");
        }
        for entry in walkdir::WalkDir::new(&candidate)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.with_context(|| {
                format!("PB-CACHE-0001: cannot traverse registered input {relative}")
            })?;
            if entry.file_type().is_symlink() {
                bail!(
                    "PB-CACHE-0001: input directory contains a symlink: {}",
                    entry.path().display()
                );
            }
            if entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                bail!(
                    "PB-CACHE-0001: input directory contains a special file: {}",
                    entry.path().display()
                );
            }
            insert_cache_file(
                &canonical_root,
                entry.path(),
                &mut inputs,
                &mut total_bytes,
                max_files,
                max_bytes,
            )?;
        }
    }
    Ok(inputs)
}

fn insert_cache_file(
    root: &Path,
    path: &Path,
    inputs: &mut BTreeMap<String, String>,
    total_bytes: &mut u64,
    max_files: usize,
    max_bytes: u64,
) -> Result<()> {
    let relative = repository_relative(root, path).with_context(|| {
        format!(
            "PB-CACHE-0001: registered input escaped the project: {}",
            path.display()
        )
    })?;
    if inputs.contains_key(&relative) {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("PB-CACHE-0001: input is not a regular file: {relative}");
    }
    if inputs.len() >= max_files {
        bail!("PB-CACHE-0001: input inventory exceeds its {max_files}-file limit");
    }
    *total_bytes = total_bytes
        .checked_add(metadata.len())
        .context("PB-CACHE-0001: input byte count overflowed")?;
    if *total_bytes > max_bytes {
        bail!("PB-CACHE-0001: input inventory exceeds its {max_bytes}-byte limit");
    }
    inputs.insert(relative, sha256_bytes(&fs::read(path)?));
    Ok(())
}

/// Bind the permission model that `fs::copy` preserves in Cargo execution
/// shadows without changing the cache map's sha256-valued wire shape.
///
/// Unix mode bits can change whether a build helper is executable even when
/// its bytes are identical. Other platforms do not expose Unix modes, so they
/// use an explicitly tagged readonly model instead of inventing mode bits.
fn bind_cargo_file_permissions(root: &Path, inputs: &mut BTreeMap<String, String>) -> Result<()> {
    let canonical_root = root
        .canonicalize()
        .context("PB-CACHE-0001: project root cannot be resolved")?;
    for (relative, identity) in inputs {
        validate_cache_relative_path(relative)?;
        let path = canonical_root.join(relative.as_str());
        reject_cache_symlink_components(&canonical_root, &path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("PB-CACHE-0001: Cargo cache input is not a regular file: {relative}");
        }
        let material = serde_json::json!({
            "schema": "proofbound-cache-file-identity/1",
            "content_sha256": identity.clone(),
            "permissions": cache_file_permission_model(&metadata),
        });
        *identity = domain_hash(
            "proofbound-cache-file-identity/1",
            &canonical_json(&material)?,
        );
    }
    Ok(())
}

#[cfg(unix)]
fn cache_file_permission_model(metadata: &fs::Metadata) -> serde_json::Value {
    use std::os::unix::fs::PermissionsExt;

    serde_json::json!({
        "model": "unix-mode/1",
        "mode": metadata.permissions().mode() & 0o7777,
    })
}

#[cfg(not(unix))]
fn cache_file_permission_model(metadata: &fs::Metadata) -> serde_json::Value {
    serde_json::json!({
        "model": "readonly/1",
        "readonly": metadata.permissions().readonly(),
    })
}

fn validate_cache_relative_path(relative: &str) -> Result<()> {
    let path = Path::new(relative);
    if relative.is_empty()
        || relative.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("PB-CACHE-0001: unsafe registered input path {relative:?}");
    }
    Ok(())
}

fn reject_cache_symlink_components(root: &Path, candidate: &Path) -> Result<()> {
    let relative = candidate.strip_prefix(root).with_context(|| {
        format!(
            "PB-CACHE-0001: registered input escaped the project: {}",
            candidate.display()
        )
    })?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "PB-CACHE-0001: registered input traverses symlink {}",
                    current.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn repository_relative(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .map(|relative| relative.replace('\\', "/"))
}

pub(crate) fn cache_key_identity(
    unit: &EvidenceUnitManifest,
    closures: &[String],
    cache_context: &[String],
    inputs: &BTreeMap<String, String>,
    environment: &BTreeMap<String, Option<String>>,
    tool_identities: &BTreeMap<String, String>,
) -> Result<String> {
    let material = serde_json::json!({
        "schema": "proofbound-cache-key/1",
        "unit": unit,
        "closures": closures,
        "runner_external_toolchain_closures": cache_context,
        "inputs": inputs,
        "environment": environment,
        "tool_and_adapter_identities": tool_identities,
        "adapter_version": env!("CARGO_PKG_VERSION"),
    });
    Ok(domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&material)?,
    ))
}

fn find_premise_owner(bundle: &ProjectBundle, premise: &str) -> Option<String> {
    bundle
        .evidence_units
        .values()
        .find(|(_, unit)| unit.premises.iter().any(|id| id == premise))
        .map(|(_, unit)| canonical_reference(unit.kind, &unit.id))
}

pub(crate) fn normalize_evidence_reference(reference: &str) -> String {
    let Some((prefix, id)) = reference.split_once(':') else {
        return reference.to_owned();
    };
    let canonical = match prefix {
        "artifact-soundness" => "artifact",
        "trusted-transcription" => "transcription",
        "refinement" => "source-refinement",
        "kani" => "bounded-check",
        "independent" => "independent-check",
        "exhaustive" => "exhaustive-check",
        "test" => "example-test",
        "mutation" => "mutation-witness",
        other => other,
    };
    format!("{canonical}:{id}")
}

fn canonical_reference(kind: ManifestEvidenceKind, id: &str) -> String {
    let prefix = match kind {
        ManifestEvidenceKind::Theorem => "theorem",
        ManifestEvidenceKind::ArtifactSoundness => "artifact",
        ManifestEvidenceKind::TrustedTranscription => "transcription",
        ManifestEvidenceKind::SourceRefinement => "source-refinement",
        ManifestEvidenceKind::BoundedCheck => "bounded-check",
        ManifestEvidenceKind::IndependentCheck => "independent-check",
        ManifestEvidenceKind::ExhaustiveCheck => "exhaustive-check",
        ManifestEvidenceKind::PropertyTest => "property-test",
        ManifestEvidenceKind::ExampleTest => "example-test",
        ManifestEvidenceKind::MutationWitness => "mutation-witness",
        ManifestEvidenceKind::StaticCheck => "static-check",
        ManifestEvidenceKind::Review => "review",
        ManifestEvidenceKind::Assumption => "assumption",
        ManifestEvidenceKind::Open => "open",
    };
    format!("{prefix}:{id}")
}

fn manifest_evidence_kind(kind: ManifestEvidenceKind) -> EvidenceKind {
    serde_json::from_value(serde_json::to_value(kind).expect("manifest enum serializes"))
        .expect("manifest and core evidence vocabularies agree")
}

fn primary_linkage(linkage: PrimaryLinkage) -> LinkageFacet {
    match linkage {
        PrimaryLinkage::Refined => LinkageFacet::Refined,
        PrimaryLinkage::ArtifactBound => LinkageFacet::ArtifactBound,
        PrimaryLinkage::Transcribed => LinkageFacet::Transcribed,
        PrimaryLinkage::ModelOnly => LinkageFacet::ModelOnly,
    }
}

fn assumption_category(category: ManifestAssumptionCategory) -> AssumptionCategory {
    serde_json::from_value(serde_json::to_value(category).expect("manifest enum serializes"))
        .expect("manifest and core assumption vocabularies agree")
}

fn assumption_status(status: ManifestAssumptionStatus) -> AssumptionStatus {
    serde_json::from_value(serde_json::to_value(status).expect("manifest enum serializes"))
        .expect("manifest and core assumption status vocabularies agree")
}

fn subject_node(subject: &str) -> NodeId {
    let digest = Sha256Digest::of_bytes(subject.as_bytes()).to_hex();
    NodeId::new(format!("subject:{digest}")).expect("digest subject ID is valid")
}

fn identity_for(name: &str, version: &str) -> ToolIdentity {
    ToolIdentity {
        name: name.into(),
        version: version.into(),
        identity_sha256: Sha256Digest::of_bytes(format!("{name}\0{version}")),
    }
}

fn parse_digest(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_str(strip_digest(value)).map_err(anyhow::Error::from)
}

fn strip_digest(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

fn create_sealed_directories(state_root: &Path) -> Result<()> {
    for path in [
        state_root.to_owned(),
        state_root.join("cache"),
        state_root.join("closures"),
        state_root.join("compiled/claims"),
    ] {
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.file_type().is_symlink()
        {
            bail!(
                "PB-PATH-0001: refusing symlinked state boundary {}",
                path.display()
            );
        }
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn write_canonical(path: &Path, value: &impl Serialize) -> Result<()> {
    write_bytes(path, &canonical_json(value)?)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        bail!(
            "PB-PATH-0002: refusing to overwrite symlink {}",
            path.display()
        );
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn worktree_snapshot(root: &Path) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        bail!("PB-PROVENANCE-0002: git worktree inventory failed");
    }
    let mut snapshot = Vec::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = std::str::from_utf8(raw)
            .context("PB-PROVENANCE-0002: git returned a non-UTF-8 path")?;
        if relative == ".proofbound" || relative.starts_with(".proofbound/") {
            continue;
        }
        let path = root.join(relative);
        snapshot.extend_from_slice(raw);
        snapshot.push(0);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                snapshot.extend_from_slice(b"symlink\0");
                snapshot.extend_from_slice(fs::read_link(path)?.as_os_str().as_encoded_bytes());
            }
            Ok(metadata) if metadata.is_file() => {
                snapshot.extend_from_slice(b"file\0");
                snapshot.extend_from_slice(sha256_bytes(&fs::read(path)?).as_bytes());
            }
            Ok(_) => snapshot.extend_from_slice(b"other"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                snapshot.extend_from_slice(b"missing")
            }
            Err(error) => return Err(error.into()),
        }
        snapshot.push(0xff);
    }
    Ok(snapshot)
}

fn validate_reviewed_tree_snapshot(root: &Path, expected: &str) -> Result<()> {
    let actual = sha256_bytes(&worktree_snapshot(root)?);
    if actual != expected {
        bail!(
            "PB-RECEIPT-0007: compiled result is stale: reviewed tree snapshot changed; run proofbound check again"
        );
    }
    Ok(())
}

fn copy_release_binaries(destination: &Path) -> Result<()> {
    let current = std::env::current_exe()?;
    let metadata = fs::symlink_metadata(&current)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("PB-RELEASE-0007: orchestrator binary is not a regular file");
    }
    let parent = current.parent().context("binary path has no parent")?;
    let verifier = parent.join("proofbound-verify");
    let verifier_metadata = fs::symlink_metadata(&verifier).with_context(|| {
        format!(
            "PB-RELEASE-0008: independent verifier binary is missing at {}",
            verifier.display()
        )
    })?;
    if verifier_metadata.file_type().is_symlink() || !verifier_metadata.is_file() {
        bail!("PB-RELEASE-0008: independent verifier is not a regular file");
    }
    fs::copy(&current, destination.join("bin/proofbound"))?;
    fs::copy(&verifier, destination.join("bin/proofbound-verify"))?;
    Ok(())
}

fn release_sealed_files(root: &Path) -> Result<Vec<serde_json::Value>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!("PB-RELEASE-0005: symlink in release boundary");
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(entry.path())?;
        files.push(serde_json::json!({
            "path": relative,
            "sha256": sha256_bytes(&bytes),
            "size_bytes": bytes.len() as u64,
        }));
    }
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    Ok(files)
}

fn tcb_projection(compiled: &CompiledProject) -> Result<serde_json::Value> {
    let included_evidence = release_evidence_ids(compiled);
    let mut components = BTreeMap::<(String, String), String>::new();
    for evidence in compiled
        .evidence
        .iter()
        .filter(|record| included_evidence.contains(&record.id))
    {
        for tool in [&evidence.provenance.tool, &evidence.provenance.adapter] {
            insert_tcb_component(&mut components, tool)?;
        }
        if let Some(transcription) = &evidence.trusted_transcription {
            let unit_id = evidence
                .unit_id
                .as_str()
                .strip_prefix("unit:")
                .unwrap_or(evidence.unit_id.as_str());
            for (role_name, role) in [
                ("transcriber", &transcription.transcriber),
                ("reencoder", &transcription.reencoder),
            ] {
                insert_tcb_component(
                    &mut components,
                    &ToolIdentity {
                        name: format!("trusted-transcription/{unit_id}/{role_name}"),
                        version: TRANSCRIPTION_DRIVER_ABI_V1.into(),
                        identity_sha256: role.role_identity,
                    },
                )?;
            }
        }
    }
    Ok(serde_json::json!({
        "schema": "proofbound-tcb-ledger/1",
        "components": components.into_iter().map(|((name, version), identity_sha256)| serde_json::json!({
            "name": name,
            "version": version,
            "identity_sha256": identity_sha256,
        })).collect::<Vec<_>>(),
    }))
}

fn insert_tcb_component(
    components: &mut BTreeMap<(String, String), String>,
    tool: &ToolIdentity,
) -> Result<()> {
    let key = (tool.name.clone(), tool.version.clone());
    let identity = format!("sha256:{}", tool.identity_sha256);
    if let Some(existing) = components.get(&key)
        && existing != &identity
    {
        bail!(
            "PB-RELEASE-0020: TCB component {}@{} has conflicting identities",
            key.0,
            key.1
        );
    }
    components.insert(key, identity);
    Ok(())
}

fn release_evidence_ids(compiled: &CompiledProject) -> BTreeSet<EvidenceId> {
    compiled
        .inputs
        .iter()
        .flat_map(|input| input.evidence.iter().map(|record| record.id.clone()))
        .collect()
}

fn merged_release_graph(compiled: &CompiledProject) -> Result<serde_json::Value> {
    let mut nodes = BTreeMap::<String, proofbound_core::GraphNode>::new();
    let mut edges = BTreeMap::<(String, String, String), proofbound_core::GraphEdge>::new();
    for input in &compiled.inputs {
        for node in &input.graph.nodes {
            if let Some(old) = nodes.insert(node.id.to_string(), node.clone())
                && old != *node
            {
                bail!("PB-RELEASE-0009: graph node identity conflict");
            }
        }
        for edge in &input.graph.edges {
            let kind = serde_json::to_value(edge.kind())?
                .as_str()
                .expect("edge kind is text")
                .to_owned();
            edges.insert(
                (edge.from().to_string(), edge.to().to_string(), kind),
                edge.clone(),
            );
        }
    }
    Ok(serde_json::json!({
        "schema": "proofbound-graph/1",
        "nodes": nodes.into_values().collect::<Vec<_>>(),
        "edges": edges.into_values().collect::<Vec<_>>(),
        "mutual_theorem_groups": [],
    }))
}

fn compiled_release_value(
    compiled: &CompiledProject,
    project_tier: u8,
    graph: serde_json::Value,
    sealed_files: Vec<serde_json::Value>,
) -> Result<serde_json::Value> {
    let mut release_closure_by_internal_id = BTreeMap::new();
    let mut closure_values = BTreeMap::new();
    for closure in &compiled.closures {
        let record = serde_json::json!({
            "schema": "proofbound-source-closure/1",
            "kind": closure.kind,
            "members": closure.members.iter().map(|member| serde_json::json!({
                "path": member.path,
                "sha256": member.sha256,
                "size_bytes": member.bytes,
            })).collect::<Vec<_>>(),
        });
        let sha = domain_hash("proofbound-source-closure/1", &canonical_json(&record)?);
        release_closure_by_internal_id.insert(closure.id.clone(), sha.clone());
        closure_values
            .entry(sha.clone())
            .or_insert_with(|| serde_json::json!({"sha256": sha, "record": record}));
    }
    let closure_values = closure_values.into_values().collect::<Vec<_>>();

    // `CompiledProject::evidence` also retains validated observations that are
    // not in any selected claim closure (for example, a review attached to a
    // future theorem premise). Portable releases must contain exactly the
    // evidence reachable through the compiled claim inputs; otherwise the
    // independent verifier correctly rejects an ungated, graphless record.
    let included_evidence = release_evidence_ids(compiled);
    let mut evidence_ids = BTreeMap::<String, String>::new();
    let mut evidence_values = Vec::new();
    for dependent in [false, true] {
        for evidence in &compiled.evidence {
            if !included_evidence.contains(&evidence.id) {
                continue;
            }
            let is_dependent =
                evidence.artifact_binding.is_some() || evidence.source_refinement.is_some();
            if is_dependent != dependent {
                continue;
            }
            let semantic_internal = format!(
                "sha256:{}",
                evidence.provenance.semantic_source_closure.to_hex()
            );
            let closure = release_closure_by_internal_id
                .get(&semantic_internal)
                .with_context(|| {
                    format!(
                        "PB-RELEASE-0011: evidence {} semantic closure is not registered",
                        evidence.id
                    )
                })?;
            let record = release_evidence_record(
                evidence,
                closure,
                &release_closure_by_internal_id,
                &evidence_ids,
            )?;
            let sha = domain_hash(EVIDENCE_DOMAIN, &canonical_json(&record)?);
            evidence_ids.insert(evidence.id.to_string(), sha.clone());
            evidence_values.push(serde_json::json!({"sha256": sha, "record": record}));
        }
    }
    evidence_values.sort_by(|left, right| left["sha256"].as_str().cmp(&right["sha256"].as_str()));

    let mut claims = Vec::new();
    let mut assumptions = BTreeMap::new();
    let mut premises = BTreeMap::new();
    let mut policies = BTreeMap::new();
    for input in &compiled.inputs {
        claims.push(serde_json::json!({
            "schema": "proofbound-claim/1",
            "id": input.claim.id,
            "node_id": input.claim.node_id,
            "title": input.claim.title,
            "statement": input.claim.statement,
            "public_language": input.claim.public_language,
            "subject": input.claim.subject,
            "policy": input.claim.policy,
            "tier": input.claim.tier,
            "cited_evidence": map_evidence_set(&input.claim.cited_evidence, &evidence_ids)?,
            "assumptions": input.claim.assumptions,
            "open_obligations": input.claim.open_obligations.iter().map(|item| serde_json::json!({
                "id": item.id,
                "statement": item.statement,
                "remediation": item.remediation,
            })).collect::<Vec<_>>(),
            "out_of_scope": input.claim.out_of_scope.iter().collect::<Vec<_>>(),
            "primary_linkage": input.claim.primary_linkage,
            "registered_inputs": input.claim.registered_inputs,
            "registered_domain_language": input.claim.registered_domain_language,
        }));
        insert_release_policy(&mut policies, &input.policy)?;
        for item in &input.assumptions {
            assumptions.insert(
                item.id.to_string(),
                serde_json::json!({
                    "schema": item.schema,
                    "id": item.id,
                    "node_id": item.node_id,
                    "statement": item.statement,
                    "category": item.category,
                    "owner": item.owner,
                    "rationale": item.rationale,
                    "scope": item.scope,
                    "affected_claims": item.affected_claims,
                    "review_evidence": map_evidence_set(&item.review_evidence, &evidence_ids)?,
                    "falsification_or_discharge_plan": item.falsification_or_discharge_plan,
                    "source_citation": item.source_citation,
                    "state": item.status,
                    "depends_on": item.depends_on,
                }),
            );
        }
        for item in &input.premises {
            let theorem_evidence = item
                .theorem_evidence
                .as_ref()
                .map(|owner| {
                    evidence_ids.get(owner.as_str()).cloned().with_context(|| {
                        format!("PB-RELEASE-0012: premise {} theorem is missing", item.id)
                    })
                })
                .transpose()?;
            let discharge = item
                .discharge
                .as_ref()
                .map(|discharge| {
                    Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({
                        "theorem_evidence": evidence_ids
                            .get(discharge.theorem_evidence.as_str())
                            .with_context(|| format!(
                                "PB-RELEASE-0012: premise {} discharge theorem is missing",
                                item.id
                            ))?,
                        "scope": discharge.scope,
                    }))
                })
                .transpose()?;
            premises.insert(
                item.id.to_string(),
                serde_json::json!({
                    "id": item.id,
                    "node_id": item.node_id,
                    "statement": item.statement,
                    "category": item.category,
                    "theorem_evidence": theorem_evidence,
                    "scope": item.scope,
                    "discharge": discharge,
                }),
            );
        }
    }
    claims.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    let graph_sha256 = domain_hash("proofbound-graph/1", &canonical_json(&graph)?);
    let statuses = compiled
        .statuses
        .iter()
        .map(|status| {
            serde_json::json!({
                "claim_id": status.claim_id,
                "public_statement": status.public_statement,
                "formal": status.formal,
                "linkage": status.linkage,
                "assumption": status.assumption.standing,
                "assumptions": status.assumption.assumptions.iter()
                    .map(|item| item.id.to_string()).collect::<BTreeSet<_>>(),
                "undischarged_premises": status.assumption.undischarged_premises.iter()
                    .map(|item| item.id.to_string()).collect::<BTreeSet<_>>(),
                "policy_admitted": status.policy.admitted,
            })
        })
        .collect::<Vec<_>>();
    let mut payload = serde_json::json!({
        "schema": "proofbound-compiled-release/3",
        "project": compiled.project,
        "project_revision": compiled.project_revision,
        "project_tier": project_tier,
        "tree_state": compiled.tree_state,
        "graph": graph,
        "graph_sha256": graph_sha256,
        "claims": claims,
        "evidence": evidence_values,
        "assumptions": assumptions.into_values().collect::<Vec<_>>(),
        "premises": premises.into_values().collect::<Vec<_>>(),
        "policies": policies.into_values().collect::<Vec<_>>(),
        "closures": closure_values,
        "sealed_files": sealed_files,
        "reported_statuses": statuses,
    });
    omit_null_object_fields(&mut payload);
    Ok(payload)
}

fn insert_release_policy(
    policies: &mut BTreeMap<String, serde_json::Value>,
    policy: &PolicyDefinition,
) -> Result<()> {
    let id = policy.id.to_string();
    let value = serde_json::to_value(policy)?;
    if let Some(existing) = policies.get(&id) {
        if existing != &value {
            bail!("PB-RELEASE-0018: policy {id} has conflicting effective semantics across claims");
        }
        return Ok(());
    }
    policies.insert(id, value);
    Ok(())
}

fn release_evidence_record(
    evidence: &EvidenceRecord,
    closure: &str,
    closure_ids: &BTreeMap<String, String>,
    evidence_ids: &BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let input_artifacts = artifact_records(&evidence.provenance.input_artifacts)?;
    let generated_artifacts = artifact_records(&evidence.provenance.generated_artifacts)?;
    let tool = serde_json::json!({
        "name": evidence.provenance.tool.name,
        "version": evidence.provenance.tool.version,
        "identity_sha256": format!("sha256:{}", evidence.provenance.tool.identity_sha256),
    });
    let adapter = serde_json::json!({
        "name": evidence.provenance.adapter.name,
        "version": evidence.provenance.adapter.version,
        "identity_sha256": format!("sha256:{}", evidence.provenance.adapter.identity_sha256),
    });
    let unit_configuration = format!("sha256:{}", evidence.provenance.unit_configuration_sha256);
    let additional_closures = evidence
        .provenance
        .additional_closures
        .iter()
        .map(|identity| {
            let internal = format!("sha256:{}", identity.sha256.to_hex());
            let sha256 = closure_ids.get(&internal).with_context(|| {
                format!(
                    "PB-RELEASE-0017: evidence {} additional closure {internal} is missing",
                    evidence.id
                )
            })?;
            Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({
                "kind": identity.kind,
                "sha256": sha256,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut cache_material = serde_json::json!({
        "semantic_closure": closure,
        "additional_closures": additional_closures,
        "input_artifacts": input_artifacts,
        "tool": tool,
        "adapter": adapter,
        "unit_configuration_sha256": unit_configuration,
    });
    omit_empty_array_field(&mut cache_material, "additional_closures");
    let cache_key = domain_hash("proofbound-cache-key/1", &canonical_json(&cache_material)?);
    let commands = evidence
        .provenance
        .commands
        .iter()
        .map(release_command)
        .collect::<Vec<_>>();
    let runs = evidence
        .provenance
        .runs
        .iter()
        .map(|run| {
            serde_json::json!({
                "command_index": run.command_index,
                "exit_code": run.exit_code,
                "stdout_sha256": format!("sha256:{}", run.stdout_sha256),
                "stderr_sha256": format!("sha256:{}", run.stderr_sha256),
                "normalized_output_sha256": format!("sha256:{}", run.normalized_output_sha256),
                "output_truncated": run.output_truncated,
                "duration_ms": run.duration_ms,
            })
        })
        .collect::<Vec<_>>();
    let reproduction = release_command(&evidence.provenance.reproduction_command);
    let theorem = evidence.theorem.as_ref().map(|item| {
        serde_json::json!({
            "declaration": item.declaration,
            "statement_encoding": item.statement_encoding,
            "statement_wire": item.statement_wire,
            "statement_sha256": format!("sha256:{}", item.statement_sha256),
            "attributed_claim": item.attributed_claim,
            "proof_environment": item.environment,
            "axiom_audit_passed": item.axiom_audit_passed,
            "contains_sorry_ax": item.contains_sorry_ax,
            "foundational_axioms": item.foundational_axioms,
            "project_axioms": item.project_axioms,
        })
    });
    let artifact_binding = evidence
        .artifact_binding
        .as_ref()
        .map(|item| {
            Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({
                "theorem_evidence": evidence_ids.get(item.theorem.as_str())
                    .with_context(|| format!("PB-RELEASE-0013: artifact theorem {} is missing", item.theorem))?,
                "artifact": {
                    "logical_name": item.artifact.logical_name,
                    "sha256": format!("sha256:{}", item.artifact.sha256),
                    "size_bytes": item.artifact.size_bytes,
                },
            }))
        })
        .transpose()?;
    let trusted_transcription = evidence.trusted_transcription.as_ref().map(|item| {
        serde_json::json!({
            "schema": item.schema,
            "source": release_artifact_identity(&item.source),
            "committed_transcription": release_artifact_identity(&item.committed_transcription),
            "transcribed_candidate": release_artifact_identity(&item.transcribed_candidate),
            "reencoded_source": release_artifact_identity(&item.reencoded_source),
            "driver": release_artifact_identity(&item.driver),
            "transcriber": {
                "tcb_node": item.transcriber.tcb_node,
                "role_identity": format!("sha256:{}", item.transcriber.role_identity),
            },
            "reencoder": {
                "tcb_node": item.reencoder.tcb_node,
                "role_identity": format!("sha256:{}", item.reencoder.role_identity),
            },
        })
    });
    let source_refinement = evidence
        .source_refinement
        .as_ref()
        .map(|item| {
            Ok::<serde_json::Value, anyhow::Error>(serde_json::json!({
                "refinement_theorem_evidence": evidence_ids.get(item.refinement_theorem.as_str())
                    .with_context(|| format!("PB-RELEASE-0014: refinement theorem {} is missing", item.refinement_theorem))?,
                "representation_premises": item.representation_premises,
                "deterministic_translation": item.deterministic_translation,
                "pinned_toolchain": item.pinned_toolchain,
                "generated_axioms_clean": item.generated_axioms_clean,
                "strength": item.adapter_strength,
            }))
        })
        .transpose()?;
    let bounded_check = evidence.bounded_check.as_ref().map(|item| {
        serde_json::json!({
            "domain": {
                "id": item.domain.id,
                "description": item.domain.description,
                "registration_sha256": format!("sha256:{}", item.domain.registration_sha256),
                "cardinality": item.domain.cardinality,
            },
            "solver": item.solver,
            "assumptions": item.assumptions,
            "harnesses": item.harnesses,
            "unwind_bounds": item.unwind_bounds,
        })
    });
    let exhaustive_check = evidence.exhaustive_check.as_ref().map(|item| {
        serde_json::json!({
            "domain": {
                "id": item.domain.id,
                "description": item.domain.description,
                "registration_sha256": format!("sha256:{}", item.domain.registration_sha256),
                "cardinality": item.domain.cardinality,
            },
            "evaluated_members": item.evaluated_members,
        })
    });
    let mutation_witness = evidence.mutation_witness.as_ref().map(|item| {
        serde_json::json!({
            "schema": item.schema,
            "mutation_id": item.mutation_id,
            "subject": item.subject,
            "guard": item.guard,
            "mutation_sha256": format!("sha256:{}", item.mutation_sha256),
            "registry": item.registry,
            "target_preimage": item.target_preimage,
            "mutant_artifact": item.mutant_artifact,
            "target_postimage": item.target_postimage,
            "witness_source": item.witness_source,
            "check_id": item.check_id,
            "baseline_run_index": item.baseline_run_index,
            "expected_failure": {
                "run_index": item.expected_failure.run_index,
                "allowed_exit_codes": item.expected_failure.allowed_exit_codes,
            },
            "proof_term_witness": item.proof_term_theorem.is_some(),
        })
    });
    let python_property = evidence.python_property.as_ref().map(|item| {
        serde_json::json!({
            "schema": item.schema,
            "framework": item.framework,
            "seed": item.seed,
            "framework_version": item.framework_version,
        })
    });
    let static_check = evidence.static_check.as_ref().map(|item| {
        serde_json::json!({
            "schema": item.schema,
            "tool": item.tool,
            "tool_version": item.tool_version,
            "configuration_sha256": format!("sha256:{}", item.configuration_sha256),
            "targets": item.targets,
            "diagnostics": item.diagnostics,
        })
    });
    let distribution_reproduction = evidence.distribution_reproduction.as_ref().map(|item| {
        serde_json::json!({
            "schema": item.schema,
            "format": item.format,
            "run_digests": item.run_digests.iter().map(|digest| format!("sha256:{digest}")).collect::<Vec<_>>(),
            "registered_digest": format!("sha256:{}", item.registered_digest),
            "source_date_epoch": item.source_date_epoch,
            "build_backend_name": item.build_backend_name,
            "build_backend_version": item.build_backend_version,
            "npm_integrity": item.npm_integrity,
            "member_inventory": item.member_inventory,
        })
    });
    let python_plugins = evidence
        .provenance
        .python_plugins
        .iter()
        .map(|plugin| {
            serde_json::json!({
                "module": plugin.module,
                "distribution": plugin.distribution,
                "version": plugin.version,
                "origin_sha256": format!("sha256:{}", plugin.origin_sha256),
            })
        })
        .collect::<Vec<_>>();
    let open_obligation = evidence.open_obligation.as_ref().map(|item| {
        serde_json::json!({
            "id": item.id,
            "statement": item.statement,
            "remediation": item.remediation,
        })
    });
    let mut record = serde_json::json!({
        "schema": EVIDENCE_DOMAIN,
        "unit_id": evidence.unit_id,
        "node_id": evidence.node_id,
        "kind": evidence.kind,
        "claim_ids": evidence.claims,
        "outcome": evidence.status,
        "evaluation_mode": evidence.evaluation_mode,
        "binding_mode": evidence.binding_mode,
        "theorem": theorem,
        "artifact_binding": artifact_binding,
        "trusted_transcription": trusted_transcription,
        "source_refinement": source_refinement,
        "bounded_check": bounded_check,
        "exhaustive_check": exhaustive_check,
        "mutation_witness": mutation_witness,
        "python_property": python_property,
        "static_check": static_check,
        "distribution_reproduction": distribution_reproduction,
        "independence": evidence.independence,
        "inventoried_targets": evidence.inventoried_targets,
        "assumptions": evidence.assumptions,
        "premises": evidence.premises,
        "open_obligation": open_obligation,
        "provenance": {
            "project_revision": evidence.provenance.project_revision,
            "tree_state": evidence.provenance.tree_state,
            "semantic_closure": closure,
            "additional_closures": additional_closures,
            "input_artifacts": input_artifacts,
            "generated_artifacts": generated_artifacts,
            "tool": tool,
            "adapter": adapter,
            "execution_kind": evidence.provenance.execution_kind,
            "commands": commands,
            "runs": runs,
            "normalization": evidence.provenance.normalization,
            "reproduction_command": reproduction,
            "started_unix_ms": evidence.provenance.started_unix_ms,
            "completed_unix_ms": evidence.provenance.completed_unix_ms,
            "deterministic_result_sha256": format!("sha256:{}", evidence.provenance.deterministic_result_identity),
            "unit_configuration_sha256": unit_configuration,
            "cache_key": cache_key,
            "reused_from": evidence.provenance.prior_receipt_sha256.map(|item| format!("sha256:{item}")),
            "resource_budget": {
                "time_ms": evidence.provenance.resource_budget.time_ms,
                "disk_bytes": evidence.provenance.resource_budget.disk_bytes,
                "memory_bytes": evidence.provenance.resource_budget.memory_bytes,
            },
            "actual_cost": {
                "time_ms": evidence.provenance.resource_usage.time_ms,
                "disk_bytes": evidence.provenance.resource_usage.peak_disk_bytes,
                "memory_bytes": evidence.provenance.resource_usage.peak_memory_bytes,
            },
            "python_plugins": python_plugins,
        },
    });
    omit_null_object_fields(&mut record);
    if let Some(provenance) = record.get_mut("provenance") {
        omit_empty_array_field(provenance, "additional_closures");
        omit_empty_array_field(provenance, "python_plugins");
    }
    Ok(record)
}

fn omit_empty_array_field(value: &mut serde_json::Value, field: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if object
        .get(field)
        .and_then(serde_json::Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        object.remove(field);
    }
}

fn omit_null_object_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            // These version-2 fields are required nullable observations. A
            // null measurement, environment identity, or exit status must
            // not be confused with omission by the optional-field cleanup.
            object.retain(|key, child| {
                matches!(key.as_str(), "memory_bytes" | "value_sha256" | "exit_code")
                    || !child.is_null()
            });
            for child in object.values_mut() {
                omit_null_object_fields(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                omit_null_object_fields(item);
            }
        }
        _ => {}
    }
}

fn release_command(command: &CommandSpec) -> serde_json::Value {
    serde_json::json!({
        "program": command.program,
        "args": command.args,
        "environment_allowlist": command.environment_allowlist.iter().map(|variable| {
            serde_json::json!({
                "name": variable.name,
                "value_sha256": variable.value_sha256.map(|digest| format!("sha256:{digest}")),
                "secret": variable.secret,
            })
        }).collect::<Vec<_>>(),
    })
}

fn artifact_records(values: &[ArtifactIdentity]) -> Result<Vec<serde_json::Value>> {
    let mut sorted = values.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.logical_name
            .cmp(&right.logical_name)
            .then_with(|| left.sha256.cmp(&right.sha256))
            .then_with(|| left.size_bytes.cmp(&right.size_bytes))
    });
    if sorted
        .windows(2)
        .any(|pair| pair[0].logical_name == pair[1].logical_name)
    {
        let duplicate = sorted
            .windows(2)
            .find(|pair| pair[0].logical_name == pair[1].logical_name)
            .expect("duplicate was detected")[0];
        bail!(
            "PB-RELEASE-0015: duplicate artifact logical name {}",
            duplicate.logical_name
        );
    }
    Ok(sorted
        .into_iter()
        .map(|value| {
            serde_json::json!({
                "logical_name": value.logical_name,
                "sha256": format!("sha256:{}", value.sha256),
                "size_bytes": value.size_bytes,
            })
        })
        .collect())
}

fn release_artifact_identity(value: &ArtifactIdentity) -> serde_json::Value {
    serde_json::json!({
        "logical_name": value.logical_name,
        "sha256": format!("sha256:{}", value.sha256),
        "size_bytes": value.size_bytes,
    })
}

fn map_evidence_set(
    values: &BTreeSet<EvidenceId>,
    evidence_ids: &BTreeMap<String, String>,
) -> Result<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            evidence_ids
                .get(value.as_str())
                .cloned()
                .with_context(|| format!("PB-RELEASE-0016: evidence {} is missing", value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy_manifest(overrides: serde_json::Value) -> PolicyManifest {
        let mut value = json!({
            "schema": "proofbound-policy/1",
            "id": "strict-profile",
            "extends": "kernel-with-assumptions",
            "allow_project_axioms": true,
            "allowed_project_axioms": ["AX-ONE"],
            "allowed_foundational_axioms": ["Classical.choice"],
            "allow_native": false,
            "native_premise_count": null,
            "allow_exhaustive_as_proved": false,
            "required_binding": "artifact-bound",
            "require_registered_premises": false,
            "publication_allows_open": false
        });
        for (key, child) in overrides.as_object().unwrap() {
            value
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), child.clone());
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn evidence_aliases_have_one_core_identity() {
        assert_eq!(normalize_evidence_reference("kani:x"), "bounded-check:x");
        assert_eq!(normalize_evidence_reference("test:x"), "example-test:x");
        assert_eq!(normalize_evidence_reference("theorem:x"), "theorem:x");
    }

    #[test]
    fn premise_reviews_are_derived_into_the_claim_evidence_closure() {
        let manifest: ClaimManifest = serde_json::from_value(json!({
            "schema": "proofbound-claim/1",
            "id": "CLAIM-PREMISE",
            "title": "Premise review closure",
            "statement": "The registered premise is reviewed.",
            "public_language": null,
            "formal_declaration": null,
            "statement_encoding": null,
            "statement_sha256": null,
            "foundational_axioms": [],
            "subject": "crate::subject",
            "subject_closure": null,
            "profile": "ledger",
            "tier": 0,
            "primary_linkage": "model-only",
            "evidence": ["test:registered-test"],
            "assumptions": [],
            "premises": ["PREMISE-ONE"],
            "open_obligations": ["A theorem owner remains future work."],
            "out_of_scope": [],
            "bounded_domain": null,
            "source_roots": ["src/**"]
        }))
        .unwrap();

        let cited = cited_evidence_ids(&manifest).unwrap();
        assert!(cited.contains(&EvidenceId::new("example-test:registered-test").unwrap()));
        assert!(cited.contains(&EvidenceId::new("review:PREMISE-ONE").unwrap()));
    }

    fn theorem_unit(id: &str, declaration: &str) -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": id,
            "adapter": "lean",
            "kind": "theorem",
            "claims": ["CLAIM-ONE"],
            "tier": 2,
            "evaluation_mode": "kernel",
            "theorem": declaration,
            "operation": {"type": "lean-audit", "targets": [declaration]},
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

    #[test]
    fn artifact_theorem_resolution_is_exact_unique_and_not_first_citation() {
        let wrong_first = theorem_unit("wrong-first", "Example.Claims.unrelated");
        let exact = theorem_unit("exact", "Example.Claims.published");
        let candidates = [&wrong_first, &exact];
        let selected = select_exact_theorem_unit(
            candidates.into_iter(),
            "Example.Claims.published",
            &["CLAIM-ONE".to_owned()],
            "artifact-unit",
        )
        .unwrap();
        assert_eq!(selected.id, "exact");

        let duplicate = theorem_unit("duplicate", "Example.Claims.published");
        let ambiguous = [&exact, &duplicate];
        assert!(
            select_exact_theorem_unit(
                ambiguous.into_iter(),
                "Example.Claims.published",
                &["CLAIM-ONE".to_owned()],
                "artifact-unit",
            )
            .is_err()
        );
    }

    #[test]
    fn assumption_review_requires_citations_and_existing_paths() {
        let temp = tempfile::tempdir().unwrap();
        let empty = validated_review_artifacts(temp.path(), "AX-EMPTY", &[])
            .unwrap_err()
            .to_string();
        assert!(empty.contains("PB-ASSUMPTION-0001"));
        assert!(empty.contains("AX-EMPTY"));

        let missing = validated_review_artifacts(
            temp.path(),
            "AX-MISSING",
            &["reviews/missing.md#decision".to_owned()],
        )
        .unwrap_err()
        .to_string();
        assert!(missing.contains("PB-ASSUMPTION-0001"));
        assert!(missing.contains("missing path"));

        let traversal = validated_review_artifacts(
            temp.path(),
            "AX-ESCAPE",
            &["../outside.md#decision".to_owned()],
        )
        .unwrap_err()
        .to_string();
        assert!(traversal.contains("normalized repository-relative path"));
    }

    #[test]
    fn assumption_review_requires_declared_anchor_to_resolve() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("review.md"),
            "# Decision record\n\nThe exact reviewed boundary.\n",
        )
        .unwrap();

        let missing = validated_review_artifacts(
            temp.path(),
            "AX-DANGLING",
            &["review.md#different-anchor".to_owned()],
        )
        .unwrap_err()
        .to_string();
        assert!(missing.contains("missing anchor"));

        let anchored = validated_review_artifacts(
            temp.path(),
            "AX-VALID",
            &["review.md#decision-record".to_owned()],
        )
        .unwrap();
        assert_eq!(anchored.len(), 1);
        assert_eq!(
            anchored[0].logical_name.as_str(),
            "review.md#decision-record"
        );
        assert_eq!(anchored[0].size_bytes, 48);

        let bare =
            validated_review_artifacts(temp.path(), "AX-BARE-FILE", &["review.md".to_owned()])
                .unwrap();
        assert_eq!(bare.len(), 1);
    }

    #[test]
    fn assumption_review_supports_checked_line_anchors() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("review.lean"), "line one\nline two\n").unwrap();
        assert!(
            validated_review_artifacts(temp.path(), "AX-LINE", &["review.lean#L1-L2".to_owned()])
                .is_ok()
        );
        assert!(
            validated_review_artifacts(temp.path(), "AX-LINE", &["review.lean#L3".to_owned()])
                .is_err()
        );
    }

    #[test]
    fn effective_built_in_policies_are_scoped_before_release_deduplication() {
        let foundational = BTreeSet::from(["propext".to_owned()]);
        let axiomatic = PolicyDefinition::built_in(
            BuiltInProfile::ArtifactBound,
            foundational.clone(),
            BTreeSet::from([AssumptionId::new("AX-ONE").unwrap()]),
        )
        .unwrap();
        let axiom_free = PolicyDefinition::built_in(
            BuiltInProfile::ArtifactBound,
            foundational,
            BTreeSet::new(),
        )
        .unwrap();

        let axiomatic = scope_built_in_policy(axiomatic, "CLAIM-AXIOMATIC").unwrap();
        let axiom_free = scope_built_in_policy(axiom_free, "CLAIM-AXIOM-FREE").unwrap();

        assert_ne!(axiomatic.id, axiom_free.id);
        assert_ne!(axiomatic.node_id, axiom_free.node_id);
        assert_eq!(axiomatic.allowed_project_axioms.len(), 1);
        assert!(axiom_free.allowed_project_axioms.is_empty());
    }

    #[test]
    fn release_policy_deduplication_rejects_same_id_with_different_semantics() {
        let foundational = BTreeSet::from(["propext".to_owned()]);
        let axiomatic = PolicyDefinition::built_in(
            BuiltInProfile::ArtifactBound,
            foundational.clone(),
            BTreeSet::from([AssumptionId::new("AX-ONE").unwrap()]),
        )
        .unwrap();
        let axiom_free = PolicyDefinition::built_in(
            BuiltInProfile::ArtifactBound,
            foundational,
            BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(axiomatic.id, axiom_free.id);

        let mut policies = BTreeMap::new();
        insert_release_policy(&mut policies, &axiomatic).unwrap();
        insert_release_policy(&mut policies, &axiomatic).unwrap();
        let error = insert_release_policy(&mut policies, &axiom_free)
            .unwrap_err()
            .to_string();
        assert!(error.contains("PB-RELEASE-0018"));
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn tcb_projection_rejects_one_tool_version_with_conflicting_identities() {
        let first = ToolIdentity {
            name: "registered-tool".into(),
            version: "1.0.0".into(),
            identity_sha256: Sha256Digest::of_bytes(b"first binary"),
        };
        let conflicting = ToolIdentity {
            name: first.name.clone(),
            version: first.version.clone(),
            identity_sha256: Sha256Digest::of_bytes(b"different binary"),
        };
        let mut components = BTreeMap::new();
        insert_tcb_component(&mut components, &first).unwrap();
        insert_tcb_component(&mut components, &first).unwrap();
        let error = insert_tcb_component(&mut components, &conflicting)
            .unwrap_err()
            .to_string();
        assert!(error.contains("PB-RELEASE-0020"));
        assert_eq!(components.len(), 1);
    }

    #[test]
    fn custom_policy_compiles_strict_fields_to_core_semantics() {
        let registered = BTreeSet::from(["AX-ONE".to_owned()]);
        let policy = compile_custom_policy(&policy_manifest(json!({})), &registered).unwrap();
        assert_eq!(
            policy.components,
            BTreeSet::from([
                BuiltInProfile::KernelWithAssumptions,
                BuiltInProfile::ArtifactBound
            ])
        );
        assert_eq!(
            policy.allowed_project_axioms,
            BTreeSet::from([AssumptionId::new("AX-ONE").unwrap()])
        );
        assert_eq!(
            policy.allowed_foundational_axioms,
            BTreeSet::from(["Classical.choice".to_owned()])
        );

        let native = compile_custom_policy(
            &policy_manifest(json!({
                "extends": "artifact-bound",
                "allow_native": true,
                "native_premise_count": 2
            })),
            &registered,
        )
        .unwrap();
        assert!(native.components.contains(&BuiltInProfile::NativeEvaluated));
        assert_eq!(
            native.native_premise_rule,
            Some(NativePremiseRule::Exactly { count: 2 })
        );
    }

    #[test]
    fn custom_policy_rejects_weakening_and_incoherent_fields() {
        let registered = BTreeSet::from(["AX-ONE".to_owned()]);
        for manifest in [
            policy_manifest(json!({"publication_allows_open": true})),
            policy_manifest(json!({"allow_native": true, "native_premise_count": null})),
            policy_manifest(json!({"allow_project_axioms": false})),
            policy_manifest(json!({
                "extends": "source-refined",
                "required_binding": "none",
                "require_registered_premises": false
            })),
            policy_manifest(json!({"require_registered_premises": true})),
            policy_manifest(json!({
                "extends": "kernel",
                "allow_project_axioms": true,
                "allowed_project_axioms": []
            })),
        ] {
            let error = compile_custom_policy(&manifest, &registered)
                .unwrap_err()
                .to_string();
            assert!(error.contains("PB-POLICY-0001"), "{error}");
        }
        assert!(
            compile_custom_policy(
                &policy_manifest(json!({"allowed_project_axioms": ["AX-UNKNOWN"]})),
                &registered
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_custom_policy_can_promote_exhaustive_evidence() {
        let manifest = policy_manifest(json!({
            "extends": "bounded",
            "allow_project_axioms": false,
            "allowed_project_axioms": [],
            "allowed_foundational_axioms": [],
            "allow_exhaustive_as_proved": true,
            "required_binding": "none"
        }));
        let policy = compile_custom_policy(&manifest, &BTreeSet::new()).unwrap();
        assert_eq!(policy.components, BTreeSet::from([BuiltInProfile::Bounded]));
        assert!(policy.admit_exhaustive_as_proved);
    }

    fn cache_test_unit() -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "translation-cache",
            "adapter": "charon-aeneas",
            "kind": "source-refinement",
            "claims": ["TEST-CLAIM-001"],
            "tier": 3,
            "refinement_theorem": "Test.refines",
            "premises": ["TEST-PREMISE-001"],
            "inputs": ["inputs"],
            "outputs": [],
            "environment_allowlist": [],
            "operation": {
                "type": "translation",
                "manifest": "proofbound/translation.toml",
                "targets": ["subject::entry"]
            },
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1048576,
                "memory_bytes": 1048576
            }
        }))
        .unwrap()
    }

    fn cache_test_bundle(root: &Path) -> ProjectBundle {
        let project = serde_json::from_value(json!({
            "schema": "proofbound-project/1",
            "project": "cache-test",
            "tier": 3,
            "claim_manifests": [],
            "assumption_manifests": [],
            "evidence_units": [],
            "translation_units": ["proofbound/translation.toml"],
            "model_check_units": [],
            "policy_manifests": [],
            "review_manifests": [],
            "demo_registry": null,
            "source": {
                "semantic": [],
                "runner": [],
                "presentation": [],
                "external_evidence": []
            },
            "toolchains": {},
            "limits": {
                "max_manifest_bytes": 2097152,
                "max_files": 100,
                "max_total_bytes": 1048576
            }
        }))
        .unwrap();
        let translation = serde_json::from_value(json!({
            "schema": "proofbound-translation-unit/3",
            "id": "translation-cache",
            "pipeline": "charon-aeneas",
            "generated_dir": "generated/tree",
            "handwritten_refinement": "lean/Refinement.lean",
            "determinism_runs": 2,
            "determinism_normalization": "pretty-printed-llbc/1",
            "forbid_generated_axioms": true,
            "claims": ["TEST-CLAIM-001"],
            "invocations": [{
                "id": "subject",
                "cargo_package": "subject",
                "cargo_manifest": "subject/Cargo.toml",
                "crate_name": "subject",
                "llbc_file": "subject.llbc",
                "start_from": ["subject::entry"],
                "opaque": [],
                "include": [],
                "translated_closure": [
                    {"kind": "function", "rust_name": "subject::entry"}
                ],
                "outputs": [
                    {
                        "kind": "lean-source",
                        "produced": "Funs.lean",
                        "destination": "generated/tree/Funs.lean"
                    },
                    {
                        "kind": "translation-report",
                        "produced": "translation.json",
                        "destination": "generated/tree/translation.json"
                    }
                ]
            }],
            "external_bridges": [],
            "template_axioms": [],
            "warning_inventory": [],
            "import_mapping": {
                "mode": "external-source-root",
                "source_roots": ["lean"]
            },
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1048576,
                "memory_bytes": 1048576
            }
        }))
        .unwrap();
        ProjectBundle {
            root: root.to_owned(),
            project,
            claims: BTreeMap::new(),
            assumptions: BTreeMap::new(),
            evidence_units: BTreeMap::new(),
            translation_units: BTreeMap::from([(
                "translation-cache".to_owned(),
                (root.join("proofbound/translation.toml"), translation),
            )]),
            model_check_units: BTreeMap::new(),
            policies: BTreeMap::new(),
            reviews: BTreeMap::new(),
            demos: None,
        }
    }

    #[test]
    fn cache_inputs_recursively_bind_directories_and_reject_missing_inputs() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("inputs/nested")).unwrap();
        fs::write(root.join("inputs/nested/value.txt"), b"first").unwrap();
        let roots = BTreeSet::from(["inputs".to_owned()]);
        let first = collect_cache_path_identities(&root, &roots, 10, 1024).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first.contains_key("inputs/nested/value.txt"));

        fs::write(root.join("inputs/nested/value.txt"), b"second").unwrap();
        let changed = collect_cache_path_identities(&root, &roots, 10, 1024).unwrap();
        assert_ne!(first, changed);
        fs::write(root.join("inputs/added.txt"), b"added").unwrap();
        let added = collect_cache_path_identities(&root, &roots, 10, 1024).unwrap();
        assert_ne!(changed, added);
        fs::remove_file(root.join("inputs/added.txt")).unwrap();
        fs::remove_file(root.join("inputs/nested/value.txt")).unwrap();
        fs::remove_dir_all(root.join("inputs")).unwrap();
        assert!(collect_cache_path_identities(&root, &roots, 10, 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cache_inputs_reject_symlinks_at_any_depth() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("inputs")).unwrap();
        fs::write(root.join("outside.txt"), b"outside").unwrap();
        symlink("../outside.txt", root.join("inputs/link.txt")).unwrap();
        let error =
            collect_cache_path_identities(&root, &BTreeSet::from(["inputs".to_owned()]), 10, 1024)
                .unwrap_err()
                .to_string();
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn translation_cache_automatically_binds_every_manifest_driven_input_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        for directory in [
            "inputs",
            "proofbound",
            "subject",
            "generated/tree",
            "lean/nested",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("inputs/source.rs"), b"source").unwrap();
        fs::write(root.join("proofbound/translation.toml"), b"manifest-v1").unwrap();
        fs::write(root.join("subject/Cargo.toml"), b"cargo-v1").unwrap();
        fs::write(root.join("generated/tree/Funs.lean"), b"funs-v1").unwrap();
        fs::write(root.join("generated/tree/translation.json"), b"report-v1").unwrap();
        fs::write(root.join("generated/tree/unmapped.txt"), b"stale-v1").unwrap();
        fs::write(root.join("lean/Refinement.lean"), b"refinement-v1").unwrap();
        fs::write(root.join("lean/Bridge.lean"), b"bridge-v1").unwrap();
        fs::write(root.join("lean/nested/Resolution.lean"), b"resolution-v1").unwrap();
        let unit = cache_test_unit();
        let mut bundle = cache_test_bundle(&root);
        bundle
            .translation_units
            .get_mut("translation-cache")
            .unwrap()
            .1
            .external_bridges
            .push(proofbound_manifest::ExternalBridge {
                file: "lean/Bridge.lean".to_owned(),
                module: Some("Bridge".to_owned()),
                reviewed_sha256: format!("sha256:{}", "11".repeat(32)),
            });

        let first = cache_input_identities(&bundle, &unit).unwrap();
        for path in [
            "inputs/source.rs",
            "proofbound/translation.toml",
            "subject/Cargo.toml",
            "generated/tree/Funs.lean",
            "generated/tree/translation.json",
            "generated/tree/unmapped.txt",
            "lean/Refinement.lean",
            "lean/Bridge.lean",
            "lean/nested/Resolution.lean",
        ] {
            assert!(first.contains_key(path), "missing {path}");
        }

        fs::write(root.join("proofbound/translation.toml"), b"manifest-v2").unwrap();
        let manifest_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(first, manifest_changed);
        fs::write(root.join("subject/Cargo.toml"), b"cargo-v2").unwrap();
        let cargo_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(manifest_changed, cargo_changed);
        fs::write(root.join("generated/tree/unmapped.txt"), b"stale-v2").unwrap();
        let generated_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(cargo_changed, generated_changed);
        fs::write(root.join("lean/Refinement.lean"), b"refinement-v2").unwrap();
        let refinement_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(generated_changed, refinement_changed);
        fs::write(root.join("lean/Bridge.lean"), b"bridge-v2").unwrap();
        let bridge_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(refinement_changed, bridge_changed);
        fs::write(root.join("lean/nested/Resolution.lean"), b"resolution-v2").unwrap();
        let source_root_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(bridge_changed, source_root_changed);
        fs::remove_dir_all(root.join("generated/tree")).unwrap();
        assert!(cache_input_identities(&bundle, &unit).is_err());
    }

    #[test]
    fn cargo_cache_binds_workspace_manifest_selected_package_and_sources() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        for directory in [
            "member/src",
            "target",
            ".proofbound",
            "node_modules/.bin",
            "empty-initial/nested",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("target/ignored.rs"), b"ephemeral target output\n").unwrap();
        fs::write(
            root.join(".proofbound/ignored.rs"),
            b"ephemeral Proofbound state\n",
        )
        .unwrap();
        fs::write(
            root.join("node_modules/.bin/ignored"),
            b"ephemeral Node installation\n",
        )
        .unwrap();
        fs::write(root.join("registered.txt"), b"unit-owned input\n").unwrap();
        let workspace = |revision: u8, members: &str| {
            format!(
                r#"[workspace]
members = [{members}]
resolver = "2"

[workspace.metadata]
revision = {revision}
"#
            )
        };
        fs::write(root.join("Cargo.toml"), workspace(1, "\"member\"")).unwrap();
        fs::write(
            root.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "cache-fixture"
version = "0.1.0"
"#,
        )
        .unwrap();
        let package_manifest = |description: &str| {
            format!(
                r#"[package]
name = "cache-fixture"
version = "0.1.0"
edition = "2021"
description = {description:?}
"#
            )
        };
        fs::write(root.join("member/Cargo.toml"), package_manifest("first")).unwrap();
        fs::write(root.join("shared.rs"), b"pub fn value() -> u8 { 1 }\n").unwrap();
        let build_helper = root.join("build-helper.sh");
        fs::write(&build_helper, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(
            root.join("member/build.rs"),
            b"fn main() { assert!(std::process::Command::new(\"../build-helper.sh\").status().unwrap().success()); }\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&build_helper, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(
            root.join("member/src/lib.rs"),
            b"#[path = \"../../shared.rs\"]\nmod shared;\npub use shared::value;\n",
        )
        .unwrap();

        let unit: EvidenceUnitManifest = serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "cargo-cache",
            "adapter": "rust-test",
            "kind": "property-test",
            "claims": ["TEST-CLAIM-001"],
            "tier": 0,
            "expected_inventory": ["tests::property"],
            "inputs": ["registered.txt"],
            "outputs": [],
            "environment_allowlist": [],
            "operation": {
                "type": "cargo-test",
                "manifest": "Cargo.toml",
                "package": "cache-fixture"
            },
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1048576,
                "memory_bytes": 1048576
            }
        }))
        .unwrap();
        let mut bundle = cache_test_bundle(&root);
        bundle.project.limits.max_files = 100;
        bundle.project.limits.max_total_bytes = 1 << 20;
        let mut directory_manifest = unit.clone();
        directory_manifest.operation.manifest = Some("member".to_owned());
        let error = cargo_execution_input_paths(&bundle, &directory_manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("regular file"), "{error}");
        let manifest_limit = bundle.project.limits.max_manifest_bytes;
        bundle.project.limits.max_manifest_bytes = 8;
        let error = cargo_execution_input_paths(&bundle, &unit)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no larger than 8 bytes"), "{error}");
        bundle.project.limits.max_manifest_bytes = manifest_limit;
        let file_limit = bundle.project.limits.max_files;
        bundle.project.limits.max_files = 1;
        let error = cargo_execution_input_paths(&bundle, &unit)
            .unwrap_err()
            .to_string();
        assert!(error.contains("reviewed Cargo shadow inputs"), "{error}");
        bundle.project.limits.max_files = file_limit;
        let key = |inputs: &BTreeMap<String, String>| {
            cache_key_identity(
                &unit,
                &[format!("sha256:{}", "11".repeat(32))],
                &[format!("sha256:{}", "22".repeat(32))],
                inputs,
                &BTreeMap::new(),
                &BTreeMap::new(),
            )
            .unwrap()
        };

        let initial = cache_input_identities(&bundle, &unit).unwrap();
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            "build-helper.sh",
            "member/build.rs",
            "member/Cargo.toml",
            "member/src/lib.rs",
            "registered.txt",
            "shared.rs",
        ] {
            assert!(
                initial.contains_key(path),
                "missing Cargo cache input {path}"
            );
        }
        assert!(!initial.contains_key("target/ignored.rs"));
        assert!(!initial.contains_key(".proofbound/ignored.rs"));
        assert!(!initial.contains_key("node_modules/.bin/ignored"));
        let initial_key = key(&initial);
        fs::create_dir_all(root.join("empty-added-later/nested")).unwrap();
        let empty_directory_added = cache_input_identities(&bundle, &unit).unwrap();
        assert_eq!(initial, empty_directory_added);

        fs::write(root.join("Cargo.toml"), workspace(2, "\"member\"")).unwrap();
        let workspace_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(initial_key, key(&workspace_changed));

        fs::write(root.join("member/Cargo.toml"), package_manifest("second")).unwrap();
        let package_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(key(&workspace_changed), key(&package_changed));

        fs::write(
            root.join("member/src/lib.rs"),
            b"#[path = \"../../shared.rs\"]\nmod shared;\npub use shared::value; // revision 2\n",
        )
        .unwrap();
        let source_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(key(&package_changed), key(&source_changed));

        // `shared.rs` is outside the selected package directory and is not a
        // declared unit input, but Rust compiles it through `#[path]` from the
        // exact project tree copied into the adapter shadow.
        fs::write(root.join("shared.rs"), b"pub fn value() -> u8 { 2 }\n").unwrap();
        let external_source_changed = cache_input_identities(&bundle, &unit).unwrap();
        assert_ne!(key(&source_changed), key(&external_source_changed));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let helper_bytes = fs::read(&build_helper).unwrap();
            fs::set_permissions(&build_helper, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(fs::read(&build_helper).unwrap(), helper_bytes);
            let execute_bit_removed = cache_input_identities(&bundle, &unit).unwrap();
            assert_ne!(key(&external_source_changed), key(&execute_bit_removed));
        }

        fs::write(root.join("Cargo.toml"), workspace(3, "")).unwrap();
        let error = cache_input_identities(&bundle, &unit)
            .unwrap_err()
            .to_string();
        assert!(error.contains("PB-CACHE-0001"), "{error}");
    }

    #[test]
    fn update_postcondition_uses_component_boundaries_and_their_intersection() {
        let changed = BTreeSet::from(["lean/Generated/Nested/Aux.lean".to_owned()]);
        let groups = vec![
            UpdateBoundaryGroup {
                paths: vec!["lean/Generated".to_owned()],
                recursive: true,
            },
            UpdateBoundaryGroup {
                paths: vec!["lean/Generated".to_owned()],
                recursive: true,
            },
        ];
        validate_output_boundaries(&groups).unwrap();
        enforce_update_output_postcondition("translation", &changed, &groups).unwrap();

        let sibling = BTreeSet::from(["lean/Generated-escape/Main.lean".to_owned()]);
        assert!(enforce_update_output_postcondition("translation", &sibling, &groups).is_err());
        let handwritten = BTreeSet::from(["lean/Handwritten.lean".to_owned()]);
        let intersecting = vec![
            UpdateBoundaryGroup {
                paths: vec!["lean".to_owned()],
                recursive: true,
            },
            UpdateBoundaryGroup {
                paths: vec!["lean/Generated".to_owned()],
                recursive: true,
            },
        ];
        assert!(
            enforce_update_output_postcondition("translation", &handwritten, &intersecting)
                .is_err()
        );
    }

    #[test]
    fn update_postcondition_rejects_missing_or_nonliteral_boundaries() {
        assert!(
            validate_output_boundaries(&[UpdateBoundaryGroup {
                paths: Vec::new(),
                recursive: false,
            }])
            .is_err()
        );
        assert!(
            validate_output_boundaries(&[UpdateBoundaryGroup {
                paths: vec!["generated/**".to_owned()],
                recursive: false,
            }])
            .is_err()
        );
        assert!(
            validate_output_boundaries(&[UpdateBoundaryGroup {
                paths: vec!["../outside".to_owned()],
                recursive: false,
            }])
            .is_err()
        );

        let exact = vec![UpdateBoundaryGroup {
            paths: vec!["fixtures/result.pbac".to_owned()],
            recursive: false,
        }];
        enforce_update_output_postcondition(
            "generator",
            &BTreeSet::from(["fixtures/result.pbac".to_owned()]),
            &exact,
        )
        .unwrap();
        assert!(
            enforce_update_output_postcondition(
                "generator",
                &BTreeSet::from(["fixtures/result.pbac/extra".to_owned()]),
                &exact,
            )
            .is_err()
        );
    }

    #[test]
    fn update_shadow_imports_only_prevalidated_output_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let shadow = temporary.path().join("shadow");
        for directory in [&root, &shadow] {
            fs::create_dir_all(directory.join("generated")).unwrap();
            fs::create_dir_all(directory.join("reviewed")).unwrap();
            fs::write(directory.join("generated/result.txt"), b"old").unwrap();
            fs::write(directory.join("reviewed/source.txt"), b"meaning").unwrap();
        }
        fs::write(shadow.join("generated/result.txt"), b"new").unwrap();
        fs::write(shadow.join("reviewed/source.txt"), b"tampered").unwrap();

        let changed = changed_update_paths(&root, &shadow, 1 << 20).unwrap();
        assert_eq!(
            changed,
            BTreeSet::from([
                "generated/result.txt".to_owned(),
                "reviewed/source.txt".to_owned()
            ])
        );
        let boundary = vec![UpdateBoundaryGroup {
            paths: vec!["generated".to_owned()],
            recursive: true,
        }];
        assert!(enforce_update_output_postcondition("unit", &changed, &boundary).is_err());
        assert_eq!(
            fs::read(root.join("reviewed/source.txt")).unwrap(),
            b"meaning"
        );

        fs::write(shadow.join("reviewed/source.txt"), b"meaning").unwrap();
        let changed = changed_update_paths(&root, &shadow, 1 << 20).unwrap();
        enforce_update_output_postcondition("unit", &changed, &boundary).unwrap();
        apply_update_changes(&root, &shadow, &changed).unwrap();
        assert_eq!(fs::read(root.join("generated/result.txt")).unwrap(), b"new");
        assert_eq!(
            fs::read(root.join("reviewed/source.txt")).unwrap(),
            b"meaning"
        );
    }

    #[test]
    fn translation_update_allows_only_exact_writes_and_owned_stale_deletions() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let shadow = temporary.path().join("shadow");
        for project in [&root, &shadow] {
            fs::create_dir_all(project.join("generated/tree")).unwrap();
            fs::create_dir_all(project.join("reviewed")).unwrap();
            fs::write(project.join("reviewed/source.txt"), b"meaning").unwrap();
        }
        fs::write(root.join("generated/tree/Funs.lean"), b"old").unwrap();
        fs::write(root.join("generated/tree/translation.json"), b"old report").unwrap();
        fs::write(root.join("generated/tree/stale.txt"), b"stale").unwrap();
        fs::write(shadow.join("generated/tree/Funs.lean"), b"new").unwrap();
        fs::write(
            shadow.join("generated/tree/translation.json"),
            b"new report",
        )
        .unwrap();

        let bundle = cache_test_bundle(&root);
        let translation = &bundle.translation_units["translation-cache"].1;
        let destinations = translation_destinations(translation).unwrap();
        let changes = classify_update_changes(&root, &shadow, 1 << 20).unwrap();
        assert!(changes.deletions.contains("generated/tree/stale.txt"));
        validate_translation_update(
            "translation-cache",
            &root,
            &shadow,
            translation,
            &destinations,
            &changes,
            100,
            1 << 20,
        )
        .unwrap();

        fs::write(shadow.join("generated/tree/unmapped.txt"), b"smuggled").unwrap();
        let changes = classify_update_changes(&root, &shadow, 1 << 20).unwrap();
        assert!(
            validate_translation_update(
                "translation-cache",
                &root,
                &shadow,
                translation,
                &destinations,
                &changes,
                100,
                1 << 20,
            )
            .is_err()
        );
        fs::remove_file(shadow.join("generated/tree/unmapped.txt")).unwrap();
        fs::write(shadow.join("reviewed/source.txt"), b"tampered").unwrap();
        let changes = classify_update_changes(&root, &shadow, 1 << 20).unwrap();
        assert!(
            validate_translation_update(
                "translation-cache",
                &root,
                &shadow,
                translation,
                &destinations,
                &changes,
                100,
                1 << 20,
            )
            .is_err()
        );
    }

    #[test]
    fn translation_update_rejects_reserved_project_control_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let mut translation = cache_test_bundle(root)
            .translation_units
            .remove("translation-cache")
            .unwrap()
            .1;
        translation.generated_dir = ".git/hooks".to_owned();
        translation.invocations[0].outputs[0].destination = ".git/hooks/Funs.lean".to_owned();
        translation.invocations[0].outputs[1].destination =
            ".git/hooks/translation.json".to_owned();

        let error = translation_destinations(&translation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("reserved project-control"), "{error}");
        let replacement_error = begin_owned_tree_replacement(root, root, ".git/hooks")
            .err()
            .unwrap()
            .to_string();
        assert!(
            replacement_error.contains("reserved project-control"),
            "{replacement_error}"
        );

        translation.generated_dir = "generated/tree".to_owned();
        translation.invocations[0].outputs[0].destination =
            "generated/tree/target/Funs.lean".to_owned();
        translation.invocations[0].outputs[1].destination =
            "generated/tree/translation.json".to_owned();
        assert!(translation_destinations(&translation).is_err());
    }

    #[test]
    fn atomic_translation_tree_replacement_supports_file_directory_shape_flips() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let shadow = temporary.path().join("shadow");
        fs::create_dir_all(root.join("generated/tree/Shape.lean")).unwrap();
        fs::write(
            root.join("generated/tree/Shape.lean/old.lean"),
            b"old nested",
        )
        .unwrap();
        fs::create_dir_all(shadow.join("generated/tree")).unwrap();
        fs::write(shadow.join("generated/tree/Shape.lean"), b"new file").unwrap();

        replace_owned_tree_atomically(&root, &shadow, "generated/tree").unwrap();
        assert_eq!(
            fs::read(root.join("generated/tree/Shape.lean")).unwrap(),
            b"new file"
        );

        fs::remove_dir_all(shadow.join("generated/tree")).unwrap();
        fs::create_dir_all(shadow.join("generated/tree/Shape.lean")).unwrap();
        fs::write(
            shadow.join("generated/tree/Shape.lean/new.lean"),
            b"new nested",
        )
        .unwrap();
        replace_owned_tree_atomically(&root, &shadow, "generated/tree").unwrap();
        assert_eq!(
            fs::read(root.join("generated/tree/Shape.lean/new.lean")).unwrap(),
            b"new nested"
        );
    }

    #[test]
    fn uncommitted_translation_tree_transaction_rolls_back_on_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let shadow = temporary.path().join("shadow");
        fs::create_dir_all(root.join("generated/tree")).unwrap();
        fs::write(root.join("generated/tree/value.lean"), b"original").unwrap();
        fs::create_dir_all(shadow.join("generated/tree")).unwrap();
        fs::write(shadow.join("generated/tree/value.lean"), b"replacement").unwrap();

        let transaction = begin_owned_tree_replacement(&root, &shadow, "generated/tree").unwrap();
        assert_eq!(
            fs::read(root.join("generated/tree/value.lean")).unwrap(),
            b"replacement"
        );
        drop(transaction);
        assert_eq!(
            fs::read(root.join("generated/tree/value.lean")).unwrap(),
            b"original"
        );
        assert_eq!(fs::read_dir(root.join("generated")).unwrap().count(), 1);
    }

    #[test]
    fn partial_backup_cleanup_failure_preserves_the_installed_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let shadow = temporary.path().join("shadow");
        fs::create_dir_all(root.join("generated/tree")).unwrap();
        fs::write(root.join("generated/tree/value.lean"), b"original").unwrap();
        fs::create_dir_all(shadow.join("generated/tree")).unwrap();
        fs::write(shadow.join("generated/tree/value.lean"), b"replacement").unwrap();

        let transaction = begin_owned_tree_replacement(&root, &shadow, "generated/tree").unwrap();
        let backup = transaction.backup.clone().unwrap();
        let error = transaction
            .commit_with_cleanup(|backup| {
                fs::remove_file(backup.join("value.lean"))?;
                Err(std::io::Error::other("injected cleanup failure"))
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("installed tree remains"), "{error}");
        assert_eq!(
            fs::read(root.join("generated/tree/value.lean")).unwrap(),
            b"replacement"
        );
        assert!(backup.exists());
        fs::remove_dir_all(backup).unwrap();
    }

    #[test]
    fn active_translation_transaction_exposes_only_the_reviewed_generated_diff() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("project");
        let shadow = temporary.path().join("shadow");
        fs::create_dir_all(root.join("generated/tree")).unwrap();
        fs::write(root.join(".gitignore"), b".proofbound/\n").unwrap();
        fs::write(root.join("generated/tree/value.lean"), b"original").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Proofbound Test",
                "-c",
                "user.email=test@proofbound.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "initial",
            ],
        ] {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
        }
        fs::create_dir_all(shadow.join("generated/tree")).unwrap();
        fs::write(shadow.join("generated/tree/value.lean"), b"replacement").unwrap();

        let transaction = begin_owned_tree_replacement(&root, &shadow, "generated/tree").unwrap();
        assert_eq!(
            changed_reviewed_paths(&root).unwrap(),
            BTreeSet::from(["generated/tree/value.lean".to_owned()])
        );
        drop(transaction);
        assert!(changed_reviewed_paths(&root).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn failed_atomic_translation_copy_leaves_original_tree_untouched() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let shadow = temporary.path().join("shadow");
        fs::create_dir_all(root.join("generated/tree")).unwrap();
        fs::write(root.join("generated/tree/original.lean"), b"original").unwrap();
        fs::create_dir_all(shadow.join("generated/tree")).unwrap();
        fs::write(shadow.join("outside.lean"), b"outside").unwrap();
        symlink(
            "../../outside.lean",
            shadow.join("generated/tree/link.lean"),
        )
        .unwrap();

        assert!(replace_owned_tree_atomically(&root, &shadow, "generated/tree").is_err());
        assert_eq!(
            fs::read(root.join("generated/tree/original.lean")).unwrap(),
            b"original"
        );
        assert!(!root.join("generated/tree/link.lean").exists());
    }

    #[cfg(unix)]
    #[test]
    fn update_shadow_rejects_symlink_outputs() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("target.txt"), b"target").unwrap();
        symlink("target.txt", temporary.path().join("generated.txt")).unwrap();
        let error = update_file_inventory(temporary.path(), 1 << 20)
            .unwrap_err()
            .to_string();
        assert!(error.contains("contains symlink"));
    }

    #[test]
    fn release_schemas_are_emitted_from_build_pinned_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("release-schemas");
        fs::create_dir_all(&destination).unwrap();

        write_release_schemas(&destination).unwrap();

        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
        let inventory = |root: &Path| {
            let mut entries = fs::read_dir(root)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), fs::read(entry.path()).unwrap())
                })
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            entries
        };
        assert_eq!(inventory(&destination), inventory(&source));
    }

    #[test]
    fn python_mutation_abi_requires_exit_one_and_distinct_exact_shadows() {
        let command = |root: &str| CommandObservation {
            program: "python3".to_owned(),
            args: vec![
                "-m".to_owned(),
                "pytest".to_owned(),
                "-p".to_owned(),
                "no:cacheprovider".to_owned(),
                "--rootdir".to_owned(),
                root.to_owned(),
                "-q".to_owned(),
                format!("{root}/tests/test_subject.py::test_guard"),
            ],
            environment_allowlist: Vec::new(),
        };
        let baseline = command("$BASELINE");
        let mutant = command("$MUTANT");

        assert_eq!(mutation_expected_exit(AdapterKind::PythonTest).unwrap(), 1);
        assert!(mutation_command_shape_valid(
            AdapterKind::PythonTest,
            &baseline,
            &mutant,
            "tests/test_subject.py::test_guard"
        ));

        let replayed_baseline = command("$BASELINE");
        assert!(!mutation_command_shape_valid(
            AdapterKind::PythonTest,
            &baseline,
            &replayed_baseline,
            "tests/test_subject.py::test_guard"
        ));
    }

    #[test]
    fn bounded_receipt_projects_exact_registered_kani_semantics() {
        let unit: EvidenceUnitManifest = serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "bounded-unit",
            "adapter": "kani",
            "kind": "bounded-check",
            "claims": ["CLAIM-ONE"],
            "tier": 1,
            "operation": {
                "type": "kani",
                "package": "subject",
                "manifest": "proofbound/model-checks/bounded-unit.toml",
                "targets": ["proofs::first", "proofs::second"]
            },
            "expected_inventory": ["proofs::first", "proofs::second"],
            "inputs": ["src/lib.rs", "proofbound/model-checks/bounded-unit.toml"],
            "outputs": [],
            "environment_allowlist": [],
            "bounded_domain": {
                "id": "finite-domain",
                "description": "all registered two-bit inputs",
                "cardinality": 4,
                "ordering_key": [0, 1]
            },
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1024,
                "memory_bytes": 2048
            }
        }))
        .unwrap();
        let model: ModelCheckUnitManifest = serde_json::from_value(json!({
            "schema": "proofbound-model-check-unit/1",
            "id": "bounded-unit",
            "adapter": "kani",
            "package": "subject",
            "harnesses": ["proofs::first", "proofs::second"],
            "claims": ["CLAIM-ONE"],
            "domain": {
                "id": "finite-domain",
                "description": "all registered two-bit inputs",
                "cardinality": 4,
                "ordering_key": [0, 1]
            },
            "solver": "cadical",
            "unwind": 7,
            "assumptions": ["Each seed is an unsigned two-bit value."],
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1024,
                "memory_bytes": 2048
            }
        }))
        .unwrap();

        let receipt = bounded_check_from_registered_model(
            &unit,
            &model,
            &["proofs::second".into(), "proofs::first".into()],
        )
        .unwrap();
        assert_eq!(receipt.solver, "cadical");
        assert_eq!(receipt.assumptions, model.assumptions);
        assert_eq!(
            receipt.unwind_bounds,
            BTreeMap::from([("proofs::first".into(), 7), ("proofs::second".into(), 7)])
        );
        let error = bounded_check_from_registered_model(
            &unit,
            &model,
            &["proofs::first".into(), "proofs::undeclared".into()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("exact Kani harness inventory"));

        let mut mismatched = model.clone();
        mismatched.harnesses[1] = "proofs::different".into();
        assert!(
            bounded_check_from_registered_model(&unit, &mismatched, &unit.expected_inventory)
                .is_err()
        );

        let mut zero_unwind = model.clone();
        zero_unwind.unwind = 0;
        assert!(
            bounded_check_from_registered_model(&unit, &zero_unwind, &unit.expected_inventory)
                .is_err()
        );

        let mut duplicate_assumptions = model.clone();
        duplicate_assumptions.assumptions = vec!["same".into(), "same".into()];
        assert!(
            bounded_check_from_registered_model(
                &unit,
                &duplicate_assumptions,
                &unit.expected_inventory
            )
            .is_err()
        );

        let mut oversized_assumption = model.clone();
        oversized_assumption.assumptions = vec!["x".repeat(4097)];
        assert!(
            bounded_check_from_registered_model(
                &unit,
                &oversized_assumption,
                &unit.expected_inventory
            )
            .is_err()
        );

        let mut too_many_assumptions = model.clone();
        too_many_assumptions.assumptions = (0..4097)
            .map(|index| format!("assumption {index}"))
            .collect();
        assert!(
            bounded_check_from_registered_model(
                &unit,
                &too_many_assumptions,
                &unit.expected_inventory
            )
            .is_err()
        );

        let mut empty_solver = model;
        empty_solver.solver.clear();
        assert!(
            bounded_check_from_registered_model(&unit, &empty_solver, &unit.expected_inventory)
                .is_err()
        );
    }

    #[test]
    fn adapter_observation_preserves_complete_execution_and_unknown_memory() {
        let unit: EvidenceUnitManifest = serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "multi-command",
            "adapter": "rust-test",
            "kind": "example-test",
            "claims": ["CLAIM-ONE"],
            "tier": 0,
            "operation": {
                "type": "cargo-test",
                "package": "subject",
                "targets": ["subject::works"]
            },
            "expected_inventory": ["subject::works"],
            "inputs": [],
            "outputs": [],
            "environment_allowlist": [],
            "resource_budget": {"time_seconds": 10, "disk_bytes": 100, "memory_bytes": 100}
        }))
        .unwrap();
        let digest = |label: &str| format!("sha256:{}", Sha256Digest::of_bytes(label.as_bytes()));
        let command = |argument: &str| {
            json!({
                "program": "cargo",
                "args": [argument],
                "environment_allowlist": [{
                    "name": "LANG",
                    "value_sha256": null,
                    "secret": false
                }]
            })
        };
        let run = |index: usize, label: &str| {
            json!({
                "command_index": index,
                "exit_code": 0,
                "stdout_sha256": digest(&format!("stdout:{label}")),
                "stderr_sha256": digest(&format!("stderr:{label}")),
                "normalized_output_sha256": digest(&format!("normalized:{label}")),
                "output_truncated": false,
                "duration_ms": index + 1
            })
        };
        let observation = json!({
            "schema": "proofbound-adapter-observation/2",
            "unit_id": "multi-command",
            "evidence_kind": "example-test",
            "outcome": "passed",
            "input_artifacts": [],
            "generated_artifacts": [],
            "tool": {"name":"cargo","version":"1","identity_sha256":digest("tool")},
            "adapter": {"name":"adapter","version":"1","identity_sha256":digest("adapter")},
            "commands": [command("--version"), command("test"), command("--list")],
            "runs": [run(0, "version"), run(1, "test"), run(2, "list")],
            "started_unix_ms": 1,
            "completed_unix_ms": 7,
            "deterministic_result_sha256": digest("result"),
            "unit_configuration_sha256": digest("configuration"),
            "resource_budget": {"time_ms":10000,"disk_bytes":100,"memory_bytes":100},
            "resource_usage": {"time_ms":6,"peak_disk_bytes":10,"peak_memory_bytes":null},
            "inventory": ["subject::works"],
            "normalization": "cargo-test-output/1"
        });
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let bundle = cache_test_bundle(root);
        let record = observation_to_record(
            root,
            &bundle,
            &unit,
            None,
            &[digest("closure")],
            &observation,
        )
        .unwrap();
        assert_eq!(record.provenance.commands.len(), 3);
        assert_eq!(record.provenance.runs.len(), 3);
        assert_eq!(record.provenance.runs[2].command_index, 2);
        assert_eq!(record.provenance.normalization, "cargo-test-output/1");
        assert_eq!(record.provenance.resource_usage.peak_memory_bytes, None);
        assert_eq!(
            record.provenance.execution_kind,
            ExecutionKind::ObservedProcesses
        );
        assert_eq!(
            record.provenance.commands[0].environment_allowlist[0].value_sha256,
            None
        );
        assert_eq!(
            record.provenance.reproduction_command.args,
            ["reproduce", "multi-command"]
        );
        let closure = digest("closure");
        let released = release_evidence_record(
            &record,
            &closure,
            &BTreeMap::from([(closure.clone(), closure.clone())]),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(
            released["provenance"]["commands"][0]["environment_allowlist"][0]["value_sha256"]
                .is_null()
        );

        let mut forged_internal = record.clone();
        forged_internal.provenance.execution_kind = ExecutionKind::CompilerInternal;
        forged_internal.provenance.commands.clear();
        forged_internal.provenance.runs.clear();
        assert!(!has_observed_adapter_execution(&forged_internal));
        let error = bind_record_to_execution(
            root,
            &bundle,
            &unit,
            std::slice::from_ref(&closure),
            &[],
            &mut forged_internal,
        )
        .unwrap_err();
        assert!(error.to_string().contains("PB-ADAPTER-0026"));

        let mut failed_with_incomplete_run = observation.clone();
        failed_with_incomplete_run["outcome"] = json!("failed");
        failed_with_incomplete_run["runs"][0]["exit_code"] = serde_json::Value::Null;
        let failed_record = observation_to_record(
            root,
            &bundle,
            &unit,
            None,
            std::slice::from_ref(&closure),
            &failed_with_incomplete_run,
        )
        .unwrap();
        assert_eq!(failed_record.status, EvidenceStatus::Failed);

        let mut missing_memory = observation.clone();
        missing_memory["resource_usage"]
            .as_object_mut()
            .unwrap()
            .remove("peak_memory_bytes");
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                &[digest("closure")],
                &missing_memory,
            )
            .is_err()
        );

        let mut missing_exit = observation.clone();
        missing_exit["runs"][0]
            .as_object_mut()
            .unwrap()
            .remove("exit_code");
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                &[digest("closure")],
                &missing_exit,
            )
            .is_err()
        );

        let mut passing_nonzero_exit = observation.clone();
        passing_nonzero_exit["runs"][1]["exit_code"] = json!(1);
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                &[digest("closure")],
                &passing_nonzero_exit,
            )
            .is_err()
        );

        let mut missing_environment_identity = observation.clone();
        missing_environment_identity["commands"][0]["environment_allowlist"][0]
            .as_object_mut()
            .unwrap()
            .remove("value_sha256");
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                &[digest("closure")],
                &missing_environment_identity
            )
            .is_err()
        );

        let mut oversized_normalization = observation;
        oversized_normalization["normalization"] = json!("x".repeat(1025));
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                &[digest("closure")],
                &oversized_normalization
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_transcription_observation_derives_round_trip_and_tcb_roles() {
        let unit: EvidenceUnitManifest = serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/2",
            "id": "round-trip",
            "adapter": "trusted-transcription",
            "kind": "trusted-transcription",
            "claims": ["CLAIM-ONE"],
            "tier": 1,
            "binding_mode": "external-round-trip",
            "operation": {"type": "transcription"},
            "expected_inventory": ["fixtures/source.bin", "fixtures/transcription.txt"],
            "inputs": [
                "fixtures/source.bin",
                "fixtures/transcription.txt",
                "scripts/transcription_driver.py"
            ],
            "outputs": [],
            "environment_allowlist": ["PATH"],
            "transcription": {
                "schema": "proofbound-trusted-transcription/1",
                "source": "fixtures/source.bin",
                "committed_transcription": "fixtures/transcription.txt",
                "driver": "scripts/transcription_driver.py",
                "source_format": "subject-bytes/1",
                "transcribed_format": "subject-text/1",
                "driver_abi": "proofbound-transcription-driver/1"
            },
            "resource_budget": {"time_seconds": 10, "disk_bytes": 1000, "memory_bytes": 1000}
        }))
        .unwrap();
        let digest = |label: &str| format!("sha256:{}", Sha256Digest::of_bytes(label.as_bytes()));
        let source_digest = digest("source bytes");
        let transcription_digest = digest("transcription bytes");
        let driver = ArtifactIdentity {
            logical_name: ArtifactLogicalName::new("scripts/transcription_driver.py").unwrap(),
            sha256: parse_digest(&digest("driver bytes")).unwrap(),
            size_bytes: 12,
        };
        let transcriber_identity = format!(
            "sha256:{}",
            transcription_role_identity(TranscriptionRole::Transcriber, &driver)
        );
        let reencoder_identity = format!(
            "sha256:{}",
            transcription_role_identity(TranscriptionRole::Reencoder, &driver)
        );
        let run = |index: usize| {
            json!({
                "command_index": index,
                "exit_code": 0,
                "stdout_sha256": digest(&format!("stdout-{index}")),
                "stderr_sha256": digest(&format!("stderr-{index}")),
                "normalized_output_sha256": digest(&format!("normalized-{index}")),
                "output_truncated": false,
                "duration_ms": 1
            })
        };
        let environment = || {
            json!([
                {"name":"PATH","value_sha256":digest("path"),"secret":false},
                {"name":"PYTHONDONTWRITEBYTECODE","value_sha256":digest("no-bytecode"),"secret":false},
                {"name":"TERM","value_sha256":digest("term"),"secret":false}
            ])
        };
        let observation = json!({
            "schema": "proofbound-adapter-observation/2",
            "unit_id": "round-trip",
            "evidence_kind": "trusted-transcription",
            "outcome": "passed",
            "input_artifacts": [
                {"logical_name":"fixtures/source.bin","sha256":source_digest,"size_bytes":12},
                {"logical_name":"fixtures/transcription.txt","sha256":transcription_digest,"size_bytes":21},
                {"logical_name":"scripts/transcription_driver.py","sha256":digest("driver bytes"),"size_bytes":12}
            ],
            "generated_artifacts": [
                {"logical_name":"trusted-transcription/round-trip/reencoded-source","sha256":source_digest,"size_bytes":12},
                {"logical_name":"trusted-transcription/round-trip/transcribed-candidate","sha256":transcription_digest,"size_bytes":21}
            ],
            "tool": {"name":"python3","version":"3","identity_sha256":digest("python")},
            "adapter": {"name":"proofbound-adapter-test","version":"1","identity_sha256":digest("adapter")},
            "commands": [
                {"program":"python3","args":["transcribe"],"environment_allowlist":environment()},
                {"program":"python3","args":["reencode"],"environment_allowlist":environment()}
            ],
            "runs": [run(0), run(1)],
            "started_unix_ms": 1,
            "completed_unix_ms": 3,
            "deterministic_result_sha256": digest("result"),
            "unit_configuration_sha256": digest("unit"),
            "resource_budget": {"time_ms":10000,"disk_bytes":1000,"memory_bytes":1000},
            "resource_usage": {"time_ms":2,"peak_disk_bytes":33,"peak_memory_bytes":null},
            "inventory": ["fixtures/source.bin", "fixtures/transcription.txt"],
            "normalization": "exact-transcription-bytes/1",
            "trusted_transcription": {
                "schema": "proofbound-trusted-transcription/1",
                "source": {"logical_name":"fixtures/source.bin","sha256":source_digest,"size_bytes":12},
                "committed_transcription": {"logical_name":"fixtures/transcription.txt","sha256":transcription_digest,"size_bytes":21},
                "transcribed_candidate": {"logical_name":"trusted-transcription/round-trip/transcribed-candidate","sha256":transcription_digest,"size_bytes":21},
                "reencoded_source": {"logical_name":"trusted-transcription/round-trip/reencoded-source","sha256":source_digest,"size_bytes":12},
                "driver": {"logical_name":"scripts/transcription_driver.py","sha256":digest("driver bytes"),"size_bytes":12},
                "driver_abi": "proofbound-transcription-driver/1",
                "source_format": "subject-bytes/1",
                "transcribed_format": "subject-text/1",
                "transcriber_role_identity": transcriber_identity,
                "reencoder_role_identity": reencoder_identity
            }
        });
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let bundle = cache_test_bundle(root);
        let closure = digest("closure");
        let record = observation_to_record(
            root,
            &bundle,
            &unit,
            None,
            std::slice::from_ref(&closure),
            &observation,
        )
        .unwrap();
        record
            .validate(&ClaimId::new("CLAIM-ONE").unwrap())
            .unwrap();
        let detail = record.trusted_transcription.as_ref().unwrap();
        assert_eq!(
            detail.transcriber.tcb_node.as_str(),
            "tcb:trusted-transcription:round-trip:transcriber"
        );
        assert_eq!(
            detail.reencoder.tcb_node.as_str(),
            "tcb:trusted-transcription:round-trip:reencoder"
        );
        let released = release_evidence_record(
            &record,
            &closure,
            &BTreeMap::from([(closure.clone(), closure.clone())]),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            released["trusted_transcription"]["schema"],
            "proofbound-trusted-transcription/1"
        );
        assert!(
            released["trusted_transcription"]
                .get("round_trip_passed")
                .is_none()
        );

        let mut smuggled_boolean = observation.clone();
        smuggled_boolean["trusted_transcription"]["round_trip_passed"] = json!(true);
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                std::slice::from_ref(&closure),
                &smuggled_boolean
            )
            .is_err()
        );

        let mut swapped_roles = observation.clone();
        swapped_roles["trusted_transcription"]["transcriber_role_identity"] =
            observation["trusted_transcription"]["reencoder_role_identity"].clone();
        assert!(
            observation_to_record(
                root,
                &bundle,
                &unit,
                None,
                std::slice::from_ref(&closure),
                &swapped_roles
            )
            .is_err()
        );

        let mut mismatched_candidate = observation;
        let wrong_digest = digest("wrong transcription");
        mismatched_candidate["trusted_transcription"]["transcribed_candidate"]["sha256"] =
            json!(wrong_digest.clone());
        mismatched_candidate["generated_artifacts"][1]["sha256"] = json!(wrong_digest);
        let invalid = observation_to_record(
            root,
            &bundle,
            &unit,
            None,
            std::slice::from_ref(&closure),
            &mismatched_candidate,
        )
        .unwrap();
        assert!(
            invalid
                .validate(&ClaimId::new("CLAIM-ONE").unwrap())
                .is_err()
        );
    }

    #[test]
    fn release_smoke_uses_the_canonical_empty_additional_closure_shape() {
        let fixture = tempfile::tempdir().unwrap();
        let destination = fixture.path().join("release");
        release_smoke(&destination).unwrap();

        let payload: serde_json::Value =
            serde_json::from_slice(&fs::read(destination.join("compiled-receipt.json")).unwrap())
                .unwrap();
        let provenance = &payload["evidence"][0]["record"]["provenance"];
        assert!(provenance.get("additional_closures").is_none());
        assert_eq!(provenance["execution_kind"], "compiler-internal");
        assert!(provenance["commands"].as_array().unwrap().is_empty());
        assert!(provenance["runs"].as_array().unwrap().is_empty());
        assert!(provenance["actual_cost"]["memory_bytes"].is_null());
        assert_eq!(
            payload["claims"][0]["statement"],
            "The release serializer preserves a Tier-0 assurance ledger."
        );
        assert_eq!(
            payload["claims"][0]["public_language"],
            "The portable release smoke remains an open Tier-0 ledger entry."
        );
        assert_eq!(
            payload["reported_statuses"][0]["public_statement"],
            "The portable release smoke remains an open Tier-0 ledger entry."
        );

        let cache_material = json!({
            "semantic_closure": provenance["semantic_closure"],
            "input_artifacts": provenance["input_artifacts"],
            "tool": provenance["tool"],
            "adapter": provenance["adapter"],
            "unit_configuration_sha256": provenance["unit_configuration_sha256"],
        });
        assert_eq!(
            provenance["cache_key"],
            domain_hash(
                "proofbound-cache-key/1",
                &canonical_json(&cache_material).unwrap()
            )
        );
    }

    fn inventory_protocol_unit() -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "inventory-protocol",
            "adapter": "rust-test",
            "kind": "example-test",
            "claims": ["CLAIM-ONE"],
            "tier": 0,
            "operation": {
                "type": "cargo-test",
                "package": "subject",
                "targets": ["alpha", "beta"]
            },
            "expected_inventory": ["alpha", "beta"],
            "inputs": [],
            "outputs": [],
            "environment_allowlist": [],
            "resource_budget": {"time_seconds":1,"disk_bytes":1,"memory_bytes":1}
        }))
        .unwrap()
    }

    fn direct_example_record_value(inventory: Vec<&str>) -> serde_json::Value {
        let digest = format!("sha256:{}", "00".repeat(32));
        json!({
            "schema": "proofbound-evidence/3",
            "id": "example-test:inventory-protocol",
            "node_id": "evidence:example-test:inventory-protocol",
            "unit_id": "unit:inventory-protocol",
            "kind": "example-test",
            "status": "passed",
            "claims": ["CLAIM-ONE"],
            "inventoried_targets": inventory,
            "assumptions": [],
            "premises": [],
            "provenance": {
                "project_revision": "adapter-observed-revision",
                "tree_state": "dirty",
                "semantic_source_closure": digest,
                "additional_closures": [],
                "input_artifacts": [],
                "generated_artifacts": [],
                "tool": {"name":"cargo","version":"1","identity_sha256":digest},
                "adapter": {"name":"proofbound-adapter-test","version":"1","identity_sha256":digest},
                "execution_kind": "observed-processes",
                "commands": [{"program":"cargo","args":["test"],"environment_allowlist":[]}],
                "runs": [{
                    "command_index": 0,
                    "exit_code": 0,
                    "stdout_sha256": digest,
                    "stderr_sha256": digest,
                    "normalized_output_sha256": digest,
                    "output_truncated": false,
                    "duration_ms": 1
                }],
                "normalization": "cargo-test-output/1",
                "reproduction_command": {"program":"cargo","args":["test"],"environment_allowlist":[]},
                "started_unix_ms": 1,
                "completed_unix_ms": 2,
                "deterministic_result_identity": digest,
                "unit_configuration_sha256": digest,
                "resource_budget": {"time_ms":1,"disk_bytes":1,"memory_bytes":1},
                "resource_usage": {"time_ms":1,"peak_disk_bytes":1,"peak_memory_bytes":1},
                "cache_origin": "executed"
            }
        })
    }

    #[test]
    fn direct_record_wire_inventory_must_equal_its_canonical_typed_encoding() {
        let canonical = direct_example_record_value(vec!["alpha", "beta"]);
        assert!(
            canonical_direct_evidence_record(&canonical)
                .unwrap()
                .is_some()
        );

        for inventory in [vec!["alpha", "alpha", "beta"], vec!["beta", "alpha"]] {
            let error = canonical_direct_evidence_record(&direct_example_record_value(inventory))
                .unwrap_err()
                .to_string();
            assert!(error.contains("PB-ADAPTER-0027"), "{error}");
        }
    }

    #[test]
    fn response_inventory_rejects_missing_extra_duplicate_order_and_inner_skew() {
        let unit = inventory_protocol_unit();
        let bundle = cache_test_bundle(Path::new("."));
        let mut source_ordered_unit = unit.clone();
        source_ordered_unit.expected_inventory = vec!["beta".to_owned(), "alpha".to_owned()];
        assert_eq!(
            registered_adapter_inventory(&bundle, &source_ordered_unit).unwrap(),
            ["alpha", "beta"]
        );
        let response = |inventory: Vec<&str>, inner: Vec<&str>| AdapterResponse {
            schema: "proofbound-adapter-protocol/1".into(),
            message_type: "response".into(),
            request_id: "0123456789abcdef0123456789abcdef".into(),
            adapter: "rust-test".into(),
            success: true,
            evidence: Some(direct_example_record_value(inner)),
            inventory: inventory.into_iter().map(str::to_owned).collect(),
            diagnostics: Vec::new(),
        };

        for outer in [
            vec!["alpha"],
            vec!["alpha", "beta", "gamma"],
            vec!["alpha", "alpha", "beta"],
            vec!["beta", "alpha"],
        ] {
            let error = response_to_record(
                Path::new("."),
                &bundle,
                &unit,
                None,
                &[],
                &[],
                &response(outer, vec!["alpha", "beta"]),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("PB-ADAPTER-0016"), "{error}");
        }

        let error = response_to_record(
            Path::new("."),
            &bundle,
            &unit,
            None,
            &[],
            &[],
            &response(vec!["alpha", "beta"], vec!["alpha"]),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("PB-ADAPTER-0022"), "{error}");
    }

    #[test]
    fn cache_reuse_rejects_duplicate_or_reordered_record_inventory_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = ContentAddressedStore::new(temporary.path().join("evidence"));
        let unit = inventory_protocol_unit();
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let bundle = cache_test_bundle(repository_root);
        let context = ExecutionContext {
            root: repository_root,
            state_root: temporary.path(),
            store: &store,
            bundle: &bundle,
        };
        let cache_key = format!("sha256:{}", "11".repeat(32));
        let closure = format!("sha256:{}", "00".repeat(32));
        let semantic_closure = ClosureRecord {
            schema: "proofbound-source-closure/1".into(),
            id: closure.clone(),
            kind: proofbound_evidence::ClosureKind::Semantic,
            root: ".".into(),
            claim_id: Some("CLAIM-ONE".into()),
            members: Vec::new(),
            total_bytes: 0,
            discovery: "test/1".into(),
            tool_identity: None,
        };
        let cache_path = temporary.path().join("cache-reference.json");

        let canonical_record: EvidenceRecord =
            serde_json::from_value(direct_example_record_value(vec!["alpha", "beta"])).unwrap();
        let canonical_digest = store.put(EVIDENCE_DOMAIN, &canonical_record).unwrap();
        write_canonical(
            &cache_path,
            &CacheReference {
                schema: "proofbound-cache-ref/1".into(),
                cache_key: cache_key.clone(),
                evidence_sha256: canonical_digest,
            },
        )
        .unwrap();
        assert!(
            reusable_cached_record(
                &context,
                &unit,
                &semantic_closure,
                std::slice::from_ref(&closure),
                &[],
                &cache_key,
                &cache_path,
            )
            .is_some()
        );

        for inventory in [vec!["alpha", "alpha", "beta"], vec!["beta", "alpha"]] {
            let bytes = canonical_json(&direct_example_record_value(inventory)).unwrap();
            let digest = store.put_bytes(EVIDENCE_DOMAIN, &bytes).unwrap();
            write_canonical(
                &cache_path,
                &CacheReference {
                    schema: "proofbound-cache-ref/1".into(),
                    cache_key: cache_key.clone(),
                    evidence_sha256: digest,
                },
            )
            .unwrap();
            assert!(
                reusable_cached_record(
                    &context,
                    &unit,
                    &semantic_closure,
                    std::slice::from_ref(&closure),
                    &[],
                    &cache_key,
                    &cache_path,
                )
                .is_none()
            );
        }
    }

    #[test]
    fn artifact_adapter_cannot_bypass_checked_observation_with_core_record() {
        let digest = format!("sha256:{}", "00".repeat(32));
        let forged = json!({
            "schema": "proofbound-evidence/3",
            "id": "artifact:forged",
            "node_id": "evidence:artifact:forged",
            "unit_id": "unit:forged",
            "kind": "artifact-soundness",
            "status": "passed",
            "claims": ["CLAIM-ONE"],
            "evaluation_mode": "native",
            "binding_mode": "digest-theorem",
            "artifact_binding": {
                "theorem": "theorem:exact",
                "artifact": {
                    "logical_name": "artifact.bin",
                    "sha256": digest,
                    "size_bytes": 1
                }
            },
            "inventoried_targets": ["published-artifact"],
            "assumptions": [],
            "premises": [],
            "provenance": {
                "project_revision": "revision",
                "tree_state": "dirty",
                "semantic_source_closure": digest,
                "additional_closures": [],
                "input_artifacts": [{
                    "logical_name": "artifact.bin",
                    "sha256": digest,
                    "size_bytes": 1
                }],
                "generated_artifacts": [],
                "tool": {"name":"checker","version":"1","identity_sha256":digest},
                "adapter": {"name":"adapter","version":"1","identity_sha256":digest},
                "execution_kind": "observed-processes",
                "commands": [{"program":"checker","args":[],"environment_allowlist":[]}],
                "runs": [{
                    "command_index": 0,
                    "exit_code": 0,
                    "stdout_sha256": digest,
                    "stderr_sha256": digest,
                    "normalized_output_sha256": digest,
                    "output_truncated": false,
                    "duration_ms": 1
                }],
                "normalization": "checker-output/1",
                "reproduction_command": {"program":"checker","args":[],"environment_allowlist":[]},
                "started_unix_ms": 1,
                "completed_unix_ms": 2,
                "deterministic_result_identity": digest,
                "unit_configuration_sha256": digest,
                "resource_budget": {"time_ms":1,"disk_bytes":1,"memory_bytes":1},
                "resource_usage": {"time_ms":1,"peak_disk_bytes":1,"peak_memory_bytes":1},
                "cache_origin": "executed"
            }
        });
        assert!(serde_json::from_value::<EvidenceRecord>(forged.clone()).is_ok());
        let unit: EvidenceUnitManifest = serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "forged",
            "adapter": "canonical-artifact",
            "kind": "artifact-soundness",
            "claims": ["CLAIM-ONE"],
            "tier": 3,
            "evaluation_mode": "native",
            "binding_mode": "digest-theorem",
            "theorem": "Example.Claims.published",
            "operation": {
                "type": "artifact-check",
                "checker": "checker.py",
                "arguments": ["artifact.bin"]
            },
            "expected_inventory": ["published-artifact"],
            "inputs": ["checker.py", "artifact.bin"],
            "outputs": [],
            "environment_allowlist": [],
            "resource_budget": {"time_seconds":1,"disk_bytes":1,"memory_bytes":1}
        }))
        .unwrap();
        let response = AdapterResponse {
            schema: "proofbound-adapter-protocol/1".to_owned(),
            message_type: "response".to_owned(),
            request_id: "0123456789abcdef0123456789abcdef".to_owned(),
            adapter: "canonical-artifact".to_owned(),
            success: true,
            evidence: Some(forged),
            inventory: vec!["published-artifact".to_owned()],
            diagnostics: vec![],
        };
        let bundle = cache_test_bundle(Path::new("."));
        let error = response_to_record(Path::new("."), &bundle, &unit, None, &[], &[], &response)
            .unwrap_err();
        assert!(error.to_string().contains("PB-ADAPTER-0012"));
    }

    #[test]
    fn failed_protocol_response_never_admits_attached_evidence() {
        let unit = theorem_unit("failed", "Example.Claims.failed");
        let response = AdapterResponse {
            schema: "proofbound-adapter-protocol/1".into(),
            message_type: "response".into(),
            request_id: "0123456789abcdef0123456789abcdef".into(),
            adapter: "lean".into(),
            success: false,
            evidence: Some(json!({"schema": "proofbound-evidence/3"})),
            inventory: Vec::new(),
            diagnostics: Vec::new(),
        };
        let bundle = cache_test_bundle(Path::new("."));
        let error = response_to_record(Path::new("."), &bundle, &unit, None, &[], &[], &response)
            .unwrap_err();
        assert!(error.to_string().contains("adapter rejected unit failed"));
    }

    #[test]
    fn mutation_target_requires_exact_reviewed_closure_preimage() {
        let artifact = ArtifactIdentity {
            logical_name: ArtifactLogicalName::new("src/decision.rs").unwrap(),
            sha256: Sha256Digest::of_bytes(b"registered target bytes"),
            size_bytes: 23,
        };
        let member = ClosureMember {
            path: artifact.logical_name.to_string(),
            sha256: format!("sha256:{}", artifact.sha256.to_hex()),
            bytes: artifact.size_bytes,
        };
        let closure = |members| ClosureRecord {
            schema: "proofbound-source-closure/1".into(),
            id: format!("sha256:{}", "00".repeat(32)),
            kind: proofbound_evidence::ClosureKind::Semantic,
            root: ".".into(),
            claim_id: Some("CLAIM-ONE".into()),
            members,
            total_bytes: artifact.size_bytes,
            discovery: "unit-claim-union/1".into(),
            tool_identity: None,
        };

        assert!(closure_binds_artifact(
            &closure(vec![member.clone()]),
            &artifact
        ));

        let mut wrong_digest = member.clone();
        wrong_digest.sha256 = format!(
            "sha256:{}",
            Sha256Digest::of_bytes(b"different bytes").to_hex()
        );
        assert!(!closure_binds_artifact(
            &closure(vec![wrong_digest]),
            &artifact
        ));

        let mut wrong_size = member.clone();
        wrong_size.bytes += 1;
        assert!(!closure_binds_artifact(
            &closure(vec![wrong_size]),
            &artifact
        ));

        assert!(!closure_binds_artifact(
            &closure(vec![member.clone(), member]),
            &artifact
        ));
    }

    #[test]
    fn load_compiled_rejects_reporting_after_reviewed_byte_drift() {
        let temporary = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(temporary.path())
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(temporary.path().join("reviewed.txt"), b"reviewed-v1").unwrap();
        let expected = sha256_bytes(&worktree_snapshot(temporary.path()).unwrap());
        let compiled = CompiledProject {
            schema: COMPILED_SCHEMA.to_owned(),
            project: "freshness-fixture".to_owned(),
            project_revision: "fixture-revision".to_owned(),
            tree_state: "dirty".to_owned(),
            reviewed_tree_sha256: expected,
            generated_at: "1970-01-01T00:00:00.000Z".to_owned(),
            inputs: Vec::new(),
            statuses: Vec::new(),
            evidence: Vec::new(),
            closures: Vec::new(),
            unit_runs: Vec::new(),
            claim_input_identities: BTreeMap::new(),
        };
        let mut stale_v1 = compiled.clone();
        stale_v1.schema = "proofbound-compiled-project/1".into();
        write_canonical(
            &temporary.path().join(".proofbound/compiled/project.json"),
            &stale_v1,
        )
        .unwrap();
        let error = load_compiled(temporary.path()).unwrap_err().to_string();
        assert!(error.contains("PB-RECEIPT-0002"));

        write_canonical(
            &temporary.path().join(".proofbound/compiled/project.json"),
            &compiled,
        )
        .unwrap();
        assert_eq!(
            load_compiled(temporary.path()).unwrap().project,
            "freshness-fixture"
        );

        fs::write(temporary.path().join("reviewed.txt"), b"reviewed-v2").unwrap();
        let error = load_compiled(temporary.path()).unwrap_err().to_string();
        assert!(error.contains("PB-RECEIPT-0007"));
        assert!(error.contains("stale"));
    }
}
