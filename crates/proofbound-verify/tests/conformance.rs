use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

use proofbound_verify::*;
use tempfile::TempDir;

fn digest(label: &str) -> String {
    raw_sha256(label.as_bytes())
}

fn named_artifact(
    logical_name: &str,
    digest_label: &str,
    size_bytes: u64,
) -> ArtifactIdentityReceipt {
    ArtifactIdentityReceipt {
        logical_name: logical_name.into(),
        sha256: digest(digest_label),
        size_bytes,
    }
}

#[derive(serde::Serialize)]
struct TranscriptionRoleMaterial<'a> {
    abi: &'static str,
    driver: &'a ArtifactIdentityReceipt,
    role: TranscriptionRole,
}

fn transcription_role_identity(
    role: TranscriptionRole,
    driver: &ArtifactIdentityReceipt,
) -> String {
    domain_hash(
        TRANSCRIPTION_TCB_ROLE_DOMAIN_V1,
        &canonical_json(&TranscriptionRoleMaterial {
            abi: TRANSCRIPTION_DRIVER_ABI_V1,
            driver,
            role,
        })
        .unwrap(),
    )
}

fn trusted_transcription(
    prefix: &str,
    closure: &str,
) -> (TrustedTranscriptionReceipt, EvidenceProvenance) {
    let source = named_artifact(&format!("{prefix}/source.bin"), "source-bytes", 12);
    let committed_transcription = named_artifact(
        &format!("{prefix}/committed.transcription"),
        "transcribed-bytes",
        18,
    );
    let transcribed_candidate = named_artifact(
        &format!("{prefix}/candidate.transcription"),
        "transcribed-bytes",
        18,
    );
    let reencoded_source = named_artifact(
        &format!("{prefix}/reencoded-source.bin"),
        "source-bytes",
        12,
    );
    let driver = named_artifact(
        &format!("{prefix}/driver"),
        &format!("driver-bytes:{prefix}"),
        24,
    );
    let mut provenance = provenance(closure);
    provenance.input_artifacts = vec![
        source.clone(),
        committed_transcription.clone(),
        driver.clone(),
    ];
    provenance.input_artifacts.sort();
    provenance.generated_artifacts = vec![transcribed_candidate.clone(), reencoded_source.clone()];
    provenance.generated_artifacts.sort();
    provenance.cache_key = domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&provenance.cache_material()).unwrap(),
    );
    (
        TrustedTranscriptionReceipt {
            schema: TRUSTED_TRANSCRIPTION_SCHEMA_V1.into(),
            source,
            committed_transcription,
            transcribed_candidate,
            reencoded_source,
            transcriber: TranscriptionTcbRoleReceipt {
                tcb_node: format!("tcb:trusted-transcription:{prefix}:transcriber"),
                role_identity: transcription_role_identity(TranscriptionRole::Transcriber, &driver),
            },
            reencoder: TranscriptionTcbRoleReceipt {
                tcb_node: format!("tcb:trusted-transcription:{prefix}:reencoder"),
                role_identity: transcription_role_identity(TranscriptionRole::Reencoder, &driver),
            },
            driver,
        },
        provenance,
    )
}

fn trusted_transcription_inventory(detail: &TrustedTranscriptionReceipt) -> BTreeSet<String> {
    BTreeSet::from([
        detail.source.logical_name.clone(),
        detail.committed_transcription.logical_name.clone(),
    ])
}

fn string_literal(value: &str) -> serde_json::Value {
    serde_json::json!([7, [1, value]])
}

fn application(function: serde_json::Value, argument: serde_json::Value) -> serde_json::Value {
    serde_json::json!([3, function, argument])
}

fn plain_statement(declaration: &str) -> serde_json::Value {
    serde_json::json!(["lean-expr-cbor/1", [2, declaration, []]])
}

fn binding_statement(claim: &str, logical_name: &str, sha256: &str) -> serde_json::Value {
    let mut root = serde_json::json!([2, "Proofbound.Artifact.DigestBindingV1", []]);
    for argument in [
        string_literal(claim),
        string_literal("synthetic-artifact/1"),
        string_literal(logical_name),
        string_literal(sha256),
        serde_json::json!([2, "Synthetic.bytes", []]),
        serde_json::json!([2, "Synthetic.meaning", []]),
    ] {
        root = application(root, argument);
    }
    serde_json::json!(["lean-expr-cbor/1", root])
}

fn graph_hash(graph: &AssuranceGraph) -> String {
    domain_hash(GRAPH_SCHEMA_V1, &canonical_json(graph).unwrap())
}

fn closure_record() -> HashedRecord<SourceClosureReceipt> {
    let record = SourceClosureReceipt {
        schema: CLOSURE_SCHEMA_V1.into(),
        kind: ClosureKind::Semantic,
        members: vec![ClosureMember {
            path: "src/model.rs".into(),
            sha256: digest("model source"),
            size_bytes: 12,
        }],
    };
    HashedRecord {
        sha256: domain_hash(CLOSURE_SCHEMA_V1, &canonical_json(&record).unwrap()),
        record,
    }
}

fn provenance(closure: &str) -> EvidenceProvenance {
    let tool = ToolIdentity {
        name: "synthetic-runner".into(),
        version: "1.0.0".into(),
        identity_sha256: digest("runner"),
    };
    let adapter = ToolIdentity {
        name: "synthetic-adapter".into(),
        version: "1.0.0".into(),
        identity_sha256: digest("adapter"),
    };
    let mut value = EvidenceProvenance {
        project_revision: "rev-1".into(),
        tree_state: TreeState::Clean,
        semantic_closure: closure.into(),
        additional_closures: vec![],
        input_artifacts: Default::default(),
        generated_artifacts: Default::default(),
        tool,
        adapter,
        execution_kind: ExecutionKind::ObservedProcesses,
        commands: vec![CommandReceipt {
            program: "synthetic-runner".into(),
            args: vec!["check".into()],
            environment_allowlist: Vec::new(),
        }],
        runs: vec![ExecutionRunReceipt {
            command_index: 0,
            exit_code: Some(0),
            stdout_sha256: digest("stdout"),
            stderr_sha256: digest("stderr"),
            normalized_output_sha256: digest("normalized output"),
            output_truncated: false,
            duration_ms: 1,
        }],
        normalization: "synthetic-output/1".into(),
        reproduction_command: CommandReceipt {
            program: "synthetic-runner".into(),
            args: vec!["check".into()],
            environment_allowlist: Vec::new(),
        },
        started_unix_ms: 100,
        completed_unix_ms: 101,
        deterministic_result_sha256: digest("result"),
        unit_configuration_sha256: digest("config"),
        cache_key: String::new(),
        reused_from: None,
        resource_budget: ResourceMeasure {
            time_ms: 1_000,
            disk_bytes: 1_000,
            memory_bytes: 1_000,
        },
        actual_cost: ActualCostReceipt {
            time_ms: 1,
            disk_bytes: 1,
            memory_bytes: Some(1),
        },
    };
    value.cache_key = domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&value.cache_material()).unwrap(),
    );
    value
}

fn hash_evidence(record: EvidenceReceipt) -> HashedRecord<EvidenceReceipt> {
    HashedRecord {
        sha256: domain_hash(EVIDENCE_SCHEMA_V2, &canonical_json(&record).unwrap()),
        record,
    }
}

fn base_release() -> CompiledRelease {
    let closure = closure_record();
    let graph = AssuranceGraph {
        schema: GRAPH_SCHEMA_V1.into(),
        nodes: vec![
            GraphNode {
                id: "claim:c".into(),
                kind: NodeKind::Claim,
                proof_environment: None,
            },
            GraphNode {
                id: "subject:s".into(),
                kind: NodeKind::Subject,
                proof_environment: None,
            },
            GraphNode {
                id: "policy:p".into(),
                kind: NodeKind::Policy,
                proof_environment: None,
            },
            GraphNode {
                id: "test:t".into(),
                kind: NodeKind::TestSuite,
                proof_environment: None,
            },
        ],
        edges: Vec::new(),
        mutual_theorem_groups: Vec::new(),
    };
    let test = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:test".into(),
        node_id: "test:t".into(),
        kind: EvidenceKind::ExampleTest,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: None,
        binding_mode: None,
        theorem: None,
        artifact_binding: None,
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: BTreeSet::from(["demo::works".into()]),
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance: provenance(&closure.sha256),
    });
    let claim = ClaimReceipt {
        schema: CLAIM_SCHEMA_V1.into(),
        id: "c".into(),
        node_id: "claim:c".into(),
        title: "Synthetic claim".into(),
        statement: "The registered example passes.".into(),
        public_language: None,
        subject: "subject:s".into(),
        policy: "ledger-ci".into(),
        tier: None,
        cited_evidence: BTreeSet::from([test.sha256.clone()]),
        assumptions: Default::default(),
        open_obligations: Default::default(),
        out_of_scope: Default::default(),
        primary_linkage: None,
        registered_inputs: Default::default(),
        registered_domain_language: None,
    };
    let status = ReportedClaimStatus {
        claim_id: "c".into(),
        public_statement: claim.statement.clone(),
        formal: FormalFacet::Tested,
        linkage: Some(LinkageFacet::ModelOnly),
        assumption: AssumptionFacet::None,
        assumptions: Default::default(),
        undischarged_premises: Default::default(),
        policy_admitted: true,
    };
    CompiledRelease {
        schema: COMPILED_RELEASE_SCHEMA_V2.into(),
        project: "synthetic".into(),
        project_revision: "rev-1".into(),
        project_tier: Tier::Ledger,
        tree_state: TreeState::Clean,
        graph_sha256: graph_hash(&graph),
        graph,
        claims: vec![claim],
        evidence: vec![test],
        assumptions: Vec::new(),
        premises: Vec::new(),
        policies: vec![PolicyReceipt {
            schema: POLICY_SCHEMA_V1.into(),
            id: "ledger-ci".into(),
            node_id: "policy:p".into(),
            components: BTreeSet::from([BuiltInProfile::Ledger]),
            allowed_foundational_axioms: Default::default(),
            allowed_project_axioms: Default::default(),
            admit_exhaustive_as_proved: false,
            require_no_assumptions: false,
            native_premise_rule: None,
            additional_required_evidence: Default::default(),
        }],
        closures: vec![closure],
        sealed_files: Vec::new(),
        reported_statuses: vec![status],
    }
}

fn theorem_release() -> CompiledRelease {
    let mut release = base_release();
    release.project_tier = Tier::Model;
    release.graph.nodes[3] = GraphNode {
        id: "theorem:t".into(),
        kind: NodeKind::Theorem,
        proof_environment: Some("lean:synthetic".into()),
    };
    let statement_wire = plain_statement("Synthetic.statement");
    let theorem = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:theorem".into(),
        node_id: "theorem:t".into(),
        kind: EvidenceKind::Theorem,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: Some(EvaluationMode::Kernel),
        binding_mode: None,
        theorem: Some(TheoremReceipt {
            declaration: "Synthetic.theorem".into(),
            statement_encoding: "lean-expr-cbor/1".into(),
            statement_sha256: lean_statement_wire_digest(&statement_wire).unwrap(),
            statement_wire,
            attributed_claim: "c".into(),
            proof_environment: "lean:synthetic".into(),
            axiom_audit_passed: true,
            contains_sorry_ax: false,
            foundational_axioms: Default::default(),
            project_axioms: Default::default(),
        }),
        artifact_binding: None,
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: BTreeSet::from(["Synthetic.theorem".into()]),
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance: provenance(&release.closures[0].sha256),
    });
    release.claims[0].cited_evidence = BTreeSet::from([theorem.sha256.clone()]);
    release.evidence = vec![theorem];
    release.policies[0].id = "kernel".into();
    release.policies[0].components = BTreeSet::from([BuiltInProfile::Kernel]);
    release.claims[0].policy = "kernel".into();
    release.reported_statuses[0].formal = FormalFacet::Proved;
    release.graph_sha256 = graph_hash(&release.graph);
    release
}

fn bounded_release() -> CompiledRelease {
    let mut release = base_release();
    release.project_tier = Tier::Bounded;
    release.graph.nodes[3] = GraphNode {
        id: "model-check:m".into(),
        kind: NodeKind::ModelCheckUnit,
        proof_environment: None,
    };
    let old = release.evidence[0].sha256.clone();
    let record = &mut release.evidence[0].record;
    record.node_id = "model-check:m".into();
    record.unit_id = "unit:bounded".into();
    record.kind = EvidenceKind::BoundedCheck;
    record.inventoried_targets = BTreeSet::from(["check_all".into()]);
    record.bounded_check = Some(BoundedCheckReceipt {
        domain: BoundedDomain {
            id: "domain:tiny".into(),
            description: "All two-bit inputs".into(),
            registration_sha256: digest("tiny domain"),
            cardinality: Some(4),
        },
        solver: "kani 1.0".into(),
        harnesses: BTreeSet::from(["check_all".into()]),
        unwind_bounds: BTreeMap::from([("check_all".into(), 1)]),
        assumptions: Vec::new(),
    });
    release.evidence[0].sha256 = domain_hash(
        EVIDENCE_SCHEMA_V2,
        &canonical_json(&release.evidence[0].record).unwrap(),
    );
    release.claims[0].cited_evidence.remove(&old);
    release.claims[0]
        .cited_evidence
        .insert(release.evidence[0].sha256.clone());
    release.claims[0].registered_domain_language =
        Some("For every input in the registered two-bit domain".into());
    release.reported_statuses[0].public_statement = bounded_public_statement_for_test(
        &release.claims[0].statement,
        release.claims[0]
            .registered_domain_language
            .as_deref()
            .unwrap(),
    );
    release.claims[0].policy = "bounded".into();
    release.policies[0].id = "bounded".into();
    release.policies[0].components = BTreeSet::from([BuiltInProfile::Bounded]);
    release.reported_statuses[0].formal = FormalFacet::BoundedChecked;
    release.graph_sha256 = graph_hash(&release.graph);
    release
}

fn rehash_first_evidence(release: &mut CompiledRelease) {
    let old = release.evidence[0].sha256.clone();
    let replacement = domain_hash(
        EVIDENCE_SCHEMA_V2,
        &canonical_json(&release.evidence[0].record).unwrap(),
    );
    release.evidence[0].sha256.clone_from(&replacement);
    for claim in &mut release.claims {
        if claim.cited_evidence.remove(&old) {
            claim.cited_evidence.insert(replacement.clone());
        }
    }
}

fn recache_and_rehash_first_evidence(release: &mut CompiledRelease) {
    let provenance = &mut release.evidence[0].record.provenance;
    provenance.cache_key = domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&provenance.cache_material()).unwrap(),
    );
    rehash_first_evidence(release);
}

fn tcb_ledger_value(release: &CompiledRelease) -> serde_json::Value {
    let mut components = BTreeSet::new();
    for evidence in &release.evidence {
        for identity in [
            &evidence.record.provenance.tool,
            &evidence.record.provenance.adapter,
        ] {
            components.insert((
                identity.name.clone(),
                identity.version.clone(),
                identity.identity_sha256.clone(),
            ));
        }
        if let Some(transcription) = &evidence.record.trusted_transcription {
            let unit = evidence
                .record
                .unit_id
                .strip_prefix("unit:")
                .unwrap_or(&evidence.record.unit_id);
            components.extend([
                (
                    format!("trusted-transcription/{unit}/transcriber"),
                    TRANSCRIPTION_DRIVER_ABI_V1.into(),
                    transcription.transcriber.role_identity.clone(),
                ),
                (
                    format!("trusted-transcription/{unit}/reencoder"),
                    TRANSCRIPTION_DRIVER_ABI_V1.into(),
                    transcription.reencoder.role_identity.clone(),
                ),
            ]);
        }
    }
    serde_json::json!({
        "schema": "proofbound-tcb-ledger/1",
        "components": components.into_iter().map(|(name, version, identity_sha256)| {
            serde_json::json!({
                "name": name,
                "version": version,
                "identity_sha256": identity_sha256,
            })
        }).collect::<Vec<_>>(),
    })
}

fn write_tcb_ledger_at(
    directory: &Path,
    release: &CompiledRelease,
    ledger: &serde_json::Value,
) -> CompiledRelease {
    let bytes = canonical_json(ledger).unwrap();
    fs::write(directory.join("tcb-ledger.json"), &bytes).unwrap();
    let mut sealed = release.clone();
    sealed
        .sealed_files
        .retain(|entry| entry.path != "tcb-ledger.json");
    sealed.sealed_files.push(SealedFile {
        path: "tcb-ledger.json".into(),
        sha256: raw_sha256(&bytes),
        size_bytes: bytes.len() as u64,
    });
    sealed
        .sealed_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    sealed
}

fn write_release_with_tcb(release: &CompiledRelease, ledger: &serde_json::Value) -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    let release = write_tcb_ledger_at(directory.path(), release, ledger);
    write_payload_at(directory.path(), &release);
    directory
}

fn write_release(release: &CompiledRelease) -> TempDir {
    write_release_with_tcb(release, &tcb_ledger_value(release))
}

fn codes(error: &VerificationErrors) -> BTreeSet<VerificationIssueCode> {
    error.issues.iter().map(|issue| issue.code).collect()
}

#[test]
fn valid_closed_receipt_is_consistent_in_memory_and_on_disk() {
    let release = base_release();
    let report = verify_compiled_release(&release).unwrap();
    assert_eq!(report.verdict, "receipt-consistent");
    assert!(!report.publication_blocked);
    assert_eq!(report.not_proved_out_of_scope.len(), 1);
    assert_eq!(report.not_proved_out_of_scope[0].claim_id, "c");

    let directory = write_release(&release);
    let report = verify_release_dir(directory.path()).unwrap();
    assert!(report.payload_sha256.starts_with("sha256:"));
}

#[test]
fn illegal_edge_endpoint_kinds_are_rejected_independently() {
    let mut release = base_release();
    release.graph.nodes.push(GraphNode {
        id: "toolchain:rust".into(),
        kind: NodeKind::Toolchain,
        proof_environment: None,
    });
    release.graph.edges.push(GraphEdge {
        from: "test:t".into(),
        to: "toolchain:rust".into(),
        kind: EdgeKind::Proves,
    });
    release.graph_sha256 = graph_hash(&release.graph);

    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidGraph));
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("illegal endpoint kinds"))
    );
}

#[test]
fn verification_report_requires_a_strict_gap_section() {
    let report = verify_compiled_release(&base_release()).unwrap();
    let mut missing = serde_json::to_value(&report).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("not_proved_out_of_scope");
    assert!(serde_json::from_value::<VerificationReport>(missing).is_err());

    let mut unknown = serde_json::to_value(report).unwrap();
    unknown["not_proved_out_of_scope"][0]["optimistic_summary"] = true.into();
    assert!(serde_json::from_value::<VerificationReport>(unknown).is_err());
}

#[test]
fn committed_release_fixture_is_canonical_and_verifies_in_place() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proofbound/conformance/v1/release-valid");
    let report = verify_release_dir(&path).unwrap();
    assert_eq!(report.verdict, "receipt-consistent");
    assert!(!report.publication_blocked);
    assert_eq!(report.claims[0].formal, FormalFacet::Tested);
}

#[test]
fn empty_additional_closures_have_one_canonical_optional_shape() {
    let release = base_release();
    assert!(
        release.evidence[0]
            .record
            .provenance
            .additional_closures
            .is_empty()
    );
    let value = serde_json::to_value(&release).unwrap();
    assert!(
        value["evidence"][0]["record"]["provenance"]
            .get("additional_closures")
            .is_none()
    );

    let directory = write_release(&release);
    assert_eq!(
        verify_release_dir(directory.path()).unwrap().verdict,
        "receipt-consistent"
    );
}

#[test]
fn standalone_cli_honors_release_and_exit_contract() {
    let directory = write_release(&base_release());
    let output = Command::new(env!("CARGO_BIN_EXE_proofbound-verify"))
        .args(["--release", directory.path().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: VerificationReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.verdict, "receipt-consistent");

    let output = Command::new(env!("CARGO_BIN_EXE_proofbound-verify"))
        .args(["--release", directory.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("claim c: TESTED · MODEL_ONLY · NONE"));
    assert!(stdout.contains("  The registered example passes."));
    assert!(stdout.contains("not proved / out of scope [c]"));
    assert!(stdout.contains("open obligations:"));

    let mut blocked = base_release();
    blocked.project_tier = Tier::Model;
    blocked.policies[0].id = "corpus-kernel".into();
    blocked.policies[0].components = BTreeSet::from([BuiltInProfile::Kernel]);
    blocked.claims[0].policy = "corpus-kernel".into();
    blocked.reported_statuses[0].policy_admitted = false;
    let directory = write_release(&blocked);
    let output = Command::new(env!("CARGO_BIN_EXE_proofbound-verify"))
        .args(["--release", directory.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn consistent_receipt_can_be_honestly_blocked_by_policy() {
    let mut release = base_release();
    release.project_tier = Tier::Model;
    release.policies[0].id = "corpus-kernel".into();
    release.policies[0].components = BTreeSet::from([BuiltInProfile::Kernel]);
    release.claims[0].policy = "corpus-kernel".into();
    release.reported_statuses[0].policy_admitted = false;
    let report = verify_compiled_release(&release).unwrap();
    assert!(report.publication_blocked);
    assert_eq!(report.claims[0].formal, FormalFacet::Tested);
}

#[test]
fn ledger_builtin_is_immutable_and_has_no_formal_requirements() {
    let mut exact = base_release();
    exact.policies[0].id = "ledger".into();
    exact.claims[0].policy = "ledger".into();
    verify_compiled_release(&exact).unwrap();

    let mut composed = exact.clone();
    composed.policies[0]
        .components
        .insert(BuiltInProfile::Kernel);
    let error = verify_compiled_release(&composed).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidPolicy));

    let mut required = exact.clone();
    required.policies[0]
        .additional_required_evidence
        .insert(EvidenceKind::BoundedCheck);
    let error = verify_compiled_release(&required).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidPolicy));

    let mut axiomatic = exact;
    axiomatic.policies[0]
        .allowed_foundational_axioms
        .insert("Classical.choice".into());
    let error = verify_compiled_release(&axiomatic).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidPolicy));
}

#[test]
fn bounded_and_exhaustive_precedence_is_recomputed() {
    let bounded = bounded_release();
    let report = verify_compiled_release(&bounded).unwrap();
    assert_eq!(report.claims[0].formal, FormalFacet::BoundedChecked);

    let mut exhaustive = bounded;
    let old = exhaustive.evidence[0].sha256.clone();
    let record = &mut exhaustive.evidence[0].record;
    record.kind = EvidenceKind::ExhaustiveCheck;
    let domain = record.bounded_check.take().unwrap().domain;
    record.exhaustive_check = Some(ExhaustiveCheckReceipt {
        evaluated_members: domain.cardinality.unwrap(),
        domain,
    });
    exhaustive.evidence[0].sha256 = domain_hash(
        EVIDENCE_SCHEMA_V2,
        &canonical_json(&exhaustive.evidence[0].record).unwrap(),
    );
    exhaustive.claims[0].cited_evidence.remove(&old);
    exhaustive.claims[0]
        .cited_evidence
        .insert(exhaustive.evidence[0].sha256.clone());
    exhaustive.claims[0].policy = "finite-ci".into();
    exhaustive.policies[0].id = "finite-ci".into();
    exhaustive.policies[0].components.clear();
    exhaustive.reported_statuses[0].formal = FormalFacet::Tested;
    exhaustive.reported_statuses[0].public_statement = exhaustive.claims[0].statement.clone();
    verify_compiled_release(&exhaustive).unwrap();

    exhaustive.policies[0].admit_exhaustive_as_proved = true;
    exhaustive.reported_statuses[0].formal = FormalFacet::Proved;
    exhaustive.reported_statuses[0].public_statement = bounded_public_statement_for_test(
        &exhaustive.claims[0].statement,
        exhaustive.claims[0]
            .registered_domain_language
            .as_deref()
            .unwrap(),
    );
    verify_compiled_release(&exhaustive).unwrap();
}

#[test]
fn bounded_language_cannot_be_silently_omitted() {
    let mut release = bounded_release();
    release.claims[0].registered_domain_language = None;
    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));
}

#[test]
fn bounded_unwind_inventory_is_exact_and_nonzero() {
    let mut extra = bounded_release();
    extra.evidence[0]
        .record
        .bounded_check
        .as_mut()
        .unwrap()
        .unwind_bounds
        .insert("undeclared".into(), 1);
    rehash_first_evidence(&mut extra);
    let error = verify_compiled_release(&extra).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));

    let mut missing = bounded_release();
    missing.evidence[0]
        .record
        .bounded_check
        .as_mut()
        .unwrap()
        .unwind_bounds
        .clear();
    rehash_first_evidence(&mut missing);
    let error = verify_compiled_release(&missing).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));

    let mut zero = bounded_release();
    zero.evidence[0]
        .record
        .bounded_check
        .as_mut()
        .unwrap()
        .unwind_bounds
        .insert("check_all".into(), 0);
    rehash_first_evidence(&mut zero);
    let error = verify_compiled_release(&zero).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
}

#[test]
fn canonical_payload_tampering_is_detected() {
    let release = base_release();
    let directory = write_release(&release);
    let path = directory.path().join("compiled-receipt.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["project"] = "tampered".into();
    fs::write(&path, canonical_json(&value).unwrap()).unwrap();
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvDigest));
}

#[test]
fn missing_and_duplicate_ids_fail_closed() {
    let mut missing = base_release();
    missing.claims[0].cited_evidence = BTreeSet::from([digest("not present")]);
    let error = verify_compiled_release(&missing).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvMissingReference));

    let mut duplicate = base_release();
    duplicate.claims.push(duplicate.claims[0].clone());
    let error = verify_compiled_release(&duplicate).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvDuplicateId));
}

#[test]
fn strict_parser_rejects_unknown_enums() {
    let release = base_release();
    let directory = tempfile::tempdir().unwrap();
    let mut value = serde_json::to_value(&release).unwrap();
    value["evidence"][0]["record"]["kind"] = "invented-proof".into();
    let payload = canonical_json(&value).unwrap();
    fs::write(directory.path().join("compiled-receipt.json"), &payload).unwrap();
    let envelope = ReleaseEnvelope {
        schema: RELEASE_ENVELOPE_SCHEMA_V2.into(),
        payload: "compiled-receipt.json".into(),
        payload_sha256: domain_hash(COMPILED_RELEASE_SCHEMA_V2, &payload),
    };
    fs::write(
        directory.path().join("release.json"),
        canonical_json(&envelope).unwrap(),
    )
    .unwrap();
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvJson));
}

#[test]
fn invalid_digest_and_drifted_evidence_are_rejected() {
    let mut malformed = base_release();
    malformed.evidence[0].sha256 = "SHA256:not-lowercase".into();
    let error = verify_compiled_release(&malformed).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));

    let mut drifted = base_release();
    let old = drifted.evidence[0].sha256.clone();
    drifted.evidence[0].record.outcome = EvidenceOutcome::Drifted;
    drifted.evidence[0].sha256 = domain_hash(
        EVIDENCE_SCHEMA_V2,
        &canonical_json(&drifted.evidence[0].record).unwrap(),
    );
    drifted.claims[0].cited_evidence.remove(&old);
    drifted.claims[0]
        .cited_evidence
        .insert(drifted.evidence[0].sha256.clone());
    let error = verify_compiled_release(&drifted).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));
}

#[test]
fn unresolved_assumption_cannot_be_omitted_from_output() {
    let mut release = theorem_release();
    release.graph.nodes.extend([
        GraphNode {
            id: "assumption:a".into(),
            kind: NodeKind::Assumption,
            proof_environment: None,
        },
        GraphNode {
            id: "review:a".into(),
            kind: NodeKind::Review,
            proof_environment: None,
        },
    ]);
    let review = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:review".into(),
        node_id: "review:a".into(),
        kind: EvidenceKind::Review,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: None,
        binding_mode: None,
        theorem: None,
        artifact_binding: None,
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: BTreeSet::from(["review:runtime-host".into()]),
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance: provenance(&release.closures[0].sha256),
    });
    release.assumptions.push(AssumptionReceipt {
        schema: ASSUMPTION_SCHEMA_V1.into(),
        id: "a".into(),
        node_id: "assumption:a".into(),
        statement: "The host is honest.".into(),
        category: AssumptionCategory::RuntimeEnvironment,
        owner: "release engineering".into(),
        rationale: "The runtime is outside the proof kernel.".into(),
        scope: "release host".into(),
        affected_claims: BTreeSet::from(["c".into()]),
        review_evidence: BTreeSet::from([review.sha256.clone()]),
        falsification_or_discharge_plan: "Audit the release host.".into(),
        source_citation: None,
        state: AssumptionState::Active,
        depends_on: Default::default(),
    });
    release.evidence.push(review);
    release.graph_sha256 = graph_hash(&release.graph);
    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));
}

#[test]
fn unresolved_premise_cannot_be_silently_discharged() {
    let mut release = theorem_release();
    release.graph.nodes.push(GraphNode {
        id: "premise:p".into(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    release.premises.push(PremiseReceipt {
        id: "p".into(),
        node_id: "premise:p".into(),
        statement: "Every input is well formed.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: Some(release.evidence[0].sha256.clone()),
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });
    release.graph_sha256 = graph_hash(&release.graph);
    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));
}

#[test]
fn direct_ownerless_premise_is_admitted_only_as_undischarged() {
    let mut release = base_release();
    release.graph.nodes.push(GraphNode {
        id: "premise:p".into(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    release.graph.edges.push(GraphEdge {
        from: "claim:c".into(),
        to: "premise:p".into(),
        kind: EdgeKind::Assumes,
    });
    release.premises.push(PremiseReceipt {
        id: "p".into(),
        node_id: "premise:p".into(),
        statement: "The external input is well formed.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: None,
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });
    release.reported_statuses[0].assumption = AssumptionFacet::Assumed;
    release.reported_statuses[0]
        .undischarged_premises
        .insert("p".into());
    release.graph_sha256 = graph_hash(&release.graph);

    let report = verify_compiled_release(&release).unwrap();
    assert_eq!(
        report.claims[0].undischarged_premises,
        BTreeSet::from(["p".into()])
    );
    assert_eq!(report.claims[0].assumption, AssumptionFacet::Assumed);
}

#[test]
fn omitting_premise_owner_and_claim_edge_cannot_promote_claim() {
    let mut release = base_release();
    release.graph.nodes.push(GraphNode {
        id: "premise:p".into(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    // Even an `assumes` edge from a non-claim node is not a direct binding.
    release.graph.edges.push(GraphEdge {
        from: "subject:s".into(),
        to: "premise:p".into(),
        kind: EdgeKind::Assumes,
    });
    release.premises.push(PremiseReceipt {
        id: "p".into(),
        node_id: "premise:p".into(),
        statement: "The external input is well formed.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: None,
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });
    // Keep the producer's stronger, premise-free status. The independent
    // verifier must reject instead of accepting the omission.
    release.graph_sha256 = graph_hash(&release.graph);

    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidPremise));
}

#[test]
fn ownerless_direct_premise_rejects_even_a_valid_theorem_discharge() {
    let mut release = theorem_release();
    let theorem = release.evidence[0].sha256.clone();
    release.graph.nodes.push(GraphNode {
        id: "premise:p".into(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    release.graph.edges.extend([
        GraphEdge {
            from: "claim:c".into(),
            to: "premise:p".into(),
            kind: EdgeKind::Assumes,
        },
        GraphEdge {
            from: "premise:p".into(),
            to: "theorem:t".into(),
            kind: EdgeKind::DischargedBy,
        },
    ]);
    release.premises.push(PremiseReceipt {
        id: "p".into(),
        node_id: "premise:p".into(),
        statement: "The external input is well formed.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: None,
        scope: FlowScope::AllRegisteredInputs,
        discharge: Some(PremiseDischarge {
            theorem_evidence: theorem,
            scope: FlowScope::AllRegisteredInputs,
        }),
    });
    release.reported_statuses[0].assumption = AssumptionFacet::Assumed;
    release.reported_statuses[0].formal = FormalFacet::Invalid;
    release.reported_statuses[0].linkage = None;
    release.reported_statuses[0]
        .undischarged_premises
        .insert("p".into());
    release.reported_statuses[0].policy_admitted = false;
    release.graph_sha256 = graph_hash(&release.graph);

    let error = verify_compiled_release(&release).unwrap_err();
    let issue_codes = codes(&error);
    assert!(issue_codes.contains(&VerificationIssueCode::PbvInvalidPremise));
    assert!(!issue_codes.contains(&VerificationIssueCode::PbvStatusMismatch));
}

fn add_binding_paths(release: &mut CompiledRelease) {
    release.project_tier = Tier::Bound;
    release.graph.nodes.extend([
        GraphNode {
            id: "artifact:a".into(),
            kind: NodeKind::Artifact,
            proof_environment: None,
        },
        GraphNode {
            id: "tcb:trusted-transcription:transcription:transcriber".into(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        },
        GraphNode {
            id: "tcb:trusted-transcription:transcription:reencoder".into(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        },
    ]);
    let artifact_identity = ArtifactIdentityReceipt {
        logical_name: "artifact.bin".into(),
        sha256: digest("artifact bytes"),
        size_bytes: 14,
    };
    let statement_wire = binding_statement(
        "c",
        &artifact_identity.logical_name,
        &artifact_identity.sha256,
    );
    let theorem_detail = release.evidence[0]
        .record
        .theorem
        .as_mut()
        .expect("theorem release contains theorem detail");
    theorem_detail.statement_sha256 = lean_statement_wire_digest(&statement_wire).unwrap();
    theorem_detail.statement_wire = statement_wire;
    rehash_first_evidence(release);
    let theorem = release.evidence[0].sha256.clone();
    let mut artifact_provenance = provenance(&release.closures[0].sha256);
    artifact_provenance
        .input_artifacts
        .push(artifact_identity.clone());
    artifact_provenance.cache_key = domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&artifact_provenance.cache_material()).unwrap(),
    );
    let artifact = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:artifact".into(),
        node_id: "artifact:a".into(),
        kind: EvidenceKind::ArtifactSoundness,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: Some(EvaluationMode::Kernel),
        binding_mode: Some(BindingMode::DigestTheorem),
        theorem: None,
        artifact_binding: Some(ArtifactBindingReceipt {
            theorem_evidence: theorem,
            artifact: artifact_identity,
        }),
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: BTreeSet::from(["artifact.bin".into()]),
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance: artifact_provenance,
    });
    let (trusted_transcription, transcription_provenance) =
        trusted_transcription("transcription", &release.closures[0].sha256);
    let transcription_inventory = trusted_transcription_inventory(&trusted_transcription);
    let transcription = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:transcription".into(),
        node_id: "artifact:a".into(),
        kind: EvidenceKind::TrustedTranscription,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: None,
        binding_mode: Some(BindingMode::ExternalRoundTrip),
        theorem: None,
        artifact_binding: None,
        trusted_transcription: Some(trusted_transcription),
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: transcription_inventory,
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance: transcription_provenance,
    });
    release.claims[0]
        .cited_evidence
        .extend([artifact.sha256.clone(), transcription.sha256.clone()]);
    release.evidence.extend([artifact, transcription]);
    release.graph_sha256 = graph_hash(&release.graph);
}

fn artifact_bound_release() -> CompiledRelease {
    let mut release = theorem_release();
    add_binding_paths(&mut release);
    let transcription = release
        .evidence
        .pop()
        .expect("binding helper appends transcription evidence");
    release.claims[0]
        .cited_evidence
        .remove(&transcription.sha256);
    release.claims[0].primary_linkage = None;
    release.policies[0].components = BTreeSet::from([BuiltInProfile::ArtifactBound]);
    release.reported_statuses[0].linkage = Some(LinkageFacet::ArtifactBound);
    release
}

fn transcribed_release() -> CompiledRelease {
    let mut release = base_release();
    release.project_tier = Tier::Bounded;
    release.graph.nodes[3] = GraphNode {
        id: "artifact:transcription".into(),
        kind: NodeKind::Artifact,
        proof_environment: None,
    };
    release.graph.nodes.extend([
        GraphNode {
            id: "tcb:trusted-transcription:transcription:transcriber".into(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        },
        GraphNode {
            id: "tcb:trusted-transcription:transcription:reencoder".into(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        },
    ]);
    let (detail, provenance) = trusted_transcription("transcription", &release.closures[0].sha256);
    let transcription_inventory = trusted_transcription_inventory(&detail);
    let transcription = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:transcription".into(),
        node_id: "artifact:transcription".into(),
        kind: EvidenceKind::TrustedTranscription,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: None,
        binding_mode: Some(BindingMode::ExternalRoundTrip),
        theorem: None,
        artifact_binding: None,
        trusted_transcription: Some(detail),
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: transcription_inventory,
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance,
    });
    release.claims[0].cited_evidence = BTreeSet::from([transcription.sha256.clone()]);
    release.evidence = vec![transcription];
    release.claims[0].policy = "transcribed".into();
    release.policies[0].id = "transcribed".into();
    release.policies[0].components = BTreeSet::from([BuiltInProfile::Transcribed]);
    release.reported_statuses[0].formal = FormalFacet::Open;
    release.reported_statuses[0].linkage = Some(LinkageFacet::Transcribed);
    release.reported_statuses[0].policy_admitted = true;
    release.graph_sha256 = graph_hash(&release.graph);
    release
}

fn rehash_evidence_at(release: &mut CompiledRelease, index: usize) {
    let old = release.evidence[index].sha256.clone();
    let replacement = domain_hash(
        EVIDENCE_SCHEMA_V2,
        &canonical_json(&release.evidence[index].record).unwrap(),
    );
    release.evidence[index].sha256.clone_from(&replacement);
    for claim in &mut release.claims {
        if claim.cited_evidence.remove(&old) {
            claim.cited_evidence.insert(replacement.clone());
        }
    }
    for wrapper in &mut release.evidence {
        if let Some(binding) = &mut wrapper.record.artifact_binding
            && binding.theorem_evidence == old
        {
            binding.theorem_evidence.clone_from(&replacement);
        }
        if let Some(refinement) = &mut wrapper.record.source_refinement
            && refinement.refinement_theorem_evidence == old
        {
            refinement
                .refinement_theorem_evidence
                .clone_from(&replacement);
        }
    }
    for premise in &mut release.premises {
        if premise.theorem_evidence.as_deref() == Some(&old) {
            premise.theorem_evidence = Some(replacement.clone());
        }
        if let Some(discharge) = &mut premise.discharge
            && discharge.theorem_evidence == old
        {
            discharge.theorem_evidence.clone_from(&replacement);
        }
    }
    for assumption in &mut release.assumptions {
        if assumption.review_evidence.remove(&old) {
            assumption.review_evidence.insert(replacement.clone());
        }
    }
}

fn replace_binding_theorem_statement(
    release: &mut CompiledRelease,
    statement_wire: serde_json::Value,
    replace_digest: bool,
) {
    let theorem = release.evidence[0]
        .record
        .theorem
        .as_mut()
        .expect("artifact fixture contains a theorem");
    if replace_digest {
        theorem.statement_sha256 = lean_statement_wire_digest(&statement_wire).unwrap();
    }
    theorem.statement_wire = statement_wire;
    rehash_evidence_at(release, 0);
    rehash_evidence_at(release, 1);
}

#[test]
fn multiple_binding_paths_require_an_exact_primary_selection() {
    let mut ambiguous = theorem_release();
    add_binding_paths(&mut ambiguous);
    let error = verify_compiled_release(&ambiguous).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvAmbiguousLinkage));

    ambiguous.claims[0].primary_linkage = Some(LinkageFacet::ArtifactBound);
    ambiguous.reported_statuses[0].linkage = Some(LinkageFacet::ArtifactBound);
    verify_compiled_release(&ambiguous).unwrap();
}

#[test]
fn checker_authored_plain_theorem_cannot_smuggle_artifact_bound_status() {
    let mut release = artifact_bound_release();
    replace_binding_theorem_statement(
        &mut release,
        plain_statement("Synthetic.unboundStatement"),
        true,
    );

    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("exact audited theorem root"))
    );
}

#[test]
fn artifact_binding_rejects_wrong_claim_path_and_digest_literals() {
    let baseline = artifact_bound_release();
    let artifact = baseline.evidence[1]
        .record
        .artifact_binding
        .as_ref()
        .unwrap()
        .artifact
        .clone();
    let attacks = [
        binding_statement("other-claim", &artifact.logical_name, &artifact.sha256),
        binding_statement("c", "other-artifact.bin", &artifact.sha256),
        binding_statement("c", &artifact.logical_name, &digest("other artifact")),
    ];

    for statement in attacks {
        let mut release = baseline.clone();
        replace_binding_theorem_statement(&mut release, statement, true);
        let error = verify_compiled_release(&release).unwrap_err();
        assert!(
            codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence),
            "attack must invalidate artifact linkage: {:?}",
            error.issues
        );
    }
}

#[test]
fn artifact_binding_rejects_a_forged_size_even_when_name_and_digest_match() {
    let mut release = artifact_bound_release();
    release.evidence[1]
        .record
        .artifact_binding
        .as_mut()
        .unwrap()
        .artifact
        .size_bytes += 1;
    rehash_evidence_at(&mut release, 1);

    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
}

#[test]
fn artifact_provenance_inventories_are_sorted_with_unique_logical_names() {
    let artifact_a = ArtifactIdentityReceipt {
        logical_name: "a.bin".into(),
        sha256: digest("a"),
        size_bytes: 1,
    };
    let artifact_b = ArtifactIdentityReceipt {
        logical_name: "b.bin".into(),
        sha256: digest("b"),
        size_bytes: 1,
    };

    let mut unsorted = base_release();
    unsorted.evidence[0].record.provenance.input_artifacts =
        vec![artifact_b.clone(), artifact_a.clone()];
    unsorted.evidence[0].record.provenance.cache_key = domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&unsorted.evidence[0].record.provenance.cache_material()).unwrap(),
    );
    rehash_first_evidence(&mut unsorted);
    let error = verify_compiled_release(&unsorted).unwrap_err();
    assert!(error.issues.iter().any(|issue| {
        issue
            .message
            .contains("artifact inventory must be strictly sorted and unique")
    }));

    let mut duplicate = base_release();
    duplicate.evidence[0].record.provenance.generated_artifacts = vec![
        artifact_a.clone(),
        ArtifactIdentityReceipt {
            sha256: digest("different a"),
            ..artifact_a
        },
    ];
    duplicate.evidence[0]
        .record
        .provenance
        .generated_artifacts
        .sort();
    duplicate.evidence[0].record.provenance.cache_key = domain_hash(
        "proofbound-cache-key/1",
        &canonical_json(&duplicate.evidence[0].record.provenance.cache_material()).unwrap(),
    );
    rehash_first_evidence(&mut duplicate);
    let error = verify_compiled_release(&duplicate).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("repeats logical name 'a.bin'"))
    );
}

#[test]
fn unknown_peak_memory_is_distinct_from_measured_zero_and_is_required() {
    let mut unknown = base_release();
    unknown.evidence[0]
        .record
        .provenance
        .actual_cost
        .memory_bytes = None;
    rehash_first_evidence(&mut unknown);
    verify_compiled_release(&unknown).unwrap();

    let mut measured_zero = unknown.clone();
    measured_zero.evidence[0]
        .record
        .provenance
        .actual_cost
        .memory_bytes = Some(0);
    rehash_first_evidence(&mut measured_zero);
    verify_compiled_release(&measured_zero).unwrap();
    assert_ne!(unknown.evidence[0].sha256, measured_zero.evidence[0].sha256);

    let mut missing = serde_json::to_value(&unknown.evidence[0].record.provenance).unwrap();
    missing["actual_cost"]
        .as_object_mut()
        .unwrap()
        .remove("memory_bytes");
    assert!(serde_json::from_value::<EvidenceProvenance>(missing).is_err());
}

#[test]
fn command_run_order_coverage_completion_and_output_are_fail_closed() {
    let mut complete = base_release();
    complete.evidence[0]
        .record
        .provenance
        .commands
        .push(CommandReceipt {
            program: "synthetic-runner".into(),
            args: vec!["cross-check".into()],
            environment_allowlist: Vec::new(),
        });
    complete.evidence[0]
        .record
        .provenance
        .runs
        .push(ExecutionRunReceipt {
            command_index: 1,
            exit_code: Some(0),
            stdout_sha256: digest("second stdout"),
            stderr_sha256: digest("second stderr"),
            normalized_output_sha256: digest("second normalized output"),
            output_truncated: false,
            duration_ms: 2,
        });
    rehash_first_evidence(&mut complete);
    verify_compiled_release(&complete).unwrap();

    let mut reordered = complete.clone();
    reordered.evidence[0].record.provenance.runs.swap(0, 1);
    rehash_first_evidence(&mut reordered);
    let error = verify_compiled_release(&reordered).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("exact command order"))
    );

    let mut omitted = complete.clone();
    omitted.evidence[0].record.provenance.runs.pop();
    rehash_first_evidence(&mut omitted);
    let error = verify_compiled_release(&omitted).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("without omission"))
    );

    let mut truncated = complete.clone();
    truncated.evidence[0].record.provenance.runs[0].output_truncated = true;
    rehash_first_evidence(&mut truncated);
    let error = verify_compiled_release(&truncated).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("truncated output"))
    );

    let mut incomplete = complete.clone();
    incomplete.evidence[0].record.provenance.runs[0].exit_code = None;
    rehash_first_evidence(&mut incomplete);
    let error = verify_compiled_release(&incomplete).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("exit status zero"))
    );

    let mut nonzero = complete.clone();
    nonzero.evidence[0].record.provenance.runs[0].exit_code = Some(1);
    rehash_first_evidence(&mut nonzero);
    let error = verify_compiled_release(&nonzero).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("exit status zero"))
    );

    let mut empty_inventory = complete;
    empty_inventory.evidence[0]
        .record
        .inventoried_targets
        .clear();
    rehash_first_evidence(&mut empty_inventory);
    let error = verify_compiled_release(&empty_inventory).unwrap_err();
    assert!(error.issues.iter().any(|issue| {
        issue
            .message
            .contains("nonempty bounded exact target inventory")
    }));
}

#[test]
fn compiler_internal_provenance_cannot_fabricate_process_execution() {
    let mut internal = base_release();
    internal.evidence[0].record.provenance.execution_kind = ExecutionKind::CompilerInternal;
    internal.evidence[0].record.provenance.commands.clear();
    internal.evidence[0].record.provenance.runs.clear();
    rehash_first_evidence(&mut internal);
    verify_compiled_release(&internal).unwrap();

    let mut fabricated = internal.clone();
    fabricated.evidence[0].record.provenance.commands = vec![CommandReceipt {
        program: "invented-review-process".into(),
        args: vec!["check".into()],
        environment_allowlist: Vec::new(),
    }];
    fabricated.evidence[0].record.provenance.runs = vec![ExecutionRunReceipt {
        command_index: 0,
        exit_code: Some(0),
        stdout_sha256: digest("invented stdout"),
        stderr_sha256: digest("invented stderr"),
        normalized_output_sha256: digest("invented output"),
        output_truncated: false,
        duration_ms: 0,
    }];
    rehash_first_evidence(&mut fabricated);
    let error = verify_compiled_release(&fabricated).unwrap_err();
    assert!(error.issues.iter().any(|issue| {
        issue
            .message
            .contains("compiler-internal provenance must not fabricate")
    }));

    let mut missing = internal;
    missing.evidence[0].record.provenance.execution_kind = ExecutionKind::ObservedProcesses;
    rehash_first_evidence(&mut missing);
    let error = verify_compiled_release(&missing).unwrap_err();
    assert!(error.issues.iter().any(|issue| {
        issue
            .message
            .contains("observed-process provenance must retain")
    }));
}

#[test]
fn command_environment_names_are_unique_per_command() {
    let mut release = base_release();
    let environment = EnvironmentReceipt {
        name: "PROOFBOUND_MODE".into(),
        value_sha256: Some(digest("strict")),
        secret: false,
    };
    release.evidence[0].record.provenance.commands[0].environment_allowlist =
        vec![environment.clone(), environment];
    rehash_first_evidence(&mut release);
    let error = verify_compiled_release(&release).unwrap_err();
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("repeats name 'PROOFBOUND_MODE'"))
    );
}

#[test]
fn internal_and_public_claim_language_survive_independently() {
    let mut release = base_release();
    release.claims[0].statement = "Internal theorem property P.".into();
    release.claims[0].public_language = Some("Reader-facing property P.".into());
    release.reported_statuses[0].public_statement = "Reader-facing property P.".into();
    verify_compiled_release(&release).unwrap();

    let mut substituted = release.clone();
    substituted.reported_statuses[0].public_statement = substituted.claims[0].statement.clone();
    let error = verify_compiled_release(&substituted).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));

    let mut bounded = bounded_release();
    bounded.claims[0].statement = "Internal bounded property P.".into();
    bounded.claims[0].public_language = Some("Reader-facing bounded property P.".into());
    bounded.reported_statuses[0].public_statement = bounded_public_statement_for_test(
        bounded.claims[0].public_language.as_deref().unwrap(),
        bounded.claims[0]
            .registered_domain_language
            .as_deref()
            .unwrap(),
    );
    verify_compiled_release(&bounded).unwrap();
    assert!(
        bounded.reported_statuses[0]
            .public_statement
            .starts_with("Reader-facing bounded property P.")
    );
    assert!(
        !bounded.reported_statuses[0]
            .public_statement
            .contains("Internal bounded property P.")
    );
}

#[test]
fn bounded_model_assumptions_are_retained_and_strict() {
    let mut valid = bounded_release();
    valid.evidence[0]
        .record
        .bounded_check
        .as_mut()
        .unwrap()
        .assumptions = vec!["--object-bits=8".into()];
    rehash_first_evidence(&mut valid);
    verify_compiled_release(&valid).unwrap();

    for assumptions in [
        vec!["".into()],
        vec!["--object-bits=8".into(), "--object-bits=8".into()],
        vec!["x".repeat(4097)],
        (0..4097)
            .map(|index| format!("assumption-{index}"))
            .collect(),
    ] {
        let mut malformed = bounded_release();
        malformed.evidence[0]
            .record
            .bounded_check
            .as_mut()
            .unwrap()
            .assumptions = assumptions;
        rehash_first_evidence(&mut malformed);
        let error = verify_compiled_release(&malformed).unwrap_err();
        assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    }

    let mut missing = serde_json::to_value(
        bounded_release().evidence[0]
            .record
            .bounded_check
            .clone()
            .unwrap(),
    )
    .unwrap();
    missing.as_object_mut().unwrap().remove("assumptions");
    assert!(serde_json::from_value::<BoundedCheckReceipt>(missing).is_err());
}

#[test]
fn nested_artifact_marker_cannot_confer_binding() {
    let mut release = artifact_bound_release();
    let exact_root = release.evidence[0]
        .record
        .theorem
        .as_ref()
        .unwrap()
        .statement_wire[1]
        .clone();
    let nested = serde_json::json!([
        "lean-expr-cbor/1",
        [3, [2, "Synthetic.Wrapper", []], exact_root]
    ]);
    replace_binding_theorem_statement(&mut release, nested, true);

    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
}

#[test]
fn theorem_statement_wire_must_match_its_recorded_digest() {
    let mut release = artifact_bound_release();
    let replacement = plain_statement("Synthetic.tamperedStatement");
    replace_binding_theorem_statement(&mut release, replacement, false);

    let error = verify_compiled_release(&release).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("canonical statement wire"))
    );
}

#[test]
fn known_status_upgrade_attacks_are_rejected() {
    let mut test_as_proof = base_release();
    test_as_proof.reported_statuses[0].formal = FormalFacet::Proved;
    let error = verify_compiled_release(&test_as_proof).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));

    let mut transcription_as_binding = theorem_release();
    add_binding_paths(&mut transcription_as_binding);
    let artifact_id = transcription_as_binding.evidence[1].sha256.clone();
    transcription_as_binding.evidence.remove(1);
    transcription_as_binding.claims[0]
        .cited_evidence
        .remove(&artifact_id);
    transcription_as_binding.claims[0].primary_linkage = None;
    transcription_as_binding.reported_statuses[0].linkage = Some(LinkageFacet::ArtifactBound);
    let error = verify_compiled_release(&transcription_as_binding).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));
}

#[test]
fn transcribed_profile_accepts_only_open_transcribed_status() {
    let release = transcribed_release();
    let report = verify_compiled_release(&release).unwrap();
    assert_eq!(report.claims[0].formal, FormalFacet::Open);
    assert_eq!(report.claims[0].linkage, Some(LinkageFacet::Transcribed));
    assert!(report.claims[0].policy_admitted);

    let mut redefined = release.clone();
    redefined.policies[0].require_no_assumptions = true;
    let error = verify_compiled_release(&redefined).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidPolicy));

    let mut upgraded = release;
    upgraded.reported_statuses[0].formal = FormalFacet::Proved;
    upgraded.reported_statuses[0].linkage = Some(LinkageFacet::ArtifactBound);
    let error = verify_compiled_release(&upgraded).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch));
}

#[test]
fn trusted_transcription_recomputes_both_byte_equalities() {
    let mut candidate_mismatch = transcribed_release();
    let generated = {
        let detail = candidate_mismatch.evidence[0]
            .record
            .trusted_transcription
            .as_mut()
            .unwrap();
        detail.transcribed_candidate.size_bytes += 1;
        vec![
            detail.transcribed_candidate.clone(),
            detail.reencoded_source.clone(),
        ]
    };
    candidate_mismatch.evidence[0]
        .record
        .provenance
        .generated_artifacts = generated;
    candidate_mismatch.evidence[0]
        .record
        .provenance
        .generated_artifacts
        .sort();
    recache_and_rehash_first_evidence(&mut candidate_mismatch);
    let error = verify_compiled_release(&candidate_mismatch).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(error.issues.iter().any(|issue| {
        issue
            .message
            .contains("candidate bytes do not match the committed transcription")
    }));

    let mut reencoded_mismatch = transcribed_release();
    let generated = {
        let detail = reencoded_mismatch.evidence[0]
            .record
            .trusted_transcription
            .as_mut()
            .unwrap();
        detail.reencoded_source.sha256 = digest("mismatched re-encoding");
        vec![
            detail.transcribed_candidate.clone(),
            detail.reencoded_source.clone(),
        ]
    };
    reencoded_mismatch.evidence[0]
        .record
        .provenance
        .generated_artifacts = generated;
    reencoded_mismatch.evidence[0]
        .record
        .provenance
        .generated_artifacts
        .sort();
    recache_and_rehash_first_evidence(&mut reencoded_mismatch);
    let error = verify_compiled_release(&reencoded_mismatch).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(error.issues.iter().any(|issue| {
        issue
            .message
            .contains("re-encoded source bytes do not match the registered source")
    }));
}

#[test]
fn trusted_transcription_rejects_aliasing_and_hidden_provenance() {
    let mut alias = transcribed_release();
    let generated = {
        let detail = alias.evidence[0]
            .record
            .trusted_transcription
            .as_mut()
            .unwrap();
        detail.transcribed_candidate.logical_name =
            detail.committed_transcription.logical_name.clone();
        vec![
            detail.transcribed_candidate.clone(),
            detail.reencoded_source.clone(),
        ]
    };
    alias.evidence[0].record.provenance.generated_artifacts = generated;
    alias.evidence[0]
        .record
        .provenance
        .generated_artifacts
        .sort();
    recache_and_rehash_first_evidence(&mut alias);
    let error = verify_compiled_release(&alias).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("aliases two artifact roles"))
    );

    let mut extra = transcribed_release();
    extra.evidence[0]
        .record
        .provenance
        .input_artifacts
        .push(named_artifact("hidden/input", "hidden", 6));
    extra.evidence[0].record.provenance.input_artifacts.sort();
    recache_and_rehash_first_evidence(&mut extra);
    let error = verify_compiled_release(&extra).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("exactly three input artifacts"))
    );
}

#[test]
fn trusted_transcription_rejects_missing_reused_or_forged_tcb_roles() {
    let mut missing = transcribed_release();
    missing
        .graph
        .nodes
        .retain(|node| node.id != "tcb:trusted-transcription:transcription:reencoder");
    missing.graph_sha256 = graph_hash(&missing.graph);
    let error = verify_compiled_release(&missing).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));

    let mut reused = transcribed_release();
    let transcriber_node = reused.evidence[0]
        .record
        .trusted_transcription
        .as_ref()
        .unwrap()
        .transcriber
        .tcb_node
        .clone();
    reused.evidence[0]
        .record
        .trusted_transcription
        .as_mut()
        .unwrap()
        .reencoder
        .tcb_node = transcriber_node;
    rehash_first_evidence(&mut reused);
    let error = verify_compiled_release(&reused).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));

    let mut forged = transcribed_release();
    forged.evidence[0]
        .record
        .trusted_transcription
        .as_mut()
        .unwrap()
        .reencoder
        .role_identity = digest("checker-authored-role");
    rehash_first_evidence(&mut forged);
    let error = verify_compiled_release(&forged).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.message.contains("not derived from the exact driver"))
    );
}

#[test]
fn trusted_transcription_wire_rejects_legacy_and_forged_booleans() {
    let release = transcribed_release();
    let mut forged = serde_json::to_value(&release).unwrap();
    forged["evidence"][0]["record"]["trusted_transcription"]
        .as_object_mut()
        .unwrap()
        .insert("round_trip_passed".into(), true.into());
    assert!(serde_json::from_value::<CompiledRelease>(forged).is_err());

    let mut legacy = serde_json::to_value(&release).unwrap();
    legacy["evidence"][0]["record"]["trusted_transcription"] = serde_json::json!({
        "transcriber_tcb_node": "tcb:transcriber",
        "reencoder_tcb_node": "tcb:reencoder",
        "round_trip_passed": true
    });
    assert!(serde_json::from_value::<CompiledRelease>(legacy).is_err());
}

#[test]
fn unit_scoped_transcription_tcb_roles_allow_distinct_drivers() {
    let mut release = transcribed_release();
    let (detail, provenance) =
        trusted_transcription("transcription-two", &release.closures[0].sha256);
    release.graph.nodes.extend([
        GraphNode {
            id: "artifact:transcription-two".into(),
            kind: NodeKind::Artifact,
            proof_environment: None,
        },
        GraphNode {
            id: "tcb:trusted-transcription:transcription-two:transcriber".into(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        },
        GraphNode {
            id: "tcb:trusted-transcription:transcription-two:reencoder".into(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        },
    ]);
    let second_inventory = trusted_transcription_inventory(&detail);
    let second = hash_evidence(EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: "unit:transcription-two".into(),
        node_id: "artifact:transcription-two".into(),
        kind: EvidenceKind::TrustedTranscription,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: EvidenceOutcome::Passed,
        evaluation_mode: None,
        binding_mode: Some(BindingMode::ExternalRoundTrip),
        theorem: None,
        artifact_binding: None,
        trusted_transcription: Some(detail),
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: second_inventory,
        assumptions: Default::default(),
        premises: Default::default(),
        open_obligation: None,
        provenance,
    });
    release.claims[0]
        .cited_evidence
        .insert(second.sha256.clone());
    release.evidence.push(second);
    release.graph_sha256 = graph_hash(&release.graph);

    verify_compiled_release(&release).unwrap();
    let directory = write_release(&release);
    verify_release_dir(directory.path()).unwrap();
}

#[test]
fn sealed_file_hashes_are_recomputed_from_release_bytes() {
    let mut release = base_release();
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("artifact.bin"), b"actual").unwrap();
    release.sealed_files.push(SealedFile {
        path: "artifact.bin".into(),
        sha256: digest("wrong"),
        size_bytes: 6,
    });
    release = write_tcb_ledger_at(directory.path(), &release, &tcb_ledger_value(&release));
    write_payload_at(directory.path(), &release);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvDigest));
}

#[test]
fn sealed_tcb_ledger_exactly_covers_evidence_tool_and_adapter_identities() {
    let release = base_release();
    let directory = write_release(&release);
    verify_release_dir(directory.path()).unwrap();

    let mut missing = tcb_ledger_value(&release);
    missing["components"].as_array_mut().unwrap().remove(0);
    let directory = write_release_with_tcb(&release, &missing);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvMissingReference));

    let mut unknown = tcb_ledger_value(&release);
    unknown["components"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "name": "unreferenced",
            "version": "1.0.0",
            "identity_sha256": digest("unreferenced"),
        }));
    unknown["components"]
        .as_array_mut()
        .unwrap()
        .sort_by(|left, right| {
            left["name"]
                .as_str()
                .cmp(&right["name"].as_str())
                .then_with(|| left["version"].as_str().cmp(&right["version"].as_str()))
                .then_with(|| {
                    left["identity_sha256"]
                        .as_str()
                        .cmp(&right["identity_sha256"].as_str())
                })
        });
    let directory = write_release_with_tcb(&release, &unknown);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvInvalidEvidence));
}

#[test]
fn tcb_ledger_rejects_missing_seal_unknown_fields_and_noncanonical_component_order() {
    let release = base_release();
    let directory = tempfile::tempdir().unwrap();
    write_payload_at(directory.path(), &release);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvMissingReference));

    let mut unknown_field = tcb_ledger_value(&release);
    unknown_field["components"][0]["unreviewed"] = true.into();
    let directory = write_release_with_tcb(&release, &unknown_field);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvJson));

    let mut unsorted = tcb_ledger_value(&release);
    unsorted["components"].as_array_mut().unwrap().reverse();
    let directory = write_release_with_tcb(&release, &unsorted);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvNonCanonical));
}

#[test]
fn tcb_ledger_rejects_duplicate_and_conflicting_components() {
    let release = base_release();
    let mut duplicate = tcb_ledger_value(&release);
    let component = duplicate["components"][0].clone();
    duplicate["components"]
        .as_array_mut()
        .unwrap()
        .insert(0, component);
    let directory = write_release_with_tcb(&release, &duplicate);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvDuplicateId));

    let mut conflicting = tcb_ledger_value(&release);
    let mut component = conflicting["components"][0].clone();
    component["identity_sha256"] = digest("conflict").into();
    conflicting["components"]
        .as_array_mut()
        .unwrap()
        .insert(1, component);
    let directory = write_release_with_tcb(&release, &conflicting);
    let error = verify_release_dir(directory.path()).unwrap_err();
    assert!(codes(&error).contains(&VerificationIssueCode::PbvDuplicateId));
}

fn write_payload_at(directory: &Path, release: &CompiledRelease) {
    let payload = canonical_json(release).unwrap();
    fs::write(directory.join("compiled-receipt.json"), &payload).unwrap();
    let envelope = ReleaseEnvelope {
        schema: RELEASE_ENVELOPE_SCHEMA_V2.into(),
        payload: "compiled-receipt.json".into(),
        payload_sha256: domain_hash(COMPILED_RELEASE_SCHEMA_V2, &payload),
    };
    fs::write(
        directory.join("release.json"),
        canonical_json(&envelope).unwrap(),
    )
    .unwrap();
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCorpus {
    schema: String,
    cases: Vec<RawCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCase {
    id: String,
    tier: u8,
    #[serde(default)]
    claim_tier: Option<u8>,
    policy: RawPolicy,
    evidence: Vec<RawEvidence>,
    assumptions: Vec<RawAssumption>,
    premises: Vec<RawPremise>,
    #[serde(default)]
    primary_linkage: Option<String>,
    registered_domain: bool,
    expected: RawStatus,
    #[serde(default)]
    asserted: Option<RawStatus>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawPolicy {
    components: Vec<String>,
    admit_exhaustive_as_proved: bool,
    require_no_assumptions: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    id: String,
    kind: String,
    #[serde(default = "raw_passed")]
    outcome: String,
    #[serde(default = "raw_true")]
    present: bool,
    #[serde(default = "raw_true")]
    cited: bool,
    #[serde(default)]
    evaluation: Option<String>,
    #[serde(default)]
    theorem_ref: Option<String>,
    #[serde(default = "raw_true")]
    typed_binding: bool,
    #[serde(default)]
    premises: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAssumption {
    id: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPremise {
    id: String,
    theorem: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStatus {
    formal: String,
    linkage: Option<String>,
    assumption: String,
    assumptions: BTreeSet<String>,
    undischarged_premises: BTreeSet<String>,
    policy_admitted: bool,
}

const fn raw_true() -> bool {
    true
}

fn raw_passed() -> String {
    "passed".into()
}

fn load_raw_corpus() -> RawCorpus {
    serde_json::from_str(include_str!(
        "../../../proofbound/conformance/v1/status-graphs.json"
    ))
    .expect("language-neutral conformance corpus must be strict JSON")
}

fn raw_profile(profile: &str) -> BuiltInProfile {
    match profile {
        "ledger" => BuiltInProfile::Ledger,
        "transcribed" => BuiltInProfile::Transcribed,
        "kernel" => BuiltInProfile::Kernel,
        "kernel-with-assumptions" => BuiltInProfile::KernelWithAssumptions,
        "artifact-bound" => BuiltInProfile::ArtifactBound,
        "source-refined" => BuiltInProfile::SourceRefined,
        "native-evaluated" => BuiltInProfile::NativeEvaluated,
        "bounded" => BuiltInProfile::Bounded,
        other => panic!("unknown raw policy profile: {other}"),
    }
}

fn raw_tier(tier: u8) -> Tier {
    match tier {
        0 => Tier::Ledger,
        1 => Tier::Bounded,
        2 => Tier::Model,
        3 => Tier::Bound,
        other => panic!("invalid raw tier: {other}"),
    }
}

fn raw_outcome(outcome: &str) -> EvidenceOutcome {
    match outcome {
        "passed" => EvidenceOutcome::Passed,
        "failed" => EvidenceOutcome::Failed,
        "drifted" => EvidenceOutcome::Drifted,
        other => panic!("unsupported raw outcome: {other}"),
    }
}

fn raw_evaluation(evaluation: Option<&str>) -> EvaluationMode {
    match evaluation.unwrap_or("kernel") {
        "kernel" => EvaluationMode::Kernel,
        "native" => EvaluationMode::Native,
        other => panic!("unsupported raw evaluation: {other}"),
    }
}

fn empty_raw_record(
    release: &CompiledRelease,
    raw: &RawEvidence,
    kind: EvidenceKind,
    node_id: String,
) -> EvidenceReceipt {
    EvidenceReceipt {
        schema: EVIDENCE_SCHEMA_V2.into(),
        unit_id: format!("unit:{}", raw.id),
        node_id,
        kind,
        claim_ids: BTreeSet::from(["c".into()]),
        outcome: raw_outcome(&raw.outcome),
        evaluation_mode: None,
        binding_mode: None,
        theorem: None,
        artifact_binding: None,
        trusted_transcription: None,
        source_refinement: None,
        bounded_check: None,
        exhaustive_check: None,
        mutation_witness: None,
        independence: None,
        inventoried_targets: if raw.outcome == "passed" {
            BTreeSet::from([format!("{}::registered", raw.id)])
        } else {
            BTreeSet::new()
        },
        assumptions: BTreeSet::new(),
        premises: raw.premises.iter().cloned().collect(),
        open_obligation: None,
        provenance: provenance(&release.closures[0].sha256),
    }
}

fn build_verifier_corpus_case(case: &RawCase) -> CompiledRelease {
    let mut release = base_release();
    release.project_tier = raw_tier(case.tier);
    release.claims[0].tier = case.claim_tier.map(raw_tier);
    release.graph.nodes.truncate(3);
    release.graph.edges.clear();
    release.evidence.clear();
    release.assumptions.clear();
    release.premises.clear();
    release.claims[0].cited_evidence.clear();
    release.claims[0].registered_domain_language = case
        .registered_domain
        .then(|| "For every member of the registered finite corpus domain, P holds.".into());
    release.claims[0].primary_linkage =
        case.primary_linkage
            .as_deref()
            .map(|linkage| match linkage {
                "REFINED" => LinkageFacet::Refined,
                "ARTIFACT_BOUND" => LinkageFacet::ArtifactBound,
                "TRANSCRIBED" => LinkageFacet::Transcribed,
                "MODEL_ONLY" => LinkageFacet::ModelOnly,
                other => panic!("unknown raw primary linkage: {other}"),
            });
    release.policies[0].id = format!("corpus-policy-{}", case.id);
    release.policies[0].components = case
        .policy
        .components
        .iter()
        .map(|profile| raw_profile(profile))
        .collect();
    release.policies[0].admit_exhaustive_as_proved = case.policy.admit_exhaustive_as_proved;
    release.policies[0].require_no_assumptions = case.policy.require_no_assumptions;
    release.claims[0].policy = release.policies[0].id.clone();

    let mut identities = std::collections::BTreeMap::new();
    for raw in &case.evidence {
        if !raw.present {
            let missing = digest(&format!("missing:{}", raw.id));
            identities.insert(raw.id.clone(), missing.clone());
            if raw.cited {
                release.claims[0].cited_evidence.insert(missing);
            }
            continue;
        }
        let (mut record, node_kind) = match raw.kind.as_str() {
            "example-test" => {
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::ExampleTest,
                    format!("test:{}", raw.id),
                );
                record
                    .inventoried_targets
                    .insert(format!("tests::{}", raw.id));
                (record, NodeKind::TestSuite)
            }
            "bounded-check" => {
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::BoundedCheck,
                    format!("model:{}", raw.id),
                );
                record.bounded_check = Some(BoundedCheckReceipt {
                    domain: BoundedDomain {
                        id: "domain:corpus".into(),
                        description: "all registered finite corpus values".into(),
                        registration_sha256: digest("corpus-domain"),
                        cardinality: Some(4),
                    },
                    solver: "corpus-solver 1".into(),
                    harnesses: BTreeSet::from(["check_all".into()]),
                    unwind_bounds: BTreeMap::from([("check_all".into(), 1)]),
                    assumptions: Vec::new(),
                });
                record.inventoried_targets = BTreeSet::from(["check_all".into()]);
                (record, NodeKind::ModelCheckUnit)
            }
            "exhaustive-check" => {
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::ExhaustiveCheck,
                    format!("model:{}", raw.id),
                );
                record.exhaustive_check = Some(ExhaustiveCheckReceipt {
                    domain: BoundedDomain {
                        id: "domain:corpus".into(),
                        description: "all registered finite corpus values".into(),
                        registration_sha256: digest("corpus-domain"),
                        cardinality: Some(4),
                    },
                    evaluated_members: 4,
                });
                (record, NodeKind::ModelCheckUnit)
            }
            "independent-check" => {
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::IndependentCheck,
                    format!("test:{}", raw.id),
                );
                record.independence = Some(IndependenceMode::Independent);
                record
                    .inventoried_targets
                    .insert(format!("independent::{}", raw.id));
                (record, NodeKind::TestSuite)
            }
            "theorem" => {
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::Theorem,
                    format!("theorem:{}", raw.id),
                );
                record.evaluation_mode = Some(raw_evaluation(raw.evaluation.as_deref()));
                let statement_wire = if raw.typed_binding {
                    let artifact_sha256 = digest("corpus artifact");
                    binding_statement("c", "corpus-artifact.bin", &artifact_sha256)
                } else {
                    plain_statement(&format!("Corpus.Unrelated.{}", raw.id))
                };
                let declaration = format!("Corpus.{}", raw.id);
                record.inventoried_targets = BTreeSet::from([declaration.clone()]);
                record.theorem = Some(TheoremReceipt {
                    declaration,
                    statement_encoding: "lean-expr-cbor/1".into(),
                    statement_sha256: lean_statement_wire_digest(&statement_wire).unwrap(),
                    statement_wire,
                    attributed_claim: "c".into(),
                    proof_environment: "lean:corpus".into(),
                    axiom_audit_passed: true,
                    contains_sorry_ax: false,
                    foundational_axioms: BTreeSet::new(),
                    project_axioms: BTreeSet::new(),
                });
                (record, NodeKind::Theorem)
            }
            "artifact-soundness" => {
                let reference = raw.theorem_ref.as_deref().unwrap();
                let theorem = identities
                    .get(reference)
                    .cloned()
                    .unwrap_or_else(|| digest(&format!("missing-reference:{reference}")));
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::ArtifactSoundness,
                    format!("artifact:{}", raw.id),
                );
                record.evaluation_mode = Some(raw_evaluation(raw.evaluation.as_deref()));
                record.binding_mode = Some(BindingMode::DigestTheorem);
                let artifact = ArtifactIdentityReceipt {
                    logical_name: "corpus-artifact.bin".into(),
                    sha256: digest("corpus artifact"),
                    size_bytes: 15,
                };
                record.provenance.input_artifacts.push(artifact.clone());
                record.provenance.cache_key = domain_hash(
                    "proofbound-cache-key/1",
                    &canonical_json(&record.provenance.cache_material()).unwrap(),
                );
                record.artifact_binding = Some(ArtifactBindingReceipt {
                    theorem_evidence: theorem,
                    artifact,
                });
                (record, NodeKind::Artifact)
            }
            "trusted-transcription" => {
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::TrustedTranscription,
                    format!("artifact:{}", raw.id),
                );
                record.binding_mode = Some(BindingMode::ExternalRoundTrip);
                let (detail, provenance) =
                    trusted_transcription(&raw.id, &release.closures[0].sha256);
                record.inventoried_targets = trusted_transcription_inventory(&detail);
                record.trusted_transcription = Some(detail);
                record.provenance = provenance;
                for suffix in ["transcriber", "reencoder"] {
                    release.graph.nodes.push(GraphNode {
                        id: format!("tcb:trusted-transcription:{}:{suffix}", raw.id),
                        kind: NodeKind::TcbComponent,
                        proof_environment: None,
                    });
                }
                (record, NodeKind::Artifact)
            }
            "source-refinement" => {
                let reference = raw.theorem_ref.as_deref().unwrap();
                let theorem = identities
                    .get(reference)
                    .cloned()
                    .unwrap_or_else(|| digest(&format!("missing-reference:{reference}")));
                let premise_ids = raw.premises.iter().cloned().collect::<BTreeSet<_>>();
                let mut record = empty_raw_record(
                    &release,
                    raw,
                    EvidenceKind::SourceRefinement,
                    format!("translation:{}", raw.id),
                );
                record.source_refinement = Some(SourceRefinementReceipt {
                    refinement_theorem_evidence: theorem,
                    representation_premises: premise_ids,
                    deterministic_translation: true,
                    pinned_toolchain: true,
                    generated_axioms_clean: true,
                    strength: RefinementStrength::DecisionAdequate,
                });
                (record, NodeKind::TranslationUnit)
            }
            other => panic!("unsupported raw evidence kind: {other}"),
        };
        record.outcome = raw_outcome(&raw.outcome);
        release.graph.nodes.push(GraphNode {
            id: record.node_id.clone(),
            kind: node_kind,
            proof_environment: (node_kind == NodeKind::Theorem).then(|| "lean:corpus".into()),
        });
        let wrapper = hash_evidence(record);
        identities.insert(raw.id.clone(), wrapper.sha256.clone());
        if raw.cited {
            release.claims[0]
                .cited_evidence
                .insert(wrapper.sha256.clone());
        }
        release.evidence.push(wrapper);
    }

    for raw in &case.assumptions {
        let review_raw = RawEvidence {
            id: format!("review-{}", raw.id),
            kind: "review".into(),
            outcome: "passed".into(),
            present: true,
            cited: false,
            evaluation: None,
            theorem_ref: None,
            typed_binding: true,
            premises: Vec::new(),
        };
        let review_node = format!("review:{}", raw.id);
        let review = hash_evidence(empty_raw_record(
            &release,
            &review_raw,
            EvidenceKind::Review,
            review_node.clone(),
        ));
        release.graph.nodes.extend([
            GraphNode {
                id: review_node,
                kind: NodeKind::Review,
                proof_environment: None,
            },
            GraphNode {
                id: format!("assumption:{}", raw.id),
                kind: NodeKind::Assumption,
                proof_environment: None,
            },
        ]);
        release.assumptions.push(AssumptionReceipt {
            schema: ASSUMPTION_SCHEMA_V1.into(),
            id: raw.id.clone(),
            node_id: format!("assumption:{}", raw.id),
            statement: "The external corpus boundary behaves as stated.".into(),
            category: AssumptionCategory::ExternalProvider,
            owner: "corpus-owner".into(),
            rationale: "The boundary is outside the registered claim.".into(),
            scope: "the corpus claim".into(),
            affected_claims: BTreeSet::from(["c".into()]),
            review_evidence: BTreeSet::from([review.sha256.clone()]),
            falsification_or_discharge_plan: "Replace with checked evidence.".into(),
            source_citation: None,
            state: AssumptionState::Active,
            depends_on: BTreeSet::new(),
        });
        release.evidence.push(review);
    }
    for raw in &case.premises {
        release.graph.nodes.push(GraphNode {
            id: format!("premise:{}", raw.id),
            kind: NodeKind::Premise,
            proof_environment: None,
        });
        release.premises.push(PremiseReceipt {
            id: raw.id.clone(),
            node_id: format!("premise:{}", raw.id),
            statement: "The registered representation invariant holds.".into(),
            category: AssumptionCategory::RepresentationPremise,
            theorem_evidence: Some(identities[&raw.theorem].clone()),
            scope: FlowScope::AllRegisteredInputs,
            discharge: None,
        });
    }
    release.graph_sha256 = graph_hash(&release.graph);
    let mut reported = raw_reported_status(case.asserted.as_ref().unwrap_or(&case.expected));
    if case.expected.formal == "BOUNDED_CHECKED"
        || (case.expected.formal == "PROVED"
            && case.policy.admit_exhaustive_as_proved
            && case
                .evidence
                .iter()
                .any(|evidence| evidence.kind == "exhaustive-check"))
    {
        reported.public_statement = bounded_public_statement_for_test(
            &release.claims[0].statement,
            release.claims[0]
                .registered_domain_language
                .as_deref()
                .expect("bounded corpus case registers a domain"),
        );
    }
    release.reported_statuses = vec![reported];
    release
}

fn bounded_public_statement_for_test(property: &str, domain: &str) -> String {
    format!("{property} Registered finite domain: {domain}")
}

fn raw_reported_status(status: &RawStatus) -> ReportedClaimStatus {
    ReportedClaimStatus {
        claim_id: "c".into(),
        public_statement: "The registered example passes.".into(),
        formal: match status.formal.as_str() {
            "PROVED" => FormalFacet::Proved,
            "BOUNDED_CHECKED" => FormalFacet::BoundedChecked,
            "TESTED" => FormalFacet::Tested,
            "OPEN" => FormalFacet::Open,
            "INVALID" => FormalFacet::Invalid,
            other => panic!("unknown raw formal facet: {other}"),
        },
        linkage: status.linkage.as_deref().map(|linkage| match linkage {
            "REFINED" => LinkageFacet::Refined,
            "ARTIFACT_BOUND" => LinkageFacet::ArtifactBound,
            "TRANSCRIBED" => LinkageFacet::Transcribed,
            "MODEL_ONLY" => LinkageFacet::ModelOnly,
            other => panic!("unknown raw linkage facet: {other}"),
        }),
        assumption: match status.assumption.as_str() {
            "NONE" => AssumptionFacet::None,
            "ASSUMED" => AssumptionFacet::Assumed,
            other => panic!("unknown raw assumption facet: {other}"),
        },
        assumptions: status.assumptions.clone(),
        undischarged_premises: status.undischarged_premises.clone(),
        policy_admitted: status.policy_admitted,
    }
}

fn snapshot_verifier_status(status: &ReportedClaimStatus) -> RawStatus {
    RawStatus {
        formal: match status.formal {
            FormalFacet::Proved => "PROVED",
            FormalFacet::BoundedChecked => "BOUNDED_CHECKED",
            FormalFacet::Tested => "TESTED",
            FormalFacet::Open => "OPEN",
            FormalFacet::Invalid => "INVALID",
        }
        .into(),
        linkage: status.linkage.map(|linkage| {
            match linkage {
                LinkageFacet::Refined => "REFINED",
                LinkageFacet::ArtifactBound => "ARTIFACT_BOUND",
                LinkageFacet::Transcribed => "TRANSCRIBED",
                LinkageFacet::ModelOnly => "MODEL_ONLY",
            }
            .into()
        }),
        assumption: match status.assumption {
            AssumptionFacet::None => "NONE",
            AssumptionFacet::Assumed => "ASSUMED",
        }
        .into(),
        assumptions: status.assumptions.clone(),
        undischarged_premises: status.undischarged_premises.clone(),
        policy_admitted: status.policy_admitted,
    }
}

#[test]
fn registered_language_neutral_status_corpus_matches_independent_verifier() {
    let corpus = load_raw_corpus();
    assert_eq!(corpus.schema, "proofbound-status-conformance/1");
    let mut ids = BTreeSet::new();
    for case in corpus.cases {
        assert!(ids.insert(case.id.clone()), "duplicate case ID {}", case.id);
        let release = build_verifier_corpus_case(&case);
        let result = verify_compiled_release(&release);
        if case.expected.formal == "INVALID" {
            let error = result.expect_err("INVALID corpus case must fail verification");
            assert!(
                !codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch),
                "independent recomputation diverged from expected INVALID status in {}: {:?}",
                case.id,
                error.issues
            );
        } else if case.asserted.is_some() {
            let error = result.expect_err("attack-shaped status must be rejected");
            assert!(
                codes(&error).contains(&VerificationIssueCode::PbvStatusMismatch),
                "attack was not rejected as a status mismatch in {}: {:?}",
                case.id,
                error.issues
            );
        } else {
            let report = result.unwrap_or_else(|error| {
                panic!("valid corpus case {} failed: {:?}", case.id, error.issues)
            });
            assert_eq!(
                snapshot_verifier_status(&report.claims[0]),
                case.expected,
                "conformance case {}",
                case.id
            );
        }
    }
}
