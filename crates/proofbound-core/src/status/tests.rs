use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{
    ASSUMPTION_SCHEMA_V1, AdapterStrength, ArtifactBindingEvidence, ArtifactIdentity,
    ArtifactLogicalName, AssumptionStatus, BindingMode, BoundedCheckEvidence, BuiltInProfile,
    CacheOrigin, CommandSpec, EnvironmentId, EnvironmentVariable, EnvironmentVariableName,
    EvidenceProvenance, ExecutionKind, ExecutionRun, ExhaustiveCheckEvidence, ExpectedFailure,
    GRAPH_SCHEMA_V1, GraphEdge, GraphNode, IndependenceMode, MutationWitnessEvidence,
    NativePremiseRule, POLICY_SCHEMA_V1, PolicyId, ResourceBudget, ResourceUsage, Sha256Digest,
    SourceRefinementEvidence, StaticCheckEvidence, TRUSTED_TRANSCRIPTION_SCHEMA_V1,
    TheoremEvidence, ToolIdentity, TranscriptionRole, TranscriptionTcbRole, TreeState,
    TrustedTranscriptionEvidence, UnitId, transcription_role_identity,
};

fn claim_id() -> ClaimId {
    ClaimId::new("CLAIM-1").unwrap()
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(label)
}

fn subject_node(subject: &str) -> NodeId {
    NodeId::new(format!(
        "subject:{}",
        Sha256Digest::of_bytes(subject.as_bytes())
    ))
    .unwrap()
}

fn bind_claim_to_subject(input: &mut ClaimEvaluationInput, subject: &str) {
    let prior = input.claim.subject.clone();
    let replacement = subject_node(subject);
    input.claim.subject.clone_from(&replacement);
    input
        .graph
        .nodes
        .iter_mut()
        .find(|node| node.id == prior)
        .expect("the claim subject node is registered")
        .id = replacement;
}

fn bound_artifact() -> ArtifactIdentity {
    ArtifactIdentity {
        logical_name: ArtifactLogicalName::new("artifact.bin").unwrap(),
        sha256: digest("artifact"),
        size_bytes: 8,
    }
}

fn named_artifact(logical_name: &str, digest_label: &str, size_bytes: u64) -> ArtifactIdentity {
    ArtifactIdentity {
        logical_name: ArtifactLogicalName::new(logical_name).unwrap(),
        sha256: digest(digest_label),
        size_bytes,
    }
}

fn attach_trusted_transcription(record: &mut EvidenceRecord, prefix: &str) {
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
    record.inventoried_targets = BTreeSet::from([
        source.logical_name.as_str().to_owned(),
        committed_transcription.logical_name.as_str().to_owned(),
    ]);
    record.provenance.input_artifacts.extend([
        source.clone(),
        committed_transcription.clone(),
        driver.clone(),
    ]);
    record
        .provenance
        .generated_artifacts
        .extend([transcribed_candidate.clone(), reencoded_source.clone()]);
    record.binding_mode = Some(BindingMode::ExternalRoundTrip);
    record.trusted_transcription = Some(TrustedTranscriptionEvidence {
        schema: TRUSTED_TRANSCRIPTION_SCHEMA_V1.into(),
        source,
        committed_transcription,
        transcribed_candidate,
        reencoded_source,
        transcriber: TranscriptionTcbRole {
            tcb_node: NodeId::new(format!("tcb:trusted-transcription:{prefix}:transcriber"))
                .unwrap(),
            role_identity: transcription_role_identity(TranscriptionRole::Transcriber, &driver),
        },
        reencoder: TranscriptionTcbRole {
            tcb_node: NodeId::new(format!("tcb:trusted-transcription:{prefix}:reencoder")).unwrap(),
            role_identity: transcription_role_identity(TranscriptionRole::Reencoder, &driver),
        },
        driver,
    });
}

fn attach_mutation_witness(
    record: &mut EvidenceRecord,
    mutation_id: &str,
    check_id: &str,
    proof_term_theorem: Option<EvidenceId>,
) {
    record.unit_id = UnitId::new(format!("unit:{mutation_id}")).unwrap();
    let registry = named_artifact(
        &format!("mutations/{mutation_id}.toml"),
        &format!("registry:{mutation_id}"),
        64,
    );
    let target_preimage = named_artifact("src/lib.rs", &format!("preimage:{mutation_id}"), 128);
    let mutant_artifact = named_artifact(
        &format!("mutants/{mutation_id}/lib.rs"),
        &format!("postimage:{mutation_id}"),
        120,
    );
    let target_postimage = named_artifact("src/lib.rs", &format!("postimage:{mutation_id}"), 120);
    let witness_source = named_artifact(
        "tests/guard_witnesses.rs",
        &format!("witness:{mutation_id}"),
        96,
    );
    let selector = check_id.split_once("::").map_or(check_id, |(_, tail)| tail);
    let baseline_command = CommandSpec {
        program: "$BASELINE/target/debug/deps/guard_witnesses-a1".into(),
        args: vec![selector.into(), "--exact".into()],
        environment_allowlist: Vec::new(),
    };
    let mutant_command = CommandSpec {
        program: "$MUTANT/target/debug/deps/guard_witnesses-b2".into(),
        ..baseline_command.clone()
    };
    record.provenance.commands = vec![baseline_command, mutant_command];
    record.provenance.runs = vec![
        ExecutionRun {
            command_index: 0,
            exit_code: Some(0),
            stdout_sha256: digest("baseline-stdout"),
            stderr_sha256: digest("baseline-stderr"),
            normalized_output_sha256: digest("baseline-normalized"),
            output_truncated: false,
            duration_ms: 1,
        },
        ExecutionRun {
            command_index: 1,
            exit_code: Some(101),
            stdout_sha256: digest("mutant-stdout"),
            stderr_sha256: digest("mutant-stderr"),
            normalized_output_sha256: digest("mutant-normalized"),
            output_truncated: false,
            duration_ms: 1,
        },
    ];
    record.provenance.input_artifacts.extend([
        registry.clone(),
        target_preimage.clone(),
        mutant_artifact.clone(),
        witness_source.clone(),
    ]);
    record
        .provenance
        .generated_artifacts
        .push(target_postimage.clone());
    record.inventoried_targets = BTreeSet::from([mutation_id.to_owned()]);
    let mut witness = MutationWitnessEvidence {
        schema: crate::MUTATION_WITNESS_SCHEMA_V2.into(),
        mutation_id: mutation_id.into(),
        subject: "rust:crate::decide".into(),
        guard: "the registered guard remains enforced".into(),
        mutation_sha256: digest("placeholder"),
        registry,
        target_preimage,
        mutant_artifact,
        target_postimage,
        witness_source,
        check_id: check_id.into(),
        baseline_run_index: 0,
        expected_failure: ExpectedFailure {
            run_index: 1,
            allowed_exit_codes: BTreeSet::from([101]),
        },
        proof_term_theorem,
    };
    witness.mutation_sha256 = witness.derived_mutation_sha256(&record.claims).unwrap();
    record.mutation_witness = Some(witness);
}

fn node_mutation_record() -> EvidenceRecord {
    let mut record = basic_record(
        "node-mutation",
        EvidenceKind::MutationWitness,
        "tests:node-mutation",
    );
    let check_id = "src/guard.test.ts::guard > rejects invalid input";
    attach_mutation_witness(&mut record, "node-mutation", check_id, None);
    record.provenance.input_artifacts.extend([
        named_artifact("package-lock.json", "node-lock", 128),
        named_artifact("package.json", "node-package", 64),
    ]);
    let args = vec![
        "run".into(),
        "src/guard.test.ts".into(),
        "--reporter=json".into(),
        "--testNamePattern".into(),
        "^guard rejects invalid input$".into(),
    ];
    record.provenance.commands = vec![
        CommandSpec {
            program: "node_modules/.bin/vitest".into(),
            args: args.clone(),
            environment_allowlist: Vec::new(),
        },
        CommandSpec {
            program: "node_modules/.bin/vitest".into(),
            args,
            environment_allowlist: Vec::new(),
        },
    ];
    record.provenance.runs[1].exit_code = Some(1);
    let claims = record.claims.clone();
    let witness = record.mutation_witness.as_mut().unwrap();
    witness.subject = "npm:fixture::guard".into();
    witness.expected_failure.allowed_exit_codes = BTreeSet::from([1]);
    witness.mutation_sha256 = witness.derived_mutation_sha256(&claims).unwrap();
    record
}

fn python_mutation_record() -> EvidenceRecord {
    let mut record = basic_record(
        "python-mutation",
        EvidenceKind::MutationWitness,
        "tests:python-mutation",
    );
    let check_id = "tests/test_guard.py::test_guard";
    attach_mutation_witness(&mut record, "python-mutation", check_id, None);
    let command = |root: &str| CommandSpec {
        program: "python3".into(),
        args: vec![
            "-m".into(),
            "pytest".into(),
            "-p".into(),
            "no:cacheprovider".into(),
            "--rootdir".into(),
            root.into(),
            "-q".into(),
            format!("{root}/{check_id}"),
        ],
        environment_allowlist: Vec::new(),
    };
    record.provenance.commands = vec![command("$BASELINE"), command("$MUTANT")];
    record.provenance.runs[1].exit_code = Some(1);
    let claims = record.claims.clone();
    let witness = record.mutation_witness.as_mut().unwrap();
    witness.subject = "python:fixture::guard.check".into();
    witness.expected_failure.allowed_exit_codes = BTreeSet::from([1]);
    witness.mutation_sha256 = witness.derived_mutation_sha256(&claims).unwrap();
    record
}

fn lean_string(value: &str) -> serde_json::Value {
    serde_json::json!([7, [1, value]])
}

fn lean_app(function: serde_json::Value, argument: serde_json::Value) -> serde_json::Value {
    serde_json::json!([3, function, argument])
}

fn binding_statement(claim: &ClaimId, artifact: &ArtifactIdentity) -> serde_json::Value {
    let mut root = serde_json::json!([2, crate::ARTIFACT_DIGEST_BINDING_MARKER_V1, []]);
    for argument in [
        lean_string(claim.as_str()),
        lean_string("example-artifact/1"),
        lean_string(artifact.logical_name.as_str()),
        lean_string(&format!("sha256:{}", artifact.sha256)),
        serde_json::json!([2, "Demo.bytes", []]),
        serde_json::json!([2, "Demo.meaning", []]),
    ] {
        root = lean_app(root, argument);
    }
    serde_json::json!([crate::LEAN_STATEMENT_ENCODING_V1, root])
}

fn provenance(label: &str) -> EvidenceProvenance {
    let command = CommandSpec {
        program: "proof-tool".into(),
        args: vec!["--unit".into(), label.into()],
        environment_allowlist: vec![EnvironmentVariable {
            name: EnvironmentVariableName::new("LANG").unwrap(),
            value_sha256: Some(digest("C")),
            secret: false,
        }],
    };
    EvidenceProvenance {
        project_revision: "0123456789012345678901234567890123456789".into(),
        tree_state: TreeState::Clean,
        semantic_source_closure: digest("source"),
        additional_closures: vec![],
        input_artifacts: vec![],
        generated_artifacts: vec![],
        tool: ToolIdentity {
            name: "tool".into(),
            version: "1.0.0".into(),
            identity_sha256: digest("tool"),
        },
        adapter: ToolIdentity {
            name: "adapter".into(),
            version: "1.0.0".into(),
            identity_sha256: digest("adapter"),
        },
        execution_kind: ExecutionKind::ObservedProcesses,
        commands: vec![command.clone()],
        runs: vec![ExecutionRun {
            command_index: 0,
            exit_code: Some(0),
            stdout_sha256: digest(&format!("stdout:{label}")),
            stderr_sha256: digest(&format!("stderr:{label}")),
            normalized_output_sha256: digest(&format!("normalized:{label}")),
            output_truncated: false,
            duration_ms: 10,
        }],
        normalization: "proofbound-output/1".into(),
        reproduction_command: command,
        started_unix_ms: 10,
        completed_unix_ms: 20,
        deterministic_result_identity: digest(label),
        unit_configuration_sha256: digest(&format!("config:{label}")),
        resource_budget: ResourceBudget::default(),
        resource_usage: ResourceUsage::default(),
        cache_origin: CacheOrigin::Executed,
        prior_receipt_sha256: None,
        python_plugins: Vec::new(),
    }
}

fn ledger_policy() -> PolicyDefinition {
    PolicyDefinition::ledger(PolicyId::new("tier-0-ledger").unwrap())
}

fn builtin(profile: BuiltInProfile) -> PolicyDefinition {
    PolicyDefinition::built_in(profile, BTreeSet::new(), BTreeSet::new()).unwrap()
}

fn base_input(tier: Tier, policy: PolicyDefinition) -> ClaimEvaluationInput {
    let claim_node = NodeId::new("claim:one").unwrap();
    let subject_node = NodeId::new("subject:one").unwrap();
    ClaimEvaluationInput {
        project_tier: tier,
        claim: ClaimDefinition {
            schema: CLAIM_SCHEMA_V1.into(),
            id: claim_id(),
            node_id: claim_node.clone(),
            title: "A precise claim".into(),
            statement: "The registered subject has property P.".into(),
            public_language: None,
            subject: subject_node.clone(),
            policy: policy.id.clone(),
            tier: None,
            cited_evidence: BTreeSet::new(),
            assumptions: BTreeSet::new(),
            open_obligations: BTreeSet::new(),
            out_of_scope: BTreeSet::new(),
            primary_linkage: None,
            registered_inputs: BTreeSet::from(["all".into()]),
            registered_domain_language: None,
        },
        graph: AssuranceGraph {
            schema: GRAPH_SCHEMA_V1.into(),
            nodes: vec![
                GraphNode {
                    id: claim_node,
                    kind: NodeKind::Claim,
                    proof_environment: None,
                },
                GraphNode {
                    id: subject_node,
                    kind: NodeKind::Subject,
                    proof_environment: None,
                },
                GraphNode {
                    id: policy.node_id.clone(),
                    kind: NodeKind::Policy,
                    proof_environment: None,
                },
            ],
            edges: vec![],
            mutual_theorem_groups: vec![],
        },
        policy,
        evidence: vec![],
        assumptions: vec![],
        premises: vec![],
    }
}

fn basic_record(id: &str, kind: EvidenceKind, node_id: &str) -> EvidenceRecord {
    EvidenceRecord {
        schema: crate::EVIDENCE_SCHEMA_V3.into(),
        id: EvidenceId::new(id).unwrap(),
        node_id: NodeId::new(node_id).unwrap(),
        unit_id: UnitId::new(format!("unit:{id}")).unwrap(),
        kind,
        status: EvidenceStatus::Passed,
        claims: BTreeSet::from([claim_id()]),
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
        inventoried_targets: BTreeSet::from([format!("{id}::registered")]),
        assumptions: BTreeSet::new(),
        premises: BTreeSet::new(),
        open_obligation: None,
        provenance: provenance(id),
    }
}

fn add_record(
    input: &mut ClaimEvaluationInput,
    record: EvidenceRecord,
    node_kind: NodeKind,
    cite: bool,
) {
    let environment =
        (node_kind == NodeKind::Theorem).then(|| EnvironmentId::new("lean:main").unwrap());
    input.graph.nodes.push(GraphNode {
        id: record.node_id.clone(),
        kind: node_kind,
        proof_environment: environment,
    });
    if cite {
        input.claim.cited_evidence.insert(record.id.clone());
    }
    input.evidence.push(record);
}

fn checked_graph_edge(
    input: &ClaimEvaluationInput,
    from: &NodeId,
    to: &NodeId,
    kind: EdgeKind,
) -> GraphEdge {
    GraphEdge::checked(
        input.graph.node(from).expect("from node is registered"),
        input.graph.node(to).expect("to node is registered"),
        kind,
    )
    .expect("test edge has legal endpoint kinds")
}

fn raw_graph_edge(from: &NodeId, to: &NodeId, kind: EdgeKind) -> GraphEdge {
    serde_json::from_value(serde_json::json!({
        "from": from,
        "to": to,
        "kind": kind,
    }))
    .expect("raw adversarial edge deserializes")
}

fn example_record(id: &str) -> EvidenceRecord {
    let mut record = basic_record(id, EvidenceKind::ExampleTest, &format!("tests:{id}"));
    record
        .inventoried_targets
        .insert("tests::registered".into());
    record
}

fn theorem_record(id: &str, mode: crate::EvaluationMode) -> EvidenceRecord {
    let mut record = basic_record(id, EvidenceKind::Theorem, &format!("theorem:{id}"));
    record.evaluation_mode = Some(mode);
    let statement_wire = binding_statement(&claim_id(), &bound_artifact());
    let declaration = format!("Proofbound.Tests.{id}");
    record.inventoried_targets = BTreeSet::from([declaration.clone()]);
    record.theorem = Some(TheoremEvidence {
        declaration,
        statement_encoding: "lean-expr-cbor/1".into(),
        statement_sha256: crate::lean_statement_wire_digest(&statement_wire).unwrap(),
        statement_wire,
        attributed_claim: claim_id(),
        environment: EnvironmentId::new("lean:main").unwrap(),
        axiom_audit_passed: true,
        contains_sorry_ax: false,
        foundational_axioms: BTreeSet::new(),
        project_axioms: BTreeSet::new(),
    });
    record
}

fn domain() -> BoundedDomain {
    BoundedDomain {
        id: UnitId::new("domain:u8").unwrap(),
        description: "all values x where 0 <= x <= 255".into(),
        registration_sha256: digest("domain"),
        cardinality: Some(256),
        constraints: vec!["x <= 255".into()],
    }
}

fn bounded_record(id: &str) -> EvidenceRecord {
    let mut record = basic_record(id, EvidenceKind::BoundedCheck, &format!("model:{id}"));
    record.inventoried_targets = BTreeSet::from(["check_all".into()]);
    record.bounded_check = Some(BoundedCheckEvidence {
        domain: domain(),
        solver: "cadical 2".into(),
        harnesses: BTreeSet::from(["check_all".into()]),
        unwind_bounds: BTreeMap::from([("check_all".into(), 256)]),
        assumptions: vec![],
    });
    record
}

fn exhaustive_record(id: &str) -> EvidenceRecord {
    let mut record = basic_record(id, EvidenceKind::ExhaustiveCheck, &format!("model:{id}"));
    record.exhaustive_check = Some(ExhaustiveCheckEvidence {
        domain: domain(),
        evaluated_members: 256,
    });
    record
}

fn review_record(id: &str) -> EvidenceRecord {
    basic_record(id, EvidenceKind::Review, &format!("review:{id}"))
}

fn assumption_record(
    id: &str,
    review: &EvidenceId,
    category: AssumptionCategory,
) -> AssumptionRecord {
    AssumptionRecord {
        schema: ASSUMPTION_SCHEMA_V1.into(),
        id: AssumptionId::new(id).unwrap(),
        node_id: NodeId::new(format!("assumption:{id}")).unwrap(),
        statement: "The external boundary behaves as stated.".into(),
        category,
        owner: "proof-team".into(),
        rationale: "The provider is outside the theorem boundary.".into(),
        scope: "this claim".into(),
        affected_claims: BTreeSet::from([claim_id()]),
        review_evidence: BTreeSet::from([review.clone()]),
        falsification_or_discharge_plan: "Replace it with a checked boundary.".into(),
        source_citation: None,
        status: AssumptionStatus::Active,
        depends_on: BTreeSet::new(),
    }
}

fn add_assumption(
    input: &mut ClaimEvaluationInput,
    id: &str,
    category: AssumptionCategory,
) -> AssumptionId {
    let review = review_record(&format!("review-{id}"));
    let review_id = review.id.clone();
    add_record(input, review, NodeKind::Review, false);
    let assumption = assumption_record(id, &review_id, category);
    let assumption_id = assumption.id.clone();
    input.graph.nodes.push(GraphNode {
        id: assumption.node_id.clone(),
        kind: NodeKind::Assumption,
        proof_environment: None,
    });
    input.assumptions.push(assumption);
    assumption_id
}

#[test]
fn empty_ledger_is_open_model_only_and_has_mandatory_gap_section() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    input.claim.open_obligations.insert(OpenObligation {
        id: crate::ObligationId::new("OPEN-1").unwrap(),
        statement: "Universal behavior is not established.".into(),
        remediation: "Add bounded or formal evidence.".into(),
    });
    input.claim.out_of_scope.insert(OutOfScope {
        id: crate::ObligationId::new("SCOPE-1").unwrap(),
        statement: "The operating system schedules fairly.".into(),
        rationale: "Runtime scheduling is outside this claim.".into(),
    });
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Open);
    assert_eq!(status.linkage, Some(LinkageFacet::ModelOnly));
    assert_eq!(status.assumption.standing, AssumptionStanding::None);
    assert_eq!(status.not_proved_out_of_scope.open_obligations.len(), 1);
    assert_eq!(status.not_proved_out_of_scope.exclusions.len(), 1);
    assert!(status.policy.admitted);
}

#[test]
fn empirical_bounded_and_theorem_precedence_is_exact_and_retains_weaker_evidence() {
    let mut input = base_input(Tier::Model, builtin(BuiltInProfile::Kernel));
    add_record(
        &mut input,
        example_record("tests"),
        NodeKind::TestSuite,
        true,
    );
    input.claim.registered_domain_language = Some("For every u8 input, P holds.".into());
    add_record(
        &mut input,
        bounded_record("kani"),
        NodeKind::ModelCheckUnit,
        true,
    );
    add_record(
        &mut input,
        theorem_record("proof", crate::EvaluationMode::Kernel),
        NodeKind::Theorem,
        true,
    );
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert!(status.policy.admitted);
    assert_eq!(status.evidence.len(), 3);
    assert!(
        status
            .evidence
            .iter()
            .any(|item| item.kind == EvidenceKind::ExampleTest)
    );
}

#[test]
fn exhaustive_is_tested_unless_policy_explicitly_admits_finite_proof() {
    let mut default = base_input(Tier::Bounded, ledger_policy());
    default.claim.registered_domain_language =
        Some("For every registered u8 value, P holds.".into());
    add_record(
        &mut default,
        exhaustive_record("all-u8"),
        NodeKind::ModelCheckUnit,
        true,
    );
    assert_eq!(derive_claim_status(&default).formal, FormalFacet::Tested);

    let policy = PolicyDefinition {
        schema: POLICY_SCHEMA_V1.into(),
        id: PolicyId::new("finite-exhaustion").unwrap(),
        node_id: NodeId::new("policy:finite-exhaustion").unwrap(),
        components: BTreeSet::new(),
        allowed_foundational_axioms: BTreeSet::new(),
        allowed_project_axioms: BTreeSet::new(),
        admit_exhaustive_as_proved: true,
        require_no_assumptions: false,
        native_premise_rule: None,
        additional_required_evidence: BTreeSet::new(),
    };
    let mut admitted = base_input(Tier::Bounded, policy);
    admitted.claim.registered_domain_language =
        Some("For every registered u8 value, P holds.".into());
    add_record(
        &mut admitted,
        exhaustive_record("all-u8"),
        NodeKind::ModelCheckUnit,
        true,
    );
    let status = derive_claim_status(&admitted);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(
        status.public_statement,
        "The registered subject has property P. Registered finite domain: For every registered u8 value, P holds."
    );
}

#[test]
fn bounded_public_statement_retains_property_and_registered_domain() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Bounded));
    input.claim.registered_domain_language = Some("For every registered u8 value, P holds.".into());
    add_record(
        &mut input,
        bounded_record("kani"),
        NodeKind::ModelCheckUnit,
        true,
    );

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::BoundedChecked);
    assert_eq!(
        status.public_statement,
        "The registered subject has property P. Registered finite domain: For every registered u8 value, P holds."
    );

    input.claim.statement = "The registered subject has a different property Q.".into();
    let changed = derive_claim_status(&input);
    assert_ne!(changed.public_statement, status.public_statement);
    assert!(changed.public_statement.starts_with(&input.claim.statement));
}

#[test]
fn public_language_is_reader_facing_without_replacing_the_internal_statement() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Bounded));
    input.claim.statement = "Internal.Predicate subject".into();
    input.claim.public_language = Some("Every registered byte has property P.".into());
    input.claim.registered_domain_language = Some("Inputs are exactly the u8 domain.".into());
    add_record(
        &mut input,
        bounded_record("kani"),
        NodeKind::ModelCheckUnit,
        true,
    );

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::BoundedChecked);
    assert_eq!(
        status.public_statement,
        "Every registered byte has property P. Registered finite domain: Inputs are exactly the u8 domain."
    );
    assert_eq!(input.claim.statement, "Internal.Predicate subject");
    let encoded = serde_json::to_value(&input.claim).unwrap();
    assert_eq!(encoded["statement"], "Internal.Predicate subject");
    assert_eq!(
        encoded["public_language"],
        "Every registered byte has property P."
    );
}

#[test]
fn bounded_check_requires_exact_nonzero_unwind_inventory() {
    let mut extra = bounded_record("kani");
    extra
        .bounded_check
        .as_mut()
        .unwrap()
        .unwind_bounds
        .insert("undeclared".into(), 1);

    let mut missing = bounded_record("kani");
    missing
        .bounded_check
        .as_mut()
        .unwrap()
        .unwind_bounds
        .clear();

    let mut zero = bounded_record("kani");
    zero.bounded_check
        .as_mut()
        .unwrap()
        .unwind_bounds
        .insert("check_all".into(), 0);

    for record in [extra, missing, zero] {
        let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Bounded));
        input.claim.registered_domain_language =
            Some("For every registered u8 value, P holds.".into());
        add_record(&mut input, record, NodeKind::ModelCheckUnit, true);
        assert_eq!(derive_claim_status(&input).formal, FormalFacet::Invalid);
    }
}

#[test]
fn bounded_check_assumptions_are_nonblank_and_unique() {
    let mut valid = bounded_record("kani");
    valid.bounded_check.as_mut().unwrap().assumptions = vec![
        "pointer width is 64 bits".into(),
        "allocator succeeds".into(),
    ];
    assert!(valid.validate(&claim_id()).is_ok());

    let mut blank = valid.clone();
    blank
        .bounded_check
        .as_mut()
        .unwrap()
        .assumptions
        .push("  ".into());
    assert!(blank.validate(&claim_id()).is_err());

    let mut duplicate = valid;
    duplicate.bounded_check.as_mut().unwrap().assumptions =
        vec!["allocator succeeds".into(), "allocator succeeds".into()];
    assert!(duplicate.validate(&claim_id()).is_err());

    let mut oversized_entry = bounded_record("kani");
    oversized_entry.bounded_check.as_mut().unwrap().assumptions = vec!["x".repeat(4097)];
    assert!(oversized_entry.validate(&claim_id()).is_err());

    let mut oversized_inventory = bounded_record("kani");
    oversized_inventory
        .bounded_check
        .as_mut()
        .unwrap()
        .assumptions = (0..4097)
        .map(|index| format!("assumption {index}"))
        .collect();
    assert!(oversized_inventory.validate(&claim_id()).is_err());
}

#[test]
fn unknown_peak_memory_is_distinct_from_measured_zero() {
    let mut provenance = provenance("memory");
    provenance.resource_budget.memory_bytes = 0;
    provenance.resource_usage.peak_memory_bytes = None;
    assert!(!provenance.exceeded_budget());
    assert_eq!(
        serde_json::to_value(&provenance.resource_usage).unwrap()["peak_memory_bytes"],
        serde_json::Value::Null
    );

    provenance.resource_usage.peak_memory_bytes = Some(0);
    assert!(!provenance.exceeded_budget());
    assert_eq!(
        serde_json::to_value(&provenance.resource_usage).unwrap()["peak_memory_bytes"],
        0
    );

    provenance.resource_usage.peak_memory_bytes = Some(1);
    assert!(provenance.exceeded_budget());
}

#[test]
fn multi_command_provenance_rejects_index_drift_truncation_and_incomplete_passes() {
    let mut valid = example_record("multi");
    let second_command = CommandSpec {
        program: "proof-tool".into(),
        args: vec!["--second".into()],
        environment_allowlist: vec![],
    };
    valid.provenance.commands.push(second_command);
    valid.provenance.runs.push(ExecutionRun {
        command_index: 1,
        exit_code: Some(0),
        stdout_sha256: digest("stdout:second"),
        stderr_sha256: digest("stderr:second"),
        normalized_output_sha256: digest("normalized:second"),
        output_truncated: false,
        duration_ms: 2,
    });
    assert!(valid.validate(&claim_id()).is_ok());

    let mut wrong_index = valid.clone();
    wrong_index.provenance.runs[1].command_index = 0;
    assert!(wrong_index.validate(&claim_id()).is_err());

    let mut truncated = valid.clone();
    truncated.provenance.runs[1].output_truncated = true;
    assert!(truncated.validate(&claim_id()).is_err());

    let mut incomplete = valid.clone();
    incomplete.provenance.runs[1].exit_code = None;
    assert!(incomplete.validate(&claim_id()).is_err());

    let mut nonzero = valid.clone();
    nonzero.provenance.runs[1].exit_code = Some(1);
    assert!(nonzero.validate(&claim_id()).is_err());

    let mut empty_inventory = valid.clone();
    empty_inventory.inventoried_targets.clear();
    assert!(empty_inventory.validate(&claim_id()).is_err());

    let mut controlled_inventory = valid.clone();
    controlled_inventory
        .inventoried_targets
        .insert("tests::bad\nname".into());
    assert!(controlled_inventory.validate(&claim_id()).is_err());

    let mut missing_run = valid.clone();
    missing_run.provenance.runs.pop();
    assert!(missing_run.validate(&claim_id()).is_err());

    let mut blank_normalization = valid.clone();
    blank_normalization.provenance.normalization = "  ".into();
    assert!(blank_normalization.validate(&claim_id()).is_err());

    let mut oversized_normalization = valid.clone();
    oversized_normalization.provenance.normalization = "x".repeat(1025);
    assert!(oversized_normalization.validate(&claim_id()).is_err());

    let mut shell = valid.clone();
    shell.provenance.commands[0].program = "/bin/sh".into();
    assert!(shell.validate(&claim_id()).is_err());

    let mut duplicate_environment = valid;
    let duplicate = duplicate_environment.provenance.commands[0].environment_allowlist[0].clone();
    duplicate_environment.provenance.commands[0]
        .environment_allowlist
        .push(duplicate);
    assert!(duplicate_environment.validate(&claim_id()).is_err());
}

#[test]
fn distribution_reproduction_requires_two_exact_registered_candidates() {
    let mut valid = example_record("wheel");
    let artifact_sha256 = digest("wheel-bytes");
    valid.inventoried_targets = BTreeSet::from(["dist/package.whl".into()]);
    valid.provenance.generated_artifacts = vec![
        ArtifactIdentity {
            logical_name: ArtifactLogicalName::new("distribution/wheel/candidate-1").unwrap(),
            sha256: artifact_sha256,
            size_bytes: 64,
        },
        ArtifactIdentity {
            logical_name: ArtifactLogicalName::new("distribution/wheel/candidate-2").unwrap(),
            sha256: artifact_sha256,
            size_bytes: 64,
        },
    ];
    valid.distribution_reproduction = Some(crate::DistributionReproductionEvidence {
        schema: crate::DISTRIBUTION_REPRODUCTION_SCHEMA_V1.into(),
        format: "wheel".into(),
        run_digests: vec![artifact_sha256, artifact_sha256],
        registered_digest: artifact_sha256,
        source_date_epoch: 315_532_800,
        build_backend_name: "hatchling".into(),
        build_backend_version: "1.27.0".into(),
        npm_integrity: None,
        member_inventory: vec!["package/__init__.py".into(), "package/py.typed".into()],
    });
    assert!(valid.validate(&claim_id()).is_ok());

    let mut drifted = valid.clone();
    drifted
        .distribution_reproduction
        .as_mut()
        .unwrap()
        .run_digests[1] = digest("drifted");
    assert!(drifted.validate(&claim_id()).is_err());

    let mut extra = valid;
    extra.provenance.generated_artifacts.push(ArtifactIdentity {
        logical_name: ArtifactLogicalName::new("distribution/wheel/candidate-3").unwrap(),
        sha256: digest("wheel-bytes"),
        size_bytes: 64,
    });
    assert!(extra.validate(&claim_id()).is_err());

    let mut npm = example_record("npm-package");
    let npm_digest = digest("npm-package-bytes");
    npm.inventoried_targets = BTreeSet::from(["fixture-1.0.0.tgz".into()]);
    npm.provenance.generated_artifacts = vec![
        ArtifactIdentity {
            logical_name: ArtifactLogicalName::new("distribution/npm-package/candidate-1").unwrap(),
            sha256: npm_digest,
            size_bytes: 64,
        },
        ArtifactIdentity {
            logical_name: ArtifactLogicalName::new("distribution/npm-package/candidate-2").unwrap(),
            sha256: npm_digest,
            size_bytes: 64,
        },
    ];
    npm.distribution_reproduction = Some(crate::DistributionReproductionEvidence {
        schema: crate::DISTRIBUTION_REPRODUCTION_SCHEMA_V1.into(),
        format: "npm-package".into(),
        run_digests: vec![npm_digest, npm_digest],
        registered_digest: npm_digest,
        source_date_epoch: 0,
        build_backend_name: "npm".into(),
        build_backend_version: "10.9.0".into(),
        npm_integrity: Some("sha512-Zml4dHVyZQ==".into()),
        member_inventory: vec!["package.json".into(), "src/index.ts".into()],
    });
    assert!(npm.validate(&claim_id()).is_ok());

    let mut missing_integrity = npm;
    missing_integrity
        .distribution_reproduction
        .as_mut()
        .unwrap()
        .npm_integrity = None;
    assert!(missing_integrity.validate(&claim_id()).is_err());
}

#[test]
fn bounded_check_requires_public_finite_domain_language() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Bounded));
    add_record(
        &mut input,
        bounded_record("kani"),
        NodeKind::ModelCheckUnit,
        true,
    );
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(
        status
            .errors
            .iter()
            .any(|error| { error.message.contains("finite-domain public language") })
    );
}

#[test]
fn every_nonpassing_cited_state_is_invalid() {
    for state in [
        EvidenceStatus::Failed,
        EvidenceStatus::Missing,
        EvidenceStatus::Drifted,
        EvidenceStatus::Unregistered,
        EvidenceStatus::Ambiguous,
        EvidenceStatus::Corrupt,
        EvidenceStatus::Skipped,
        EvidenceStatus::Unavailable,
    ] {
        let mut input = base_input(Tier::Ledger, ledger_policy());
        let mut record = example_record("tests");
        record.status = state;
        add_record(&mut input, record, NodeKind::TestSuite, true);
        assert_eq!(
            derive_claim_status(&input).formal,
            FormalFacet::Invalid,
            "state {state:?}"
        );
    }
}

#[test]
fn absent_citation_and_ungated_discovery_both_fail_closed() {
    let mut missing = base_input(Tier::Ledger, ledger_policy());
    missing
        .claim
        .cited_evidence
        .insert(EvidenceId::new("missing").unwrap());
    assert_eq!(derive_claim_status(&missing).formal, FormalFacet::Invalid);

    let mut discovered = base_input(Tier::Ledger, ledger_policy());
    add_record(
        &mut discovered,
        example_record("ungated"),
        NodeKind::TestSuite,
        false,
    );
    let status = derive_claim_status(&discovered);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::PbCoreEvidenceUnregistered)
    );
}

#[test]
fn tier_ceiling_rejects_stronger_evidence() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    add_record(
        &mut input,
        bounded_record("kani"),
        NodeKind::ModelCheckUnit,
        true,
    );
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::PbCoreTierExceeded)
    );
}

#[test]
fn hidden_affected_assumption_is_still_enumerated() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let assumption_id = add_assumption(
        &mut input,
        "EXTERNAL-1",
        AssumptionCategory::ExternalProvider,
    );
    assert!(!input.claim.assumptions.contains(&assumption_id));
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Open);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert_eq!(status.assumption.assumptions[0].id, assumption_id);
    assert_eq!(status.not_proved_out_of_scope.explicit_assumptions.len(), 1);
}

#[test]
fn manually_marking_an_assumption_discharged_cannot_upgrade_status() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let assumption_id = add_assumption(
        &mut input,
        "EXTERNAL-DISCHARGED",
        AssumptionCategory::ExternalProvider,
    );
    input
        .assumptions
        .iter_mut()
        .find(|record| record.id == assumption_id)
        .unwrap()
        .status = AssumptionStatus::Discharged;
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::PbCoreInvalidDischarge)
    );
}

#[test]
fn inadmissible_theorem_falls_back_to_tests_but_cannot_satisfy_kernel_policy() {
    let mut input = base_input(Tier::Model, builtin(BuiltInProfile::Kernel));
    let mut theorem = theorem_record("native", crate::EvaluationMode::Native);
    theorem.evaluation_mode = Some(crate::EvaluationMode::Native);
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    add_record(
        &mut input,
        example_record("tests"),
        NodeKind::TestSuite,
        true,
    );
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Tested);
    assert!(!status.policy.admitted);
    assert!(status.evidence.iter().any(|assessment| {
        assessment.kind == EvidenceKind::Theorem && !assessment.policy_admitted
    }));
}

#[test]
fn source_refinement_premise_is_assumed_until_scoped_policy_admitted_discharge() {
    let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::SourceRefined));
    let proof = theorem_record("refinement-proof", crate::EvaluationMode::Kernel);
    let proof_id = proof.id.clone();
    let proof_node = proof.node_id.clone();
    add_record(&mut input, proof, NodeKind::Theorem, true);

    let premise_id = PremiseId::new("PREMISE-VALID").unwrap();
    let premise_node = NodeId::new("premise:valid").unwrap();
    let mut refinement = basic_record(
        "translation",
        EvidenceKind::SourceRefinement,
        "translation:kernel",
    );
    refinement.premises.insert(premise_id.clone());
    refinement.source_refinement = Some(SourceRefinementEvidence {
        refinement_theorem: proof_id.clone(),
        representation_premises: BTreeSet::from([premise_id.clone()]),
        deterministic_translation: true,
        pinned_toolchain: true,
        generated_axioms_clean: true,
        adapter_strength: AdapterStrength::DecisionAdequate,
    });
    add_record(&mut input, refinement, NodeKind::TranslationUnit, true);
    input.graph.nodes.push(GraphNode {
        id: premise_node.clone(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    let edge = checked_graph_edge(&input, &proof_node, &premise_node, EdgeKind::Assumes);
    input.graph.edges.push(edge);
    input.premises.push(PremiseRecord {
        id: premise_id,
        node_id: premise_node.clone(),
        statement: "The decoded carrier is valid.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: Some(proof_id),
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });

    let assumed = derive_claim_status(&input);
    assert_eq!(assumed.formal, FormalFacet::Proved);
    assert_eq!(assumed.linkage, Some(LinkageFacet::Refined));
    assert_eq!(assumed.assumption.standing, AssumptionStanding::Assumed);
    assert!(assumed.policy.admitted);

    let discharge = theorem_record("decoder-proof", crate::EvaluationMode::Kernel);
    let discharge_id = discharge.id.clone();
    let discharge_node = discharge.node_id.clone();
    add_record(&mut input, discharge, NodeKind::Theorem, false);
    input.premises[0].discharge = Some(crate::PremiseDischarge {
        theorem_evidence: discharge_id.clone(),
        scope: FlowScope::AllRegisteredInputs,
    });
    let edge = checked_graph_edge(
        &input,
        &premise_node,
        &discharge_node,
        EdgeKind::DischargedBy,
    );
    input.graph.edges.push(edge);
    let discharged = derive_claim_status(&input);
    assert_eq!(discharged.formal, FormalFacet::Proved);
    assert_eq!(discharged.assumption.standing, AssumptionStanding::None);
    assert_eq!(discharged.premises[0].discharged_by, Some(discharge_id));
    assert!(
        discharged
            .not_proved_out_of_scope
            .undischarged_premises
            .is_empty()
    );
}

#[test]
fn directly_registered_premise_cannot_disappear_without_an_evidence_reference() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let premise_id = PremiseId::new("PREMISE-DIRECT").unwrap();
    let premise_node = NodeId::new("premise:direct").unwrap();
    input.graph.nodes.push(GraphNode {
        id: premise_node.clone(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    let edge = checked_graph_edge(
        &input,
        &input.claim.node_id,
        &premise_node,
        EdgeKind::Assumes,
    );
    input.graph.edges.push(edge);
    input.premises.push(PremiseRecord {
        id: premise_id.clone(),
        node_id: premise_node,
        statement: "The registered external representation is faithful.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: None,
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });

    let status = derive_claim_status(&input);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert_eq!(status.assumption.undischarged_premises.len(), 1);
    assert_eq!(status.assumption.undischarged_premises[0].id, premise_id);
    assert_eq!(
        status.not_proved_out_of_scope.undischarged_premises.len(),
        1
    );
}

#[test]
fn ownerless_premise_requires_the_exact_claim_assumes_edge() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let premise_id = PremiseId::new("PREMISE-DIRECT").unwrap();
    let premise_node = NodeId::new("premise:direct").unwrap();
    input.graph.nodes.push(GraphNode {
        id: premise_node.clone(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    // An `assumes` edge from another node must not stand in for direct claim
    // ownership.
    input.graph.edges.push(raw_graph_edge(
        &input.claim.subject,
        &premise_node,
        EdgeKind::Assumes,
    ));
    input.premises.push(PremiseRecord {
        id: premise_id.clone(),
        node_id: premise_node,
        statement: "The external representation is faithful.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: None,
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert_eq!(status.assumption.undischarged_premises.len(), 1);
    assert_eq!(status.assumption.undischarged_premises[0].id, premise_id);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("no exact claim-to-premise assumes edge")
    }));
}

#[test]
fn ownerless_direct_premise_cannot_be_discharged_or_promote_the_claim() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let mut discharge = theorem_record("direct-discharge", crate::EvaluationMode::Kernel);
    discharge.claims.clear();
    let discharge_id = discharge.id.clone();
    let discharge_node = discharge.node_id.clone();
    add_record(&mut input, discharge, NodeKind::Theorem, false);

    let premise_id = PremiseId::new("PREMISE-DIRECT").unwrap();
    let premise_node = NodeId::new("premise:direct").unwrap();
    input.graph.nodes.push(GraphNode {
        id: premise_node.clone(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    let claim_assumes = checked_graph_edge(
        &input,
        &input.claim.node_id,
        &premise_node,
        EdgeKind::Assumes,
    );
    let discharged_by = checked_graph_edge(
        &input,
        &premise_node,
        &discharge_node,
        EdgeKind::DischargedBy,
    );
    input.graph.edges.extend([claim_assumes, discharged_by]);
    input.premises.push(PremiseRecord {
        id: premise_id.clone(),
        node_id: premise_node,
        statement: "The external representation is faithful.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: None,
        scope: FlowScope::AllRegisteredInputs,
        discharge: Some(crate::PremiseDischarge {
            theorem_evidence: discharge_id,
            scope: FlowScope::AllRegisteredInputs,
        }),
    });

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert_eq!(status.assumption.undischarged_premises.len(), 1);
    assert_eq!(status.assumption.undischarged_premises[0].id, premise_id);
    assert!(
        status.assumption.undischarged_premises[0]
            .discharge_rejection_reasons
            .iter()
            .any(|reason| reason.contains("necessarily undischarged"))
    );
}

#[test]
fn missing_discharge_edge_can_only_weaken_status() {
    let mut input = base_input(Tier::Model, builtin(BuiltInProfile::Kernel));
    let main = theorem_record("main", crate::EvaluationMode::Kernel);
    let main_id = main.id.clone();
    add_record(&mut input, main, NodeKind::Theorem, true);
    let discharge = theorem_record("discharge", crate::EvaluationMode::Kernel);
    let discharge_id = discharge.id.clone();
    add_record(&mut input, discharge, NodeKind::Theorem, false);
    let transitive_premise_id = PremiseId::new("PREMISE-TRANSITIVE").unwrap();
    let transitive_premise_node = NodeId::new("premise:transitive").unwrap();
    input
        .evidence
        .iter_mut()
        .find(|record| record.id == discharge_id)
        .unwrap()
        .premises
        .insert(transitive_premise_id.clone());
    input.graph.nodes.push(GraphNode {
        id: transitive_premise_node.clone(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    input.premises.push(PremiseRecord {
        id: transitive_premise_id,
        node_id: transitive_premise_node,
        statement: "The discharge input is canonical.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: Some(discharge_id.clone()),
        scope: FlowScope::AllRegisteredInputs,
        discharge: None,
    });
    let premise_id = PremiseId::new("PREMISE-1").unwrap();
    let premise_node = NodeId::new("premise:one").unwrap();
    input.graph.nodes.push(GraphNode {
        id: premise_node.clone(),
        kind: NodeKind::Premise,
        proof_environment: None,
    });
    input.evidence[0].premises.insert(premise_id.clone());
    input.premises.push(PremiseRecord {
        id: premise_id,
        node_id: premise_node,
        statement: "Input is normalized.".into(),
        category: AssumptionCategory::RepresentationPremise,
        theorem_evidence: Some(main_id),
        scope: FlowScope::AllRegisteredInputs,
        discharge: Some(crate::PremiseDischarge {
            theorem_evidence: discharge_id,
            scope: FlowScope::AllRegisteredInputs,
        }),
    });
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert_eq!(status.assumption.undischarged_premises.len(), 2);
    assert!(
        status
            .premises
            .iter()
            .all(|premise| premise.discharged_by.is_none())
    );
    assert!(status.premises.iter().any(|premise| {
        premise
            .discharge_rejection_reasons
            .iter()
            .any(|reason| reason.contains("no discharged-by edge"))
    }));
}

#[test]
fn trusted_transcription_never_satisfies_artifact_bound() {
    let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::ArtifactBound));
    let theorem = theorem_record("meaning", crate::EvaluationMode::Kernel);
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    let mut transcription = basic_record(
        "transcription",
        EvidenceKind::TrustedTranscription,
        "artifact:transcribed",
    );
    attach_trusted_transcription(&mut transcription, "transcription");
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut input, "transcription");
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(status.linkage, Some(LinkageFacet::Transcribed));
    assert!(!status.policy.admitted);
}

fn register_transcription_tcb_nodes(input: &mut ClaimEvaluationInput, prefix: &str) {
    for suffix in ["transcriber", "reencoder"] {
        input.graph.nodes.push(GraphNode {
            id: NodeId::new(format!("tcb:trusted-transcription:{prefix}:{suffix}")).unwrap(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        });
    }
}

#[test]
fn transcribed_profile_admits_only_derived_transcription_without_a_theorem() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Transcribed));
    let mut transcription = basic_record(
        "profile-transcription",
        EvidenceKind::TrustedTranscription,
        "artifact:profile-transcription",
    );
    attach_trusted_transcription(&mut transcription, "profile-transcription");
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut input, "profile-transcription");

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Open);
    assert_eq!(status.linkage, Some(LinkageFacet::Transcribed));
    assert!(status.policy.admitted);
}

#[test]
fn transcription_content_mismatch_fails_closed() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Transcribed));
    let mut transcription = basic_record(
        "mismatched-transcription",
        EvidenceKind::TrustedTranscription,
        "artifact:mismatched-transcription",
    );
    attach_trusted_transcription(&mut transcription, "mismatched-transcription");
    transcription
        .trusted_transcription
        .as_mut()
        .unwrap()
        .transcribed_candidate
        .size_bytes += 1;
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut input, "mismatched-transcription");

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert_eq!(status.linkage, None);
    assert!(!status.policy.admitted);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("candidate bytes do not match the committed transcription")
    }));
}

#[test]
fn transcription_requires_distinct_derived_tcb_roles() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Transcribed));
    let mut transcription = basic_record(
        "reused-role",
        EvidenceKind::TrustedTranscription,
        "artifact:reused-role",
    );
    attach_trusted_transcription(&mut transcription, "reused-role");
    let detail = transcription.trusted_transcription.as_mut().unwrap();
    detail.reencoder.tcb_node = detail.transcriber.tcb_node.clone();
    detail.reencoder.role_identity = detail.transcriber.role_identity;
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut input, "reused-role");

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("collapses the transcriber and re-encoder TCB roles")
    }));
}

#[test]
fn transcription_role_identity_is_recomputed_from_the_driver() {
    let mut input = base_input(Tier::Bounded, builtin(BuiltInProfile::Transcribed));
    let mut transcription = basic_record(
        "forged-role",
        EvidenceKind::TrustedTranscription,
        "artifact:forged-role",
    );
    attach_trusted_transcription(&mut transcription, "forged-role");
    transcription
        .trusted_transcription
        .as_mut()
        .unwrap()
        .reencoder
        .role_identity = digest("checker-authored-role");
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut input, "forged-role");

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("not derived from the exact registered driver and ABI")
    }));
}

#[test]
fn transcription_rejects_logical_aliases_and_hidden_provenance() {
    let mut alias = base_input(Tier::Bounded, builtin(BuiltInProfile::Transcribed));
    let mut transcription = basic_record(
        "alias",
        EvidenceKind::TrustedTranscription,
        "artifact:alias",
    );
    attach_trusted_transcription(&mut transcription, "alias");
    let generated = {
        let detail = transcription.trusted_transcription.as_mut().unwrap();
        detail.transcribed_candidate.logical_name =
            detail.committed_transcription.logical_name.clone();
        vec![
            detail.transcribed_candidate.clone(),
            detail.reencoded_source.clone(),
        ]
    };
    transcription.provenance.generated_artifacts = generated;
    add_record(&mut alias, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut alias, "alias");
    let status = derive_claim_status(&alias);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.message.contains("aliases two artifact roles"))
    );

    let mut hidden = base_input(Tier::Bounded, builtin(BuiltInProfile::Transcribed));
    let mut transcription = basic_record(
        "hidden",
        EvidenceKind::TrustedTranscription,
        "artifact:hidden",
    );
    attach_trusted_transcription(&mut transcription, "hidden");
    transcription
        .provenance
        .input_artifacts
        .push(named_artifact("hidden/extra", "hidden-extra", 5));
    add_record(&mut hidden, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut hidden, "hidden");
    let status = derive_claim_status(&hidden);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("not the exact three registered artifacts")
    }));
}

#[test]
fn strong_artifact_binding_produces_artifact_bound_linkage() {
    let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::ArtifactBound));
    let theorem = theorem_record("meaning", crate::EvaluationMode::Kernel);
    let theorem_id = theorem.id.clone();
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    let mut artifact = basic_record(
        "artifact-proof",
        EvidenceKind::ArtifactSoundness,
        "artifact:certificate",
    );
    artifact.evaluation_mode = Some(crate::EvaluationMode::Kernel);
    artifact.binding_mode = Some(BindingMode::DigestTheorem);
    let artifact_identity = bound_artifact();
    artifact
        .provenance
        .input_artifacts
        .push(artifact_identity.clone());
    artifact.artifact_binding = Some(ArtifactBindingEvidence {
        theorem: theorem_id,
        artifact: artifact_identity,
    });
    add_record(&mut input, artifact, NodeKind::Artifact, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(status.linkage, Some(LinkageFacet::ArtifactBound));
    assert!(status.policy.admitted);
}

fn add_artifact_binding(
    input: &mut ClaimEvaluationInput,
    theorem: EvidenceId,
    artifact: ArtifactIdentity,
    id: &str,
) {
    let mut record = basic_record(
        id,
        EvidenceKind::ArtifactSoundness,
        &format!("artifact:{id}"),
    );
    record.evaluation_mode = Some(crate::EvaluationMode::Kernel);
    record.binding_mode = Some(BindingMode::DigestTheorem);
    record.provenance.input_artifacts.push(artifact.clone());
    record.artifact_binding = Some(ArtifactBindingEvidence { theorem, artifact });
    add_record(input, record, NodeKind::Artifact, true);
}

#[test]
fn unrelated_theorem_cannot_smuggle_a_nested_binding_marker() {
    let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::ArtifactBound));
    let mut theorem = theorem_record("smuggled", crate::EvaluationMode::Kernel);
    let exact_binding = theorem
        .theorem
        .as_ref()
        .unwrap()
        .statement_wire
        .as_array()
        .unwrap()[1]
        .clone();
    let wrapped = serde_json::json!([
        crate::LEAN_STATEMENT_ENCODING_V1,
        [3, [2, "Demo.Unrelated", []], exact_binding]
    ]);
    let theorem_detail = theorem.theorem.as_mut().unwrap();
    theorem_detail.statement_sha256 = crate::lean_statement_wire_digest(&wrapped).unwrap();
    theorem_detail.statement_wire = wrapped;
    let theorem_id = theorem.id.clone();
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    add_artifact_binding(
        &mut input,
        theorem_id,
        bound_artifact(),
        "smuggled-artifact",
    );

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert_eq!(status.linkage, None);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("not derived from the exact audited theorem root")
    }));
}

#[test]
fn artifact_path_digest_and_claim_mismatches_fail_closed() {
    for mismatch in ["path", "digest", "claim"] {
        let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::ArtifactBound));
        let mut theorem = theorem_record(mismatch, crate::EvaluationMode::Kernel);
        let mut artifact = bound_artifact();
        match mismatch {
            "path" => {
                artifact.logical_name = ArtifactLogicalName::new("other.bin").unwrap();
            }
            "digest" => artifact.sha256 = digest("different artifact"),
            "claim" => {
                let wire =
                    binding_statement(&ClaimId::new("OTHER-CLAIM").unwrap(), &bound_artifact());
                let detail = theorem.theorem.as_mut().unwrap();
                detail.statement_sha256 = crate::lean_statement_wire_digest(&wire).unwrap();
                detail.statement_wire = wire;
            }
            _ => unreachable!(),
        }
        let theorem_id = theorem.id.clone();
        add_record(&mut input, theorem, NodeKind::Theorem, true);
        add_artifact_binding(
            &mut input,
            theorem_id,
            artifact,
            &format!("artifact-{mismatch}"),
        );

        let status = derive_claim_status(&input);
        assert_eq!(status.formal, FormalFacet::Invalid, "{mismatch}");
        assert_eq!(status.linkage, None, "{mismatch}");
    }
}

#[test]
fn wire_hash_mismatch_and_ambiguous_provenance_fail_locally() {
    let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::ArtifactBound));
    let mut theorem = theorem_record("wrong-hash", crate::EvaluationMode::Kernel);
    theorem.theorem.as_mut().unwrap().statement_sha256 = digest("not the statement");
    let theorem_id = theorem.id.clone();
    add_record(&mut input, theorem, NodeKind::Theorem, true);

    let artifact = bound_artifact();
    let mut record = basic_record(
        "duplicate-input",
        EvidenceKind::ArtifactSoundness,
        "artifact:duplicate-input",
    );
    record.evaluation_mode = Some(crate::EvaluationMode::Kernel);
    record.binding_mode = Some(BindingMode::DigestTheorem);
    record.provenance.input_artifacts = vec![artifact.clone(), artifact.clone()];
    record.artifact_binding = Some(ArtifactBindingEvidence {
        theorem: theorem_id,
        artifact,
    });
    add_record(&mut input, record, NodeKind::Artifact, true);

    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert_eq!(status.linkage, None);
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("statement wire, or axiom audit is invalid")
    }));
    assert!(status.errors.iter().any(|error| {
        error
            .message
            .contains("does not match exactly one provenance input")
    }));
}

#[test]
fn multiple_linkages_are_invalid_without_an_explicit_primary() {
    let mut input = base_input(Tier::Bound, builtin(BuiltInProfile::ArtifactBound));
    let theorem = theorem_record("meaning", crate::EvaluationMode::Kernel);
    let theorem_id = theorem.id.clone();
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    let mut artifact = basic_record(
        "artifact",
        EvidenceKind::ArtifactSoundness,
        "artifact:strong",
    );
    artifact.evaluation_mode = Some(crate::EvaluationMode::Kernel);
    artifact.binding_mode = Some(BindingMode::DigestTheorem);
    let artifact_identity = bound_artifact();
    artifact
        .provenance
        .input_artifacts
        .push(artifact_identity.clone());
    artifact.artifact_binding = Some(ArtifactBindingEvidence {
        theorem: theorem_id,
        artifact: artifact_identity,
    });
    add_record(&mut input, artifact, NodeKind::Artifact, true);
    let mut transcription = basic_record(
        "transcribed",
        EvidenceKind::TrustedTranscription,
        "artifact:weak",
    );
    attach_trusted_transcription(&mut transcription, "transcribed");
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    register_transcription_tcb_nodes(&mut input, "transcribed");
    assert_eq!(derive_claim_status(&input).formal, FormalFacet::Invalid);
    input.claim.primary_linkage = Some(LinkageFacet::ArtifactBound);
    let resolved = derive_claim_status(&input);
    assert_eq!(resolved.formal, FormalFacet::Proved);
    assert_eq!(resolved.linkage, Some(LinkageFacet::ArtifactBound));
}

#[test]
fn native_policy_requires_exact_registered_native_premise() {
    let mut input = base_input(Tier::Model, builtin(BuiltInProfile::NativeEvaluated));
    add_record(
        &mut input,
        theorem_record("native", crate::EvaluationMode::Native),
        NodeKind::Theorem,
        true,
    );
    let missing = derive_claim_status(&input);
    assert_eq!(missing.formal, FormalFacet::Open);
    assert!(!missing.policy.admitted);

    let premise = add_assumption(&mut input, "NATIVE-1", AssumptionCategory::NativeEvaluation);
    input.claim.assumptions.insert(premise.clone());
    input
        .evidence
        .iter_mut()
        .find(|record| record.kind == EvidenceKind::Theorem)
        .unwrap()
        .assumptions
        .insert(premise);
    let admitted = derive_claim_status(&input);
    assert_eq!(admitted.formal, FormalFacet::Proved);
    assert_eq!(admitted.assumption.standing, AssumptionStanding::Assumed);
    assert!(admitted.policy.admitted);
}

#[test]
fn project_axiom_without_active_registered_assumption_is_invalid() {
    let axiom = AssumptionId::new("AXIOM-1").unwrap();
    let mut policy = builtin(BuiltInProfile::KernelWithAssumptions);
    policy.allowed_project_axioms.insert(axiom.clone());
    let mut input = base_input(Tier::Model, policy);
    let mut theorem = theorem_record("with-axiom", crate::EvaluationMode::Kernel);
    theorem
        .theorem
        .as_mut()
        .unwrap()
        .project_axioms
        .insert(axiom);
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::PbCoreMissingAssumption)
    );
}

#[test]
fn allowlisted_project_axiom_is_proved_with_enumerated_assumption() {
    let axiom = AssumptionId::new("AXIOM-ALLOWED").unwrap();
    let mut policy = builtin(BuiltInProfile::KernelWithAssumptions);
    policy.allowed_project_axioms.insert(axiom.clone());
    let mut input = base_input(Tier::Model, policy);
    let registered = add_assumption(
        &mut input,
        "AXIOM-ALLOWED",
        AssumptionCategory::MathematicalHypothesis,
    );
    input.claim.assumptions.insert(registered.clone());
    let mut theorem = theorem_record("with-allowed-axiom", crate::EvaluationMode::Kernel);
    theorem.assumptions.insert(registered.clone());
    theorem
        .theorem
        .as_mut()
        .unwrap()
        .project_axioms
        .insert(registered);
    add_record(&mut input, theorem, NodeKind::Theorem, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(status.assumption.standing, AssumptionStanding::Assumed);
    assert_eq!(status.assumption.assumptions[0].id, axiom);
    assert!(status.policy.admitted);
}

#[test]
fn qualifiers_from_another_evidence_kind_fail_closed() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let mut evidence = example_record("tests-with-proof-mode");
    evidence.evaluation_mode = Some(crate::EvaluationMode::Kernel);
    add_record(&mut input, evidence, NodeKind::TestSuite, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(
        status
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::PbCoreInvalidEvidence)
    );
}

#[test]
fn mutation_witness_without_separate_theorem_is_empirical() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    bind_claim_to_subject(&mut input, "rust:crate::decide");
    let mut mutation = basic_record("mutation", EvidenceKind::MutationWitness, "tests:mutation");
    attach_mutation_witness(&mut mutation, "remove-guard", "tests::guard_removed", None);
    add_record(&mut input, mutation, NodeKind::TestSuite, true);
    assert_eq!(derive_claim_status(&input).formal, FormalFacet::Tested);
}

#[test]
fn rehashed_mutation_witness_cannot_attach_to_another_claim_subject() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    bind_claim_to_subject(&mut input, "rust:crate::decide");
    let mut mutation = basic_record(
        "mutation-subject",
        EvidenceKind::MutationWitness,
        "tests:mutation-subject",
    );
    attach_mutation_witness(&mut mutation, "remove-guard", "tests::guard_removed", None);
    let claims = mutation.claims.clone();
    let witness = mutation.mutation_witness.as_mut().unwrap();
    witness.subject = "rust:crate::unrelated".into();
    witness.mutation_sha256 = witness.derived_mutation_sha256(&claims).unwrap();
    assert!(mutation.validate(&claim_id()).is_ok());

    add_record(&mut input, mutation, NodeKind::TestSuite, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Invalid);
    assert!(status.errors.iter().any(|error| {
        error.code == ErrorCode::PbCoreInvalidEvidence
            && error.message.contains("different subject")
    }));
}

#[test]
fn mutation_witness_replay_is_exact_and_fail_closed() {
    let mut valid = basic_record(
        "mutation-exact",
        EvidenceKind::MutationWitness,
        "tests:mutation-exact",
    );
    attach_mutation_witness(
        &mut valid,
        "remove-guard",
        "guard_witnesses::guard_removed",
        None,
    );
    assert!(valid.validate(&claim_id()).is_ok());

    let mut cases = Vec::new();

    let mut wrong_exit = valid.clone();
    wrong_exit.provenance.runs[1].exit_code = Some(1);
    cases.push(("wrong registered exit", wrong_exit));

    let mut extra_failure = valid.clone();
    extra_failure.provenance.runs[0].exit_code = Some(101);
    cases.push(("more than one nonzero run", extra_failure));

    let mut broadened_exit = valid.clone();
    broadened_exit
        .mutation_witness
        .as_mut()
        .unwrap()
        .expected_failure
        .allowed_exit_codes
        .insert(1);
    cases.push(("broadened failure codes", broadened_exit));

    let mut changed_command = valid.clone();
    changed_command.provenance.commands[1].args[0] = "another_test".into();
    cases.push(("different mutant witness", changed_command));

    let mut replayed_baseline_binary = valid.clone();
    replayed_baseline_binary.provenance.commands[1].program =
        replayed_baseline_binary.provenance.commands[0]
            .program
            .clone();
    cases.push((
        "baseline binary replayed as mutant",
        replayed_baseline_binary,
    ));

    let mut hidden_input = valid.clone();
    hidden_input
        .provenance
        .input_artifacts
        .push(named_artifact("hidden/input", "hidden-input", 1));
    cases.push(("extra provenance input", hidden_input));

    let mut changed_postimage = valid.clone();
    changed_postimage
        .mutation_witness
        .as_mut()
        .unwrap()
        .target_postimage
        .sha256 = digest("different-postimage");
    cases.push(("unbound mutant postimage", changed_postimage));

    let mut forged_identity = valid.clone();
    forged_identity
        .mutation_witness
        .as_mut()
        .unwrap()
        .mutation_sha256 = digest("forged-mutation");
    cases.push(("forged mutation identity", forged_identity));

    let mut uppercase_id = valid.clone();
    let witness = uppercase_id.mutation_witness.as_mut().unwrap();
    witness.mutation_id = "remove-Guard".into();
    witness.mutation_sha256 = witness
        .derived_mutation_sha256(&uppercase_id.claims)
        .unwrap();
    uppercase_id.inventoried_targets = BTreeSet::from(["remove-Guard".into()]);
    cases.push(("non-canonical mutation ID", uppercase_id));

    let mut multi_inventory = valid.clone();
    multi_inventory
        .inventoried_targets
        .insert("remove-another-guard".into());
    cases.push(("multi-mutation unit", multi_inventory));

    let mut mismatched_unit = valid.clone();
    mismatched_unit.unit_id = UnitId::new("unit:another-mutation").unwrap();
    cases.push(("unit and mutation identities differ", mismatched_unit));

    for (label, record) in cases {
        assert!(record.validate(&claim_id()).is_err(), "accepted {label}");
    }
}

#[test]
fn node_mutation_witness_requires_exact_vitest_abi_and_package_inputs() {
    let valid = node_mutation_record();
    assert!(valid.validate(&claim_id()).is_ok());

    let mut wrong_pattern = valid.clone();
    wrong_pattern.provenance.commands[1].args[4] = ".*".into();
    assert!(wrong_pattern.validate(&claim_id()).is_err());

    let mut wrong_exit = valid.clone();
    wrong_exit.provenance.runs[1].exit_code = Some(101);
    assert!(wrong_exit.validate(&claim_id()).is_err());

    let mut missing_lock = valid;
    missing_lock
        .provenance
        .input_artifacts
        .retain(|artifact| artifact.logical_name.as_str() != "package-lock.json");
    assert!(missing_lock.validate(&claim_id()).is_err());
}

#[test]
fn python_mutation_witness_requires_exact_pytest_shadow_abi() {
    let valid = python_mutation_record();
    assert!(valid.validate(&claim_id()).is_ok());

    let mut replayed_baseline = valid.clone();
    replayed_baseline.provenance.commands[1] = replayed_baseline.provenance.commands[0].clone();
    assert!(replayed_baseline.validate(&claim_id()).is_err());

    let mut injected_argument = valid;
    injected_argument.provenance.commands[1]
        .args
        .insert(7, "--maxfail=1".into());
    assert!(injected_argument.validate(&claim_id()).is_err());
}

#[test]
fn expected_nonzero_exit_is_never_available_to_other_evidence_kinds() {
    let mut ordinary = example_record("ordinary-nonzero");
    ordinary.provenance.runs[0].exit_code = Some(101);
    assert!(ordinary.validate(&claim_id()).is_err());
}

#[test]
fn proof_term_mutation_witness_is_supporting_and_cannot_prove_the_claim() {
    let mut input = base_input(Tier::Model, ledger_policy());
    bind_claim_to_subject(&mut input, "rust:crate::decide");
    let mut mutation = basic_record(
        "proof-mutation",
        EvidenceKind::MutationWitness,
        "tests:proof-mutation",
    );
    attach_mutation_witness(
        &mut mutation,
        "proof-mutation",
        "Lean.Mutation.guard_violation",
        Some(EvidenceId::new("theorem:mutation-only").unwrap()),
    );
    add_record(&mut input, mutation, NodeKind::TestSuite, true);
    assert_eq!(derive_claim_status(&input).formal, FormalFacet::Open);
}

#[test]
fn status_output_itself_is_strict_and_cannot_accept_manual_fields() {
    let input = base_input(Tier::Ledger, ledger_policy());
    let status = derive_claim_status(&input);
    let mut value = serde_json::to_value(status).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("aggregate_score".into(), serde_json::json!(100));
    assert!(serde_json::from_value::<ClaimStatus>(value).is_err());
}

#[test]
fn resource_budget_overrun_is_visible_but_does_not_truncate_coverage() {
    let mut input = base_input(Tier::Ledger, ledger_policy());
    let mut evidence = example_record("expensive");
    evidence.provenance.resource_usage.time_ms = 10;
    add_record(&mut input, evidence, NodeKind::TestSuite, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Tested);
    assert!(status.evidence[0].budget_exceeded);
}

#[test]
fn policy_native_premise_rule_is_not_silently_mutable_on_builtin_name() {
    let mut policy = builtin(BuiltInProfile::NativeEvaluated);
    policy.native_premise_rule = Some(NativePremiseRule::AtLeastOne);
    // The profile explicitly permits the policy to state whether exactly one
    // is required; this is configuration, not a status override.
    assert!(policy.validate().is_ok());
}

#[test]
fn common_origin_cannot_masquerade_as_independent_check() {
    let mut input = base_input(Tier::Bounded, ledger_policy());
    let mut evidence = basic_record(
        "cross-check",
        EvidenceKind::IndependentCheck,
        "tests:cross-check",
    );
    evidence.independence = Some(IndependenceMode::CommonOrigin);
    evidence.inventoried_targets.insert("rust-and-lean".into());
    add_record(&mut input, evidence, NodeKind::TestSuite, true);
    assert_eq!(derive_claim_status(&input).formal, FormalFacet::Invalid);
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusDocument {
    schema: String,
    cases: Vec<CorpusCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    tier: u8,
    #[serde(default)]
    claim_tier: Option<u8>,
    policy: CorpusPolicy,
    evidence: Vec<CorpusEvidence>,
    assumptions: Vec<CorpusAssumption>,
    premises: Vec<CorpusPremise>,
    #[serde(default)]
    primary_linkage: Option<String>,
    registered_domain: bool,
    expected: CorpusStatus,
    #[serde(default)]
    asserted: Option<CorpusStatus>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CorpusPolicy {
    components: Vec<String>,
    admit_exhaustive_as_proved: bool,
    require_no_assumptions: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusEvidence {
    id: String,
    kind: String,
    #[serde(default = "corpus_passed")]
    outcome: String,
    #[serde(default = "corpus_true")]
    present: bool,
    #[serde(default = "corpus_true")]
    cited: bool,
    #[serde(default = "corpus_true")]
    typed_binding: bool,
    #[serde(default)]
    evaluation: Option<String>,
    #[serde(default)]
    theorem_ref: Option<String>,
    #[serde(default)]
    premises: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusAssumption {
    id: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusPremise {
    id: String,
    theorem: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusStatus {
    formal: String,
    linkage: Option<String>,
    assumption: String,
    assumptions: BTreeSet<String>,
    undischarged_premises: BTreeSet<String>,
    policy_admitted: bool,
}

const fn corpus_true() -> bool {
    true
}

fn corpus_passed() -> String {
    "passed".into()
}

fn read_status_corpus() -> CorpusDocument {
    serde_json::from_str(include_str!(
        "../../../../proofbound/conformance/v1/status-graphs.json"
    ))
    .expect("registered conformance corpus must be strict JSON")
}

fn corpus_profile(name: &str) -> BuiltInProfile {
    match name {
        "ledger" => BuiltInProfile::Ledger,
        "transcribed" => BuiltInProfile::Transcribed,
        "kernel" => BuiltInProfile::Kernel,
        "kernel-with-assumptions" => BuiltInProfile::KernelWithAssumptions,
        "artifact-bound" => BuiltInProfile::ArtifactBound,
        "source-refined" => BuiltInProfile::SourceRefined,
        "native-evaluated" => BuiltInProfile::NativeEvaluated,
        "bounded" => BuiltInProfile::Bounded,
        other => panic!("unknown corpus policy component: {other}"),
    }
}

fn corpus_tier(tier: u8) -> Tier {
    match tier {
        0 => Tier::Ledger,
        1 => Tier::Bounded,
        2 => Tier::Model,
        3 => Tier::Bound,
        other => panic!("invalid corpus tier: {other}"),
    }
}

fn corpus_evidence_status(outcome: &str) -> EvidenceStatus {
    match outcome {
        "passed" => EvidenceStatus::Passed,
        "failed" => EvidenceStatus::Failed,
        "drifted" => EvidenceStatus::Drifted,
        other => panic!("unsupported corpus evidence outcome: {other}"),
    }
}

fn corpus_evaluation(mode: Option<&str>) -> crate::EvaluationMode {
    match mode.unwrap_or("kernel") {
        "kernel" => crate::EvaluationMode::Kernel,
        "native" => crate::EvaluationMode::Native,
        other => panic!("unsupported corpus evaluation mode: {other}"),
    }
}

fn build_core_corpus_case(case: &CorpusCase) -> ClaimEvaluationInput {
    let policy_id = PolicyId::new(format!("corpus-policy-{}", case.id)).unwrap();
    let policy = PolicyDefinition {
        schema: POLICY_SCHEMA_V1.into(),
        node_id: NodeId::new(format!("policy:corpus-{}", case.id)).unwrap(),
        id: policy_id,
        components: case
            .policy
            .components
            .iter()
            .map(|component| corpus_profile(component))
            .collect(),
        allowed_foundational_axioms: BTreeSet::new(),
        allowed_project_axioms: BTreeSet::new(),
        admit_exhaustive_as_proved: case.policy.admit_exhaustive_as_proved,
        require_no_assumptions: case.policy.require_no_assumptions,
        native_premise_rule: None,
        additional_required_evidence: BTreeSet::new(),
    };
    let mut input = base_input(corpus_tier(case.tier), policy);
    input.claim.tier = case.claim_tier.map(corpus_tier);
    input.claim.registered_domain_language = case
        .registered_domain
        .then(|| "For every member of the registered finite corpus domain, P holds.".into());
    input.claim.primary_linkage = case
        .primary_linkage
        .as_deref()
        .map(|linkage| match linkage {
            "REFINED" => LinkageFacet::Refined,
            "ARTIFACT_BOUND" => LinkageFacet::ArtifactBound,
            "TRANSCRIBED" => LinkageFacet::Transcribed,
            "MODEL_ONLY" => LinkageFacet::ModelOnly,
            other => panic!("unknown corpus linkage: {other}"),
        });

    for raw in &case.evidence {
        if !raw.present {
            if raw.cited {
                input
                    .claim
                    .cited_evidence
                    .insert(EvidenceId::new(&raw.id).unwrap());
            }
            continue;
        }
        let (mut record, node_kind) = match raw.kind.as_str() {
            "example-test" => (example_record(&raw.id), NodeKind::TestSuite),
            "static-check" => {
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::StaticCheck,
                    &format!("test:{}", raw.id),
                );
                let target = format!("python/{}.py", raw.id);
                let configuration = named_artifact("mypy.ini", "mypy-configuration", 16);
                record.inventoried_targets = BTreeSet::from([target.clone()]);
                record
                    .provenance
                    .input_artifacts
                    .push(configuration.clone());
                record.static_check = Some(StaticCheckEvidence {
                    schema: crate::STATIC_CHECK_SCHEMA_V1.into(),
                    tool: "mypy".into(),
                    tool_version: "1.18.2".into(),
                    configuration_sha256: configuration.sha256,
                    targets: BTreeSet::from([target]),
                    diagnostics: 0,
                });
                (record, NodeKind::TestSuite)
            }
            "bounded-check" => (bounded_record(&raw.id), NodeKind::ModelCheckUnit),
            "exhaustive-check" => (exhaustive_record(&raw.id), NodeKind::ModelCheckUnit),
            "independent-check" => {
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::IndependentCheck,
                    &format!("test:{}", raw.id),
                );
                record.independence = Some(IndependenceMode::Independent);
                record
                    .inventoried_targets
                    .insert(format!("independent::{}", raw.id));
                (record, NodeKind::TestSuite)
            }
            "theorem" => {
                let mut record =
                    theorem_record(&raw.id, corpus_evaluation(raw.evaluation.as_deref()));
                if !raw.typed_binding {
                    let wire = serde_json::json!([
                        crate::LEAN_STATEMENT_ENCODING_V1,
                        [2, "Demo.Unrelated", []]
                    ]);
                    let detail = record.theorem.as_mut().unwrap();
                    detail.statement_sha256 = crate::lean_statement_wire_digest(&wire).unwrap();
                    detail.statement_wire = wire;
                }
                (record, NodeKind::Theorem)
            }
            "artifact-soundness" => {
                let theorem = EvidenceId::new(raw.theorem_ref.as_deref().unwrap()).unwrap();
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::ArtifactSoundness,
                    &format!("artifact:{}", raw.id),
                );
                record.evaluation_mode = Some(corpus_evaluation(raw.evaluation.as_deref()));
                record.binding_mode = Some(BindingMode::DigestTheorem);
                let artifact = bound_artifact();
                record.provenance.input_artifacts.push(artifact.clone());
                record.artifact_binding = Some(ArtifactBindingEvidence { theorem, artifact });
                (record, NodeKind::Artifact)
            }
            "trusted-transcription" => {
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::TrustedTranscription,
                    &format!("artifact:{}", raw.id),
                );
                attach_trusted_transcription(&mut record, &raw.id);
                for suffix in ["transcriber", "reencoder"] {
                    input.graph.nodes.push(GraphNode {
                        id: NodeId::new(format!("tcb:trusted-transcription:{}:{suffix}", raw.id))
                            .unwrap(),
                        kind: NodeKind::TcbComponent,
                        proof_environment: None,
                    });
                }
                (record, NodeKind::Artifact)
            }
            "source-refinement" => {
                let theorem = EvidenceId::new(raw.theorem_ref.as_deref().unwrap()).unwrap();
                let registered = raw
                    .premises
                    .iter()
                    .map(|id| PremiseId::new(id).unwrap())
                    .collect::<BTreeSet<_>>();
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::SourceRefinement,
                    &format!("translation:{}", raw.id),
                );
                record.premises = registered.clone();
                record.source_refinement = Some(SourceRefinementEvidence {
                    refinement_theorem: theorem,
                    representation_premises: registered,
                    deterministic_translation: true,
                    pinned_toolchain: true,
                    generated_axioms_clean: true,
                    adapter_strength: AdapterStrength::DecisionAdequate,
                });
                (record, NodeKind::TranslationUnit)
            }
            other => panic!("unsupported corpus evidence kind: {other}"),
        };
        record.status = corpus_evidence_status(&raw.outcome);
        record
            .premises
            .extend(raw.premises.iter().map(|id| PremiseId::new(id).unwrap()));
        add_record(&mut input, record, node_kind, raw.cited);
    }

    for raw in &case.assumptions {
        add_assumption(&mut input, &raw.id, AssumptionCategory::ExternalProvider);
    }
    for raw in &case.premises {
        let id = PremiseId::new(&raw.id).unwrap();
        let node_id = NodeId::new(format!("premise:{}", raw.id)).unwrap();
        input.graph.nodes.push(GraphNode {
            id: node_id.clone(),
            kind: NodeKind::Premise,
            proof_environment: None,
        });
        input.premises.push(PremiseRecord {
            id,
            node_id,
            statement: "The registered representation invariant holds.".into(),
            category: AssumptionCategory::RepresentationPremise,
            theorem_evidence: Some(EvidenceId::new(&raw.theorem).unwrap()),
            scope: FlowScope::AllRegisteredInputs,
            discharge: None,
        });
    }
    input
}

fn snapshot_core_status(status: &ClaimStatus) -> CorpusStatus {
    CorpusStatus {
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
        assumption: match status.assumption.standing {
            AssumptionStanding::None => "NONE",
            AssumptionStanding::Assumed => "ASSUMED",
        }
        .into(),
        assumptions: status
            .assumption
            .assumptions
            .iter()
            .map(|assumption| assumption.id.to_string())
            .collect(),
        undischarged_premises: status
            .assumption
            .undischarged_premises
            .iter()
            .map(|premise| premise.id.to_string())
            .collect(),
        policy_admitted: status.policy.admitted,
    }
}

#[test]
fn registered_language_neutral_status_corpus_matches_core_derivation() {
    let corpus = read_status_corpus();
    assert_eq!(corpus.schema, "proofbound-status-conformance/1");
    let mut ids = BTreeSet::new();
    let mut formals = BTreeSet::new();
    let mut linkages = BTreeSet::new();
    let mut attacks = 0;
    for case in corpus.cases {
        assert!(ids.insert(case.id.clone()), "duplicate case ID {}", case.id);
        let status = derive_claim_status(&build_core_corpus_case(&case));
        let actual = snapshot_core_status(&status);
        assert_eq!(actual, case.expected, "conformance case {}", case.id);
        if let Some(asserted) = &case.asserted {
            attacks += 1;
            assert_ne!(
                actual, *asserted,
                "attack-shaped assertion unexpectedly matched in {}",
                case.id
            );
        }
        if actual.formal == "INVALID" {
            assert!(
                !status.errors.is_empty(),
                "{} must explain INVALID",
                case.id
            );
        }
        formals.insert(actual.formal);
        if let Some(linkage) = actual.linkage {
            linkages.insert(linkage);
        }
    }
    assert_eq!(
        formals,
        BTreeSet::from([
            "BOUNDED_CHECKED".into(),
            "INVALID".into(),
            "OPEN".into(),
            "PROVED".into(),
            "TESTED".into(),
        ])
    );
    assert_eq!(
        linkages,
        BTreeSet::from([
            "ARTIFACT_BOUND".into(),
            "MODEL_ONLY".into(),
            "REFINED".into(),
            "TRANSCRIBED".into(),
        ])
    );
    assert!(attacks >= 3, "corpus lost omission/upgrade attacks");
}
