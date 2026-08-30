use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{
    ASSUMPTION_SCHEMA_V1, AdapterStrength, ArtifactBindingEvidence, AssumptionStatus, BindingMode,
    BoundedCheckEvidence, BuiltInProfile, CacheOrigin, CommandSpec, EnvironmentId,
    EnvironmentVariable, EnvironmentVariableName, EvidenceProvenance, ExhaustiveCheckEvidence,
    GRAPH_SCHEMA_V1, GraphEdge, GraphNode, IndependenceMode, MutationWitnessEvidence,
    NativePremiseRule, POLICY_SCHEMA_V1, PolicyId, ResourceBudget, ResourceUsage, Sha256Digest,
    SourceRefinementEvidence, TheoremEvidence, ToolIdentity, TreeState,
    TrustedTranscriptionEvidence, UnitId,
};

fn claim_id() -> ClaimId {
    ClaimId::new("CLAIM-1").unwrap()
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::of_bytes(label)
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
        command: command.clone(),
        reproduction_command: command,
        started_unix_ms: 10,
        completed_unix_ms: 20,
        deterministic_result_identity: digest(label),
        unit_configuration_sha256: digest(&format!("config:{label}")),
        resource_budget: ResourceBudget::default(),
        resource_usage: ResourceUsage::default(),
        cache_origin: CacheOrigin::Executed,
        prior_receipt_sha256: None,
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
        schema: crate::EVIDENCE_SCHEMA_V1.into(),
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
        independence: None,
        inventoried_targets: BTreeSet::new(),
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
    record.theorem = Some(TheoremEvidence {
        declaration: format!("Proofbound.Tests.{id}"),
        statement_encoding: "lean-expr-cbor/1".into(),
        statement_sha256: digest(&format!("statement:{id}")),
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
    record.bounded_check = Some(BoundedCheckEvidence {
        domain: domain(),
        solver: "cadical 2".into(),
        harnesses: BTreeSet::from(["check_all".into()]),
        unwind_bounds: BTreeMap::from([("loop".into(), 256)]),
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
        "For every registered u8 value, P holds."
    );
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
    transcription.binding_mode = Some(BindingMode::ExternalRoundTrip);
    transcription.trusted_transcription = Some(TrustedTranscriptionEvidence {
        transcriber_tcb: NodeId::new("tcb:transcriber").unwrap(),
        reencoder_tcb: NodeId::new("tcb:reencoder").unwrap(),
        round_trip_passed: true,
    });
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    for id in ["tcb:transcriber", "tcb:reencoder"] {
        input.graph.nodes.push(GraphNode {
            id: NodeId::new(id).unwrap(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        });
    }
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(status.linkage, Some(LinkageFacet::Transcribed));
    assert!(!status.policy.admitted);
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
    artifact.artifact_binding = Some(ArtifactBindingEvidence {
        theorem: theorem_id,
        canonical_payload: true,
        schema_bound: true,
        literal_claim_bound: true,
        digest_bound: true,
        reencoding_passed: true,
        trailing_bytes_rejected: true,
    });
    add_record(&mut input, artifact, NodeKind::Artifact, true);
    let status = derive_claim_status(&input);
    assert_eq!(status.formal, FormalFacet::Proved);
    assert_eq!(status.linkage, Some(LinkageFacet::ArtifactBound));
    assert!(status.policy.admitted);
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
    artifact.artifact_binding = Some(ArtifactBindingEvidence {
        theorem: theorem_id,
        canonical_payload: true,
        schema_bound: true,
        literal_claim_bound: true,
        digest_bound: true,
        reencoding_passed: true,
        trailing_bytes_rejected: true,
    });
    add_record(&mut input, artifact, NodeKind::Artifact, true);
    let mut transcription = basic_record(
        "transcribed",
        EvidenceKind::TrustedTranscription,
        "artifact:weak",
    );
    transcription.binding_mode = Some(BindingMode::ExternalRoundTrip);
    transcription.trusted_transcription = Some(TrustedTranscriptionEvidence {
        transcriber_tcb: NodeId::new("tcb:a").unwrap(),
        reencoder_tcb: NodeId::new("tcb:b").unwrap(),
        round_trip_passed: true,
    });
    add_record(&mut input, transcription, NodeKind::Artifact, true);
    for id in ["tcb:a", "tcb:b"] {
        input.graph.nodes.push(GraphNode {
            id: NodeId::new(id).unwrap(),
            kind: NodeKind::TcbComponent,
            proof_environment: None,
        });
    }
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
    let mut mutation = basic_record("mutation", EvidenceKind::MutationWitness, "tests:mutation");
    mutation.mutation_witness = Some(MutationWitnessEvidence {
        mutation_sha256: digest("mutation"),
        check_id: "tests::guard_removed".into(),
        proof_term_theorem: None,
    });
    add_record(&mut input, mutation, NodeKind::TestSuite, true);
    assert_eq!(derive_claim_status(&input).formal, FormalFacet::Tested);
}

#[test]
fn proof_term_mutation_witness_is_supporting_and_cannot_prove_the_claim() {
    let mut input = base_input(Tier::Model, ledger_policy());
    let mut mutation = basic_record(
        "proof-mutation",
        EvidenceKind::MutationWitness,
        "tests:proof-mutation",
    );
    mutation.mutation_witness = Some(MutationWitnessEvidence {
        mutation_sha256: digest("proof-mutation"),
        check_id: "Lean.Mutation.guard_violation".into(),
        proof_term_theorem: Some(EvidenceId::new("theorem:mutation-only").unwrap()),
    });
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
            "theorem" => (
                theorem_record(&raw.id, corpus_evaluation(raw.evaluation.as_deref())),
                NodeKind::Theorem,
            ),
            "artifact-soundness" => {
                let theorem = EvidenceId::new(raw.theorem_ref.as_deref().unwrap()).unwrap();
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::ArtifactSoundness,
                    &format!("artifact:{}", raw.id),
                );
                record.evaluation_mode = Some(corpus_evaluation(raw.evaluation.as_deref()));
                record.binding_mode = Some(BindingMode::DigestTheorem);
                record.artifact_binding = Some(ArtifactBindingEvidence {
                    theorem,
                    canonical_payload: true,
                    schema_bound: true,
                    literal_claim_bound: true,
                    digest_bound: true,
                    reencoding_passed: true,
                    trailing_bytes_rejected: true,
                });
                (record, NodeKind::Artifact)
            }
            "trusted-transcription" => {
                let mut record = basic_record(
                    &raw.id,
                    EvidenceKind::TrustedTranscription,
                    &format!("artifact:{}", raw.id),
                );
                record.binding_mode = Some(BindingMode::ExternalRoundTrip);
                record.trusted_transcription = Some(TrustedTranscriptionEvidence {
                    transcriber_tcb: NodeId::new(format!("tcb:{}-transcriber", raw.id)).unwrap(),
                    reencoder_tcb: NodeId::new(format!("tcb:{}-reencoder", raw.id)).unwrap(),
                    round_trip_passed: true,
                });
                for suffix in ["transcriber", "reencoder"] {
                    input.graph.nodes.push(GraphNode {
                        id: NodeId::new(format!("tcb:{}-{suffix}", raw.id)).unwrap(),
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
