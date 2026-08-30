use std::{collections::BTreeMap, path::Path};

use proofbound_adapter_lean::{
    handle_bytes,
    model::{
        AuditClaim, AuditOutput, AuditSource, CapturedExecution, DeclarationKind, ExpectedClaim,
        LEAN_ADAPTER_UNIT_SCHEMA, LEAN_AUDIT_SCHEMA, LeanAdapterUnit,
    },
    protocol::{ADAPTER_NAME, ADAPTER_PROTOCOL_SCHEMA, LeanAdapterResponse},
    wire::{STATEMENT_ENCODING, statement_digest},
};
use proofbound_core::{CommandSpec, EnvironmentId, ResourceUsage, Sha256Digest, ToolIdentity};
use proofbound_evidence::canonical_json;
use proofbound_manifest::{
    AdapterKind, AdapterOperation, AdapterRequest, EvaluationMode, EvidenceKind,
    EvidenceUnitManifest, OperationKind, ResourceBudget,
};
use serde_json::json;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("adapter crate is nested below the workspace root")
}

fn request() -> AdapterRequest {
    let expr_wire = json!([
        STATEMENT_ENCODING,
        [5, 0, [2, "Nat", []], [3, [2, "Eq", [[0]]], [0, "0"]]]
    ]);
    let digest = statement_digest(&expr_wire).unwrap();
    let audit = AuditOutput {
        schema: LEAN_AUDIT_SCHEMA.to_owned(),
        statement_encoding: STATEMENT_ENCODING.to_owned(),
        claims: vec![AuditClaim {
            axioms: Vec::new(),
            claim_id: "FIXTURE-CLAIM-001".to_owned(),
            declaration: "Fixture.identity".to_owned(),
            expr_wire,
            kind: DeclarationKind::Theorem,
            module: "Fixture".to_owned(),
        }],
        exemptions: Vec::new(),
    };
    let unit = LeanAdapterUnit {
        schema: LEAN_ADAPTER_UNIT_SCHEMA.to_owned(),
        evidence_unit: EvidenceUnitManifest {
            schema: "proofbound-evidence-unit/1".to_owned(),
            id: "fixture-theorem".to_owned(),
            adapter: AdapterKind::Lean,
            kind: EvidenceKind::Theorem,
            claims: vec!["FIXTURE-CLAIM-001".to_owned()],
            tier: 2,
            operation: AdapterOperation {
                kind: OperationKind::LeanAudit,
                package: None,
                targets: vec!["Fixture.identity".to_owned()],
                paths: vec![
                    "crates/proofbound-adapter-lean/tests/fixtures/Semantic.lean".to_owned(),
                ],
                manifest: None,
                inventory: None,
                checker: None,
                arguments: Vec::new(),
            },
            evaluation_mode: Some(EvaluationMode::Kernel),
            binding_mode: None,
            theorem: Some("Fixture.identity".to_owned()),
            refinement_theorem: None,
            premises: Vec::new(),
            assumptions: Vec::new(),
            expected_inventory: Vec::new(),
            inputs: vec!["crates/proofbound-adapter-lean/tests/fixtures/Semantic.lean".to_owned()],
            outputs: Vec::new(),
            environment_allowlist: Vec::new(),
            bounded_domain: None,
            resource_budget: ResourceBudget {
                time_seconds: 10,
                disk_bytes: 1 << 20,
                memory_bytes: 1 << 20,
            },
        },
        environment_id: EnvironmentId::new("lean:fixture-environment").unwrap(),
        claim_inventory: vec![ExpectedClaim {
            claim_id: "FIXTURE-CLAIM-001".to_owned(),
            declaration: "Fixture.identity".to_owned(),
            declaration_kind: DeclarationKind::Theorem,
            statement_sha256: Some(format!("sha256:{digest}")),
            foundational_axioms: Vec::new(),
            project_axioms: BTreeMap::new(),
        }],
        audit: AuditSource::Captured {
            output: Box::new(audit),
            execution: Box::new(CapturedExecution {
                tool: ToolIdentity {
                    name: "fixture-proofbound_lean_audit".to_owned(),
                    version: "fixture/1".to_owned(),
                    identity_sha256: Sha256Digest::of_bytes(b"fixture audit executable"),
                },
                command: CommandSpec {
                    program: "/fixture/proofbound_lean_audit".to_owned(),
                    args: vec!["Fixture".to_owned(), "--surface=Fixture".to_owned()],
                    environment_allowlist: Vec::new(),
                },
                started_unix_ms: 1_000,
                completed_unix_ms: 1_005,
                resource_usage: ResourceUsage {
                    time_ms: 5,
                    peak_disk_bytes: 0,
                    peak_memory_bytes: 0,
                },
            }),
        },
    };
    AdapterRequest {
        schema: ADAPTER_PROTOCOL_SCHEMA.to_owned(),
        message_type: "request".to_owned(),
        request_id: "0123456789abcdef0123456789abcdef".to_owned(),
        adapter: ADAPTER_NAME.to_owned(),
        operation: "check".to_owned(),
        project_root: ".".to_owned(),
        unit: serde_json::to_value(unit).unwrap(),
    }
}

#[test]
fn canonical_protocol_returns_a_direct_core_evidence_record() {
    let request = request();
    let input = canonical_json(&request).unwrap();
    let output = handle_bytes(&input, root());
    let response: LeanAdapterResponse = serde_json::from_slice(&output).unwrap();
    assert!(response.success, "{:?}", response.diagnostics);
    assert_eq!(output, canonical_json(&response).unwrap());
    assert_eq!(response.inventory, vec!["Fixture.identity"]);

    let evidence = response.evidence.unwrap();
    let claim = proofbound_core::ClaimId::new("FIXTURE-CLAIM-001").unwrap();
    evidence.validate(&claim).unwrap();
    let round_trip = serde_json::to_value(&evidence).unwrap();
    let decoded: proofbound_core::EvidenceRecord = serde_json::from_value(round_trip).unwrap();
    assert_eq!(decoded, evidence);
}

#[test]
fn canonical_protocol_reports_statement_drift_without_evidence() {
    let mut request = request();
    let inventory = request.unit["claim_inventory"]
        .as_array_mut()
        .expect("claim_inventory is an array");
    inventory[0]["statement_sha256"] =
        json!(format!("sha256:{}", Sha256Digest::of_bytes(b"drift")));
    let output = handle_bytes(&canonical_json(&request).unwrap(), root());
    let response: LeanAdapterResponse = serde_json::from_slice(&output).unwrap();
    assert!(!response.success);
    assert!(response.evidence.is_none());
    assert_eq!(response.diagnostics[0].code, "PB-LEAN-0008");
}

#[test]
fn update_observes_new_digest_but_marks_receipt_drifted() {
    let mut request = request();
    request.operation = "update".to_owned();
    request.unit["claim_inventory"][0]["statement_sha256"] =
        json!(format!("sha256:{}", Sha256Digest::of_bytes(b"old theorem")));
    let output = handle_bytes(&canonical_json(&request).unwrap(), root());
    let response: LeanAdapterResponse = serde_json::from_slice(&output).unwrap();
    assert!(response.success, "{:?}", response.diagnostics);
    let evidence = response.evidence.unwrap();
    assert_eq!(evidence.status, proofbound_core::EvidenceStatus::Drifted);
    assert_ne!(
        evidence.theorem.unwrap().statement_sha256,
        Sha256Digest::of_bytes(b"old theorem")
    );
}
