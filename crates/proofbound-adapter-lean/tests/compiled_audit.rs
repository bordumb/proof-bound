use std::{collections::BTreeMap, path::Path};

use proofbound_adapter_lean::{
    audit::verify_audit,
    model::{
        AuditSource, DeclarationKind, ExpectedClaim, LEAN_ADAPTER_UNIT_SCHEMA, LeanAdapterUnit,
    },
    runtime::execute_audit,
};
use proofbound_core::EnvironmentId;
use proofbound_manifest::{
    AdapterKind, AdapterOperation, EvaluationMode, EvidenceKind, EvidenceUnitManifest,
    OperationKind, ResourceBudget,
};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("adapter crate is nested below the workspace root")
}

fn compiled_demo_unit() -> LeanAdapterUnit {
    LeanAdapterUnit {
        schema: LEAN_ADAPTER_UNIT_SCHEMA.to_owned(),
        evidence_unit: EvidenceUnitManifest {
            schema: "proofbound-evidence-unit/1".to_owned(),
            id: "compiled-audit-smoke".to_owned(),
            adapter: AdapterKind::Lean,
            kind: EvidenceKind::Theorem,
            claims: vec!["PBAC-SUM-001".to_owned()],
            tier: 2,
            operation: AdapterOperation {
                kind: OperationKind::LeanAudit,
                package: None,
                targets: vec!["ProofboundArtifactDemo.Claims".to_owned()],
                paths: vec![
                    "demo/artifact-certificate/lean/ProofboundArtifactDemo/Certificate.lean"
                        .to_owned(),
                    "demo/artifact-certificate/lean/ProofboundArtifactDemo/Claims.lean".to_owned(),
                    "lean/Proofbound/Artifact.lean".to_owned(),
                    "lean/Proofbound/Sha256.lean".to_owned(),
                ],
                manifest: None,
                inventory: None,
                checker: None,
                arguments: Vec::new(),
            },
            evaluation_mode: Some(EvaluationMode::Native),
            binding_mode: None,
            theorem: Some(
                "ProofboundArtifactDemo.Claims.publishedArtifactSoundness".to_owned(),
            ),
            refinement_theorem: None,
            premises: Vec::new(),
            assumptions: vec!["PBAC-NATIVE-SHA256-001".to_owned()],
            expected_inventory: Vec::new(),
            inputs: vec![
                "demo/artifact-certificate/lean/ProofboundArtifactDemo/Certificate.lean".to_owned(),
                "demo/artifact-certificate/lean/ProofboundArtifactDemo/Claims.lean".to_owned(),
                "lean/Proofbound/Artifact.lean".to_owned(),
                "lean/Proofbound/Sha256.lean".to_owned(),
            ],
            outputs: Vec::new(),
            environment_allowlist: vec!["LEAN_PATH".to_owned()],
            bounded_domain: None,
            resource_budget: ResourceBudget {
                time_seconds: 60,
                disk_bytes: 256 << 20,
                memory_bytes: 1 << 30,
            },
        },
        environment_id: EnvironmentId::new("lean:workspace-smoke").unwrap(),
        claim_inventory: vec![
            ExpectedClaim {
                claim_id: "PBAC-CALIBRATED-001".to_owned(),
                declaration:
                    "ProofboundArtifactDemo.Claims.publishedCalibratedArtifactSoundness".to_owned(),
                declaration_kind: DeclarationKind::Theorem,
                statement_sha256: None,
                foundational_axioms: vec![
                    "Classical.choice".to_owned(),
                    "ProofboundArtifactDemo.Claims.publishedCalibratedArtifactSoundness._native.native_decide.ax_1_1".to_owned(),
                    "Quot.sound".to_owned(),
                    "propext".to_owned(),
                ],
                project_axioms: BTreeMap::from([(
                    "ProofboundArtifactDemo.Claims.providerMeasurementsAccurate".to_owned(),
                    "PBAC-CALIBRATION-AX-001".to_owned(),
                )]),
            },
            ExpectedClaim {
                claim_id: "PBAC-SUM-001".to_owned(),
                declaration: "ProofboundArtifactDemo.Claims.publishedArtifactSoundness".to_owned(),
                declaration_kind: DeclarationKind::Theorem,
                statement_sha256: None,
                foundational_axioms: vec![
                    "Classical.choice".to_owned(),
                    "ProofboundArtifactDemo.Claims.publishedArtifactSoundness._native.native_decide.ax_1_1".to_owned(),
                    "Quot.sound".to_owned(),
                    "propext".to_owned(),
                ],
                project_axioms: BTreeMap::new(),
            },
        ],
        audit: AuditSource::Execute,
    }
}

#[test]
#[ignore = "requires the pinned Lean toolchain and compiled workspace audit executable"]
fn executes_the_compiled_attribute_and_axiom_audit() {
    let unit = compiled_demo_unit();
    let run = execute_audit(root(), &unit).unwrap();
    let verified = verify_audit(&unit, &run.output, false).unwrap();
    assert_eq!(
        verified.inventory,
        [
            "ProofboundArtifactDemo.Claims.publishedArtifactSoundness".to_owned(),
            "ProofboundArtifactDemo.Claims.publishedCalibratedArtifactSoundness".to_owned(),
        ]
        .into_iter()
        .collect()
    );
}
