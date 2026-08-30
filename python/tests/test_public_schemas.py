import json
import os
import subprocess
import tomllib
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "schemas"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def schema_registry() -> tuple[dict[str, object], Registry]:
    schemas: dict[str, object] = {}
    registry = Registry()
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return schemas, registry


def validator(name: str) -> Draft202012Validator:
    schemas, registry = schema_registry()
    return Draft202012Validator(schemas[name], registry=registry)


def sample_claim_status() -> dict[str, object]:
    premise = {
        "id": "DEMO-PREMISE-001",
        "statement": "The registered representation is faithful.",
        "category": "representation-premise",
        "scope": {"kind": "all-registered-inputs"},
        "discharge_rejection_reasons": [],
    }
    return {
        "schema": "proofbound-claim-status/1",
        "claim_id": "DEMO-CLAIM-001",
        "public_statement": "The claim remains open under its registered premise.",
        "formal": "OPEN",
        "linkage": "MODEL_ONLY",
        "assumption": {
            "standing": "ASSUMED",
            "assumptions": [],
            "undischarged_premises": [premise],
        },
        "policy": {"admitted": True, "blockers": []},
        "evidence": [],
        "bounded_domains": [],
        "premises": [premise],
        "not_proved_out_of_scope": {
            "open_obligations": [],
            "undischarged_premises": [premise],
            "explicit_assumptions": [],
            "exclusions": [],
        },
        "errors": [],
    }


def test_every_public_schema_is_valid_draft_2020_12() -> None:
    schemas, _ = schema_registry()
    assert schemas


def test_actual_runtime_closure_records_match_public_schema() -> None:
    configured_target = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    target = configured_target if configured_target.is_absolute() else ROOT / configured_target
    producer_fixture = target / "proofbound-schema-fixtures" / "closure-record.json"
    if not producer_fixture.is_file():
        subprocess.run(
            [
                "cargo",
                "test",
                "--quiet",
                "--locked",
                "--offline",
                "-p",
                "proofbound-evidence",
                "runtime_closure_record_is_emitted_for_public_schema_test",
            ],
            cwd=ROOT,
            check=True,
        )

    produced = [producer_fixture]
    produced.extend(sorted((ROOT / ".proofbound" / "closures").glob("*.json")))
    validate = validator("closure.schema.json")
    for path in produced:
        validate.validate(load_json(path))


def test_standalone_verifier_release_fixture_matches_shipped_receipt_schema() -> None:
    validate = validator("receipt.schema.json")
    release = ROOT / "proofbound" / "conformance" / "v1" / "release-valid"
    validate.validate(load_json(release / "release.json"))
    compiled = load_json(release / "compiled-receipt.json")
    validate.validate(compiled)
    validator("graph.schema.json").validate(compiled["graph"])


def test_runtime_report_and_graph_export_shapes_match_public_schemas() -> None:
    status = sample_claim_status()
    report = {
        "schema": "proofbound-report/1",
        "project": "proofbound",
        "project_revision": "90a117e",
        "claims": [status],
        "publication_blocked": False,
        "not_proved_out_of_scope": {
            "open_obligations": [],
            "undischarged_premises": ["DEMO-PREMISE-001"],
            "assumptions": [],
            "exclusions": [],
        },
    }
    graph = {
        "schema": "proofbound-graph-export/1",
        "project": "proofbound",
        "revision": "90a117e",
        "nodes": [
            {"id": "claim:DEMO-CLAIM-001", "kind": "claim"},
            {"id": "premise:DEMO-PREMISE-001", "kind": "premise"},
        ],
        "edges": [
            {
                "from": "claim:DEMO-CLAIM-001",
                "to": "premise:DEMO-PREMISE-001",
                "kind": "assumes",
            }
        ],
        "claims": [status],
    }
    validator("report.schema.json").validate(report)
    validator("graph.schema.json").validate(graph)


def test_tcb_ledger_schema_matches_the_release_projection() -> None:
    ledger = {
        "schema": "proofbound-tcb-ledger/1",
        "components": [
            {
                "name": "proofbound-adapter-test",
                "version": "0.5.0",
                "identity_sha256": f"sha256:{'01' * 32}",
            },
            {
                "name": "rust-test",
                "version": "1.94.0",
                "identity_sha256": f"sha256:{'02' * 32}",
            },
        ],
    }
    validate = validator("tcb.schema.json")
    validate.validate(ledger)

    ledger["components"][0]["invented_kind"] = "compiler"
    assert list(validate.iter_errors(ledger))


def test_adapter_schema_forbids_evidence_on_failure() -> None:
    response = {
        "schema": "proofbound-adapter-protocol/1",
        "type": "response",
        "request_id": "0123456789abcdef0123456789abcdef",
        "adapter": "lean",
        "success": False,
        "evidence": {"schema": "proofbound-evidence/1"},
        "inventory": [],
        "diagnostics": [],
    }
    assert list(validator("adapter-protocol.schema.json").iter_errors(response))


def test_auxiliary_adapter_manifests_match_strict_public_schemas() -> None:
    mutation = tomllib.loads(
        (
            ROOT
            / "demo"
            / "allowance"
            / "proofbound"
            / "mutations"
            / "transfer-guards.toml"
        ).read_text(encoding="utf-8")
    )
    translation_lock = tomllib.loads(
        (ROOT / "proofbound" / "toolchains" / "translation.lock").read_text(
            encoding="utf-8"
        )
    )
    validator("mutation-registry.schema.json").validate(mutation)
    validator("translation-toolchain-lock.schema.json").validate(translation_lock)

    mutation["unexpected"] = True
    translation_lock["unexpected"] = True
    assert list(validator("mutation-registry.schema.json").iter_errors(mutation))
    assert list(
        validator("translation-toolchain-lock.schema.json").iter_errors(translation_lock)
    )


def test_every_shipped_template_manifest_matches_its_public_schema() -> None:
    template_contracts = {
        "templates/explicit-assumption/claim.toml": "claim.schema.json",
        "templates/explicit-assumption/assumption.toml": "assumption.schema.json",
        "templates/explicit-assumption/evidence-unit.toml": "evidence-unit.schema.json",
        "templates/artifact-checker/manifests/claim.toml": "claim.schema.json",
        "templates/artifact-checker/manifests/theorem-evidence.toml": "evidence-unit.schema.json",
        "templates/artifact-checker/manifests/artifact-evidence.toml": "evidence-unit.schema.json",
        "templates/artifact-checker/manifests/independent-evidence.toml": "evidence-unit.schema.json",
        "templates/rust-aeneas-refinement/claim.toml": "claim.schema.json",
        "templates/rust-aeneas-refinement/representation-premise.toml": "assumption.schema.json",
        "templates/rust-aeneas-refinement/source-refinement-evidence.toml": "evidence-unit.schema.json",
        "templates/rust-aeneas-refinement/translation-unit.toml": "translation-unit.schema.json",
    }
    assert {
        path.as_posix()
        for path in (ROOT / "templates").rglob("*.toml")
        if path.name != "Cargo.toml"
    } == {
        (ROOT / relative).as_posix() for relative in template_contracts
    }
    for relative, schema in template_contracts.items():
        with (ROOT / relative).open("rb") as source:
            validator(schema).validate(tomllib.load(source))


def test_structured_error_contract_is_closed_and_complete() -> None:
    error = {
        "schema": "proofbound-error/1",
        "code": "PB-RECEIPT-0001",
        "message": "No compiled result exists.",
        "claim_id": None,
        "unit_id": None,
        "file": ".proofbound/compiled/project.json",
        "logical_path": None,
        "byte_offset": None,
        "expected_identity": None,
        "actual_identity": None,
        "affected_claims": [],
        "remediation": "Run proofbound check first.",
    }
    validator("error.schema.json").validate(error)
    error["optimistic_override"] = True
    assert list(validator("error.schema.json").iter_errors(error))
