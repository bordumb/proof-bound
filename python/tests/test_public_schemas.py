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


def sample_bounded_evidence() -> dict[str, object]:
    digest = f"sha256:{'01' * 32}"
    command = {
        "program": "kani",
        "args": ["--harness", "check_registered_case"],
        "environment_allowlist": [],
    }
    return {
        "schema": "proofbound-evidence/2",
        "id": "kani:registered-case",
        "node_id": "evidence:kani:registered-case",
        "unit_id": "unit:registered-case",
        "kind": "bounded-check",
        "status": "passed",
        "claims": ["DEMO-CLAIM-001"],
        "inventoried_targets": ["check_registered_case"],
        "assumptions": [],
        "premises": [],
        "bounded_check": {
            "domain": {
                "id": "registered-domain",
                "description": "The registered finite inputs.",
                "registration_sha256": digest,
                "constraints": [],
            },
            "solver": "cadical",
            "harnesses": ["check_registered_case"],
            "unwind_bounds": {"check_registered_case": 6},
            "assumptions": ["Allocator calls do not fail."],
        },
        "provenance": {
            "project_revision": "90a117e",
            "tree_state": "clean",
            "semantic_source_closure": digest,
            "additional_closures": [],
            "input_artifacts": [],
            "generated_artifacts": [],
            "tool": {
                "name": "kani",
                "version": "1.0.0",
                "identity_sha256": digest,
            },
            "adapter": {
                "name": "proofbound-adapter-kani",
                "version": "0.8.0",
                "identity_sha256": digest,
            },
            "execution_kind": "observed-processes",
            "commands": [command],
            "runs": [
                {
                    "command_index": 0,
                    "exit_code": 0,
                    "stdout_sha256": digest,
                    "stderr_sha256": digest,
                    "normalized_output_sha256": digest,
                    "output_truncated": False,
                    "duration_ms": 12,
                }
            ],
            "normalization": "stable-tool-output/1",
            "reproduction_command": command,
            "started_unix_ms": 1,
            "completed_unix_ms": 13,
            "deterministic_result_identity": digest,
            "unit_configuration_sha256": digest,
            "resource_budget": {
                "time_ms": 1000,
                "disk_bytes": 1024,
                "memory_bytes": 2048,
            },
            "resource_usage": {
                "time_ms": 12,
                "peak_disk_bytes": 512,
                "peak_memory_bytes": None,
            },
            "cache_origin": "executed",
        },
    }


def sample_adapter_observation() -> dict[str, object]:
    evidence = sample_bounded_evidence()
    provenance = evidence["provenance"]
    assert isinstance(provenance, dict)
    return {
        "schema": "proofbound-adapter-observation/1",
        "unit_id": "registered-case",
        "evidence_kind": "bounded-check",
        "outcome": "passed",
        "input_artifacts": [],
        "generated_artifacts": [],
        "tool": provenance["tool"],
        "adapter": provenance["adapter"],
        "commands": provenance["commands"],
        "runs": provenance["runs"],
        "started_unix_ms": provenance["started_unix_ms"],
        "completed_unix_ms": provenance["completed_unix_ms"],
        "deterministic_result_sha256": provenance["deterministic_result_identity"],
        "unit_configuration_sha256": provenance["unit_configuration_sha256"],
        "resource_budget": provenance["resource_budget"],
        "resource_usage": provenance["resource_usage"],
        "inventory": ["check_registered_case"],
        "normalization": provenance["normalization"],
    }


def test_every_public_schema_is_valid_draft_2020_12() -> None:
    schemas, _ = schema_registry()
    assert schemas


def test_actual_runtime_closure_records_match_public_schema() -> None:
    configured_target = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
    target = (
        configured_target
        if configured_target.is_absolute()
        else ROOT / configured_target
    )
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

    observed_without_processes = json.loads(json.dumps(compiled))
    provenance = observed_without_processes["evidence"][0]["record"]["provenance"]
    provenance["execution_kind"] = "observed-processes"
    provenance["commands"] = []
    provenance["runs"] = []
    assert list(validate.iter_errors(observed_without_processes))

    internal_with_processes = json.loads(json.dumps(compiled))
    provenance = internal_with_processes["evidence"][0]["record"]["provenance"]
    provenance["execution_kind"] = "compiler-internal"
    assert list(validate.iter_errors(internal_with_processes))

    compiler_internal = json.loads(json.dumps(compiled))
    provenance = compiler_internal["evidence"][0]["record"]["provenance"]
    provenance["execution_kind"] = "compiler-internal"
    provenance["commands"] = []
    provenance["runs"] = []
    validate.validate(compiler_internal)


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
        "evidence": {"schema": "proofbound-evidence/2"},
        "inventory": [],
        "diagnostics": [],
    }
    assert list(validator("adapter-protocol.schema.json").iter_errors(response))


def test_version_2_evidence_schema_preserves_receipt_fidelity() -> None:
    validate = validator("evidence.schema.json")
    evidence = sample_bounded_evidence()
    validate.validate(evidence)

    evidence["provenance"]["resource_usage"]["peak_memory_bytes"] = 0
    validate.validate(evidence)

    del evidence["bounded_check"]["assumptions"]
    assert list(validate.iter_errors(evidence))
    evidence["bounded_check"]["assumptions"] = ["   "]
    assert list(validate.iter_errors(evidence))
    evidence["bounded_check"]["assumptions"] = ["same", "same"]
    assert list(validate.iter_errors(evidence))

    evidence = sample_bounded_evidence()
    del evidence["provenance"]["resource_usage"]["peak_memory_bytes"]
    assert list(validate.iter_errors(evidence))

    evidence = sample_bounded_evidence()
    evidence["provenance"]["command"] = evidence["provenance"].pop("commands")[0]
    assert list(validate.iter_errors(evidence))

    evidence = sample_bounded_evidence()
    del evidence["provenance"]["execution_kind"]
    assert list(validate.iter_errors(evidence))

    evidence = sample_bounded_evidence()
    evidence["provenance"]["commands"] = []
    evidence["provenance"]["runs"] = []
    assert list(validate.iter_errors(evidence))

    evidence = sample_bounded_evidence()
    evidence["provenance"]["execution_kind"] = "compiler-internal"
    assert list(validate.iter_errors(evidence))

    evidence["provenance"]["commands"] = []
    evidence["provenance"]["runs"] = []
    validate.validate(evidence)


def test_adapter_observation_schema_keeps_ordered_execution_facts() -> None:
    validate = validator("adapter-observation.schema.json")
    observation = sample_adapter_observation()
    validate.validate(observation)

    observation["normalization"] = "   "
    assert list(validate.iter_errors(observation))

    observation = sample_adapter_observation()
    del observation["runs"][0]["exit_code"]
    assert list(validate.iter_errors(observation))


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
        validator("translation-toolchain-lock.schema.json").iter_errors(
            translation_lock
        )
    )


def test_translation_unit_v2_schema_closes_invocations_and_outputs() -> None:
    validate = validator("translation-unit.schema.json")
    with (
        ROOT
        / "demo"
        / "allowance"
        / "proofbound"
        / "translations"
        / "transfer-kernel.toml"
    ).open("rb") as source:
        translation = tomllib.load(source)
    validate.validate(translation)

    version_1 = json.loads(json.dumps(translation))
    version_1["schema"] = "proofbound-translation-unit/1"
    assert list(validate.iter_errors(version_1))

    advisory = json.loads(json.dumps(translation))
    advisory["adapter"] = "charon-aeneas"
    assert list(validate.iter_errors(advisory))

    missing_identity = json.loads(json.dumps(translation))
    del missing_identity["invocations"][0]["cargo_manifest"]
    assert list(validate.iter_errors(missing_identity))

    selector_injection = json.loads(json.dumps(translation))
    selector_injection["invocations"][0]["start_from"] = [
        "allowance_kernel::decide_transfer,--include"
    ]
    assert list(validate.iter_errors(selector_injection))

    for invalid_id in ["allowance--kernel", "allowance-kernel-", "Allowance"]:
        invalid_invocation_id = json.loads(json.dumps(translation))
        invalid_invocation_id["invocations"][0]["id"] = invalid_id
        assert list(validate.iter_errors(invalid_invocation_id))

    for invalid_path in [
        "lean//Generated",
        "lean/Generated/",
        "lean\\Generated",
        "lean/Generated\nControl",
        "lean/Généré",
        ".git/Generated",
        "lean/target/Generated",
        "a" * 4097,
    ]:
        unsafe_path = json.loads(json.dumps(translation))
        unsafe_path["generated_dir"] = invalid_path
        assert list(validate.iter_errors(unsafe_path)), invalid_path

    incomplete_outputs = json.loads(json.dumps(translation))
    incomplete_outputs["invocations"][0]["outputs"] = incomplete_outputs["invocations"][
        0
    ]["outputs"][:1]
    assert list(validate.iter_errors(incomplete_outputs))

    mislabeled_output = json.loads(json.dumps(translation))
    mislabeled_output["invocations"][0]["outputs"][0]["kind"] = "translation-report"
    assert list(validate.iter_errors(mislabeled_output))

    for invalid_report in ["report.json", "Transfer/translation.json"]:
        misplaced_report = json.loads(json.dumps(translation))
        report = next(
            output
            for output in misplaced_report["invocations"][0]["outputs"]
            if output["kind"] == "translation-report"
        )
        report["produced"] = invalid_report
        assert list(validate.iter_errors(misplaced_report)), invalid_report

    missing_bridge_module = json.loads(json.dumps(translation))
    del missing_bridge_module["external_bridges"][0]["module"]
    assert list(validate.iter_errors(missing_bridge_module))

    unsupported_warning = json.loads(json.dumps(translation))
    unsupported_warning["warning_inventory"] = [
        {
            "artifact": unsupported_warning["invocations"][0]["outputs"][0][
                "destination"
            ],
            "line": 1,
            "kind": "arbitrary-warning",
        }
    ]
    assert list(validate.iter_errors(unsupported_warning))

    reserved_rewrite = json.loads(json.dumps(translation))
    reserved_rewrite["import_mapping"] = {
        "mode": "audited-rewrite",
        "rewrite_digest": f"sha256:{'01' * 32}",
    }
    validate.validate(reserved_rewrite)


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
    } == {(ROOT / relative).as_posix() for relative in template_contracts}
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
