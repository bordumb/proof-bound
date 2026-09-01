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
        "schema": "proofbound-evidence/3",
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
                "version": "0.11.0",
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
        "schema": "proofbound-adapter-observation/2",
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


def sample_artifact_checker_result() -> dict[str, object]:
    return {
        "schema": "proofbound-artifact-check-result/1",
        "accepted": True,
        "artifact_logical_name": "fixtures/valid-basic.pbac",
        "artifact_sha256": f"sha256:{'01' * 32}",
        "inventory": ["valid-basic.pbac"],
    }


def sample_independent_checker_result() -> dict[str, object]:
    return {
        "schema": "proofbound-independent-check-result/1",
        "accepted": True,
        "inventory": ["valid-basic.pbac"],
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

    invalid_inventory = json.loads(json.dumps(compiled))
    invalid_inventory["evidence"][0]["record"]["inventoried_targets"] = [
        "target\u0085smuggled"
    ]
    assert list(validate.iter_errors(invalid_inventory))

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
    internal_record = compiler_internal["evidence"][0]["record"]
    provenance = internal_record["provenance"]
    provenance["execution_kind"] = "compiler-internal"
    provenance["commands"] = []
    provenance["runs"] = []
    internal_record["inventoried_targets"] = []
    validate.validate(compiler_internal)

    observed_without_inventory = json.loads(json.dumps(compiled))
    observed_without_inventory["evidence"][0]["record"]["inventoried_targets"] = []
    assert list(validate.iter_errors(observed_without_inventory))

    for field, value in [("exit_code", 1), ("output_truncated", True)]:
        invalid_run = json.loads(json.dumps(compiled))
        invalid_run["evidence"][0]["record"]["provenance"]["runs"][0][field] = value
        assert list(validate.iter_errors(invalid_run))

    failed_observation = json.loads(json.dumps(compiled))
    failed_record = failed_observation["evidence"][0]["record"]
    failed_record["outcome"] = "failed"
    failed_record["inventoried_targets"] = []
    failed_record["provenance"]["runs"][0]["exit_code"] = 1
    failed_record["provenance"]["runs"][0]["output_truncated"] = True
    validate.validate(failed_observation)


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
        "evidence": {"schema": "proofbound-evidence/3"},
        "inventory": [],
        "diagnostics": [],
    }
    assert list(validator("adapter-protocol.schema.json").iter_errors(response))

    response["evidence"] = None
    response["inventory"] = ["must-not-survive-failure"]
    assert list(validator("adapter-protocol.schema.json").iter_errors(response))

    response["success"] = True
    response["evidence"] = None
    response["inventory"] = ["   "]
    assert list(validator("adapter-protocol.schema.json").iter_errors(response))


def test_checker_result_schema_is_closed_nonempty_and_exact() -> None:
    validate = validator("checker-result.schema.json")
    artifact = sample_artifact_checker_result()
    independent = sample_independent_checker_result()
    validate.validate(artifact)
    validate.validate(independent)

    for valid in [artifact, independent]:
        unknown = json.loads(json.dumps(valid))
        unknown["claims"] = ["DEMO-CLAIM-001"]
        assert list(validate.iter_errors(unknown))

        empty = json.loads(json.dumps(valid))
        empty["inventory"] = []
        assert list(validate.iter_errors(empty))

        duplicate = json.loads(json.dumps(valid))
        duplicate["inventory"] = ["same", "same"]
        assert list(validate.iter_errors(duplicate))

        for control_item in [
            "valid\nsmuggled",
            "valid\u0000smuggled",
            "valid\u007fsmuggled",
            "valid\u0085smuggled",
            "   ",
        ]:
            control = json.loads(json.dumps(valid))
            control["inventory"] = [control_item]
            assert list(validate.iter_errors(control))

        maximum = json.loads(json.dumps(valid))
        maximum["inventory"] = ["é" * 4096]
        validate.validate(maximum)

        oversized = json.loads(json.dumps(valid))
        oversized["inventory"] = ["é" * 4097]
        assert list(validate.iter_errors(oversized))

        failure_shape = json.loads(json.dumps(valid))
        failure_shape["accepted"] = False
        assert list(validate.iter_errors(failure_shape))

    artifact_control = sample_artifact_checker_result()
    artifact_control["artifact_logical_name"] = "fixtures/valid\u007f.pbac"
    assert list(validate.iter_errors(artifact_control))

    artifact_failure = {
        "schema": "proofbound-artifact-check-result/1",
        "accepted": False,
        "error": "diagnostic only",
    }
    assert list(validate.iter_errors(artifact_failure))

    cross_route_shape = sample_independent_checker_result()
    cross_route_shape["artifact_sha256"] = f"sha256:{'01' * 32}"
    assert list(validate.iter_errors(cross_route_shape))


def test_checker_result_wire_requires_one_canonical_json_value() -> None:
    validate = validator("checker-result.schema.json")
    value = sample_independent_checker_result()
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    parsed = json.loads(payload)
    validate.validate(parsed)
    assert json.dumps(parsed, sort_keys=True, separators=(",", ":")) == payload

    for trailing in ["\n", "{}", "[]"]:
        framed = payload + trailing
        try:
            candidate = json.loads(framed)
        except json.JSONDecodeError:
            continue
        assert json.dumps(candidate, sort_keys=True, separators=(",", ":")) != framed


def test_version_3_evidence_schema_preserves_receipt_fidelity() -> None:
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
    evidence["inventoried_targets"] = []
    validate.validate(evidence)

    evidence = sample_bounded_evidence()
    evidence["inventoried_targets"] = []
    assert list(validate.iter_errors(evidence))

    evidence["inventoried_targets"] = ["target\u0085smuggled"]
    assert list(validate.iter_errors(evidence))

    for field, value in [("exit_code", 1), ("output_truncated", True)]:
        evidence = sample_bounded_evidence()
        evidence["provenance"]["runs"][0][field] = value
        assert list(validate.iter_errors(evidence))

    failed = sample_bounded_evidence()
    failed["status"] = "failed"
    failed["inventoried_targets"] = []
    failed["provenance"]["runs"][0]["exit_code"] = 1
    failed["provenance"]["runs"][0]["output_truncated"] = True
    validate.validate(failed)


def test_adapter_observation_schema_keeps_ordered_execution_facts() -> None:
    validate = validator("adapter-observation.schema.json")
    observation = sample_adapter_observation()
    validate.validate(observation)

    observation["normalization"] = "   "
    assert list(validate.iter_errors(observation))

    observation = sample_adapter_observation()
    del observation["runs"][0]["exit_code"]
    assert list(validate.iter_errors(observation))

    observation = sample_adapter_observation()
    observation["inventory"] = ["   "]
    assert list(validate.iter_errors(observation))

    for field, value in [("exit_code", 1), ("output_truncated", True)]:
        observation = sample_adapter_observation()
        observation["runs"][0][field] = value
        assert list(validate.iter_errors(observation))

    failed = sample_adapter_observation()
    failed["outcome"] = "failed"
    failed["inventory"] = []
    failed["runs"][0]["exit_code"] = 1
    failed["runs"][0]["output_truncated"] = True
    validate.validate(failed)


def test_auxiliary_adapter_manifests_match_strict_public_schemas() -> None:
    mutation_paths = sorted(
        (ROOT / "demo/allowance/proofbound/mutations").glob("remove-*.toml")
    )
    assert len(mutation_paths) == 5
    mutations = [
        tomllib.loads(path.read_text(encoding="utf-8")) for path in mutation_paths
    ]
    translation_lock = tomllib.loads(
        (ROOT / "proofbound" / "toolchains" / "translation.lock").read_text(
            encoding="utf-8"
        )
    )
    mutation_validator = validator("mutation-registry.schema.json")
    for mutation in mutations:
        mutation_validator.validate(mutation)
    validator("translation-toolchain-lock.schema.json").validate(translation_lock)

    mutation = json.loads(json.dumps(mutations[0]))
    mutation["unexpected"] = True
    translation_lock["unexpected"] = True
    assert list(mutation_validator.iter_errors(mutation))
    legacy = {
        "schema": "proofbound-mutation-registry/1",
        "subject": "rust:subject",
        "mutations": [mutations[0]["mutation"], mutations[1]["mutation"]],
    }
    assert list(mutation_validator.iter_errors(legacy))
    assert list(
        validator("translation-toolchain-lock.schema.json").iter_errors(
            translation_lock
        )
    )


def test_translation_unit_v3_schema_closes_invocations_outputs_and_report_inventory() -> (
    None
):
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

    version_2 = json.loads(json.dumps(translation))
    version_2["schema"] = "proofbound-translation-unit/2"
    assert list(validate.iter_errors(version_2))

    advisory = json.loads(json.dumps(translation))
    advisory["adapter"] = "charon-aeneas"
    assert list(validate.iter_errors(advisory))

    missing_identity = json.loads(json.dumps(translation))
    del missing_identity["invocations"][0]["cargo_manifest"]
    assert list(validate.iter_errors(missing_identity))

    missing_closure = json.loads(json.dumps(translation))
    del missing_closure["invocations"][0]["translated_closure"]
    assert list(validate.iter_errors(missing_closure))

    invalid_closure_kind = json.loads(json.dumps(translation))
    invalid_closure_kind["invocations"][0]["translated_closure"][0]["kind"] = "global"
    assert list(validate.iter_errors(invalid_closure_kind))

    invalid_closure_name = json.loads(json.dumps(translation))
    invalid_closure_name["invocations"][0]["translated_closure"][0]["rust_name"] = (
        " allowance_kernel::decide_transfer"
    )
    assert list(validate.iter_errors(invalid_closure_name))

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
        "templates/trusted-transcription/claim.toml": "claim.schema.json",
        "templates/trusted-transcription/evidence-unit.toml": "evidence-unit.schema.json",
    }
    assert {
        path.as_posix()
        for path in (ROOT / "templates").rglob("*.toml")
        if path.name != "Cargo.toml"
    } == {(ROOT / relative).as_posix() for relative in template_contracts}
    for relative, schema in template_contracts.items():
        with (ROOT / relative).open("rb") as source:
            validator(schema).validate(tomllib.load(source))


def test_evidence_unit_routes_and_registered_inventory_are_closed() -> None:
    validate = validator("evidence-unit.schema.json")
    with (ROOT / "templates/explicit-assumption/evidence-unit.toml").open(
        "rb"
    ) as source:
        base = tomllib.load(source)

    supported = [
        ("lean", "lean-audit", "theorem"),
        ("charon-aeneas", "translation", "source-refinement"),
        ("kani", "kani", "bounded-check"),
        ("rust-test", "cargo-test", "example-test"),
        ("rust-test", "cargo-test", "property-test"),
        ("python-test", "pytest", "example-test"),
        ("python-test", "pytest", "property-test"),
        ("python-test", "generator", "example-test"),
        ("canonical-artifact", "artifact-check", "artifact-soundness"),
        ("independent-check", "independent-check", "independent-check"),
    ]
    for adapter, operation, kind in supported:
        candidate = json.loads(json.dumps(base))
        candidate["adapter"] = adapter
        candidate["operation"]["type"] = operation
        candidate["kind"] = kind
        if adapter == "charon-aeneas":
            candidate.pop("expected_inventory")
        else:
            candidate["expected_inventory"] = ["z", "a"]
        validate.validate(candidate)

    unsupported = [
        ("lean", "lean-audit", "example-test"),
        ("charon-aeneas", "translation", "example-test"),
        ("kani", "kani", "example-test"),
        ("rust-test", "cargo-test", "exhaustive-check"),
        ("rust-test", "cargo-test", "mutation-witness"),
        ("python-test", "pytest", "exhaustive-check"),
        ("python-test", "generator", "property-test"),
        ("canonical-artifact", "artifact-check", "independent-check"),
        ("independent-check", "independent-check", "example-test"),
        ("human-review", "review", "review"),
        ("source-closure", "closure", "review"),
    ]
    for adapter, operation, kind in unsupported:
        candidate = json.loads(json.dumps(base))
        candidate["adapter"] = adapter
        candidate["operation"]["type"] = operation
        candidate["kind"] = kind
        assert list(validate.iter_errors(candidate)), (adapter, operation, kind)

    for invalid_inventory in [
        [],
        ["same", "same"],
        ["\u2003"],
        ["target\u001fsmuggled"],
        ["target\u007fsmuggled"],
        ["target\u0085smuggled"],
        ["x" * 4097],
    ]:
        candidate = json.loads(json.dumps(base))
        candidate["expected_inventory"] = invalid_inventory
        assert list(validate.iter_errors(candidate)), invalid_inventory

    aeneas = json.loads(json.dumps(base))
    aeneas["adapter"] = "charon-aeneas"
    aeneas["operation"]["type"] = "translation"
    aeneas["kind"] = "source-refinement"
    aeneas["expected_inventory"] = ["checker-authored-selector"]
    assert list(validate.iter_errors(aeneas))

    with (ROOT / "templates/trusted-transcription/evidence-unit.toml").open(
        "rb"
    ) as source:
        transcription = tomllib.load(source)
    for required in [
        "expected_inventory",
        "inputs",
        "outputs",
        "environment_allowlist",
    ]:
        missing = json.loads(json.dumps(transcription))
        del missing[required]
        assert list(validate.iter_errors(missing)), required


def test_mutation_replay_route_is_versioned_singleton_and_closed() -> None:
    unit_path = (
        ROOT / "demo/allowance/proofbound/evidence/remove-authorization-guard.toml"
    )
    with unit_path.open("rb") as source:
        unit = tomllib.load(source)
    validate = validator("evidence-unit.schema.json")
    validate.validate(unit)

    for legacy_schema in ["proofbound-evidence-unit/1", "proofbound-evidence-unit/2"]:
        legacy = json.loads(json.dumps(unit))
        legacy["schema"] = legacy_schema
        assert list(validate.iter_errors(legacy)), legacy_schema

    for field in ["mutation", "expected_inventory", "inputs", "outputs"]:
        missing = json.loads(json.dumps(unit))
        del missing[field]
        assert list(validate.iter_errors(missing)), field

    extra_target = json.loads(json.dumps(unit))
    extra_target["operation"]["targets"] = ["checker-authored-alias"]
    assert list(validate.iter_errors(extra_target))

    shared_fate = json.loads(json.dumps(unit))
    shared_fate["expected_inventory"].append("another-mutation")
    assert list(validate.iter_errors(shared_fate))


def test_typescript_routes_are_exact_and_ecosystem_coupled() -> None:
    validate_unit = validator("evidence-unit.schema.json")
    validate_mutation = validator("mutation-registry.schema.json")
    root = ROOT / "demo/typescript-codec"

    units = {
        path.stem: tomllib.loads(path.read_text(encoding="utf-8"))
        for path in sorted((root / "evidence").glob("*.toml"))
    }
    assert set(units) == {
        "bounded-roundtrip",
        "npm-package",
        "reject-padding-mutant",
        "reject-padding",
        "strict-types",
    }
    for unit in units.values():
        validate_unit.validate(unit)
    validate_mutation.validate(
        tomllib.loads(
            (root / "mutations/reject-padding.toml").read_text(encoding="utf-8")
        )
    )

    reserved = json.loads(json.dumps(units["strict-types"]))
    reserved["operation"]["type"] = "tsgo"
    assert list(validate_unit.iter_errors(reserved))

    smuggled_argument = json.loads(json.dumps(units["reject-padding"]))
    smuggled_argument["operation"]["arguments"] = ["--run-anything"]
    assert list(validate_unit.iter_errors(smuggled_argument))

    mismatched_mutation = json.loads(json.dumps(units["reject-padding-mutant"]))
    mismatched_mutation["adapter"] = "rust-test"
    assert list(validate_unit.iter_errors(mismatched_mutation))

    mismatched_distribution = json.loads(json.dumps(units["npm-package"]))
    mismatched_distribution["adapter"] = "python-test"
    assert list(validate_unit.iter_errors(mismatched_distribution))

    nonzero_epoch = json.loads(json.dumps(units["npm-package"]))
    nonzero_epoch["distribution"]["source_date_epoch"] = 1
    assert list(validate_unit.iter_errors(nonzero_epoch))


def test_python_routes_are_exact_and_reserved_analyzers_fail_closed() -> None:
    validate_unit = validator("evidence-unit.schema.json")
    validate_mutation = validator("mutation-registry.schema.json")
    root = ROOT / "demo/python-inventory-service"
    names = [
        "reservation-property",
        "reservation-types",
        "reservation-mutant",
        "wheel-reproduction",
    ]
    units = {
        name: tomllib.loads(
            (root / f"evidence/{name}.toml").read_text(encoding="utf-8")
        )
        for name in names
    }
    for unit in units.values():
        validate_unit.validate(unit)
    validate_mutation.validate(
        tomllib.loads(
            (root / "mutations/accept-over-cap.toml").read_text(encoding="utf-8")
        )
    )

    reserved = json.loads(json.dumps(units["reservation-types"]))
    reserved["operation"]["type"] = "pyright"
    assert list(validate_unit.iter_errors(reserved))


def test_npm_distribution_records_require_integrity_and_member_inventory() -> None:
    schemas, registry = schema_registry()
    definitions = [
        ("adapter-observation.schema.json", "distribution_reproduction"),
        ("evidence.schema.json", "distributionReproduction"),
        ("receipt.schema.json", "distributionReproductionReceipt"),
    ]
    digest = f"sha256:{'01' * 32}"
    valid = {
        "schema": "proofbound-distribution-reproduction/1",
        "format": "npm-package",
        "run_digests": [digest, digest],
        "registered_digest": digest,
        "source_date_epoch": 0,
        "build_backend_name": "npm",
        "build_backend_version": "10.9.0",
        "npm_integrity": "sha512-Zml4dHVyZQ==",
        "member_inventory": ["package.json", "src/index.ts"],
    }
    for schema_name, definition in definitions:
        definition_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"#/$defs/{definition}",
            "$defs": schemas[schema_name]["$defs"],
        }
        validate = Draft202012Validator(definition_schema, registry=registry)
        validate.validate(valid)

        missing_integrity = json.loads(json.dumps(valid))
        del missing_integrity["npm_integrity"]
        assert list(validate.iter_errors(missing_integrity))

        empty_members = json.loads(json.dumps(valid))
        empty_members["member_inventory"] = []
        assert list(validate.iter_errors(empty_members))

        wrong_backend = json.loads(json.dumps(valid))
        wrong_backend["build_backend_name"] = "custom-script"
        assert list(validate.iter_errors(wrong_backend))


def test_trusted_transcription_route_is_versioned_and_closed() -> None:
    with (ROOT / "demo/trusted-transcription/evidence/trusted-values.toml").open(
        "rb"
    ) as source:
        unit = tomllib.load(source)
    validate_unit = validator("evidence-unit.schema.json")
    validate_unit.validate(unit)

    legacy = json.loads(json.dumps(unit))
    legacy["schema"] = "proofbound-evidence-unit/1"
    assert list(validate_unit.iter_errors(legacy))

    smuggled = json.loads(json.dumps(unit))
    smuggled["operation"]["arguments"] = ["--accept-anything"]
    assert list(validate_unit.iter_errors(smuggled))

    extra_environment = json.loads(json.dumps(unit))
    extra_environment["environment_allowlist"].append("HOME")
    assert list(validate_unit.iter_errors(extra_environment))

    digest = f"sha256:{'01' * 32}"
    artifact = {"logical_name": "source", "sha256": digest, "size_bytes": 1}
    observation = sample_adapter_observation()
    observation["evidence_kind"] = "trusted-transcription"
    observation["inventory"] = ["source", "transcribed"]
    observation["trusted_transcription"] = {
        "schema": "proofbound-trusted-transcription/1",
        "source": artifact,
        "committed_transcription": {
            "logical_name": "transcribed",
            "sha256": digest,
            "size_bytes": 1,
        },
        "transcribed_candidate": {
            "logical_name": "candidate",
            "sha256": digest,
            "size_bytes": 1,
        },
        "reencoded_source": {
            "logical_name": "reencoded",
            "sha256": digest,
            "size_bytes": 1,
        },
        "driver": {"logical_name": "driver", "sha256": digest, "size_bytes": 1},
        "driver_abi": "proofbound-transcription-driver/1",
        "source_format": "proofbound-u32-lines/1",
        "transcribed_format": "proofbound-u32-json/1",
        "transcriber_role_identity": digest,
        "reencoder_role_identity": digest,
    }
    validator("adapter-observation.schema.json").validate(observation)

    del observation["trusted_transcription"]
    assert list(validator("adapter-observation.schema.json").iter_errors(observation))

    evidence = sample_bounded_evidence()
    evidence["kind"] = "trusted-transcription"
    evidence["binding_mode"] = "external-round-trip"
    del evidence["bounded_check"]
    role = {"tcb_node": "tcb:transcriber", "role_identity": digest}
    evidence["trusted_transcription"] = {
        "schema": "proofbound-trusted-transcription/1",
        "source": artifact,
        "committed_transcription": artifact,
        "transcribed_candidate": artifact,
        "reencoded_source": artifact,
        "driver": artifact,
        "transcriber": role,
        "reencoder": {"tcb_node": "tcb:reencoder", "role_identity": digest},
    }
    validate_evidence = validator("evidence.schema.json")
    validate_evidence.validate(evidence)

    evidence["trusted_transcription"] = {
        "transcriber_tcb": "tcb:transcriber",
        "reencoder_tcb": "tcb:reencoder",
        "round_trip_passed": True,
    }
    assert list(validate_evidence.iter_errors(evidence))


def test_shipped_transcription_drivers_round_trip_the_fresh_candidate(
    tmp_path: Path,
) -> None:
    for relative in ["demo/trusted-transcription", "templates/trusted-transcription"]:
        root = ROOT / relative
        candidate = tmp_path / f"{root.parent.name}-candidate.json"
        reencoded = tmp_path / f"{root.parent.name}-reencoded.pbtt"
        subprocess.run(
            [
                "python3",
                str(root / "python/transcription_driver.py"),
                "transcribe",
                "--source",
                str(root / "source/values.pbtt"),
                "--output",
                str(candidate),
            ],
            check=True,
        )
        assert candidate.read_bytes() == (root / "transcribed/values.json").read_bytes()
        subprocess.run(
            [
                "python3",
                str(root / "python/transcription_driver.py"),
                "reencode",
                "--transcription",
                str(candidate),
                "--output",
                str(reencoded),
            ],
            check=True,
        )
        assert reencoded.read_bytes() == (root / "source/values.pbtt").read_bytes()


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
