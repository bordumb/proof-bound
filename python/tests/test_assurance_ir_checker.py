import json
import hashlib
from pathlib import Path
import subprocess

import pytest

from proofbound.assurance_ir_checker import (
    AssuranceIrError,
    canonical_json,
    check_canonical_vectors,
    check_projection,
    validate_case_program,
)


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/cases.json"
VECTORS = (
    ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/canonical-vectors.json"
)
ADVERSARIAL = (
    ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/adversarial-cases.json"
)


def producer_projection() -> bytes:
    return subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            str(ROOT),
            str(CORPUS),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def test_independent_checker_agrees_with_rust_projection() -> None:
    report = check_projection(ROOT, CORPUS, producer_projection())
    assert report.case_count == 20
    assert report.projection_sha256.startswith("sha256:")


def test_checker_rejects_projection_semantic_drift() -> None:
    value = json.loads(producer_projection())
    value["cases"][0]["evidence_family"] = "theorem"
    value.pop("projection_sha256")
    value["projection_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(AssuranceIrError, match="differs from independent"):
        check_projection(ROOT, CORPUS, canonical_json(value))


def test_checker_rejects_noncanonical_projection() -> None:
    with pytest.raises(AssuranceIrError, match="not canonical"):
        check_projection(ROOT, CORPUS, producer_projection() + b"\n")


def test_independent_canonical_vectors_match() -> None:
    assert check_canonical_vectors(VECTORS) == 15


def test_portable_projection_retains_programme_and_execution_meaning() -> None:
    projection = json.loads(producer_projection())
    program = next(
        case["program"] for case in projection["cases"] if case["id"] == "IR-REL-001"
    )
    assert program["programme"]["project"] == {
        "id": "synthetic",
        "revision": "rev-1",
        "tier": 0,
        "tree_state": "clean",
    }
    assert (
        program["programme"]["closures"][0]["members"][0]["logical_name"]
        == "src/model.rs"
    )
    assert (
        program["programme"]["sealed_artifacts"][0]["logical_name"] == "tcb-ledger.json"
    )
    evidence = program["evidence"][0]
    assert (
        evidence["content_sha256"]
        == "sha256:0472956f8429866d293913903a3b1ac9ae42764e658078953dae8015939b44d4"
    )
    assert evidence["provenance"]["commands"][0]["program"] == "synthetic-runner"
    assert evidence["provenance"]["runs"][0]["exit_code"] == 0
    assert evidence["provenance"]["usage"]["disk_bytes"] == 1

    missing_policy = json.loads(json.dumps(program))
    missing_policy["programme"]["policies"] = []
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(missing_policy))
    assert caught.value.code == "IR-PROGRAMME-POLICY-OMITTED"

    wrong_revision = json.loads(json.dumps(program))
    wrong_revision["evidence"][0]["provenance"]["revision"] = "rev-substituted"
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(wrong_revision))
    assert caught.value.code == "IR-PROGRAMME-PROVENANCE-MISMATCH"


def test_registration_cache_binds_actual_input_bytes() -> None:
    projection = json.loads(producer_projection())
    program = next(
        case["program"] for case in projection["cases"] if case["id"] == "IR-PY-001"
    )
    cache_input = next(
        item
        for item in program["cache"]["registered_inputs"]
        if item["selector"] == "pyproject.toml"
    )
    data = (ROOT / "demo/python-inventory-service/pyproject.toml").read_bytes()
    assert cache_input["identity"] == f"sha256:{hashlib.sha256(data).hexdigest()}"


def test_both_implementations_reject_every_preregistered_attack() -> None:
    projection = json.loads(producer_projection())
    programs = {case["id"]: case["program"] for case in projection["cases"]}
    adversarial = json.loads(ADVERSARIAL.read_bytes())
    assert adversarial["revision"] == 2
    assert len(adversarial["cases"]) == 20
    rust_validator = ROOT / "target/debug/proofbound-ir-prototype"

    for attack in adversarial["cases"]:
        data = mutate_case(programs[attack["base_case"]], attack["mutation"])
        expected = attack["expected"]["code"]
        with pytest.raises(AssuranceIrError) as caught:
            validate_case_program(data)
        assert caught.value.code == expected, attack["id"]

        rust = subprocess.run(
            [rust_validator, "validate"],
            cwd=ROOT,
            input=data,
            capture_output=True,
            check=False,
        )
        assert rust.returncode == 1, attack["id"]
        assert rust.stderr.decode().startswith(f"{expected}:"), attack["id"]


def mutate_case(program: dict[str, object], mutation: dict[str, object]) -> bytes:
    """Apply one preregistered transformation to an isolated base case."""

    value = json.loads(json.dumps(program))
    operation = mutation["operation"]
    if operation == "delete":
        parent, field = pointer_parent(value, str(mutation["path"]))
        del parent[field]
    elif operation in {"replace", "replace-reported-status"}:
        parent, field = pointer_parent(value, str(mutation["path"]))
        parent[field] = mutation["value"]
    elif operation == "duplicate-set-member":
        items = pointer(value, str(mutation["path"]))
        index = int(mutation["index"])
        items.insert(index, items[index])
    elif operation == "replace-family":
        family = next(
            item["family"]
            for item in value["evidence"]
            if item["family"]["kind"] == mutation["from"]
        )
        family["kind"] = mutation["to"]
    elif operation == "remove-set-member":
        items = pointer(value, str(mutation["path"]))
        if "value" in mutation:
            items.remove(mutation["value"])
        else:
            items.remove(
                next(item for item in items if item["selector"] == mutation["selector"])
            )
    elif operation == "add-set-member":
        items = pointer(value, str(mutation["path"]))
        items.append(mutation["value"])
        items.sort()
    elif operation == "encode-noncanonical":
        return canonical_json(value) + b"\n"
    elif operation == "encode-duplicate-object-key":
        data = canonical_json(value)
        unit = value["evidence"][0]["unit"]
        needle = f'"unit":"{unit}"'.encode()
        return data.replace(needle, needle + b"," + needle, 1)
    else:
        raise AssertionError(f"unsupported adversarial operation {operation}")
    return canonical_json(value)


def pointer(value: object, path: str) -> object:
    if not path:
        return value
    current = value
    for part in path.removeprefix("/").split("/"):
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def pointer_parent(value: object, path: str) -> tuple[object, str]:
    parent_path, field = path.rsplit("/", 1)
    return pointer(value, parent_path), field
