import json
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
