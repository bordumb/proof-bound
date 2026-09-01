import json
from pathlib import Path
import subprocess

import pytest

from proofbound.assurance_ir_checker import (
    AssuranceIrError,
    canonical_json,
    check_canonical_vectors,
    check_projection,
)


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/cases.json"
VECTORS = (
    ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/canonical-vectors.json"
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
