from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from proofbound import native_research

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0016-native-canonical-parser/corpus")
pytestmark = pytest.mark.skipif(
    shutil.which("z3") is None,
    reason="requires the preregistered Z3 4.15.2 executable",
)


def _rust_report() -> bytes:
    completed = subprocess.run(
        [
            str(ROOT / "target/debug/proofbound-ir-prototype"),
            "execute-native",
            str(ROOT),
            str(CORPUS),
            "10",
        ],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )
    assert completed.stderr == b""
    return completed.stdout


def test_independent_checker_reconstructs_rust_report_exactly() -> None:
    payload = _rust_report()
    report = native_research.reconstruct_native_report(ROOT, CORPUS, payload)
    assert native_research.canonical_json(report) == payload
    assert len(report["certificate"]["value_rows"]) == 4
    assert len(report["certificate"]["input_rows"]) == 156
    assert all(item["killed"] for item in report["certificate"]["semantic_mutants"])
    assert all(item["exact"] for item in report["attacks"])
    assert report["assurance"]["artifact_proved"] is False


def test_independent_checker_rejects_self_consistent_scope_upgrade() -> None:
    payload = _rust_report()
    report = json.loads(payload)
    report["certificate"]["scope"]["input_unbounded"] = True
    certificate = deepcopy(report["certificate"])
    certificate["identity"] = ""
    report["certificate"]["identity"] = native_research.domain_hash(
        native_research.CERTIFICATE_SCHEMA,
        native_research.canonical_json(certificate),
    )
    with pytest.raises(native_research.NativeFailure, match="NATIVE-CERT-SCOPE"):
        native_research.reconstruct_native_report(
            ROOT, CORPUS, native_research.canonical_json(report)
        )


def test_independent_checker_rejects_solver_receipt_substitution() -> None:
    payload = _rust_report()
    report = json.loads(payload)
    report["certificate"]["solver"]["version"] += "-forged"
    with pytest.raises(native_research.NativeFailure, match="NATIVE-SMT-RESULT"):
        native_research.reconstruct_native_report(
            ROOT, CORPUS, native_research.canonical_json(report)
        )
