from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from proofbound import native_experiment

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/proofbound-ir-prototype"
pytestmark = pytest.mark.skipif(
    shutil.which("z3") is None or not BINARY.exists(),
    reason="requires the built research binary and preregistered Z3",
)


def test_experiment_passes_every_preregistered_question() -> None:
    report = native_experiment.execute_experiment(ROOT, BINARY)
    assert report["schema"] == native_experiment.REPORT_SCHEMA
    assert all(question["passed"] for question in report["questions"].values())
    assert report["metrics"]["certificate_value_rows"] == 4
    assert report["metrics"]["certificate_input_rows"] == 156
    assert report["metrics"]["killed_semantic_mutants"] == 6
    assert report["metrics"]["exact_attack_rejections"] == 28
    assert report["implementations"]["canonical_reports_equal"]


def test_retained_result_matches_fresh_execution() -> None:
    retained_path = (
        ROOT / "docs/experiments/0016-native-canonical-parser/results/execution.json"
    )
    if not retained_path.exists():
        return
    retained = json.loads(retained_path.read_bytes())
    fresh = native_experiment.execute_experiment(ROOT, BINARY)
    retained_elapsed = retained["metrics"].pop("elapsed_ms")
    fresh_elapsed = fresh["metrics"].pop("elapsed_ms")
    assert retained == fresh
    assert retained_elapsed <= 30_000
    assert fresh_elapsed <= 30_000
