from __future__ import annotations

import json
from pathlib import Path

import proofbound.assurance_v2_experiment as experiment

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/proofbound-ir-prototype"


def test_experiment_passes_every_preregistered_question() -> None:
    report = experiment.execute_experiment(ROOT, BINARY)
    assert report["schema"] == experiment.REPORT_SCHEMA
    assert all(question["passed"] for question in report["questions"].values())
    assert report["metrics"]["valid_programs"] == 500
    assert report["metrics"]["adversarial_programs"] == 500
    assert report["metrics"]["exact_attack_rejections"] == 28
    assert report["implementations"]["canonical_reports_equal"]


def test_retained_result_matches_fresh_execution() -> None:
    retained_path = (
        ROOT
        / "docs/experiments/0015-assurance-ir-differential-kernel/results/execution.json"
    )
    if not retained_path.exists():
        return
    retained = json.loads(retained_path.read_bytes())
    fresh = experiment.execute_experiment(ROOT, BINARY)
    retained["implementations"]["rust"].pop("binary_sha256")
    fresh["implementations"]["rust"].pop("binary_sha256")
    assert retained == fresh
