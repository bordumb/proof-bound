from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESULT = ROOT / "docs/experiments/0011-dual-frontend-equivalence/results/execution.json"


def test_retained_frontend_execution_preserves_the_negative_result() -> None:
    report = json.loads(RESULT.read_bytes())

    assert report["schema"] == "proofbound-research-frontend-execution/1"
    assert report["experiment"] == "EXP-0011"
    assert report["programme_experiment"] == "EXP-LANG-004"
    assert report["metrics"]["implementation_exact_pairs"] == 9
    assert report["metrics"]["implementation_pair_count"] == 9
    assert report["metrics"]["exact_attack_rejections"] == 22
    assert report["metrics"]["attack_count"] == 22
    assert report["metrics"]["frozen_controls_matching"] == 0
    assert report["confirmatory_valid"] is False

    assert all(case["repetitions"] == 10 for case in report["positive_cases"])
    assert all(case["implementation_bytes_equal"] for case in report["positive_cases"])
    assert all(
        attack["rust_code"] == attack["expected_code"]
        and attack["python_code"] == attack["expected_code"]
        for attack in report["attacks"]
    )
    assert [report["questions"][f"Q{number}"]["passed"] for number in range(1, 6)] == [
        False,
        False,
        True,
        True,
        True,
    ]


def test_frontend_receipts_preserve_provenance_instead_of_false_equivalence() -> None:
    report = json.loads(RESULT.read_bytes())

    assert all(
        project["programme_bytes_equal"]
        and project["effective_bytes_equal"]
        and not project["receipt_bytes_equal"]
        for project in report["project_equivalence"]
    )
    assert all(
        control["actual_bytes"] == control["expected_bytes"]
        and control["actual_identity"] != control["expected_identity"]
        and not control["matches"]
        for control in report["frozen_programme_controls"]
    )
