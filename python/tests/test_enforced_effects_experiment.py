from __future__ import annotations

from pathlib import Path

from proofbound.enforced_effects_experiment import evaluate_experiment

ROOT = Path(__file__).parents[2]


def test_retained_experiment_passes_semantics_and_retains_performance_failure() -> None:
    report = evaluate_experiment(ROOT)

    assert report["decision"] == "revise"
    assert all(report["questions"][name]["passed"] for name in ["Q1", "Q2", "Q3", "Q4"])
    assert not report["questions"]["Q5"]["passed"]
    assert report["metrics"]["elapsed_ms"] == 93_574
    assert report["metrics"]["exact_attack_rejections"] == 30
    assert report["implementations"]["canonical_reports_equal"]
