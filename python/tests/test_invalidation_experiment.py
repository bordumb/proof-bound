from __future__ import annotations

from pathlib import Path

from proofbound.invalidation_experiment import execute_corpus


ROOT = Path(__file__).resolve().parents[2]


def test_executes_frozen_invalidation_corpus_without_using_expected_sets() -> None:
    report = execute_corpus(ROOT)
    assert report["projection_count"] == 19
    assert report["scenario_count"] == 26
    assert report["metrics"]["exact_scenarios"] == 26
    assert report["metrics"]["stale_retention"] == 0
    assert report["metrics"]["overinvalidating_scenarios"] == 0
    coverage = report["metrics"]["explanation_coverage"]
    assert coverage["numerator"] == coverage["denominator"]


def test_negative_controls_do_not_invalidate_technical_evidence() -> None:
    report = execute_corpus(ROOT)
    controls = [
        scenario
        for scenario in report["scenarios"]
        if scenario["class"]
        in {
            "presentation-only-control",
            "unrelated-language-control",
        }
    ]
    assert len(controls) == 4
    assert all(not scenario["predicted_invalidated"] for scenario in controls)
