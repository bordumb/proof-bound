from __future__ import annotations

from pathlib import Path
import json

from proofbound.invalidation_experiment import (
    execute_corpus,
    execute_revision_falsifier,
)


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


def test_global_revision_or_unenforced_declarations_cannot_meet_both_targets() -> None:
    report = execute_revision_falsifier()
    assert report["baseline_exit_code"] == 0
    assert report["changed_exit_code"] == 1
    assert report["fixed_snapshot_strategy"]["stale_reuse"] is True
    assert report["global_revision_strategy"]["reader_identity_changed"] is True
    assert report["global_revision_strategy"]["unrelated_identity_changed"] is True
    assert report["global_revision_strategy"]["overinvalidates"] is True


def test_retained_forced_fresh_smoke_does_not_overstate_coverage() -> None:
    result = json.loads(
        (
            ROOT
            / "docs/experiments/0010-invalidation-precision/results/forced-fresh-smoke.json"
        ).read_bytes()
    )
    assert result["summary"]["route_shapes_registered"] == 14
    assert result["summary"]["route_shapes_with_passing_baseline"] == 13
    assert result["summary"]["required_forced_fresh_change_matrix_complete"] is False
    assert result["summary"]["external_holdouts_passing"] == 1
