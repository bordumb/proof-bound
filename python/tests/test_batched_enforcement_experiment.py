from __future__ import annotations

from pathlib import Path

from proofbound.batched_enforcement_experiment import evaluate_experiment

ROOT = Path(__file__).resolve().parents[2]


def test_retained_experiment_passes_every_registered_question() -> None:
    report = evaluate_experiment(ROOT)
    assert report["decision"] == "pass"
    assert all(question["passed"] for question in report["questions"].values())
    assert report["metrics"]["elapsed_ms"] <= report["elapsed_ceiling_ms"]
