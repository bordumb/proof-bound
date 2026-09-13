from __future__ import annotations

import json
from pathlib import Path

import pytest

from proofbound import batched_enforcement_research as batch

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "docs/experiments/0019-batched-enforcement-latency/results"


def test_independent_report_matches_rust_bytes() -> None:
    capture = (RESULTS / "capture.json").read_bytes()
    report = batch.validate_capture_bytes(ROOT, capture)
    assert (
        batch.effects.canonical_json(report)
        == (RESULTS / "rust-report.json").read_bytes()
    )
    assert report["metrics"]["completed_slots"] == 51
    assert report["metrics"]["scheduler_attack_rejections"] == 10


def test_partial_and_unknown_batch_fields_fail_closed() -> None:
    capture = json.loads((RESULTS / "capture.json").read_bytes())
    capture["completed_slots"] -= 1
    with pytest.raises(batch.BatchedEnforcementError, match="BFX-PARTIAL"):
        batch.validate_capture(ROOT, capture)
    capture = json.loads((RESULTS / "capture.json").read_bytes())
    capture["unknown"] = True
    with pytest.raises(batch.BatchedEnforcementError, match="BFX-DECODE"):
        batch.validate_capture(ROOT, capture)
