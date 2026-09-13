from __future__ import annotations

from pathlib import Path

import pytest

from proofbound import linux_enforcement_confirmation as confirmation


ROOT = Path(__file__).resolve().parents[2]
EXP_0020_RESULTS = ROOT / "docs/experiments/0020-linux-enforcement-portability/results"


def test_retained_unsupported_capture_remains_unanswered() -> None:
    result = confirmation.evaluate(
        ROOT,
        EXP_0020_RESULTS / "capture.json",
        EXP_0020_RESULTS / "rust-report.json",
        EXP_0020_RESULTS / "python-report.json",
    )
    assert result["decision"] == "unanswered"
    assert result["availability_fail_closed"] is True
    assert result["questions"] == {
        "Q1": False,
        "Q2": False,
        "Q3": False,
        "Q4": True,
        "Q5": True,
    }


def test_supported_confirmation_can_reach_pass() -> None:
    assert (
        confirmation._decision(
            "supported",
            {"Q1": True, "Q2": True, "Q3": True, "Q4": True, "Q5": True},
        )
        == "pass"
    )


def test_supported_confirmation_revises_on_any_failed_question() -> None:
    assert (
        confirmation._decision(
            "supported",
            {"Q1": True, "Q2": True, "Q3": False, "Q4": True, "Q5": True},
        )
        == "revise"
    )


def test_unknown_availability_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown availability"):
        confirmation._decision("simulated", {"Q1": True})
