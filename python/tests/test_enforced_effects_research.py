from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from proofbound import enforced_effects_research as effects

ROOT = Path(__file__).parents[2]
RESULTS = ROOT / "docs/experiments/0018-os-enforced-effects/results"


def test_retained_capture_matches_both_independent_reports() -> None:
    capture = (RESULTS / "capture.json").read_bytes()
    report = effects.validate_capture_bytes(ROOT, capture)
    encoded = effects.canonical_json(report)

    assert encoded == (RESULTS / "python-report.json").read_bytes()
    assert encoded == (RESULTS / "rust-report.json").read_bytes()
    assert report["metrics"]["exact_attack_rejections"] == 30
    assert report["metrics"]["denied_reusable"] == 0


def test_policy_and_report_identity_attacks_fail_closed() -> None:
    capture = json.loads((RESULTS / "capture.json").read_bytes())
    altered = deepcopy(capture)
    altered["positive_runs"][0]["plan"]["policy"] += "(allow network*)\n"

    with pytest.raises(effects.EnforcedEffectsError, match="EFX-COMMAND"):
        effects.validate_capture(ROOT, altered)

    report = effects.validate_capture(ROOT, capture)
    report["identity"] = "sha256:" + "0" * 64
    with pytest.raises(effects.EnforcedEffectsError, match="EFX-REPORT-IDENTITY"):
        effects.validate_report(report)


def test_capture_is_canonical_and_runtime_specific_without_language_semantics() -> None:
    capture = (RESULTS / "capture.json").read_bytes()
    parsed = json.loads(capture)

    assert effects.canonical_json(parsed) == capture
    assert parsed["elapsed_ms"] == 93_574
    assert {item["plan"]["subject_id"] for item in parsed["positive_runs"]} == {
        "subject:node",
        "subject:python",
        "subject:rust",
    }
    assert all(not item["receipt"]["reusable"] for item in parsed["authority_probes"])
