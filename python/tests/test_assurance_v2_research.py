from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

import proofbound.assurance_v2_research as assurance_v2

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0015-assurance-ir-differential-kernel/corpus")


def test_frozen_corpus_executes_every_case_and_attack() -> None:
    report = assurance_v2.execute_assurance_v2_corpus(ROOT, CORPUS, 10)
    assert len(report["templates"]) == 6
    assert report["valid_programs"] == 500
    assert report["adversarial_programs"] == 500
    assert len(report["attacks"]) == 28
    assert all(item["exact"] for item in report["attacks"])
    assert len(set(report["repetition_report_identities"])) == 1


def test_self_consistent_linkage_upgrade_is_rejected() -> None:
    model, templates, _, _ = assurance_v2.load_assurance_v2_corpus(ROOT, CORPUS)
    theorem = next(
        item
        for item in templates["profiles"]
        if item["id"] == "theorem-with-assumption"
    )
    programme = assurance_v2.expand_assurance_v2_profile(model, theorem, 42)
    programme["expected_decision"]["linkage"] = "artifact-bound"
    with pytest.raises(assurance_v2.AssuranceV2Failure, match="IR2-DECISION-UPGRADE"):
        assurance_v2.validate_assurance_v2_program(
            model, assurance_v2.canonical_json(programme)
        )


def test_report_identity_cannot_be_reused_after_dependency_change() -> None:
    model, templates, _, _ = assurance_v2.load_assurance_v2_corpus(ROOT, CORPUS)
    programme = assurance_v2.expand_assurance_v2_profile(
        model, templates["profiles"][0], 7
    )
    original = assurance_v2.validate_assurance_v2_program(
        model, assurance_v2.canonical_json(programme)
    )
    changed = deepcopy(programme)
    changed["dependencies"][0]["identity"] = "sha256:" + "a" * 64
    changed["invalidation"]["identity"] = original["invalidation_identity"]
    replacement = assurance_v2.validate_assurance_v2_program(
        model, assurance_v2.canonical_json(changed)
    )
    assert replacement["identity"] != original["identity"]
    assert replacement["dependency_identity"] != original["dependency_identity"]
