from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from proofbound.effects_research import (
    EffectFailure,
    execute_effect_corpus,
    execute_effect_plan,
    load_effect_corpus,
    validate_effect_trace,
)

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0012-effect-checked-replay/corpus")


def test_frozen_effect_corpus_executes_exactly() -> None:
    report = execute_effect_corpus(ROOT, CORPUS, 10)

    assert len(report["plans"]) == 6
    assert len(report["attacks"]) == 23
    assert all(attack["exact"] for attack in report["attacks"])
    assert all(
        len(plan["repetition_trace_identities"]) == 10 for plan in report["plans"]
    )
    assert [output["path"] for output in report["route_outputs"]] == [
        "ephemeral/distribution/package.json",
        "ephemeral/mutation/target.txt",
    ]


def test_invalidation_repairs_hidden_read_without_global_revision() -> None:
    report = execute_effect_corpus(ROOT, CORPUS, 10)

    assert all(
        decision["invalidated"] and decision["changed_effects"] == ["read-policy"]
        for decision in report["invalidation"][0]["decisions"]
    )
    assert all(
        not decision["invalidated"] and not decision["changed_effects"]
        for decision in report["invalidation"][1]["decisions"]
    )


def test_self_consistent_trace_value_substitution_rejects() -> None:
    corpus, enforcement, _ = load_effect_corpus(ROOT, CORPUS)
    plan = next(plan for plan in corpus["plans"] if plan["id"] == "hidden-reader")
    trace = execute_effect_plan(ROOT, plan, enforcement)
    trace = deepcopy(trace)
    trace["observations"][0]["value"]["sha256"] = "sha256:" + "0" * 64

    with pytest.raises(EffectFailure, match="EFFECT-TRACE-UNBOUND"):
        validate_effect_trace(ROOT, plan, enforcement, trace)


def test_forbidden_authority_attacks_stop_before_body_entry() -> None:
    report = execute_effect_corpus(ROOT, CORPUS, 10)
    preflight = {
        "undeclared-file-read",
        "undeclared-environment",
        "network-attempt",
        "clock-attempt",
        "random-attempt",
        "reviewed-root-write",
        "ephemeral-write-escape",
        "symlink-substitution",
        "lifecycle-script",
        "executable-substitution",
        "argv-substitution",
        "missing-enforcement",
        "forged-enforcement",
        "weakened-enforcement",
        "effect-id-alias",
        "duplicate-effect",
    }

    assert all(
        attack["id"] not in preflight or not attack["workload_body_entered"]
        for attack in report["attacks"]
    )
