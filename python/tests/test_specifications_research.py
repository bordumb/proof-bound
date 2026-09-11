from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from proofbound.specifications_research import (
    REPORT_SCHEMA,
    SpecificationFailure,
    canonical_json,
    derive_specification_report,
    domain_hash,
    execute_specification_corpus,
    load_specification_corpus,
    validate_specification_report,
)

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0014-specification-falsifiers/corpus")


def test_correct_relation_and_all_mutants_are_distinguished() -> None:
    model = execute_specification_corpus(ROOT, CORPUS, 10)
    report = model["specification_report"]

    assert report["correct_accepted"] is True
    assert (
        sum(item["satisfied_obligations"] for item in report["contract_results"]) == 34
    )
    assert len(report["mutant_results"]) == 6
    assert all(item["killed"] for item in report["mutant_results"])
    assert report["ast_nodes"] == 24
    assert report["carrier_values"] == 14


def test_every_frozen_attack_rejects_exactly() -> None:
    model = execute_specification_corpus(ROOT, CORPUS, 10)

    assert len(model["attacks"]) == 20
    assert all(item["exact"] for item in model["attacks"])
    assert len(model["repetition_report_identities"]) == 10


def test_self_consistent_counterexample_substitution_rejects() -> None:
    universe, suite, executions, _, universe_bytes, execution_bytes = (
        load_specification_corpus(ROOT, CORPUS)
    )
    report = derive_specification_report(
        universe, suite, executions, universe_bytes, execution_bytes
    )
    changed = deepcopy(report)
    changed["mutant_results"][0]["first_counterexample"]["case"] = "I-EMPTY"
    material = {key: value for key, value in changed.items() if key != "identity"}
    changed["identity"] = domain_hash(REPORT_SCHEMA, canonical_json(material))

    with pytest.raises(SpecificationFailure, match="SPEC-REPORT-MISMATCH"):
        validate_specification_report(
            universe,
            suite,
            executions,
            universe_bytes,
            execution_bytes,
            changed,
        )
