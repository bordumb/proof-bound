from __future__ import annotations

import json
from pathlib import Path

from proofbound import specifications_experiment, specifications_research

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0014-specification-falsifiers/corpus")
RESULT = ROOT / "docs/experiments/0014-specification-falsifiers/results/execution.json"


def test_metric_derivation_accepts_independent_equal_reports() -> None:
    model = specifications_research.execute_specification_corpus(ROOT, CORPUS, 10)
    encoded = specifications_research.canonical_json(model)

    report = specifications_experiment._summarize(
        ROOT,
        ROOT / "VERSION",
        model,
        specifications_research.execute_specification_corpus(ROOT, CORPUS, 10),
        encoded,
        encoded,
        10,
    )

    assert report["metrics"]["correct_obligations_satisfied"] == 34
    assert report["metrics"]["mutants_killed"] == 6
    assert report["metrics"]["exact_attack_rejections"] == 20
    assert all(report["questions"][f"Q{index}"]["passed"] for index in range(1, 6))


def test_retained_execution_preserves_registered_outcomes() -> None:
    report = json.loads(RESULT.read_bytes())

    assert report["schema"] == "proofbound-research-specification-execution/1"
    assert report["experiment"] == "EXP-0014"
    assert report["programme_experiment"] == "EXP-LANG-009"
    assert report["implementations"]["canonical_reports_equal"] is True
    assert report["metrics"]["model_report_bytes"] <= 16384
    assert len(report["mutant_results"]) == 6
    assert all(result["killed"] for result in report["mutant_results"])
    assert all(report["questions"][f"Q{index}"]["passed"] for index in range(1, 6))
