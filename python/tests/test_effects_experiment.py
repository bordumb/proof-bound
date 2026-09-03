from __future__ import annotations

import json
from pathlib import Path

from proofbound import effects_experiment, effects_research

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0012-effect-checked-replay/corpus")
RESULT = ROOT / "docs/experiments/0012-effect-checked-replay/results/execution.json"


def test_metric_derivation_accepts_two_independently_shaped_equal_reports() -> None:
    model = effects_research.execute_effect_corpus(ROOT, CORPUS, 10)
    encoded = effects_research.canonical_json(model)
    fixtures = effects_experiment._fixture_projection(ROOT)

    report = effects_experiment._summarize(
        ROOT,
        ROOT / "VERSION",
        model,
        effects_research.execute_effect_corpus(ROOT, CORPUS, 10),
        encoded,
        encoded,
        fixtures,
        fixtures,
        10,
    )

    assert report["metrics"]["exact_attack_rejections"] == 23
    assert report["metrics"]["stale_cache_acceptance"] == 0
    assert report["metrics"]["unrelated_invalidation"] == 0
    assert [report["questions"][f"Q{index}"]["passed"] for index in range(1, 6)] == [
        True,
        True,
        True,
        True,
        True,
    ]


def test_retained_execution_preserves_all_registered_outcomes() -> None:
    report = json.loads(RESULT.read_bytes())

    assert report["schema"] == "proofbound-research-effect-execution/1"
    assert report["experiment"] == "EXP-0012"
    assert report["programme_experiment"] == "EXP-LANG-005"
    assert report["repetitions"] == 10
    assert report["implementations"]["canonical_reports_equal"] is True
    assert len(report["attack_results"]) == 23
    assert all(attack["exact"] for attack in report["attack_results"])
    assert report["metrics"]["forbidden_preflight_rejections"] == 16
    assert report["metrics"]["authorized_observations"] == 12
    assert report["metrics"]["declaration_dispositions"] == 15
    assert report["metrics"]["stale_cache_acceptance"] == 0
    assert report["metrics"]["unrelated_invalidation"] == 0
    assert all(report["questions"][f"Q{index}"]["passed"] for index in range(1, 6))
