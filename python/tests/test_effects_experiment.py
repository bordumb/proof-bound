from __future__ import annotations

from pathlib import Path

from proofbound import effects_experiment, effects_research

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0012-effect-checked-replay/corpus")


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
