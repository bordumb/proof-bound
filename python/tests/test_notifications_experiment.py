from __future__ import annotations

import json
from pathlib import Path

from proofbound import notifications_experiment, notifications_research

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0013-claim-oriented-notification-precision/corpus")
RESULT = (
    ROOT
    / "docs/experiments/0013-claim-oriented-notification-precision/results/execution.json"
)


def test_metric_derivation_keeps_human_question_unanswered() -> None:
    model = notifications_research.execute_notification_corpus(ROOT, CORPUS, 10)
    encoded = notifications_research.canonical_json(model)

    report = notifications_experiment._summarize(
        ROOT,
        ROOT / "VERSION",
        model,
        notifications_research.execute_notification_corpus(ROOT, CORPUS, 10),
        encoded,
        encoded,
        10,
    )

    assert report["metrics"]["baseline_alerts"] == 20
    assert report["metrics"]["candidate_notifications"] == 7
    assert report["metrics"]["baseline_false_escalations"] == 9
    assert report["metrics"]["candidate_false_escalations"] == 0
    assert all(report["questions"][f"Q{index}"]["passed"] for index in range(1, 5))
    assert report["questions"]["Q5"] == {
        "status": "unanswered",
        "passed": None,
        "reason": "no eligible participant responses exist; machine proxies are not human evidence",
    }


def test_retained_execution_preserves_registered_outcomes() -> None:
    report = json.loads(RESULT.read_bytes())

    assert report["schema"] == "proofbound-research-notification-execution/1"
    assert report["experiment"] == "EXP-0013"
    assert report["programme_experiment"] == "EXP-LANG-006"
    assert report["implementations"]["canonical_reports_equal"] is True
    assert report["metrics"]["exact_attack_rejections"] == 20
    assert report["metrics"]["critical_action_count"] == 6
    assert report["metrics"]["retained_findings"] == 20
    assert all(report["questions"][f"Q{index}"]["passed"] for index in range(1, 5))
    assert report["questions"]["Q5"]["status"] == "unanswered"
