from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from proofbound.notifications_research import (
    NotificationFailure,
    derive_notification_report,
    execute_notification_corpus,
    load_notification_corpus,
    validate_notification_report,
)

ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0013-claim-oriented-notification-precision/corpus")


def test_frozen_notification_corpus_executes_exactly() -> None:
    report = execute_notification_corpus(ROOT, CORPUS, 10)

    assert len(report["decision_report"]["baseline_alerts"]) == 20
    assert len(report["decision_report"]["notifications"]) == 7
    assert len(report["decision_report"]["graph_updates"]) == 9
    assert len(report["decision_report"]["fact_kinds"]) == 6
    assert len(report["attacks"]) == 20
    assert all(attack["exact"] for attack in report["attacks"])
    assert len(report["repetition_report_identities"]) == 10


def test_low_severity_consumed_finding_remains_interrupting() -> None:
    report = execute_notification_corpus(ROOT, CORPUS, 10)["decision_report"]

    assert any("DEP-001" in item["findings"] for item in report["notifications"])
    assert all(item["finding"] != "DEP-001" for item in report["graph_updates"])


def test_self_consistent_notification_path_substitution_rejects() -> None:
    corpus, _ = load_notification_corpus(ROOT, CORPUS)
    report = derive_notification_report(corpus)
    changed = deepcopy(report)
    notification = next(
        item for item in changed["notifications"] if "DEP-001" in item["findings"]
    )
    notification["paths"][0]["nodes"][-1] = "claim:UNKNOWN"
    from proofbound.notifications_research import canonical_json, domain_hash

    material = {key: value for key, value in notification.items() if key != "identity"}
    notification["identity"] = domain_hash(
        "proofbound-research-notification/1", canonical_json(material)
    )
    changed["notifications"].sort(key=lambda item: item["identity"])
    report_material = {
        key: value for key, value in changed.items() if key != "identity"
    }
    changed["identity"] = domain_hash(
        "proofbound-research-notification-report/1", canonical_json(report_material)
    )

    with pytest.raises(NotificationFailure, match="UNCERTAINTY-REPORT-MISMATCH"):
        validate_notification_report(corpus, changed)
