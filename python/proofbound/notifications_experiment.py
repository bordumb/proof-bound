"""Execute the preregistered claim-oriented notification experiment."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import proofbound.notifications_research as notifications

REPORT_SCHEMA = "proofbound-research-notification-execution/1"
CORPUS = Path("docs/experiments/0013-claim-oriented-notification-precision/corpus")


def execute_experiment(
    repository: Path, rust_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Run both candidates before opening the frozen oracle and expectations.

    Args:
        repository: Proofbound repository root.
        rust_binary: Built ``proofbound-ir-prototype`` executable.
        repetitions: Frozen deterministic repetition count.

    Returns:
        Canonicalizable execution report with Q1--Q5 outcomes.

    Raises:
        ValueError: If an implementation or registered invariant fails.
    """

    repository = repository.resolve()
    rust_binary = rust_binary.resolve()
    if repetitions != 10:
        raise ValueError("Experiment 0013 requires exactly ten repetitions")
    rust_bytes = _run_rust(repository, rust_binary, repetitions)
    python_model = notifications.execute_notification_corpus(
        repository, CORPUS, repetitions
    )
    python_bytes = notifications.canonical_json(python_model)
    rust_model = json.loads(rust_bytes)
    if not isinstance(rust_model, dict):
        raise ValueError("Rust report is not an object")
    return _summarize(
        repository,
        rust_binary,
        rust_model,
        python_model,
        rust_bytes,
        python_bytes,
        repetitions,
    )


def _summarize(
    repository: Path,
    rust_binary: Path,
    rust_model: dict[str, Any],
    python_model: dict[str, Any],
    rust_bytes: bytes,
    python_bytes: bytes,
    repetitions: int,
) -> dict[str, Any]:
    preregistration = _read_json(
        repository
        / "docs/experiments/0013-claim-oriented-notification-precision/preregistration.json"
    )
    scenario_corpus = _read_json(repository / CORPUS / "scenarios.json")
    attack_corpus = _read_json(repository / CORPUS / "attacks.json")
    oracle = _read_json(repository / CORPUS / "oracle.json")
    expected = _read_json(repository / CORPUS / "expected.json")
    instrument = _read_json(repository / CORPUS / "instrument.json")
    registered_attacks = [
        (item["id"], item["code"]) for item in attack_corpus["attacks"]
    ]
    if registered_attacks != [
        (item["id"], item["code"]) for item in preregistration["attacks"]
    ]:
        raise ValueError("attack corpus differs from preregistration")
    if repetitions != expected["repetitions"]:
        raise ValueError("repetition count differs from the frozen expectation")
    if (
        rust_model.get("schema") != notifications.MODEL_REPORT_SCHEMA
        or python_model.get("schema") != notifications.MODEL_REPORT_SCHEMA
    ):
        raise ValueError("implementation report schema differs")
    implementation_equal = rust_bytes == python_bytes
    rust_attacks = {item["id"]: item for item in rust_model["attacks"]}
    python_attacks = {item["id"]: item for item in python_model["attacks"]}
    registered_ids = {identifier for identifier, _ in registered_attacks}
    if set(rust_attacks) != registered_ids or set(python_attacks) != registered_ids:
        raise ValueError("implementation attack inventory differs")
    exact_attacks = sum(
        rust_attacks[identifier]["actual_code"] == code
        and python_attacks[identifier]["actual_code"] == code
        and rust_attacks[identifier]["exact"]
        and python_attacks[identifier]["exact"]
        for identifier, code in registered_attacks
    )
    report = rust_model["decision_report"]
    baseline = report["baseline_alerts"]
    candidate = report["notifications"]
    updates = report["graph_updates"]
    oracle_actions = {_action_tuple(item) for item in oracle["critical_actions"]}
    paths_by_finding: dict[tuple[str, str], list[dict[str, Any]]] = {}
    all_findings: set[tuple[str, str]] = set()
    low_findings: set[tuple[str, str]] = set()
    for scenario in scenario_corpus["scenarios"]:
        facts = {fact["id"]: fact for fact in scenario["facts"]}
        for finding in scenario["findings"]:
            key = (scenario["id"], finding["id"])
            all_findings.add(key)
            if finding["severity"] == "low":
                low_findings.add(key)
            paths_by_finding[key] = [
                path
                for path in scenario["paths"]
                if path["finding"] == finding["id"] and path["consumed"]
            ]
            for path in paths_by_finding[key]:
                path["kind"] = facts[path["fact"]]["kind"]
    baseline_actions = {
        _path_action_tuple(alert["scenario"], path)
        for alert in baseline
        for path in paths_by_finding[(alert["scenario"], alert["finding"])]
    }
    candidate_actions = {_action_tuple(item) for item in candidate}
    baseline_recalled = len(oracle_actions & baseline_actions)
    candidate_recalled = len(oracle_actions & candidate_actions)
    baseline_false = sum(
        not paths_by_finding[(alert["scenario"], alert["finding"])]
        for alert in baseline
    )
    candidate_false = sum(not item["paths"] for item in candidate)
    retained = {
        (item["scenario"], finding)
        for item in candidate
        for finding in item["findings"]
    } | {(item["scenario"], item["finding"]) for item in updates}
    complete_notifications = sum(_notification_complete(item) for item in candidate)
    low_severity_critical = any(
        (alert["scenario"], alert["finding"]) in low_findings
        and any(
            _path_action_tuple(alert["scenario"], path) in oracle_actions
            for path in paths_by_finding[(alert["scenario"], alert["finding"])]
        )
        for alert in baseline
    )
    deterministic = all(
        len(model["repetition_report_identities"]) == repetitions
        and len(set(model["repetition_report_identities"])) == 1
        for model in (rust_model, python_model)
    )
    fact_kinds = set(report["fact_kinds"])
    q1 = fact_kinds == set(notifications.KINDS) and exact_attacks == len(
        registered_attacks
    )
    q2 = (
        baseline_recalled == len(oracle_actions)
        and candidate_recalled == len(oracle_actions)
        and low_severity_critical
        and deterministic
    )
    q3 = (
        len(candidate) * expected["maximum_candidate_volume"]["denominator"]
        <= len(baseline) * expected["maximum_candidate_volume"]["numerator"]
        and candidate_false == 0
        and baseline_false > 0
        and retained == all_findings
        and deterministic
    )
    q4 = (
        implementation_equal
        and complete_notifications == len(candidate)
        and exact_attacks == len(registered_attacks)
    )
    _assert_expected_counts(
        expected,
        scenario_corpus,
        baseline,
        candidate,
        updates,
        oracle_actions,
        baseline_false,
        candidate_false,
    )
    participant_count = len(instrument.get("responses", []))
    human_threshold = expected["minimum_human_participants"]
    if participant_count >= human_threshold:
        raise ValueError(
            "participant data exists but no registered analysis result was supplied"
        )
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0013",
        "programme_experiment": "EXP-LANG-006",
        "repetitions": repetitions,
        "implementations": {
            "rust": {
                "binary_sha256": _sha256_bytes(rust_binary.read_bytes()),
                "report_sha256": _sha256_bytes(rust_bytes),
            },
            "python": {
                "source_sha256": _sha256_bytes(
                    (
                        repository / "python/proofbound/notifications_research.py"
                    ).read_bytes()
                ),
                "report_sha256": _sha256_bytes(python_bytes),
            },
            "canonical_reports_equal": implementation_equal,
        },
        "metrics": {
            "fact_kind_count": len(fact_kinds),
            "baseline_alerts": len(baseline),
            "candidate_notifications": len(candidate),
            "graph_updates": len(updates),
            "baseline_false_escalations": baseline_false,
            "candidate_false_escalations": candidate_false,
            "baseline_critical_actions_recalled": baseline_recalled,
            "candidate_critical_actions_recalled": candidate_recalled,
            "critical_action_count": len(oracle_actions),
            "complete_notifications": complete_notifications,
            "retained_findings": len(retained),
            "finding_count": len(all_findings),
            "exact_attack_rejections": exact_attacks,
            "attack_count": len(registered_attacks),
            "low_severity_critical_retained": low_severity_critical,
            "participant_count": participant_count,
            "minimum_human_participants": human_threshold,
        },
        "questions": {
            "Q1": {
                "status": "passed" if q1 else "failed",
                "passed": q1,
                "reason": "six typed states remain distinct and category attacks reject exactly",
            },
            "Q2": {
                "status": "passed" if q2 else "failed",
                "passed": q2,
                "reason": "both interfaces retain every critical action including low-severity dependencies",
            },
            "Q3": {
                "status": "passed" if q3 else "failed",
                "passed": q3,
                "reason": "claim grouping reduces interruption volume without losing graph findings",
            },
            "Q4": {
                "status": "passed" if q4 else "failed",
                "passed": q4,
                "reason": "independent canonical reports match and all decision records are actionable",
            },
            "Q5": {
                "status": "unanswered",
                "passed": None,
                "reason": "no eligible participant responses exist; machine proxies are not human evidence",
            },
        },
        "decision_report_identity": report["identity"],
        "attack_results": rust_model["attacks"],
    }


def _assert_expected_counts(
    expected: dict[str, Any],
    corpus: dict[str, Any],
    baseline: list[dict[str, Any]],
    candidate: list[dict[str, Any]],
    updates: list[dict[str, Any]],
    oracle_actions: set[tuple[str, str, str, str, str]],
    baseline_false: int,
    candidate_false: int,
) -> None:
    actual = {
        "scenario_count": len(corpus["scenarios"]),
        "baseline_alerts": len(baseline),
        "candidate_notifications": len(candidate),
        "graph_updates": len(updates),
        "critical_actions": len(oracle_actions),
        "baseline_false_escalations": baseline_false,
        "candidate_false_escalations": candidate_false,
    }
    if any(actual[key] != expected[key] for key in actual):
        raise ValueError("derived counts differ from the frozen expectations")


def _notification_complete(item: dict[str, Any]) -> bool:
    return bool(
        item["claim"]
        and item["kind"]
        and item["requested_action"]
        and item["publication_consequence"]
        and item["findings"]
        and item["paths"]
        and all(
            path["claim"] == item["claim"]
            and path["requested_action"] == item["requested_action"]
            and path["publication_consequence"] == item["publication_consequence"]
            and path["nodes"]
            for path in item["paths"]
        )
    )


def _action_tuple(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        item["scenario"],
        item["claim"],
        item["kind"],
        item["requested_action"],
        item["publication_consequence"],
    )


def _path_action_tuple(
    scenario: str, path: dict[str, Any]
) -> tuple[str, str, str, str, str]:
    return (
        scenario,
        path["claim"],
        path["kind"],
        path["requested_action"],
        path["publication_consequence"],
    )


def _run_rust(repository: Path, rust_binary: Path, repetitions: int) -> bytes:
    result = subprocess.run(
        [
            str(rust_binary),
            "execute-notifications",
            str(repository),
            str(CORPUS),
            str(repetitions),
        ],
        cwd=repository,
        env={"PATH": "/usr/bin:/bin"},
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError(
            "Rust notification model failed: " + result.stderr.decode(errors="replace")
        )
    return result.stdout


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def main(argv: list[str] | None = None) -> int:
    """Run Experiment 0013 and emit its canonical execution report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print(
            "usage: python -m proofbound.notifications_experiment <repository> <rust-binary>",
            file=sys.stderr,
        )
        return 2
    try:
        report = execute_experiment(Path(arguments[0]), Path(arguments[1]))
    except (OSError, ValueError, notifications.NotificationFailure) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(notifications.canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
