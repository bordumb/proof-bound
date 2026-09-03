"""Evaluate the preregistered EXP-0022 Linux confirmation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from proofbound import linux_enforcement_execute as execution
from proofbound import linux_enforcement_research as research


EXPERIMENT = Path("docs/experiments/0022-linux-enforcement-confirmation")
EXECUTION_SCHEMA = "proofbound-research-linux-confirmation-execution/1"


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def _validate_frozen_inputs(repository: Path, registration: dict[str, Any]) -> None:
    for item in registration["frozen_inputs"]:
        path = repository / item["path"]
        if _sha256(path) != item["sha256"]:
            raise ValueError(f"frozen input changed: {item['path']}")


def _decision(availability: str, questions: dict[str, bool]) -> str:
    """Derive the registered decision without EXP-0020's unreachable pass bug."""

    if availability == "unsupported":
        return "unanswered"
    if availability != "supported":
        raise ValueError("unknown availability")
    return "pass" if all(questions.values()) else "revise"


def evaluate(
    repository: Path,
    capture_path: Path,
    rust_report_path: Path,
    python_report_path: Path,
) -> dict[str, Any]:
    """Validate one frozen EXP-0020 rerun as the EXP-0022 confirmation.

    Args:
        repository: Proofbound repository root.
        capture_path: Canonical capture produced by the frozen Linux runner.
        rust_report_path: Report emitted by the independent Rust validator.
        python_report_path: Report emitted by the independent Python validator.

    Returns:
        The canonicalizable EXP-0022 decision record.

    Raises:
        ValueError: If registrations, reports, or frozen inputs differ.
        LinuxEnforcementError: If the capture violates the frozen contract.
    """

    repository = repository.resolve()
    registration = _load_object(repository / EXPERIMENT / "preregistration.json")
    _validate_frozen_inputs(repository, registration)

    capture_bytes = capture_path.read_bytes()
    capture = json.loads(capture_bytes)
    report = research.validate_capture_bytes(repository, capture_bytes)
    python_bytes = execution.canonical_json(report)
    rust_bytes = rust_report_path.read_bytes()
    retained_python = python_report_path.read_bytes()
    if rust_bytes != python_bytes or retained_python != python_bytes:
        raise ValueError("independent Linux reports differ")

    metrics = report["metrics"]
    platform = report["platform"]
    supported = report["availability"] == "supported"
    questions = {
        "Q1": supported
        and platform["landlock_abi"] is not None
        and platform["landlock_abi"] >= 4
        and platform["probe_exit_code"] == 0
        and platform["no_new_privs"] is True,
        "Q2": supported and metrics["positive_executions"] == 30,
        "Q3": supported
        and metrics["authority_probe_executions"] == 21
        and metrics["denied_reusable"] == 0,
        "Q4": rust_bytes == python_bytes
        and len(report["policy_attacks"]) == 16
        and all(item["exact"] for item in report["policy_attacks"]),
        "Q5": capture["reviewed_tree_before"] == capture["reviewed_tree_after"]
        and capture["container_confinement_counted"] is False,
    }
    availability_fail_closed = supported or (
        report["availability"] == "unsupported"
        and capture["slots"] == []
        and platform["probe_exit_code"] != 0
        and platform["landlock_abi"] is None
    )
    if not availability_fail_closed:
        raise ValueError("availability did not fail closed")

    result = {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0022",
        "programme_experiment": "EXP-LANG-015",
        "decision": _decision(report["availability"], questions),
        "availability": report["availability"],
        "availability_fail_closed": availability_fail_closed,
        "questions": questions,
        "metrics": {
            "positive_executions": metrics["positive_executions"],
            "authority_probe_executions": metrics["authority_probe_executions"],
            "denied_reusable": metrics["denied_reusable"],
            "reviewed_tree_changed": metrics["reviewed_tree_changed"],
            "policy_attack_rejections": len(report["policy_attacks"]),
            "elapsed_ms": metrics["elapsed_ms"],
        },
        "identities": {
            "capture_sha256": _sha256(capture_path),
            "rust_report_sha256": _sha256(rust_report_path),
            "python_report_sha256": _sha256(python_report_path),
            "reports_equal": rust_bytes == python_bytes,
        },
    }
    return result


def main(argv: list[str] | None = None) -> int:
    """Write a canonical EXP-0022 decision record."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 5:
        print(
            "usage: linux_enforcement_confirmation REPOSITORY CAPTURE "
            "RUST_REPORT PYTHON_REPORT EXECUTION",
            file=sys.stderr,
        )
        return 2
    try:
        result = evaluate(
            Path(arguments[0]),
            Path(arguments[1]),
            Path(arguments[2]),
            Path(arguments[3]),
        )
        Path(arguments[4]).write_bytes(execution.canonical_json(result))
    except (OSError, ValueError, research.LinuxEnforcementError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
