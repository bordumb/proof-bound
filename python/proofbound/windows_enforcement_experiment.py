"""Evaluate retained EXP-0021 Windows portability evidence."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from proofbound import windows_enforcement_execute as execution
from proofbound import windows_enforcement_research as research


EXECUTION_SCHEMA = "proofbound-research-windows-enforcement-execution/1"
EXPERIMENT = Path("docs/experiments/0021-windows-enforcement-portability")


def _nonblank_lines(path: Path) -> int:
    return sum(
        bool(line.strip()) for line in path.read_text(encoding="utf-8").splitlines()
    )


def evaluate_experiment(repository: Path) -> dict[str, Any]:
    """Derive the preregistered decision from retained artifacts.

    Args:
        repository: Proofbound repository root.

    Returns:
        Canonicalizable EXP-0021 decision record.

    Raises:
        ValueError: If retained evidence is inconsistent.
    """

    repository = repository.resolve()
    root = repository / EXPERIMENT
    results = root / "results"
    capture_bytes = (results / "capture.json").read_bytes()
    report = research.validate_capture_bytes(repository, capture_bytes)
    python_bytes = execution.canonical_json(report)
    rust_bytes = (results / "rust-report.json").read_bytes()
    retained_python = (results / "python-report.json").read_bytes()
    if python_bytes != rust_bytes or python_bytes != retained_python:
        raise ValueError("independent Windows reports differ")
    registration = json.loads((root / "preregistration.json").read_bytes())
    capture = json.loads(capture_bytes)
    ceilings = registration["ceilings"]
    rust_lines = _nonblank_lines(
        repository / "crates/proofbound-ir-prototype/src/windows_enforcement.rs"
    )
    python_lines = _nonblank_lines(
        repository / "python/proofbound/windows_enforcement_research.py"
    )
    policy = report["effective_policy"]
    q1 = (
        len(policy["path_authority"]) == 5
        and policy["appcontainer"]["capabilities"] == []
        and policy["job_object"]["active_process_limit"] == 1
        and policy["restricted_token"]["disable_max_privilege"] is True
    )
    q2 = False
    q3 = (
        report["availability"] == "unsupported"
        and capture["slots"] == []
        and capture["fallback_used"] is False
        and report["metrics"]["supported_execution"] is False
    )
    q4 = (
        python_bytes == rust_bytes
        and len(report["policy_attacks"]) == registration["inventory"]["policy_attacks"]
        and all(item["exact"] for item in report["policy_attacks"])
    )
    q5 = (
        rust_lines <= ceilings["max_rust_lines"]
        and python_lines <= ceilings["max_python_lines"]
        and len(python_bytes) <= ceilings["max_report_bytes"]
    )
    decision = "unanswered" if q1 and q3 and q4 and q5 else "revise"
    return {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0021",
        "programme_experiment": "EXP-LANG-014",
        "decision": decision,
        "availability": report["availability"],
        "questions": {
            "Q1": {
                "passed": q1,
                "reason": "all authority classes have explicit AppContainer, token, job, ACL, or preflight dispositions",
            },
            "Q2": {
                "passed": q2,
                "unavailable": True,
                "reason": "no supported Windows 11 execution environment was available; no workload ran",
            },
            "Q3": {
                "passed": q3,
                "reason": "the host gate emitted zero receipts and admitted no fallback",
            },
            "Q4": {
                "passed": q4,
                "reason": "independent Rust and Python reports are byte-identical and all 18 attacks are exact",
            },
            "Q5": {
                "passed": q5,
                "reason": "implementation and report sizes remain below preregistered ceilings",
            },
        },
        "metrics": {
            **report["metrics"],
            "path_authority_rows": len(policy["path_authority"]),
            "policy_attack_rejections": len(report["policy_attacks"]),
            "rust_lines": rust_lines,
            "python_lines": python_lines,
            "canonical_report_bytes": len(python_bytes),
        },
        "identities": {
            "capture_sha256": execution.sha256_bytes(capture_bytes),
            "rust_report_sha256": execution.sha256_bytes(rust_bytes),
            "python_report_sha256": execution.sha256_bytes(python_bytes),
            "reports_equal": python_bytes == rust_bytes,
        },
    }


def main(argv: list[str] | None = None) -> int:
    """Write the canonical EXP-0021 evaluation."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print(
            "usage: windows_enforcement_experiment REPOSITORY EXECUTION",
            file=sys.stderr,
        )
        return 2
    try:
        result = evaluate_experiment(Path(arguments[0]))
        Path(arguments[1]).write_bytes(execution.canonical_json(result))
    except (OSError, ValueError, research.WindowsEnforcementError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
