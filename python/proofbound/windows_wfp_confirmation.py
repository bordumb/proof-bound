"""Derive the preregistered EXP-0027 decision."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from proofbound.windows_enforcement_execute import canonical_json, domain_hash, sha256_bytes
from proofbound.windows_wfp_research import (
    ATTACKS,
    WindowsWfpError,
    validate_capture_bytes,
)


EXECUTION_SCHEMA = "proofbound-research-windows-wfp-execution/1"


def evaluate(
    repository: Path,
    capture_path: Path,
    rust_report_path: Path,
    python_report_path: Path,
    rust_attacks_path: Path,
    python_attacks_path: Path,
) -> dict[str, Any]:
    """Validate both implementations and derive a fail-closed decision."""

    capture_bytes = capture_path.read_bytes()
    expected_report = canonical_json(validate_capture_bytes(repository, capture_bytes))
    rust_report = rust_report_path.read_bytes()
    python_report = python_report_path.read_bytes()
    rust_attacks = rust_attacks_path.read_bytes()
    python_attacks = python_attacks_path.read_bytes()
    if expected_report != rust_report or expected_report != python_report:
        raise ValueError("independent EXP-0027 reports differ")
    if rust_attacks != python_attacks:
        raise ValueError("independent EXP-0027 attack reports differ")
    report = json.loads(expected_report)
    attack_report = json.loads(python_attacks)
    capture = json.loads(capture_bytes)
    exact_attacks = (
        attack_report.get("all_exact") is True
        and len(attack_report.get("attacks", [])) == len(ATTACKS)
        and all(item.get("exact") is True for item in attack_report["attacks"])
    )
    metrics = report["metrics"]
    questions = {
        "Q1": report["questions"]["Q1"] is True,
        "Q2": report["questions"]["Q2"] is True
        and metrics["network_authority_denials"] == 3
        and metrics["network_control_connections"] == 3
        and metrics["network_sandbox_connections"] == 0,
        "Q3": report["questions"]["Q3"] is True and exact_attacks,
        "Q4": report["questions"]["Q4"] is True
        and rust_report == python_report
        and rust_attacks == python_attacks,
        "Q5": report["questions"]["Q5"] is True
        and metrics["reviewed_tree_changed"] is False
        and capture["within_elapsed_ceiling"] is True,
    }
    decision = (
        "stop"
        if capture.get("fallback_used") is not False
        else "pass"
        if all(questions.values())
        else "revise"
    )
    result = {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0027",
        "programme_experiment": "EXP-LANG-020",
        "decision": decision,
        "availability": report["availability"],
        "questions": questions,
        "metrics": {
            **metrics,
            "policy_attack_rejections": len(attack_report["attacks"]),
            "validator_disagreement": False,
        },
        "identities": {
            "capture_sha256": sha256_bytes(capture_bytes),
            "closure": report["closure_identity"],
            "observer": report["observer_identity"],
            "corpus_revision": report["corpus_revision_sha256"],
            "rust_report_sha256": sha256_bytes(rust_report),
            "python_report_sha256": sha256_bytes(python_report),
            "rust_attacks_sha256": sha256_bytes(rust_attacks),
            "python_attacks_sha256": sha256_bytes(python_attacks),
            "reports_equal": True,
            "attack_reports_equal": True,
        },
    }
    result["identity"] = domain_hash(EXECUTION_SCHEMA, result)
    return result


def main(argv: list[str] | None = None) -> int:
    """Write one canonical EXP-0027 decision record."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 7:
        print(
            "usage: windows_wfp_confirmation REPOSITORY CAPTURE RUST_REPORT "
            "PYTHON_REPORT RUST_ATTACKS PYTHON_ATTACKS EXECUTION",
            file=sys.stderr,
        )
        return 2
    try:
        result = evaluate(
            Path(arguments[0]),
            Path(arguments[1]),
            Path(arguments[2]),
            Path(arguments[3]),
            Path(arguments[4]),
            Path(arguments[5]),
        )
        Path(arguments[6]).write_bytes(canonical_json(result))
    except (OSError, ValueError, json.JSONDecodeError, WindowsWfpError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0 if result["decision"] in {"pass", "revise"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
