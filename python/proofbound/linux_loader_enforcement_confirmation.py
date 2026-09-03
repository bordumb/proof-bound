"""Evaluate the preregistered EXP-0024 Linux loader repair."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from proofbound import linux_enforcement_execute as base
from proofbound import linux_loader_enforcement_research as research


EXPERIMENT = Path("docs/experiments/0024-linux-loader-closure")
EXECUTION_SCHEMA = "proofbound-research-linux-loader-execution/1"


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def evaluate(
    repository: Path,
    capture_path: Path,
    rust_report_path: Path,
    python_report_path: Path,
    attacks_path: Path,
) -> dict[str, Any]:
    """Derive the registered EXP-0024 decision from exact artifacts."""

    repository = repository.resolve()
    registration = _load_object(repository / EXPERIMENT / "preregistration.json")
    contract_path = repository / registration["frozen_contract"]["path"]
    retained_path = repository / registration["retained_falsifier"]["path"]
    if _sha256(contract_path) != registration["frozen_contract"]["sha256"]:
        raise ValueError("frozen contract changed")
    if _sha256(retained_path) != registration["retained_falsifier"]["sha256"]:
        raise ValueError("retained falsifier changed")

    capture_bytes = capture_path.read_bytes()
    capture = json.loads(capture_bytes)
    report = research.validate_capture_bytes(repository, capture_bytes)
    expected_report = base.canonical_json(report)
    rust_report = rust_report_path.read_bytes()
    python_report = python_report_path.read_bytes()
    if rust_report != expected_report or python_report != expected_report:
        raise ValueError("independent Linux loader reports differ")

    attacks = _load_object(attacks_path)
    rows = attacks.get("validators")
    if (
        attacks.get("schema") != "proofbound-research-linux-loader-attacks/1"
        or not isinstance(rows, dict)
        or set(rows) != {"python", "rust"}
        or any(len(rows[name]) != 20 for name in rows)
        or not all(item["exact"] for name in rows for item in rows[name])
    ):
        raise ValueError("registered validator attacks differ")

    metrics = report["metrics"]
    platform = report["platform"]
    questions = {
        "Q1": report["availability"] == "supported"
        and metrics["positive_executions"] == 30,
        "Q2": metrics["authority_probe_executions"] == 21
        and metrics["denied_reusable"] == 0,
        "Q3": len(report["runtime_loaders"]) == 3
        and report["system_root_execute_authority"] == "deny",
        "Q4": rust_report == python_report
        and all(item["exact"] for name in rows for item in rows[name]),
        "Q5": platform["landlock_abi"] is not None
        and platform["landlock_abi"] >= 4
        and platform["no_new_privs"] is True
        and capture["reviewed_tree_before"] == capture["reviewed_tree_after"]
        and capture["container_confinement_counted"] is False
        and 0 < metrics["elapsed_ms"] <= registration["ceilings"]["max_elapsed_ms"],
    }
    decision = "pass" if all(questions.values()) else "revise"
    result = {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0024",
        "programme_experiment": "EXP-LANG-017",
        "decision": decision,
        "availability": report["availability"],
        "questions": questions,
        "metrics": metrics,
        "identities": {
            "capture_sha256": _sha256(capture_path),
            "rust_report_sha256": _sha256(rust_report_path),
            "python_report_sha256": _sha256(python_report_path),
            "attacks_sha256": _sha256(attacks_path),
            "reports_equal": rust_report == python_report,
        },
    }
    return result


def main(argv: list[str] | None = None) -> int:
    """Write a canonical EXP-0024 decision record."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 6:
        print(
            "usage: linux_loader_enforcement_confirmation REPOSITORY CAPTURE "
            "RUST_REPORT PYTHON_REPORT ATTACKS EXECUTION",
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
        )
        Path(arguments[5]).write_bytes(base.canonical_json(result))
    except (OSError, ValueError, research.LinuxLoaderError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
