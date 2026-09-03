"""Evaluate retained EXP-0019 batched-enforcement evidence."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from proofbound import batched_enforcement_research as batch
from proofbound import enforced_effects_research as effects

EXECUTION_SCHEMA = "proofbound-research-batched-enforcement-execution/1"
EXPERIMENT = Path("docs/experiments/0019-batched-enforcement-latency")


def evaluate_experiment(repository: Path) -> dict[str, Any]:
    """Derive the registered EXP-0019 decision from retained bytes.

    Args:
        repository: Proofbound repository root.

    Returns:
        Canonicalizable experiment decision.

    Raises:
        ValueError: If retained artifacts disagree or violate registration.
    """

    repository = repository.resolve()
    results = repository / EXPERIMENT / "results"
    capture_bytes = (results / "capture.json").read_bytes()
    if effects.canonical_json(json.loads(capture_bytes)) != capture_bytes:
        raise ValueError("retained capture is not canonical")
    python_report = batch.validate_capture_bytes(repository, capture_bytes)
    python_bytes = effects.canonical_json(python_report)
    rust_bytes = (results / "rust-report.json").read_bytes()
    retained_python = (results / "python-report.json").read_bytes()
    if python_bytes != rust_bytes or python_bytes != retained_python:
        raise ValueError("independent batch reports differ")
    preregistration = json.loads(
        (repository / EXPERIMENT / "preregistration.json").read_bytes()
    )
    capture = json.loads(capture_bytes)
    metrics = python_report["metrics"]
    attacks = python_report["scheduler_attacks"]
    ceilings = preregistration["ceilings"]
    rust_lines = _nonblank_lines(
        repository / "crates/proofbound-ir-prototype/src/enforced_batch.rs"
    )
    python_lines = _nonblank_lines(
        repository / "python/proofbound/batched_enforcement_research.py"
    )
    policy_lines = max(
        len(slot["receipt"]["plan"]["policy"].splitlines()) for slot in capture["slots"]
    )
    q1 = (
        metrics["positive_executions"] == 30
        and metrics["authority_probe_executions"] == 21
        and metrics["denied_reusable"] == 0
        and not metrics["reviewed_tree_changed"]
        and metrics["elapsed_ms"] <= ceilings["max_elapsed_ms"]
    )
    q2 = (
        metrics["completed_slots"] == 51
        and metrics["unique_ephemeral_roots"] == 51
        and metrics["unique_positive_outputs"] == 30
        and all(item["exact"] for item in attacks)
    )
    q3 = (
        metrics["base_attack_rejections"]
        == preregistration["inventory"]["base_attacks"]
        and metrics["scheduler_attack_rejections"]
        == preregistration["inventory"]["scheduler_attacks"]
        and metrics["stale_reuse"] == 0
        and metrics["unrelated_invalidation"] == 0
    )
    q4 = python_bytes == rust_bytes
    q5 = (
        rust_lines <= ceilings["max_rust_scheduler_and_validator_lines"]
        and python_lines <= ceilings["max_python_validator_lines"]
        and policy_lines <= ceilings["max_policy_lines"]
        and len(python_bytes) <= ceilings["max_report_bytes"]
    )
    questions = {
        "Q1": {
            "passed": q1,
            "reason": (
                f"all 51 isolated slots completed in {metrics['elapsed_ms']} ms with "
                "no reusable denial or reviewed-tree change"
            ),
        },
        "Q2": {
            "passed": q2,
            "reason": "all slot, root, output, completion, and scheduler attacks are exact",
        },
        "Q3": {
            "passed": q3,
            "reason": "all 30 base attacks remain exact and invalidation remains sound and narrow",
        },
        "Q4": {
            "passed": q4,
            "reason": "Rust and Python derived byte-identical canonical batch reports",
        },
        "Q5": {
            "passed": q5,
            "reason": "scheduler, validator, policy, and report sizes remain below frozen ceilings",
        },
    }
    return {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0019",
        "programme_experiment": "EXP-LANG-012",
        "decision": "pass"
        if all(item["passed"] for item in questions.values())
        else "revise",
        "baseline_elapsed_ms": preregistration["frozen_baseline"]["elapsed_ms"],
        "elapsed_ceiling_ms": ceilings["max_elapsed_ms"],
        "metrics": {
            **metrics,
            "elapsed_reduction_ms": (
                preregistration["frozen_baseline"]["elapsed_ms"] - metrics["elapsed_ms"]
            ),
            "rust_scheduler_and_validator_lines": rust_lines,
            "python_validator_lines": python_lines,
            "max_policy_lines": policy_lines,
            "canonical_report_bytes": len(python_bytes),
        },
        "implementations": {
            "canonical_reports_equal": q4,
            "rust_report_sha256": effects.sha256_bytes(rust_bytes),
            "python_report_sha256": effects.sha256_bytes(python_bytes),
            "capture_sha256": effects.sha256_bytes(capture_bytes),
        },
        "questions": questions,
    }


def _nonblank_lines(path: Path) -> int:
    return sum(
        bool(line.strip()) for line in path.read_text(encoding="utf-8").splitlines()
    )


def main(argv: list[str] | None = None) -> int:
    """Write the canonical retained EXP-0019 evaluation."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print(
            "usage: python -m proofbound.batched_enforcement_experiment "
            "<repository> <execution.json>",
            file=sys.stderr,
        )
        return 2
    try:
        report = evaluate_experiment(Path(arguments[0]))
        Path(arguments[1]).write_bytes(effects.canonical_json(report))
    except (OSError, ValueError, batch.BatchedEnforcementError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
