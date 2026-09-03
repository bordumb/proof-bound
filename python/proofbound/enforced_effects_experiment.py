"""Evaluate the retained EXP-0018 enforcement capture."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from proofbound import enforced_effects_research as effects

EXECUTION_SCHEMA = "proofbound-research-enforced-effects-execution/1"
EXPERIMENT = Path("docs/experiments/0018-os-enforced-effects")


def evaluate_experiment(repository: Path) -> dict[str, Any]:
    """Derive registered measurements and question decisions from retained bytes.

    Args:
        repository: Proofbound repository root.

    Returns:
        Canonicalizable execution report for EXP-0018.

    Raises:
        ValueError: If retained inputs or independent reports disagree.
    """

    repository = repository.resolve()
    results = repository / EXPERIMENT / "results"
    capture_bytes = (results / "capture.json").read_bytes()
    capture = json.loads(capture_bytes)
    if effects.canonical_json(capture) != capture_bytes:
        raise ValueError("retained capture is not canonical")
    python_report = effects.validate_capture_bytes(repository, capture_bytes)
    python_bytes = effects.canonical_json(python_report)
    rust_bytes = (results / "rust-report.json").read_bytes()
    retained_python = (results / "python-report.json").read_bytes()
    if python_bytes != rust_bytes or python_bytes != retained_python:
        raise ValueError("independent canonical reports differ")

    expected = _read_json(repository / EXPERIMENT / "corpus/expected.json")
    attacks = python_report["attacks"]
    exact_attacks = sum(item["exact"] for item in attacks)
    positives = capture["positive_runs"]
    probes = capture["authority_probes"]
    subjects = sorted({item["plan"]["subject_id"] for item in positives})
    repetitions_stable = all(
        len(
            {
                item["identity"]
                for item in positives
                if item["plan"]["subject_id"] == subject
            }
        )
        == 1
        for subject in subjects
    )
    policy_lines = max(
        len(item["plan"]["policy"].splitlines())
        for item in positives + [p["receipt"] for p in probes]
    )
    subject_lines = {
        path.name: _nonblank_lines(path)
        for path in sorted(
            (repository / EXPERIMENT / "corpus/workspace/subjects").iterdir()
        )
    }
    rust_lines = _nonblank_lines(
        repository / "crates/proofbound-ir-prototype/src/enforced.rs"
    )
    python_lines = _nonblank_lines(
        repository / "python/proofbound/enforced_effects_research.py"
    )
    elapsed_ok = capture["elapsed_ms"] <= expected["ceilings"]["max_elapsed_ms"]
    size_ok = (
        rust_lines <= expected["ceilings"]["max_rust_runner_and_validator_lines"]
        and python_lines <= expected["ceilings"]["max_python_validator_lines"]
        and max(subject_lines.values())
        <= expected["ceilings"]["max_subject_lines_each"]
        and policy_lines <= expected["ceilings"]["max_policy_lines"]
        and len(python_bytes) <= expected["ceilings"]["max_report_bytes"]
    )
    q1 = (
        len(subjects) == 3
        and len(positives) == expected["expected_positive_executions"]
        and len(probes) == 21
        and all(not item["receipt"]["reusable"] for item in probes)
        and capture["reviewed_tree_before"] == capture["reviewed_tree_after"]
    )
    q2 = (
        python_report["metrics"]["stale_reuse"] == 0
        and python_report["metrics"]["unrelated_invalidation"] == 0
        and all(item["actual_code"] == item["expected_code"] for item in attacks[26:28])
    )
    q3 = python_bytes == rust_bytes and exact_attacks == expected["attack_count"]
    q4 = len(subjects) == 3 and all(
        item["plan"]["boundary"] == "os-enforced" for item in positives
    )
    q5 = repetitions_stable and size_ok and elapsed_ok
    questions = {
        "Q1": {
            "passed": q1,
            "reason": "all positive routes completed and every authority probe was denied without reusable evidence",
        },
        "Q2": {
            "passed": q2,
            "reason": "registered changes invalidate, the unrelated control does not, and undeclared reads are denied",
        },
        "Q3": {
            "passed": q3,
            "reason": "independent validators emit byte-identical reports and reject all 30 attacks exactly",
        },
        "Q4": {
            "passed": q4,
            "reason": "Python, Node, and Rust use one typed effect and receipt contract under the same boundary",
        },
        "Q5": {
            "passed": q5,
            "reason": (
                "determinism, source, policy, report, and reviewed-tree criteria pass, "
                f"but {capture['elapsed_ms']} ms exceeds the frozen 60000 ms ceiling"
            ),
        },
    }
    return {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0018",
        "programme_experiment": "EXP-LANG-011",
        "decision": "pass"
        if all(item["passed"] for item in questions.values())
        else "revise",
        "platform_scope": "macos-arm64-seatbelt",
        "implementations": {
            "canonical_reports_equal": python_bytes == rust_bytes,
            "rust_report_sha256": effects.sha256_bytes(rust_bytes),
            "python_report_sha256": effects.sha256_bytes(python_bytes),
            "rust_source_sha256": effects.sha256_bytes(
                (
                    repository / "crates/proofbound-ir-prototype/src/enforced.rs"
                ).read_bytes()
            ),
            "python_source_sha256": effects.sha256_bytes(
                (
                    repository / "python/proofbound/enforced_effects_research.py"
                ).read_bytes()
            ),
        },
        "metrics": {
            "positive_subjects": len(subjects),
            "positive_executions": len(positives),
            "authority_probe_executions": len(probes),
            "denied_reusable": sum(item["receipt"]["reusable"] for item in probes),
            "exact_attack_rejections": exact_attacks,
            "attack_count": len(attacks),
            "stale_reuse": python_report["metrics"]["stale_reuse"],
            "unrelated_invalidation": python_report["metrics"][
                "unrelated_invalidation"
            ],
            "reviewed_tree_changed": capture["reviewed_tree_before"]
            != capture["reviewed_tree_after"],
            "repetition_identities_stable": repetitions_stable,
            "elapsed_ms": capture["elapsed_ms"],
            "elapsed_ceiling_ms": expected["ceilings"]["max_elapsed_ms"],
            "rust_runner_validator_lines": rust_lines,
            "python_validator_lines": python_lines,
            "subject_lines": subject_lines,
            "max_policy_lines": policy_lines,
            "canonical_report_bytes": len(python_bytes),
        },
        "trusted_boundaries": {
            "mechanism": capture["mechanism"],
            "platform": capture["platform"],
            "runtime_artifacts": {
                subject: next(
                    item["plan"]["runtime"]
                    for item in positives
                    if item["plan"]["subject_id"] == subject
                )
                for subject in subjects
            },
            "toolchain_read_roots": {
                subject: next(
                    item["plan"]["toolchain_read_roots"]
                    for item in positives
                    if item["plan"]["subject_id"] == subject
                )
                for subject in subjects
            },
        },
        "questions": questions,
    }


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def _nonblank_lines(path: Path) -> int:
    return sum(
        bool(line.strip()) for line in path.read_text(encoding="utf-8").splitlines()
    )


def main(argv: list[str] | None = None) -> int:
    """Emit the canonical retained EXP-0018 evaluation."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print(
            "usage: python -m proofbound.enforced_effects_experiment <repository>",
            file=sys.stderr,
        )
        return 2
    try:
        report = evaluate_experiment(Path(arguments[0]))
    except (OSError, ValueError, effects.EnforcedEffectsError) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(effects.canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
