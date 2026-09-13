"""Execute the preregistered native canonical-parser experiment."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from proofbound import native_research

REPORT_SCHEMA = "proofbound-research-native-execution/1"
CORPUS = Path("docs/experiments/0016-native-canonical-parser/corpus")


def execute_experiment(
    repository: Path, rust_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Run the producer and independent checker before opening expectations.

    Args:
        repository: Proofbound repository root.
        rust_binary: Built native research executable.
        repetitions: Frozen deterministic repetition count.

    Returns:
        Canonicalizable measurements and Q1--Q5 decisions.

    Raises:
        ValueError: If a registered control, comparison, or limit fails.
    """

    repository = repository.resolve()
    rust_binary = rust_binary.resolve()
    if repetitions != 10:
        raise ValueError("Experiment 0016 requires exactly ten repetitions")
    started = time.monotonic_ns()
    rust_bytes = _run_rust(repository, rust_binary, repetitions)
    independent = native_research.reconstruct_native_report(
        repository, CORPUS, rust_bytes
    )
    independent_bytes = native_research.canonical_json(independent)
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    return _summarize(
        repository,
        rust_binary,
        json.loads(rust_bytes),
        rust_bytes,
        independent_bytes,
        elapsed_ms,
        repetitions,
    )


def _summarize(
    repository: Path,
    rust_binary: Path,
    report: dict[str, Any],
    rust_bytes: bytes,
    independent_bytes: bytes,
    elapsed_ms: int,
    repetitions: int,
) -> dict[str, Any]:
    preregistration = _read_json(
        repository
        / "docs/experiments/0016-native-canonical-parser/preregistration.json"
    )
    expected = _read_json(repository / CORPUS / "expected.json")
    attacks = _read_json(repository / CORPUS / "attacks.json")
    registered = [(item["id"], item["expected"]) for item in attacks["attacks"]]
    preregistered = [
        (item["id"], item["expected"]) for item in preregistration["attacks"]
    ]
    if registered != preregistered:
        raise ValueError("attack corpus differs from preregistration")
    if repetitions != expected["repetitions"]:
        raise ValueError("repetition count differs from expectation")
    report_attacks = {item["id"]: item for item in report["attacks"]}
    if set(report_attacks) != {identifier for identifier, _ in registered}:
        raise ValueError("implementation attack inventory differs")
    exact_attacks = sum(
        report_attacks[identifier]["actual_code"] == code
        and report_attacks[identifier]["exact"]
        for identifier, code in registered
    )
    by_class = {
        name: [item for item in attacks["attacks"] if item["class"] == name]
        for name in ("source", "artifact", "certificate", "smt")
    }
    exact_by_class = {
        name: all(report_attacks[item["id"]]["exact"] for item in items)
        for name, items in by_class.items()
    }
    certificate = report["certificate"]
    model_reports_equal = rust_bytes == independent_bytes
    repetitions_stable = (
        len(report["repetition_identities"]) == repetitions
        and len(set(report["repetition_identities"])) == 1
        and report["repetition_identities"][0] == report["identity"]
    )
    source_path = repository / CORPUS / "parser.pb"
    smt = native_research.generate_native_smt(
        native_research.parse_native_source(source_path.read_bytes())
    ).encode()
    limits = expected["limits"]
    metrics = {
        "artifact_bytes": len(bytes.fromhex(report["artifact_hex"])),
        "attack_count": len(report["attacks"]),
        "certificate_bytes": len(native_research.canonical_json(certificate)),
        "certificate_input_rows": len(certificate["input_rows"]),
        "certificate_value_rows": len(certificate["value_rows"]),
        "elapsed_ms": elapsed_ms,
        "exact_attack_rejections": exact_attacks,
        "killed_semantic_mutants": sum(
            item["killed"] for item in certificate["semantic_mutants"]
        ),
        "python_checker_lines": _source_lines(
            repository / "python/proofbound/native_research.py", "#"
        ),
        "report_bytes": len(rust_bytes),
        "rust_native_lines": _source_lines(
            repository / "crates/proofbound-ir-prototype/src/native.rs", "//"
        ),
        "smt_bytes": len(smt),
        "source_bytes": source_path.stat().st_size,
    }
    assurance = report["assurance"]
    q1 = model_reports_equal and exact_by_class["source"]
    q2 = (
        certificate["solver"]["results"] == expected["solver_results"]
        and metrics["certificate_value_rows"] == expected["value_rows"]
        and metrics["certificate_input_rows"] == expected["input_rows"]
        and exact_by_class["certificate"]
        and exact_by_class["smt"]
    )
    q3 = model_reports_equal and repetitions_stable and exact_by_class["artifact"]
    q4 = assurance == {
        "artifact_correspondence": "independent-dual-compilation-assumption-bound",
        "artifact_proved": False,
        "examples": "tested-only",
        "input_properties": "bounded-exhaustive-alphabet-0-4-length-0-3",
        "round_trip": "universal-over-declared-u2",
    }
    q5 = (
        metrics["source_bytes"] <= limits["max_source_bytes"]
        and metrics["artifact_bytes"] <= limits["max_artifact_bytes"]
        and metrics["certificate_bytes"] <= limits["max_certificate_bytes"]
        and metrics["smt_bytes"] <= limits["max_smt_bytes"]
        and metrics["rust_native_lines"] <= limits["max_rust_module_lines"]
        and metrics["python_checker_lines"] <= limits["max_python_checker_lines"]
        and metrics["report_bytes"] <= limits["max_report_bytes"]
        and metrics["elapsed_ms"] <= limits["max_elapsed_ms"]
        and metrics["killed_semantic_mutants"] == expected["semantic_mutants"]
    )
    if exact_attacks != expected["attack_count"] or not all((q1, q2, q3, q4, q5)):
        raise ValueError("one or more preregistered native questions failed")
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0016",
        "programme_experiment": "EXP-LANG-007",
        "repetitions": repetitions,
        "implementations": {
            "canonical_reports_equal": model_reports_equal,
            "independent_report_sha256": native_research.sha256_bytes(
                independent_bytes
            ),
            "python_checker_sha256": native_research.sha256_bytes(
                (repository / "python/proofbound/native_research.py").read_bytes()
            ),
            "rust_binary_sha256": native_research.sha256_bytes(
                rust_binary.read_bytes()
            ),
            "rust_report_sha256": native_research.sha256_bytes(rust_bytes),
        },
        "identities": {
            "artifact": report["artifact_identity"],
            "certificate": certificate["identity"],
            "report": report["identity"],
            "smt_sha256": report["smt_sha256"],
            "solver_executable_sha256": certificate["solver"]["executable_sha256"],
            "source_sha256": report["source_sha256"],
        },
        "metrics": metrics,
        "questions": {
            "Q1": {
                "passed": q1,
                "reason": "both parsers accept one canonical source and reject all source attacks exactly",
            },
            "Q2": {
                "passed": q2,
                "reason": "five VCs are unsat and the independent checker reconstructs every finite certificate obligation",
            },
            "Q3": {
                "passed": q3,
                "reason": "independent compilation is byte-identical across ten stable repetitions and all artifact attacks reject",
            },
            "Q4": {
                "passed": q4,
                "reason": "finite universality, bounded exhaustiveness, tests, and artifact assumptions remain distinct",
            },
            "Q5": {
                "passed": q5,
                "reason": "all semantic mutants reject and every frozen size, source, and elapsed-time ceiling holds",
            },
        },
    }


def _run_rust(repository: Path, binary: Path, repetitions: int) -> bytes:
    completed = subprocess.run(
        [
            str(binary),
            "execute-native",
            str(repository),
            str(CORPUS),
            str(repetitions),
        ],
        check=False,
        capture_output=True,
        cwd=repository,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr:
        detail = completed.stderr.decode(errors="replace")
        raise ValueError(f"Rust native producer failed: {detail}")
    return completed.stdout


def _source_lines(path: Path, comment_prefix: str) -> int:
    return sum(
        bool(line.strip()) and not line.lstrip().startswith(comment_prefix)
        for line in path.read_text().splitlines()
    )


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value
