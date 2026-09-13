"""Execute the preregistered mixed-language migration experiment."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from proofbound import migration_research

REPORT_SCHEMA = "proofbound-research-mixed-migration-execution/1"
EXPERIMENT = Path("docs/experiments/0017-mixed-language-migration")
CORPUS = EXPERIMENT / "corpus"


def execute_experiment(
    repository: Path, rust_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Run both callers and both graph kernels before opening expectations.

    Args:
        repository: Proofbound repository root.
        rust_binary: Built mixed-graph research executable.
        repetitions: Frozen deterministic repetition count.

    Returns:
        Canonicalizable measurements and Q1--Q5 decisions.

    Raises:
        ValueError: If a registered execution, comparison, or limit fails.
    """

    repository = repository.resolve()
    rust_binary = rust_binary.resolve()
    if repetitions != 10:
        raise ValueError("Experiment 0017 requires exactly ten repetitions")
    started = time.monotonic_ns()
    contract = _read_json(repository / CORPUS / "contract.json")
    observations, caller_bytes = _run_callers(repository, contract)
    envelope = migration_research.encode_observation_envelope(observations)
    rust_bytes = _run_rust(repository, rust_binary, envelope, repetitions)
    independent = migration_research.reconstruct_migration_report(
        repository, CORPUS, envelope, repetitions
    )
    independent_bytes = migration_research.canonical_json(independent)
    if rust_bytes != independent_bytes:
        raise ValueError("independent mixed-language reports differ")
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    return _summarize(
        repository,
        rust_binary,
        contract,
        observations,
        caller_bytes,
        envelope,
        json.loads(rust_bytes),
        rust_bytes,
        independent_bytes,
        elapsed_ms,
        repetitions,
    )


def _run_callers(
    repository: Path, contract: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    subjects = {
        "python": EXPERIMENT / "subjects/python_caller.py",
        "typescript": EXPERIMENT / "subjects/typescript_caller.mjs",
    }
    runtime_programs = {
        runtime["language"]: runtime["program"] for runtime in contract["runtimes"]
    }
    observations = []
    caller_bytes = {}
    for language in sorted(subjects):
        source = repository / subjects[language]
        caller_bytes[language] = migration_research.sha256_bytes(source.read_bytes())
        for phase in ("baseline", "migrated"):
            completed = subprocess.run(
                [
                    runtime_programs[language],
                    str(source),
                    str(repository / CORPUS / "contract.json"),
                    str(repository / CORPUS / "cases.json"),
                    phase,
                ],
                check=False,
                capture_output=True,
                cwd=repository,
                timeout=10,
            )
            if completed.returncode != 0 or completed.stderr:
                detail = completed.stderr.decode(errors="replace")
                raise ValueError(
                    f"foreign caller failed for {language}/{phase}: {detail}"
                )
            observation = json.loads(completed.stdout)
            if migration_research.canonical_json(observation) != completed.stdout:
                raise ValueError(
                    f"foreign caller output is noncanonical: {language}/{phase}"
                )
            observations.append(observation)
    return observations, caller_bytes


def _run_rust(
    repository: Path,
    binary: Path,
    envelope: bytes,
    repetitions: int,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="proofbound-migration-") as temporary:
        observation_path = Path(temporary) / "observations.json"
        observation_path.write_bytes(envelope)
        completed = subprocess.run(
            [
                str(binary),
                "execute-migration",
                str(repository),
                str(CORPUS),
                str(observation_path),
                str(repetitions),
            ],
            check=False,
            capture_output=True,
            cwd=repository,
            timeout=30,
        )
    if completed.returncode != 0 or completed.stderr:
        detail = completed.stderr.decode(errors="replace")
        raise ValueError(f"Rust mixed-graph kernel failed: {detail}")
    return completed.stdout


def _summarize(
    repository: Path,
    rust_binary: Path,
    contract: dict[str, Any],
    observations: list[dict[str, Any]],
    caller_bytes: dict[str, str],
    envelope: bytes,
    report: dict[str, Any],
    rust_bytes: bytes,
    independent_bytes: bytes,
    elapsed_ms: int,
    repetitions: int,
) -> dict[str, Any]:
    preregistration = _read_json(repository / EXPERIMENT / "preregistration.json")
    attacks = _read_json(repository / CORPUS / "attacks.json")
    expected = _read_json(repository / CORPUS / "expected.json")
    registered = [(item["id"], item["expected"]) for item in attacks["attacks"]]
    preregistered = [
        (item["id"], item["expected"]) for item in preregistration["attacks"]
    ]
    if registered != preregistered:
        raise ValueError("attack corpus differs from preregistration")
    if repetitions != expected["repetitions"]:
        raise ValueError("repetition count differs from expectation")
    attacks_by_id = {item["id"]: item for item in report["attacks"]}
    if set(attacks_by_id) != {identifier for identifier, _ in registered}:
        raise ValueError("implementation attack inventory differs")
    exact_attacks = sum(
        attacks_by_id[identifier]["actual_code"] == code
        and attacks_by_id[identifier]["exact"]
        for identifier, code in registered
    )
    calls = [call for observation in observations for call in observation["calls"]]
    semantic_projection = {
        (
            call["case_id"],
            call["accepted"],
            call["value"],
            call["output_hex"],
            call["error"],
            call["consumed"],
        )
        for call in calls
    }
    case_count = len(_read_json(repository / CORPUS / "cases.json")["cases"])
    semantic_agreement = len(semantic_projection) == case_count
    model_reports_equal = rust_bytes == independent_bytes
    stable = (
        len(report["repetition_identities"]) == repetitions
        and len(set(report["repetition_identities"])) == 1
        and report["repetition_identities"][0] == report["identity"]
    )
    limits = expected["limits"]
    caller_lines = {
        language: _source_lines(
            repository
            / EXPERIMENT
            / f"subjects/{language}_caller{'.py' if language == 'python' else '.mjs'}",
            "#" if language == "python" else "//",
        )
        for language in ("python", "typescript")
    }
    kernel_paths = {
        "rust": repository / "crates/proofbound-ir-prototype/src/migration.rs",
        "python": repository / "python/proofbound/migration_research.py",
    }
    kernel_lines = {
        "rust": _source_lines(kernel_paths["rust"], "//"),
        "python": _source_lines(kernel_paths["python"], "#"),
    }
    forbidden = preregistration["complexity"]["forbidden_common_names"]
    forbidden_hits = {
        name: sorted(
            backend
            for backend, path in kernel_paths.items()
            if name.casefold() in path.read_text().casefold()
        )
        for name in forbidden
    }
    metrics = {
        "attack_count": len(report["attacks"]),
        "caller_lines": caller_lines,
        "elapsed_ms": elapsed_ms,
        "exact_attack_rejections": exact_attacks,
        "foreign_calls": len(calls),
        "kernel_lines": kernel_lines,
        "observation_sets": len(observations),
        "report_bytes": len(rust_bytes),
        "semantic_projections": len(semantic_projection),
    }
    q1 = (
        len(calls) == expected["observation_count"]
        and semantic_agreement
        and model_reports_equal
        and exact_attacks == expected["attack_count"]
    )
    q2 = (
        report["migrated"]["derivations"][1]["formal"] == "proved-finite-type"
        and report["migrated"]["derivations"][1]["artifact"] == "assumption-bound"
        and all(
            derivation["formal"] == "tested"
            for derivation in report["migrated"]["derivations"]
            if derivation["claim_id"].endswith("-packet")
        )
        and "assumption:artifact-correspondence" in report["migrated"]["assumptions"]
        and all(
            value in report["migrated"]["assumptions"]
            for value in (
                "assumption:python-bridge",
                "assumption:python-runtime",
                "assumption:typescript-bridge",
                "assumption:typescript-runtime",
            )
        )
    )
    q3 = (
        report["migration"]["affected_claims"] == expected["affected_claims"]
        and report["migration"]["unaffected_claims"] == expected["unaffected_claims"]
        and report["baseline"]["derivations"][0] == report["migrated"]["derivations"][0]
    )
    q4 = model_reports_equal and stable and exact_attacks == expected["attack_count"]
    q5 = (
        all(value <= limits["max_caller_lines_each"] for value in caller_lines.values())
        and kernel_lines["rust"] <= limits["max_rust_kernel_lines"]
        and kernel_lines["python"] <= limits["max_python_kernel_lines"]
        and len(rust_bytes) <= limits["max_report_bytes"]
        and elapsed_ms <= limits["max_elapsed_ms"]
        and all(not hits for hits in forbidden_hits.values())
        and report["explanation"]["affected_claims"] == expected["affected_claims"]
        and report["explanation"]["unaffected_claims"] == expected["unaffected_claims"]
    )
    if not all((q1, q2, q3, q4, q5)):
        raise ValueError("one or more preregistered migration questions failed")
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0017",
        "programme_experiment": "EXP-LANG-008",
        "repetitions": repetitions,
        "implementations": {
            "caller_sha256": caller_bytes,
            "canonical_reports_equal": model_reports_equal,
            "independent_kernel_sha256": migration_research.sha256_bytes(
                kernel_paths["python"].read_bytes()
            ),
            "independent_report_sha256": migration_research.sha256_bytes(
                independent_bytes
            ),
            "rust_binary_sha256": migration_research.sha256_bytes(
                rust_binary.read_bytes()
            ),
            "rust_kernel_sha256": migration_research.sha256_bytes(
                kernel_paths["rust"].read_bytes()
            ),
            "rust_report_sha256": migration_research.sha256_bytes(rust_bytes),
        },
        "identities": {
            "artifact": contract["artifact"]["identity"],
            "contract": contract["identity"],
            "observation_envelope": migration_research.sha256_bytes(envelope),
            "report": report["identity"],
        },
        "metrics": metrics,
        "forbidden_common_name_hits": forbidden_hits,
        "questions": {
            "Q1": {
                "passed": q1,
                "reason": "both callers agree on all 48 calls and both kernels reject every boundary attack exactly",
            },
            "Q2": {
                "passed": q2,
                "reason": "finite native assurance, tested foreign ceilings, and every bridge/runtime assumption remain distinct",
            },
            "Q3": {
                "passed": q3,
                "reason": "only the registered packet-dependent claims change while the unrelated derivation remains byte-identical",
            },
            "Q4": {
                "passed": q4,
                "reason": "independent kernels emit one byte-identical report and exact attack codes across ten repetitions",
            },
            "Q5": {
                "passed": q5,
                "reason": "callers, common kernels, report, execution, and explanation satisfy every frozen ceiling",
            },
        },
    }


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


def main(arguments: list[str]) -> int:
    """Execute from a repository root and emit one canonical result."""

    if len(arguments) != 2:
        raise SystemExit("usage: migration_experiment.py REPOSITORY RUST_BINARY")
    report = execute_experiment(Path(arguments[0]), Path(arguments[1]))
    sys.stdout.buffer.write(migration_research.canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
