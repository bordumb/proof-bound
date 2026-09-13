"""Execute the preregistered specification-falsifier experiment."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import proofbound.specifications_research as specifications

REPORT_SCHEMA = "proofbound-research-specification-execution/1"
CORPUS = Path("docs/experiments/0014-specification-falsifiers/corpus")
VACUITY_ATTACKS = {
    "unreachable-precondition",
    "tautological-postcondition",
    "result-independent-postcondition",
    "inconsistent-postconditions",
    "vacuous-implication",
    "empty-obligations",
}
STRUCTURAL_ATTACKS = {
    "unknown-constructor",
    "duplicate-contract",
    "duplicate-carrier-value",
    "empty-carrier",
    "incomplete-carrier",
    "unknown-variable",
    "expression-type-mismatch",
    "forged-report-identity",
    "noncanonical-order",
}
SURVIVOR_ATTACKS = {
    "always-success-survives",
    "always-error-survives",
    "noncanonical-mutant-survives",
}


def execute_experiment(
    repository: Path, rust_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Run both checkers before opening frozen expectations.

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
        raise ValueError("Experiment 0014 requires exactly ten repetitions")
    rust_bytes = _run_rust(repository, rust_binary, repetitions)
    python_model = specifications.execute_specification_corpus(
        repository, CORPUS, repetitions
    )
    python_bytes = specifications.canonical_json(python_model)
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
        / "docs/experiments/0014-specification-falsifiers/preregistration.json"
    )
    universe = _read_json(repository / CORPUS / "universe.json")
    suite = _read_json(repository / CORPUS / "contracts.json")
    expected = _read_json(repository / CORPUS / "expected.json")
    attack_corpus = _read_json(repository / CORPUS / "attacks.json")
    registered = [(item["id"], item["code"]) for item in attack_corpus["attacks"]]
    if registered != [
        (item["id"], item["code"]) for item in preregistration["attacks"]
    ]:
        raise ValueError("attack corpus differs from preregistration")
    if repetitions != expected["repetitions"]:
        raise ValueError("repetition count differs from expectation")
    if (
        rust_model.get("schema") != specifications.MODEL_REPORT_SCHEMA
        or python_model.get("schema") != specifications.MODEL_REPORT_SCHEMA
    ):
        raise ValueError("implementation report schema differs")
    rust_attacks = {item["id"]: item for item in rust_model["attacks"]}
    python_attacks = {item["id"]: item for item in python_model["attacks"]}
    wanted_attacks = {identifier for identifier, _ in registered}
    if set(rust_attacks) != wanted_attacks or set(python_attacks) != wanted_attacks:
        raise ValueError("attack inventory differs")
    exact = sum(
        rust_attacks[identifier]["actual_code"] == code
        and python_attacks[identifier]["actual_code"] == code
        and rust_attacks[identifier]["exact"]
        and python_attacks[identifier]["exact"]
        for identifier, code in registered
    )
    report = rust_model["specification_report"]
    contract_count = len(report["contract_results"])
    mutant_count = len(report["mutant_results"])
    correct_obligations = sum(
        result["satisfied_obligations"] for result in report["contract_results"]
    )
    reachable_contracts = sum(
        result["reachable_cases"] > 0 for result in report["contract_results"]
    )
    killed_mutants = sum(result["killed"] for result in report["mutant_results"])
    complete_counterexamples = sum(
        bool(result["first_counterexample"]["contract"])
        and bool(result["first_counterexample"]["case"])
        and bool(result["failing_contracts"])
        for result in report["mutant_results"]
    )
    implementation_equal = rust_bytes == python_bytes
    deterministic = all(
        len(model["repetition_report_identities"]) == repetitions
        and len(set(model["repetition_report_identities"])) == 1
        for model in (rust_model, python_model)
    )
    q1 = all(
        rust_attacks[identifier]["exact"] and python_attacks[identifier]["exact"]
        for identifier in STRUCTURAL_ATTACKS
    )
    q2 = reachable_contracts == contract_count and all(
        rust_attacks[identifier]["exact"] and python_attacks[identifier]["exact"]
        for identifier in VACUITY_ATTACKS
    )
    q3 = (
        report["correct_accepted"]
        and correct_obligations == expected["correct_obligation_count"]
        and killed_mutants == expected["mutant_count"]
        and complete_counterexamples == expected["mutant_count"]
        and all(
            rust_attacks[identifier]["exact"] and python_attacks[identifier]["exact"]
            for identifier in SURVIVOR_ATTACKS
        )
    )
    q4 = implementation_equal and exact == expected["attack_count"] and deterministic
    limits = expected["limits"]
    q5 = (
        {contract["role"] for contract in suite["contracts"]}
        == set(universe["required_roles"])
        and report["ast_nodes"] <= limits["max_ast_nodes"]
        and report["carrier_values"] <= limits["max_carrier_values"]
        and contract_count <= limits["max_contracts"]
        and len(universe["variables"]) <= limits["max_variables"]
        and len(rust_bytes) <= limits["max_report_bytes"]
    )
    _assert_expected(
        expected,
        universe,
        suite,
        rust_model,
        report,
        correct_obligations,
    )
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0014",
        "programme_experiment": "EXP-LANG-009",
        "repetitions": repetitions,
        "implementations": {
            "rust": {
                "binary_sha256": specifications.sha256_bytes(rust_binary.read_bytes()),
                "report_sha256": specifications.sha256_bytes(rust_bytes),
            },
            "python": {
                "source_sha256": specifications.sha256_bytes(
                    (
                        repository / "python/proofbound/specifications_research.py"
                    ).read_bytes()
                ),
                "report_sha256": specifications.sha256_bytes(python_bytes),
            },
            "canonical_reports_equal": implementation_equal,
        },
        "metrics": {
            "exact_attack_rejections": exact,
            "attack_count": len(registered),
            "contract_count": contract_count,
            "reachable_contracts": reachable_contracts,
            "correct_obligations_satisfied": correct_obligations,
            "correct_obligation_count": expected["correct_obligation_count"],
            "mutants_killed": killed_mutants,
            "mutant_count": mutant_count,
            "complete_counterexamples": complete_counterexamples,
            "ast_nodes": report["ast_nodes"],
            "carrier_values": report["carrier_values"],
            "variable_count": len(universe["variables"]),
            "model_report_bytes": len(rust_bytes),
        },
        "questions": {
            f"Q{index}": {
                "passed": passed,
                "reason": reason,
            }
            for index, (passed, reason) in enumerate(
                [
                    (q1, "closed structural and type attacks reject exactly"),
                    (
                        q2,
                        "all accepted contracts are reachable and registered vacuity forms reject",
                    ),
                    (
                        q3,
                        "the correct relation passes while every explicit mutant is killed",
                    ),
                    (
                        q4,
                        "independent canonical reports and attack outcomes match deterministically",
                    ),
                    (
                        q5,
                        "all five parser roles fit within the frozen backend-neutral complexity ceilings",
                    ),
                ],
                start=1,
            )
        },
        "specification_report_identity": report["identity"],
        "mutant_results": report["mutant_results"],
        "attack_results": rust_model["attacks"],
    }


def _assert_expected(
    expected: dict[str, Any],
    universe: dict[str, Any],
    suite: dict[str, Any],
    model: dict[str, Any],
    report: dict[str, Any],
    correct_obligations: int,
) -> None:
    actual = {
        "attack_count": len(model["attacks"]),
        "carrier_count": len(universe["carriers"]),
        "carrier_value_count": report["carrier_values"],
        "contract_count": len(suite["contracts"]),
        "correct_obligation_count": correct_obligations,
        "implementation_count": 1 + len(suite["required_mutants"]),
        "mutant_count": len(report["mutant_results"]),
        "role_count": len(universe["required_roles"]),
        "variable_count": len(universe["variables"]),
    }
    if any(actual[key] != expected[key] for key in actual):
        raise ValueError("derived counts differ from frozen expectations")


def _run_rust(repository: Path, rust_binary: Path, repetitions: int) -> bytes:
    result = subprocess.run(
        [
            str(rust_binary),
            "execute-specifications",
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
            "Rust specification model failed: " + result.stderr.decode(errors="replace")
        )
    return result.stdout


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    """Run Experiment 0014 and emit its canonical execution report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print(
            "usage: python -m proofbound.specifications_experiment <repository> <rust-binary>",
            file=sys.stderr,
        )
        return 2
    try:
        report = execute_experiment(Path(arguments[0]), Path(arguments[1]))
    except (OSError, ValueError, specifications.SpecificationFailure) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(specifications.canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
