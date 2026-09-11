"""Execute the preregistered Assurance IR differential experiment."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import proofbound.assurance_v2_research as assurance_v2

REPORT_SCHEMA = "proofbound-research-assurance-execution/1"
CORPUS = Path("docs/experiments/0015-assurance-ir-differential-kernel/corpus")
FAMILY_ATTACKS = {
    "EXP-0015-A025",
    "EXP-0015-A026",
    "EXP-0015-A027",
    "EXP-0015-A028",
}


def execute_experiment(
    repository: Path, rust_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Run both kernels before opening frozen expected values.

    Args:
        repository: Proofbound repository root.
        rust_binary: Built research-kernel executable.
        repetitions: Frozen deterministic repetition count.

    Returns:
        Canonicalizable report containing metrics and Q1--Q5 outcomes.

    Raises:
        ValueError: If either kernel or a preregistered invariant fails.
    """

    repository = repository.resolve()
    rust_binary = rust_binary.resolve()
    if repetitions != 10:
        raise ValueError("Experiment 0015 requires exactly ten repetitions")
    rust_bytes = _run_rust(repository, rust_binary, repetitions)
    python_model = assurance_v2.execute_assurance_v2_corpus(
        repository, CORPUS, repetitions
    )
    python_bytes = assurance_v2.canonical_json(python_model)
    rust_model = json.loads(rust_bytes)
    if not isinstance(rust_model, dict):
        raise ValueError("Rust model report is not an object")
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
        / "docs/experiments/0015-assurance-ir-differential-kernel/preregistration.json"
    )
    expected = _read_json(repository / CORPUS / "expected.json")
    model, templates, attacks, generation = assurance_v2.load_assurance_v2_corpus(
        repository, CORPUS
    )
    registered = [(item["id"], item["expected"]) for item in attacks["attacks"]]
    preregistered = [
        (item["id"], item["expected"]) for item in preregistration["attacks"]
    ]
    if registered != preregistered:
        raise ValueError("attack corpus differs from preregistration")
    if repetitions != expected["repetitions"]:
        raise ValueError("repetition count differs from expectation")
    if (
        rust_model.get("schema") != assurance_v2.MODEL_REPORT_SCHEMA
        or python_model.get("schema") != assurance_v2.MODEL_REPORT_SCHEMA
    ):
        raise ValueError("implementation report schema differs")
    rust_attacks = {item["id"]: item for item in rust_model["attacks"]}
    python_attacks = {item["id"]: item for item in python_model["attacks"]}
    identifiers = {identifier for identifier, _ in registered}
    if set(rust_attacks) != identifiers or set(python_attacks) != identifiers:
        raise ValueError("attack inventory differs")
    exact_attacks = sum(
        rust_attacks[identifier]["actual_code"] == code
        and python_attacks[identifier]["actual_code"] == code
        and rust_attacks[identifier]["exact"]
        and python_attacks[identifier]["exact"]
        for identifier, code in registered
    )
    canonical_reports_equal = rust_bytes == python_bytes
    stable = all(
        len(candidate["repetition_report_identities"]) == repetitions
        and len(set(candidate["repetition_report_identities"])) == 1
        for candidate in (rust_model, python_model)
    )
    template_families = {
        report["decision"]["formal"] + ":" + report["decision"]["linkage"]
        for report in rust_model["templates"]
    }
    expected_facets = {
        item["formal"] + ":" + item["linkage"] for item in model["families"]
    }
    rust_lines = _source_lines(
        repository / "crates/proofbound-ir-prototype/src/assurance_v2.rs", "//"
    )
    python_lines = _source_lines(
        repository / "python/proofbound/assurance_v2_research.py", "#"
    )
    generated_corpus_bytes = _generated_corpus_bytes(
        model, templates, attacks, generation
    )
    forbidden_names = sorted(
        name
        for name in preregistration["complexity"]["forbidden_common_names"]
        if _source_contains_name(repository, name)
    )
    forbidden_dependencies = sorted(
        name
        for name in ("proofbound-cli", "proofbound-core", "proofbound-verify")
        if name
        in (repository / "crates/proofbound-ir-prototype/Cargo.toml").read_text()
    )
    limits = expected["limits"]
    q1 = (
        canonical_reports_equal
        and len(rust_model["templates"]) == expected["profile_count"]
        and rust_model["valid_programs"] == expected["valid_programs"]
        and rust_model["constructor_coverage"] == model["object_constructors"]
        and len(rust_model["constructor_coverage"])
        == expected["object_constructor_count"]
    )
    q2 = exact_attacks == expected["attack_count"]
    q3 = template_families == expected_facets and all(
        rust_attacks[identifier]["exact"] and python_attacks[identifier]["exact"]
        for identifier in FAMILY_ATTACKS
    )
    q4 = (
        canonical_reports_equal
        and stable
        and rust_model["valid_programs"] == expected["valid_programs"]
        and rust_model["adversarial_programs"] == expected["adversarial_programs"]
        and exact_attacks == expected["attack_count"]
    )
    q5 = (
        rust_lines <= limits["max_rust_kernel_lines"]
        and python_lines <= limits["max_python_kernel_lines"]
        and len(model["object_constructors"])
        <= limits["max_top_level_and_variant_constructors"]
        and len(model["validation_codes"]) <= limits["max_validation_codes"]
        and len(rust_bytes) <= limits["max_report_bytes"]
        and generated_corpus_bytes <= limits["max_corpus_bytes"]
        and not forbidden_names
        and not forbidden_dependencies
    )
    if not all((q1, q2, q3, q4, q5)):
        raise ValueError("one or more preregistered questions failed")
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0015",
        "programme_experiment": "EXP-LANG-010",
        "repetitions": repetitions,
        "implementations": {
            "canonical_reports_equal": canonical_reports_equal,
            "python": {
                "report_sha256": assurance_v2.sha256_bytes(python_bytes),
                "source_sha256": assurance_v2.sha256_bytes(
                    (
                        repository / "python/proofbound/assurance_v2_research.py"
                    ).read_bytes()
                ),
            },
            "rust": {
                "binary_sha256": assurance_v2.sha256_bytes(rust_binary.read_bytes()),
                "report_sha256": assurance_v2.sha256_bytes(rust_bytes),
            },
        },
        "metrics": {
            "adversarial_programs": rust_model["adversarial_programs"],
            "attack_count": expected["attack_count"],
            "constructor_count": len(model["object_constructors"]),
            "exact_attack_rejections": exact_attacks,
            "forbidden_common_names": forbidden_names,
            "forbidden_direct_dependencies": forbidden_dependencies,
            "generated_corpus_bytes": generated_corpus_bytes,
            "kernel_report_bytes": len(rust_bytes),
            "python_kernel_lines": python_lines,
            "rust_kernel_lines": rust_lines,
            "template_count": len(rust_model["templates"]),
            "valid_programs": rust_model["valid_programs"],
            "validation_code_count": len(model["validation_codes"]),
            "validation_codes_exercised": len(rust_model["validation_code_coverage"]),
        },
        "model": {
            "adversarial_corpus_identity": rust_model["adversarial_corpus_identity"],
            "identity": rust_model["identity"],
            "valid_corpus_identity": rust_model["valid_corpus_identity"],
        },
        "questions": {
            "Q1": {
                "passed": q1,
                "reason": "all templates and valid programmes have identical closed reports",
            },
            "Q2": {
                "passed": q2,
                "reason": "every frozen cross-component attack rejects exactly",
            },
            "Q3": {
                "passed": q3,
                "reason": "family ceilings survive and all strengthening attacks reject",
            },
            "Q4": {
                "passed": q4,
                "reason": "both kernels agree across the deterministic 500/500 corpus",
            },
            "Q5": {
                "passed": q5,
                "reason": "backend-neutral kernels and reports remain inside frozen ceilings",
            },
        },
    }


def _generated_corpus_bytes(
    model: dict[str, Any],
    templates: dict[str, Any],
    attacks: dict[str, Any],
    generation: dict[str, Any],
) -> int:
    profiles = {item["id"]: item for item in templates["profiles"]}
    total = 0
    for index in range(generation["valid_programs"]):
        profile = templates["profiles"][index % len(templates["profiles"])]
        total += len(
            assurance_v2.canonical_json(
                assurance_v2.expand_assurance_v2_profile(model, profile, index)
            )
        )
    for index in range(generation["adversarial_programs"]):
        attack = attacks["attacks"][index % len(attacks["attacks"])]
        programme = assurance_v2.expand_assurance_v2_profile(
            model, profiles[attack["template"]], 500_000 + index
        )
        assurance_v2._mutate(programme, attack["action"])
        total += len(assurance_v2.canonical_json(programme))
        if attack["action"] == "noncanonical-bytes":
            total += 1
    return total


def _source_lines(path: Path, comment_prefix: str) -> int:
    return sum(
        bool(line.strip()) and not line.lstrip().startswith(comment_prefix)
        for line in path.read_text().splitlines()
    )


def _source_contains_name(repository: Path, name: str) -> bool:
    sources = (
        repository / "crates/proofbound-ir-prototype/src/assurance_v2.rs",
        repository / "python/proofbound/assurance_v2_research.py",
    )
    return any(name.casefold() in path.read_text().casefold() for path in sources)


def _run_rust(repository: Path, binary: Path, repetitions: int) -> bytes:
    process = subprocess.run(
        [
            str(binary),
            "execute-assurance-v2",
            str(repository),
            str(CORPUS),
            str(repetitions),
        ],
        cwd=repository,
        check=False,
        capture_output=True,
    )
    if process.returncode != 0:
        raise ValueError(
            "Rust Assurance IR kernel failed: "
            + process.stderr.decode(errors="replace")
        )
    return process.stdout


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not an object")
    return value


def main() -> None:
    """Execute the experiment and write canonical JSON to stdout."""

    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: python -m proofbound.assurance_v2_experiment REPOSITORY RUST_BINARY"
        )
    report = execute_experiment(Path(sys.argv[1]), Path(sys.argv[2]))
    sys.stdout.buffer.write(assurance_v2.canonical_json(report))


if __name__ == "__main__":
    main()
