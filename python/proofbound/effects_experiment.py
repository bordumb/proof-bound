"""Execute the preregistered effect-checked replay experiment."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import proofbound.effects_research as effects

REPORT_SCHEMA = "proofbound-research-effect-execution/1"
CORPUS = Path("docs/experiments/0012-effect-checked-replay/corpus")
PREFLIGHT_ATTACKS = {
    "undeclared-file-read",
    "undeclared-environment",
    "network-attempt",
    "clock-attempt",
    "random-attempt",
    "reviewed-root-write",
    "ephemeral-write-escape",
    "symlink-substitution",
    "lifecycle-script",
    "executable-substitution",
    "argv-substitution",
    "missing-enforcement",
    "forged-enforcement",
    "weakened-enforcement",
    "effect-id-alias",
    "duplicate-effect",
}
ENFORCEMENT_ATTACKS = {
    "missing-enforcement",
    "forged-enforcement",
    "weakened-enforcement",
}


def execute_experiment(
    repository: Path, rust_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Run both implementations and independently derive the registered metrics.

    Args:
        repository: Proofbound repository root.
        rust_binary: Built ``proofbound-ir-prototype`` executable.
        repetitions: Frozen deterministic repetition count.

    Returns:
        Canonicalizable execution report with Q1--Q5 outcomes.

    Raises:
        ValueError: If either implementation or a frozen invariant fails.
    """

    repository = repository.resolve()
    rust_binary = rust_binary.resolve()
    if repetitions != 10:
        raise ValueError("Experiment 0012 requires exactly ten repetitions")
    before = _fixture_projection(repository)
    rust_bytes = _run_rust(repository, rust_binary, repetitions)
    python_model = effects.execute_effect_corpus(repository, CORPUS, repetitions)
    python_bytes = effects.canonical_json(python_model)
    after = _fixture_projection(repository)
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
        before,
        after,
        repetitions,
    )


def _summarize(
    repository: Path,
    rust_binary: Path,
    rust_model: dict[str, Any],
    python_model: dict[str, Any],
    rust_bytes: bytes,
    python_bytes: bytes,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    repetitions: int,
) -> dict[str, Any]:
    preregistration = _read_json(
        repository / "docs/experiments/0012-effect-checked-replay/preregistration.json"
    )
    attacks = _read_json(repository / CORPUS / "attacks.json")["attacks"]
    expected = _read_json(repository / CORPUS / "expected.json")
    registered_attacks = [(item["id"], item["code"]) for item in attacks]
    if registered_attacks != [
        (item["id"], item["code"]) for item in preregistration["attacks"]
    ]:
        raise ValueError("attack corpus differs from preregistration")
    if (
        rust_model["schema"] != effects.REPORT_SCHEMA
        or python_model["schema"] != effects.REPORT_SCHEMA
    ):
        raise ValueError("implementation report schema differs")
    rust_attacks = {item["id"]: item for item in rust_model["attacks"]}
    python_attacks = {item["id"]: item for item in python_model["attacks"]}
    if set(rust_attacks) != {item[0] for item in registered_attacks} or set(
        python_attacks
    ) != set(rust_attacks):
        raise ValueError("implementation attack inventory differs")
    exact_attacks = sum(
        rust_attacks[attack_id]["actual_code"] == code
        and python_attacks[attack_id]["actual_code"] == code
        and rust_attacks[attack_id]["exact"]
        and python_attacks[attack_id]["exact"]
        for attack_id, code in registered_attacks
    )
    preflight_exact = sum(
        rust_attacks[attack_id]["exact"]
        and python_attacks[attack_id]["exact"]
        and not rust_attacks[attack_id]["workload_body_entered"]
        and not python_attacks[attack_id]["workload_body_entered"]
        for attack_id in PREFLIGHT_ATTACKS
    )
    observations = 0
    authorized = 0
    declarations = 0
    dispositions = 0
    for plan in rust_model["plans"]:
        trace = plan["trace"]
        observations += len(trace["observations"])
        declarations += plan["declaration_count"]
        authorized += len({item["effect_id"] for item in trace["observations"]})
        dispositions += len(trace["dispositions"])
        if (
            len(plan["repetition_trace_identities"]) != repetitions
            or len(set(plan["repetition_trace_identities"])) != 1
        ):
            raise ValueError(f"nondeterministic Rust trace for {plan['id']}")
    for plan in python_model["plans"]:
        if (
            len(plan["repetition_trace_identities"]) != repetitions
            or len(set(plan["repetition_trace_identities"])) != 1
        ):
            raise ValueError(f"nondeterministic Python trace for {plan['id']}")
    invalidation = {
        item["id"]: item["decisions"] for item in rust_model["invalidation"]
    }
    stale_acceptance = sum(
        not decision["invalidated"] for decision in invalidation["policy-change"]
    )
    unrelated_invalidation = sum(
        decision["invalidated"] for decision in invalidation["unrelated-change"]
    )
    plans = {item["id"]: item for item in rust_model["plans"]}
    opaque_incorrect = int(plans["opaque-process"]["trace"]["cache_eligible"])
    external_eligible = plans["externally-enforced-process"]["trace"]["cache_eligible"]
    expected_outputs = sorted(
        [expected["distribution_output"], expected["mutation_output"]],
        key=lambda item: (item["path"], item["sha256"], item["size_bytes"]),
    )
    exact_outputs = sum(
        actual == wanted
        for actual, wanted in zip(
            rust_model["route_outputs"], expected_outputs, strict=True
        )
    )
    route_plans = [plans["distribution-build"], plans["mutation-replay"]]
    no_ambient_route_authority = all(
        observation["kind"] in {"read-file", "require-absent", "write-ephemeral"}
        for plan in route_plans
        for observation in plan["trace"]["observations"]
    )
    implementation_equal = rust_bytes == python_bytes
    reviewed_unchanged = before == after
    q1 = preflight_exact == len(PREFLIGHT_ATTACKS)
    q2 = (
        implementation_equal
        and authorized == observations
        and dispositions == declarations
    )
    q3 = (
        stale_acceptance == 0
        and unrelated_invalidation == 0
        and len(invalidation["policy-change"]) == repetitions
        and len(invalidation["unrelated-change"]) == repetitions
    )
    q4 = (
        opaque_incorrect == 0
        and external_eligible
        and all(
            rust_attacks[attack_id]["exact"] and python_attacks[attack_id]["exact"]
            for attack_id in ENFORCEMENT_ATTACKS
        )
    )
    q5 = (
        exact_outputs == 2
        and reviewed_unchanged
        and no_ambient_route_authority
        and rust_attacks["mutation-postimage-drift"]["exact"]
        and rust_attacks["package-extra-path"]["exact"]
        and python_attacks["mutation-postimage-drift"]["exact"]
        and python_attacks["package-extra-path"]["exact"]
    )
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0012",
        "programme_experiment": "EXP-LANG-005",
        "repetitions": repetitions,
        "implementations": {
            "rust": {
                "binary_sha256": effects.sha256_bytes(rust_binary.read_bytes()),
                "report_sha256": effects.sha256_bytes(rust_bytes),
            },
            "python": {
                "source_sha256": effects.sha256_bytes(
                    (repository / "python/proofbound/effects_research.py").read_bytes()
                ),
                "report_sha256": effects.sha256_bytes(python_bytes),
            },
            "canonical_reports_equal": implementation_equal,
        },
        "metrics": {
            "forbidden_preflight_rejections": preflight_exact,
            "forbidden_preflight_count": len(PREFLIGHT_ATTACKS),
            "exact_attack_rejections": exact_attacks,
            "attack_count": len(registered_attacks),
            "authorized_observations": authorized,
            "observation_count": observations,
            "declaration_dispositions": dispositions,
            "declaration_count": declarations,
            "stale_cache_acceptance": stale_acceptance,
            "unrelated_invalidation": unrelated_invalidation,
            "opaque_cache_eligible": opaque_incorrect,
            "exact_route_outputs": exact_outputs,
            "route_output_count": 2,
            "reviewed_root_unchanged": reviewed_unchanged,
            "plan_bytes": {
                plan["id"]: plan["plan_bytes"] for plan in rust_model["plans"]
            },
            "trace_bytes": {
                plan["id"]: plan["trace_bytes"] for plan in rust_model["plans"]
            },
        },
        "questions": {
            "Q1": {
                "passed": q1,
                "reason": "all registered authority violations reject before workload entry",
            },
            "Q2": {
                "passed": q2,
                "reason": "independent canonical traces match with complete authorization and dispositions",
            },
            "Q3": {
                "passed": q3,
                "reason": "the consumed hidden input invalidates while the unrelated control does not",
            },
            "Q4": {
                "passed": q4,
                "reason": "opaque execution is non-reusable and exact external enforcement is required",
            },
            "Q5": {
                "passed": q5,
                "reason": "mutation and distribution outputs are exact without ambient authority or reviewed writes",
            },
        },
    }


def _run_rust(repository: Path, rust_binary: Path, repetitions: int) -> bytes:
    result = subprocess.run(
        [
            str(rust_binary),
            "execute-effects",
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
            "Rust effect model failed: " + result.stderr.decode(errors="replace")
        )
    return result.stdout


def _fixture_projection(repository: Path) -> list[dict[str, Any]]:
    expected = _read_json(repository / CORPUS / "expected.json")
    return [
        {
            "path": fixture["path"],
            "sha256": effects.sha256_bytes((repository / fixture["path"]).read_bytes()),
            "mode": (repository / fixture["path"]).stat().st_mode & 0o7777,
        }
        for fixture in expected["fixtures"]
    ]


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    """Run Experiment 0012 and emit its canonical execution report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print(
            "usage: python -m proofbound.effects_experiment <repository> <rust-binary>",
            file=sys.stderr,
        )
        return 2
    try:
        report = execute_experiment(Path(arguments[0]), Path(arguments[1]))
    except (OSError, ValueError, effects.EffectFailure) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(effects.canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
