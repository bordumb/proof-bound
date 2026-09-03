"""Execute the preregistered dual-frontend equivalence experiment."""

from __future__ import annotations

import copy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable

import proofbound.frontend_research as frontend


REPORT_SCHEMA = "proofbound-research-frontend-execution/1"
SUBJECTS = ("python-inventory", "typescript-codec", "rust-allowance")
FRONTENDS = ("toml", "proofbound-dsl", "pkl")


def execute_experiment(
    repository: Path, rust_binary: Path, pkl_binary: Path, *, repetitions: int = 10
) -> dict[str, Any]:
    """Execute both implementations, Pkl, metrics, and registered attacks.

    Args:
        repository: Proofbound repository root.
        rust_binary: Built ``proofbound-ir-prototype`` executable.
        pkl_binary: Exact preregistered Pkl 0.32.1 executable.
        repetitions: Number of deterministic runs per project/frontend pair.

    Returns:
        Canonicalizable report with observations and derived Q1--Q5 outcomes.

    Raises:
        ValueError: If an executable is missing or an unregistered failure occurs.
    """

    repository = repository.resolve()
    rust_binary = rust_binary.resolve()
    pkl_binary = pkl_binary.resolve()
    corpus = Path(
        "docs/experiments/0011-dual-frontend-equivalence/corpus/subjects.json"
    )
    experiment = repository / corpus.parent.parent
    if _sha256(pkl_binary.read_bytes()) != frontend.PKL_SHA256:
        raise ValueError("Pkl executable does not match the preregistered identity")
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")

    rendered: dict[str, bytes] = {}
    positive: list[dict[str, Any]] = []
    bases: dict[tuple[str, str], dict[str, Any]] = {}
    for subject in SUBJECTS:
        for flavor in FRONTENDS:
            rust_runs: list[bytes] = []
            python_runs: list[bytes] = []
            rendered_runs: list[bytes] = []
            for _ in range(repetitions):
                if flavor == "pkl":
                    evaluated = _evaluate_pkl(repository, pkl_binary, subject)
                    rendered_runs.append(evaluated)
                    rendered[subject] = evaluated
                else:
                    evaluated = b""
                rust = _compile_rust(
                    repository,
                    rust_binary,
                    pkl_binary,
                    corpus,
                    subject,
                    flavor,
                    evaluated,
                )
                python = _compile_python(repository, corpus, subject, flavor, evaluated)
                rust_runs.append(rust)
                python_runs.append(frontend.canonical_json(python))
            if len(set(rust_runs)) != 1 or len(set(python_runs)) != 1:
                raise ValueError(
                    f"nondeterministic compiler output: {subject}/{flavor}"
                )
            rust_record = json.loads(rust_runs[0])
            python_record = json.loads(python_runs[0])
            bases[(subject, flavor)] = python_record
            rust_effective = frontend.canonical_json(rust_record["effective_programme"])
            python_effective = frontend.canonical_json(
                python_record["effective_programme"]
            )
            positive.append(
                {
                    "project": subject,
                    "frontend": flavor,
                    "repetitions": repetitions,
                    "rust_compilation_sha256": _sha256(rust_runs[0]),
                    "python_compilation_sha256": _sha256(python_runs[0]),
                    "implementation_bytes_equal": rust_runs[0] == python_runs[0],
                    "programme_sha256": rust_record["receipt"]["programme_sha256"],
                    "effective_programme_sha256": rust_record["receipt"][
                        "effective_programme_sha256"
                    ],
                    "effective_bytes_equal": rust_effective == python_effective,
                    "receipt_bytes_equal": frontend.canonical_json(
                        rust_record["receipt"]
                    )
                    == frontend.canonical_json(python_record["receipt"]),
                    "rendered_pkl_deterministic": flavor != "pkl"
                    or len(set(rendered_runs)) == 1,
                }
            )

    controls = []
    project_equivalence = []
    for subject in SUBJECTS:
        records = [bases[(subject, flavor)] for flavor in FRONTENDS]
        programme_bytes = [
            frontend.canonical_json(record["programme"]) for record in records
        ]
        effective_bytes = [
            frontend.canonical_json(record["effective_programme"]) for record in records
        ]
        receipt_bytes = [
            frontend.canonical_json(record["receipt"]) for record in records
        ]
        control = frontend.compare_frozen_control(
            repository, corpus, subject, records[0]["programme"]
        )
        controls.append(control)
        project_equivalence.append(
            {
                "project": subject,
                "programme_bytes_equal": len(set(programme_bytes)) == 1,
                "effective_bytes_equal": len(set(effective_bytes)) == 1,
                "receipt_bytes_equal": len(set(receipt_bytes)) == 1,
            }
        )

    attacks = _execute_attacks(
        repository,
        rust_binary,
        pkl_binary,
        corpus,
        experiment / "corpus/attacks.json",
        bases,
        rendered,
    )
    metrics = _read_json(experiment / "corpus/metrics.json")
    reductions = {
        subject["id"]: {
            flavor: subject["reductions"][flavor]
            for flavor in ("proofbound-dsl", "pkl")
        }
        for subject in metrics["subjects"]
    }
    qualifying = {
        flavor: sum(
            Decimal(values[flavor]) >= Decimal(metrics["threshold"])
            for values in reductions.values()
        )
        for flavor in ("proofbound-dsl", "pkl")
    }
    all_pairs_equal = all(item["implementation_bytes_equal"] for item in positive)
    all_attack_codes = all(
        item["rust_code"] == item["expected_code"]
        and item["python_code"] == item["expected_code"]
        for item in attacks
    )
    source_attacks = [item for item in attacks if item["source_origin"]]
    map_attacks = [
        item
        for item in attacks
        if item["id"].startswith("source-map-")
        or item["id"] == "effective-programme-noncanonical"
    ]
    question_outcomes = {
        "Q1": {
            "passed": all_pairs_equal
            and all(item["programme_bytes_equal"] for item in project_equivalence)
            and all(item["effective_bytes_equal"] for item in project_equivalence)
            and all(item["receipt_bytes_equal"] for item in project_equivalence),
            "reason": "frontend-specific source maps and dependencies make cross-frontend receipts intentionally unequal",
        },
        "Q2": {
            "passed": all_attack_codes
            and all(
                item["rust_has_source_span"] and item["python_has_source_span"]
                for item in source_attacks
            ),
            "reason": "exact attack rejection and source-origin span coverage",
        },
        "Q3": {
            "passed": all(count >= 2 for count in qualifying.values()),
            "reason": "both typed frontends exceed the frozen 25% threshold in two projects",
        },
        "Q4": {
            "passed": repetitions == 10
            and all(
                item["rendered_pkl_deterministic"]
                and item["implementation_bytes_equal"]
                for item in positive
            )
            and all_attack_codes,
            "reason": "ten deterministic runs and registered authority/dependency attacks",
        },
        "Q5": {
            "passed": all_attack_codes
            and all(
                item["rust_code"] == item["expected_code"]
                and item["python_code"] == item["expected_code"]
                for item in map_attacks
            )
            and all(item["effective_bytes_equal"] for item in positive),
            "reason": "independent effective-programme and total source-map validation",
        },
    }
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0011",
        "programme_experiment": "EXP-LANG-004",
        "pkl": {
            "version": _pkl_version(pkl_binary),
            "sha256": _sha256(pkl_binary.read_bytes()),
            "policy": frontend.PKL_POLICY,
        },
        "positive_cases": positive,
        "project_equivalence": project_equivalence,
        "frozen_programme_controls": controls,
        "attacks": attacks,
        "metrics": {
            "implementation_exact_pairs": sum(
                item["implementation_bytes_equal"] for item in positive
            ),
            "implementation_pair_count": len(positive),
            "exact_attack_rejections": sum(
                item["rust_code"] == item["expected_code"]
                and item["python_code"] == item["expected_code"]
                for item in attacks
            ),
            "attack_count": len(attacks),
            "assignment_reductions": reductions,
            "projects_meeting_threshold": qualifying,
            "frozen_controls_matching": sum(item["matches"] for item in controls),
        },
        "questions": question_outcomes,
        "confirmatory_valid": all(item["matches"] for item in controls),
    }


def _execute_attacks(
    repository: Path,
    rust_binary: Path,
    pkl_binary: Path,
    corpus: Path,
    attack_path: Path,
    bases: dict[tuple[str, str], dict[str, Any]],
    rendered: dict[str, bytes],
) -> list[dict[str, Any]]:
    registrations = _read_json(attack_path)["attacks"]
    results = []
    for attack in registrations:
        attack_id = attack["id"]
        expected = attack["code"]
        if attack_id in {
            "pkl-environment-read",
            "pkl-remote-or-package-import",
            "path-escape",
            "unregistered-import",
        }:
            source = {
                "pkl-environment-read": 'amends "Schema.pkl"\nlocal x = read("env:HOME")\n',
                "pkl-remote-or-package-import": 'amends "Schema.pkl"\nimport "https://example.test/x.pkl"\n',
                "path-escape": 'amends "../Schema.pkl"\n',
                "unregistered-import": 'amends "Schema.pkl"\nimport "other.pkl"\n',
            }[attack_id]
            python_code, python_span = _python_error(
                lambda: frontend._preflight_pkl(source.encode(), "attack.pkl")
            )
            rust_code, rust_span = _rust_source_error(
                rust_binary, "preflight-frontend-pkl", source, ".pkl"
            )
            source_origin = True
        elif attack_id == "unknown-field":
            source_path = repository / (
                "docs/experiments/0011-dual-frontend-equivalence/corpus/"
                "python-inventory.pb"
            )
            source = source_path.read_text().replace(
                'source_roots = ["src/inventory_service/reservations.py"]',
                'source_roots = ["src/inventory_service/reservations.py"]\n'
                "executable_status = true",
                1,
            )
            python_code, python_span = _python_error(
                lambda: frontend._parse_dsl(source.encode(), "attack.pb")
            )
            rust_code, rust_span = _rust_source_error(
                rust_binary, "format-frontend-dsl", source, ".pb"
            )
            source_origin = True
        elif attack_id == "evaluator-substitution":
            python_code, python_span = _python_error(
                lambda: frontend.compile_pkl_frontend(
                    repository,
                    corpus,
                    "typescript-codec",
                    rendered["typescript-codec"],
                    f"sha256:{'0' * 64}",
                )
            )
            with tempfile.NamedTemporaryFile() as replacement:
                replacement.write(b"not the registered Pkl executable")
                replacement.flush()
                rust_code, rust_span = _rust_compile_error(
                    repository,
                    rust_binary,
                    Path(replacement.name),
                    corpus,
                    "typescript-codec",
                    rendered["typescript-codec"],
                )
            source_origin = False
        elif attack_id == "dependency-byte-drift":
            python_code, python_span, rust_code, rust_span = _dependency_drift_attack(
                repository,
                rust_binary,
                pkl_binary,
                corpus,
                rendered["rust-allowance"],
            )
            source_origin = True
        elif attack_id == "effective-programme-noncanonical":
            effective = bases[("rust-allowance", "proofbound-dsl")][
                "effective_programme"
            ]
            pretty = json.dumps(effective, indent=2, sort_keys=True).encode()
            python_code, python_span = _python_error(
                lambda: frontend.validate_effective_bytes(pretty)
            )
            rust_code, rust_span = _rust_bytes_error(
                rust_binary, "validate-effective-frontend", pretty, ".json"
            )
            source_origin = False
        else:
            base_flavor = (
                "toml"
                if attack_id == "source-map-file-substitution"
                else _base_flavor(attack["frontend"])
            )
            base = copy.deepcopy(bases[(attack["base"], base_flavor)])
            _mutate_compilation(attack_id, base, repository)
            python_code, python_span = _python_error(
                lambda: frontend.validate_compilation(repository, base)
            )
            rust_code, rust_span = _rust_compilation_error(
                repository, rust_binary, base
            )
            source_origin = attack["frontend"] in {"toml", "proofbound-dsl", "pkl"}
        results.append(
            {
                "id": attack_id,
                "expected_code": expected,
                "rust_code": rust_code,
                "python_code": python_code,
                "source_origin": source_origin,
                "rust_has_source_span": rust_span,
                "python_has_source_span": python_span,
            }
        )
    return results


def _mutate_compilation(
    attack_id: str, compilation: dict[str, Any], repository: Path
) -> None:
    programme = compilation["programme"]
    if attack_id == "sampled-as-theorem":
        unit = next(
            item for item in programme["evidence"] if item["kind"] == "property-test"
        )
        unit.update(
            {
                "adapter": "lean",
                "kind": "theorem",
                "operation": {
                    "type": "lean-audit",
                    "targets": unit["expected_inventory"],
                    "paths": ["Proofbound.lean"],
                },
                "evaluation_mode": "kernel",
                "theorem": unit["expected_inventory"][0],
            }
        )
    elif attack_id == "unbound-theorem":
        programme["claims"][0].pop("formal_declaration")
    elif attack_id == "duplicate-inventory":
        values = programme["evidence"][0]["expected_inventory"]
        values.append(values[0])
    elif attack_id == "partial-inventory":
        unit = next(
            item for item in programme["evidence"] if item["kind"] == "property-test"
        )
        unit["operation"]["targets"] = ["substituted_test"]
    elif attack_id == "unowned-assumption":
        programme["evidence"][0]["assumptions"].append("UNOWNED-001")
    elif attack_id == "conflicting-policy-ceiling":
        programme["evidence"][0]["tier"] = programme["claims"][0]["tier"] + 1
    elif attack_id == "undeclared-tool-authority":
        programme["evidence"][0]["environment_allowlist"].append("NETWORK")
    elif attack_id == "stable-id-alias":
        programme["evidence"][0]["claims"][0] = programme["evidence"][0]["claims"][
            0
        ].lower()
    elif attack_id == "noncanonical-order":
        programme["evidence"].reverse()
    elif attack_id == "source-map-deletion":
        compilation["source_map"]["entries"].pop()
    elif attack_id == "source-map-overlap":
        entries = compilation["source_map"]["entries"]
        entries.append(copy.deepcopy(entries[0]))
        entries.sort(
            key=lambda item: (item["leaf"], *frontend._span_key(item["source"]))
        )
    elif attack_id == "source-map-file-substitution":
        replacement = next(
            item
            for item in compilation["dependencies"]
            if item["kind"] == "artifact"
            and item["logical_name"].endswith("reject-padding.toml")
        )
        entry = next(
            item
            for item in compilation["source_map"]["entries"]
            if item["leaf"].startswith("/claims/")
        )
        entry["source"] = {
            "path": replacement["logical_name"],
            "sha256": replacement["identity"],
            "start": 0,
            "end": (repository / replacement["logical_name"]).stat().st_size,
        }
        _reseal(compilation)
    elif attack_id == "source-map-span-substitution":
        compilation["source_map"]["entries"][0]["source"]["end"] = 2**64 - 1
        _reseal(compilation)
    elif attack_id == "source-map-leaf-substitution":
        entries = compilation["source_map"]["entries"]
        entries[0]["leaf"] = "/unknown"
        entries.sort(
            key=lambda item: (item["leaf"], *frontend._span_key(item["source"]))
        )
        _reseal(compilation)
    else:
        raise ValueError(f"no attack mutation for {attack_id}")


def _reseal(compilation: dict[str, Any]) -> None:
    source_map = compilation["source_map"]
    source_map["identity"] = frontend.domain_hash(
        frontend.SOURCE_MAP_SCHEMA, frontend.canonical_json(source_map["entries"])
    )
    compilation["receipt"] = frontend._make_receipt(
        compilation["frontend"],
        compilation["programme"],
        compilation["effective_programme"],
        source_map,
        compilation["dependencies"],
    )


def _compile_python(
    repository: Path,
    corpus: Path,
    subject: str,
    flavor: str,
    rendered: bytes,
) -> dict[str, Any]:
    if flavor == "toml":
        return frontend.compile_toml_frontend(repository, corpus, subject)
    if flavor == "proofbound-dsl":
        return frontend.compile_dsl_frontend(repository, corpus, subject)
    return frontend.compile_pkl_frontend(
        repository, corpus, subject, rendered, frontend.PKL_SHA256
    )


def _compile_rust(
    repository: Path,
    rust_binary: Path,
    pkl_binary: Path,
    corpus: Path,
    subject: str,
    flavor: str,
    rendered: bytes,
) -> bytes:
    command = [
        str(rust_binary),
        "compile-frontend",
        flavor,
        str(repository),
        str(corpus),
        subject,
    ]
    with tempfile.NamedTemporaryFile(suffix=".json") as rendered_file:
        if flavor == "pkl":
            rendered_file.write(rendered)
            rendered_file.flush()
            command.extend([rendered_file.name, str(pkl_binary)])
        result = subprocess.run(
            command,
            cwd=repository,
            env={"PATH": "/usr/bin:/bin"},
            check=False,
            capture_output=True,
        )
    if result.returncode != 0 or result.stderr:
        raise ValueError(
            f"Rust frontend failed: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def _evaluate_pkl(repository: Path, pkl_binary: Path, subject: str) -> bytes:
    corpus_root = Path("docs/experiments/0011-dual-frontend-equivalence/corpus")
    result = subprocess.run(
        [
            str(pkl_binary),
            "eval",
            "--allowed-modules",
            "pkl:,file:",
            "--allowed-resources",
            "^$",
            "--root-dir",
            str(corpus_root),
            "--no-cache",
            "--color",
            "never",
            "--timeout",
            "10",
            str(corpus_root / f"{subject}.pkl"),
        ],
        cwd=repository,
        env={"PATH": "/usr/bin:/bin"},
        check=False,
        capture_output=True,
        timeout=11,
    )
    if result.returncode != 0 or result.stderr:
        raise ValueError(
            f"Pkl evaluation failed: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def _rust_compilation_error(
    repository: Path, rust_binary: Path, compilation: dict[str, Any]
) -> tuple[str, bool]:
    return _rust_bytes_error(
        rust_binary,
        "validate-frontend",
        frontend.canonical_json(compilation),
        ".json",
        extra=(str(repository),),
    )


def _rust_source_error(
    rust_binary: Path, command: str, source: str, suffix: str
) -> tuple[str, bool]:
    return _rust_bytes_error(rust_binary, command, source.encode(), suffix)


def _rust_bytes_error(
    rust_binary: Path,
    command: str,
    data: bytes,
    suffix: str,
    *,
    extra: tuple[str, ...] = (),
) -> tuple[str, bool]:
    with tempfile.NamedTemporaryFile(suffix=suffix) as source:
        source.write(data)
        source.flush()
        arguments = [str(rust_binary), command, *extra, source.name]
        result = subprocess.run(arguments, check=False, capture_output=True)
    if result.returncode == 0:
        raise ValueError(f"Rust accepted attack for {command}")
    stderr = result.stderr.decode(errors="replace").strip()
    return stderr.split(":", 1)[0], " [" in stderr and ".." in stderr


def _rust_compile_error(
    repository: Path,
    rust_binary: Path,
    pkl_binary: Path,
    corpus: Path,
    subject: str,
    rendered: bytes,
) -> tuple[str, bool]:
    with tempfile.NamedTemporaryFile(suffix=".json") as rendered_file:
        rendered_file.write(rendered)
        rendered_file.flush()
        result = subprocess.run(
            [
                str(rust_binary),
                "compile-frontend",
                "pkl",
                str(repository),
                str(corpus),
                subject,
                rendered_file.name,
                str(pkl_binary),
            ],
            cwd=repository,
            check=False,
            capture_output=True,
        )
    if result.returncode == 0:
        raise ValueError("Rust accepted Pkl attack")
    stderr = result.stderr.decode(errors="replace").strip()
    return stderr.split(":", 1)[0], " [" in stderr and ".." in stderr


def _dependency_drift_attack(
    repository: Path,
    rust_binary: Path,
    pkl_binary: Path,
    corpus: Path,
    rendered: bytes,
) -> tuple[str, bool, str, bool]:
    with tempfile.TemporaryDirectory(prefix="proofbound-frontend-drift-") as raw:
        root = Path(raw)
        experiment_relative = corpus.parent.parent
        shutil.copytree(repository / experiment_relative, root / experiment_relative)
        schema = root / corpus.parent / "Schema.pkl"
        schema.write_bytes(schema.read_bytes() + b"\n")
        python_code, python_span = _python_error(
            lambda: frontend.compile_pkl_frontend(
                root, corpus, "rust-allowance", rendered, frontend.PKL_SHA256
            )
        )
        rust_code, rust_span = _rust_compile_error(
            root,
            rust_binary,
            pkl_binary,
            corpus,
            "rust-allowance",
            rendered,
        )
    return python_code, python_span, rust_code, rust_span


def _python_error(call: Callable[[], object]) -> tuple[str, bool]:
    try:
        call()
    except frontend.FrontendResearchError as error:
        return error.code, (
            error.path is not None
            and error.start is not None
            and error.end is not None
            and error.end > error.start
        )
    raise ValueError("Python accepted registered attack")


def _base_flavor(flavor: str) -> str:
    if flavor in FRONTENDS:
        return flavor
    return "proofbound-dsl" if flavor in {"source-map", "effective"} else "toml"


def _pkl_version(pkl_binary: Path) -> str:
    result = subprocess.run(
        [str(pkl_binary), "--version"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_bytes())


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
