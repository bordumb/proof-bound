"""Research-only adapter-owned Hypothesis property driver."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import hypothesis
from hypothesis import Phase, given, seed, settings
from hypothesis.errors import UnsatisfiedAssumption


def canonical_json(value: object) -> bytes:
    """Return compact canonical JSON bytes for the bounded driver values."""

    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def domain_hash(domain: str, value: object) -> str:
    """Hash a canonical value behind a UTF-8 domain separator."""

    payload = domain.encode() + bytes([0]) + canonical_json(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def file_identity(root: Path, path: Path) -> dict[str, object]:
    """Return one normalized path, digest, and size identity."""

    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("closure path is not a normalized relative path")
    data = root.joinpath(path).resolve(strict=True).read_bytes()
    return {
        "logical_name": path.as_posix(),
        "sha256": f"sha256:{hashlib.sha256(data).hexdigest()}",
        "size_bytes": len(data),
    }


def load_property(path: Path) -> ModuleType:
    """Load one registered property export module from its exact path."""

    spec = importlib.util.spec_from_file_location("proofbound_property", path)
    if spec is None or spec.loader is None:
        raise ValueError("property module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parser() -> argparse.ArgumentParser:
    """Build the closed command-line interface for the research driver."""

    result = argparse.ArgumentParser()
    result.add_argument("--root", type=Path, required=True)
    result.add_argument("--module", type=Path, required=True)
    result.add_argument("--closure", type=Path, action="append", required=True)
    result.add_argument("--target", required=True)
    result.add_argument("--seed", type=int, required=True)
    result.add_argument("--cases", type=int, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> None:
    """Execute the registered property and exclusively create its report."""

    arguments = parser().parse_args()
    if arguments.seed < 0 or arguments.cases < 1:
        raise ValueError("seed and case budget are outside the registered domain")
    root = arguments.root.resolve(strict=True)
    module = load_property(root.joinpath(arguments.module).resolve(strict=True))
    if module.TARGET != arguments.target:
        raise ValueError("property target differs from registration")
    strategy = module.STRATEGY
    predicate: Callable[[Any], None] = module.predicate
    attempted_cases = 0
    completed_cases = 0
    skipped_cases = 0
    last_value: Any = None

    @seed(arguments.seed)
    @settings(
        max_examples=arguments.cases,
        database=None,
        phases=(Phase.generate,),
        derandomize=False,
    )
    @given(strategy)
    def execute(value: Any) -> None:
        nonlocal attempted_cases, completed_cases, last_value, skipped_cases
        attempted_cases += 1
        last_value = value
        try:
            predicate(value)
        except UnsatisfiedAssumption:
            skipped_cases += 1
            raise
        completed_cases += 1

    result: dict[str, object] = {"status": "passed"}
    try:
        execute()
    except Exception as error:  # noqa: BLE001 - the report binds arbitrary property failures.
        result = {
            "status": "counterexample",
            "counterexample": last_value,
            "failure_kind": type(error).__qualname__,
        }
    closure = sorted(
        (file_identity(root, path) for path in arguments.closure),
        key=lambda item: str(item["logical_name"]),
    )
    generator = {
        "entrypoint": f"{arguments.module.as_posix()}::STRATEGY+predicate",
        "closure": closure,
    }
    generator["identity_sha256"] = domain_hash(
        "proofbound-generator-closure/1", generator
    )
    contract = {
        "schema": "proofbound-sampling-contract/1",
        "framework": {
            "name": "hypothesis",
            "version": hypothesis.__version__,
        },
        "seed": {"encoding": "decimal-u64", "value": arguments.seed},
        "successful_cases": arguments.cases,
        "generator": generator,
        "targets": [arguments.target],
        "replay": "fresh-only",
        "persistence": "disabled",
        "shrinking": "disabled",
    }
    report = {
        "schema": "proofbound-sampling-observation/1",
        "contract": contract,
        "contract_identity": domain_hash("proofbound-sampling-contract/1", contract),
        "actual_seed": {"encoding": "decimal-u64", "value": arguments.seed},
        "attempted_cases": attempted_cases,
        "completed_cases": completed_cases,
        "skipped_cases": skipped_cases,
        "shrink_count": 0,
        "targets": [arguments.target],
        "result": result,
    }
    with arguments.output.open("xb") as output:
        output.write(canonical_json(report))
    if result["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
