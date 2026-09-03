#!/usr/bin/env python3
"""Execute the frozen packet ABI through Python legacy or native paths."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

CALL_SCHEMA = "proofbound-research-foreign-call/1"
OBSERVATIONS_SCHEMA = "proofbound-research-foreign-observations/1"
CONTRACT_SCHEMA = "proofbound-research-foreign-contract/1"


def canonical_json(value: object) -> bytes:
    """Encode recursively sorted compact JSON."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def domain_hash(domain: str, value: object) -> str:
    """Hash canonical data under an explicit domain."""

    return (
        "sha256:"
        + hashlib.sha256(domain.encode() + b"\0" + canonical_json(value)).hexdigest()
    )


def sha256_bytes(value: bytes) -> str:
    """Hash exact bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def main(arguments: list[str]) -> int:
    """Load controls, execute every case, and emit one observation set."""

    if len(arguments) != 3 or arguments[2] not in {"baseline", "migrated"}:
        raise SystemExit("usage: python_caller.py CONTRACT CASES baseline|migrated")
    contract = json.loads(Path(arguments[0]).read_bytes())
    cases = json.loads(Path(arguments[1]).read_bytes())
    phase = arguments[2]
    validate_contract(contract)
    runtime = next(
        item for item in contract["runtimes"] if item["language"] == "python"
    )
    actual_runtime = {
        "language": "python",
        "program": "python3",
        "version": "Python " + platform.python_version(),
        "executable_sha256": sha256_bytes(Path(sys.executable).resolve().read_bytes()),
    }
    if actual_runtime != runtime:
        raise ValueError("registered Python runtime differs")
    artifact = bytes.fromhex(contract["artifact"]["hex"])
    calls = [execute_case(contract, case, phase, artifact) for case in cases["cases"]]
    observation = {
        "schema": OBSERVATIONS_SCHEMA,
        "language": "python",
        "phase": phase,
        "contract_identity": contract["identity"],
        "runtime": runtime,
        "calls": calls,
        "identity": "",
    }
    observation["identity"] = domain_hash(OBSERVATIONS_SCHEMA, observation)
    sys.stdout.buffer.write(canonical_json(observation))
    return 0


def validate_contract(contract: dict[str, Any]) -> None:
    """Reject a substituted or unsupported foreign contract."""

    expected = dict(contract)
    identity = expected["identity"]
    expected["identity"] = ""
    if identity != domain_hash(CONTRACT_SCHEMA, expected):
        raise ValueError("contract identity differs")
    if (
        contract["schema"] != CONTRACT_SCHEMA
        or contract["abi_version"] != 1
        or contract["operations"] != ["decode", "encode"]
        or contract["request_encoding"] != "canonical-lowercase-hex-or-u2"
        or contract["response_encoding"] != "canonical-json-tagged-result"
        or contract["error_policy"] != "error-as-data-no-host-exception"
        or contract["callback_policy"] != "forbidden"
    ):
        raise ValueError("unsupported foreign contract")


def execute_case(
    contract: dict[str, Any],
    case: dict[str, Any],
    phase: str,
    artifact: bytes,
) -> dict[str, Any]:
    """Execute one exact case and bind its semantic result."""

    if phase == "migrated":
        validate_artifact(contract, artifact)
        result = execute_artifact(artifact, case)
        artifact_identity: str | None = contract["artifact"]["identity"]
    else:
        result = execute_legacy(case)
        artifact_identity = None
    if result != case["expected"]:
        raise ValueError(f"case result differs: {case['id']}")
    call = {
        "schema": CALL_SCHEMA,
        "case_id": case["id"],
        "phase": phase,
        "language": "python",
        "contract_identity": contract["identity"],
        "artifact_identity": artifact_identity,
        "operation": case["operation"],
        "input_hex": case["input_hex"],
        "input_value": case["input_value"],
        **result,
        "identity": "",
    }
    call["identity"] = domain_hash(CALL_SCHEMA, call)
    return call


def execute_legacy(case: dict[str, Any]) -> dict[str, Any]:
    """Execute the frozen direct implementation used before migration."""

    if case["operation"] == "encode":
        value = case["input_value"]
        return result(True, value, bytes([1, value]).hex(), None, 0)
    return decode(bytes.fromhex(case["input_hex"]), 1, 2, 3)


def execute_artifact(artifact: bytes, case: dict[str, Any]) -> dict[str, Any]:
    """Execute one request through the registered bytecode artifact."""

    if case["operation"] == "encode":
        value = case["input_value"]
        return result(True, value, bytes([artifact[8], value]).hex(), None, 0)
    return decode(
        bytes.fromhex(case["input_hex"]), artifact[15], artifact[12], artifact[18]
    )


def decode(value: bytes, prefix: int, length: int, maximum: int) -> dict[str, Any]:
    """Return tagged data rather than throwing a host exception."""

    if len(value) != length:
        return result(False, None, None, "invalid-length", len(value))
    if value[0] != prefix:
        return result(False, None, None, "invalid-prefix", len(value))
    if value[1] > maximum:
        return result(False, None, None, "invalid-payload", len(value))
    return result(True, value[1], value.hex(), None, len(value))


def result(
    accepted: bool,
    value: int | None,
    output_hex: str | None,
    error: str | None,
    consumed: int,
) -> dict[str, Any]:
    """Build the exact ABI result projection."""

    return {
        "accepted": accepted,
        "value": value,
        "output_hex": output_hex,
        "error": error,
        "consumed": consumed,
    }


def validate_artifact(contract: dict[str, Any], artifact: bytes) -> None:
    """Validate all bytes consumed by the migrated bridge."""

    registered = contract["artifact"]
    if (
        artifact.hex() != registered["hex"]
        or len(artifact) != registered["size_bytes"]
        or sha256_bytes(artifact) != registered["sha256"]
        or artifact[:7] != b"PBVM\x01\x04\x0b"
        or [artifact[index] for index in [7, 9, 10, 11, 13, 16, 19, 21]]
        != [0x10, 0x11, 0xFF, 0x20, 0x21, 0x22, 0x23, 0xFE]
    ):
        raise ValueError("native artifact differs")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
