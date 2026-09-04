"""Generate and validate the registered EXP-0026 capture attacks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any, Callable

from proofbound.windows_enforcement_execute import (
    canonical_json,
    domain_hash,
    sha256_bytes,
)
from proofbound import windows_initialization_attacks as initialization_attacks
from proofbound.windows_initialization_research import CLOSURE_SCHEMA, SLOT_SCHEMA
from proofbound.windows_output_network_execute import CAPTURE_SCHEMA, ORACLE_SCHEMA
from proofbound.windows_output_network_research import (
    ATTACKS,
    WindowsOutputNetworkError,
    validate_capture,
)


INDEX_SCHEMA = "proofbound-research-windows-output-network-attack-index/1"
REPORT_SCHEMA = "proofbound-research-windows-output-network-attack-report/1"
Mutation = Callable[[dict[str, Any]], None]


def _rehash_slot(slot: dict[str, Any]) -> None:
    body = copy.deepcopy(slot)
    body.pop("identity", None)
    slot["identity"] = domain_hash(SLOT_SCHEMA, body)


def _rehash_oracle(oracle: dict[str, Any]) -> None:
    body = copy.deepcopy(oracle)
    body.pop("identity", None)
    oracle["identity"] = domain_hash(ORACLE_SCHEMA, body)


def _rehash_capture(value: dict[str, Any]) -> None:
    body = copy.deepcopy(value)
    body.pop("identity", None)
    value["identity"] = domain_hash(CAPTURE_SCHEMA, body)


def _rehash_closure(value: dict[str, Any]) -> None:
    closure = value["closure"]
    body = copy.deepcopy(closure)
    body.pop("identity", None)
    closure["identity"] = domain_hash(CLOSURE_SCHEMA, body)
    for slot in value["slots"]:
        slot["closure_identity"] = closure["identity"]
        _rehash_slot(slot)
    _rehash_capture(value)


def _successor_inherited(mutate: Mutation) -> Mutation:
    def wrapped(value: dict[str, Any]) -> None:
        mutate(value)
        _rehash_capture(value)

    return wrapped


def _network_pair(value: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    oracle = value["network_oracles"][0]
    slot = next(item for item in value["slots"] if item["slot_id"] == oracle["slot_id"])
    return oracle, slot


def _change_corpus_revision(value: dict[str, Any]) -> None:
    value["corpus_revision_sha256"] = "sha256:" + "0" * 64
    _rehash_capture(value)


def _restore_text_python(value: dict[str, Any]) -> None:
    python_row = next(
        row
        for row in value["closure"]["corpus"]
        if row["path"] == "workspace/subjects/python_subject.py"
    )
    python_row["sha256"] = "sha256:" + "0" * 64
    python_row["size_bytes"] = 0
    _rehash_closure(value)


def _fail_control(value: dict[str, Any]) -> None:
    oracle, _ = _network_pair(value)
    oracle["control"]["completed"] = False
    _rehash_oracle(oracle)
    _rehash_capture(value)


def _change_sandbox_endpoint(value: dict[str, Any]) -> None:
    oracle, slot = _network_pair(value)
    port = oracle["endpoint"]["port"]
    slot["logical_command"][-1] = str(1 if port != 1 else 2)
    _rehash_slot(slot)
    _rehash_capture(value)


def _accept_connection_refused(value: dict[str, Any]) -> None:
    oracle, slot = _network_pair(value)
    ambiguous = "connect failed: WSAECONNREFUSED 10061"
    oracle["sandbox"]["stderr"] = ambiguous
    slot["boundary"]["stderr"] = ambiguous
    slot["outcome"] = "denied"
    slot["reusable"] = False
    _rehash_oracle(oracle)
    _rehash_slot(slot)
    _rehash_capture(value)


def _accept_listener_connection(value: dict[str, Any]) -> None:
    oracle, _ = _network_pair(value)
    oracle["sandbox"]["listener_accepted"] = True
    _rehash_oracle(oracle)
    _rehash_capture(value)


def _add_loopback_exemption(value: dict[str, Any]) -> None:
    oracle, _ = _network_pair(value)
    sid = oracle["appcontainer_sid"]
    for name in ("loopback_exemptions_before", "loopback_exemptions_after"):
        oracle[name] = sorted([*oracle[name], sid])
    oracle["appcontainer_sid_exempt_before"] = True
    oracle["appcontainer_sid_exempt_after"] = True
    _rehash_oracle(oracle)
    _rehash_capture(value)


def _reuse_oracle(value: dict[str, Any]) -> None:
    oracle, _ = _network_pair(value)
    oracle["reusable"] = True
    _rehash_oracle(oracle)
    _rehash_capture(value)


def _forge_elapsed_classification(value: dict[str, Any]) -> None:
    value["elapsed_ms"] = 60_001
    value["within_elapsed_ceiling"] = True
    _rehash_capture(value)


MUTATIONS: tuple[Mutation, ...] = (
    *tuple(
        _successor_inherited(item) for item in initialization_attacks.MUTATIONS[:28]
    ),
    _forge_elapsed_classification,
    _successor_inherited(initialization_attacks.MUTATIONS[29]),
    _change_corpus_revision,
    _restore_text_python,
    _fail_control,
    _change_sandbox_endpoint,
    _accept_connection_refused,
    _accept_listener_connection,
    _add_loopback_exemption,
    _reuse_oracle,
)


def generate_attacks(
    repository: Path, capture: dict[str, Any], output_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write every frozen attack and prove that Python rejects it exactly."""

    if len(MUTATIONS) != len(ATTACKS):
        raise AssertionError("attack registration and mutation count differ")
    output_root.mkdir(parents=True, exist_ok=False)
    rows = []
    report_rows = []
    for (attack_id, expected_code), mutate in zip(ATTACKS, MUTATIONS, strict=True):
        value = copy.deepcopy(capture)
        mutate(value)
        payload = canonical_json(value)
        path = output_root / f"{attack_id.lower()}.json"
        path.write_bytes(payload)
        try:
            validate_capture(value, repository)
        except WindowsOutputNetworkError as issue:
            actual_code = issue.code
        else:
            actual_code = "accepted"
        exact = actual_code == expected_code
        rows.append(
            {
                "id": attack_id,
                "expected_code": expected_code,
                "path": path.name,
                "sha256": sha256_bytes(payload),
                "size_bytes": len(payload),
            }
        )
        report_rows.append(
            {
                "id": attack_id,
                "expected_code": expected_code,
                "actual_code": actual_code,
                "exact": exact,
            }
        )
    index = {"schema": INDEX_SCHEMA, "attacks": rows}
    index["identity"] = domain_hash(INDEX_SCHEMA, index)
    report = {
        "schema": REPORT_SCHEMA,
        "attacks": report_rows,
        "all_exact": all(row["exact"] for row in report_rows),
    }
    report["identity"] = domain_hash(REPORT_SCHEMA, report)
    return index, report


def main(argv: list[str] | None = None) -> int:
    """Materialize and validate the frozen EXP-0026 attack corpus."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 5:
        print(
            "usage: windows_output_network_attacks REPOSITORY CAPTURE "
            "ATTACK_ROOT INDEX REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        repository = Path(arguments[0])
        capture = json.loads(Path(arguments[1]).read_bytes())
        index, report = generate_attacks(repository, capture, Path(arguments[2]))
        Path(arguments[3]).write_bytes(canonical_json(index))
        Path(arguments[4]).write_bytes(canonical_json(report))
    except (OSError, ValueError, json.JSONDecodeError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0 if report["all_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
