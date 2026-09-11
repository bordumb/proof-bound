"""Generate and validate the registered EXP-0025 capture attacks."""

from __future__ import annotations

import base64
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
from proofbound.windows_initialization_research import (
    ATTACKS,
    CAPTURE_SCHEMA,
    CLOSURE_SCHEMA,
    POLICY_SCHEMA,
    SLOT_SCHEMA,
    WindowsInitializationError,
    validate_capture,
)


INDEX_SCHEMA = "proofbound-research-windows-initialization-attack-index/1"
REPORT_SCHEMA = "proofbound-research-windows-initialization-attack-report/1"
Mutation = Callable[[dict[str, Any]], None]


def _rehash_slot(slot: dict[str, Any]) -> None:
    body = copy.deepcopy(slot)
    body.pop("identity", None)
    slot["identity"] = domain_hash(SLOT_SCHEMA, body)


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


def _closure_field(path: tuple[str, ...], replacement: object) -> Mutation:
    def mutate(value: dict[str, Any]) -> None:
        target = value["closure"]
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = replacement
        _rehash_closure(value)

    return mutate


def _capture_field(path: tuple[str, ...], replacement: object) -> Mutation:
    def mutate(value: dict[str, Any]) -> None:
        target = value
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = replacement
        _rehash_capture(value)

    return mutate


def _remove_corpus(value: dict[str, Any]) -> None:
    value["closure"]["corpus"].pop()
    _rehash_closure(value)


def _bad_closure_identity(value: dict[str, Any]) -> None:
    value["closure"]["identity"] = "sha256:" + "0" * 64
    _rehash_capture(value)


def _remove_slot(value: dict[str, Any]) -> None:
    value["slots"].pop()
    _rehash_capture(value)


def _swap_slots(value: dict[str, Any]) -> None:
    value["slots"][0], value["slots"][1] = value["slots"][1], value["slots"][0]
    _rehash_capture(value)


def _bad_slot_identity(value: dict[str, Any]) -> None:
    value["slots"][0]["identity"] = "sha256:" + "0" * 64
    _rehash_capture(value)


def _widen_policy(value: dict[str, Any]) -> None:
    slot = value["slots"][0]
    slot["policy"]["appcontainer"]["capabilities"] = ["internet-client"]
    body = copy.deepcopy(slot["policy"])
    body.pop("identity", None)
    slot["policy"]["identity"] = domain_hash(POLICY_SCHEMA, body)
    _rehash_slot(slot)
    _rehash_capture(value)


def _substitute_positive_output(value: dict[str, Any]) -> None:
    slot = value["slots"][0]
    output = slot["boundary"]["captured_files"][0]
    payload = b"substituted-output\n"
    output["content_base64"] = base64.b64encode(payload).decode("ascii")
    output["sha256"] = sha256_bytes(payload)
    output["size_bytes"] = len(payload)
    _rehash_slot(slot)
    _rehash_capture(value)


def _reuse_denial(value: dict[str, Any]) -> None:
    slot = value["slots"][30]
    slot["reusable"] = True
    _rehash_slot(slot)
    _rehash_capture(value)


def _replace_denial_with_initialization_failure(value: dict[str, Any]) -> None:
    slot = value["slots"][30]
    slot["boundary"]["exit_code"] = 0xC0000142
    _rehash_slot(slot)
    _rehash_capture(value)


def _duplicate_profile(value: dict[str, Any]) -> None:
    value["slots"][1]["boundary"]["profile"] = value["slots"][0]["boundary"]["profile"]
    _rehash_slot(value["slots"][1])
    _rehash_capture(value)


MUTATIONS: tuple[Mutation, ...] = (
    _capture_field(("schema",), "proofbound-research-windows-initialization-capture/0"),
    _capture_field(("experiment",), "EXP-0000"),
    _capture_field(("contract_sha256",), "sha256:" + "0" * 64),
    _capture_field(("candidate_sha256",), "sha256:" + "0" * 64),
    _capture_field(("fallback_used",), True),
    _capture_field(("host", "architecture"), "x86_64"),
    _closure_field(("schema",), "proofbound-research-windows-initialization-closure/0"),
    _bad_closure_identity,
    _closure_field(("frozen_before_first_slot",), False),
    _closure_field(("boundary", "appcontainer"), False),
    _closure_field(("boundary", "capabilities"), ["internet-client"]),
    _closure_field(("boundary", "integrity_sid"), "S-1-16-8192"),
    _closure_field(("boundary", "active_process_limit"), 2),
    _closure_field(("boundary", "breakaway"), "allowed"),
    _closure_field(("boundary", "private_desktop"), False),
    _closure_field(("boundary", "create_no_window"), True),
    _closure_field(("boundary", "drive_alias"), "Q:"),
    _closure_field(("runtime_closures", "node", "version"), "24.20.1"),
    _closure_field(("runtime_closures", "node", "executable", "pe_machine"), "x86_64"),
    _remove_corpus,
    _remove_slot,
    _swap_slots,
    _bad_slot_identity,
    _widen_policy,
    _substitute_positive_output,
    _reuse_denial,
    _replace_denial_with_initialization_failure,
    _capture_field(("reviewed_tree_after",), "sha256:" + "0" * 64),
    _capture_field(("elapsed_ms",), 60_001),
    _duplicate_profile,
)


def generate_attacks(
    repository: Path, capture: dict[str, Any], output_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write all self-contained attacks and prove Python rejects them exactly."""

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
        except WindowsInitializationError as issue:
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
    """Materialize and validate the frozen EXP-0025 attack corpus."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 5:
        print(
            "usage: windows_initialization_attacks REPOSITORY CAPTURE "
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
