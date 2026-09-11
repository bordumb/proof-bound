"""Execute the preregistered EXP-0024 validator attacks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable

from proofbound import linux_enforcement_execute as base
from proofbound import linux_loader_enforcement_research as research


REPORT_SCHEMA = "proofbound-research-linux-loader-attacks/1"
Mutation = Callable[[dict[str, Any]], None]


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    material = copy.deepcopy(value)
    material.pop("identity", None)
    return material


def _capture_identity(value: dict[str, Any]) -> None:
    value["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-capture/1", _without_identity(value)
    )


def _slot_identity(value: dict[str, Any], index: int) -> None:
    slot = value["slots"][index]
    slot["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-slot/1", _without_identity(slot)
    )
    _capture_identity(value)


def _policy_identity(value: dict[str, Any], index: int) -> None:
    policy = value["slots"][index]["policy"]
    policy["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-policy/1", _without_identity(policy)
    )
    _slot_identity(value, index)


def _set_capture(value: dict[str, Any], field: str, item: object) -> None:
    value[field] = item
    _capture_identity(value)


def _set_platform(value: dict[str, Any], field: str, item: object) -> None:
    value["platform"][field] = item
    _capture_identity(value)


def _set_loader(value: dict[str, Any], field: str, item: object) -> None:
    value["slots"][0]["policy"]["runtime_loader"][field] = item
    _capture_identity(value)


def _extra_loader_field(value: dict[str, Any]) -> None:
    value["slots"][0]["policy"]["runtime_loader"]["alias"] = "/lib/alias.so"
    _capture_identity(value)


def _inconsistent_loader(value: dict[str, Any]) -> None:
    value["slots"][1]["policy"]["runtime_loader"]["sha256"] = "sha256:" + "1" * 64
    _policy_identity(value, 1)


def _remove_loader_authority(value: dict[str, Any]) -> None:
    policy = value["slots"][0]["policy"]
    policy["executable_allowlist"] = [policy["runtime"]]
    _policy_identity(value, 0)


def _broaden_executable_authority(value: dict[str, Any]) -> None:
    value["slots"][0]["policy"]["executable_allowlist"].append("/usr/bin/true")
    _policy_identity(value, 0)


def _change_command_loader(value: dict[str, Any]) -> None:
    value["slots"][0]["command"][2] = "/usr/lib/substitute.so"
    _slot_identity(value, 0)


def _change_policy_identity(value: dict[str, Any]) -> None:
    value["slots"][0]["policy"]["identity"] = "sha256:" + "2" * 64
    _slot_identity(value, 0)


def _change_slot_identity(value: dict[str, Any]) -> None:
    value["slots"][0]["identity"] = "sha256:" + "3" * 64
    _capture_identity(value)


def _positive_failed(value: dict[str, Any]) -> None:
    slot = value["slots"][0]
    slot["exit_code"] = 1
    slot["outcome"] = "denied"
    slot["output"] = None
    slot["reusable"] = False
    slot["stderr"] = "Permission denied\n"
    _slot_identity(value, 0)


def _denial_succeeded(value: dict[str, Any]) -> None:
    index = next(
        index
        for index, slot in enumerate(value["slots"])
        if slot["kind"] == "authority-probe"
    )
    value["slots"][index]["exit_code"] = 0
    _slot_identity(value, index)


def _denial_reusable(value: dict[str, Any]) -> None:
    index = next(
        index
        for index, slot in enumerate(value["slots"])
        if slot["kind"] == "authority-probe"
    )
    value["slots"][index]["reusable"] = True
    _slot_identity(value, index)


ATTACKS: list[tuple[str, str, Mutation]] = [
    ("EXP-0024-A001", "LNX4-CAPTURE-SCHEMA", lambda value: value.update(schema="old")),
    (
        "EXP-0024-A002",
        "LNX4-CAPTURE-IDENTITY",
        lambda value: value.update(identity="sha256:" + "0" * 64),
    ),
    ("EXP-0024-A003", "LNX4-LOADER-FIELDS", _extra_loader_field),
    (
        "EXP-0024-A004",
        "LNX4-LOADER-PATH",
        lambda value: _set_loader(value, "requested_path", "relative-loader.so"),
    ),
    (
        "EXP-0024-A005",
        "LNX4-LOADER-PATH",
        lambda value: _set_loader(value, "resolved_path", "/usr/bin/true"),
    ),
    (
        "EXP-0024-A006",
        "LNX4-LOADER-DIGEST",
        lambda value: _set_loader(value, "sha256", "sha256:bad"),
    ),
    (
        "EXP-0024-A007",
        "LNX4-LOADER-SIZE",
        lambda value: _set_loader(value, "size_bytes", 0),
    ),
    (
        "EXP-0024-A008",
        "LNX4-LOADER-MODE",
        lambda value: _set_loader(value, "mode", 0o644),
    ),
    ("EXP-0024-A009", "LNX4-LOADER-CONSISTENCY", _inconsistent_loader),
    ("EXP-0024-A010", "LNX4-EXECUTABLE-AUTHORITY", _remove_loader_authority),
    ("EXP-0024-A011", "LNX4-EXECUTABLE-AUTHORITY", _broaden_executable_authority),
    ("EXP-0024-A012", "LNX4-COMMAND", _change_command_loader),
    ("EXP-0024-A013", "LNX4-POLICY-IDENTITY", _change_policy_identity),
    ("EXP-0024-A014", "LNX4-SLOT-IDENTITY", _change_slot_identity),
    ("EXP-0024-A015", "LNX-POSITIVE-OUTCOME", _positive_failed),
    ("EXP-0024-A016", "LNX-DENIAL-OUTCOME", _denial_succeeded),
    ("EXP-0024-A017", "LNX-DENIED-REUSABLE", _denial_reusable),
    (
        "EXP-0024-A018",
        "LNX-TREE-MUTATED",
        lambda value: _set_capture(value, "reviewed_tree_after", "sha256:" + "4" * 64),
    ),
    (
        "EXP-0024-A019",
        "LNX-CONTAINER-FALLBACK",
        lambda value: _set_capture(value, "container_confinement_counted", True),
    ),
    (
        "EXP-0024-A020",
        "LNX-MECHANISM",
        lambda value: _set_platform(value, "no_new_privs", False),
    ),
]


def attack_payloads(payload: bytes) -> list[tuple[str, str, bytes]]:
    """Return canonical payloads for all preregistered attacks."""

    original = json.loads(payload)
    results = []
    for attack_id, expected, mutate in ATTACKS:
        value = copy.deepcopy(original)
        mutate(value)
        results.append((attack_id, expected, base.canonical_json(value)))
    return results


def execute_attacks(
    repository: Path, capture_path: Path, rust_binary: Path
) -> dict[str, Any]:
    """Run every attack through both independent validators."""

    payload = capture_path.read_bytes()
    results: dict[str, list[dict[str, Any]]] = {"python": [], "rust": []}
    with tempfile.TemporaryDirectory(prefix="proofbound-exp0024-attacks-") as directory:
        root = Path(directory)
        for index, (attack_id, expected, attacked) in enumerate(
            attack_payloads(payload)
        ):
            try:
                research.validate_capture_bytes(repository, attacked)
            except research.LinuxLoaderError as issue:
                python_code = issue.code
            else:
                python_code = "accepted"
            results["python"].append(
                {
                    "id": attack_id,
                    "expected_code": expected,
                    "actual_code": python_code,
                    "exact": python_code == expected,
                }
            )

            case_path = root / f"attack-{index:02}.json"
            report_path = root / f"report-{index:02}.json"
            case_path.write_bytes(attacked)
            completed = subprocess.run(
                [
                    str(rust_binary),
                    "validate-linux-loader-enforcement",
                    str(repository),
                    str(case_path),
                    str(report_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stderr = completed.stderr.decode("utf-8", errors="strict")
            rust_code = (
                stderr.split(":", 1)[0] if completed.returncode == 1 else "accepted"
            )
            results["rust"].append(
                {
                    "id": attack_id,
                    "expected_code": expected,
                    "actual_code": rust_code,
                    "exact": rust_code == expected,
                }
            )

    if not all(row["exact"] for rows in results.values() for row in rows):
        raise RuntimeError("one or more preregistered attacks did not fail exactly")
    capture = json.loads(payload)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0024",
        "programme_experiment": "EXP-LANG-017",
        "capture_identity": capture["identity"],
        "validators": results,
    }
    report["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-attacks/1", report
    )
    return report


def main(argv: list[str] | None = None) -> int:
    """Execute attacks and write one canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 4:
        print(
            "usage: linux_loader_enforcement_attacks REPOSITORY CAPTURE RUST_BINARY REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        report = execute_attacks(
            Path(arguments[0]), Path(arguments[1]), Path(arguments[2])
        )
        Path(arguments[3]).write_bytes(base.canonical_json(report))
    except (OSError, RuntimeError, UnicodeDecodeError, json.JSONDecodeError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
