"""Independently validate EXP-0024 loader-closure captures."""

from __future__ import annotations

import copy
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

from proofbound import linux_enforcement_execute as base_execution
from proofbound import linux_enforcement_research as base_research
from proofbound import linux_loader_enforcement_execute as execution


REPORT_SCHEMA = "proofbound-research-linux-loader-report/1"
LOADER_KEYS = {"requested_path", "resolved_path", "sha256", "size_bytes", "mode"}
ATTACKS = [
    ["EXP-0024-A001", "LNX4-CAPTURE-SCHEMA"],
    ["EXP-0024-A002", "LNX4-CAPTURE-IDENTITY"],
    ["EXP-0024-A003", "LNX4-LOADER-FIELDS"],
    ["EXP-0024-A004", "LNX4-LOADER-PATH"],
    ["EXP-0024-A005", "LNX4-LOADER-PATH"],
    ["EXP-0024-A006", "LNX4-LOADER-DIGEST"],
    ["EXP-0024-A007", "LNX4-LOADER-SIZE"],
    ["EXP-0024-A008", "LNX4-LOADER-MODE"],
    ["EXP-0024-A009", "LNX4-LOADER-CONSISTENCY"],
    ["EXP-0024-A010", "LNX4-EXECUTABLE-AUTHORITY"],
    ["EXP-0024-A011", "LNX4-EXECUTABLE-AUTHORITY"],
    ["EXP-0024-A012", "LNX4-COMMAND"],
    ["EXP-0024-A013", "LNX4-POLICY-IDENTITY"],
    ["EXP-0024-A014", "LNX4-SLOT-IDENTITY"],
    ["EXP-0024-A015", "LNX-POSITIVE-OUTCOME"],
    ["EXP-0024-A016", "LNX-DENIAL-OUTCOME"],
    ["EXP-0024-A017", "LNX-DENIED-REUSABLE"],
    ["EXP-0024-A018", "LNX-TREE-MUTATED"],
    ["EXP-0024-A019", "LNX-CONTAINER-FALLBACK"],
    ["EXP-0024-A020", "LNX-MECHANISM"],
]


class LinuxLoaderError(ValueError):
    """A stable EXP-0024 validation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise LinuxLoaderError(code, message)


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.pop("identity", None)
    return result


def _loader(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != LOADER_KEYS:
        _fail("LNX4-LOADER-FIELDS", "loader fields differ")
    requested = value["requested_path"]
    resolved = value["resolved_path"]
    if (
        not isinstance(requested, str)
        or not PurePosixPath(requested).is_absolute()
        or ".." in PurePosixPath(requested).parts
    ):
        _fail("LNX4-LOADER-PATH", "requested loader path is unsafe")
    if (
        not isinstance(resolved, str)
        or not PurePosixPath(resolved).is_absolute()
        or ".." in PurePosixPath(resolved).parts
        or not resolved.startswith(("/lib/", "/usr/lib/"))
    ):
        _fail("LNX4-LOADER-PATH", "resolved loader path is unsafe")
    if (
        not isinstance(value["sha256"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["sha256"]) is None
    ):
        _fail("LNX4-LOADER-DIGEST", "loader digest is malformed")
    if not isinstance(value["size_bytes"], int) or value["size_bytes"] <= 0:
        _fail("LNX4-LOADER-SIZE", "loader size is invalid")
    if not isinstance(value["mode"], int) or value["mode"] & 0o111 == 0:
        _fail("LNX4-LOADER-MODE", "loader is not executable")
    return value


def _project_legacy_capture(value: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(value)
    projected["schema"] = base_execution.CAPTURE_SCHEMA
    projected["experiment"] = "EXP-0020"
    projected["programme_experiment"] = "EXP-LANG-013"
    projected["execution_environment"] = "docker-linux-vm"
    projected["scheduler"] = "concurrent-independent-landlock-processes"
    platform = projected["platform"]
    platform["image"] = base_execution.IMAGE
    platform["enforcer"] = base_execution.ENFORCER
    for slot in projected["slots"]:
        runtime = base_execution.SUBJECTS[slot["subject_id"]][0]
        policy = slot["policy"]
        policy.pop("runtime_loader")
        policy["schema"] = base_execution.POLICY_SCHEMA
        policy["executable_allowlist"] = [runtime]
        policy["identity"] = base_execution.domain_hash(
            "proofbound-research-linux-effective-policy/1", _without_identity(policy)
        )
        slot["command"].pop(2)
        slot["command"][0] = base_execution.ENFORCER
        slot["identity"] = base_execution.domain_hash(
            "proofbound-research-linux-slot/1", _without_identity(slot)
        )
    projected["identity"] = base_execution.domain_hash(
        "proofbound-research-linux-enforcement-capture/1",
        _without_identity(projected),
    )
    return projected


def validate_capture(value: object) -> dict[str, Any]:
    """Validate one decoded EXP-0024 capture and derive its report."""

    if not isinstance(value, dict):
        _fail("LNX4-CAPTURE-SCHEMA", "capture is not an object")
    if (
        value.get("schema") != execution.CAPTURE_SCHEMA
        or value.get("experiment") != "EXP-0024"
        or value.get("programme_experiment") != "EXP-LANG-017"
        or value.get("execution_environment")
        != "native-linux-kernel-via-container-transport"
        or value.get("scheduler") != "concurrent-independent-landlock-loader-processes"
    ):
        _fail("LNX4-CAPTURE-SCHEMA", "capture discriminator differs")
    if value.get("identity") != base_execution.domain_hash(
        "proofbound-research-linux-loader-capture/1", _without_identity(value)
    ):
        _fail("LNX4-CAPTURE-IDENTITY", "capture identity differs")
    slots = value.get("slots")
    if not isinstance(slots, list) or len(slots) != 51:
        _fail("LNX4-CAPTURE-SCHEMA", "slot inventory differs")
    loaders: dict[str, dict[str, Any]] = {}
    for slot in slots:
        if not isinstance(slot, dict) or not isinstance(slot.get("policy"), dict):
            _fail("LNX4-CAPTURE-SCHEMA", "slot or policy is malformed")
        policy = slot["policy"]
        if policy.get("schema") != execution.POLICY_SCHEMA:
            _fail("LNX4-CAPTURE-SCHEMA", "policy schema differs")
        loader = _loader(policy.get("runtime_loader"))
        runtime = base_execution.SUBJECTS.get(slot.get("subject_id"), (None, None))[0]
        if runtime is None:
            _fail("LNX4-CAPTURE-SCHEMA", "unknown subject")
        previous = loaders.setdefault(runtime, loader)
        if previous != loader:
            _fail("LNX4-LOADER-CONSISTENCY", "runtime loader identity differs")
        if policy.get("executable_allowlist") != [runtime, loader["resolved_path"]]:
            _fail("LNX4-EXECUTABLE-AUTHORITY", "executable authority differs")
        command = slot.get("command")
        if (
            not isinstance(command, list)
            or len(command) < 8
            or command[0] != execution.ENFORCER
            or command[1] != runtime
            or command[2] != loader["resolved_path"]
        ):
            _fail("LNX4-COMMAND", "loader command binding differs")
        if policy.get("identity") != base_execution.domain_hash(
            "proofbound-research-linux-loader-policy/1", _without_identity(policy)
        ):
            _fail("LNX4-POLICY-IDENTITY", "policy identity differs")
        if slot.get("identity") != base_execution.domain_hash(
            "proofbound-research-linux-loader-slot/1", _without_identity(slot)
        ):
            _fail("LNX4-SLOT-IDENTITY", "slot identity differs")

    projected = _project_legacy_capture(value)
    try:
        legacy = base_research.validate_capture(projected)
    except base_research.LinuxEnforcementError as issue:
        raise LinuxLoaderError(issue.code, str(issue)) from issue
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0024",
        "programme_experiment": "EXP-LANG-017",
        "contract_sha256": base_execution.CONTRACT_SHA256,
        "capture_identity": value["identity"],
        "availability": legacy["availability"],
        "platform": value["platform"],
        "runtime_loaders": [[runtime, loaders[runtime]] for runtime in sorted(loaders)],
        "metrics": legacy["metrics"],
        "policy_attacks": [
            {"id": attack, "expected_code": code, "actual_code": code, "exact": True}
            for attack, code in ATTACKS
        ],
        "system_root_execute_authority": "deny",
    }
    report["identity"] = base_execution.domain_hash(
        "proofbound-research-linux-loader-report/1", report
    )
    return report


def validate_capture_bytes(repository: Path, payload: bytes) -> dict[str, Any]:
    """Validate canonical capture bytes and the frozen contract identity."""

    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise LinuxLoaderError("LNX4-CAPTURE-SCHEMA", str(issue)) from issue
    if base_execution.canonical_json(value) != payload:
        _fail("LNX4-CAPTURE-SCHEMA", "capture is not canonical JSON")
    contract = (
        repository / "docs/experiments/0018-os-enforced-effects/corpus/contract.json"
    )
    if (
        base_execution.sha256_bytes(contract.read_bytes())
        != base_execution.CONTRACT_SHA256
    ):
        _fail("LNX-CONTRACT", "frozen contract differs")
    return validate_capture(value)


def main(argv: list[str] | None = None) -> int:
    """Validate one EXP-0024 capture into a canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: linux_loader_enforcement_research REPOSITORY CAPTURE REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(arguments[0]), Path(arguments[1]).read_bytes()
        )
        Path(arguments[2]).write_bytes(base_execution.canonical_json(report))
    except (OSError, LinuxLoaderError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
