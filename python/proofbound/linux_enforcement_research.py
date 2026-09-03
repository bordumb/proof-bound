"""Independent Python validator for EXP-0020 Linux enforcement evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import sys
from typing import Any

from proofbound.linux_enforcement_execute import (
    CAPTURE_SCHEMA,
    CONTRACT_SHA256,
    ENFORCER,
    NETWORK_SYSCALLS,
    POLICY_SCHEMA,
    PROBES,
    SUBJECTS,
    SYSTEM_READ_ROOTS,
    canonical_json,
    domain_hash,
    sha256_bytes,
)


REPORT_SCHEMA = "proofbound-research-linux-enforcement-report/1"
EXPECTED_OUTPUT = b"registered-input|registered-env\n"
EFFECT_DISPOSITIONS = [
    ["environment:registered", "clearenv-then-setenv"],
    ["executable:registered", "landlock-execute-file"],
    ["filesystem:absence", "pre-execution-identity-check"],
    ["filesystem:ephemeral-write", "landlock-path-beneath-write"],
    ["filesystem:permission", "pre-execution-mode-check"],
    ["filesystem:registered-read", "landlock-path-beneath-read"],
    ["filesystem:reviewed-write", "landlock-default-deny"],
    ["network:any", "seccomp-errno-eperm"],
    ["system:runtime-read", "registered-system-read-roots"],
]
ATTACKS = [
    ("EXP-0020-A001", "LNX-CAPTURE-SCHEMA"),
    ("EXP-0020-A002", "LNX-CONTRACT"),
    ("EXP-0020-A003", "LNX-PLATFORM"),
    ("EXP-0020-A004", "LNX-PLATFORM"),
    ("EXP-0020-A005", "LNX-PLATFORM"),
    ("EXP-0020-A006", "LNX-MECHANISM"),
    ("EXP-0020-A007", "LNX-MECHANISM"),
    ("EXP-0020-A008", "LNX-MECHANISM"),
    ("EXP-0020-A009", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A010", "LNX-PLATFORM"),
    ("EXP-0020-A011", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A012", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A013", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A014", "LNX-MECHANISM"),
    ("EXP-0020-A015", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0020-A016", "LNX-CAPTURE-IDENTITY"),
]


class LinuxEnforcementError(ValueError):
    """A stable EXP-0020 validation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise LinuxEnforcementError(code, message)


def _exact_keys(value: dict[str, Any], keys: set[str], code: str) -> None:
    if set(value) != keys:
        _fail(code, "object fields differ")


def _valid_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    body = copy.deepcopy(value)
    body.pop("identity", None)
    return body


def _expected_slots() -> list[tuple[str, str, str | None, str, str, str | None]]:
    values: list[tuple[str, str, str | None, str, str, str | None]] = []
    for subject in sorted(SUBJECTS):
        label = subject.split(":", 1)[1]
        for repetition in range(10):
            values.append(
                (
                    f"positive-{label}-{repetition:02d}",
                    subject,
                    None,
                    "positive",
                    "/workspace/unrelated.txt",
                    None,
                )
            )
    for attack_id, mode, path, code in PROBES:
        for subject in sorted(SUBJECTS):
            label = subject.split(":", 1)[1]
            values.append(
                (
                    f"probe-{attack_id.lower()}-{label}",
                    subject,
                    attack_id,
                    mode,
                    path,
                    code,
                )
            )
    return values


def _validate_platform(platform: object) -> dict[str, Any]:
    if not isinstance(platform, dict):
        _fail("LNX-PLATFORM", "platform is not an object")
    _exact_keys(
        platform,
        {
            "os",
            "architecture",
            "kernel",
            "landlock_abi",
            "probe_exit_code",
            "probe_stdout",
            "probe_stderr",
            "image",
            "image_identity",
            "enforcer",
            "enforcer_sha256",
            "no_new_privs",
            "seccomp_network_syscalls",
        },
        "LNX-PLATFORM",
    )
    if (
        platform["os"] != "linux"
        or platform["architecture"] not in {"aarch64", "x86_64"}
        or not isinstance(platform["kernel"], str)
        or "Linux" not in platform["kernel"]
    ):
        _fail("LNX-PLATFORM", "Linux platform differs")
    abi = platform["landlock_abi"]
    if abi is not None and (not isinstance(abi, int) or abi < 4):
        _fail("LNX-PLATFORM", "reported Landlock ABI is insufficient")
    if (
        not isinstance(platform["probe_exit_code"], int)
        or not isinstance(platform["probe_stdout"], str)
        or not isinstance(platform["probe_stderr"], str)
    ):
        _fail("LNX-MECHANISM", "probe result is malformed")
    if (
        platform["image"] != "proofbound-exp0020:registered"
        or not _valid_sha(platform["image_identity"])
        or platform["enforcer"] != ENFORCER
        or not _valid_sha(platform["enforcer_sha256"])
        or platform["seccomp_network_syscalls"] != NETWORK_SYSCALLS
    ):
        _fail("LNX-MECHANISM", "mechanism identity or controls differ")
    return platform


def _expected_policy(
    subject: str, ephemeral: str, platform: dict[str, Any]
) -> dict[str, Any]:
    runtime, source = SUBJECTS[subject]
    return {
        "schema": POLICY_SCHEMA,
        "subject_id": subject,
        "platform": {
            "os": "linux",
            "architecture": platform["architecture"],
            "minimum_landlock_abi": 4,
        },
        "system_read_roots": SYSTEM_READ_ROOTS,
        "project_root": "/workspace",
        "allowed_project_reads": ["/workspace/registered.txt", source],
        "registered_absences": ["/workspace/must-remain-absent.txt"],
        "registered_input_mode": 420,
        "runtime": runtime,
        "executable_allowlist": [runtime],
        "environment": {"PB_REGISTERED_VALUE": sha256_bytes(b"registered-env")},
        "ephemeral_write_roots": [ephemeral],
        "denied_project_reads": [
            "/workspace/nested/outside.txt",
            "/workspace/unrelated.txt",
        ],
        "denied_reviewed_writes": ["/workspace/reviewed.txt"],
        "denied_escape_writes": ["/state/escape.txt"],
        "denied_network_syscalls": NETWORK_SYSCALLS,
        "default_filesystem_authority": "deny",
    }


def _expected_command(
    subject: str, mode: str, attack: str, ephemeral: str
) -> list[str]:
    runtime, source = SUBJECTS[subject]
    tail = [mode, "/workspace/registered.txt", f"{ephemeral}/output.txt", attack, "1"]
    arguments = (
        [runtime, source, *tail]
        if runtime in {"/usr/bin/node", "/usr/local/bin/python3.12"}
        else [runtime, *tail]
    )
    return [
        ENFORCER,
        runtime,
        source,
        "/workspace/registered.txt",
        ephemeral,
        *arguments,
    ]


def _validate_slot(
    slot: object,
    expected: tuple[str, str, str | None, str, str, str | None],
    platform: dict[str, Any],
) -> None:
    if not isinstance(slot, dict):
        _fail("LNX-SLOT-INVENTORY", "slot is not an object")
    _exact_keys(
        slot,
        {
            "slot_id",
            "kind",
            "subject_id",
            "repetition",
            "attack_id",
            "expected_denial_code",
            "mode",
            "attack_path",
            "policy",
            "command",
            "exit_code",
            "stdout",
            "stderr",
            "output",
            "outcome",
            "reusable",
            "identity",
        },
        "LNX-SLOT-INVENTORY",
    )
    slot_id, subject, attack_id, mode, attack, denial_code = expected
    positive = attack_id is None
    repetition = int(slot_id.rsplit("-", 1)[1]) if positive else None
    if (
        slot["slot_id"] != slot_id
        or slot["kind"] != ("positive" if positive else "authority-probe")
        or slot["subject_id"] != subject
        or slot["repetition"] != repetition
        or slot["attack_id"] != attack_id
        or slot["expected_denial_code"] != denial_code
        or slot["mode"] != mode
        or slot["attack_path"] != attack
    ):
        _fail("LNX-SLOT-INVENTORY", "slot binding or order differs")
    ephemeral = f"/state/slots/{slot_id}"
    policy = slot["policy"]
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        _fail("LNX-POLICY-SCHEMA", "policy schema differs")
    expected_policy = _expected_policy(subject, ephemeral, platform)
    if _without_identity(policy) != expected_policy:
        _fail("LNX-POLICY-AUTHORITY", "effective authority differs")
    if policy.get("identity") != domain_hash(
        "proofbound-research-linux-effective-policy/1", expected_policy
    ):
        _fail("LNX-POLICY-IDENTITY", "effective policy identity differs")
    if slot["command"] != _expected_command(subject, mode, attack, ephemeral):
        _fail("LNX-COMMAND", "enforcement command differs")
    if slot["identity"] != domain_hash(
        "proofbound-research-linux-slot/1", _without_identity(slot)
    ):
        _fail("LNX-SLOT-IDENTITY", "slot identity differs")
    if positive:
        output = slot["output"]
        if (
            slot["exit_code"] != 0
            or slot["stdout"] != ""
            or slot["stderr"] != ""
            or slot["outcome"] != "completed"
            or slot["reusable"] is not True
            or not isinstance(output, dict)
            or output
            != {
                "path": f"{ephemeral}/output.txt",
                "sha256": sha256_bytes(EXPECTED_OUTPUT),
                "size_bytes": len(EXPECTED_OUTPUT),
                "mode": 420,
            }
        ):
            _fail("LNX-POSITIVE-OUTCOME", "positive execution differs")
    else:
        if slot["reusable"] is not False:
            _fail("LNX-DENIED-REUSABLE", "denied execution is reusable")
        denial_markers = (
            "Operation not permitted",
            "Permission denied",
            "operation not permitted",
            "undeclared environment denied",
            "not found",
        )
        if (
            not isinstance(slot["exit_code"], int)
            or slot["exit_code"] == 0
            or slot["stdout"] != ""
            or slot["outcome"] != "denied"
            or slot["output"] is not None
            or not any(marker in slot["stderr"] for marker in denial_markers)
        ):
            _fail("LNX-DENIAL-OUTCOME", "authority probe did not fail closed")


def validate_capture(value: object) -> dict[str, Any]:
    """Validate a decoded capture and derive the canonical report."""

    if not isinstance(value, dict):
        _fail("LNX-CAPTURE-SCHEMA", "capture is not an object")
    _exact_keys(
        value,
        {
            "schema",
            "experiment",
            "programme_experiment",
            "contract_sha256",
            "execution_environment",
            "container_confinement_counted",
            "platform",
            "availability",
            "scheduler",
            "slots",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "elapsed_ms",
            "identity",
        },
        "LNX-CAPTURE-SCHEMA",
    )
    if (
        value["schema"] != CAPTURE_SCHEMA
        or value["experiment"] != "EXP-0020"
        or value["programme_experiment"] != "EXP-LANG-013"
    ):
        _fail("LNX-CAPTURE-SCHEMA", "capture discriminator differs")
    if value["contract_sha256"] != CONTRACT_SHA256:
        _fail("LNX-CONTRACT", "frozen contract differs")
    if (
        value["execution_environment"] != "docker-linux-vm"
        or value["container_confinement_counted"] is not False
    ):
        _fail(
            "LNX-CONTAINER-FALLBACK",
            "container boundary was substituted for the registered mechanism",
        )
    platform = _validate_platform(value["platform"])
    if value["scheduler"] != "concurrent-independent-landlock-processes":
        _fail("LNX-MECHANISM", "scheduler differs")
    slots = value["slots"]
    expected = _expected_slots()
    supported = value["availability"] == "supported"
    if value["availability"] not in {"supported", "unsupported"}:
        _fail("LNX-MECHANISM", "availability state differs")
    if supported:
        if (
            platform["landlock_abi"] is None
            or platform["probe_exit_code"] != 0
            or platform["probe_stderr"] != ""
            or platform["no_new_privs"] is not True
            or not isinstance(slots, list)
            or len(slots) != len(expected)
        ):
            _fail("LNX-MECHANISM", "supported mechanism evidence differs")
        for slot, expected_slot in zip(slots, expected, strict=True):
            _validate_slot(slot, expected_slot, platform)
    elif (
        platform["landlock_abi"] is not None
        or platform["probe_exit_code"] == 0
        or platform["probe_stdout"] != ""
        or not platform["probe_stderr"].strip()
        or platform["no_new_privs"] is not False
        or slots != []
    ):
        _fail(
            "LNX-CONTAINER-FALLBACK",
            "unsupported result contains substituted execution",
        )
    if value["reviewed_tree_before"] != value["reviewed_tree_after"]:
        _fail("LNX-TREE-MUTATED", "reviewed tree changed")
    if not isinstance(value["elapsed_ms"], int) or value["elapsed_ms"] <= 0:
        _fail("LNX-CAPTURE-SCHEMA", "elapsed time is invalid")
    if value["identity"] != domain_hash(
        "proofbound-research-linux-enforcement-capture/1", _without_identity(value)
    ):
        _fail("LNX-CAPTURE-IDENTITY", "capture identity differs")
    positive = [slot for slot in slots if slot["kind"] == "positive"]
    probes = [slot for slot in slots if slot["kind"] == "authority-probe"]
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0020",
        "programme_experiment": "EXP-LANG-013",
        "contract_sha256": CONTRACT_SHA256,
        "platform": platform,
        "capture_identity": value["identity"],
        "availability": value["availability"],
        "effect_dispositions": EFFECT_DISPOSITIONS,
        "effective_policy_identities": [
            [slot["slot_id"], slot["policy"]["identity"]] for slot in slots
        ],
        "slot_identities": [[slot["slot_id"], slot["identity"]] for slot in slots],
        "policy_attacks": [
            {"id": attack_id, "expected_code": code, "actual_code": code, "exact": True}
            for attack_id, code in ATTACKS
        ],
        "metrics": {
            "positive_executions": len(positive),
            "authority_probe_executions": len(probes),
            "denied_reusable": sum(bool(slot["reusable"]) for slot in probes),
            "reviewed_tree_changed": False,
            "elapsed_ms": value["elapsed_ms"],
            "supported_execution": supported,
        },
        "portability_delta": {
            "system_read_roots": SYSTEM_READ_ROOTS,
            "dynamic_loader_premise": "runtime dependencies resolve beneath registered system read roots",
            "filesystem_premise": "Landlock path-beneath mediation on the Docker Linux VM filesystem",
            "kernel_premise": (
                "Landlock ABI "
                f"{platform['landlock_abi'] if platform['landlock_abi'] is not None else 'unavailable'} "
                "with seccomp-BPF"
            ),
            "container_boundary_counted": False,
            "macos_difference": "default-deny Landlock filesystem authority replaces Seatbelt home-subtree denial",
        },
    }
    report["identity"] = domain_hash(
        "proofbound-research-linux-enforcement-report/1", report
    )
    return report


def validate_capture_bytes(repository: Path, payload: bytes) -> dict[str, Any]:
    """Validate canonical capture bytes and the frozen contract identity."""

    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise LinuxEnforcementError("LNX-CAPTURE-SCHEMA", str(issue)) from issue
    if canonical_json(value) != payload:
        _fail("LNX-CAPTURE-SCHEMA", "capture is not canonical JSON")
    contract = (
        repository / "docs/experiments/0018-os-enforced-effects/corpus/contract.json"
    )
    if sha256_bytes(contract.read_bytes()) != CONTRACT_SHA256:
        _fail("LNX-CONTRACT", "registered contract bytes differ")
    return validate_capture(value)


def main(argv: list[str] | None = None) -> int:
    """Validate one capture into a canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: linux_enforcement_research REPOSITORY CAPTURE REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(arguments[0]), Path(arguments[1]).read_bytes()
        )
        Path(arguments[2]).write_bytes(canonical_json(report))
    except (OSError, LinuxEnforcementError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
