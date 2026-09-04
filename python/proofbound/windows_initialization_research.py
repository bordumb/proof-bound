"""Independent Python validator for the frozen EXP-0025 confirmation."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path, PureWindowsPath
import re
import sys
from typing import Any

from proofbound.windows_enforcement_execute import (
    canonical_json,
    domain_hash,
    sha256_bytes,
)


CAPTURE_SCHEMA = "proofbound-research-windows-initialization-capture/1"
CLOSURE_SCHEMA = "proofbound-research-windows-initialization-closure/1"
POLICY_SCHEMA = "proofbound-research-windows-initialization-policy/1"
SLOT_SCHEMA = "proofbound-research-windows-initialization-slot/1"
REPORT_SCHEMA = "proofbound-research-windows-initialization-report/1"
CONTRACT_SHA256 = (
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d"
)
CANDIDATE_PATH = Path(
    "docs/experiments/0025-windows-initialization-closure/candidate.json"
)
CORPUS_PATH = Path("docs/experiments/0018-os-enforced-effects/corpus")
EXPECTED_OUTPUT = b"registered-input|registered-env\n"
DRIVE_ALIAS = "P:"
MAX_REPORT_BYTES = 524_288
MAX_ELAPSED_MS = 60_000
INITIALIZATION_FAILURES = {0xC0000135, 0xC0000142}
PROBES = (
    (
        "EXP-0018-A001",
        "read-undeclared",
        "workspace/unrelated.txt",
        "appcontainer-path-read",
    ),
    (
        "EXP-0018-A002",
        "read-undeclared",
        "workspace/nested/outside.txt",
        "appcontainer-path-read",
    ),
    (
        "EXP-0018-A007",
        "env-undeclared",
        "workspace/unrelated.txt",
        "cleared-environment",
    ),
    (
        "EXP-0018-A009",
        "exec-unregistered",
        "/usr/bin/true",
        "job-active-process-limit",
    ),
    (
        "EXP-0018-A011",
        "network",
        "workspace/unrelated.txt",
        "appcontainer-network-capability",
    ),
    (
        "EXP-0018-A012",
        "write-reviewed",
        "workspace/reviewed.txt",
        "appcontainer-path-write",
    ),
    (
        "EXP-0018-A013",
        "write-escape",
        "state/escape.txt",
        "appcontainer-path-write",
    ),
)
SUBJECTS = {
    "subject:node": ("node", "workspace/subjects/node_subject.mjs"),
    "subject:python": ("python", "workspace/subjects/python_subject.py"),
    "subject:rust": ("rust", "workspace/subjects/rust_subject.rs"),
}
ATTACKS = (
    ("EXP-0025-A001", "WIN25-CAPTURE-SCHEMA"),
    ("EXP-0025-A002", "WIN25-DISCRIMINATOR"),
    ("EXP-0025-A003", "WIN25-CONTRACT"),
    ("EXP-0025-A004", "WIN25-CANDIDATE"),
    ("EXP-0025-A005", "WIN25-FALLBACK"),
    ("EXP-0025-A006", "WIN25-PLATFORM"),
    ("EXP-0025-A007", "WIN25-CLOSURE-SCHEMA"),
    ("EXP-0025-A008", "WIN25-CLOSURE-IDENTITY"),
    ("EXP-0025-A009", "WIN25-CLOSURE-FREEZE"),
    ("EXP-0025-A010", "WIN25-APPCONTAINER"),
    ("EXP-0025-A011", "WIN25-APPCONTAINER"),
    ("EXP-0025-A012", "WIN25-TOKEN"),
    ("EXP-0025-A013", "WIN25-JOB"),
    ("EXP-0025-A014", "WIN25-JOB"),
    ("EXP-0025-A015", "WIN25-DESKTOP"),
    ("EXP-0025-A016", "WIN25-PROCESS-CREATION"),
    ("EXP-0025-A017", "WIN25-DRIVE-ALIAS"),
    ("EXP-0025-A018", "WIN25-RUNTIME"),
    ("EXP-0025-A019", "WIN25-ARTIFACT"),
    ("EXP-0025-A020", "WIN25-CORPUS"),
    ("EXP-0025-A021", "WIN25-SLOT-INVENTORY"),
    ("EXP-0025-A022", "WIN25-SLOT-INVENTORY"),
    ("EXP-0025-A023", "WIN25-SLOT-IDENTITY"),
    ("EXP-0025-A024", "WIN25-POLICY"),
    ("EXP-0025-A025", "WIN25-POSITIVE"),
    ("EXP-0025-A026", "WIN25-DENIED-REUSABLE"),
    ("EXP-0025-A027", "WIN25-DENIAL"),
    ("EXP-0025-A028", "WIN25-TREE"),
    ("EXP-0025-A029", "WIN25-ELAPSED"),
    ("EXP-0025-A030", "WIN25-FRESHNESS"),
)


class WindowsInitializationError(ValueError):
    """A stable EXP-0025 validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise WindowsInitializationError(code, message)


def _exact_keys(value: object, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code, "object fields differ")
    return value


def _valid_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    body = copy.deepcopy(value)
    body.pop("identity", None)
    return body


def _expected_slots() -> list[dict[str, Any]]:
    slots: list[dict[str, Any]] = []
    for subject_id in sorted(SUBJECTS):
        runtime, _ = SUBJECTS[subject_id]
        for repetition in range(10):
            slots.append(
                {
                    "slot_id": f"positive-{runtime}-{repetition:02d}",
                    "kind": "positive",
                    "subject_id": subject_id,
                    "runtime": runtime,
                    "repetition": repetition,
                    "attack_id": None,
                    "mode": "positive",
                    "attack_path": "workspace/unrelated.txt",
                    "denial_mechanism": None,
                }
            )
    for attack_id, mode, path, mechanism in PROBES:
        for subject_id in sorted(SUBJECTS):
            runtime, _ = SUBJECTS[subject_id]
            slots.append(
                {
                    "slot_id": f"probe-{attack_id.lower()}-{runtime}",
                    "kind": "authority-probe",
                    "subject_id": subject_id,
                    "runtime": runtime,
                    "repetition": None,
                    "attack_id": attack_id,
                    "mode": mode,
                    "attack_path": path,
                    "denial_mechanism": mechanism,
                }
            )
    return slots


def _validate_artifact(value: object, code: str = "WIN25-ARTIFACT") -> dict[str, Any]:
    artifact = _exact_keys(
        value,
        {
            "logical_name",
            "requested_path",
            "resolved_path",
            "sha256",
            "size_bytes",
            "pe_machine",
            "reparse_point",
        },
        code,
    )
    if (
        not isinstance(artifact["logical_name"], str)
        or not artifact["logical_name"]
        or not isinstance(artifact["requested_path"], str)
        or not artifact["requested_path"]
        or not isinstance(artifact["resolved_path"], str)
        or not artifact["resolved_path"]
        or not _valid_sha(artifact["sha256"])
        or not isinstance(artifact["size_bytes"], int)
        or artifact["size_bytes"] < 0
        or artifact["pe_machine"] not in {None, "aarch64"}
        or artifact["reparse_point"] is not False
    ):
        _fail(code, "artifact identity differs")
    return artifact


def _validate_staged_artifact(value: object) -> dict[str, Any]:
    artifact = _exact_keys(
        value,
        {
            "destination",
            "file_id",
            "security_descriptor_sha256",
            "reparse_point",
        },
        "WIN25-ARTIFACT",
    )
    if (
        not isinstance(artifact["destination"], str)
        or not artifact["destination"]
        or "\\" in artifact["destination"]
        or PureWindowsPath(artifact["destination"]).is_absolute()
        or not isinstance(artifact["file_id"], str)
        or re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{16}", artifact["file_id"]) is None
        or not _valid_sha(artifact["security_descriptor_sha256"])
        or artifact["reparse_point"] is not False
    ):
        _fail("WIN25-ARTIFACT", "staged artifact identity differs")
    return artifact


def _validate_corpus(repository: Path, value: object) -> dict[str, dict[str, Any]]:
    index = json.loads((repository / CORPUS_PATH / "index.json").read_bytes())
    expected = index.get("files")
    if value != expected or not isinstance(value, list):
        _fail("WIN25-CORPUS", "frozen corpus inventory differs")
    by_path = {row["path"]: row for row in value}
    for relative, row in by_path.items():
        payload = (repository / CORPUS_PATH / relative).read_bytes()
        if sha256_bytes(payload) != row["sha256"] or len(payload) != row["size_bytes"]:
            _fail("WIN25-CORPUS", f"frozen corpus bytes differ: {relative}")
    return by_path


def _validate_closure(
    repository: Path, value: object
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    closure = _exact_keys(
        value,
        {
            "schema",
            "candidate_sha256",
            "contract_sha256",
            "frozen_before_first_slot",
            "corpus",
            "boundary",
            "runtime_closures",
            "instruments",
            "environment",
            "slot_inventory",
            "identity",
        },
        "WIN25-CLOSURE-SCHEMA",
    )
    if closure["schema"] != CLOSURE_SCHEMA:
        _fail("WIN25-CLOSURE-SCHEMA", "closure schema differs")
    if closure["identity"] != domain_hash(CLOSURE_SCHEMA, _without_identity(closure)):
        _fail("WIN25-CLOSURE-IDENTITY", "closure identity differs")
    if closure["frozen_before_first_slot"] is not True:
        _fail("WIN25-CLOSURE-FREEZE", "closure was not sealed before execution")
    candidate = repository / CANDIDATE_PATH
    if closure["candidate_sha256"] != sha256_bytes(candidate.read_bytes()):
        _fail("WIN25-CANDIDATE", "frozen candidate bytes differ")
    if closure["contract_sha256"] != CONTRACT_SHA256:
        _fail("WIN25-CONTRACT", "closure contract differs")
    corpus = _validate_corpus(repository, closure["corpus"])
    expected_boundary = {
        "appcontainer": True,
        "capabilities": [],
        "restricted_token": True,
        "integrity_sid": "S-1-16-4096",
        "administrator_sids": "deny-only",
        "active_process_limit": 1,
        "kill_on_close": True,
        "assigned_before_resume": True,
        "breakaway": "forbidden",
        "private_desktop": True,
        "create_no_window": False,
        "drive_alias": DRIVE_ALIAS,
        "drive_alias_api": "DefineDosDeviceW",
        "drive_alias_scope": "same-authentication-id",
        "fallback": "forbidden",
    }
    boundary = closure["boundary"]
    if not isinstance(boundary, dict):
        _fail("WIN25-APPCONTAINER", "boundary is not an object")
    if boundary.get("appcontainer") is not True or boundary.get("capabilities") != []:
        _fail("WIN25-APPCONTAINER", "AppContainer authority differs")
    if (
        boundary.get("restricted_token") is not True
        or boundary.get("integrity_sid") != "S-1-16-4096"
        or boundary.get("administrator_sids") != "deny-only"
    ):
        _fail("WIN25-TOKEN", "restricted-token authority differs")
    if (
        boundary.get("active_process_limit") != 1
        or boundary.get("kill_on_close") is not True
        or boundary.get("assigned_before_resume") is not True
    ):
        _fail("WIN25-JOB", "job limit differs")
    if boundary.get("breakaway") != "forbidden":
        _fail("WIN25-JOB", "job breakaway differs")
    if boundary.get("private_desktop") is not True:
        _fail("WIN25-DESKTOP", "desktop isolation differs")
    if boundary.get("create_no_window") is not False:
        _fail("WIN25-PROCESS-CREATION", "console initialization differs")
    if (
        boundary.get("drive_alias") != DRIVE_ALIAS
        or boundary.get("drive_alias_api") != "DefineDosDeviceW"
        or boundary.get("drive_alias_scope") != "same-authentication-id"
    ):
        _fail("WIN25-DRIVE-ALIAS", "drive alias premise differs")
    if boundary != expected_boundary:
        _fail("WIN25-APPCONTAINER", "closure boundary has unknown authority")
    expected_environment = {
        "workload": ["PB_REGISTERED_VALUE"],
        "platform": ["SystemDrive", "SystemRoot"],
        "python": ["PYTHONDONTWRITEBYTECODE", "PYTHONHOME", "PYTHONPATH"],
        "boundary_added": ["LOCALAPPDATA", "TEMP", "TMP"],
        "undeclared_present": False,
    }
    if closure["environment"] != expected_environment:
        _fail("WIN25-APPCONTAINER", "environment closure differs")
    if closure["slot_inventory"] != {
        "positive": 30,
        "authority_probes": 21,
        "subjects": sorted(SUBJECTS),
        "probes": [list(row) for row in PROBES],
    }:
        _fail("WIN25-SLOT-INVENTORY", "registered slot inventory differs")
    runtimes = _exact_keys(
        closure["runtime_closures"], {"node", "python", "rust"}, "WIN25-RUNTIME"
    )
    node = _exact_keys(
        runtimes["node"],
        {"version", "version_output", "executable", "staged_layout"},
        "WIN25-RUNTIME",
    )
    if (
        node["version"] != "24.20.0"
        or node["version_output"] != "v24.20.0"
        or node["staged_layout"] != ["node.exe"]
    ):
        _fail("WIN25-RUNTIME", "Node closure differs")
    _validate_artifact(node["executable"])
    python = _exact_keys(
        runtimes["python"],
        {
            "version",
            "executable",
            "native_artifacts",
            "pure_python_modules",
            "site_packages",
        },
        "WIN25-RUNTIME",
    )
    if (
        python["version"] != "3.12.10"
        or python["site_packages"] != "excluded"
        or not isinstance(python["pure_python_modules"], int)
        or python["pure_python_modules"] < 1
        or not isinstance(python["native_artifacts"], list)
        or not 1 <= len(python["native_artifacts"]) <= 511
    ):
        _fail("WIN25-RUNTIME", "Python closure differs")
    _validate_artifact(python["executable"])
    for artifact in python["native_artifacts"]:
        _validate_artifact(artifact)
    names = [artifact["logical_name"] for artifact in python["native_artifacts"]]
    if (
        len(names) != len(set(name.casefold() for name in names))
        or "runtime/python/python312.zip" not in names
    ):
        _fail("WIN25-RUNTIME", "Python artifact inventory differs")
    rust = _exact_keys(
        runtimes["rust"],
        {"toolchain", "version_output", "compiler", "source", "executable"},
        "WIN25-RUNTIME",
    )
    if (
        rust["toolchain"] != "1.94.0"
        or not isinstance(rust["version_output"], str)
        or not rust["version_output"].startswith("rustc 1.94.0 ")
    ):
        _fail("WIN25-RUNTIME", "Rust closure differs")
    for field in ("compiler", "source", "executable"):
        _validate_artifact(rust[field])
    instruments = _exact_keys(
        closure["instruments"],
        {"registered_child_source", "registered_child_executable"},
        "WIN25-ARTIFACT",
    )
    for artifact in instruments.values():
        _validate_artifact(artifact)
    return closure, corpus


def _expected_policy(
    runtime_name: str, runtime_identity: str, expected: dict[str, Any]
) -> dict[str, Any]:
    environment = ["PB_REGISTERED_VALUE", "SystemDrive", "SystemRoot"]
    if runtime_name == "python":
        environment.extend(["PYTHONDONTWRITEBYTECODE", "PYTHONHOME", "PYTHONPATH"])
    body = {
        "schema": POLICY_SCHEMA,
        "subject_id": expected["subject_id"],
        "runtime": runtime_name,
        "runtime_identity": runtime_identity,
        "appcontainer": {
            "fresh_profile": True,
            "capabilities": [],
            "network_authority": "none",
        },
        "token": {
            "integrity_sid": "S-1-16-4096",
            "administrator_sids": "deny-only",
        },
        "job": {
            "active_process_limit": 1,
            "kill_on_close": True,
            "assigned_before_resume": True,
            "breakaway": "forbidden",
        },
        "desktop": "fresh-private-appcontainer-acl",
        "process_creation": {"suspended": True, "create_no_window": False},
        "filesystem": {
            "application_root": "fresh-profile-owned",
            "registered_reads": ["registered.txt", "subjects/<subject>"],
            "ephemeral_writes": ["outputs/output.txt"],
            "reviewed_tree": "outside-package-sid-authority",
            "reparse_points": "rejected",
        },
        "environment": sorted(environment),
        "unregistered_child": {
            "logical_path": "/usr/bin/true",
            "drive_alias": DRIVE_ALIAS
            if expected["mode"] == "exec-unregistered"
            else None,
            "denied_by": "job-active-process-limit",
        },
    }
    body["identity"] = domain_hash(POLICY_SCHEMA, body)
    return body


def _expected_staged(
    closure: dict[str, Any],
    corpus: dict[str, dict[str, Any]],
    expected: dict[str, Any],
) -> dict[str, tuple[str, int, str | None]]:
    runtime_name = expected["runtime"]
    runtime = closure["runtime_closures"][runtime_name]
    executable = runtime["executable"]
    values = {
        PureWindowsPath(executable["requested_path"]).name: (
            executable["sha256"],
            executable["size_bytes"],
            executable["pe_machine"],
        )
    }
    if runtime_name == "python":
        for artifact in runtime["native_artifacts"]:
            destination = artifact["logical_name"].removeprefix("runtime/python/")
            values[destination] = (
                artifact["sha256"],
                artifact["size_bytes"],
                artifact["pe_machine"],
            )
    _, source_path = SUBJECTS[expected["subject_id"]]
    source = corpus[source_path]
    values[f"subjects/{Path(source_path).name}"] = (
        source["sha256"],
        source["size_bytes"],
        None,
    )
    registered = corpus["workspace/registered.txt"]
    values["registered.txt"] = (
        registered["sha256"],
        registered["size_bytes"],
        None,
    )
    if expected["mode"] == "exec-unregistered":
        helper = closure["instruments"]["registered_child_executable"]
        values["usr/bin/true.exe"] = (
            helper["sha256"],
            helper["size_bytes"],
            helper["pe_machine"],
        )
    return values


def _validate_target(target: object, expected: dict[str, Any]) -> None:
    if (
        not isinstance(target, dict)
        or target.get("logical_name") != expected["attack_path"]
    ):
        _fail("WIN25-DENIAL", "attack target differs")
    if expected["mode"] == "exec-unregistered":
        if target != {
            "logical_name": "/usr/bin/true",
            "kind": "registered-child-image",
            "present_after": False,
        }:
            _fail("WIN25-DRIVE-ALIAS", "registered child alias differs")
        return
    if expected["mode"] == "write-escape":
        if (
            target.get("present_before") is not False
            or target.get("present_after") is not False
        ):
            _fail("WIN25-TREE", "escape write changed external state")
        return
    if (
        not _valid_sha(target.get("sha256"))
        or target.get("sha256_after") != target.get("sha256")
        or target.get("size_bytes_after") != target.get("size_bytes")
        or target.get("present_after") is not True
        or target.get("reparse_point") is not False
    ):
        _fail("WIN25-TREE", "reviewed attack target changed")


def _validate_output(value: object, positive: bool) -> bool:
    if not isinstance(value, dict) or value.get("path") != "outputs/output.txt":
        _fail("WIN25-POSITIVE" if positive else "WIN25-DENIAL", "output path differs")
    if value == {"path": "outputs/output.txt", "present": False}:
        return False
    expected_shape = {
        "path",
        "present",
        "resolved_path",
        "file_id",
        "sha256",
        "size_bytes",
        "pe_machine",
        "security_descriptor_sha256",
        "reparse_point",
        "content_base64",
    }
    if set(value) != expected_shape or value.get("present") is not True:
        _fail("WIN25-POSITIVE" if positive else "WIN25-DENIAL", "output shape differs")
    if (
        not isinstance(value.get("resolved_path"), str)
        or not value["resolved_path"]
        or re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{16}", str(value.get("file_id", "")))
        is None
        or not _valid_sha(value.get("sha256"))
        or not isinstance(value.get("size_bytes"), int)
        or value["size_bytes"] < 0
        or value.get("pe_machine") is not None
        or not _valid_sha(value.get("security_descriptor_sha256"))
        or value.get("reparse_point") is not False
    ):
        _fail("WIN25-ARTIFACT", "output file identity differs")
    try:
        decoded = base64.b64decode(value.get("content_base64", ""), validate=True)
    except (ValueError, TypeError) as issue:
        raise WindowsInitializationError("WIN25-ARTIFACT", str(issue)) from issue
    if (
        base64.b64encode(decoded).decode("ascii") != value["content_base64"]
        or value["size_bytes"] != len(decoded)
        or value["sha256"] != sha256_bytes(decoded)
    ):
        _fail("WIN25-ARTIFACT", "output content identity differs")
    expected = {
        "sha256": sha256_bytes(EXPECTED_OUTPUT),
        "size_bytes": len(EXPECTED_OUTPUT),
    }
    return (
        positive
        and decoded == EXPECTED_OUTPUT
        and all(value.get(key) == item for key, item in expected.items())
    )


def _validate_boundary(
    value: object,
    closure: dict[str, Any],
    corpus: dict[str, dict[str, Any]],
    expected: dict[str, Any],
) -> bool:
    boundary = _exact_keys(
        value,
        {
            "profile",
            "window_station",
            "application_staged",
            "application_root",
            "requested_application_identity",
            "staged_files",
            "staged_content_identity",
            "captured_files",
            "drive_alias",
            "drive_alias_target",
            "appcontainer_sid",
            "restricted_token",
            "administrator_sids",
            "integrity_level",
            "child_token",
            "job",
            "create_no_window",
            "exit_code",
            "stdout",
            "stderr",
        },
        "WIN25-APPCONTAINER",
    )
    if (
        not isinstance(boundary["profile"], str)
        or re.fullmatch(r"proofbound\.exp0023\.[0-9a-f]{32}", boundary["profile"])
        is None
        or boundary["application_staged"] is not True
        or boundary["restricted_token"] is not True
        or boundary["administrator_sids"] != "deny-only"
        or boundary["integrity_level"] != "low"
    ):
        _fail("WIN25-APPCONTAINER", "executed AppContainer boundary differs")
    application_root = boundary["application_root"]
    if (
        not isinstance(application_root, str)
        or not PureWindowsPath(application_root).is_absolute()
        or PureWindowsPath(application_root).name.casefold() != "application"
    ):
        _fail("WIN25-ARTIFACT", "application root identity differs")
    station = boundary["window_station"]
    if (
        not isinstance(station, dict)
        or station.get("private") is not True
        or station.get("appcontainer_acl") is not True
        or station.get("desktop") != "default"
    ):
        _fail("WIN25-DESKTOP", "private desktop boundary differs")
    child = boundary["child_token"]
    if (
        not isinstance(child, dict)
        or child.get("appcontainer") is not True
        or child.get("appcontainer_sid") != boundary["appcontainer_sid"]
        or child.get("integrity_sid") != "S-1-16-4096"
        or child.get("administrator_deny_only") is not True
        or child.get("verified_before_resume") is not True
    ):
        _fail("WIN25-TOKEN", "actual suspended child token differs")
    if boundary["job"] != {
        "active_process_limit": 1,
        "kill_on_close": True,
        "assigned_before_resume": True,
    }:
        _fail("WIN25-JOB", "actual job boundary differs")
    if boundary["create_no_window"] is not False:
        _fail("WIN25-PROCESS-CREATION", "actual console initialization differs")
    alias = DRIVE_ALIAS if expected["mode"] == "exec-unregistered" else None
    if boundary["drive_alias"] != alias or (alias is None) != (
        boundary["drive_alias_target"] is None
    ):
        _fail("WIN25-DRIVE-ALIAS", "actual drive alias differs")
    runtime = closure["runtime_closures"][expected["runtime"]]
    requested = boundary["requested_application_identity"]
    executable = runtime["executable"]
    if (
        not isinstance(requested, dict)
        or set(requested)
        != {
            "requested_path",
            "resolved_path",
            "file_id",
            "sha256",
            "size_bytes",
            "pe_machine",
            "security_descriptor_sha256",
            "reparse_point",
        }
        or requested.get("sha256") != executable["sha256"]
        or requested.get("size_bytes") != executable["size_bytes"]
        or requested.get("pe_machine") != "aarch64"
        or requested.get("reparse_point") is not False
        or re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{16}", str(requested.get("file_id", "")))
        is None
        or not _valid_sha(requested.get("security_descriptor_sha256"))
    ):
        _fail("WIN25-ARTIFACT", "requested runtime identity differs")
    staged = boundary["staged_files"]
    if not isinstance(staged, list):
        _fail("WIN25-ARTIFACT", "staged inventory is absent")
    actual: set[str] = set()
    for row in staged:
        artifact = _validate_staged_artifact(row)
        destination = artifact["destination"]
        if destination.casefold() in {name.casefold() for name in actual}:
            _fail("WIN25-ARTIFACT", "staged destinations are duplicated")
        actual.add(destination)
    expected_staged = _expected_staged(closure, corpus, expected)
    if actual != set(expected_staged) or [
        row["destination"] for row in staged
    ] != sorted(expected_staged):
        _fail("WIN25-ARTIFACT", "staged artifact inventory differs")
    staged_content = [
        [destination, sha256, size_bytes, machine]
        for destination, (sha256, size_bytes, machine) in sorted(
            expected_staged.items()
        )
    ]
    if boundary["staged_content_identity"] != domain_hash(
        "proofbound-research-windows-staged-content/1", staged_content
    ):
        _fail("WIN25-ARTIFACT", "staged content identity differs")
    captured = boundary["captured_files"]
    if not isinstance(captured, list) or len(captured) != 1:
        _fail("WIN25-POSITIVE", "captured output inventory differs")
    return _validate_output(captured[0], expected["kind"] == "positive")


def _denial_marker(mode: str, stderr: str) -> bool:
    markers = {
        "env-undeclared": (
            "PB_UNDECLARED_VALUE",
            "undeclared environment denied",
            "NotPresent",
        ),
        "exec-unregistered": (
            "Access is denied",
            "access is denied",
            "EACCES",
            "EPERM",
            "spawnSync",
            "os error 5",
        ),
        "network": (
            "forbidden by its access permissions",
            "PermissionDenied",
            "Permission denied",
            "EACCES",
            "EPERM",
            "connect",
        ),
        "read-undeclared": (
            "PermissionDenied",
            "Permission denied",
            "Access is denied",
            "EACCES",
            "EPERM",
            "os error 5",
        ),
        "write-reviewed": (
            "PermissionDenied",
            "Permission denied",
            "Access is denied",
            "EACCES",
            "EPERM",
            "os error 5",
        ),
        "write-escape": (
            "PermissionDenied",
            "Permission denied",
            "Access is denied",
            "EACCES",
            "EPERM",
            "os error 5",
        ),
    }
    return any(marker in stderr for marker in markers[mode])


def _validate_slot(
    value: object,
    expected: dict[str, Any],
    closure: dict[str, Any],
    corpus: dict[str, dict[str, Any]],
) -> str:
    slot = _exact_keys(
        value,
        {
            "schema",
            "slot_id",
            "kind",
            "subject_id",
            "runtime",
            "repetition",
            "attack_id",
            "mode",
            "attack_path",
            "denial_mechanism",
            "closure_identity",
            "policy",
            "logical_command",
            "attack_target",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "registered_child_identity",
            "boundary",
            "operation_reached",
            "outcome",
            "reusable",
            "identity",
        },
        "WIN25-SLOT-INVENTORY",
    )
    if slot["schema"] != SLOT_SCHEMA or any(
        slot.get(key) != item for key, item in expected.items()
    ):
        _fail("WIN25-SLOT-INVENTORY", "slot binding differs")
    if slot["closure_identity"] != closure["identity"]:
        _fail("WIN25-CLOSURE-IDENTITY", "slot closure binding differs")
    if slot["identity"] != domain_hash(SLOT_SCHEMA, _without_identity(slot)):
        _fail("WIN25-SLOT-IDENTITY", "slot identity differs")
    runtime = closure["runtime_closures"][expected["runtime"]]
    policy = _expected_policy(
        expected["runtime"], runtime["executable"]["sha256"], expected
    )
    if slot["policy"] != policy:
        _fail("WIN25-POLICY", "effective slot policy differs")
    _, source_path = SUBJECTS[expected["subject_id"]]
    expected_command = [
        expected["runtime"],
        f"subjects/{Path(source_path).name}" if expected["runtime"] != "rust" else None,
        expected["mode"],
        "registered.txt",
        "outputs/output.txt",
        expected["attack_path"],
        "1",
    ]
    if slot["logical_command"] != expected_command:
        _fail("WIN25-POLICY", "logical workload command differs")
    _validate_target(slot["attack_target"], expected)
    if slot["reviewed_tree_before"] != slot["reviewed_tree_after"]:
        _fail("WIN25-TREE", "slot reviewed tree changed")
    helper = closure["instruments"]["registered_child_executable"]["sha256"]
    expected_helper = helper if expected["mode"] == "exec-unregistered" else None
    if slot["registered_child_identity"] != expected_helper:
        _fail("WIN25-DRIVE-ALIAS", "registered child identity differs")
    output_exact = _validate_boundary(slot["boundary"], closure, corpus, expected)
    boundary = slot["boundary"]
    positive = expected["kind"] == "positive"
    exit_code = boundary["exit_code"]
    entered = (
        isinstance(exit_code, int)
        and exit_code not in INITIALIZATION_FAILURES
        and boundary["child_token"]["verified_before_resume"] is True
    )
    if slot["operation_reached"] is not entered:
        _fail("WIN25-PROCESS-CREATION", "operation reachability differs")
    if positive:
        completed = (
            entered
            and exit_code == 0
            and boundary["stdout"] == ""
            and boundary["stderr"] == ""
            and output_exact
        )
        if slot["outcome"] != ("completed" if completed else "incomplete"):
            _fail("WIN25-POSITIVE", "positive outcome classification differs")
        if slot["reusable"] is not completed:
            _fail("WIN25-POSITIVE", "positive reuse classification differs")
        return boundary["profile"]
    if slot["reusable"] is not False:
        _fail("WIN25-DENIED-REUSABLE", "denied execution became reusable")
    denied = (
        entered
        and exit_code != 0
        and boundary["stdout"] == ""
        and isinstance(boundary["stderr"], str)
        and _denial_marker(expected["mode"], boundary["stderr"])
        and not output_exact
        and boundary["captured_files"]
        == [{"path": "outputs/output.txt", "present": False}]
    )
    if slot["outcome"] != ("denied" if denied else "incomplete"):
        _fail("WIN25-DENIAL", "authority outcome classification differs")
    return boundary["profile"]


def _validate_capture(repository: Path, value: object) -> dict[str, Any]:
    capture = _exact_keys(
        value,
        {
            "schema",
            "experiment",
            "programme_experiment",
            "contract_sha256",
            "candidate_sha256",
            "execution_environment",
            "fallback_used",
            "host",
            "closure",
            "slots",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "elapsed_ms",
            "within_elapsed_ceiling",
            "identity",
        },
        "WIN25-CAPTURE-SCHEMA",
    )
    if capture["schema"] != CAPTURE_SCHEMA:
        _fail("WIN25-CAPTURE-SCHEMA", "capture schema differs")
    if (
        capture["experiment"] != "EXP-0025"
        or capture["programme_experiment"] != "EXP-LANG-018"
    ):
        _fail("WIN25-DISCRIMINATOR", "experiment discriminator differs")
    if capture["contract_sha256"] != CONTRACT_SHA256:
        _fail("WIN25-CONTRACT", "frozen contract differs")
    candidate_sha = sha256_bytes((repository / CANDIDATE_PATH).read_bytes())
    if capture["candidate_sha256"] != candidate_sha:
        _fail("WIN25-CANDIDATE", "candidate identity differs")
    if (
        capture["execution_environment"] != "github-windows-11-arm-native"
        or capture["fallback_used"] is not False
    ):
        _fail("WIN25-FALLBACK", "execution environment substituted or fell back")
    host = capture["host"]
    if (
        not isinstance(host, dict)
        or host.get("os") != "windows"
        or host.get("architecture") != "aarch64"
        or not isinstance(host.get("release"), str)
        or not isinstance(host.get("version"), str)
    ):
        _fail("WIN25-PLATFORM", "host is not native Windows 11 ARM64")
    closure, corpus = _validate_closure(repository, capture["closure"])
    if capture["candidate_sha256"] != closure["candidate_sha256"]:
        _fail("WIN25-CANDIDATE", "capture and closure candidates differ")
    expected_slots = _expected_slots()
    slots = capture["slots"]
    if not isinstance(slots, list) or len(slots) != len(expected_slots):
        _fail("WIN25-SLOT-INVENTORY", "slot count differs")
    profiles = [
        _validate_slot(slot, expected, closure, corpus)
        for slot, expected in zip(slots, expected_slots, strict=True)
    ]
    if len(profiles) != len(set(profiles)):
        _fail("WIN25-FRESHNESS", "AppContainer profile was reused")
    if capture["reviewed_tree_before"] != capture["reviewed_tree_after"]:
        _fail("WIN25-TREE", "frozen reviewed tree changed")
    if (
        not isinstance(capture["elapsed_ms"], int)
        or capture["elapsed_ms"] < 0
        or capture["elapsed_ms"] > MAX_ELAPSED_MS
        or capture["within_elapsed_ceiling"] is not True
    ):
        _fail("WIN25-ELAPSED", "confirmation exceeded its frozen ceiling")
    if capture["identity"] != domain_hash(CAPTURE_SCHEMA, _without_identity(capture)):
        _fail("WIN25-CAPTURE-SCHEMA", "capture identity differs")
    positives = sum(slot["outcome"] == "completed" for slot in slots)
    denials = sum(slot["outcome"] == "denied" for slot in slots)
    denied_reusable = sum(
        slot["kind"] == "authority-probe" and slot["reusable"] is True for slot in slots
    )
    return {
        "capture": capture,
        "closure": closure,
        "metrics": {
            "positive_executions": positives,
            "authority_probe_executions": denials,
            "denied_reusable": denied_reusable,
            "reviewed_tree_changed": capture["reviewed_tree_before"]
            != capture["reviewed_tree_after"],
            "elapsed_ms": capture["elapsed_ms"],
        },
    }


def validate_capture(value: object, repository: Path) -> dict[str, Any]:
    """Validate a decoded capture and derive its canonical report."""

    validated = _validate_capture(repository, value)
    capture = validated["capture"]
    metrics = validated["metrics"]
    questions = {
        "Q1": all(slot["operation_reached"] for slot in capture["slots"]),
        "Q2": metrics["positive_executions"] == 30,
        "Q3": metrics["authority_probe_executions"] == 21
        and metrics["denied_reusable"] == 0,
        "Q4": capture["closure"]["frozen_before_first_slot"] is True,
        "Q5": metrics["reviewed_tree_changed"] is False,
    }
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "contract_sha256": CONTRACT_SHA256,
        "candidate_sha256": capture["candidate_sha256"],
        "availability": "supported",
        "capture_identity": capture["identity"],
        "closure_identity": validated["closure"]["identity"],
        "platform": capture["host"],
        "questions": questions,
        "policy_attacks": [
            {
                "id": attack_id,
                "expected_code": code,
                "actual_code": code,
                "exact": True,
            }
            for attack_id, code in ATTACKS
        ],
        "metrics": metrics,
    }
    report["identity"] = domain_hash(REPORT_SCHEMA, report)
    return report


def validate_capture_bytes(repository: Path, payload: bytes) -> dict[str, Any]:
    """Validate canonical capture bytes and frozen repository artifacts."""

    if len(payload) > MAX_REPORT_BYTES:
        _fail("WIN25-CAPTURE-SCHEMA", "capture exceeds its frozen byte ceiling")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise WindowsInitializationError("WIN25-CAPTURE-SCHEMA", str(issue)) from issue
    if canonical_json(value) != payload:
        _fail("WIN25-CAPTURE-SCHEMA", "capture is not canonical JSON")
    contract = repository / CORPUS_PATH / "contract.json"
    if sha256_bytes(contract.read_bytes()) != CONTRACT_SHA256:
        _fail("WIN25-CONTRACT", "registered contract bytes differ")
    return validate_capture(value, repository)


def main(argv: list[str] | None = None) -> int:
    """Validate one EXP-0025 capture into a canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_initialization_research REPOSITORY CAPTURE REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(arguments[0]), Path(arguments[1]).read_bytes()
        )
        Path(arguments[2]).write_bytes(canonical_json(report))
    except (OSError, WindowsInitializationError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
