"""Execute the frozen EXP-0025 corpus on native Windows 11 ARM64."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import time
from typing import Any
import zipfile

from proofbound.windows_enforcement_execute import (
    canonical_json,
    domain_hash,
    sha256_bytes,
)
from proofbound.windows_native_boundary import (
    WindowsBoundaryOptions,
    pe_machine,
    run_appcontainer_process,
)
from proofbound.windows_python_closure_discovery import (
    build_standard_library_archive,
    native_runtime_files,
)


CAPTURE_SCHEMA = "proofbound-research-windows-initialization-capture/1"
CLOSURE_SCHEMA = "proofbound-research-windows-initialization-closure/1"
POLICY_SCHEMA = "proofbound-research-windows-initialization-policy/1"
SLOT_SCHEMA = "proofbound-research-windows-initialization-slot/1"
CONTRACT_SHA256 = (
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d"
)
CANDIDATE_PATH = Path(
    "docs/experiments/0025-windows-initialization-closure/candidate.json"
)
CORPUS_PATH = Path("docs/experiments/0018-os-enforced-effects/corpus")
EXPECTED_OUTPUT = b"registered-input|registered-env\n"
PYTHON_VERSION = "3.12.10"
NODE_VERSION = "24.20.0"
RUST_VERSION = "1.94.0"
DRIVE_ALIAS = "P:"
MAX_INITIALIZATION_ARTIFACTS = 512
MAX_REPORT_BYTES = 524_288
MAX_ELAPSED_MS = 60_000
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


@dataclass(frozen=True)
class Runtime:
    """One runtime closure sealed before the first confirmation slot."""

    name: str
    executable: Path
    staged_files: tuple[tuple[Path, str], ...]
    environment: dict[str, str]
    identity: dict[str, Any]


def _artifact(path: Path, logical_name: str) -> dict[str, Any]:
    """Return a portable pre-execution identity for one regular file."""

    metadata = path.stat(follow_symlinks=False)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if path.is_symlink() or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"registered artifact is a reparse point: {logical_name}")
    if not path.is_file():
        raise ValueError(f"registered artifact is not a file: {logical_name}")
    payload = path.read_bytes()
    return {
        "logical_name": logical_name,
        "requested_path": str(path),
        "resolved_path": str(path.resolve(strict=True)),
        "sha256": sha256_bytes(payload),
        "size_bytes": len(payload),
        "pe_machine": pe_machine(payload),
        "reparse_point": False,
    }


def _tree_snapshot(root: Path) -> list[dict[str, Any]]:
    """Return a canonical path-and-byte inventory with no reparse points."""

    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.stat(follow_symlinks=False)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if path.is_symlink() or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f"reparse point in reviewed tree: {relative}")
        if path.is_dir():
            rows.append({"path": relative, "kind": "directory"})
        elif path.is_file():
            payload = path.read_bytes()
            rows.append(
                {
                    "path": relative,
                    "kind": "file",
                    "sha256": sha256_bytes(payload),
                    "size_bytes": len(payload),
                }
            )
        else:
            raise ValueError(f"special entry in reviewed tree: {relative}")
    return rows


def _tree_identity(root: Path) -> str:
    return domain_hash("proofbound-research-windows-tree/1", _tree_snapshot(root))


def _strict_tool_output(arguments: list[str]) -> str:
    process = subprocess.run(arguments, check=True, capture_output=True, timeout=120)
    if process.stderr or not process.stdout.endswith(b"\n"):
        raise ValueError(
            f"tool identity output differs: {arguments[0]}: "
            f"stdout={process.stdout!r} stderr={process.stderr!r}"
        )
    value = process.stdout[:-1]
    if value.endswith(b"\r"):
        value = value[:-1]
    if not value or b"\r" in value or b"\n" in value:
        raise ValueError(f"tool identity is not one canonical line: {arguments[0]}")
    return value.decode("utf-8", errors="strict")


def _rust_compiler() -> Path:
    """Resolve the installed compiler behind rustup before measuring it."""

    process = subprocess.run(
        ["rustup", "which", "--toolchain", RUST_VERSION, "rustc"],
        check=True,
        capture_output=True,
        timeout=120,
    )
    if process.stderr or not process.stdout.endswith(b"\n"):
        raise ValueError(
            "rustup did not return one silent compiler path: "
            f"stdout={process.stdout!r} stderr={process.stderr!r}"
        )
    path = Path(process.stdout[:-1].decode("utf-8", errors="strict"))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("rustup returned an unsafe compiler path")
    return path.resolve(strict=True)


def _compile_rust(compiler: Path, source: Path, destination: Path) -> None:
    process = subprocess.run(
        [
            str(compiler),
            "--edition",
            "2021",
            "-C",
            "debuginfo=0",
            str(source),
            "-o",
            str(destination),
        ],
        check=True,
        capture_output=True,
        timeout=180,
    )
    if process.stdout or process.stderr:
        raise ValueError("rustc emitted unexpected output")


def _corpus_inventory(repository: Path) -> list[dict[str, Any]]:
    index_path = repository / CORPUS_PATH / "index.json"
    index = json.loads(index_path.read_bytes())
    if index.get("schema") != "proofbound-research-enforced-corpus/1":
        raise ValueError("frozen corpus index schema differs")
    rows = index.get("files")
    if not isinstance(rows, list):
        raise ValueError("frozen corpus file inventory is absent")
    for row in rows:
        path = repository / CORPUS_PATH / row["path"]
        payload = path.read_bytes()
        if sha256_bytes(payload) != row["sha256"] or len(payload) != row["size_bytes"]:
            raise ValueError(f"frozen corpus artifact changed: {row['path']}")
    return rows


def _build_runtimes(
    repository: Path, build_root: Path
) -> tuple[dict[str, Runtime], dict[str, Any]]:
    """Construct and identity-bind all runtime artifacts before confirmation."""

    python_version = platform.python_version()
    if python_version != PYTHON_VERSION:
        raise ValueError(f"Python identity differs: {python_version}")
    node_text = _strict_tool_output(["node", "--version"])
    if node_text != f"v{NODE_VERSION}":
        raise ValueError(f"Node identity differs: {node_text}")
    rustc_executable = _rust_compiler()
    rust_text = _strict_tool_output([str(rustc_executable), "--version"])
    if not rust_text.startswith(f"rustc {RUST_VERSION} "):
        raise ValueError(f"Rust identity differs: {rust_text}")

    node_executable_text = shutil.which("node")
    if node_executable_text is None:
        raise OSError("a frozen runtime executable is unavailable")
    node_executable = Path(node_executable_text)
    python_executable = Path(sys.executable)

    corpus = repository / CORPUS_PATH
    rust_source = corpus / "workspace/subjects/rust_subject.rs"
    rust_binary = build_root / "rust_subject.exe"
    _compile_rust(rustc_executable, rust_source, rust_binary)
    helper_source = build_root / "registered_true.rs"
    helper_source.write_bytes(b"fn main() {}\n")
    helper_binary = build_root / "registered_true.exe"
    _compile_rust(rustc_executable, helper_source, helper_binary)

    runtime_root = python_executable.parent
    archive_name = "python312.zip"
    archive = build_root / archive_name
    pure_module_count = build_standard_library_archive(runtime_root / "Lib", archive)
    python_native = tuple(
        (path, destination)
        for path, destination in native_runtime_files(runtime_root)
        if pe_machine(path.read_bytes()) == "aarch64"
    )
    python_staged = (*python_native, (archive, archive_name))
    if len(python_staged) + 4 > MAX_INITIALIZATION_ARTIFACTS:
        raise ValueError("Python initialization closure exceeds its frozen ceiling")

    platform_environment = {
        "PB_REGISTERED_VALUE": "registered-env",
        "SystemDrive": os.environ["SystemDrive"],
        "SystemRoot": os.environ["SystemRoot"],
    }
    python_environment = {
        **platform_environment,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHOME": "{APPLICATION_ROOT}",
        "PYTHONPATH": ("{APPLICATION_ROOT}/python312.zip;{APPLICATION_ROOT}/DLLs"),
    }
    runtimes = {
        "node": Runtime(
            "node",
            node_executable,
            (),
            platform_environment,
            {
                "version": NODE_VERSION,
                "version_output": node_text,
                "executable": _artifact(node_executable, "runtime/node.exe"),
                "staged_layout": ["node.exe"],
            },
        ),
        "python": Runtime(
            "python",
            python_executable,
            python_staged,
            python_environment,
            {
                "version": PYTHON_VERSION,
                "executable": _artifact(python_executable, "runtime/python/python.exe"),
                "native_artifacts": [
                    _artifact(path, f"runtime/python/{destination}")
                    for path, destination in python_staged
                ],
                "pure_python_modules": pure_module_count,
                "site_packages": "excluded",
            },
        ),
        "rust": Runtime(
            "rust",
            rust_binary,
            (),
            platform_environment,
            {
                "toolchain": RUST_VERSION,
                "version_output": rust_text,
                "compiler": _artifact(rustc_executable, "tool/rustc.exe"),
                "source": _artifact(rust_source, "source/rust_subject.rs"),
                "executable": _artifact(rust_binary, "runtime/rust_subject.exe"),
            },
        ),
    }
    instruments = {
        "registered_child_source": _artifact(
            helper_source, "instrument/registered_true.rs"
        ),
        "registered_child_executable": _artifact(
            helper_binary, "instrument/registered_true.exe"
        ),
    }
    return runtimes, instruments


def _closure(
    repository: Path,
    runtimes: dict[str, Runtime],
    instruments: dict[str, Any],
) -> dict[str, Any]:
    candidate = repository / CANDIDATE_PATH
    body = {
        "schema": CLOSURE_SCHEMA,
        "candidate_sha256": sha256_bytes(candidate.read_bytes()),
        "contract_sha256": CONTRACT_SHA256,
        "frozen_before_first_slot": True,
        "corpus": _corpus_inventory(repository),
        "boundary": {
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
        },
        "runtime_closures": {
            name: runtime.identity for name, runtime in sorted(runtimes.items())
        },
        "instruments": instruments,
        "environment": {
            "workload": ["PB_REGISTERED_VALUE"],
            "platform": ["SystemDrive", "SystemRoot"],
            "python": ["PYTHONDONTWRITEBYTECODE", "PYTHONHOME", "PYTHONPATH"],
            "boundary_added": ["LOCALAPPDATA", "TEMP", "TMP"],
            "undeclared_present": False,
        },
        "slot_inventory": {
            "positive": 30,
            "authority_probes": 21,
            "subjects": sorted(SUBJECTS),
            "probes": [list(row) for row in PROBES],
        },
    }
    body["identity"] = domain_hash(CLOSURE_SCHEMA, body)
    return body


def _slot_definitions() -> list[dict[str, Any]]:
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


def _policy(runtime: Runtime, slot: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": POLICY_SCHEMA,
        "subject_id": slot["subject_id"],
        "runtime": runtime.name,
        "runtime_identity": runtime.identity["executable"]["sha256"],
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
        "process_creation": {
            "suspended": True,
            "create_no_window": False,
        },
        "filesystem": {
            "application_root": "fresh-profile-owned",
            "registered_reads": ["registered.txt", "subjects/<subject>"],
            "ephemeral_writes": ["outputs/output.txt"],
            "reviewed_tree": "outside-package-sid-authority",
            "reparse_points": "rejected",
        },
        "environment": sorted(runtime.environment),
        "unregistered_child": {
            "logical_path": "/usr/bin/true",
            "drive_alias": DRIVE_ALIAS,
            "denied_by": "job-active-process-limit",
        },
    }
    body["identity"] = domain_hash(POLICY_SCHEMA, body)
    return body


def _runtime_command(
    runtime: Runtime,
    source_destination: str,
    slot: dict[str, Any],
    attack_path: Path,
) -> list[str]:
    root = "{APPLICATION_ROOT}"
    tail = [
        slot["mode"],
        f"{root}/registered.txt",
        f"{root}/outputs/output.txt",
        str(attack_path),
        "1",
    ]
    if runtime.name == "python":
        return [
            runtime.executable.as_posix(),
            "-S",
            f"{root}/{source_destination}",
            *tail,
        ]
    if runtime.name == "node":
        return [runtime.executable.as_posix(), f"{root}/{source_destination}", *tail]
    return [runtime.executable.as_posix(), *tail]


def _compact_boundary(result: dict[str, Any]) -> dict[str, Any]:
    ordered = sorted(result["staged_files"], key=lambda row: row["destination"])
    staged = [
        {
            key: row[key]
            for key in (
                "destination",
                "file_id",
                "security_descriptor_sha256",
                "reparse_point",
            )
        }
        for row in ordered
    ]
    staged_content = [
        [row["destination"], row["sha256"], row["size_bytes"], row["pe_machine"]]
        for row in ordered
    ]
    return {
        "profile": result["profile"],
        "window_station": result["window_station"],
        "application_staged": result["application_staged"],
        "application_root": result["application_root"],
        "requested_application_identity": result["requested_application_identity"],
        "staged_files": staged,
        "staged_content_identity": domain_hash(
            "proofbound-research-windows-staged-content/1", staged_content
        ),
        "captured_files": result["captured_files"],
        "drive_alias": result["drive_alias"],
        "drive_alias_target": result["drive_alias_target"],
        "appcontainer_sid": result["appcontainer_sid"],
        "restricted_token": result["restricted_token"],
        "administrator_sids": result["administrator_sids"],
        "integrity_level": result["integrity_level"],
        "child_token": result["child_token"],
        "job": result["job"],
        "create_no_window": result["create_no_window"],
        "exit_code": result["exit_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }


def _attack_target(
    workspace: Path, state_root: Path, slot: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    logical = slot["attack_path"]
    if logical == "/usr/bin/true":
        path = Path(f"{DRIVE_ALIAS}/usr/bin/true")
        return path, {"logical_name": logical, "kind": "registered-child-image"}
    if logical == "state/escape.txt":
        path = state_root / "escape" / f"{slot['slot_id']}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path, {
            "logical_name": logical,
            "requested_path": str(path),
            "present_before": False,
        }
    relative = logical.removeprefix("workspace/")
    path = workspace / relative
    return path, {
        **_artifact(path, logical),
    }


def _execute_slot(
    repository: Path,
    state_root: Path,
    runtime: Runtime,
    instruments: dict[str, Any],
    helper_binary: Path,
    slot: dict[str, Any],
    closure_identity: str,
) -> dict[str, Any]:
    workspace = state_root / "reviewed" / slot["slot_id"]
    shutil.copytree(repository / CORPUS_PATH / "workspace", workspace, symlinks=True)
    before = _tree_identity(workspace)
    attack_path, target = _attack_target(workspace, state_root, slot)
    _, subject_relative = SUBJECTS[slot["subject_id"]]
    subject = repository / CORPUS_PATH / subject_relative
    source_destination = f"subjects/{subject.name}"
    staged = [
        *runtime.staged_files,
        (subject, source_destination),
        (workspace / "registered.txt", "registered.txt"),
    ]
    drive_alias = DRIVE_ALIAS
    if slot["mode"] == "exec-unregistered":
        staged.append((helper_binary, "usr/bin/true.exe"))
    command = _runtime_command(runtime, source_destination, slot, attack_path)
    policy = _policy(runtime, slot)
    result = run_appcontainer_process(
        command,
        runtime.executable.parent,
        runtime.environment,
        timeout_ms=10_000,
        stage_application=True,
        staged_files=tuple(staged),
        captured_files=("outputs/output.txt",),
        options=WindowsBoundaryOptions(
            active_process_limit=1,
            private_desktop=True,
            create_no_window=False,
            drive_alias=drive_alias,
        ),
    )
    after = _tree_identity(workspace)
    output = result["captured_files"][0]
    positive = slot["kind"] == "positive"
    completed = (
        positive
        and result["exit_code"] == 0
        and result["stdout"] == ""
        and result["stderr"] == ""
        and output.get("present") is True
        and output.get("sha256") == sha256_bytes(EXPECTED_OUTPUT)
        and output.get("size_bytes") == len(EXPECTED_OUTPUT)
    )
    denied = (
        not positive
        and result["exit_code"] != 0
        and result["stdout"] == ""
        and result["stderr"] != ""
        and output == {"path": "outputs/output.txt", "present": False}
    )
    runtime_entered = result["child_token"][
        "verified_before_resume"
    ] is True and result["exit_code"] not in {0xC0000135, 0xC0000142}
    target["present_after"] = attack_path.exists()
    if (
        attack_path.exists()
        and attack_path.is_file()
        and slot["mode"] != "exec-unregistered"
    ):
        target["sha256_after"] = sha256_bytes(attack_path.read_bytes())
        target["size_bytes_after"] = attack_path.stat().st_size
    body = {
        "schema": SLOT_SCHEMA,
        **slot,
        "closure_identity": closure_identity,
        "policy": policy,
        "logical_command": [
            runtime.name,
            source_destination if runtime.name != "rust" else None,
            slot["mode"],
            "registered.txt",
            "outputs/output.txt",
            slot["attack_path"],
            "1",
        ],
        "attack_target": target,
        "reviewed_tree_before": before,
        "reviewed_tree_after": after,
        "registered_child_identity": (
            instruments["registered_child_executable"]["sha256"]
            if slot["mode"] == "exec-unregistered"
            else None
        ),
        "boundary": _compact_boundary(result),
        "operation_reached": runtime_entered,
        "outcome": "completed" if completed else "denied" if denied else "incomplete",
        "reusable": completed,
    }
    body["identity"] = domain_hash(SLOT_SCHEMA, body)
    return body


def capture(repository: Path, state_root: Path) -> dict[str, Any]:
    """Execute all 51 frozen slots without expanding the sealed closure."""

    repository = repository.resolve()
    state_root = state_root.resolve()
    if os.name != "nt":
        raise OSError("EXP-0025 requires native Windows")
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if platform.system().lower() != "windows" or architecture != "aarch64":
        raise OSError("EXP-0025 requires native Windows 11 ARM64")
    if state_root.exists():
        raise ValueError("state root must be absent")
    state_root.mkdir(parents=True)
    build_root = state_root / "build"
    build_root.mkdir()
    runtimes, instruments = _build_runtimes(repository, build_root)
    closure = _closure(repository, runtimes, instruments)
    closure_identity = closure["identity"]
    helper_binary = build_root / "registered_true.exe"
    definitions = _slot_definitions()
    if len(definitions) != 51:
        raise AssertionError("frozen slot inventory differs")
    reviewed_before = _tree_identity(repository / CORPUS_PATH / "workspace")
    started = time.monotonic()
    slots = [
        _execute_slot(
            repository,
            state_root,
            runtimes[slot["runtime"]],
            instruments,
            helper_binary,
            slot,
            closure_identity,
        )
        for slot in definitions
    ]
    elapsed_ms = int((time.monotonic() - started) * 1000)
    reviewed_after = _tree_identity(repository / CORPUS_PATH / "workspace")
    body = {
        "schema": CAPTURE_SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "contract_sha256": CONTRACT_SHA256,
        "candidate_sha256": closure["candidate_sha256"],
        "execution_environment": "github-windows-11-arm-native",
        "fallback_used": False,
        "host": {
            "os": "windows",
            "architecture": architecture,
            "release": platform.release(),
            "version": platform.version(),
        },
        "closure": closure,
        "slots": slots,
        "reviewed_tree_before": reviewed_before,
        "reviewed_tree_after": reviewed_after,
        "elapsed_ms": elapsed_ms,
        "within_elapsed_ceiling": elapsed_ms <= MAX_ELAPSED_MS,
    }
    body["identity"] = domain_hash(CAPTURE_SCHEMA, body)
    encoded = canonical_json(body)
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError(f"capture exceeds frozen report ceiling: {len(encoded)} bytes")
    return body


def main(argv: list[str] | None = None) -> int:
    """Write one canonical native EXP-0025 capture."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_initialization_execute REPOSITORY FRESH_STATE CAPTURE",
            file=sys.stderr,
        )
        return 2
    try:
        value = capture(Path(arguments[0]), Path(arguments[1]))
        Path(arguments[2]).write_bytes(canonical_json(value))
        print(
            json.dumps(
                {
                    "elapsed_ms": value["elapsed_ms"],
                    "positive": sum(
                        slot["outcome"] == "completed" for slot in value["slots"]
                    ),
                    "denied": sum(
                        slot["outcome"] == "denied" for slot in value["slots"]
                    ),
                    "size_bytes": len(canonical_json(value)),
                },
                sort_keys=True,
            )
        )
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
    ) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
