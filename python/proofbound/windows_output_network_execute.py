"""Execute the frozen EXP-0026 Windows confirmation corpus."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import socket
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
from proofbound import windows_initialization_execute as initialization
from proofbound.windows_native_boundary import loopback_exempt_appcontainer_sids


CAPTURE_SCHEMA = "proofbound-research-windows-output-network-capture/1"
ORACLE_SCHEMA = "proofbound-research-windows-network-oracle/1"
CORPUS_PATH = Path("docs/experiments/0026-windows-output-network-confirmation/corpus")
PYTHON_SUBJECT = CORPUS_PATH / "python_subject.py"
EXPECTED_PATH = CORPUS_PATH / "expected.json"
INDEX_PATH = CORPUS_PATH / "index.json"
EXPECTED_NETWORK_OUTPUT = b"network-observed\n"
MAX_CAPTURE_BYTES = 524_288
MAX_ELAPSED_MS = 60_000


def _effective_corpus_inventory(repository: Path) -> list[dict[str, Any]]:
    """Validate and return the EXP-0018 inventory with its Python replacement."""

    successor = json.loads((repository / INDEX_PATH).read_bytes())
    if successor.get("schema") != "proofbound-research-windows-output-network-corpus/1":
        raise ValueError("EXP-0026 corpus schema differs")
    for row in successor.get("files", []):
        payload = (repository / CORPUS_PATH / row["path"]).read_bytes()
        if sha256_bytes(payload) != row["sha256"] or len(payload) != row["size_bytes"]:
            raise ValueError(f"EXP-0026 corpus artifact changed: {row['path']}")
    base = initialization._corpus_inventory(repository)
    replacement = successor.get("replacements")
    if not isinstance(replacement, list) or len(replacement) != 1:
        raise ValueError("EXP-0026 replacement inventory differs")
    replacement_row = replacement[0]
    if replacement_row.get("base_path") != "workspace/subjects/python_subject.py":
        raise ValueError("EXP-0026 Python replacement target differs")
    return [
        {
            **row,
            "sha256": replacement_row["sha256"],
            "size_bytes": replacement_row["size_bytes"],
        }
        if row["path"] == replacement_row["base_path"]
        else row
        for row in base
    ]


def _effective_tree_identity(repository: Path) -> str:
    """Return the base workspace identity after applying the frozen overlay."""

    workspace = repository / initialization.CORPUS_PATH / "workspace"
    rows = initialization._tree_snapshot(workspace)
    payload = (repository / PYTHON_SUBJECT).read_bytes()
    expected_path = "subjects/python_subject.py"
    changed = False
    for row in rows:
        if row["path"] == expected_path:
            row["sha256"] = sha256_bytes(payload)
            row["size_bytes"] = len(payload)
            changed = True
    if not changed:
        raise ValueError("base Python subject is absent")
    return domain_hash("proofbound-research-windows-tree/1", rows)


def _closure(
    repository: Path,
    runtimes: dict[str, initialization.Runtime],
    instruments: dict[str, Any],
) -> dict[str, Any]:
    """Build the retained initialization closure over the revised corpus."""

    value = initialization._closure(repository, runtimes, instruments)
    value["corpus"] = _effective_corpus_inventory(repository)
    value["identity"] = domain_hash(
        initialization.CLOSURE_SCHEMA,
        {name: field for name, field in value.items() if name != "identity"},
    )
    return value


def _control_environment(
    runtime: initialization.Runtime, application_root: Path
) -> dict[str, str]:
    """Construct the exact registered environment for an unsandboxed control."""

    temporary = application_root / "Temp"
    temporary.mkdir()
    root = str(application_root)
    values = {
        name: value.replace("{APPLICATION_ROOT}", root)
        for name, value in runtime.environment.items()
    }
    values.update(
        {
            "LOCALAPPDATA": root,
            "TEMP": str(temporary),
            "TMP": str(temporary),
        }
    )
    return values


def _stage_control(
    repository: Path,
    state_root: Path,
    runtime: initialization.Runtime,
) -> tuple[Path, str, dict[str, str]]:
    """Stage the same runtime and subject identities outside AppContainer."""

    root = state_root / "network-controls" / runtime.name
    root.mkdir(parents=True)
    executable = root / runtime.executable.name
    shutil.copy2(runtime.executable, executable)
    for source, relative in runtime.staged_files:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.resolve(strict=False) != executable.resolve(strict=False):
            shutil.copy2(source, destination)
    _, base_subject = initialization.SUBJECTS[f"subject:{runtime.name}"]
    source = (
        repository / PYTHON_SUBJECT
        if runtime.name == "python"
        else repository / initialization.CORPUS_PATH / base_subject
    )
    source_destination = f"subjects/{source.name}"
    staged_source = root / source_destination
    staged_source.parent.mkdir()
    shutil.copy2(source, staged_source)
    shutil.copy2(
        repository / initialization.CORPUS_PATH / "workspace/registered.txt",
        root / "registered.txt",
    )
    (root / "outputs").mkdir()
    return executable, source_destination, _control_environment(runtime, root)


def _control_command(
    executable: Path,
    runtime: initialization.Runtime,
    root: Path,
    source_destination: str,
    port: int,
) -> list[str]:
    tail = [
        "network",
        str(root / "registered.txt"),
        str(root / "outputs/output.txt"),
        str(root / "unrelated.txt"),
        str(port),
    ]
    if runtime.name == "python":
        return [str(executable), "-S", str(root / source_destination), *tail]
    if runtime.name == "node":
        return [str(executable), str(root / source_destination), *tail]
    return [str(executable), *tail]


def _run_network_control(
    repository: Path,
    state_root: Path,
    runtime: initialization.Runtime,
    listener: socket.socket,
    port: int,
) -> dict[str, Any]:
    executable, source_destination, environment = _stage_control(
        repository, state_root, runtime
    )
    root = executable.parent
    command = _control_command(executable, runtime, root, source_destination, port)
    process = subprocess.Popen(
        command,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    listener_accepted = _accept(listener, 2.0)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    output_path = root / "outputs/output.txt"
    output = output_path.read_bytes() if output_path.is_file() else None
    return {
        "logical_command": [
            runtime.name,
            source_destination if runtime.name != "rust" else None,
            "network",
            "registered.txt",
            "outputs/output.txt",
            "workspace/unrelated.txt",
            str(port),
        ],
        "runtime_sha256": sha256_bytes(executable.read_bytes()),
        "subject_sha256": sha256_bytes((root / source_destination).read_bytes())
        if runtime.name != "rust"
        else runtime.identity["source"]["sha256"],
        "exit_code": process.returncode,
        "stdout": stdout.decode("utf-8", errors="strict"),
        "stderr": stderr.decode("utf-8", errors="strict"),
        "output_sha256": sha256_bytes(output) if output is not None else None,
        "output_size_bytes": len(output) if output is not None else None,
        "completed": process.returncode == 0
        and not stdout
        and not stderr
        and output == EXPECTED_NETWORK_OUTPUT,
        "reusable": False,
        "listener_accepted": listener_accepted,
    }


def _accept(listener: socket.socket, timeout: float) -> bool:
    listener.settimeout(timeout)
    try:
        connection, _ = listener.accept()
    except TimeoutError:
        return False
    with connection:
        return True


def _network_slot(
    repository: Path,
    state_root: Path,
    runtime: initialization.Runtime,
    instruments: dict[str, Any],
    helper_binary: Path,
    slot: dict[str, Any],
    closure_identity: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    exemptions_before = loopback_exempt_appcontainer_sids()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        address, port = listener.getsockname()
        control = _run_network_control(repository, state_root, runtime, listener, port)
        sandboxed = initialization._execute_slot(
            repository,
            state_root,
            runtime,
            instruments,
            helper_binary,
            slot,
            closure_identity,
            subject_overrides={"subject:python": repository / PYTHON_SUBJECT},
            network_port=port,
        )
        sandbox_accepted = _accept(listener, 0.5)
    exemptions_after = loopback_exempt_appcontainer_sids()
    appcontainer_sid = sandboxed["boundary"]["appcontainer_sid"]
    body = {
        "schema": ORACLE_SCHEMA,
        "slot_id": slot["slot_id"],
        "subject_id": slot["subject_id"],
        "runtime": runtime.name,
        "endpoint": {"address": address, "port": port},
        "control": control,
        "sandbox": {
            "listener_accepted": sandbox_accepted,
            "exit_code": sandboxed["boundary"]["exit_code"],
            "stderr": sandboxed["boundary"]["stderr"],
            "output_present": sandboxed["boundary"]["captured_files"][0]["present"],
        },
        "loopback_exemptions_before": list(exemptions_before),
        "loopback_exemptions_after": list(exemptions_after),
        "appcontainer_sid": appcontainer_sid,
        "appcontainer_sid_exempt_before": appcontainer_sid in exemptions_before,
        "appcontainer_sid_exempt_after": appcontainer_sid in exemptions_after,
        "reusable": False,
    }
    body["identity"] = domain_hash(ORACLE_SCHEMA, body)
    return sandboxed, body


def capture(repository: Path, state_root: Path) -> dict[str, Any]:
    """Execute the 51-slot confirmation and three reachability controls."""

    repository = repository.resolve()
    state_root = state_root.resolve()
    if os.name != "nt":
        raise OSError("EXP-0026 requires native Windows")
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if platform.system().lower() != "windows" or architecture != "aarch64":
        raise OSError("EXP-0026 requires native Windows 11 ARM64")
    if state_root.exists():
        raise ValueError("state root must be absent")
    state_root.mkdir(parents=True)
    build_root = state_root / "build"
    build_root.mkdir()
    runtimes, instruments = initialization._build_runtimes(repository, build_root)
    closure = _closure(repository, runtimes, instruments)
    definitions = initialization._slot_definitions()
    reviewed_before = _effective_tree_identity(repository)
    helper_binary = build_root / "registered_true.exe"
    slots: list[dict[str, Any]] = []
    oracles: list[dict[str, Any]] = []
    started = time.monotonic()
    for slot in definitions:
        runtime = runtimes[slot["runtime"]]
        if slot["mode"] == "network":
            result, oracle = _network_slot(
                repository,
                state_root,
                runtime,
                instruments,
                helper_binary,
                slot,
                closure["identity"],
            )
            slots.append(result)
            oracles.append(oracle)
        else:
            slots.append(
                initialization._execute_slot(
                    repository,
                    state_root,
                    runtime,
                    instruments,
                    helper_binary,
                    slot,
                    closure["identity"],
                    subject_overrides={"subject:python": repository / PYTHON_SUBJECT},
                )
            )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    reviewed_after = _effective_tree_identity(repository)
    body = {
        "schema": CAPTURE_SCHEMA,
        "experiment": "EXP-0026",
        "programme_experiment": "EXP-LANG-019",
        "contract_sha256": initialization.CONTRACT_SHA256,
        "candidate_sha256": closure["candidate_sha256"],
        "corpus_revision_sha256": sha256_bytes((repository / INDEX_PATH).read_bytes()),
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
        "network_oracles": oracles,
        "reviewed_tree_before": reviewed_before,
        "reviewed_tree_after": reviewed_after,
        "elapsed_ms": elapsed_ms,
        "within_elapsed_ceiling": elapsed_ms <= MAX_ELAPSED_MS,
    }
    body["identity"] = domain_hash(CAPTURE_SCHEMA, body)
    encoded = canonical_json(body)
    if len(encoded) > MAX_CAPTURE_BYTES:
        raise ValueError(f"capture exceeds frozen ceiling: {len(encoded)} bytes")
    return body


def main(argv: list[str] | None = None) -> int:
    """Write one canonical native EXP-0026 capture."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_output_network_execute REPOSITORY FRESH_STATE CAPTURE",
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
                    "network_controls": sum(
                        oracle["control"]["completed"]
                        and oracle["control"]["listener_accepted"]
                        for oracle in value["network_oracles"]
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
