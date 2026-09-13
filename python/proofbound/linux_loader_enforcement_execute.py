"""Capture EXP-0024 with an exact ELF-interpreter execution closure."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time
from typing import Any
import uuid

from proofbound import linux_enforcement_execute as base


CAPTURE_SCHEMA = "proofbound-research-linux-loader-capture/1"
POLICY_SCHEMA = "proofbound-research-linux-loader-policy/1"
IMAGE = "proofbound-exp0024:registered"
ENFORCER = "/usr/local/bin/proofbound-linux-loader-enforcer"
INTERPRETER_PATTERN = re.compile(
    r"\s*\[Requesting program interpreter: (/[^\]\n]+)\]\s*"
)


def _container_identity(container: str) -> dict[str, Any]:
    image = base._run(
        [
            "docker",
            "image",
            "inspect",
            IMAGE,
            "--format",
            "{{.Id}} {{.Architecture}} {{.Os}}",
        ]
    )
    image_id, docker_architecture, operating_system = (
        image.stdout.decode("ascii").strip().split()
    )
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        docker_architecture, docker_architecture
    )
    probe = base._docker_exec(container, [ENFORCER, "--probe"], check=False)
    stdout = probe.stdout.decode("utf-8", errors="strict")
    stderr = probe.stderr.decode("utf-8", errors="strict")
    prefix = f"linux-enforcer/1 architecture={architecture} landlock-abi="
    landlock_abi = None
    if probe.returncode == 0:
        text = stdout.strip()
        if not text.startswith(prefix):
            raise ValueError(f"unexpected enforcer probe: {text!r}")
        landlock_abi = int(text.removeprefix(prefix))
    kernel = (
        base._docker_exec(container, ["uname", "-srmo"]).stdout.decode("ascii").strip()
    )
    digest = (
        base._docker_exec(container, ["sha256sum", ENFORCER])
        .stdout.decode("ascii")
        .split()[0]
    )
    return {
        "os": operating_system,
        "architecture": architecture,
        "kernel": kernel,
        "landlock_abi": landlock_abi,
        "probe_exit_code": probe.returncode,
        "probe_stdout": stdout,
        "probe_stderr": stderr,
        "image": IMAGE,
        "image_identity": image_id,
        "enforcer": ENFORCER,
        "enforcer_sha256": f"sha256:{digest}",
        "no_new_privs": landlock_abi is not None and landlock_abi >= 4,
        "seccomp_network_syscalls": base.NETWORK_SYSCALLS,
    }


def _loader_identity(container: str, runtime: str) -> dict[str, Any]:
    report = base._docker_exec(container, ["/usr/bin/readelf", "-lW", runtime])
    text = report.stdout.decode("utf-8", errors="strict")
    matches = INTERPRETER_PATTERN.findall(text)
    if len(matches) != 1:
        raise ValueError(f"runtime has {len(matches)} PT_INTERP entries: {runtime}")
    requested = matches[0]
    if (
        not PurePosixPath(requested).is_absolute()
        or ".." in PurePosixPath(requested).parts
    ):
        raise ValueError(f"unsafe PT_INTERP path: {requested}")
    resolved = (
        base._docker_exec(container, ["readlink", "-f", requested])
        .stdout.decode("utf-8", errors="strict")
        .strip()
    )
    if not resolved or not PurePosixPath(resolved).is_absolute():
        raise ValueError(f"unresolved PT_INTERP path: {requested}")
    metadata = (
        base._docker_exec(container, ["stat", "-Lc", "%s %a", resolved])
        .stdout.decode("ascii")
        .strip()
        .split()
    )
    digest = (
        base._docker_exec(container, ["sha256sum", resolved])
        .stdout.decode("ascii")
        .split()[0]
    )
    return {
        "requested_path": requested,
        "resolved_path": resolved,
        "sha256": f"sha256:{digest}",
        "size_bytes": int(metadata[0]),
        "mode": int(metadata[1], 8),
    }


def _policy(
    subject_id: str,
    runtime: str,
    source: str,
    ephemeral: str,
    platform: dict[str, Any],
    loader: dict[str, Any],
) -> dict[str, Any]:
    value = base._policy(subject_id, runtime, source, ephemeral, platform)
    value["schema"] = POLICY_SCHEMA
    value["runtime_loader"] = loader
    value["executable_allowlist"] = [runtime, loader["resolved_path"]]
    value.pop("identity")
    value["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-policy/1", value
    )
    return value


def _execute_slot(
    container: str,
    slot: dict[str, Any],
    platform: dict[str, Any],
    loaders: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    slot_id = slot["slot_id"]
    subject_id = slot["subject_id"]
    runtime, source = base.SUBJECTS[subject_id]
    loader = loaders[runtime]
    ephemeral = f"/state/slots/{slot_id}"
    output = f"{ephemeral}/output.txt"
    host_output = Path(slot["host_state"]) / "slots" / slot_id / "output.txt"
    host_output.parent.mkdir(parents=True, exist_ok=False)
    policy = _policy(subject_id, runtime, source, ephemeral, platform, loader)
    arguments = base._command(
        runtime, source, slot["mode"], output, slot["attack_path"]
    )
    command = [
        ENFORCER,
        runtime,
        loader["resolved_path"],
        source,
        "/workspace/registered.txt",
        ephemeral,
        *arguments,
    ]
    process = base._docker_exec(container, command, check=False)
    output_identity = None
    if host_output.exists():
        payload = host_output.read_bytes()
        output_identity = {
            "path": output,
            "sha256": base.sha256_bytes(payload),
            "size_bytes": len(payload),
            "mode": stat.S_IMODE(host_output.stat().st_mode),
        }
    outcome = "completed" if process.returncode == 0 else "denied"
    result = {
        "slot_id": slot_id,
        "kind": slot["kind"],
        "subject_id": subject_id,
        "repetition": slot.get("repetition"),
        "attack_id": slot.get("attack_id"),
        "expected_denial_code": slot.get("expected_denial_code"),
        "mode": slot["mode"],
        "attack_path": slot["attack_path"],
        "policy": policy,
        "command": command,
        "exit_code": process.returncode,
        "stdout": process.stdout.decode("utf-8", errors="strict"),
        "stderr": process.stderr.decode("utf-8", errors="strict"),
        "output": output_identity,
        "outcome": outcome,
        "reusable": outcome == "completed",
    }
    result["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-slot/1", result
    )
    return result


def capture(repository: Path, state_root: Path) -> dict[str, Any]:
    """Execute the registered EXP-0024 corpus and return its raw capture."""

    repository = repository.resolve()
    state_root = state_root.resolve()
    if state_root.exists():
        raise ValueError("state root must be absent")
    workspace = state_root / "workspace"
    runtime_state = state_root / "state"
    source = repository / "docs/experiments/0018-os-enforced-effects/corpus/workspace"
    shutil.copytree(source, workspace, symlinks=True)
    runtime_state.mkdir()
    container = f"proofbound-exp0024-{uuid.uuid4().hex[:12]}"
    started = time.monotonic()
    before = base._tree_identity(workspace)
    supported = False
    try:
        base._run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                container,
                "--mount",
                f"type=bind,src={workspace},dst=/workspace",
                "--mount",
                f"type=bind,src={runtime_state},dst=/state",
                IMAGE,
            ]
        )
        platform = _container_identity(container)
        supported = (
            platform["os"] == "linux"
            and platform["architecture"] in {"aarch64", "x86_64"}
            and platform["landlock_abi"] is not None
            and platform["landlock_abi"] >= 4
        )
        if supported:
            base._docker_exec(
                container,
                [
                    "rustc",
                    "/workspace/subjects/rust_subject.rs",
                    "-o",
                    "/state/rust-subject",
                ],
            )
            runtimes = sorted({runtime for runtime, _source in base.SUBJECTS.values()})
            loaders = {
                runtime: _loader_identity(container, runtime) for runtime in runtimes
            }
            definitions = base._slots(runtime_state)
            with ThreadPoolExecutor(max_workers=18) as executor:
                futures = [
                    executor.submit(_execute_slot, container, item, platform, loaders)
                    for item in definitions
                ]
                slots = [future.result() for future in futures]
        else:
            slots = []
    finally:
        base._run(["docker", "rm", "--force", container], check=False)
    after = base._tree_identity(workspace)
    value = {
        "schema": CAPTURE_SCHEMA,
        "experiment": "EXP-0024",
        "programme_experiment": "EXP-LANG-017",
        "contract_sha256": base.CONTRACT_SHA256,
        "execution_environment": "native-linux-kernel-via-container-transport",
        "container_confinement_counted": False,
        "availability": "supported" if supported else "unsupported",
        "platform": platform,
        "scheduler": "concurrent-independent-landlock-loader-processes",
        "slots": slots,
        "reviewed_tree_before": before,
        "reviewed_tree_after": after,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    value["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-capture/1", value
    )
    return value


def main(argv: list[str] | None = None) -> int:
    """Write one canonical EXP-0024 capture."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: linux_loader_enforcement_execute REPOSITORY FRESH_STATE CAPTURE",
            file=sys.stderr,
        )
        return 2
    try:
        value = capture(Path(arguments[0]), Path(arguments[1]))
        Path(arguments[2]).write_bytes(base.canonical_json(value))
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
