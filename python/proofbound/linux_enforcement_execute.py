"""Capture EXP-0020 on a real Linux Landlock and seccomp boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from typing import Any
import uuid


CAPTURE_SCHEMA = "proofbound-research-linux-enforcement-capture/1"
POLICY_SCHEMA = "proofbound-research-linux-effective-policy/1"
CONTRACT_SHA256 = (
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d"
)
IMAGE = "proofbound-exp0020:registered"
ENFORCER = "/usr/local/bin/proofbound-linux-enforcer"
SYSTEM_READ_ROOTS = ["/dev", "/etc", "/lib", "/proc", "/sys", "/usr"]
NETWORK_SYSCALLS = [
    "accept",
    "accept4",
    "bind",
    "connect",
    "listen",
    "socket",
    "socketpair",
]
SUBJECTS = {
    "subject:node": ("/usr/bin/node", "/workspace/subjects/node_subject.mjs"),
    "subject:python": (
        "/usr/local/bin/python3.12",
        "/workspace/subjects/python_subject.py",
    ),
    "subject:rust": ("/state/rust-subject", "/workspace/subjects/rust_subject.rs"),
}
PROBES = [
    (
        "EXP-0018-A001",
        "read-undeclared",
        "/workspace/unrelated.txt",
        "EFX-FILE-READ-DENIED",
    ),
    (
        "EXP-0018-A002",
        "read-undeclared",
        "/workspace/nested/outside.txt",
        "EFX-FILE-READ-DENIED",
    ),
    ("EXP-0018-A007", "env-undeclared", "/workspace/unrelated.txt", "EFX-ENV-DENIED"),
    ("EXP-0018-A009", "exec-unregistered", "/usr/bin/true", "EFX-EXEC-DENIED"),
    ("EXP-0018-A011", "network", "/workspace/unrelated.txt", "EFX-NETWORK-DENIED"),
    (
        "EXP-0018-A012",
        "write-reviewed",
        "/workspace/reviewed.txt",
        "EFX-REVIEWED-WRITE-DENIED",
    ),
    ("EXP-0018-A013", "write-escape", "/state/escape.txt", "EFX-WRITE-ESCAPE"),
]


def canonical_json(value: Any) -> bytes:
    """Return the repository canonical JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sha256_bytes(value: bytes) -> str:
    """Return a tagged SHA-256 identity."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def domain_hash(domain: str, value: Any) -> str:
    """Hash canonical JSON under a NUL-separated domain."""

    payload = canonical_json(value)
    return sha256_bytes(domain.encode() + b"\0" + payload)


def _run(
    arguments: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(arguments, check=check, capture_output=True, timeout=180)


def _docker_exec(
    container: str, arguments: list[str], *, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return _run(["docker", "exec", container, *arguments], check=check)


def _container_identity(container: str) -> dict[str, Any]:
    image = _run(
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
    architecture = "aarch64" if docker_architecture == "arm64" else docker_architecture
    probe = _docker_exec(container, [ENFORCER, "--probe"], check=False)
    probe_stdout = probe.stdout.decode("utf-8", errors="strict")
    probe_stderr = probe.stderr.decode("utf-8", errors="strict")
    expected_prefix = f"linux-enforcer/1 architecture={architecture} landlock-abi="
    landlock_abi = None
    if probe.returncode == 0:
        probe_text = probe_stdout.strip()
        if not probe_text.startswith(expected_prefix):
            raise ValueError(f"unexpected enforcer probe: {probe_text!r}")
        landlock_abi = int(probe_text.removeprefix(expected_prefix))
    kernel = _docker_exec(container, ["uname", "-srmo"]).stdout.decode("ascii").strip()
    digest = (
        _docker_exec(container, ["sha256sum", ENFORCER])
        .stdout.decode("ascii")
        .split()[0]
    )
    return {
        "os": operating_system,
        "architecture": architecture,
        "kernel": kernel,
        "landlock_abi": landlock_abi,
        "probe_exit_code": probe.returncode,
        "probe_stdout": probe_stdout,
        "probe_stderr": probe_stderr,
        "image": IMAGE,
        "image_identity": image_id,
        "enforcer": ENFORCER,
        "enforcer_sha256": f"sha256:{digest}",
        "no_new_privs": landlock_abi is not None and landlock_abi >= 4,
        "seccomp_network_syscalls": NETWORK_SYSCALLS,
    }


def _tree_identity(root: Path) -> str:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"symlink in reviewed tree: {relative}")
        if path.is_dir():
            entries.append(
                {
                    "path": relative,
                    "kind": "directory",
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
        elif path.is_file():
            payload = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "size_bytes": len(payload),
                    "sha256": sha256_bytes(payload),
                }
            )
        else:
            raise ValueError(f"special file in reviewed tree: {relative}")
    return domain_hash("proofbound-research-tree/1", entries)


def _policy(
    subject_id: str,
    runtime: str,
    source: str,
    ephemeral_root: str,
    platform: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": POLICY_SCHEMA,
        "subject_id": subject_id,
        "platform": {
            "os": platform["os"],
            "architecture": platform["architecture"],
            "minimum_landlock_abi": 4,
        },
        "system_read_roots": SYSTEM_READ_ROOTS,
        "project_root": "/workspace",
        "allowed_project_reads": ["/workspace/registered.txt", source],
        "registered_absences": ["/workspace/must-remain-absent.txt"],
        "registered_input_mode": 0o644,
        "runtime": runtime,
        "executable_allowlist": [runtime],
        "environment": {"PB_REGISTERED_VALUE": sha256_bytes(b"registered-env")},
        "ephemeral_write_roots": [ephemeral_root],
        "denied_project_reads": [
            "/workspace/nested/outside.txt",
            "/workspace/unrelated.txt",
        ],
        "denied_reviewed_writes": ["/workspace/reviewed.txt"],
        "denied_escape_writes": ["/state/escape.txt"],
        "denied_network_syscalls": NETWORK_SYSCALLS,
        "default_filesystem_authority": "deny",
    }
    body["identity"] = domain_hash("proofbound-research-linux-effective-policy/1", body)
    return body


def _command(
    runtime: str, source: str, mode: str, output: str, attack: str
) -> list[str]:
    tail = [mode, "/workspace/registered.txt", output, attack, "1"]
    if runtime in {"/usr/bin/node", "/usr/local/bin/python3.12"}:
        return [runtime, source, *tail]
    return [runtime, *tail]


def _execute_slot(
    container: str, slot: dict[str, Any], platform: dict[str, Any]
) -> dict[str, Any]:
    slot_id = slot["slot_id"]
    subject_id = slot["subject_id"]
    runtime, source = SUBJECTS[subject_id]
    ephemeral = f"/state/slots/{slot_id}"
    output = f"{ephemeral}/output.txt"
    host_output = Path(slot["host_state"]) / "slots" / slot_id / "output.txt"
    host_output.parent.mkdir(parents=True, exist_ok=False)
    policy = _policy(subject_id, runtime, source, ephemeral, platform)
    arguments = _command(runtime, source, slot["mode"], output, slot["attack_path"])
    process = _docker_exec(
        container,
        [ENFORCER, runtime, source, "/workspace/registered.txt", ephemeral, *arguments],
        check=False,
    )
    output_identity = None
    if host_output.exists():
        payload = host_output.read_bytes()
        output_identity = {
            "path": output,
            "sha256": sha256_bytes(payload),
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
        "command": [
            ENFORCER,
            runtime,
            source,
            "/workspace/registered.txt",
            ephemeral,
            *arguments,
        ],
        "exit_code": process.returncode,
        "stdout": process.stdout.decode("utf-8", errors="strict"),
        "stderr": process.stderr.decode("utf-8", errors="strict"),
        "output": output_identity,
        "outcome": outcome,
        "reusable": outcome == "completed",
    }
    result["identity"] = domain_hash("proofbound-research-linux-slot/1", result)
    result.pop("host_state", None)
    return result


def _slots(host_state: Path) -> list[dict[str, Any]]:
    slots: list[dict[str, Any]] = []
    for subject_id in sorted(SUBJECTS):
        label = subject_id.split(":", 1)[1]
        for repetition in range(10):
            slots.append(
                {
                    "slot_id": f"positive-{label}-{repetition:02d}",
                    "kind": "positive",
                    "subject_id": subject_id,
                    "repetition": repetition,
                    "mode": "positive",
                    "attack_path": "/workspace/unrelated.txt",
                    "host_state": str(host_state),
                }
            )
    for attack_id, mode, path, code in PROBES:
        for subject_id in sorted(SUBJECTS):
            label = subject_id.split(":", 1)[1]
            slots.append(
                {
                    "slot_id": f"probe-{attack_id.lower()}-{label}",
                    "kind": "authority-probe",
                    "subject_id": subject_id,
                    "attack_id": attack_id,
                    "expected_denial_code": code,
                    "mode": mode,
                    "attack_path": path,
                    "host_state": str(host_state),
                }
            )
    return slots


def capture(repository: Path, state_root: Path) -> dict[str, Any]:
    """Execute the registered Linux corpus and return its raw capture."""

    repository = repository.resolve()
    state_root = state_root.resolve()
    if state_root.exists():
        raise ValueError("state root must be absent")
    workspace = state_root / "workspace"
    runtime_state = state_root / "state"
    source = repository / "docs/experiments/0018-os-enforced-effects/corpus/workspace"
    shutil.copytree(source, workspace, symlinks=True)
    runtime_state.mkdir()
    container = f"proofbound-exp0020-{uuid.uuid4().hex[:12]}"
    started = time.monotonic()
    before = _tree_identity(workspace)
    try:
        _run(
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
            _docker_exec(
                container,
                [
                    "rustc",
                    "/workspace/subjects/rust_subject.rs",
                    "-o",
                    "/state/rust-subject",
                ],
            )
            definitions = _slots(runtime_state)
            with ThreadPoolExecutor(max_workers=18) as executor:
                futures = [
                    executor.submit(_execute_slot, container, item, platform)
                    for item in definitions
                ]
                slots = [future.result() for future in futures]
        else:
            slots = []
    finally:
        _run(["docker", "rm", "--force", container], check=False)
    after = _tree_identity(workspace)
    capture_value = {
        "schema": CAPTURE_SCHEMA,
        "experiment": "EXP-0020",
        "programme_experiment": "EXP-LANG-013",
        "contract_sha256": CONTRACT_SHA256,
        "execution_environment": "docker-linux-vm",
        "container_confinement_counted": False,
        "availability": "supported" if supported else "unsupported",
        "platform": platform,
        "scheduler": "concurrent-independent-landlock-processes",
        "slots": slots,
        "reviewed_tree_before": before,
        "reviewed_tree_after": after,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    capture_value["identity"] = domain_hash(
        "proofbound-research-linux-enforcement-capture/1", capture_value
    )
    return capture_value


def main(argv: list[str] | None = None) -> int:
    """Write one canonical EXP-0020 capture."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: linux_enforcement_execute REPOSITORY FRESH_STATE CAPTURE",
            file=sys.stderr,
        )
        return 2
    try:
        value = capture(Path(arguments[0]), Path(arguments[1]))
        Path(arguments[2]).write_bytes(canonical_json(value))
    except (OSError, ValueError, subprocess.SubprocessError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
