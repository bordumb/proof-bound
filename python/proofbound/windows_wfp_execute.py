"""Execute the frozen EXP-0027 WFP attribution experiment."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import time
from typing import Any
import zipfile

from proofbound.windows_enforcement_execute import canonical_json, domain_hash
from proofbound import windows_initialization_execute as initialization
from proofbound import windows_output_network_execute as predecessor


CAPTURE_SCHEMA = "proofbound-research-windows-wfp-capture/1"
ATTRIBUTION_SCHEMA = "proofbound-research-windows-wfp-attribution/1"
OBSERVER_SCHEMA = "proofbound-research-windows-wfp-observer/1"
OBSERVER_SOURCE = Path(
    "docs/experiments/0027-windows-wfp-drop-attribution/instrument/wfp_observer.rs"
)
MAX_CAPTURE_BYTES = 786_432
MAX_EVENTS_PER_SLOT = 64
MAX_ELAPSED_MS = 60_000
NETWORK_TIMEOUT_MS = 5_000
REQUIRED_FLAGS = 0x01 | 0x04 | 0x10 | 0x20 | 0x100 | 0x400


class WfpUnavailable(OSError):
    """The read-only WFP observer cannot run before workload execution."""


def _filetime_now() -> int:
    """Return the precise Windows system time in FILETIME units."""

    value = wintypes.FILETIME()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemTimePreciseAsFileTime.argtypes = [
        ctypes.POINTER(wintypes.FILETIME)
    ]
    kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(value))
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


def _compile_observer(
    repository: Path,
    build_root: Path,
    instruments: dict[str, Any],
) -> Path:
    """Build and identity-bind the frozen native WFP observer."""

    source = repository / OBSERVER_SOURCE
    source_text = source.read_text(encoding="utf-8")
    forbidden = (
        "FwpmEngineSetOption",
        "FwpmFilterAdd",
        "FwpmFilterDelete",
        "NetworkIsolationSetAppContainerConfig",
    )
    if any(name in source_text for name in forbidden):
        raise ValueError("WFP observer contains a forbidden policy mutation API")
    compiler = initialization._rust_compiler()
    binary = build_root / "wfp_observer.exe"
    invocation = [
        str(compiler),
        "--edition",
        "2021",
        "-C",
        "debuginfo=0",
        str(source),
        "-o",
        str(binary),
    ]
    process = subprocess.run(
        invocation,
        check=True,
        capture_output=True,
        timeout=180,
    )
    if process.stdout or process.stderr:
        raise ValueError("WFP observer compiler emitted unexpected output")
    instruments.update(
        {
            "wfp_observer_source": initialization._artifact(
                source, "instrument/wfp_observer.rs"
            ),
            "wfp_observer_executable": initialization._artifact(
                binary, "instrument/wfp_observer.exe"
            ),
            "wfp_observer_build": {
                "compiler_sha256": initialization._artifact(
                    compiler, "tool/rustc.exe"
                )["sha256"],
                "arguments": [
                    "--edition",
                    "2021",
                    "-C",
                    "debuginfo=0",
                    "instrument/wfp_observer.rs",
                    "-o",
                    "instrument/wfp_observer.exe",
                ],
                "target": "aarch64-pc-windows-msvc",
                "linked_library": "Fwpuclnt",
                "policy_mutation_apis": [],
            },
        }
    )
    return binary


def _run_observer_command(binary: Path, *arguments: str) -> tuple[int, str, str]:
    process = subprocess.run(
        [str(binary), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=120,
    )
    return process.returncode, process.stdout.replace("\r\n", "\n"), process.stderr.replace(
        "\r\n", "\n"
    )


def _probe(binary: Path) -> dict[str, Any]:
    code, stdout, stderr = _run_observer_command(binary, "probe")
    expected = "PROBE\t1\tFwpmNetEventSubscribe1\tFWPM_NET_EVENT2\n"
    if code != 0 or stderr or stdout != expected:
        raise WfpUnavailable(
            f"read-only WFP probe unavailable: exit={code} stdout={stdout!r} stderr={stderr!r}"
        )
    return {
        "collection_enabled": True,
        "collection_query": "FwpmEngineGetOption0",
        "subscription_api": "FwpmNetEventSubscribe1",
        "event_schema": "FWPM_NET_EVENT2",
    }


def _application_id(binary: Path, application: Path) -> str:
    code, stdout, stderr = _run_observer_command(binary, "appid", str(application))
    if code != 0 or stderr or not stdout.startswith("APPID\t") or not stdout.endswith("\n"):
        raise ValueError(
            f"WFP application identity failed: exit={code} stdout={stdout!r} stderr={stderr!r}"
        )
    value = stdout.removesuffix("\n").removeprefix("APPID\t")
    if not value or len(value) % 2 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("WFP application identity is not canonical hexadecimal")
    return value


def _start_observer(binary: Path, stop: Path, output: Path) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [str(binary), "observe", str(stop), str(output)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    assert process.stdout is not None
    ready = process.stdout.readline().replace("\r\n", "\n")
    if ready != "READY\tproofbound-wfp-events/1\n":
        process.kill()
        _, stderr = process.communicate(timeout=10)
        raise WfpUnavailable(
            f"WFP subscription unavailable: ready={ready!r} stderr={stderr!r}"
        )
    return process


def _stop_observer(
    process: subprocess.Popen[str], stop: Path, output: Path
) -> tuple[list[dict[str, Any]], str, str]:
    stop.write_bytes(b"stop\n")
    stdout, stderr = process.communicate(timeout=15)
    stdout = stdout.replace("\r\n", "\n")
    stderr = stderr.replace("\r\n", "\n")
    if process.returncode != 0 or stdout or stderr:
        raise ValueError(
            "WFP observer did not close canonically: "
            f"exit={process.returncode} stdout={stdout!r} stderr={stderr!r}"
        )
    return _parse_events(output), stdout, stderr


def _parse_events(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "proofbound-wfp-events/1":
        raise ValueError("WFP event protocol differs")
    events = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 14:
            raise ValueError("WFP event field count differs")
        numeric = [int(value) for value in fields[:9]]
        tail = [int(value) for value in fields[11:]]
        event = {
            "timestamp": numeric[0],
            "flags": numeric[1],
            "event_type": numeric[2],
            "ip_version": numeric[3],
            "ip_protocol": numeric[4],
            "local_address": socket.inet_ntoa(struct.pack("=I", numeric[5])),
            "remote_address": socket.inet_ntoa(struct.pack("=I", numeric[6])),
            "local_port": numeric[7],
            "remote_port": numeric[8],
            "application_id_hex": fields[9],
            "package_sid": fields[10],
            "capability_id": tail[0],
            "filter_id": tail[1],
            "is_loopback": tail[2] == 1,
        }
        event["identity"] = domain_hash(
            "proofbound-research-windows-wfp-event/1", event
        )
        events.append(event)
    return events


def _matching_events(
    events: list[dict[str, Any]],
    sid: str,
    started: int,
    ended: int,
) -> list[dict[str, Any]]:
    matches = [
        event
        for event in events
        if event["package_sid"] == sid and started <= event["timestamp"] <= ended
    ]
    if len(matches) > MAX_EVENTS_PER_SLOT:
        raise ValueError("WFP per-slot event ceiling exceeded")
    return matches


def _event_matches(
    event: dict[str, Any], expected_app_id: str, port: int
) -> bool:
    return (
        event["event_type"] == 7
        and event["flags"] & REQUIRED_FLAGS == REQUIRED_FLAGS
        and event["ip_version"] == 0
        and event["ip_protocol"] == 6
        and event["remote_address"] == "127.0.0.1"
        and event["remote_port"] == port
        and event["application_id_hex"] == expected_app_id
        and event["capability_id"] in {0, 1, 2}
        and event["filter_id"] > 0
        and event["is_loopback"]
    )


def _attribution(
    oracle: dict[str, Any],
    events: list[dict[str, Any]],
    expected_app_id: str,
    application_path: str,
    started: int,
    ended: int,
) -> dict[str, Any]:
    relevant = _matching_events(
        events, oracle["appcontainer_sid"], started, ended
    )
    sandbox = oracle["sandbox"]
    marker = predecessor.NETWORK_DENIAL_MARKERS[oracle["runtime"]]
    synchronous = marker in sandbox["stderr"]
    matching_drops = [
        event
        for event in relevant
        if _event_matches(event, expected_app_id, oracle["endpoint"]["port"])
    ]
    contradictory_allow = any(event["event_type"] == 8 for event in relevant)
    if sandbox["listener_accepted"] or sandbox["output_present"] or contradictory_allow:
        outcome = "accepted"
    elif synchronous:
        outcome = "synchronous-denial"
    elif matching_drops:
        outcome = "capability-drop-denial"
    else:
        outcome = "bounded-non-delivery"
    body = {
        "schema": ATTRIBUTION_SCHEMA,
        "slot_id": oracle["slot_id"],
        "runtime": oracle["runtime"],
        "appcontainer_sid": oracle["appcontainer_sid"],
        "expected_application_id_hex": expected_app_id,
        "expected_application_path": application_path,
        "application_identity_api": "FwpmGetAppIdFromFileName0",
        "endpoint": oracle["endpoint"],
        "window": {"start_filetime": started, "end_filetime": ended},
        "events": relevant,
        "matching_capability_drops": len(matching_drops),
        "contradictory_allow": contradictory_allow,
        "outcome": outcome,
        "reusable": False,
    }
    body["identity"] = domain_hash(ATTRIBUTION_SCHEMA, body)
    return body


def capture(repository: Path, state_root: Path) -> dict[str, Any]:
    """Run the complete frozen corpus with read-only WFP observation."""

    repository = repository.resolve()
    state_root = state_root.resolve()
    if os.name != "nt":
        raise OSError("EXP-0027 requires native Windows")
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    if platform.system().lower() != "windows" or architecture != "aarch64":
        raise OSError("EXP-0027 requires native Windows 11 ARM64")
    if state_root.exists():
        raise ValueError("state root must be absent")
    state_root.mkdir(parents=True)
    build_root = state_root / "build"
    build_root.mkdir()
    runtimes, instruments = initialization._build_runtimes(repository, build_root)
    observer_binary = _compile_observer(repository, build_root, instruments)
    probe_before = _probe(observer_binary)
    closure = predecessor._closure(repository, runtimes, instruments)
    reviewed_before = predecessor._effective_tree_identity(repository)
    stop_path = state_root / "wfp-observer.stop"
    events_path = state_root / "wfp-events.tsv"
    observer_process = _start_observer(observer_binary, stop_path, events_path)
    definitions = initialization._slot_definitions()
    helper_binary = build_root / "registered_true.exe"
    slots: list[dict[str, Any]] = []
    oracles: list[dict[str, Any]] = []
    windows: dict[str, tuple[int, int, str, str]] = {}
    started_run = time.monotonic()
    try:
        for slot in definitions:
            runtime = runtimes[slot["runtime"]]
            if slot["mode"] == "network":
                suspended: dict[str, str] = {}

                def observe_suspended(application: Path, sid: str) -> None:
                    suspended["application"] = str(application)
                    suspended["appcontainer_sid"] = sid
                    suspended["application_id"] = _application_id(
                        observer_binary, application
                    )

                started = _filetime_now()
                result, oracle = predecessor._network_slot(
                    repository,
                    state_root,
                    runtime,
                    instruments,
                    helper_binary,
                    slot,
                    closure["identity"],
                    process_timeout_ms=NETWORK_TIMEOUT_MS,
                    on_suspended=observe_suspended,
                )
                ended = _filetime_now()
                if suspended.get("appcontainer_sid") != oracle["appcontainer_sid"]:
                    raise ValueError("suspended application SID differs from network oracle")
                windows[slot["slot_id"]] = (
                    started,
                    ended,
                    suspended["application_id"],
                    suspended["application"],
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
                        subject_overrides={
                            "subject:python": repository / predecessor.PYTHON_SUBJECT
                        },
                    )
                )
    finally:
        events, observer_stdout, observer_stderr = _stop_observer(
            observer_process, stop_path, events_path
        )
    elapsed_ms = int((time.monotonic() - started_run) * 1000)
    probe_after = _probe(observer_binary)
    attributions = [
        _attribution(
            oracle,
            events,
            windows[oracle["slot_id"]][2],
            windows[oracle["slot_id"]][3],
            windows[oracle["slot_id"]][0],
            windows[oracle["slot_id"]][1],
        )
        for oracle in oracles
    ]
    reviewed_after = predecessor._effective_tree_identity(repository)
    observer = {
        "schema": OBSERVER_SCHEMA,
        "probe_before": probe_before,
        "probe_after": probe_after,
        "collection_unchanged": probe_before == probe_after,
        "policy_mutations": [],
        "event_count": len(events),
        "retained_event_identities": [event["identity"] for event in events],
        "stdout": observer_stdout,
        "stderr": observer_stderr,
    }
    observer["identity"] = domain_hash(OBSERVER_SCHEMA, observer)
    body = {
        "schema": CAPTURE_SCHEMA,
        "experiment": "EXP-0027",
        "programme_experiment": "EXP-LANG-020",
        "availability": "supported",
        "contract_sha256": initialization.CONTRACT_SHA256,
        "candidate_sha256": closure["candidate_sha256"],
        "corpus_revision_sha256": predecessor.sha256_bytes(
            (repository / predecessor.INDEX_PATH).read_bytes()
        ),
        "execution_environment": "github-windows-11-arm-native",
        "fallback_used": False,
        "host": {
            "os": "windows",
            "architecture": architecture,
            "release": platform.release(),
            "version": platform.version(),
        },
        "closure": closure,
        "observer": observer,
        "slots": slots,
        "network_oracles": oracles,
        "network_attributions": attributions,
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
    """Write one canonical native EXP-0027 capture."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print("usage: windows_wfp_execute REPOSITORY FRESH_STATE CAPTURE", file=sys.stderr)
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
                    "non_network_denied": sum(
                        slot["outcome"] == "denied"
                        for slot in value["slots"]
                        if slot["mode"] != "network"
                    ),
                    "network_outcomes": [
                        row["outcome"] for row in value["network_attributions"]
                    ],
                    "size_bytes": len(canonical_json(value)),
                },
                sort_keys=True,
            )
        )
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
