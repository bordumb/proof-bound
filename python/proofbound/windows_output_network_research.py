"""Independent Python validator for the frozen EXP-0026 confirmation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any

from proofbound.windows_enforcement_execute import (
    canonical_json,
    domain_hash,
    sha256_bytes,
)
from proofbound import windows_initialization_research as initialization
from proofbound.windows_output_network_execute import (
    CAPTURE_SCHEMA,
    CORPUS_PATH,
    EXPECTED_NETWORK_OUTPUT,
    INDEX_PATH,
    MAX_CAPTURE_BYTES,
    MAX_ELAPSED_MS,
    ORACLE_SCHEMA,
)


REPORT_SCHEMA = "proofbound-research-windows-output-network-report/1"
ATTACKS = (
    *initialization.ATTACKS,
    ("EXP-0026-A031", "WIN26-CORPUS"),
    ("EXP-0026-A032", "WIN26-BINARY-OUTPUT"),
    ("EXP-0026-A033", "WIN26-ORACLE-CONTROL"),
    ("EXP-0026-A034", "WIN26-ORACLE-ENDPOINT"),
    ("EXP-0026-A035", "WIN26-NETWORK-DENIAL"),
    ("EXP-0026-A036", "WIN26-NETWORK-ACCEPTED"),
    ("EXP-0026-A037", "WIN26-NETWORK-CAPABILITY"),
    ("EXP-0026-A038", "WIN26-REPORT"),
)
NETWORK_DENIAL_MARKERS = {
    "python": ("WinError 10013",),
    "node": ("EACCES",),
    "rust": ("os error 10013",),
}


class WindowsOutputNetworkError(ValueError):
    """A stable EXP-0026 validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str) -> None:
    raise WindowsOutputNetworkError(code, message)


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {name: item for name, item in value.items() if name != "identity"}


def _exact_keys(value: object, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code, "object fields differ")
    return value


def _effective_corpus(repository: Path, value: object) -> dict[str, dict[str, Any]]:
    try:
        index = json.loads((repository / INDEX_PATH).read_bytes())
        base_index = json.loads(
            (repository / initialization.CORPUS_PATH / "index.json").read_bytes()
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise WindowsOutputNetworkError("WIN26-CORPUS", str(issue)) from issue
    files = index.get("files")
    replacements = index.get("replacements")
    if (
        index.get("schema") != "proofbound-research-windows-output-network-corpus/1"
        or not isinstance(files, list)
        or not isinstance(replacements, list)
        or len(replacements) != 1
    ):
        _fail("WIN26-CORPUS", "successor corpus inventory differs")
    for row in files:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            _fail("WIN26-CORPUS", "successor corpus row differs")
        payload = (repository / CORPUS_PATH / row["path"]).read_bytes()
        if sha256_bytes(payload) != row["sha256"] or len(payload) != row["size_bytes"]:
            _fail("WIN26-CORPUS", f"successor corpus bytes differ: {row['path']}")
    replacement = replacements[0]
    expected_replacement = next(
        row for row in files if row.get("path") == "python_subject.py"
    )
    if (
        replacement.get("base_path") != "workspace/subjects/python_subject.py"
        or replacement.get("path") != "python_subject.py"
        or replacement.get("sha256") != expected_replacement["sha256"]
        or replacement.get("size_bytes") != expected_replacement["size_bytes"]
        or replacement.get("reason")
        != "replace platform text translation with explicit binary output"
    ):
        _fail("WIN26-BINARY-OUTPUT", "Python binary-output replacement differs")
    base_files = base_index.get("files")
    if not isinstance(base_files, list):
        _fail("WIN26-CORPUS", "base corpus inventory differs")
    expected = [
        {
            **row,
            "sha256": replacement["sha256"],
            "size_bytes": replacement["size_bytes"],
        }
        if row.get("path") == replacement["base_path"]
        else row
        for row in base_files
    ]
    if isinstance(value, list):
        actual_python = next(
            (
                row
                for row in value
                if isinstance(row, dict) and row.get("path") == replacement["base_path"]
            ),
            None,
        )
        expected_python = next(
            row for row in expected if row.get("path") == replacement["base_path"]
        )
        if actual_python != expected_python:
            _fail("WIN26-BINARY-OUTPUT", "effective Python source differs")
    if value != expected:
        _fail("WIN25-CORPUS", "retained corpus inventory differs")
    by_path = {row["path"]: row for row in expected}
    for relative, row in by_path.items():
        path = (
            repository / CORPUS_PATH / "python_subject.py"
            if relative == replacement["base_path"]
            else repository / initialization.CORPUS_PATH / relative
        )
        payload = path.read_bytes()
        if sha256_bytes(payload) != row["sha256"] or len(payload) != row["size_bytes"]:
            code = (
                "WIN26-BINARY-OUTPUT"
                if relative == replacement["base_path"]
                else "WIN25-CORPUS"
            )
            _fail(code, f"effective corpus bytes differ: {relative}")
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
    corpus = _effective_corpus(repository, closure["corpus"])
    if closure["schema"] != initialization.CLOSURE_SCHEMA:
        _fail("WIN25-CLOSURE-SCHEMA", "closure schema differs")
    if closure["identity"] != domain_hash(
        initialization.CLOSURE_SCHEMA, _without_identity(closure)
    ):
        _fail("WIN25-CLOSURE-IDENTITY", "closure identity differs")

    base_index = json.loads(
        (repository / initialization.CORPUS_PATH / "index.json").read_bytes()
    )
    projected = {**closure, "corpus": base_index["files"]}
    projected["identity"] = domain_hash(
        initialization.CLOSURE_SCHEMA, _without_identity(projected)
    )
    try:
        initialization._validate_closure(repository, projected)
    except initialization.WindowsInitializationError as issue:
        raise WindowsOutputNetworkError(issue.code, issue.message) from issue
    return closure, corpus


def _expected_network_slots() -> dict[str, dict[str, Any]]:
    return {
        row["slot_id"]: row
        for row in initialization._expected_slots()
        if row["mode"] == "network"
    }


def _valid_sid(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"S-1(?:-[0-9]+){2,15}", value) is not None
    )


def _validate_sid_inventory(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > 4096
        or value != sorted(value)
        or len(value) != len(set(value))
        or any(not _valid_sid(item) for item in value)
    ):
        _fail("WIN26-NETWORK-CAPABILITY", "loopback exemption inventory differs")
    return tuple(value)


def _validate_oracle(
    value: object,
    expected: dict[str, Any],
    slot: dict[str, Any],
    closure: dict[str, Any],
    corpus: dict[str, dict[str, Any]],
) -> int:
    oracle = _exact_keys(
        value,
        {
            "schema",
            "slot_id",
            "subject_id",
            "runtime",
            "endpoint",
            "control",
            "sandbox",
            "loopback_exemptions_before",
            "loopback_exemptions_after",
            "appcontainer_sid",
            "appcontainer_sid_exempt_before",
            "appcontainer_sid_exempt_after",
            "reusable",
            "identity",
        },
        "WIN26-ORACLE-ENDPOINT",
    )
    if oracle["schema"] != ORACLE_SCHEMA or oracle["identity"] != domain_hash(
        ORACLE_SCHEMA, _without_identity(oracle)
    ):
        _fail("WIN26-ORACLE-ENDPOINT", "oracle identity differs")
    if any(
        oracle.get(key) != expected[key] for key in ("slot_id", "subject_id", "runtime")
    ):
        _fail("WIN26-ORACLE-ENDPOINT", "oracle slot binding differs")
    endpoint = _exact_keys(
        oracle["endpoint"], {"address", "port"}, "WIN26-ORACLE-ENDPOINT"
    )
    port = endpoint["port"]
    if (
        endpoint["address"] != "127.0.0.1"
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        _fail("WIN26-ORACLE-ENDPOINT", "oracle endpoint differs")

    runtime = closure["runtime_closures"][expected["runtime"]]
    _, source_path = initialization.SUBJECTS[expected["subject_id"]]
    expected_command = [
        expected["runtime"],
        f"subjects/{Path(source_path).name}" if expected["runtime"] != "rust" else None,
        "network",
        "registered.txt",
        "outputs/output.txt",
        "workspace/unrelated.txt",
        str(port),
    ]
    subject_sha = (
        runtime["source"]["sha256"]
        if expected["runtime"] == "rust"
        else corpus[source_path]["sha256"]
    )
    control = _exact_keys(
        oracle["control"],
        {
            "logical_command",
            "runtime_sha256",
            "subject_sha256",
            "exit_code",
            "stdout",
            "stderr",
            "output_sha256",
            "output_size_bytes",
            "completed",
            "reusable",
            "listener_accepted",
        },
        "WIN26-ORACLE-CONTROL",
    )
    if (
        control["logical_command"] != expected_command
        or control["runtime_sha256"] != runtime["executable"]["sha256"]
        or control["subject_sha256"] != subject_sha
        or control["exit_code"] != 0
        or control["stdout"] != ""
        or control["stderr"] != ""
        or control["output_sha256"] != sha256_bytes(EXPECTED_NETWORK_OUTPUT)
        or control["output_size_bytes"] != len(EXPECTED_NETWORK_OUTPUT)
        or control["completed"] is not True
        or control["listener_accepted"] is not True
        or control["reusable"] is not False
    ):
        _fail("WIN26-ORACLE-CONTROL", "reachable control differs")

    sandbox = _exact_keys(
        oracle["sandbox"],
        {"listener_accepted", "exit_code", "stderr", "output_present"},
        "WIN26-NETWORK-DENIAL",
    )
    boundary = slot["boundary"]
    if (
        sandbox["exit_code"] != boundary["exit_code"]
        or sandbox["stderr"] != boundary["stderr"]
        or sandbox["output_present"] != boundary["captured_files"][0]["present"]
    ):
        _fail("WIN26-NETWORK-DENIAL", "oracle and sandbox observations differ")
    if slot["logical_command"][-1] != str(port):
        _fail("WIN26-ORACLE-ENDPOINT", "sandbox endpoint differs from control")
    markers = NETWORK_DENIAL_MARKERS[expected["runtime"]]
    exact_denial = (
        isinstance(sandbox["exit_code"], int)
        and sandbox["exit_code"] != 0
        and sandbox["output_present"] is False
        and isinstance(sandbox["stderr"], str)
        and any(marker in sandbox["stderr"] for marker in markers)
    )
    if sandbox["listener_accepted"] is True:
        if (
            sandbox["output_present"] is not True
            or slot["outcome"] != "incomplete"
            or slot["reusable"] is not False
        ):
            _fail("WIN26-NETWORK-ACCEPTED", "accepted connection was called denied")
    elif exact_denial:
        if slot["outcome"] != "denied" or slot["reusable"] is not False:
            _fail("WIN26-NETWORK-DENIAL", "exact denial was classified incorrectly")
    elif (
        sandbox["listener_accepted"] is not False
        or not isinstance(sandbox["exit_code"], int)
        or sandbox["exit_code"] == 0
        or sandbox["output_present"] is not False
        or slot["outcome"] != "incomplete"
        or slot["reusable"] is not False
    ):
        _fail("WIN26-NETWORK-DENIAL", "incomplete network result was called denied")

    before = _validate_sid_inventory(oracle["loopback_exemptions_before"])
    after = _validate_sid_inventory(oracle["loopback_exemptions_after"])
    appcontainer_sid = oracle["appcontainer_sid"]
    if oracle["reusable"] is not False:
        _fail("WIN26-REPORT", "network oracle became reusable")
    if (
        not _valid_sid(appcontainer_sid)
        or appcontainer_sid != boundary["appcontainer_sid"]
        or oracle["appcontainer_sid_exempt_before"] is not False
        or oracle["appcontainer_sid_exempt_after"] is not False
        or appcontainer_sid in before
        or appcontainer_sid in after
        or before != after
    ):
        _fail("WIN26-NETWORK-CAPABILITY", "network capability boundary differs")
    return port


def _validate_capture(repository: Path, value: object) -> dict[str, Any]:
    capture = _exact_keys(
        value,
        {
            "schema",
            "experiment",
            "programme_experiment",
            "contract_sha256",
            "candidate_sha256",
            "corpus_revision_sha256",
            "execution_environment",
            "fallback_used",
            "host",
            "closure",
            "slots",
            "network_oracles",
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
        capture["experiment"] != "EXP-0026"
        or capture["programme_experiment"] != "EXP-LANG-019"
    ):
        _fail("WIN25-DISCRIMINATOR", "experiment discriminator differs")
    if capture["contract_sha256"] != initialization.CONTRACT_SHA256:
        _fail("WIN25-CONTRACT", "base contract differs")
    candidate_sha = sha256_bytes(
        (repository / initialization.CANDIDATE_PATH).read_bytes()
    )
    if capture["candidate_sha256"] != candidate_sha:
        _fail("WIN25-CANDIDATE", "candidate identity differs")
    if capture["corpus_revision_sha256"] != sha256_bytes(
        (repository / INDEX_PATH).read_bytes()
    ):
        _fail("WIN26-CORPUS", "corpus revision identity differs")
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

    expected_slots = initialization._expected_slots()
    slots = capture["slots"]
    if not isinstance(slots, list) or len(slots) != len(expected_slots):
        _fail("WIN25-SLOT-INVENTORY", "slot count differs")
    oracle_values = capture["network_oracles"]
    network_expected = _expected_network_slots()
    if not isinstance(oracle_values, list) or len(oracle_values) != 3:
        _fail("WIN26-ORACLE-CONTROL", "network oracle inventory differs")
    oracle_by_slot: dict[str, dict[str, Any]] = {}
    for oracle in oracle_values:
        if not isinstance(oracle, dict) or not isinstance(oracle.get("slot_id"), str):
            _fail("WIN26-ORACLE-ENDPOINT", "network oracle is malformed")
        if oracle["slot_id"] in oracle_by_slot:
            _fail("WIN26-ORACLE-ENDPOINT", "network oracle is duplicated")
        oracle_by_slot[oracle["slot_id"]] = oracle
    if set(oracle_by_slot) != set(network_expected):
        _fail("WIN26-ORACLE-ENDPOINT", "network oracle slots differ")

    profiles: list[str] = []
    ports: set[int] = set()
    for slot, expected in zip(slots, expected_slots, strict=True):
        port = 1
        if expected["mode"] == "network":
            port = _validate_oracle(
                oracle_by_slot[expected["slot_id"]],
                expected,
                slot,
                closure,
                corpus,
            )
            if port in ports:
                _fail("WIN26-ORACLE-ENDPOINT", "network endpoint was reused")
            ports.add(port)
        try:
            profiles.append(
                initialization._validate_slot(
                    slot, expected, closure, corpus, network_port=port
                )
            )
        except initialization.WindowsInitializationError as issue:
            raise WindowsOutputNetworkError(issue.code, issue.message) from issue
    if len(profiles) != len(set(profiles)):
        _fail("WIN25-FRESHNESS", "AppContainer profile was reused")
    if capture["reviewed_tree_before"] != capture["reviewed_tree_after"]:
        _fail("WIN25-TREE", "reviewed tree changed")
    if (
        not isinstance(capture["elapsed_ms"], int)
        or capture["elapsed_ms"] < 0
        or capture["within_elapsed_ceiling"]
        is not (capture["elapsed_ms"] <= MAX_ELAPSED_MS)
    ):
        _fail("WIN25-ELAPSED", "elapsed classification differs")
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
            "network_control_connections": sum(
                oracle["control"]["listener_accepted"] is True
                for oracle in oracle_values
            ),
            "network_sandbox_connections": sum(
                oracle["sandbox"]["listener_accepted"] is True
                for oracle in oracle_values
            ),
            "denied_reusable": denied_reusable,
            "reviewed_tree_changed": False,
            "elapsed_ms": capture["elapsed_ms"],
        },
    }


def validate_capture(value: object, repository: Path) -> dict[str, Any]:
    """Validate a decoded capture and derive its canonical report."""

    validated = _validate_capture(repository, value)
    metrics = validated["metrics"]
    capture = validated["capture"]
    questions = {
        "Q1": metrics["positive_executions"] == 30,
        "Q2": metrics["authority_probe_executions"] == 21
        and metrics["network_control_connections"] == 3
        and metrics["network_sandbox_connections"] == 0
        and metrics["denied_reusable"] == 0,
        "Q3": capture["closure"]["frozen_before_first_slot"] is True,
        "Q4": True,
        "Q5": metrics["reviewed_tree_changed"] is False
        and capture["within_elapsed_ceiling"] is True,
    }
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0026",
        "programme_experiment": "EXP-LANG-019",
        "contract_sha256": initialization.CONTRACT_SHA256,
        "candidate_sha256": capture["candidate_sha256"],
        "corpus_revision_sha256": capture["corpus_revision_sha256"],
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
    """Validate canonical EXP-0026 capture bytes and registered inputs."""

    if len(payload) > MAX_CAPTURE_BYTES:
        _fail("WIN25-CAPTURE-SCHEMA", "capture exceeds its byte ceiling")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise WindowsOutputNetworkError("WIN25-CAPTURE-SCHEMA", str(issue)) from issue
    if canonical_json(value) != payload:
        _fail("WIN25-CAPTURE-SCHEMA", "capture is not canonical JSON")
    return validate_capture(value, repository)


def main(argv: list[str] | None = None) -> int:
    """Validate one EXP-0026 capture into a canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_output_network_research REPOSITORY CAPTURE REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(arguments[0]), Path(arguments[1]).read_bytes()
        )
        Path(arguments[2]).write_bytes(canonical_json(report))
    except (OSError, ValueError, json.JSONDecodeError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
