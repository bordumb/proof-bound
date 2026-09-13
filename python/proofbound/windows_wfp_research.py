"""Independently validate the frozen EXP-0027 WFP capture."""

from __future__ import annotations

import copy
import json
from pathlib import Path, PureWindowsPath
import re
import sys
from typing import Any

from proofbound.windows_enforcement_execute import canonical_json, domain_hash, sha256_bytes
from proofbound import windows_initialization_research as initialization
from proofbound import windows_output_network_execute as predecessor_execute
from proofbound import windows_output_network_research as predecessor
from proofbound.windows_wfp_execute import (
    ATTRIBUTION_SCHEMA,
    CAPTURE_SCHEMA,
    MAX_CAPTURE_BYTES,
    MAX_ELAPSED_MS,
    MAX_EVENTS_PER_SLOT,
    OBSERVER_SCHEMA,
    OBSERVER_SOURCE,
    REQUIRED_FLAGS,
)


REPORT_SCHEMA = "proofbound-research-windows-wfp-report/1"
EVENT_SCHEMA = "proofbound-research-windows-wfp-event/1"
ATTACKS = (
    *predecessor.ATTACKS,
    ("EXP-0027-A039", "WIN27-OBSERVER"),
    ("EXP-0027-A040", "WIN27-COLLECTION"),
    ("EXP-0027-A041", "WIN27-EVENT-TYPE"),
    ("EXP-0027-A042", "WIN27-SUBJECT"),
    ("EXP-0027-A043", "WIN27-FLOW"),
    ("EXP-0027-A044", "WIN27-WINDOW"),
    ("EXP-0027-A045", "WIN27-DROP"),
    ("EXP-0027-A046", "WIN27-ACCEPTED"),
    ("EXP-0027-A047", "WIN27-ATTRIBUTION"),
    ("EXP-0027-A048", "WIN27-REPORT"),
)


class WindowsWfpError(ValueError):
    """A stable EXP-0027 validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise WindowsWfpError(code, message)


def _without_identity(value: dict[str, Any]) -> dict[str, Any]:
    return {name: item for name, item in value.items() if name != "identity"}


def _exact_keys(value: object, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code, "object fields differ")
    return value


def _project_predecessor(value: dict[str, Any]) -> dict[str, Any]:
    """Project the successor capture onto the complete EXP-0026 contract."""

    projected = copy.deepcopy(value)
    projected.pop("availability")
    projected.pop("observer")
    projected.pop("network_attributions")
    projected["schema"] = predecessor_execute.CAPTURE_SCHEMA
    projected["experiment"] = "EXP-0026"
    projected["programme_experiment"] = "EXP-LANG-019"
    closure = projected["closure"]
    for name in (
        "wfp_observer_source",
        "wfp_observer_executable",
        "wfp_observer_build",
    ):
        closure["instruments"].pop(name, None)
    closure["identity"] = domain_hash(
        initialization.CLOSURE_SCHEMA, _without_identity(closure)
    )
    for slot in projected["slots"]:
        slot["closure_identity"] = closure["identity"]
        slot["identity"] = domain_hash(
            initialization.SLOT_SCHEMA, _without_identity(slot)
        )
    projected["identity"] = domain_hash(
        predecessor_execute.CAPTURE_SCHEMA, _without_identity(projected)
    )
    return projected


def _validate_successor_hashes(capture: dict[str, Any]) -> dict[str, Any]:
    closure = capture["closure"]
    if not isinstance(closure, dict) or closure.get("schema") != initialization.CLOSURE_SCHEMA:
        _fail("WIN25-CLOSURE-SCHEMA", "closure schema differs")
    if closure.get("identity") != domain_hash(
        initialization.CLOSURE_SCHEMA, _without_identity(closure)
    ):
        _fail("WIN25-CLOSURE-IDENTITY", "closure identity differs")
    slots = capture["slots"]
    if not isinstance(slots, list):
        _fail("WIN25-SLOT-INVENTORY", "slots are absent")
    for slot in slots:
        if not isinstance(slot, dict):
            _fail("WIN25-SLOT-INVENTORY", "slot is not an object")
        if slot.get("closure_identity") != closure["identity"]:
            _fail("WIN25-CLOSURE-IDENTITY", "slot closure identity differs")
        if slot.get("identity") != domain_hash(
            initialization.SLOT_SCHEMA, _without_identity(slot)
        ):
            _fail("WIN25-SLOT-IDENTITY", "slot identity differs")
    return closure


def _validate_observer_source(repository: Path, closure: dict[str, Any]) -> None:
    instruments = closure["instruments"]
    if set(instruments) != {
        "registered_child_source",
        "registered_child_executable",
        "wfp_observer_source",
        "wfp_observer_executable",
        "wfp_observer_build",
    }:
        _fail("WIN27-OBSERVER", "observer instrument inventory differs")
    source = repository / OBSERVER_SOURCE
    payload = source.read_bytes()
    source_record = instruments["wfp_observer_source"]
    if (
        source_record.get("logical_name") != "instrument/wfp_observer.rs"
        or source_record.get("sha256") != sha256_bytes(payload)
        or source_record.get("size_bytes") != len(payload)
        or source_record.get("reparse_point") is not False
    ):
        _fail("WIN27-OBSERVER", "observer source identity differs")
    text = payload.decode("utf-8")
    forbidden = (
        "FwpmEngineSetOption",
        "FwpmFilterAdd",
        "FwpmFilterDelete",
        "NetworkIsolationSetAppContainerConfig",
    )
    if any(name in text for name in forbidden):
        _fail("WIN27-COLLECTION", "observer contains a policy mutation API")
    executable = instruments["wfp_observer_executable"]
    if (
        executable.get("logical_name") != "instrument/wfp_observer.exe"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", executable.get("sha256", ""))
        or not isinstance(executable.get("size_bytes"), int)
        or executable["size_bytes"] <= 0
        or executable.get("pe_machine") != "aarch64"
        or executable.get("reparse_point") is not False
    ):
        _fail("WIN27-OBSERVER", "observer executable identity differs")
    build = instruments["wfp_observer_build"]
    rust_compiler = closure["runtime_closures"]["rust"]["compiler"]["sha256"]
    if build != {
        "compiler_sha256": rust_compiler,
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
    }:
        _fail("WIN27-OBSERVER", "observer build closure differs")


def _validate_observer(value: object, closure: dict[str, Any]) -> dict[str, Any]:
    observer = _exact_keys(
        value,
        {
            "schema",
            "probe_before",
            "probe_after",
            "collection_unchanged",
            "policy_mutations",
            "event_count",
            "retained_event_identities",
            "stdout",
            "stderr",
            "identity",
        },
        "WIN27-COLLECTION",
    )
    probe = {
        "collection_enabled": True,
        "collection_query": "FwpmEngineGetOption0",
        "subscription_api": "FwpmNetEventSubscribe1",
        "event_schema": "FWPM_NET_EVENT2",
    }
    if (
        observer["schema"] != OBSERVER_SCHEMA
        or observer["probe_before"] != probe
        or observer["probe_after"] != probe
        or observer["collection_unchanged"] is not True
        or observer["policy_mutations"] != []
        or observer["stdout"] != ""
        or observer["stderr"] != ""
    ):
        _fail("WIN27-COLLECTION", "read-only collection state differs")
    identities = observer["retained_event_identities"]
    if (
        not isinstance(observer["event_count"], int)
        or observer["event_count"] < 0
        or not isinstance(identities, list)
        or len(identities) != observer["event_count"]
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item or "") for item in identities)
    ):
        _fail("WIN27-OBSERVER", "observer event inventory differs")
    if observer["identity"] != domain_hash(OBSERVER_SCHEMA, _without_identity(observer)):
        _fail("WIN27-OBSERVER", "observer identity differs")
    _ = closure
    return observer


def _validate_event(value: object) -> dict[str, Any]:
    event = _exact_keys(
        value,
        {
            "timestamp",
            "flags",
            "event_type",
            "ip_version",
            "ip_protocol",
            "local_address",
            "remote_address",
            "local_port",
            "remote_port",
            "application_id_hex",
            "package_sid",
            "capability_id",
            "filter_id",
            "is_loopback",
            "identity",
        },
        "WIN27-EVENT-TYPE",
    )
    if event["identity"] != domain_hash(EVENT_SCHEMA, _without_identity(event)):
        _fail("WIN27-EVENT-TYPE", "WFP event identity differs")
    return event


def _validate_attribution(
    value: object,
    oracle: dict[str, Any],
    slot: dict[str, Any],
    closure: dict[str, Any],
    retained_identities: set[str],
) -> str:
    attribution = _exact_keys(
        value,
        {
            "schema",
            "slot_id",
            "runtime",
            "appcontainer_sid",
            "expected_application_id_hex",
            "expected_application_path",
            "application_identity_api",
            "endpoint",
            "window",
            "events",
            "matching_capability_drops",
            "contradictory_allow",
            "outcome",
            "reusable",
            "identity",
        },
        "WIN27-ATTRIBUTION",
    )
    if attribution["schema"] != ATTRIBUTION_SCHEMA:
        _fail("WIN27-ATTRIBUTION", "attribution schema differs")
    if attribution["identity"] != domain_hash(
        ATTRIBUTION_SCHEMA, _without_identity(attribution)
    ):
        _fail("WIN27-ATTRIBUTION", "attribution identity differs")
    if (
        attribution["slot_id"] != oracle["slot_id"]
        or attribution["runtime"] != oracle["runtime"]
        or attribution["appcontainer_sid"] != oracle["appcontainer_sid"]
    ):
        _fail("WIN27-SUBJECT", "attribution subject binding differs")
    runtime = closure["runtime_closures"][oracle["runtime"]]
    expected_path = str(
        PureWindowsPath(slot["boundary"]["application_root"])
        / PureWindowsPath(runtime["executable"]["requested_path"]).name
    )
    expected_app_id = attribution["expected_application_id_hex"]
    if (
        attribution["expected_application_path"] != expected_path
        or attribution["application_identity_api"] != "FwpmGetAppIdFromFileName0"
        or not isinstance(expected_app_id, str)
        or not expected_app_id
        or len(expected_app_id) % 2
        or re.fullmatch(r"[0-9a-f]+", expected_app_id) is None
    ):
        _fail("WIN27-SUBJECT", "expected application identity differs")
    if attribution["endpoint"] != oracle["endpoint"]:
        _fail("WIN27-FLOW", "attribution endpoint differs")
    window = _exact_keys(
        attribution["window"], {"start_filetime", "end_filetime"}, "WIN27-WINDOW"
    )
    if (
        not isinstance(window["start_filetime"], int)
        or not isinstance(window["end_filetime"], int)
        or window["start_filetime"] <= 0
        or window["end_filetime"] < window["start_filetime"]
    ):
        _fail("WIN27-WINDOW", "observation window differs")
    events = attribution["events"]
    if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_SLOT:
        _fail("WIN27-OBSERVER", "per-slot event inventory differs")
    validated_events = [_validate_event(event) for event in events]
    if any(event["identity"] not in retained_identities for event in validated_events):
        _fail("WIN27-OBSERVER", "attribution event was not retained by observer")
    if any(
        event["package_sid"] != attribution["appcontainer_sid"]
        for event in validated_events
    ):
        _fail("WIN27-SUBJECT", "event package SID differs")
    if any(
        not window["start_filetime"] <= event["timestamp"] <= window["end_filetime"]
        for event in validated_events
    ):
        _fail("WIN27-WINDOW", "event is outside its execution window")
    drops = []
    for event in validated_events:
        if event["event_type"] not in {7, 8}:
            _fail("WIN27-EVENT-TYPE", "non-capability WFP event retained")
        if event["event_type"] != 7:
            continue
        if event["flags"] & REQUIRED_FLAGS != REQUIRED_FLAGS:
            _fail("WIN27-FLOW", "required WFP header flags are absent")
        if (
            event["ip_version"] != 0
            or event["ip_protocol"] != 6
            or event["remote_address"] != "127.0.0.1"
            or event["remote_port"] != oracle["endpoint"]["port"]
        ):
            _fail("WIN27-FLOW", "WFP flow binding differs")
        if event["application_id_hex"] != expected_app_id:
            _fail("WIN27-SUBJECT", "WFP application identity differs")
        if (
            event["capability_id"] not in {0, 1, 2}
            or event["filter_id"] <= 0
            or event["is_loopback"] is not True
        ):
            _fail("WIN27-DROP", "WFP capability-drop authority differs")
        drops.append(event)
    contradictory = any(event["event_type"] == 8 for event in validated_events)
    sandbox = oracle["sandbox"]
    marker = predecessor_execute.NETWORK_DENIAL_MARKERS[oracle["runtime"]]
    synchronous = marker in sandbox["stderr"]
    if sandbox["listener_accepted"] or sandbox["output_present"] or contradictory:
        expected_outcome = "accepted"
    elif synchronous:
        expected_outcome = "synchronous-denial"
    elif drops:
        expected_outcome = "capability-drop-denial"
    else:
        expected_outcome = "bounded-non-delivery"
    if attribution["matching_capability_drops"] != len(drops):
        _fail("WIN27-DROP", "capability-drop count differs")
    if attribution["contradictory_allow"] is not contradictory:
        _fail("WIN27-ACCEPTED", "capability-allow classification differs")
    if attribution["outcome"] != expected_outcome:
        _fail("WIN27-ATTRIBUTION", "typed network outcome differs")
    if attribution["reusable"] is not False:
        _fail("WIN27-REPORT", "network attribution became reusable")
    if expected_outcome == "accepted":
        _fail("WIN27-ACCEPTED", "sandboxed network connection was accepted")
    return expected_outcome


def validate_capture(value: object, repository: Path) -> dict[str, Any]:
    """Validate a decoded capture and derive its canonical report."""

    capture = _exact_keys(
        value,
        {
            "schema",
            "experiment",
            "programme_experiment",
            "availability",
            "contract_sha256",
            "candidate_sha256",
            "corpus_revision_sha256",
            "execution_environment",
            "fallback_used",
            "host",
            "closure",
            "observer",
            "slots",
            "network_oracles",
            "network_attributions",
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
        capture["experiment"] != "EXP-0027"
        or capture["programme_experiment"] != "EXP-LANG-020"
    ):
        _fail("WIN25-DISCRIMINATOR", "experiment discriminator differs")
    if capture["availability"] != "supported":
        _fail("WIN27-COLLECTION", "eligible capture is not supported")
    if capture["identity"] != domain_hash(CAPTURE_SCHEMA, _without_identity(capture)):
        _fail("WIN25-CAPTURE-SCHEMA", "capture identity differs")
    closure = _validate_successor_hashes(capture)
    _validate_observer_source(repository, closure)
    observer = _validate_observer(capture["observer"], closure)
    try:
        base = predecessor.validate_capture(_project_predecessor(capture), repository)
    except predecessor.WindowsOutputNetworkError as issue:
        raise WindowsWfpError(issue.code, issue.args[0]) from issue
    oracles = capture["network_oracles"]
    attributions = capture["network_attributions"]
    if not isinstance(attributions, list) or len(attributions) != 3:
        _fail("WIN27-ATTRIBUTION", "attribution inventory differs")
    oracle_by_slot = {oracle["slot_id"]: oracle for oracle in oracles}
    slot_by_id = {slot["slot_id"]: slot for slot in capture["slots"]}
    if len(oracle_by_slot) != 3 or len(slot_by_id) != 51:
        _fail("WIN27-ATTRIBUTION", "predecessor inventory differs")
    outcomes = []
    seen = set()
    retained = set(observer["retained_event_identities"])
    for attribution in attributions:
        if not isinstance(attribution, dict) or attribution.get("slot_id") in seen:
            _fail("WIN27-ATTRIBUTION", "attribution slot is missing or duplicated")
        slot_id = attribution["slot_id"]
        if slot_id not in oracle_by_slot or slot_id not in slot_by_id:
            _fail("WIN27-ATTRIBUTION", "attribution slot is unknown")
        seen.add(slot_id)
        outcomes.append(
            _validate_attribution(
                attribution,
                oracle_by_slot[slot_id],
                slot_by_id[slot_id],
                closure,
                retained,
            )
        )
    if seen != set(oracle_by_slot):
        _fail("WIN27-ATTRIBUTION", "attribution slots differ")
    base_metrics = base["metrics"]
    non_network_denials = sum(
        slot["mode"] != "network" and slot["outcome"] == "denied"
        for slot in capture["slots"]
    )
    network_denials = sum(
        outcome in {"synchronous-denial", "capability-drop-denial"}
        for outcome in outcomes
    )
    metrics = {
        "positive_executions": base_metrics["positive_executions"],
        "non_network_authority_denials": non_network_denials,
        "network_authority_denials": network_denials,
        "network_control_connections": base_metrics["network_control_connections"],
        "network_sandbox_connections": base_metrics["network_sandbox_connections"],
        "denied_reusable": base_metrics["denied_reusable"],
        "wfp_capability_drop_events": sum(
            attribution["matching_capability_drops"] for attribution in attributions
        ),
        "reviewed_tree_changed": base_metrics["reviewed_tree_changed"],
        "elapsed_ms": capture["elapsed_ms"],
    }
    questions = {
        "Q1": metrics["positive_executions"] == 30
        and metrics["non_network_authority_denials"] == 18
        and metrics["denied_reusable"] == 0,
        "Q2": metrics["network_authority_denials"] == 3
        and metrics["network_control_connections"] == 3
        and metrics["network_sandbox_connections"] == 0,
        "Q3": closure["frozen_before_first_slot"] is True,
        "Q4": True,
        "Q5": observer["collection_unchanged"] is True
        and observer["policy_mutations"] == []
        and metrics["reviewed_tree_changed"] is False
        and capture["within_elapsed_ceiling"] is True
        and capture["elapsed_ms"] <= MAX_ELAPSED_MS,
    }
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0027",
        "programme_experiment": "EXP-LANG-020",
        "availability": "supported",
        "contract_sha256": capture["contract_sha256"],
        "candidate_sha256": capture["candidate_sha256"],
        "corpus_revision_sha256": capture["corpus_revision_sha256"],
        "capture_identity": capture["identity"],
        "closure_identity": closure["identity"],
        "observer_identity": observer["identity"],
        "platform": capture["host"],
        "network_outcomes": outcomes,
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
    """Validate canonical EXP-0027 capture bytes and registered inputs."""

    if len(payload) > MAX_CAPTURE_BYTES:
        _fail("WIN25-CAPTURE-SCHEMA", "capture exceeds its byte ceiling")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        raise WindowsWfpError("WIN25-CAPTURE-SCHEMA", str(issue)) from issue
    if canonical_json(value) != payload:
        _fail("WIN25-CAPTURE-SCHEMA", "capture is not canonical JSON")
    return validate_capture(value, repository)


def main(argv: list[str] | None = None) -> int:
    """Validate one EXP-0027 capture into a canonical report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print("usage: windows_wfp_research REPOSITORY CAPTURE REPORT", file=sys.stderr)
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
