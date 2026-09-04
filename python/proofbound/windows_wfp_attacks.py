"""Generate and validate the registered EXP-0027 capture attacks."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from typing import Any, Callable

from proofbound.windows_enforcement_execute import (
    canonical_json,
    domain_hash,
    sha256_bytes,
)
from proofbound import windows_output_network_attacks as predecessor
from proofbound.windows_wfp_execute import (
    ATTRIBUTION_SCHEMA,
    CAPTURE_SCHEMA,
    OBSERVER_SCHEMA,
)
from proofbound.windows_wfp_research import ATTACKS, WindowsWfpError, validate_capture


INDEX_SCHEMA = "proofbound-research-windows-wfp-attack-index/1"
REPORT_SCHEMA = "proofbound-research-windows-wfp-attack-report/1"
EVENT_SCHEMA = "proofbound-research-windows-wfp-event/1"
Mutation = Callable[[dict[str, Any]], None]


def _rehash(value: dict[str, Any], schema: str) -> None:
    body = copy.deepcopy(value)
    body.pop("identity", None)
    value["identity"] = domain_hash(schema, body)


def _rehash_capture(value: dict[str, Any]) -> None:
    _rehash(value, CAPTURE_SCHEMA)


def _successor_inherited(mutate: Mutation) -> Mutation:
    def wrapped(value: dict[str, Any]) -> None:
        mutate(value)
        _rehash_capture(value)

    return wrapped


def _first_attribution(value: dict[str, Any]) -> dict[str, Any]:
    return value["network_attributions"][0]


def _first_event_attribution(value: dict[str, Any]) -> dict[str, Any]:
    return next(
        attribution
        for attribution in value["network_attributions"]
        if attribution["events"]
    )


def _rehash_attribution(value: dict[str, Any], attribution: dict[str, Any]) -> None:
    _rehash(attribution, ATTRIBUTION_SCHEMA)
    _rehash_capture(value)


def _rehash_event(
    value: dict[str, Any], attribution: dict[str, Any], event: dict[str, Any]
) -> None:
    previous = event["identity"]
    _rehash(event, EVENT_SCHEMA)
    identities = value["observer"]["retained_event_identities"]
    identities[identities.index(previous)] = event["identity"]
    _rehash(value["observer"], OBSERVER_SCHEMA)
    _rehash_attribution(value, attribution)


def _change_observer(value: dict[str, Any]) -> None:
    value["closure"]["instruments"]["wfp_observer_build"]["target"] = "x86_64-pc-windows-msvc"
    predecessor._rehash_closure(value)
    _rehash_capture(value)


def _change_collection(value: dict[str, Any]) -> None:
    observer = value["observer"]
    observer["probe_after"]["collection_enabled"] = False
    observer["collection_unchanged"] = False
    _rehash(observer, OBSERVER_SCHEMA)
    _rehash_capture(value)


def _change_event_type(value: dict[str, Any]) -> None:
    attribution = _first_event_attribution(value)
    event = attribution["events"][0]
    event["event_type"] = 3
    _rehash_event(value, attribution, event)


def _change_subject(value: dict[str, Any]) -> None:
    attribution = _first_event_attribution(value)
    event = attribution["events"][0]
    event["package_sid"] = "S-1-15-2-1"
    _rehash_event(value, attribution, event)


def _change_flow(value: dict[str, Any]) -> None:
    attribution = _first_event_attribution(value)
    event = attribution["events"][0]
    event["remote_port"] = 1
    _rehash_event(value, attribution, event)


def _change_window(value: dict[str, Any]) -> None:
    attribution = _first_event_attribution(value)
    event = attribution["events"][0]
    event["timestamp"] = attribution["window"]["end_filetime"] + 1
    _rehash_event(value, attribution, event)


def _remove_drop_authority(value: dict[str, Any]) -> None:
    attribution = _first_event_attribution(value)
    event = attribution["events"][0]
    event["filter_id"] = 0
    _rehash_event(value, attribution, event)


def _hide_allow(value: dict[str, Any]) -> None:
    attribution = _first_event_attribution(value)
    event = attribution["events"][0]
    event["event_type"] = 8
    attribution["matching_capability_drops"] -= 1
    _rehash_event(value, attribution, event)


def _forge_attribution(value: dict[str, Any]) -> None:
    attribution = _first_attribution(value)
    attribution["events"] = []
    attribution["matching_capability_drops"] = 0
    attribution["outcome"] = "capability-drop-denial"
    _rehash_attribution(value, attribution)


def _forge_reuse(value: dict[str, Any]) -> None:
    attribution = _first_attribution(value)
    attribution["reusable"] = True
    _rehash_attribution(value, attribution)


MUTATIONS: tuple[Mutation, ...] = (
    *(_successor_inherited(mutate) for mutate in predecessor.MUTATIONS),
    _change_observer,
    _change_collection,
    _change_event_type,
    _change_subject,
    _change_flow,
    _change_window,
    _remove_drop_authority,
    _hide_allow,
    _forge_attribution,
    _forge_reuse,
)


def generate_attacks(
    repository: Path, capture: dict[str, Any], output_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write every frozen attack and prove that Python rejects it exactly."""

    if len(MUTATIONS) != len(ATTACKS):
        raise AssertionError("attack registration and mutation count differ")
    output_root.mkdir(parents=True, exist_ok=False)
    rows = []
    report_rows = []
    for (attack_id, expected_code), mutate in zip(ATTACKS, MUTATIONS, strict=True):
        value = copy.deepcopy(capture)
        mutate(value)
        payload = canonical_json(value)
        path = output_root / f"{attack_id.lower()}.json"
        path.write_bytes(payload)
        try:
            validate_capture(value, repository)
        except WindowsWfpError as issue:
            actual_code = issue.code
        else:
            actual_code = "accepted"
        exact = actual_code == expected_code
        rows.append(
            {
                "id": attack_id,
                "expected_code": expected_code,
                "path": path.name,
                "sha256": sha256_bytes(payload),
                "size_bytes": len(payload),
            }
        )
        report_rows.append(
            {
                "id": attack_id,
                "expected_code": expected_code,
                "actual_code": actual_code,
                "exact": exact,
            }
        )
    index = {"schema": INDEX_SCHEMA, "attacks": rows}
    index["identity"] = domain_hash(INDEX_SCHEMA, index)
    report = {
        "schema": REPORT_SCHEMA,
        "attacks": report_rows,
        "all_exact": all(row["exact"] for row in report_rows),
    }
    report["identity"] = domain_hash(REPORT_SCHEMA, report)
    return index, report


def main(argv: list[str] | None = None) -> int:
    """Materialize and validate the frozen EXP-0027 attack corpus."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 5:
        print(
            "usage: windows_wfp_attacks REPOSITORY CAPTURE ATTACK_ROOT INDEX REPORT",
            file=sys.stderr,
        )
        return 2
    try:
        repository = Path(arguments[0])
        capture = json.loads(Path(arguments[1]).read_bytes())
        index, report = generate_attacks(repository, capture, Path(arguments[2]))
        Path(arguments[3]).write_bytes(canonical_json(index))
        Path(arguments[4]).write_bytes(canonical_json(report))
    except (OSError, ValueError, json.JSONDecodeError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0 if report["all_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
