"""Independently validate EXP-0019 batched enforcement captures."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, NoReturn

from proofbound import enforced_effects_research as effects

CAPTURE_SCHEMA = "proofbound-research-batched-enforcement-capture/1"
REPORT_SCHEMA = "proofbound-research-batched-enforcement-report/1"
REPORT_DOMAIN = "proofbound-research-batched-enforcement-report/1"
CORPUS_IDENTITY = effects.CORPUS_IDENTITY
SUBJECTS = ["subject:node", "subject:python", "subject:rust"]
SCHEDULER_ATTACKS = [
    ("EXP-0019-A031", "BFX-SLOT-MISSING"),
    ("EXP-0019-A032", "BFX-SLOT-DUPLICATE"),
    ("EXP-0019-A033", "BFX-NONCANONICAL"),
    ("EXP-0019-A034", "BFX-SLOT-BINDING"),
    ("EXP-0019-A035", "BFX-EPHEMERAL-ALIAS"),
    ("EXP-0019-A036", "BFX-OUTPUT-ALIAS"),
    ("EXP-0019-A037", "BFX-PARTIAL"),
    ("EXP-0019-A038", "EFX-POLICY-IDENTITY"),
    ("EXP-0019-A039", "EFX-RUN-OUTCOME"),
    ("EXP-0019-A040", "BFX-REPORT-IDENTITY"),
]
CAPTURE_KEYS = {
    "schema",
    "experiment",
    "corpus_identity",
    "scheduler",
    "max_in_flight",
    "platform",
    "mechanism",
    "slots",
    "completed_slots",
    "reviewed_tree_before",
    "reviewed_tree_after",
    "elapsed_ms",
}
SLOT_KEYS = {
    "slot_id",
    "kind",
    "subject_id",
    "repetition",
    "attack_id",
    "expected_denial_code",
    "receipt",
}


class BatchedEnforcementError(ValueError):
    """Report one exact independent batch-validation rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def validate_capture_bytes(repository: Path, data: bytes) -> dict[str, Any]:
    """Validate canonical capture bytes and derive the independent report.

    Args:
        repository: Proofbound repository containing the frozen EXP-0018 corpus.
        data: Canonical EXP-0019 capture bytes.

    Returns:
        Canonicalizable independently derived batch report.

    Raises:
        BatchedEnforcementError: If decoding or validation fails.
    """

    try:
        capture = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as issue:
        _raise("BFX-DECODE", f"invalid capture: {issue}")
    if effects.canonical_json(capture) != data:
        _raise("BFX-NONCANONICAL", "capture is not canonical JSON")
    return validate_capture(repository, capture)


def validate_capture(repository: Path, capture: dict[str, Any]) -> dict[str, Any]:
    """Validate one batch without executing a subject language."""

    _validate_structure(capture)
    base_report = effects.validate_capture(repository, _base_projection(capture))
    scheduler_attacks = _execute_scheduler_attacks(capture)
    positives = [slot for slot in capture["slots"] if slot["kind"] == "positive"]
    probes = [slot for slot in capture["slots"] if slot["kind"] == "authority-probe"]
    metrics = {
        "positive_executions": len(positives),
        "authority_probe_executions": len(probes),
        "completed_slots": capture["completed_slots"],
        "denied_reusable": sum(slot["receipt"]["reusable"] for slot in probes),
        "unique_ephemeral_roots": len(
            {slot["receipt"]["plan"]["ephemeral_root"] for slot in capture["slots"]}
        ),
        "unique_positive_outputs": len(
            {slot["receipt"]["run"]["output"]["path"] for slot in positives}
        ),
        "base_attack_rejections": sum(item["exact"] for item in base_report["attacks"]),
        "scheduler_attack_rejections": sum(item["exact"] for item in scheduler_attacks),
        "stale_reuse": base_report["metrics"]["stale_reuse"],
        "unrelated_invalidation": base_report["metrics"]["unrelated_invalidation"],
        "reviewed_tree_changed": (
            capture["reviewed_tree_before"] != capture["reviewed_tree_after"]
        ),
        "elapsed_ms": capture["elapsed_ms"],
    }
    if metrics != {
        "positive_executions": 30,
        "authority_probe_executions": 21,
        "completed_slots": 51,
        "denied_reusable": 0,
        "unique_ephemeral_roots": 51,
        "unique_positive_outputs": 30,
        "base_attack_rejections": 30,
        "scheduler_attack_rejections": 10,
        "stale_reuse": 0,
        "unrelated_invalidation": 0,
        "reviewed_tree_changed": False,
        "elapsed_ms": capture["elapsed_ms"],
    }:
        _raise("BFX-METRICS", "batch metrics differ")
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0019",
        "corpus_identity": CORPUS_IDENTITY,
        "scheduler": capture["scheduler"],
        "platform": capture["platform"],
        "mechanism": capture["mechanism"],
        "base_report_identity": base_report["identity"],
        "slot_identities": [
            [slot["slot_id"], slot["receipt"]["identity"]] for slot in capture["slots"]
        ],
        "base_attacks": base_report["attacks"],
        "scheduler_attacks": scheduler_attacks,
        "metrics": metrics,
        "identity": "",
    }
    report["identity"] = _hash_without(REPORT_DOMAIN, report, "identity")
    validate_report(report)
    return report


def validate_report(report: dict[str, Any]) -> None:
    """Validate a derived batch report and its identity."""

    if report.get("schema") != REPORT_SCHEMA or report.get("experiment") != "EXP-0019":
        _raise("BFX-SCHEMA", "batch report schema differs")
    if report.get("identity") != _hash_without(REPORT_DOMAIN, report, "identity"):
        _raise("BFX-REPORT-IDENTITY", "batch report identity differs")


def _validate_structure(capture: dict[str, Any]) -> None:
    _keys(capture, CAPTURE_KEYS)
    if (
        capture["schema"] != CAPTURE_SCHEMA
        or capture["experiment"] != "EXP-0019"
        or capture["corpus_identity"] != CORPUS_IDENTITY
        or capture["scheduler"] != "concurrent-isolated-processes"
        or capture["max_in_flight"] != 51
    ):
        _raise("BFX-SCHEMA", "batch capture identity differs")
    slots = capture["slots"]
    if not isinstance(slots, list):
        _raise("BFX-DECODE", "slots are not an array")
    if capture["completed_slots"] != len(slots):
        _raise("BFX-PARTIAL", "batch completion count differs")
    for slot in slots:
        _keys(slot, SLOT_KEYS)
    actual = [slot["slot_id"] for slot in slots]
    if len(set(actual)) != len(actual):
        _raise("BFX-SLOT-DUPLICATE", "batch slot is duplicated")
    expected = _expected_slots()
    if len(actual) < len(expected):
        _raise("BFX-SLOT-MISSING", "batch slot is absent")
    if len(actual) > len(expected):
        _raise("BFX-SLOT-DUPLICATE", "batch has an extra slot")
    if set(actual) != set(expected):
        _raise("BFX-SLOT-BINDING", "batch slot inventory differs")
    if actual != expected:
        _raise("BFX-NONCANONICAL", "batch slots are not canonical")
    roots = [slot["receipt"]["plan"]["ephemeral_root"] for slot in slots]
    if len(set(roots)) != len(roots):
        _raise("BFX-EPHEMERAL-ALIAS", "ephemeral root is shared")
    outputs = [
        slot["receipt"]["run"]["output"]["path"]
        for slot in slots
        if slot["kind"] == "positive"
    ]
    if len(set(outputs)) != len(outputs):
        _raise("BFX-OUTPUT-ALIAS", "positive output is shared")
    if capture["reviewed_tree_before"] != capture["reviewed_tree_after"]:
        _raise("EFX-REVIEWED-WRITE-DENIED", "reviewed tree changed")
    for slot in slots:
        _validate_slot_binding(slot)
        plan = slot["receipt"]["plan"]
        if (
            plan["platform"] != capture["platform"]
            or plan["mechanism"] != capture["mechanism"]
        ):
            _raise("BFX-SLOT-BINDING", "slot boundary differs")
        try:
            effects.validate_receipt(slot["receipt"])
        except effects.EnforcedEffectsError as issue:
            _raise(issue.code, str(issue).split(": ", 1)[-1])


def _validate_slot_binding(slot: dict[str, Any]) -> None:
    plan = slot["receipt"]["plan"]
    subject = slot["subject_id"]
    if plan["subject_id"] != subject:
        _raise("BFX-SLOT-BINDING", "slot subject differs")
    suffix = _subject_suffix(subject)
    if slot["kind"] == "positive":
        repetition = slot["repetition"]
        if (
            not isinstance(repetition, int)
            or isinstance(repetition, bool)
            or not 0 <= repetition < 10
            or slot["slot_id"] != f"positive-{repetition:02}-{suffix}"
            or slot["attack_id"] is not None
            or slot["expected_denial_code"] is not None
            or plan["mode"] != "positive"
        ):
            _raise("BFX-SLOT-BINDING", "positive slot differs")
        return
    if slot["kind"] != "authority-probe":
        _raise("BFX-SLOT-BINDING", "slot kind differs")
    definition = _authority_definition(slot["attack_id"])
    if definition is None:
        _raise("BFX-SLOT-BINDING", "probe attack is unknown")
    ordinal, mode, denial = definition
    if (
        slot["slot_id"] != f"probe-{ordinal:03}-{suffix}"
        or slot["repetition"] is not None
        or slot["expected_denial_code"] != denial
        or plan["mode"] != mode
    ):
        _raise("BFX-SLOT-BINDING", "authority slot differs")


def _base_projection(capture: dict[str, Any]) -> dict[str, Any]:
    first = {}
    for slot in capture["slots"]:
        if slot["kind"] == "positive":
            first.setdefault(slot["subject_id"], slot["receipt"])
    positives = []
    for _ in range(10):
        for subject in SUBJECTS:
            if subject not in first:
                _raise("BFX-SLOT-MISSING", "positive subject is absent")
            positives.append(deepcopy(first[subject]))
    probes = [
        {
            "attack_id": slot["attack_id"],
            "subject_id": slot["subject_id"],
            "denial_code": slot["expected_denial_code"],
            "receipt": deepcopy(slot["receipt"]),
        }
        for slot in capture["slots"]
        if slot["kind"] == "authority-probe"
    ]
    return {
        "schema": effects.CAPTURE_SCHEMA,
        "experiment": "EXP-0018",
        "corpus_identity": CORPUS_IDENTITY,
        "platform": capture["platform"],
        "mechanism": capture["mechanism"],
        "positive_runs": positives,
        "authority_probes": probes,
        "reviewed_tree_before": capture["reviewed_tree_before"],
        "reviewed_tree_after": capture["reviewed_tree_after"],
        "elapsed_ms": capture["elapsed_ms"],
    }


def _execute_scheduler_attacks(capture: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for attack_id, expected in SCHEDULER_ATTACKS:
        if attack_id == "EXP-0019-A040":
            forged = _empty_forged_report(capture)
            actual = _rejection_code(lambda: validate_report(forged))
        else:
            altered = _mutate_capture(capture, attack_id)
            actual = _rejection_code(lambda: _validate_structure(altered))
        results.append(
            {
                "id": attack_id,
                "expected_code": expected,
                "actual_code": actual,
                "exact": actual == expected,
            }
        )
    return results


def _mutate_capture(capture: dict[str, Any], attack_id: str) -> dict[str, Any]:
    altered = deepcopy(capture)
    slots = altered["slots"]
    if attack_id == "EXP-0019-A031":
        slots.pop()
        altered["completed_slots"] -= 1
    elif attack_id == "EXP-0019-A032":
        slots.append(deepcopy(slots[0]))
        altered["completed_slots"] += 1
    elif attack_id == "EXP-0019-A033":
        slots[0], slots[1] = slots[1], slots[0]
    elif attack_id == "EXP-0019-A034":
        slots[0]["receipt"], slots[1]["receipt"] = (
            slots[1]["receipt"],
            slots[0]["receipt"],
        )
    elif attack_id == "EXP-0019-A035":
        slots[1]["receipt"]["plan"]["ephemeral_root"] = slots[0]["receipt"]["plan"][
            "ephemeral_root"
        ]
    elif attack_id == "EXP-0019-A036":
        slots[1]["receipt"]["run"]["output"]["path"] = slots[0]["receipt"]["run"][
            "output"
        ]["path"]
    elif attack_id == "EXP-0019-A037":
        altered["completed_slots"] -= 1
    elif attack_id == "EXP-0019-A038":
        plan = slots[0]["receipt"]["plan"]
        plan["policy"] += "(allow file-read*)\n"
        plan["command"]["arguments"][1] = plan["policy"]
    elif attack_id == "EXP-0019-A039":
        next(slot for slot in slots if slot["kind"] == "authority-probe")["receipt"][
            "reusable"
        ] = True
    else:
        _raise("BFX-CORPUS", f"unknown attack {attack_id}")
    return altered


def _empty_forged_report(capture: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0019",
        "corpus_identity": CORPUS_IDENTITY,
        "scheduler": capture["scheduler"],
        "platform": capture["platform"],
        "mechanism": capture["mechanism"],
        "base_report_identity": "sha256:" + "0" * 64,
        "slot_identities": [],
        "base_attacks": [],
        "scheduler_attacks": [],
        "metrics": {
            "positive_executions": 0,
            "authority_probe_executions": 0,
            "completed_slots": 0,
            "denied_reusable": 0,
            "unique_ephemeral_roots": 0,
            "unique_positive_outputs": 0,
            "base_attack_rejections": 0,
            "scheduler_attack_rejections": 0,
            "stale_reuse": 0,
            "unrelated_invalidation": 0,
            "reviewed_tree_changed": False,
            "elapsed_ms": 0,
        },
        "identity": "sha256:" + "0" * 64,
    }


def _expected_slots() -> list[str]:
    slots = [
        f"positive-{repetition:02}-{subject}"
        for repetition in range(10)
        for subject in ["node", "python", "rust"]
    ]
    slots.extend(
        f"probe-{ordinal:03}-{subject}"
        for ordinal in [1, 2, 7, 9, 11, 12, 13]
        for subject in ["node", "python", "rust"]
    )
    return sorted(slots)


def _authority_definition(attack_id: object) -> tuple[int, str, str] | None:
    definitions = {
        "EXP-0018-A001": (1, "read-undeclared", "EFX-FILE-READ-DENIED"),
        "EXP-0018-A002": (2, "read-undeclared", "EFX-FILE-READ-DENIED"),
        "EXP-0018-A007": (7, "environment-undeclared", "EFX-ENV-DENIED"),
        "EXP-0018-A009": (9, "execute-unregistered", "EFX-EXEC-DENIED"),
        "EXP-0018-A011": (11, "network", "EFX-NETWORK-DENIED"),
        "EXP-0018-A012": (12, "write-reviewed", "EFX-REVIEWED-WRITE-DENIED"),
        "EXP-0018-A013": (13, "write-escape", "EFX-WRITE-ESCAPE"),
    }
    return definitions.get(attack_id) if isinstance(attack_id, str) else None


def _subject_suffix(subject: object) -> str:
    if not isinstance(subject, str) or subject not in SUBJECTS:
        _raise("BFX-SLOT-BINDING", "subject is unknown")
    return subject.removeprefix("subject:")


def _hash_without(domain: str, value: dict[str, Any], field: str) -> str:
    material = deepcopy(value)
    material.pop(field, None)
    return effects.domain_hash(domain, effects.canonical_json(material))


def _keys(value: object, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _raise("BFX-DECODE", "object fields differ")


def _rejection_code(operation: Any) -> str:
    try:
        operation()
    except BatchedEnforcementError as issue:
        return issue.code
    return "ACCEPTED"


def _raise(code: str, message: str) -> NoReturn:
    raise BatchedEnforcementError(code, message)


def main(argv: list[str] | None = None) -> int:
    """Validate a capture and write one canonical independent report."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: python -m proofbound.batched_enforcement_research "
            "<repository> <capture.json> <report.json>",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(arguments[0]), Path(arguments[1]).read_bytes()
        )
        Path(arguments[2]).write_bytes(effects.canonical_json(report))
    except (OSError, BatchedEnforcementError, effects.EnforcedEffectsError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
