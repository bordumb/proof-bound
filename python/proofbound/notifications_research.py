"""Independent claim-oriented notification model for Experiment 0013."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn

CORPUS_SCHEMA = "proofbound-research-notification-corpus/1"
REPORT_SCHEMA = "proofbound-research-notification-report/1"
MODEL_REPORT_SCHEMA = "proofbound-research-notification-model-report/1"
ATTACK_SCHEMA = "proofbound-research-notification-attacks/1"

KINDS = (
    "assumption",
    "exclusion",
    "uncertainty",
    "contradiction",
    "stale-evidence",
    "missing-evidence",
)
CONSEQUENCES = {"may-weaken", "does-not-strengthen", "blocks-publication"}
PUBLICATION_CONSEQUENCES = {"block", "warn", "none"}
SEVERITIES = {"low", "medium", "high", "critical"}


class NotificationFailure(ValueError):
    """Report one exact notification-model rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    """Encode a research record as compact sorted-key UTF-8 JSON."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def domain_hash(domain: str, payload: bytes) -> str:
    """Return a domain-separated SHA-256 identity."""

    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def load_notification_corpus(
    root: Path, corpus_dir: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and validate the frozen scenario and attack corpora."""

    corpus = _load_json(root / corpus_dir / "scenarios.json")
    attacks = _load_json(root / corpus_dir / "attacks.json")
    validate_notification_corpus(corpus)
    _exact_keys(attacks, {"schema", "attacks"}, "UNCERTAINTY-SCHEMA")
    if attacks["schema"] != ATTACK_SCHEMA:
        _fail("UNCERTAINTY-SCHEMA", "unexpected attack schema")
    if not isinstance(attacks["attacks"], list) or not attacks["attacks"]:
        _fail("UNCERTAINTY-NONCANONICAL", "attack corpus is empty")
    identifiers: set[str] = set()
    for attack in attacks["attacks"]:
        _exact_keys(attack, {"id", "base", "code", "action"}, "UNCERTAINTY-SCHEMA")
        _validate_id(attack["id"], "attack")
        _validate_id(attack["base"], "attack base")
        _validate_id(attack["code"], "attack code")
        if attack["id"] in identifiers:
            _fail("UNCERTAINTY-NONCANONICAL", "duplicate attack ID")
        identifiers.add(attack["id"])
        if not isinstance(attack["action"], dict):
            _fail("UNCERTAINTY-SCHEMA", "attack action is not an object")
    return corpus, attacks


def validate_notification_corpus(corpus: dict[str, Any]) -> None:
    """Validate all closed records and joins in a notification corpus."""

    _exact_keys(corpus, {"schema", "scenarios"}, "UNCERTAINTY-SCHEMA")
    if corpus["schema"] != CORPUS_SCHEMA:
        _fail("UNCERTAINTY-SCHEMA", "unexpected corpus schema")
    scenarios = corpus["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        _fail("UNCERTAINTY-SCHEMA", "scenario corpus is empty")
    seen: set[str] = set()
    for scenario in scenarios:
        _validate_scenario(scenario)
        if scenario["id"] in seen:
            _fail("UNCERTAINTY-NONCANONICAL", "duplicate scenario ID")
        seen.add(scenario["id"])


def derive_notification_report(corpus: dict[str, Any]) -> dict[str, Any]:
    """Derive baseline alerts, decision notifications, and graph updates."""

    validate_notification_corpus(corpus)
    baseline: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    groups: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    kinds: set[str] = set()
    scenario_identities: list[dict[str, str]] = []
    for scenario in corpus["scenarios"]:
        facts = {fact["id"]: fact for fact in scenario["facts"]}
        kinds.update(fact["kind"] for fact in scenario["facts"])
        scenario_identities.append(
            {
                "id": scenario["id"],
                "identity": domain_hash(
                    "proofbound-research-notification-scenario/1",
                    canonical_json(scenario),
                ),
            }
        )
        for finding in scenario["findings"]:
            alert = {
                "identity": "",
                "scenario": scenario["id"],
                "finding": finding["id"],
                "fact": finding["fact"],
                "tool": finding["tool"],
                "code": finding["code"],
                "severity": finding["severity"],
            }
            alert["identity"] = domain_hash(
                "proofbound-research-tool-alert/1",
                canonical_json(
                    {key: value for key, value in alert.items() if key != "identity"}
                ),
            )
            baseline.append(alert)
            consumed = [
                path
                for path in scenario["paths"]
                if path["finding"] == finding["id"] and path["consumed"]
            ]
            if not consumed:
                updates.append(
                    {
                        "scenario": scenario["id"],
                        "finding": finding["id"],
                        "fact": finding["fact"],
                        "reason": "no-consumed-claim-path",
                    }
                )
            for path in consumed:
                key = (
                    scenario["id"],
                    path["claim"],
                    facts[path["fact"]]["kind"],
                    path["requested_action"],
                    path["publication_consequence"],
                )
                groups.setdefault(key, []).append(deepcopy(path))
    notifications: list[dict[str, Any]] = []
    for key in sorted(groups):
        paths = sorted(groups[key], key=lambda item: _path_order(item))
        notification = {
            "identity": "",
            "scenario": key[0],
            "claim": key[1],
            "kind": key[2],
            "requested_action": key[3],
            "publication_consequence": key[4],
            "findings": sorted({path["finding"] for path in paths}),
            "paths": paths,
        }
        notification["identity"] = _notification_identity(notification)
        notifications.append(notification)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "baseline_alerts": sorted(baseline, key=_baseline_order),
        "notifications": sorted(notifications, key=lambda item: item["identity"]),
        "graph_updates": sorted(updates, key=_update_order),
        "fact_kinds": [kind for kind in KINDS if kind in kinds],
        "scenario_identities": sorted(
            scenario_identities, key=lambda item: (item["id"], item["identity"])
        ),
        "identity": "",
    }
    report["identity"] = _report_identity(report)
    return report


def validate_notification_report(
    corpus: dict[str, Any], report: dict[str, Any]
) -> None:
    """Validate a complete decision report against independent derivation."""

    validate_notification_corpus(corpus)
    _exact_keys(
        report,
        {
            "schema",
            "baseline_alerts",
            "notifications",
            "graph_updates",
            "fact_kinds",
            "scenario_identities",
            "identity",
        },
        "UNCERTAINTY-SCHEMA",
    )
    if report["schema"] != REPORT_SCHEMA or report["identity"] != _report_identity(
        report
    ):
        _fail("UNCERTAINTY-IDENTITY-FORGED", "report identity is invalid")
    identities = [item["identity"] for item in report["notifications"]]
    if identities != sorted(set(identities)):
        _fail("UNCERTAINTY-NOTIFICATION-DUPLICATE", "notifications are not canonical")
    if report["baseline_alerts"] != sorted(
        report["baseline_alerts"], key=_baseline_order
    ):
        _fail("UNCERTAINTY-NONCANONICAL", "baseline alerts are not canonical")
    for notification in report["notifications"]:
        if notification["identity"] != _notification_identity(notification):
            _fail("UNCERTAINTY-IDENTITY-FORGED", "notification identity is invalid")
    expected = derive_notification_report(corpus)
    if report == expected:
        return
    _classify_report_difference(expected, report)


def execute_notification_corpus(
    root: Path, corpus_dir: Path, repetitions: int
) -> dict[str, Any]:
    """Execute the frozen model and every registered attack."""

    if isinstance(repetitions, bool) or not 1 <= repetitions <= 100:
        _fail("UNCERTAINTY-REPETITIONS", "invalid repetition count")
    corpus, attack_corpus = load_notification_corpus(root, corpus_dir)
    report = derive_notification_report(corpus)
    validate_notification_report(corpus, report)
    repeated: list[str] = []
    for _ in range(repetitions):
        candidate = derive_notification_report(corpus)
        if candidate != report:
            _fail("UNCERTAINTY-NONDETERMINISTIC", "report changed")
        repeated.append(candidate["identity"])
    scenarios = {scenario["id"]: scenario for scenario in corpus["scenarios"]}
    results = [
        _evaluate_attack(corpus, scenarios[attack["base"]], attack)
        for attack in attack_corpus["attacks"]
    ]
    return {
        "schema": MODEL_REPORT_SCHEMA,
        "decision_report": report,
        "attacks": results,
        "repetition_report_identities": repeated,
    }


def _validate_scenario(scenario: dict[str, Any]) -> None:
    _exact_keys(
        scenario, {"id", "claims", "facts", "findings", "paths"}, "UNCERTAINTY-SCHEMA"
    )
    _validate_id(scenario["id"], "scenario")
    for field in ("claims", "facts", "findings", "paths"):
        values = scenario[field]
        if not isinstance(values, list) or not values:
            _fail("UNCERTAINTY-NONCANONICAL", f"{field} is empty")
        identifiers = [item.get("id") for item in values]
        if identifiers != sorted(set(identifiers)):
            _fail("UNCERTAINTY-NONCANONICAL", f"{field} IDs are not canonical")
    claims: set[str] = set()
    for claim in scenario["claims"]:
        _exact_keys(claim, {"id", "title", "publication_gate"}, "UNCERTAINTY-SCHEMA")
        _validate_id(claim["id"], "claim")
        _validate_text(claim["title"], "claim title")
        if not isinstance(claim["publication_gate"], bool):
            _fail("UNCERTAINTY-SCHEMA", "publication gate is not Boolean")
        claims.add(claim["id"])
    facts: dict[str, dict[str, Any]] = {}
    for fact in scenario["facts"]:
        _validate_fact(fact)
        facts[fact["id"]] = fact
    findings: dict[str, dict[str, Any]] = {}
    for finding in scenario["findings"]:
        _exact_keys(
            finding, {"id", "tool", "code", "severity", "fact"}, "UNCERTAINTY-SCHEMA"
        )
        _validate_id(finding["id"], "finding")
        _validate_id(finding["tool"], "tool")
        _validate_id(finding["code"], "finding code")
        if finding["severity"] not in SEVERITIES:
            _fail("UNCERTAINTY-SCHEMA", "invalid severity")
        if finding["fact"] not in facts:
            _fail("UNCERTAINTY-PATH-FORGED", "finding references an unknown fact")
        findings[finding["id"]] = finding
    for path in scenario["paths"]:
        _validate_path(path, claims, facts, findings)


def _validate_fact(fact: dict[str, Any]) -> None:
    _exact_keys(
        fact,
        {"id", "kind", "owner", "scope", "expires_at", "consequence", "evidence"},
        "UNCERTAINTY-SCHEMA",
    )
    _validate_id(fact["id"], "fact")
    if fact["kind"] not in KINDS:
        _fail("UNCERTAINTY-KIND-ALIAS", "invalid uncertainty kind")
    try:
        _validate_text(fact["owner"], "owner")
    except NotificationFailure:
        _fail("UNCERTAINTY-OWNER-MISSING", "fact owner is missing")
    _validate_text(fact["scope"], "scope")
    if fact["expires_at"] is not None:
        _validate_timestamp(fact["expires_at"])
    if fact["consequence"] not in CONSEQUENCES:
        _fail("UNCERTAINTY-SCHEMA", "invalid consequence")
    evidence = fact["evidence"]
    if not isinstance(evidence, list) or evidence != sorted(set(evidence)):
        _fail("UNCERTAINTY-EVIDENCE-SET", "fact evidence is not canonical")
    if any(not _is_digest(identity) for identity in evidence):
        _fail("UNCERTAINTY-EVIDENCE-SET", "fact evidence identity is invalid")
    kind = fact["kind"]
    consequence = fact["consequence"]
    if kind == "assumption" and (
        fact["expires_at"] is None or consequence != "may-weaken"
    ):
        _fail("UNCERTAINTY-EXPIRY-MISSING", "assumption semantics are invalid")
    if kind == "exclusion" and consequence != "does-not-strengthen":
        _fail("UNCERTAINTY-EXCLUSION-STRENGTH", "exclusion semantics are invalid")
    if kind == "contradiction" and (
        len(evidence) < 2 or consequence != "blocks-publication"
    ):
        _fail(
            "UNCERTAINTY-CONTRADICTION-INVALID", "contradiction semantics are invalid"
        )
    if kind == "stale-evidence" and (len(evidence) != 1 or consequence != "may-weaken"):
        _fail("UNCERTAINTY-STALE-CURRENT", "stale evidence semantics are invalid")
    if kind == "missing-evidence" and (evidence or consequence != "blocks-publication"):
        _fail(
            "UNCERTAINTY-MISSING-SUPPRESSED", "missing evidence semantics are invalid"
        )


def _validate_path(
    path: dict[str, Any],
    claims: set[str],
    facts: dict[str, dict[str, Any]],
    findings: dict[str, dict[str, Any]],
) -> None:
    _exact_keys(
        path,
        {
            "id",
            "finding",
            "fact",
            "claim",
            "nodes",
            "consumed",
            "requested_action",
            "publication_consequence",
        },
        "UNCERTAINTY-SCHEMA",
    )
    _validate_id(path["id"], "path")
    _validate_id(path["requested_action"], "action")
    if not isinstance(path["consumed"], bool):
        _fail("UNCERTAINTY-SCHEMA", "consumed is not Boolean")
    if path["publication_consequence"] not in PUBLICATION_CONSEQUENCES:
        _fail("UNCERTAINTY-SCHEMA", "invalid publication consequence")
    finding = findings.get(path["finding"])
    if finding is None:
        _fail("UNCERTAINTY-PATH-MISSING", "path finding is missing")
    if (
        finding["fact"] != path["fact"]
        or path["fact"] not in facts
        or path["claim"] not in claims
    ):
        _fail("UNCERTAINTY-CLAIM-UNKNOWN", "path join is unknown or mismatched")
    nodes = path["nodes"]
    expected = (
        f"finding:{path['finding']}",
        f"fact:{path['fact']}",
        f"claim:{path['claim']}",
    )
    if (
        not isinstance(nodes, list)
        or len(nodes) < 3
        or nodes[0] != expected[0]
        or nodes[1] != expected[1]
        or nodes[-1] != expected[2]
        or len(nodes) != len(set(nodes))
    ):
        _fail("UNCERTAINTY-PATH-FORGED", "dependency path is not exact")
    for node in nodes:
        _validate_text(node, "path node")


def _evaluate_attack(
    corpus: dict[str, Any], scenario: dict[str, Any], attack: dict[str, Any]
) -> dict[str, Any]:
    try:
        _run_attack(corpus, scenario, attack["action"])
    except NotificationFailure as error:
        actual = error.code
    else:
        actual = "ACCEPTED"
    return {
        "id": attack["id"],
        "expected_code": attack["code"],
        "actual_code": actual,
        "exact": actual == attack["code"],
    }


def _run_attack(
    corpus: dict[str, Any], scenario: dict[str, Any], action: dict[str, Any]
) -> None:
    kind = action.get("kind")
    if kind == "substitute-kind":
        mutated = deepcopy(scenario)
        fact = _find(mutated["facts"], action["fact"], "UNCERTAINTY-FACT")
        value = action["value"]
        fact["kind"] = value
        code = {
            "evidence": "UNCERTAINTY-ASSUMPTION-EVIDENCE",
            "current-evidence": "UNCERTAINTY-STALE-CURRENT",
        }.get(value, "UNCERTAINTY-KIND-ALIAS")
        try:
            _validate_scenario(mutated)
        except NotificationFailure:
            _fail(code, "uncertainty kind substitution rejected")
        return
    if kind == "substitute-consequence":
        mutated = deepcopy(scenario)
        _find(mutated["facts"], action["fact"], "UNCERTAINTY-FACT")["consequence"] = (
            "may-weaken"
        )
        _validate_scenario(mutated)
        return
    if kind == "drop-finding":
        mutated = deepcopy(scenario)
        mutated["findings"] = [
            item for item in mutated["findings"] if item["id"] != action["finding"]
        ]
        try:
            _validate_scenario(mutated)
        except NotificationFailure:
            _fail("UNCERTAINTY-CRITICAL-DROPPED", "consumed finding was removed")
        return
    if kind == "remove-path":
        mutated = deepcopy(scenario)
        mutated["paths"] = [
            item for item in mutated["paths"] if item["id"] != action["path"]
        ]
        base = derive_notification_report(
            {"schema": CORPUS_SCHEMA, "scenarios": [scenario]}
        )
        changed = derive_notification_report(
            {"schema": CORPUS_SCHEMA, "scenarios": [mutated]}
        )
        if changed["notifications"] != base["notifications"]:
            _fail("UNCERTAINTY-PATH-MISSING", "consumed impact path was removed")
        return
    if kind in {"substitute-path-node", "substitute-claim"}:
        mutated = deepcopy(scenario)
        path = _find(mutated["paths"], action["path"], "UNCERTAINTY-PATH-MISSING")
        if kind == "substitute-path-node":
            path["nodes"][-1] = action["value"]
        else:
            path["claim"] = action["claim"]
        _validate_scenario(mutated)
        return
    if kind in {"remove-owner", "remove-expiry"}:
        mutated = deepcopy(scenario)
        fact = _find(mutated["facts"], action["fact"], "UNCERTAINTY-FACT")
        fact.pop("owner" if kind == "remove-owner" else "expires_at")
        code = (
            "UNCERTAINTY-OWNER-MISSING"
            if kind == "remove-owner"
            else "UNCERTAINTY-EXPIRY-MISSING"
        )
        try:
            _validate_scenario(mutated)
        except (NotificationFailure, KeyError):
            _fail(code, "required fact field was omitted")
        return
    if kind in {"remove-action", "remove-publication"}:
        mutated = deepcopy(scenario)
        path = _find(mutated["paths"], action["path"], "UNCERTAINTY-PATH-MISSING")
        path.pop(
            "requested_action" if kind == "remove-action" else "publication_consequence"
        )
        code = (
            "UNCERTAINTY-ACTION-MISSING"
            if kind == "remove-action"
            else "UNCERTAINTY-PUBLICATION-MISSING"
        )
        try:
            _validate_scenario(mutated)
        except (NotificationFailure, KeyError):
            _fail(code, "required path field was omitted")
        return
    if kind == "duplicate-finding":
        mutated = deepcopy(scenario)
        mutated["findings"].append(
            deepcopy(
                _find(mutated["findings"], action["finding"], "UNCERTAINTY-FINDING")
            )
        )
        try:
            _validate_scenario(mutated)
        except NotificationFailure:
            _fail("UNCERTAINTY-FINDING-DUPLICATE", "finding was duplicated")
        return
    if kind == "reverse-findings":
        mutated = deepcopy(scenario)
        mutated["findings"].reverse()
        _validate_scenario(mutated)
        return
    report = derive_notification_report(corpus)
    if kind == "drop-notification":
        report["notifications"] = [
            item
            for item in report["notifications"]
            if item["scenario"] != action["scenario"]
        ]
    elif kind == "merge-notifications":
        indices = [
            index
            for index, item in enumerate(report["notifications"])
            if item["scenario"] in action["scenarios"]
        ]
        if len(indices) >= 2:
            first, second = indices[:2]
            removed = report["notifications"].pop(second)
            merged = report["notifications"][first]
            merged["findings"] = sorted(merged["findings"] + removed["findings"])
            merged["paths"] = sorted(
                merged["paths"] + removed["paths"], key=_path_order
            )
            merged["identity"] = _notification_identity(merged)
    elif kind == "duplicate-notification":
        report["notifications"].append(
            deepcopy(
                next(
                    item
                    for item in report["notifications"]
                    if item["scenario"] == action["scenario"]
                )
            )
        )
    elif kind == "forge-report-identity":
        report["identity"] = action["value"]
        validate_notification_report(corpus, report)
        return
    elif kind == "escalate-unrelated":
        update = next(
            item
            for item in report["graph_updates"]
            if item["finding"] == action["finding"]
        )
        notification = {
            "identity": "",
            "scenario": update["scenario"],
            "claim": "RELEASE-001",
            "kind": "uncertainty",
            "requested_action": "investigate",
            "publication_consequence": "warn",
            "findings": [update["finding"]],
            "paths": [],
        }
        notification["identity"] = _notification_identity(notification)
        report["notifications"].append(notification)
    else:
        _fail("UNCERTAINTY-SCHEMA", "unknown attack kind")
    report["notifications"].sort(key=lambda item: item["identity"])
    report["identity"] = _report_identity(report)
    validate_notification_report(corpus, report)


def _classify_report_difference(
    expected: dict[str, Any], actual: dict[str, Any]
) -> NoReturn:
    actual_findings = {
        finding for item in actual["notifications"] for finding in item["findings"]
    }
    for notification in expected["notifications"]:
        key = (
            notification["scenario"],
            notification["claim"],
            notification["kind"],
            notification["requested_action"],
            notification["publication_consequence"],
        )
        if any(
            (
                item["scenario"],
                item["claim"],
                item["kind"],
                item["requested_action"],
                item["publication_consequence"],
            )
            == key
            for item in actual["notifications"]
        ):
            continue
        if notification["kind"] == "contradiction":
            _fail(
                "UNCERTAINTY-CONTRADICTION-SUPPRESSED", "contradiction was suppressed"
            )
        if notification["kind"] == "missing-evidence":
            _fail("UNCERTAINTY-MISSING-SUPPRESSED", "missing evidence was suppressed")
        if any(finding not in actual_findings for finding in notification["findings"]):
            _fail("UNCERTAINTY-CRITICAL-DROPPED", "consumed finding was dropped")
        _fail("UNCERTAINTY-GROUPING-LOSS", "distinct decision groups were merged")
    if any(not item["paths"] for item in actual["notifications"]):
        _fail("UNCERTAINTY-UNRELATED-ESCALATED", "unrelated finding was escalated")
    _fail("UNCERTAINTY-REPORT-MISMATCH", "report differs from derivation")


def _notification_identity(notification: dict[str, Any]) -> str:
    material = {key: value for key, value in notification.items() if key != "identity"}
    return domain_hash("proofbound-research-notification/1", canonical_json(material))


def _report_identity(report: dict[str, Any]) -> str:
    material = {key: value for key, value in report.items() if key != "identity"}
    return domain_hash(REPORT_SCHEMA, canonical_json(material))


def _baseline_order(item: dict[str, Any]) -> tuple[object, ...]:
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return (
        item["identity"],
        item["scenario"],
        item["finding"],
        item["fact"],
        item["tool"],
        item["code"],
        severity_order[item["severity"]],
    )


def _path_order(item: dict[str, Any]) -> tuple[object, ...]:
    publication_order = {"block": 0, "warn": 1, "none": 2}
    return (
        item["id"],
        item["finding"],
        item["fact"],
        item["claim"],
        tuple(item["nodes"]),
        item["consumed"],
        item["requested_action"],
        publication_order[item["publication_consequence"]],
    )


def _update_order(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return item["scenario"], item["finding"], item["fact"], item["reason"]


def _find(values: list[dict[str, Any]], identifier: str, code: str) -> dict[str, Any]:
    for value in values:
        if value.get("id") == identifier:
            return value
    _fail(code, "record is missing")


def _validate_id(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > 128
        or any(
            not (character.isascii() and (character.isalnum() or character in "-_.:"))
            for character in value
        )
    ):
        _fail("UNCERTAINTY-ID", f"invalid {label} ID")


def _validate_text(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
        )
    ):
        _fail("UNCERTAINTY-TEXT", f"invalid {label}")


def _validate_timestamp(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 20
        or any(
            value[index] != marker
            for index, marker in (
                (4, "-"),
                (7, "-"),
                (10, "T"),
                (13, ":"),
                (16, ":"),
                (19, "Z"),
            )
        )
        or any(
            not character.isascii() or not character.isdigit()
            for index, character in enumerate(value)
            if index not in {4, 7, 10, 13, 16, 19}
        )
    ):
        _fail("UNCERTAINTY-EXPIRY-MISSING", "expiry is not canonical UTC RFC 3339")


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _exact_keys(value: object, expected: set[str], code: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(code, "record fields do not match the closed schema")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("UNCERTAINTY-DECODE", str(error))
    if not isinstance(value, dict):
        _fail("UNCERTAINTY-DECODE", "top-level JSON value is not an object")
    return value


def _fail(code: str, message: str) -> NoReturn:
    raise NotificationFailure(code, message)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: notifications_research.py <repository-root> <corpus-dir> <repetitions>"
        )
    model = execute_notification_corpus(
        Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    )
    sys.stdout.buffer.write(canonical_json(model))
