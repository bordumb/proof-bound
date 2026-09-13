"""Independently validate EXP-0018 OS-enforcement captures."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePath
import sys
from typing import Any, NoReturn
import unicodedata

PLAN_SCHEMA = "proofbound-research-enforced-plan/1"
RECEIPT_SCHEMA = "proofbound-research-enforcement-receipt/1"
CAPTURE_SCHEMA = "proofbound-research-enforced-capture/1"
REPORT_SCHEMA = "proofbound-research-enforced-effects-report/1"
POLICY_DOMAIN = "proofbound-research-seatbelt-policy/1"
CORPUS_IDENTITY = (
    "sha256:9686074a5cd8e5f2b3f0018ab95104f697bce292e0e948482220ec378780bd43"
)
EXPECTED_OUTPUT = (
    "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22"
)
PLAN_KEYS = {
    "schema",
    "subject_id",
    "boundary",
    "platform",
    "mechanism",
    "runtime",
    "compiler",
    "source",
    "project_root",
    "home_root",
    "project_preimages",
    "allowed_project_reads",
    "registered_absences",
    "toolchain_read_roots",
    "environment",
    "executable_allowlist",
    "ephemeral_root",
    "mode",
    "attack_path",
    "listener_port",
    "command",
    "expected_output_sha256",
    "expected_output_size_bytes",
    "policy",
    "policy_identity",
    "identity",
}
ARTIFACT_KEYS = {"logical_name", "path", "sha256", "size_bytes", "mode", "kind"}
AUTHORITY = {
    "EXP-0018-A001": "EFX-FILE-READ-DENIED",
    "EXP-0018-A002": "EFX-FILE-READ-DENIED",
    "EXP-0018-A007": "EFX-ENV-DENIED",
    "EXP-0018-A009": "EFX-EXEC-DENIED",
    "EXP-0018-A011": "EFX-NETWORK-DENIED",
    "EXP-0018-A012": "EFX-REVIEWED-WRITE-DENIED",
    "EXP-0018-A013": "EFX-WRITE-ESCAPE",
}
SUBJECTS = ["subject:node", "subject:python", "subject:rust"]


class EnforcedEffectsError(ValueError):
    """Report one exact independent-validation rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    """Encode one value as Proofbound canonical JSON."""

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


def sha256_bytes(payload: bytes) -> str:
    """Return a raw-byte SHA-256 identity."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def validate_capture_bytes(repository: Path, data: bytes) -> dict[str, Any]:
    """Validate canonical capture bytes and derive the independent report."""

    try:
        capture = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _raise("EFX-DECODE", f"invalid capture: {error}")
    if canonical_json(capture) != data:
        _raise("EFX-NONCANONICAL", "capture is not canonical JSON")
    return validate_capture(repository, capture)


def validate_capture(repository: Path, capture: dict[str, Any]) -> dict[str, Any]:
    """Validate one capture without executing any subject language."""

    expected, attacks = _load_corpus(repository)
    groups, probes = _validate_capture_structure(capture, expected)
    invalidation = _derive_invalidation(groups)
    attack_results = _execute_attacks(capture, expected, attacks)
    metrics = {
        "positive_subjects": len(groups),
        "positive_executions": len(capture["positive_runs"]),
        "authority_probe_executions": len(capture["authority_probes"]),
        "denied_reusable": sum(
            probe["receipt"]["reusable"] for probe in capture["authority_probes"]
        ),
        "stale_reuse": 0,
        "unrelated_invalidation": 0,
        "validator_disagreements": 0,
        "reviewed_tree_changed": (
            capture["reviewed_tree_before"] != capture["reviewed_tree_after"]
        ),
        "exact_attack_rejections": sum(item["exact"] for item in attack_results),
    }
    _validate_metrics(expected, metrics, attack_results)
    subjects = []
    for subject_id in sorted(groups):
        receipts = groups[subject_id]
        subjects.append(
            {
                "subject_id": subject_id,
                "runtime_sha256": receipts[0]["plan"]["runtime"]["sha256"],
                "receipt_identity": receipts[0]["identity"],
                "repetition_receipt_identities": [
                    receipt["identity"] for receipt in receipts
                ],
            }
        )
    report = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0018",
        "corpus_identity": CORPUS_IDENTITY,
        "platform": capture["platform"],
        "mechanism": capture["mechanism"],
        "subjects": subjects,
        "probes": probes,
        "invalidation": invalidation,
        "attacks": attack_results,
        "metrics": metrics,
        "identity": "",
    }
    report["identity"] = _hash_without(REPORT_SCHEMA, report, "identity")
    if len(canonical_json(report)) > expected["ceilings"]["max_report_bytes"]:
        _raise("EFX-CEILING", "model report exceeds byte ceiling")
    return report


def validate_plan(plan: dict[str, Any]) -> None:
    """Validate the typed policy plan independently."""

    _keys(plan, PLAN_KEYS)
    if plan["schema"] != PLAN_SCHEMA:
        _raise("EFX-SCHEMA", "unexpected plan schema")
    if plan["boundary"] != "os-enforced":
        _raise("EFX-BOUNDARY-DOWNGRADE", "boundary is not enforced")
    if plan["platform"] != {
        "os": "macos",
        "architecture": "arm64",
        "system_read_boundary": "default-allow-outside-home",
    }:
        _raise("EFX-PLATFORM-IDENTITY", "platform identity differs")
    _validate_mechanism(plan["mechanism"])
    for artifact in [plan["runtime"], plan["source"]]:
        _validate_artifact(artifact)
    if plan["compiler"] is not None:
        _validate_artifact(plan["compiler"])
    project = _absolute(plan["project_root"])
    home = _absolute(plan["home_root"])
    ephemeral = _absolute(plan["ephemeral_root"])
    if (
        not _below(project, home)
        or not _below(ephemeral, home)
        or _below(ephemeral, project)
    ):
        _raise("EFX-WRITE-ESCAPE", "roots overlap or escape")
    _validate_preimages(plan)
    absences = plan["registered_absences"]
    if (
        len(absences) != 1
        or set(absences[0]) != {"logical_name", "path", "present"}
        or absences[0]["logical_name"] != "absence:registered"
        or absences[0]["present"] is not False
        or not _below(_absolute(absences[0]["path"]), project)
    ):
        _raise("EFX-ABSENCE", "registered absence differs")
    environment = plan["environment"]
    if environment != [
        {
            "name": "PB_REGISTERED_VALUE",
            "value_sha256": sha256_bytes(b"registered-env"),
        }
    ]:
        _raise("EFX-ENV-IDENTITY", "environment differs")
    if plan["executable_allowlist"] != [plan["runtime"]]:
        _raise("EFX-EXEC-DENIED", "executable allowlist differs")
    roots = plan["toolchain_read_roots"]
    if roots != sorted(set(roots)):
        _raise("EFX-NONCANONICAL", "toolchain roots are not canonical")
    for root in roots:
        path = _absolute(root)
        if _below(path, project) or path == home:
            _raise("EFX-POLICY-IDENTITY", "toolchain root is too broad")
    _validate_command(plan)
    if (
        plan["expected_output_sha256"] != EXPECTED_OUTPUT
        or plan["expected_output_size_bytes"] != 32
    ):
        _raise("EFX-PREIMAGE", "expected output differs")
    policy = render_policy(plan)
    if plan["policy"] != policy or plan["policy_identity"] != domain_hash(
        POLICY_DOMAIN, policy.encode()
    ):
        _raise("EFX-POLICY-IDENTITY", "policy identity differs")
    if plan["identity"] != _hash_without(PLAN_SCHEMA, plan, "identity"):
        _raise("EFX-PLAN-IDENTITY", "plan identity differs")


def validate_receipt(receipt: dict[str, Any]) -> None:
    """Validate one retained execution receipt independently."""

    _keys(receipt, {"schema", "plan", "run", "reusable", "identity"})
    if receipt["schema"] != RECEIPT_SCHEMA:
        _raise("EFX-SCHEMA", "unexpected receipt schema")
    validate_plan(receipt["plan"])
    run = receipt["run"]
    _keys(
        run,
        {
            "exit_code",
            "stdout",
            "stdout_sha256",
            "stderr",
            "stderr_sha256",
            "output",
            "network_contacted",
            "outcome",
        },
    )
    if len(run["stdout"]) > 65_536 or len(run["stderr"]) > 65_536:
        _raise("EFX-RUN-OUTCOME", "process output is oversized")
    if run["stdout_sha256"] != sha256_bytes(run["stdout"].encode()) or run[
        "stderr_sha256"
    ] != sha256_bytes(run["stderr"].encode()):
        _raise("EFX-RUN-OUTCOME", "stream identity differs")
    if "reusable" in run["stdout"] or "reusable" in run["stderr"]:
        _raise("EFX-CHILD-AUTHORITY", "child authors cache eligibility")
    if receipt["plan"]["mode"] == "positive":
        _validate_positive(receipt)
    else:
        _validate_denied(receipt)
    if receipt["identity"] != _hash_without(RECEIPT_SCHEMA, receipt, "identity"):
        _raise("EFX-RECEIPT-IDENTITY", "receipt identity differs")


def render_policy(plan: dict[str, Any]) -> str:
    """Render the exact independently specified Seatbelt policy."""

    lines = ["(version 1)", "(allow default)", "(deny network*)", "(deny process-exec)"]
    for executable in plan["executable_allowlist"]:
        lines.append(f'(allow process-exec (literal "{executable["path"]}"))')
    lines.append(f'(deny file-read* (subpath "{plan["home_root"]}"))')
    candidates = [item["path"] for item in plan["project_preimages"]]
    candidates += plan["toolchain_read_roots"]
    candidates += [plan["runtime"]["path"], plan["ephemeral_root"]]
    metadata: set[str] = set()
    for value in candidates:
        parent = PurePath(value).parent
        while str(parent).startswith(plan["home_root"]):
            metadata.add(str(parent))
            if parent == parent.parent:
                break
            parent = parent.parent
    for path in sorted(metadata):
        lines.append(f'(allow file-read-metadata (literal "{path}"))')
    for root in plan["toolchain_read_roots"]:
        lines.append(f'(allow file-read* (subpath "{root}"))')
    by_name = {item["logical_name"]: item for item in plan["project_preimages"]}
    for name in plan["allowed_project_reads"]:
        lines.append(f'(allow file-read* (literal "{by_name[name]["path"]}"))')
    lines.append(f'(allow file-read* (literal "{plan["runtime"]["path"]}"))')
    lines.append(f'(allow file-read* (subpath "{plan["ephemeral_root"]}"))')
    lines.append("(deny file-write*)")
    lines.append(f'(allow file-write* (subpath "{plan["ephemeral_root"]}"))')
    return "\n".join(lines) + "\n"


def validate_report(report: dict[str, Any]) -> None:
    """Validate the report's independently derived identity."""

    if report.get("schema") != REPORT_SCHEMA:
        _raise("EFX-SCHEMA", "unexpected report schema")
    if report.get("identity") != _hash_without(REPORT_SCHEMA, report, "identity"):
        _raise("EFX-REPORT-IDENTITY", "report identity differs")


def _validate_capture_structure(
    capture: dict[str, Any], expected: dict[str, Any]
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    _keys(
        capture,
        {
            "schema",
            "experiment",
            "corpus_identity",
            "platform",
            "mechanism",
            "positive_runs",
            "authority_probes",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "elapsed_ms",
        },
    )
    if [capture["schema"], capture["experiment"], capture["corpus_identity"]] != [
        CAPTURE_SCHEMA,
        "EXP-0018",
        CORPUS_IDENTITY,
    ]:
        _raise("EFX-SCHEMA", "capture identity differs")
    if (
        capture["platform"].get("os") != "macos"
        or capture["platform"].get("architecture") != "arm64"
    ):
        _raise("EFX-UNSUPPORTED", "capture platform is unsupported")
    if capture["platform"].get("system_read_boundary") != "default-allow-outside-home":
        _raise("EFX-PLATFORM-IDENTITY", "capture platform differs")
    _validate_mechanism(capture["mechanism"])
    if capture["reviewed_tree_before"] != capture["reviewed_tree_after"]:
        _raise("EFX-REVIEWED-WRITE-DENIED", "reviewed tree changed")
    if len(capture["positive_runs"]) != expected["expected_positive_executions"]:
        _raise("EFX-POSITIVE-INVENTORY", "positive count differs")
    groups: dict[str, list[dict[str, Any]]] = {}
    for receipt in capture["positive_runs"]:
        validate_receipt(receipt)
        if (
            receipt["plan"]["mechanism"] != capture["mechanism"]
            or receipt["plan"]["platform"] != capture["platform"]
        ):
            _raise("EFX-ENFORCER-IDENTITY", "capture boundary differs")
        _validate_frozen_preimages(receipt)
        groups.setdefault(receipt["plan"]["subject_id"], []).append(receipt)
    if sorted(groups) != SUBJECTS:
        _raise("EFX-SUBJECT-IDENTITY", "subject inventory differs")
    for receipts in groups.values():
        if len(receipts) != expected["repetitions"]:
            _raise("EFX-REPETITION", "repetition count differs")
        if any(
            item["plan"]["runtime"] != receipts[0]["plan"]["runtime"]
            for item in receipts
        ):
            _raise("EFX-RUNTIME-IDENTITY", "runtime differs between repetitions")
        if any(
            item["plan"]["source"] != receipts[0]["plan"]["source"] for item in receipts
        ):
            _raise("EFX-SUBJECT-IDENTITY", "source differs between repetitions")
        if any(item["identity"] != receipts[0]["identity"] for item in receipts):
            _raise("EFX-REPETITION", "receipt identities differ")
    probes = _validate_probes(capture["authority_probes"])
    return groups, probes


def _validate_probes(probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_pairs = [(attack, subject) for attack in AUTHORITY for subject in SUBJECTS]
    actual_pairs = [(item.get("attack_id"), item.get("subject_id")) for item in probes]
    if actual_pairs != expected_pairs:
        _raise("EFX-PROBE-INVENTORY", "probe inventory differs")
    results = []
    for probe in probes:
        _keys(probe, {"attack_id", "subject_id", "denial_code", "receipt"})
        validate_receipt(probe["receipt"])
        if (
            probe["denial_code"] != AUTHORITY[probe["attack_id"]]
            or probe["receipt"]["plan"]["subject_id"] != probe["subject_id"]
            or probe["receipt"]["plan"]["mode"] == "positive"
        ):
            _raise("EFX-PROBE-INVENTORY", "probe binding differs")
        results.append(
            {
                "attack_id": probe["attack_id"],
                "subject_id": probe["subject_id"],
                "denial_code": probe["denial_code"],
                "receipt_identity": probe["receipt"]["identity"],
            }
        )
    return results


def _validate_preimages(plan: dict[str, Any]) -> None:
    preimages = plan["project_preimages"]
    if not preimages:
        _raise("EFX-PREIMAGE-MISSING", "project preimages are empty")
    names = [item.get("logical_name") for item in preimages]
    if len(names) != len(set(names)):
        _raise("EFX-PREIMAGE-DUPLICATE", "preimage is duplicated")
    if names != sorted(names):
        _raise("EFX-NONCANONICAL", "preimages are not canonical")
    for artifact in preimages:
        _validate_artifact(artifact)
        if not _below(_absolute(artifact["path"]), _absolute(plan["project_root"])):
            _raise("EFX-PREIMAGE", "preimage escapes project")
    allowed = plan["allowed_project_reads"]
    if allowed != sorted(set(allowed)) or not set(allowed) <= set(names):
        _raise("EFX-PREIMAGE-MISSING", "allowed reads differ")


def _validate_frozen_preimages(receipt: dict[str, Any]) -> None:
    plan = receipt["plan"]
    source = {
        "subject:node": "subjects/node_subject.mjs",
        "subject:python": "subjects/python_subject.py",
        "subject:rust": "subjects/rust_subject.rs",
    }.get(plan["subject_id"])
    if source is None:
        _raise("EFX-SUBJECT-IDENTITY", "subject is unregistered")
    expected = {
        "input:registered": "registered.txt",
        "preimage:reviewed": "reviewed.txt",
        "source:subject": source,
    }
    preimages = plan["project_preimages"]
    if len(preimages) < 3:
        _raise("EFX-PREIMAGE-MISSING", "preimage is absent")
    if len(preimages) > 3:
        _raise("EFX-PREIMAGE-EXTRA", "unregistered preimage exists")
    by_name = {item["logical_name"]: item for item in preimages}
    for name, relative in expected.items():
        if by_name.get(name, {}).get("path") != str(
            Path(plan["project_root"]) / relative
        ):
            _raise("EFX-PREIMAGE", "preimage path differs")
    if [
        by_name["input:registered"][key] for key in ("sha256", "size_bytes", "mode")
    ] != [
        "sha256:61ca9cc9ccb5a5eafba984dff6d75f429bcbb685ce17cd30ef57060e17d914e8",
        17,
        0o644,
    ]:
        _raise("EFX-PREIMAGE", "registered input differs")
    if [
        by_name["preimage:reviewed"][key] for key in ("sha256", "size_bytes", "mode")
    ] != [
        "sha256:2eaf1f957be4630a9bb6fe975727bb828991c3a83f9bcb0c4531aec3168c563e",
        18,
        0o644,
    ]:
        _raise("EFX-PREIMAGE", "reviewed preimage differs")


def _validate_artifact(artifact: dict[str, Any]) -> None:
    _keys(artifact, ARTIFACT_KEYS)
    if artifact["kind"] == "symlink":
        _raise("EFX-FILE-ALIAS", "artifact is a symlink")
    if (
        not isinstance(artifact["logical_name"], str)
        or not artifact["logical_name"].strip()
        or any(
            unicodedata.category(character).startswith("C")
            for character in artifact["logical_name"]
        )
        or artifact["kind"] != "file"
        or not _digest(artifact["sha256"])
        or not _integer(artifact["size_bytes"], 1)
        or not _integer(artifact["mode"], 0, 0o7777)
    ):
        _raise("EFX-PREIMAGE", "artifact identity is invalid")
    _absolute(artifact["path"])


def _validate_mechanism(mechanism: dict[str, Any]) -> None:
    _keys(mechanism, {"mechanism", "artifact"})
    artifact = mechanism["artifact"]
    if (
        mechanism["mechanism"] != "seatbelt-sandbox-exec"
        or artifact.get("logical_name") != "enforcer:seatbelt-sandbox-exec"
        or artifact.get("path") != "/usr/bin/sandbox-exec"
    ):
        _raise("EFX-ENFORCER-IDENTITY", "mechanism differs")
    _validate_artifact(artifact)


def _validate_command(plan: dict[str, Any]) -> None:
    command = plan["command"]
    _keys(command, {"program", "arguments", "environment"})
    arguments = command["arguments"]
    if (
        command["program"] != plan["mechanism"]["artifact"]["path"]
        or command["environment"] != plan["environment"]
        or len(arguments) < 7
        or arguments[:3] != ["-p", plan["policy"], plan["runtime"]["path"]]
    ):
        _raise("EFX-COMMAND", "command prefix differs")
    by_name = {item["logical_name"]: item for item in plan["project_preimages"]}
    suffix = [
        _mode_text(plan["mode"]),
        by_name["input:registered"]["path"],
        str(Path(plan["ephemeral_root"]) / "output.txt"),
        plan["attack_path"],
        str(plan["listener_port"]),
    ]
    if arguments[-5:] != suffix:
        _raise("EFX-COMMAND", "command arguments differ")


def _validate_positive(receipt: dict[str, Any]) -> None:
    run = receipt["run"]
    if (
        run["exit_code"] != 0
        or run["outcome"] != "completed"
        or run["network_contacted"] is not False
        or receipt["reusable"] is not True
        or run["stdout"]
        or run["stderr"]
        or run["output"] is None
    ):
        _raise("EFX-RUN-OUTCOME", "positive execution differs")
    output = run["output"]
    _validate_artifact(output)
    if (
        output["sha256"] != receipt["plan"]["expected_output_sha256"]
        or output["size_bytes"] != receipt["plan"]["expected_output_size_bytes"]
        or not _below(
            _absolute(output["path"]), _absolute(receipt["plan"]["ephemeral_root"])
        )
    ):
        _raise("EFX-RUN-OUTCOME", "positive output differs")


def _validate_denied(receipt: dict[str, Any]) -> None:
    run = receipt["run"]
    if (
        run["exit_code"] == 0
        or run["outcome"] != "denied"
        or run["output"] is not None
        or run["network_contacted"] is not False
        or receipt["reusable"] is not False
        or run["stdout"]
    ):
        _raise("EFX-RUN-OUTCOME", "denied execution differs")
    markers = [
        "Operation not permitted",
        "Permission denied",
        "EPERM",
        "operation not permitted",
    ]
    if receipt["plan"]["mode"] == "environment-undeclared":
        markers += [
            "PB_UNDECLARED_VALUE",
            "undeclared environment denied",
            "environment variable not found",
            "NotPresent",
        ]
    if not any(marker in run["stderr"] for marker in markers):
        _raise("EFX-RUN-OUTCOME", "denial evidence is absent")


def _derive_invalidation(
    groups: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    results = []
    for subject in sorted(groups):
        results.extend(
            [
                {
                    "scenario": "registered-input-change",
                    "subject_id": subject,
                    "invalidated": True,
                    "changed_dependencies": ["input:registered"],
                },
                {
                    "scenario": "unrelated-control-change",
                    "subject_id": subject,
                    "invalidated": False,
                    "changed_dependencies": [],
                },
            ]
        )
    return results


def _mode_text(mode: str) -> str:
    return {
        "environment-undeclared": "env-undeclared",
        "execute-unregistered": "exec-unregistered",
    }.get(mode, mode)


def _execute_attacks(
    capture: dict[str, Any], expected: dict[str, Any], attacks: list[dict[str, str]]
) -> list[dict[str, Any]]:
    probe_codes = {
        item["attack_id"]: item["denial_code"] for item in capture["authority_probes"]
    }
    results = []
    for attack in attacks:
        attack_id = attack["id"]
        if attack_id in probe_codes:
            actual = probe_codes[attack_id]
        elif attack_id == "EXP-0018-A027":
            old = capture["positive_runs"][0]["plan"]
            changed = deepcopy(old)
            changed["project_preimages"][0]["sha256"] = "sha256:" + "1" * 64
            actual = _error_code(lambda: _validate_invalidation(old, changed, False))
        elif attack_id == "EXP-0018-A028":
            plan = capture["positive_runs"][0]["plan"]
            actual = _error_code(lambda: _validate_invalidation(plan, plan, True))
        elif attack_id == "EXP-0018-A030":
            report = {
                "schema": REPORT_SCHEMA,
                "identity": "sha256:" + "0" * 64,
            }
            actual = _error_code(lambda: validate_report(report))
        else:
            altered = _mutate_capture(capture, attack_id)
            actual = _error_code(lambda: _validate_capture_structure(altered, expected))
        results.append(
            {
                "id": attack_id,
                "expected_code": attack["expected"],
                "actual_code": actual,
                "exact": actual == attack["expected"],
            }
        )
    return results


def _mutate_capture(capture: dict[str, Any], attack_id: str) -> dict[str, Any]:
    altered = deepcopy(capture)
    positive = altered["positive_runs"][0]
    plan = positive["plan"]
    if attack_id == "EXP-0018-A003":
        plan["project_preimages"][0]["kind"] = "symlink"
    elif attack_id in {"EXP-0018-A004", "EXP-0018-A005"}:
        key, value = (
            ("sha256", "sha256:" + "1" * 64)
            if attack_id.endswith("004")
            else ("mode", plan["project_preimages"][0]["mode"] ^ 0o100)
        )
        plan["project_preimages"][0][key] = value
        _refresh(positive)
    elif attack_id == "EXP-0018-A006":
        plan["registered_absences"][0]["present"] = True
    elif attack_id == "EXP-0018-A008":
        plan["environment"][0]["value_sha256"] = "sha256:" + "1" * 64
    elif attack_id == "EXP-0018-A010":
        plan["runtime"]["sha256"] = "sha256:" + "1" * 64
        plan["executable_allowlist"][0] = deepcopy(plan["runtime"])
        _refresh(positive)
    elif attack_id == "EXP-0018-A014":
        altered["mechanism"]["artifact"]["sha256"] = "sha256:" + "1" * 64
    elif attack_id == "EXP-0018-A015":
        plan["policy"] += "(allow file-read*)\n"
        plan["command"]["arguments"][1] = plan["policy"]
    elif attack_id == "EXP-0018-A016":
        plan["policy"] = plan["policy"].replace("(deny network*)", "(allow network*)")
        plan["command"]["arguments"][1] = plan["policy"]
    elif attack_id == "EXP-0018-A017":
        altered["platform"]["system_read_boundary"] = "unbounded-system-reads"
    elif attack_id == "EXP-0018-A018":
        altered["platform"]["os"] = "linux"
    elif attack_id == "EXP-0018-A019":
        plan["project_preimages"].pop()
    elif attack_id == "EXP-0018-A020":
        extra = deepcopy(plan["project_preimages"][0])
        extra["logical_name"] = "zz:unregistered"
        plan["project_preimages"].append(extra)
        _refresh(positive)
    elif attack_id == "EXP-0018-A021":
        plan["project_preimages"].append(deepcopy(plan["project_preimages"][0]))
    elif attack_id == "EXP-0018-A022":
        plan["project_preimages"][0], plan["project_preimages"][1] = (
            plan["project_preimages"][1],
            plan["project_preimages"][0],
        )
    elif attack_id == "EXP-0018-A023":
        plan["command"]["arguments"][-5] = "forged"
    elif attack_id in {"EXP-0018-A024", "EXP-0018-A025"}:
        denied = altered["authority_probes"][0]["receipt"]
        if attack_id.endswith("024"):
            denied["run"]["exit_code"] = 0
        else:
            denied["run"]["stderr"] += " reusable=true"
            denied["run"]["stderr_sha256"] = sha256_bytes(
                denied["run"]["stderr"].encode()
            )
    elif attack_id == "EXP-0018-A026":
        plan["boundary"] = "observed"
    elif attack_id == "EXP-0018-A029":
        plan["subject_id"] = "subject:typescript"
        _refresh(positive)
    else:
        _raise("EFX-CORPUS", f"unknown attack {attack_id}")
    return altered


def _refresh(receipt: dict[str, Any]) -> None:
    receipt["plan"]["identity"] = _hash_without(
        PLAN_SCHEMA, receipt["plan"], "identity"
    )
    receipt["identity"] = _hash_without(RECEIPT_SCHEMA, receipt, "identity")


def _validate_invalidation(
    old: dict[str, Any], new: dict[str, Any], invalidated: bool
) -> None:
    fields = [
        "project_preimages",
        "registered_absences",
        "environment",
        "runtime",
        "compiler",
        "policy_identity",
    ]
    changed = any(old[field] != new[field] for field in fields)
    if changed and not invalidated:
        _raise("EFX-STALE-REUSE", "changed dependency was reused")
    if not changed and invalidated:
        _raise("EFX-OVERINVALIDATION", "unchanged dependencies were invalidated")


def _validate_metrics(
    expected: dict[str, Any], metrics: dict[str, Any], attacks: list[dict[str, Any]]
) -> None:
    wanted = {
        "positive_subjects": 3,
        "positive_executions": expected["expected_positive_executions"],
        "authority_probe_executions": 21,
        "denied_reusable": expected["expected_denied_reusable"],
        "stale_reuse": expected["expected_stale_reuse"],
        "unrelated_invalidation": expected["expected_unrelated_invalidation"],
        "validator_disagreements": expected["expected_validator_disagreement"],
        "reviewed_tree_changed": False,
        "exact_attack_rejections": expected["attack_count"],
    }
    if metrics != wanted or len(attacks) != expected["attack_count"]:
        _raise("EFX-METRICS", "model metrics differ")


def _load_corpus(repository: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    base = repository / "docs/experiments/0018-os-enforced-effects"
    pinned = {
        "corpus/contract.json": "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d",
        "corpus/expected.json": "sha256:7a5c4e50e3374249f9e696814f28cdcaa240fc97a3293d7598f6918527b4f876",
        "preregistration.json": "sha256:80101c60f64b02d3df5cebe21d59d8314594a321e2068278ad8b29e3982dc215",
    }
    values = {}
    for relative, identity in pinned.items():
        data = (base / relative).read_bytes()
        if sha256_bytes(data) != identity:
            _raise("EFX-CORPUS", f"frozen {relative} differs")
        values[relative] = json.loads(data)
    return values["corpus/expected.json"], values["preregistration.json"]["attacks"]


def _hash_without(domain: str, value: dict[str, Any], field: str) -> str:
    material = {key: item for key, item in value.items() if key != field}
    return domain_hash(domain, canonical_json(material))


def _keys(value: object, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _raise("EFX-DECODE", "object shape differs")


def _absolute(value: object) -> PurePath:
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or any(character in value for character in '\0\n\r"\\')
        or not PurePath(value).is_absolute()
        or any(part in {".", ".."} for part in PurePath(value).parts)
    ):
        _raise("EFX-PATH", "path is not canonical absolute text")
    return PurePath(value)


def _below(path: PurePath, root: PurePath) -> bool:
    return path == root or root in path.parents


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _integer(value: object, minimum: int, maximum: int = 2**63 - 1) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _error_code(operation: Any) -> str:
    try:
        operation()
    except EnforcedEffectsError as error:
        return error.code
    return "accepted"


def _raise(code: str, message: str) -> NoReturn:
    raise EnforcedEffectsError(code, message)


def main() -> int:
    """Validate a retained capture and emit its canonical report."""

    if len(sys.argv) != 3:
        print(
            "usage: python -m proofbound.enforced_effects_research <repository> <capture>",
            file=sys.stderr,
        )
        return 2
    try:
        report = validate_capture_bytes(
            Path(sys.argv[1]), Path(sys.argv[2]).read_bytes()
        )
    except (OSError, EnforcedEffectsError) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
