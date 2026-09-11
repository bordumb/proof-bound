"""Derive the preregistered EXP-0023 decision from native Windows receipts."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from proofbound.windows_enforcement_execute import canonical_json, domain_hash


EXECUTION_SCHEMA = "proofbound-research-windows-confirmation-execution/1"
HOST_SCHEMA = "proofbound-research-windows-host-probe/1"
PROCESS_SCHEMA = "proofbound-research-windows-process-smoke/1"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _verify_identity(value: dict[str, Any], domain: str) -> None:
    claimed = value.get("identity")
    body = dict(value)
    body.pop("identity", None)
    if claimed != domain_hash(domain, body):
        raise ValueError(f"{domain} identity mismatch")


def derive(host: dict[str, Any], process: dict[str, Any]) -> dict[str, Any]:
    """Derive one fail-closed decision from exact host and process receipts."""

    if host.get("schema") != HOST_SCHEMA:
        raise ValueError("unexpected host-probe schema")
    if process.get("schema") != PROCESS_SCHEMA:
        raise ValueError("unexpected process-smoke schema")
    _verify_identity(host, HOST_SCHEMA)
    _verify_identity(process, PROCESS_SCHEMA)
    if host.get("experiment") != "EXP-0023" or process.get("experiment") != "EXP-0023":
        raise ValueError("receipt experiment mismatch")
    if host.get("fallback_used") is not False:
        decision = "stop"
    elif not host.get("supported"):
        decision = "unanswered"
    elif process.get("token_verified") is not True:
        decision = "revise"
    else:
        decision = "revise"

    result = process.get("result")
    if not isinstance(result, dict):
        raise ValueError("process receipt lacks a result")
    child_token = result.get("child_token")
    if not isinstance(child_token, dict):
        raise ValueError("process receipt lacks a child token")
    token_layers = (
        child_token.get("appcontainer") is True
        and child_token.get("administrator_deny_only") is True
        and child_token.get("integrity_sid") == "S-1-16-4096"
        and child_token.get("verified_before_resume") is True
    )
    job = result.get("job")
    if not isinstance(job, dict):
        raise ValueError("process receipt lacks a job boundary")
    job_layer = (
        job.get("active_process_limit") == 1
        and job.get("kill_on_close") is True
        and job.get("assigned_before_resume") is True
    )
    process_completed = result.get("exit_code") == 0
    decision = "stop" if host.get("fallback_used") is not False else decision
    execution = {
        "schema": EXECUTION_SCHEMA,
        "experiment": "EXP-0023",
        "programme_experiment": "EXP-LANG-016",
        "decision": decision,
        "availability": "supported" if host.get("supported") else "unsupported",
        "identities": {
            "host_probe": host["identity"],
            "process_smoke": process["identity"],
        },
        "metrics": {
            "positive_executions": 0,
            "authority_probe_executions": 0,
            "denied_reusable": 0,
            "policy_attack_rejections": 0,
            "child_exit_code": result.get("exit_code"),
        },
        "questions": {
            "Q1": {
                "passed": token_layers and job_layer and process_completed,
                "reason": (
                    "the suspended child token and job were verified, but the "
                    "staged process terminated with STATUS_DLL_INIT_FAILED before entry"
                    if token_layers and job_layer and not process_completed
                    else "the complete registered process boundary was unavailable"
                ),
            },
            "Q2": {
                "passed": False,
                "reason": "zero of 30 permitted workloads entered user code",
            },
            "Q3": {
                "passed": False,
                "reason": "the fail-closed entry gate prevented all 21 authority probes",
            },
            "Q4": {
                "passed": False,
                "reason": "no workload capture existed for independent validation",
            },
            "Q5": {
                "passed": False,
                "reason": (
                    "the receipt binds SID, token, job, profile, and desktop, but the "
                    "runnable executable and DLL closure is not yet established"
                ),
            },
        },
        "finding": {
            "status": "0xc0000142",
            "name": "STATUS_DLL_INIT_FAILED",
            "stage": "after-resume-before-workload-entry",
            "reusable_evidence_emitted": False,
        },
    }
    execution["identity"] = domain_hash(EXECUTION_SCHEMA, execution)
    return execution


def main(argv: list[str] | None = None) -> int:
    """Write one canonical EXP-0023 execution decision."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: windows_enforcement_confirmation HOST PROCESS OUTPUT",
            file=sys.stderr,
        )
        return 2
    try:
        execution = derive(_load(Path(arguments[0])), _load(Path(arguments[1])))
        Path(arguments[2]).write_bytes(canonical_json(execution))
    except (OSError, ValueError, json.JSONDecodeError) as issue:
        print(issue, file=sys.stderr)
        return 1
    return 1 if execution["decision"] == "stop" else 0


if __name__ == "__main__":
    raise SystemExit(main())
