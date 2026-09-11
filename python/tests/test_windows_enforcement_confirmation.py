from __future__ import annotations

import copy

import pytest

from proofbound.windows_enforcement_confirmation import derive
from proofbound.windows_enforcement_execute import domain_hash


def _receipt(domain: str, value: dict[str, object]) -> dict[str, object]:
    value["identity"] = domain_hash(domain, value)
    return value


def _host() -> dict[str, object]:
    return _receipt(
        "proofbound-research-windows-host-probe/1",
        {
            "schema": "proofbound-research-windows-host-probe/1",
            "experiment": "EXP-0023",
            "supported": True,
            "fallback_used": False,
        },
    )


def _process() -> dict[str, object]:
    return _receipt(
        "proofbound-research-windows-process-smoke/1",
        {
            "schema": "proofbound-research-windows-process-smoke/1",
            "experiment": "EXP-0023",
            "token_verified": False,
            "result": {
                "exit_code": 0xC0000142,
                "child_token": {
                    "appcontainer": True,
                    "administrator_deny_only": True,
                    "integrity_sid": "S-1-16-4096",
                    "verified_before_resume": True,
                },
                "job": {
                    "active_process_limit": 1,
                    "kill_on_close": True,
                    "assigned_before_resume": True,
                },
            },
        },
    )


def test_pre_entry_dll_failure_derives_revise_without_reusable_evidence() -> None:
    execution = derive(_host(), _process())

    assert execution["decision"] == "revise"
    assert execution["metrics"]["positive_executions"] == 0
    assert execution["metrics"]["authority_probe_executions"] == 0
    assert execution["metrics"]["denied_reusable"] == 0
    assert execution["questions"]["Q1"]["passed"] is False


def test_tampered_receipt_is_rejected() -> None:
    process = copy.deepcopy(_process())
    process["token_verified"] = True

    with pytest.raises(ValueError, match="identity mismatch"):
        derive(_host(), process)


def test_fallback_is_a_stop_decision() -> None:
    host = _host()
    host["fallback_used"] = True
    host.pop("identity")
    _receipt("proofbound-research-windows-host-probe/1", host)

    assert derive(host, _process())["decision"] == "stop"
