from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from proofbound import windows_enforcement_execute as execution
from proofbound import windows_enforcement_research as research


ROOT = Path(__file__).resolve().parents[2]
CAPTURE = (
    ROOT / "docs/experiments/0021-windows-enforcement-portability/results/capture.json"
)


def _replace(
    value: dict[str, object], path: tuple[str, ...], replacement: object
) -> None:
    target = value
    for component in path[:-1]:
        target = target[component]  # type: ignore[assignment]
    target[path[-1]] = replacement


def test_retained_windows_result_is_unanswered_and_fail_closed() -> None:
    report = research.validate_capture_bytes(ROOT, CAPTURE.read_bytes())
    assert report["availability"] == "unsupported"
    assert report["metrics"]["supported_execution"] is False
    assert report["metrics"]["positive_executions"] == 0
    assert len(report["policy_attacks"]) == 18


@pytest.mark.parametrize(
    ("path", "replacement", "code"),
    [
        (("schema",), "old", "WIN-CAPTURE-SCHEMA"),
        (("contract_sha256",), "sha256:bad", "WIN-CONTRACT"),
        (("requested_platform", "minimum_release"), "Windows 10", "WIN-TARGET"),
        (("candidate_mechanisms",), [], "WIN-MECHANISM"),
        (("fallback_used",), True, "WIN-FALLBACK"),
        (("availability",), "supported", "WIN-FALLBACK"),
        (("identity",), "sha256:bad", "WIN-CAPTURE-IDENTITY"),
    ],
)
def test_capture_attacks_fail_exactly(
    path: tuple[str, ...], replacement: object, code: str
) -> None:
    value = copy.deepcopy(json.loads(CAPTURE.read_bytes()))
    _replace(value, path, replacement)
    with pytest.raises(research.WindowsEnforcementError) as caught:
        research.validate_capture_bytes(ROOT, execution.canonical_json(value))
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("path", "replacement", "code"),
    [
        (("schema",), "old", "WIN-POLICY-SCHEMA"),
        (("appcontainer", "capabilities"), ["internet-client"], "WIN-APPCONTAINER"),
        (("appcontainer", "network_authority"), "outbound", "WIN-APPCONTAINER"),
        (("restricted_token", "disable_max_privilege"), False, "WIN-TOKEN"),
        (("restricted_token", "integrity_level"), "medium", "WIN-TOKEN"),
        (("job_object", "active_process_limit"), 2, "WIN-JOB"),
        (("job_object", "breakaway"), "allow", "WIN-JOB"),
        (("path_authority",), [], "WIN-PATH-AUTHORITY"),
        (("environment",), [], "WIN-ENVIRONMENT"),
        (("executable_allowlist",), ["any"], "WIN-EXECUTABLE"),
        (("identity",), "sha256:bad", "WIN-POLICY-IDENTITY"),
    ],
)
def test_policy_attacks_fail_exactly(
    path: tuple[str, ...], replacement: object, code: str
) -> None:
    policy = research.compile_policy()
    _replace(policy, path, replacement)
    with pytest.raises(research.WindowsEnforcementError) as caught:
        research.validate_policy(policy)
    assert caught.value.code == code
