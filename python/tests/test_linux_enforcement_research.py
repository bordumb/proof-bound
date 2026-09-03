from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from proofbound import linux_enforcement_execute as execution
from proofbound import linux_enforcement_research as research


ROOT = Path(__file__).resolve().parents[2]
CAPTURE = (
    ROOT / "docs/experiments/0020-linux-enforcement-portability/results/capture.json"
)


def test_retained_linux_result_is_unsupported_and_fail_closed() -> None:
    report = research.validate_capture_bytes(ROOT, CAPTURE.read_bytes())
    assert report["availability"] == "unsupported"
    assert report["metrics"]["supported_execution"] is False
    assert report["metrics"]["positive_executions"] == 0
    assert len(report["policy_attacks"]) == 16


@pytest.mark.parametrize(
    ("path", "replacement", "code"),
    [
        (("schema",), "old", "LNX-CAPTURE-SCHEMA"),
        (("contract_sha256",), "sha256:" + "0" * 64, "LNX-CONTRACT"),
        (("platform", "os"), "macos", "LNX-PLATFORM"),
        (("platform", "architecture"), "riscv64", "LNX-PLATFORM"),
        (("platform", "kernel"), "unknown", "LNX-PLATFORM"),
        (("platform", "image_identity"), "sha256:bad", "LNX-MECHANISM"),
        (("platform", "enforcer_sha256"), "sha256:bad", "LNX-MECHANISM"),
        (("platform", "seccomp_network_syscalls"), [], "LNX-MECHANISM"),
        (("platform", "no_new_privs"), True, "LNX-CONTAINER-FALLBACK"),
        (("platform", "landlock_abi"), 3, "LNX-PLATFORM"),
        (("platform", "probe_exit_code"), 0, "LNX-CONTAINER-FALLBACK"),
        (("platform", "probe_stdout"), "substitute", "LNX-CONTAINER-FALLBACK"),
        (("platform", "probe_stderr"), "", "LNX-CONTAINER-FALLBACK"),
        (("scheduler",), "serial-fallback", "LNX-MECHANISM"),
        (("container_confinement_counted",), True, "LNX-CONTAINER-FALLBACK"),
        (("identity",), "sha256:" + "0" * 64, "LNX-CAPTURE-IDENTITY"),
    ],
)
def test_registered_attacks_fail_exactly(
    path: tuple[str, ...], replacement: object, code: str
) -> None:
    value = copy.deepcopy(json.loads(CAPTURE.read_bytes()))
    target = value
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    with pytest.raises(research.LinuxEnforcementError) as caught:
        research.validate_capture_bytes(ROOT, execution.canonical_json(value))
    assert caught.value.code == code
