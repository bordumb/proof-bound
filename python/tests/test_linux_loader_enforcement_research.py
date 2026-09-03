from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from proofbound import linux_enforcement_execute as base
from proofbound import linux_loader_enforcement_attacks as attacks
from proofbound import linux_loader_enforcement_research as research


ROOT = Path(__file__).resolve().parents[2]
CAPTURE = Path("/private/tmp/exp0024-run-33810683583/capture.json")


@pytest.mark.skipif(not CAPTURE.exists(), reason="live EXP-0024 capture is not local")
def test_live_loader_capture_passes() -> None:
    report = research.validate_capture_bytes(ROOT, CAPTURE.read_bytes())
    assert report["availability"] == "supported"
    assert report["metrics"]["positive_executions"] == 30
    assert report["metrics"]["authority_probe_executions"] == 21
    assert report["metrics"]["denied_reusable"] == 0
    assert len(report["runtime_loaders"]) == 3
    assert len(report["policy_attacks"]) == 20


@pytest.mark.skipif(not CAPTURE.exists(), reason="live EXP-0024 capture is not local")
@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("resolved_path", "/usr/bin/true", "LNX4-LOADER-PATH"),
        ("sha256", "sha256:" + "0" * 64, "LNX4-POLICY-IDENTITY"),
        ("size_bytes", 0, "LNX4-LOADER-SIZE"),
        ("mode", 0o644, "LNX4-LOADER-MODE"),
    ],
)
def test_loader_attacks_fail_closed(field: str, replacement: object, code: str) -> None:
    value = copy.deepcopy(json.loads(CAPTURE.read_bytes()))
    value["slots"][0]["policy"]["runtime_loader"][field] = replacement
    value["identity"] = base.domain_hash(
        "proofbound-research-linux-loader-capture/1",
        {key: item for key, item in value.items() if key != "identity"},
    )
    with pytest.raises(research.LinuxLoaderError) as caught:
        research.validate_capture(value)
    assert caught.value.code == code


@pytest.mark.skipif(not CAPTURE.exists(), reason="live EXP-0024 capture is not local")
def test_all_registered_python_attacks_fail_exactly() -> None:
    for _attack_id, expected, payload in attacks.attack_payloads(CAPTURE.read_bytes()):
        with pytest.raises(research.LinuxLoaderError) as caught:
            research.validate_capture_bytes(ROOT, payload)
        assert caught.value.code == expected
