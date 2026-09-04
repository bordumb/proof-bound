from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from proofbound import windows_initialization_attacks as attacks
from proofbound import windows_initialization_execute as execution
from proofbound import windows_initialization_research as research
from proofbound.windows_enforcement_execute import sha256_bytes
from proofbound.windows_native_boundary import pe_machine


ROOT = Path(__file__).resolve().parents[2]


def test_frozen_slot_inventory_matches_both_independent_implementations() -> None:
    produced = execution._slot_definitions()
    expected = research._expected_slots()
    assert produced == expected
    assert len(produced) == 51
    assert sum(row["kind"] == "positive" for row in produced) == 30
    assert sum(row["kind"] == "authority-probe" for row in produced) == 21
    assert produced[0]["slot_id"] == "positive-node-00"
    assert produced[30]["slot_id"] == "probe-exp-0018-a001-node"
    assert produced[-1]["slot_id"] == "probe-exp-0018-a013-rust"


def test_registered_attack_inventory_is_exact_and_above_minimum() -> None:
    assert len(attacks.MUTATIONS) == len(research.ATTACKS) == 30
    assert len(research.ATTACKS) >= 24
    assert [item[0] for item in research.ATTACKS] == [
        f"EXP-0025-A{index:03d}" for index in range(1, 31)
    ]


def test_corpus_inventory_is_still_byte_pinned() -> None:
    rows = execution._corpus_inventory(ROOT)
    assert len(rows) == 10
    for row in rows:
        payload = (ROOT / execution.CORPUS_PATH / row["path"]).read_bytes()
        assert row["sha256"] == sha256_bytes(payload)
        assert row["size_bytes"] == len(payload)


def test_tree_identity_rejects_reparse_points(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("host cannot create symlinks")
    with pytest.raises(ValueError, match="reparse point"):
        execution._tree_identity(tmp_path)


def test_tool_identity_normalizes_only_one_platform_line_ending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(["tool"], 0, b"tool 1.2.3\r\n", b"")

    monkeypatch.setattr(execution.subprocess, "run", run)
    assert execution._strict_tool_output(["tool", "--version"]) == "tool 1.2.3"


def test_tool_identity_rejects_stderr_or_multiple_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = iter(
        [
            subprocess.CompletedProcess(["tool"], 0, b"tool 1\n", b"warning\n"),
            subprocess.CompletedProcess(["tool"], 0, b"tool 1\ntool 2\n", b""),
        ]
    )
    monkeypatch.setattr(
        execution.subprocess, "run", lambda *_args, **_kwargs: next(values)
    )
    with pytest.raises(ValueError, match="output differs"):
        execution._strict_tool_output(["tool", "--version"])
    with pytest.raises(ValueError, match="canonical line"):
        execution._strict_tool_output(["tool", "--version"])


def test_pe_machine_rejects_malformed_and_unknown_images() -> None:
    malformed = bytearray(64)
    malformed[:2] = b"MZ"
    malformed[0x3C:0x40] = (60).to_bytes(4, "little")
    with pytest.raises(ValueError, match="invalid header"):
        pe_machine(bytes(malformed))

    unknown = bytearray(72)
    unknown[:2] = b"MZ"
    unknown[0x3C:0x40] = (64).to_bytes(4, "little")
    unknown[64:68] = b"PE\0\0"
    unknown[68:70] = (0xFFFF).to_bytes(2, "little")
    with pytest.raises(ValueError, match="unsupported staged PE machine"):
        pe_machine(bytes(unknown))


def test_pe_machine_accepts_arm64_image_header() -> None:
    image = bytearray(72)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    image[68:70] = (0xAA64).to_bytes(2, "little")
    assert pe_machine(bytes(image)) == "aarch64"
