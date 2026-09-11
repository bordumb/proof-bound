from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from proofbound import windows_output_network_attacks as attacks
from proofbound import windows_output_network_execute as execution
from proofbound import windows_output_network_research as research
from proofbound.windows_enforcement_execute import sha256_bytes
from proofbound.windows_native_boundary import loopback_exempt_appcontainer_sids


ROOT = Path(__file__).resolve().parents[2]


def test_successor_corpus_is_exact_and_changes_only_python() -> None:
    effective = execution._effective_corpus_inventory(ROOT)
    base = execution.initialization._corpus_inventory(ROOT)
    differences = [
        (before, after)
        for before, after in zip(base, effective, strict=True)
        if before != after
    ]
    assert len(differences) == 1
    before, after = differences[0]
    assert before["path"] == after["path"] == "workspace/subjects/python_subject.py"
    payload = (ROOT / execution.PYTHON_SUBJECT).read_bytes()
    assert after["sha256"] == sha256_bytes(payload)
    assert after["size_bytes"] == len(payload)


def test_python_subject_writes_binary_exact_output(tmp_path: Path) -> None:
    registered = tmp_path / "registered.txt"
    registered.write_bytes(b"registered-input\n")
    output = tmp_path / "output.txt"
    environment = {"PB_REGISTERED_VALUE": "registered-env"}
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            str(ROOT / execution.PYTHON_SUBJECT),
            "positive",
            str(registered),
            str(output),
            str(tmp_path / "unrelated.txt"),
            "1",
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""
    assert output.read_bytes() == b"registered-input|registered-env\n"


def test_registered_attack_inventory_is_exact() -> None:
    assert len(attacks.MUTATIONS) == len(research.ATTACKS) == 38
    assert [attack_id for attack_id, _ in research.ATTACKS[30:]] == [
        f"EXP-0026-A{index:03d}" for index in range(31, 39)
    ]


def test_listener_oracle_observes_one_real_connection() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=1):
            assert execution._accept(listener, 1) is True
        assert execution._accept(listener, 0.01) is False


@pytest.mark.skipif(os.name == "nt", reason="non-Windows fail-closed check")
def test_loopback_inventory_requires_native_windows() -> None:
    with pytest.raises(OSError, match="requires native Windows"):
        loopback_exempt_appcontainer_sids()
