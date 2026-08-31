from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifact_certificate.checker import MAX_BYTES, Rejection, encode, inspect, main

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


def test_fixture_manifest_is_reproduced_by_independent_checker() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    assert manifest["schema"] == "pbac-fixture-manifest/1"
    for record in manifest["fixtures"]:
        payload = (FIXTURES / record["file"]).read_bytes()
        if record["accepted"]:
            certificate = inspect(payload)
            assert certificate.total == certificate.target
        else:
            with pytest.raises(Rejection) as raised:
                inspect(payload)
            assert raised.value.code == record["error_code"], record["file"]


def test_every_truncation_and_suffix_is_rejected() -> None:
    valid = (FIXTURES / "valid-basic.pbac").read_bytes()
    for length in range(len(valid)):
        with pytest.raises(Rejection):
            inspect(valid[:length])
    for suffix in range(256):
        with pytest.raises(Rejection, match="PBAC_E_TRAILING_BYTES"):
            inspect(valid + bytes([suffix]))


def test_deterministic_fuzz_like_corpus_is_total_and_sound_when_accepted() -> None:
    state = 0xA5A5_1234
    for length in range(MAX_BYTES + 9):
        candidate = bytearray()
        for _ in range(length):
            state ^= (state << 13) & 0xFFFF_FFFF
            state ^= state >> 17
            state ^= (state << 5) & 0xFFFF_FFFF
            state &= 0xFFFF_FFFF
            candidate.append(state & 0xFF)
        try:
            certificate = inspect(bytes(candidate))
        except Rejection:
            continue
        assert certificate.total == certificate.target


def test_canonical_binding_report_contains_only_observed_artifact_facts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repository = ROOT.parents[1]
    monkeypatch.chdir(repository)
    certificate = "demo/artifact-certificate/fixtures/valid-basic.pbac"
    binding = "demo/artifact-certificate/fixtures/pbac-sum.binding.json"
    assert main([certificate, binding]) == 0
    output = capsys.readouterr().out
    assert not output.endswith("\n")
    report = json.loads(output)
    assert set(report) == {
        "accepted",
        "artifact_logical_name",
        "artifact_sha256",
        "inventory",
        "schema",
    }
    assert report == {
        "accepted": True,
        "artifact_logical_name": certificate,
        "artifact_sha256": report["artifact_sha256"],
        "inventory": ["valid-basic.pbac"],
        "schema": "proofbound-artifact-check-result/1",
    }
    assert report["artifact_sha256"].endswith(
        "dd7cf87ba3535aad431c473b71286fb6806fcc785fc3b39290c4a99d561dfe2d"
    )
    decoded = inspect((repository / certificate).read_bytes())
    assert encode(decoded) == (repository / certificate).read_bytes()


def test_independent_mode_emits_exact_canonical_inventory(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repository = ROOT.parents[1]
    monkeypatch.chdir(repository)
    certificate = "demo/artifact-certificate/fixtures/valid-basic.pbac"
    assert main([certificate]) == 0
    output = capsys.readouterr().out
    assert output == (
        '{"accepted":true,"inventory":["valid-basic.pbac"],'
        '"schema":"proofbound-independent-check-result/1"}'
    )


def test_binding_report_rejects_digest_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = ROOT.parents[1]
    monkeypatch.chdir(repository)
    binding = json.loads((FIXTURES / "pbac-sum.binding.json").read_text())
    binding["artifact_sha256"] = "sha256:" + "00" * 32
    altered = tmp_path / "binding.json"
    altered.write_text(json.dumps(binding, sort_keys=True, separators=(",", ":")))
    assert (
        main(
            [
                "demo/artifact-certificate/fixtures/valid-basic.pbac",
                str(altered),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["accepted"] is False
