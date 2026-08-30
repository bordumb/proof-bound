from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from proofbound_demo.allowance import (
    CanonicalRequestError,
    EndpointReceipt,
    ReceiptMismatchError,
    Request,
    decode_request,
    main,
    registered_fixture,
    submit_exact_bytes,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "v1"


class CapturingTransport:
    def __init__(self, *, corrupt_receipt: bool = False) -> None:
        self.payloads: list[bytes] = []
        self.corrupt_receipt = corrupt_receipt

    def submit(self, payload: bytes) -> EndpointReceipt:
        self.payloads.append(payload)
        digest = hashlib.sha256(payload).hexdigest()
        if self.corrupt_receipt:
            digest = "0" * 64
        return EndpointReceipt(request_sha256=digest)


def test_python_encoder_matches_registered_accepted_bytes() -> None:
    expected, expected_digest = registered_fixture(FIXTURES / "accepted.bin")
    request = Request(
        from_balance=100,
        to_balance=25,
        amount=30,
        cap=40,
        authorized=True,
    )
    assert request.encode() == expected
    assert hashlib.sha256(expected).hexdigest() == expected_digest
    assert decode_request(expected) == request


def test_every_fixture_round_trips_and_matches_manifest() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["fixtures"]:
        payload, expected_digest = registered_fixture(FIXTURES / entry["path"])
        assert hashlib.sha256(payload).hexdigest() == expected_digest
        assert decode_request(payload).encode() == payload


def test_decoder_rejects_trailing_and_noncanonical_authorization() -> None:
    payload, _ = registered_fixture(FIXTURES / "accepted.bin")
    with pytest.raises(CanonicalRequestError, match="exactly"):
        decode_request(payload + b"\x00")
    mutated = bytearray(payload)
    mutated[5] = 2
    with pytest.raises(CanonicalRequestError, match="authorization"):
        decode_request(bytes(mutated))


def test_orchestrator_submits_the_exact_registered_bytes() -> None:
    payload, expected_digest = registered_fixture(FIXTURES / "accepted.bin")
    transport = CapturingTransport()
    receipt = submit_exact_bytes(
        payload, expected_sha256=expected_digest, transport=transport
    )
    assert transport.payloads == [payload]
    assert receipt.request_sha256 == expected_digest
    assert receipt.receiver_sha256 == expected_digest
    assert receipt.digest_match is True
    assert receipt.evidence_kind == "example-test"
    assert receipt.formal_facet == "TESTED"
    assert receipt.evaluation == "empirical-runtime-observation"


def test_receiver_digest_mismatch_fails_closed() -> None:
    payload, expected_digest = registered_fixture(FIXTURES / "accepted.bin")
    with pytest.raises(ReceiptMismatchError, match="receiver digest"):
        submit_exact_bytes(
            payload,
            expected_sha256=expected_digest,
            transport=CapturingTransport(corrupt_receipt=True),
        )


def test_cli_emits_an_explicitly_empirical_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt_path = tmp_path / "receipt.json"
    assert main(["--fixture", str(FIXTURES / "accepted.bin"), "--receipt", str(receipt_path)]) == 0
    stdout_receipt = json.loads(capsys.readouterr().out)
    file_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert stdout_receipt == file_receipt
    assert stdout_receipt["formal_facet"] == "TESTED"
    assert stdout_receipt["evaluation"] == "empirical-runtime-observation"
