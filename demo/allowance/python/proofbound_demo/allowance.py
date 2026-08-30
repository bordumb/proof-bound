"""Empirical exact-byte submission boundary for the allowance demo.

This module deliberately does not implement claim status or formal policy. It
independently encodes/decodes the request format, submits the exact bytes to a
transport, and compares the receiver's digest with the registered fixture
digest. That runtime observation is example-test evidence, never a proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, Sequence

REQUEST_SCHEMA = "proofbound-allowance-request/1"
RECEIPT_SCHEMA = "proofbound-allowance-orchestrator-receipt/1"
MAGIC = b"PBAL"
VERSION = 1
REQUEST_LENGTH = 38
MAX_U64 = (1 << 64) - 1
_REQUEST = struct.Struct(">4sBBQQQQ")


class CanonicalRequestError(ValueError):
    """Raised when bytes are not canonical allowance request version 1."""


class ReceiptMismatchError(RuntimeError):
    """Raised when the receiver did not acknowledge the submitted bytes."""


@dataclass(frozen=True, slots=True)
class Request:
    from_balance: int
    to_balance: int
    amount: int
    cap: int
    authorized: bool

    def __post_init__(self) -> None:
        for field_name in ("from_balance", "to_balance", "amount", "cap"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if not 0 <= value <= MAX_U64:
                raise ValueError(f"{field_name} must fit unsigned 64-bit")
        if type(self.authorized) is not bool:
            raise TypeError("authorized must be a Boolean")

    def encode(self) -> bytes:
        """Independently encode `proofbound-allowance-request/1`."""

        return _REQUEST.pack(
            MAGIC,
            VERSION,
            int(self.authorized),
            self.from_balance,
            self.to_balance,
            self.amount,
            self.cap,
        )


def decode_request(payload: bytes) -> Request:
    """Independently decode exact canonical request bytes."""

    if len(payload) != REQUEST_LENGTH:
        raise CanonicalRequestError(
            f"request must be exactly {REQUEST_LENGTH} bytes, got {len(payload)}"
        )
    magic, version, authorized, from_balance, to_balance, amount, cap = (
        _REQUEST.unpack(payload)
    )
    if magic != MAGIC:
        raise CanonicalRequestError("invalid request magic")
    if version != VERSION:
        raise CanonicalRequestError(f"unsupported request version {version}")
    if authorized not in (0, 1):
        raise CanonicalRequestError("authorization must use canonical byte 0 or 1")
    request = Request(
        from_balance=from_balance,
        to_balance=to_balance,
        amount=amount,
        cap=cap,
        authorized=bool(authorized),
    )
    if request.encode() != payload:
        raise CanonicalRequestError("request does not round-trip canonically")
    return request


@dataclass(frozen=True, slots=True)
class EndpointReceipt:
    request_sha256: str


class SubmissionTransport(Protocol):
    def submit(self, payload: bytes) -> EndpointReceipt:
        """Submit bytes and return the receiver's digest acknowledgement."""


class LocalDigestEndpoint:
    """Small deterministic receiver used by the standalone teaching demo.

    A deployed integration replaces this object with its network transport. The
    receiver hashes the bytes it receives rather than accepting the sender's
    claimed digest.
    """

    def submit(self, payload: bytes) -> EndpointReceipt:
        return EndpointReceipt(request_sha256=hashlib.sha256(payload).hexdigest())


@dataclass(frozen=True, slots=True)
class EmpiricalReceipt:
    schema: str
    evidence_kind: str
    formal_facet: str
    evaluation: str
    request_schema: str
    request_sha256: str
    submitted_length: int
    receiver_sha256: str
    digest_match: bool

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def submit_exact_bytes(
    payload: bytes,
    *,
    expected_sha256: str,
    transport: SubmissionTransport,
) -> EmpiricalReceipt:
    """Submit exact canonical bytes and compare sender, fixture, and receiver digests."""

    decode_request(payload)
    local_digest = hashlib.sha256(payload).hexdigest()
    if local_digest != expected_sha256:
        raise ReceiptMismatchError(
            f"fixture digest mismatch: expected {expected_sha256}, got {local_digest}"
        )

    endpoint_receipt = transport.submit(payload)
    if endpoint_receipt.request_sha256 != local_digest:
        raise ReceiptMismatchError(
            "receiver digest does not identify the bytes submitted by the orchestrator"
        )

    return EmpiricalReceipt(
        schema=RECEIPT_SCHEMA,
        evidence_kind="example-test",
        formal_facet="TESTED",
        evaluation="empirical-runtime-observation",
        request_schema=REQUEST_SCHEMA,
        request_sha256=local_digest,
        submitted_length=len(payload),
        receiver_sha256=endpoint_receipt.request_sha256,
        digest_match=True,
    )


def _fixture_root() -> Path:
    return Path(__file__).resolve().parents[2] / "fixtures" / "v1"


def registered_fixture(path: Path) -> tuple[bytes, str]:
    """Read one registered fixture and return its bytes and sealed digest."""

    root = _fixture_root().resolve()
    resolved = path.resolve()
    if resolved.parent != root:
        raise CanonicalRequestError("fixture must be a direct child of fixtures/v1")

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entries = manifest.get("fixtures")
    if not isinstance(entries, list):
        raise CanonicalRequestError("fixture manifest has no fixture inventory")
    matches = [entry for entry in entries if entry.get("path") == resolved.name]
    if len(matches) != 1:
        raise CanonicalRequestError("fixture is missing or ambiguous in manifest")
    expected_digest = matches[0].get("sha256")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise CanonicalRequestError("fixture manifest has an invalid SHA-256")
    return resolved.read_bytes(), expected_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofbound-allowance-demo",
        description="Submit exact allowance request bytes and emit empirical evidence.",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=_fixture_root() / "accepted.bin",
        help="registered binary fixture beneath fixtures/v1",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="optional path for the canonical JSON runtime receipt",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload, expected_digest = registered_fixture(args.fixture)
    receipt = submit_exact_bytes(
        payload,
        expected_sha256=expected_digest,
        transport=LocalDigestEndpoint(),
    )
    rendered = receipt.to_json()
    if args.receipt is not None:
        args.receipt.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main
    raise SystemExit(main())
