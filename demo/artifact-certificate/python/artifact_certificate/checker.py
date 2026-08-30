"""Independent Python implementation of the PBAC v1 checker.

This module was written directly from FORMAT.md. It intentionally does not call
the Rust checker or consume code generated from the Rust implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 64
MAX_ENTRIES = 8
MAX_VALUE = 1_000_000


class Rejection(Exception):
    def __init__(self, code: str, offset: int):
        super().__init__(f"{code} at byte {offset}")
        self.code = code
        self.offset = offset


@dataclass(frozen=True)
class Entry:
    identifier: int
    value: int


@dataclass(frozen=True)
class Certificate:
    target: int
    entries: tuple[Entry, ...]

    @property
    def total(self) -> int:
        return sum(entry.value for entry in self.entries)


class _Cursor:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.position = 0

    def take(self) -> int:
        if self.position == len(self.payload):
            raise Rejection("PBAC_E_TRUNCATED", self.position)
        result = self.payload[self.position]
        self.position += 1
        return result

    def expect(self, wanted: int, code: str) -> None:
        offset = self.position
        if self.take() != wanted:
            raise Rejection(code, offset)

    def unsigned_leb128(self) -> int:
        origin = self.position
        result = 0
        group = 0
        while group != 5:
            octet = self.take()
            payload = octet & 0x7F
            if group == 4 and payload > 0x0F:
                raise Rejection("PBAC_E_VARINT_OVERFLOW", origin)
            result += payload * (128**group)
            if octet < 0x80:
                if group and payload == 0:
                    raise Rejection("PBAC_E_NONCANONICAL_VARINT", origin)
                return result
            group += 1
        raise Rejection("PBAC_E_VARINT_OVERFLOW", origin)


def inspect(payload: bytes) -> Certificate:
    """Return the decoded certificate or raise a stable fail-closed error."""

    if len(payload) > MAX_BYTES:
        raise Rejection("PBAC_E_TOO_LARGE", MAX_BYTES)

    cursor = _Cursor(payload)
    for expected in b"PBAC":
        cursor.expect(expected, "PBAC_E_BAD_MAGIC")
    cursor.expect(1, "PBAC_E_UNSUPPORTED_VERSION")
    cursor.expect(0, "PBAC_E_NONZERO_FLAGS")

    count_offset = cursor.position
    count = cursor.take()
    if count < 1 or count > MAX_ENTRIES:
        raise Rejection("PBAC_E_COUNT_RANGE", count_offset)

    target_offset = cursor.position
    target = cursor.unsigned_leb128()
    if target > MAX_VALUE:
        raise Rejection("PBAC_E_VALUE_RANGE", target_offset)

    entries: list[Entry] = []
    last_identifier = 0
    for _ in range(count):
        identifier_offset = cursor.position
        identifier = cursor.take()
        if identifier == 0:
            raise Rejection("PBAC_E_ID_ZERO", identifier_offset)
        if identifier <= last_identifier:
            raise Rejection("PBAC_E_ID_ORDER", identifier_offset)
        last_identifier = identifier

        value_offset = cursor.position
        value = cursor.unsigned_leb128()
        if value > MAX_VALUE:
            raise Rejection("PBAC_E_VALUE_RANGE", value_offset)
        entries.append(Entry(identifier, value))

    if cursor.position != len(payload):
        raise Rejection("PBAC_E_TRAILING_BYTES", cursor.position)

    certificate = Certificate(target, tuple(entries))
    if certificate.total != target:
        raise Rejection("PBAC_E_SUM_MISMATCH", 0)
    return certificate


def inspect_path(path: Path) -> Certificate:
    with path.open("rb") as source:
        payload = source.read(MAX_BYTES + 1)
    return inspect(payload)


def _unsigned_leb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        octet = value & 0x7F
        value >>= 7
        if value:
            octet |= 0x80
        encoded.append(octet)
        if not value:
            return bytes(encoded)


def encode(certificate: Certificate) -> bytes:
    payload = bytearray(b"PBAC\x01\x00")
    payload.append(len(certificate.entries))
    payload.extend(_unsigned_leb128(certificate.target))
    for entry in certificate.entries:
        payload.append(entry.identifier)
        payload.extend(_unsigned_leb128(entry.value))
    return bytes(payload)


def _load_binding(path: Path) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate binding key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    required = {
        "schema",
        "theorem",
        "claims",
        "artifact_logical_name",
        "artifact_sha256",
        "inventory",
        "target",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("binding expectation has missing or unknown fields")
    if value["schema"] != "pbac-binding-expectation/1":
        raise ValueError("unsupported binding expectation schema")
    for field in ("theorem", "artifact_logical_name"):
        if not isinstance(value[field], str) or not value[field]:
            raise ValueError(f"binding expectation {field} must be non-empty text")
    digest = value["artifact_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 71
        or not digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in digest[7:])
    ):
        raise ValueError("binding expectation digest is not canonical SHA-256")
    for field in ("claims", "inventory"):
        items = value[field]
        if (
            not isinstance(items, list)
            or not items
            or any(not isinstance(item, str) or not item for item in items)
            or items != sorted(set(items))
        ):
            raise ValueError(f"binding expectation {field} must be sorted and unique")
    if not isinstance(value["target"], int) or isinstance(value["target"], bool):
        raise ValueError("binding expectation target must be an integer")
    return value


def _artifact_binding_report(
    certificate_path: Path, binding_path: Path
) -> dict[str, object]:
    with certificate_path.open("rb") as source:
        payload = source.read(MAX_BYTES + 1)
    certificate = inspect(payload)
    binding = _load_binding(binding_path)
    artifact_name = certificate_path.as_posix()
    actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if binding["artifact_logical_name"] != artifact_name:
        raise ValueError("binding expectation names a different artifact input")
    if binding["artifact_sha256"] != actual_digest:
        raise ValueError("artifact digest does not match binding expectation")
    if binding["target"] != certificate.target:
        raise ValueError("decoded target does not match the literal claim expectation")
    reencoding_passed = encode(certificate) == payload
    if not reencoding_passed:
        raise ValueError("accepted artifact did not round-trip canonically")
    try:
        inspect(payload + b"\x00")
    except Rejection as error:
        trailing_bytes_rejected = error.code in {
            "PBAC_E_TRAILING_BYTES",
            "PBAC_E_TOO_LARGE",
        }
    else:
        trailing_bytes_rejected = False
    if not trailing_bytes_rejected:
        raise ValueError("checker accepted a trailing-byte mutation")
    return {
        "schema": "proofbound-artifact-check-result/1",
        "accepted": True,
        "theorem": binding["theorem"],
        "claims": binding["claims"],
        "artifact_logical_name": artifact_name,
        "artifact_sha256": actual_digest,
        "inventory": binding["inventory"],
        "canonical_payload": True,
        "schema_bound": True,
        "literal_claim_bound": True,
        "digest_bound": True,
        "reencoding_passed": reencoding_passed,
        "trailing_bytes_rejected": trailing_bytes_rejected,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="independent PBAC diagnostic checker")
    parser.add_argument("certificate", type=Path)
    parser.add_argument("binding", type=Path, nargs="?")
    args = parser.parse_args(argv)

    if args.binding is not None:
        try:
            report = _artifact_binding_report(args.certificate, args.binding)
        except (OSError, Rejection, ValueError, json.JSONDecodeError) as error:
            sys.stdout.write(
                json.dumps(
                    {
                        "schema": "proofbound-artifact-check-result/1",
                        "accepted": False,
                        "error": str(error),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 2
        sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0

    try:
        certificate = inspect_path(args.certificate)
    except OSError as error:
        print(
            json.dumps(
                {
                    "schema": "pbac-check-result/1",
                    "accepted": False,
                    "code": "PBAC_E_IO",
                    "message": str(error),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 3
    except Rejection as error:
        print(
            json.dumps(
                {
                    "schema": "pbac-check-result/1",
                    "accepted": False,
                    "code": error.code,
                    "offset": error.offset,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2

    print(
        json.dumps(
            {
                "schema": "pbac-check-result/1",
                "accepted": True,
                "entries": len(certificate.entries),
                "target": certificate.target,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
