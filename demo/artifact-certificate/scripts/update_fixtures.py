#!/usr/bin/env python3
"""Reproduce PBAC fixtures. Default mode is verify-only; use --update to write."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def uleb(value: int) -> bytes:
    if value < 0 or value > 0xFFFF_FFFF:
        raise ValueError("value outside u32")
    output = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        output.append(part | (0x80 if value else 0))
        if not value:
            return bytes(output)


def certificate(target: int, entries: list[tuple[int, int]]) -> bytes:
    output = bytearray(b"PBAC\x01\x00")
    output.append(len(entries))
    output.extend(uleb(target))
    for entry_id, value in entries:
        output.append(entry_id)
        output.extend(uleb(value))
    return bytes(output)


BASIC = certificate(1_021, [(1, 3), (4, 128), (9, 890)])
BOUNDARY_VALUES = [0, 1, 127, 128, 16_383, 16_384, 100_000]
BOUNDARY_VALUES.append(1_000_000 - sum(BOUNDARY_VALUES))
BOUNDARY = certificate(1_000_000, list(enumerate(BOUNDARY_VALUES, start=1)))

NONCANONICAL_TARGET = BASIC[:7] + bytes([0xFD, 0x87, 0x00]) + BASIC[9:]
OVERFLOW_TARGET = BASIC[:7] + bytes([0x80, 0x80, 0x80, 0x80, 0x10]) + BASIC[9:]

CASES: dict[str, tuple[bytes, bool, str | None]] = {
    "valid-basic.pbac": (BASIC, True, None),
    "valid-boundary.pbac": (BOUNDARY, True, None),
    "invalid-bad-version.pbac": (
        BASIC[:4] + b"\x02" + BASIC[5:],
        False,
        "PBAC_E_UNSUPPORTED_VERSION",
    ),
    "invalid-count-zero.pbac": (
        BASIC[:6] + b"\x00" + BASIC[7:],
        False,
        "PBAC_E_COUNT_RANGE",
    ),
    "invalid-duplicate-id.pbac": (
        BASIC[:11] + b"\x01" + BASIC[12:],
        False,
        "PBAC_E_ID_ORDER",
    ),
    "invalid-noncanonical-target.pbac": (
        NONCANONICAL_TARGET,
        False,
        "PBAC_E_NONCANONICAL_VARINT",
    ),
    "invalid-overflow-target.pbac": (OVERFLOW_TARGET, False, "PBAC_E_VARINT_OVERFLOW"),
    "invalid-oversized.pbac": (
        BASIC + bytes(65 - len(BASIC)),
        False,
        "PBAC_E_TOO_LARGE",
    ),
    "invalid-sum.pbac": (
        BASIC[:7] + uleb(1_020) + BASIC[9:],
        False,
        "PBAC_E_SUM_MISMATCH",
    ),
    "invalid-trailing.pbac": (BASIC + b"\x00", False, "PBAC_E_TRAILING_BYTES"),
    "invalid-truncated.pbac": (BASIC[:8], False, "PBAC_E_TRUNCATED"),
}


def expected_files() -> dict[Path, bytes]:
    files = {FIXTURES / name: payload for name, (payload, _, _) in CASES.items()}
    records = []
    for name, (payload, accepted, code) in sorted(CASES.items()):
        record: dict[str, object] = {
            "accepted": accepted,
            "bytes": len(payload),
            "file": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        if code is not None:
            record["error_code"] = code
        records.append(record)
    manifest = {"schema": "pbac-fixture-manifest/1", "fixtures": records}
    files[FIXTURES / "manifest.json"] = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--update", action="store_true", help="write generated fixtures"
    )
    args = parser.parse_args()

    drifted: list[str] = []
    for path, expected in expected_files().items():
        if args.update:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
        elif not path.exists() or path.read_bytes() != expected:
            drifted.append(path.name)

    if drifted:
        print("fixture drift: " + ", ".join(drifted))
        return 1
    print("PBAC fixtures reproduced" if args.update else "PBAC fixtures match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
