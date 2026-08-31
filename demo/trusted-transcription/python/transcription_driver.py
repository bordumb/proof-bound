#!/usr/bin/env python3
"""Reference implementation of proofbound-transcription-driver/1.

This intentionally tiny format makes the trust boundary inspectable. The
driver parses canonical unsigned-32-bit line values into a typed JSON value and
can re-encode that value into the exact canonical source bytes.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


TRANSCRIBED_FORMAT = "proofbound-u32-json/1"
SOURCE_MAGIC = b"PBTT-U32-LINES/1\n"
U32_MAX = (1 << 32) - 1


def encode_source(values: list[int]) -> bytes:
    return SOURCE_MAGIC + f"{len(values)}\n".encode() + b"".join(
        f"{value}\n".encode() for value in values
    )


def decode_source(raw: bytes) -> list[int]:
    if not raw.startswith(SOURCE_MAGIC):
        raise ValueError("source magic does not identify proofbound-u32-lines/1")
    lines = raw[len(SOURCE_MAGIC) :].splitlines(keepends=True)
    if not lines or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("source must contain canonical newline-terminated fields")
    try:
        count = int(lines[0][:-1].decode("ascii"))
        values = [int(line[:-1].decode("ascii")) for line in lines[1:]]
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("source fields must be canonical ASCII integers") from error
    if count != len(values) or any(value < 0 or value > U32_MAX for value in values):
        raise ValueError("source count or unsigned-32-bit value is invalid")
    if encode_source(values) != raw:
        raise ValueError("source is not canonically encoded")
    return values


def encode_transcription(values: list[int]) -> bytes:
    document = {"schema": TRANSCRIBED_FORMAT, "values": values}
    return (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode()


def decode_transcription(raw: bytes) -> list[int]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("transcription must be UTF-8 JSON") from error
    if not isinstance(document, dict) or set(document) != {"schema", "values"}:
        raise ValueError("transcription has unknown or missing fields")
    values = document["values"]
    if (
        document["schema"] != TRANSCRIBED_FORMAT
        or not isinstance(values, list)
        or any(type(value) is not int or value < 0 or value > U32_MAX for value in values)
    ):
        raise ValueError("transcription schema or typed values are invalid")
    if encode_transcription(values) != raw:
        raise ValueError("transcription is not canonical")
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    transcribe = commands.add_parser("transcribe")
    transcribe.add_argument("--source", required=True)
    transcribe.add_argument("--output", required=True)
    reencode = commands.add_parser("reencode")
    reencode.add_argument("--transcription", required=True)
    reencode.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "transcribe":
        result = encode_transcription(decode_source(Path(args.source).read_bytes()))
    else:
        result = encode_source(decode_transcription(Path(args.transcription).read_bytes()))
    Path(args.output).write_bytes(result)


if __name__ == "__main__":
    main()
