#!/usr/bin/env python3
"""Reusable proofbound-transcription-driver/1 example."""

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
        raise ValueError("wrong source format magic")
    lines = raw[len(SOURCE_MAGIC) :].splitlines(keepends=True)
    if not lines or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("source fields must be newline terminated")
    try:
        count = int(lines[0][:-1].decode("ascii"))
        values = [int(line[:-1].decode("ascii")) for line in lines[1:]]
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("source fields must be ASCII integers") from error
    if count != len(values) or any(value < 0 or value > U32_MAX for value in values):
        raise ValueError("source count or u32 value is invalid")
    if encode_source(values) != raw:
        raise ValueError("source is not canonical")
    return values


def encode_transcription(values: list[int]) -> bytes:
    return (
        json.dumps(
            {"schema": TRANSCRIBED_FORMAT, "values": values},
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def decode_transcription(raw: bytes) -> list[int]:
    document = json.loads(raw)
    if not isinstance(document, dict) or set(document) != {"schema", "values"}:
        raise ValueError("transcription has unknown or missing fields")
    values = document["values"]
    if (
        document["schema"] != TRANSCRIBED_FORMAT
        or not isinstance(values, list)
        or any(type(value) is not int or value < 0 or value > U32_MAX for value in values)
    ):
        raise ValueError("transcription schema or values are invalid")
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
    result = (
        encode_transcription(decode_source(Path(args.source).read_bytes()))
        if args.command == "transcribe"
        else encode_source(decode_transcription(Path(args.transcription).read_bytes()))
    )
    Path(args.output).write_bytes(result)


if __name__ == "__main__":
    main()
