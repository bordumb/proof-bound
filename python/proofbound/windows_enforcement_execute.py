"""Capture the fail-closed EXP-0021 Windows availability gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import sys
from typing import Any


CAPTURE_SCHEMA = "proofbound-research-windows-enforcement-capture/1"
CONTRACT_SHA256 = (
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d"
)
MECHANISMS = [
    "appcontainer",
    "restricted-token",
    "job-object",
    "explicit-path-acl",
]


def canonical_json(value: Any) -> bytes:
    """Return the repository canonical JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sha256_bytes(value: bytes) -> str:
    """Return a tagged SHA-256 identity."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def domain_hash(domain: str, value: Any) -> str:
    """Hash canonical JSON under a NUL-separated domain."""

    return sha256_bytes(domain.encode() + b"\0" + canonical_json(value))


def capture() -> dict[str, Any]:
    """Return a typed availability result without executing a fallback."""

    host_os = platform.system().lower()
    machine = platform.machine().lower()
    host_architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(machine, machine)
    supported_host = host_os == "windows" and host_architecture in {
        "aarch64",
        "x86_64",
    }
    reason = (
        "native-backend-not-implemented"
        if supported_host
        else "host-os-or-architecture-not-windows-candidate"
    )
    value = {
        "schema": CAPTURE_SCHEMA,
        "experiment": "EXP-0021",
        "programme_experiment": "EXP-LANG-014",
        "contract_sha256": CONTRACT_SHA256,
        "requested_platform": {
            "os": "windows",
            "architectures": ["aarch64", "x86_64"],
            "minimum_release": "Windows 11",
        },
        "candidate_mechanisms": MECHANISMS,
        "host": {
            "os": host_os,
            "architecture": host_architecture,
            "release": platform.release(),
            "version": platform.version(),
        },
        "availability": "unsupported",
        "unsupported_reason": reason,
        "mechanism_probe": "host-platform-gate-before-tool-execution",
        "fallback_used": False,
        "slots": [],
    }
    value["identity"] = domain_hash(
        "proofbound-research-windows-enforcement-capture/1", value
    )
    return value


def main(argv: list[str] | None = None) -> int:
    """Write one canonical availability capture."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_enforcement_execute CAPTURE", file=sys.stderr)
        return 2
    try:
        Path(arguments[0]).write_bytes(canonical_json(capture()))
    except OSError as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
