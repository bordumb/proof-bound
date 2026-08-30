"""Strict helpers for Proofbound's JSON adapter envelope.

These helpers deliberately do not load project manifests or derive assurance
status.  They preserve the architecture's single Rust authority while making
it straightforward to implement a Python tool adapter without shell parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Mapping


SCHEMA = "proofbound-adapter-protocol/1"
_REQUEST_FIELDS = {
    "schema",
    "type",
    "request_id",
    "adapter",
    "operation",
    "project_root",
    "unit",
}
_RESPONSE_FIELDS = {
    "schema",
    "type",
    "request_id",
    "adapter",
    "success",
    "evidence",
    "inventory",
    "diagnostics",
}


class ProtocolError(ValueError):
    """Raised when a protocol envelope is not the closed v1 shape."""


def canonical_json(value: object) -> bytes:
    """Encode canonical UTF-8 JSON with sorted keys and no trailing newline."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError(f"invalid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise ProtocolError("protocol message must be an object")
    if canonical_json(value) != data:
        raise ProtocolError("protocol message is not canonical JSON")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{field} must be non-empty text")
    return value


def _identity(value: object, field: str, pattern: str) -> str:
    text = _text(value, field)
    if re.fullmatch(pattern, text) is None:
        raise ProtocolError(f"{field} is not canonical")
    return text


@dataclass(frozen=True)
class AdapterRequest:
    request_id: str
    adapter: str
    operation: str
    project_root: str
    unit: Mapping[str, Any]

    @classmethod
    def parse(cls, data: bytes) -> AdapterRequest:
        value = _object(data)
        if set(value) != _REQUEST_FIELDS:
            raise ProtocolError("request has missing or unknown fields")
        if value["schema"] != SCHEMA or value["type"] != "request":
            raise ProtocolError("unsupported request envelope")
        if not isinstance(value["unit"], dict):
            raise ProtocolError("unit must be an object")
        if value["operation"] not in {
            "doctor",
            "inventory",
            "check",
            "reproduce",
            "update",
        }:
            raise ProtocolError("unsupported operation")
        if value["project_root"] != ".":
            raise ProtocolError("project_root must be '.'")
        return cls(
            request_id=_identity(value["request_id"], "request_id", r"[0-9a-f]{32}"),
            adapter=_identity(
                value["adapter"], "adapter", r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
            ),
            operation=value["operation"],
            project_root=".",
            unit=value["unit"],
        )

    def to_bytes(self) -> bytes:
        return canonical_json(
            {
                "adapter": self.adapter,
                "type": "request",
                "operation": self.operation,
                "project_root": self.project_root,
                "request_id": self.request_id,
                "schema": SCHEMA,
                "unit": dict(self.unit),
            }
        )


@dataclass(frozen=True)
class AdapterResponse:
    request_id: str
    adapter: str
    success: bool
    evidence: Mapping[str, Any] | None
    inventory: tuple[str, ...]
    diagnostics: tuple[Mapping[str, Any], ...]

    @classmethod
    def parse(cls, data: bytes) -> AdapterResponse:
        value = _object(data)
        if set(value) != _RESPONSE_FIELDS:
            raise ProtocolError("response has missing or unknown fields")
        if value["schema"] != SCHEMA or value["type"] != "response":
            raise ProtocolError("unsupported response envelope")
        if not isinstance(value["success"], bool):
            raise ProtocolError("success must be Boolean")
        evidence = value["evidence"]
        if evidence is not None and not isinstance(evidence, dict):
            raise ProtocolError("evidence must be an object or null")
        if value["success"] != (evidence is not None):
            raise ProtocolError("success and evidence presence disagree")
        inventory = value["inventory"]
        diagnostics = value["diagnostics"]
        if (
            not isinstance(inventory, list)
            or any(not isinstance(item, str) or not item for item in inventory)
            or inventory != sorted(set(inventory))
        ):
            raise ProtocolError("inventory must be sorted, unique, non-empty strings")
        if not isinstance(diagnostics, list) or any(not isinstance(item, dict) for item in diagnostics):
            raise ProtocolError("diagnostics must be objects")
        for diagnostic in diagnostics:
            if not {"code", "message"}.issubset(diagnostic) or not set(diagnostic).issubset(
                {"code", "message", "path", "remediation"}
            ):
                raise ProtocolError("diagnostic has missing or unknown fields")
            _identity(diagnostic["code"], "diagnostic code", r"PB-[A-Z]+-[0-9]{4}")
            _text(diagnostic["message"], "diagnostic message")
        return cls(
            request_id=_identity(value["request_id"], "request_id", r"[0-9a-f]{32}"),
            adapter=_identity(
                value["adapter"], "adapter", r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
            ),
            success=value["success"],
            evidence=evidence,
            inventory=tuple(inventory),
            diagnostics=tuple(diagnostics),
        )

    def to_bytes(self) -> bytes:
        return canonical_json(
            {
                "adapter": self.adapter,
                "diagnostics": [dict(item) for item in self.diagnostics],
                "evidence": None if self.evidence is None else dict(self.evidence),
                "inventory": list(self.inventory),
                "type": "response",
                "request_id": self.request_id,
                "schema": SCHEMA,
                "success": self.success,
            }
        )
