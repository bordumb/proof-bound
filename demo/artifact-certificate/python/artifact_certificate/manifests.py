"""Strict validation for the demo's Proofbound-schema TOML manifests."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Never

CLAIM_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
LOCAL_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EVIDENCE_REF = re.compile(r"[a-z][a-z0-9-]*:[A-Za-z0-9_.:-]+\Z")

CLAIM_ALLOWED = {
    "schema",
    "id",
    "title",
    "statement",
    "public_language",
    "formal_declaration",
    "statement_encoding",
    "statement_sha256",
    "foundational_axioms",
    "subject",
    "subject_closure",
    "profile",
    "tier",
    "primary_linkage",
    "evidence",
    "assumptions",
    "premises",
    "open_obligations",
    "out_of_scope",
    "bounded_domain",
    "source_roots",
}
CLAIM_REQUIRED = {
    "schema",
    "id",
    "title",
    "statement",
    "subject",
    "profile",
    "evidence",
    "assumptions",
    "open_obligations",
    "out_of_scope",
}
ASSUMPTION_ALLOWED = {
    "schema",
    "id",
    "statement",
    "category",
    "owner",
    "rationale",
    "scope",
    "affected_claims",
    "review_evidence",
    "discharge_plan",
    "source_citation",
    "status",
}
ASSUMPTION_REQUIRED = ASSUMPTION_ALLOWED - {"source_citation"}
EVIDENCE_ALLOWED = {
    "schema",
    "id",
    "adapter",
    "kind",
    "claims",
    "tier",
    "operation",
    "evaluation_mode",
    "binding_mode",
    "theorem",
    "refinement_theorem",
    "premises",
    "assumptions",
    "expected_inventory",
    "inputs",
    "outputs",
    "environment_allowlist",
    "bounded_domain",
    "resource_budget",
}
EVIDENCE_REQUIRED = {
    "schema",
    "id",
    "adapter",
    "kind",
    "claims",
    "tier",
    "operation",
    "resource_budget",
}
OPERATION_ALLOWED = {
    "type",
    "package",
    "targets",
    "paths",
    "manifest",
    "inventory",
    "checker",
    "arguments",
}
RESOURCE_KEYS = {"time_seconds", "disk_bytes", "memory_bytes"}

LIST_FIELDS = {
    "evidence",
    "assumptions",
    "premises",
    "open_obligations",
    "out_of_scope",
    "source_roots",
    "affected_claims",
    "review_evidence",
    "claims",
    "expected_inventory",
    "inputs",
    "outputs",
    "environment_allowlist",
    "targets",
    "paths",
    "arguments",
    "foundational_axioms",
}


@dataclass
class ManifestError(Exception):
    code: str
    path: Path
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.detail}"


def _fail(code: str, path: Path, detail: str) -> Never:
    raise ManifestError(code, path, detail)


def _keys(
    document: dict[str, Any], allowed: set[str], required: set[str], path: Path
) -> None:
    unknown = set(document) - allowed
    missing = required - set(document)
    if unknown:
        _fail("PBAC_M_UNKNOWN_FIELD", path, ", ".join(sorted(unknown)))
    if missing:
        _fail("PBAC_M_MISSING_FIELD", path, ", ".join(sorted(missing)))


def _string(document: dict[str, Any], name: str, path: Path) -> None:
    if name in document and (not isinstance(document[name], str) or not document[name]):
        _fail("PBAC_M_BAD_TYPE", path, f"{name} must be a nonempty string")


def _string_list(document: dict[str, Any], name: str, path: Path) -> None:
    if name not in document:
        return
    value = document[name]
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        _fail("PBAC_M_BAD_TYPE", path, f"{name} must be a string list")
    if len(value) != len(set(value)):
        _fail("PBAC_M_DUPLICATE", path, name)


def _relative(value: str, path: Path) -> None:
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or not parsed.parts:
        _fail("PBAC_M_PATH_ESCAPE", path, value)


def _validate_claim(document: dict[str, Any], path: Path) -> None:
    _keys(document, CLAIM_ALLOWED, CLAIM_REQUIRED, path)
    for name in CLAIM_ALLOWED - LIST_FIELDS - {"tier", "bounded_domain"}:
        _string(document, name, path)
    for name in LIST_FIELDS & CLAIM_ALLOWED:
        _string_list(document, name, path)
    if document["schema"] != "proofbound-claim/1":
        _fail("PBAC_M_BAD_SCHEMA", path, str(document["schema"]))
    if not CLAIM_ID.fullmatch(document["id"]):
        _fail("PBAC_M_BAD_ID", path, document["id"])
    if document.get("tier") not in {None, 0, 1, 2, 3}:
        _fail("PBAC_M_BAD_ENUM", path, "tier")
    if document.get("primary_linkage") not in {
        None,
        "refined",
        "artifact-bound",
        "transcribed",
        "model-only",
    }:
        _fail("PBAC_M_BAD_ENUM", path, "primary_linkage")
    for reference in document["evidence"]:
        if not EVIDENCE_REF.fullmatch(reference):
            _fail("PBAC_M_BAD_REFERENCE", path, reference)
    for claim_id in [*document["assumptions"], *document.get("premises", [])]:
        if not CLAIM_ID.fullmatch(claim_id):
            _fail("PBAC_M_BAD_ID", path, claim_id)
    identity = (
        document.get("formal_declaration"),
        document.get("statement_encoding"),
        document.get("statement_sha256"),
    )
    if any(value is not None for value in identity):
        if any(value is None for value in identity):
            _fail("PBAC_M_PARTIAL_FORMAL_ID", path, document["id"])
        if identity[1] != "lean-expr-cbor/1" or not DIGEST.fullmatch(identity[2]):
            _fail("PBAC_M_BAD_DIGEST", path, "statement identity")
    if "subject_closure" in document and not DIGEST.fullmatch(
        document["subject_closure"]
    ):
        _fail("PBAC_M_BAD_DIGEST", path, "subject_closure")
    for source_root in document.get("source_roots", []):
        _relative(source_root, path)


def _validate_assumption(document: dict[str, Any], path: Path) -> None:
    _keys(document, ASSUMPTION_ALLOWED, ASSUMPTION_REQUIRED, path)
    for name in ASSUMPTION_ALLOWED - LIST_FIELDS:
        _string(document, name, path)
    for name in LIST_FIELDS & ASSUMPTION_ALLOWED:
        _string_list(document, name, path)
    if document["schema"] != "proofbound-assumption/1":
        _fail("PBAC_M_BAD_SCHEMA", path, str(document["schema"]))
    if not CLAIM_ID.fullmatch(document["id"]):
        _fail("PBAC_M_BAD_ID", path, document["id"])
    if document["category"] not in {
        "mathematical-hypothesis",
        "representation-premise",
        "translator-tcb",
        "compiler-tcb",
        "runtime-environment",
        "external-provider",
        "cryptographic-library",
        "human-attestation",
        "native-evaluation",
    } or document["status"] not in {"active", "discharged", "retired"}:
        _fail("PBAC_M_BAD_ENUM", path, "category/status")
    if not document["affected_claims"]:
        _fail("PBAC_M_BAD_TYPE", path, "affected_claims must not be empty")
    if not document["review_evidence"]:
        _fail("PBAC_M_BAD_TYPE", path, "review_evidence must not be empty")
    for claim_id in document["affected_claims"]:
        if not CLAIM_ID.fullmatch(claim_id):
            _fail("PBAC_M_BAD_ID", path, claim_id)


def _validate_evidence(document: dict[str, Any], path: Path) -> None:
    _keys(document, EVIDENCE_ALLOWED, EVIDENCE_REQUIRED, path)
    for name in (
        EVIDENCE_ALLOWED
        - LIST_FIELDS
        - {"tier", "operation", "resource_budget", "bounded_domain"}
    ):
        _string(document, name, path)
    for name in LIST_FIELDS & EVIDENCE_ALLOWED:
        _string_list(document, name, path)
    if document["schema"] != "proofbound-evidence-unit/1":
        _fail("PBAC_M_BAD_SCHEMA", path, str(document["schema"]))
    if not LOCAL_ID.fullmatch(document["id"]):
        _fail("PBAC_M_BAD_ID", path, document["id"])
    if document["tier"] not in {0, 1, 2, 3} or isinstance(document["tier"], bool):
        _fail("PBAC_M_BAD_ENUM", path, "tier")
    if not document["claims"]:
        _fail("PBAC_M_BAD_TYPE", path, "claims must not be empty")
    for claim_id in document["claims"]:
        if not CLAIM_ID.fullmatch(claim_id):
            _fail("PBAC_M_BAD_ID", path, claim_id)

    operation = document["operation"]
    if not isinstance(operation, dict):
        _fail("PBAC_M_BAD_TYPE", path, "operation must be a table")
    _keys(operation, OPERATION_ALLOWED, {"type"}, path)
    for name in OPERATION_ALLOWED - LIST_FIELDS:
        _string(operation, name, path)
    for name in LIST_FIELDS & OPERATION_ALLOWED:
        _string_list(operation, name, path)
    resource = document["resource_budget"]
    if not isinstance(resource, dict):
        _fail("PBAC_M_BAD_TYPE", path, "resource_budget must be a table")
    _keys(resource, RESOURCE_KEYS, RESOURCE_KEYS, path)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1
        for value in resource.values()
    ):
        _fail(
            "PBAC_M_BAD_TYPE", path, "resource budget values must be positive integers"
        )

    valid_operations = {
        ("lean", "lean-audit"),
        ("canonical-artifact", "artifact-check"),
        ("independent-check", "independent-check"),
        ("python-test", "generator"),
    }
    if (document["adapter"], operation["type"]) not in valid_operations:
        _fail("PBAC_M_BAD_ENUM", path, "adapter/operation")
    if document["kind"] in {"theorem", "artifact-soundness"}:
        if document.get("evaluation_mode") not in {"kernel", "native"}:
            _fail("PBAC_M_BAD_ENUM", path, "evaluation_mode")
        if not document.get("theorem"):
            _fail("PBAC_M_MISSING_FIELD", path, "theorem")
    if document["kind"] == "artifact-soundness":
        if document.get("binding_mode") not in {"bytes-in-theorem", "digest-theorem"}:
            _fail("PBAC_M_BAD_ENUM", path, "binding_mode")
    elif document["kind"] == "theorem":
        if "binding_mode" in document:
            _fail("PBAC_M_BAD_ENUM", path, "binding_mode")
    elif document["kind"] in {"independent-check", "example-test"}:
        if "binding_mode" in document:
            _fail("PBAC_M_BAD_ENUM", path, "binding_mode")
    else:
        _fail("PBAC_M_BAD_ENUM", path, "kind")
    for value in [
        *document.get("inputs", []),
        *document.get("outputs", []),
        *operation.get("paths", []),
    ]:
        _relative(value, path)
    for name in ("manifest", "inventory", "checker"):
        if name in operation:
            _relative(operation[name], path)
    if operation["type"] == "generator":
        if not operation.get("checker"):
            _fail("PBAC_M_MISSING_FIELD", path, "operation.checker")
        outputs = document.get("outputs", [])
        if not outputs or outputs != document.get("expected_inventory"):
            _fail(
                "PBAC_M_GENERATOR_BOUNDARY",
                path,
                "outputs must exactly equal expected_inventory",
            )
        if operation.get("arguments"):
            _fail("PBAC_M_GENERATOR_BOUNDARY", path, "arguments must be empty")


def validate_document(kind: str, document: dict[str, Any], path: Path) -> None:
    if kind == "claim":
        _validate_claim(document, path)
    elif kind == "assumption":
        _validate_assumption(document, path)
    elif kind == "evidence":
        _validate_evidence(document, path)
    else:
        raise ValueError(f"unsupported manifest kind: {kind}")


def _load(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            document = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        _fail("PBAC_M_PARSE", path, str(error))
    if not isinstance(document, dict):
        _fail("PBAC_M_BAD_TYPE", path, "document must be a table")
    return document


def _validate_fixture_manifest(root: Path) -> str:
    path = root / "fixtures/manifest.json"
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        _fail("PBAC_M_PARSE", path, str(error))
    if (
        set(manifest) != {"schema", "fixtures"}
        or manifest["schema"] != "pbac-fixture-manifest/1"
    ):
        _fail("PBAC_M_BAD_SCHEMA", path, str(manifest.get("schema")))
    basic_digest = ""
    for record in manifest["fixtures"]:
        fixture = root / "fixtures" / record["file"]
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        if digest != record["sha256"]:
            _fail("PBAC_M_DIGEST_MISMATCH", fixture, record["file"])
        if record["file"] == "valid-basic.pbac":
            basic_digest = digest
    if not basic_digest:
        _fail("PBAC_M_MISSING_ARTIFACT", path, "valid-basic.pbac")
    return basic_digest


def validate_tree(root: Path) -> None:
    collections: dict[str, dict[str, dict[str, Any]]] = {}
    for kind, directory in (
        ("claim", "claims"),
        ("assumption", "assumptions"),
        ("evidence", "evidence"),
    ):
        records: dict[str, dict[str, Any]] = {}
        paths = sorted((root / directory).glob("*.toml"))
        if not paths:
            _fail("PBAC_M_EMPTY_COLLECTION", root / directory, kind)
        for path in paths:
            document = _load(path)
            validate_document(kind, document, path)
            record_id = document["id"]
            if record_id in records:
                _fail("PBAC_M_DUPLICATE_ID", path, record_id)
            records[record_id] = document
        collections[kind] = records

    claims = collections["claim"]
    assumptions = collections["assumption"]
    evidence = collections["evidence"]
    prefix = {
        "theorem": "theorem",
        "artifact-soundness": "artifact",
        "independent-check": "independent",
        "example-test": "test",
    }
    by_reference = {
        f"{prefix[unit['kind']]}:{unit_id}": unit for unit_id, unit in evidence.items()
    }
    for claim_id, claim in claims.items():
        for reference in claim["evidence"]:
            unit = by_reference.get(reference)
            if unit is None or claim_id not in unit["claims"]:
                _fail("PBAC_M_BAD_REFERENCE", root, f"{claim_id} -> {reference}")
        for assumption_id in claim["assumptions"]:
            assumption = assumptions.get(assumption_id)
            if assumption is None or claim_id not in assumption["affected_claims"]:
                _fail("PBAC_M_BAD_REFERENCE", root, f"{claim_id} -> {assumption_id}")

    for unit_id, unit in evidence.items():
        for claim_id in unit["claims"]:
            claim = claims.get(claim_id)
            reference = f"{prefix[unit['kind']]}:{unit_id}"
            if claim is None or reference not in claim["evidence"]:
                _fail("PBAC_M_BAD_REFERENCE", root, f"{unit_id} -> {claim_id}")
            if unit["kind"] in {"theorem", "artifact-soundness"} and set(
                unit.get("assumptions", [])
            ) != set(claim["assumptions"]):
                _fail("PBAC_M_ASSUMPTION_DRIFT", root, unit_id)
        if unit["kind"] == "artifact-soundness":
            exact_theorems = [
                (candidate_id, candidate)
                for candidate_id, candidate in evidence.items()
                if candidate["kind"] == "theorem"
                and candidate.get("theorem") == unit.get("theorem")
                and set(unit["claims"]).issubset(candidate["claims"])
            ]
            if len(exact_theorems) != 1:
                _fail(
                    "PBAC_M_BAD_REFERENCE",
                    root,
                    f"{unit_id} exact theorem evidence count={len(exact_theorems)}",
                )
            theorem_id, _ = exact_theorems[0]
            for claim_id in unit["claims"]:
                if f"theorem:{theorem_id}" not in claims[claim_id]["evidence"]:
                    _fail(
                        "PBAC_M_BAD_REFERENCE",
                        root,
                        f"{unit_id} -> theorem:{theorem_id}",
                    )

    digest = _validate_fixture_manifest(root)
    identity = f"#sha256:{digest}"
    for claim_id, claim in claims.items():
        if identity not in claim["subject"] or digest not in claim.get(
            "public_language", ""
        ):
            _fail("PBAC_M_DIGEST_MISMATCH", root, claim_id)
