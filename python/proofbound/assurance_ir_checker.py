"""Independent checker for the Experiment 0005 projection prototype.

The module intentionally does not import Rust-generated bindings or production
Proofbound model types. It reconstructs the registered projection directly
from frozen source files and compares that result with canonical producer
output.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import tomllib
from typing import Any


CORPUS_SCHEMA = "proofbound-research-projection-corpus/1"
PROJECTION_SCHEMA = "proofbound-assurance-ir-projection/1"
PROJECTION_DOMAIN = "proofbound-assurance-ir-projection/1"


class AssuranceIrError(ValueError):
    """Raised when a corpus or projection violates the research contract."""


@dataclass(frozen=True)
class CheckReport:
    """Summary returned after independent projection validation.

    Attributes:
        case_count: Number of positive cases checked.
        projection_sha256: Independently recomputed projection identity.
    """

    case_count: int
    projection_sha256: str


def canonical_json(value: object) -> bytes:
    """Encode the bounded research JSON form canonically.

    Args:
        value: JSON-compatible value containing no floating-point numbers.

    Returns:
        Compact UTF-8 JSON with lexically sorted object keys.

    Raises:
        AssuranceIrError: If a floating-point number is present.
    """

    _reject_floats(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def domain_hash(domain: str, data: bytes) -> str:
    """Compute SHA-256 with the registered UTF-8 domain and NUL boundary."""

    return f"sha256:{hashlib.sha256(domain.encode() + bytes([0]) + data).hexdigest()}"


def check_projection(
    root: Path, corpus_path: Path, projection_bytes: bytes
) -> CheckReport:
    """Reconstruct and verify one producer projection.

    Args:
        root: Repository root containing every frozen source path.
        corpus_path: Positive corpus registry.
        projection_bytes: Canonical output from the producer prototype.

    Returns:
        Case count and independently recomputed projection identity.

    Raises:
        AssuranceIrError: If bytes, structure, identities, or semantics differ.
    """

    corpus_bytes = corpus_path.read_bytes()
    corpus = _strict_json(corpus_bytes, require_canonical=False)
    projection = _strict_json(projection_bytes, require_canonical=True)
    _require_keys(
        corpus,
        {
            "schema",
            "experiment",
            "baseline",
            "revision",
            "status",
            "source_identity",
            "projection_profiles",
            "supporting_sources",
            "cases",
        },
        "corpus",
    )
    _require_keys(
        projection,
        {
            "schema",
            "experiment",
            "baseline",
            "corpus_sha256",
            "cases",
            "projection_sha256",
        },
        "projection",
    )
    if corpus["schema"] != CORPUS_SCHEMA or projection["schema"] != PROJECTION_SCHEMA:
        raise AssuranceIrError("unsupported corpus or projection schema")
    if corpus["experiment"] != "EXP-0005" or projection["experiment"] != "EXP-0005":
        raise AssuranceIrError("unexpected experiment")
    if corpus["baseline"] != projection["baseline"]:
        raise AssuranceIrError("baseline mismatch")
    if corpus["status"] != "frozen-positive-unexecuted":
        raise AssuranceIrError("corpus is not frozen")

    corpus_sha256 = _sha256(corpus_bytes)
    if projection["corpus_sha256"] != corpus_sha256:
        raise AssuranceIrError("corpus identity mismatch")

    for source in corpus["supporting_sources"]:
        _verify_source(root, source["path"], source["sha256"])

    expected_cases = sorted(
        (
            _project_case(root, case, corpus["projection_profiles"])
            for case in corpus["cases"]
        ),
        key=lambda item: item["id"],
    )
    if projection["cases"] != expected_cases:
        raise AssuranceIrError(
            "producer projection differs from independent reconstruction"
        )

    material = {
        "baseline": projection["baseline"],
        "cases": projection["cases"],
        "corpus_sha256": projection["corpus_sha256"],
        "experiment": projection["experiment"],
        "schema": projection["schema"],
    }
    identity = domain_hash(PROJECTION_DOMAIN, canonical_json(material))
    if projection["projection_sha256"] != identity:
        raise AssuranceIrError("projection identity mismatch")
    return CheckReport(len(expected_cases), identity)


def check_canonical_vectors(path: Path) -> int:
    """Validate every preregistered canonical byte and domain-hash vector."""

    document = _strict_json(path.read_bytes(), require_canonical=False)
    count = 0
    for vector in document["vectors"]:
        encoded = canonical_json(vector["value"])
        if encoded.decode() != vector["canonical_utf8"]:
            raise AssuranceIrError(f"canonical bytes differ for {vector['id']}")
        for domain, expected in vector["hashes"].items():
            if domain_hash(domain, encoded) != expected:
                raise AssuranceIrError(
                    f"domain hash differs for {vector['id']} and {domain}"
                )
            count += 1
    return count


def _project_case(
    root: Path, case: dict[str, Any], profiles: dict[str, Any]
) -> dict[str, Any]:
    source = case["source"]
    source_bytes = _verify_source(root, source["path"], source["sha256"])
    for profile in case["projection_profiles"]:
        if profile not in profiles:
            raise AssuranceIrError(f"unknown projection profile {profile}")

    registration: dict[str, Any] | None = None
    semantic_case_id: str | None = None
    if case["role"] == "positive-registration":
        registration = _project_registration(case, source_bytes)
    elif case["role"] == "positive-semantic-status":
        semantic_case_id = _project_semantic_case(case, source_bytes)
    elif case["role"] == "positive-portable-release":
        _verify_release_case(root, case, source_bytes)
    else:
        raise AssuranceIrError(f"unsupported case role {case['role']}")

    return {
        "id": case["id"],
        "role": case["role"],
        "source": {
            "path": source["path"],
            "sha256": source["sha256"],
            "json_pointer": source.get("json_pointer"),
            "envelope_path": source.get("envelope_path"),
            "envelope_sha256": source.get("envelope_sha256"),
        },
        "evidence_family": case["evidence_family"],
        "unit_id": case.get("unit_id"),
        "claim_ids": case["claim_ids"],
        "expected_claim": case["expected_claim"],
        "registration": registration,
        "semantic_case_id": semantic_case_id,
        "projection_profiles": case["projection_profiles"],
    }


def _project_registration(case: dict[str, Any], data: bytes) -> dict[str, Any]:
    registration = tomllib.loads(data.decode("utf-8"))
    unit_id = _required_text(registration, "id")
    declared_kind = _required_text(registration, "kind")
    claims = _text_list(registration, "claims")
    if unit_id != case.get("unit_id") or claims != case["claim_ids"]:
        raise AssuranceIrError(f"registration attribution mismatch for {case['id']}")
    operation = registration.get("operation")
    if not isinstance(operation, dict):
        raise AssuranceIrError("registration operation must be a table")

    projected_family = (
        "distribution-reproduction" if "distribution" in registration else declared_kind
    )
    if projected_family != case["evidence_family"]:
        raise AssuranceIrError(f"registration family mismatch for {case['id']}")
    family_configuration = {
        "bounded_domain": registration.get("bounded_domain"),
        "distribution": registration.get("distribution"),
        "mutation": registration.get("mutation"),
        "operation": registration.get("operation"),
        "property": registration.get("property"),
        "transcription": registration.get("transcription"),
    }
    return {
        "schema": _required_text(registration, "schema"),
        "unit_id": unit_id,
        "declared_kind": declared_kind,
        "adapter": _required_text(registration, "adapter"),
        "operation": _required_text(operation, "type"),
        "claims": claims,
        "assumptions": _optional_text_list(registration, "assumptions"),
        "inventory": _optional_text_list(registration, "expected_inventory"),
        "inputs": _optional_text_list(registration, "inputs"),
        "outputs": _optional_text_list(registration, "outputs"),
        "family_configuration_sha256": domain_hash(
            PROJECTION_DOMAIN, canonical_json(family_configuration)
        ),
    }


def _project_semantic_case(case: dict[str, Any], data: bytes) -> str:
    pointer = case["source"].get("json_pointer")
    if not isinstance(pointer, str):
        raise AssuranceIrError("semantic case has no JSON pointer")
    selected: Any = _strict_json(data, require_canonical=False)
    for part in pointer.removeprefix("/").split("/"):
        selected = selected[int(part)] if isinstance(selected, list) else selected[part]
    expected = {
        key: selected["expected"][key]
        for key in ("formal", "linkage", "assumption", "policy_admitted")
    }
    if expected != case["expected_claim"]:
        raise AssuranceIrError("semantic expected status mismatch")
    return _required_text(selected, "id")


def _verify_release_case(root: Path, case: dict[str, Any], data: bytes) -> None:
    receipt = _strict_json(data, require_canonical=False)
    by_claim = {status["claim_id"]: status for status in receipt["reported_statuses"]}
    for claim_id in case["claim_ids"]:
        status = by_claim.get(claim_id)
        if status is None:
            raise AssuranceIrError(f"release status missing for {claim_id}")
        projected = {
            key: status[key]
            for key in ("formal", "linkage", "assumption", "policy_admitted")
        }
        if projected != case["expected_claim"]:
            raise AssuranceIrError("release status mismatch")
    source = case["source"]
    _verify_source(root, source["envelope_path"], source["envelope_sha256"])


def _strict_json(data: bytes, *, require_canonical: bool) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AssuranceIrError(f"duplicate object key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssuranceIrError(f"invalid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise AssuranceIrError("document root must be an object")
    if require_canonical and canonical_json(value) != data:
        raise AssuranceIrError("projection is not canonical JSON")
    return value


def _verify_source(root: Path, relative: str, expected: str) -> bytes:
    data = (root / relative).read_bytes()
    if _sha256(data) != expected:
        raise AssuranceIrError(f"source identity mismatch for {relative}")
    return data


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _required_text(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        raise AssuranceIrError(f"{field} must be non-empty text")
    return item


def _text_list(value: dict[str, Any], field: str) -> list[str]:
    items = value.get(field)
    if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        raise AssuranceIrError(f"{field} must be a text list")
    return items


def _optional_text_list(value: dict[str, Any], field: str) -> list[str]:
    return _text_list(value, field) if field in value else []


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise AssuranceIrError(f"{label} has missing or unknown fields")


def _reject_floats(value: object) -> None:
    if isinstance(value, float):
        raise AssuranceIrError("floating-point values are forbidden")
    if isinstance(value, dict):
        for child in value.values():
            _reject_floats(child)
    elif isinstance(value, list):
        for child in value:
            _reject_floats(child)
