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
CASE_SCHEMA = "proofbound-assurance-ir-case/1"
CACHE_DOMAIN = "proofbound-assurance-ir-cache/1"


class AssuranceIrError(ValueError):
    """Raised when a corpus or projection violates the research contract."""

    def __init__(self, message: str, *, code: str = "IR-DECODE-INVALID") -> None:
        super().__init__(message)
        self.code = code


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
    if corpus["revision"] != 2 or corpus["status"] != "frozen-positive-expanded-for-q1":
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


def validate_case_program(data: bytes) -> None:
    """Validate one canonical research case without trusting reported status.

    Args:
        data: Canonical UTF-8 JSON for one projected case.

    Raises:
        AssuranceIrError: With a stable ``code`` for the first failed invariant.
    """

    root = _strict_json(data, require_canonical=True)
    if root.get("schema") != CASE_SCHEMA:
        _fail("IR-DECODE-SCHEMA", "unsupported case schema")
    source = _object(root, "source")
    source_sha256 = _required_text(source, "sha256")
    claims = _list(root, "claims")
    evidence = _list(root, "evidence")
    programme = _object(root, "programme")
    claim_ids = [_required_text(_as_object(claim), "id") for claim in claims]
    _require_sorted_unique(claim_ids)
    claim_assumptions: list[list[str]] = []
    obligations = False
    for claim_value in claims:
        claim = _as_object(claim_value)
        _required_text(claim, "subject")
        assumptions = _text_list(claim, "assumptions")
        _require_sorted_unique(assumptions)
        for field in (
            "cited_evidence",
            "premises",
            "open_obligations",
            "out_of_scope",
            "registered_inputs",
        ):
            _require_sorted_unique(_text_list(claim, field))
        if claim.get("source") is not None:
            source = _object(claim, "source")
            _required_text(source, "logical_name")
            _required_text(source, "sha256")
            if not isinstance(source.get("size_bytes"), int):
                _fail("IR-DECODE-INVALID", "claim source size is required")
            _required_text(_object(claim, "meaning"), "schema")
            _required_text(_object(claim, "meaning"), "statement")
            _required_text(_object(claim, "presentation"), "title")
            _required_text(_object(claim, "admission"), "policy")
        obligations = obligations or bool(_list(claim, "open_obligations"))
        claim_assumptions.append(assumptions)

    kinds: list[str] = []
    portable_receipt = False
    for evidence_value in evidence:
        item = _as_object(evidence_value)
        if "authority" not in item:
            _fail("IR-DECODE-REQUIRED-AUTHORITY", "evidence authority is required")
        item_claims = _text_list(item, "claims")
        _require_sorted_unique(item_claims)
        if item_claims != claim_ids:
            _fail(
                "IR-EVIDENCE-CLAIM-ATTRIBUTION",
                "evidence claim attribution differs from the case",
            )
        assumptions = _text_list(item, "assumptions")
        _require_sorted_unique(assumptions)
        _require_sorted_unique(_text_list(item, "inventory"))
        authority = _required_text(item, "authority")
        if authority == "registered":
            _object(item, "request")
        if authority == "portable-receipt":
            portable_receipt = True
            _required_text(item, "content_sha256")
        if any(
            any(assumption not in registered for assumption in assumptions)
            for registered in claim_assumptions
        ):
            _fail(
                "IR-ASSUMPTION-JOIN",
                "claim and evidence assumptions differ",
            )

        family = _object(item, "family")
        kind = _required_text(family, "kind")
        detail = _object(family, "detail")
        try:
            expected_schema = _family_schema(kind)
        except AssuranceIrError:
            expected_schema = None
        if detail.get("schema") != expected_schema:
            _fail(
                "IR-EVIDENCE-FAMILY-DETAIL",
                "family discriminant and detail schema differ",
            )
        kinds.append(kind)

        declared_fact_schemas = detail.get("required_fact_schemas", [])
        if not isinstance(declared_fact_schemas, list) or any(
            not isinstance(schema, str) for schema in declared_fact_schemas
        ):
            _fail("IR-DECODE-INVALID", "required_fact_schemas must be an array")

        backend = _object(item, "backend")
        for fact_value in _list(backend, "retained_facts"):
            fact = _as_object(fact_value)
            if (
                fact.get("required") is True
                and fact.get("schema") not in declared_fact_schemas
            ):
                _fail(
                    "IR-BACKEND-UNKNOWN-REQUIRED",
                    "unknown required retained fact",
                )

        if kind == "mutation-witness":
            subject = _required_text(detail, "subject")
            expected_subject = _required_text(_as_object(claims[0]), "subject")
            if subject != expected_subject:
                _fail(
                    "IR-EVIDENCE-SUBJECT-MISMATCH",
                    "mutation subject differs from the claim subject",
                )
        if kind == "artifact-correspondence":
            artifact = _object(detail, "artifact")
            if _required_text(artifact, "sha256") != source_sha256:
                _fail(
                    "IR-ARTIFACT-IDENTITY-MISMATCH",
                    "artifact identity differs from the registered source",
                )

        provenance = _object(item, "provenance")
        for index, run_value in enumerate(_list(provenance, "runs")):
            run = _as_object(run_value)
            if run.get("command_index") != index:
                _fail(
                    "IR-PROVENANCE-RUN-ORDER",
                    "run index differs from its registered position",
                )
        usage = _object(provenance, "usage")
        if "peak_memory" not in usage:
            _fail(
                "IR-DECODE-REQUIRED-UNKNOWN",
                "required nullable peak_memory is missing",
            )
        provenance_cache = _object(provenance, "cache")
        prior = provenance_cache.get("prior_receipt")
        unit = _required_text(item, "unit")
        if provenance_cache.get("key") != _cache_key(unit, prior):
            _fail(
                "IR-CACHE-REUSE-MISMATCH",
                "cache key does not bind the prior receipt",
            )

    _validate_programme(programme, portable_receipt)
    if portable_receipt:
        _validate_portable_joins(programme, evidence)

    cache = _object(root, "cache")
    registered = _cache_inputs(cache, "registered_inputs")
    execution = _cache_inputs(cache, "execution_inputs")
    if registered != execution:
        _fail(
            "IR-CACHE-DEPENDENCY-OMITTED",
            "execution cache inputs differ from registration",
        )
    exact = root.get("exact_status")
    if not isinstance(exact, bool):
        _fail("IR-DECODE-INVALID", "missing exact_status")
    assumed = any(bool(items) for items in claim_assumptions)
    _validate_reported(_object(root, "reported"), kinds, assumed or obligations, exact)


def _validate_programme(programme: dict[str, Any], portable_receipt: bool) -> None:
    if portable_receipt:
        project = _object(programme, "project")
        for field in ("id", "revision", "tree_state"):
            _required_text(project, field)
        if not isinstance(project.get("tier"), int):
            _fail("IR-DECODE-INVALID", "portable project tier is required")
        _object(programme, "graph")
        if not _list(programme, "policies"):
            _fail(
                "IR-PROGRAMME-POLICY-OMITTED",
                "portable programme must retain its policies",
            )
    for closure_value in _list(programme, "closures"):
        closure = _as_object(closure_value)
        _required_text(closure, "sha256")
        _required_text(closure, "kind")
        for member in _list(closure, "members"):
            _validate_artifact(_as_object(member))
    for artifact in _list(programme, "sealed_artifacts"):
        _validate_artifact(_as_object(artifact))
    for field in ("assumptions", "premises", "publication_blockers"):
        _list(programme, field)


def _validate_portable_joins(programme: dict[str, Any], evidence: list[object]) -> None:
    project = _object(programme, "project")
    revision = _required_text(project, "revision")
    tree_state = _required_text(project, "tree_state")
    closure_ids = {
        _required_text(_as_object(closure), "sha256")
        for closure in _list(programme, "closures")
    }
    for item_value in evidence:
        item = _as_object(item_value)
        if _required_text(item, "authority") != "portable-receipt":
            continue
        provenance = _object(item, "provenance")
        if (
            provenance.get("revision") != revision
            or provenance.get("tree_state") != tree_state
        ):
            _fail(
                "IR-PROGRAMME-PROVENANCE-MISMATCH",
                "portable provenance differs from project identity",
            )
        if provenance.get("semantic_closure") not in closure_ids:
            _fail(
                "IR-PROGRAMME-CLOSURE-MISSING",
                "portable evidence names an unregistered semantic closure",
            )


def _validate_artifact(artifact: dict[str, Any]) -> None:
    _required_text(artifact, "logical_name")
    _required_text(artifact, "sha256")
    if not isinstance(artifact.get("size_bytes"), int):
        _fail("IR-DECODE-INVALID", "artifact size is required")


def _validate_reported(
    reported: dict[str, Any], kinds: list[str], assumed: bool, exact: bool
) -> None:
    if "universal-source-proof" in kinds:
        formal = "PROVED"
    elif "bounded-model-check" in kinds:
        formal = "BOUNDED_CHECKED"
    elif kinds and all(kind == "trusted-transcription" for kind in kinds):
        formal = "OPEN"
    else:
        formal = "TESTED"
    if "artifact-correspondence" in kinds:
        linkage = "ARTIFACT_BOUND"
    elif "source-correspondence" in kinds:
        linkage = "REFINED"
    elif "trusted-transcription" in kinds:
        linkage = "TRANSCRIBED"
    else:
        linkage = "MODEL_ONLY"

    reported_formal = _required_text(reported, "formal")
    if exact:
        formal_matches = reported_formal == formal
    else:
        allowed = {
            "PROVED": {"PROVED"},
            "BOUNDED_CHECKED": {
                "BOUNDED_CHECKED",
                "BOUNDED_CHECKED_OR_STRONGER_PER_CLAIM",
            },
            "OPEN": {"OPEN"},
            "TESTED": {"TESTED", "TESTED_OR_STRONGER_PER_CLAIM"},
        }
        formal_matches = reported_formal in allowed[formal]
    assumption_matches = not exact or reported.get("assumption") == (
        "ASSUMED" if assumed else "NONE"
    )
    if (
        not formal_matches
        or reported.get("linkage") != linkage
        or not assumption_matches
    ):
        _fail(
            "IR-STATUS-MISMATCH",
            "reported status differs from independent derivation",
        )


def _cache_inputs(value: dict[str, Any], field: str) -> list[dict[str, str]]:
    inputs = [
        {
            "selector": _required_text(_as_object(item), "selector"),
            "identity": _required_text(_as_object(item), "identity"),
        }
        for item in _list(value, field)
    ]
    if inputs != sorted(inputs, key=lambda item: (item["selector"], item["identity"])):
        _fail("IR-DECODE-DUPLICATE", "cache inputs must be canonical")
    if len({(item["selector"], item["identity"]) for item in inputs}) != len(inputs):
        _fail("IR-DECODE-DUPLICATE", "cache inputs must be unique")
    return inputs


def _require_sorted_unique(values: list[str]) -> None:
    if values != sorted(set(values)):
        _fail(
            "IR-DECODE-DUPLICATE",
            "set-like text arrays must be sorted and unique",
        )


def _fail(code: str, message: str) -> None:
    raise AssuranceIrError(message, code=code)


def _project_case(
    root: Path, case: dict[str, Any], profiles: dict[str, Any]
) -> dict[str, Any]:
    source = case["source"]
    source_bytes = _verify_source(root, source["path"], source["sha256"])
    registered_claims = _project_claim_sources(root, case)
    for profile in case["projection_profiles"]:
        if profile not in profiles:
            raise AssuranceIrError(f"unknown projection profile {profile}")

    registration: dict[str, Any] | None = None
    semantic_case_id: str | None = None
    if case["role"] == "positive-registration":
        registration = _project_registration(case, source_bytes)
        program = _registration_program(
            root, case, len(source_bytes), registration, registered_claims
        )
    elif case["role"] == "positive-semantic-status":
        semantic_case_id, selected = _project_semantic_case(case, source_bytes)
        program = _semantic_program(case, len(source_bytes), selected)
    elif case["role"] == "positive-portable-release":
        _verify_release_case(root, case, source_bytes)
        program = _release_program(case, len(source_bytes), source_bytes)
    else:
        raise AssuranceIrError(f"unsupported case role {case['role']}")

    projected = {
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
        "program": program,
    }
    return projected


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
    common_fields = {
        "schema",
        "id",
        "adapter",
        "kind",
        "claims",
        "tier",
        "assumptions",
        "premises",
        "open_obligation",
        "evaluation_mode",
        "binding_mode",
        "expected_inventory",
        "inputs",
        "outputs",
        "environment_allowlist",
        "resource_budget",
        "operation",
    }
    family_configuration = {
        field: value
        for field, value in registration.items()
        if field not in common_fields
    }
    projected = {
        "schema": _required_text(registration, "schema"),
        "unit_id": unit_id,
        "declared_kind": declared_kind,
        "adapter": _required_text(registration, "adapter"),
        "operation": _required_text(operation, "type"),
        "claims": claims,
        "assumptions": _optional_text_list(registration, "assumptions"),
        "premises": _optional_text_list(registration, "premises"),
        "open_obligation": registration.get("open_obligation"),
        "evaluation_mode": registration.get("evaluation_mode"),
        "binding_mode": registration.get("binding_mode"),
        "inventory": _optional_text_list(registration, "expected_inventory"),
        "inputs": _optional_text_list(registration, "inputs"),
        "outputs": _optional_text_list(registration, "outputs"),
        "tier": registration["tier"],
        "environment_allowlist": _optional_text_list(
            registration, "environment_allowlist"
        ),
        "resource_budget": registration["resource_budget"],
        "operation_configuration": registration["operation"],
        "family_configuration": family_configuration,
        "family_configuration_sha256": domain_hash(
            PROJECTION_DOMAIN, canonical_json(family_configuration)
        ),
    }
    if _registration_source_projection(registration) != _registration_ir_projection(
        projected
    ):
        raise AssuranceIrError(
            f"registration {unit_id} is not lossless under the registered semantic projection"
        )
    return projected


def _registration_source_projection(registration: dict[str, Any]) -> dict[str, Any]:
    common_fields = {
        "schema",
        "id",
        "adapter",
        "kind",
        "claims",
        "tier",
        "assumptions",
        "premises",
        "open_obligation",
        "evaluation_mode",
        "binding_mode",
        "expected_inventory",
        "inputs",
        "outputs",
        "environment_allowlist",
        "resource_budget",
        "operation",
    }
    return {
        "schema": registration["schema"],
        "unit": registration["id"],
        "adapter": registration["adapter"],
        "kind": registration["kind"],
        "claims": registration.get("claims", []),
        "tier": registration.get("tier"),
        "assumptions": registration.get("assumptions", []),
        "premises": registration.get("premises", []),
        "open_obligation": registration.get("open_obligation"),
        "evaluation_mode": registration.get("evaluation_mode"),
        "binding_mode": registration.get("binding_mode"),
        "inventory": registration.get("expected_inventory", []),
        "inputs": registration.get("inputs", []),
        "outputs": registration.get("outputs", []),
        "environment_allowlist": registration.get("environment_allowlist", []),
        "resource_budget": registration.get("resource_budget"),
        "operation": registration.get("operation"),
        "family_configuration": {
            field: value
            for field, value in registration.items()
            if field not in common_fields
        },
    }


def _registration_ir_projection(registration: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": registration["schema"],
        "unit": registration["unit_id"],
        "adapter": registration["adapter"],
        "kind": registration["declared_kind"],
        "claims": registration["claims"],
        "tier": registration["tier"],
        "assumptions": registration["assumptions"],
        "premises": registration["premises"],
        "open_obligation": registration["open_obligation"],
        "evaluation_mode": registration["evaluation_mode"],
        "binding_mode": registration["binding_mode"],
        "inventory": registration["inventory"],
        "inputs": registration["inputs"],
        "outputs": registration["outputs"],
        "environment_allowlist": registration["environment_allowlist"],
        "resource_budget": registration["resource_budget"],
        "operation": registration["operation_configuration"],
        "family_configuration": registration["family_configuration"],
    }


def _project_semantic_case(
    case: dict[str, Any], data: bytes
) -> tuple[str, dict[str, Any]]:
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
    return _required_text(selected, "id"), selected


def _project_claim_sources(root: Path, case: dict[str, Any]) -> list[dict[str, Any]]:
    claims = []
    for source in case.get("claim_sources", []):
        data = _verify_source(root, source["path"], source["sha256"])
        claim = tomllib.loads(data.decode())
        projected = {
            "id": _required_text(claim, "id"),
            "subject": _required_text(claim, "subject"),
            "source": {
                "logical_name": source["path"],
                "sha256": source["sha256"],
                "size_bytes": len(data),
            },
            "node": None,
            "meaning": {
                "schema": _required_text(claim, "schema"),
                "statement": _required_text(claim, "statement"),
                "formal_declaration": claim.get("formal_declaration"),
                "statement_encoding": claim.get("statement_encoding"),
                "statement_sha256": claim.get("statement_sha256"),
                "foundational_axioms": sorted(
                    _optional_text_list(claim, "foundational_axioms")
                ),
                "bounded_domain": claim.get("bounded_domain"),
                "registered_domain_language": claim.get("registered_domain_language"),
            },
            "presentation": {
                "title": _required_text(claim, "title"),
                "public_language": claim.get("public_language"),
                "public_statement": None,
            },
            "cited_evidence": sorted(_optional_text_list(claim, "evidence")),
            "assumptions": sorted(_optional_text_list(claim, "assumptions")),
            "premises": sorted(_optional_text_list(claim, "premises")),
            "open_obligations": sorted(_optional_text_list(claim, "open_obligations")),
            "out_of_scope": sorted(_optional_text_list(claim, "out_of_scope")),
            "registered_inputs": sorted(_optional_text_list(claim, "source_roots")),
            "admission": {
                "policy": _required_text(claim, "profile"),
                "tier": claim.get("tier"),
                "primary_linkage": claim.get("primary_linkage"),
            },
        }
        if _claim_source_projection(claim) != _claim_ir_projection(projected):
            raise AssuranceIrError(
                f"claim {projected['id']} is not lossless under the registered semantic projection"
            )
        claims.append(projected)
    claims.sort(key=lambda claim: claim["id"])
    expected_ids = sorted(case["claim_ids"])
    if claims and [claim["id"] for claim in claims] != expected_ids:
        raise AssuranceIrError(f"claim source attribution differs for {case['id']}")
    return claims


def _claim_source_projection(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": _required_text(claim, "schema"),
        "id": _required_text(claim, "id"),
        "title": _required_text(claim, "title"),
        "statement": _required_text(claim, "statement"),
        "public_language": claim.get("public_language"),
        "subject": _required_text(claim, "subject"),
        "formal_declaration": claim.get("formal_declaration"),
        "statement_encoding": claim.get("statement_encoding"),
        "statement_sha256": claim.get("statement_sha256"),
        "foundational_axioms": sorted(
            _optional_text_list(claim, "foundational_axioms")
        ),
        "policy": _required_text(claim, "profile"),
        "tier": claim.get("tier"),
        "primary_linkage": claim.get("primary_linkage"),
        "cited_evidence": sorted(_optional_text_list(claim, "evidence")),
        "assumptions": sorted(_optional_text_list(claim, "assumptions")),
        "premises": sorted(_optional_text_list(claim, "premises")),
        "open_obligations": sorted(_optional_text_list(claim, "open_obligations")),
        "out_of_scope": sorted(_optional_text_list(claim, "out_of_scope")),
        "registered_inputs": sorted(_optional_text_list(claim, "source_roots")),
        "bounded_domain": claim.get("bounded_domain"),
        "registered_domain_language": claim.get("registered_domain_language"),
    }


def _claim_ir_projection(claim: dict[str, Any]) -> dict[str, Any]:
    meaning = claim["meaning"]
    presentation = claim["presentation"]
    admission = claim["admission"]
    return {
        "schema": meaning["schema"],
        "id": claim["id"],
        "title": presentation["title"],
        "statement": meaning["statement"],
        "public_language": presentation["public_language"],
        "subject": claim["subject"],
        "formal_declaration": meaning["formal_declaration"],
        "statement_encoding": meaning["statement_encoding"],
        "statement_sha256": meaning["statement_sha256"],
        "foundational_axioms": meaning["foundational_axioms"],
        "policy": admission["policy"],
        "tier": admission["tier"],
        "primary_linkage": admission["primary_linkage"],
        "cited_evidence": claim["cited_evidence"],
        "assumptions": claim["assumptions"],
        "premises": claim["premises"],
        "open_obligations": claim["open_obligations"],
        "out_of_scope": claim["out_of_scope"],
        "registered_inputs": claim["registered_inputs"],
        "bounded_domain": meaning["bounded_domain"],
        "registered_domain_language": meaning["registered_domain_language"],
    }


def _registration_program(
    root: Path,
    case: dict[str, Any],
    source_size: int,
    registration: dict[str, Any],
    claims: list[dict[str, Any]],
) -> dict[str, Any]:
    claim_ids = sorted(registration["claims"])
    assumptions = sorted(registration["assumptions"])
    kind = _family_kind(case["evidence_family"])
    retained_facts = []
    if kind == "sampled-property":
        retained_facts.append(
            {
                "schema": "proofbound-python-property/1",
                "required": True,
                "value": {
                    "configuration_sha256": registration["family_configuration_sha256"]
                },
            }
        )
    cache = _registration_cache(root, case, registration)
    unit = registration["unit_id"]
    return {
        "schema": CASE_SCHEMA,
        "case_id": case["id"],
        "evidence_family": case["evidence_family"],
        "source": _source_artifact(case["source"], source_size),
        "claims": claims,
        "evidence": [
            {
                "authority": "registered",
                "unit": unit,
                "content_sha256": None,
                "node": None,
                "claims": claim_ids,
                "outcome": None,
                "evaluation": registration["evaluation_mode"],
                "binding": registration["binding_mode"],
                "inventory": registration["inventory"],
                "assumptions": assumptions,
                "premises": registration["premises"],
                "open_obligation": registration["open_obligation"],
                "request": {
                    "schema": registration["schema"],
                    "adapter": registration["adapter"],
                    "tier": registration["tier"],
                    "input_names": registration["inputs"],
                    "output_names": registration["outputs"],
                    "environment_allowlist": registration["environment_allowlist"],
                    "resource_budget": registration["resource_budget"],
                    "operation": registration["operation_configuration"],
                    "family_configuration": registration["family_configuration"],
                },
                "family": {
                    "kind": kind,
                    "detail": _family_detail(
                        kind,
                        claims[0]["subject"] if claims else None,
                        case["source"],
                        source_size,
                        registration["family_configuration_sha256"],
                    ),
                },
                "backend": {"retained_facts": retained_facts},
                "provenance": _empty_provenance(unit),
            }
        ],
        "cache": cache,
        "policy": {"required_components": ["registered-aggregate"]},
        "programme": _empty_programme(),
        "reported": case["expected_claim"],
        "exact_status": False,
    }


def _semantic_program(
    case: dict[str, Any], source_size: int, selected: dict[str, Any]
) -> dict[str, Any]:
    expected = selected["expected"]
    assumptions = list(expected["assumptions"])
    obligations = list(expected["undischarged_premises"])
    claim_ids = sorted(case["claim_ids"])
    claims = [
        {
            "id": claim_id,
            "subject": f"subject:{claim_id}",
            "source": None,
            "node": None,
            "meaning": None,
            "presentation": None,
            "cited_evidence": [],
            "assumptions": assumptions,
            "premises": [],
            "open_obligations": obligations,
            "out_of_scope": [],
            "registered_inputs": [],
            "admission": None,
        }
        for claim_id in claim_ids
    ]
    evidence = []
    for item in selected["evidence"]:
        kind = _family_kind(item["kind"])
        unit = item["id"]
        evidence.append(
            {
                "authority": "derived-conformance",
                "unit": unit,
                "content_sha256": None,
                "node": None,
                "claims": claim_ids,
                "outcome": "passed",
                "evaluation": item.get("evaluation"),
                "binding": None,
                "inventory": [],
                "assumptions": assumptions,
                "premises": item.get("premises", []),
                "open_obligation": None,
                "request": None,
                "family": {
                    "kind": kind,
                    "detail": _family_detail(
                        kind,
                        claims[0]["subject"] if claims else None,
                        case["source"],
                        source_size,
                        None,
                    ),
                },
                "backend": {"retained_facts": []},
                "provenance": _empty_provenance(unit),
            }
        )
    return {
        "schema": CASE_SCHEMA,
        "case_id": case["id"],
        "evidence_family": case["evidence_family"],
        "source": _source_artifact(case["source"], source_size),
        "claims": claims,
        "evidence": evidence,
        "cache": {"registered_inputs": [], "execution_inputs": []},
        "policy": {"required_components": selected["policy"]["components"]},
        "programme": _empty_programme(),
        "reported": case["expected_claim"],
        "exact_status": True,
    }


def _release_program(
    case: dict[str, Any], source_size: int, data: bytes
) -> dict[str, Any]:
    receipt = _strict_json(data, require_canonical=False)
    evidence = []
    for wrapped in receipt["evidence"]:
        record = wrapped["record"]
        kind = _family_kind(record["kind"])
        unit = record["unit_id"]
        assumptions = list(record["assumptions"])
        provenance = record["provenance"]
        prior_receipt = provenance.get("reused_from")
        evidence.append(
            {
                "authority": "portable-receipt",
                "unit": unit,
                "content_sha256": wrapped["sha256"],
                "node": record.get("node_id"),
                "claims": record["claim_ids"],
                "outcome": record.get("outcome"),
                "evaluation": record.get("evaluation_mode"),
                "binding": record.get("binding_mode"),
                "inventory": record["inventoried_targets"],
                "assumptions": assumptions,
                "premises": record.get("premises", []),
                "open_obligation": record.get("open_obligation"),
                "request": None,
                "family": {
                    "kind": kind,
                    "detail": _family_detail(
                        kind, "subject:c", case["source"], source_size, None
                    ),
                },
                "backend": {"retained_facts": []},
                "provenance": {
                    "revision": provenance.get("project_revision"),
                    "tree_state": provenance.get("tree_state"),
                    "semantic_closure": provenance.get("semantic_closure"),
                    "input_artifacts": [
                        _portable_artifact(item)
                        for item in provenance["input_artifacts"]
                    ],
                    "generated_artifacts": [
                        _portable_artifact(item)
                        for item in provenance["generated_artifacts"]
                    ],
                    "tool": _portable_tool(provenance["tool"]),
                    "adapter": _portable_tool(provenance["adapter"]),
                    "execution_kind": provenance.get("execution_kind"),
                    "commands": [
                        _portable_command(command) for command in provenance["commands"]
                    ],
                    "runs": [
                        {
                            "command_index": run["command_index"],
                            "exit_code": run["exit_code"],
                            "stdout_sha256": run.get("stdout_sha256"),
                            "stderr_sha256": run.get("stderr_sha256"),
                            "normalized_output_sha256": run.get(
                                "normalized_output_sha256"
                            ),
                            "output_truncated": run.get("output_truncated"),
                            "duration_ms": run.get("duration_ms"),
                        }
                        for run in provenance["runs"]
                    ],
                    "normalization": provenance.get("normalization"),
                    "reproduction": _portable_command(
                        provenance["reproduction_command"]
                    ),
                    "started_unix_ms": provenance.get("started_unix_ms"),
                    "completed_unix_ms": provenance.get("completed_unix_ms"),
                    "result_sha256": provenance.get("deterministic_result_sha256"),
                    "unit_configuration_sha256": provenance.get(
                        "unit_configuration_sha256"
                    ),
                    "budget": {
                        "time_ms": provenance["resource_budget"]["time_ms"],
                        "disk_bytes": provenance["resource_budget"]["disk_bytes"],
                        "memory_bytes": provenance["resource_budget"]["memory_bytes"],
                    },
                    "usage": {
                        "time_ms": provenance["actual_cost"]["time_ms"],
                        "disk_bytes": provenance["actual_cost"]["disk_bytes"],
                        "peak_memory": provenance["actual_cost"]["memory_bytes"],
                    },
                    "cache": {
                        "prior_receipt": prior_receipt,
                        "key": _cache_key(unit, prior_receipt),
                        "source_key": provenance.get("cache_key"),
                        "origin": "reused" if prior_receipt is not None else "executed",
                        "reuse_eligible": True,
                    },
                },
            }
        )
    claims = [_release_claim(claim, receipt) for claim in receipt["claims"]]
    return {
        "schema": CASE_SCHEMA,
        "case_id": case["id"],
        "evidence_family": case["evidence_family"],
        "source": _source_artifact(case["source"], source_size),
        "claims": claims,
        "evidence": evidence,
        "cache": {"registered_inputs": [], "execution_inputs": []},
        "policy": {"required_components": ["ledger"]},
        "programme": _release_programme(receipt),
        "reported": case["expected_claim"],
        "exact_status": True,
    }


def _empty_programme() -> dict[str, Any]:
    return {
        "project": None,
        "graph": None,
        "assumptions": [],
        "premises": [],
        "policies": [],
        "closures": [],
        "sealed_artifacts": [],
        "publication_blockers": [],
    }


def _release_programme(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "project": {
            "id": receipt["project"],
            "revision": receipt["project_revision"],
            "tier": receipt["project_tier"],
            "tree_state": receipt["tree_state"],
        },
        "graph": receipt["graph"],
        "assumptions": receipt["assumptions"],
        "premises": receipt["premises"],
        "policies": receipt["policies"],
        "closures": [
            {
                "sha256": closure["sha256"],
                "kind": closure["record"]["kind"],
                "members": [
                    _portable_artifact(member)
                    for member in closure["record"]["members"]
                ],
            }
            for closure in receipt["closures"]
        ],
        "sealed_artifacts": [
            _portable_artifact(artifact) for artifact in receipt["sealed_files"]
        ],
        "publication_blockers": sorted(
            status["claim_id"]
            for status in receipt["reported_statuses"]
            if status["policy_admitted"] is False
        ),
    }


def _registration_cache(
    root: Path, case: dict[str, Any], registration: dict[str, Any]
) -> dict[str, Any]:
    project_root = _registration_project_root(root, case, registration["inputs"])
    mutation_target = None
    if registration["declared_kind"] == "mutation-witness":
        mutation_target = next(
            (
                path
                for path in registration["inputs"]
                if path.startswith("src/") or "/src/" in path
            ),
            None,
        )
    inputs = sorted(
        (
            {
                "selector": "target-preimage" if path == mutation_target else path,
                "identity": _sha256((project_root / path).read_bytes()),
            }
            for path in registration["inputs"]
        ),
        key=lambda item: (item["selector"], item["identity"]),
    )
    return {"registered_inputs": inputs, "execution_inputs": inputs}


def _registration_project_root(
    root: Path, case: dict[str, Any], inputs: list[str]
) -> Path:
    source = root / case["source"]["path"]
    candidates = [
        candidate
        for candidate in (source.parent, *source.parent.parents)
        if candidate.is_relative_to(root)
        and all((candidate / path).is_file() for path in inputs)
    ]
    if len(candidates) != 1:
        raise AssuranceIrError(
            "registration inputs must resolve from exactly one project root"
        )
    return candidates[0]


def _release_claim(claim: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    claim_id = _required_text(claim, "id")
    status = next(
        item for item in receipt["reported_statuses"] if item["claim_id"] == claim_id
    )
    return {
        "id": claim_id,
        "subject": _required_text(claim, "subject"),
        "source": None,
        "node": claim.get("node_id"),
        "meaning": {
            "schema": _required_text(claim, "schema"),
            "statement": _required_text(claim, "statement"),
            "formal_declaration": claim.get("formal_declaration"),
            "statement_encoding": claim.get("statement_encoding"),
            "statement_sha256": claim.get("statement_sha256"),
            "foundational_axioms": sorted(claim.get("foundational_axioms", [])),
            "bounded_domain": claim.get("bounded_domain"),
            "registered_domain_language": claim.get("registered_domain_language"),
        },
        "presentation": {
            "title": _required_text(claim, "title"),
            "public_language": claim.get("public_language"),
            "public_statement": status.get("public_statement"),
        },
        "cited_evidence": sorted(claim.get("cited_evidence", [])),
        "assumptions": sorted(claim.get("assumptions", [])),
        "premises": sorted(claim.get("premises", [])),
        "open_obligations": sorted(claim.get("open_obligations", [])),
        "out_of_scope": sorted(claim.get("out_of_scope", [])),
        "registered_inputs": sorted(claim.get("registered_inputs", [])),
        "admission": {
            "policy": _required_text(claim, "policy"),
            "tier": claim.get("tier"),
            "primary_linkage": claim.get("primary_linkage"),
        },
    }


def _portable_artifact(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "logical_name": value.get("logical_name", value.get("path")),
        "sha256": value["sha256"],
        "size_bytes": value["size_bytes"],
    }


def _portable_tool(value: dict[str, Any]) -> dict[str, str]:
    return {
        "name": value["name"],
        "version": value["version"],
        "identity_sha256": value["identity_sha256"],
    }


def _portable_command(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "program": value["program"],
        "args": value["args"],
        "environment_allowlist": [
            {
                "name": environment["name"],
                "value_sha256": environment.get("value_sha256"),
                "secret": environment["secret"],
            }
            for environment in value["environment_allowlist"]
        ],
    }


def _family_kind(source_kind: str) -> str:
    kinds = {
        "example-test": "example",
        "property-test": "sampled-property",
        "static-check": "static-consistency",
        "mutation-witness": "mutation-witness",
        "distribution-reproduction": "distribution-reproduction",
        "bounded-check": "bounded-model-check",
        "theorem": "universal-source-proof",
        "exhaustive-check": "finite-exhaustive",
        "artifact-soundness": "artifact-correspondence",
        "trusted-transcription": "trusted-transcription",
        "source-refinement": "source-correspondence",
    }
    try:
        return kinds[source_kind]
    except KeyError as error:
        raise AssuranceIrError(f"unsupported evidence family {source_kind}") from error


def _family_schema(kind: str) -> str:
    schemas = {
        "example": "proofbound-ir-example/1",
        "sampled-property": "proofbound-ir-sampled-property/1",
        "static-consistency": "proofbound-ir-static-consistency/1",
        "mutation-witness": "proofbound-ir-mutation-witness/1",
        "distribution-reproduction": "proofbound-ir-distribution/1",
        "bounded-model-check": "proofbound-ir-bounded-model/1",
        "universal-source-proof": "proofbound-ir-source-proof/1",
        "finite-exhaustive": "proofbound-ir-finite-exhaustive/1",
        "artifact-correspondence": "proofbound-ir-artifact/1",
        "trusted-transcription": "proofbound-ir-transcription/1",
        "source-correspondence": "proofbound-ir-source-correspondence/1",
    }
    try:
        return schemas[kind]
    except KeyError as error:
        raise AssuranceIrError(f"unsupported IR family {kind}") from error


def _family_detail(
    kind: str,
    subject: str | None,
    source: dict[str, Any],
    source_size: int,
    configuration_sha256: str | None,
) -> dict[str, Any]:
    schema = _family_schema(kind)
    if kind == "mutation-witness":
        return {"schema": schema, "subject": subject or "subject:unknown"}
    if kind == "artifact-correspondence":
        return {
            "schema": schema,
            "artifact": _source_artifact(source, source_size),
        }
    if kind == "sampled-property":
        return {
            "schema": schema,
            "configuration_sha256": configuration_sha256,
            "required_fact_schemas": ["proofbound-python-property/1"],
        }
    return {"schema": schema, "configuration_sha256": configuration_sha256}


def _source_artifact(source: dict[str, Any], size_bytes: int) -> dict[str, Any]:
    return {
        "logical_name": source["path"],
        "sha256": source["sha256"],
        "size_bytes": size_bytes,
    }


def _cache_key(unit: str, prior_receipt: str | None) -> str:
    return domain_hash(
        CACHE_DOMAIN,
        canonical_json({"prior_receipt": prior_receipt, "unit": unit}),
    )


def _empty_provenance(unit: str) -> dict[str, Any]:
    return {
        "revision": None,
        "tree_state": None,
        "semantic_closure": None,
        "input_artifacts": [],
        "generated_artifacts": [],
        "tool": None,
        "adapter": None,
        "execution_kind": None,
        "commands": [],
        "runs": [],
        "normalization": None,
        "reproduction": None,
        "started_unix_ms": None,
        "completed_unix_ms": None,
        "result_sha256": None,
        "unit_configuration_sha256": None,
        "budget": None,
        "usage": {"time_ms": None, "disk_bytes": None, "peak_memory": None},
        "cache": {
            "prior_receipt": None,
            "key": _cache_key(unit, None),
            "source_key": None,
            "origin": "not-executed",
            "reuse_eligible": False,
        },
    }


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
                raise AssuranceIrError(
                    f"duplicate object key {key}", code="IR-DECODE-DUPLICATE-KEY"
                )
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssuranceIrError(f"invalid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise AssuranceIrError("document root must be an object")
    if require_canonical and canonical_json(value) != data:
        raise AssuranceIrError(
            "projection is not canonical JSON", code="IR-DECODE-NONCANONICAL"
        )
    return value


def _as_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("IR-DECODE-INVALID", "expected an object")
    return value


def _object(value: dict[str, Any], field: str) -> dict[str, Any]:
    return _as_object(value.get(field))


def _list(value: dict[str, Any], field: str) -> list[Any]:
    items = value.get(field)
    if not isinstance(items, list):
        _fail("IR-DECODE-INVALID", f"{field} must be an array")
    return items


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
