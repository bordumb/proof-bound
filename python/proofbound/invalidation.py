"""Independent dependency and invalidation model for Experiment 0010.

This module intentionally does not import producer bindings. It implements the
research wire directly so Rust/Python agreement is meaningful evidence rather
than two callers sharing one decoder.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from typing import Any

from proofbound.assurance_ir_checker import (
    AssuranceIrError,
    canonical_json,
    domain_hash,
)


DEPENDENCY_PROJECTION_SCHEMA = "proofbound-ir-dependency-projection/1"
DEPENDENCY_PROJECTION_DOMAIN = "proofbound-ir-dependency-projection/1"
INVALIDATION_TRACE_SCHEMA = "proofbound-ir-invalidation-trace/1"
INVALIDATION_TRACE_DOMAIN = "proofbound-ir-invalidation-trace/1"

_NODE_KINDS = (
    "artifact",
    "resolution",
    "environment",
    "tool",
    "contract",
    "platform",
)
_ROLE_ORDER = {
    "semantic": 0,
    "execution": 1,
    "generated-baseline": 2,
    "external-contract": 3,
}


def dependency_node_id(kind: str, selector: str) -> str:
    """Derive a stable node ID from kind and logical selector.

    Args:
        kind: Closed dependency-node kind.
        selector: Stable logical selector without content identity.

    Returns:
        Domain-separated SHA-256 dependency-node identity.
    """

    if kind not in _NODE_KINDS:
        _fail("IR-DEPENDENCY-OPAQUE", "unknown dependency kind")
    _bounded_selector(selector)
    return domain_hash(
        "proofbound-ir-dependency-node/1", f"{kind}\0{selector}".encode()
    )


def make_dependency_projection(
    *,
    unit: str,
    route: str,
    source_revision: str,
    claims: Iterable[str],
    nodes: Iterable[Mapping[str, Any]],
    uses: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Construct and validate one canonical dependency projection.

    Args:
        unit: Evidence-unit identifier.
        route: Backend-neutral registered route class.
        source_revision: Exact source revision identity.
        claims: Claim identifiers attributed to the unit.
        nodes: Complete typed dependency nodes.
        uses: Edges from dependency nodes to the unit.

    Returns:
        Canonical projection as JSON-compatible data.

    Raises:
        AssuranceIrError: If the source values cannot form a valid projection.
    """

    node_values = [deepcopy(dict(node)) for node in nodes]
    node_values.sort(key=lambda node: str(node.get("id", "")))
    use_values = [deepcopy(dict(dependency_use)) for dependency_use in uses]
    use_values.sort(key=_use_sort_key)
    claim_values = sorted(claims)
    secret_present = any(
        node.get("kind") == "environment"
        and isinstance(node.get("state"), Mapping)
        and node["state"].get("state") == "secret-present-no-reuse"
        for node in node_values
    )
    projection: dict[str, Any] = {
        "schema": DEPENDENCY_PROJECTION_SCHEMA,
        "unit": unit,
        "route": route,
        "source_revision": source_revision,
        "claims": claim_values,
        "nodes": node_values,
        "uses": use_values,
        "reuse_allowed": not secret_present,
        "identity": "",
    }
    projection["identity"] = _projection_identity(projection)
    validate_dependency_projection(projection)
    return projection


def validate_dependency_projection(projection: Mapping[str, Any]) -> None:
    """Validate one canonical, source-retained dependency projection."""

    _exact_keys(
        projection,
        {
            "schema",
            "unit",
            "route",
            "source_revision",
            "claims",
            "nodes",
            "uses",
            "reuse_allowed",
            "identity",
        },
    )
    if projection["schema"] != DEPENDENCY_PROJECTION_SCHEMA:
        _fail("IR-DEPENDENCY-OPAQUE", "unknown dependency projection schema")
    _bounded_text(projection["unit"])
    _bounded_text(projection["route"])
    _digest(projection["source_revision"])
    claims = _text_list(projection["claims"])
    _sorted_unique(claims)
    if not claims:
        _fail("IR-DEPENDENCY-BINDING-MISMATCH", "projection has no claims")
    nodes = _object_list(projection["nodes"])
    if not nodes:
        _fail("IR-DEPENDENCY-OMITTED", "projection has no dependency nodes")
    node_ids = [str(node.get("id", "")) for node in nodes]
    if len(node_ids) != len(set(node_ids)):
        _fail("IR-DEPENDENCY-DUPLICATE", "duplicate dependency node")
    if node_ids != sorted(node_ids):
        _fail(
            "IR-DEPENDENCY-NONCANONICAL",
            "dependency nodes must be sorted and unique by ID",
        )
    for node in nodes:
        _validate_node(node)
    uses = _object_list(projection["uses"])
    if not uses:
        _fail("IR-DEPENDENCY-OMITTED", "projection has no dependency uses")
    if len({canonical_json(item) for item in uses}) != len(uses):
        _fail("IR-DEPENDENCY-DUPLICATE", "duplicate dependency use")
    if uses != sorted(uses, key=_use_sort_key):
        _fail(
            "IR-DEPENDENCY-NONCANONICAL",
            "dependency uses must be sorted and unique",
        )
    known_nodes = set(node_ids)
    for dependency_use in uses:
        _exact_keys(dependency_use, {"node", "role", "purpose"})
        if dependency_use["node"] not in known_nodes:
            _fail("IR-DEPENDENCY-OMITTED", "dependency use references a missing node")
        if dependency_use["role"] not in _ROLE_ORDER:
            _fail("IR-DEPENDENCY-ROLE-MISMATCH", "unknown dependency role")
        _bounded_text(dependency_use["purpose"])
    secret_present = any(
        node["kind"] == "environment"
        and node["state"]["state"] == "secret-present-no-reuse"
        for node in nodes
    )
    if not isinstance(projection["reuse_allowed"], bool):
        _fail("IR-DEPENDENCY-OPAQUE", "reuse_allowed must be Boolean")
    if secret_present and projection["reuse_allowed"]:
        _fail(
            "IR-DEPENDENCY-SECRET-REUSE",
            "secret-bearing environment state cannot be reusable",
        )
    if projection["identity"] != _projection_identity(projection):
        _fail(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "dependency projection identity does not match its content",
        )


def validate_cache_dependency_evidence(
    evidence: Mapping[str, Any], *, reuse_requested: bool
) -> None:
    """Validate complete or legacy cache evidence under an explicit reuse request."""

    state = evidence.get("state")
    if state == "complete":
        _exact_keys(evidence, {"state", "projection"})
        projection = _object(evidence["projection"])
        validate_dependency_projection(projection)
        if reuse_requested and not projection["reuse_allowed"]:
            _fail("IR-DEPENDENCY-SECRET-REUSE", "projection forbids reuse")
        return
    if state == "legacy-opaque-cache":
        _exact_keys(evidence, {"state", "key"})
        _digest(evidence["key"])
        if reuse_requested:
            _fail(
                "IR-DEPENDENCY-OPAQUE",
                "an opaque legacy cache key cannot independently authorize reuse",
            )
        return
    _fail("IR-DEPENDENCY-OPAQUE", "unknown cache dependency evidence")


def validate_projection_against_source(
    source: Mapping[str, Any], claimed: Mapping[str, Any]
) -> None:
    """Compare a claimed projection with independently reconstructed source meaning."""

    validate_dependency_projection(source)
    validate_dependency_projection(claimed)
    for field in ("unit", "route", "source_revision", "claims"):
        if source[field] != claimed[field]:
            _fail(
                "IR-DEPENDENCY-BINDING-MISMATCH",
                "projection binding differs from its source",
            )
    source_nodes = {node["id"]: node for node in source["nodes"]}
    claimed_nodes = {node["id"]: node for node in claimed["nodes"]}
    source_ids = set(source_nodes)
    claimed_ids = set(claimed_nodes)
    if source_ids < claimed_ids:
        _fail(
            "IR-DEPENDENCY-OVERINVALIDATION",
            "claimed projection adds a dependency absent from its source",
        )
    if claimed_ids < source_ids:
        _fail("IR-DEPENDENCY-OMITTED", "claimed projection omits a source dependency")
    if source_ids != claimed_ids:
        _fail(
            "IR-DEPENDENCY-ROLE-MISMATCH",
            "claimed projection substitutes its dependency inventory",
        )
    for node_id, source_node in source_nodes.items():
        claimed_node = claimed_nodes[node_id]
        if (
            source_node["kind"] != claimed_node["kind"]
            or source_node["selector"] != claimed_node["selector"]
        ):
            _fail(
                "IR-DEPENDENCY-ROLE-MISMATCH",
                "dependency kind or selector differs from its source",
            )
        if source_node != claimed_node:
            _fail(_node_mismatch_code(source_node, claimed_node), "dependency drift")
    if source["uses"] != claimed["uses"]:
        _fail(
            "IR-DEPENDENCY-ROLE-MISMATCH",
            "dependency uses differ from their source",
        )
    if source["reuse_allowed"] != claimed["reuse_allowed"]:
        _fail(
            "IR-DEPENDENCY-SECRET-REUSE",
            "reuse eligibility differs from its source",
        )


def derive_invalidation_trace(
    projections: Sequence[Mapping[str, Any]],
    changed_nodes: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive exact affected units, claims, and explanation paths."""

    changes = [deepcopy(dict(node)) for node in changed_nodes]
    if not changes:
        _fail("IR-DEPENDENCY-OMITTED", "invalidation has no changed node")
    changes.sort(key=_changed_sort_key)
    if len({canonical_json(node) for node in changes}) != len(changes):
        _fail("IR-DEPENDENCY-DUPLICATE", "changed-node set contains a duplicate")
    changed_ids = {
        dependency_node_id(str(change.get("kind")), str(change.get("selector")))
        for change in changes
    }
    units: set[str] = set()
    claims: set[str] = set()
    paths: set[tuple[str, str, str]] = set()
    for projection in projections:
        validate_dependency_projection(projection)
        used = {
            dependency_use["node"]
            for dependency_use in projection["uses"]
            if dependency_use["node"] in changed_ids
        }
        if not used:
            continue
        unit = str(projection["unit"])
        units.add(unit)
        for claim in projection["claims"]:
            claims.add(claim)
            paths.update((node, unit, claim) for node in used)
    trace: dict[str, Any] = {
        "schema": INVALIDATION_TRACE_SCHEMA,
        "changed_nodes": changes,
        "invalidated_units": sorted(units),
        "affected_claims": sorted(claims),
        "paths": [
            {"dependency": dependency, "unit": unit, "claim": claim}
            for dependency, unit, claim in sorted(paths)
        ],
        "identity": "",
    }
    trace["identity"] = _trace_identity(trace)
    return trace


def validate_invalidation_trace(
    projections: Sequence[Mapping[str, Any]], trace: Mapping[str, Any]
) -> None:
    """Reject a trace that does not equal generic dependency derivation."""

    _exact_keys(
        trace,
        {
            "schema",
            "changed_nodes",
            "invalidated_units",
            "affected_claims",
            "paths",
            "identity",
        },
    )
    if trace["schema"] != INVALIDATION_TRACE_SCHEMA:
        _fail("IR-DEPENDENCY-OPAQUE", "unknown invalidation trace schema")
    expected = derive_invalidation_trace(
        projections, _object_list(trace["changed_nodes"])
    )
    for field in ("invalidated_units", "affected_claims", "paths"):
        if trace[field] != expected[field]:
            _fail(
                "IR-DEPENDENCY-STALE-KEY",
                "reported invalidation differs from dependency derivation",
            )
    if trace["identity"] != _trace_identity(trace):
        _fail(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "invalidation trace identity does not match its content",
        )


def _projection_identity(projection: Mapping[str, Any]) -> str:
    material = deepcopy(dict(projection))
    material.pop("identity", None)
    return domain_hash(DEPENDENCY_PROJECTION_DOMAIN, canonical_json(material))


def _trace_identity(trace: Mapping[str, Any]) -> str:
    material = deepcopy(dict(trace))
    material.pop("identity", None)
    return domain_hash(INVALIDATION_TRACE_DOMAIN, canonical_json(material))


def _validate_node(node: Mapping[str, Any]) -> None:
    kind = node.get("kind")
    if kind not in _NODE_KINDS:
        _fail("IR-DEPENDENCY-OPAQUE", "unknown dependency kind")
    selector = node.get("selector")
    _bounded_selector(selector)
    if node.get("id") != dependency_node_id(str(kind), str(selector)):
        _fail(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "dependency node ID does not match kind and selector",
        )
    common = {"kind", "id", "selector"}
    if kind == "artifact":
        _exact_keys(node, common | {"sha256", "size_bytes", "permissions"})
        _digest(node["sha256"])
        _nonnegative_int(node["size_bytes"])
        _permissions(_object(node["permissions"]))
    elif kind == "resolution":
        _exact_keys(node, common | {"candidates"})
        candidates = _object_list(node["candidates"])
        if not candidates:
            _fail(
                "IR-DEPENDENCY-RESOLUTION-MISMATCH",
                "resolution node has no candidates",
            )
        if len({candidate["path"] for candidate in candidates}) != len(candidates):
            _fail("IR-DEPENDENCY-DUPLICATE", "duplicate resolution candidate")
        if candidates != sorted(candidates, key=lambda item: item["path"]):
            _fail(
                "IR-DEPENDENCY-NONCANONICAL",
                "resolution candidates must be a nonempty canonical set",
            )
        for candidate in candidates:
            _exact_keys(candidate, {"path", "state"})
            _bounded_selector(candidate["path"])
            state = _object(candidate["state"])
            if state.get("state") == "absent":
                _exact_keys(state, {"state"})
            elif state.get("state") == "present":
                _exact_keys(state, {"state", "sha256", "size_bytes", "permissions"})
                _digest(state["sha256"])
                _nonnegative_int(state["size_bytes"])
                _permissions(_object(state["permissions"]))
            else:
                _fail("IR-DEPENDENCY-RESOLUTION-MISMATCH", "unknown path state")
    elif kind == "environment":
        _exact_keys(node, common | {"state"})
        state = _object(node["state"])
        state_kind = state.get("state")
        if state_kind == "absent":
            _exact_keys(state, {"state"})
        elif state_kind == "value-digest":
            _exact_keys(state, {"state", "sha256"})
            _digest(state["sha256"])
        elif state_kind == "secret-present-no-reuse":
            _exact_keys(state, {"state", "identity"})
            _digest(state["identity"])
        else:
            _fail("IR-DEPENDENCY-ENVIRONMENT-MISMATCH", "unknown environment state")
    elif kind == "tool":
        _exact_keys(node, common | {"executable_sha256", "version_identity"})
        _digest(node["executable_sha256"])
        _digest(node["version_identity"])
    elif kind == "contract":
        _exact_keys(node, common | {"contract_schema", "contract_identity"})
        _bounded_text(node["contract_schema"])
        _digest(node["contract_identity"])
    else:
        _exact_keys(node, common | {"operating_system", "architecture"})
        _bounded_text(node["operating_system"])
        _bounded_text(node["architecture"])


def _node_mismatch_code(source: Mapping[str, Any], claimed: Mapping[str, Any]) -> str:
    kind = source["kind"]
    if kind != claimed["kind"]:
        return "IR-DEPENDENCY-ROLE-MISMATCH"
    if kind == "artifact" and source["permissions"] != claimed["permissions"]:
        return "IR-DEPENDENCY-PERMISSION-MISMATCH"
    return {
        "resolution": "IR-DEPENDENCY-RESOLUTION-MISMATCH",
        "environment": "IR-DEPENDENCY-ENVIRONMENT-MISMATCH",
        "tool": "IR-DEPENDENCY-TOOL-MISMATCH",
    }.get(str(kind), "IR-DEPENDENCY-IDENTITY-MISMATCH")


def _permissions(value: Mapping[str, Any]) -> None:
    model = value.get("model")
    if model == "unix-mode":
        _exact_keys(value, {"model", "mode"})
        mode = value["mode"]
        if (
            not isinstance(mode, int)
            or isinstance(mode, bool)
            or not 0 <= mode <= 0o7777
        ):
            _fail("IR-DEPENDENCY-PERMISSION-MISMATCH", "invalid Unix mode")
    elif model == "readonly":
        _exact_keys(value, {"model", "readonly"})
        if not isinstance(value["readonly"], bool):
            _fail("IR-DEPENDENCY-PERMISSION-MISMATCH", "invalid readonly state")
    else:
        _fail("IR-DEPENDENCY-PERMISSION-MISMATCH", "unknown permission model")


def _use_sort_key(value: Mapping[str, Any]) -> tuple[str, int, str]:
    return (
        str(value.get("node", "")),
        _ROLE_ORDER.get(str(value.get("role", "")), len(_ROLE_ORDER)),
        str(value.get("purpose", "")),
    )


def _changed_sort_key(value: Mapping[str, Any]) -> tuple[int, str]:
    kind = str(value.get("kind", ""))
    return (
        _NODE_KINDS.index(kind) if kind in _NODE_KINDS else len(_NODE_KINDS),
        str(value.get("selector", "")),
    )


def _bounded_text(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
        )
    ):
        _fail("IR-DEPENDENCY-OPAQUE", "invalid bounded dependency text")


def _bounded_selector(value: object) -> None:
    _bounded_text(value)
    assert isinstance(value, str)
    if (
        value.startswith("/")
        or "\\" in value
        or any(component in {"", ".", ".."} for component in value.split("/"))
    ):
        _fail("IR-DEPENDENCY-UNSAFE-PATH", "unsafe dependency selector")


def _digest(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        _fail("IR-DEPENDENCY-IDENTITY-MISMATCH", "invalid SHA-256 identity")


def _nonnegative_int(value: object) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail("IR-DEPENDENCY-OPAQUE", "expected a nonnegative integer")


def _exact_keys(value: Mapping[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        _fail("IR-DEPENDENCY-OPAQUE", "object has unknown or missing fields")


def _sorted_unique(values: list[str]) -> None:
    if values != sorted(values) or len(values) != len(set(values)):
        _fail("IR-DEPENDENCY-NONCANONICAL", "text set is not canonical")


def _text_list(value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail("IR-DEPENDENCY-OPAQUE", "expected text array")
    return value


def _object(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail("IR-DEPENDENCY-OPAQUE", "expected object")
    return value


def _object_list(value: object) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        _fail("IR-DEPENDENCY-OPAQUE", "expected object array")
    return [_object(item) for item in value]


def _fail(code: str, message: str) -> None:
    raise AssuranceIrError(message, code=code)
