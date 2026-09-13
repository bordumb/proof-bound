from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from proofbound.assurance_ir_checker import AssuranceIrError
from proofbound.assurance_ir_checker import canonical_json, domain_hash
from proofbound.invalidation import (
    dependency_node_id,
    derive_invalidation_trace,
    make_dependency_projection,
    validate_cache_dependency_evidence,
    validate_dependency_projection,
    validate_invalidation_trace,
    validate_projection_against_source,
)


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _artifact(selector: str) -> dict[str, object]:
    return {
        "kind": "artifact",
        "id": dependency_node_id("artifact", selector),
        "selector": selector,
        "sha256": _digest("1"),
        "size_bytes": 7,
        "permissions": {"model": "unix-mode", "mode": 0o644},
    }


def _projection() -> dict[str, object]:
    node = _artifact("python-controlled/src/value.py")
    return make_dependency_projection(
        unit="unit-a",
        route="python-pytest",
        source_revision=_digest("2"),
        claims=["CLAIM-A"],
        nodes=[node],
        uses=[
            {
                "node": node["id"],
                "role": "semantic",
                "purpose": "execute registered test",
            }
        ],
    )


def _rich_projection() -> dict[str, object]:
    nodes: list[dict[str, object]] = [
        _artifact("python-controlled/src/value.py"),
        {
            "kind": "resolution",
            "id": dependency_node_id(
                "resolution", "python-controlled/python-module:plugin"
            ),
            "selector": "python-controlled/python-module:plugin",
            "candidates": [
                {
                    "path": "python-controlled/plugin.py",
                    "state": {"state": "absent"},
                }
            ],
        },
        {
            "kind": "environment",
            "id": dependency_node_id("environment", "python-controlled/PATH"),
            "selector": "python-controlled/PATH",
            "state": {"state": "absent"},
        },
        {
            "kind": "tool",
            "id": dependency_node_id("tool", "python-controlled/python"),
            "selector": "python-controlled/python",
            "executable_sha256": _digest("7"),
            "version_identity": _digest("8"),
        },
        {
            "kind": "contract",
            "id": dependency_node_id(
                "contract", "python-controlled/unit#artifact-sha256"
            ),
            "selector": "python-controlled/unit#artifact-sha256",
            "contract_schema": "proofbound-contract/1",
            "contract_identity": _digest("9"),
        },
        {
            "kind": "platform",
            "id": dependency_node_id("platform", "python-controlled/platform"),
            "selector": "python-controlled/platform",
            "operating_system": "linux",
            "architecture": "x86_64",
        },
    ]
    return make_dependency_projection(
        unit="unit-a",
        route="python-pytest",
        source_revision=_digest("2"),
        claims=["CLAIM-A"],
        nodes=nodes,
        uses=[
            {
                "node": node["id"],
                "role": "execution",
                "purpose": "execute registered unit",
            }
            for node in nodes
        ],
    )


def _refresh(projection: dict[str, object]) -> dict[str, object]:
    return make_dependency_projection(
        unit=str(projection["unit"]),
        route=str(projection["route"]),
        source_revision=str(projection["source_revision"]),
        claims=list(projection["claims"]),
        nodes=list(projection["nodes"]),
        uses=list(projection["uses"]),
    )


def _rehash_without_validation(projection: dict[str, object]) -> None:
    material = deepcopy(projection)
    material.pop("identity")
    projection["identity"] = domain_hash(
        "proofbound-ir-dependency-projection/1", canonical_json(material)
    )


def _rehash_trace_without_validation(trace: dict[str, object]) -> None:
    material = deepcopy(trace)
    material.pop("identity")
    trace["identity"] = domain_hash(
        "proofbound-ir-invalidation-trace/1", canonical_json(material)
    )


def test_derives_exact_invalidation_path() -> None:
    trace = derive_invalidation_trace(
        [_projection()],
        [{"kind": "artifact", "selector": "python-controlled/src/value.py"}],
    )
    assert trace["invalidated_units"] == ["unit-a"]
    assert trace["affected_claims"] == ["CLAIM-A"]
    assert len(trace["paths"]) == 1


def test_legacy_cache_never_authorizes_reuse() -> None:
    evidence = {"state": "legacy-opaque-cache", "key": _digest("3")}
    validate_cache_dependency_evidence(evidence, reuse_requested=False)
    with pytest.raises(AssuranceIrError, match="opaque") as raised:
        validate_cache_dependency_evidence(evidence, reuse_requested=True)
    assert raised.value.code == "IR-DEPENDENCY-OPAQUE"


def test_rejects_omission_binding_and_content_substitution() -> None:
    source = _projection()

    omitted = deepcopy(source)
    omitted["nodes"] = []
    omitted["uses"] = []
    _rehash_without_validation(omitted)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, omitted)
    assert raised.value.code == "IR-DEPENDENCY-OMITTED"

    rebound = deepcopy(source)
    rebound["unit"] = "unit-b"
    rebound = _refresh(rebound)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, rebound)
    assert raised.value.code == "IR-DEPENDENCY-BINDING-MISMATCH"

    changed = deepcopy(source)
    changed["nodes"][0]["sha256"] = _digest("4")
    changed = _refresh(changed)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, changed)
    assert raised.value.code == "IR-DEPENDENCY-IDENTITY-MISMATCH"


def test_secret_environment_forces_non_reuse() -> None:
    selector = "project/API_TOKEN"
    node = {
        "kind": "environment",
        "id": dependency_node_id("environment", selector),
        "selector": selector,
        "state": {"state": "secret-present-no-reuse", "identity": _digest("5")},
    }
    projection = make_dependency_projection(
        unit="unit-secret",
        route="independent-check",
        source_revision=_digest("6"),
        claims=["CLAIM-A"],
        nodes=[node],
        uses=[{"node": node["id"], "role": "execution", "purpose": "read secret"}],
    )
    assert projection["reuse_allowed"] is False


def test_rejects_all_preregistered_attacks_with_exact_codes() -> None:
    source = _rich_projection()
    actual: dict[str, str] = {}

    omitted = deepcopy(source)
    removed = omitted["nodes"].pop(0)
    omitted["uses"] = [
        item for item in omitted["uses"] if item["node"] != removed["id"]
    ]
    _rehash_without_validation(omitted)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, omitted)
    actual["INV-001"] = raised.value.code

    role = deepcopy(source)
    role["uses"][0]["role"] = "semantic"
    role = _refresh(role)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, role)
    actual["INV-002"] = raised.value.code

    content = deepcopy(source)
    next(node for node in content["nodes"] if node["kind"] == "artifact")["sha256"] = (
        _digest("a")
    )
    content = _refresh(content)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, content)
    actual["INV-003"] = raised.value.code

    mode = deepcopy(source)
    next(node for node in mode["nodes"] if node["kind"] == "artifact")[
        "permissions"
    ] = {"model": "unix-mode", "mode": 0o755}
    mode = _refresh(mode)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, mode)
    actual["INV-004"] = raised.value.code

    resolution = deepcopy(source)
    next(node for node in resolution["nodes"] if node["kind"] == "resolution")[
        "candidates"
    ][0]["state"] = {
        "state": "present",
        "sha256": _digest("b"),
        "size_bytes": 3,
        "permissions": {"model": "unix-mode", "mode": 0o644},
    }
    resolution = _refresh(resolution)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, resolution)
    actual["INV-005"] = raised.value.code

    environment = deepcopy(source)
    next(node for node in environment["nodes"] if node["kind"] == "environment")[
        "state"
    ] = {"state": "value-digest", "sha256": _digest("c")}
    environment = _refresh(environment)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, environment)
    actual["INV-006"] = raised.value.code

    tool = deepcopy(source)
    next(node for node in tool["nodes"] if node["kind"] == "tool")[
        "executable_sha256"
    ] = _digest("d")
    tool = _refresh(tool)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, tool)
    actual["INV-007"] = raised.value.code

    duplicate = deepcopy(source)
    duplicate["nodes"].append(deepcopy(duplicate["nodes"][0]))
    duplicate["nodes"].sort(key=lambda node: node["id"])
    _rehash_without_validation(duplicate)
    with pytest.raises(AssuranceIrError) as raised:
        validate_dependency_projection(duplicate)
    actual["INV-008"] = raised.value.code

    reordered = deepcopy(source)
    reordered["nodes"][0], reordered["nodes"][1] = (
        reordered["nodes"][1],
        reordered["nodes"][0],
    )
    _rehash_without_validation(reordered)
    with pytest.raises(AssuranceIrError) as raised:
        validate_dependency_projection(reordered)
    actual["INV-009"] = raised.value.code

    extra = deepcopy(source)
    extra_node = _artifact("python-controlled/docs/presentation.md")
    extra["nodes"].append(extra_node)
    extra["uses"].append(
        {
            "node": extra_node["id"],
            "role": "execution",
            "purpose": "invented execution input",
        }
    )
    extra = _refresh(extra)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, extra)
    actual["INV-010"] = raised.value.code

    rebound = deepcopy(source)
    rebound["claims"] = ["CLAIM-B"]
    rebound = _refresh(rebound)
    with pytest.raises(AssuranceIrError) as raised:
        validate_projection_against_source(source, rebound)
    actual["INV-011"] = raised.value.code

    with pytest.raises(AssuranceIrError) as raised:
        validate_cache_dependency_evidence(
            {"state": "legacy-opaque-cache", "key": _digest("e")},
            reuse_requested=True,
        )
    actual["INV-012"] = raised.value.code

    trace = derive_invalidation_trace(
        [source],
        [{"kind": "artifact", "selector": "python-controlled/src/value.py"}],
    )
    trace["invalidated_units"] = []
    _rehash_trace_without_validation(trace)
    with pytest.raises(AssuranceIrError) as raised:
        validate_invalidation_trace([source], trace)
    actual["INV-013"] = raised.value.code

    secret = deepcopy(source)
    next(node for node in secret["nodes"] if node["kind"] == "environment")["state"] = {
        "state": "secret-present-no-reuse",
        "identity": _digest("f"),
    }
    secret["reuse_allowed"] = True
    _rehash_without_validation(secret)
    with pytest.raises(AssuranceIrError) as raised:
        validate_dependency_projection(secret)
    actual["INV-014"] = raised.value.code

    unsafe = deepcopy(source)
    artifact = next(node for node in unsafe["nodes"] if node["kind"] == "artifact")
    artifact["selector"] = "../escape"
    artifact["id"] = domain_hash(
        "proofbound-ir-dependency-node/1", b"artifact\0../escape"
    )
    unsafe["nodes"].sort(key=lambda node: node["id"])
    _rehash_without_validation(unsafe)
    with pytest.raises(AssuranceIrError) as raised:
        validate_dependency_projection(unsafe)
    actual["INV-015"] = raised.value.code

    preregistration = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "docs/experiments/0010-invalidation-precision/preregistration.json"
        ).read_text()
    )
    expected = {
        attack["id"]: attack["expected_code"] for attack in preregistration["attacks"]
    }
    assert actual == expected


def test_matches_independent_rust_canonical_vector() -> None:
    projection = _rich_projection()
    assert projection["identity"] == (
        "sha256:b96828804e3089507d3302aa98cf62853a4fa007932bd158bd89ac639a53f953"
    )
    trace = derive_invalidation_trace(
        [projection],
        [{"kind": "artifact", "selector": "python-controlled/src/value.py"}],
    )
    assert trace["identity"] == (
        "sha256:6c74e55ab257d8cd3995652ed770b1ccd0e0d71068d57a2157c950ab72dcc005"
    )
