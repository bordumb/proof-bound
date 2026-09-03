"""Execute the source-retained invalidation experiment corpus.

The converter reads registered manifests and their exact filesystem inputs. It
does not read scenario ground truth until after projections and traces exist.
That separation keeps expected invalidation sets out of dependency discovery.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any

from proofbound.assurance_ir_checker import canonical_json
from proofbound.invalidation import (
    dependency_node_id,
    derive_invalidation_trace,
    make_dependency_projection,
)


REPORT_SCHEMA = "proofbound-research-invalidation-execution/1"


@dataclass(frozen=True)
class ProjectSource:
    """Filesystem and logical namespace for a registered project.

    Attributes:
        root: Directory against which manifest inputs resolve.
        namespace: Stable selector prefix used across machines.
        revision: Exact registered Git revision text.
    """

    root: Path
    namespace: str
    revision: str


def execute_corpus(repository: Path) -> dict[str, Any]:
    """Project all registered cases and compare dependency-derived scenarios.

    Args:
        repository: Proofbound repository root containing the frozen corpus.

    Returns:
        Canonicalizable execution report with projections, traces, and metrics.

    Raises:
        ValueError: If a frozen input has drifted or a source cannot be projected.
    """

    experiment = repository / "docs/experiments/0010-invalidation-precision"
    cases = _read_json(experiment / "corpus/cases.json")
    scenarios = _read_json(experiment / "corpus/scenarios.json")
    extension = _read_json(experiment / "corpus/extension-r2.json")
    bindings = _read_json(experiment / "corpus/scenario-bindings-r3.json")
    sources = _project_sources(repository, cases)
    projections = [
        _project_manifest_case(repository, case, sources[_scope_for_case(case)])
        for case in cases["controlled_units"]
    ]
    projections.extend(
        _project_external_case(repository, case, sources[_scope_for_case(case)])
        for case in cases["external_holdouts"]
    )
    projections.extend(_project_auxiliary_cases(repository, cases, extension))

    projection_units = [projection["unit"] for projection in projections]
    if len(projection_units) != len(set(projection_units)):
        raise ValueError("projected unit IDs are not globally unique")

    expected_by_scenario = {
        scenario["id"]: scenario for scenario in scenarios["scenarios"]
    }
    extension_scenario = extension["scenario"]
    expected_by_scenario[extension_scenario["id"]] = extension_scenario
    binding_by_scenario = {
        binding["scenario"]: binding["changed_node"] for binding in bindings["bindings"]
    }
    if set(expected_by_scenario) != set(binding_by_scenario):
        raise ValueError("scenario ground truth and changed-node bindings differ")

    results: list[dict[str, Any]] = []
    for scenario_id in sorted(binding_by_scenario):
        expected = expected_by_scenario[scenario_id]
        scope = expected["scope"]
        scoped = [
            projection
            for projection in projections
            if _projection_scope(str(projection["unit"])) == scope
        ]
        trace = derive_invalidation_trace(scoped, [binding_by_scenario[scenario_id]])
        predicted = trace["invalidated_units"]
        registered = expected["expected_invalidated"]
        true_positive = len(set(predicted) & set(registered))
        precision = _ratio(true_positive, len(predicted))
        recall = _ratio(true_positive, len(registered))
        results.append(
            {
                "scenario": scenario_id,
                "class": expected["class"],
                "scope": scope,
                "scope_units": sorted(str(projection["unit"]) for projection in scoped),
                "predicted_invalidated": predicted,
                "registered_invalidated": registered,
                "exact": predicted == registered,
                "precision": precision,
                "recall": recall,
                "avoided_units": len(scoped) - len(predicted),
                "trace": trace,
            }
        )

    invalidated = sum(len(result["predicted_invalidated"]) for result in results)
    explained = sum(
        len(
            {
                path["unit"]
                for path in result["trace"]["paths"]
                if path["unit"] in result["predicted_invalidated"]
            }
        )
        for result in results
    )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "experiment": "EXP-0010",
        "programme_experiment": "EXP-LANG-003",
        "source_revision": _digest_text(str(cases["subject"])),
        "projection_count": len(projections),
        "scenario_count": len(results),
        "projections": sorted(projections, key=lambda value: str(value["unit"])),
        "scenarios": results,
        "metrics": {
            "exact_scenarios": sum(result["exact"] for result in results),
            "stale_retention": sum(
                bool(
                    set(result["registered_invalidated"])
                    - set(result["predicted_invalidated"])
                )
                for result in results
            ),
            "overinvalidating_scenarios": sum(
                bool(
                    set(result["predicted_invalidated"])
                    - set(result["registered_invalidated"])
                )
                for result in results
            ),
            "invalidated_unit_events": invalidated,
            "explanation_coverage": _ratio(explained, invalidated),
        },
    }
    return report


def write_report(repository: Path, destination: Path) -> None:
    """Execute the corpus and write canonical JSON to one destination."""

    destination.write_bytes(canonical_json(execute_corpus(repository)))


def _project_sources(
    repository: Path, cases: dict[str, Any]
) -> dict[str, ProjectSource]:
    controlled_revision = str(cases["subject"])
    external = {case["id"]: case for case in cases["external_holdouts"]}
    return {
        "python-controlled": ProjectSource(
            repository / "demo/python-inventory-service",
            "python-controlled",
            controlled_revision,
        ),
        "typescript-controlled": ProjectSource(
            repository / "demo/typescript-codec",
            "typescript-controlled",
            controlled_revision,
        ),
        "allowance-controlled": ProjectSource(
            repository, "allowance-controlled", controlled_revision
        ),
        "external-click": ProjectSource(
            repository / "other_repos/python-click-acceptance",
            "external-click",
            str(external["external-click-existing-tests"]["upstream_subject"]),
        ),
        "external-vitest-action": ProjectSource(
            repository / "other_repos/typescript-vitest-coverage-action",
            "external-vitest-action",
            str(external["external-vitest-action-existing-tests"]["upstream_subject"]),
        ),
    }


def _scope_for_case(case: dict[str, Any]) -> str:
    case_id = str(case["id"])
    if case_id.startswith("external-click"):
        return "external-click"
    if case_id.startswith("external-vitest"):
        return "external-vitest-action"
    route = str(case["route"])
    if route.startswith("python-") or route == "independent-check":
        return "python-controlled"
    if route.startswith("typescript-"):
        return "typescript-controlled"
    return "allowance-controlled"


def _project_manifest_case(
    repository: Path, case: dict[str, Any], source: ProjectSource
) -> dict[str, Any]:
    manifest_path = repository / str(case["manifest"])
    _require_digest(manifest_path, str(case["manifest_sha256"]))
    manifest = tomllib.loads(manifest_path.read_text())
    if manifest.get("id") != case["id"] or manifest.get("claims") != case["claims"]:
        raise ValueError(f"frozen case binding drifted: {case['id']}")
    nodes: list[dict[str, Any]] = []
    uses: list[dict[str, Any]] = []
    for path in manifest.get("inputs", []):
        artifact = _artifact_node(source, str(path))
        nodes.append(artifact)
        uses.append(_use(artifact, _artifact_role(str(path)), "registered input"))

    route = str(case["route"])
    if route in {"rust-cargo-test", "rust-mutation", "kani-bounded-check"}:
        transitive = "demo/allowance/rust/kernel/src/decision.rs"
        if not any(node["selector"].endswith(transitive) for node in nodes):
            node = _artifact_node(source, transitive)
            nodes.append(node)
            uses.append(_use(node, "semantic", "transitive Rust module"))
    if route == "python-hypothesis":
        selector = f"{source.namespace}/python-module:_hypothesis_pytestplugin"
        candidate_path = source.root / "_hypothesis_pytestplugin.py"
        resolution = _resolution_node(selector, source.namespace, candidate_path)
        nodes.append(resolution)
        uses.append(_use(resolution, "execution", "resolve registered pytest plugin"))
    for variable in manifest.get("environment_allowlist", []):
        environment = _environment_node(source.namespace, str(variable))
        nodes.append(environment)
        uses.append(_use(environment, "execution", "admit environment value"))
    for tool in _route_tools(route):
        tool_node = _tool_node(source.namespace, tool)
        nodes.append(tool_node)
        uses.append(_use(tool_node, "execution", f"execute {tool}"))
    distribution = manifest.get("distribution")
    if isinstance(distribution, dict):
        contract = _contract_node(
            f"{source.namespace}/{case['id']}#artifact-sha256",
            str(distribution["schema"]),
            str(distribution["artifact_sha256"]),
        )
        nodes.append(contract)
        uses.append(_use(contract, "generated-baseline", "registered artifact digest"))
    return make_dependency_projection(
        unit=str(case["id"]),
        route=route,
        source_revision=_digest_text(source.revision),
        claims=[str(claim) for claim in case["claims"]],
        nodes=nodes,
        uses=uses,
    )


def _project_external_case(
    repository: Path, case: dict[str, Any], source: ProjectSource
) -> dict[str, Any]:
    manifest_path = source.root / "proofbound/evidence/existing-tests.toml"
    project_path = source.root / "proofbound.toml"
    closure_path = source.root / ".proofbound/closures/PROJECT-CLAIM-001.semantic.json"
    _require_digest(manifest_path, str(case["unit_manifest_sha256"]))
    _require_digest(project_path, str(case["project_manifest_sha256"]))
    _require_digest(closure_path, str(case["semantic_closure_file_sha256"]))
    manifest = tomllib.loads(manifest_path.read_text())
    closure = _read_json(closure_path)
    if closure["id"] != case["semantic_closure"]:
        raise ValueError(f"external closure identity drifted: {case['id']}")
    nodes = [_artifact_node(source, str(path)) for path in manifest["inputs"]]
    uses = [
        _use(node, "semantic", "registered external semantic input") for node in nodes
    ]
    for variable in manifest.get("environment_allowlist", []):
        node = _environment_node(source.namespace, str(variable))
        nodes.append(node)
        uses.append(_use(node, "execution", "admit environment value"))
    tool_name = "python" if str(case["route"]).startswith("python-") else "node"
    tool = _tool_node(source.namespace, tool_name)
    nodes.append(tool)
    uses.append(_use(tool, "execution", f"execute {tool_name}"))
    return make_dependency_projection(
        unit=str(case["id"]),
        route=str(case["route"]),
        source_revision=_digest_text(source.revision),
        claims=[str(claim) for claim in case["claims"]],
        nodes=nodes,
        uses=uses,
    )


def _project_auxiliary_cases(
    repository: Path, cases: dict[str, Any], extension: dict[str, Any]
) -> list[dict[str, Any]]:
    controlled_revision = _digest_text(str(cases["subject"]))
    mode_root = repository / str(cases["auxiliary_fixtures"][0]["root"])
    mode_source = ProjectSource(
        mode_root, "auxiliary-mode-fixture", str(cases["subject"])
    )
    mode_node = _artifact_node(mode_source, "mode_gate.sh")
    mode = make_dependency_projection(
        unit="fixture-cargo-mode",
        route="rust-cargo-test",
        source_revision=controlled_revision,
        claims=["FIXTURE-MODE-CLAIM"],
        nodes=[mode_node],
        uses=[_use(mode_node, "execution", "execute build helper")],
    )
    transitive_root = repository / str(extension["auxiliary_fixture"]["root"])
    transitive_source = ProjectSource(
        transitive_root,
        "auxiliary-transitive-fixture",
        str(cases["subject"]),
    )
    shared_node = _artifact_node(transitive_source, "shared.rs")
    transitive = make_dependency_projection(
        unit="fixture-cargo-transitive",
        route="rust-cargo-test",
        source_revision=controlled_revision,
        claims=["FIXTURE-TRANSITIVE-CLAIM"],
        nodes=[shared_node],
        uses=[_use(shared_node, "semantic", "compile external Rust module")],
    )
    return [mode, transitive]


def _projection_scope(unit: str) -> str:
    if unit == "fixture-cargo-mode":
        return "auxiliary-mode-fixture"
    if unit == "fixture-cargo-transitive":
        return "auxiliary-transitive-fixture"
    if unit.startswith("external-click"):
        return "external-click"
    if unit.startswith("external-vitest"):
        return "external-vitest-action"
    if unit in {
        "accept-over-cap-mutant",
        "reservation-example",
        "reservation-property",
        "reservation-types",
        "reservation-vectors",
        "wheel-reproduction",
    }:
        return "python-controlled"
    if unit in {
        "bounded-roundtrip",
        "npm-package",
        "reject-padding",
        "reject-padding-mutant",
        "strict-types",
    }:
        return "typescript-controlled"
    return "allowance-controlled"


def _artifact_node(source: ProjectSource, path: str) -> dict[str, Any]:
    absolute = source.root / path
    if absolute.is_symlink() or not absolute.is_file():
        raise ValueError(f"artifact is not a regular non-symlink file: {absolute}")
    selector = f"{source.namespace}/{path}"
    metadata = absolute.stat()
    permissions: dict[str, Any]
    if os.name == "posix":
        permissions = {"model": "unix-mode", "mode": stat.S_IMODE(metadata.st_mode)}
    else:
        permissions = {
            "model": "readonly",
            "readonly": not os.access(absolute, os.W_OK),
        }
    return {
        "kind": "artifact",
        "id": dependency_node_id("artifact", selector),
        "selector": selector,
        "sha256": _digest_bytes(absolute.read_bytes()),
        "size_bytes": metadata.st_size,
        "permissions": permissions,
    }


def _resolution_node(selector: str, namespace: str, candidate: Path) -> dict[str, Any]:
    path = f"{namespace}/{candidate.name}"
    if candidate.exists():
        source = ProjectSource(candidate.parent, namespace, "local")
        artifact = _artifact_node(source, candidate.name)
        state = {
            "state": "present",
            "sha256": artifact["sha256"],
            "size_bytes": artifact["size_bytes"],
            "permissions": artifact["permissions"],
        }
    else:
        state = {"state": "absent"}
    return {
        "kind": "resolution",
        "id": dependency_node_id("resolution", selector),
        "selector": selector,
        "candidates": [{"path": path, "state": state}],
    }


def _environment_node(namespace: str, name: str) -> dict[str, Any]:
    selector = f"{namespace}/{name}"
    value = os.environ.get(name)
    state = (
        {"state": "absent"}
        if value is None
        else {
            "state": "value-digest",
            "sha256": _digest_text(value),
        }
    )
    return {
        "kind": "environment",
        "id": dependency_node_id("environment", selector),
        "selector": selector,
        "state": state,
    }


def _tool_node(namespace: str, name: str) -> dict[str, Any]:
    executable_name, argv = _tool_probe(name)
    resolved = shutil.which(executable_name)
    if resolved is None:
        raise ValueError(f"required tool is unavailable: {executable_name}")
    path = Path(resolved).resolve()
    completed = subprocess.run(
        [resolved, *argv],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise ValueError(f"tool identity probe failed: {name}")
    selector = f"{namespace}/{name}"
    return {
        "kind": "tool",
        "id": dependency_node_id("tool", selector),
        "selector": selector,
        "executable_sha256": _digest_bytes(path.read_bytes()),
        "version_identity": _digest_bytes(completed.stdout.strip()),
    }


def _tool_probe(name: str) -> tuple[str, list[str]]:
    return {
        "python": (sys.executable, ["--version"]),
        "node": ("node", ["--version"]),
        "npm": ("npm", ["--version"]),
        "cargo": ("cargo", ["--version"]),
        "kani": ("cargo-kani", ["--version"]),
        "lean": ("lean", ["--version"]),
        "lake": ("lake", ["--version"]),
    }[name]


def _route_tools(route: str) -> tuple[str, ...]:
    if route.startswith("python-") or route == "independent-check":
        return ("python",)
    if route == "typescript-npm-package":
        return ("node", "npm")
    if route.startswith("typescript-"):
        return ("node",)
    if route == "lean-theorem":
        return ("lake", "lean")
    if route == "kani-bounded-check":
        return ("cargo", "kani")
    return ("cargo",)


def _contract_node(selector: str, schema: str, identity: str) -> dict[str, Any]:
    return {
        "kind": "contract",
        "id": dependency_node_id("contract", selector),
        "selector": selector,
        "contract_schema": schema,
        "contract_identity": identity,
    }


def _artifact_role(path: str) -> str:
    if path.endswith((".lock", "requirements-dev.txt", ".ini", ".json", ".toml")):
        return "execution"
    if "/tools/" in f"/{path}" or path.startswith("tools/"):
        return "external-contract"
    return "semantic"


def _use(node: dict[str, Any], role: str, purpose: str) -> dict[str, str]:
    return {"node": str(node["id"]), "role": role, "purpose": purpose}


def _require_digest(path: Path, expected: str) -> None:
    actual = _digest_bytes(path.read_bytes())
    if actual != expected:
        raise ValueError(f"frozen artifact drifted: {path}: {actual} != {expected}")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _digest_text(value: str) -> str:
    return _digest_bytes(value.encode())


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _ratio(numerator: int, denominator: int) -> dict[str, int]:
    if denominator == 0:
        return {"numerator": 1, "denominator": 1}
    return {"numerator": numerator, "denominator": denominator}
