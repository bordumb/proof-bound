"""Independent frontend compiler and checker for Experiment 0011."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Any


PROGRAMME_SCHEMA = "proofbound-research-frontend-programme/1"
EFFECTIVE_SCHEMA = "proofbound-research-effective-programme/1"
SOURCE_MAP_SCHEMA = "proofbound-research-source-map/1"
RECEIPT_SCHEMA = "proofbound-research-frontend-receipt/1"
COMPILATION_SCHEMA = "proofbound-research-frontend-compilation/1"
PKL_SHA256 = "sha256:563eb51c9a20b16a3625464ed745c675ed9750381f2126722696a0d7cac1d9d3"
PKL_POLICY = (
    "pkl-0.32.1;modules=pkl:,file:;resources=^$;root=corpus;cache=off;"
    "env=PATH:/usr/bin:/bin;timeout=10"
)

_SET_FIELDS = (
    "evidence",
    "assumptions",
    "premises",
    "open_obligations",
    "out_of_scope",
    "source_roots",
    "foundational_axioms",
)
_EVIDENCE_SETS = (
    "claims",
    "assumptions",
    "expected_inventory",
    "inputs",
    "outputs",
    "environment_allowlist",
)
_CONSTRUCTORS = {
    "python-example": ("proofbound-evidence-unit/1", "python-test", "example-test"),
    "python-property": ("proofbound-evidence-unit/1", "python-test", "property-test"),
    "node-example": ("proofbound-evidence-unit/1", "node-test", "example-test"),
    "node-property": ("proofbound-evidence-unit/1", "node-test", "property-test"),
    "rust-example": ("proofbound-evidence-unit/1", "rust-test", "example-test"),
    "kani-bounded": ("proofbound-evidence-unit/1", "kani", "bounded-check"),
    "rust-mutation": (
        "proofbound-evidence-unit/3",
        "rust-test",
        "mutation-witness",
    ),
    "lean-theorem": ("proofbound-evidence-unit/1", "lean", "theorem"),
}


class FrontendResearchError(ValueError):
    """A fail-closed frontend compilation or validation error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.path = path
        self.start = start
        self.end = end


def canonical_json(value: object) -> bytes:
    """Encode a research record as compact, sorted-key UTF-8 JSON."""

    _reject_floats(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def domain_hash(domain: str, payload: bytes) -> str:
    """Hash bytes using the experiment's domain-separated convention."""

    digest = hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()
    return f"sha256:{digest}"


def compile_toml_frontend(
    root: Path, corpus_path: Path, subject_id: str
) -> dict[str, Any]:
    """Compile the exact registered TOML documents for one subject."""

    corpus, subject = _load_subject(root, corpus_path, subject_id)
    preregistration_path = corpus_path.parent.parent / "preregistration.json"
    preregistration = _strict_json((root / preregistration_path).read_bytes())
    registered_subject = next(
        (item for item in preregistration["subjects"] if item["id"] == subject_id),
        None,
    )
    if registered_subject is None:
        _fail("FRONTEND-DEPENDENCY-DRIFT", "subject is absent from preregistration")
    registered = {item["path"]: item for item in registered_subject["files"]}
    claims: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    origins: dict[str, dict[str, Any]] = {}
    dependencies: list[dict[str, str]] = []
    for relative in subject["toml_paths"]:
        if relative not in registered:
            _fail(
                "FRONTEND-DEPENDENCY-DRIFT",
                f"TOML source {relative} lacks a registered identity",
            )
        data = _read_registered(root, registered[relative])
        try:
            value = tomllib.loads(data.decode())
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            _source_fail("FRONTEND-SYNTAX-UNKNOWN", str(error), relative, len(data))
        origins_key: str
        schema = value.get("schema")
        if schema == "proofbound-claim/1":
            claims.append(value)
            origins_key = f"claim:{value.get('id', '')}"
        elif isinstance(schema, str) and schema.startswith("proofbound-evidence-unit/"):
            evidence.append(value)
            origins_key = f"evidence:{value.get('id', '')}"
        else:
            _source_fail(
                "FRONTEND-SYNTAX-UNKNOWN",
                "unsupported TOML document schema",
                relative,
                len(data),
            )
        origins[origins_key] = _source_span(relative, data)
        dependencies.append(_source_dependency(relative, data))
    index_relative = corpus_path.as_posix()
    index_data = (root / corpus_path).read_bytes()
    origins["programme"] = _source_span(index_relative, index_data)
    dependencies.append(_source_dependency(index_relative, index_data))
    programme = {
        "schema": PROGRAMME_SCHEMA,
        "project": {"id": subject["id"], "ecosystem": subject["ecosystem"]},
        "claims": claims,
        "evidence": evidence,
    }
    return _finish(root, "toml", programme, origins, dependencies)


def compile_dsl_frontend(
    root: Path, corpus_path: Path, subject_id: str
) -> dict[str, Any]:
    """Compile the bounded custom Proofbound research DSL."""

    _, subject = _load_subject(root, corpus_path, subject_id)
    registered = subject["frontends"]["proofbound-dsl"]
    data = _read_registered(root, registered)
    programme = _parse_dsl(data, registered["path"])
    span = _source_span(registered["path"], data)
    origins = _programme_origins(programme, span)
    return _finish(
        root,
        "proofbound-dsl",
        programme,
        origins,
        [_source_dependency(registered["path"], data)],
    )


def compile_pkl_frontend(
    root: Path,
    corpus_path: Path,
    subject_id: str,
    rendered_json: bytes,
    tool_sha256: str,
) -> dict[str, Any]:
    """Compile Pkl-rendered JSON while independently binding source authority."""

    corpus, subject = _load_subject(root, corpus_path, subject_id)
    registered = subject["frontends"]["pkl"]
    source = _read_registered(root, registered)
    _preflight_pkl(source, registered["path"])
    schema_registered = corpus["pkl_schema"]
    schema = _read_registered(root, schema_registered)
    if tool_sha256 != PKL_SHA256:
        _fail(
            "FRONTEND-TOOL-SUBSTITUTION",
            "Pkl executable identity differs from the preregistered release",
        )
    programme = _strict_json(rendered_json)
    project_span = _source_span(registered["path"], source)
    origins = _programme_origins(programme, project_span)
    origins["programme"] = _source_span(schema_registered["path"], schema)
    dependencies = [
        _source_dependency(registered["path"], source),
        _source_dependency(schema_registered["path"], schema),
        {
            "kind": "tool",
            "role": "frontend-evaluator",
            "logical_name": "pkl",
            "identity": tool_sha256,
            "detail": "Pkl 0.32.1",
        },
        {
            "kind": "contract",
            "role": "authority-policy",
            "logical_name": "pkl-evaluation-policy",
            "identity": domain_hash(
                "proofbound-research-pkl-policy/1", PKL_POLICY.encode()
            ),
            "detail": PKL_POLICY,
        },
    ]
    return _finish(root, "pkl", programme, origins, dependencies)


def validate_compilation(root: Path, compilation: dict[str, Any]) -> None:
    """Independently validate one canonical frontend compilation record."""

    _exact_keys(
        compilation,
        {
            "schema",
            "frontend",
            "programme",
            "effective_programme",
            "source_map",
            "dependencies",
            "receipt",
        },
    )
    if compilation["schema"] != COMPILATION_SCHEMA:
        _fail("FRONTEND-SYNTAX-UNKNOWN", "unknown compilation schema")
    frontend = compilation["frontend"]
    if frontend not in {"toml", "proofbound-dsl", "pkl"}:
        _fail("FRONTEND-SYNTAX-UNKNOWN", "unknown frontend")
    programme = _normalize_programme(_copy_json(compilation["programme"]))
    if programme != compilation["programme"]:
        _fail("FRONTEND-NONCANONICAL", "programme is not in canonical order")
    effective = {"schema": EFFECTIVE_SCHEMA, "programme": programme}
    if compilation["effective_programme"] != effective:
        _fail(
            "FRONTEND-EFFECTIVE-NONCANONICAL",
            "effective programme differs from canonical meaning",
        )
    dependencies = compilation["dependencies"]
    if dependencies != sorted(dependencies, key=_dependency_key) or len(
        {canonical_json(item) for item in dependencies}
    ) != len(dependencies):
        _fail("FRONTEND-NONCANONICAL", "dependencies are not a strict sorted set")
    _validate_source_map(
        root, frontend, programme, compilation["source_map"], dependencies
    )
    expected_receipt = _make_receipt(
        frontend, programme, effective, compilation["source_map"], dependencies
    )
    if compilation["receipt"] != expected_receipt:
        _fail("FRONTEND-MAP-LEAF", "receipt does not bind compilation content")


def validate_compilation_bytes(root: Path, data: bytes) -> dict[str, Any]:
    """Reject noncanonical bytes before validating a compilation."""

    compilation = _strict_json(data)
    if canonical_json(compilation) != data:
        _fail("FRONTEND-EFFECTIVE-NONCANONICAL", "compilation is not canonical JSON")
    validate_compilation(root, compilation)
    return compilation


def validate_effective_bytes(data: bytes) -> dict[str, Any]:
    """Validate a standalone effective programme without a frontend evaluator."""

    effective = _strict_json(data)
    if canonical_json(effective) != data:
        _fail(
            "FRONTEND-EFFECTIVE-NONCANONICAL",
            "effective programme is not canonical JSON",
        )
    _exact_keys(effective, {"schema", "programme"})
    if effective["schema"] != EFFECTIVE_SCHEMA:
        _fail("FRONTEND-SYNTAX-UNKNOWN", "unknown effective programme schema")
    normalized = _normalize_programme(_copy_json(effective["programme"]))
    if normalized != effective["programme"]:
        _fail("FRONTEND-NONCANONICAL", "effective content is not canonical")
    return effective


def compare_frozen_control(
    root: Path, corpus_path: Path, subject_id: str, programme: dict[str, Any]
) -> dict[str, Any]:
    """Compare compiled bytes with the separately frozen programme control."""

    _, subject = _load_subject(root, corpus_path, subject_id)
    normalized = _normalize_programme(_copy_json(programme))
    if normalized != programme:
        _fail("FRONTEND-NONCANONICAL", "programme is not canonical")
    data = canonical_json(programme)
    actual = domain_hash(PROGRAMME_SCHEMA, data)
    return {
        "project": subject_id,
        "expected_bytes": subject["expected_programme_bytes"],
        "actual_bytes": len(data),
        "expected_identity": subject["expected_programme_identity"],
        "actual_identity": actual,
        "matches": len(data) == subject["expected_programme_bytes"]
        and actual == subject["expected_programme_identity"],
    }


def _finish(
    root: Path,
    frontend: str,
    programme: dict[str, Any],
    origins: dict[str, dict[str, Any]],
    dependencies: list[dict[str, str]],
) -> dict[str, Any]:
    programme = _normalize_programme(programme)
    effective = {"schema": EFFECTIVE_SCHEMA, "programme": programme}
    source_map = _make_source_map(programme, origins)
    dependencies.append(
        {
            "kind": "contract",
            "role": "frontend-semantics",
            "logical_name": "frontend-grammar",
            "identity": domain_hash(
                "proofbound-research-frontend-contract/1", PROGRAMME_SCHEMA.encode()
            ),
            "detail": "GRAMMAR.md revision 1",
        }
    )
    dependencies.sort(key=_dependency_key)
    compilation = {
        "schema": COMPILATION_SCHEMA,
        "frontend": frontend,
        "programme": programme,
        "effective_programme": effective,
        "source_map": source_map,
        "dependencies": dependencies,
        "receipt": _make_receipt(
            frontend, programme, effective, source_map, dependencies
        ),
    }
    validate_compilation(root, compilation)
    return compilation


def _normalize_programme(programme: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(programme, {"schema", "project", "claims", "evidence"})
    if programme["schema"] != PROGRAMME_SCHEMA:
        _fail("FRONTEND-SYNTAX-UNKNOWN", "unknown frontend programme schema")
    project = programme["project"]
    _exact_keys(project, {"id", "ecosystem"})
    _stable_id(project["id"], uppercase=False)
    if project["ecosystem"] not in {"python", "typescript", "rust"}:
        _fail("FRONTEND-TYPE-EVIDENCE", "unknown project ecosystem")
    for claim in programme["claims"]:
        required = {
            "schema",
            "id",
            "title",
            "statement",
            "public_language",
            "subject",
            "profile",
            "tier",
            "primary_linkage",
            "evidence",
            "source_roots",
        }
        optional = {
            "assumptions",
            "premises",
            "open_obligations",
            "out_of_scope",
            "formal_declaration",
            "statement_encoding",
            "statement_sha256",
            "foundational_axioms",
            "bounded_domain",
        }
        _typed_keys(claim, required, optional)
        for field in _SET_FIELDS:
            claim.setdefault(field, [])
            claim[field] = _strict_set(claim[field])
        if claim["schema"] != "proofbound-claim/1":
            _fail("FRONTEND-SYNTAX-UNKNOWN", "unknown claim schema")
        _stable_id(claim["id"], uppercase=True)
        for field in ("title", "statement", "public_language", "subject"):
            _bounded_text(claim[field])
        if (
            not isinstance(claim["tier"], int)
            or isinstance(claim["tier"], bool)
            or not 0 <= claim["tier"] <= 2
        ):
            _fail("FRONTEND-POLICY-CONFLICT", "claim tier is outside range")
        if not claim["source_roots"]:
            _fail("FRONTEND-JOIN-CORRESPONDENCE", "claim has no source root")
    programme["claims"].sort(key=lambda item: item["id"])
    _unique_ids(programme["claims"])
    for unit in programme["evidence"]:
        required = {
            "schema",
            "id",
            "adapter",
            "kind",
            "claims",
            "tier",
            "expected_inventory",
            "inputs",
            "environment_allowlist",
            "operation",
            "resource_budget",
        }
        optional = {
            "assumptions",
            "outputs",
            "property",
            "bounded_domain",
            "mutation",
            "evaluation_mode",
            "theorem",
        }
        _typed_keys(unit, required, optional)
        unit.setdefault("assumptions", [])
        unit.setdefault("outputs", [])
        for field in _EVIDENCE_SETS:
            unit[field] = _strict_set(unit[field])
        _stable_id(unit["id"], uppercase=False)
        if not unit["expected_inventory"] or not unit["inputs"]:
            _fail("FRONTEND-JOIN-INVENTORY", "inventory and inputs must be nonempty")
        _normalize_operation(unit["operation"])
        _validate_evidence_shape(unit)
    programme["evidence"].sort(key=lambda item: item["id"])
    _unique_ids(programme["evidence"])
    _validate_joins(programme)
    return programme


def _normalize_operation(operation: dict[str, Any]) -> None:
    kind = operation.get("type")
    shapes = {
        "pytest": ({"type", "manifest", "targets", "paths"}, {"plugins"}),
        "vitest": ({"type"}, set()),
        "cargo-test": ({"type", "package", "manifest"}, {"targets"}),
        "kani": ({"type", "package", "manifest", "targets"}, set()),
        "lean-audit": ({"type", "targets", "paths"}, set()),
    }
    if kind not in shapes:
        _fail("FRONTEND-TYPE-EVIDENCE", "unknown operation")
    required, optional = shapes[kind]
    _typed_keys(operation, required, optional)
    if kind == "pytest":
        operation.setdefault("plugins", [])
        for field in ("targets", "paths", "plugins"):
            operation[field] = _strict_set(operation[field])
    elif kind == "kani":
        operation["targets"] = _strict_set(operation["targets"])
    elif kind == "lean-audit":
        operation["targets"] = _strict_set(operation["targets"])
        operation["paths"] = _strict_set(operation["paths"])
    elif kind == "cargo-test":
        operation.setdefault("targets", [])


def _validate_evidence_shape(unit: dict[str, Any]) -> None:
    operation = unit["operation"]
    route = (unit["adapter"], unit["kind"], operation["type"])
    shape = False
    if route == ("python-test", "example-test", "pytest"):
        shape = (
            unit["schema"] == "proofbound-evidence-unit/1" and "property" not in unit
        )
    elif route == ("python-test", "property-test", "pytest"):
        prop = unit.get("property")
        shape = (
            unit["schema"] == "proofbound-evidence-unit/1"
            and isinstance(prop, dict)
            and prop.get("schema") == "proofbound-python-property/1"
            and prop.get("framework") == "hypothesis"
            and set(prop) == {"schema", "framework", "seed"}
        )
    elif (
        route[0:2]
        in {
            ("node-test", "example-test"),
            ("node-test", "property-test"),
        }
        and route[2] == "vitest"
    ):
        shape = (
            unit["schema"] == "proofbound-evidence-unit/1" and "property" not in unit
        )
    elif route == ("rust-test", "example-test", "cargo-test"):
        shape = (
            unit["schema"] == "proofbound-evidence-unit/1" and "mutation" not in unit
        )
    elif route == ("rust-test", "mutation-witness", "cargo-test"):
        mutation = unit.get("mutation")
        shape = (
            unit["schema"] == "proofbound-evidence-unit/3"
            and isinstance(mutation, dict)
            and mutation.get("schema") == "proofbound-mutation-replay/1"
            and unit["expected_inventory"] == [unit["id"]]
        )
    elif route == ("kani", "bounded-check", "kani"):
        shape = (
            unit["schema"] == "proofbound-evidence-unit/1"
            and "bounded_domain" in unit
            and unit["expected_inventory"] == operation["targets"]
        )
    elif route == ("lean", "theorem", "lean-audit"):
        shape = (
            unit["schema"] == "proofbound-evidence-unit/1"
            and all(
                field not in unit
                for field in ("property", "bounded_domain", "mutation")
            )
            and unit.get("evaluation_mode") == "kernel"
            and operation["targets"] == [unit.get("theorem")]
            and unit.get("theorem") in unit["expected_inventory"]
        )
    if not shape:
        _fail("FRONTEND-TYPE-EVIDENCE", "evidence route or typed detail disagrees")
    if operation["type"] == "pytest":
        names = [value.rsplit("::", 1)[-1] for value in unit["expected_inventory"]]
        if names != operation["targets"]:
            _fail("FRONTEND-JOIN-INVENTORY", "pytest inventory differs from targets")
    allowed = {
        "python-test": {"PATH"},
        "node-test": {"PATH"},
        "rust-test": {"CARGO_HOME", "PATH", "RUSTUP_HOME"},
        "kani": {"CARGO_HOME", "PATH", "RUSTUP_HOME"},
        "lean": {"LEAN_PATH", "PATH"},
    }.get(unit["adapter"], set())
    if not set(unit["environment_allowlist"]).issubset(allowed):
        _fail("FRONTEND-AUTHORITY-UNDECLARED", "undeclared frontend authority")
    budget = unit["resource_budget"]
    _exact_keys(budget, {"time_seconds", "disk_bytes", "memory_bytes"})
    if budget["time_seconds"] <= 0 or budget["disk_bytes"] <= 0:
        _fail("FRONTEND-POLICY-CONFLICT", "resource budget must be positive")


def _validate_joins(programme: dict[str, Any]) -> None:
    claims = {claim["id"]: claim for claim in programme["claims"]}
    for unit in programme["evidence"]:
        attributed = [claims[value] for value in unit["claims"] if value in claims]
        if not attributed:
            if any(
                known.lower() == reference.lower()
                for known in claims
                for reference in unit["claims"]
            ):
                _fail("FRONTEND-ID-ALIAS", "claim reference uses an alias")
            _fail("FRONTEND-JOIN-CORRESPONDENCE", "evidence has no selected claim")
        reference = f"{unit['kind']}:{unit['id']}"
        for claim in attributed:
            if reference not in claim["evidence"]:
                _fail("FRONTEND-JOIN-CORRESPONDENCE", "claim omits attributed evidence")
            if unit["tier"] > claim["tier"]:
                _fail("FRONTEND-POLICY-CONFLICT", "evidence exceeds claim tier")
            if not set(unit["assumptions"]).issubset(claim["assumptions"]):
                _fail("FRONTEND-JOIN-ASSUMPTION", "unit assumption is not claim-owned")
            if unit["kind"] == "theorem" and (
                claim.get("formal_declaration") != unit.get("theorem")
                or "statement_encoding" not in claim
                or "statement_sha256" not in claim
            ):
                _fail(
                    "FRONTEND-JOIN-CORRESPONDENCE",
                    "theorem correspondence is incomplete",
                )


def _make_source_map(
    programme: dict[str, Any], origins: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    entries = []
    for leaf in _semantic_leaves(programme):
        if leaf == "/schema" or leaf.startswith("/project/"):
            key = "programme"
        elif leaf.startswith("/claims/"):
            key = f"claim:{leaf.split('/')[2]}"
        else:
            key = f"evidence:{leaf.split('/')[2]}"
        if key not in origins:
            _fail("FRONTEND-MAP-MISSING", f"{leaf} has no source origin")
        entries.append({"leaf": leaf, "source": origins[key]})
    entries.sort(key=lambda item: (item["leaf"], *_span_key(item["source"])))
    return {
        "schema": SOURCE_MAP_SCHEMA,
        "entries": entries,
        "identity": domain_hash(
            "proofbound-research-source-map/1", canonical_json(entries)
        ),
    }


def _validate_source_map(
    root: Path,
    frontend: str,
    programme: dict[str, Any],
    source_map: dict[str, Any],
    dependencies: list[dict[str, str]],
) -> None:
    _exact_keys(source_map, {"schema", "entries", "identity"})
    if source_map["schema"] != SOURCE_MAP_SCHEMA:
        _fail("FRONTEND-MAP-LEAF", "unknown source-map schema")
    entries = source_map["entries"]
    mapped = [entry["leaf"] for entry in entries]
    leaves = _semantic_leaves(programme)
    if len(mapped) != len(set(mapped)):
        _fail("FRONTEND-MAP-OVERLAP", "semantic leaf is mapped more than once")
    if len(mapped) < len(leaves):
        _fail("FRONTEND-MAP-MISSING", "source map omits a semantic leaf")
    if mapped != leaves:
        _fail("FRONTEND-MAP-LEAF", "source-map leaves differ from programme")
    expected_order = sorted(
        entries, key=lambda item: (item["leaf"], *_span_key(item["source"]))
    )
    if entries != expected_order or len(
        {canonical_json(item) for item in entries}
    ) != len(entries):
        _fail("FRONTEND-NONCANONICAL", "source map is not a strict sorted set")
    sources = {
        item["logical_name"]: item["identity"]
        for item in dependencies
        if item["kind"] == "artifact" and item["role"] == "frontend-source"
    }
    for entry in entries:
        source = entry["source"]
        _exact_keys(source, {"path", "sha256", "start", "end"})
        if sources.get(source["path"]) != source["sha256"]:
            _fail("FRONTEND-MAP-FILE", "map source is not a bound dependency")
        if source["path"] != _expected_source(frontend, entry["leaf"], list(sources)):
            _fail("FRONTEND-MAP-FILE", "leaf is attributed to the wrong source")
        try:
            data = (root / source["path"]).read_bytes()
        except OSError:
            _fail("FRONTEND-MAP-FILE", "map source cannot be read")
        if _sha256(data) != source["sha256"]:
            _fail("FRONTEND-MAP-FILE", "map source identity changed")
        if not 0 <= source["start"] < source["end"] <= len(data):
            _fail("FRONTEND-MAP-SPAN", "map span is outside its source")
    identity = domain_hash("proofbound-research-source-map/1", canonical_json(entries))
    if source_map["identity"] != identity:
        _fail("FRONTEND-MAP-LEAF", "source-map identity does not match entries")


def _expected_source(frontend: str, leaf: str, sources: list[str]) -> str:
    if frontend == "proofbound-dsl":
        selected = [path for path in sources if path.endswith(".pb")]
    elif frontend == "pkl":
        if leaf == "/schema" or leaf.startswith("/project/"):
            selected = [path for path in sources if path.endswith("/Schema.pkl")]
        else:
            selected = [
                path
                for path in sources
                if path.endswith(".pkl") and not path.endswith("/Schema.pkl")
            ]
    elif leaf == "/schema" or leaf.startswith("/project/"):
        selected = [path for path in sources if path.endswith("/subjects.json")]
    else:
        record_id = leaf.split("/")[2]
        selected = [path for path in sources if Path(path).stem == record_id]
    if len(selected) != 1:
        _fail("FRONTEND-MAP-FILE", "leaf has no unique registered source")
    return selected[0]


def _make_receipt(
    frontend: str,
    programme: dict[str, Any],
    effective: dict[str, Any],
    source_map: dict[str, Any],
    dependencies: list[dict[str, str]],
) -> dict[str, str]:
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "project": programme["project"]["id"],
        "frontend": frontend,
        "programme_sha256": domain_hash(PROGRAMME_SCHEMA, canonical_json(programme)),
        "effective_programme_sha256": domain_hash(
            EFFECTIVE_SCHEMA, canonical_json(effective)
        ),
        "source_map_sha256": source_map["identity"],
        "dependencies_sha256": domain_hash(
            "proofbound-research-frontend-dependencies/1", canonical_json(dependencies)
        ),
    }
    receipt["identity"] = domain_hash(RECEIPT_SCHEMA, canonical_json(receipt))
    return receipt


def _semantic_leaves(programme: dict[str, Any]) -> list[str]:
    leaves = ["/schema", *[f"/project/{key}" for key in programme["project"]]]
    for collection in ("claims", "evidence"):
        for record in programme[collection]:
            leaves.extend(f"/{collection}/{record['id']}/{key}" for key in record)
    return sorted(leaves)


def _parse_dsl(data: bytes, path: str) -> dict[str, Any]:
    try:
        source = data.decode()
    except UnicodeDecodeError:
        _source_fail("FRONTEND-SYNTAX-UNKNOWN", "DSL is not UTF-8", path, len(data))
    if "\r" in source or not source.endswith("\n"):
        _source_fail("FRONTEND-SYNTAX-UNKNOWN", "DSL must use LF", path, len(data))
    lines = list(enumerate(source.splitlines()))
    if not lines:
        _source_fail("FRONTEND-SYNTAX-UNKNOWN", "empty DSL", path, len(data))
    header = re.fullmatch(r'programme (".*") ecosystem (".*")', lines[0][1])
    if header is None:
        _source_fail(
            "FRONTEND-SYNTAX-UNKNOWN", "invalid programme header", path, len(data)
        )
    project_id = _json_string(header.group(1), path, len(data))
    ecosystem = _json_string(header.group(2), path, len(data))
    defaults: dict[str, dict[str, Any]] = {}
    claims: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    cursor = 1
    ended = False
    while cursor < len(lines):
        line = lines[cursor][1].strip()
        cursor += 1
        if not line:
            continue
        if line == "end":
            if any(value.strip() for _, value in lines[cursor:]):
                _source_fail(
                    "FRONTEND-SYNTAX-UNKNOWN", "content follows end", path, len(data)
                )
            ended = True
            break
        if line.startswith("defaults "):
            name = _json_string(line.removeprefix("defaults "), path, len(data))
            fields, cursor = _assignment_block(lines, cursor, path, len(data))
            if name in defaults:
                _source_fail("FRONTEND-ID-ALIAS", "duplicate defaults", path, len(data))
            defaults[name] = fields
            continue
        if line.startswith("claim "):
            claim_id = _json_string(line.removeprefix("claim "), path, len(data))
            fields, cursor = _assignment_block(lines, cursor, path, len(data))
            fields |= {"schema": "proofbound-claim/1", "id": claim_id}
            claims.append(fields)
            continue
        if line.startswith("evidence "):
            match = re.fullmatch(r'evidence ([a-z-]+) (".*?")(?: using (".*"))?', line)
            if match is None or match.group(1) not in _CONSTRUCTORS:
                _source_fail(
                    "FRONTEND-TYPE-EVIDENCE", "invalid constructor", path, len(data)
                )
            constructor, encoded_id, encoded_defaults = match.groups()
            unit_id = _json_string(encoded_id, path, len(data))
            fields = {}
            if encoded_defaults is not None:
                name = _json_string(encoded_defaults, path, len(data))
                if name not in defaults:
                    _source_fail(
                        "FRONTEND-ID-ALIAS", "unknown defaults", path, len(data)
                    )
                fields = _copy_json(defaults[name])
            explicit, cursor = _assignment_block(lines, cursor, path, len(data))
            overlap = set(fields) & set(explicit)
            if overlap:
                _source_fail(
                    "FRONTEND-SYNTAX-UNKNOWN", "default override", path, len(data)
                )
            fields.update(explicit)
            schema, adapter, kind = _CONSTRUCTORS[constructor]
            owned = {"schema": schema, "adapter": adapter, "kind": kind, "id": unit_id}
            if set(fields) & set(owned):
                _source_fail(
                    "FRONTEND-TYPE-EVIDENCE",
                    "constructor field override",
                    path,
                    len(data),
                )
            fields.update(owned)
            evidence.append(fields)
            continue
        _source_fail("FRONTEND-SYNTAX-UNKNOWN", "unknown declaration", path, len(data))
    if not ended:
        _source_fail("FRONTEND-SYNTAX-UNKNOWN", "programme has no end", path, len(data))
    programme = {
        "schema": PROGRAMME_SCHEMA,
        "project": {"id": project_id, "ecosystem": ecosystem},
        "claims": claims,
        "evidence": evidence,
    }
    try:
        return _normalize_programme(programme)
    except FrontendResearchError as error:
        if error.path is not None:
            raise
        _source_fail(error.code, str(error), path, len(data))


def _assignment_block(
    lines: list[tuple[int, str]], cursor: int, path: str, size: int
) -> tuple[dict[str, Any], int]:
    fields: dict[str, Any] = {}
    while cursor < len(lines):
        line = lines[cursor][1].strip()
        cursor += 1
        if not line:
            continue
        if line == "end":
            return fields, cursor
        if " = " not in line:
            _source_fail("FRONTEND-SYNTAX-UNKNOWN", "invalid assignment", path, size)
        key, encoded = line.split(" = ", 1)
        if re.fullmatch(r"[a-z][a-z0-9_]*", key) is None or key in fields:
            _source_fail(
                "FRONTEND-SYNTAX-UNKNOWN", "invalid or duplicate field", path, size
            )
        fields[key] = _strict_json(encoded.encode())
    _source_fail("FRONTEND-SYNTAX-UNKNOWN", "unterminated declaration", path, size)


def _preflight_pkl(data: bytes, path: str) -> None:
    try:
        source = data.decode()
    except UnicodeDecodeError:
        _source_fail(
            "FRONTEND-SYNTAX-UNKNOWN", "Pkl source is not UTF-8", path, len(data)
        )
    if any(token in source for token in ("read(", "read?(", "read*(")):
        _source_fail("FRONTEND-PKL-RESOURCE", "Pkl resource read", path, len(data))
    if any(
        token in source for token in ("https:", "http:", "package:", "projectpackage:")
    ):
        _source_fail("FRONTEND-PKL-MODULE", "remote or package module", path, len(data))
    if any(
        line.strip().startswith(('amends "../', 'amends "/'))
        for line in source.splitlines()
    ):
        _source_fail(
            "FRONTEND-PATH-ESCAPE", "Pkl template escapes root", path, len(data)
        )
    module_lines = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith(("amends ", "import "))
        or "import(" in line
        or "import*(" in line
    ]
    if module_lines != ['amends "Schema.pkl"']:
        _source_fail(
            "FRONTEND-DEPENDENCY-UNREGISTERED",
            "Pkl source must amend only Schema.pkl",
            path,
            len(data),
        )


def _load_subject(
    root: Path, corpus_path: Path, subject_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    corpus = _strict_json((root / corpus_path).read_bytes())
    _exact_keys(corpus, {"schema", "pkl_schema", "subjects"})
    if corpus["schema"] != "proofbound-research-frontend-corpus/1":
        _fail("FRONTEND-SYNTAX-UNKNOWN", "unknown corpus schema")
    subject = next(
        (item for item in corpus["subjects"] if item["id"] == subject_id), None
    )
    if subject is None:
        _fail("FRONTEND-ID-ALIAS", "unknown subject")
    return corpus, subject


def _read_registered(root: Path, registered: dict[str, Any]) -> bytes:
    try:
        data = (root / registered["path"]).read_bytes()
    except OSError as error:
        _fail("FRONTEND-DEPENDENCY-DRIFT", str(error))
    if _sha256(data) != f"sha256:{registered['sha256']}":
        _source_fail(
            "FRONTEND-DEPENDENCY-DRIFT",
            "registered source identity changed",
            registered["path"],
            len(data),
        )
    return data


def _strict_json(data: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                _fail("FRONTEND-SYNTAX-UNKNOWN", f"duplicate JSON key {key}")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_float=_reject_number)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("FRONTEND-SYNTAX-UNKNOWN", str(error))


def _json_string(encoded: str, path: str, size: int) -> str:
    value = _strict_json(encoded.encode())
    if not isinstance(value, str):
        _source_fail("FRONTEND-SYNTAX-UNKNOWN", "expected JSON string", path, size)
    return value


def _strict_set(values: Any) -> list[str]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        _fail("FRONTEND-TYPE-EVIDENCE", "semantic set is not a string list")
    for value in values:
        _bounded_text(value)
    if len(values) != len(set(values)):
        _fail("FRONTEND-SET-DUPLICATE", "semantic set contains a duplicate")
    return sorted(values)


def _stable_id(value: Any, *, uppercase: bool) -> None:
    if not isinstance(value, str):
        _fail("FRONTEND-ID-ALIAS", "stable ID is not a string")
    pattern = r"[A-Z][A-Z0-9-]{0,127}" if uppercase else r"[a-z][a-z0-9-]{0,127}"
    if re.fullmatch(pattern, value) is None:
        _fail("FRONTEND-ID-ALIAS", "stable ID is not canonical")


def _bounded_text(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
        )
    ):
        _fail("FRONTEND-SYNTAX-UNKNOWN", "text is blank, oversized, or controlled")


def _unique_ids(records: list[dict[str, Any]]) -> None:
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        _fail("FRONTEND-ID-ALIAS", "duplicate stable ID")


def _typed_keys(value: dict[str, Any], required: set[str], optional: set[str]) -> None:
    if not isinstance(value, dict):
        _fail("FRONTEND-TYPE-EVIDENCE", "record is not an object")
    unknown = set(value) - required - optional
    missing = required - set(value)
    if unknown:
        _fail("FRONTEND-SYNTAX-UNKNOWN", f"unknown fields: {sorted(unknown)}")
    if missing:
        _fail("FRONTEND-TYPE-EVIDENCE", f"missing fields: {sorted(missing)}")


def _exact_keys(value: Any, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _fail("FRONTEND-SYNTAX-UNKNOWN", "record keys differ from closed schema")


def _source_span(path: str, data: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": _sha256(data), "start": 0, "end": max(1, len(data))}


def _source_dependency(path: str, data: bytes) -> dict[str, str]:
    return {
        "kind": "artifact",
        "role": "frontend-source",
        "logical_name": path,
        "identity": _sha256(data),
        "detail": f"{len(data)} bytes",
    }


def _programme_origins(
    programme: dict[str, Any], span: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    origins = {"programme": span}
    origins.update({f"claim:{item['id']}": span for item in programme["claims"]})
    origins.update({f"evidence:{item['id']}": span for item in programme["evidence"]})
    return origins


def _dependency_key(value: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        value[key] for key in ("kind", "role", "logical_name", "identity", "detail")
    )


def _span_key(value: dict[str, Any]) -> tuple[Any, ...]:
    return value["path"], value["sha256"], value["start"], value["end"]


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _copy_json(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _reject_floats(value: object) -> None:
    if isinstance(value, float):
        _fail(
            "FRONTEND-SYNTAX-UNKNOWN", "floating-point values are outside the grammar"
        )
    if isinstance(value, dict):
        for child in value.values():
            _reject_floats(child)
    elif isinstance(value, list):
        for child in value:
            _reject_floats(child)


def _reject_number(value: str) -> None:
    _fail("FRONTEND-SYNTAX-UNKNOWN", f"non-integer number {value}")


def _source_fail(code: str, message: str, path: str, size: int) -> None:
    raise FrontendResearchError(code, message, path=path, start=0, end=max(1, size))


def _fail(code: str, message: str) -> None:
    raise FrontendResearchError(code, message)
