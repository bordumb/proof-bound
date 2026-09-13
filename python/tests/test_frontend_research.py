from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import proofbound.frontend_research as frontend


ROOT = Path(__file__).resolve().parents[2]
CORPUS = Path("docs/experiments/0011-dual-frontend-equivalence/corpus/subjects.json")
SUBJECTS = ("python-inventory", "typescript-codec", "rust-allowance")


def _code(callable_: object, *args: object) -> str:
    with pytest.raises(frontend.FrontendResearchError) as caught:
        callable_(*args)  # type: ignore[operator]
    return caught.value.code


def _compilations(subject: str) -> tuple[dict[str, object], ...]:
    toml = frontend.compile_toml_frontend(ROOT, CORPUS, subject)
    dsl = frontend.compile_dsl_frontend(ROOT, CORPUS, subject)
    pkl = frontend.compile_pkl_frontend(
        ROOT,
        CORPUS,
        subject,
        frontend.canonical_json(dsl["programme"]),
        frontend.PKL_SHA256,
    )
    return toml, dsl, pkl


def _reseal(compilation: dict[str, object]) -> None:
    source_map = compilation["source_map"]
    assert isinstance(source_map, dict)
    source_map["identity"] = frontend.domain_hash(
        frontend.SOURCE_MAP_SCHEMA,
        frontend.canonical_json(source_map["entries"]),
    )
    compilation["receipt"] = frontend._make_receipt(
        str(compilation["frontend"]),
        compilation["programme"],  # type: ignore[arg-type]
        compilation["effective_programme"],  # type: ignore[arg-type]
        source_map,
        compilation["dependencies"],  # type: ignore[arg-type]
    )


def test_independent_frontends_have_one_effective_meaning() -> None:
    actual_identities = {
        "python-inventory": "sha256:6c8acad7f1c5bbbfc6aa22fb585967d729d6320ae8b0437a7d78fa7b04fb8a70",
        "typescript-codec": "sha256:61235f3f7df9d68f9b99b88b3d986e4cc1e6f24f9bd40710f29967187e3afc39",
        "rust-allowance": "sha256:e23b5451b4381b6ac829ff9807084eeb44a1c64a4faab7705d5cf6d98d19005a",
    }
    for subject in SUBJECTS:
        toml, dsl, pkl = _compilations(subject)
        assert toml["programme"] == dsl["programme"] == pkl["programme"]
        assert (
            toml["effective_programme"]
            == dsl["effective_programme"]
            == pkl["effective_programme"]
        )
        for compilation in (toml, dsl, pkl):
            frontend.validate_compilation(ROOT, compilation)
            encoded = frontend.canonical_json(compilation)
            assert frontend.validate_compilation_bytes(ROOT, encoded) == compilation
        control = frontend.compare_frozen_control(
            ROOT,
            CORPUS,
            subject,
            toml["programme"],  # type: ignore[arg-type]
        )
        assert control["actual_bytes"] == control["expected_bytes"]
        assert control["actual_identity"] == actual_identities[subject]
        assert control["matches"] is False
        assert toml["receipt"] != dsl["receipt"] != pkl["receipt"]


def test_semantic_attack_codes_are_independently_reproduced() -> None:
    sampled = copy.deepcopy(_compilations("python-inventory")[1]["programme"])
    unit = next(item for item in sampled["evidence"] if item["kind"] == "property-test")
    unit.update(
        {
            "adapter": "lean",
            "kind": "theorem",
            "operation": {
                "type": "lean-audit",
                "targets": unit["expected_inventory"],
                "paths": ["Proofbound.lean"],
            },
            "evaluation_mode": "kernel",
            "theorem": unit["expected_inventory"][0],
        }
    )
    assert _code(frontend._normalize_programme, sampled) == "FRONTEND-TYPE-EVIDENCE"

    theorem = copy.deepcopy(_compilations("rust-allowance")[1]["programme"])
    theorem["claims"][0].pop("formal_declaration")
    assert (
        _code(frontend._normalize_programme, theorem) == "FRONTEND-JOIN-CORRESPONDENCE"
    )

    duplicate = copy.deepcopy(_compilations("python-inventory")[0]["programme"])
    inventory = duplicate["evidence"][0]["expected_inventory"]
    inventory.append(inventory[0])
    assert _code(frontend._normalize_programme, duplicate) == "FRONTEND-SET-DUPLICATE"

    partial = copy.deepcopy(_compilations("python-inventory")[1]["programme"])
    unit = next(item for item in partial["evidence"] if item["kind"] == "property-test")
    unit["operation"]["targets"] = ["substituted_test"]
    assert _code(frontend._normalize_programme, partial) == "FRONTEND-JOIN-INVENTORY"

    assumption = copy.deepcopy(_compilations("python-inventory")[2]["programme"])
    assumption["evidence"][0]["assumptions"].append("UNOWNED-001")
    assert (
        _code(frontend._normalize_programme, assumption) == "FRONTEND-JOIN-ASSUMPTION"
    )

    tier = copy.deepcopy(_compilations("typescript-codec")[0]["programme"])
    tier["evidence"][0]["tier"] = tier["claims"][0]["tier"] + 1
    assert _code(frontend._normalize_programme, tier) == "FRONTEND-POLICY-CONFLICT"

    authority = copy.deepcopy(_compilations("rust-allowance")[1]["programme"])
    authority["evidence"][0]["environment_allowlist"].append("NETWORK")
    assert (
        _code(frontend._normalize_programme, authority)
        == "FRONTEND-AUTHORITY-UNDECLARED"
    )

    alias = copy.deepcopy(_compilations("typescript-codec")[2]["programme"])
    alias["evidence"][0]["claims"][0] = alias["evidence"][0]["claims"][0].lower()
    assert _code(frontend._normalize_programme, alias) == "FRONTEND-ID-ALIAS"

    noncanonical = copy.deepcopy(_compilations("rust-allowance")[0])
    noncanonical["programme"]["evidence"].reverse()
    assert (
        _code(frontend.validate_compilation, ROOT, noncanonical)
        == "FRONTEND-NONCANONICAL"
    )


def test_syntax_and_pkl_authority_attacks_retain_a_source_span() -> None:
    path = Path(
        "docs/experiments/0011-dual-frontend-equivalence/corpus/python-inventory.pb"
    )
    source = (ROOT / path).read_text()
    changed = source.replace(
        'source_roots = ["src/inventory_service/reservations.py"]',
        'source_roots = ["src/inventory_service/reservations.py"]\n'
        "executable_status = true",
        1,
    )
    with pytest.raises(frontend.FrontendResearchError) as caught:
        frontend._parse_dsl(changed.encode(), path.as_posix())
    assert caught.value.code == "FRONTEND-SYNTAX-UNKNOWN"
    assert caught.value.path == path.as_posix()
    assert caught.value.end > caught.value.start

    attacks = (
        ('amends "Schema.pkl"\nlocal x = read("env:HOME")\n', "FRONTEND-PKL-RESOURCE"),
        (
            'amends "Schema.pkl"\nimport "https://example.test/x.pkl"\n',
            "FRONTEND-PKL-MODULE",
        ),
        ('amends "../Schema.pkl"\n', "FRONTEND-PATH-ESCAPE"),
        (
            'amends "Schema.pkl"\nimport "other.pkl"\n',
            "FRONTEND-DEPENDENCY-UNREGISTERED",
        ),
    )
    for source, code in attacks:
        with pytest.raises(frontend.FrontendResearchError) as caught:
            frontend._preflight_pkl(source.encode(), "attack.pkl")
        assert caught.value.code == code
        assert caught.value.path == "attack.pkl"
        assert caught.value.end > caught.value.start

    rendered = frontend.canonical_json(
        _compilations("typescript-codec")[1]["programme"]
    )
    assert (
        _code(
            frontend.compile_pkl_frontend,
            ROOT,
            CORPUS,
            "typescript-codec",
            rendered,
            f"sha256:{'0' * 64}",
        )
        == "FRONTEND-TOOL-SUBSTITUTION"
    )


def test_source_map_and_effective_attacks_reject_exactly() -> None:
    missing = copy.deepcopy(_compilations("python-inventory")[1])
    missing["source_map"]["entries"].pop()
    assert _code(frontend.validate_compilation, ROOT, missing) == "FRONTEND-MAP-MISSING"

    overlap = copy.deepcopy(_compilations("python-inventory")[1])
    overlap["source_map"]["entries"].append(
        copy.deepcopy(overlap["source_map"]["entries"][0])
    )
    overlap["source_map"]["entries"].sort(
        key=lambda item: (item["leaf"], *frontend._span_key(item["source"]))
    )
    assert _code(frontend.validate_compilation, ROOT, overlap) == "FRONTEND-MAP-OVERLAP"

    file_attack = copy.deepcopy(_compilations("typescript-codec")[0])
    replacement = next(
        item
        for item in file_attack["dependencies"]
        if item["logical_name"].endswith("reject-padding.toml")
    )
    entry = next(
        item
        for item in file_attack["source_map"]["entries"]
        if item["leaf"].startswith("/claims/")
    )
    entry["source"] = {
        "path": replacement["logical_name"],
        "sha256": replacement["identity"],
        "start": 0,
        "end": (ROOT / replacement["logical_name"]).stat().st_size,
    }
    _reseal(file_attack)
    assert (
        _code(frontend.validate_compilation, ROOT, file_attack) == "FRONTEND-MAP-FILE"
    )

    span = copy.deepcopy(_compilations("typescript-codec")[1])
    span["source_map"]["entries"][0]["source"]["end"] = 2**64 - 1
    _reseal(span)
    assert _code(frontend.validate_compilation, ROOT, span) == "FRONTEND-MAP-SPAN"

    leaf = copy.deepcopy(_compilations("rust-allowance")[1])
    leaf["source_map"]["entries"][0]["leaf"] = "/unknown"
    leaf["source_map"]["entries"].sort(
        key=lambda item: (item["leaf"], *frontend._span_key(item["source"]))
    )
    _reseal(leaf)
    assert _code(frontend.validate_compilation, ROOT, leaf) == "FRONTEND-MAP-LEAF"

    effective = _compilations("rust-allowance")[1]["effective_programme"]
    pretty = json.dumps(effective, indent=2, sort_keys=True).encode()
    assert (
        _code(frontend.validate_effective_bytes, pretty)
        == "FRONTEND-EFFECTIVE-NONCANONICAL"
    )


def test_strict_json_rejects_duplicate_keys_and_non_integer_numbers() -> None:
    assert _code(frontend._strict_json, b'{"a":1,"a":2}') == "FRONTEND-SYNTAX-UNKNOWN"
    assert _code(frontend._strict_json, b'{"a":1.5}') == "FRONTEND-SYNTAX-UNKNOWN"
