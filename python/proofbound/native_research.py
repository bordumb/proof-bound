"""Independent native parser and certificate checker for Experiment 0016."""

from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn

AST_SCHEMA = "proofbound-research-native-ast/1"
CERTIFICATE_SCHEMA = "proofbound-native-certificate/1"
REPORT_SCHEMA = "proofbound-research-native-report/1"
TOOLCHAIN_SCHEMA = "proofbound-research-native-toolchain/1"
ATTACKS_SCHEMA = "proofbound-research-native-attacks/1"
ARTIFACT_DOMAIN = "proofbound-native-bytecode/1"

CONTRACT_IDS = [
    "round-trip",
    "malformed-rejection",
    "canonicality",
    "exact-consumption",
    "bounded-termination",
]
MUTANT_IDS = [
    "accept-noncanonical",
    "accept-trailing",
    "always-error",
    "always-success",
    "ignore-length",
    "payload-substitution",
]


class NativeFailure(ValueError):
    """Report one exact independent-checker rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    """Encode compact canonical UTF-8 JSON."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def sha256_bytes(payload: bytes) -> str:
    """Return the raw SHA-256 identity of bytes."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def domain_hash(domain: str, payload: bytes) -> str:
    """Return a domain-separated SHA-256 identity."""

    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def parse_native_source(source: bytes) -> dict[str, Any]:
    """Parse and type-check the frozen canonical source language."""

    try:
        text = source.decode()
    except UnicodeDecodeError as error:
        _fail("NATIVE-SYNTAX", str(error))
    if "\r" in text or not text.endswith("\n"):
        _fail("NATIVE-NONCANONICAL", "source must be LF-terminated")
    lines = text.splitlines()
    if any(not line for line in lines):
        _fail("NATIVE-NONCANONICAL", "blank source line")
    if any(line.startswith("loop ") for line in lines):
        _fail("NATIVE-NONTOTAL", "loop construct is not total")
    if any(line.startswith("foreign ") for line in lines):
        _fail("NATIVE-SYNTAX", "unknown declaration")
    if (
        sum(line.startswith("module ") for line in lines) != 1
        or sum(line.startswith("fn encode(") for line in lines) > 1
        or sum(line.startswith("fn decode(") for line in lines) > 1
    ):
        _fail("NATIVE-DUPLICATE", "duplicate declaration")
    if len(lines) != 13:
        if sum(line.startswith("spec ") for line in lines) != 5:
            _fail("NATIVE-SPEC-MISSING", "specification set differs")
        _fail("NATIVE-SYNTAX", "declaration count differs")

    module = _between(lines[0], "module ", ";", "NATIVE-SYNTAX")
    if (
        not module
        or module.startswith("-")
        or module.endswith("-")
        or "--" in module
        or any(
            not (
                character.isascii()
                and (character.islower() or character.isdigit() or character == "-")
            )
            for character in module
        )
    ):
        _fail("NATIVE-SYNTAX", "module identifier differs")
    value_min, value_max = _pair(lines[1], "type Value = range(", ");")
    if lines[2] != "type Decode = result(Value, Error);":
        _fail("NATIVE-TYPE", "Decode result type differs")
    encode_effect = _between(lines[3], "effect encode = ", ";", "NATIVE-EFFECT")
    decode_effect = _between(lines[4], "effect decode = ", ";", "NATIVE-EFFECT")
    if encode_effect != "pure" or decode_effect != "pure":
        _fail("NATIVE-EFFECT", "native function is not pure")
    encode_prefix = _byte(
        _between(
            lines[5],
            "fn encode(value: Value) -> Bytes = bytes(",
            ", value);",
            "NATIVE-TYPE",
        )
    )
    decode_length, decode_prefix, payload_max, fallback_error = _decode_declaration(
        lines[6]
    )
    expected_specs = _specification_lines(decode_length)
    if lines[7:12] != expected_specs:
        _fail("NATIVE-SPEC-BINDING", "specification expression differs")
    alphabet_min, alphabet_max, input_length_min, input_length_max = _bound(lines[12])
    if (
        value_min != 0
        or value_max != 3
        or payload_max != value_max
        or decode_length != 2
    ):
        _fail("NATIVE-TYPE", "finite type or decoder bound differs")
    if encode_prefix != decode_prefix:
        _fail("NATIVE-SPEC-BINDING", "encoder and decoder prefixes differ")
    if not fallback_error:
        _fail("NATIVE-NONTOTAL", "decoder has no Error fallback")
    if (alphabet_min, alphabet_max, input_length_min, input_length_max) != (
        0,
        4,
        0,
        3,
    ):
        _fail("NATIVE-TYPE", "bounded input carrier differs")
    ast = {
        "schema": AST_SCHEMA,
        "module": module,
        "value_min": value_min,
        "value_max": value_max,
        "encode_prefix": encode_prefix,
        "decode_length": decode_length,
        "decode_prefix": decode_prefix,
        "payload_max": payload_max,
        "fallback_error": fallback_error,
        "pure_functions": ["decode", "encode"],
        "specifications": CONTRACT_IDS,
        "alphabet_min": alphabet_min,
        "alphabet_max": alphabet_max,
        "input_length_min": input_length_min,
        "input_length_max": input_length_max,
        "termination_slack": 4,
    }
    if _format_source(ast).encode() != source:
        _fail("NATIVE-NONCANONICAL", "source encoding differs")
    return ast


def compile_native_artifact(ast: dict[str, Any]) -> bytes:
    """Compile the typed source tree to the frozen bytecode format."""

    return bytes(
        [
            0x50,
            0x42,
            0x56,
            0x4D,
            1,
            4,
            11,
            0x10,
            ast["encode_prefix"],
            0x11,
            0xFF,
            0x20,
            ast["decode_length"],
            0x21,
            0,
            ast["decode_prefix"],
            0x22,
            1,
            ast["payload_max"],
            0x23,
            1,
            0xFE,
        ]
    )


def validate_native_artifact(ast: dict[str, Any], artifact: bytes) -> None:
    """Validate every structural and semantic byte in a bytecode artifact."""

    if len(artifact) < 4:
        _fail("NATIVE-ARTIFACT-TRUNCATED", "artifact header is truncated")
    if artifact[:4] != b"PBVM":
        _fail("NATIVE-ARTIFACT-MAGIC", "artifact magic differs")
    if len(artifact) < 5:
        _fail("NATIVE-ARTIFACT-TRUNCATED", "artifact version is absent")
    if artifact[4] != 1:
        _fail("NATIVE-ARTIFACT-VERSION", "artifact version differs")
    if len(artifact) < 7:
        _fail("NATIVE-ARTIFACT-TRUNCATED", "section lengths are absent")
    if artifact[5:7] != bytes([4, 11]):
        _fail("NATIVE-ARTIFACT-ORDER", "section order or size differs")
    if len(artifact) < 22:
        _fail("NATIVE-ARTIFACT-TRUNCATED", "artifact body is truncated")
    if len(artifact) > 22:
        _fail("NATIVE-ARTIFACT-TRAILING", "artifact has trailing bytes")
    positions = [7, 9, 10, 11, 13, 16, 19, 21]
    opcodes = [0x10, 0x11, 0xFF, 0x20, 0x21, 0x22, 0x23, 0xFE]
    if any(
        artifact[position] != opcode for position, opcode in zip(positions, opcodes)
    ):
        _fail("NATIVE-ARTIFACT-OPCODE", "artifact opcode differs")
    immediates = (
        artifact[8],
        artifact[12],
        artifact[14],
        artifact[15],
        artifact[17],
        artifact[18],
        artifact[20],
    )
    expected = (
        ast["encode_prefix"],
        ast["decode_length"],
        0,
        ast["decode_prefix"],
        1,
        ast["payload_max"],
        1,
    )
    if immediates != expected:
        _fail("NATIVE-ARTIFACT-SEMANTICS", "artifact immediate differs")


def generate_native_smt(ast: dict[str, Any]) -> str:
    """Generate the exact five frozen SMT-LIB verification conditions."""

    return "\n".join(
        [
            "(set-logic QF_LIA)",
            "; VC round-trip",
            "(push)",
            "(declare-const v Int)",
            f"(assert (and (<= {ast['value_min']} v) (<= v {ast['value_max']})))",
            "(assert (not (= v v)))",
            "(check-sat)",
            "(pop)",
            "; VC malformed-rejection",
            "(push)",
            "(declare-const len1 Int)",
            "(declare-const b0 Int)",
            "(declare-const b1 Int)",
            f"(assert (and (<= 0 len1) (<= len1 {ast['input_length_max']}) (<= 0 b0) (<= b0 {ast['alphabet_max']}) (<= 0 b1) (<= b1 {ast['alphabet_max']})))",
            f"(assert (not (and (= len1 {ast['decode_length']}) (= b0 {ast['decode_prefix']}) (<= b1 {ast['payload_max']}))))",
            f"(assert (and (= len1 {ast['decode_length']}) (= b0 {ast['decode_prefix']}) (<= b1 {ast['payload_max']})))",
            "(check-sat)",
            "(pop)",
            "; VC canonicality",
            "(push)",
            "(declare-const c0 Int)",
            "(declare-const c1 Int)",
            f"(assert (and (= c0 {ast['decode_prefix']}) (<= 0 c1) (<= c1 {ast['payload_max']})))",
            f"(assert (not (and (= c0 {ast['encode_prefix']}) (= c1 c1))))",
            "(check-sat)",
            "(pop)",
            "; VC exact-consumption",
            "(push)",
            "(declare-const consumed Int)",
            f"(assert (= consumed {ast['decode_length']}))",
            f"(assert (not (= consumed {ast['decode_length']})))",
            "(check-sat)",
            "(pop)",
            "; VC bounded-termination",
            "(push)",
            "(declare-const steps Int)",
            "(declare-const input_len Int)",
            f"(assert (and (<= 0 input_len) (<= input_len {ast['input_length_max']}) (<= steps (+ input_len {ast['termination_slack']}))))",
            f"(assert (> steps (+ input_len {ast['termination_slack']})))",
            "(check-sat)",
            "(pop)",
            "",
        ]
    )


def reconstruct_native_report(
    root: Path, corpus_dir: Path, report_bytes: bytes
) -> dict[str, Any]:
    """Independently validate and reconstruct a Rust-produced report."""

    report = _decode_canonical(report_bytes)
    source = (root / corpus_dir / "parser.pb").read_bytes()
    attacks = _read_json(root / corpus_dir / "attacks.json")
    toolchain = _read_json(root / corpus_dir / "toolchain.json")
    _validate_attacks(attacks)
    ast = parse_native_source(source)
    artifact = compile_native_artifact(ast)
    validate_native_artifact(ast, artifact)
    smt = generate_native_smt(ast)
    solver = report.get("certificate", {}).get("solver")
    if not isinstance(solver, dict):
        _fail("NATIVE-CERT-SCHEMA", "solver receipt is absent")
    _validate_solver_receipt(toolchain, solver, smt.encode())
    candidate = _derive_report(source, solver, attacks)
    candidate["repetition_identities"] = [candidate["identity"]] * 10
    _validate_report_shape(source, attacks, report)
    if report != candidate:
        _fail("NATIVE-CERT-IDENTITY", "independent report reconstruction differs")
    return candidate


def derive_native_certificate(
    source: bytes,
    ast: dict[str, Any],
    artifact: bytes,
    solver: dict[str, Any],
) -> dict[str, Any]:
    """Derive the complete finite certificate without proof search."""

    validate_native_artifact(ast, artifact)
    value_rows = []
    for value in range(ast["value_min"], ast["value_max"] + 1):
        encoded = _execute_encode(artifact, value)
        decoded, consumed, steps = _execute_decode(artifact, encoded)
        value_rows.append(
            {
                "value": value,
                "encoded_hex": encoded.hex(),
                "decode_ok": decoded is not None,
                "decoded_value": decoded,
                "consumed": consumed,
                "steps": steps,
            }
        )
    input_rows = []
    for index, input_bytes in enumerate(_enumerate_inputs(0, 4, 3)):
        decoded, consumed, steps = _execute_decode(artifact, input_bytes)
        reencoded = (
            None if decoded is None else _execute_encode(artifact, decoded).hex()
        )
        input_rows.append(
            {
                "id": f"input:{index:03d}",
                "input_hex": input_bytes.hex(),
                "decode_ok": decoded is not None,
                "decoded_value": decoded,
                "reencoded_hex": reencoded,
                "consumed": consumed,
                "steps": steps,
            }
        )
    certificate = {
        "schema": CERTIFICATE_SCHEMA,
        "source_sha256": sha256_bytes(source),
        "artifact_sha256": sha256_bytes(artifact),
        "artifact_identity": domain_hash(ARTIFACT_DOMAIN, artifact),
        "contract_ids": CONTRACT_IDS,
        "scope": {
            "value_type": "Value",
            "value_cardinality": 4,
            "value_universal": True,
            "input_alphabet": [0, 1, 2, 3, 4],
            "maximum_input_length": 3,
            "input_exhaustive": True,
            "input_unbounded": False,
            "compiler_correspondence": "independent-dual-compilation",
        },
        "solver": deepcopy(solver),
        "value_rows": value_rows,
        "input_rows": input_rows,
        "semantic_mutants": [_evaluate_mutant(ast, mutant) for mutant in MUTANT_IDS],
        "identity": "",
    }
    certificate["identity"] = _certificate_identity(certificate)
    return certificate


def validate_native_certificate(
    source: bytes,
    ast: dict[str, Any],
    artifact: bytes,
    certificate: dict[str, Any],
) -> None:
    """Independently validate a complete native certificate."""

    _require_keys(
        certificate,
        {
            "schema",
            "source_sha256",
            "artifact_sha256",
            "artifact_identity",
            "contract_ids",
            "scope",
            "solver",
            "value_rows",
            "input_rows",
            "semantic_mutants",
            "identity",
        },
        "NATIVE-CERT-SCHEMA",
    )
    if certificate["schema"] != CERTIFICATE_SCHEMA:
        _fail("NATIVE-CERT-SCHEMA", "certificate schema differs")
    if certificate["source_sha256"] != sha256_bytes(source):
        _fail("NATIVE-CERT-SOURCE", "source identity differs")
    if certificate["artifact_sha256"] != sha256_bytes(artifact) or certificate[
        "artifact_identity"
    ] != domain_hash(ARTIFACT_DOMAIN, artifact):
        _fail("NATIVE-CERT-ARTIFACT", "artifact identity differs")
    expected_scope = {
        "value_type": "Value",
        "value_cardinality": 4,
        "value_universal": True,
        "input_alphabet": [0, 1, 2, 3, 4],
        "maximum_input_length": 3,
        "input_exhaustive": True,
        "input_unbounded": False,
        "compiler_correspondence": "independent-dual-compilation",
    }
    if certificate["scope"] != expected_scope:
        _fail("NATIVE-CERT-SCOPE", "certificate scope differs")
    if certificate["contract_ids"] != CONTRACT_IDS:
        _fail("NATIVE-CERT-INCOMPLETE", "contract set differs")
    value_rows = certificate["value_rows"]
    input_rows = certificate["input_rows"]
    value_ids = [row.get("value") for row in value_rows]
    input_ids = [row.get("id") for row in input_rows]
    if len(set(value_ids)) != len(value_ids) or len(set(input_ids)) != len(input_ids):
        _fail("NATIVE-CERT-DUPLICATE", "certificate row is duplicated")
    if value_ids != [0, 1, 2, 3] or len(input_rows) != 156:
        _fail("NATIVE-CERT-INCOMPLETE", "certificate carrier is incomplete")
    expected = derive_native_certificate(source, ast, artifact, certificate["solver"])
    if (
        value_rows != expected["value_rows"]
        or input_rows != expected["input_rows"]
        or certificate["semantic_mutants"] != expected["semantic_mutants"]
    ):
        _fail("NATIVE-CERT-TRACE", "certificate trace differs")
    if certificate["identity"] != _certificate_identity(certificate):
        _fail("NATIVE-CERT-IDENTITY", "certificate identity differs")


def _derive_report(
    source: bytes, solver: dict[str, Any], attacks: dict[str, Any]
) -> dict[str, Any]:
    ast = parse_native_source(source)
    artifact = compile_native_artifact(ast)
    smt = generate_native_smt(ast)
    _validate_smt(smt, solver["results"])
    certificate = derive_native_certificate(source, ast, artifact, solver)
    validate_native_certificate(source, ast, artifact, certificate)
    attack_results = [
        _execute_attack(source, ast, artifact, smt, certificate, attack)
        for attack in attacks["attacks"]
    ]
    report = {
        "schema": REPORT_SCHEMA,
        "source_sha256": sha256_bytes(source),
        "ast_identity": domain_hash(AST_SCHEMA, canonical_json(ast)),
        "artifact_hex": artifact.hex(),
        "artifact_sha256": sha256_bytes(artifact),
        "artifact_identity": domain_hash(ARTIFACT_DOMAIN, artifact),
        "smt_sha256": sha256_bytes(smt.encode()),
        "certificate": certificate,
        "attacks": attack_results,
        "assurance": {
            "round_trip": "universal-over-declared-u2",
            "input_properties": "bounded-exhaustive-alphabet-0-4-length-0-3",
            "examples": "tested-only",
            "artifact_correspondence": "independent-dual-compilation-assumption-bound",
            "artifact_proved": False,
        },
        "repetition_identities": [],
        "identity": "",
    }
    report["identity"] = _report_identity(report)
    return report


def _validate_report_shape(
    source: bytes, attacks: dict[str, Any], report: dict[str, Any]
) -> None:
    _require_keys(
        report,
        {
            "schema",
            "source_sha256",
            "ast_identity",
            "artifact_hex",
            "artifact_sha256",
            "artifact_identity",
            "smt_sha256",
            "certificate",
            "attacks",
            "assurance",
            "repetition_identities",
            "identity",
        },
        "NATIVE-CERT-SCHEMA",
    )
    if report["schema"] != REPORT_SCHEMA:
        _fail("NATIVE-CERT-SCHEMA", "report schema differs")
    ast = parse_native_source(source)
    artifact = compile_native_artifact(ast)
    smt = generate_native_smt(ast)
    expected_identities = (
        sha256_bytes(source),
        domain_hash(AST_SCHEMA, canonical_json(ast)),
        artifact.hex(),
        sha256_bytes(artifact),
        domain_hash(ARTIFACT_DOMAIN, artifact),
        sha256_bytes(smt.encode()),
    )
    actual_identities = (
        report["source_sha256"],
        report["ast_identity"],
        report["artifact_hex"],
        report["artifact_sha256"],
        report["artifact_identity"],
        report["smt_sha256"],
    )
    if actual_identities != expected_identities:
        _fail("NATIVE-CERT-IDENTITY", "report identities differ")
    validate_native_certificate(source, ast, artifact, report["certificate"])
    expected_attacks = [
        _execute_attack(source, ast, artifact, smt, report["certificate"], attack)
        for attack in attacks["attacks"]
    ]
    if report["attacks"] != expected_attacks or not all(
        result["exact"] for result in report["attacks"]
    ):
        _fail("NATIVE-CERT-TRACE", "report attacks differ")
    expected_assurance = {
        "round_trip": "universal-over-declared-u2",
        "input_properties": "bounded-exhaustive-alphabet-0-4-length-0-3",
        "examples": "tested-only",
        "artifact_correspondence": "independent-dual-compilation-assumption-bound",
        "artifact_proved": False,
    }
    if report["assurance"] != expected_assurance:
        _fail("NATIVE-CERT-SCOPE", "report assurance scope differs")
    identity = _report_identity(report)
    if (
        report["identity"] != identity
        or len(report["repetition_identities"]) != 10
        or any(item != identity for item in report["repetition_identities"])
    ):
        _fail("NATIVE-CERT-IDENTITY", "report repetition identity differs")


def _execute_attack(
    source: bytes,
    ast: dict[str, Any],
    artifact: bytes,
    smt: str,
    certificate: dict[str, Any],
    attack: dict[str, str],
) -> dict[str, Any]:
    try:
        if attack["class"] == "source":
            parse_native_source(_mutate_source(source, attack["action"]))
        elif attack["class"] == "artifact":
            validate_native_artifact(ast, _mutate_artifact(artifact, attack["action"]))
        elif attack["class"] == "certificate":
            candidate = deepcopy(certificate)
            _mutate_certificate(candidate, attack["action"])
            validate_native_certificate(source, ast, artifact, candidate)
        elif attack["class"] == "smt":
            candidate_smt = smt
            results = list(certificate["solver"]["results"])
            if attack["action"] == "remove-verification-condition":
                position = candidate_smt.rfind("(check-sat)\n")
                if position < 0:
                    _fail("NATIVE-SMT-INCOMPLETE", "VC is absent")
                candidate_smt = (
                    candidate_smt[:position] + candidate_smt[position + 12 :]
                )
            elif attack["action"] == "replace-solver-result":
                results[0] = "sat"
            _validate_smt(candidate_smt, results)
        else:
            _fail("NATIVE-SYNTAX", "unknown attack class")
    except NativeFailure as error:
        actual = error.code
    else:
        actual = "NATIVE-ACCEPTED"
    return {
        "id": attack["id"],
        "expected_code": attack["expected"],
        "actual_code": actual,
        "exact": actual == attack["expected"],
    }


def _mutate_source(source: bytes, action: str) -> bytes:
    text = source.decode()
    if action == "unknown-declaration":
        result = text + "foreign host;\n"
    elif action == "duplicate-module":
        result = text + "module canonical-packet;\n"
    elif action == "duplicate-function":
        result = text + "fn encode(value: Value) -> Bytes = bytes(1, value);\n"
    elif action == "replace-value-bound":
        result = text.replace("range(0, 3)", "range(0, 4)")
    elif action == "replace-prefix":
        result = text.replace("bytes(1, value)", "bytes(2, value)")
    elif action == "remove-wildcard-branch":
        result = text.replace("fallback=Error", "fallback=Missing")
    elif action == "add-unbounded-loop":
        result = text + "loop forever;\n"
    elif action == "add-undeclared-effect":
        result = text.replace("effect decode = pure", "effect decode = network")
    elif action == "remove-specification":
        result = "".join(
            line + "\n"
            for line in text.splitlines()
            if not line.startswith("spec canonicality")
        )
    elif action == "noncanonical-source":
        result = text + "\n"
    else:
        _fail("NATIVE-SYNTAX", "unknown source attack")
    return result.encode()


def _mutate_artifact(artifact: bytes, action: str) -> bytes:
    result = bytearray(artifact)
    if action == "replace-magic":
        result[0] = ord("X")
    elif action == "replace-version":
        result[4] = 2
    elif action == "replace-opcode":
        result[7] = 0x99
    elif action == "replace-immediate":
        result[8] = 2
    elif action == "truncate-artifact":
        result.pop()
    elif action == "append-artifact-byte":
        result.append(0)
    elif action == "swap-programs":
        result[5:7] = bytes([11, 4])
    else:
        _fail("NATIVE-ARTIFACT-OPCODE", "unknown artifact attack")
    return bytes(result)


def _mutate_certificate(certificate: dict[str, Any], action: str) -> None:
    if action == "replace-certificate-schema":
        certificate["schema"] = "proofbound-native-certificate/2"
    elif action == "replace-source-identity":
        certificate["source_sha256"] = _zero_sha()
    elif action == "replace-artifact-identity":
        certificate["artifact_sha256"] = _zero_sha()
    elif action == "remove-value-row":
        certificate["value_rows"].pop()
    elif action == "remove-input-row":
        certificate["input_rows"].pop()
    elif action == "duplicate-row":
        certificate["input_rows"].append(deepcopy(certificate["input_rows"][0]))
    elif action == "replace-trace-result":
        certificate["value_rows"][0]["decoded_value"] = 1
    elif action == "claim-unbounded-input":
        certificate["scope"]["input_unbounded"] = True
    elif action == "forge-certificate-identity":
        certificate["identity"] = _zero_sha()
    else:
        _fail("NATIVE-CERT-SCHEMA", "unknown certificate attack")


def _evaluate_mutant(ast: dict[str, Any], identifier: str) -> dict[str, Any]:
    for value in range(ast["value_min"], ast["value_max"] + 1):
        result = _mutant_decode(ast, identifier, bytes([ast["encode_prefix"], value]))
        if result != value:
            return {
                "id": identifier,
                "killed": True,
                "first_counterexample": f"value:{value}",
            }
    for index, input_bytes in enumerate(_enumerate_inputs(0, 4, 3)):
        result = _mutant_decode(ast, identifier, input_bytes)
        correct = (
            len(input_bytes) == 2
            and input_bytes[0] == ast["decode_prefix"]
            and input_bytes[1] <= ast["payload_max"]
        )
        if (result is not None) != correct or (
            result is not None and bytes([ast["encode_prefix"], result]) != input_bytes
        ):
            return {
                "id": identifier,
                "killed": True,
                "first_counterexample": f"input:{index:03d}",
            }
    _fail("NATIVE-CERT-TRACE", "semantic mutant survived")


def _mutant_decode(ast: dict[str, Any], identifier: str, value: bytes) -> int | None:
    valid = (
        len(value) == 2
        and value[0] == ast["decode_prefix"]
        and value[1] <= ast["payload_max"]
    )
    if identifier == "always-error":
        return None
    if identifier == "always-success":
        return min(value[1] if len(value) > 1 else 0, 3)
    if identifier == "accept-noncanonical" and value == bytes([0]):
        return 0
    if identifier == "accept-trailing" and len(value) == 3 and valid is False:
        if value[0] == ast["decode_prefix"] and value[1] <= ast["payload_max"]:
            return value[1]
    if identifier == "ignore-length" and value and value[0] == ast["decode_prefix"]:
        return min(value[1] if len(value) > 1 else 0, 3)
    if identifier == "payload-substitution" and valid:
        return (value[1] + 1) % 4
    return value[1] if valid else None


def _execute_encode(artifact: bytes, value: int) -> bytes:
    if value > artifact[18]:
        _fail("NATIVE-TYPE", "value is outside finite type")
    return bytes([artifact[8], value])


def _execute_decode(artifact: bytes, value: bytes) -> tuple[int | None, int, int]:
    if len(value) != artifact[12]:
        return None, len(value), 1
    if value[artifact[14]] != artifact[15]:
        return None, len(value), 2
    if value[artifact[17]] > artifact[18]:
        return None, len(value), 3
    return value[artifact[20]], len(value), 4


def _enumerate_inputs(minimum: int, maximum: int, maximum_length: int) -> list[bytes]:
    output = [b""]
    prior = [b""]
    for _ in range(maximum_length):
        current = [
            prefix + bytes([byte])
            for prefix in prior
            for byte in range(minimum, maximum + 1)
        ]
        output.extend(current)
        prior = current
    return output


def _validate_solver_receipt(
    toolchain: dict[str, Any], solver: dict[str, Any], smt: bytes
) -> None:
    _require_keys(toolchain, {"schema", "solver"}, "NATIVE-SMT-RESULT")
    registration = toolchain["solver"]
    _require_keys(
        registration,
        {
            "program",
            "argv",
            "version_argv",
            "expected_version",
            "expected_results",
        },
        "NATIVE-SMT-RESULT",
    )
    _require_keys(
        solver,
        {
            "program",
            "argv",
            "executable_sha256",
            "version",
            "input_sha256",
            "results",
            "stdout_sha256",
            "stderr_sha256",
        },
        "NATIVE-SMT-RESULT",
    )
    program = registration["program"]
    executable = shutil.which(program)
    if executable is None:
        _fail("NATIVE-SMT-RESULT", "registered solver is unavailable")
    stdout = ("\n".join(registration["expected_results"]) + "\n").encode()
    expected = {
        "program": program,
        "argv": registration["argv"],
        "executable_sha256": sha256_bytes(Path(executable).resolve().read_bytes()),
        "version": registration["expected_version"],
        "input_sha256": sha256_bytes(smt),
        "results": registration["expected_results"],
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(b""),
    }
    if toolchain["schema"] != TOOLCHAIN_SCHEMA or solver != expected:
        _fail("NATIVE-SMT-RESULT", "solver receipt differs")


def _validate_smt(smt: str, results: list[str]) -> None:
    if smt.count("; VC ") != 5 or smt.count("(check-sat)\n") != 5:
        _fail("NATIVE-SMT-INCOMPLETE", "verification condition set differs")
    if results != ["unsat"] * 5:
        _fail("NATIVE-SMT-RESULT", "solver result differs")


def _validate_attacks(corpus: dict[str, Any]) -> None:
    _require_keys(corpus, {"schema", "attacks"}, "NATIVE-SYNTAX")
    if corpus["schema"] != ATTACKS_SCHEMA or len(corpus["attacks"]) != 28:
        _fail("NATIVE-SYNTAX", "attack corpus differs")
    ids = [attack["id"] for attack in corpus["attacks"]]
    if ids != sorted(set(ids)):
        _fail("NATIVE-DUPLICATE", "attack IDs differ")


def _certificate_identity(certificate: dict[str, Any]) -> str:
    candidate = deepcopy(certificate)
    candidate["identity"] = ""
    return domain_hash(CERTIFICATE_SCHEMA, canonical_json(candidate))


def _report_identity(report: dict[str, Any]) -> str:
    candidate = deepcopy(report)
    candidate["identity"] = ""
    candidate["repetition_identities"] = []
    return domain_hash(REPORT_SCHEMA, canonical_json(candidate))


def _format_source(ast: dict[str, Any]) -> str:
    specifications = "\n".join(_specification_lines(ast["decode_length"]))
    return (
        f"module {ast['module']};\n"
        f"type Value = range({ast['value_min']}, {ast['value_max']});\n"
        "type Decode = result(Value, Error);\n"
        "effect encode = pure;\n"
        "effect decode = pure;\n"
        f"fn encode(value: Value) -> Bytes = bytes({ast['encode_prefix']}, value);\n"
        f"fn decode(input: Bytes) -> Decode = match-exact(input, length={ast['decode_length']}, prefix={ast['decode_prefix']}, payload-max={ast['payload_max']}, fallback=Error);\n"
        f"{specifications}\n"
        f"bound BytesBounded = bytes(alphabet={ast['alphabet_min']}..{ast['alphabet_max']}, length={ast['input_length_min']}..{ast['input_length_max']});\n"
    )


def _specification_lines(consumption: int) -> list[str]:
    return [
        "spec round-trip = forall value: Value => decode(encode(value)) == Ok(value);",
        "spec malformed-rejection = forall input: BytesBounded => malformed(input) implies decode(input) == Error;",
        "spec canonicality = forall input: BytesBounded => is-ok(decode(input)) implies encode(value-of(decode(input))) == input;",
        f"spec exact-consumption = forall input: BytesBounded => is-ok(decode(input)) implies consumed(input) == {consumption};",
        "spec bounded-termination = forall input: BytesBounded => steps(decode(input)) <= length(input) + 4;",
    ]


def _decode_declaration(line: str) -> tuple[int, int, int, bool]:
    body = _between(
        line,
        "fn decode(input: Bytes) -> Decode = match-exact(input, length=",
        ");",
        "NATIVE-TYPE",
    )
    parts = body.split(", ")
    if len(parts) != 4:
        _fail("NATIVE-TYPE", "decoder fields differ")
    length = _byte(parts[0])
    prefix = _byte(_prefix(parts[1], "prefix=", "NATIVE-TYPE"))
    maximum = _byte(_prefix(parts[2], "payload-max=", "NATIVE-TYPE"))
    return length, prefix, maximum, parts[3] == "fallback=Error"


def _bound(line: str) -> tuple[int, int, int, int]:
    body = _between(
        line,
        "bound BytesBounded = bytes(alphabet=",
        ");",
        "NATIVE-TYPE",
    )
    try:
        alphabet, lengths = body.split(", length=", 1)
        a0, a1 = alphabet.split("..", 1)
        l0, l1 = lengths.split("..", 1)
    except ValueError:
        _fail("NATIVE-TYPE", "bound fields differ")
    return _byte(a0), _byte(a1), _byte(l0), _byte(l1)


def _pair(line: str, prefix: str, suffix: str) -> tuple[int, int]:
    body = _between(line, prefix, suffix, "NATIVE-TYPE")
    try:
        left, right = body.split(", ", 1)
    except ValueError:
        _fail("NATIVE-TYPE", "range values differ")
    return _byte(left), _byte(right)


def _byte(value: str) -> int:
    if len(value) > 1 and value.startswith("0"):
        _fail("NATIVE-NONCANONICAL", "integer has a leading zero")
    try:
        parsed = int(value)
    except ValueError:
        _fail("NATIVE-TYPE", "integer differs")
    if not 0 <= parsed <= 255 or str(parsed) != value:
        _fail("NATIVE-TYPE", "integer differs")
    return parsed


def _between(line: str, prefix: str, suffix: str, code: str) -> str:
    if not line.startswith(prefix) or not line.endswith(suffix):
        _fail(code, "declaration differs")
    return line[len(prefix) : -len(suffix)]


def _prefix(value: str, prefix: str, code: str) -> str:
    if not value.startswith(prefix):
        _fail(code, "field differs")
    return value[len(prefix) :]


def _read_json(path: Path) -> dict[str, Any]:
    return _decode_json(path.read_bytes())


def _decode_canonical(payload: bytes) -> dict[str, Any]:
    value = _decode_json(payload)
    if canonical_json(value) != payload:
        _fail("NATIVE-CERT-SCHEMA", "report JSON is not canonical")
    return value


def _decode_json(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("NATIVE-SYNTAX", str(error))
    if not isinstance(value, dict):
        _fail("NATIVE-SYNTAX", "JSON document must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("NATIVE-DUPLICATE", f"duplicate JSON key {key}")
        value[key] = item
    return value


def _require_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        _fail(code, "object fields differ")


def _zero_sha() -> str:
    return "sha256:" + "0" * 64


def _fail(code: str, message: str) -> NoReturn:
    raise NativeFailure(code, message)
