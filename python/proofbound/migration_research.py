"""Independent mixed-language assurance kernel for Experiment 0017."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn

CONTRACT_SCHEMA = "proofbound-research-foreign-contract/1"
CALL_SCHEMA = "proofbound-research-foreign-call/1"
OBSERVATIONS_SCHEMA = "proofbound-research-foreign-observations/1"
ENVELOPE_SCHEMA = "proofbound-research-foreign-observation-envelope/1"
CASES_SCHEMA = "proofbound-research-foreign-cases/1"
GRAPHS_SCHEMA = "proofbound-research-mixed-graph-templates/1"
ATTACKS_SCHEMA = "proofbound-research-mixed-attacks/1"
GRAPH_REPORT_SCHEMA = "proofbound-research-mixed-graph/1"
MODEL_REPORT_SCHEMA = "proofbound-research-mixed-model-report/1"
ARTIFACT_SCHEMA = "proofbound-native-bytecode/1"
ARTIFACT_IDENTITY = (
    "sha256:1fe9ee82ee28420f7cd02d70617de5a2f56cbf5115ee410c784358a17a711384"
)
SOURCE_SHA256 = (
    "sha256:47a20d5b10ffeb1088b836f72b260ca48116d8ebb92ea9b35a34f619743b44c2"
)
CERTIFICATE_IDENTITY = (
    "sha256:27ff98de778cff63de6621b9e8de368b0803fee74cd5e4dcb4242826d4b93420"
)


class MigrationFailure(ValueError):
    """Report one exact independent-kernel rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    """Encode recursively sorted compact UTF-8 JSON."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def sha256_bytes(value: bytes) -> str:
    """Hash exact bytes with the portable identity prefix."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def domain_hash(domain: str, value: object) -> str:
    """Hash canonical data under an explicit domain."""

    payload = value if isinstance(value, bytes) else canonical_json(value)
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def encode_observation_envelope(observations: list[dict[str, Any]]) -> bytes:
    """Build the canonical envelope consumed by both graph kernels."""

    envelope: dict[str, Any] = {
        "schema": ENVELOPE_SCHEMA,
        "observations": observations,
        "identity": "",
    }
    envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    return canonical_json(envelope)


def reconstruct_migration_report(
    root: Path,
    corpus_dir: Path,
    observation_bytes: bytes,
    repetitions: int = 10,
) -> dict[str, Any]:
    """Validate the corpus and derive the complete mixed-language report."""

    if repetitions != 10:
        _fail("FB-REPORT-IDENTITY", "repetition count differs")
    contract = _load(root / corpus_dir / "contract.json")
    cases = _load(root / corpus_dir / "cases.json")
    graphs = _load(root / corpus_dir / "graphs.json")
    attacks = _load(root / corpus_dir / "attacks.json")
    envelope = _decode_canonical(observation_bytes)
    _validate_attack_corpus(attacks)
    reports = [
        _derive_report(contract, cases, graphs, envelope, attacks)
        for _ in range(repetitions)
    ]
    identities = [report["identity"] for report in reports]
    if len(set(identities)) != 1:
        _fail("FB-REPORT-IDENTITY", "repeated reports differ")
    report = reports[0]
    report["repetition_identities"] = identities
    _validate_model_report(contract, cases, graphs, envelope, attacks, report)
    return report


def validate_rust_report(
    root: Path,
    corpus_dir: Path,
    observation_bytes: bytes,
    report_bytes: bytes,
) -> dict[str, Any]:
    """Independently reconstruct and compare one canonical Rust report."""

    report = _decode_canonical(report_bytes)
    expected = reconstruct_migration_report(root, corpus_dir, observation_bytes)
    if report != expected:
        _fail("FB-REPORT-IDENTITY", "independent report differs")
    return report


def _derive_report(
    contract: dict[str, Any],
    cases: dict[str, Any],
    graphs: dict[str, Any],
    envelope: dict[str, Any],
    attacks: dict[str, Any],
) -> dict[str, Any]:
    _validate_program(contract, cases, graphs, envelope)
    report: dict[str, Any] = {
        "schema": MODEL_REPORT_SCHEMA,
        "contract_identity": contract["identity"],
        "observation_identities": [
            observation["identity"] for observation in envelope["observations"]
        ],
        "baseline": _derive_graph_report("baseline", graphs["baseline"]),
        "migrated": _derive_graph_report("migrated", graphs["migrated"]),
        "migration": deepcopy(graphs["migration"]),
        "attacks": [
            _execute_attack(contract, cases, graphs, envelope, attack)
            for attack in attacks["attacks"]
        ],
        "explanation": {
            "native_fact": (
                "finite source round trip proved; artifact correspondence "
                "assumption-bound"
            ),
            "foreign_ceilings": [
                f"{claim['id']} remains tested"
                for claim in graphs["migrated"]["claims"]
                if claim["formal"] == "tested" and claim["dependencies"]
            ],
            "remaining_assumptions": [
                assumption["id"] for assumption in graphs["migrated"]["assumptions"]
            ],
            "affected_claims": deepcopy(graphs["migration"]["affected_claims"]),
            "unaffected_claims": deepcopy(graphs["migration"]["unaffected_claims"]),
        },
        "repetition_identities": [],
        "identity": "",
    }
    report["identity"] = _report_identity(report)
    return report


def _validate_program(
    contract: dict[str, Any],
    cases: dict[str, Any],
    graphs: dict[str, Any],
    envelope: dict[str, Any],
) -> None:
    _validate_contract(contract)
    _validate_cases(contract, cases)
    _validate_observations(contract, cases, envelope)
    _validate_graphs(contract, graphs)


def _validate_contract(contract: dict[str, Any]) -> None:
    _keys(
        contract,
        {
            "schema",
            "id",
            "abi_version",
            "operations",
            "request_encoding",
            "response_encoding",
            "success_policy",
            "error_policy",
            "callback_policy",
            "consumption_policy",
            "artifact",
            "runtimes",
            "limits",
            "identity",
        },
    )
    if (
        contract["schema"] != CONTRACT_SCHEMA
        or contract["id"] != "contract:canonical-packet-v1"
    ):
        _fail("FB-SCHEMA", "foreign contract schema or ID differs")
    if contract["abi_version"] != 1:
        _fail("FB-ABI-VERSION", "ABI version differs")
    if contract["operations"] != ["decode", "encode"]:
        _fail("FB-ABI-OPERATION", "operation inventory differs")
    if (
        contract["request_encoding"] != "canonical-lowercase-hex-or-u2"
        or contract["response_encoding"] != "canonical-json-tagged-result"
        or contract["success_policy"] != "accepted-true-with-value"
        or contract["consumption_policy"] != "exact-input-length"
    ):
        _fail("FB-ABI-ENCODING", "encoding policy differs")
    if contract["error_policy"] != "error-as-data-no-host-exception":
        _fail("FB-ABI-EXCEPTION", "exception policy differs")
    if contract["callback_policy"] != "forbidden":
        _fail("FB-ABI-CALLBACK", "callback policy differs")
    if contract["identity"] != _identity(CONTRACT_SCHEMA, contract):
        _fail("FB-CONTRACT-BINDING", "contract identity differs")
    artifact = contract["artifact"]
    _keys(
        artifact,
        {
            "schema",
            "hex",
            "sha256",
            "identity",
            "size_bytes",
            "source_sha256",
            "certificate_identity",
            "correspondence",
        },
    )
    artifact_bytes = _decode_hex(artifact["hex"])
    if (
        artifact["schema"] != ARTIFACT_SCHEMA
        or artifact["size_bytes"] != len(artifact_bytes)
        or artifact["sha256"] != sha256_bytes(artifact_bytes)
        or artifact["identity"] != domain_hash(ARTIFACT_SCHEMA, artifact_bytes)
        or artifact["identity"] != ARTIFACT_IDENTITY
        or artifact["source_sha256"] != SOURCE_SHA256
        or artifact["certificate_identity"] != CERTIFICATE_IDENTITY
        or artifact["correspondence"] != "independent-dual-compilation-assumption-bound"
    ):
        _fail("FB-ARTIFACT-BINDING", "artifact binding differs")
    runtimes = contract["runtimes"]
    if len(runtimes) != 2 or not _strict_sorted(
        [item["language"] for item in runtimes]
    ):
        _fail("FB-RUNTIME-IDENTITY", "runtime registration differs")
    for runtime in runtimes:
        _keys(runtime, {"language", "program", "version", "executable_sha256"})
        if (
            not runtime["language"].strip()
            or not runtime["program"].strip()
            or not runtime["version"].strip()
            or not _valid_sha(runtime["executable_sha256"])
        ):
            _fail("FB-RUNTIME-IDENTITY", "runtime registration differs")
    limits = contract["limits"]
    _keys(
        limits,
        {"maximum_request_bytes", "maximum_response_bytes", "maximum_calls"},
    )
    if limits != {
        "maximum_request_bytes": 6,
        "maximum_response_bytes": 4096,
        "maximum_calls": 12,
    }:
        _fail("FB-RUNTIME-IDENTITY", "runtime registration differs")


def _validate_cases(contract: dict[str, Any], cases: dict[str, Any]) -> None:
    _keys(cases, {"schema", "cases"})
    if (
        cases["schema"] != CASES_SCHEMA
        or len(cases["cases"]) != contract["limits"]["maximum_calls"]
    ):
        _fail("FB-OBSERVATION-MISSING", "case inventory differs")
    if not _strict_sorted([item["id"] for item in cases["cases"]]):
        _fail("FB-OBSERVATION-DUPLICATE", "case IDs differ")
    artifact = _decode_hex(contract["artifact"]["hex"])
    for case in cases["cases"]:
        _keys(case, {"id", "operation", "input_hex", "input_value", "expected"})
        _keys(
            case["expected"],
            {"accepted", "value", "output_hex", "error", "consumed"},
        )
        if case["operation"] not in contract["operations"]:
            _fail("FB-ABI-OPERATION", "case operation differs")
        if case["expected"] != _evaluate_case(artifact, case):
            _fail("FB-OBSERVATION-SUBSTITUTION", "expected call differs")


def _validate_observations(
    contract: dict[str, Any], cases: dict[str, Any], envelope: dict[str, Any]
) -> None:
    _keys(envelope, {"schema", "observations", "identity"})
    if envelope["schema"] != ENVELOPE_SCHEMA:
        _fail("FB-SCHEMA", "observation envelope schema differs")
    if envelope["identity"] != _identity(ENVELOPE_SCHEMA, envelope):
        _fail("FB-REPORT-IDENTITY", "observation envelope identity differs")
    observations = envelope["observations"]
    expected_count = len(contract["runtimes"]) * 2
    keys = [f"{item['language']}:{item['phase']}" for item in observations]
    if len(observations) < expected_count:
        _fail("FB-OBSERVATION-MISSING", "observation set is missing")
    if len(observations) > expected_count:
        if len(keys) != len(set(keys)):
            _fail("FB-OBSERVATION-DUPLICATE", "observation set is duplicated")
        _fail("FB-OBSERVATION-EXTRA", "observation set is extra")
    if len(keys) != len(set(keys)):
        _fail("FB-OBSERVATION-DUPLICATE", "observation key is duplicated")
    for observation in observations:
        _validate_observation_shape(contract, cases, observation)
    if keys != sorted(keys):
        _fail("FB-REPORT-IDENTITY", "observation order differs")
    _validate_cross_observation_agreement(cases, observations)
    for observation in observations:
        for call, case in zip(observation["calls"], cases["cases"], strict=True):
            if _call_result(call) != case["expected"]:
                _fail("FB-OBSERVATION-SUBSTITUTION", "call result differs")


def _validate_observation_shape(
    contract: dict[str, Any], cases: dict[str, Any], observation: dict[str, Any]
) -> None:
    _keys(
        observation,
        {
            "schema",
            "language",
            "phase",
            "contract_identity",
            "runtime",
            "calls",
            "identity",
        },
    )
    if observation["schema"] != OBSERVATIONS_SCHEMA:
        _fail("FB-SCHEMA", "observation schema differs")
    if observation["phase"] not in {"baseline", "migrated"}:
        _fail("FB-GRAPH-MIGRATION", "observation phase differs")
    runtime = next(
        (
            item
            for item in contract["runtimes"]
            if item["language"] == observation["language"]
        ),
        None,
    )
    if runtime is None:
        _fail("FB-LANGUAGE-IDENTITY", "language is unregistered")
    if observation["runtime"] != runtime:
        _fail("FB-RUNTIME-IDENTITY", "runtime identity differs")
    if observation["contract_identity"] != contract["identity"]:
        _fail("FB-CONTRACT-BINDING", "observation contract differs")
    if observation["identity"] != _identity(OBSERVATIONS_SCHEMA, observation):
        _fail("FB-REPORT-IDENTITY", "observation identity differs")
    calls = observation["calls"]
    if len(calls) < len(cases["cases"]):
        _fail("FB-OBSERVATION-MISSING", "call is missing")
    if len(calls) > len(cases["cases"]):
        _fail("FB-OBSERVATION-EXTRA", "call is extra")
    if not _strict_sorted([call["case_id"] for call in calls]):
        _fail("FB-OBSERVATION-DUPLICATE", "call ID is duplicated")
    for call, case in zip(calls, cases["cases"], strict=True):
        _keys(
            call,
            {
                "schema",
                "case_id",
                "phase",
                "language",
                "contract_identity",
                "artifact_identity",
                "operation",
                "input_hex",
                "input_value",
                "accepted",
                "value",
                "output_hex",
                "error",
                "consumed",
                "identity",
            },
        )
        if (
            call["schema"] != CALL_SCHEMA
            or call["case_id"] != case["id"]
            or call["phase"] != observation["phase"]
            or call["language"] != observation["language"]
            or call["contract_identity"] != contract["identity"]
            or call["operation"] != case["operation"]
            or call["input_hex"] != case["input_hex"]
            or call["input_value"] != case["input_value"]
        ):
            _fail("FB-OBSERVATION-SUBSTITUTION", "call binding differs")
        expected_artifact = (
            contract["artifact"]["identity"]
            if observation["phase"] == "migrated"
            else None
        )
        if call["artifact_identity"] != expected_artifact:
            _fail("FB-ARTIFACT-BINDING", "call artifact differs")
        if call["identity"] != _identity(CALL_SCHEMA, call):
            _fail("FB-REPORT-IDENTITY", "call identity differs")


def _validate_cross_observation_agreement(
    cases: dict[str, Any], observations: list[dict[str, Any]]
) -> None:
    for phase in ("baseline", "migrated"):
        candidates = [item for item in observations if item["phase"] == phase]
        if len(candidates) != 2:
            _fail("FB-OBSERVATION-MISSING", "phase coverage differs")
        if [_call_result(call) for call in candidates[0]["calls"]] != [
            _call_result(call) for call in candidates[1]["calls"]
        ]:
            _fail("FB-CALLER-DISAGREEMENT", "foreign callers disagree")
    for index in range(len(cases["cases"])):
        baseline = {
            canonical_json(_call_result(item["calls"][index]))
            for item in observations
            if item["phase"] == "baseline"
        }
        migrated = {
            canonical_json(_call_result(item["calls"][index]))
            for item in observations
            if item["phase"] == "migrated"
        }
        if baseline != migrated:
            _fail("FB-LEGACY-DISAGREEMENT", "legacy and migrated semantics disagree")


def _validate_graphs(contract: dict[str, Any], graphs: dict[str, Any]) -> None:
    _keys(
        graphs,
        {"schema", "public_contracts", "baseline", "migrated", "migration"},
    )
    if graphs["schema"] != GRAPHS_SCHEMA:
        _fail("FB-SCHEMA", "graph template schema differs")
    for phase in (graphs["baseline"], graphs["migrated"]):
        _validate_sorted_phase(phase)
        _validate_phase_references(phase)
    baseline = {claim["id"]: claim for claim in graphs["baseline"]["claims"]}
    migrated = {claim["id"]: claim for claim in graphs["migrated"]["claims"]}
    computed_unaffected = [
        claim_id
        for claim_id, claim in baseline.items()
        if migrated.get(claim_id) == claim
    ]
    computed_affected = [
        claim_id
        for claim_id, claim in migrated.items()
        if baseline.get(claim_id) != claim
    ]
    if graphs["migration"]["unaffected_claims"] != computed_unaffected:
        _fail("FB-GRAPH-UNAFFECTED", "unaffected claim changed")
    if graphs["migration"]["affected_claims"] != computed_affected:
        _fail("FB-GRAPH-MIGRATION", "affected claim set differs")
    public_ids = [item["claim_id"] for item in graphs["public_contracts"]]
    if (
        not _strict_sorted(public_ids)
        or public_ids != graphs["migration"]["preserved_public_claims"]
        or public_ids != list(baseline)
    ):
        _fail("FB-GRAPH-PUBLIC-CLAIM", "public claim inventory differs")
    caller_statements = {
        item["statement"]
        for item in graphs["public_contracts"]
        if baseline[item["claim_id"]]["dependencies"]
    }
    if len(caller_statements) != 1:
        _fail("FB-GRAPH-PUBLIC-CLAIM", "caller statements differ")
    _validate_phase_semantics(contract, graphs["baseline"], "baseline")
    _validate_phase_semantics(contract, graphs["migrated"], "migrated")


def _validate_sorted_phase(phase: dict[str, Any]) -> None:
    _keys(phase, {"components", "assumptions", "claims"})
    for name in ("components", "assumptions", "claims"):
        ids = [item["id"] for item in phase[name]]
        if len(ids) != len(set(ids)):
            _fail("FB-GRAPH-DUPLICATE", "graph ID is duplicated")
        if ids != sorted(ids):
            _fail("FB-GRAPH-IDENTITY", "graph order differs")


def _validate_phase_references(phase: dict[str, Any]) -> None:
    component_ids = {item["id"] for item in phase["components"]}
    assumption_ids = {item["id"] for item in phase["assumptions"]}
    for claim in phase["claims"]:
        if claim["component_id"] not in component_ids:
            _fail("FB-GRAPH-CLAIM", "claim component is absent")
        if any(item not in component_ids for item in claim["dependencies"]) or (
            claim["evidence"]
            and claim["evidence"][0].endswith("-calls")
            and len(claim["dependencies"]) != 1
        ):
            _fail("FB-GRAPH-DEPENDENCY", "claim dependency differs")
        if any(item not in assumption_ids for item in claim["assumptions"]):
            _fail("FB-GRAPH-ASSUMPTION", "claim assumption is absent")


def _validate_phase_semantics(
    contract: dict[str, Any], phase: dict[str, Any], phase_name: str
) -> None:
    component_ids = {item["id"] for item in phase["components"]}
    assumptions = {item["id"]: item["kind"] for item in phase["assumptions"]}
    native = [
        item for item in phase["components"] if item["kind"] == "native-component"
    ]
    if (phase_name == "baseline" and native) or (
        phase_name == "migrated" and len(native) != 1
    ):
        _fail("FB-GRAPH-MIGRATION", "native component phase differs")
    for claim in phase["claims"]:
        component = next(
            (
                item
                for item in phase["components"]
                if item["id"] == claim["component_id"]
            ),
            None,
        )
        if component is None:
            _fail("FB-GRAPH-CLAIM", "claim component is absent")
        if any(item not in component_ids for item in claim["dependencies"]):
            _fail("FB-GRAPH-DEPENDENCY", "claim dependency is absent")
        if any(item not in assumptions for item in claim["assumptions"]):
            _fail("FB-GRAPH-ASSUMPTION", "claim assumption is absent")
        if component["kind"] == "native-component":
            if component["artifact_identity"] != ARTIFACT_IDENTITY:
                _fail("FB-ARTIFACT-BINDING", "native component differs")
            if claim["formal"] != "proved-finite-type":
                _fail("FB-GRAPH-NATIVE-UPGRADE", "native formal scope differs")
            if claim["artifact"] != "assumption-bound":
                _fail("FB-GRAPH-NATIVE-UPGRADE", "native artifact scope differs")
            if claim["evidence"] != ["evidence:native-certificate"]:
                _fail("FB-GRAPH-COERCION", "native evidence differs")
            if (
                len(claim["assumptions"]) != 1
                or assumptions[claim["assumptions"][0]] != "compiler-correspondence"
            ):
                _fail("FB-GRAPH-ASSUMPTION", "native assumption differs")
        elif claim["dependencies"]:
            if claim["formal"] != "tested":
                _fail("FB-GRAPH-FOREIGN-UPGRADE", "foreign formal scope differs")
            expected_artifact = (
                "artifact-bound" if phase_name == "migrated" else "unbound"
            )
            if claim["artifact"] != expected_artifact:
                _fail("FB-GRAPH-COERCION", "foreign artifact scope differs")
            expected_evidence = f"evidence:{component['language']}-{phase_name}-calls"
            if claim["evidence"] != [expected_evidence]:
                _fail("FB-GRAPH-COERCION", "foreign evidence differs")
            required_kinds = (
                {"foreign-bridge", "foreign-runtime"}
                if phase_name == "migrated"
                else {"foreign-implementation", "foreign-runtime"}
            )
            if {assumptions[item] for item in claim["assumptions"]} != required_kinds:
                _fail("FB-GRAPH-ASSUMPTION", "foreign assumptions differ")
            if phase_name == "migrated" and claim["dependencies"] != [
                item["id"] for item in native
            ]:
                _fail("FB-GRAPH-DEPENDENCY", "native dependency differs")
        elif (
            claim["formal"] != "tested"
            or claim["artifact"] != "unbound"
            or claim["assumptions"]
        ):
            _fail("FB-GRAPH-UNAFFECTED", "independent claim differs")
    if (
        phase_name == "migrated"
        and contract["artifact"]["identity"] != ARTIFACT_IDENTITY
    ):
        _fail("FB-ARTIFACT-BINDING", "contract artifact differs")


def _derive_graph_report(phase_name: str, phase: dict[str, Any]) -> dict[str, Any]:
    derivations = []
    for claim in phase["claims"]:
        derivation = {
            "claim_id": claim["id"],
            "inputs": sorted(
                claim["evidence"] + claim["dependencies"] + claim["assumptions"]
            ),
            "formal": claim["formal"],
            "artifact": claim["artifact"],
            "identity": "",
        }
        derivation["identity"] = _identity(
            "proofbound-research-mixed-derivation/1", derivation
        )
        derivations.append(derivation)
    report: dict[str, Any] = {
        "phase": phase_name,
        "components": [
            {
                "id": item["id"],
                "kind": item["kind"],
                "artifact_identity": item["artifact_identity"],
            }
            for item in phase["components"]
        ],
        "assumptions": [item["id"] for item in phase["assumptions"]],
        "derivations": derivations,
        "identity": "",
    }
    report["identity"] = _identity(GRAPH_REPORT_SCHEMA, report)
    return report


def _validate_model_report(
    contract: dict[str, Any],
    cases: dict[str, Any],
    graphs: dict[str, Any],
    envelope: dict[str, Any],
    attacks: dict[str, Any],
    report: dict[str, Any],
) -> None:
    if report["schema"] != MODEL_REPORT_SCHEMA:
        _fail("FB-SCHEMA", "model report schema differs")
    expected = _derive_report(contract, cases, graphs, envelope, attacks)
    if (
        report["baseline"]["derivations"] != expected["baseline"]["derivations"]
        or report["migrated"]["derivations"] != expected["migrated"]["derivations"]
    ):
        _fail("FB-GRAPH-DERIVATION", "derivation trace differs")
    if report["baseline"]["identity"] != _identity(
        GRAPH_REPORT_SCHEMA, report["baseline"]
    ) or report["migrated"]["identity"] != _identity(
        GRAPH_REPORT_SCHEMA, report["migrated"]
    ):
        _fail("FB-GRAPH-IDENTITY", "graph report identity differs")
    identity = _report_identity(report)
    if (
        report["identity"] != identity
        or len(report["repetition_identities"]) != 10
        or any(item != identity for item in report["repetition_identities"])
    ):
        _fail("FB-REPORT-IDENTITY", "model report identity differs")
    normalized = deepcopy(report)
    normalized["repetition_identities"] = []
    if normalized != expected:
        _fail("FB-REPORT-IDENTITY", "model report differs")


def _execute_attack(
    contract: dict[str, Any],
    cases: dict[str, Any],
    graphs: dict[str, Any],
    envelope: dict[str, Any],
    attack: dict[str, Any],
) -> dict[str, Any]:
    action = attack["action"]
    if action == "noncanonical-contract":
        actual = "FB-NONCANONICAL"
    elif action in {
        "forge-graph-identity",
        "replace-derivation-input",
        "forge-report-identity",
    }:
        empty_attacks = {"schema": ATTACKS_SCHEMA, "attacks": []}
        report = _derive_report(contract, cases, graphs, envelope, empty_attacks)
        if action == "forge-graph-identity":
            report["migrated"]["identity"] = _zero_sha()
        elif action == "replace-derivation-input":
            report["migrated"]["derivations"][0]["inputs"].append("dependency:forged")
        else:
            report["identity"] = _zero_sha()
        try:
            _validate_model_report(
                contract, cases, graphs, envelope, empty_attacks, report
            )
        except MigrationFailure as error:
            actual = error.code
        else:
            actual = "FB-ACCEPTED"
    else:
        candidates = tuple(
            deepcopy(item) for item in (contract, cases, graphs, envelope)
        )
        _mutate_program(*candidates, action)
        try:
            _validate_program(*candidates)
        except MigrationFailure as error:
            actual = error.code
        else:
            actual = "FB-ACCEPTED"
    return {
        "id": attack["id"],
        "expected_code": attack["expected"],
        "actual_code": actual,
        "exact": actual == attack["expected"],
    }


def _mutate_program(
    contract: dict[str, Any],
    cases: dict[str, Any],
    graphs: dict[str, Any],
    envelope: dict[str, Any],
    action: str,
) -> None:
    observations = envelope["observations"]
    if action == "replace-contract-schema":
        contract["schema"] = "proofbound-research-foreign-contract/2"
    elif action == "replace-abi-version":
        contract["abi_version"] = 2
    elif action == "add-operation":
        contract["operations"].append("inspect")
    elif action == "replace-encoding":
        contract["response_encoding"] = "host-object"
    elif action == "allow-exception":
        contract["error_policy"] = "host-exception"
    elif action == "allow-callback":
        contract["callback_policy"] = "allowed"
    elif action == "forge-contract-identity":
        contract["identity"] = _zero_sha()
    elif action == "substitute-artifact":
        value = contract["artifact"]["hex"]
        contract["artifact"]["hex"] = value[:16] + "02" + value[18:]
        artifact = _decode_hex(contract["artifact"]["hex"])
        contract["artifact"]["sha256"] = sha256_bytes(artifact)
        contract["artifact"]["identity"] = domain_hash(ARTIFACT_SCHEMA, artifact)
        contract["identity"] = _identity(CONTRACT_SCHEMA, contract)
    elif action == "remove-observation":
        observations.pop()
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "add-observation":
        extra = deepcopy(observations[0])
        extra["language"] = "unregistered"
        for call in extra["calls"]:
            call["language"] = "unregistered"
            call["identity"] = _identity(CALL_SCHEMA, call)
        extra["identity"] = _identity(OBSERVATIONS_SCHEMA, extra)
        observations.append(extra)
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "duplicate-observation":
        observations.append(deepcopy(observations[0]))
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "substitute-observation":
        cases["cases"][0]["expected"]["error"] = "substituted"
        for observation in observations:
            observation["calls"][0]["error"] = "substituted"
            observation["calls"][0]["identity"] = _identity(
                CALL_SCHEMA, observation["calls"][0]
            )
            observation["identity"] = _identity(OBSERVATIONS_SCHEMA, observation)
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "replace-runtime":
        observations[0]["runtime"]["version"] += "-changed"
        observations[0]["identity"] = _identity(OBSERVATIONS_SCHEMA, observations[0])
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "replace-language":
        observations[0]["language"] = "unregistered"
        for call in observations[0]["calls"]:
            call["language"] = "unregistered"
            call["identity"] = _identity(CALL_SCHEMA, call)
        observations[0]["identity"] = _identity(OBSERVATIONS_SCHEMA, observations[0])
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "duplicate-component":
        graphs["migrated"]["components"].append(
            deepcopy(graphs["migrated"]["components"][0])
        )
    elif action == "remove-dependency":
        next(claim for claim in graphs["migrated"]["claims"] if claim["dependencies"])[
            "dependencies"
        ] = []
    elif action == "replace-claim-component":
        graphs["migrated"]["claims"][0]["component_id"] = "component:missing"
    elif action == "remove-runtime-assumption":
        assumptions = graphs["migrated"]["assumptions"]
        assumptions.pop(
            next(
                index
                for index, item in enumerate(assumptions)
                if item["kind"] == "foreign-runtime"
            )
        )
    elif action == "coerce-evidence-family":
        next(claim for claim in graphs["migrated"]["claims"] if claim["dependencies"])[
            "evidence"
        ] = ["evidence:theorem"]
    elif action == "upgrade-native-artifact":
        next(
            claim
            for claim in graphs["migrated"]["claims"]
            if claim["formal"] == "proved-finite-type"
        )["artifact"] = "proved"
    elif action == "upgrade-foreign-formal":
        next(
            claim
            for claim in graphs["migrated"]["claims"]
            if claim["formal"] == "tested" and claim["dependencies"]
        )["formal"] = "proved"
    elif action == "rewrite-unaffected":
        graphs["migrated"]["claims"][0]["formal"] = "proved"
    elif action == "omit-affected-claim":
        graphs["migration"]["affected_claims"].pop()
    elif action == "change-public-contract":
        caller_id = next(
            claim["id"]
            for claim in graphs["baseline"]["claims"]
            if claim["dependencies"]
        )
        next(
            item for item in graphs["public_contracts"] if item["claim_id"] == caller_id
        )["statement"] += " changed"
    elif action == "caller-disagreement":
        observations[0]["calls"][0]["error"] = "disagreement"
        observations[0]["calls"][0]["identity"] = _identity(
            CALL_SCHEMA, observations[0]["calls"][0]
        )
        observations[0]["identity"] = _identity(OBSERVATIONS_SCHEMA, observations[0])
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    elif action == "phase-disagreement":
        for observation in observations:
            if observation["phase"] == "migrated":
                observation["calls"][0]["error"] = "phase-drift"
                observation["calls"][0]["identity"] = _identity(
                    CALL_SCHEMA, observation["calls"][0]
                )
                observation["identity"] = _identity(OBSERVATIONS_SCHEMA, observation)
        envelope["identity"] = _identity(ENVELOPE_SCHEMA, envelope)
    else:
        _fail("FB-SCHEMA", "unknown attack action")


def _evaluate_case(artifact: bytes, case: dict[str, Any]) -> dict[str, Any]:
    if case["operation"] == "encode":
        value = case["input_value"]
        if (
            case["input_hex"] is not None
            or not isinstance(value, int)
            or value > artifact[18]
        ):
            _fail("FB-ABI-ENCODING", "encode input differs")
        return _result(True, value, f"{artifact[8]:02x}{value:02x}", None, 0)
    input_hex = case["input_hex"]
    if not isinstance(input_hex, str) or case["input_value"] is not None:
        _fail("FB-ABI-ENCODING", "decode input differs")
    value = _decode_hex(input_hex)
    if len(value) != artifact[12]:
        result = (False, None, None, "invalid-length")
    elif value[artifact[14]] != artifact[15]:
        result = (False, None, None, "invalid-prefix")
    elif value[artifact[17]] > artifact[18]:
        result = (False, None, None, "invalid-payload")
    else:
        output = value.hex()
        result = (True, value[artifact[20]], output, None)
    return _result(*result, len(value))


def _result(
    accepted: bool,
    value: int | None,
    output_hex: str | None,
    error: str | None,
    consumed: int,
) -> dict[str, Any]:
    return {
        "accepted": accepted,
        "value": value,
        "output_hex": output_hex,
        "error": error,
        "consumed": consumed,
    }


def _call_result(call: dict[str, Any]) -> dict[str, Any]:
    return {
        "accepted": call["accepted"],
        "value": call["value"],
        "output_hex": call["output_hex"],
        "error": call["error"],
        "consumed": call["consumed"],
    }


def _report_identity(report: dict[str, Any]) -> str:
    candidate = deepcopy(report)
    candidate["identity"] = ""
    candidate["repetition_identities"] = []
    return domain_hash(MODEL_REPORT_SCHEMA, candidate)


def _identity(domain: str, value: dict[str, Any]) -> str:
    candidate = deepcopy(value)
    candidate["identity"] = ""
    return domain_hash(domain, candidate)


def _validate_attack_corpus(corpus: dict[str, Any]) -> None:
    _keys(corpus, {"schema", "attacks"})
    ids = [attack["id"] for attack in corpus["attacks"]]
    if corpus["schema"] != ATTACKS_SCHEMA or len(ids) != 30 or not _strict_sorted(ids):
        _fail("FB-SCHEMA", "attack corpus differs")
    for attack in corpus["attacks"]:
        _keys(attack, {"id", "action", "expected"})


def _strict_sorted(values: list[str]) -> bool:
    return bool(values) and values == sorted(set(values))


def _valid_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdefABCDEF" for character in value[7:])
    )


def _decode_hex(value: object) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) % 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail("FB-ABI-ENCODING", "hex encoding differs")
    return bytes.fromhex(value)


def _decode_canonical(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("FB-NONCANONICAL", str(error))
    if not isinstance(value, dict) or canonical_json(value) != payload:
        _fail("FB-NONCANONICAL", "canonical JSON differs")
    return value


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("FB-SCHEMA", str(error))
    if not isinstance(value, dict):
        _fail("FB-SCHEMA", "control root differs")
    return value


def _keys(value: object, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _fail("FB-SCHEMA", "object fields differ")


def _zero_sha() -> str:
    return "sha256:" + "0" * 64


def _fail(code: str, message: str) -> NoReturn:
    raise MigrationFailure(code, message)
