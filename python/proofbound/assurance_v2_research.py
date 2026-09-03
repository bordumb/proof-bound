"""Independent Assurance IR `/2` differential kernel for Experiment 0015."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn

PROGRAM_SCHEMA = "proofbound-research-assurance-program/2"
REPORT_SCHEMA = "proofbound-research-assurance-kernel-report/2"
MODEL_REPORT_SCHEMA = "proofbound-research-assurance-model-report/2"
MODEL_SCHEMA = "proofbound-research-assurance-model/2"
TEMPLATES_SCHEMA = "proofbound-research-assurance-templates/2"
ATTACKS_SCHEMA = "proofbound-research-assurance-attacks/2"
GENERATION_SCHEMA = "proofbound-research-assurance-generation/2"


class AssuranceV2Failure(ValueError):
    """Report one exact research-kernel rejection."""

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
    """Return a raw byte identity."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def domain_hash(domain: str, payload: bytes) -> str:
    """Return a domain-separated canonical identity."""

    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def load_assurance_v2_corpus(
    root: Path, corpus_dir: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load and validate every frozen corpus control."""

    model = _read_json(root / corpus_dir / "model.json")
    templates = _read_json(root / corpus_dir / "templates.json")
    attacks = _read_json(root / corpus_dir / "attacks.json")
    generation = _read_json(root / corpus_dir / "generation.json")
    _validate_corpus(model, templates, attacks, generation)
    return model, templates, attacks, generation


def expand_assurance_v2_profile(
    model: dict[str, Any], profile: dict[str, Any], index: int
) -> dict[str, Any]:
    """Expand one frozen profile into a complete Assurance IR programme."""

    suffix = f"{index:06d}"
    family = _family(model, profile["family"])
    profile_id = profile["id"]
    programme_id = f"programme:{profile_id}:{suffix}"
    claim_id = f"claim:{profile_id}:{suffix}"
    specification_id = f"specification:{profile_id}:{suffix}"
    evidence_id = f"evidence:{profile_id}:{suffix}"
    uncertainty_id = f"uncertainty:{profile_id}:{suffix}"
    dependencies = []
    for role in profile["dependency_roles"]:
        identifier = f"dependency:{profile_id}:{role}:{suffix}"
        dependencies.append(
            {
                "declared": True,
                "id": identifier,
                "identity": sha256_bytes(identifier.encode()),
                "observed": True,
                "role": role,
            }
        )
    dependencies.sort(key=lambda item: item["id"])
    external = next(
        (item["id"] for item in dependencies if item["role"] == "external-contract"),
        None,
    )
    effects = []
    for source in profile["effects"]:
        effects.append(
            {
                "boundary": source["boundary"],
                "capability": source["capability"],
                "disposition": source["disposition"],
                "enforcement_dependency": (
                    external if source["boundary"] == "externally-enforced" else None
                ),
                "id": f"effect:{profile_id}:{source['capability']}:{suffix}",
            }
        )
    effects.sort(key=lambda item: item["id"])
    artifacts = []
    for role in profile["artifact_roles"]:
        identifier = f"artifact:{profile_id}:{role}:{suffix}"
        artifacts.append(
            {
                "corresponds_to": None,
                "id": identifier,
                "role": role,
                "sha256": sha256_bytes(identifier.encode()),
                "size_bytes": 64 + len(role),
            }
        )
    artifacts.sort(key=lambda item: item["id"])
    by_role = {item["role"]: item for item in artifacts}
    for artifact in artifacts:
        if artifact["role"] == "bound":
            artifact["corresponds_to"] = by_role["generated"]["id"]
        elif artifact["role"] == "reproduced":
            source = by_role["source"]
            artifact["corresponds_to"] = source["id"]
            artifact["sha256"] = source["sha256"]
            artifact["size_bytes"] = source["size_bytes"]
    roles = deepcopy(model["specification_roles"])
    suite_identity = _hash_value(
        "proofbound-research-specification-suite/2",
        {"profile": profile_id, "roles": roles},
    )
    adequacy_identity = _hash_value(
        "proofbound-research-specification-adequacy/2",
        {
            "killed_mutants": 6,
            "required_mutants": 6,
            "suite_identity": suite_identity,
        },
    )
    specification = {
        "adequacy_identity": adequacy_identity,
        "id": specification_id,
        "killed_mutants": 6,
        "required_mutants": 6,
        "roles": roles,
        "suite_identity": suite_identity,
    }
    uncertainty = {
        "consequence": profile["uncertainty"]["consequence"],
        "detail_sha256": sha256_bytes(uncertainty_id.encode()),
        "id": uncertainty_id,
        "kind": profile["uncertainty"]["kind"],
    }
    consumed = [] if uncertainty["consequence"] == "informational" else [uncertainty_id]
    decision = {
        "admitted": uncertainty["consequence"] != "blocks-admission",
        "assumption": (
            "assumed" if uncertainty["consequence"] == "marks-assumed" else "none"
        ),
        "cache_eligible": profile["cache_eligible"],
        "consumed_uncertainties": consumed,
        "formal": family["formal"],
        "linkage": family["linkage"],
    }
    evidence = {
        "artifact_ids": [item["id"] for item in artifacts],
        "dependency_ids": [item["id"] for item in dependencies],
        "effect_ids": [item["id"] for item in effects],
        "family": profile["family"],
        "id": evidence_id,
        "outcome": "passed",
        "specification_id": specification_id,
    }
    changed = [dependencies[0]["id"]]
    invalidated = [evidence_id]
    invalidation = {
        "changed_dependencies": changed,
        "identity": _hash_value(
            "proofbound-research-invalidation-set/2",
            {
                "changed_dependencies": changed,
                "invalidated_evidence": invalidated,
            },
        ),
        "invalidated_evidence": invalidated,
    }
    derivation = _derive_derivation(
        profile_id,
        suffix,
        evidence_id,
        specification_id,
        uncertainty_id,
        decision,
    )
    return {
        "artifacts": artifacts,
        "claim": {
            "id": claim_id,
            "specification_id": specification_id,
            "subject": f"subject:{profile_id}",
        },
        "dependencies": dependencies,
        "derivation": derivation,
        "effects": effects,
        "evidence": evidence,
        "expected_decision": decision,
        "id": programme_id,
        "invalidation": invalidation,
        "schema": PROGRAM_SCHEMA,
        "specification": specification,
        "uncertainties": [uncertainty],
    }


def validate_assurance_v2_program(
    model: dict[str, Any], payload: bytes
) -> dict[str, Any]:
    """Validate canonical programme bytes and derive the complete report."""

    value = _decode_bytes(payload)
    if canonical_json(value) != payload:
        _fail("IR2-NONCANONICAL", "programme is not canonical JSON")
    _exact_keys(
        value,
        {
            "artifacts",
            "claim",
            "dependencies",
            "derivation",
            "effects",
            "evidence",
            "expected_decision",
            "id",
            "invalidation",
            "schema",
            "specification",
            "uncertainties",
        },
    )
    _validate_program(model, value)
    return _derive_kernel_report(value)


def execute_assurance_v2_corpus(
    root: Path, corpus_dir: Path, repetitions: int
) -> dict[str, Any]:
    """Execute all templates and generated differential cases."""

    model, templates, attacks, generation = load_assurance_v2_corpus(root, corpus_dir)
    if repetitions != generation["repetitions"]:
        _fail("IR2-SCHEMA", "repetition count differs from corpus")
    report = _derive_model_report(model, templates, attacks, generation)
    stable = report["identity"]
    report["repetition_report_identities"] = [
        _derive_model_report(model, templates, attacks, generation)["identity"]
        for _ in range(repetitions)
    ]
    if any(item != stable for item in report["repetition_report_identities"]):
        _fail("IR2-DECISION-MISMATCH", "model report is unstable")
    report["identity"] = _model_report_identity(report)
    return report


def _derive_model_report(
    model: dict[str, Any],
    templates: dict[str, Any],
    attacks: dict[str, Any],
    generation: dict[str, Any],
) -> dict[str, Any]:
    profiles = {item["id"]: item for item in templates["profiles"]}
    template_reports = [
        _validate_value(model, expand_assurance_v2_profile(model, profile, index))
        for index, profile in enumerate(templates["profiles"])
    ]
    valid_rows = []
    for index in range(generation["valid_programs"]):
        profile = templates["profiles"][index % len(templates["profiles"])]
        result = _validate_value(
            model, expand_assurance_v2_profile(model, profile, index)
        )
        valid_rows.append(
            {
                "index": index,
                "report_identity": result["identity"],
                "semantic_identity": result["semantic_identity"],
            }
        )
    attack_results = []
    for index, attack in enumerate(attacks["attacks"]):
        programme = expand_assurance_v2_profile(
            model, profiles[attack["template"]], 900_000 + index
        )
        actual = _run_attack(model, programme, attack["action"])
        attack_results.append(
            {
                "actual_code": actual,
                "exact": actual == attack["expected"],
                "expected_code": attack["expected"],
                "id": attack["id"],
            }
        )
    adversarial_rows = []
    for index in range(generation["adversarial_programs"]):
        attack = attacks["attacks"][index % len(attacks["attacks"])]
        programme = expand_assurance_v2_profile(
            model, profiles[attack["template"]], 500_000 + index
        )
        actual = _run_attack(model, programme, attack["action"])
        adversarial_rows.append(
            {"actual_code": actual, "attack": attack["id"], "index": index}
        )
    report = {
        "adversarial_corpus_identity": _hash_value(
            "proofbound-research-assurance-adversarial-corpus/2", adversarial_rows
        ),
        "adversarial_programs": generation["adversarial_programs"],
        "attacks": attack_results,
        "constructor_coverage": deepcopy(model["object_constructors"]),
        "identity": "",
        "repetition_report_identities": [],
        "schema": MODEL_REPORT_SCHEMA,
        "templates": template_reports,
        "valid_corpus_identity": _hash_value(
            "proofbound-research-assurance-valid-corpus/2", valid_rows
        ),
        "valid_programs": generation["valid_programs"],
        "validation_code_coverage": sorted(
            {item["actual_code"] for item in attack_results}
        ),
    }
    report["identity"] = _model_report_identity(report)
    return report


def _validate_program(model: dict[str, Any], programme: dict[str, Any]) -> None:
    if programme["schema"] != PROGRAM_SCHEMA:
        _fail("IR2-SCHEMA", "unsupported programme schema")
    _validate_id(programme["id"])
    _validate_id(programme["claim"]["id"])
    _validate_id(programme["evidence"]["id"])
    groups = [
        [item["id"] for item in programme[field]]
        for field in ("dependencies", "effects", "artifacts", "uncertainties")
    ]
    all_ids: set[str] = set()
    for group in groups:
        if len(group) != len(set(group)):
            _fail("IR2-DUPLICATE", "duplicate identity")
        if all_ids.intersection(group):
            _fail("IR2-ALIAS", "typed identities alias")
        all_ids.update(group)
    for group in groups:
        if group != sorted(group):
            _fail("IR2-ORDER", "collection is not lexical")
    _validate_dependencies(programme)
    _validate_effects(model, programme)
    _validate_specification(model, programme)
    _validate_artifacts(model, programme)
    _validate_uncertainty(model, programme)
    _validate_family(model, programme)
    _validate_invalidation(programme)
    _validate_derivation(programme)
    expected = _derive_decision(model, programme)
    if (
        programme["expected_decision"]["linkage"] == "artifact-bound"
        and expected["linkage"] != "artifact-bound"
    ):
        _fail("IR2-DECISION-UPGRADE", "artifact linkage lacks correspondence")
    if programme["expected_decision"] != expected:
        _fail("IR2-DECISION-MISMATCH", "decision is not derived")


def _validate_dependencies(programme: dict[str, Any]) -> None:
    identifiers = [item["id"] for item in programme["dependencies"]]
    for dependency in programme["dependencies"]:
        _validate_id(dependency["id"])
        _validate_sha(dependency["identity"])
        if not dependency["declared"] or not dependency["observed"]:
            _fail("IR2-DEPENDENCY-INCOMPLETE", "dependency is incomplete")
    for reference in programme["evidence"]["dependency_ids"]:
        if reference not in identifiers:
            _fail("IR2-DEPENDENCY-MISSING", "dependency reference is missing")
    if programme["evidence"]["dependency_ids"] != identifiers:
        _fail("IR2-DEPENDENCY-BINDING", "dependency set differs")


def _validate_effects(model: dict[str, Any], programme: dict[str, Any]) -> None:
    identifiers = [item["id"] for item in programme["effects"]]
    for reference in programme["evidence"]["effect_ids"]:
        if reference not in identifiers:
            _fail("IR2-EFFECT-MISSING", "effect reference is missing")
    if programme["evidence"]["effect_ids"] != identifiers:
        _fail("IR2-EFFECT-MISSING", "effect set differs")
    for effect in programme["effects"]:
        if (
            effect["capability"] not in model["effect_capabilities"]
            or effect["boundary"] not in model["effect_boundaries"]
        ):
            _fail("IR2-SCHEMA", "unknown effect value")
        if effect["disposition"] not in {"observed", "unused"}:
            _fail("IR2-EFFECT-DISPOSITION", "effect is unresolved")
        if (
            effect["boundary"] == "statically-denied"
            and effect["disposition"] != "unused"
        ):
            _fail("IR2-EFFECT-DISPOSITION", "denied effect was observed")
        if effect["boundary"] == "externally-enforced":
            reference = effect["enforcement_dependency"]
            if not any(
                item["id"] == reference and item["role"] == "external-contract"
                for item in programme["dependencies"]
            ):
                _fail("IR2-EFFECT-ENFORCEMENT", "enforcement is unbound")
        elif effect["enforcement_dependency"] is not None:
            _fail("IR2-EFFECT-OPAQUE", "non-external effect carries enforcement")
    if (
        any(item["boundary"] == "opaque" for item in programme["effects"])
        and programme["expected_decision"]["cache_eligible"]
    ):
        _fail("IR2-CACHE-INELIGIBLE", "opaque execution is reusable")


def _validate_specification(model: dict[str, Any], programme: dict[str, Any]) -> None:
    family = _family(model, programme["evidence"]["family"])
    specification = programme["specification"]
    if specification is None:
        if family["requires_specification"]:
            _fail("IR2-SPECIFICATION-MISSING", "specification is absent")
        return
    if (
        specification["id"] not in {programme["claim"]["specification_id"]}
        or specification["id"] != programme["evidence"]["specification_id"]
    ):
        _fail("IR2-SPECIFICATION-MISSING", "specification reference differs")
    if specification["roles"] != model["specification_roles"]:
        _fail("IR2-ORDER", "specification roles are noncanonical")
    if (
        specification["required_mutants"] != 6
        or specification["killed_mutants"] != specification["required_mutants"]
    ):
        _fail("IR2-SPECIFICATION-INADEQUATE", "required mutant survived")
    profile = _profile_from_program(programme["id"])
    expected_suite = _hash_value(
        "proofbound-research-specification-suite/2",
        {"profile": profile, "roles": specification["roles"]},
    )
    expected_adequacy = _hash_value(
        "proofbound-research-specification-adequacy/2",
        {
            "killed_mutants": specification["killed_mutants"],
            "required_mutants": specification["required_mutants"],
            "suite_identity": specification["suite_identity"],
        },
    )
    if (
        specification["suite_identity"] != expected_suite
        or specification["adequacy_identity"] != expected_adequacy
    ):
        _fail("IR2-SPECIFICATION-BINDING", "specification identity differs")


def _validate_artifacts(model: dict[str, Any], programme: dict[str, Any]) -> None:
    family = _family(model, programme["evidence"]["family"])
    roles = [item["role"] for item in programme["artifacts"]]
    if roles != family["required_artifact_roles"]:
        _fail("IR2-ARTIFACT-ROLE", "artifact roles differ")
    identifiers = [item["id"] for item in programme["artifacts"]]
    if programme["evidence"]["artifact_ids"] != identifiers:
        _fail("IR2-ARTIFACT-ROLE", "evidence artifact set differs")
    by_role = {item["role"]: item for item in programme["artifacts"]}
    for artifact in programme["artifacts"]:
        _validate_sha(artifact["sha256"])
        if artifact["role"] == "bound":
            if artifact["corresponds_to"] != by_role["generated"]["id"]:
                _fail("IR2-ARTIFACT-BINDING", "bound artifact is unjoined")
        elif artifact["role"] == "reproduced":
            source = by_role["source"]
            if (
                artifact["corresponds_to"] != source["id"]
                or artifact["sha256"] != source["sha256"]
                or artifact["size_bytes"] != source["size_bytes"]
            ):
                _fail("IR2-ARTIFACT-BINDING", "reproduction differs")
        elif artifact["corresponds_to"] is not None:
            _fail("IR2-ARTIFACT-BINDING", "unexpected correspondence")


def _validate_uncertainty(model: dict[str, Any], programme: dict[str, Any]) -> None:
    if not programme["uncertainties"]:
        _fail("IR2-UNCERTAINTY-MISSING", "uncertainty is absent")
    if len(programme["uncertainties"]) != 1:
        _fail("IR2-DUPLICATE", "expected one uncertainty")
    uncertainty = programme["uncertainties"][0]
    expected = next(
        (
            item
            for item in model["uncertainties"]
            if item["kind"] == uncertainty["kind"]
        ),
        None,
    )
    if expected is None or uncertainty["consequence"] != expected["consequence"]:
        _fail("IR2-UNCERTAINTY-KIND", "uncertainty consequence differs")
    consumed = programme["expected_decision"]["consumed_uncertainties"]
    if uncertainty["consequence"] == "informational":
        if consumed:
            _fail("IR2-UNCERTAINTY-CONSEQUENCE", "telemetry was consumed")
    elif consumed != [uncertainty["id"]]:
        _fail("IR2-UNCERTAINTY-CONSEQUENCE", "uncertainty is not consumed")


def _validate_family(model: dict[str, Any], programme: dict[str, Any]) -> None:
    family = _family(model, programme["evidence"]["family"])
    decision = programme["expected_decision"]
    if programme["evidence"]["outcome"] != "passed":
        _fail("IR2-FAMILY-COERCION", "evidence did not pass")
    if (
        decision["linkage"] == "artifact-bound"
        and family["linkage"] != "artifact-bound"
    ):
        _fail("IR2-DECISION-UPGRADE", "artifact linkage lacks correspondence")
    if (
        decision["formal"] != family["formal"]
        or decision["linkage"] != family["linkage"]
    ):
        _fail("IR2-FAMILY-COERCION", "family facet was strengthened")


def _validate_invalidation(programme: dict[str, Any]) -> None:
    expected_changed = [programme["dependencies"][0]["id"]]
    expected_evidence = [programme["evidence"]["id"]]
    expected_identity = _hash_value(
        "proofbound-research-invalidation-set/2",
        {
            "changed_dependencies": expected_changed,
            "invalidated_evidence": expected_evidence,
        },
    )
    invalidation = programme["invalidation"]
    if invalidation != {
        "changed_dependencies": expected_changed,
        "identity": expected_identity,
        "invalidated_evidence": expected_evidence,
    }:
        _fail("IR2-INVALIDATION", "invalidation projection differs")


def _validate_derivation(programme: dict[str, Any]) -> None:
    expected = _derive_derivation(
        _profile_from_program(programme["id"]),
        _suffix_from_program(programme["id"]),
        programme["evidence"]["id"],
        programme["evidence"]["specification_id"],
        programme["uncertainties"][0]["id"],
        programme["expected_decision"],
    )
    derivation = programme["derivation"]
    if derivation["root"] != expected["root"]:
        _fail("IR2-DERIVATION-ROOT", "derivation root differs")
    if derivation["steps"] != expected["steps"]:
        _fail("IR2-DERIVATION-DEPENDENCY", "derivation dependencies differ")
    if derivation["identity"] != expected["identity"]:
        _fail("IR2-DERIVATION-IDENTITY", "derivation identity differs")


def _derive_decision(
    model: dict[str, Any], programme: dict[str, Any]
) -> dict[str, Any]:
    family = _family(model, programme["evidence"]["family"])
    uncertainty = programme["uncertainties"][0]
    return {
        "admitted": uncertainty["consequence"] != "blocks-admission",
        "assumption": (
            "assumed" if uncertainty["consequence"] == "marks-assumed" else "none"
        ),
        "cache_eligible": not any(
            item["boundary"] == "opaque" for item in programme["effects"]
        ),
        "consumed_uncertainties": (
            [] if uncertainty["consequence"] == "informational" else [uncertainty["id"]]
        ),
        "formal": family["formal"],
        "linkage": family["linkage"],
    }


def _derive_derivation(
    profile: str,
    suffix: str,
    evidence_id: str,
    specification_id: str,
    uncertainty_id: str,
    decision: dict[str, Any],
) -> dict[str, Any]:
    prefix = f"step:{profile}:{suffix}"
    evidence_step = f"{prefix}:01-evidence"
    family_step = f"{prefix}:02-family"
    uncertainty_step = f"{prefix}:03-uncertainty"
    admission_step = f"{prefix}:04-admission"
    steps = [
        {
            "conclusion": "evidence=valid",
            "id": evidence_step,
            "inputs": [evidence_id],
            "rule": "evidence-valid",
        },
        {
            "conclusion": f"formal={decision['formal']};linkage={decision['linkage']}",
            "id": family_step,
            "inputs": [evidence_step, specification_id],
            "rule": "family-facet",
        },
        {
            "conclusion": (
                f"assumption={decision['assumption']};admitted="
                f"{str(decision['admitted']).lower()}"
            ),
            "id": uncertainty_step,
            "inputs": [uncertainty_id],
            "rule": "uncertainty-evaluated",
        },
        {
            "conclusion": _decision_text(decision),
            "id": admission_step,
            "inputs": [family_step, uncertainty_step],
            "rule": "admission-decided",
        },
    ]
    return {
        "identity": _hash_value(
            "proofbound-research-derivation-trace/2",
            {"root": admission_step, "steps": steps},
        ),
        "root": admission_step,
        "steps": steps,
    }


def _derive_kernel_report(programme: dict[str, Any]) -> dict[str, Any]:
    report = {
        "cache_eligible": programme["expected_decision"]["cache_eligible"],
        "consumed_uncertainties": deepcopy(
            programme["expected_decision"]["consumed_uncertainties"]
        ),
        "decision": deepcopy(programme["expected_decision"]),
        "dependency_identity": _hash_value(
            "proofbound-research-dependency-projection/2",
            programme["dependencies"],
        ),
        "derivation_identity": programme["derivation"]["identity"],
        "identity": "",
        "invalidation_identity": programme["invalidation"]["identity"],
        "programme": programme["id"],
        "schema": REPORT_SCHEMA,
        "semantic_identity": _hash_value(
            "proofbound-research-assurance-program/2", programme
        ),
    }
    report["identity"] = _kernel_report_identity(report)
    return report


def _run_attack(model: dict[str, Any], programme: dict[str, Any], action: str) -> str:
    candidate = deepcopy(programme)
    _mutate(candidate, action)
    payload = canonical_json(candidate)
    if action == "noncanonical-bytes":
        payload += b"\n"
    try:
        validate_assurance_v2_program(model, payload)
    except AssuranceV2Failure as error:
        return error.code
    return "IR2-ACCEPTED"


def _mutate(programme: dict[str, Any], action: str) -> None:
    if action == "replace-schema":
        programme["schema"] = "proofbound-research-assurance-program/3"
    elif action == "noncanonical-bytes":
        pass
    elif action == "duplicate-dependency":
        programme["dependencies"].append(deepcopy(programme["dependencies"][0]))
    elif action == "alias-dependency-artifact":
        programme["artifacts"][0]["id"] = programme["dependencies"][0]["id"]
    elif action == "remove-dependency":
        programme["dependencies"].pop(0)
    elif action == "substitute-dependency-reference":
        programme["evidence"]["dependency_ids"][0] = programme["dependencies"][1]["id"]
    elif action == "mark-dependency-unobserved":
        programme["dependencies"][0]["observed"] = False
    elif action == "forge-invalidation-identity":
        programme["invalidation"]["identity"] = _zero_sha()
    elif action == "enable-opaque-cache":
        programme["expected_decision"]["cache_eligible"] = True
    elif action == "remove-effect":
        programme["effects"].pop(0)
    elif action == "unresolve-effect-disposition":
        programme["effects"][0]["disposition"] = "unresolved"
    elif action == "forge-external-enforcement":
        effect = next(
            item
            for item in programme["effects"]
            if item["boundary"] == "externally-enforced"
        )
        effect["enforcement_dependency"] = "dependency:forged:external-contract:000000"
    elif action == "retain-enforcement-on-opaque":
        effect = next(
            item
            for item in programme["effects"]
            if item["boundary"] == "externally-enforced"
        )
        effect["boundary"] = "opaque"
    elif action == "remove-specification":
        programme["specification"] = None
    elif action == "forge-adequacy-identity":
        programme["specification"]["adequacy_identity"] = _zero_sha()
    elif action == "leave-mutant-alive":
        programme["specification"]["killed_mutants"] = 5
    elif action == "substitute-artifact-role":
        programme["artifacts"][0]["role"] = "sealed"
    elif action == "remove-artifact-correspondence":
        artifact = next(
            item for item in programme["artifacts"] if item["role"] == "bound"
        )
        artifact["corresponds_to"] = None
    elif action == "remove-uncertainty":
        programme["uncertainties"] = []
    elif action == "coerce-telemetry-to-assumption":
        programme["uncertainties"][0]["kind"] = "assumption"
    elif action == "omit-consumed-uncertainty":
        programme["expected_decision"]["consumed_uncertainties"] = []
    elif action == "substitute-derivation-input":
        programme["derivation"]["steps"][1]["inputs"][0] = "step:substituted"
    elif action == "replace-derivation-root":
        programme["derivation"]["root"] = "step:substituted"
    elif action == "forge-derivation-identity":
        programme["derivation"]["identity"] = _zero_sha()
    elif action == "upgrade-formal-facet":
        programme["expected_decision"]["formal"] = "proved"
    elif action == "upgrade-transcription-linkage":
        programme["expected_decision"]["linkage"] = "refined"
    elif action == "upgrade-artifact-linkage":
        programme["expected_decision"]["linkage"] = "artifact-bound"
    elif action == "replace-derived-decision":
        programme["expected_decision"]["admitted"] = True
        programme["derivation"] = _derive_derivation(
            _profile_from_program(programme["id"]),
            _suffix_from_program(programme["id"]),
            programme["evidence"]["id"],
            programme["evidence"]["specification_id"],
            programme["uncertainties"][0]["id"],
            programme["expected_decision"],
        )
    else:
        _fail("IR2-SCHEMA", f"unknown attack action {action}")


def _validate_corpus(
    model: dict[str, Any],
    templates: dict[str, Any],
    attacks: dict[str, Any],
    generation: dict[str, Any],
) -> None:
    if (
        model.get("schema") != MODEL_SCHEMA
        or model.get("program_schema") != PROGRAM_SCHEMA
        or model.get("report_schema") != REPORT_SCHEMA
        or templates.get("schema") != TEMPLATES_SCHEMA
        or attacks.get("schema") != ATTACKS_SCHEMA
        or generation.get("schema") != GENERATION_SCHEMA
        or generation.get("algorithm") != "proofbound-exp-0015-generator/1"
    ):
        _fail("IR2-SCHEMA", "corpus schema differs")
    for field in (
        "dependency_roles",
        "effect_capabilities",
        "effect_boundaries",
        "artifact_roles",
        "specification_roles",
        "derivation_rules",
        "object_constructors",
        "validation_codes",
    ):
        _require_sorted_unique(model[field])
    _require_sorted_unique([item["id"] for item in model["families"]])
    _require_sorted_unique([item["kind"] for item in model["uncertainties"]])
    _require_sorted_unique([item["id"] for item in templates["profiles"]])
    _require_sorted_unique([item["id"] for item in attacks["attacks"]])
    if (
        len(templates["profiles"]) != 6
        or len(attacks["attacks"]) != 28
        or generation["valid_programs"] != 500
        or generation["adversarial_programs"] != 500
        or generation["repetitions"] != 10
        or generation["mutation_cardinality"] != 1
        or generation["seed"] != 151_510
    ):
        _fail("IR2-SCHEMA", "frozen cardinality differs")
    profile_ids = {item["id"] for item in templates["profiles"]}
    uncertainty_pairs = {
        (item["kind"], item["consequence"]) for item in model["uncertainties"]
    }
    for profile in templates["profiles"]:
        _family(model, profile["family"])
        _require_sorted_unique(profile["dependency_roles"])
        _require_sorted_unique(profile["artifact_roles"])
        _require_sorted_unique([item["capability"] for item in profile["effects"]])
        if (
            profile["uncertainty"]["kind"],
            profile["uncertainty"]["consequence"],
        ) not in uncertainty_pairs:
            _fail("IR2-UNCERTAINTY-KIND", "profile uncertainty differs")
        has_opaque = any(item["boundary"] == "opaque" for item in profile["effects"])
        if profile["cache_eligible"] == has_opaque:
            _fail("IR2-CACHE-INELIGIBLE", "profile cache policy differs")
    for attack in attacks["attacks"]:
        if (
            attack["template"] not in profile_ids
            or attack["expected"] not in model["validation_codes"]
        ):
            _fail("IR2-REFERENCE", "attack registration differs")


def _validate_value(model: dict[str, Any], programme: dict[str, Any]) -> dict[str, Any]:
    return validate_assurance_v2_program(model, canonical_json(programme))


def _family(model: dict[str, Any], identifier: str) -> dict[str, Any]:
    family = next(
        (item for item in model["families"] if item["id"] == identifier), None
    )
    if family is None:
        _fail("IR2-FAMILY-COERCION", "unknown evidence family")
    return family


def _require_sorted_unique(values: list[str]) -> None:
    if len(values) != len(set(values)):
        _fail("IR2-DUPLICATE", "duplicate identity")
    if values != sorted(values):
        _fail("IR2-ORDER", "collection is not lexical")


def _validate_id(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > 256
        or any(
            not (character.islower() or character.isdigit() or character in ":-")
            for character in value
        )
    ):
        _fail("IR2-IDENTIFIER", "identifier is not canonical")


def _validate_sha(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        _fail("IR2-IDENTIFIER", "identity is not canonical SHA-256")


def _hash_value(domain: str, value: object) -> str:
    return domain_hash(domain, canonical_json(value))


def _kernel_report_identity(report: dict[str, Any]) -> str:
    candidate = deepcopy(report)
    candidate["identity"] = ""
    return _hash_value(REPORT_SCHEMA, candidate)


def _model_report_identity(report: dict[str, Any]) -> str:
    candidate = deepcopy(report)
    candidate["identity"] = ""
    candidate["repetition_report_identities"] = []
    return _hash_value(MODEL_REPORT_SCHEMA, candidate)


def _decision_text(decision: dict[str, Any]) -> str:
    return (
        f"formal={decision['formal']};linkage={decision['linkage']};"
        f"assumption={decision['assumption']};"
        f"admitted={str(decision['admitted']).lower()};"
        f"cache={str(decision['cache_eligible']).lower()}"
    )


def _profile_from_program(value: str) -> str:
    if not value.startswith("programme:") or ":" not in value[10:]:
        _fail("IR2-IDENTIFIER", "programme shape differs")
    return value[10:].rsplit(":", 1)[0]


def _suffix_from_program(value: str) -> str:
    if ":" not in value:
        _fail("IR2-IDENTIFIER", "programme suffix is absent")
    return value.rsplit(":", 1)[1]


def _decode_bytes(payload: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("IR2-SCHEMA", f"duplicate object key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("IR2-SCHEMA", str(error))
    if not isinstance(value, dict):
        _fail("IR2-SCHEMA", "programme root is not an object")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("IR2-SCHEMA", f"{path}: {error}")
    if not isinstance(value, dict):
        _fail("IR2-SCHEMA", f"{path} is not an object")
    return value


def _exact_keys(value: dict[str, Any], fields: set[str]) -> None:
    if set(value) != fields:
        _fail("IR2-SCHEMA", "programme fields differ")


def _zero_sha() -> str:
    return "sha256:" + "0" * 64


def _fail(code: str, message: str) -> NoReturn:
    raise AssuranceV2Failure(code, message)
