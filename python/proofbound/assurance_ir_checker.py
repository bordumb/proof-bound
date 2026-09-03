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
import unicodedata


CORPUS_SCHEMA = "proofbound-research-projection-corpus/1"
PROJECTION_SCHEMA = "proofbound-assurance-ir-projection/1"
PROJECTION_DOMAIN = "proofbound-assurance-ir-projection/1"
CASE_SCHEMA = "proofbound-assurance-ir-case/1"
CACHE_DOMAIN = "proofbound-assurance-ir-cache/1"
PORTABLE_FAMILY_PROJECTION_SCHEMA = "proofbound-ir-portable-family-projection/1"
PORTABLE_FAMILY_PROJECTION_DOMAIN = "proofbound-ir-portable-family-projection/1"
LEGACY_SAMPLING_REASON = "sampling-detail-not-yet-portable"
DERIVATION_PROGRAM_SCHEMA = "proofbound-derivation-program/1"
DERIVATION_FACT_SCHEMA = "proofbound-derivation-fact/1"
DERIVATION_STEP_SCHEMA = "proofbound-derivation-step/1"
DERIVATION_JUDGMENT_SCHEMA = "proofbound-derivation-judgment/1"
DERIVATION_TRACE_DOMAIN = "proofbound-derivation-trace/1"
GENERATED_DERIVATION_SCHEMA = "proofbound-generated-derivation-corpus/1"
DERIVATION_GENERATOR = "proofbound-exp-0009-generator/1"


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


@dataclass(frozen=True)
class SamplingCheckReport:
    """Summary of one independently validated sampling observation.

    Attributes:
        framework: Registered sampling framework.
        framework_version: Exact registered framework version.
        contract_identity: Independently recomputed contract identity.
        generator_identity: Independently recomputed generator identity.
        result: Typed observation result.
    """

    framework: str
    framework_version: str
    contract_identity: str
    generator_identity: str
    result: str


@dataclass(frozen=True)
class LayeredSamplingCheckReport:
    """Independent admission result for one layered sampling case.

    Attributes:
        intent_identity: Recomputed common sampling-intent identity.
        plan_identity: Recomputed backend-plan identity.
        result: Typed sampling result.
        admitted: Whether the registered empirical rule is satisfied.
        alerts: Consequence-bearing admission alerts.
    """

    intent_identity: str
    plan_identity: str
    result: str
    admitted: bool
    alerts: tuple[str, ...]


@dataclass(frozen=True)
class DerivationCheckReport:
    """Independent result for one closed evidence derivation.

    Attributes:
        claim_id: Claim whose status was derived.
        conclusion: Complete derived status judgment.
        trace_identity: Identity of the canonical derivation program.
        alerts: Consequence-bearing alerts emitted by the checker.
    """

    claim_id: str
    conclusion: dict[str, Any]
    trace_identity: str
    alerts: tuple[str, ...]


@dataclass(frozen=True)
class GeneratedDerivationCheckReport:
    """Independent summary for a generated derivation corpus.

    Attributes:
        valid_count: Number of valid programs accepted.
        adversarial_count: Number of registered mutations checked.
        corpus_identity: Independently recomputed generator identity.
    """

    valid_count: int
    adversarial_count: int
    corpus_identity: str


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


def derive_release_trace_bundle(receipt_bytes: bytes) -> dict[str, Any]:
    """Derive a backend-neutral admission trace from one portable receipt."""

    receipt = _strict_json(receipt_bytes, require_canonical=False)
    traces, publication = _release_derivation_traces(receipt)
    return {
        "schema": "proofbound-ir-release-trace-bundle/1",
        "project": _required_text(receipt, "project"),
        "receipt_sha256": _sha256(receipt_bytes),
        "traces": traces,
        "publication": publication,
    }


def validate_release_trace_bundle(receipt_bytes: bytes, trace_bytes: bytes) -> None:
    """Reject a claimed trace that differs from independent receipt derivation."""

    actual = _strict_json(trace_bytes, require_canonical=True)
    expected = derive_release_trace_bundle(receipt_bytes)
    if actual != expected:
        _fail(
            "IR-DERIVATION-TRACE-MISMATCH",
            "trace bundle differs from independently derived receipt semantics",
        )


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


def check_portable_family_projection(
    root: Path, capture_index_path: Path, projection_bytes: bytes
) -> CheckReport:
    """Independently reconstruct the portable evidence-family projection.

    Args:
        root: Repository root containing the immutable semantic captures.
        capture_index_path: Identity index for the completion capture.
        projection_bytes: Canonical bytes produced by the Rust prototype.

    Returns:
        Projected record count and independently recomputed identity.

    Raises:
        AssuranceIrError: If capture identities or family semantics differ.
    """

    index_bytes = capture_index_path.read_bytes()
    index = _strict_json(index_bytes, require_canonical=False)
    projection = _strict_json(projection_bytes, require_canonical=True)
    if (
        index.get("schema") != "proofbound-research-q1-completion-capture/1"
        or index.get("revision") != 1
    ):
        raise AssuranceIrError("unsupported completion capture")
    records: list[dict[str, Any]] = []
    capture_root = capture_index_path.parent
    for case in index["cases"]:
        compiled_files = [
            item
            for item in case["files"]
            if item["path"].endswith("/compiled-receipt.json")
        ]
        if len(compiled_files) != 1:
            raise AssuranceIrError("capture case has no unique compiled receipt")
        registered = compiled_files[0]
        relative = Path(registered["path"])
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in registered["path"]
        ):
            raise AssuranceIrError("capture path is not normalized")
        path = capture_root / relative
        try:
            path.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise AssuranceIrError("capture path escapes repository") from error
        data = path.read_bytes()
        if (
            _sha256(data) != registered["sha256"]
            or len(data) != registered["size_bytes"]
        ):
            raise AssuranceIrError("captured compiled receipt identity differs")
        receipt = _strict_json(data, require_canonical=False)
        evidence = receipt.get("evidence")
        if not isinstance(evidence, list) or len(evidence) != case["evidence_records"]:
            raise AssuranceIrError("capture evidence count differs")
        records.extend(_project_portable_record(item) for item in evidence)

    records.sort(key=lambda item: item["content_sha256"])
    identities = [item["content_sha256"] for item in records]
    if len(identities) != len(set(identities)):
        raise AssuranceIrError("duplicate portable evidence identity")
    material = {
        "capture_sha256": _sha256(index_bytes),
        "records": records,
        "schema": PORTABLE_FAMILY_PROJECTION_SCHEMA,
    }
    identity = domain_hash(PORTABLE_FAMILY_PROJECTION_DOMAIN, canonical_json(material))
    expected = material | {"projection_sha256": identity}
    if projection != expected:
        raise AssuranceIrError(
            "portable family projection differs from independent reconstruction"
        )
    return CheckReport(len(records), identity)


def check_sampling_observation(
    root: Path, contract_bytes: bytes, observation_bytes: bytes
) -> SamplingCheckReport:
    """Validate a backend-neutral sampling observation against registration.

    Args:
        root: Repository root containing the exact generator closure.
        contract_bytes: Canonical registered sampling contract.
        observation_bytes: Canonical driver observation.

    Returns:
        Independently recomputed identities and the typed result.

    Raises:
        AssuranceIrError: If the contract, closure, observation, or identity differs.
    """

    contract = _sampling_json(
        contract_bytes, "sampling contract", allow_final_newline=True
    )
    observation = _sampling_json(
        observation_bytes, "sampling observation", allow_final_newline=False
    )
    _validate_sampling_contract(root, contract)
    _require_keys(
        observation,
        {
            "schema",
            "contract",
            "contract_identity",
            "actual_seed",
            "attempted_cases",
            "completed_cases",
            "skipped_cases",
            "shrink_count",
            "targets",
            "result",
        },
        "sampling observation",
    )
    if (
        contract.get("schema") != "proofbound-sampling-contract/1"
        or observation.get("schema") != "proofbound-sampling-observation/1"
    ):
        _sampling_fail("sampling-schema-mismatch", "unsupported sampling schema")
    observed = _as_object(observation["contract"])
    if observed.get("framework") != contract["framework"]:
        _sampling_fail("sampling-tool-mismatch", "framework differs")
    if observed.get("generator") != contract["generator"]:
        _sampling_fail("generator-identity-mismatch", "generator differs")
    if (
        observed.get("targets") != contract["targets"]
        or observation["targets"] != contract["targets"]
    ):
        _sampling_fail("sampling-inventory-mismatch", "targets differ")
    if observed != contract:
        _sampling_fail("sampling-contract-mismatch", "contract differs")
    identity = domain_hash("proofbound-sampling-contract/1", canonical_json(contract))
    if (
        observation["contract_identity"] != identity
        or observation["actual_seed"] != contract["seed"]
    ):
        _sampling_fail("sampling-contract-mismatch", "observed execution differs")
    if contract["shrinking"] == "disabled" and observation["shrink_count"] != 0:
        _sampling_fail("sampling-contract-mismatch", "disabled shrinking was observed")
    for field in (
        "attempted_cases",
        "completed_cases",
        "skipped_cases",
        "shrink_count",
    ):
        value = observation[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            _sampling_fail("sampling-report-invalid", f"{field} is invalid")
    result = _as_object(observation["result"])
    status = result.get("status")
    if status == "passed":
        _require_keys(result, {"status"}, "sampling result")
        if (
            observation["completed_cases"] != contract["successful_cases"]
            or observation["attempted_cases"]
            != observation["completed_cases"] + observation["skipped_cases"]
        ):
            _sampling_fail(
                "sampling-contract-mismatch", "completed case budget differs"
            )
    elif status == "counterexample":
        _require_keys(
            result,
            {"status", "counterexample", "failure_kind"},
            "sampling result",
        )
        _sampling_text(result["failure_kind"], "counterexample failure kind")
        if (
            observation["completed_cases"] >= contract["successful_cases"]
            or observation["attempted_cases"]
            <= observation["completed_cases"] + observation["skipped_cases"]
        ):
            _sampling_fail(
                "sampling-report-invalid",
                "counterexample follows a completed successful budget",
            )
    else:
        _sampling_fail("sampling-report-invalid", "sampling result is invalid")
    framework = _as_object(contract["framework"])
    return SamplingCheckReport(
        framework=framework["name"],
        framework_version=framework["version"],
        contract_identity=identity,
        generator_identity=_as_object(contract["generator"])["identity_sha256"],
        result=status,
    )


def check_layered_sampling_case(
    root: Path, case_bytes: bytes
) -> LayeredSamplingCheckReport:
    """Validate a layered sampling case without framework runtime imports.

    Args:
        root: Repository root containing the generator closure.
        case_bytes: Canonical layered case bytes.

    Returns:
        Recomputed identities and the consequence-bearing admission decision.

    Raises:
        AssuranceIrError: If layering, identity, authority, or admission fails.
    """

    case = _sampling_json(case_bytes, "layered sampling case", allow_final_newline=True)
    if case.get("schema") != "proofbound-layered-sampling-case/1":
        _sampling_fail("sampling-schema-mismatch", "unsupported layered case schema")
    _require_keys(
        case,
        {
            "schema",
            "intent",
            "intent_identity",
            "plan",
            "plan_identity",
            "observation",
            "admission_rule",
        },
        "layered sampling case",
    )
    intent = _as_object(case["intent"])
    backend_fields = {
        "rng_algorithm",
        "phases",
        "database",
        "random_type",
        "skip_limit",
        "max_local_rejects",
        "max_global_rejects",
        "max_shrink_iters",
    }
    if backend_fields.intersection(intent):
        _sampling_fail(
            "sampling-layer-violation",
            "backend execution control appears in common sampling intent",
        )
    _validate_layered_intent(root, intent)
    intent_identity = domain_hash(
        "proofbound-sampling-intent/1", canonical_json(intent)
    )
    observation = _as_object(case["observation"])
    if (
        case["intent_identity"] != intent_identity
        or observation.get("intent_identity") != intent_identity
    ):
        _sampling_fail(
            "sampling-intent-identity-mismatch", "sampling intent identity differs"
        )

    plan = _as_object(case["plan"])
    capabilities = _validate_layered_plan(plan)
    plan_identity = domain_hash(
        "proofbound-backend-sampling-plan/1", canonical_json(plan)
    )
    if (
        case["plan_identity"] != plan_identity
        or observation.get("plan_identity") != plan_identity
    ):
        _sampling_fail(
            "sampling-plan-identity-mismatch", "backend plan identity differs"
        )
    required_observation = {
        "schema",
        "intent_identity",
        "plan_identity",
        "targets",
        "result",
    }
    allowed_observation = required_observation | {
        "attempted",
        "completed",
        "skipped",
        "shrinks",
    }
    if not required_observation.issubset(observation) or not set(observation).issubset(
        allowed_observation
    ):
        raise AssuranceIrError(
            "layered sampling observation has missing or unknown fields"
        )
    if observation["schema"] != "proofbound-layered-sampling-observation/1":
        _sampling_fail("sampling-schema-mismatch", "unsupported observation schema")
    if observation["targets"] != intent["targets"]:
        _sampling_fail("sampling-inventory-mismatch", "observed targets differ")
    for name in ("attempted", "completed", "skipped", "shrinks"):
        _validate_layered_fact(observation.get(name), capabilities[name], name)

    rule = _as_object(case["admission_rule"])
    _require_keys(rule, {"schema", "id", "required_facts"}, "sampling rule")
    if (
        rule["schema"] != "proofbound-sampling-admission-rule/1"
        or rule["id"] != "empirical-sample-pass"
        or rule["required_facts"] != ["completed"]
    ):
        _sampling_fail(
            "sampling-rule-overreach",
            "empirical admission consumes only the completed fact",
        )
    result = _as_object(observation["result"])
    if result == {"status": "passed"}:
        status = "passed"
    elif (
        set(result) == {"status", "counterexample"}
        and result.get("status") == "counterexample"
    ):
        status = "counterexample"
    else:
        _sampling_fail("sampling-plan-invalid", "sampling result is invalid")

    completed_fact = observation.get("completed")
    if (
        isinstance(completed_fact, dict)
        and completed_fact.get("authority") == "derived"
        and completed_fact.get("rule") == "runner-success-contract"
        and status != "passed"
    ):
        _sampling_fail(
            "sampling-derivation-incomplete",
            "runner-success derivation requires a passed typed result",
        )
    completed = _layered_fact_value(observation.get("completed"))
    alerts: list[str] = []
    if completed is None:
        alerts.append("required-fact-unavailable:completed")
    if status == "passed" and completed != intent["successful_cases"]:
        alerts.append("completed-budget-not-established")
    if alerts:
        _sampling_fail("sampling-admission-blocked", ",".join(alerts))
    return LayeredSamplingCheckReport(
        intent_identity=intent_identity,
        plan_identity=plan_identity,
        result=status,
        admitted=status == "passed",
        alerts=tuple(alerts),
    )


def check_derivation_program(program_bytes: bytes) -> DerivationCheckReport:
    """Independently validate one canonical evidence derivation.

    The rule table is deliberately implemented here rather than shared with the
    Rust producer. This makes agreement evidence about the model instead of an
    artifact of calling the same validator twice.

    Args:
        program_bytes: Canonical UTF-8 JSON, with at most one final newline.

    Returns:
        The independently derived status and trace identity.

    Raises:
        AssuranceIrError: If structure, authority, dependencies, or rules fail.
    """

    document = program_bytes.removesuffix(b"\n")
    try:
        program = _strict_json(document, require_canonical=True)
    except AssuranceIrError as error:
        code = (
            "derivation-noncanonical"
            if error.code == "IR-DECODE-NONCANONICAL"
            else "derivation-schema-mismatch"
        )
        _derivation_fail(code, str(error))
    _derivation_exact_fields(
        program, {"schema", "claim_id", "facts", "steps", "conclusion"}
    )
    if program["schema"] != DERIVATION_PROGRAM_SCHEMA:
        _derivation_fail("derivation-schema-mismatch", "unsupported program schema")
    claim_id = _derivation_text(program["claim_id"], "claim ID")

    facts: dict[str, dict[str, Any]] = {}
    fact_ids: list[str] = []
    for raw_fact in _derivation_list(program["facts"], "facts"):
        fact = _derivation_object(raw_fact, "fact")
        _validate_derivation_fact(fact)
        fact_id = _derivation_text(fact["id"], "fact ID")
        fact_ids.append(fact_id)
        if fact_id in facts:
            _derivation_fail(
                "derivation-duplicate-identity", "fact identity is duplicated"
            )
        facts[fact_id] = fact
    if fact_ids != sorted(set(fact_ids)):
        _derivation_fail(
            "derivation-duplicate-identity",
            "fact identities must be strictly sorted and unique",
        )
    _validate_derivation_authorities(facts)

    raw_steps = _derivation_list(program["steps"], "steps")
    all_step_ids = [
        _derivation_text(_derivation_object(item, "step").get("id"), "step ID")
        for item in raw_steps
    ]
    judgments: dict[str, dict[str, Any]] = {}
    prior_step: str | None = None
    for raw_step in raw_steps:
        step = _derivation_object(raw_step, "step")
        _derivation_exact_fields(step, {"schema", "id", "rule", "inputs", "conclusion"})
        if step["schema"] != DERIVATION_STEP_SCHEMA:
            _derivation_fail("derivation-schema-mismatch", "unsupported step schema")
        step_id = _derivation_text(step["id"], "step ID")
        if (
            step_id in facts
            or step_id in judgments
            or (prior_step is not None and prior_step >= step_id)
        ):
            _derivation_fail(
                "derivation-duplicate-identity",
                "fact and step identities must be globally unique",
            )
        inputs = _derivation_text_list(step["inputs"], "step inputs")
        if inputs != sorted(set(inputs)):
            _derivation_fail(
                "derivation-dependency-mismatch",
                "step inputs must be strictly sorted and unique",
            )
        for dependency in inputs:
            if dependency in all_step_ids and dependency not in judgments:
                _derivation_fail(
                    "derivation-cycle", f"{step_id} depends on a non-prior step"
                )
            if dependency not in facts and dependency not in judgments:
                _derivation_fail(
                    "derivation-dependency-mismatch",
                    f"{step_id} names unknown input {dependency}",
                )
        _validate_derivation_step(step, facts, judgments)
        judgments[step_id] = _derivation_object(step["conclusion"], "conclusion")
        prior_step = step_id

    root = program["conclusion"]
    if not isinstance(root, str) or root not in judgments:
        _derivation_fail(
            "derivation-root-mismatch", "declared conclusion is not a derived step"
        )
    conclusion = judgments[root]
    if conclusion.get("kind") != "status":
        _derivation_fail(
            "derivation-root-mismatch", "declared root is not a complete status"
        )
    return DerivationCheckReport(
        claim_id=claim_id,
        conclusion=conclusion,
        trace_identity=domain_hash(DERIVATION_TRACE_DOMAIN, canonical_json(program)),
        alerts=(),
    )


def check_generated_derivation_corpus(
    corpus_bytes: bytes,
) -> GeneratedDerivationCheckReport:
    """Check the complete deterministic EXP-0009 generated corpus.

    Args:
        corpus_bytes: Canonical corpus emitted by the Rust generator.

    Returns:
        Independently checked counts and corpus identity.

    Raises:
        AssuranceIrError: If any valid or adversarial program disagrees.
    """

    corpus = _strict_json(corpus_bytes.removesuffix(b"\n"), require_canonical=True)
    _derivation_exact_fields(
        corpus,
        {"schema", "algorithm", "seed", "valid", "adversarial", "corpus_identity"},
    )
    if (
        corpus["schema"] != GENERATED_DERIVATION_SCHEMA
        or corpus["algorithm"] != DERIVATION_GENERATOR
        or corpus["seed"] != 9009
    ):
        _derivation_fail(
            "derivation-generation-invalid", "generated corpus header differs"
        )
    valid = _derivation_list(corpus["valid"], "valid cases")
    adversarial = _derivation_list(corpus["adversarial"], "adversarial cases")
    for raw_case in valid:
        case = _derivation_object(raw_case, "valid case")
        _derivation_exact_fields(case, {"id", "program", "expected_trace_identity"})
        report = check_derivation_program(canonical_json(case["program"]))
        if report.trace_identity != case["expected_trace_identity"]:
            _derivation_fail(
                "derivation-generation-invalid", "valid trace identity differs"
            )
    for raw_case in adversarial:
        case = _derivation_object(raw_case, "adversarial case")
        _derivation_exact_fields(
            case, {"id", "attack", "encoding", "program", "expected"}
        )
        expected = _derivation_text(case["expected"], "expected result")
        encoding = case["encoding"]
        if encoding == "pretty":
            encoded = json.dumps(
                case["program"], ensure_ascii=False, indent=2, sort_keys=True
            ).encode()
        elif encoding == "canonical":
            encoded = canonical_json(case["program"])
        else:
            _derivation_fail(
                "derivation-generation-invalid", "unknown adversarial encoding"
            )
        try:
            report = check_derivation_program(encoded)
        except AssuranceIrError as error:
            if error.code != expected:
                _derivation_fail(
                    "derivation-generation-invalid",
                    f"{case['attack']} expected {expected}, received {error.code}",
                )
        else:
            if expected != "no-admission-consequence" or report.alerts:
                _derivation_fail(
                    "derivation-generation-invalid",
                    f"{case['attack']} unexpectedly passed",
                )
    material = {
        "adversarial": adversarial,
        "algorithm": corpus["algorithm"],
        "schema": corpus["schema"],
        "seed": corpus["seed"],
        "valid": valid,
    }
    identity = domain_hash(DERIVATION_GENERATOR, canonical_json(material))
    if corpus["corpus_identity"] != identity:
        _derivation_fail(
            "derivation-generation-invalid", "generated corpus identity differs"
        )
    return GeneratedDerivationCheckReport(len(valid), len(adversarial), identity)


def _validate_derivation_fact(fact: dict[str, Any]) -> None:
    _derivation_exact_fields(
        fact, {"schema", "id", "authority", "proposition", "sources"}
    )
    if fact["schema"] != DERIVATION_FACT_SCHEMA:
        _derivation_fail("derivation-schema-mismatch", "unsupported fact schema")
    _derivation_text(fact["id"], "fact ID")
    if fact["authority"] not in {
        "registered",
        "observed",
        "reviewed",
        "derived",
        "unavailable",
    }:
        _derivation_fail("derivation-schema-mismatch", "unknown fact authority")
    _validate_derivation_proposition(
        _derivation_object(fact["proposition"], "proposition")
    )
    sources = _derivation_text_list(fact["sources"], "fact sources")
    if sources != sorted(set(sources)):
        _derivation_fail(
            "derivation-dependency-mismatch", "fact sources are not canonical"
        )


def _validate_derivation_proposition(proposition: dict[str, Any]) -> None:
    kind = proposition.get("kind")
    fields = {
        "evidence-passed": {"kind", "evidence_id", "family"},
        "binding-matches": {"kind", "theorem_id", "artifact_id"},
        "assumption-open": {"kind", "assumption_id"},
        "policy-registered": {
            "kind",
            "policy_id",
            "required_formal",
            "required_linkage",
            "allow_assumptions",
        },
        "telemetry": {"kind", "name", "value"},
    }
    if kind not in fields:
        _derivation_fail("derivation-schema-mismatch", "unknown proposition")
    _derivation_exact_fields(proposition, fields[kind])
    if kind == "evidence-passed":
        _derivation_text(proposition["evidence_id"], "evidence ID")
        _derivation_family(proposition["family"])
    elif kind == "binding-matches":
        _derivation_text(proposition["theorem_id"], "theorem ID")
        _derivation_text(proposition["artifact_id"], "artifact ID")
    elif kind == "assumption-open":
        _derivation_text(proposition["assumption_id"], "assumption ID")
    elif kind == "policy-registered":
        _derivation_text(proposition["policy_id"], "policy ID")
        _derivation_formal(proposition["required_formal"])
        _derivation_linkage(proposition["required_linkage"])
        if not isinstance(proposition["allow_assumptions"], bool):
            _derivation_fail("derivation-schema-mismatch", "policy flag is not Boolean")
    else:
        _derivation_text(proposition["name"], "telemetry name")
        if (
            not isinstance(proposition["value"], int)
            or isinstance(proposition["value"], bool)
            or not 0 <= proposition["value"] <= 2**64 - 1
        ):
            _derivation_fail("derivation-schema-mismatch", "telemetry value is invalid")


def _validate_derivation_judgment(judgment: dict[str, Any]) -> None:
    kind = judgment.get("kind")
    fields = {
        "evidence-valid": {"kind", "schema", "evidence_id", "family"},
        "formal": {"kind", "schema", "value"},
        "linkage": {"kind", "schema", "value"},
        "assumption": {"kind", "schema", "value"},
        "status": {"kind", "schema", "formal", "linkage", "assumption", "policy"},
    }
    if kind not in fields:
        _derivation_fail("derivation-schema-mismatch", "unknown judgment")
    _derivation_exact_fields(judgment, fields[kind])
    if judgment["schema"] != DERIVATION_JUDGMENT_SCHEMA:
        _derivation_fail("derivation-schema-mismatch", "unsupported judgment schema")
    if kind == "evidence-valid":
        _derivation_text(judgment["evidence_id"], "evidence ID")
        _derivation_family(judgment["family"])
    elif kind == "formal":
        _derivation_formal(judgment["value"])
    elif kind == "linkage":
        _derivation_linkage(judgment["value"])
    elif kind == "assumption":
        if judgment["value"] not in {"none", "assumed"}:
            _derivation_fail("derivation-schema-mismatch", "unknown assumption facet")
    else:
        _derivation_formal(judgment["formal"])
        _derivation_linkage(judgment["linkage"])
        if judgment["assumption"] not in {"none", "assumed"}:
            _derivation_fail("derivation-schema-mismatch", "unknown assumption facet")
        if judgment["policy"] != "admitted":
            _derivation_fail("derivation-schema-mismatch", "unknown policy decision")


def _validate_derivation_authorities(facts: dict[str, dict[str, Any]]) -> None:
    expected_authorities = {
        "policy-registered": "registered",
        "assumption-open": "reviewed",
        "evidence-passed": "observed",
        "binding-matches": "derived",
        "telemetry": "observed",
    }
    for fact_id, fact in facts.items():
        authority = fact["authority"]
        sources = fact["sources"]
        if authority == "derived":
            if not sources or any(source not in facts for source in sources):
                _derivation_fail(
                    "derivation-authority-mismatch",
                    f"derived fact {fact_id} lacks exact sources",
                )
        elif sources:
            _derivation_fail(
                "derivation-authority-mismatch",
                f"non-derived fact {fact_id} carries sources",
            )
        kind = fact["proposition"]["kind"]
        if authority != "unavailable" and authority != expected_authorities[kind]:
            _derivation_fail(
                "derivation-authority-mismatch",
                f"fact {fact_id} has the wrong authority",
            )
        if kind == "binding-matches":
            proposition = fact["proposition"]
            expected_sources = {
                (
                    source["proposition"].get("evidence_id"),
                    source["proposition"].get("family"),
                )
                for source in (facts[name] for name in sources)
                if source["proposition"]["kind"] == "evidence-passed"
            }
            required = {
                (proposition["theorem_id"], "theorem"),
                (proposition["artifact_id"], "artifact-binding"),
            }
            if len(sources) != 2 or expected_sources != required:
                _derivation_fail(
                    "derivation-binding-mismatch",
                    f"binding fact {fact_id} does not join exact evidence",
                )


def _validate_derivation_step(
    step: dict[str, Any],
    facts: dict[str, dict[str, Any]],
    judgments: dict[str, dict[str, Any]],
) -> None:
    rule = step["rule"]
    known = {
        "evidence-valid",
        "sampled-tested",
        "bounded-tested",
        "theorem-proved",
        "mutation-tested",
        "transcription-open",
        "model-linked",
        "transcription-linked",
        "artifact-bound",
        "assumption-facet",
        "policy-admitted",
    }
    if rule not in known:
        _derivation_fail("derivation-unknown-rule", "unknown or backend-named rule")
    inputs = step["inputs"]
    conclusion = _derivation_object(step["conclusion"], "conclusion")
    _validate_derivation_judgment(conclusion)
    if rule == "evidence-valid":
        fact = _derivation_one_fact(inputs, facts)
        if fact["authority"] == "unavailable":
            _derivation_fail(
                "derivation-admission-blocked", "required evidence is unavailable"
            )
        proposition = fact["proposition"]
        if proposition["kind"] != "evidence-passed":
            _derivation_fail("derivation-rule-input-mismatch", "expected evidence fact")
        expected = {
            "kind": "evidence-valid",
            "schema": DERIVATION_JUDGMENT_SCHEMA,
            "evidence_id": proposition["evidence_id"],
            "family": proposition["family"],
        }
    elif rule in {
        "sampled-tested",
        "bounded-tested",
        "theorem-proved",
        "mutation-tested",
        "transcription-open",
    }:
        expected_family, formal = {
            "sampled-tested": ("sampled-property", "tested"),
            "bounded-tested": ("bounded-check", "tested"),
            "theorem-proved": ("theorem", "proved"),
            "mutation-tested": ("mutation-witness", "tested"),
            "transcription-open": ("trusted-transcription", "open"),
        }[rule]
        judgment = _derivation_one_judgment(inputs, judgments)
        if (
            judgment.get("kind") != "evidence-valid"
            or judgment.get("family") != expected_family
        ):
            _derivation_fail(
                "derivation-rule-input-mismatch", "formal rule received wrong family"
            )
        expected = {
            "kind": "formal",
            "schema": DERIVATION_JUDGMENT_SCHEMA,
            "value": formal,
        }
    elif rule == "model-linked":
        judgment = _derivation_one_judgment(inputs, judgments)
        if judgment.get("kind") != "formal":
            _derivation_fail(
                "derivation-rule-input-mismatch", "model linkage requires formal facet"
            )
        expected = {
            "kind": "linkage",
            "schema": DERIVATION_JUDGMENT_SCHEMA,
            "value": "model-only",
        }
    elif rule == "transcription-linked":
        judgment = _derivation_one_judgment(inputs, judgments)
        if (
            judgment.get("kind") != "evidence-valid"
            or judgment.get("family") != "trusted-transcription"
        ):
            _derivation_fail(
                "derivation-rule-input-mismatch",
                "transcription linkage requires transcription evidence",
            )
        expected = {
            "kind": "linkage",
            "schema": DERIVATION_JUDGMENT_SCHEMA,
            "value": "transcribed",
        }
    elif rule == "artifact-bound":
        expected = _derive_artifact_bound(inputs, facts, judgments)
    elif rule == "assumption-facet":
        expected = _derive_assumption(inputs, facts)
    else:
        expected = _derive_policy(inputs, facts, judgments)
    if conclusion != expected:
        _derivation_fail(
            "derivation-conclusion-mismatch", "rule emitted an invalid conclusion"
        )


def _derive_artifact_bound(
    inputs: list[str],
    facts: dict[str, dict[str, Any]],
    judgments: dict[str, dict[str, Any]],
) -> dict[str, str]:
    if len(inputs) != 3:
        _derivation_fail(
            "derivation-dependency-mismatch", "artifact binding needs three inputs"
        )
    evidence: dict[str, str] = {}
    binding: dict[str, Any] | None = None
    for item in inputs:
        judgment = judgments.get(item)
        if judgment is not None and judgment.get("kind") == "evidence-valid":
            evidence[judgment["family"]] = judgment["evidence_id"]
        fact = facts.get(item)
        if fact is not None and fact["proposition"]["kind"] == "binding-matches":
            if fact["authority"] == "unavailable":
                _derivation_fail(
                    "derivation-admission-blocked", "binding fact is unavailable"
                )
            binding = fact["proposition"]
    if binding is None:
        _derivation_fail(
            "derivation-dependency-mismatch", "artifact binding fact is absent"
        )
    if (
        evidence.get("theorem") != binding["theorem_id"]
        or evidence.get("artifact-binding") != binding["artifact_id"]
    ):
        _derivation_fail(
            "derivation-binding-mismatch", "artifact binding joins different evidence"
        )
    return {
        "kind": "linkage",
        "schema": DERIVATION_JUDGMENT_SCHEMA,
        "value": "artifact-bound",
    }


def _derive_assumption(
    inputs: list[str], facts: dict[str, dict[str, Any]]
) -> dict[str, str]:
    for item in inputs:
        fact = facts.get(item)
        if fact is None:
            _derivation_fail(
                "derivation-dependency-mismatch", "assumption source is not a fact"
            )
        if fact["authority"] == "unavailable":
            _derivation_fail(
                "derivation-admission-blocked", "assumption source is unavailable"
            )
        if fact["proposition"]["kind"] != "assumption-open":
            _derivation_fail(
                "derivation-rule-input-mismatch", "assumption source is incompatible"
            )
    return {
        "kind": "assumption",
        "schema": DERIVATION_JUDGMENT_SCHEMA,
        "value": "assumed" if inputs else "none",
    }


def _derive_policy(
    inputs: list[str],
    facts: dict[str, dict[str, Any]],
    judgments: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if len(inputs) != 4:
        _derivation_fail(
            "derivation-dependency-mismatch", "policy requires four exact inputs"
        )
    policy: dict[str, Any] | None = None
    facets: dict[str, str] = {}
    for item in inputs:
        fact = facts.get(item)
        if (
            fact is not None
            and fact["authority"] == "registered"
            and fact["proposition"]["kind"] == "policy-registered"
        ):
            policy = fact["proposition"]
        judgment = judgments.get(item)
        if judgment is not None and judgment.get("kind") in {
            "formal",
            "linkage",
            "assumption",
        }:
            facets[judgment["kind"]] = judgment["value"]
    if policy is None or set(facets) != {"formal", "linkage", "assumption"}:
        _derivation_fail(
            "derivation-dependency-mismatch", "policy lacks a registered input facet"
        )
    if (
        facets["formal"] != policy["required_formal"]
        or facets["linkage"] != policy["required_linkage"]
        or (facets["assumption"] == "assumed" and not policy["allow_assumptions"])
    ):
        _derivation_fail(
            "derivation-admission-blocked", "registered policy blocks the result"
        )
    return {
        "kind": "status",
        "schema": DERIVATION_JUDGMENT_SCHEMA,
        **facets,
        "policy": "admitted",
    }


def _derivation_one_fact(
    inputs: list[str], facts: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if len(inputs) != 1:
        _derivation_fail(
            "derivation-dependency-mismatch", "rule requires one fact input"
        )
    fact = facts.get(inputs[0])
    if fact is None:
        _derivation_fail("derivation-rule-input-mismatch", "expected a fact input")
    return fact


def _derivation_one_judgment(
    inputs: list[str], judgments: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    if len(inputs) != 1:
        _derivation_fail(
            "derivation-dependency-mismatch", "rule requires one derived input"
        )
    judgment = judgments.get(inputs[0])
    if judgment is None:
        _derivation_fail("derivation-rule-input-mismatch", "expected a derived input")
    return judgment


def _derivation_exact_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        _derivation_fail(
            "derivation-schema-mismatch", "object has missing or unknown fields"
        )


def _derivation_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _derivation_fail("derivation-schema-mismatch", f"{label} must be an object")
    return value


def _derivation_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _derivation_fail("derivation-schema-mismatch", f"{label} must be an array")
    return value


def _derivation_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        _derivation_fail("derivation-schema-mismatch", f"{label} is invalid")
    return value


def _derivation_text_list(value: Any, label: str) -> list[str]:
    items = _derivation_list(value, label)
    return [_derivation_text(item, label) for item in items]


def _derivation_family(value: Any) -> str:
    if value not in {
        "sampled-property",
        "bounded-check",
        "theorem",
        "mutation-witness",
        "trusted-transcription",
        "artifact-binding",
    }:
        _derivation_fail("derivation-schema-mismatch", "unknown evidence family")
    return value


def _derivation_formal(value: Any) -> str:
    if value not in {"open", "tested", "proved"}:
        _derivation_fail("derivation-schema-mismatch", "unknown formal facet")
    return value


def _derivation_linkage(value: Any) -> str:
    if value not in {"model-only", "transcribed", "artifact-bound"}:
        _derivation_fail("derivation-schema-mismatch", "unknown linkage facet")
    return value


def _derivation_fail(code: str, message: str) -> None:
    raise AssuranceIrError(message, code=code)


def _project_portable_record(wrapped: object) -> dict[str, Any]:
    item = _as_object(wrapped)
    record = _as_object(item.get("record"))
    source_kind = _required_text(record, "kind")
    details = {
        field
        for field in (
            "artifact_binding",
            "bounded_check",
            "distribution_reproduction",
            "independence",
            "mutation_witness",
            "python_property",
            "static_check",
            "theorem",
            "trusted_transcription",
        )
        if field in record
    }
    allowed = {
        "artifact-soundness": {"artifact_binding"},
        "bounded-check": {"bounded_check"},
        "example-test": {"distribution_reproduction"},
        "independent-check": {"independence"},
        "mutation-witness": {"mutation_witness"},
        "property-test": {"python_property"},
        "review": set(),
        "static-check": {"static_check"},
        "theorem": {"theorem"},
        "trusted-transcription": {"trusted_transcription"},
    }.get(source_kind, set())
    if len(details) > 1 or not details <= allowed:
        raise AssuranceIrError("portable evidence contains conflicting family detail")

    if source_kind == "example-test" and "distribution_reproduction" in record:
        detail = _distribution_detail(record["distribution_reproduction"])
        family = {"kind": "reproducible-artifact", "detail": detail}
    elif source_kind == "example-test":
        family = {"kind": "example", "detail": {}}
    elif source_kind == "property-test":
        property_value = record.get("python_property")
        if property_value is None:
            provenance = _as_object(record.get("provenance"))
            sampling = {
                "mode": "legacy-backend",
                "contract_identity": _required_text(
                    provenance, "unit_configuration_sha256"
                ),
                "reason": LEGACY_SAMPLING_REASON,
            }
        else:
            property_detail = _as_object(property_value)
            _require_keys(
                property_detail,
                {"schema", "framework", "seed", "framework_version"},
                "property detail",
            )
            if not isinstance(property_detail["seed"], int):
                raise AssuranceIrError("property seed is not an integer")
            sampling = {
                "mode": "explicit",
                "schema": _required_text(property_detail, "schema"),
                "framework": _required_text(property_detail, "framework"),
                "framework_version": _required_text(
                    property_detail, "framework_version"
                ),
                "seed": property_detail["seed"],
            }
        family = {"kind": "sampled-property", "detail": {"sampling": sampling}}
    elif source_kind == "static-check":
        detail = _copy_exact_detail(
            record["static_check"],
            {
                "schema",
                "tool",
                "tool_version",
                "configuration_sha256",
                "targets",
                "diagnostics",
            },
        )
        detail["targets"] = sorted(detail["targets"])
        family = {"kind": "static-consistency", "detail": detail}
    elif source_kind == "independent-check":
        mode = record.get("independence")
        if mode not in {"independent", "common-origin"}:
            raise AssuranceIrError("unknown independence mode")
        family = {
            "kind": "independent-observation",
            "detail": {"independence": mode},
        }
    elif source_kind == "mutation-witness":
        detail = _copy_exact_detail(
            record["mutation_witness"],
            {
                "schema",
                "mutation_id",
                "subject",
                "guard",
                "mutation_sha256",
                "registry",
                "target_preimage",
                "mutant_artifact",
                "target_postimage",
                "witness_source",
                "check_id",
                "baseline_run_index",
                "expected_failure",
                "proof_term_witness",
            },
        )
        expected_failure = _as_object(detail["expected_failure"])
        _require_keys(
            expected_failure,
            {"run_index", "allowed_exit_codes"},
            "expected failure",
        )
        expected_failure["allowed_exit_codes"] = sorted(
            expected_failure["allowed_exit_codes"]
        )
        family = {"kind": "mutation-witness", "detail": detail}
    elif source_kind == "theorem":
        detail = _copy_exact_detail(
            record["theorem"],
            {
                "declaration",
                "statement_encoding",
                "statement_wire",
                "statement_sha256",
                "attributed_claim",
                "proof_environment",
                "axiom_audit_passed",
                "contains_sorry_ax",
                "foundational_axioms",
                "project_axioms",
            },
        )
        detail["foundational_axioms"] = sorted(detail["foundational_axioms"])
        detail["project_axioms"] = sorted(detail["project_axioms"])
        family = {"kind": "universal-source-proof", "detail": detail}
    elif source_kind == "bounded-check":
        detail = _copy_exact_detail(
            record["bounded_check"],
            {"domain", "solver", "harnesses", "unwind_bounds", "assumptions"},
        )
        domain = _as_object(detail["domain"])
        allowed_domain = {"id", "description", "registration_sha256", "cardinality"}
        if (
            not {"id", "description", "registration_sha256"} <= domain.keys()
            or not set(domain) <= allowed_domain
        ):
            raise AssuranceIrError("bounded domain has invalid fields")
        detail["harnesses"] = sorted(detail["harnesses"])
        family = {"kind": "bounded-model-check", "detail": detail}
    elif source_kind == "artifact-soundness":
        detail = _copy_exact_detail(
            record["artifact_binding"], {"theorem_evidence", "artifact"}
        )
        family = {"kind": "artifact-correspondence", "detail": detail}
    elif source_kind == "trusted-transcription":
        detail = _copy_exact_detail(
            record["trusted_transcription"],
            {
                "schema",
                "source",
                "committed_transcription",
                "transcribed_candidate",
                "reencoded_source",
                "driver",
                "transcriber",
                "reencoder",
            },
        )
        family = {"kind": "trusted-transcription", "detail": detail}
    elif source_kind == "review":
        family = {"kind": "human-review", "detail": {}}
    else:
        raise AssuranceIrError(f"unsupported portable evidence family {source_kind}")

    return {
        "content_sha256": _required_text(item, "sha256"),
        "unit_id": _required_text(record, "unit_id"),
        "claims": _text_list(record, "claim_ids"),
        "inventory": _text_list(record, "inventoried_targets"),
        "family": family,
    }


def _distribution_detail(value: object) -> dict[str, Any]:
    detail = _as_object(value)
    required = {
        "schema",
        "format",
        "run_digests",
        "registered_digest",
        "source_date_epoch",
        "build_backend_name",
        "build_backend_version",
    }
    optional = {"npm_integrity", "member_inventory"}
    if not required <= detail.keys() or not set(detail) <= required | optional:
        raise AssuranceIrError("distribution detail has invalid fields")
    result = dict(detail)
    result.setdefault("member_inventory", [])
    return result


def _copy_exact_detail(value: object, fields: set[str]) -> dict[str, Any]:
    detail = _as_object(value)
    _require_keys(detail, fields, "portable family detail")
    return json.loads(json.dumps(detail))


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
    case_source = _object(root, "source")
    _required_text(case_source, "sha256")
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
        ):
            _require_sorted_unique(_text_list(claim, field))
        registered_inputs = _text_list(claim, "registered_inputs")
        _require_sorted_unique(registered_inputs)
        if claim.get("source") is not None:
            claim_source = _object(claim, "source")
            _required_text(claim_source, "logical_name")
            _required_text(claim_source, "sha256")
            if not isinstance(claim_source.get("size_bytes"), int):
                _fail("IR-DECODE-INVALID", "claim source size is required")
            _required_text(_object(claim, "meaning"), "schema")
            _required_text(_object(claim, "meaning"), "statement")
            _required_text(_object(claim, "presentation"), "title")
            _required_text(_object(claim, "admission"), "policy")
            _validate_subject_closure(
                _object(claim, "subject_closure"), registered_inputs
            )
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
        request = _object(item, "request") if authority == "registered" else None
        if authority == "portable-receipt":
            portable_receipt = True
            if item.get("schema") != "proofbound-evidence/3":
                _fail(
                    "IR-PORTABLE-EVIDENCE-SCHEMA",
                    "portable evidence schema is missing or unsupported",
                )
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
        _validate_family_detail(kind, detail)
        if request is not None:
            _validate_registered_family_join(kind, detail, request)
        kinds.append(kind)

        declared_fact_schemas = detail.get("required_fact_schemas", [])
        if not isinstance(declared_fact_schemas, list) or any(
            not isinstance(schema, str) for schema in declared_fact_schemas
        ):
            _fail("IR-DECODE-INVALID", "required_fact_schemas must be an array")

        backend = _object(item, "backend")
        for fact_value in _list(backend, "retained_facts"):
            fact = _as_object(fact_value)
            _require_exact_fields(
                fact, {"schema", "required"}, {"value", "payload_sha256"}
            )
            if not isinstance(fact.get("required"), bool):
                _fail("IR-DECODE-INVALID", "retained fact disposition is required")
            if (
                fact.get("required") is True
                and fact.get("schema") not in declared_fact_schemas
            ):
                _fail(
                    "IR-BACKEND-UNKNOWN-REQUIRED",
                    "unknown required retained fact",
                )
            if fact.get("schema") != "proofbound-python-property/1":
                if (
                    fact["required"]
                    or "value" in fact
                    or not isinstance(fact.get("payload_sha256"), str)
                ):
                    _fail(
                        "IR-BACKEND-UNKNOWN-OPTIONAL",
                        "unknown optional fact must retain only its canonical payload identity",
                    )
                continue
            if "payload_sha256" in fact:
                _fail(
                    "IR-BACKEND-FACT-MISMATCH",
                    "known retained fact must use its typed value",
                )
            retained_value = _as_object(fact.get("value"))
            _require_exact_fields(retained_value, {"configuration_sha256"})
            configuration_sha256 = _required_text(
                retained_value, "configuration_sha256"
            )
            if request is None or "family_configuration" not in request:
                _fail(
                    "IR-BACKEND-FACT-MISMATCH",
                    "retained fact has no registered family configuration",
                )
            expected_configuration = domain_hash(
                PROJECTION_DOMAIN, canonical_json(request["family_configuration"])
            )
            if configuration_sha256 != expected_configuration:
                _fail(
                    "IR-BACKEND-FACT-MISMATCH",
                    "retained fact identity differs from the registered family configuration",
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
            if artifact != case_source:
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
    reported = _object(root, "reported")
    if portable_receipt:
        _validate_portable_joins(
            programme,
            claims,
            evidence,
            reported,
            _object(root, "policy"),
        )

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
    _validate_reported(reported, kinds, assumed or obligations, exact)


def _validate_programme(programme: dict[str, Any], portable_receipt: bool) -> None:
    if portable_receipt:
        _required_text(programme, "release_schema")
        project = _object(programme, "project")
        for field in ("id", "revision", "tree_state"):
            _required_text(project, field)
        if not isinstance(project.get("tier"), int):
            _fail("IR-DECODE-INVALID", "portable project tier is required")
        graph = _object(programme, "graph")
        _validate_graph_semantics(graph)
        graph_schema = _required_text(graph, "schema")
        graph_sha256 = _required_text(programme, "graph_sha256")
        if domain_hash(graph_schema, canonical_json(graph)) != graph_sha256:
            _fail(
                "IR-PROGRAMME-GRAPH-IDENTITY",
                "portable graph identity does not match its typed content",
            )
        if not _list(programme, "policies"):
            _fail(
                "IR-PROGRAMME-POLICY-OMITTED",
                "portable programme must retain its policies",
            )
    for closure_value in _list(programme, "closures"):
        closure = _as_object(closure_value)
        schema = _required_text(closure, "schema")
        sha256 = _required_text(closure, "sha256")
        kind = _required_text(closure, "kind")
        source_members = []
        for member in _list(closure, "members"):
            artifact = _as_object(member)
            _validate_artifact(artifact)
            source_members.append(
                {
                    "path": artifact["logical_name"],
                    "sha256": artifact["sha256"],
                    "size_bytes": artifact["size_bytes"],
                }
            )
        source_record = {"schema": schema, "kind": kind, "members": source_members}
        if domain_hash(schema, canonical_json(source_record)) != sha256:
            _fail(
                "IR-PROGRAMME-CLOSURE-IDENTITY",
                "portable closure identity does not match its typed content",
            )
    for assumption in _list(programme, "assumptions"):
        _typed_assumption(_as_object(assumption))
    for premise in _list(programme, "premises"):
        _typed_premise(_as_object(premise))
    for policy in _list(programme, "policies"):
        _typed_policy(_as_object(policy))
    for artifact in _list(programme, "sealed_artifacts"):
        _validate_artifact(_as_object(artifact))
    components = [
        _as_object(component) for component in _list(programme, "tcb_components")
    ]
    identities = []
    for component in components:
        _require_exact_fields(component, {"name", "version", "identity_sha256"})
        identities.append(
            (
                _required_text(component, "name"),
                _required_text(component, "version"),
                _required_text(component, "identity_sha256"),
            )
        )
    if identities != sorted(set(identities)):
        _fail("IR-PROGRAMME-TCB-MISMATCH", "TCB components must be sorted and unique")
    if components:
        ledger = {"components": components, "schema": "proofbound-tcb-ledger/1"}
        data = canonical_json(ledger)
        sealed = next(
            (
                _as_object(artifact)
                for artifact in _list(programme, "sealed_artifacts")
                if artifact.get("logical_name") == "tcb-ledger.json"
            ),
            None,
        )
        if (
            sealed is None
            or sealed.get("sha256") != _sha256(data)
            or sealed.get("size_bytes") != len(data)
        ):
            _fail(
                "IR-PROGRAMME-TCB-MISMATCH",
                "typed TCB components differ from the sealed ledger identity",
            )
    for field in (
        "assumptions",
        "premises",
        "publication_blockers",
        "derivation_traces",
    ):
        _list(programme, field)


def _validate_portable_joins(
    programme: dict[str, Any],
    claims: list[object],
    evidence: list[object],
    reported: dict[str, Any],
    derived_policy: dict[str, Any],
) -> None:
    project = _object(programme, "project")
    revision = _required_text(project, "revision")
    tree_state = _required_text(project, "tree_state")
    closure_ids = {
        _required_text(_as_object(closure), "sha256")
        for closure in _list(programme, "closures")
    }
    claim_ids = {_required_text(_as_object(claim), "id") for claim in claims}
    statuses = [_as_object(status) for status in _list(programme, "reported_statuses")]
    status_claims = {_required_text(status, "claim_id") for status in statuses}
    if len(status_claims) != len(statuses):
        _fail(
            "IR-DECODE-DUPLICATE",
            "portable reported statuses contain duplicate claim ownership",
        )
    if claim_ids != status_claims:
        _fail(
            "IR-PROGRAMME-STATUS-MISMATCH",
            "portable reported statuses do not cover the exact claim set",
        )
    claims_by_id = {
        _required_text(_as_object(claim), "id"): _as_object(claim) for claim in claims
    }
    for status in statuses:
        claim = claims_by_id[_required_text(status, "claim_id")]
        presentation = _object(claim, "presentation")
        if status.get("public_statement") != presentation.get("public_statement"):
            _fail(
                "IR-PROGRAMME-PRESENTATION-MISMATCH",
                "reported public statement differs from the claim presentation",
            )
        if any(
            status.get(field) != reported.get(field)
            for field in ("formal", "linkage", "assumption")
        ):
            _fail(
                "IR-PROGRAMME-STATUS-MISMATCH",
                "portable reported status differs from independent derivation",
            )
        if status.get("policy_admitted") != reported.get("policy_admitted"):
            _fail(
                "IR-PROGRAMME-STATUS-MISMATCH",
                "portable policy decision differs from independent derivation",
            )

    policies = {
        _required_text(policy, "id"): policy
        for policy in (_as_object(item) for item in _list(programme, "policies"))
    }
    required_components = _text_list(derived_policy, "required_components")
    for claim in claims_by_id.values():
        policy_id = _required_text(_object(claim, "admission"), "policy")
        policy = policies.get(policy_id)
        if policy is None or _text_list(policy, "components") != required_components:
            _fail(
                "IR-PROGRAMME-POLICY-MISMATCH",
                "effective policy differs from the policy used by status derivation",
            )
    _validate_derivation_traces(programme, list(claims_by_id.values()), evidence)
    blockers = [
        status["claim_id"]
        for status in statuses
        if status.get("policy_admitted") is False
    ]
    if _text_list(programme, "publication_blockers") != blockers:
        _fail(
            "IR-PROGRAMME-BLOCKER-MISMATCH",
            "publication blockers differ from non-admitted statuses",
        )
    _validate_ledger_joins(programme, claim_ids, evidence)
    tcb_components = [
        _as_object(component) for component in _list(programme, "tcb_components")
    ]
    for item in (_as_object(value) for value in evidence):
        provenance = _object(item, "provenance")
        for role in ("tool", "adapter"):
            identity = provenance.get(role)
            if identity is None:
                continue
            identity = _as_object(identity)
            if not any(
                all(
                    component.get(field) == identity.get(field)
                    for field in ("name", "version", "identity_sha256")
                )
                for component in tcb_components
            ):
                _fail(
                    "IR-PROGRAMME-TCB-MISMATCH",
                    "observed tool or adapter is absent from the typed TCB ledger",
                )
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


def _validate_derivation_traces(
    programme: dict[str, Any],
    claims: list[dict[str, Any]],
    evidence: list[object],
) -> None:
    project_tier = _object(programme, "project").get("tier")
    if not isinstance(project_tier, int):
        _fail("IR-DECODE-INVALID", "project tier is missing")
    policies = {
        _required_text(policy, "id"): policy
        for policy in (_as_object(item) for item in _list(programme, "policies"))
    }
    evidence_by_id = {
        _required_text(item, "content_sha256"): item
        for item in (_as_object(value) for value in evidence)
    }
    expected: list[dict[str, Any]] = []
    for claim in claims:
        cited = _text_list(claim, "cited_evidence")
        cited_records = [
            evidence_by_id[item] for item in cited if item in evidence_by_id
        ]
        passed_kinds = [
            _required_text(_object(item, "family"), "kind")
            for item in cited_records
            if item.get("outcome") == "passed"
        ]
        formal, formal_rule = _derive_ir_formal(passed_kinds)
        linkage, linkage_rule = _derive_ir_linkage(passed_kinds)
        assumption_inputs = sorted(
            set(_text_list(claim, "assumptions"))
            | set(_text_list(claim, "premises"))
            | set(_text_list(claim, "open_obligations"))
        )
        admission = _object(claim, "admission")
        policy_id = _required_text(admission, "policy")
        policy = policies.get(policy_id)
        if policy is None:
            _fail("IR-DERIVATION-TRACE-MISMATCH", "claim derivation policy is absent")
        required_components = _text_list(policy, "components")
        native = any(item.get("evaluation") == "native" for item in cited_records)
        satisfied_components = [
            component
            for component in required_components
            if _policy_component_satisfied(
                component, formal, linkage, native, cited_records
            )
        ]
        blockers: list[str] = []
        if len(cited_records) != len(cited):
            blockers.append("cited-evidence-missing")
        if any(item.get("outcome") != "passed" for item in cited_records):
            blockers.append("cited-evidence-not-passed")
        blockers.extend(
            f"policy-component:{component}"
            for component in required_components
            if component not in satisfied_components
        )
        if policy.get("require_no_assumptions") is True and assumption_inputs:
            blockers.append("assumptions-forbidden")
        blockers.extend(
            f"required-evidence:{required}"
            for required in _text_list(policy, "additional_required_evidence")
            if required not in cited
        )
        tier = admission.get("tier")
        expected.append(
            {
                "schema": "proofbound-ir-derivation-trace/1",
                "claim_id": _required_text(claim, "id"),
                "formal_value_and_rule": {
                    "value": formal,
                    "rule": formal_rule,
                },
                "linkage_value_and_rule": {
                    "value": linkage,
                    "rule": linkage_rule,
                },
                "assumption_value_and_inputs": {
                    "value": "ASSUMED" if assumption_inputs else "NONE",
                    "inputs": assumption_inputs,
                },
                "policy_id": policy_id,
                "effective_tier": tier if isinstance(tier, int) else project_tier,
                "required_policy_components": required_components,
                "satisfied_policy_components": satisfied_components,
                "load_bearing_evidence": cited,
                "open_obligations": _text_list(claim, "open_obligations"),
                "blockers": sorted(set(blockers)),
            }
        )
    expected.sort(key=lambda trace: trace["claim_id"])
    if _list(programme, "derivation_traces") != expected:
        _fail(
            "IR-DERIVATION-TRACE-MISMATCH",
            "registered derivation traces differ from independently derived traces",
        )
    admitted = [trace["claim_id"] for trace in expected if not trace["blockers"]]
    blocked = [trace["claim_id"] for trace in expected if trace["blockers"]]
    publication = {
        "admitted_claims": admitted,
        "blocked_claims": blocked,
        "blockers": [
            f"{trace['claim_id']}:{blocker}"
            for trace in expected
            for blocker in trace["blockers"]
        ],
    }
    if programme.get("publication_trace") != publication:
        _fail(
            "IR-DERIVATION-TRACE-MISMATCH",
            "publication trace differs from independently derived claim blockers",
        )


def _derive_ir_formal(kinds: list[str]) -> tuple[str, str]:
    if "universal-source-proof" in kinds:
        return "PROVED", "universal-source-proof"
    if "bounded-model-check" in kinds:
        return "BOUNDED_CHECKED", "bounded-model-check"
    if kinds and all(kind == "trusted-transcription" for kind in kinds):
        return "OPEN", "no-functional-evidence"
    return "TESTED", "empirical-evidence"


def _derive_ir_linkage(kinds: list[str]) -> tuple[str, str]:
    if "artifact-correspondence" in kinds:
        return "ARTIFACT_BOUND", "artifact-correspondence"
    if "source-correspondence" in kinds:
        return "REFINED", "source-correspondence"
    if "trusted-transcription" in kinds:
        return "TRANSCRIBED", "trusted-transcription"
    return "MODEL_ONLY", "no-artifact-binding"


def _validate_ledger_joins(
    programme: dict[str, Any], claim_ids: set[str], evidence: list[object]
) -> None:
    graph = _object(programme, "graph")
    nodes = {
        _required_text(node, "id"): _required_text(node, "kind")
        for node in (_as_object(item) for item in _list(graph, "nodes"))
    }
    evidence_ids = {
        item["content_sha256"]
        for item in (_as_object(value) for value in evidence)
        if isinstance(item.get("content_sha256"), str)
    }
    for assumption in (_as_object(item) for item in _list(programme, "assumptions")):
        node_id = _required_text(assumption, "node_id")
        affected = _text_list(assumption, "affected_claims")
        reviews = _text_list(assumption, "review_evidence")
        if (
            nodes.get(node_id) != "assumption"
            or any(claim not in claim_ids for claim in affected)
            or any(review not in evidence_ids for review in reviews)
        ):
            _fail(
                "IR-PROGRAMME-LEDGER-JOIN",
                "assumption ledger references absent programme identities",
            )
    for premise in (_as_object(item) for item in _list(programme, "premises")):
        node_id = _required_text(premise, "node_id")
        theorem = premise.get("theorem_evidence")
        discharge = premise.get("discharge")
        discharged_by = (
            discharge.get("theorem_evidence") if isinstance(discharge, dict) else None
        )
        if (
            nodes.get(node_id) != "premise"
            or (theorem is not None and theorem not in evidence_ids)
            or (discharged_by is not None and discharged_by not in evidence_ids)
        ):
            _fail(
                "IR-PROGRAMME-LEDGER-JOIN",
                "premise ledger references absent programme identities",
            )


def _validate_subject_closure(
    closure: dict[str, Any], registered_inputs: list[str]
) -> None:
    _require_exact_fields(closure, {"schema", "sha256", "selectors", "members"})
    schema = _required_text(closure, "schema")
    if schema != "proofbound-ir-subject-closure/1":
        _fail("IR-CLAIM-SUBJECT-CLOSURE", "unsupported subject-closure schema")
    selectors = _text_list(closure, "selectors")
    _require_sorted_unique(selectors)
    members = [_as_object(member) for member in _list(closure, "members")]
    for member in members:
        _validate_artifact(member)
    if (
        selectors != registered_inputs
        or [_required_text(member, "logical_name") for member in members] != selectors
    ):
        _fail(
            "IR-CLAIM-SUBJECT-CLOSURE",
            "subject closure differs from the registered source selectors",
        )
    material = {"schema": schema, "selectors": selectors, "members": members}
    if domain_hash(schema, canonical_json(material)) != closure["sha256"]:
        _fail(
            "IR-CLAIM-SUBJECT-CLOSURE",
            "subject closure identity differs from its typed members",
        )


def _validate_artifact(artifact: dict[str, Any]) -> None:
    _required_text(artifact, "logical_name")
    _required_text(artifact, "sha256")
    if not isinstance(artifact.get("size_bytes"), int):
        _fail("IR-DECODE-INVALID", "artifact size is required")


def _validate_family_detail(kind: str, detail: dict[str, Any]) -> None:
    if kind == "mutation-witness":
        _require_exact_fields(detail, {"schema", "subject"}, {"mutation"})
        _required_text(detail, "subject")
        if "mutation" in detail:
            mutation = _as_object(detail["mutation"])
            _require_exact_fields(mutation, {"schema", "registry"})
            _required_text(mutation, "schema")
            _required_text(mutation, "registry")
        return
    if kind == "artifact-correspondence":
        _require_exact_fields(detail, {"schema", "artifact"})
        _validate_artifact(_object(detail, "artifact"))
        return
    if kind == "sampled-property":
        _require_exact_fields(detail, {"schema"}, {"property", "required_fact_schemas"})
        if "property" not in detail:
            if "required_fact_schemas" in detail:
                _fail(
                    "IR-PROGRAMME-TYPED-RECORD",
                    "sampled-property facts require a typed property registration",
                )
            return
        property_registration = _object(detail, "property")
        _require_exact_fields(property_registration, {"schema", "framework", "seed"})
        schema = _required_text(property_registration, "schema")
        _required_text(property_registration, "framework")
        if type(property_registration.get("seed")) is not int:
            _fail(
                "IR-PROGRAMME-TYPED-RECORD",
                "sampled-property seed must be an unsigned integer",
            )
        if _text_list(detail, "required_fact_schemas") != [schema]:
            _fail(
                "IR-PROGRAMME-TYPED-RECORD",
                "sampled-property fact declaration differs from its typed property",
            )
        return
    if kind == "distribution-reproduction":
        _require_exact_fields(detail, {"schema"}, {"distribution"})
        if "distribution" in detail:
            distribution = _object(detail, "distribution")
            _require_exact_fields(
                distribution,
                {
                    "schema",
                    "format",
                    "artifact_name",
                    "artifact_sha256",
                    "source_date_epoch",
                },
            )
            for field in ("schema", "format", "artifact_name", "artifact_sha256"):
                _required_text(distribution, field)
            if type(distribution.get("source_date_epoch")) is not int:
                _fail(
                    "IR-PROGRAMME-TYPED-RECORD",
                    "distribution epoch must be an unsigned integer",
                )
        return
    if kind == "bounded-model-check":
        _require_exact_fields(detail, {"schema"}, {"bounded_domain"})
        if "bounded_domain" in detail:
            bounded = _object(detail, "bounded_domain")
            _require_exact_fields(
                bounded, {"id", "description", "cardinality", "ordering_key"}
            )
            _required_text(bounded, "id")
            _required_text(bounded, "description")
            ordering_key = _list(bounded, "ordering_key")
            if type(bounded.get("cardinality")) is not int or any(
                type(item) is not int for item in ordering_key
            ):
                _fail(
                    "IR-PROGRAMME-TYPED-RECORD",
                    "bounded-domain cardinality and ordering key must be unsigned",
                )
        return
    if kind == "universal-source-proof":
        _require_exact_fields(detail, {"schema"}, {"theorem"})
        if "theorem" in detail:
            _required_text(detail, "theorem")
        return
    if kind in {
        "example",
        "static-consistency",
        "finite-exhaustive",
        "trusted-transcription",
        "source-correspondence",
    }:
        _require_exact_fields(detail, {"schema"})
        return
    _fail("IR-EVIDENCE-FAMILY-DETAIL", "unknown evidence family detail")


def _validate_registered_family_join(
    kind: str, detail: dict[str, Any], request: dict[str, Any]
) -> None:
    configuration_field = {
        "sampled-property": "property",
        "mutation-witness": "mutation",
        "distribution-reproduction": "distribution",
        "bounded-model-check": "bounded_domain",
        "universal-source-proof": "theorem",
    }.get(kind)
    projected = {}
    if configuration_field is not None and configuration_field in detail:
        projected[configuration_field] = detail[configuration_field]
    if request.get("family_configuration") != projected:
        _fail(
            "IR-EVIDENCE-FAMILY-DETAIL",
            "typed family detail differs from the registered family configuration",
        )


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
        program = _release_program(root, case, len(source_bytes), source_bytes)
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
        registered_inputs = sorted(_optional_text_list(claim, "source_roots"))
        subject_closure = _subject_closure(root, source["path"], registered_inputs)
        projected = {
            "id": _required_text(claim, "id"),
            "subject": _required_text(claim, "subject"),
            "subject_closure": subject_closure,
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
            "registered_inputs": registered_inputs,
            "admission": {
                "policy": _required_text(claim, "profile"),
                "tier": claim.get("tier"),
                "primary_linkage": claim.get("primary_linkage"),
            },
        }
        if _claim_source_projection(claim, subject_closure) != _claim_ir_projection(
            projected
        ):
            raise AssuranceIrError(
                f"claim {projected['id']} is not lossless under the registered semantic projection"
            )
        claims.append(projected)
    claims.sort(key=lambda claim: claim["id"])
    expected_ids = sorted(case["claim_ids"])
    if claims and [claim["id"] for claim in claims] != expected_ids:
        raise AssuranceIrError(f"claim source attribution differs for {case['id']}")
    return claims


def _claim_source_projection(
    claim: dict[str, Any], subject_closure: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "schema": _required_text(claim, "schema"),
        "id": _required_text(claim, "id"),
        "title": _required_text(claim, "title"),
        "statement": _required_text(claim, "statement"),
        "public_language": claim.get("public_language"),
        "public_statement": None,
        "subject": _required_text(claim, "subject"),
        "subject_closure": subject_closure,
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
        "public_statement": presentation["public_statement"],
        "subject": claim["subject"],
        "subject_closure": claim["subject_closure"],
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
    if (
        kind == "sampled-property"
        and "property" in registration["family_configuration"]
    ):
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
    program = {
        "schema": CASE_SCHEMA,
        "case_id": case["id"],
        "evidence_family": case["evidence_family"],
        "source": _source_artifact(case["source"], source_size),
        "claims": claims,
        "evidence": [
            {
                "authority": "registered",
                "schema": None,
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
                        registration["family_configuration"],
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
    return program


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
            "subject_closure": None,
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
                "schema": None,
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


def _release_tcb_components(
    root: Path, case: dict[str, Any], receipt: dict[str, Any]
) -> list[dict[str, str]]:
    sealed = next(
        (
            artifact
            for artifact in receipt["sealed_files"]
            if artifact.get("path", artifact.get("logical_name")) == "tcb-ledger.json"
        ),
        None,
    )
    if sealed is None:
        raise AssuranceIrError("portable release does not seal tcb-ledger.json")
    path = (root / case["source"]["path"]).parent / "tcb-ledger.json"
    data = path.read_bytes()
    if _sha256(data) != sealed["sha256"] or len(data) != sealed["size_bytes"]:
        raise AssuranceIrError("sealed TCB ledger identity differs from its bytes")
    ledger = _strict_json(data, require_canonical=True)
    _require_keys(ledger, {"schema", "components"}, "TCB ledger")
    if ledger["schema"] != "proofbound-tcb-ledger/1":
        raise AssuranceIrError("unsupported TCB ledger schema")
    components = []
    for component in ledger["components"]:
        _require_keys(
            component, {"name", "version", "identity_sha256"}, "TCB component"
        )
        components.append(
            {
                "name": _required_text(component, "name"),
                "version": _required_text(component, "version"),
                "identity_sha256": _required_text(component, "identity_sha256"),
            }
        )
    identities = [
        (component["name"], component["version"], component["identity_sha256"])
        for component in components
    ]
    if not components or identities != sorted(set(identities)):
        raise AssuranceIrError("TCB components must be sorted and unique")
    return components


def _release_program(
    root: Path, case: dict[str, Any], source_size: int, data: bytes
) -> dict[str, Any]:
    receipt = _strict_json(data, require_canonical=False)
    tcb_components = _release_tcb_components(root, case, receipt)
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
                "schema": record.get("schema"),
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
                    "additional_closures": [
                        {"kind": closure["kind"], "sha256": closure["sha256"]}
                        for closure in provenance.get("additional_closures", [])
                    ],
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
                    "python_plugins": [
                        {
                            "module": plugin["module"],
                            "distribution": plugin["distribution"],
                            "version": plugin["version"],
                            "origin_sha256": plugin["origin_sha256"],
                        }
                        for plugin in provenance.get("python_plugins", [])
                    ],
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
    program = {
        "schema": CASE_SCHEMA,
        "case_id": case["id"],
        "evidence_family": case["evidence_family"],
        "source": _source_artifact(case["source"], source_size),
        "claims": claims,
        "evidence": evidence,
        "cache": {"registered_inputs": [], "execution_inputs": []},
        "policy": {"required_components": ["ledger"]},
        "programme": _release_programme(receipt, tcb_components),
        "reported": case["expected_claim"],
        "exact_status": True,
    }
    if _release_source_semantics(
        receipt, case, source_size, tcb_components
    ) != _release_ir_semantics(program):
        raise AssuranceIrError(
            "portable release is not lossless under the registered semantic projection"
        )
    return program


def _empty_programme() -> dict[str, Any]:
    return {
        "release_schema": None,
        "project": None,
        "graph": None,
        "graph_sha256": None,
        "assumptions": [],
        "premises": [],
        "policies": [],
        "closures": [],
        "sealed_artifacts": [],
        "tcb_components": [],
        "publication_blockers": [],
        "reported_statuses": [],
        "derivation_traces": [],
    }


def _release_programme(
    receipt: dict[str, Any], tcb_components: list[dict[str, str]]
) -> dict[str, Any]:
    derivation_traces, publication_trace = _release_derivation_traces(receipt)
    return {
        "release_schema": receipt["schema"],
        "project": {
            "id": receipt["project"],
            "revision": receipt["project_revision"],
            "tier": receipt["project_tier"],
            "tree_state": receipt["tree_state"],
        },
        "graph": _typed_graph(receipt["graph"]),
        "graph_sha256": receipt["graph_sha256"],
        "assumptions": [_typed_assumption(item) for item in receipt["assumptions"]],
        "premises": [_typed_premise(item) for item in receipt["premises"]],
        "policies": [_typed_policy(item) for item in receipt["policies"]],
        "closures": [
            {
                "sha256": closure["sha256"],
                "schema": closure["record"]["schema"],
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
        "tcb_components": tcb_components,
        "publication_blockers": sorted(
            status["claim_id"]
            for status in receipt["reported_statuses"]
            if status["policy_admitted"] is False
        ),
        "reported_statuses": [
            {
                "claim_id": status["claim_id"],
                "formal": status["formal"],
                "linkage": status["linkage"],
                "assumption": status["assumption"],
                "policy_admitted": status["policy_admitted"],
                "public_statement": status["public_statement"],
                "assumptions": status["assumptions"],
                "undischarged_premises": status["undischarged_premises"],
            }
            for status in receipt["reported_statuses"]
        ],
        "derivation_traces": derivation_traces,
        "publication_trace": publication_trace,
    }


def _release_derivation_traces(
    receipt: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    evidence_by_id = {item["sha256"]: item["record"] for item in receipt["evidence"]}
    policies = {policy["id"]: policy for policy in receipt["policies"]}
    traces: list[dict[str, Any]] = []
    for claim in receipt["claims"]:
        cited = sorted(claim.get("cited_evidence", []))
        cited_records = [
            evidence_by_id[item] for item in cited if item in evidence_by_id
        ]
        passed_kinds = [
            record["kind"]
            for record in cited_records
            if record.get("outcome") == "passed"
        ]
        formal, formal_rule = _derive_formal_facet(passed_kinds)
        linkage, linkage_rule = _derive_linkage_facet(passed_kinds)
        assumption_inputs = sorted(
            set(claim.get("assumptions", []))
            | set(claim.get("premises", []))
            | set(_obligation_ids(claim))
        )
        policy = policies[claim["policy"]]
        required_components = list(policy["components"])
        native = any(
            record.get("evaluation_mode") == "native" for record in cited_records
        )
        satisfied_components = [
            component
            for component in required_components
            if _policy_component_satisfied(
                component, formal, linkage, native, cited_records
            )
        ]
        blockers: list[str] = []
        if len(cited_records) != len(cited):
            blockers.append("cited-evidence-missing")
        if any(record.get("outcome") != "passed" for record in cited_records):
            blockers.append("cited-evidence-not-passed")
        blockers.extend(
            f"policy-component:{component}"
            for component in required_components
            if component not in satisfied_components
        )
        if policy.get("require_no_assumptions") is True and assumption_inputs:
            blockers.append("assumptions-forbidden")
        blockers.extend(
            f"required-evidence:{required}"
            for required in policy.get("additional_required_evidence", [])
            if required not in cited
        )
        traces.append(
            {
                "schema": "proofbound-ir-derivation-trace/1",
                "claim_id": claim["id"],
                "formal_value_and_rule": {
                    "value": formal,
                    "rule": formal_rule,
                },
                "linkage_value_and_rule": {
                    "value": linkage,
                    "rule": linkage_rule,
                },
                "assumption_value_and_inputs": {
                    "value": "ASSUMED" if assumption_inputs else "NONE",
                    "inputs": assumption_inputs,
                },
                "policy_id": claim["policy"],
                "effective_tier": (
                    claim["tier"]
                    if claim.get("tier") is not None
                    else receipt["project_tier"]
                ),
                "required_policy_components": required_components,
                "satisfied_policy_components": satisfied_components,
                "load_bearing_evidence": cited,
                "open_obligations": _obligation_ids(claim),
                "blockers": sorted(set(blockers)),
            }
        )
    traces.sort(key=lambda trace: trace["claim_id"])
    admitted = [trace["claim_id"] for trace in traces if not trace["blockers"]]
    blocked = [trace["claim_id"] for trace in traces if trace["blockers"]]
    blockers = [
        f"{trace['claim_id']}:{blocker}"
        for trace in traces
        for blocker in trace["blockers"]
    ]
    return traces, {
        "admitted_claims": admitted,
        "blocked_claims": blocked,
        "blockers": blockers,
    }


def _obligation_ids(claim: dict[str, Any]) -> list[str]:
    obligations: list[str] = []
    for item in claim.get("open_obligations", []):
        if isinstance(item, str):
            obligations.append(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            obligations.append(item["id"])
        else:
            raise AssuranceIrError("open obligation has no typed identity")
    return sorted(set(obligations))


def _derive_formal_facet(kinds: list[str]) -> tuple[str, str]:
    if "theorem" in kinds:
        return "PROVED", "universal-source-proof"
    if "bounded-check" in kinds:
        return "BOUNDED_CHECKED", "bounded-model-check"
    if kinds and all(kind == "trusted-transcription" for kind in kinds):
        return "OPEN", "no-functional-evidence"
    return "TESTED", "empirical-evidence"


def _derive_linkage_facet(kinds: list[str]) -> tuple[str, str]:
    if "artifact-soundness" in kinds:
        return "ARTIFACT_BOUND", "artifact-correspondence"
    if "source-refinement" in kinds:
        return "REFINED", "source-correspondence"
    if "trusted-transcription" in kinds:
        return "TRANSCRIBED", "trusted-transcription"
    return "MODEL_ONLY", "no-artifact-binding"


def _policy_component_satisfied(
    component: str,
    formal: str,
    linkage: str,
    native: bool,
    cited_records: list[dict[str, Any]],
) -> bool:
    if component == "ledger":
        return bool(cited_records)
    if component in {"kernel", "kernel-with-assumptions"}:
        return formal == "PROVED"
    if component == "artifact-bound":
        return linkage == "ARTIFACT_BOUND"
    if component == "native-evaluated":
        return native
    if component == "transcribed":
        return linkage == "TRANSCRIBED"
    return False


def _typed_graph(graph: dict[str, Any]) -> dict[str, Any]:
    _require_exact_fields(graph, {"schema", "nodes", "edges", "mutual_theorem_groups"})
    return {
        "schema": graph["schema"],
        "nodes": [
            _typed_optional_record(node, {"id", "kind"}, {"proof_environment"})
            for node in graph["nodes"]
        ],
        "edges": [
            _typed_optional_record(edge, {"from", "to", "kind"}, set())
            for edge in graph["edges"]
        ],
        "mutual_theorem_groups": [
            _typed_optional_record(group, {"id", "proof_environment", "members"}, set())
            for group in graph["mutual_theorem_groups"]
        ],
    }


def _validate_graph_semantics(graph: dict[str, Any]) -> None:
    node_kinds = {
        "claim",
        "theorem",
        "subject",
        "artifact",
        "source-closure",
        "translation-unit",
        "model-check-unit",
        "test-suite",
        "assumption",
        "premise",
        "toolchain",
        "tcb-component",
        "review",
        "policy",
    }
    edge_kinds = {
        "proves",
        "refines",
        "decodes",
        "checks",
        "generated-from",
        "depends-on",
        "assumes",
        "discharged-by",
        "cross-checks",
        "covers-bounded-domain",
        "binds-digest",
        "reviewed-by",
        "admitted-by-policy",
    }
    typed = _typed_graph(graph)
    node_ids: set[str] = set()
    for node in typed["nodes"]:
        node_id = _required_text(node, "id")
        kind = _required_text(node, "kind")
        if node_id in node_ids or kind not in node_kinds:
            _fail(
                "IR-PROGRAMME-GRAPH-SEMANTICS",
                "graph contains a duplicate node or unknown node kind",
            )
        node_ids.add(node_id)
    for edge in typed["edges"]:
        source = _required_text(edge, "from")
        target = _required_text(edge, "to")
        kind = _required_text(edge, "kind")
        if source not in node_ids or target not in node_ids or kind not in edge_kinds:
            _fail(
                "IR-PROGRAMME-GRAPH-SEMANTICS",
                "graph edge has an absent endpoint or unknown kind",
            )
    for group in typed["mutual_theorem_groups"]:
        members = _text_list(group, "members")
        _require_sorted_unique(members)
        if any(member not in node_ids for member in members):
            _fail(
                "IR-PROGRAMME-GRAPH-SEMANTICS",
                "mutual theorem group names an absent graph node",
            )


def _typed_assumption(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "id",
        "node_id",
        "statement",
        "category",
        "owner",
        "rationale",
        "scope",
        "affected_claims",
        "review_evidence",
        "falsification_or_discharge_plan",
        "state",
        "depends_on",
    }
    return _typed_optional_record(value, required, {"source_citation"})


def _typed_premise(value: dict[str, Any]) -> dict[str, Any]:
    projected = _typed_optional_record(
        value,
        {"id", "node_id", "statement", "category", "scope"},
        {"theorem_evidence", "discharge"},
    )
    projected["scope"] = _typed_flow_scope(value["scope"])
    if "discharge" in value:
        discharge = _typed_optional_record(
            value["discharge"], {"theorem_evidence", "scope"}, set()
        )
        discharge["scope"] = _typed_flow_scope(discharge["scope"])
        projected["discharge"] = discharge
    return projected


def _typed_flow_scope(value: dict[str, Any]) -> dict[str, Any]:
    return _typed_optional_record(value, {"kind"}, {"flows"})


def _typed_policy(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "id",
        "node_id",
        "components",
        "allowed_foundational_axioms",
        "allowed_project_axioms",
        "admit_exhaustive_as_proved",
        "require_no_assumptions",
        "additional_required_evidence",
    }
    projected = _typed_optional_record(value, required, {"native_premise_rule"})
    if "native_premise_rule" in value:
        projected["native_premise_rule"] = _typed_optional_record(
            value["native_premise_rule"], {"kind"}, {"count"}
        )
    return projected


def _typed_optional_record(
    value: dict[str, Any], required: set[str], optional: set[str]
) -> dict[str, Any]:
    _require_exact_fields(value, required, optional)
    return {
        field: value[field] for field in sorted(required | optional) if field in value
    }


def _require_exact_fields(
    value: dict[str, Any], required: set[str], optional: set[str] | None = None
) -> None:
    optional = optional or set()
    if not required.issubset(value) or set(value) - required - optional:
        _fail(
            "IR-PROGRAMME-TYPED-RECORD",
            "typed programme record has missing or unknown fields",
        )


def _release_source_semantics(
    receipt: dict[str, Any],
    case: dict[str, Any],
    source_size: int,
    tcb_components: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "claims": [
            _release_claim_source_projection(claim, receipt)
            for claim in receipt["claims"]
        ],
        "evidence": [
            _release_evidence_source_projection(wrapped, case["source"], source_size)
            for wrapped in receipt["evidence"]
        ],
        "programme": _release_programme_source_projection(receipt, tcb_components),
    }


def _release_ir_semantics(program: dict[str, Any]) -> dict[str, Any]:
    return {
        "claims": [_claim_ir_projection(claim) for claim in program["claims"]],
        "evidence": program["evidence"],
        "programme": program["programme"],
    }


def _release_claim_source_projection(
    claim: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    status = next(
        item for item in receipt["reported_statuses"] if item["claim_id"] == claim["id"]
    )
    return {
        "schema": claim["schema"],
        "id": claim["id"],
        "title": claim["title"],
        "statement": claim["statement"],
        "public_language": claim.get("public_language"),
        "public_statement": status["public_statement"],
        "subject": claim["subject"],
        "subject_closure": None,
        "formal_declaration": claim.get("formal_declaration"),
        "statement_encoding": claim.get("statement_encoding"),
        "statement_sha256": claim.get("statement_sha256"),
        "foundational_axioms": sorted(claim.get("foundational_axioms", [])),
        "policy": claim["policy"],
        "tier": claim.get("tier"),
        "primary_linkage": claim.get("primary_linkage"),
        "cited_evidence": sorted(claim.get("cited_evidence", [])),
        "assumptions": sorted(claim.get("assumptions", [])),
        "premises": sorted(claim.get("premises", [])),
        "open_obligations": sorted(claim.get("open_obligations", [])),
        "out_of_scope": sorted(claim.get("out_of_scope", [])),
        "registered_inputs": sorted(claim.get("registered_inputs", [])),
        "bounded_domain": claim.get("bounded_domain"),
        "registered_domain_language": claim.get("registered_domain_language"),
    }


def _release_evidence_source_projection(
    wrapped: dict[str, Any], source: dict[str, Any], source_size: int
) -> dict[str, Any]:
    record = wrapped["record"]
    provenance = record["provenance"]
    kind = _family_kind(record["kind"])
    unit = record["unit_id"]
    prior_receipt = provenance.get("reused_from")
    return {
        "authority": "portable-receipt",
        "schema": record.get("schema"),
        "unit": unit,
        "content_sha256": wrapped.get("sha256"),
        "node": record.get("node_id"),
        "claims": record.get("claim_ids", []),
        "outcome": record.get("outcome"),
        "evaluation": record.get("evaluation_mode"),
        "binding": record.get("binding_mode"),
        "inventory": record.get("inventoried_targets", []),
        "assumptions": record.get("assumptions", []),
        "premises": record.get("premises", []),
        "open_obligation": record.get("open_obligation"),
        "request": None,
        "family": {
            "kind": kind,
            "detail": _family_detail(kind, "subject:c", source, source_size, None),
        },
        "backend": {"retained_facts": []},
        "provenance": {
            "revision": provenance.get("project_revision"),
            "tree_state": provenance.get("tree_state"),
            "semantic_closure": provenance.get("semantic_closure"),
            "additional_closures": provenance.get("additional_closures", []),
            "input_artifacts": [
                _source_artifact_projection(item)
                for item in provenance.get("input_artifacts", [])
            ],
            "generated_artifacts": [
                _source_artifact_projection(item)
                for item in provenance.get("generated_artifacts", [])
            ],
            "tool": provenance.get("tool"),
            "adapter": provenance.get("adapter"),
            "execution_kind": provenance.get("execution_kind"),
            "commands": [
                _source_command_projection(command)
                for command in provenance.get("commands", [])
            ],
            "runs": provenance.get("runs", []),
            "normalization": provenance.get("normalization"),
            "reproduction": _source_command_projection(
                provenance["reproduction_command"]
            ),
            "started_unix_ms": provenance.get("started_unix_ms"),
            "completed_unix_ms": provenance.get("completed_unix_ms"),
            "result_sha256": provenance.get("deterministic_result_sha256"),
            "unit_configuration_sha256": provenance.get("unit_configuration_sha256"),
            "budget": provenance.get("resource_budget"),
            "usage": {
                "time_ms": provenance["actual_cost"].get("time_ms"),
                "disk_bytes": provenance["actual_cost"].get("disk_bytes"),
                "peak_memory": provenance["actual_cost"].get("memory_bytes"),
            },
            "python_plugins": provenance.get("python_plugins", []),
            "cache": {
                "prior_receipt": prior_receipt,
                "key": _cache_key(unit, prior_receipt),
                "source_key": provenance.get("cache_key"),
                "origin": "reused" if prior_receipt is not None else "executed",
                "reuse_eligible": True,
            },
        },
    }


def _release_programme_source_projection(
    receipt: dict[str, Any], tcb_components: list[dict[str, str]]
) -> dict[str, Any]:
    derivation_traces, publication_trace = _release_derivation_traces(receipt)
    return {
        "release_schema": receipt.get("schema"),
        "project": {
            "id": receipt["project"],
            "revision": receipt["project_revision"],
            "tier": receipt["project_tier"],
            "tree_state": receipt["tree_state"],
        },
        "graph": receipt.get("graph"),
        "graph_sha256": receipt.get("graph_sha256"),
        "assumptions": receipt.get("assumptions", []),
        "premises": receipt.get("premises", []),
        "policies": receipt.get("policies", []),
        "closures": [
            {
                "schema": closure["record"]["schema"],
                "sha256": closure["sha256"],
                "kind": closure["record"]["kind"],
                "members": [
                    _source_artifact_projection(member)
                    for member in closure["record"]["members"]
                ],
            }
            for closure in receipt["closures"]
        ],
        "sealed_artifacts": [
            _source_artifact_projection(artifact)
            for artifact in receipt["sealed_files"]
        ],
        "tcb_components": tcb_components,
        "publication_blockers": sorted(
            status["claim_id"]
            for status in receipt["reported_statuses"]
            if status["policy_admitted"] is False
        ),
        "reported_statuses": [
            {
                "claim_id": status["claim_id"],
                "formal": status["formal"],
                "linkage": status["linkage"],
                "assumption": status["assumption"],
                "policy_admitted": status["policy_admitted"],
                "public_statement": status["public_statement"],
                "assumptions": status["assumptions"],
                "undischarged_premises": status["undischarged_premises"],
            }
            for status in receipt["reported_statuses"]
        ],
        "derivation_traces": derivation_traces,
        "publication_trace": publication_trace,
    }


def _source_artifact_projection(artifact: dict[str, Any]) -> dict[str, Any]:
    return {
        "logical_name": artifact.get("logical_name", artifact.get("path")),
        "sha256": artifact["sha256"],
        "size_bytes": artifact["size_bytes"],
    }


def _source_command_projection(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "program": command["program"],
        "args": command["args"],
        "environment_allowlist": command["environment_allowlist"],
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
    return _source_project_root(root, case["source"]["path"], inputs)


def _source_project_root(root: Path, source_path: str, inputs: list[str]) -> Path:
    source = root / source_path
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


def _subject_closure(
    root: Path, source_path: str, selectors: list[str]
) -> dict[str, Any]:
    if not selectors:
        raise AssuranceIrError("claim subject closure is empty")
    project_root = _source_project_root(root, source_path, selectors)
    members = []
    for selector in selectors:
        path = Path(selector)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise AssuranceIrError(
                "claim source selector is not a normalized relative path"
            )
        absolute = project_root / path
        if not absolute.is_file() or absolute.is_symlink():
            raise AssuranceIrError("claim source member must be a regular file")
        data = absolute.read_bytes()
        members.append(
            {
                "logical_name": selector,
                "sha256": _sha256(data),
                "size_bytes": len(data),
            }
        )
    material = {
        "schema": "proofbound-ir-subject-closure/1",
        "selectors": selectors,
        "members": members,
    }
    return {
        **material,
        "sha256": domain_hash(material["schema"], canonical_json(material)),
    }


def _release_claim(claim: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    claim_id = _required_text(claim, "id")
    status = next(
        item for item in receipt["reported_statuses"] if item["claim_id"] == claim_id
    )
    return {
        "id": claim_id,
        "subject": _required_text(claim, "subject"),
        "subject_closure": None,
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
    configuration: dict[str, Any] | None,
) -> dict[str, Any]:
    schema = _family_schema(kind)
    configuration = configuration or {}
    if kind == "mutation-witness":
        _require_configuration_fields(configuration, {"mutation"})
        detail = {"schema": schema, "subject": subject or "subject:unknown"}
        if "mutation" in configuration:
            mutation = _as_object(configuration["mutation"])
            _require_exact_fields(mutation, {"schema", "registry"})
            detail["mutation"] = dict(mutation)
        return detail
    if kind == "artifact-correspondence":
        _require_configuration_fields(configuration, set())
        return {
            "schema": schema,
            "artifact": _source_artifact(source, source_size),
        }
    if kind == "sampled-property":
        _require_configuration_fields(configuration, {"property"})
        detail = {"schema": schema}
        if "property" in configuration:
            property_registration = _as_object(configuration["property"])
            _require_exact_fields(
                property_registration, {"schema", "framework", "seed"}
            )
            detail["property"] = dict(property_registration)
            detail["required_fact_schemas"] = [property_registration["schema"]]
        return detail
    if kind == "distribution-reproduction":
        _require_configuration_fields(configuration, {"distribution"})
        detail = {"schema": schema}
        if "distribution" in configuration:
            distribution = _as_object(configuration["distribution"])
            _require_exact_fields(
                distribution,
                {
                    "schema",
                    "format",
                    "artifact_name",
                    "artifact_sha256",
                    "source_date_epoch",
                },
            )
            detail["distribution"] = dict(distribution)
        return detail
    if kind == "bounded-model-check":
        _require_configuration_fields(configuration, {"bounded_domain"})
        detail = {"schema": schema}
        if "bounded_domain" in configuration:
            bounded_domain = _as_object(configuration["bounded_domain"])
            _require_exact_fields(
                bounded_domain,
                {"id", "description", "cardinality", "ordering_key"},
            )
            detail["bounded_domain"] = dict(bounded_domain)
        return detail
    if kind == "universal-source-proof":
        _require_configuration_fields(configuration, {"theorem"})
        detail = {"schema": schema}
        if "theorem" in configuration:
            detail["theorem"] = configuration["theorem"]
        return detail
    _require_configuration_fields(configuration, set())
    return {"schema": schema}


def _require_configuration_fields(
    configuration: dict[str, Any], allowed: set[str]
) -> None:
    if set(configuration) - allowed:
        raise AssuranceIrError(
            "family configuration contains fields outside its typed IR variant"
        )


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
        "additional_closures": [],
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
        "python_plugins": [],
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


def _sampling_json(
    data: bytes, label: str, *, allow_final_newline: bool
) -> dict[str, Any]:
    document = data.removesuffix(b"\n") if allow_final_newline else data
    try:
        value = _strict_json(document, require_canonical=True)
    except AssuranceIrError as error:
        raise AssuranceIrError(str(error), code="sampling-report-invalid") from error
    if not isinstance(value, dict):
        _sampling_fail("sampling-report-invalid", f"{label} must be an object")
    return value


def _validate_sampling_contract(root: Path, contract: dict[str, Any]) -> None:
    _require_keys(
        contract,
        {
            "schema",
            "framework",
            "seed",
            "successful_cases",
            "generator",
            "targets",
            "replay",
            "persistence",
            "shrinking",
        },
        "sampling contract",
    )
    if contract["schema"] != "proofbound-sampling-contract/1":
        _sampling_fail("sampling-schema-mismatch", "unsupported contract schema")
    framework = _as_object(contract["framework"])
    _require_keys(framework, {"name", "version"}, "sampling framework")
    _sampling_text(framework["name"], "framework name")
    _sampling_text(framework["version"], "framework version")
    seed = _as_object(contract["seed"])
    _require_keys(seed, {"encoding", "value"}, "sampling seed")
    if (
        seed["encoding"] != "decimal-u64"
        or not isinstance(seed["value"], int)
        or isinstance(seed["value"], bool)
        or not 0 <= seed["value"] <= 2**64 - 1
    ):
        _sampling_fail("sampling-contract-mismatch", "seed is invalid")
    cases = contract["successful_cases"]
    if (
        not isinstance(cases, int)
        or isinstance(cases, bool)
        or not 1 <= cases <= 1_000_000
    ):
        _sampling_fail("sampling-contract-mismatch", "case budget is invalid")
    if contract["replay"] != "fresh-only" or contract["persistence"] != "disabled":
        _sampling_fail("sampling-contract-mismatch", "state policy is invalid")
    if contract["shrinking"] not in {"disabled", "enabled"}:
        _sampling_fail("sampling-contract-mismatch", "shrinking policy is invalid")
    targets = contract["targets"]
    if not isinstance(targets, list) or not targets:
        _sampling_fail("sampling-contract-mismatch", "targets are empty")
    _sampling_sorted_text(targets, "sampling targets")
    generator = _as_object(contract["generator"])
    _require_keys(
        generator,
        {"entrypoint", "closure", "identity_sha256"},
        "sampling generator",
    )
    _sampling_text(generator["entrypoint"], "generator entrypoint")
    closure = generator["closure"]
    if not isinstance(closure, list) or not closure:
        _sampling_fail("generator-identity-mismatch", "generator closure is empty")
    names: list[str] = []
    for item in closure:
        artifact = _as_object(item)
        _require_keys(
            artifact,
            {"logical_name", "sha256", "size_bytes"},
            "generator artifact",
        )
        logical_name = artifact["logical_name"]
        _sampling_text(logical_name, "generator path")
        relative = Path(logical_name)
        if (
            relative.is_absolute()
            or "\\" in logical_name
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            _sampling_fail("generator-identity-mismatch", "generator path is unsafe")
        try:
            resolved = (root / relative).resolve(strict=True)
            resolved.relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise AssuranceIrError(
                "generator path escapes or is missing",
                code="generator-identity-mismatch",
            ) from error
        data = resolved.read_bytes()
        if artifact["sha256"] != _sha256(data) or artifact["size_bytes"] != len(data):
            _sampling_fail("generator-identity-mismatch", "generator bytes differ")
        names.append(logical_name)
    _sampling_sorted_text(names, "generator closure")
    material = {"entrypoint": generator["entrypoint"], "closure": closure}
    identity = domain_hash("proofbound-generator-closure/1", canonical_json(material))
    if generator["identity_sha256"] != identity:
        _sampling_fail("generator-identity-mismatch", "generator identity differs")


def _validate_layered_intent(root: Path, intent: dict[str, Any]) -> None:
    _require_keys(
        intent,
        {
            "schema",
            "seed",
            "successful_cases",
            "generator",
            "targets",
            "persistence",
            "ceiling",
        },
        "sampling intent",
    )
    if intent["schema"] != "proofbound-sampling-intent/1":
        _sampling_fail("sampling-schema-mismatch", "unsupported sampling intent")
    seed = _as_object(intent["seed"])
    _require_keys(seed, {"encoding", "value"}, "sampling seed")
    if (
        seed["encoding"] != "decimal-u64"
        or not isinstance(seed["value"], int)
        or isinstance(seed["value"], bool)
        or not 0 <= seed["value"] <= 2**64 - 1
    ):
        _sampling_fail("sampling-plan-invalid", "sampling seed is invalid")
    budget = intent["successful_cases"]
    if (
        not isinstance(budget, int)
        or isinstance(budget, bool)
        or not 1 <= budget <= 1_000_000
    ):
        _sampling_fail("sampling-plan-invalid", "sampling budget is invalid")
    if intent["ceiling"] != "empirical-sample":
        _sampling_fail("sampling-plan-invalid", "sampling ceiling is invalid")
    persistence = _as_object(intent["persistence"])
    if persistence == {"mode": "disabled"}:
        pass
    elif set(persistence) == {"mode", "artifact"} and persistence["mode"] == (
        "read-only-bound"
    ):
        _validate_layered_artifact(root, _as_object(persistence["artifact"]))
    else:
        _sampling_fail("sampling-plan-invalid", "persistence policy is invalid")
    targets = intent["targets"]
    if not isinstance(targets, list) or not targets:
        _sampling_fail("sampling-plan-invalid", "sampling targets are empty")
    _sampling_sorted_text(targets, "sampling targets")
    generator = _as_object(intent["generator"])
    _require_keys(
        generator,
        {"entrypoint", "closure", "identity_sha256"},
        "sampling generator",
    )
    _sampling_text(generator["entrypoint"], "generator entrypoint")
    closure = generator["closure"]
    if not isinstance(closure, list) or not closure:
        _sampling_fail("generator-identity-mismatch", "generator closure is empty")
    names = []
    for item in closure:
        artifact = _as_object(item)
        _validate_layered_artifact(root, artifact)
        names.append(artifact["logical_name"])
    _sampling_sorted_text(names, "generator closure")
    identity = domain_hash(
        "proofbound-generator-closure/1",
        canonical_json({"closure": closure, "entrypoint": generator["entrypoint"]}),
    )
    if generator["identity_sha256"] != identity:
        _sampling_fail("generator-identity-mismatch", "generator identity differs")


def _validate_layered_artifact(root: Path, artifact: dict[str, Any]) -> None:
    _require_keys(
        artifact, {"logical_name", "sha256", "size_bytes"}, "sampling artifact"
    )
    logical_name = artifact["logical_name"]
    _sampling_text(logical_name, "artifact path")
    path = Path(logical_name)
    if (
        path.is_absolute()
        or "\\" in logical_name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        _sampling_fail("generator-identity-mismatch", "artifact path is unsafe")
    try:
        resolved = (root / path).resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise AssuranceIrError(
            "artifact path escapes or is missing",
            code="generator-identity-mismatch",
        ) from error
    data = resolved.read_bytes()
    if artifact["sha256"] != _sha256(data) or artifact["size_bytes"] != len(data):
        _sampling_fail("generator-identity-mismatch", "artifact bytes differ")


def _validate_layered_plan(plan: dict[str, Any]) -> dict[str, str]:
    backend = plan.get("backend")
    common = {"backend", "schema", "version", "capabilities"}
    expected_fields = {
        "hypothesis": common | {"phases", "database", "shrinking"},
        "fast-check": common | {"random_type", "examples", "skip_limit", "shrinking"},
        "proptest": common
        | {
            "rng_algorithm",
            "max_local_rejects",
            "max_global_rejects",
            "max_shrink_iters",
        },
    }
    if backend not in expected_fields:
        _sampling_fail("sampling-plan-invalid", "unknown sampling backend")
    if set(plan) != expected_fields[backend]:
        _sampling_fail(
            "sampling-plan-invalid",
            "backend sampling plan has missing or unknown fields",
        )
    if plan["schema"] != "proofbound-backend-sampling-plan/1":
        _sampling_fail("sampling-schema-mismatch", "unsupported backend plan schema")
    _sampling_text(plan["version"], "backend version")
    if backend == "hypothesis":
        _sampling_sorted_text(plan["phases"], "Hypothesis phases")
        _sampling_text(plan["database"], "Hypothesis database policy")
        _sampling_text(plan["shrinking"], "Hypothesis shrinking policy")
    elif backend == "fast-check":
        _sampling_text(plan["random_type"], "fast-check random type")
        _sampling_text(plan["shrinking"], "fast-check shrinking policy")
        if not isinstance(plan["examples"], list) or not _layered_u64(
            plan["skip_limit"]
        ):
            _sampling_fail("sampling-plan-invalid", "fast-check plan is invalid")
    else:
        _sampling_text(plan["rng_algorithm"], "proptest RNG algorithm")
        for field in (
            "max_local_rejects",
            "max_global_rejects",
            "max_shrink_iters",
        ):
            if not _layered_u64(plan[field]) or plan[field] == 0:
                _sampling_fail("sampling-plan-invalid", f"{field} is invalid")
    capabilities = _as_object(plan["capabilities"])
    _require_keys(
        capabilities,
        {"attempted", "completed", "skipped", "shrinks"},
        "sampling capabilities",
    )
    for authority in capabilities.values():
        if authority not in {"observed", "derived", "unavailable"}:
            _sampling_fail("sampling-plan-invalid", "fact authority is invalid")
    return capabilities


def _validate_layered_fact(value: Any, expected: str, name: str) -> None:
    if value is None:
        return
    fact = _as_object(value)
    authority = fact.get("authority")
    if authority != expected:
        _sampling_fail(
            "sampling-authority-mismatch",
            f"{name} authority differs from backend capability",
        )
    if authority == "observed":
        _require_keys(fact, {"authority", "value", "source"}, f"{name} fact")
        if not _layered_u64(fact["value"]):
            _sampling_fail("sampling-plan-invalid", f"{name} value is invalid")
        _sampling_text(fact["source"], "observation source")
    elif authority == "derived":
        _require_keys(
            fact,
            {"authority", "value", "rule", "dependencies"},
            f"{name} fact",
        )
        if not _layered_u64(fact["value"]):
            _sampling_fail("sampling-plan-invalid", f"{name} value is invalid")
        if fact["rule"] != "runner-success-contract" or fact["dependencies"] != [
            "intent.successful-cases",
            "result.passed",
        ]:
            _sampling_fail(
                "sampling-derivation-incomplete",
                "derived dependencies differ from the closed rule",
            )
    elif authority == "unavailable":
        _require_keys(fact, {"authority", "reason"}, f"{name} fact")
        _sampling_text(fact["reason"], "unavailable reason")
    else:
        _sampling_fail("sampling-plan-invalid", "fact authority is invalid")


def _layered_fact_value(value: Any) -> int | None:
    if value is None:
        return None
    fact = _as_object(value)
    return None if fact.get("authority") == "unavailable" else fact.get("value")


def _layered_u64(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 2**64 - 1
    )


def _sampling_sorted_text(values: list[Any], label: str) -> None:
    for value in values:
        _sampling_text(value, label)
    if values != sorted(set(values)):
        _sampling_fail("sampling-report-invalid", f"{label} is not canonical")


def _sampling_text(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(unicodedata.category(character) == "Cc" for character in value)
    ):
        _sampling_fail("sampling-report-invalid", f"{label} is invalid")


def _sampling_fail(code: str, message: str) -> None:
    raise AssuranceIrError(message, code=code)


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
