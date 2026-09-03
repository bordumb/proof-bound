import json
import hashlib
from pathlib import Path
import subprocess

import pytest

from proofbound.assurance_ir_checker import (
    AssuranceIrError,
    canonical_json,
    check_canonical_vectors,
    check_generated_derivation_corpus,
    check_portable_family_projection,
    check_projection,
    check_layered_sampling_case,
    check_sampling_observation,
    domain_hash,
    derive_release_trace_bundle,
    validate_case_program,
    validate_release_trace_bundle,
)


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/cases.json"
VECTORS = (
    ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/canonical-vectors.json"
)
ADVERSARIAL = (
    ROOT / "docs/experiments/0005-assurance-ir-extraction/corpus/adversarial-cases.json"
)
Q1_ADVERSARIAL = (
    ROOT
    / "docs/experiments/0005-assurance-ir-extraction/corpus/q1-adversarial-cases.json"
)
COMPLETION_CAPTURE = (
    ROOT
    / "docs/experiments/0005-assurance-ir-extraction/captures/q1-completion-r1/index.json"
)
SAMPLING = ROOT / "docs/experiments/0006-explicit-sampling-contract/corpus"
DERIVATION_TEMPLATES = (
    ROOT / "docs/experiments/0009-generated-evidence-algebra/corpus/templates.json"
)
COMPLETION_ROOT = COMPLETION_CAPTURE.parent


def layered_sampling_case(backend: str) -> dict[str, object]:
    path = (
        ROOT / "docs/experiments/0008-layered-sampling-model/corpus" / f"{backend}.json"
    )
    return json.loads(path.read_bytes())


def producer_projection() -> bytes:
    return subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            str(ROOT),
            str(CORPUS),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def producer_portable_family_projection() -> bytes:
    return subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            "project-portable-families",
            str(ROOT),
            str(COMPLETION_CAPTURE),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def producer_release_trace(receipt: Path) -> bytes:
    return subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            "derive-release-trace",
            str(receipt),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def producer_layered_sampling(case: Path) -> dict[str, object]:
    output = subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            "validate-layered-sampling",
            str(ROOT),
            str(case),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return json.loads(output)


def producer_derivation_corpus() -> bytes:
    return subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            "generate-derivations",
            str(DERIVATION_TEMPLATES),
            "500",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout


def test_independent_checker_agrees_with_rust_projection() -> None:
    report = check_projection(ROOT, CORPUS, producer_projection())
    assert report.case_count == 20
    assert report.projection_sha256.startswith("sha256:")


def test_independent_checker_agrees_on_portable_family_projection() -> None:
    projection = producer_portable_family_projection()
    report = check_portable_family_projection(ROOT, COMPLETION_CAPTURE, projection)
    assert report.case_count == 45
    value = json.loads(projection)
    legacy = [
        record
        for record in value["records"]
        if record["family"]["kind"] == "sampled-property"
        and record["family"]["detail"]["sampling"]["mode"] == "legacy-backend"
    ]
    assert sorted(record["unit_id"] for record in legacy) == [
        "unit:bounded-roundtrip",
        "unit:rust-kernel-tests",
    ]


def test_both_implementations_derive_identical_completion_traces() -> None:
    for language in ("python", "typescript", "rust"):
        receipt_path = COMPLETION_ROOT / language / "compiled-receipt.json"
        receipt = receipt_path.read_bytes()
        python_trace = derive_release_trace_bundle(receipt)
        rust_trace = producer_release_trace(receipt_path)
        assert canonical_json(python_trace) == rust_trace
        validate_release_trace_bundle(receipt, rust_trace)


def test_both_implementations_reject_preregistered_trace_attacks(
    tmp_path: Path,
) -> None:
    receipt_path = COMPLETION_ROOT / "python" / "compiled-receipt.json"
    receipt = receipt_path.read_bytes()
    original = derive_release_trace_bundle(receipt)
    attacks: list[dict[str, object]] = []

    missing = json.loads(canonical_json(original))
    missing["traces"][0]["load_bearing_evidence"].pop()
    attacks.append(missing)

    stronger = json.loads(canonical_json(original))
    stronger["traces"][0]["formal_value_and_rule"]["rule"] = "universal-source-proof"
    attacks.append(stronger)

    component = json.loads(canonical_json(original))
    component["traces"][0]["satisfied_policy_components"] = [
        "forged-component",
        "ledger",
    ]
    attacks.append(component)

    publication = json.loads(canonical_json(original))
    publication["publication"]["admitted_claims"].pop()
    attacks.append(publication)

    moved = json.loads(canonical_json(original))
    moved["traces"][0]["claim_id"] = "PY-WHEEL-001"
    attacks.append(moved)

    for index, attack in enumerate(attacks):
        encoded = canonical_json(attack)
        with pytest.raises(AssuranceIrError) as caught:
            validate_release_trace_bundle(receipt, encoded)
        assert caught.value.code == "IR-DERIVATION-TRACE-MISMATCH"
        trace_path = tmp_path / f"trace-{index}.json"
        trace_path.write_bytes(encoded)
        process = subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "proofbound-ir-prototype",
                "--",
                "validate-release-trace",
                str(receipt_path),
                str(trace_path),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert process.returncode == 1
        assert "IR-DERIVATION-TRACE-MISMATCH" in process.stderr

    reported = json.loads(receipt)
    reported["reported_statuses"][0]["policy_admitted"] = False
    reported_bytes = canonical_json(reported)
    reported_authored = derive_release_trace_bundle(reported_bytes)
    reported_authored["traces"][0]["blockers"] = ["reported-policy-blocked"]
    reported_authored["publication"]["admitted_claims"].remove("PY-RESERVATION-001")
    reported_authored["publication"]["blocked_claims"] = ["PY-RESERVATION-001"]
    reported_authored["publication"]["blockers"] = [
        "PY-RESERVATION-001:reported-policy-blocked"
    ]
    encoded = canonical_json(reported_authored)
    with pytest.raises(AssuranceIrError) as caught:
        validate_release_trace_bundle(reported_bytes, encoded)
    assert caught.value.code == "IR-DERIVATION-TRACE-MISMATCH"
    reported_receipt_path = tmp_path / "reported-receipt.json"
    reported_trace_path = tmp_path / "reported-trace.json"
    reported_receipt_path.write_bytes(reported_bytes)
    reported_trace_path.write_bytes(encoded)
    process = subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "proofbound-ir-prototype",
            "--",
            "validate-release-trace",
            str(reported_receipt_path),
            str(reported_trace_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert process.returncode == 1
    assert "IR-DERIVATION-TRACE-MISMATCH" in process.stderr


def sampling_fixture(path: Path) -> bytes:
    return path.read_bytes().removesuffix(b"\n")


def test_independent_checker_agrees_on_backend_neutral_sampling() -> None:
    for backend in ("hypothesis", "fast-check"):
        report = check_sampling_observation(
            ROOT,
            sampling_fixture(SAMPLING / "contracts" / f"{backend}.json"),
            sampling_fixture(SAMPLING / "observations" / f"{backend}-passed.json"),
        )
        assert report.framework == backend
        assert report.result == "passed"
        assert report.contract_identity.startswith("sha256:")


def test_independent_checker_rejects_every_sampling_attack() -> None:
    contract = json.loads(sampling_fixture(SAMPLING / "contracts" / "hypothesis.json"))
    observation = json.loads(
        sampling_fixture(SAMPLING / "observations" / "hypothesis-passed.json")
    )
    attacks = {
        "EXP-0006-A001": "sampling-contract-mismatch",
        "EXP-0006-A002": "sampling-contract-mismatch",
        "EXP-0006-A003": "generator-identity-mismatch",
        "EXP-0006-A004": "generator-identity-mismatch",
        "EXP-0006-A005": "sampling-inventory-mismatch",
        "EXP-0006-A006": "sampling-report-invalid",
        "EXP-0006-A007": "sampling-contract-mismatch",
        "EXP-0006-A008": "sampling-schema-mismatch",
        "EXP-0006-A009": "sampling-contract-mismatch",
        "EXP-0006-A010": "sampling-tool-mismatch",
    }
    for attack, expected in attacks.items():
        registered = json.loads(json.dumps(contract))
        observed = json.loads(json.dumps(observation))
        if attack == "EXP-0006-A001":
            registered["seed"]["value"] = 1
        elif attack == "EXP-0006-A002":
            registered["successful_cases"] = 101
        elif attack == "EXP-0006-A003":
            registered["generator"]["entrypoint"] = "substituted::property"
            material = {
                "entrypoint": registered["generator"]["entrypoint"],
                "closure": registered["generator"]["closure"],
            }
            registered["generator"]["identity_sha256"] = domain_hash(
                "proofbound-generator-closure/1", canonical_json(material)
            )
        elif attack == "EXP-0006-A004":
            registered["generator"]["closure"][0]["sha256"] = "sha256:" + "0" * 64
        elif attack == "EXP-0006-A005":
            observed["contract"]["targets"] = ["substituted::target"]
            observed["targets"] = ["substituted::target"]
        elif attack == "EXP-0006-A007":
            observed["actual_seed"]["value"] = 1
        elif attack == "EXP-0006-A008":
            observed["schema"] = "legacy-backend-sampling/1"
        elif attack == "EXP-0006-A009":
            observed["contract"]["persistence"] = "ambient-writable-database"
        elif attack == "EXP-0006-A010":
            observed["contract"]["framework"]["version"] = "6.113.0"
        observation_bytes = canonical_json(observed)
        if attack == "EXP-0006-A006":
            observation_bytes = observation_bytes.replace(
                b'"completed_cases":100',
                b'"completed_cases":100,"completed_cases":100',
                1,
            )
        with pytest.raises(AssuranceIrError) as caught:
            check_sampling_observation(
                ROOT, canonical_json(registered), observation_bytes
            )
        assert caught.value.code == expected, attack


def test_independent_checker_admits_three_layered_sampling_plans() -> None:
    for backend in ("hypothesis", "fast-check", "proptest"):
        case_path = (
            ROOT
            / "docs/experiments/0008-layered-sampling-model/corpus"
            / f"{backend}.json"
        )
        report = check_layered_sampling_case(ROOT, case_path.read_bytes())
        producer = producer_layered_sampling(case_path)
        assert report.admitted
        assert report.result == "passed"
        assert report.alerts == ()
        assert producer == {
            "admitted": report.admitted,
            "alerts": list(report.alerts),
            "intent_identity": report.intent_identity,
            "plan_identity": report.plan_identity,
            "result": report.result,
            "schema": "proofbound-layered-sampling-validation/1",
        }


def test_independent_checker_agrees_on_generated_evidence_algebra() -> None:
    corpus = producer_derivation_corpus()
    report = check_generated_derivation_corpus(corpus)
    assert report.valid_count == 500
    assert report.adversarial_count == 500
    assert report.corpus_identity.startswith("sha256:")

    attacks = {case["attack"] for case in json.loads(corpus)["adversarial"]}
    assert attacks == {f"EXP-0009-A{number:03}" for number in range(1, 17)}


def test_independent_checker_rejects_layered_sampling_attacks() -> None:
    expected = {
        "EXP-0008-A001": "sampling-layer-violation",
        "EXP-0008-A002": "sampling-plan-invalid",
        "EXP-0008-A003": "sampling-plan-identity-mismatch",
        "EXP-0008-A004": "sampling-authority-mismatch",
        "EXP-0008-A005": "sampling-authority-mismatch",
        "EXP-0008-A006": "sampling-derivation-incomplete",
        "EXP-0008-A007": "sampling-admission-blocked",
        "EXP-0008-A008": "sampling-rule-overreach",
        "EXP-0008-A010": "sampling-inventory-mismatch",
        "EXP-0008-A011": "sampling-schema-mismatch",
        "EXP-0008-A012": "sampling-schema-mismatch",
    }
    for attack, expected_code in expected.items():
        case = json.loads(json.dumps(layered_sampling_case("proptest")))
        if attack == "EXP-0008-A001":
            case["intent"]["rng_algorithm"] = "chacha"
        elif attack == "EXP-0008-A002":
            del case["plan"]["rng_algorithm"]
            rehash_layered_plan(case)
        elif attack == "EXP-0008-A003":
            case["plan"]["rng_algorithm"] = "xorshift"
        elif attack == "EXP-0008-A004":
            case["observation"]["completed"] = {
                "authority": "observed",
                "value": 100,
                "source": "runner-success",
            }
        elif attack == "EXP-0008-A005":
            case["observation"]["shrinks"] = {
                "authority": "observed",
                "value": 0,
                "source": "invented-zero",
            }
        elif attack == "EXP-0008-A006":
            case["observation"]["completed"]["dependencies"] = ["result.passed"]
        elif attack == "EXP-0008-A007":
            case["plan"]["capabilities"]["completed"] = "unavailable"
            rehash_layered_plan(case)
            case["observation"]["completed"] = {
                "authority": "unavailable",
                "reason": "runner completion could not be established",
            }
        elif attack == "EXP-0008-A008":
            case["admission_rule"]["required_facts"] = ["completed", "shrinks"]
        elif attack == "EXP-0008-A010":
            case["observation"]["targets"] = ["proptest::substituted"]
        elif attack == "EXP-0008-A011":
            case["schema"] = "proofbound-sampling-observation/1"
        elif attack == "EXP-0008-A012":
            case["schema"] = "legacy-backend-sampling/1"
        with pytest.raises(AssuranceIrError) as caught:
            check_layered_sampling_case(ROOT, canonical_json(case))
        assert caught.value.code == expected_code, attack


def test_unused_layered_shrink_telemetry_has_no_admission_consequence() -> None:
    case = layered_sampling_case("proptest")
    del case["observation"]["shrinks"]
    report = check_layered_sampling_case(ROOT, canonical_json(case))
    assert report.admitted
    assert report.alerts == ()


def rehash_layered_plan(case: dict[str, object]) -> None:
    identity = domain_hash(
        "proofbound-backend-sampling-plan/1", canonical_json(case["plan"])
    )
    case["plan_identity"] = identity
    case["observation"]["plan_identity"] = identity


def test_portable_family_checker_rejects_sampling_upgrade() -> None:
    value = json.loads(producer_portable_family_projection())
    legacy = next(
        record
        for record in value["records"]
        if record["unit_id"] == "unit:bounded-roundtrip"
    )
    legacy["family"]["detail"]["sampling"] = {
        "mode": "explicit",
        "schema": "invented-fast-check-property/1",
        "framework": "fast-check",
        "framework_version": "4.3.0",
        "seed": 424242,
    }
    material = {
        "capture_sha256": value["capture_sha256"],
        "records": value["records"],
        "schema": value["schema"],
    }
    value["projection_sha256"] = domain_hash(value["schema"], canonical_json(material))
    with pytest.raises(AssuranceIrError, match="differs from independent"):
        check_portable_family_projection(
            ROOT, COMPLETION_CAPTURE, canonical_json(value)
        )


def test_checker_rejects_projection_semantic_drift() -> None:
    value = json.loads(producer_projection())
    value["cases"][0]["evidence_family"] = "theorem"
    value.pop("projection_sha256")
    value["projection_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(AssuranceIrError, match="differs from independent"):
        check_projection(ROOT, CORPUS, canonical_json(value))


def test_checker_rejects_noncanonical_projection() -> None:
    with pytest.raises(AssuranceIrError, match="not canonical"):
        check_projection(ROOT, CORPUS, producer_projection() + b"\n")


def test_independent_canonical_vectors_match() -> None:
    assert check_canonical_vectors(VECTORS) == 15


def test_portable_projection_retains_programme_and_execution_meaning() -> None:
    projection = json.loads(producer_projection())
    program = next(
        case["program"] for case in projection["cases"] if case["id"] == "IR-REL-001"
    )
    assert program["programme"]["project"] == {
        "id": "synthetic",
        "revision": "rev-1",
        "tier": 0,
        "tree_state": "clean",
    }
    assert (
        program["programme"]["closures"][0]["members"][0]["logical_name"]
        == "src/model.rs"
    )
    assert (
        program["programme"]["sealed_artifacts"][0]["logical_name"] == "tcb-ledger.json"
    )
    assert program["programme"]["graph"]["nodes"][0]["kind"] == "claim"
    assert program["programme"]["policies"][0]["id"] == "ledger-ci"
    assert len(program["programme"]["tcb_components"]) == 2
    evidence = program["evidence"][0]
    assert (
        evidence["content_sha256"]
        == "sha256:0472956f8429866d293913903a3b1ac9ae42764e658078953dae8015939b44d4"
    )
    assert evidence["provenance"]["commands"][0]["program"] == "synthetic-runner"
    assert evidence["provenance"]["runs"][0]["exit_code"] == 0
    assert evidence["provenance"]["usage"]["disk_bytes"] == 1

    missing_policy = json.loads(json.dumps(program))
    missing_policy["programme"]["policies"] = []
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(missing_policy))
    assert caught.value.code == "IR-PROGRAMME-POLICY-OMITTED"

    wrong_revision = json.loads(json.dumps(program))
    wrong_revision["evidence"][0]["provenance"]["revision"] = "rev-substituted"
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(wrong_revision))
    assert caught.value.code == "IR-PROGRAMME-PROVENANCE-MISMATCH"

    wrong_graph = json.loads(json.dumps(program))
    wrong_graph["programme"]["graph"]["nodes"][0]["kind"] = "subject"
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(wrong_graph))
    assert caught.value.code == "IR-PROGRAMME-GRAPH-IDENTITY"

    wrong_closure = json.loads(json.dumps(program))
    wrong_closure["programme"]["closures"][0]["members"][0]["size_bytes"] = 13
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(wrong_closure))
    assert caught.value.code == "IR-PROGRAMME-CLOSURE-IDENTITY"

    missing_status = json.loads(json.dumps(program))
    missing_status["programme"]["reported_statuses"] = []
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(missing_status))
    assert caught.value.code == "IR-PROGRAMME-STATUS-MISMATCH"

    false_blocker = json.loads(json.dumps(program))
    false_blocker["programme"]["publication_blockers"] = ["c"]
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(false_blocker))
    assert caught.value.code == "IR-PROGRAMME-BLOCKER-MISMATCH"

    unknown_policy_field = json.loads(json.dumps(program))
    unknown_policy_field["programme"]["policies"][0]["backend_hint"] = "hidden"
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(unknown_policy_field))
    assert caught.value.code == "IR-PROGRAMME-TYPED-RECORD"

    substituted_tcb = json.loads(json.dumps(program))
    substituted_tcb["programme"]["tcb_components"][0]["identity_sha256"] = (
        f"sha256:{'2' * 64}"
    )
    ledger = {
        "components": substituted_tcb["programme"]["tcb_components"],
        "schema": "proofbound-tcb-ledger/1",
    }
    ledger_bytes = canonical_json(ledger)
    substituted_tcb["programme"]["sealed_artifacts"][0]["sha256"] = (
        f"sha256:{hashlib.sha256(ledger_bytes).hexdigest()}"
    )
    substituted_tcb["programme"]["sealed_artifacts"][0]["size_bytes"] = len(
        ledger_bytes
    )
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(substituted_tcb))
    assert caught.value.code == "IR-PROGRAMME-TCB-MISMATCH"


def test_registration_cache_binds_actual_input_bytes() -> None:
    projection = json.loads(producer_projection())
    program = next(
        case["program"] for case in projection["cases"] if case["id"] == "IR-PY-001"
    )
    cache_input = next(
        item
        for item in program["cache"]["registered_inputs"]
        if item["selector"] == "pyproject.toml"
    )
    data = (ROOT / "demo/python-inventory-service/pyproject.toml").read_bytes()
    assert cache_input["identity"] == f"sha256:{hashlib.sha256(data).hexdigest()}"


def test_typed_family_details_bind_registration_and_artifact_roles() -> None:
    projection = json.loads(producer_projection())
    programs = {case["id"]: case["program"] for case in projection["cases"]}
    property_program = programs["IR-PY-002"]
    assert (
        property_program["evidence"][0]["family"]["detail"]["property"]["seed"]
        == 4_025_493_768
    )

    substituted_property = json.loads(json.dumps(property_program))
    substituted_property["evidence"][0]["family"]["detail"]["property"]["seed"] = 1
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(substituted_property))
    assert caught.value.code == "IR-EVIDENCE-FAMILY-DETAIL"

    substituted_fact = json.loads(json.dumps(property_program))
    substituted_fact["evidence"][0]["backend"]["retained_facts"][0]["value"][
        "configuration_sha256"
    ] = f"sha256:{'0' * 64}"
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(substituted_fact))
    assert caught.value.code == "IR-BACKEND-FACT-MISMATCH"

    optional_extension = json.loads(json.dumps(property_program))
    fact = optional_extension["evidence"][0]["backend"]["retained_facts"][0]
    fact.clear()
    fact.update(
        {
            "schema": "extension-observation/1",
            "required": False,
            "payload_sha256": f"sha256:{'1' * 64}",
        }
    )
    validate_case_program(canonical_json(optional_extension))

    substituted_role = json.loads(json.dumps(programs["IR-SEM-004"]))
    substituted_role["evidence"][1]["family"]["detail"]["artifact"]["logical_name"] = (
        "substituted-artifact"
    )
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(substituted_role))
    assert caught.value.code == "IR-ARTIFACT-IDENTITY-MISMATCH"


def test_subject_closure_binds_registered_paths_and_bytes() -> None:
    projection = json.loads(producer_projection())
    program = next(
        case["program"] for case in projection["cases"] if case["id"] == "IR-PY-001"
    )
    closure = program["claims"][0]["subject_closure"]
    assert closure["selectors"] == ["src/inventory_service/reservations.py"]
    assert closure["members"][0]["logical_name"] == closure["selectors"][0]

    substituted = json.loads(json.dumps(program))
    closure = substituted["claims"][0]["subject_closure"]
    closure["selectors"][0] = "src/inventory_service/substituted.py"
    closure["members"][0]["logical_name"] = "src/inventory_service/substituted.py"
    material = {
        "schema": closure["schema"],
        "selectors": closure["selectors"],
        "members": closure["members"],
    }
    closure["sha256"] = domain_hash(closure["schema"], canonical_json(material))
    with pytest.raises(AssuranceIrError) as caught:
        validate_case_program(canonical_json(substituted))
    assert caught.value.code == "IR-CLAIM-SUBJECT-CLOSURE"


def test_both_implementations_reject_every_preregistered_attack() -> None:
    projection = json.loads(producer_projection())
    programs = {case["id"]: case["program"] for case in projection["cases"]}
    adversarial = json.loads(ADVERSARIAL.read_bytes())
    assert adversarial["revision"] == 2
    assert len(adversarial["cases"]) == 20
    rust_validator = ROOT / "target/debug/proofbound-ir-prototype"

    for attack in adversarial["cases"]:
        data = mutate_case(programs[attack["base_case"]], attack["mutation"])
        expected = attack["expected"]["code"]
        with pytest.raises(AssuranceIrError) as caught:
            validate_case_program(data)
        assert caught.value.code == expected, attack["id"]

        rust = subprocess.run(
            [rust_validator, "validate"],
            cwd=ROOT,
            input=data,
            capture_output=True,
            check=False,
        )
        assert rust.returncode == 1, attack["id"]
        assert rust.stderr.decode().startswith(f"{expected}:"), attack["id"]


def test_both_implementations_reject_every_preregistered_q1_attack() -> None:
    projection = json.loads(producer_projection())
    programs = {case["id"]: case["program"] for case in projection["cases"]}
    adversarial = json.loads(Q1_ADVERSARIAL.read_bytes())
    assert adversarial["revision"] == 1
    assert adversarial["status"] == "preregistered-not-executed"
    attacks = adversarial["cases"]
    assert len(attacks) == 12
    base = programs[adversarial["base_case"]]
    rust_validator = ROOT / "target/debug/proofbound-ir-prototype"

    for attack in attacks:
        data = mutate_case(base, attack["mutation"])
        expected = attack["expected"]["code"]
        with pytest.raises(AssuranceIrError) as caught:
            validate_case_program(data)
        assert caught.value.code == expected, attack["id"]

        rust = subprocess.run(
            [rust_validator, "validate"],
            cwd=ROOT,
            input=data,
            capture_output=True,
            check=False,
        )
        assert rust.returncode == 1, attack["id"]
        assert rust.stderr.decode().startswith(f"{expected}:"), attack["id"]


def mutate_case(program: dict[str, object], mutation: dict[str, object]) -> bytes:
    """Apply one preregistered transformation to an isolated base case."""

    value = json.loads(json.dumps(program))
    operation = mutation["operation"]
    if operation == "delete":
        parent, field = pointer_parent(value, str(mutation["path"]))
        if isinstance(parent, list):
            del parent[int(field)]
        else:
            del parent[field]
    elif operation in {"replace", "replace-reported-status"}:
        parent, field = pointer_parent(value, str(mutation["path"]))
        if isinstance(parent, list):
            parent[int(field)] = mutation["value"]
        else:
            parent[field] = mutation["value"]
    elif operation == "duplicate-set-member":
        items = pointer(value, str(mutation["path"]))
        index = int(mutation["index"])
        items.insert(index, items[index])
    elif operation == "replace-family":
        family = next(
            item["family"]
            for item in value["evidence"]
            if item["family"]["kind"] == mutation["from"]
        )
        family["kind"] = mutation["to"]
    elif operation == "remove-set-member":
        items = pointer(value, str(mutation["path"]))
        if "value" in mutation:
            items.remove(mutation["value"])
        else:
            items.remove(
                next(item for item in items if item["selector"] == mutation["selector"])
            )
    elif operation == "add-set-member":
        items = pointer(value, str(mutation["path"]))
        items.append(mutation["value"])
        items.sort()
    elif operation == "add-object-field":
        parent = pointer(value, str(mutation["path"]))
        parent[mutation["field"]] = mutation["value"]
    elif operation == "add-array-member":
        pointer(value, str(mutation["path"])).append(mutation["value"])
    elif operation == "delete-array-member":
        del pointer(value, str(mutation["path"]))[int(mutation["index"])]
    elif operation == "duplicate-array-member":
        items = pointer(value, str(mutation["path"]))
        index = int(mutation["index"])
        items.insert(index, json.loads(json.dumps(items[index])))
    elif operation == "add-graph-edge-and-rehash":
        graph = value["programme"]["graph"]
        graph["edges"].append(mutation["value"])
        value["programme"]["graph_sha256"] = domain_hash(
            graph["schema"], canonical_json(graph)
        )
    elif operation == "replace-and-rehash-graph":
        parent, field = pointer_parent(value, str(mutation["path"]))
        if isinstance(parent, list):
            parent[int(field)] = mutation["value"]
        else:
            parent[field] = mutation["value"]
        graph = value["programme"]["graph"]
        value["programme"]["graph_sha256"] = domain_hash(
            graph["schema"], canonical_json(graph)
        )
    elif operation == "encode-noncanonical":
        return canonical_json(value) + b"\n"
    elif operation == "encode-duplicate-object-key":
        data = canonical_json(value)
        unit = value["evidence"][0]["unit"]
        needle = f'"unit":"{unit}"'.encode()
        return data.replace(needle, needle + b"," + needle, 1)
    else:
        raise AssertionError(f"unsupported adversarial operation {operation}")
    return canonical_json(value)


def pointer(value: object, path: str) -> object:
    if not path:
        return value
    current = value
    for part in path.removeprefix("/").split("/"):
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def pointer_parent(value: object, path: str) -> tuple[object, str]:
    parent_path, field = path.rsplit("/", 1)
    return pointer(value, parent_path), field
