"""Independent specification-adequacy model for Experiment 0014."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, NoReturn

UNIVERSE_SCHEMA = "proofbound-research-specification-universe/1"
SUITE_SCHEMA = "proofbound-research-specification-suite/1"
EXECUTIONS_SCHEMA = "proofbound-research-specification-executions/1"
REPORT_SCHEMA = "proofbound-research-specification-report/1"
MODEL_REPORT_SCHEMA = "proofbound-research-specification-model-report/1"
ATTACK_SCHEMA = "proofbound-research-specification-attacks/1"
ROW_FIELDS = [
    "case",
    "result_ok",
    "decoded_value",
    "roundtrip_equal",
    "canonical_equal",
    "consumed",
    "steps",
]


class SpecificationFailure(ValueError):
    """Report one exact specification-model rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def canonical_json(value: object) -> bytes:
    """Encode a research value as compact sorted-key UTF-8 JSON."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def domain_hash(domain: str, payload: bytes) -> str:
    """Return a domain-separated SHA-256 identity."""

    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def sha256_bytes(payload: bytes) -> str:
    """Return a raw-byte SHA-256 identity."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_specification_corpus(
    root: Path, corpus_dir: Path
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], bytes, bytes
]:
    """Load and cross-validate all frozen specification inputs."""

    universe_bytes = (root / corpus_dir / "universe.json").read_bytes()
    suite_bytes = (root / corpus_dir / "contracts.json").read_bytes()
    execution_bytes = (root / corpus_dir / "execution-tables.json").read_bytes()
    universe = _decode(universe_bytes)
    suite = _decode(suite_bytes)
    executions = _decode(execution_bytes)
    attacks = _decode((root / corpus_dir / "attacks.json").read_bytes())
    _validate_sources(universe, suite, executions, universe_bytes)
    _exact_keys(attacks, {"schema", "attacks"}, "SPEC-SCHEMA")
    if attacks["schema"] != ATTACK_SCHEMA or not attacks["attacks"]:
        _fail("SPEC-SCHEMA", "invalid attack corpus")
    identifiers: set[str] = set()
    for attack in attacks["attacks"]:
        _exact_keys(attack, {"id", "code", "action"}, "SPEC-SCHEMA")
        _validate_id(attack["id"])
        _validate_id(attack["code"])
        if attack["id"] in identifiers:
            _fail("SPEC-NONCANONICAL", "duplicate attack ID")
        identifiers.add(attack["id"])
    return universe, suite, executions, attacks, universe_bytes, execution_bytes


def derive_specification_report(
    universe: dict[str, Any],
    suite: dict[str, Any],
    executions: dict[str, Any],
    universe_bytes: bytes,
    execution_bytes: bytes,
) -> dict[str, Any]:
    """Derive correct obligations and exact mutant counterexamples."""

    tables = _validate_sources(universe, suite, executions, universe_bytes)
    variables = {item["name"]: item for item in universe["variables"]}
    carriers = {item["id"]: item for item in universe["carriers"]}
    correct = tables[suite["correct_implementation"]]
    contract_results: list[dict[str, Any]] = []
    for contract in suite["contracts"]:
        reachable, satisfied, failure = _evaluate_contract(
            contract, variables, carriers, correct
        )
        if failure is not None:
            _fail(
                "SPEC-CORRECT-REJECTED",
                f"correct implementation failed {contract['id']} at {failure}",
            )
        contract_results.append(
            {
                "id": contract["id"],
                "role": contract["role"],
                "reachable_cases": reachable,
                "satisfied_obligations": satisfied,
            }
        )
    mutant_results: list[dict[str, Any]] = []
    for mutant in suite["required_mutants"]:
        table = tables.get(mutant)
        if table is None:
            _fail("SPEC-MUTANT-UNKNOWN", "mutant table is missing")
        failing: list[str] = []
        counterexample: dict[str, str] | None = None
        for contract in suite["contracts"]:
            _, _, failure = _evaluate_contract(contract, variables, carriers, table)
            if failure is not None:
                failing.append(contract["id"])
                if counterexample is None:
                    counterexample = {"contract": contract["id"], "case": failure}
        if counterexample is None:
            _fail("SPEC-MUTANT-SURVIVED", f"mutant {mutant} satisfies every contract")
        mutant_results.append(
            {
                "id": mutant,
                "killed": True,
                "failing_contracts": failing,
                "first_counterexample": counterexample,
            }
        )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "suite_identity": domain_hash(SUITE_SCHEMA, canonical_json(suite)),
        "universe_sha256": sha256_bytes(universe_bytes),
        "executions_sha256": sha256_bytes(execution_bytes),
        "correct_implementation": suite["correct_implementation"],
        "correct_accepted": True,
        "contract_results": contract_results,
        "mutant_results": mutant_results,
        "ast_nodes": sum(
            _expression_nodes(contract["requires"])
            + _expression_nodes(contract["ensures"])
            for contract in suite["contracts"]
        ),
        "carrier_values": sum(
            len(carrier["cases"]) for carrier in universe["carriers"]
        ),
        "identity": "",
    }
    report["identity"] = _report_identity(report)
    return report


def validate_specification_report(
    universe: dict[str, Any],
    suite: dict[str, Any],
    executions: dict[str, Any],
    universe_bytes: bytes,
    execution_bytes: bytes,
    report: dict[str, Any],
) -> None:
    """Validate a report by independently deriving its complete value."""

    if report.get("schema") != REPORT_SCHEMA or report.get(
        "identity"
    ) != _report_identity(report):
        _fail("SPEC-IDENTITY-FORGED", "report identity is invalid")
    expected = derive_specification_report(
        universe, suite, executions, universe_bytes, execution_bytes
    )
    if report != expected:
        _fail("SPEC-REPORT-MISMATCH", "report differs from derivation")


def execute_specification_corpus(
    root: Path, corpus_dir: Path, repetitions: int
) -> dict[str, Any]:
    """Execute the frozen adequacy model and every registered attack."""

    if isinstance(repetitions, bool) or not 1 <= repetitions <= 100:
        _fail("SPEC-REPETITIONS", "invalid repetition count")
    universe, suite, executions, attacks, universe_bytes, execution_bytes = (
        load_specification_corpus(root, corpus_dir)
    )
    report = derive_specification_report(
        universe, suite, executions, universe_bytes, execution_bytes
    )
    validate_specification_report(
        universe, suite, executions, universe_bytes, execution_bytes, report
    )
    repeated: list[str] = []
    for _ in range(repetitions):
        candidate = derive_specification_report(
            universe, suite, executions, universe_bytes, execution_bytes
        )
        if candidate != report:
            _fail("SPEC-NONDETERMINISTIC", "report changed")
        repeated.append(candidate["identity"])
    attack_results = [
        _evaluate_attack(
            universe,
            suite,
            executions,
            universe_bytes,
            execution_bytes,
            attack,
        )
        for attack in attacks["attacks"]
    ]
    return {
        "schema": MODEL_REPORT_SCHEMA,
        "specification_report": report,
        "attacks": attack_results,
        "repetition_report_identities": repeated,
    }


def _validate_sources(
    universe: dict[str, Any],
    suite: dict[str, Any],
    executions: dict[str, Any],
    universe_bytes: bytes,
) -> dict[str, dict[str, dict[str, dict[str, object]]]]:
    _validate_universe(universe)
    _validate_suite(universe, suite, universe_bytes)
    return _validate_executions(universe, suite, executions)


def _validate_universe(universe: dict[str, Any]) -> None:
    _exact_keys(
        universe,
        {"schema", "carriers", "required_mutants", "required_roles", "variables"},
        "SPEC-SCHEMA",
    )
    if universe["schema"] != UNIVERSE_SCHEMA:
        _fail("SPEC-SCHEMA", "unexpected universe schema")
    _strict_named(universe["carriers"], "id")
    _strict_strings(universe["required_mutants"])
    _strict_strings(universe["required_roles"])
    _strict_named(universe["variables"], "name")
    variables: dict[str, dict[str, str]] = {}
    for variable in universe["variables"]:
        _exact_keys(variable, {"name", "type", "role"}, "SPEC-SCHEMA")
        _validate_id(variable["name"])
        if variable["type"] not in {"bool", "int"} or variable["role"] not in {
            "input",
            "result",
        }:
            _fail("SPEC-TYPE-MISMATCH", "variable type or role is invalid")
        variables[variable["name"]] = variable
    for carrier in universe["carriers"]:
        _exact_keys(carrier, {"id", "cases"}, "SPEC-SCHEMA")
        _validate_id(carrier["id"])
        _strict_named(carrier["cases"], "id")
        for case in carrier["cases"]:
            _exact_keys(case, {"id", "environment"}, "SPEC-SCHEMA")
            _validate_id(case["id"])
            if not isinstance(case["environment"], dict) or not case["environment"]:
                _fail("SPEC-CARRIER-EMPTY", "case environment is empty")
            for name, value in case["environment"].items():
                variable = variables.get(name)
                if variable is None:
                    _fail("SPEC-VARIABLE-UNKNOWN", "case variable is unknown")
                if variable["role"] != "input" or not _value_matches(
                    value, variable["type"]
                ):
                    _fail("SPEC-TYPE-MISMATCH", "case value type is invalid")


def _validate_suite(
    universe: dict[str, Any], suite: dict[str, Any], universe_bytes: bytes
) -> None:
    _exact_keys(
        suite,
        {
            "schema",
            "universe_sha256",
            "correct_implementation",
            "required_mutants",
            "contracts",
        },
        "SPEC-SCHEMA",
    )
    if suite["schema"] != SUITE_SCHEMA or suite["universe_sha256"] != sha256_bytes(
        universe_bytes
    ):
        _fail("SPEC-SOURCE-DRIFT", "suite is not bound to universe bytes")
    contracts = suite["contracts"]
    if not isinstance(contracts, list) or not contracts:
        _fail("SPEC-OBLIGATION-EMPTY", "contract list is empty")
    identifiers = [contract.get("id") for contract in contracts]
    if len(set(identifiers)) != len(identifiers):
        _fail("SPEC-CONTRACT-DUPLICATE", "contract ID is duplicated")
    if identifiers != sorted(identifiers):
        _fail("SPEC-NONCANONICAL", "contracts are not lexical")
    if any(
        mutant not in universe["required_mutants"]
        for mutant in suite["required_mutants"]
    ):
        _fail("SPEC-MUTANT-UNKNOWN", "required mutant is unknown")
    if suite["required_mutants"] != universe["required_mutants"]:
        _fail("SPEC-MUTANT-COVERAGE", "required mutant set is incomplete")
    if {contract["role"] for contract in contracts} != set(universe["required_roles"]):
        _fail("SPEC-OBLIGATION-EMPTY", "required property role is missing")
    variables = {item["name"]: item for item in universe["variables"]}
    carriers = {item["id"]: item for item in universe["carriers"]}
    for contract in contracts:
        _exact_keys(
            contract,
            {"id", "role", "carrier", "cases", "requires", "ensures"},
            "SPEC-SCHEMA",
        )
        _validate_id(contract["id"])
        _validate_id(contract["role"])
        carrier = carriers.get(contract["carrier"])
        if carrier is None:
            _fail("SPEC-CARRIER-UNKNOWN", "contract carrier is unknown")
        cases = contract["cases"]
        if not cases:
            _fail("SPEC-CARRIER-EMPTY", "contract carrier is empty")
        if len(cases) != len(set(cases)):
            _fail("SPEC-CARRIER-DUPLICATE", "contract case is duplicated")
        if cases != sorted(cases):
            _fail("SPEC-NONCANONICAL", "contract cases are not lexical")
        if cases != [case["id"] for case in carrier["cases"]]:
            _fail("SPEC-CARRIER-INCOMPLETE", "contract carrier is incomplete")
        if (
            _expression_type(contract["requires"], variables) != "bool"
            or _expression_type(contract["ensures"], variables) != "bool"
        ):
            _fail("SPEC-TYPE-MISMATCH", "contract expressions are not Boolean")
        if any(
            variables[name]["role"] == "result"
            for name in _expression_variables(contract["requires"])
        ):
            _fail(
                "SPEC-RESULT-IN-PRECONDITION",
                "precondition references a result variable",
            )
        if contract["ensures"] == {"kind": "bool", "value": True}:
            _fail("SPEC-ENSURES-TAUTOLOGY", "postcondition is literal true")
        if not any(
            variables[name]["role"] == "result"
            for name in _expression_variables(contract["ensures"])
        ):
            _fail("SPEC-RESULT-UNBOUND", "postcondition does not constrain result")
        if _is_vacuous_implication(contract["ensures"]):
            _fail("SPEC-IMPLICATION-VACUOUS", "implication premise is false")
        if _is_direct_contradiction(contract["ensures"]):
            _fail("SPEC-ENSURES-UNSAT", "postcondition is inconsistent")
        reachable = sum(
            _evaluate_bool(contract["requires"], case["environment"])
            for case in carrier["cases"]
        )
        if reachable == 0:
            _fail("SPEC-REQUIRES-UNSAT", "precondition is unreachable")


def _validate_executions(
    universe: dict[str, Any], suite: dict[str, Any], executions: dict[str, Any]
) -> dict[str, dict[str, dict[str, dict[str, object]]]]:
    _exact_keys(
        executions,
        {"schema", "row_fields", "implementations"},
        "SPEC-EXECUTION-SCHEMA",
    )
    if (
        executions["schema"] != EXECUTIONS_SCHEMA
        or executions["row_fields"] != ROW_FIELDS
    ):
        _fail("SPEC-EXECUTION-SCHEMA", "execution schema is invalid")
    _strict_named(executions["implementations"], "id")
    wanted = set(suite["required_mutants"]) | {suite["correct_implementation"]}
    if {item["id"] for item in executions["implementations"]} != wanted:
        _fail("SPEC-MUTANT-UNKNOWN", "execution inventory is invalid")
    carriers = {carrier["id"]: carrier for carrier in universe["carriers"]}
    tables: dict[str, dict[str, dict[str, dict[str, object]]]] = {}
    for implementation in executions["implementations"]:
        _exact_keys(implementation, {"id", "rows"}, "SPEC-EXECUTION-SCHEMA")
        if set(implementation["rows"]) != set(carriers):
            _fail("SPEC-EXECUTION-INCOMPLETE", "carrier rows are incomplete")
        table: dict[str, dict[str, dict[str, object]]] = {}
        for carrier_id, carrier in carriers.items():
            rows = implementation["rows"][carrier_id]
            if len(rows) != len(carrier["cases"]):
                _fail("SPEC-EXECUTION-INCOMPLETE", "case rows are incomplete")
            case_table: dict[str, dict[str, object]] = {}
            for row, case in zip(rows, carrier["cases"], strict=True):
                case_id, output = _parse_row(row)
                if case_id != case["id"] or case_id in case_table:
                    _fail("SPEC-NONCANONICAL", "execution rows are not exact")
                case_table[case_id] = output
            table[carrier_id] = case_table
        tables[implementation["id"]] = table
    return tables


def _evaluate_contract(
    contract: dict[str, Any],
    variables: dict[str, dict[str, str]],
    carriers: dict[str, dict[str, Any]],
    table: dict[str, dict[str, dict[str, object]]],
) -> tuple[int, int, str | None]:
    reachable = 0
    satisfied = 0
    first_failure: str | None = None
    for case in carriers[contract["carrier"]]["cases"]:
        if not _evaluate_bool(contract["requires"], case["environment"]):
            continue
        reachable += 1
        environment = dict(case["environment"])
        environment.update(table[contract["carrier"]][case["id"]])
        for name, value in environment.items():
            if name in variables and not _value_matches(value, variables[name]["type"]):
                _fail("SPEC-TYPE-MISMATCH", "execution value type is invalid")
        if _evaluate_bool(contract["ensures"], environment):
            satisfied += 1
        elif first_failure is None:
            first_failure = case["id"]
    return reachable, satisfied, first_failure


def _evaluate_attack(
    universe: dict[str, Any],
    suite: dict[str, Any],
    executions: dict[str, Any],
    universe_bytes: bytes,
    execution_bytes: bytes,
    attack: dict[str, Any],
) -> dict[str, Any]:
    try:
        _run_attack(
            universe,
            suite,
            executions,
            universe_bytes,
            execution_bytes,
            attack["action"],
        )
    except SpecificationFailure as error:
        actual = error.code
    else:
        actual = "ACCEPTED"
    return {
        "id": attack["id"],
        "expected_code": attack["code"],
        "actual_code": actual,
        "exact": actual == attack["code"],
    }


def _run_attack(
    universe: dict[str, Any],
    suite: dict[str, Any],
    executions: dict[str, Any],
    universe_bytes: bytes,
    execution_bytes: bytes,
    action: dict[str, Any],
) -> None:
    kind = action["kind"]
    if kind == "forge-report-identity":
        report = derive_specification_report(
            universe, suite, executions, universe_bytes, execution_bytes
        )
        report["identity"] = action["value"]
        validate_specification_report(
            universe, suite, executions, universe_bytes, execution_bytes, report
        )
        return
    changed = deepcopy(suite)
    if kind == "replace-expression-kind":
        contract = _contract(changed, action["contract"])
        contract["ensures"]["kind"] = action["value"]
    elif kind == "duplicate-contract":
        changed["contracts"].append(deepcopy(_contract(changed, action["contract"])))
    elif kind == "duplicate-case":
        _contract(changed, action["contract"])["cases"].append(action["case"])
    elif kind == "empty-cases":
        _contract(changed, action["contract"])["cases"] = []
    elif kind == "remove-case":
        contract = _contract(changed, action["contract"])
        contract["cases"] = [
            case for case in contract["cases"] if case != action["case"]
        ]
    elif kind in {"replace-ensures", "replace-requires"}:
        _contract(changed, action["contract"])[
            "ensures" if kind == "replace-ensures" else "requires"
        ] = deepcopy(action["value"])
    elif kind == "empty-contracts":
        changed["contracts"] = []
    elif kind == "add-required-mutant":
        changed["required_mutants"].append(action["mutant"])
        changed["required_mutants"].sort()
    elif kind == "remove-required-mutant":
        changed["required_mutants"] = [
            mutant
            for mutant in changed["required_mutants"]
            if mutant != action["mutant"]
        ]
    elif kind == "replace-ensures-many":
        for replacement in action["replacements"]:
            _contract(changed, replacement["contract"])["ensures"] = deepcopy(
                replacement["value"]
            )
    elif kind == "reverse-contracts":
        changed["contracts"].reverse()
    else:
        _fail("SPEC-CONSTRUCTOR-UNKNOWN", "unknown attack action")
    derive_specification_report(
        universe, changed, executions, universe_bytes, execution_bytes
    )


def _expression_type(expression: object, variables: dict[str, dict[str, str]]) -> str:
    if not isinstance(expression, dict) or not isinstance(expression.get("kind"), str):
        _fail("SPEC-CONSTRUCTOR-UNKNOWN", "expression is not a typed object")
    kind = expression["kind"]
    if kind == "bool":
        _exact_keys(expression, {"kind", "value"}, "SPEC-CONSTRUCTOR-UNKNOWN")
        if not isinstance(expression["value"], bool):
            _fail("SPEC-TYPE-MISMATCH", "Boolean literal is invalid")
        return "bool"
    if kind == "int":
        _exact_keys(expression, {"kind", "value"}, "SPEC-CONSTRUCTOR-UNKNOWN")
        if not _is_int(expression["value"]):
            _fail("SPEC-TYPE-MISMATCH", "integer literal is invalid")
        return "int"
    if kind == "var":
        _exact_keys(expression, {"kind", "name"}, "SPEC-CONSTRUCTOR-UNKNOWN")
        variable = variables.get(expression["name"])
        if variable is None:
            _fail("SPEC-VARIABLE-UNKNOWN", "expression variable is unknown")
        return variable["type"]
    if kind == "not":
        _exact_keys(expression, {"kind", "value"}, "SPEC-CONSTRUCTOR-UNKNOWN")
        _require_type(_expression_type(expression["value"], variables), "bool")
        return "bool"
    if kind == "and":
        _exact_keys(expression, {"kind", "values"}, "SPEC-CONSTRUCTOR-UNKNOWN")
        if not isinstance(expression["values"], list) or len(expression["values"]) < 2:
            _fail("SPEC-CONSTRUCTOR-UNKNOWN", "and requires two values")
        for value in expression["values"]:
            _require_type(_expression_type(value, variables), "bool")
        return "bool"
    if kind in {"eq", "le", "add"}:
        _exact_keys(expression, {"kind", "left", "right"}, "SPEC-CONSTRUCTOR-UNKNOWN")
        left = _expression_type(expression["left"], variables)
        right = _expression_type(expression["right"], variables)
        if kind == "eq":
            _require_type(right, left)
            return "bool"
        _require_type(left, "int")
        _require_type(right, "int")
        return "bool" if kind == "le" else "int"
    if kind == "implies":
        _exact_keys(
            expression,
            {"kind", "premise", "conclusion"},
            "SPEC-CONSTRUCTOR-UNKNOWN",
        )
        _require_type(_expression_type(expression["premise"], variables), "bool")
        _require_type(_expression_type(expression["conclusion"], variables), "bool")
        return "bool"
    _fail("SPEC-CONSTRUCTOR-UNKNOWN", "expression constructor is unknown")


def _evaluate_bool(expression: dict[str, Any], environment: dict[str, object]) -> bool:
    value = _evaluate(expression, environment)
    if not isinstance(value, bool):
        _fail("SPEC-TYPE-MISMATCH", "expected Boolean")
    return value


def _evaluate(expression: dict[str, Any], environment: dict[str, object]) -> object:
    kind = expression["kind"]
    if kind in {"bool", "int"}:
        return expression["value"]
    if kind == "var":
        if expression["name"] not in environment:
            _fail("SPEC-VARIABLE-UNKNOWN", "case variable value is missing")
        return environment[expression["name"]]
    if kind == "not":
        return not _evaluate_bool(expression["value"], environment)
    if kind == "and":
        return all(_evaluate_bool(value, environment) for value in expression["values"])
    if kind == "eq":
        return _evaluate(expression["left"], environment) == _evaluate(
            expression["right"], environment
        )
    if kind == "le":
        return _evaluate_int(expression["left"], environment) <= _evaluate_int(
            expression["right"], environment
        )
    if kind == "add":
        value = _evaluate_int(expression["left"], environment) + _evaluate_int(
            expression["right"], environment
        )
        if value > 2**64 - 1:
            _fail("SPEC-INTEGER-OVERFLOW", "integer addition overflowed")
        return value
    if kind == "implies":
        return not _evaluate_bool(expression["premise"], environment) or _evaluate_bool(
            expression["conclusion"], environment
        )
    _fail("SPEC-CONSTRUCTOR-UNKNOWN", "expression constructor is unknown")


def _evaluate_int(expression: dict[str, Any], environment: dict[str, object]) -> int:
    value = _evaluate(expression, environment)
    if not _is_int(value):
        _fail("SPEC-TYPE-MISMATCH", "expected integer")
    return value


def _expression_variables(expression: dict[str, Any]) -> set[str]:
    kind = expression["kind"]
    if kind == "var":
        return {expression["name"]}
    if kind == "not":
        return _expression_variables(expression["value"])
    if kind == "and":
        return set().union(
            *(_expression_variables(item) for item in expression["values"])
        )
    if kind in {"eq", "le", "add"}:
        return _expression_variables(expression["left"]) | _expression_variables(
            expression["right"]
        )
    if kind == "implies":
        return _expression_variables(expression["premise"]) | _expression_variables(
            expression["conclusion"]
        )
    return set()


def _expression_nodes(expression: dict[str, Any]) -> int:
    kind = expression["kind"]
    if kind == "not":
        return 1 + _expression_nodes(expression["value"])
    if kind == "and":
        return 1 + sum(_expression_nodes(value) for value in expression["values"])
    if kind in {"eq", "le", "add"}:
        return (
            1
            + _expression_nodes(expression["left"])
            + _expression_nodes(expression["right"])
        )
    if kind == "implies":
        return (
            1
            + _expression_nodes(expression["premise"])
            + _expression_nodes(expression["conclusion"])
        )
    return 1


def _is_vacuous_implication(expression: dict[str, Any]) -> bool:
    return expression["kind"] == "implies" and expression["premise"] == {
        "kind": "bool",
        "value": False,
    }


def _is_direct_contradiction(expression: dict[str, Any]) -> bool:
    if expression["kind"] != "and":
        return False
    values = expression["values"]
    return any(
        other.get("kind") == "not" and other.get("value") == candidate
        for candidate in values
        for other in values
        if isinstance(other, dict)
    )


def _parse_row(row: object) -> tuple[str, dict[str, object]]:
    if not isinstance(row, list) or len(row) != 7 or not isinstance(row[0], str):
        _fail("SPEC-EXECUTION-INCOMPLETE", "execution row is invalid")
    if not all(isinstance(row[index], bool) for index in (1, 3, 4)) or not all(
        _is_int(row[index]) for index in (2, 5, 6)
    ):
        _fail("SPEC-TYPE-MISMATCH", "execution row value is invalid")
    return row[0], {
        "result_ok": row[1],
        "decoded_value": row[2],
        "roundtrip_equal": row[3],
        "canonical_equal": row[4],
        "consumed": row[5],
        "steps": row[6],
    }


def _report_identity(report: dict[str, Any]) -> str:
    return domain_hash(
        REPORT_SCHEMA,
        canonical_json(
            {key: value for key, value in report.items() if key != "identity"}
        ),
    )


def _contract(suite: dict[str, Any], identifier: str) -> dict[str, Any]:
    for contract in suite["contracts"]:
        if contract["id"] == identifier:
            return contract
    _fail("SPEC-CONTRACT-UNKNOWN", "contract is missing")


def _strict_named(values: object, field: str) -> None:
    if not isinstance(values, list) or not values:
        _fail("SPEC-NONCANONICAL", "named records are empty")
    names = [value.get(field) for value in values]
    if names != sorted(set(names)):
        _fail("SPEC-NONCANONICAL", "named records are not a strict lexical set")


def _strict_strings(values: object) -> None:
    if not isinstance(values, list) or values != sorted(set(values)) or not values:
        _fail("SPEC-NONCANONICAL", "strings are not a strict lexical set")
    for value in values:
        _validate_id(value)


def _validate_id(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > 128
        or any(
            not (character.isascii() and (character.isalnum() or character in "-_.:"))
            for character in value
        )
    ):
        _fail("SPEC-ID", "identifier is invalid")


def _value_matches(value: object, value_type: str) -> bool:
    return isinstance(value, bool) if value_type == "bool" else _is_int(value)


def _is_int(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 2**64 - 1
    )


def _require_type(actual: str, expected: str) -> None:
    if actual != expected:
        _fail("SPEC-TYPE-MISMATCH", "expression types differ")


def _exact_keys(value: object, expected: set[str], code: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        _fail(code, "record fields do not match the closed schema")


def _decode(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("SPEC-DECODE", str(error))
    if not isinstance(value, dict):
        _fail("SPEC-DECODE", "top-level value is not an object")
    return value


def _fail(code: str, message: str) -> NoReturn:
    raise SpecificationFailure(code, message)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: specifications_research.py <repository-root> <corpus-dir> <repetitions>"
        )
    model = execute_specification_corpus(
        Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    )
    sys.stdout.buffer.write(canonical_json(model))
