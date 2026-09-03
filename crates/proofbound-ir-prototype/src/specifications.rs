use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SPECIFICATION_UNIVERSE_SCHEMA: &str = "proofbound-research-specification-universe/1";
pub const SPECIFICATION_SUITE_SCHEMA: &str = "proofbound-research-specification-suite/1";
pub const SPECIFICATION_EXECUTIONS_SCHEMA: &str = "proofbound-research-specification-executions/1";
pub const SPECIFICATION_REPORT_SCHEMA: &str = "proofbound-research-specification-report/1";
pub const SPECIFICATION_MODEL_REPORT_SCHEMA: &str =
    "proofbound-research-specification-model-report/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationUniverse {
    pub schema: String,
    pub carriers: Vec<SpecificationCarrier>,
    pub required_mutants: Vec<String>,
    pub required_roles: Vec<String>,
    pub variables: Vec<SpecificationVariable>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationCarrier {
    pub id: String,
    pub cases: Vec<SpecificationCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationCase {
    pub id: String,
    pub environment: BTreeMap<String, SpecificationValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SpecificationValue {
    Bool(bool),
    Int(u64),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationVariable {
    pub name: String,
    #[serde(rename = "type")]
    pub value_type: SpecificationType,
    pub role: SpecificationVariableRole,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpecificationType {
    Bool,
    Int,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpecificationVariableRole {
    Input,
    Result,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationSuite {
    pub schema: String,
    pub universe_sha256: String,
    pub correct_implementation: String,
    pub required_mutants: Vec<String>,
    pub contracts: Vec<SpecificationContract>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationContract {
    pub id: String,
    pub role: String,
    pub carrier: String,
    pub cases: Vec<String>,
    pub requires: SpecificationExpression,
    pub ensures: SpecificationExpression,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SpecificationExpression {
    Bool {
        value: bool,
    },
    Int {
        value: u64,
    },
    Var {
        name: String,
    },
    Not {
        value: Box<SpecificationExpression>,
    },
    And {
        values: Vec<SpecificationExpression>,
    },
    Eq {
        left: Box<SpecificationExpression>,
        right: Box<SpecificationExpression>,
    },
    Le {
        left: Box<SpecificationExpression>,
        right: Box<SpecificationExpression>,
    },
    Add {
        left: Box<SpecificationExpression>,
        right: Box<SpecificationExpression>,
    },
    Implies {
        premise: Box<SpecificationExpression>,
        conclusion: Box<SpecificationExpression>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationExecutions {
    pub schema: String,
    pub row_fields: Vec<String>,
    pub implementations: Vec<SpecificationImplementation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationImplementation {
    pub id: String,
    pub rows: BTreeMap<String, Vec<Vec<Value>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutionOutput {
    result_ok: bool,
    decoded_value: u64,
    roundtrip_equal: bool,
    canonical_equal: bool,
    consumed: u64,
    steps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationReport {
    pub schema: String,
    pub suite_identity: String,
    pub universe_sha256: String,
    pub executions_sha256: String,
    pub correct_implementation: String,
    pub correct_accepted: bool,
    pub contract_results: Vec<SpecificationContractResult>,
    pub mutant_results: Vec<SpecificationMutantResult>,
    pub ast_nodes: u64,
    pub carrier_values: u64,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationContractResult {
    pub id: String,
    pub role: String,
    pub reachable_cases: u64,
    pub satisfied_obligations: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationMutantResult {
    pub id: String,
    pub killed: bool,
    pub failing_contracts: Vec<String>,
    pub first_counterexample: SpecificationCounterexample,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationCounterexample {
    pub contract: String,
    pub case: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationAttackCorpus {
    pub schema: String,
    pub attacks: Vec<SpecificationAttack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationAttack {
    pub id: String,
    pub code: String,
    pub action: SpecificationAttackAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SpecificationAttackAction {
    ReplaceExpressionKind {
        contract: String,
        value: String,
    },
    DuplicateContract {
        contract: String,
    },
    DuplicateCase {
        contract: String,
        case: String,
    },
    EmptyCases {
        contract: String,
    },
    RemoveCase {
        contract: String,
        case: String,
    },
    ReplaceEnsures {
        contract: String,
        value: Value,
    },
    ReplaceRequires {
        contract: String,
        value: Value,
    },
    EmptyContracts,
    AddRequiredMutant {
        mutant: String,
    },
    RemoveRequiredMutant {
        mutant: String,
    },
    ReplaceEnsuresMany {
        replacements: Vec<SpecificationReplacement>,
    },
    ForgeReportIdentity {
        value: String,
    },
    ReverseContracts,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationReplacement {
    pub contract: String,
    pub value: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationModelReport {
    pub schema: String,
    pub specification_report: SpecificationReport,
    pub attacks: Vec<SpecificationAttackResult>,
    pub repetition_report_identities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecificationError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for SpecificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SpecificationError {}

type Variables<'a> = BTreeMap<&'a str, &'a SpecificationVariable>;
type Carriers<'a> = BTreeMap<&'a str, &'a SpecificationCarrier>;
type ExecutionTables = BTreeMap<String, BTreeMap<String, BTreeMap<String, ExecutionOutput>>>;
type LoadedSpecificationCorpus = (
    SpecificationUniverse,
    SpecificationSuite,
    SpecificationExecutions,
    SpecificationAttackCorpus,
    Vec<u8>,
    Vec<u8>,
);

pub fn load_specification_corpus(
    root: &Path,
    corpus_dir: &Path,
) -> Result<LoadedSpecificationCorpus, SpecificationError> {
    let universe_bytes = read(root, &corpus_dir.join("universe.json"))?;
    let suite_bytes = read(root, &corpus_dir.join("contracts.json"))?;
    let execution_bytes = read(root, &corpus_dir.join("execution-tables.json"))?;
    let attacks_bytes = read(root, &corpus_dir.join("attacks.json"))?;
    let universe: SpecificationUniverse = decode(&universe_bytes)?;
    let suite: SpecificationSuite = decode(&suite_bytes)?;
    let executions: SpecificationExecutions = decode(&execution_bytes)?;
    let attacks: SpecificationAttackCorpus = decode(&attacks_bytes)?;
    validate_source_records(
        &universe,
        &suite,
        &executions,
        &universe_bytes,
        &execution_bytes,
    )?;
    if attacks.schema != "proofbound-research-specification-attacks/1" || attacks.attacks.is_empty()
    {
        return Err(invalid("SPEC-SCHEMA", "invalid attack corpus"));
    }
    let mut attack_ids = BTreeSet::new();
    for attack in &attacks.attacks {
        validate_id(&attack.id)?;
        validate_id(&attack.code)?;
        if !attack_ids.insert(attack.id.as_str()) {
            return Err(invalid("SPEC-NONCANONICAL", "duplicate attack ID"));
        }
    }
    Ok((
        universe,
        suite,
        executions,
        attacks,
        universe_bytes,
        execution_bytes,
    ))
}

pub fn derive_specification_report(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    executions: &SpecificationExecutions,
    universe_bytes: &[u8],
    execution_bytes: &[u8],
) -> Result<SpecificationReport, SpecificationError> {
    let tables =
        validate_source_records(universe, suite, executions, universe_bytes, execution_bytes)?;
    let variables = variable_map(universe);
    let carriers = carrier_map(universe);
    let correct = tables
        .get(&suite.correct_implementation)
        .ok_or_else(|| invalid("SPEC-CORRECT-UNKNOWN", "correct implementation is missing"))?;
    let mut contract_results = Vec::new();
    for contract in &suite.contracts {
        let evaluation = evaluate_contract(contract, &variables, &carriers, correct)?;
        if let Some(case) = evaluation.first_failure {
            return Err(invalid(
                "SPEC-CORRECT-REJECTED",
                format!("correct implementation failed {} at {case}", contract.id),
            ));
        }
        contract_results.push(SpecificationContractResult {
            id: contract.id.clone(),
            role: contract.role.clone(),
            reachable_cases: evaluation.reachable,
            satisfied_obligations: evaluation.satisfied,
        });
    }
    let mut mutant_results = Vec::new();
    for mutant in &suite.required_mutants {
        let table = tables
            .get(mutant)
            .ok_or_else(|| invalid("SPEC-MUTANT-UNKNOWN", "mutant table is missing"))?;
        let mut failing_contracts = Vec::new();
        let mut first_counterexample = None;
        for contract in &suite.contracts {
            let evaluation = evaluate_contract(contract, &variables, &carriers, table)?;
            if let Some(case) = evaluation.first_failure {
                failing_contracts.push(contract.id.clone());
                if first_counterexample.is_none() {
                    first_counterexample = Some(SpecificationCounterexample {
                        contract: contract.id.clone(),
                        case,
                    });
                }
            }
        }
        let Some(counterexample) = first_counterexample else {
            return Err(invalid(
                "SPEC-MUTANT-SURVIVED",
                format!("mutant {mutant} satisfies every contract"),
            ));
        };
        mutant_results.push(SpecificationMutantResult {
            id: mutant.clone(),
            killed: true,
            failing_contracts,
            first_counterexample: counterexample,
        });
    }
    let suite_bytes =
        canonical_json(suite).map_err(|error| invalid("SPEC-ENCODE", error.to_string()))?;
    let mut report = SpecificationReport {
        schema: SPECIFICATION_REPORT_SCHEMA.to_owned(),
        suite_identity: domain_hash(SPECIFICATION_SUITE_SCHEMA, &suite_bytes),
        universe_sha256: sha256_bytes(universe_bytes),
        executions_sha256: sha256_bytes(execution_bytes),
        correct_implementation: suite.correct_implementation.clone(),
        correct_accepted: true,
        contract_results,
        mutant_results,
        ast_nodes: suite
            .contracts
            .iter()
            .map(|contract| {
                expression_nodes(&contract.requires) + expression_nodes(&contract.ensures)
            })
            .sum(),
        carrier_values: universe
            .carriers
            .iter()
            .map(|carrier| carrier.cases.len() as u64)
            .sum(),
        identity: String::new(),
    };
    report.identity = report_identity(&report)?;
    Ok(report)
}

pub fn validate_specification_report(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    executions: &SpecificationExecutions,
    universe_bytes: &[u8],
    execution_bytes: &[u8],
    report: &SpecificationReport,
) -> Result<(), SpecificationError> {
    if report.schema != SPECIFICATION_REPORT_SCHEMA || report.identity != report_identity(report)? {
        return Err(invalid(
            "SPEC-IDENTITY-FORGED",
            "report identity is invalid",
        ));
    }
    let expected =
        derive_specification_report(universe, suite, executions, universe_bytes, execution_bytes)?;
    if report != &expected {
        return Err(invalid(
            "SPEC-REPORT-MISMATCH",
            "report differs from derivation",
        ));
    }
    Ok(())
}

pub fn execute_specification_corpus(
    root: &Path,
    corpus_dir: &Path,
    repetitions: usize,
) -> Result<SpecificationModelReport, SpecificationError> {
    if repetitions == 0 || repetitions > 100 {
        return Err(invalid("SPEC-REPETITIONS", "invalid repetition count"));
    }
    let (universe, suite, executions, attacks, universe_bytes, execution_bytes) =
        load_specification_corpus(root, corpus_dir)?;
    let report = derive_specification_report(
        &universe,
        &suite,
        &executions,
        &universe_bytes,
        &execution_bytes,
    )?;
    validate_specification_report(
        &universe,
        &suite,
        &executions,
        &universe_bytes,
        &execution_bytes,
        &report,
    )?;
    let mut repetition_report_identities = Vec::new();
    for _ in 0..repetitions {
        let repeated = derive_specification_report(
            &universe,
            &suite,
            &executions,
            &universe_bytes,
            &execution_bytes,
        )?;
        if repeated != report {
            return Err(invalid("SPEC-NONDETERMINISTIC", "report changed"));
        }
        repetition_report_identities.push(repeated.identity);
    }
    let attack_results = attacks
        .attacks
        .iter()
        .map(|attack| {
            evaluate_attack(
                &universe,
                &suite,
                &executions,
                &universe_bytes,
                &execution_bytes,
                attack,
            )
        })
        .collect();
    Ok(SpecificationModelReport {
        schema: SPECIFICATION_MODEL_REPORT_SCHEMA.to_owned(),
        specification_report: report,
        attacks: attack_results,
        repetition_report_identities,
    })
}

struct ContractEvaluation {
    reachable: u64,
    satisfied: u64,
    first_failure: Option<String>,
}

fn validate_source_records(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    executions: &SpecificationExecutions,
    universe_bytes: &[u8],
    execution_bytes: &[u8],
) -> Result<ExecutionTables, SpecificationError> {
    validate_universe(universe)?;
    validate_suite(universe, suite, universe_bytes)?;
    validate_executions(universe, suite, executions, execution_bytes)
}

fn validate_universe(universe: &SpecificationUniverse) -> Result<(), SpecificationError> {
    if universe.schema != SPECIFICATION_UNIVERSE_SCHEMA {
        return Err(invalid("SPEC-SCHEMA", "unexpected universe schema"));
    }
    strict_named(&universe.carriers, |carrier| carrier.id.as_str())?;
    strict_strings(&universe.required_mutants)?;
    strict_strings(&universe.required_roles)?;
    strict_named(&universe.variables, |variable| variable.name.as_str())?;
    for carrier in &universe.carriers {
        validate_id(&carrier.id)?;
        strict_named(&carrier.cases, |case| case.id.as_str())?;
        for case in &carrier.cases {
            validate_id(&case.id)?;
        }
    }
    let variables = variable_map(universe);
    for carrier in &universe.carriers {
        for case in &carrier.cases {
            if case.environment.is_empty() {
                return Err(invalid("SPEC-CARRIER-EMPTY", "case environment is empty"));
            }
            for (name, value) in &case.environment {
                let variable = variables
                    .get(name.as_str())
                    .ok_or_else(|| invalid("SPEC-VARIABLE-UNKNOWN", "case variable is unknown"))?;
                if variable.role != SpecificationVariableRole::Input
                    || !value_matches(value, variable.value_type)
                {
                    return Err(invalid("SPEC-TYPE-MISMATCH", "case value type is invalid"));
                }
            }
        }
    }
    Ok(())
}

fn validate_suite(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    universe_bytes: &[u8],
) -> Result<(), SpecificationError> {
    if suite.schema != SPECIFICATION_SUITE_SCHEMA
        || suite.universe_sha256 != sha256_bytes(universe_bytes)
    {
        return Err(invalid(
            "SPEC-SOURCE-DRIFT",
            "suite is not bound to universe bytes",
        ));
    }
    if suite.contracts.is_empty() {
        return Err(invalid("SPEC-OBLIGATION-EMPTY", "contract list is empty"));
    }
    let contract_ids: Vec<_> = suite
        .contracts
        .iter()
        .map(|contract| contract.id.as_str())
        .collect();
    if has_duplicates(&contract_ids) {
        return Err(invalid(
            "SPEC-CONTRACT-DUPLICATE",
            "contract ID is duplicated",
        ));
    }
    if contract_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("SPEC-NONCANONICAL", "contracts are not lexical"));
    }
    if suite
        .required_mutants
        .iter()
        .any(|mutant| !universe.required_mutants.contains(mutant))
    {
        return Err(invalid("SPEC-MUTANT-UNKNOWN", "required mutant is unknown"));
    }
    if suite.required_mutants != universe.required_mutants {
        return Err(invalid(
            "SPEC-MUTANT-COVERAGE",
            "required mutant set is incomplete",
        ));
    }
    let roles: BTreeSet<_> = suite
        .contracts
        .iter()
        .map(|contract| contract.role.as_str())
        .collect();
    if roles != universe.required_roles.iter().map(String::as_str).collect() {
        return Err(invalid(
            "SPEC-OBLIGATION-EMPTY",
            "required property role is missing",
        ));
    }
    let variables = variable_map(universe);
    let carriers = carrier_map(universe);
    for contract in &suite.contracts {
        validate_id(&contract.id)?;
        validate_id(&contract.role)?;
        let carrier = carriers
            .get(contract.carrier.as_str())
            .ok_or_else(|| invalid("SPEC-CARRIER-UNKNOWN", "contract carrier is unknown"))?;
        if contract.cases.is_empty() {
            return Err(invalid("SPEC-CARRIER-EMPTY", "contract carrier is empty"));
        }
        if has_duplicates(
            &contract
                .cases
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ) {
            return Err(invalid(
                "SPEC-CARRIER-DUPLICATE",
                "contract case is duplicated",
            ));
        }
        if contract.cases.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid(
                "SPEC-NONCANONICAL",
                "contract cases are not lexical",
            ));
        }
        let expected_cases: Vec<_> = carrier.cases.iter().map(|case| case.id.as_str()).collect();
        if contract
            .cases
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_cases
        {
            return Err(invalid(
                "SPEC-CARRIER-INCOMPLETE",
                "contract carrier is incomplete",
            ));
        }
        let requires_type = expression_type(&contract.requires, &variables)?;
        let ensures_type = expression_type(&contract.ensures, &variables)?;
        if requires_type != SpecificationType::Bool || ensures_type != SpecificationType::Bool {
            return Err(invalid(
                "SPEC-TYPE-MISMATCH",
                "contract expressions are not Boolean",
            ));
        }
        if expression_variables(&contract.requires).iter().any(|name| {
            variables
                .get(name.as_str())
                .is_some_and(|variable| variable.role == SpecificationVariableRole::Result)
        }) {
            return Err(invalid(
                "SPEC-RESULT-IN-PRECONDITION",
                "precondition references a result variable",
            ));
        }
        if matches!(
            contract.ensures,
            SpecificationExpression::Bool { value: true }
        ) {
            return Err(invalid(
                "SPEC-ENSURES-TAUTOLOGY",
                "postcondition is literal true",
            ));
        }
        if !expression_variables(&contract.ensures).iter().any(|name| {
            variables
                .get(name.as_str())
                .is_some_and(|variable| variable.role == SpecificationVariableRole::Result)
        }) {
            return Err(invalid(
                "SPEC-RESULT-UNBOUND",
                "postcondition does not constrain result",
            ));
        }
        if expression_is_vacuous_implication(&contract.ensures) {
            return Err(invalid(
                "SPEC-IMPLICATION-VACUOUS",
                "implication premise is false",
            ));
        }
        if expression_is_direct_contradiction(&contract.ensures) {
            return Err(invalid(
                "SPEC-ENSURES-UNSAT",
                "postcondition is inconsistent",
            ));
        }
        let reachable = carrier.cases.iter().try_fold(0_u64, |count, case| {
            evaluate_bool(&contract.requires, &case.environment)
                .map(|value| count + u64::from(value))
        })?;
        if reachable == 0 {
            return Err(invalid(
                "SPEC-REQUIRES-UNSAT",
                "precondition is unreachable",
            ));
        }
    }
    Ok(())
}

fn validate_executions(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    executions: &SpecificationExecutions,
    _execution_bytes: &[u8],
) -> Result<ExecutionTables, SpecificationError> {
    if executions.schema != SPECIFICATION_EXECUTIONS_SCHEMA
        || executions.row_fields
            != [
                "case",
                "result_ok",
                "decoded_value",
                "roundtrip_equal",
                "canonical_equal",
                "consumed",
                "steps",
            ]
    {
        return Err(invalid(
            "SPEC-EXECUTION-SCHEMA",
            "execution schema is invalid",
        ));
    }
    strict_named(&executions.implementations, |implementation| {
        implementation.id.as_str()
    })?;
    let expected_implementations: BTreeSet<_> = suite
        .required_mutants
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(suite.correct_implementation.as_str()))
        .collect();
    if executions
        .implementations
        .iter()
        .map(|implementation| implementation.id.as_str())
        .collect::<BTreeSet<_>>()
        != expected_implementations
    {
        return Err(invalid(
            "SPEC-MUTANT-UNKNOWN",
            "execution inventory is invalid",
        ));
    }
    let mut tables = BTreeMap::new();
    for implementation in &executions.implementations {
        let mut carrier_tables = BTreeMap::new();
        if implementation
            .rows
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != universe
                .carriers
                .iter()
                .map(|carrier| carrier.id.as_str())
                .collect()
        {
            return Err(invalid(
                "SPEC-EXECUTION-INCOMPLETE",
                "carrier rows are incomplete",
            ));
        }
        for carrier in &universe.carriers {
            let rows = implementation
                .rows
                .get(&carrier.id)
                .ok_or_else(|| invalid("SPEC-EXECUTION-INCOMPLETE", "carrier rows are missing"))?;
            if rows.len() != carrier.cases.len() {
                return Err(invalid(
                    "SPEC-EXECUTION-INCOMPLETE",
                    "case rows are incomplete",
                ));
            }
            let mut case_rows = BTreeMap::new();
            for (row, case) in rows.iter().zip(&carrier.cases) {
                let (case_id, output) = parse_execution_row(row)?;
                if case_id != case.id || case_rows.insert(case_id, output).is_some() {
                    return Err(invalid("SPEC-NONCANONICAL", "execution rows are not exact"));
                }
            }
            carrier_tables.insert(carrier.id.clone(), case_rows);
        }
        tables.insert(implementation.id.clone(), carrier_tables);
    }
    Ok(tables)
}

fn evaluate_contract(
    contract: &SpecificationContract,
    variables: &Variables<'_>,
    carriers: &Carriers<'_>,
    tables: &BTreeMap<String, BTreeMap<String, ExecutionOutput>>,
) -> Result<ContractEvaluation, SpecificationError> {
    let carrier = carriers
        .get(contract.carrier.as_str())
        .ok_or_else(|| invalid("SPEC-CARRIER-UNKNOWN", "carrier is unknown"))?;
    let rows = tables
        .get(&contract.carrier)
        .ok_or_else(|| invalid("SPEC-EXECUTION-INCOMPLETE", "carrier table is missing"))?;
    let mut reachable = 0;
    let mut satisfied = 0;
    let mut first_failure = None;
    for case in &carrier.cases {
        if !evaluate_bool(&contract.requires, &case.environment)? {
            continue;
        }
        reachable += 1;
        let output = rows
            .get(&case.id)
            .ok_or_else(|| invalid("SPEC-EXECUTION-INCOMPLETE", "case result is missing"))?;
        let environment = merge_environment(&case.environment, output, variables)?;
        if evaluate_bool(&contract.ensures, &environment)? {
            satisfied += 1;
        } else if first_failure.is_none() {
            first_failure = Some(case.id.clone());
        }
    }
    Ok(ContractEvaluation {
        reachable,
        satisfied,
        first_failure,
    })
}

fn evaluate_attack(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    executions: &SpecificationExecutions,
    universe_bytes: &[u8],
    execution_bytes: &[u8],
    attack: &SpecificationAttack,
) -> SpecificationAttackResult {
    let actual_code = run_attack(
        universe,
        suite,
        executions,
        universe_bytes,
        execution_bytes,
        &attack.action,
    )
    .err()
    .map_or_else(|| "ACCEPTED".to_owned(), |error| error.code.to_owned());
    SpecificationAttackResult {
        id: attack.id.clone(),
        expected_code: attack.code.clone(),
        exact: actual_code == attack.code,
        actual_code,
    }
}

fn run_attack(
    universe: &SpecificationUniverse,
    suite: &SpecificationSuite,
    executions: &SpecificationExecutions,
    universe_bytes: &[u8],
    execution_bytes: &[u8],
    action: &SpecificationAttackAction,
) -> Result<(), SpecificationError> {
    if let SpecificationAttackAction::ForgeReportIdentity { value } = action {
        let mut report = derive_specification_report(
            universe,
            suite,
            executions,
            universe_bytes,
            execution_bytes,
        )?;
        report.identity.clone_from(value);
        return validate_specification_report(
            universe,
            suite,
            executions,
            universe_bytes,
            execution_bytes,
            &report,
        );
    }
    let mut changed = suite.clone();
    match action {
        SpecificationAttackAction::ReplaceExpressionKind { contract, value } => {
            let target = contract_mut(&mut changed, contract)?;
            let mut expression = serde_json::to_value(&target.ensures)
                .map_err(|error| invalid("SPEC-ENCODE", error.to_string()))?;
            expression
                .as_object_mut()
                .ok_or_else(|| invalid("SPEC-CONSTRUCTOR-UNKNOWN", "expression is not an object"))?
                .insert("kind".to_owned(), Value::String(value.clone()));
            target.ensures = serde_json::from_value(expression).map_err(|_| {
                invalid(
                    "SPEC-CONSTRUCTOR-UNKNOWN",
                    "expression constructor is unknown",
                )
            })?;
        }
        SpecificationAttackAction::DuplicateContract { contract } => {
            let duplicate = contract_ref(&changed, contract)?.clone();
            changed.contracts.push(duplicate);
        }
        SpecificationAttackAction::DuplicateCase { contract, case } => {
            contract_mut(&mut changed, contract)?
                .cases
                .push(case.clone());
        }
        SpecificationAttackAction::EmptyCases { contract } => {
            contract_mut(&mut changed, contract)?.cases.clear();
        }
        SpecificationAttackAction::RemoveCase { contract, case } => {
            contract_mut(&mut changed, contract)?
                .cases
                .retain(|item| item != case);
        }
        SpecificationAttackAction::ReplaceEnsures { contract, value } => {
            contract_mut(&mut changed, contract)?.ensures = decode_expression(value.clone())?;
        }
        SpecificationAttackAction::ReplaceRequires { contract, value } => {
            contract_mut(&mut changed, contract)?.requires = decode_expression(value.clone())?;
        }
        SpecificationAttackAction::EmptyContracts => changed.contracts.clear(),
        SpecificationAttackAction::AddRequiredMutant { mutant } => {
            changed.required_mutants.push(mutant.clone());
            changed.required_mutants.sort();
        }
        SpecificationAttackAction::RemoveRequiredMutant { mutant } => {
            changed.required_mutants.retain(|item| item != mutant);
        }
        SpecificationAttackAction::ReplaceEnsuresMany { replacements } => {
            for replacement in replacements {
                contract_mut(&mut changed, &replacement.contract)?.ensures =
                    decode_expression(replacement.value.clone())?;
            }
        }
        SpecificationAttackAction::ReverseContracts => changed.contracts.reverse(),
        SpecificationAttackAction::ForgeReportIdentity { .. } => unreachable!(),
    }
    derive_specification_report(
        universe,
        &changed,
        executions,
        universe_bytes,
        execution_bytes,
    )
    .map(|_| ())
}

fn parse_execution_row(row: &[Value]) -> Result<(String, ExecutionOutput), SpecificationError> {
    if row.len() != 7 {
        return Err(invalid(
            "SPEC-EXECUTION-INCOMPLETE",
            "execution row width is invalid",
        ));
    }
    let case = row[0]
        .as_str()
        .ok_or_else(|| invalid("SPEC-TYPE-MISMATCH", "row case is not text"))?
        .to_owned();
    let boolean = |index: usize| {
        row[index]
            .as_bool()
            .ok_or_else(|| invalid("SPEC-TYPE-MISMATCH", "row Boolean is invalid"))
    };
    let integer = |index: usize| {
        row[index]
            .as_u64()
            .ok_or_else(|| invalid("SPEC-TYPE-MISMATCH", "row integer is invalid"))
    };
    Ok((
        case,
        ExecutionOutput {
            result_ok: boolean(1)?,
            decoded_value: integer(2)?,
            roundtrip_equal: boolean(3)?,
            canonical_equal: boolean(4)?,
            consumed: integer(5)?,
            steps: integer(6)?,
        },
    ))
}

fn merge_environment(
    input: &BTreeMap<String, SpecificationValue>,
    output: &ExecutionOutput,
    variables: &Variables<'_>,
) -> Result<BTreeMap<String, SpecificationValue>, SpecificationError> {
    let mut environment = input.clone();
    let result_values = [
        (
            "canonical_equal",
            SpecificationValue::Bool(output.canonical_equal),
        ),
        ("consumed", SpecificationValue::Int(output.consumed)),
        (
            "decoded_value",
            SpecificationValue::Int(output.decoded_value),
        ),
        ("result_ok", SpecificationValue::Bool(output.result_ok)),
        (
            "roundtrip_equal",
            SpecificationValue::Bool(output.roundtrip_equal),
        ),
        ("steps", SpecificationValue::Int(output.steps)),
    ];
    for (name, value) in result_values {
        let variable = variables
            .get(name)
            .ok_or_else(|| invalid("SPEC-VARIABLE-UNKNOWN", "result variable is unknown"))?;
        if variable.role != SpecificationVariableRole::Result
            || !value_matches(&value, variable.value_type)
        {
            return Err(invalid(
                "SPEC-TYPE-MISMATCH",
                "result variable type is invalid",
            ));
        }
        environment.insert(name.to_owned(), value);
    }
    Ok(environment)
}

fn expression_type(
    expression: &SpecificationExpression,
    variables: &Variables<'_>,
) -> Result<SpecificationType, SpecificationError> {
    match expression {
        SpecificationExpression::Bool { .. } => Ok(SpecificationType::Bool),
        SpecificationExpression::Int { .. } => Ok(SpecificationType::Int),
        SpecificationExpression::Var { name } => variables
            .get(name.as_str())
            .map(|variable| variable.value_type)
            .ok_or_else(|| invalid("SPEC-VARIABLE-UNKNOWN", "expression variable is unknown")),
        SpecificationExpression::Not { value } => {
            require_type(expression_type(value, variables)?, SpecificationType::Bool)?;
            Ok(SpecificationType::Bool)
        }
        SpecificationExpression::And { values } => {
            if values.len() < 2 {
                return Err(invalid(
                    "SPEC-CONSTRUCTOR-UNKNOWN",
                    "and requires two values",
                ));
            }
            for value in values {
                require_type(expression_type(value, variables)?, SpecificationType::Bool)?;
            }
            Ok(SpecificationType::Bool)
        }
        SpecificationExpression::Eq { left, right } => {
            let left_type = expression_type(left, variables)?;
            require_type(expression_type(right, variables)?, left_type)?;
            Ok(SpecificationType::Bool)
        }
        SpecificationExpression::Le { left, right }
        | SpecificationExpression::Add { left, right } => {
            require_type(expression_type(left, variables)?, SpecificationType::Int)?;
            require_type(expression_type(right, variables)?, SpecificationType::Int)?;
            Ok(match expression {
                SpecificationExpression::Le { .. } => SpecificationType::Bool,
                _ => SpecificationType::Int,
            })
        }
        SpecificationExpression::Implies {
            premise,
            conclusion,
        } => {
            require_type(
                expression_type(premise, variables)?,
                SpecificationType::Bool,
            )?;
            require_type(
                expression_type(conclusion, variables)?,
                SpecificationType::Bool,
            )?;
            Ok(SpecificationType::Bool)
        }
    }
}

fn evaluate_bool(
    expression: &SpecificationExpression,
    environment: &BTreeMap<String, SpecificationValue>,
) -> Result<bool, SpecificationError> {
    match evaluate(expression, environment)? {
        SpecificationValue::Bool(value) => Ok(value),
        SpecificationValue::Int(_) => Err(invalid("SPEC-TYPE-MISMATCH", "expected Boolean")),
    }
}

fn evaluate(
    expression: &SpecificationExpression,
    environment: &BTreeMap<String, SpecificationValue>,
) -> Result<SpecificationValue, SpecificationError> {
    match expression {
        SpecificationExpression::Bool { value } => Ok(SpecificationValue::Bool(*value)),
        SpecificationExpression::Int { value } => Ok(SpecificationValue::Int(*value)),
        SpecificationExpression::Var { name } => environment
            .get(name)
            .cloned()
            .ok_or_else(|| invalid("SPEC-VARIABLE-UNKNOWN", "case variable value is missing")),
        SpecificationExpression::Not { value } => Ok(SpecificationValue::Bool(!evaluate_bool(
            value,
            environment,
        )?)),
        SpecificationExpression::And { values } => Ok(SpecificationValue::Bool(
            values
                .iter()
                .map(|value| evaluate_bool(value, environment))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .all(|value| value),
        )),
        SpecificationExpression::Eq { left, right } => Ok(SpecificationValue::Bool(
            evaluate(left, environment)? == evaluate(right, environment)?,
        )),
        SpecificationExpression::Le { left, right } => Ok(SpecificationValue::Bool(
            evaluate_int(left, environment)? <= evaluate_int(right, environment)?,
        )),
        SpecificationExpression::Add { left, right } => Ok(SpecificationValue::Int(
            evaluate_int(left, environment)?
                .checked_add(evaluate_int(right, environment)?)
                .ok_or_else(|| invalid("SPEC-INTEGER-OVERFLOW", "integer addition overflowed"))?,
        )),
        SpecificationExpression::Implies {
            premise,
            conclusion,
        } => Ok(SpecificationValue::Bool(
            !evaluate_bool(premise, environment)? || evaluate_bool(conclusion, environment)?,
        )),
    }
}

fn evaluate_int(
    expression: &SpecificationExpression,
    environment: &BTreeMap<String, SpecificationValue>,
) -> Result<u64, SpecificationError> {
    match evaluate(expression, environment)? {
        SpecificationValue::Int(value) => Ok(value),
        SpecificationValue::Bool(_) => Err(invalid("SPEC-TYPE-MISMATCH", "expected integer")),
    }
}

fn expression_variables(expression: &SpecificationExpression) -> BTreeSet<String> {
    let mut variables = BTreeSet::new();
    collect_expression_variables(expression, &mut variables);
    variables
}

fn collect_expression_variables(
    expression: &SpecificationExpression,
    variables: &mut BTreeSet<String>,
) {
    match expression {
        SpecificationExpression::Var { name } => {
            variables.insert(name.clone());
        }
        SpecificationExpression::Not { value } => collect_expression_variables(value, variables),
        SpecificationExpression::And { values } => {
            for value in values {
                collect_expression_variables(value, variables);
            }
        }
        SpecificationExpression::Eq { left, right }
        | SpecificationExpression::Le { left, right }
        | SpecificationExpression::Add { left, right } => {
            collect_expression_variables(left, variables);
            collect_expression_variables(right, variables);
        }
        SpecificationExpression::Implies {
            premise,
            conclusion,
        } => {
            collect_expression_variables(premise, variables);
            collect_expression_variables(conclusion, variables);
        }
        SpecificationExpression::Bool { .. } | SpecificationExpression::Int { .. } => {}
    }
}

fn expression_nodes(expression: &SpecificationExpression) -> u64 {
    1 + match expression {
        SpecificationExpression::Not { value } => expression_nodes(value),
        SpecificationExpression::And { values } => values.iter().map(expression_nodes).sum(),
        SpecificationExpression::Eq { left, right }
        | SpecificationExpression::Le { left, right }
        | SpecificationExpression::Add { left, right } => {
            expression_nodes(left) + expression_nodes(right)
        }
        SpecificationExpression::Implies {
            premise,
            conclusion,
        } => expression_nodes(premise) + expression_nodes(conclusion),
        SpecificationExpression::Bool { .. }
        | SpecificationExpression::Int { .. }
        | SpecificationExpression::Var { .. } => 0,
    }
}

fn expression_is_vacuous_implication(expression: &SpecificationExpression) -> bool {
    matches!(
        expression,
        SpecificationExpression::Implies { premise, .. }
            if matches!(premise.as_ref(), SpecificationExpression::Bool { value: false })
    )
}

fn expression_is_direct_contradiction(expression: &SpecificationExpression) -> bool {
    let SpecificationExpression::And { values } = expression else {
        return false;
    };
    values.iter().any(|candidate| {
        values.iter().any(|other| match other {
            SpecificationExpression::Not { value } => value.as_ref() == candidate,
            _ => false,
        })
    })
}

fn decode_expression(value: Value) -> Result<SpecificationExpression, SpecificationError> {
    serde_json::from_value(value)
        .map_err(|_| invalid("SPEC-CONSTRUCTOR-UNKNOWN", "expression cannot be decoded"))
}

fn report_identity(report: &SpecificationReport) -> Result<String, SpecificationError> {
    let mut material =
        serde_json::to_value(report).map_err(|error| invalid("SPEC-ENCODE", error.to_string()))?;
    material
        .as_object_mut()
        .expect("serialized specification report is an object")
        .remove("identity");
    Ok(domain_hash(
        SPECIFICATION_REPORT_SCHEMA,
        &canonical_json(&material).map_err(|error| invalid("SPEC-ENCODE", error.to_string()))?,
    ))
}

fn contract_ref<'a>(
    suite: &'a SpecificationSuite,
    id: &str,
) -> Result<&'a SpecificationContract, SpecificationError> {
    suite
        .contracts
        .iter()
        .find(|contract| contract.id == id)
        .ok_or_else(|| invalid("SPEC-CONTRACT-UNKNOWN", "contract is missing"))
}

fn contract_mut<'a>(
    suite: &'a mut SpecificationSuite,
    id: &str,
) -> Result<&'a mut SpecificationContract, SpecificationError> {
    suite
        .contracts
        .iter_mut()
        .find(|contract| contract.id == id)
        .ok_or_else(|| invalid("SPEC-CONTRACT-UNKNOWN", "contract is missing"))
}

fn variable_map(universe: &SpecificationUniverse) -> Variables<'_> {
    universe
        .variables
        .iter()
        .map(|variable| (variable.name.as_str(), variable))
        .collect()
}

fn carrier_map(universe: &SpecificationUniverse) -> Carriers<'_> {
    universe
        .carriers
        .iter()
        .map(|carrier| (carrier.id.as_str(), carrier))
        .collect()
}

fn require_type(
    actual: SpecificationType,
    expected: SpecificationType,
) -> Result<(), SpecificationError> {
    if actual != expected {
        return Err(invalid("SPEC-TYPE-MISMATCH", "expression types differ"));
    }
    Ok(())
}

fn value_matches(value: &SpecificationValue, expected: SpecificationType) -> bool {
    matches!(
        (value, expected),
        (SpecificationValue::Bool(_), SpecificationType::Bool)
            | (SpecificationValue::Int(_), SpecificationType::Int)
    )
}

fn strict_named<T>(values: &[T], name: impl Fn(&T) -> &str) -> Result<(), SpecificationError> {
    if values.is_empty()
        || values
            .windows(2)
            .any(|pair| name(&pair[0]) >= name(&pair[1]))
    {
        return Err(invalid(
            "SPEC-NONCANONICAL",
            "named records are not a strict lexical set",
        ));
    }
    Ok(())
}

fn strict_strings(values: &[String]) -> Result<(), SpecificationError> {
    if values.is_empty() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "SPEC-NONCANONICAL",
            "strings are not a strict lexical set",
        ));
    }
    for value in values {
        validate_id(value)?;
    }
    Ok(())
}

fn has_duplicates(values: &[&str]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
}

fn validate_id(value: &str) -> Result<(), SpecificationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid("SPEC-ID", "identifier is invalid"));
    }
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, SpecificationError> {
    serde_json::from_slice(bytes).map_err(|error| invalid("SPEC-DECODE", error.to_string()))
}

fn read(root: &Path, path: &Path) -> Result<Vec<u8>, SpecificationError> {
    let full = if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    };
    fs::read(&full).map_err(|error| invalid("SPEC-IO", format!("{}: {error}", full.display())))
}

fn invalid(code: &'static str, message: impl Into<String>) -> SpecificationError {
    SpecificationError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from("docs/experiments/0014-specification-falsifiers/corpus")
    }

    #[test]
    fn accepts_correct_relation_and_kills_every_mutant() {
        let report = execute_specification_corpus(&root(), &corpus(), 10).unwrap();
        assert!(report.specification_report.correct_accepted);
        assert_eq!(report.specification_report.contract_results.len(), 5);
        assert_eq!(report.specification_report.mutant_results.len(), 6);
        assert!(
            report
                .specification_report
                .mutant_results
                .iter()
                .all(|result| result.killed)
        );
        assert_eq!(
            report
                .specification_report
                .contract_results
                .iter()
                .map(|result| result.satisfied_obligations)
                .sum::<u64>(),
            34
        );
    }

    #[test]
    fn rejects_all_frozen_attacks_exactly() {
        let report = execute_specification_corpus(&root(), &corpus(), 10).unwrap();
        assert_eq!(report.attacks.len(), 20);
        assert!(report.attacks.iter().all(|attack| attack.exact));
    }
}
