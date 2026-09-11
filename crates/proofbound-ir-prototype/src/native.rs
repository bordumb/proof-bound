use std::{
    collections::BTreeSet,
    env, fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};

pub const NATIVE_AST_SCHEMA: &str = "proofbound-research-native-ast/1";
pub const NATIVE_CERTIFICATE_SCHEMA: &str = "proofbound-native-certificate/1";
pub const NATIVE_REPORT_SCHEMA: &str = "proofbound-research-native-report/1";

const TOOLCHAIN_SCHEMA: &str = "proofbound-research-native-toolchain/1";
const ATTACKS_SCHEMA: &str = "proofbound-research-native-attacks/1";
const ARTIFACT_DOMAIN: &str = "proofbound-native-bytecode/1";

const CONTRACT_IDS: [&str; 5] = [
    "round-trip",
    "malformed-rejection",
    "canonicality",
    "exact-consumption",
    "bounded-termination",
];
const MUTANT_IDS: [&str; 6] = [
    "accept-noncanonical",
    "accept-trailing",
    "always-error",
    "always-success",
    "ignore-length",
    "payload-substitution",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAst {
    pub schema: String,
    pub module: String,
    pub value_min: u8,
    pub value_max: u8,
    pub encode_prefix: u8,
    pub decode_length: u8,
    pub decode_prefix: u8,
    pub payload_max: u8,
    pub fallback_error: bool,
    pub pure_functions: Vec<String>,
    pub specifications: Vec<String>,
    pub alphabet_min: u8,
    pub alphabet_max: u8,
    pub input_length_min: u8,
    pub input_length_max: u8,
    pub termination_slack: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeValueRow {
    pub value: u8,
    pub encoded_hex: String,
    pub decode_ok: bool,
    pub decoded_value: Option<u8>,
    pub consumed: u64,
    pub steps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputRow {
    pub id: String,
    pub input_hex: String,
    pub decode_ok: bool,
    pub decoded_value: Option<u8>,
    pub reencoded_hex: Option<String>,
    pub consumed: u64,
    pub steps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeScope {
    pub value_type: String,
    pub value_cardinality: u64,
    pub value_universal: bool,
    pub input_alphabet: Vec<u8>,
    pub maximum_input_length: u8,
    pub input_exhaustive: bool,
    pub input_unbounded: bool,
    pub compiler_correspondence: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSolverReceipt {
    pub program: String,
    pub argv: Vec<String>,
    pub executable_sha256: String,
    pub version: String,
    pub input_sha256: String,
    pub results: Vec<String>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMutantResult {
    pub id: String,
    pub killed: bool,
    pub first_counterexample: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCertificate {
    pub schema: String,
    pub source_sha256: String,
    pub artifact_sha256: String,
    pub artifact_identity: String,
    pub contract_ids: Vec<String>,
    pub scope: NativeScope,
    pub solver: NativeSolverReceipt,
    pub value_rows: Vec<NativeValueRow>,
    pub input_rows: Vec<NativeInputRow>,
    pub semantic_mutants: Vec<NativeMutantResult>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttackCorpus {
    pub schema: String,
    pub attacks: Vec<NativeAttack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttack {
    pub id: String,
    pub class: String,
    pub action: String,
    pub expected: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAssuranceSummary {
    pub round_trip: String,
    pub input_properties: String,
    pub examples: String,
    pub artifact_correspondence: String,
    pub artifact_proved: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReport {
    pub schema: String,
    pub source_sha256: String,
    pub ast_identity: String,
    pub artifact_hex: String,
    pub artifact_sha256: String,
    pub artifact_identity: String,
    pub smt_sha256: String,
    pub certificate: NativeCertificate,
    pub attacks: Vec<NativeAttackResult>,
    pub assurance: NativeAssuranceSummary,
    pub repetition_identities: Vec<String>,
    pub identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NativeError {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeToolchain {
    schema: String,
    solver: SolverConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SolverConfig {
    program: String,
    argv: Vec<String>,
    version_argv: Vec<String>,
    expected_version: String,
    expected_results: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecodeResult {
    value: Option<u8>,
    consumed: u64,
    steps: u64,
}

fn invalid(code: &'static str, message: impl Into<String>) -> NativeError {
    NativeError {
        code,
        message: message.into(),
    }
}

pub fn parse_native_source(source: &[u8]) -> Result<NativeAst, NativeError> {
    let text =
        std::str::from_utf8(source).map_err(|error| invalid("NATIVE-SYNTAX", error.to_string()))?;
    if text.contains('\r') || !text.ends_with('\n') {
        return Err(invalid(
            "NATIVE-NONCANONICAL",
            "source must be LF-terminated",
        ));
    }
    let lines = text.lines().collect::<Vec<_>>();
    if lines.iter().any(|line| line.is_empty()) {
        return Err(invalid("NATIVE-NONCANONICAL", "blank source line"));
    }
    if lines.iter().any(|line| line.starts_with("loop ")) {
        return Err(invalid("NATIVE-NONTOTAL", "loop construct is not total"));
    }
    if lines.iter().any(|line| line.starts_with("foreign ")) {
        return Err(invalid("NATIVE-SYNTAX", "unknown declaration"));
    }
    if lines
        .iter()
        .filter(|line| line.starts_with("module "))
        .count()
        != 1
        || lines
            .iter()
            .filter(|line| line.starts_with("fn encode("))
            .count()
            > 1
        || lines
            .iter()
            .filter(|line| line.starts_with("fn decode("))
            .count()
            > 1
    {
        return Err(invalid("NATIVE-DUPLICATE", "duplicate declaration"));
    }
    if lines.len() != 13 {
        let specifications = lines
            .iter()
            .filter(|line| line.starts_with("spec "))
            .count();
        if specifications != 5 {
            return Err(invalid("NATIVE-SPEC-MISSING", "specification set differs"));
        }
        return Err(invalid("NATIVE-SYNTAX", "declaration count differs"));
    }
    let module = lines[0]
        .strip_prefix("module ")
        .and_then(|value| value.strip_suffix(';'))
        .ok_or_else(|| invalid("NATIVE-SYNTAX", "module declaration differs"))?
        .to_owned();
    validate_module_id(&module)?;
    let (value_min, value_max) = parse_pair(lines[1], "type Value = range(", ");")?;
    if lines[2] != "type Decode = result(Value, Error);" {
        return Err(invalid("NATIVE-TYPE", "Decode result type differs"));
    }
    let encode_effect = parse_effect(lines[3], "encode")?;
    let decode_effect = parse_effect(lines[4], "decode")?;
    if encode_effect != "pure" || decode_effect != "pure" {
        return Err(invalid("NATIVE-EFFECT", "native function is not pure"));
    }
    let encode_prefix = parse_encode(lines[5])?;
    let (decode_length, decode_prefix, payload_max, fallback_error) = parse_decode(lines[6])?;
    let expected_specs = expected_spec_lines(decode_length);
    let actual_specs = lines[7..12]
        .iter()
        .map(|line| (*line).to_owned())
        .collect::<Vec<_>>();
    if actual_specs.len() != expected_specs.len() {
        return Err(invalid(
            "NATIVE-SPEC-MISSING",
            "specification count differs",
        ));
    }
    if actual_specs != expected_specs {
        return Err(invalid(
            "NATIVE-SPEC-BINDING",
            "specification expression differs",
        ));
    }
    let (alphabet_min, alphabet_max, input_length_min, input_length_max) = parse_bound(lines[12])?;
    if value_min != 0 || value_max != 3 || payload_max != value_max || decode_length != 2 {
        return Err(invalid(
            "NATIVE-TYPE",
            "finite type or decoder bound differs",
        ));
    }
    if encode_prefix != decode_prefix {
        return Err(invalid(
            "NATIVE-SPEC-BINDING",
            "encoder and decoder prefixes differ",
        ));
    }
    if !fallback_error {
        return Err(invalid("NATIVE-NONTOTAL", "decoder has no Error fallback"));
    }
    if (
        alphabet_min,
        alphabet_max,
        input_length_min,
        input_length_max,
    ) != (0, 4, 0, 3)
    {
        return Err(invalid("NATIVE-TYPE", "bounded input carrier differs"));
    }
    let ast = NativeAst {
        schema: NATIVE_AST_SCHEMA.to_owned(),
        module,
        value_min,
        value_max,
        encode_prefix,
        decode_length,
        decode_prefix,
        payload_max,
        fallback_error,
        pure_functions: vec!["decode".to_owned(), "encode".to_owned()],
        specifications: CONTRACT_IDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        alphabet_min,
        alphabet_max,
        input_length_min,
        input_length_max,
        termination_slack: 4,
    };
    if format_native_source(&ast).as_bytes() != source {
        return Err(invalid("NATIVE-NONCANONICAL", "source encoding differs"));
    }
    Ok(ast)
}

pub fn compile_native_artifact(ast: &NativeAst) -> Vec<u8> {
    vec![
        b'P',
        b'B',
        b'V',
        b'M',
        1,
        4,
        11,
        0x10,
        ast.encode_prefix,
        0x11,
        0xff,
        0x20,
        ast.decode_length,
        0x21,
        0,
        ast.decode_prefix,
        0x22,
        1,
        ast.payload_max,
        0x23,
        1,
        0xfe,
    ]
}

pub fn validate_native_artifact(ast: &NativeAst, artifact: &[u8]) -> Result<(), NativeError> {
    if artifact.len() < 4 {
        return Err(invalid(
            "NATIVE-ARTIFACT-TRUNCATED",
            "artifact header is truncated",
        ));
    }
    if &artifact[..4] != b"PBVM" {
        return Err(invalid("NATIVE-ARTIFACT-MAGIC", "artifact magic differs"));
    }
    if artifact.len() < 5 {
        return Err(invalid(
            "NATIVE-ARTIFACT-TRUNCATED",
            "artifact version is absent",
        ));
    }
    if artifact[4] != 1 {
        return Err(invalid(
            "NATIVE-ARTIFACT-VERSION",
            "artifact version differs",
        ));
    }
    if artifact.len() < 7 {
        return Err(invalid(
            "NATIVE-ARTIFACT-TRUNCATED",
            "section lengths are absent",
        ));
    }
    if (artifact[5], artifact[6]) != (4, 11) {
        return Err(invalid(
            "NATIVE-ARTIFACT-ORDER",
            "section order or size differs",
        ));
    }
    if artifact.len() < 22 {
        return Err(invalid(
            "NATIVE-ARTIFACT-TRUNCATED",
            "artifact body is truncated",
        ));
    }
    if artifact.len() > 22 {
        return Err(invalid(
            "NATIVE-ARTIFACT-TRAILING",
            "artifact has trailing bytes",
        ));
    }
    let opcode_positions = [7, 9, 10, 11, 13, 16, 19, 21];
    let opcodes = [0x10, 0x11, 0xff, 0x20, 0x21, 0x22, 0x23, 0xfe];
    if opcode_positions
        .iter()
        .zip(opcodes)
        .any(|(position, opcode)| artifact[*position] != opcode)
    {
        return Err(invalid("NATIVE-ARTIFACT-OPCODE", "artifact opcode differs"));
    }
    if artifact[8] != ast.encode_prefix
        || artifact[12] != ast.decode_length
        || artifact[14] != 0
        || artifact[15] != ast.decode_prefix
        || artifact[17] != 1
        || artifact[18] != ast.payload_max
        || artifact[20] != 1
    {
        return Err(invalid(
            "NATIVE-ARTIFACT-SEMANTICS",
            "artifact immediate differs",
        ));
    }
    Ok(())
}

pub fn generate_native_smt(ast: &NativeAst) -> String {
    format!(
        "(set-logic QF_LIA)\n; VC round-trip\n(push)\n(declare-const v Int)\n(assert (and (<= {} v) (<= v {})))\n(assert (not (= v v)))\n(check-sat)\n(pop)\n; VC malformed-rejection\n(push)\n(declare-const len1 Int)\n(declare-const b0 Int)\n(declare-const b1 Int)\n(assert (and (<= 0 len1) (<= len1 {}) (<= 0 b0) (<= b0 {}) (<= 0 b1) (<= b1 {})))\n(assert (not (and (= len1 {}) (= b0 {}) (<= b1 {}))))\n(assert (and (= len1 {}) (= b0 {}) (<= b1 {})))\n(check-sat)\n(pop)\n; VC canonicality\n(push)\n(declare-const c0 Int)\n(declare-const c1 Int)\n(assert (and (= c0 {}) (<= 0 c1) (<= c1 {})))\n(assert (not (and (= c0 {}) (= c1 c1))))\n(check-sat)\n(pop)\n; VC exact-consumption\n(push)\n(declare-const consumed Int)\n(assert (= consumed {}))\n(assert (not (= consumed {})))\n(check-sat)\n(pop)\n; VC bounded-termination\n(push)\n(declare-const steps Int)\n(declare-const input_len Int)\n(assert (and (<= 0 input_len) (<= input_len {}) (<= steps (+ input_len {}))))\n(assert (> steps (+ input_len {})))\n(check-sat)\n(pop)\n",
        ast.value_min,
        ast.value_max,
        ast.input_length_max,
        ast.alphabet_max,
        ast.alphabet_max,
        ast.decode_length,
        ast.decode_prefix,
        ast.payload_max,
        ast.decode_length,
        ast.decode_prefix,
        ast.payload_max,
        ast.decode_prefix,
        ast.payload_max,
        ast.encode_prefix,
        ast.decode_length,
        ast.decode_length,
        ast.input_length_max,
        ast.termination_slack,
        ast.termination_slack,
    )
}

pub fn execute_native_corpus(
    root: &Path,
    corpus_dir: &Path,
    repetitions: usize,
) -> Result<NativeReport, NativeError> {
    if repetitions != 10 {
        return Err(invalid("NATIVE-SMT-RESULT", "repetition count differs"));
    }
    let source = read(root, &corpus_dir.join("parser.pb"))?;
    let ast = parse_native_source(&source)?;
    let smt = generate_native_smt(&ast);
    let toolchain: NativeToolchain = decode_file(root, &corpus_dir.join("toolchain.json"))?;
    let solver = run_solver(&toolchain, smt.as_bytes())?;
    validate_smt(&smt, &solver.results)?;
    let attacks: NativeAttackCorpus = decode_file(root, &corpus_dir.join("attacks.json"))?;
    validate_attacks(&attacks)?;
    let mut reports = (0..repetitions)
        .map(|_| derive_native_report_once(&source, solver.clone(), &attacks))
        .collect::<Result<Vec<_>, _>>()?;
    let identities = reports
        .iter()
        .map(|report| report.identity.clone())
        .collect::<Vec<_>>();
    if identities.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(invalid(
            "NATIVE-CERT-IDENTITY",
            "repeated native executions differ",
        ));
    }
    let mut report = reports.remove(0);
    report.repetition_identities = identities;
    validate_native_report(&source, &attacks, &report)?;
    Ok(report)
}

pub fn validate_native_report(
    source: &[u8],
    attacks: &NativeAttackCorpus,
    report: &NativeReport,
) -> Result<(), NativeError> {
    if report.schema != NATIVE_REPORT_SCHEMA {
        return Err(invalid("NATIVE-CERT-SCHEMA", "report schema differs"));
    }
    let ast = parse_native_source(source)?;
    let artifact = compile_native_artifact(&ast);
    let smt = generate_native_smt(&ast);
    if report.source_sha256 != sha256_bytes(source)
        || report.ast_identity != hash_serialized(NATIVE_AST_SCHEMA, &ast)?
        || report.artifact_hex != encode_hex(&artifact)
        || report.artifact_sha256 != sha256_bytes(&artifact)
        || report.artifact_identity != domain_hash(ARTIFACT_DOMAIN, &artifact)
        || report.smt_sha256 != sha256_bytes(smt.as_bytes())
    {
        return Err(invalid(
            "NATIVE-CERT-IDENTITY",
            "report source, artifact, or SMT identity differs",
        ));
    }
    validate_native_certificate(source, &ast, &artifact, &report.certificate)?;
    validate_attacks(attacks)?;
    let expected_attacks = attacks
        .attacks
        .iter()
        .map(|attack| execute_attack(source, &ast, &artifact, &smt, &report.certificate, attack))
        .collect::<Result<Vec<_>, _>>()?;
    if report.attacks != expected_attacks || report.attacks.iter().any(|result| !result.exact) {
        return Err(invalid("NATIVE-CERT-TRACE", "report attacks differ"));
    }
    let expected_assurance = native_assurance_summary();
    if report.assurance != expected_assurance || report.assurance.artifact_proved {
        return Err(invalid(
            "NATIVE-CERT-SCOPE",
            "report assurance scope differs",
        ));
    }
    let identity = native_report_identity(report)?;
    if report.identity != identity
        || report.repetition_identities.len() != 10
        || report
            .repetition_identities
            .iter()
            .any(|candidate| candidate != &identity)
    {
        return Err(invalid(
            "NATIVE-CERT-IDENTITY",
            "report repetition identity differs",
        ));
    }
    Ok(())
}

fn derive_native_report_once(
    source: &[u8],
    solver: NativeSolverReceipt,
    attacks: &NativeAttackCorpus,
) -> Result<NativeReport, NativeError> {
    let ast = parse_native_source(source)?;
    let artifact = compile_native_artifact(&ast);
    validate_native_artifact(&ast, &artifact)?;
    let smt = generate_native_smt(&ast);
    validate_smt(&smt, &solver.results)?;
    let certificate = derive_native_certificate(source, &ast, &artifact, solver)?;
    validate_native_certificate(source, &ast, &artifact, &certificate)?;
    let attack_results = attacks
        .attacks
        .iter()
        .map(|attack| execute_attack(source, &ast, &artifact, &smt, &certificate, attack))
        .collect::<Result<Vec<_>, _>>()?;
    let mut report = NativeReport {
        schema: NATIVE_REPORT_SCHEMA.to_owned(),
        source_sha256: sha256_bytes(source),
        ast_identity: hash_serialized(NATIVE_AST_SCHEMA, &ast)?,
        artifact_hex: encode_hex(&artifact),
        artifact_sha256: sha256_bytes(&artifact),
        artifact_identity: domain_hash(ARTIFACT_DOMAIN, &artifact),
        smt_sha256: sha256_bytes(smt.as_bytes()),
        certificate,
        attacks: attack_results,
        assurance: native_assurance_summary(),
        repetition_identities: Vec::new(),
        identity: String::new(),
    };
    report.identity = native_report_identity(&report)?;
    Ok(report)
}

fn native_assurance_summary() -> NativeAssuranceSummary {
    NativeAssuranceSummary {
        round_trip: "universal-over-declared-u2".to_owned(),
        input_properties: "bounded-exhaustive-alphabet-0-4-length-0-3".to_owned(),
        examples: "tested-only".to_owned(),
        artifact_correspondence: "independent-dual-compilation-assumption-bound".to_owned(),
        artifact_proved: false,
    }
}

pub fn derive_native_certificate(
    source: &[u8],
    ast: &NativeAst,
    artifact: &[u8],
    solver: NativeSolverReceipt,
) -> Result<NativeCertificate, NativeError> {
    validate_native_artifact(ast, artifact)?;
    let value_rows = (ast.value_min..=ast.value_max)
        .map(|value| {
            let encoded = execute_encode(artifact, value)?;
            let decoded = execute_decode(artifact, &encoded)?;
            Ok(NativeValueRow {
                value,
                encoded_hex: encode_hex(&encoded),
                decode_ok: decoded.value.is_some(),
                decoded_value: decoded.value,
                consumed: decoded.consumed,
                steps: decoded.steps,
            })
        })
        .collect::<Result<Vec<_>, NativeError>>()?;
    let inputs = enumerate_inputs(ast.alphabet_min, ast.alphabet_max, ast.input_length_max);
    let input_rows = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let decoded = execute_decode(artifact, input)?;
            let reencoded = decoded
                .value
                .map(|value| execute_encode(artifact, value))
                .transpose()?;
            Ok(NativeInputRow {
                id: format!("input:{index:03}"),
                input_hex: encode_hex(input),
                decode_ok: decoded.value.is_some(),
                decoded_value: decoded.value,
                reencoded_hex: reencoded.as_deref().map(encode_hex),
                consumed: decoded.consumed,
                steps: decoded.steps,
            })
        })
        .collect::<Result<Vec<_>, NativeError>>()?;
    let semantic_mutants = MUTANT_IDS
        .iter()
        .map(|identifier| evaluate_mutant(ast, identifier))
        .collect::<Result<Vec<_>, _>>()?;
    let mut certificate = NativeCertificate {
        schema: NATIVE_CERTIFICATE_SCHEMA.to_owned(),
        source_sha256: sha256_bytes(source),
        artifact_sha256: sha256_bytes(artifact),
        artifact_identity: domain_hash(ARTIFACT_DOMAIN, artifact),
        contract_ids: CONTRACT_IDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        scope: NativeScope {
            value_type: "Value".to_owned(),
            value_cardinality: 4,
            value_universal: true,
            input_alphabet: (ast.alphabet_min..=ast.alphabet_max).collect(),
            maximum_input_length: ast.input_length_max,
            input_exhaustive: true,
            input_unbounded: false,
            compiler_correspondence: "independent-dual-compilation".to_owned(),
        },
        solver,
        value_rows,
        input_rows,
        semantic_mutants,
        identity: String::new(),
    };
    certificate.identity = native_certificate_identity(&certificate)?;
    Ok(certificate)
}

pub fn validate_native_certificate(
    source: &[u8],
    ast: &NativeAst,
    artifact: &[u8],
    certificate: &NativeCertificate,
) -> Result<(), NativeError> {
    if certificate.schema != NATIVE_CERTIFICATE_SCHEMA {
        return Err(invalid("NATIVE-CERT-SCHEMA", "certificate schema differs"));
    }
    if certificate.source_sha256 != sha256_bytes(source) {
        return Err(invalid("NATIVE-CERT-SOURCE", "source identity differs"));
    }
    if certificate.artifact_sha256 != sha256_bytes(artifact)
        || certificate.artifact_identity != domain_hash(ARTIFACT_DOMAIN, artifact)
    {
        return Err(invalid("NATIVE-CERT-ARTIFACT", "artifact identity differs"));
    }
    if certificate.scope.input_unbounded
        || certificate.scope.value_type != "Value"
        || certificate.scope.value_cardinality != 4
        || !certificate.scope.value_universal
        || !certificate.scope.input_exhaustive
        || certificate.scope.input_alphabet != (0..=4).collect::<Vec<_>>()
        || certificate.scope.maximum_input_length != 3
        || certificate.scope.compiler_correspondence != "independent-dual-compilation"
    {
        return Err(invalid("NATIVE-CERT-SCOPE", "certificate scope differs"));
    }
    if certificate.contract_ids != CONTRACT_IDS {
        return Err(invalid("NATIVE-CERT-INCOMPLETE", "contract set differs"));
    }
    let value_ids = certificate
        .value_rows
        .iter()
        .map(|row| row.value)
        .collect::<Vec<_>>();
    let input_ids = certificate
        .input_rows
        .iter()
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    if has_duplicates(&value_ids) || has_duplicates(&input_ids) {
        return Err(invalid(
            "NATIVE-CERT-DUPLICATE",
            "certificate row is duplicated",
        ));
    }
    if value_ids != vec![0, 1, 2, 3] || certificate.input_rows.len() != 156 {
        return Err(invalid(
            "NATIVE-CERT-INCOMPLETE",
            "certificate carrier is incomplete",
        ));
    }
    let expected = derive_native_certificate(source, ast, artifact, certificate.solver.clone())?;
    if certificate.value_rows != expected.value_rows
        || certificate.input_rows != expected.input_rows
        || certificate.semantic_mutants != expected.semantic_mutants
    {
        return Err(invalid("NATIVE-CERT-TRACE", "certificate trace differs"));
    }
    if certificate.identity != native_certificate_identity(certificate)? {
        return Err(invalid(
            "NATIVE-CERT-IDENTITY",
            "certificate identity differs",
        ));
    }
    Ok(())
}

fn execute_encode(artifact: &[u8], value: u8) -> Result<Vec<u8>, NativeError> {
    if value > artifact[18] {
        return Err(invalid("NATIVE-TYPE", "value is outside finite type"));
    }
    Ok(vec![artifact[8], value])
}

fn execute_decode(artifact: &[u8], input: &[u8]) -> Result<DecodeResult, NativeError> {
    if input.len() != usize::from(artifact[12]) {
        return Ok(DecodeResult {
            value: None,
            consumed: input.len() as u64,
            steps: 1,
        });
    }
    if input[usize::from(artifact[14])] != artifact[15] {
        return Ok(DecodeResult {
            value: None,
            consumed: input.len() as u64,
            steps: 2,
        });
    }
    if input[usize::from(artifact[17])] > artifact[18] {
        return Ok(DecodeResult {
            value: None,
            consumed: input.len() as u64,
            steps: 3,
        });
    }
    Ok(DecodeResult {
        value: Some(input[usize::from(artifact[20])]),
        consumed: input.len() as u64,
        steps: 4,
    })
}

fn evaluate_mutant(ast: &NativeAst, identifier: &str) -> Result<NativeMutantResult, NativeError> {
    let values = ast.value_min..=ast.value_max;
    for value in values {
        let input = vec![ast.encode_prefix, value];
        let result = mutant_decode(ast, identifier, &input);
        if result != Some(value) {
            return Ok(NativeMutantResult {
                id: identifier.to_owned(),
                killed: true,
                first_counterexample: format!("value:{value}"),
            });
        }
    }
    for (index, input) in enumerate_inputs(0, 4, 3).iter().enumerate() {
        let result = mutant_decode(ast, identifier, input);
        let correct =
            input.len() == 2 && input[0] == ast.decode_prefix && input[1] <= ast.payload_max;
        if result.is_some() != correct
            || result.is_some_and(|value| vec![ast.encode_prefix, value] != *input)
        {
            return Ok(NativeMutantResult {
                id: identifier.to_owned(),
                killed: true,
                first_counterexample: format!("input:{index:03}"),
            });
        }
    }
    Err(invalid("NATIVE-CERT-TRACE", "semantic mutant survived"))
}

fn mutant_decode(ast: &NativeAst, identifier: &str, input: &[u8]) -> Option<u8> {
    match identifier {
        "always-error" => None,
        "always-success" => Some(input.get(1).copied().unwrap_or(0).min(3)),
        "accept-noncanonical" if input == [0] => Some(0),
        "accept-trailing"
            if input.len() == 3 && input[0] == ast.decode_prefix && input[1] <= ast.payload_max =>
        {
            Some(input[1])
        }
        "ignore-length" if input.first() == Some(&ast.decode_prefix) => {
            Some(input.get(1).copied().unwrap_or(0).min(3))
        }
        "payload-substitution"
            if input.len() == 2 && input[0] == ast.decode_prefix && input[1] <= ast.payload_max =>
        {
            Some((input[1] + 1) % 4)
        }
        _ if input.len() == 2 && input[0] == ast.decode_prefix && input[1] <= ast.payload_max => {
            Some(input[1])
        }
        _ => None,
    }
}

fn execute_attack(
    source: &[u8],
    ast: &NativeAst,
    artifact: &[u8],
    smt: &str,
    certificate: &NativeCertificate,
    attack: &NativeAttack,
) -> Result<NativeAttackResult, NativeError> {
    let actual = match attack.class.as_str() {
        "source" => {
            let candidate = mutate_source(source, &attack.action)?;
            parse_native_source(&candidate)
                .err()
                .map(|error| error.code)
        }
        "artifact" => {
            let candidate = mutate_artifact(artifact, &attack.action)?;
            validate_native_artifact(ast, &candidate)
                .err()
                .map(|error| error.code)
        }
        "certificate" => {
            let mut candidate = certificate.clone();
            mutate_certificate(&mut candidate, &attack.action)?;
            validate_native_certificate(source, ast, artifact, &candidate)
                .err()
                .map(|error| error.code)
        }
        "smt" => {
            let mut candidate_smt = smt.to_owned();
            let mut results = certificate.solver.results.clone();
            if attack.action == "remove-verification-condition" {
                let position = candidate_smt
                    .rfind("(check-sat)\n")
                    .ok_or_else(|| invalid("NATIVE-SMT-INCOMPLETE", "VC is absent"))?;
                candidate_smt.replace_range(position..position + 12, "");
            } else if attack.action == "replace-solver-result" {
                results[0] = "sat".to_owned();
            }
            validate_smt(&candidate_smt, &results)
                .err()
                .map(|error| error.code)
        }
        _ => return Err(invalid("NATIVE-SYNTAX", "unknown attack class")),
    }
    .unwrap_or("NATIVE-ACCEPTED")
    .to_owned();
    Ok(NativeAttackResult {
        id: attack.id.clone(),
        expected_code: attack.expected.clone(),
        exact: actual == attack.expected,
        actual_code: actual,
    })
}

fn mutate_source(source: &[u8], action: &str) -> Result<Vec<u8>, NativeError> {
    let text =
        std::str::from_utf8(source).map_err(|error| invalid("NATIVE-SYNTAX", error.to_string()))?;
    let candidate = match action {
        "unknown-declaration" => format!("{text}foreign host;\n"),
        "duplicate-module" => format!("{text}module canonical-packet;\n"),
        "duplicate-function" => {
            format!("{text}fn encode(value: Value) -> Bytes = bytes(1, value);\n")
        }
        "replace-value-bound" => text.replace("range(0, 3)", "range(0, 4)"),
        "replace-prefix" => text.replace("bytes(1, value)", "bytes(2, value)"),
        "remove-wildcard-branch" => text.replace("fallback=Error", "fallback=Missing"),
        "add-unbounded-loop" => format!("{text}loop forever;\n"),
        "add-undeclared-effect" => text.replace("effect decode = pure", "effect decode = network"),
        "remove-specification" => text
            .lines()
            .filter(|line| !line.starts_with("spec canonicality"))
            .map(|line| format!("{line}\n"))
            .collect(),
        "noncanonical-source" => format!("{text}\n"),
        _ => return Err(invalid("NATIVE-SYNTAX", "unknown source attack")),
    };
    Ok(candidate.into_bytes())
}

fn mutate_artifact(artifact: &[u8], action: &str) -> Result<Vec<u8>, NativeError> {
    let mut candidate = artifact.to_vec();
    match action {
        "replace-magic" => candidate[0] = b'X',
        "replace-version" => candidate[4] = 2,
        "replace-opcode" => candidate[7] = 0x99,
        "replace-immediate" => candidate[8] = 2,
        "truncate-artifact" => {
            candidate.pop();
        }
        "append-artifact-byte" => candidate.push(0),
        "swap-programs" => {
            candidate[5] = 11;
            candidate[6] = 4;
        }
        _ => return Err(invalid("NATIVE-ARTIFACT-OPCODE", "unknown artifact attack")),
    }
    Ok(candidate)
}

fn mutate_certificate(
    certificate: &mut NativeCertificate,
    action: &str,
) -> Result<(), NativeError> {
    match action {
        "replace-certificate-schema" => {
            certificate.schema = "proofbound-native-certificate/2".to_owned()
        }
        "replace-source-identity" => certificate.source_sha256 = zero_sha(),
        "replace-artifact-identity" => certificate.artifact_sha256 = zero_sha(),
        "remove-value-row" => {
            certificate.value_rows.pop();
        }
        "remove-input-row" => {
            certificate.input_rows.pop();
        }
        "duplicate-row" => certificate
            .input_rows
            .push(certificate.input_rows[0].clone()),
        "replace-trace-result" => certificate.value_rows[0].decoded_value = Some(1),
        "claim-unbounded-input" => certificate.scope.input_unbounded = true,
        "forge-certificate-identity" => certificate.identity = zero_sha(),
        _ => return Err(invalid("NATIVE-CERT-SCHEMA", "unknown certificate attack")),
    }
    Ok(())
}

fn validate_smt(smt: &str, results: &[String]) -> Result<(), NativeError> {
    if smt.matches("; VC ").count() != 5 || smt.matches("(check-sat)\n").count() != 5 {
        return Err(invalid(
            "NATIVE-SMT-INCOMPLETE",
            "verification condition set differs",
        ));
    }
    if results != ["unsat", "unsat", "unsat", "unsat", "unsat"] {
        return Err(invalid("NATIVE-SMT-RESULT", "solver result differs"));
    }
    Ok(())
}

fn run_solver(toolchain: &NativeToolchain, smt: &[u8]) -> Result<NativeSolverReceipt, NativeError> {
    if toolchain.schema != TOOLCHAIN_SCHEMA
        || toolchain.solver.argv != ["-in", "-smt2"]
        || toolchain.solver.version_argv != ["--version"]
    {
        return Err(invalid("NATIVE-SMT-RESULT", "solver registration differs"));
    }
    let executable = resolve_program(&toolchain.solver.program)?;
    let version_output = Command::new(&executable)
        .args(&toolchain.solver.version_argv)
        .env_clear()
        .output()
        .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?;
    let version = String::from_utf8(version_output.stdout)
        .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?
        .trim_end_matches('\n')
        .to_owned();
    if !version_output.status.success()
        || !version_output.stderr.is_empty()
        || version != toolchain.solver.expected_version
    {
        return Err(invalid("NATIVE-SMT-RESULT", "solver version differs"));
    }
    let mut child = Command::new(&executable)
        .args(&toolchain.solver.argv)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| invalid("NATIVE-SMT-RESULT", "solver stdin unavailable"))?
        .write_all(smt)
        .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?;
    let output = child
        .wait_with_output()
        .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(invalid("NATIVE-SMT-RESULT", "solver execution failed"));
    }
    let stdout = String::from_utf8(output.stdout.clone())
        .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?;
    let results = stdout.lines().map(str::to_owned).collect::<Vec<_>>();
    if results != toolchain.solver.expected_results {
        return Err(invalid("NATIVE-SMT-RESULT", "solver output differs"));
    }
    Ok(NativeSolverReceipt {
        program: toolchain.solver.program.clone(),
        argv: toolchain.solver.argv.clone(),
        executable_sha256: sha256_bytes(
            &fs::read(&executable)
                .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()))?,
        ),
        version,
        input_sha256: sha256_bytes(smt),
        results,
        stdout_sha256: sha256_bytes(&output.stdout),
        stderr_sha256: sha256_bytes(&output.stderr),
    })
}

fn format_native_source(ast: &NativeAst) -> String {
    format!(
        "module {};\ntype Value = range({}, {});\ntype Decode = result(Value, Error);\neffect encode = pure;\neffect decode = pure;\nfn encode(value: Value) -> Bytes = bytes({}, value);\nfn decode(input: Bytes) -> Decode = match-exact(input, length={}, prefix={}, payload-max={}, fallback=Error);\n{}\nbound BytesBounded = bytes(alphabet={}..{}, length={}..{});\n",
        ast.module,
        ast.value_min,
        ast.value_max,
        ast.encode_prefix,
        ast.decode_length,
        ast.decode_prefix,
        ast.payload_max,
        expected_spec_lines(ast.decode_length).join("\n"),
        ast.alphabet_min,
        ast.alphabet_max,
        ast.input_length_min,
        ast.input_length_max,
    )
}

fn expected_spec_lines(consumption: u8) -> Vec<String> {
    vec![
        "spec round-trip = forall value: Value => decode(encode(value)) == Ok(value);".to_owned(),
        "spec malformed-rejection = forall input: BytesBounded => malformed(input) implies decode(input) == Error;".to_owned(),
        "spec canonicality = forall input: BytesBounded => is-ok(decode(input)) implies encode(value-of(decode(input))) == input;".to_owned(),
        format!("spec exact-consumption = forall input: BytesBounded => is-ok(decode(input)) implies consumed(input) == {consumption};"),
        "spec bounded-termination = forall input: BytesBounded => steps(decode(input)) <= length(input) + 4;".to_owned(),
    ]
}

fn parse_pair(line: &str, prefix: &str, suffix: &str) -> Result<(u8, u8), NativeError> {
    let body = line
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .ok_or_else(|| invalid("NATIVE-TYPE", "range declaration differs"))?;
    let (left, right) = body
        .split_once(", ")
        .ok_or_else(|| invalid("NATIVE-TYPE", "range values differ"))?;
    Ok((parse_byte(left)?, parse_byte(right)?))
}

fn parse_effect<'a>(line: &'a str, name: &str) -> Result<&'a str, NativeError> {
    line.strip_prefix(&format!("effect {name} = "))
        .and_then(|value| value.strip_suffix(';'))
        .ok_or_else(|| invalid("NATIVE-EFFECT", "effect declaration differs"))
}

fn parse_encode(line: &str) -> Result<u8, NativeError> {
    let body = line
        .strip_prefix("fn encode(value: Value) -> Bytes = bytes(")
        .and_then(|value| value.strip_suffix(", value);"))
        .ok_or_else(|| invalid("NATIVE-TYPE", "encoder declaration differs"))?;
    parse_byte(body)
}

fn parse_decode(line: &str) -> Result<(u8, u8, u8, bool), NativeError> {
    let body = line
        .strip_prefix("fn decode(input: Bytes) -> Decode = match-exact(input, length=")
        .and_then(|value| value.strip_suffix(");"))
        .ok_or_else(|| invalid("NATIVE-TYPE", "decoder declaration differs"))?;
    let parts = body.split(", ").collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(invalid("NATIVE-TYPE", "decoder fields differ"));
    }
    let length = parse_byte(parts[0])?;
    let prefix = parse_byte(
        parts[1]
            .strip_prefix("prefix=")
            .ok_or_else(|| invalid("NATIVE-TYPE", "decoder prefix differs"))?,
    )?;
    let maximum = parse_byte(
        parts[2]
            .strip_prefix("payload-max=")
            .ok_or_else(|| invalid("NATIVE-TYPE", "decoder maximum differs"))?,
    )?;
    let fallback = parts[3] == "fallback=Error";
    Ok((length, prefix, maximum, fallback))
}

fn parse_bound(line: &str) -> Result<(u8, u8, u8, u8), NativeError> {
    let body = line
        .strip_prefix("bound BytesBounded = bytes(alphabet=")
        .and_then(|value| value.strip_suffix(");"))
        .ok_or_else(|| invalid("NATIVE-TYPE", "bound declaration differs"))?;
    let (alphabet, lengths) = body
        .split_once(", length=")
        .ok_or_else(|| invalid("NATIVE-TYPE", "bound fields differ"))?;
    let (a0, a1) = alphabet
        .split_once("..")
        .ok_or_else(|| invalid("NATIVE-TYPE", "alphabet range differs"))?;
    let (l0, l1) = lengths
        .split_once("..")
        .ok_or_else(|| invalid("NATIVE-TYPE", "length range differs"))?;
    Ok((
        parse_byte(a0)?,
        parse_byte(a1)?,
        parse_byte(l0)?,
        parse_byte(l1)?,
    ))
}

fn parse_byte(value: &str) -> Result<u8, NativeError> {
    if value.len() > 1 && value.starts_with('0') {
        return Err(invalid("NATIVE-NONCANONICAL", "integer has a leading zero"));
    }
    value
        .parse::<u8>()
        .map_err(|error| invalid("NATIVE-TYPE", error.to_string()))
}

fn enumerate_inputs(minimum: u8, maximum: u8, maximum_length: u8) -> Vec<Vec<u8>> {
    let mut output = vec![Vec::new()];
    let alphabet = (minimum..=maximum).collect::<Vec<_>>();
    let mut prior = vec![Vec::new()];
    for _ in 1..=maximum_length {
        let mut current = Vec::new();
        for prefix in &prior {
            for byte in &alphabet {
                let mut value = prefix.clone();
                value.push(*byte);
                current.push(value);
            }
        }
        output.extend(current.clone());
        prior = current;
    }
    output
}

fn validate_module_id(value: &str) -> Result<(), NativeError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid("NATIVE-SYNTAX", "module identifier differs"));
    }
    Ok(())
}

fn resolve_program(program: &str) -> Result<PathBuf, NativeError> {
    for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .map_err(|error| invalid("NATIVE-SMT-RESULT", error.to_string()));
        }
    }
    Err(invalid("NATIVE-SMT-RESULT", "solver is unavailable"))
}

fn validate_attacks(corpus: &NativeAttackCorpus) -> Result<(), NativeError> {
    if corpus.schema != ATTACKS_SCHEMA || corpus.attacks.len() != 28 {
        return Err(invalid("NATIVE-SYNTAX", "attack corpus differs"));
    }
    let ids = corpus
        .attacks
        .iter()
        .map(|item| &item.id)
        .collect::<Vec<_>>();
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("NATIVE-DUPLICATE", "attack IDs differ"));
    }
    Ok(())
}

fn native_certificate_identity(certificate: &NativeCertificate) -> Result<String, NativeError> {
    let mut candidate = certificate.clone();
    candidate.identity.clear();
    hash_serialized(NATIVE_CERTIFICATE_SCHEMA, &candidate)
}

fn native_report_identity(report: &NativeReport) -> Result<String, NativeError> {
    let mut candidate = report.clone();
    candidate.identity.clear();
    candidate.repetition_identities.clear();
    hash_serialized(NATIVE_REPORT_SCHEMA, &candidate)
}

fn hash_serialized<T: Serialize>(domain: &str, value: &T) -> Result<String, NativeError> {
    canonical_json(value)
        .map(|bytes| domain_hash(domain, &bytes))
        .map_err(|error| invalid("NATIVE-SYNTAX", error.to_string()))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn has_duplicates<T: Ord + Clone>(values: &[T]) -> bool {
    values.iter().cloned().collect::<BTreeSet<_>>().len() != values.len()
}

fn zero_sha() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn read(root: &Path, path: &Path) -> Result<Vec<u8>, NativeError> {
    fs::read(root.join(path)).map_err(|error| invalid("NATIVE-SYNTAX", error.to_string()))
}

fn decode_file<T: for<'de> Deserialize<'de>>(root: &Path, path: &Path) -> Result<T, NativeError> {
    serde_json::from_slice(&read(root, path)?)
        .map_err(|error| invalid("NATIVE-SYNTAX", error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORPUS: &str = "docs/experiments/0016-native-canonical-parser/corpus";

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root should resolve")
    }

    fn fixture() -> (Vec<u8>, NativeAst, Vec<u8>, String, NativeCertificate) {
        let root = repository_root();
        let source =
            read(&root, Path::new(CORPUS).join("parser.pb").as_path()).expect("source should load");
        let ast = parse_native_source(&source).expect("source should parse");
        let artifact = compile_native_artifact(&ast);
        let smt = generate_native_smt(&ast);
        let solver = NativeSolverReceipt {
            program: "z3".to_owned(),
            argv: vec!["-in".to_owned(), "-smt2".to_owned()],
            executable_sha256: zero_sha(),
            version: "Z3 version 4.15.2 - 64 bit".to_owned(),
            input_sha256: sha256_bytes(smt.as_bytes()),
            results: vec!["unsat".to_owned(); 5],
            stdout_sha256: zero_sha(),
            stderr_sha256: zero_sha(),
        };
        let certificate = derive_native_certificate(&source, &ast, &artifact, solver)
            .expect("certificate should derive");
        (source, ast, artifact, smt, certificate)
    }

    #[test]
    fn native_model_rejects_every_frozen_attack_exactly() {
        let root = repository_root();
        let (source, ast, artifact, smt, certificate) = fixture();
        let attacks: NativeAttackCorpus =
            decode_file(&root, Path::new(CORPUS).join("attacks.json").as_path())
                .expect("attacks should load");
        validate_attacks(&attacks).expect("attacks should validate");
        let results = attacks
            .attacks
            .iter()
            .map(|attack| execute_attack(&source, &ast, &artifact, &smt, &certificate, attack))
            .collect::<Result<Vec<_>, _>>()
            .expect("attacks should execute");
        assert_eq!(results.len(), 28);
        assert!(results.iter().all(|result| result.exact));
    }

    #[test]
    fn certificate_does_not_claim_artifact_proof() {
        let (source, ast, artifact, _, certificate) = fixture();
        validate_native_certificate(&source, &ast, &artifact, &certificate)
            .expect("certificate should validate");
        assert!(certificate.scope.value_universal);
        assert!(!certificate.scope.input_unbounded);
        assert_eq!(
            certificate.scope.compiler_correspondence,
            "independent-dual-compilation"
        );
    }

    #[test]
    #[ignore = "requires preregistered Z3 4.15.2"]
    fn live_native_corpus_executes_with_exact_attacks() {
        let report = execute_native_corpus(&repository_root(), Path::new(CORPUS), 10)
            .expect("native corpus should execute");
        assert_eq!(report.artifact_hex.len(), 44);
        assert_eq!(report.certificate.value_rows.len(), 4);
        assert_eq!(report.certificate.input_rows.len(), 156);
        assert_eq!(report.certificate.semantic_mutants.len(), 6);
        assert_eq!(report.attacks.len(), 28);
        assert!(report.attacks.iter().all(|result| result.exact));
        assert!(!report.assurance.artifact_proved);
        assert_eq!(report.assurance.round_trip, "universal-over-declared-u2");
    }
}
