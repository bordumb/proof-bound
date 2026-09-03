use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::assurance::decode_strict_json;

pub const FRONTEND_PROGRAMME_SCHEMA: &str = "proofbound-research-frontend-programme/1";
pub const EFFECTIVE_PROGRAMME_SCHEMA: &str = "proofbound-research-effective-programme/1";
pub const SOURCE_MAP_SCHEMA: &str = "proofbound-research-source-map/1";
pub const FRONTEND_RECEIPT_SCHEMA: &str = "proofbound-research-frontend-receipt/1";
pub const FRONTEND_COMPILATION_SCHEMA: &str = "proofbound-research-frontend-compilation/1";
const PROGRAMME_DOMAIN: &str = "proofbound-research-frontend-programme/1";
const EFFECTIVE_DOMAIN: &str = "proofbound-research-effective-programme/1";
const SOURCE_MAP_DOMAIN: &str = "proofbound-research-source-map/1";
const DEPENDENCIES_DOMAIN: &str = "proofbound-research-frontend-dependencies/1";
const RECEIPT_DOMAIN: &str = "proofbound-research-frontend-receipt/1";
const REGISTERED_PKL_SHA256: &str =
    "sha256:563eb51c9a20b16a3625464ed745c675ed9750381f2126722696a0d7cac1d9d3";
const PKL_POLICY: &str = "pkl-0.32.1;modules=pkl:,file:;resources=^$;root=corpus;cache=off;env=PATH:/usr/bin:/bin;timeout=10";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendProgramme {
    pub schema: String,
    pub project: FrontendProject,
    pub claims: Vec<FrontendClaim>,
    pub evidence: Vec<FrontendEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendProject {
    pub id: String,
    pub ecosystem: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendClaim {
    pub schema: String,
    pub id: String,
    pub title: String,
    pub statement: String,
    pub public_language: String,
    pub subject: String,
    pub profile: String,
    pub tier: u8,
    pub primary_linkage: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub premises: Vec<String>,
    #[serde(default)]
    pub open_obligations: Vec<String>,
    #[serde(default)]
    pub out_of_scope: Vec<String>,
    pub source_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formal_declaration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_sha256: Option<String>,
    #[serde(default)]
    pub foundational_axioms: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_domain: Option<FrontendBoundedDomain>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendEvidence {
    pub schema: String,
    pub id: String,
    pub adapter: String,
    pub kind: String,
    pub claims: Vec<String>,
    pub tier: u8,
    #[serde(default)]
    pub assumptions: Vec<String>,
    pub expected_inventory: Vec<String>,
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    pub environment_allowlist: Vec<String>,
    pub operation: FrontendOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<FrontendPythonProperty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_domain: Option<FrontendBoundedDomain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<FrontendMutation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem: Option<String>,
    pub resource_budget: FrontendBudget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FrontendOperation {
    Pytest {
        manifest: String,
        targets: Vec<String>,
        paths: Vec<String>,
        #[serde(default)]
        plugins: Vec<String>,
    },
    Vitest,
    CargoTest {
        package: String,
        manifest: String,
        #[serde(default)]
        targets: Vec<String>,
    },
    Kani {
        package: String,
        manifest: String,
        targets: Vec<String>,
    },
    LeanAudit {
        targets: Vec<String>,
        paths: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendBudget {
    pub time_seconds: u64,
    pub disk_bytes: u64,
    pub memory_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendBoundedDomain {
    pub id: String,
    pub description: String,
    pub cardinality: u64,
    pub ordering_key: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendPythonProperty {
    pub schema: String,
    pub framework: String,
    pub seed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendMutation {
    pub schema: String,
    pub registry: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendCompilation {
    pub schema: String,
    pub frontend: String,
    pub programme: FrontendProgramme,
    pub effective_programme: EffectiveProgramme,
    pub source_map: FrontendSourceMap,
    pub dependencies: Vec<FrontendDependency>,
    pub receipt: FrontendReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveProgramme {
    pub schema: String,
    pub programme: FrontendProgramme,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendSourceMap {
    pub schema: String,
    pub entries: Vec<FrontendSourceMapEntry>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendSourceMapEntry {
    pub leaf: String,
    pub source: FrontendSourceSpan,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendSourceSpan {
    pub path: String,
    pub sha256: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendDependency {
    pub kind: String,
    pub role: String,
    pub logical_name: String,
    pub identity: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendReceipt {
    pub schema: String,
    pub project: String,
    pub frontend: String,
    pub programme_sha256: String,
    pub effective_programme_sha256: String,
    pub source_map_sha256: String,
    pub dependencies_sha256: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendProgrammeControl {
    pub project: String,
    pub expected_bytes: usize,
    pub actual_bytes: usize,
    pub expected_identity: String,
    pub actual_identity: String,
    pub matches: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendError {
    pub code: &'static str,
    pub message: String,
    pub path: Option<String>,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

impl std::fmt::Display for FrontendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for FrontendError {}

impl FrontendError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            path: None,
            start: None,
            end: None,
        }
    }

    fn at_source(code: &'static str, message: impl Into<String>, path: &Path, size: usize) -> Self {
        Self {
            code,
            message: message.into(),
            path: Some(path.to_string_lossy().into_owned()),
            start: Some(0),
            end: Some(size.max(1) as u64),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrontendCorpus {
    schema: String,
    pkl_schema: RegisteredSource,
    subjects: Vec<FrontendSubject>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrontendSubject {
    id: String,
    ecosystem: String,
    expected_programme_bytes: usize,
    expected_programme_identity: String,
    frontends: BTreeMap<String, RegisteredSource>,
    toml_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisteredSource {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Preregistration {
    subjects: Vec<RegisteredSubject>,
    #[serde(flatten)]
    _ignored: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct RegisteredSubject {
    id: String,
    files: Vec<RegisteredSource>,
    #[serde(flatten)]
    _ignored: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrontendFlavor {
    Toml,
    ProofboundDsl,
    Pkl,
}

impl FrontendFlavor {
    fn as_str(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::ProofboundDsl => "proofbound-dsl",
            Self::Pkl => "pkl",
        }
    }

    fn parse(value: &str) -> Result<Self, FrontendError> {
        match value {
            "toml" => Ok(Self::Toml),
            "proofbound-dsl" => Ok(Self::ProofboundDsl),
            "pkl" => Ok(Self::Pkl),
            _ => Err(FrontendError::new(
                "FRONTEND-SYNTAX-UNKNOWN",
                "unknown frontend",
            )),
        }
    }
}

pub fn compile_toml_frontend(
    root: &Path,
    corpus_path: &Path,
    subject_id: &str,
) -> Result<FrontendCompilation, FrontendError> {
    let (corpus, subject) = load_subject(root, corpus_path, subject_id)?;
    let preregistration_path = corpus_path
        .parent()
        .and_then(Path::parent)
        .map(|path| path.join("preregistration.json"))
        .ok_or_else(|| FrontendError::new("FRONTEND-DEPENDENCY-DRIFT", "invalid corpus path"))?;
    let registration = load_registration(root, &preregistration_path)?;
    let registered = registration
        .subjects
        .iter()
        .find(|candidate| candidate.id == subject.id)
        .ok_or_else(|| {
            FrontendError::new(
                "FRONTEND-DEPENDENCY-DRIFT",
                "subject is absent from the preregistration",
            )
        })?;
    let registered_by_path = registered
        .files
        .iter()
        .map(|source| (source.path.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    let mut claims = Vec::new();
    let mut evidence = Vec::new();
    let mut origins = BTreeMap::new();
    let mut dependencies = Vec::new();
    for relative in &subject.toml_paths {
        let source = registered_by_path.get(relative.as_str()).ok_or_else(|| {
            FrontendError::new(
                "FRONTEND-DEPENDENCY-DRIFT",
                format!("TOML source {relative} lacks a registered identity"),
            )
        })?;
        let bytes = read_registered(root, source)?;
        let value: toml::Value = toml::from_str(std::str::from_utf8(&bytes).map_err(|_| {
            FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                "TOML source is not UTF-8",
                Path::new(relative),
                bytes.len(),
            )
        })?)
        .map_err(|error| {
            FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                error.to_string(),
                Path::new(relative),
                bytes.len(),
            )
        })?;
        let value = serde_json::to_value(value).map_err(|error| {
            FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                error.to_string(),
                Path::new(relative),
                bytes.len(),
            )
        })?;
        let artifact = source_span(relative, &bytes);
        dependencies.push(source_dependency(relative, &bytes));
        match value.get("schema").and_then(Value::as_str) {
            Some("proofbound-claim/1") => {
                let claim: FrontendClaim = decode_typed(value, relative, bytes.len())?;
                origins.insert(format!("claim:{}", claim.id), artifact);
                claims.push(claim);
            }
            Some(schema) if schema.starts_with("proofbound-evidence-unit/") => {
                let unit: FrontendEvidence = decode_typed(value, relative, bytes.len())?;
                origins.insert(format!("evidence:{}", unit.id), artifact);
                evidence.push(unit);
            }
            _ => {
                return Err(FrontendError::at_source(
                    "FRONTEND-SYNTAX-UNKNOWN",
                    "unsupported TOML document schema",
                    Path::new(relative),
                    bytes.len(),
                ));
            }
        }
    }
    let index_relative = relative_path(root, corpus_path)?;
    let index_bytes = fs::read(root.join(&index_relative))
        .map_err(|error| FrontendError::new("FRONTEND-DEPENDENCY-DRIFT", error.to_string()))?;
    origins.insert(
        "programme".to_owned(),
        source_span(&index_relative, &index_bytes),
    );
    dependencies.push(source_dependency(&index_relative, &index_bytes));
    let programme = FrontendProgramme {
        schema: FRONTEND_PROGRAMME_SCHEMA.to_owned(),
        project: FrontendProject {
            id: subject.id.clone(),
            ecosystem: subject.ecosystem.clone(),
        },
        claims,
        evidence,
    };
    finish_compilation(
        root,
        FrontendFlavor::Toml,
        programme,
        origins,
        dependencies,
        &corpus,
    )
}

pub fn compile_dsl_frontend(
    root: &Path,
    corpus_path: &Path,
    subject_id: &str,
) -> Result<FrontendCompilation, FrontendError> {
    let (corpus, subject) = load_subject(root, corpus_path, subject_id)?;
    let source = subject
        .frontends
        .get("proofbound-dsl")
        .cloned()
        .ok_or_else(|| FrontendError::new("FRONTEND-DEPENDENCY-DRIFT", "DSL source is missing"))?;
    let bytes = read_registered(root, &source)?;
    let programme = parse_dsl(&bytes, Path::new(&source.path))?;
    let span = source_span(&source.path, &bytes);
    let origins = programme_origins(&programme, &span);
    finish_compilation(
        root,
        FrontendFlavor::ProofboundDsl,
        programme,
        origins,
        vec![source_dependency(&source.path, &bytes)],
        &corpus,
    )
}

pub fn format_dsl_frontend(bytes: &[u8], path: &Path) -> Result<Vec<u8>, FrontendError> {
    parse_dsl(bytes, path)?;
    let source = std::str::from_utf8(bytes).map_err(|_| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "DSL source is not UTF-8",
            path,
            bytes.len(),
        )
    })?;
    let lines = source.lines().enumerate().collect::<Vec<_>>();
    let mut output = String::new();
    let Some((_, header)) = lines.first() else {
        return Err(FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "empty DSL source",
            path,
            bytes.len(),
        ));
    };
    output.push_str(header.trim());
    output.push_str("\n\n");
    let mut cursor = 1;
    loop {
        while cursor < lines.len() && lines[cursor].1.trim().is_empty() {
            cursor += 1;
        }
        let Some((_, declaration)) = lines.get(cursor) else {
            return Err(FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                "programme has no final end",
                path,
                bytes.len(),
            ));
        };
        if declaration.trim() == "end" {
            output.push_str("end\n");
            break;
        }
        output.push_str(declaration.trim());
        output.push('\n');
        cursor += 1;
        let (fields, next) = parse_assignment_block(&lines, cursor, path, bytes.len())?;
        cursor = next;
        let mut fields = fields.into_iter().collect::<Vec<_>>();
        fields.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, value) in fields {
            let encoded = canonical_json(&value).map_err(|error| {
                FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string())
            })?;
            output.push_str(&key);
            output.push_str(" = ");
            output.push_str(std::str::from_utf8(&encoded).expect("canonical JSON is UTF-8"));
            output.push('\n');
        }
        output.push_str("end\n\n");
    }
    Ok(output.into_bytes())
}

pub fn compile_pkl_frontend(
    root: &Path,
    corpus_path: &Path,
    subject_id: &str,
    rendered_json: &[u8],
    pkl_executable: &Path,
) -> Result<FrontendCompilation, FrontendError> {
    let tool_bytes = fs::read(pkl_executable).map_err(|error| {
        FrontendError::new(
            "FRONTEND-TOOL-SUBSTITUTION",
            format!("failed to read Pkl executable: {error}"),
        )
    })?;
    compile_pkl_frontend_with_identity(
        root,
        corpus_path,
        subject_id,
        rendered_json,
        &sha256_bytes(&tool_bytes),
    )
}

pub fn compile_pkl_frontend_with_identity(
    root: &Path,
    corpus_path: &Path,
    subject_id: &str,
    rendered_json: &[u8],
    tool_sha256: &str,
) -> Result<FrontendCompilation, FrontendError> {
    let (corpus, subject) = load_subject(root, corpus_path, subject_id)?;
    let source =
        subject.frontends.get("pkl").cloned().ok_or_else(|| {
            FrontendError::new("FRONTEND-DEPENDENCY-DRIFT", "Pkl source is missing")
        })?;
    let source_bytes = read_registered(root, &source)?;
    preflight_pkl_source(&source_bytes, Path::new(&source.path))?;
    let schema_bytes = read_registered(root, &corpus.pkl_schema)?;
    if tool_sha256 != REGISTERED_PKL_SHA256 {
        return Err(FrontendError::new(
            "FRONTEND-TOOL-SUBSTITUTION",
            "Pkl executable identity differs from the preregistered release",
        ));
    }
    let value = decode_strict_json(rendered_json)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    let programme: FrontendProgramme = decode_typed(value, &source.path, source_bytes.len())?;
    let project_span = source_span(&source.path, &source_bytes);
    let schema_span = source_span(&corpus.pkl_schema.path, &schema_bytes);
    let mut origins = programme_origins(&programme, &project_span);
    origins.insert("programme".to_owned(), schema_span);
    let dependencies = vec![
        source_dependency(&source.path, &source_bytes),
        source_dependency(&corpus.pkl_schema.path, &schema_bytes),
        FrontendDependency {
            kind: "tool".to_owned(),
            role: "frontend-evaluator".to_owned(),
            logical_name: "pkl".to_owned(),
            identity: tool_sha256.to_owned(),
            detail: "Pkl 0.32.1".to_owned(),
        },
        FrontendDependency {
            kind: "contract".to_owned(),
            role: "authority-policy".to_owned(),
            logical_name: "pkl-evaluation-policy".to_owned(),
            identity: domain_hash("proofbound-research-pkl-policy/1", PKL_POLICY.as_bytes()),
            detail: PKL_POLICY.to_owned(),
        },
    ];
    finish_compilation(
        root,
        FrontendFlavor::Pkl,
        programme,
        origins,
        dependencies,
        &corpus,
    )
}

pub fn validate_frontend_compilation(
    root: &Path,
    compilation: &FrontendCompilation,
) -> Result<(), FrontendError> {
    if compilation.schema != FRONTEND_COMPILATION_SCHEMA {
        return Err(FrontendError::new(
            "FRONTEND-SYNTAX-UNKNOWN",
            "unknown compilation schema",
        ));
    }
    let mut programme = compilation.programme.clone();
    normalize_and_validate_programme(&mut programme)?;
    if programme != compilation.programme {
        return Err(FrontendError::new(
            "FRONTEND-NONCANONICAL",
            "programme is not in canonical order",
        ));
    }
    let expected_effective = EffectiveProgramme {
        schema: EFFECTIVE_PROGRAMME_SCHEMA.to_owned(),
        programme: programme.clone(),
    };
    if compilation.effective_programme != expected_effective {
        return Err(FrontendError::new(
            "FRONTEND-EFFECTIVE-NONCANONICAL",
            "effective programme differs from the canonical programme",
        ));
    }
    require_sorted_unique_dependencies(&compilation.dependencies)?;
    validate_source_map(
        root,
        FrontendFlavor::parse(&compilation.frontend)?,
        &programme,
        &compilation.source_map,
        &compilation.dependencies,
    )?;
    let expected_receipt = make_receipt(
        &compilation.frontend,
        &programme,
        &expected_effective,
        &compilation.source_map,
        &compilation.dependencies,
    )?;
    if compilation.receipt != expected_receipt {
        return Err(FrontendError::new(
            "FRONTEND-MAP-LEAF",
            "frontend receipt does not match its programme, map, or dependencies",
        ));
    }
    Ok(())
}

pub fn compare_frontend_programme_control(
    root: &Path,
    corpus_path: &Path,
    subject_id: &str,
    programme: &FrontendProgramme,
) -> Result<FrontendProgrammeControl, FrontendError> {
    let (_, subject) = load_subject(root, corpus_path, subject_id)?;
    let mut normalized = programme.clone();
    normalize_and_validate_programme(&mut normalized)?;
    if &normalized != programme {
        return Err(FrontendError::new(
            "FRONTEND-NONCANONICAL",
            "programme is not in canonical order",
        ));
    }
    let bytes = canonical_json(programme)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    let actual_identity = domain_hash(PROGRAMME_DOMAIN, &bytes);
    Ok(FrontendProgrammeControl {
        project: subject.id,
        expected_bytes: subject.expected_programme_bytes,
        actual_bytes: bytes.len(),
        expected_identity: subject.expected_programme_identity.clone(),
        matches: bytes.len() == subject.expected_programme_bytes
            && actual_identity == subject.expected_programme_identity,
        actual_identity,
    })
}

pub fn validate_frontend_compilation_bytes(
    root: &Path,
    bytes: &[u8],
) -> Result<FrontendCompilation, FrontendError> {
    let value = decode_strict_json(bytes)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    let compilation: FrontendCompilation = serde_json::from_value(value)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    let canonical = canonical_json(&compilation)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    if canonical != bytes {
        return Err(FrontendError::new(
            "FRONTEND-EFFECTIVE-NONCANONICAL",
            "compilation is not canonical JSON",
        ));
    }
    validate_frontend_compilation(root, &compilation)?;
    Ok(compilation)
}

pub fn validate_effective_programme_bytes(
    bytes: &[u8],
) -> Result<EffectiveProgramme, FrontendError> {
    let value = decode_strict_json(bytes)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    let effective: EffectiveProgramme = serde_json::from_value(value)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    let canonical = canonical_json(&effective)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    if canonical != bytes {
        return Err(FrontendError::new(
            "FRONTEND-EFFECTIVE-NONCANONICAL",
            "effective programme is not canonical JSON",
        ));
    }
    if effective.schema != EFFECTIVE_PROGRAMME_SCHEMA {
        return Err(FrontendError::new(
            "FRONTEND-SYNTAX-UNKNOWN",
            "unknown effective programme schema",
        ));
    }
    let mut normalized = effective.programme.clone();
    normalize_and_validate_programme(&mut normalized)?;
    if normalized != effective.programme {
        return Err(FrontendError::new(
            "FRONTEND-NONCANONICAL",
            "effective programme content is not canonical",
        ));
    }
    Ok(effective)
}

fn load_subject(
    root: &Path,
    corpus_path: &Path,
    subject_id: &str,
) -> Result<(FrontendCorpus, FrontendSubject), FrontendError> {
    let bytes = fs::read(root.join(corpus_path))
        .map_err(|error| FrontendError::new("FRONTEND-DEPENDENCY-DRIFT", error.to_string()))?;
    let corpus: FrontendCorpus = serde_json::from_slice(&bytes)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?;
    if corpus.schema != "proofbound-research-frontend-corpus/1" {
        return Err(FrontendError::new(
            "FRONTEND-SYNTAX-UNKNOWN",
            "unknown frontend corpus schema",
        ));
    }
    let subject = corpus
        .subjects
        .iter()
        .find(|subject| subject.id == subject_id)
        .cloned()
        .ok_or_else(|| FrontendError::new("FRONTEND-ID-ALIAS", "unknown subject ID"))?;
    Ok((corpus, subject))
}

fn load_registration(root: &Path, path: &Path) -> Result<Preregistration, FrontendError> {
    let bytes = fs::read(root.join(path))
        .map_err(|error| FrontendError::new("FRONTEND-DEPENDENCY-DRIFT", error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))
}

fn read_registered(root: &Path, source: &RegisteredSource) -> Result<Vec<u8>, FrontendError> {
    let path = root.join(&source.path);
    let bytes = fs::read(&path).map_err(|error| {
        FrontendError::new(
            "FRONTEND-DEPENDENCY-DRIFT",
            format!("failed to read {}: {error}", source.path),
        )
    })?;
    if sha256_bytes(&bytes) != format!("sha256:{}", source.sha256) {
        return Err(FrontendError::at_source(
            "FRONTEND-DEPENDENCY-DRIFT",
            "registered source identity changed",
            Path::new(&source.path),
            bytes.len(),
        ));
    }
    Ok(bytes)
}

fn decode_typed<T: for<'de> Deserialize<'de>>(
    value: Value,
    path: &str,
    size: usize,
) -> Result<T, FrontendError> {
    serde_json::from_value(value).map_err(|error| {
        let code = if error.to_string().contains("unknown field") {
            "FRONTEND-SYNTAX-UNKNOWN"
        } else {
            "FRONTEND-TYPE-EVIDENCE"
        };
        FrontendError::at_source(code, error.to_string(), Path::new(path), size)
    })
}

fn parse_dsl(bytes: &[u8], path: &Path) -> Result<FrontendProgramme, FrontendError> {
    let source = std::str::from_utf8(bytes).map_err(|_| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "DSL source is not UTF-8",
            path,
            bytes.len(),
        )
    })?;
    if source.contains('\r') || !source.ends_with('\n') {
        return Err(FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "DSL source must use LF and end with one LF",
            path,
            bytes.len(),
        ));
    }
    let mut lines = source.lines().enumerate();
    let Some((_, header)) = lines.next() else {
        return Err(FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "empty DSL source",
            path,
            bytes.len(),
        ));
    };
    let (project_id, ecosystem) = parse_programme_header(header, path, bytes.len())?;
    let mut defaults: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut claims = Vec::new();
    let mut evidence = Vec::new();
    let mut ended = false;
    let remaining = lines.collect::<Vec<_>>();
    let mut cursor = 0;
    while cursor < remaining.len() {
        let (_, raw) = remaining[cursor];
        cursor += 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line == "end" {
            ended = true;
            if remaining[cursor..]
                .iter()
                .any(|(_, trailing)| !trailing.trim().is_empty())
            {
                return Err(FrontendError::at_source(
                    "FRONTEND-SYNTAX-UNKNOWN",
                    "content follows programme end",
                    path,
                    bytes.len(),
                ));
            }
            break;
        }
        if let Some(name) = line.strip_prefix("defaults ") {
            let name = parse_json_string(name, path, bytes.len())?;
            let (fields, next) = parse_assignment_block(&remaining, cursor, path, bytes.len())?;
            cursor = next;
            if defaults.insert(name, fields).is_some() {
                return Err(FrontendError::at_source(
                    "FRONTEND-ID-ALIAS",
                    "duplicate defaults name",
                    path,
                    bytes.len(),
                ));
            }
            continue;
        }
        if let Some(id) = line.strip_prefix("claim ") {
            let id = parse_json_string(id, path, bytes.len())?;
            let (mut fields, next) = parse_assignment_block(&remaining, cursor, path, bytes.len())?;
            cursor = next;
            fields.insert(
                "schema".to_owned(),
                Value::String("proofbound-claim/1".to_owned()),
            );
            fields.insert("id".to_owned(), Value::String(id));
            claims.push(decode_typed(
                Value::Object(fields),
                &path.to_string_lossy(),
                bytes.len(),
            )?);
            continue;
        }
        if let Some(header) = line.strip_prefix("evidence ") {
            let (constructor, id, defaults_name) =
                parse_evidence_header(header, path, bytes.len())?;
            let mut fields = match defaults_name {
                Some(name) => defaults.get(&name).cloned().ok_or_else(|| {
                    FrontendError::at_source(
                        "FRONTEND-ID-ALIAS",
                        "unknown or forward defaults reference",
                        path,
                        bytes.len(),
                    )
                })?,
                None => Map::new(),
            };
            let (explicit, next) = parse_assignment_block(&remaining, cursor, path, bytes.len())?;
            cursor = next;
            for (key, value) in explicit {
                if fields.insert(key.clone(), value).is_some() {
                    return Err(FrontendError::at_source(
                        "FRONTEND-SYNTAX-UNKNOWN",
                        format!("explicit field {key} overrides a default"),
                        path,
                        bytes.len(),
                    ));
                }
            }
            let (schema, adapter, kind) = constructor_fields(&constructor).ok_or_else(|| {
                FrontendError::at_source(
                    "FRONTEND-TYPE-EVIDENCE",
                    "unknown evidence constructor",
                    path,
                    bytes.len(),
                )
            })?;
            for (key, value) in [
                ("schema", schema),
                ("adapter", adapter),
                ("kind", kind),
                ("id", id.as_str()),
            ] {
                if fields
                    .insert(key.to_owned(), Value::String(value.to_owned()))
                    .is_some()
                {
                    return Err(FrontendError::at_source(
                        "FRONTEND-TYPE-EVIDENCE",
                        format!("constructor-owned field {key} cannot be assigned"),
                        path,
                        bytes.len(),
                    ));
                }
            }
            evidence.push(decode_typed(
                Value::Object(fields),
                &path.to_string_lossy(),
                bytes.len(),
            )?);
            continue;
        }
        return Err(FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            format!("unknown declaration {line}"),
            path,
            bytes.len(),
        ));
    }
    if !ended {
        return Err(FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "programme has no final end",
            path,
            bytes.len(),
        ));
    }
    Ok(FrontendProgramme {
        schema: FRONTEND_PROGRAMME_SCHEMA.to_owned(),
        project: FrontendProject {
            id: project_id,
            ecosystem,
        },
        claims,
        evidence,
    })
}

fn parse_programme_header(
    header: &str,
    path: &Path,
    size: usize,
) -> Result<(String, String), FrontendError> {
    let rest = header.strip_prefix("programme ").ok_or_else(|| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "invalid programme header",
            path,
            size,
        )
    })?;
    let marker = " ecosystem ";
    let (id, ecosystem) = rest.split_once(marker).ok_or_else(|| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "programme header lacks ecosystem",
            path,
            size,
        )
    })?;
    Ok((
        parse_json_string(id, path, size)?,
        parse_json_string(ecosystem, path, size)?,
    ))
}

fn parse_evidence_header(
    header: &str,
    path: &Path,
    size: usize,
) -> Result<(String, String, Option<String>), FrontendError> {
    let (core, defaults) = match header.split_once(" using ") {
        Some((core, name)) => (core, Some(parse_json_string(name, path, size)?)),
        None => (header, None),
    };
    let split = core.find(' ').ok_or_else(|| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "evidence header lacks an ID",
            path,
            size,
        )
    })?;
    let constructor = core[..split].to_owned();
    let id = parse_json_string(&core[split + 1..], path, size)?;
    Ok((constructor, id, defaults))
}

fn parse_assignment_block(
    lines: &[(usize, &str)],
    mut cursor: usize,
    path: &Path,
    size: usize,
) -> Result<(Map<String, Value>, usize), FrontendError> {
    let mut fields = Map::new();
    while cursor < lines.len() {
        let (_, raw) = lines[cursor];
        cursor += 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line == "end" {
            return Ok((fields, cursor));
        }
        let (key, encoded) = line.split_once(" = ").ok_or_else(|| {
            FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                "assignment must use ` = `",
                path,
                size,
            )
        })?;
        if !valid_field_name(key) {
            return Err(FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                "invalid field name",
                path,
                size,
            ));
        }
        let value = decode_strict_json(encoded.as_bytes()).map_err(|error| {
            FrontendError::at_source("FRONTEND-SYNTAX-UNKNOWN", error.to_string(), path, size)
        })?;
        if fields.insert(key.to_owned(), value).is_some() {
            return Err(FrontendError::at_source(
                "FRONTEND-SYNTAX-UNKNOWN",
                format!("duplicate assignment {key}"),
                path,
                size,
            ));
        }
    }
    Err(FrontendError::at_source(
        "FRONTEND-SYNTAX-UNKNOWN",
        "unterminated declaration",
        path,
        size,
    ))
}

fn parse_json_string(value: &str, path: &Path, size: usize) -> Result<String, FrontendError> {
    let decoded = decode_strict_json(value.as_bytes()).map_err(|error| {
        FrontendError::at_source("FRONTEND-SYNTAX-UNKNOWN", error.to_string(), path, size)
    })?;
    decoded.as_str().map(str::to_owned).ok_or_else(|| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "expected a JSON string",
            path,
            size,
        )
    })
}

fn constructor_fields(constructor: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match constructor {
        "python-example" => Some(("proofbound-evidence-unit/1", "python-test", "example-test")),
        "python-property" => Some(("proofbound-evidence-unit/1", "python-test", "property-test")),
        "node-example" => Some(("proofbound-evidence-unit/1", "node-test", "example-test")),
        "node-property" => Some(("proofbound-evidence-unit/1", "node-test", "property-test")),
        "rust-example" => Some(("proofbound-evidence-unit/1", "rust-test", "example-test")),
        "kani-bounded" => Some(("proofbound-evidence-unit/1", "kani", "bounded-check")),
        "rust-mutation" => Some((
            "proofbound-evidence-unit/3",
            "rust-test",
            "mutation-witness",
        )),
        "lean-theorem" => Some(("proofbound-evidence-unit/1", "lean", "theorem")),
        _ => None,
    }
}

fn valid_field_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn preflight_pkl_source(bytes: &[u8], path: &Path) -> Result<(), FrontendError> {
    let source = std::str::from_utf8(bytes).map_err(|_| {
        FrontendError::at_source(
            "FRONTEND-SYNTAX-UNKNOWN",
            "Pkl source is not UTF-8",
            path,
            bytes.len(),
        )
    })?;
    if source.contains("read(") || source.contains("read?(") || source.contains("read*(") {
        return Err(FrontendError::at_source(
            "FRONTEND-PKL-RESOURCE",
            "Pkl resource reads are forbidden",
            path,
            bytes.len(),
        ));
    }
    if source.contains("https:")
        || source.contains("http:")
        || source.contains("package:")
        || source.contains("projectpackage:")
    {
        return Err(FrontendError::at_source(
            "FRONTEND-PKL-MODULE",
            "remote and package Pkl modules are forbidden",
            path,
            bytes.len(),
        ));
    }
    if source.lines().any(|line| {
        let line = line.trim();
        line.starts_with("amends \"../") || line.starts_with("amends \"/")
    }) {
        return Err(FrontendError::at_source(
            "FRONTEND-PATH-ESCAPE",
            "Pkl template escapes the registered corpus root",
            path,
            bytes.len(),
        ));
    }
    let module_lines = source
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("amends ")
                || line.starts_with("import ")
                || line.contains("import(")
                || line.contains("import*(")
        })
        .collect::<Vec<_>>();
    if module_lines != ["amends \"Schema.pkl\""] {
        return Err(FrontendError::at_source(
            "FRONTEND-DEPENDENCY-UNREGISTERED",
            "Pkl source must amend only the registered Schema.pkl module",
            path,
            bytes.len(),
        ));
    }
    Ok(())
}

fn finish_compilation(
    root: &Path,
    frontend: FrontendFlavor,
    mut programme: FrontendProgramme,
    origins: BTreeMap<String, FrontendSourceSpan>,
    mut dependencies: Vec<FrontendDependency>,
    _corpus: &FrontendCorpus,
) -> Result<FrontendCompilation, FrontendError> {
    normalize_and_validate_programme(&mut programme)?;
    let effective_programme = EffectiveProgramme {
        schema: EFFECTIVE_PROGRAMME_SCHEMA.to_owned(),
        programme: programme.clone(),
    };
    let source_map = make_source_map(&programme, &origins)?;
    dependencies.push(FrontendDependency {
        kind: "contract".to_owned(),
        role: "frontend-semantics".to_owned(),
        logical_name: "frontend-grammar".to_owned(),
        identity: domain_hash(
            "proofbound-research-frontend-contract/1",
            FRONTEND_PROGRAMME_SCHEMA.as_bytes(),
        ),
        detail: "GRAMMAR.md revision 1".to_owned(),
    });
    dependencies.sort();
    require_sorted_unique_dependencies(&dependencies)?;
    let receipt = make_receipt(
        frontend.as_str(),
        &programme,
        &effective_programme,
        &source_map,
        &dependencies,
    )?;
    let compilation = FrontendCompilation {
        schema: FRONTEND_COMPILATION_SCHEMA.to_owned(),
        frontend: frontend.as_str().to_owned(),
        programme,
        effective_programme,
        source_map,
        dependencies,
        receipt,
    };
    validate_frontend_compilation(root, &compilation)?;
    Ok(compilation)
}

fn normalize_and_validate_programme(
    programme: &mut FrontendProgramme,
) -> Result<(), FrontendError> {
    if programme.schema != FRONTEND_PROGRAMME_SCHEMA {
        return Err(FrontendError::new(
            "FRONTEND-SYNTAX-UNKNOWN",
            "unknown frontend programme schema",
        ));
    }
    stable_id(&programme.project.id, false)?;
    if !matches!(
        programme.project.ecosystem.as_str(),
        "python" | "typescript" | "rust"
    ) {
        return Err(FrontendError::new(
            "FRONTEND-TYPE-EVIDENCE",
            "unknown project ecosystem",
        ));
    }
    for claim in &mut programme.claims {
        if claim.schema != "proofbound-claim/1" {
            return Err(FrontendError::new(
                "FRONTEND-SYNTAX-UNKNOWN",
                "unknown claim schema",
            ));
        }
        stable_id(&claim.id, true)?;
        bounded_text(&claim.title)?;
        bounded_text(&claim.statement)?;
        bounded_text(&claim.public_language)?;
        bounded_text(&claim.subject)?;
        if claim.tier > 2 {
            return Err(FrontendError::new(
                "FRONTEND-POLICY-CONFLICT",
                "claim tier is outside the registered range",
            ));
        }
        for values in [
            &mut claim.evidence,
            &mut claim.assumptions,
            &mut claim.premises,
            &mut claim.open_obligations,
            &mut claim.out_of_scope,
            &mut claim.source_roots,
            &mut claim.foundational_axioms,
        ] {
            sort_string_set(values)?;
        }
        if claim.source_roots.is_empty() {
            return Err(FrontendError::new(
                "FRONTEND-JOIN-CORRESPONDENCE",
                "claim has no source root",
            ));
        }
    }
    programme
        .claims
        .sort_by(|left, right| left.id.cmp(&right.id));
    unique_by(programme.claims.iter().map(|claim| claim.id.as_str()))?;
    for unit in &mut programme.evidence {
        stable_id(&unit.id, false)?;
        for values in [
            &mut unit.claims,
            &mut unit.assumptions,
            &mut unit.expected_inventory,
            &mut unit.inputs,
            &mut unit.outputs,
            &mut unit.environment_allowlist,
        ] {
            sort_string_set(values)?;
        }
        if unit.expected_inventory.is_empty() || unit.inputs.is_empty() {
            return Err(FrontendError::new(
                "FRONTEND-JOIN-INVENTORY",
                "evidence inventory and inputs must be nonempty",
            ));
        }
        normalize_operation(&mut unit.operation)?;
        validate_evidence_shape(unit)?;
    }
    programme
        .evidence
        .sort_by(|left, right| left.id.cmp(&right.id));
    unique_by(programme.evidence.iter().map(|unit| unit.id.as_str()))?;
    validate_programme_joins(programme)
}

fn normalize_operation(operation: &mut FrontendOperation) -> Result<(), FrontendError> {
    match operation {
        FrontendOperation::Pytest {
            targets,
            paths,
            plugins,
            ..
        } => {
            sort_string_set(targets)?;
            sort_string_set(paths)?;
            sort_string_set(plugins)?;
        }
        FrontendOperation::Vitest => {}
        FrontendOperation::CargoTest { .. } => {}
        FrontendOperation::Kani { targets, .. } => sort_string_set(targets)?,
        FrontendOperation::LeanAudit { targets, paths } => {
            sort_string_set(targets)?;
            sort_string_set(paths)?;
        }
    }
    Ok(())
}

fn validate_evidence_shape(unit: &FrontendEvidence) -> Result<(), FrontendError> {
    let shape_matches = match (unit.adapter.as_str(), unit.kind.as_str(), &unit.operation) {
        ("python-test", "example-test", FrontendOperation::Pytest { .. }) => {
            unit.schema == "proofbound-evidence-unit/1" && unit.property.is_none()
        }
        ("python-test", "property-test", FrontendOperation::Pytest { .. }) => {
            unit.schema == "proofbound-evidence-unit/1"
                && unit.property.as_ref().is_some_and(|property| {
                    property.schema == "proofbound-python-property/1"
                        && property.framework == "hypothesis"
                })
        }
        ("node-test", "example-test" | "property-test", FrontendOperation::Vitest) => {
            unit.schema == "proofbound-evidence-unit/1" && unit.property.is_none()
        }
        ("rust-test", "example-test", FrontendOperation::CargoTest { .. }) => {
            unit.schema == "proofbound-evidence-unit/1" && unit.mutation.is_none()
        }
        ("rust-test", "mutation-witness", FrontendOperation::CargoTest { .. }) => {
            unit.schema == "proofbound-evidence-unit/3"
                && unit
                    .mutation
                    .as_ref()
                    .is_some_and(|mutation| mutation.schema == "proofbound-mutation-replay/1")
                && unit.expected_inventory == [unit.id.clone()]
        }
        ("kani", "bounded-check", FrontendOperation::Kani { targets, .. }) => {
            unit.schema == "proofbound-evidence-unit/1"
                && unit.bounded_domain.is_some()
                && &unit.expected_inventory == targets
        }
        ("lean", "theorem", FrontendOperation::LeanAudit { targets, .. }) => {
            unit.schema == "proofbound-evidence-unit/1"
                && unit.property.is_none()
                && unit.bounded_domain.is_none()
                && unit.mutation.is_none()
                && unit.evaluation_mode.as_deref() == Some("kernel")
                && unit.theorem.as_ref().is_some_and(|theorem| {
                    targets == std::slice::from_ref(theorem)
                        && unit.expected_inventory.contains(theorem)
                })
        }
        _ => false,
    };
    if !shape_matches {
        return Err(FrontendError::new(
            "FRONTEND-TYPE-EVIDENCE",
            "evidence constructor, adapter, kind, schema, operation, or detail disagree",
        ));
    }
    if let FrontendOperation::Pytest { targets, .. } = &unit.operation {
        let inventory_targets = unit
            .expected_inventory
            .iter()
            .map(|item| item.rsplit("::").next().unwrap_or(item))
            .collect::<Vec<_>>();
        if inventory_targets != targets.iter().map(String::as_str).collect::<Vec<_>>() {
            return Err(FrontendError::new(
                "FRONTEND-JOIN-INVENTORY",
                "pytest target inventory does not match operation targets",
            ));
        }
    }
    let allowed = match unit.adapter.as_str() {
        "python-test" | "node-test" => &["PATH"][..],
        "rust-test" | "kani" => &["CARGO_HOME", "PATH", "RUSTUP_HOME"][..],
        "lean" => &["LEAN_PATH", "PATH"][..],
        _ => &[][..],
    };
    if unit
        .environment_allowlist
        .iter()
        .any(|name| !allowed.contains(&name.as_str()))
    {
        return Err(FrontendError::new(
            "FRONTEND-AUTHORITY-UNDECLARED",
            "evidence requests undeclared frontend authority",
        ));
    }
    if unit.resource_budget.time_seconds == 0 || unit.resource_budget.disk_bytes == 0 {
        return Err(FrontendError::new(
            "FRONTEND-POLICY-CONFLICT",
            "resource budget must be positive",
        ));
    }
    Ok(())
}

fn validate_programme_joins(programme: &FrontendProgramme) -> Result<(), FrontendError> {
    let claims = programme
        .claims
        .iter()
        .map(|claim| (claim.id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    for unit in &programme.evidence {
        let present = unit
            .claims
            .iter()
            .filter_map(|id| claims.get(id.as_str()).copied())
            .collect::<Vec<_>>();
        if present.is_empty() {
            if unit.claims.iter().any(|id| {
                claims
                    .keys()
                    .any(|known| known.eq_ignore_ascii_case(id.as_str()))
            }) {
                return Err(FrontendError::new(
                    "FRONTEND-ID-ALIAS",
                    "claim reference uses a noncanonical alias",
                ));
            }
            return Err(FrontendError::new(
                "FRONTEND-JOIN-CORRESPONDENCE",
                "evidence has no claim in the selected programme",
            ));
        }
        let reference = format!("{}:{}", unit.kind, unit.id);
        for claim in &present {
            if !claim.evidence.contains(&reference) {
                return Err(FrontendError::new(
                    "FRONTEND-JOIN-CORRESPONDENCE",
                    "claim does not cite attributed evidence",
                ));
            }
            if unit.tier > claim.tier {
                return Err(FrontendError::new(
                    "FRONTEND-POLICY-CONFLICT",
                    "evidence tier exceeds the claim ceiling",
                ));
            }
            if unit
                .assumptions
                .iter()
                .any(|assumption| !claim.assumptions.contains(assumption))
            {
                return Err(FrontendError::new(
                    "FRONTEND-JOIN-ASSUMPTION",
                    "evidence names an assumption not owned by its claim",
                ));
            }
            if unit.kind == "theorem"
                && (claim.formal_declaration.as_deref() != unit.theorem.as_deref()
                    || claim.statement_encoding.is_none()
                    || claim.statement_sha256.is_none())
            {
                return Err(FrontendError::new(
                    "FRONTEND-JOIN-CORRESPONDENCE",
                    "theorem lacks exact claim statement correspondence",
                ));
            }
        }
    }
    Ok(())
}

fn sort_string_set(values: &mut Vec<String>) -> Result<(), FrontendError> {
    for value in values.iter() {
        bounded_text(value)?;
    }
    let before = values.len();
    values.sort();
    values.dedup();
    if values.len() != before {
        return Err(FrontendError::new(
            "FRONTEND-SET-DUPLICATE",
            "semantic set contains a duplicate",
        ));
    }
    Ok(())
}

fn unique_by<'a>(values: impl Iterator<Item = &'a str>) -> Result<(), FrontendError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(FrontendError::new(
                "FRONTEND-ID-ALIAS",
                "duplicate stable ID",
            ));
        }
    }
    Ok(())
}

fn stable_id(value: &str, uppercase: bool) -> Result<(), FrontendError> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(FrontendError::new("FRONTEND-ID-ALIAS", "empty stable ID"));
    };
    let first_valid = if uppercase {
        first.is_ascii_uppercase()
    } else {
        first.is_ascii_lowercase()
    };
    let rest_valid = if uppercase {
        chars.all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '-'
        })
    } else {
        chars.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    };
    if !first_valid || value.len() > 128 || !rest_valid {
        return Err(FrontendError::new(
            "FRONTEND-ID-ALIAS",
            "stable ID is not canonical",
        ));
    }
    Ok(())
}

fn bounded_text(value: &str) -> Result<(), FrontendError> {
    if value.trim().is_empty()
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(FrontendError::new(
            "FRONTEND-SYNTAX-UNKNOWN",
            "semantic text is blank, oversized, or contains control characters",
        ));
    }
    Ok(())
}

fn make_source_map(
    programme: &FrontendProgramme,
    origins: &BTreeMap<String, FrontendSourceSpan>,
) -> Result<FrontendSourceMap, FrontendError> {
    let mut entries = Vec::new();
    for leaf in semantic_leaves(programme)? {
        let origin_key = if leaf == "/schema" || leaf.starts_with("/project/") {
            "programme".to_owned()
        } else if let Some(rest) = leaf.strip_prefix("/claims/") {
            format!("claim:{}", rest.split('/').next().unwrap_or_default())
        } else if let Some(rest) = leaf.strip_prefix("/evidence/") {
            format!("evidence:{}", rest.split('/').next().unwrap_or_default())
        } else {
            return Err(FrontendError::new(
                "FRONTEND-MAP-LEAF",
                "unknown semantic leaf",
            ));
        };
        let source = origins.get(&origin_key).cloned().ok_or_else(|| {
            FrontendError::new(
                "FRONTEND-MAP-MISSING",
                format!("semantic leaf {leaf} has no source origin"),
            )
        })?;
        entries.push(FrontendSourceMapEntry { leaf, source });
    }
    entries.sort();
    let identity = domain_hash(
        SOURCE_MAP_DOMAIN,
        &canonical_json(&entries)
            .map_err(|error| FrontendError::new("FRONTEND-MAP-LEAF", error.to_string()))?,
    );
    Ok(FrontendSourceMap {
        schema: SOURCE_MAP_SCHEMA.to_owned(),
        entries,
        identity,
    })
}

fn validate_source_map(
    root: &Path,
    frontend: FrontendFlavor,
    programme: &FrontendProgramme,
    source_map: &FrontendSourceMap,
    dependencies: &[FrontendDependency],
) -> Result<(), FrontendError> {
    if source_map.schema != SOURCE_MAP_SCHEMA {
        return Err(FrontendError::new(
            "FRONTEND-MAP-LEAF",
            "unknown source-map schema",
        ));
    }
    let leaves = semantic_leaves(programme)?;
    let mapped = source_map
        .entries
        .iter()
        .map(|entry| entry.leaf.clone())
        .collect::<Vec<_>>();
    if mapped.len() != mapped.iter().collect::<BTreeSet<_>>().len() {
        return Err(FrontendError::new(
            "FRONTEND-MAP-OVERLAP",
            "a semantic leaf has multiple source-map entries",
        ));
    }
    if mapped.len() < leaves.len() {
        return Err(FrontendError::new(
            "FRONTEND-MAP-MISSING",
            "source map omits a semantic leaf",
        ));
    }
    if mapped != leaves {
        return Err(FrontendError::new(
            "FRONTEND-MAP-LEAF",
            "source-map leaves differ from the programme",
        ));
    }
    if source_map.entries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(FrontendError::new(
            "FRONTEND-NONCANONICAL",
            "source-map entries are not strictly sorted",
        ));
    }
    let source_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.kind == "artifact" && dependency.role == "frontend-source")
        .map(|dependency| {
            (
                dependency.logical_name.as_str(),
                dependency.identity.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let dsl_sources = source_dependencies
        .keys()
        .filter(|path| path.ends_with(".pb"))
        .copied()
        .collect::<Vec<_>>();
    let pkl_schema = source_dependencies
        .keys()
        .find(|path| path.ends_with("/Schema.pkl"))
        .copied();
    let pkl_programmes = source_dependencies
        .keys()
        .filter(|path| path.ends_with(".pkl") && !path.ends_with("/Schema.pkl"))
        .copied()
        .collect::<Vec<_>>();
    for entry in &source_map.entries {
        let Some(dependency_identity) = source_dependencies.get(entry.source.path.as_str()) else {
            return Err(FrontendError::new(
                "FRONTEND-MAP-FILE",
                "source-map file is not a bound frontend dependency",
            ));
        };
        if *dependency_identity != entry.source.sha256 {
            return Err(FrontendError::new(
                "FRONTEND-MAP-FILE",
                "source-map identity differs from its bound dependency",
            ));
        }
        let expected_path = match frontend {
            FrontendFlavor::ProofboundDsl => {
                if dsl_sources.len() != 1 {
                    return Err(FrontendError::new(
                        "FRONTEND-MAP-FILE",
                        "DSL compilation must bind exactly one source",
                    ));
                }
                dsl_sources[0]
            }
            FrontendFlavor::Pkl => {
                if pkl_programmes.len() != 1 || pkl_schema.is_none() {
                    return Err(FrontendError::new(
                        "FRONTEND-MAP-FILE",
                        "Pkl compilation must bind one programme and one schema",
                    ));
                }
                if entry.leaf == "/schema" || entry.leaf.starts_with("/project/") {
                    pkl_schema.expect("checked above")
                } else {
                    pkl_programmes[0]
                }
            }
            FrontendFlavor::Toml => {
                if entry.leaf == "/schema" || entry.leaf.starts_with("/project/") {
                    source_dependencies
                        .keys()
                        .find(|path| path.ends_with("/subjects.json"))
                        .copied()
                        .ok_or_else(|| {
                            FrontendError::new(
                                "FRONTEND-MAP-FILE",
                                "TOML compilation lacks its corpus index dependency",
                            )
                        })?
                } else {
                    let id = entry.leaf.split('/').nth(2).ok_or_else(|| {
                        FrontendError::new("FRONTEND-MAP-LEAF", "invalid semantic leaf")
                    })?;
                    source_dependencies
                        .keys()
                        .find(|path| {
                            Path::new(path)
                                .file_stem()
                                .is_some_and(|stem| stem == std::ffi::OsStr::new(id))
                        })
                        .copied()
                        .ok_or_else(|| {
                            FrontendError::new(
                                "FRONTEND-MAP-FILE",
                                "TOML semantic record has no matching source dependency",
                            )
                        })?
                }
            }
        };
        if entry.source.path != expected_path {
            return Err(FrontendError::new(
                "FRONTEND-MAP-FILE",
                "source-map leaf is attributed to the wrong registered source",
            ));
        }
        let bytes = fs::read(root.join(&entry.source.path)).map_err(|_| {
            FrontendError::new("FRONTEND-MAP-FILE", "source-map file cannot be read")
        })?;
        if sha256_bytes(&bytes) != entry.source.sha256 {
            return Err(FrontendError::new(
                "FRONTEND-MAP-FILE",
                "source-map file identity changed",
            ));
        }
        if entry.source.start >= entry.source.end || entry.source.end > bytes.len() as u64 {
            return Err(FrontendError::new(
                "FRONTEND-MAP-SPAN",
                "source-map span is empty or outside the source",
            ));
        }
    }
    let identity = domain_hash(
        SOURCE_MAP_DOMAIN,
        &canonical_json(&source_map.entries)
            .map_err(|error| FrontendError::new("FRONTEND-MAP-LEAF", error.to_string()))?,
    );
    if source_map.identity != identity {
        return Err(FrontendError::new(
            "FRONTEND-MAP-LEAF",
            "source-map identity does not match its entries",
        ));
    }
    Ok(())
}

fn semantic_leaves(programme: &FrontendProgramme) -> Result<Vec<String>, FrontendError> {
    let value = serde_json::to_value(programme)
        .map_err(|error| FrontendError::new("FRONTEND-MAP-LEAF", error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| FrontendError::new("FRONTEND-MAP-LEAF", "programme is not an object"))?;
    let mut leaves = vec!["/schema".to_owned()];
    let project = object
        .get("project")
        .and_then(Value::as_object)
        .ok_or_else(|| FrontendError::new("FRONTEND-MAP-LEAF", "project is missing"))?;
    leaves.extend(project.keys().map(|key| format!("/project/{key}")));
    for claim in &programme.claims {
        extend_record_leaves(&mut leaves, "claims", &claim.id, claim)?;
    }
    for unit in &programme.evidence {
        extend_record_leaves(&mut leaves, "evidence", &unit.id, unit)?;
    }
    leaves.sort();
    Ok(leaves)
}

fn extend_record_leaves<T: Serialize>(
    leaves: &mut Vec<String>,
    collection: &str,
    id: &str,
    value: &T,
) -> Result<(), FrontendError> {
    let encoded = serde_json::to_value(value)
        .map_err(|error| FrontendError::new("FRONTEND-MAP-LEAF", error.to_string()))?;
    let record = encoded
        .as_object()
        .ok_or_else(|| FrontendError::new("FRONTEND-MAP-LEAF", "record is not an object"))?;
    leaves.extend(record.keys().map(|key| format!("/{collection}/{id}/{key}")));
    Ok(())
}

fn programme_origins(
    programme: &FrontendProgramme,
    span: &FrontendSourceSpan,
) -> BTreeMap<String, FrontendSourceSpan> {
    let mut origins = BTreeMap::from([("programme".to_owned(), span.clone())]);
    origins.extend(
        programme
            .claims
            .iter()
            .map(|claim| (format!("claim:{}", claim.id), span.clone())),
    );
    origins.extend(
        programme
            .evidence
            .iter()
            .map(|unit| (format!("evidence:{}", unit.id), span.clone())),
    );
    origins
}

fn make_receipt(
    frontend: &str,
    programme: &FrontendProgramme,
    effective: &EffectiveProgramme,
    source_map: &FrontendSourceMap,
    dependencies: &[FrontendDependency],
) -> Result<FrontendReceipt, FrontendError> {
    let programme_sha256 = domain_hash(
        PROGRAMME_DOMAIN,
        &canonical_json(programme)
            .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?,
    );
    let effective_programme_sha256 = domain_hash(
        EFFECTIVE_DOMAIN,
        &canonical_json(effective)
            .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?,
    );
    let source_map_sha256 = source_map.identity.clone();
    let dependencies_sha256 = domain_hash(
        DEPENDENCIES_DOMAIN,
        &canonical_json(&dependencies)
            .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?,
    );
    let mut receipt = FrontendReceipt {
        schema: FRONTEND_RECEIPT_SCHEMA.to_owned(),
        project: programme.project.id.clone(),
        frontend: frontend.to_owned(),
        programme_sha256,
        effective_programme_sha256,
        source_map_sha256,
        dependencies_sha256,
        identity: String::new(),
    };
    receipt.identity = receipt_identity(&receipt)?;
    Ok(receipt)
}

fn receipt_identity(receipt: &FrontendReceipt) -> Result<String, FrontendError> {
    let material = serde_json::json!({
        "schema": receipt.schema,
        "project": receipt.project,
        "frontend": receipt.frontend,
        "programme_sha256": receipt.programme_sha256,
        "effective_programme_sha256": receipt.effective_programme_sha256,
        "source_map_sha256": receipt.source_map_sha256,
        "dependencies_sha256": receipt.dependencies_sha256,
    });
    Ok(domain_hash(
        RECEIPT_DOMAIN,
        &canonical_json(&material)
            .map_err(|error| FrontendError::new("FRONTEND-SYNTAX-UNKNOWN", error.to_string()))?,
    ))
}

fn require_sorted_unique_dependencies(
    dependencies: &[FrontendDependency],
) -> Result<(), FrontendError> {
    if dependencies.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(FrontendError::new(
            "FRONTEND-NONCANONICAL",
            "frontend dependencies are not strictly sorted",
        ));
    }
    Ok(())
}

fn source_span(path: &str, bytes: &[u8]) -> FrontendSourceSpan {
    FrontendSourceSpan {
        path: path.to_owned(),
        sha256: sha256_bytes(bytes),
        start: 0,
        end: bytes.len().max(1) as u64,
    }
}

fn source_dependency(path: &str, bytes: &[u8]) -> FrontendDependency {
    FrontendDependency {
        kind: "artifact".to_owned(),
        role: "frontend-source".to_owned(),
        logical_name: path.to_owned(),
        identity: sha256_bytes(bytes),
        detail: format!("{} bytes", bytes.len()),
    }
}

fn relative_path(root: &Path, path: &Path) -> Result<String, FrontendError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    absolute
        .strip_prefix(root)
        .map(|relative| relative.to_string_lossy().into_owned())
        .map_err(|_| {
            FrontendError::new(
                "FRONTEND-PATH-ESCAPE",
                "frontend path escapes the repository root",
            )
        })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};

    use super::*;

    const CORPUS: &str = "docs/experiments/0011-dual-frontend-equivalence/corpus/subjects.json";
    const SUBJECTS: [&str; 3] = ["python-inventory", "typescript-codec", "rust-allowance"];

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root")
    }

    fn compile_all(subject: &str) -> [FrontendCompilation; 3] {
        let repository = root();
        let corpus = Path::new(CORPUS);
        let toml = compile_toml_frontend(&repository, corpus, subject).expect("TOML frontend");
        let dsl = compile_dsl_frontend(&repository, corpus, subject).expect("DSL frontend");
        let rendered = canonical_json(&dsl.programme).expect("rendered Pkl fixture");
        let pkl = compile_pkl_frontend_with_identity(
            &repository,
            corpus,
            subject,
            &rendered,
            REGISTERED_PKL_SHA256,
        )
        .expect("Pkl frontend");
        [toml, dsl, pkl]
    }

    fn error_code<T: std::fmt::Debug>(result: Result<T, FrontendError>) -> &'static str {
        result.expect_err("attack must reject").code
    }

    fn reseal(compilation: &mut FrontendCompilation) {
        compilation.source_map.identity = domain_hash(
            SOURCE_MAP_DOMAIN,
            &canonical_json(&compilation.source_map.entries).expect("source map"),
        );
        compilation.receipt = make_receipt(
            &compilation.frontend,
            &compilation.programme,
            &compilation.effective_programme,
            &compilation.source_map,
            &compilation.dependencies,
        )
        .expect("receipt");
    }

    #[test]
    fn all_frontends_emit_the_same_programme_and_effective_meaning() {
        let expected_actual = BTreeMap::from([
            (
                "python-inventory",
                "sha256:6c8acad7f1c5bbbfc6aa22fb585967d729d6320ae8b0437a7d78fa7b04fb8a70",
            ),
            (
                "typescript-codec",
                "sha256:61235f3f7df9d68f9b99b88b3d986e4cc1e6f24f9bd40710f29967187e3afc39",
            ),
            (
                "rust-allowance",
                "sha256:e23b5451b4381b6ac829ff9807084eeb44a1c64a4faab7705d5cf6d98d19005a",
            ),
        ]);
        for subject in SUBJECTS {
            let [toml, dsl, pkl] = compile_all(subject);
            assert_eq!(toml.programme, dsl.programme, "{subject}");
            assert_eq!(dsl.programme, pkl.programme, "{subject}");
            assert_eq!(
                toml.effective_programme, dsl.effective_programme,
                "{subject}"
            );
            assert_eq!(
                dsl.effective_programme, pkl.effective_programme,
                "{subject}"
            );
            for compilation in [&toml, &dsl, &pkl] {
                validate_frontend_compilation(&root(), compilation).expect("valid compilation");
                let bytes = canonical_json(compilation).expect("canonical compilation");
                assert_eq!(
                    validate_frontend_compilation_bytes(&root(), &bytes)
                        .expect("valid canonical compilation"),
                    *compilation
                );
            }
            assert_ne!(toml.receipt, dsl.receipt);
            assert_ne!(dsl.receipt, pkl.receipt);
            let control = compare_frontend_programme_control(
                &root(),
                Path::new(CORPUS),
                subject,
                &toml.programme,
            )
            .expect("frozen control comparison");
            assert_eq!(control.expected_bytes, control.actual_bytes);
            assert_eq!(
                control.actual_identity, expected_actual[subject],
                "actual identity changed"
            );
            assert!(!control.matches, "frozen identity unexpectedly matched");
        }
    }

    #[test]
    fn dsl_formatter_is_byte_idempotent_for_the_frozen_corpus() {
        let repository = root();
        let corpus: FrontendCorpus =
            serde_json::from_slice(&fs::read(repository.join(CORPUS)).expect("corpus index"))
                .expect("corpus");
        for subject in corpus.subjects {
            let source = subject.frontends.get("proofbound-dsl").expect("DSL source");
            let bytes = fs::read(repository.join(&source.path)).expect("DSL bytes");
            let once = format_dsl_frontend(&bytes, Path::new(&source.path)).expect("format");
            let twice = format_dsl_frontend(&once, Path::new(&source.path)).expect("reformat");
            assert_eq!(once, twice);
        }
    }

    #[test]
    fn semantic_attacks_reject_with_the_registered_codes() {
        let mut sampled = compile_all("python-inventory")[1].programme.clone();
        let unit = sampled
            .evidence
            .iter_mut()
            .find(|unit| unit.kind == "property-test")
            .expect("property");
        unit.adapter = "lean".to_owned();
        unit.kind = "theorem".to_owned();
        unit.operation = FrontendOperation::LeanAudit {
            targets: unit.expected_inventory.clone(),
            paths: vec!["Proofbound.lean".to_owned()],
        };
        unit.evaluation_mode = Some("kernel".to_owned());
        unit.theorem = unit.expected_inventory.first().cloned();
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut sampled)),
            "FRONTEND-TYPE-EVIDENCE"
        );

        let mut theorem = compile_all("rust-allowance")[1].programme.clone();
        theorem.claims[0].formal_declaration = None;
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut theorem)),
            "FRONTEND-JOIN-CORRESPONDENCE"
        );

        let mut duplicate = compile_all("python-inventory")[0].programme.clone();
        let repeated = duplicate.evidence[0].expected_inventory[0].clone();
        duplicate.evidence[0].expected_inventory.push(repeated);
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut duplicate)),
            "FRONTEND-SET-DUPLICATE"
        );

        let mut partial = compile_all("python-inventory")[1].programme.clone();
        let unit = partial
            .evidence
            .iter_mut()
            .find(|unit| unit.kind == "property-test")
            .expect("property");
        if let FrontendOperation::Pytest { targets, .. } = &mut unit.operation {
            targets[0] = "substituted_test".to_owned();
        }
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut partial)),
            "FRONTEND-JOIN-INVENTORY"
        );

        let mut assumption = compile_all("python-inventory")[1].programme.clone();
        assumption.evidence[0]
            .assumptions
            .push("UNOWNED-001".to_owned());
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut assumption)),
            "FRONTEND-JOIN-ASSUMPTION"
        );

        let mut tier = compile_all("typescript-codec")[0].programme.clone();
        tier.evidence[0].tier = tier.claims[0].tier + 1;
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut tier)),
            "FRONTEND-POLICY-CONFLICT"
        );

        let mut authority = compile_all("rust-allowance")[1].programme.clone();
        authority.evidence[0]
            .environment_allowlist
            .push("NETWORK".to_owned());
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut authority)),
            "FRONTEND-AUTHORITY-UNDECLARED"
        );

        let mut alias = compile_all("typescript-codec")[2].programme.clone();
        alias.evidence[0].claims[0] = alias.evidence[0].claims[0].to_ascii_lowercase();
        assert_eq!(
            error_code(normalize_and_validate_programme(&mut alias)),
            "FRONTEND-ID-ALIAS"
        );

        let mut noncanonical = compile_all("rust-allowance")[0].clone();
        noncanonical.programme.evidence.reverse();
        assert_eq!(
            error_code(validate_frontend_compilation(&root(), &noncanonical)),
            "FRONTEND-NONCANONICAL"
        );
    }

    #[test]
    fn syntax_and_pkl_authority_attacks_have_source_spans() {
        let repository = root();
        let source_path = repository
            .join("docs/experiments/0011-dual-frontend-equivalence/corpus/python-inventory.pb");
        let source = fs::read_to_string(&source_path).expect("DSL");
        let changed = source.replacen(
            "source_roots = [\"src/inventory_service/reservations.py\"]",
            "source_roots = [\"src/inventory_service/reservations.py\"]\nexecutable_status = true",
            1,
        );
        let error = parse_dsl(changed.as_bytes(), &source_path).expect_err("unknown field");
        assert_eq!(error.code, "FRONTEND-SYNTAX-UNKNOWN");
        assert!(error.path.is_some());
        assert!(error.end.expect("end") > error.start.expect("start"));

        for (source, code) in [
            (
                "amends \"Schema.pkl\"\nlocal x = read(\"env:HOME\")\n",
                "FRONTEND-PKL-RESOURCE",
            ),
            (
                "amends \"Schema.pkl\"\nimport \"https://example.test/x.pkl\"\n",
                "FRONTEND-PKL-MODULE",
            ),
            ("amends \"../Schema.pkl\"\n", "FRONTEND-PATH-ESCAPE"),
            (
                "amends \"Schema.pkl\"\nimport \"other.pkl\"\n",
                "FRONTEND-DEPENDENCY-UNREGISTERED",
            ),
        ] {
            let error = preflight_pkl_source(source.as_bytes(), Path::new("attack.pkl"))
                .expect_err("Pkl attack");
            assert_eq!(error.code, code);
            assert_eq!(error.path.as_deref(), Some("attack.pkl"));
            assert!(error.end.expect("end") > error.start.expect("start"));
        }

        let dsl =
            compile_dsl_frontend(&repository, Path::new(CORPUS), "typescript-codec").expect("DSL");
        let rendered = canonical_json(&dsl.programme).expect("rendered");
        assert_eq!(
            error_code(compile_pkl_frontend_with_identity(
                &repository,
                Path::new(CORPUS),
                "typescript-codec",
                &rendered,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )),
            "FRONTEND-TOOL-SUBSTITUTION"
        );
    }

    #[test]
    fn registered_dependency_drift_rejects_before_parsing() {
        let directory = tempfile::tempdir().expect("temporary root");
        let path = directory.path().join("source.pb");
        fs::write(&path, b"programme\n").expect("write source");
        let registered = RegisteredSource {
            path: "source.pb".to_owned(),
            sha256: "00".repeat(32),
        };
        let error = read_registered(directory.path(), &registered).expect_err("drift");
        assert_eq!(error.code, "FRONTEND-DEPENDENCY-DRIFT");
        assert!(error.end.expect("end") > error.start.expect("start"));
    }

    #[test]
    fn source_map_and_effective_programme_attacks_reject_exactly() {
        let repository = root();
        let mut missing = compile_all("python-inventory")[1].clone();
        missing.source_map.entries.pop();
        assert_eq!(
            error_code(validate_frontend_compilation(&repository, &missing)),
            "FRONTEND-MAP-MISSING"
        );

        let mut overlap = compile_all("python-inventory")[1].clone();
        overlap
            .source_map
            .entries
            .push(overlap.source_map.entries[0].clone());
        overlap.source_map.entries.sort();
        assert_eq!(
            error_code(validate_frontend_compilation(&repository, &overlap)),
            "FRONTEND-MAP-OVERLAP"
        );

        let mut file = compile_all("typescript-codec")[0].clone();
        let replacement = file
            .dependencies
            .iter()
            .find(|dependency| {
                dependency.kind == "artifact"
                    && dependency.logical_name.ends_with("reject-padding.toml")
            })
            .expect("replacement")
            .clone();
        let entry = file
            .source_map
            .entries
            .iter_mut()
            .find(|entry| entry.leaf.starts_with("/claims/"))
            .expect("claim entry");
        entry.source.path = replacement.logical_name;
        entry.source.sha256 = replacement.identity;
        entry.source.end = fs::metadata(repository.join(&entry.source.path))
            .expect("replacement metadata")
            .len();
        reseal(&mut file);
        assert_eq!(
            error_code(validate_frontend_compilation(&repository, &file)),
            "FRONTEND-MAP-FILE"
        );

        let mut span = compile_all("typescript-codec")[1].clone();
        span.source_map.entries[0].source.end = u64::MAX;
        reseal(&mut span);
        assert_eq!(
            error_code(validate_frontend_compilation(&repository, &span)),
            "FRONTEND-MAP-SPAN"
        );

        let mut leaf = compile_all("rust-allowance")[1].clone();
        leaf.source_map.entries[0].leaf = "/unknown".to_owned();
        leaf.source_map.entries.sort();
        reseal(&mut leaf);
        assert_eq!(
            error_code(validate_frontend_compilation(&repository, &leaf)),
            "FRONTEND-MAP-LEAF"
        );

        let effective = &compile_all("rust-allowance")[1].effective_programme;
        let pretty = serde_json::to_vec_pretty(effective).expect("pretty effective programme");
        assert_ne!(
            pretty,
            canonical_json(effective).expect("canonical effective")
        );
        assert_eq!(
            error_code(validate_effective_programme_bytes(&pretty)),
            "FRONTEND-EFFECTIVE-NONCANONICAL"
        );
    }

    #[test]
    fn stable_ids_do_not_admit_case_aliases() {
        assert_eq!(error_code(stable_id("PY-lower", true)), "FRONTEND-ID-ALIAS");
        assert_eq!(
            error_code(stable_id("unit-UPPER", false)),
            "FRONTEND-ID-ALIAS"
        );
        stable_id("PY-RESERVATION-001", true).expect("claim ID");
        stable_id("reservation-example", false).expect("unit ID");
    }

    #[test]
    fn source_dependency_identity_is_the_registered_file_identity() {
        let bytes = b"source";
        let dependency = source_dependency("source.pb", bytes);
        assert_eq!(dependency.identity, sha256_bytes(bytes));
    }
}
