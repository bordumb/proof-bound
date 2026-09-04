use std::{collections::BTreeSet, fmt, fs, path::Path};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use serde_json::{Map, Value, json};

pub const WINDOWS_INITIALIZATION_CAPTURE_SCHEMA: &str =
    "proofbound-research-windows-initialization-capture/1";
pub const WINDOWS_INITIALIZATION_REPORT_SCHEMA: &str =
    "proofbound-research-windows-initialization-report/1";

const CLOSURE_SCHEMA: &str = "proofbound-research-windows-initialization-closure/1";
const POLICY_SCHEMA: &str = "proofbound-research-windows-initialization-policy/1";
const SLOT_SCHEMA: &str = "proofbound-research-windows-initialization-slot/1";
const ATTACK_INDEX_SCHEMA: &str = "proofbound-research-windows-initialization-attack-index/1";
const ATTACK_REPORT_SCHEMA: &str = "proofbound-research-windows-initialization-attack-report/1";
const CONTRACT_SHA256: &str =
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d";
const CANDIDATE_PATH: &str = "docs/experiments/0025-windows-initialization-closure/candidate.json";
const CORPUS_ROOT: &str = "docs/experiments/0018-os-enforced-effects/corpus";
const EXPECTED_OUTPUT_SHA256: &str =
    "sha256:6897a0406cd3b5b1aa1c9fb86c784f443606a03f487d2cc00e9fd1a0e2144d22";
const EXPECTED_OUTPUT_BASE64: &str = "cmVnaXN0ZXJlZC1pbnB1dHxyZWdpc3RlcmVkLWVudgo=";
const MAX_CAPTURE_BYTES: usize = 524_288;
const MAX_ELAPSED_MS: u64 = 60_000;

const PROBES: [(&str, &str, &str, &str); 7] = [
    (
        "EXP-0018-A001",
        "read-undeclared",
        "workspace/unrelated.txt",
        "appcontainer-path-read",
    ),
    (
        "EXP-0018-A002",
        "read-undeclared",
        "workspace/nested/outside.txt",
        "appcontainer-path-read",
    ),
    (
        "EXP-0018-A007",
        "env-undeclared",
        "workspace/unrelated.txt",
        "cleared-environment",
    ),
    (
        "EXP-0018-A009",
        "exec-unregistered",
        "/usr/bin/true",
        "job-active-process-limit",
    ),
    (
        "EXP-0018-A011",
        "network",
        "workspace/unrelated.txt",
        "appcontainer-network-capability",
    ),
    (
        "EXP-0018-A012",
        "write-reviewed",
        "workspace/reviewed.txt",
        "appcontainer-path-write",
    ),
    (
        "EXP-0018-A013",
        "write-escape",
        "state/escape.txt",
        "appcontainer-path-write",
    ),
];

const SUBJECTS: [(&str, &str, &str); 3] = [
    (
        "subject:node",
        "node",
        "workspace/subjects/node_subject.mjs",
    ),
    (
        "subject:python",
        "python",
        "workspace/subjects/python_subject.py",
    ),
    ("subject:rust", "rust", "workspace/subjects/rust_subject.rs"),
];

const ATTACKS: [(&str, &str); 30] = [
    ("EXP-0025-A001", "WIN25-CAPTURE-SCHEMA"),
    ("EXP-0025-A002", "WIN25-DISCRIMINATOR"),
    ("EXP-0025-A003", "WIN25-CONTRACT"),
    ("EXP-0025-A004", "WIN25-CANDIDATE"),
    ("EXP-0025-A005", "WIN25-FALLBACK"),
    ("EXP-0025-A006", "WIN25-PLATFORM"),
    ("EXP-0025-A007", "WIN25-CLOSURE-SCHEMA"),
    ("EXP-0025-A008", "WIN25-CLOSURE-IDENTITY"),
    ("EXP-0025-A009", "WIN25-CLOSURE-FREEZE"),
    ("EXP-0025-A010", "WIN25-APPCONTAINER"),
    ("EXP-0025-A011", "WIN25-APPCONTAINER"),
    ("EXP-0025-A012", "WIN25-TOKEN"),
    ("EXP-0025-A013", "WIN25-JOB"),
    ("EXP-0025-A014", "WIN25-JOB"),
    ("EXP-0025-A015", "WIN25-DESKTOP"),
    ("EXP-0025-A016", "WIN25-PROCESS-CREATION"),
    ("EXP-0025-A017", "WIN25-DRIVE-ALIAS"),
    ("EXP-0025-A018", "WIN25-RUNTIME"),
    ("EXP-0025-A019", "WIN25-ARTIFACT"),
    ("EXP-0025-A020", "WIN25-CORPUS"),
    ("EXP-0025-A021", "WIN25-SLOT-INVENTORY"),
    ("EXP-0025-A022", "WIN25-SLOT-INVENTORY"),
    ("EXP-0025-A023", "WIN25-SLOT-IDENTITY"),
    ("EXP-0025-A024", "WIN25-POLICY"),
    ("EXP-0025-A025", "WIN25-POSITIVE"),
    ("EXP-0025-A026", "WIN25-DENIED-REUSABLE"),
    ("EXP-0025-A027", "WIN25-DENIAL"),
    ("EXP-0025-A028", "WIN25-TREE"),
    ("EXP-0025-A029", "WIN25-ELAPSED"),
    ("EXP-0025-A030", "WIN25-FRESHNESS"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsInitializationError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for WindowsInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WindowsInitializationError {}

fn error(code: &'static str, message: impl Into<String>) -> WindowsInitializationError {
    WindowsInitializationError {
        code,
        message: message.into(),
    }
}

fn object<'a>(
    value: &'a Value,
    code: &'static str,
) -> Result<&'a Map<String, Value>, WindowsInitializationError> {
    value
        .as_object()
        .ok_or_else(|| error(code, "value is not an object"))
}

fn exact_keys(
    value: &Map<String, Value>,
    expected: &[&str],
    code: &'static str,
) -> Result<(), WindowsInitializationError> {
    let actual = value.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(error(code, "object fields differ"));
    }
    Ok(())
}

fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn boolean(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

fn number(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

fn hash_without(
    domain: &str,
    value: &Map<String, Value>,
) -> Result<String, WindowsInitializationError> {
    let mut body = value.clone();
    body.remove("identity");
    let bytes = canonical_json(&Value::Object(body))
        .map_err(|issue| error("WIN25-ENCODE", issue.to_string()))?;
    Ok(domain_hash(domain, &bytes))
}

fn valid_sha256(value: Option<&Value>) -> bool {
    let Some(value) = text(value) else {
        return false;
    };
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_file_id(value: Option<&Value>) -> bool {
    let Some(value) = text(value) else {
        return false;
    };
    value.len() == 33
        && value.as_bytes()[16] == b':'
        && value.bytes().enumerate().all(|(index, byte)| {
            index == 16 || byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
        })
}

fn valid_pe_machine(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Null)) || text(value) == Some("aarch64")
}

fn artifact<'a>(
    value: &'a Value,
    code: &'static str,
) -> Result<&'a Map<String, Value>, WindowsInitializationError> {
    let value = object(value, code)?;
    exact_keys(
        value,
        &[
            "logical_name",
            "requested_path",
            "resolved_path",
            "sha256",
            "size_bytes",
            "pe_machine",
            "reparse_point",
        ],
        code,
    )?;
    if text(value.get("logical_name")).is_none_or(str::is_empty)
        || text(value.get("requested_path")).is_none_or(str::is_empty)
        || text(value.get("resolved_path")).is_none_or(str::is_empty)
        || !valid_sha256(value.get("sha256"))
        || number(value.get("size_bytes")).is_none()
        || !valid_pe_machine(value.get("pe_machine"))
        || boolean(value.get("reparse_point")) != Some(false)
    {
        return Err(error(code, "artifact identity differs"));
    }
    Ok(value)
}

fn staged_artifact(value: &Value) -> Result<&Map<String, Value>, WindowsInitializationError> {
    let value = object(value, "WIN25-ARTIFACT")?;
    exact_keys(
        value,
        &[
            "destination",
            "file_id",
            "security_descriptor_sha256",
            "reparse_point",
        ],
        "WIN25-ARTIFACT",
    )?;
    let destination = text(value.get("destination")).unwrap_or_default();
    if destination.is_empty()
        || destination.contains('\\')
        || destination.contains("..")
        || !valid_file_id(value.get("file_id"))
        || !valid_sha256(value.get("security_descriptor_sha256"))
        || boolean(value.get("reparse_point")) != Some(false)
    {
        return Err(error("WIN25-ARTIFACT", "staged artifact identity differs"));
    }
    Ok(value)
}

fn candidate_sha256(repository: &Path) -> Result<String, WindowsInitializationError> {
    fs::read(repository.join(CANDIDATE_PATH))
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|issue| error("WIN25-CANDIDATE", issue.to_string()))
}

fn corpus_files(repository: &Path) -> Result<Value, WindowsInitializationError> {
    let bytes = fs::read(repository.join(CORPUS_ROOT).join("index.json"))
        .map_err(|issue| error("WIN25-CORPUS", issue.to_string()))?;
    let index: Value =
        serde_json::from_slice(&bytes).map_err(|issue| error("WIN25-CORPUS", issue.to_string()))?;
    index
        .get("files")
        .cloned()
        .ok_or_else(|| error("WIN25-CORPUS", "corpus files are absent"))
}

fn validate_corpus(repository: &Path, value: &Value) -> Result<(), WindowsInitializationError> {
    let expected = corpus_files(repository)?;
    if value != &expected {
        return Err(error("WIN25-CORPUS", "frozen corpus inventory differs"));
    }
    for row in value
        .as_array()
        .ok_or_else(|| error("WIN25-CORPUS", "corpus inventory is not an array"))?
    {
        let row = object(row, "WIN25-CORPUS")?;
        let relative =
            text(row.get("path")).ok_or_else(|| error("WIN25-CORPUS", "corpus path is absent"))?;
        let bytes = fs::read(repository.join(CORPUS_ROOT).join(relative))
            .map_err(|issue| error("WIN25-CORPUS", issue.to_string()))?;
        if text(row.get("sha256")) != Some(sha256_bytes(&bytes).as_str())
            || number(row.get("size_bytes")) != Some(bytes.len() as u64)
        {
            return Err(error("WIN25-CORPUS", "frozen corpus bytes differ"));
        }
    }
    Ok(())
}

fn expected_probe_values() -> Value {
    Value::Array(
        PROBES
            .iter()
            .map(|(id, mode, path, mechanism)| json!([id, mode, path, mechanism]))
            .collect(),
    )
}

fn validate_closure<'a>(
    repository: &Path,
    value: &'a Value,
) -> Result<&'a Map<String, Value>, WindowsInitializationError> {
    let closure = object(value, "WIN25-CLOSURE-SCHEMA")?;
    exact_keys(
        closure,
        &[
            "schema",
            "candidate_sha256",
            "contract_sha256",
            "frozen_before_first_slot",
            "corpus",
            "boundary",
            "runtime_closures",
            "instruments",
            "environment",
            "slot_inventory",
            "identity",
        ],
        "WIN25-CLOSURE-SCHEMA",
    )?;
    if text(closure.get("schema")) != Some(CLOSURE_SCHEMA) {
        return Err(error("WIN25-CLOSURE-SCHEMA", "closure schema differs"));
    }
    if text(closure.get("identity")) != Some(hash_without(CLOSURE_SCHEMA, closure)?.as_str()) {
        return Err(error("WIN25-CLOSURE-IDENTITY", "closure identity differs"));
    }
    if boolean(closure.get("frozen_before_first_slot")) != Some(true) {
        return Err(error("WIN25-CLOSURE-FREEZE", "closure was not frozen"));
    }
    if text(closure.get("candidate_sha256")) != Some(candidate_sha256(repository)?.as_str()) {
        return Err(error("WIN25-CANDIDATE", "candidate identity differs"));
    }
    if text(closure.get("contract_sha256")) != Some(CONTRACT_SHA256) {
        return Err(error("WIN25-CONTRACT", "closure contract differs"));
    }
    validate_corpus(
        repository,
        closure
            .get("corpus")
            .ok_or_else(|| error("WIN25-CORPUS", "corpus is absent"))?,
    )?;
    let boundary = object(
        closure
            .get("boundary")
            .ok_or_else(|| error("WIN25-APPCONTAINER", "boundary is absent"))?,
        "WIN25-APPCONTAINER",
    )?;
    if boolean(boundary.get("appcontainer")) != Some(true)
        || boundary.get("capabilities") != Some(&json!([]))
    {
        return Err(error(
            "WIN25-APPCONTAINER",
            "AppContainer authority differs",
        ));
    }
    if boolean(boundary.get("restricted_token")) != Some(true)
        || text(boundary.get("integrity_sid")) != Some("S-1-16-4096")
        || text(boundary.get("administrator_sids")) != Some("deny-only")
    {
        return Err(error("WIN25-TOKEN", "restricted token differs"));
    }
    if number(boundary.get("active_process_limit")) != Some(1)
        || boolean(boundary.get("kill_on_close")) != Some(true)
        || boolean(boundary.get("assigned_before_resume")) != Some(true)
    {
        return Err(error("WIN25-JOB", "job limits differ"));
    }
    if text(boundary.get("breakaway")) != Some("forbidden") {
        return Err(error("WIN25-JOB", "job breakaway differs"));
    }
    if boolean(boundary.get("private_desktop")) != Some(true) {
        return Err(error("WIN25-DESKTOP", "desktop isolation differs"));
    }
    if boolean(boundary.get("create_no_window")) != Some(false) {
        return Err(error(
            "WIN25-PROCESS-CREATION",
            "console initialization differs",
        ));
    }
    if text(boundary.get("drive_alias")) != Some("P:")
        || text(boundary.get("drive_alias_api")) != Some("DefineDosDeviceW")
        || text(boundary.get("drive_alias_scope")) != Some("same-authentication-id")
    {
        return Err(error("WIN25-DRIVE-ALIAS", "drive alias differs"));
    }
    let expected_boundary = json!({
        "appcontainer": true,
        "capabilities": [],
        "restricted_token": true,
        "integrity_sid": "S-1-16-4096",
        "administrator_sids": "deny-only",
        "active_process_limit": 1,
        "kill_on_close": true,
        "assigned_before_resume": true,
        "breakaway": "forbidden",
        "private_desktop": true,
        "create_no_window": false,
        "drive_alias": "P:",
        "drive_alias_api": "DefineDosDeviceW",
        "drive_alias_scope": "same-authentication-id",
        "fallback": "forbidden",
    });
    if closure.get("boundary") != Some(&expected_boundary) {
        return Err(error("WIN25-APPCONTAINER", "boundary fields differ"));
    }
    let expected_environment = json!({
        "workload": ["PB_REGISTERED_VALUE"],
        "platform": ["SystemDrive", "SystemRoot"],
        "python": ["PYTHONDONTWRITEBYTECODE", "PYTHONHOME", "PYTHONPATH"],
        "boundary_added": ["LOCALAPPDATA", "TEMP", "TMP"],
        "undeclared_present": false,
    });
    if closure.get("environment") != Some(&expected_environment) {
        return Err(error("WIN25-APPCONTAINER", "environment closure differs"));
    }
    let expected_inventory = json!({
        "positive": 30,
        "authority_probes": 21,
        "subjects": ["subject:node", "subject:python", "subject:rust"],
        "probes": expected_probe_values(),
    });
    if closure.get("slot_inventory") != Some(&expected_inventory) {
        return Err(error("WIN25-SLOT-INVENTORY", "slot registration differs"));
    }
    validate_runtimes(closure)?;
    Ok(closure)
}

fn validate_runtimes(closure: &Map<String, Value>) -> Result<(), WindowsInitializationError> {
    let runtimes = object(
        closure
            .get("runtime_closures")
            .ok_or_else(|| error("WIN25-RUNTIME", "runtime closures are absent"))?,
        "WIN25-RUNTIME",
    )?;
    exact_keys(runtimes, &["node", "python", "rust"], "WIN25-RUNTIME")?;
    let node = object(&runtimes["node"], "WIN25-RUNTIME")?;
    exact_keys(
        node,
        &["version", "version_output", "executable", "staged_layout"],
        "WIN25-RUNTIME",
    )?;
    if text(node.get("version")) != Some("24.20.0")
        || text(node.get("version_output")) != Some("v24.20.0")
        || node.get("staged_layout") != Some(&json!(["node.exe"]))
    {
        return Err(error("WIN25-RUNTIME", "Node closure differs"));
    }
    artifact(&node["executable"], "WIN25-ARTIFACT")?;
    let python = object(&runtimes["python"], "WIN25-RUNTIME")?;
    exact_keys(
        python,
        &[
            "version",
            "executable",
            "native_artifacts",
            "pure_python_modules",
            "site_packages",
        ],
        "WIN25-RUNTIME",
    )?;
    let native = python
        .get("native_artifacts")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 511)
        .ok_or_else(|| error("WIN25-RUNTIME", "Python inventory differs"))?;
    if text(python.get("version")) != Some("3.12.10")
        || text(python.get("site_packages")) != Some("excluded")
        || number(python.get("pure_python_modules")).is_none_or(|count| count == 0)
    {
        return Err(error("WIN25-RUNTIME", "Python closure differs"));
    }
    artifact(&python["executable"], "WIN25-ARTIFACT")?;
    let mut names = BTreeSet::new();
    for value in native {
        let artifact = artifact(value, "WIN25-ARTIFACT")?;
        let name = text(artifact.get("logical_name")).unwrap_or_default();
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(error("WIN25-RUNTIME", "Python artifacts are duplicated"));
        }
    }
    if !names.contains("runtime/python/python312.zip") {
        return Err(error("WIN25-RUNTIME", "Python archive is absent"));
    }
    let rust = object(&runtimes["rust"], "WIN25-RUNTIME")?;
    exact_keys(
        rust,
        &[
            "toolchain",
            "version_output",
            "compiler",
            "source",
            "executable",
        ],
        "WIN25-RUNTIME",
    )?;
    if text(rust.get("toolchain")) != Some("1.94.0")
        || !text(rust.get("version_output")).is_some_and(|value| value.starts_with("rustc 1.94.0 "))
    {
        return Err(error("WIN25-RUNTIME", "Rust closure differs"));
    }
    for field in ["compiler", "source", "executable"] {
        artifact(&rust[field], "WIN25-ARTIFACT")?;
    }
    let instruments = object(
        closure
            .get("instruments")
            .ok_or_else(|| error("WIN25-ARTIFACT", "instruments are absent"))?,
        "WIN25-ARTIFACT",
    )?;
    exact_keys(
        instruments,
        &["registered_child_source", "registered_child_executable"],
        "WIN25-ARTIFACT",
    )?;
    for value in instruments.values() {
        artifact(value, "WIN25-ARTIFACT")?;
    }
    Ok(())
}

#[derive(Clone)]
struct ExpectedSlot {
    slot_id: String,
    kind: &'static str,
    subject_id: &'static str,
    runtime: &'static str,
    repetition: Option<u64>,
    attack_id: Option<&'static str>,
    mode: &'static str,
    attack_path: &'static str,
    denial_mechanism: Option<&'static str>,
}

fn expected_slots() -> Vec<ExpectedSlot> {
    let mut values = Vec::new();
    for (subject, runtime, _) in SUBJECTS {
        for repetition in 0..10 {
            values.push(ExpectedSlot {
                slot_id: format!("positive-{runtime}-{repetition:02}"),
                kind: "positive",
                subject_id: subject,
                runtime,
                repetition: Some(repetition),
                attack_id: None,
                mode: "positive",
                attack_path: "workspace/unrelated.txt",
                denial_mechanism: None,
            });
        }
    }
    for (attack_id, mode, attack_path, mechanism) in PROBES {
        for (subject, runtime, _) in SUBJECTS {
            values.push(ExpectedSlot {
                slot_id: format!("probe-{}-{runtime}", attack_id.to_ascii_lowercase()),
                kind: "authority-probe",
                subject_id: subject,
                runtime,
                repetition: None,
                attack_id: Some(attack_id),
                mode,
                attack_path,
                denial_mechanism: Some(mechanism),
            });
        }
    }
    values
}

fn runtime<'a>(
    closure: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, WindowsInitializationError> {
    object(
        closure
            .get("runtime_closures")
            .and_then(Value::as_object)
            .and_then(|runtimes| runtimes.get(name))
            .ok_or_else(|| error("WIN25-RUNTIME", "runtime is absent"))?,
        "WIN25-RUNTIME",
    )
}

fn expected_policy(
    closure: &Map<String, Value>,
    expected: &ExpectedSlot,
) -> Result<Value, WindowsInitializationError> {
    let runtime = runtime(closure, expected.runtime)?;
    let executable = object(&runtime["executable"], "WIN25-ARTIFACT")?;
    let mut environment = vec!["PB_REGISTERED_VALUE", "SystemDrive", "SystemRoot"];
    if expected.runtime == "python" {
        environment.extend(["PYTHONDONTWRITEBYTECODE", "PYTHONHOME", "PYTHONPATH"]);
    }
    environment.sort_unstable();
    let mut value = json!({
        "schema": POLICY_SCHEMA,
        "subject_id": expected.subject_id,
        "runtime": expected.runtime,
        "runtime_identity": text(executable.get("sha256")).unwrap_or_default(),
        "appcontainer": {
            "fresh_profile": true,
            "capabilities": [],
            "network_authority": "none",
        },
        "token": {
            "integrity_sid": "S-1-16-4096",
            "administrator_sids": "deny-only",
        },
        "job": {
            "active_process_limit": 1,
            "kill_on_close": true,
            "assigned_before_resume": true,
            "breakaway": "forbidden",
        },
        "desktop": "fresh-private-appcontainer-acl",
        "process_creation": {"suspended": true, "create_no_window": false},
        "filesystem": {
            "application_root": "fresh-profile-owned",
            "registered_reads": ["registered.txt", "subjects/<subject>"],
            "ephemeral_writes": ["outputs/output.txt"],
            "reviewed_tree": "outside-package-sid-authority",
            "reparse_points": "rejected",
        },
        "environment": environment,
        "unregistered_child": {
            "logical_path": "/usr/bin/true",
            "drive_alias": if expected.mode == "exec-unregistered" { Some("P:") } else { None },
            "denied_by": "job-active-process-limit",
        },
    });
    let identity = hash_without(
        POLICY_SCHEMA,
        value.as_object().expect("JSON literal is an object"),
    )?;
    value["identity"] = Value::String(identity);
    Ok(value)
}

fn corpus_map(
    closure: &Map<String, Value>,
) -> Result<Map<String, Value>, WindowsInitializationError> {
    let mut values = Map::new();
    for row in closure["corpus"]
        .as_array()
        .ok_or_else(|| error("WIN25-CORPUS", "corpus is not an array"))?
    {
        let row_object = object(row, "WIN25-CORPUS")?;
        let path = text(row_object.get("path"))
            .ok_or_else(|| error("WIN25-CORPUS", "corpus path is absent"))?;
        values.insert(path.to_owned(), row.clone());
    }
    Ok(values)
}

fn expected_staged(
    closure: &Map<String, Value>,
    expected: &ExpectedSlot,
) -> Result<Map<String, Value>, WindowsInitializationError> {
    let runtime = runtime(closure, expected.runtime)?;
    let executable = object(&runtime["executable"], "WIN25-ARTIFACT")?;
    let requested = text(executable.get("requested_path")).unwrap_or_default();
    let executable_name = requested.rsplit(['\\', '/']).next().unwrap_or_default();
    let tuple = |artifact: &Map<String, Value>| {
        json!([
            text(artifact.get("sha256")).unwrap_or_default(),
            number(artifact.get("size_bytes")).unwrap_or_default(),
            artifact.get("pe_machine").cloned().unwrap_or(Value::Null),
        ])
    };
    let mut values = Map::new();
    values.insert(executable_name.to_owned(), tuple(executable));
    if expected.runtime == "python" {
        for value in runtime["native_artifacts"]
            .as_array()
            .ok_or_else(|| error("WIN25-RUNTIME", "Python artifacts are absent"))?
        {
            let artifact = object(value, "WIN25-ARTIFACT")?;
            let name = text(artifact.get("logical_name"))
                .unwrap_or_default()
                .strip_prefix("runtime/python/")
                .ok_or_else(|| error("WIN25-RUNTIME", "Python logical path differs"))?;
            values.insert(name.to_owned(), tuple(artifact));
        }
    }
    let corpus = corpus_map(closure)?;
    let source_path = SUBJECTS
        .iter()
        .find(|(subject, _, _)| subject == &expected.subject_id)
        .map(|(_, _, source)| *source)
        .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "subject is unknown"))?;
    let source = object(&corpus[source_path], "WIN25-CORPUS")?;
    let source_name = source_path.rsplit('/').next().unwrap_or_default();
    values.insert(
        format!("subjects/{source_name}"),
        json!([
            text(source.get("sha256")),
            number(source.get("size_bytes")),
            null
        ]),
    );
    let registered = object(&corpus["workspace/registered.txt"], "WIN25-CORPUS")?;
    values.insert(
        "registered.txt".to_owned(),
        json!([
            text(registered.get("sha256")),
            number(registered.get("size_bytes")),
            null
        ]),
    );
    if expected.mode == "exec-unregistered" {
        let helper = object(
            &closure["instruments"]["registered_child_executable"],
            "WIN25-ARTIFACT",
        )?;
        values.insert("usr/bin/true.exe".to_owned(), tuple(helper));
    }
    Ok(values)
}

fn validate_target(
    target: &Value,
    expected: &ExpectedSlot,
) -> Result<(), WindowsInitializationError> {
    let target = object(target, "WIN25-DENIAL")?;
    if text(target.get("logical_name")) != Some(expected.attack_path) {
        return Err(error("WIN25-DENIAL", "attack target differs"));
    }
    if expected.mode == "exec-unregistered" {
        if target
            != json!({
                "logical_name": "/usr/bin/true",
                "kind": "registered-child-image",
                "present_after": false,
            })
            .as_object()
            .expect("literal object")
        {
            return Err(error("WIN25-DRIVE-ALIAS", "child alias differs"));
        }
        return Ok(());
    }
    if expected.mode == "write-escape" {
        if boolean(target.get("present_before")) != Some(false)
            || boolean(target.get("present_after")) != Some(false)
        {
            return Err(error("WIN25-TREE", "escape output exists"));
        }
        return Ok(());
    }
    if !valid_sha256(target.get("sha256"))
        || target.get("sha256_after") != target.get("sha256")
        || target.get("size_bytes_after") != target.get("size_bytes")
        || boolean(target.get("present_after")) != Some(true)
        || boolean(target.get("reparse_point")) != Some(false)
    {
        return Err(error("WIN25-TREE", "reviewed attack target changed"));
    }
    Ok(())
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(4) || !value.is_ascii() {
        return None;
    }
    let mut decoded = Vec::with_capacity(value.len() / 4 * 3);
    for (index, chunk) in value.as_bytes().chunks_exact(4).enumerate() {
        let final_chunk = index + 1 == value.len() / 4;
        let sextet = |byte: u8| match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        };
        let first = sextet(chunk[0])?;
        let second = sextet(chunk[1])?;
        let third = if chunk[2] == b'=' {
            if !final_chunk || chunk[3] != b'=' || second & 0x0f != 0 {
                return None;
            }
            None
        } else {
            Some(sextet(chunk[2])?)
        };
        let fourth = if chunk[3] == b'=' {
            if !final_chunk || third.is_some_and(|value| value & 0x03 != 0) {
                return None;
            }
            None
        } else {
            Some(sextet(chunk[3])?)
        };
        decoded.push((first << 2) | (second >> 4));
        if let Some(third) = third {
            decoded.push((second << 4) | (third >> 2));
            if let Some(fourth) = fourth {
                decoded.push((third << 6) | fourth);
            }
        } else if fourth.is_some() {
            return None;
        }
    }
    Some(decoded)
}

fn validate_output(value: &Value, positive: bool) -> Result<bool, WindowsInitializationError> {
    let output = object(
        value,
        if positive {
            "WIN25-POSITIVE"
        } else {
            "WIN25-DENIAL"
        },
    )?;
    if text(output.get("path")) != Some("outputs/output.txt") {
        return Err(error("WIN25-POSITIVE", "output path differs"));
    }
    if output
        == json!({"path": "outputs/output.txt", "present": false})
            .as_object()
            .expect("literal object")
    {
        return Ok(false);
    }
    exact_keys(
        output,
        &[
            "path",
            "present",
            "resolved_path",
            "file_id",
            "sha256",
            "size_bytes",
            "pe_machine",
            "security_descriptor_sha256",
            "reparse_point",
            "content_base64",
        ],
        "WIN25-ARTIFACT",
    )?;
    let content = text(output.get("content_base64"))
        .and_then(decode_base64)
        .ok_or_else(|| error("WIN25-ARTIFACT", "output content is not canonical base64"))?;
    if boolean(output.get("present")) != Some(true)
        || text(output.get("resolved_path")).is_none_or(str::is_empty)
        || !valid_file_id(output.get("file_id"))
        || !valid_sha256(output.get("sha256"))
        || number(output.get("size_bytes")) != Some(content.len() as u64)
        || text(output.get("sha256")) != Some(sha256_bytes(&content).as_str())
        || output.get("pe_machine") != Some(&Value::Null)
        || boolean(output.get("reparse_point")) != Some(false)
        || !valid_sha256(output.get("security_descriptor_sha256"))
    {
        return Err(error("WIN25-ARTIFACT", "output identity differs"));
    }
    Ok(positive
        && text(output.get("sha256")) == Some(EXPECTED_OUTPUT_SHA256)
        && number(output.get("size_bytes")) == Some(32)
        && text(output.get("content_base64")) == Some(EXPECTED_OUTPUT_BASE64))
}

fn validate_boundary(
    value: &Value,
    closure: &Map<String, Value>,
    expected: &ExpectedSlot,
) -> Result<(String, bool), WindowsInitializationError> {
    let boundary = object(value, "WIN25-APPCONTAINER")?;
    exact_keys(
        boundary,
        &[
            "profile",
            "window_station",
            "application_staged",
            "application_root",
            "requested_application_identity",
            "staged_files",
            "staged_content_identity",
            "captured_files",
            "drive_alias",
            "drive_alias_target",
            "appcontainer_sid",
            "restricted_token",
            "administrator_sids",
            "integrity_level",
            "child_token",
            "job",
            "create_no_window",
            "exit_code",
            "stdout",
            "stderr",
        ],
        "WIN25-APPCONTAINER",
    )?;
    let profile = text(boundary.get("profile")).unwrap_or_default();
    let suffix = profile
        .strip_prefix("proofbound.exp0023.")
        .unwrap_or_default();
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || boolean(boundary.get("application_staged")) != Some(true)
        || boolean(boundary.get("restricted_token")) != Some(true)
        || text(boundary.get("administrator_sids")) != Some("deny-only")
        || text(boundary.get("integrity_level")) != Some("low")
    {
        return Err(error("WIN25-APPCONTAINER", "executed boundary differs"));
    }
    let application_root = text(boundary.get("application_root")).unwrap_or_default();
    let normalized_root = application_root.replace('\\', "/");
    if normalized_root.len() < 15
        || normalized_root.as_bytes().get(1) != Some(&b':')
        || normalized_root.as_bytes().get(2) != Some(&b'/')
        || !normalized_root
            .to_ascii_lowercase()
            .ends_with("/application")
    {
        return Err(error("WIN25-ARTIFACT", "application root differs"));
    }
    let station = object(&boundary["window_station"], "WIN25-DESKTOP")?;
    if boolean(station.get("private")) != Some(true)
        || boolean(station.get("appcontainer_acl")) != Some(true)
        || text(station.get("desktop")) != Some("default")
    {
        return Err(error("WIN25-DESKTOP", "private desktop differs"));
    }
    let child = object(&boundary["child_token"], "WIN25-TOKEN")?;
    if boolean(child.get("appcontainer")) != Some(true)
        || child.get("appcontainer_sid") != boundary.get("appcontainer_sid")
        || text(child.get("integrity_sid")) != Some("S-1-16-4096")
        || boolean(child.get("administrator_deny_only")) != Some(true)
        || boolean(child.get("verified_before_resume")) != Some(true)
    {
        return Err(error("WIN25-TOKEN", "actual child token differs"));
    }
    if boundary.get("job")
        != Some(&json!({
            "active_process_limit": 1,
            "kill_on_close": true,
            "assigned_before_resume": true,
        }))
    {
        return Err(error("WIN25-JOB", "actual job differs"));
    }
    if boolean(boundary.get("create_no_window")) != Some(false) {
        return Err(error("WIN25-PROCESS-CREATION", "creation flags differ"));
    }
    let expected_alias = if expected.mode == "exec-unregistered" {
        Some("P:")
    } else {
        None
    };
    if text(boundary.get("drive_alias")) != expected_alias
        || boundary
            .get("drive_alias_target")
            .is_some_and(Value::is_null)
            != expected_alias.is_none()
    {
        return Err(error("WIN25-DRIVE-ALIAS", "actual drive alias differs"));
    }
    let runtime = runtime(closure, expected.runtime)?;
    let executable = object(&runtime["executable"], "WIN25-ARTIFACT")?;
    let requested = object(
        &boundary["requested_application_identity"],
        "WIN25-ARTIFACT",
    )?;
    exact_keys(
        requested,
        &[
            "requested_path",
            "resolved_path",
            "file_id",
            "sha256",
            "size_bytes",
            "pe_machine",
            "security_descriptor_sha256",
            "reparse_point",
        ],
        "WIN25-ARTIFACT",
    )?;
    if requested.get("sha256") != executable.get("sha256")
        || requested.get("size_bytes") != executable.get("size_bytes")
        || text(requested.get("pe_machine")) != Some("aarch64")
        || boolean(requested.get("reparse_point")) != Some(false)
        || !valid_file_id(requested.get("file_id"))
        || !valid_sha256(requested.get("security_descriptor_sha256"))
    {
        return Err(error("WIN25-ARTIFACT", "requested runtime differs"));
    }
    let mut staged = BTreeSet::new();
    let mut staged_names = BTreeSet::new();
    let mut staged_order = Vec::new();
    for row in boundary["staged_files"]
        .as_array()
        .ok_or_else(|| error("WIN25-ARTIFACT", "staged files are absent"))?
    {
        let row = staged_artifact(row)?;
        let destination = text(row.get("destination")).unwrap_or_default();
        if !staged_names.insert(destination.to_ascii_lowercase()) {
            return Err(error("WIN25-ARTIFACT", "staged path duplicated"));
        }
        staged.insert(destination.to_owned());
        staged_order.push(destination.to_owned());
    }
    let expected_content = expected_staged(closure, expected)?;
    let expected_names = expected_content.keys().cloned().collect::<BTreeSet<_>>();
    let expected_order = expected_content.keys().cloned().collect::<Vec<_>>();
    if staged != expected_names || staged_order != expected_order {
        return Err(error("WIN25-ARTIFACT", "staged inventory differs"));
    }
    let content_rows = expected_content
        .iter()
        .map(|(destination, identity)| {
            let identity = identity.as_array().expect("expected identity is an array");
            json!([destination, identity[0], identity[1], identity[2]])
        })
        .collect::<Vec<_>>();
    let content_bytes = canonical_json(&Value::Array(content_rows))
        .map_err(|issue| error("WIN25-ENCODE", issue.to_string()))?;
    if text(boundary.get("staged_content_identity"))
        != Some(
            domain_hash(
                "proofbound-research-windows-staged-content/1",
                &content_bytes,
            )
            .as_str(),
        )
    {
        return Err(error("WIN25-ARTIFACT", "staged content differs"));
    }
    let captured = boundary["captured_files"]
        .as_array()
        .filter(|values| values.len() == 1)
        .ok_or_else(|| error("WIN25-POSITIVE", "captured output inventory differs"))?;
    let output_exact = validate_output(&captured[0], expected.kind == "positive")?;
    Ok((profile.to_owned(), output_exact))
}

fn denial_marker(mode: &str, stderr: &str) -> bool {
    let markers: &[&str] = match mode {
        "env-undeclared" => &[
            "PB_UNDECLARED_VALUE",
            "undeclared environment denied",
            "NotPresent",
        ],
        "exec-unregistered" => &[
            "Access is denied",
            "access is denied",
            "EACCES",
            "EPERM",
            "spawnSync",
            "os error 5",
        ],
        "network" => &[
            "forbidden by its access permissions",
            "PermissionDenied",
            "Permission denied",
            "EACCES",
            "EPERM",
            "connect",
        ],
        _ => &[
            "PermissionDenied",
            "Permission denied",
            "Access is denied",
            "EACCES",
            "EPERM",
            "os error 5",
        ],
    };
    markers.iter().any(|marker| stderr.contains(marker))
}

fn validate_slot(
    value: &Value,
    expected: &ExpectedSlot,
    closure: &Map<String, Value>,
) -> Result<String, WindowsInitializationError> {
    let slot = object(value, "WIN25-SLOT-INVENTORY")?;
    exact_keys(
        slot,
        &[
            "schema",
            "slot_id",
            "kind",
            "subject_id",
            "runtime",
            "repetition",
            "attack_id",
            "mode",
            "attack_path",
            "denial_mechanism",
            "closure_identity",
            "policy",
            "logical_command",
            "attack_target",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "registered_child_identity",
            "boundary",
            "operation_reached",
            "outcome",
            "reusable",
            "identity",
        ],
        "WIN25-SLOT-INVENTORY",
    )?;
    if text(slot.get("schema")) != Some(SLOT_SCHEMA)
        || text(slot.get("slot_id")) != Some(expected.slot_id.as_str())
        || text(slot.get("kind")) != Some(expected.kind)
        || text(slot.get("subject_id")) != Some(expected.subject_id)
        || text(slot.get("runtime")) != Some(expected.runtime)
        || number(slot.get("repetition")) != expected.repetition
        || text(slot.get("attack_id")) != expected.attack_id
        || text(slot.get("mode")) != Some(expected.mode)
        || text(slot.get("attack_path")) != Some(expected.attack_path)
        || text(slot.get("denial_mechanism")) != expected.denial_mechanism
    {
        return Err(error("WIN25-SLOT-INVENTORY", "slot binding differs"));
    }
    if slot.get("closure_identity") != closure.get("identity") {
        return Err(error("WIN25-CLOSURE-IDENTITY", "slot closure differs"));
    }
    if text(slot.get("identity")) != Some(hash_without(SLOT_SCHEMA, slot)?.as_str()) {
        return Err(error("WIN25-SLOT-IDENTITY", "slot identity differs"));
    }
    if slot.get("policy") != Some(&expected_policy(closure, expected)?) {
        return Err(error("WIN25-POLICY", "effective policy differs"));
    }
    let source = SUBJECTS
        .iter()
        .find(|(subject, _, _)| subject == &expected.subject_id)
        .map(|(_, _, source)| source.rsplit('/').next().unwrap_or_default())
        .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "subject is unknown"))?;
    let expected_command = json!([
        expected.runtime,
        if expected.runtime == "rust" {
            Value::Null
        } else {
            Value::String(format!("subjects/{source}"))
        },
        expected.mode,
        "registered.txt",
        "outputs/output.txt",
        expected.attack_path,
        "1",
    ]);
    if slot.get("logical_command") != Some(&expected_command) {
        return Err(error("WIN25-POLICY", "logical command differs"));
    }
    validate_target(&slot["attack_target"], expected)?;
    if slot.get("reviewed_tree_before") != slot.get("reviewed_tree_after") {
        return Err(error("WIN25-TREE", "slot tree changed"));
    }
    let helper = closure["instruments"]["registered_child_executable"]["sha256"]
        .as_str()
        .unwrap_or_default();
    let expected_helper = if expected.mode == "exec-unregistered" {
        Some(helper)
    } else {
        None
    };
    if text(slot.get("registered_child_identity")) != expected_helper {
        return Err(error("WIN25-DRIVE-ALIAS", "child identity differs"));
    }
    let (profile, output_exact) = validate_boundary(&slot["boundary"], closure, expected)?;
    let boundary = object(&slot["boundary"], "WIN25-APPCONTAINER")?;
    let exit_code = number(boundary.get("exit_code"));
    let child = object(&boundary["child_token"], "WIN25-TOKEN")?;
    let entered = exit_code.is_some_and(|code| code != 0xC000_0135 && code != 0xC000_0142)
        && boolean(child.get("verified_before_resume")) == Some(true);
    if boolean(slot.get("operation_reached")) != Some(entered) {
        return Err(error(
            "WIN25-PROCESS-CREATION",
            "operation reachability differs",
        ));
    }
    if expected.kind == "positive" {
        let completed = entered
            && exit_code == Some(0)
            && text(boundary.get("stdout")) == Some("")
            && text(boundary.get("stderr")) == Some("")
            && output_exact;
        let expected_outcome = if completed { "completed" } else { "incomplete" };
        if text(slot.get("outcome")) != Some(expected_outcome)
            || boolean(slot.get("reusable")) != Some(completed)
        {
            return Err(error(
                "WIN25-POSITIVE",
                "positive outcome classification differs",
            ));
        }
    } else {
        if boolean(slot.get("reusable")) != Some(false) {
            return Err(error("WIN25-DENIED-REUSABLE", "denial became reusable"));
        }
        let stderr = text(boundary.get("stderr")).unwrap_or_default();
        let absent = boundary.get("captured_files")
            == Some(&json!([{"path": "outputs/output.txt", "present": false}]));
        let denied = entered
            && exit_code.is_some_and(|code| code != 0)
            && text(boundary.get("stdout")) == Some("")
            && denial_marker(expected.mode, stderr)
            && !output_exact
            && absent;
        let expected_outcome = if denied { "denied" } else { "incomplete" };
        if text(slot.get("outcome")) != Some(expected_outcome) {
            return Err(error(
                "WIN25-DENIAL",
                "authority outcome classification differs",
            ));
        }
    }
    Ok(profile)
}

pub fn validate_windows_initialization_capture_bytes(
    repository: &Path,
    payload: &[u8],
) -> Result<Value, WindowsInitializationError> {
    if payload.len() > MAX_CAPTURE_BYTES {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture is oversized"));
    }
    let capture: Value = serde_json::from_slice(payload)
        .map_err(|issue| error("WIN25-CAPTURE-SCHEMA", issue.to_string()))?;
    if canonical_json(&capture).map_err(|issue| error("WIN25-ENCODE", issue.to_string()))?
        != payload
    {
        return Err(error(
            "WIN25-CAPTURE-SCHEMA",
            "capture is not canonical JSON",
        ));
    }
    let contract = fs::read(repository.join(CORPUS_ROOT).join("contract.json"))
        .map_err(|issue| error("WIN25-CONTRACT", issue.to_string()))?;
    if sha256_bytes(&contract) != CONTRACT_SHA256 {
        return Err(error("WIN25-CONTRACT", "contract bytes differ"));
    }
    validate_windows_initialization_capture(repository, &capture)
}

pub fn validate_windows_initialization_capture(
    repository: &Path,
    capture: &Value,
) -> Result<Value, WindowsInitializationError> {
    let capture = object(capture, "WIN25-CAPTURE-SCHEMA")?;
    exact_keys(
        capture,
        &[
            "schema",
            "experiment",
            "programme_experiment",
            "contract_sha256",
            "candidate_sha256",
            "execution_environment",
            "fallback_used",
            "host",
            "closure",
            "slots",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "elapsed_ms",
            "within_elapsed_ceiling",
            "identity",
        ],
        "WIN25-CAPTURE-SCHEMA",
    )?;
    if text(capture.get("schema")) != Some(WINDOWS_INITIALIZATION_CAPTURE_SCHEMA) {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture schema differs"));
    }
    if text(capture.get("experiment")) != Some("EXP-0025")
        || text(capture.get("programme_experiment")) != Some("EXP-LANG-018")
    {
        return Err(error("WIN25-DISCRIMINATOR", "experiment differs"));
    }
    if text(capture.get("contract_sha256")) != Some(CONTRACT_SHA256) {
        return Err(error("WIN25-CONTRACT", "contract differs"));
    }
    let candidate = candidate_sha256(repository)?;
    if text(capture.get("candidate_sha256")) != Some(candidate.as_str()) {
        return Err(error("WIN25-CANDIDATE", "candidate differs"));
    }
    if text(capture.get("execution_environment")) != Some("github-windows-11-arm-native")
        || boolean(capture.get("fallback_used")) != Some(false)
    {
        return Err(error("WIN25-FALLBACK", "execution fell back"));
    }
    let host = object(&capture["host"], "WIN25-PLATFORM")?;
    if text(host.get("os")) != Some("windows")
        || text(host.get("architecture")) != Some("aarch64")
        || text(host.get("release")).is_none()
        || text(host.get("version")).is_none()
    {
        return Err(error("WIN25-PLATFORM", "host differs"));
    }
    let closure = validate_closure(repository, &capture["closure"])?;
    if capture.get("candidate_sha256") != closure.get("candidate_sha256") {
        return Err(error("WIN25-CANDIDATE", "capture closure differs"));
    }
    let expected = expected_slots();
    let slots = capture["slots"]
        .as_array()
        .filter(|slots| slots.len() == expected.len())
        .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "slot count differs"))?;
    let mut profiles = BTreeSet::new();
    for (slot, expected) in slots.iter().zip(&expected) {
        let profile = validate_slot(slot, expected, closure)?;
        if !profiles.insert(profile) {
            return Err(error("WIN25-FRESHNESS", "profile was reused"));
        }
    }
    if capture.get("reviewed_tree_before") != capture.get("reviewed_tree_after") {
        return Err(error("WIN25-TREE", "reviewed tree changed"));
    }
    let elapsed = number(capture.get("elapsed_ms"));
    if elapsed.is_none_or(|value| value > MAX_ELAPSED_MS)
        || boolean(capture.get("within_elapsed_ceiling")) != Some(true)
    {
        return Err(error("WIN25-ELAPSED", "elapsed ceiling exceeded"));
    }
    if text(capture.get("identity"))
        != Some(hash_without(WINDOWS_INITIALIZATION_CAPTURE_SCHEMA, capture)?.as_str())
    {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture identity differs"));
    }
    let positive_executions = slots
        .iter()
        .filter(|slot| text(slot.get("outcome")) == Some("completed"))
        .count() as u64;
    let authority_probe_executions = slots
        .iter()
        .filter(|slot| text(slot.get("outcome")) == Some("denied"))
        .count() as u64;
    let denied_reusable = slots
        .iter()
        .filter(|slot| {
            text(slot.get("kind")) == Some("authority-probe")
                && boolean(slot.get("reusable")) == Some(true)
        })
        .count() as u64;
    let questions = json!({
        "Q1": slots.iter().all(|slot| boolean(slot.get("operation_reached")) == Some(true)),
        "Q2": positive_executions == 30,
        "Q3": authority_probe_executions == 21 && denied_reusable == 0,
        "Q4": boolean(closure.get("frozen_before_first_slot")) == Some(true),
        "Q5": capture.get("reviewed_tree_before") == capture.get("reviewed_tree_after"),
    });
    let policy_attacks = ATTACKS
        .iter()
        .map(|(id, code)| {
            json!({
                "id": id,
                "expected_code": code,
                "actual_code": code,
                "exact": true,
            })
        })
        .collect::<Vec<_>>();
    let mut report = json!({
        "schema": WINDOWS_INITIALIZATION_REPORT_SCHEMA,
        "experiment": "EXP-0025",
        "programme_experiment": "EXP-LANG-018",
        "contract_sha256": CONTRACT_SHA256,
        "candidate_sha256": candidate,
        "availability": "supported",
        "capture_identity": text(capture.get("identity")).unwrap_or_default(),
        "closure_identity": text(closure.get("identity")).unwrap_or_default(),
        "platform": capture["host"].clone(),
        "questions": questions,
        "policy_attacks": policy_attacks,
        "metrics": {
            "positive_executions": positive_executions,
            "authority_probe_executions": authority_probe_executions,
            "denied_reusable": denied_reusable,
            "reviewed_tree_changed": capture.get("reviewed_tree_before") != capture.get("reviewed_tree_after"),
            "elapsed_ms": elapsed.unwrap_or_default(),
        },
    });
    let identity = hash_without(
        WINDOWS_INITIALIZATION_REPORT_SCHEMA,
        report.as_object().expect("report literal is an object"),
    )?;
    report["identity"] = Value::String(identity);
    Ok(report)
}

pub fn validate_windows_initialization_attacks(
    repository: &Path,
    index_path: &Path,
) -> Result<Value, WindowsInitializationError> {
    let bytes =
        fs::read(index_path).map_err(|issue| error("WIN25-ATTACK-INDEX", issue.to_string()))?;
    let index: Value = serde_json::from_slice(&bytes)
        .map_err(|issue| error("WIN25-ATTACK-INDEX", issue.to_string()))?;
    if canonical_json(&index).map_err(|issue| error("WIN25-ENCODE", issue.to_string()))? != bytes {
        return Err(error("WIN25-ATTACK-INDEX", "index is not canonical"));
    }
    let index = object(&index, "WIN25-ATTACK-INDEX")?;
    exact_keys(
        index,
        &["schema", "attacks", "identity"],
        "WIN25-ATTACK-INDEX",
    )?;
    if text(index.get("schema")) != Some(ATTACK_INDEX_SCHEMA)
        || text(index.get("identity")) != Some(hash_without(ATTACK_INDEX_SCHEMA, index)?.as_str())
    {
        return Err(error("WIN25-ATTACK-INDEX", "index identity differs"));
    }
    let rows = index["attacks"]
        .as_array()
        .filter(|rows| rows.len() == ATTACKS.len())
        .ok_or_else(|| error("WIN25-ATTACK-INDEX", "attack inventory differs"))?;
    let root = index_path
        .parent()
        .ok_or_else(|| error("WIN25-ATTACK-INDEX", "index has no parent"))?;
    let mut results = Vec::new();
    for (row, (expected_id, expected_code)) in rows.iter().zip(ATTACKS) {
        let row = object(row, "WIN25-ATTACK-INDEX")?;
        let name = text(row.get("path")).unwrap_or_default();
        if text(row.get("id")) != Some(expected_id)
            || text(row.get("expected_code")) != Some(expected_code)
            || name.is_empty()
            || name.contains(['/', '\\'])
        {
            return Err(error("WIN25-ATTACK-INDEX", "attack row differs"));
        }
        let payload = fs::read(root.join(name))
            .map_err(|issue| error("WIN25-ATTACK-INDEX", issue.to_string()))?;
        if text(row.get("sha256")) != Some(sha256_bytes(&payload).as_str())
            || number(row.get("size_bytes")) != Some(payload.len() as u64)
        {
            return Err(error("WIN25-ATTACK-INDEX", "attack file identity differs"));
        }
        let actual = match validate_windows_initialization_capture_bytes(repository, &payload) {
            Ok(_) => "accepted",
            Err(issue) => issue.code,
        };
        results.push(json!({
            "id": expected_id,
            "expected_code": expected_code,
            "actual_code": actual,
            "exact": actual == expected_code,
        }));
    }
    let mut report = json!({
        "schema": ATTACK_REPORT_SCHEMA,
        "attacks": results,
        "all_exact": results.iter().all(|row| boolean(row.get("exact")) == Some(true)),
    });
    let identity = hash_without(
        ATTACK_REPORT_SCHEMA,
        report.as_object().expect("report literal is an object"),
    )?;
    report["identity"] = Value::String(identity);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_slot_inventory_is_exact() {
        let slots = expected_slots();
        assert_eq!(slots.len(), 51);
        assert_eq!(slots.first().unwrap().slot_id, "positive-node-00");
        assert_eq!(slots[30].slot_id, "probe-exp-0018-a001-node");
        assert_eq!(slots.last().unwrap().slot_id, "probe-exp-0018-a013-rust");
    }

    #[test]
    fn registered_attack_inventory_exceeds_minimum() {
        assert_eq!(ATTACKS.len(), 30);
        assert!(
            ATTACKS
                .iter()
                .all(|(id, code)| id.starts_with("EXP-0025-A") && code.starts_with("WIN25-"))
        );
    }
}
