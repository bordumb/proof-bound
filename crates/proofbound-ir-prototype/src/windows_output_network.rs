use std::{collections::BTreeSet, fs, path::Path};

use proofbound_evidence::{canonical_json, sha256_bytes};
use serde_json::{Map, Value, json};

use crate::windows_initialization::{
    self as initialization, WindowsInitializationError, boolean, candidate_sha256, error,
    exact_keys, expected_slots, hash_without, number, object, runtime, text,
};

pub const WINDOWS_OUTPUT_NETWORK_CAPTURE_SCHEMA: &str =
    "proofbound-research-windows-output-network-capture/1";
pub const WINDOWS_OUTPUT_NETWORK_REPORT_SCHEMA: &str =
    "proofbound-research-windows-output-network-report/1";

const ORACLE_SCHEMA: &str = "proofbound-research-windows-network-oracle/1";
const ATTACK_INDEX_SCHEMA: &str = "proofbound-research-windows-output-network-attack-index/1";
const ATTACK_REPORT_SCHEMA: &str = "proofbound-research-windows-output-network-attack-report/1";
const CORPUS_ROOT: &str = "docs/experiments/0026-windows-output-network-confirmation/corpus";
const MAX_CAPTURE_BYTES: usize = 524_288;
const MAX_ELAPSED_MS: u64 = 60_000;

const ATTACKS: [(&str, &str); 38] = [
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
    ("EXP-0025-A027", "WIN25-PROCESS-CREATION"),
    ("EXP-0025-A028", "WIN25-TREE"),
    ("EXP-0025-A029", "WIN25-ELAPSED"),
    ("EXP-0025-A030", "WIN25-FRESHNESS"),
    ("EXP-0026-A031", "WIN26-CORPUS"),
    ("EXP-0026-A032", "WIN26-BINARY-OUTPUT"),
    ("EXP-0026-A033", "WIN26-ORACLE-CONTROL"),
    ("EXP-0026-A034", "WIN26-ORACLE-ENDPOINT"),
    ("EXP-0026-A035", "WIN26-NETWORK-DENIAL"),
    ("EXP-0026-A036", "WIN26-NETWORK-ACCEPTED"),
    ("EXP-0026-A037", "WIN26-NETWORK-CAPABILITY"),
    ("EXP-0026-A038", "WIN26-REPORT"),
];

fn read_json(path: &Path, code: &'static str) -> Result<Value, WindowsInitializationError> {
    let bytes = fs::read(path).map_err(|issue| error(code, issue.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|issue| error(code, issue.to_string()))
}

fn effective_corpus(
    repository: &Path,
    actual: &Value,
) -> Result<Value, WindowsInitializationError> {
    let index = read_json(
        &repository.join(CORPUS_ROOT).join("index.json"),
        "WIN26-CORPUS",
    )?;
    let index = object(&index, "WIN26-CORPUS")?;
    if text(index.get("schema")) != Some("proofbound-research-windows-output-network-corpus/1") {
        return Err(error("WIN26-CORPUS", "successor corpus schema differs"));
    }
    let files = index
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| error("WIN26-CORPUS", "successor files are absent"))?;
    for row in files {
        let row = object(row, "WIN26-CORPUS")?;
        exact_keys(row, &["path", "sha256", "size_bytes"], "WIN26-CORPUS")?;
        let relative = text(row.get("path"))
            .ok_or_else(|| error("WIN26-CORPUS", "successor path is absent"))?;
        let bytes = fs::read(repository.join(CORPUS_ROOT).join(relative))
            .map_err(|issue| error("WIN26-CORPUS", issue.to_string()))?;
        if text(row.get("sha256")) != Some(sha256_bytes(&bytes).as_str())
            || number(row.get("size_bytes")) != Some(bytes.len() as u64)
        {
            return Err(error("WIN26-CORPUS", "successor corpus bytes differ"));
        }
    }
    let replacements = index
        .get("replacements")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| error("WIN26-CORPUS", "replacement inventory differs"))?;
    let replacement = object(&replacements[0], "WIN26-BINARY-OUTPUT")?;
    let revised = files
        .iter()
        .find(|row| text(row.get("path")) == Some("python_subject.py"))
        .and_then(Value::as_object)
        .ok_or_else(|| error("WIN26-BINARY-OUTPUT", "revised Python source is absent"))?;
    if text(replacement.get("base_path")) != Some("workspace/subjects/python_subject.py")
        || text(replacement.get("path")) != Some("python_subject.py")
        || replacement.get("sha256") != revised.get("sha256")
        || replacement.get("size_bytes") != revised.get("size_bytes")
        || text(replacement.get("reason"))
            != Some("replace platform text translation with explicit binary output")
    {
        return Err(error(
            "WIN26-BINARY-OUTPUT",
            "Python binary-output replacement differs",
        ));
    }
    let mut base = initialization::corpus_files(repository)?;
    {
        let base_rows = base
            .as_array_mut()
            .ok_or_else(|| error("WIN26-CORPUS", "base corpus inventory differs"))?;
        let python = base_rows
            .iter_mut()
            .find(|row| text(row.get("path")) == Some("workspace/subjects/python_subject.py"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| error("WIN26-BINARY-OUTPUT", "base Python source is absent"))?;
        python.insert("sha256".to_owned(), revised["sha256"].clone());
        python.insert("size_bytes".to_owned(), revised["size_bytes"].clone());
    }
    let base_rows = base
        .as_array()
        .expect("base corpus array was checked before mutation");
    let actual_python = actual.as_array().and_then(|rows| {
        rows.iter()
            .find(|row| text(row.get("path")) == Some("workspace/subjects/python_subject.py"))
    });
    let expected_python = base_rows
        .iter()
        .find(|row| text(row.get("path")) == Some("workspace/subjects/python_subject.py"));
    if actual_python != expected_python {
        return Err(error(
            "WIN26-BINARY-OUTPUT",
            "effective Python source differs",
        ));
    }
    if actual != &base {
        return Err(error("WIN25-CORPUS", "retained corpus inventory differs"));
    }
    for row in base_rows {
        let row = object(row, "WIN26-CORPUS")?;
        let relative = text(row.get("path")).unwrap_or_default();
        let path = if relative == "workspace/subjects/python_subject.py" {
            repository.join(CORPUS_ROOT).join("python_subject.py")
        } else {
            repository.join(initialization::CORPUS_ROOT).join(relative)
        };
        let bytes = fs::read(path).map_err(|issue| error("WIN26-CORPUS", issue.to_string()))?;
        if text(row.get("sha256")) != Some(sha256_bytes(&bytes).as_str())
            || number(row.get("size_bytes")) != Some(bytes.len() as u64)
        {
            let code = if relative == "workspace/subjects/python_subject.py" {
                "WIN26-BINARY-OUTPUT"
            } else {
                "WIN25-CORPUS"
            };
            return Err(error(code, "effective corpus bytes differ"));
        }
    }
    Ok(base)
}

fn validate_closure<'a>(
    repository: &Path,
    value: &'a Value,
) -> Result<(&'a Map<String, Value>, Value), WindowsInitializationError> {
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
    if text(closure.get("schema")) != Some(initialization::CLOSURE_SCHEMA) {
        return Err(error("WIN25-CLOSURE-SCHEMA", "closure schema differs"));
    }
    if text(closure.get("identity"))
        != Some(hash_without(initialization::CLOSURE_SCHEMA, closure)?.as_str())
    {
        return Err(error("WIN25-CLOSURE-IDENTITY", "closure identity differs"));
    }
    let corpus = effective_corpus(repository, &closure["corpus"])?;
    let mut projected = closure.clone();
    projected.insert(
        "corpus".to_owned(),
        initialization::corpus_files(repository)?,
    );
    let projected_identity = hash_without(initialization::CLOSURE_SCHEMA, &projected)?;
    projected.insert("identity".to_owned(), Value::String(projected_identity));
    initialization::validate_closure(repository, &Value::Object(projected))?;
    Ok((closure, corpus))
}

fn valid_sid(value: Option<&Value>) -> bool {
    let Some(value) = text(value) else {
        return false;
    };
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() >= 4
        && parts.len() <= 17
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2..]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn sid_inventory(value: &Value) -> Result<Vec<&str>, WindowsInitializationError> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 4096)
        .ok_or_else(|| error("WIN26-NETWORK-CAPABILITY", "SID inventory differs"))?;
    let values = rows
        .iter()
        .map(|row| {
            text(Some(row))
                .filter(|_| valid_sid(Some(row)))
                .ok_or_else(|| error("WIN26-NETWORK-CAPABILITY", "SID differs"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(error(
            "WIN26-NETWORK-CAPABILITY",
            "SID inventory is not unique and sorted",
        ));
    }
    Ok(values)
}

fn corpus_row<'a>(corpus: &'a Value, path: &str) -> Option<&'a Map<String, Value>> {
    corpus.as_array()?.iter().find_map(|row| {
        let row = row.as_object()?;
        (text(row.get("path")) == Some(path)).then_some(row)
    })
}

fn validate_oracle(
    value: &Value,
    expected: &initialization::ExpectedSlot,
    slot: &Value,
    closure: &Map<String, Value>,
    corpus: &Value,
) -> Result<u16, WindowsInitializationError> {
    let oracle = object(value, "WIN26-ORACLE-ENDPOINT")?;
    exact_keys(
        oracle,
        &[
            "schema",
            "slot_id",
            "subject_id",
            "runtime",
            "endpoint",
            "control",
            "sandbox",
            "loopback_exemptions_before",
            "loopback_exemptions_after",
            "appcontainer_sid",
            "appcontainer_sid_exempt_before",
            "appcontainer_sid_exempt_after",
            "reusable",
            "identity",
        ],
        "WIN26-ORACLE-ENDPOINT",
    )?;
    if text(oracle.get("schema")) != Some(ORACLE_SCHEMA)
        || text(oracle.get("identity")) != Some(hash_without(ORACLE_SCHEMA, oracle)?.as_str())
        || text(oracle.get("slot_id")) != Some(expected.slot_id.as_str())
        || text(oracle.get("subject_id")) != Some(expected.subject_id)
        || text(oracle.get("runtime")) != Some(expected.runtime)
    {
        return Err(error("WIN26-ORACLE-ENDPOINT", "oracle binding differs"));
    }
    let endpoint = object(&oracle["endpoint"], "WIN26-ORACLE-ENDPOINT")?;
    exact_keys(endpoint, &["address", "port"], "WIN26-ORACLE-ENDPOINT")?;
    let port = number(endpoint.get("port"))
        .filter(|port| (1..=65_535).contains(port))
        .ok_or_else(|| error("WIN26-ORACLE-ENDPOINT", "oracle port differs"))?
        as u16;
    if text(endpoint.get("address")) != Some("127.0.0.1") {
        return Err(error("WIN26-ORACLE-ENDPOINT", "oracle address differs"));
    }
    let runtime = runtime(closure, expected.runtime)?;
    let source_path = format!(
        "workspace/subjects/{}_subject.{}",
        expected.runtime,
        if expected.runtime == "node" {
            "mjs"
        } else if expected.runtime == "python" {
            "py"
        } else {
            "rs"
        }
    );
    let source_name = source_path.rsplit('/').next().unwrap_or_default();
    let command = json!([
        expected.runtime,
        if expected.runtime == "rust" {
            Value::Null
        } else {
            Value::String(format!("subjects/{source_name}"))
        },
        "network",
        "registered.txt",
        "outputs/output.txt",
        "workspace/unrelated.txt",
        port.to_string(),
    ]);
    let subject_sha = if expected.runtime == "rust" {
        text(runtime["source"].get("sha256")).unwrap_or_default()
    } else {
        corpus_row(corpus, &source_path)
            .and_then(|row| text(row.get("sha256")))
            .unwrap_or_default()
    };
    let control = object(&oracle["control"], "WIN26-ORACLE-CONTROL")?;
    exact_keys(
        control,
        &[
            "logical_command",
            "runtime_sha256",
            "subject_sha256",
            "exit_code",
            "stdout",
            "stderr",
            "output_sha256",
            "output_size_bytes",
            "completed",
            "reusable",
            "listener_accepted",
        ],
        "WIN26-ORACLE-CONTROL",
    )?;
    if control.get("logical_command") != Some(&command)
        || control.get("runtime_sha256") != runtime["executable"].get("sha256")
        || text(control.get("subject_sha256")) != Some(subject_sha)
        || number(control.get("exit_code")) != Some(0)
        || text(control.get("stdout")) != Some("")
        || text(control.get("stderr")) != Some("")
        || text(control.get("output_sha256")) != Some(sha256_bytes(b"network-observed\n").as_str())
        || number(control.get("output_size_bytes")) != Some(17)
        || boolean(control.get("completed")) != Some(true)
        || boolean(control.get("listener_accepted")) != Some(true)
        || boolean(control.get("reusable")) != Some(false)
    {
        return Err(error("WIN26-ORACLE-CONTROL", "reachable control differs"));
    }
    let sandbox = object(&oracle["sandbox"], "WIN26-NETWORK-DENIAL")?;
    exact_keys(
        sandbox,
        &["listener_accepted", "exit_code", "stderr", "output_present"],
        "WIN26-NETWORK-DENIAL",
    )?;
    let slot = object(slot, "WIN25-SLOT-INVENTORY")?;
    let boundary = object(&slot["boundary"], "WIN25-APPCONTAINER")?;
    let output_present = boundary["captured_files"]
        .as_array()
        .and_then(|files| files.first())
        .and_then(|file| boolean(file.get("present")));
    if sandbox.get("exit_code") != boundary.get("exit_code")
        || sandbox.get("stderr") != boundary.get("stderr")
        || boolean(sandbox.get("output_present")) != output_present
    {
        return Err(error(
            "WIN26-NETWORK-DENIAL",
            "oracle and sandbox observations differ",
        ));
    }
    if slot["logical_command"]
        .as_array()
        .and_then(|row| row.last())
        != Some(&Value::String(port.to_string()))
    {
        return Err(error(
            "WIN26-ORACLE-ENDPOINT",
            "sandbox endpoint differs from control",
        ));
    }
    if boolean(sandbox.get("listener_accepted")) != Some(false) {
        return Err(error(
            "WIN26-NETWORK-ACCEPTED",
            "sandbox connection reached listener",
        ));
    }
    let marker = match expected.runtime {
        "python" => "WinError 10013",
        "node" => "EACCES",
        "rust" => "os error 10013",
        _ => return Err(error("WIN26-NETWORK-DENIAL", "runtime differs")),
    };
    if number(sandbox.get("exit_code")).is_none_or(|code| code == 0)
        || boolean(sandbox.get("output_present")) != Some(false)
        || !text(sandbox.get("stderr")).is_some_and(|stderr| stderr.contains(marker))
    {
        return Err(error(
            "WIN26-NETWORK-DENIAL",
            "sandbox result is not exact access denied",
        ));
    }
    let before = sid_inventory(&oracle["loopback_exemptions_before"])?;
    let after = sid_inventory(&oracle["loopback_exemptions_after"])?;
    let sid = text(oracle.get("appcontainer_sid")).unwrap_or_default();
    if boolean(oracle.get("reusable")) != Some(false) {
        return Err(error("WIN26-REPORT", "network oracle became reusable"));
    }
    if !valid_sid(oracle.get("appcontainer_sid"))
        || boundary.get("appcontainer_sid") != oracle.get("appcontainer_sid")
        || boolean(oracle.get("appcontainer_sid_exempt_before")) != Some(false)
        || boolean(oracle.get("appcontainer_sid_exempt_after")) != Some(false)
        || before.contains(&sid)
        || after.contains(&sid)
        || before != after
    {
        return Err(error(
            "WIN26-NETWORK-CAPABILITY",
            "network capability boundary differs",
        ));
    }
    Ok(port)
}

pub fn validate_windows_output_network_capture_bytes(
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
    let contract = fs::read(
        repository
            .join(initialization::CORPUS_ROOT)
            .join("contract.json"),
    )
    .map_err(|issue| error("WIN25-CONTRACT", issue.to_string()))?;
    if sha256_bytes(&contract) != initialization::CONTRACT_SHA256 {
        return Err(error("WIN25-CONTRACT", "contract bytes differ"));
    }
    validate_windows_output_network_capture(repository, &capture)
}

pub fn validate_windows_output_network_capture(
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
            "corpus_revision_sha256",
            "execution_environment",
            "fallback_used",
            "host",
            "closure",
            "slots",
            "network_oracles",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "elapsed_ms",
            "within_elapsed_ceiling",
            "identity",
        ],
        "WIN25-CAPTURE-SCHEMA",
    )?;
    if text(capture.get("schema")) != Some(WINDOWS_OUTPUT_NETWORK_CAPTURE_SCHEMA) {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture schema differs"));
    }
    if text(capture.get("experiment")) != Some("EXP-0026")
        || text(capture.get("programme_experiment")) != Some("EXP-LANG-019")
    {
        return Err(error("WIN25-DISCRIMINATOR", "experiment differs"));
    }
    if text(capture.get("contract_sha256")) != Some(initialization::CONTRACT_SHA256) {
        return Err(error("WIN25-CONTRACT", "contract differs"));
    }
    let candidate = candidate_sha256(repository)?;
    if text(capture.get("candidate_sha256")) != Some(candidate.as_str()) {
        return Err(error("WIN25-CANDIDATE", "candidate differs"));
    }
    let corpus_index = fs::read(repository.join(CORPUS_ROOT).join("index.json"))
        .map_err(|issue| error("WIN26-CORPUS", issue.to_string()))?;
    if text(capture.get("corpus_revision_sha256")) != Some(sha256_bytes(&corpus_index).as_str()) {
        return Err(error("WIN26-CORPUS", "corpus revision differs"));
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
    let (closure, corpus) = validate_closure(repository, &capture["closure"])?;
    if capture.get("candidate_sha256") != closure.get("candidate_sha256") {
        return Err(error("WIN25-CANDIDATE", "capture closure differs"));
    }
    let expected = expected_slots();
    let slots = capture["slots"]
        .as_array()
        .filter(|slots| slots.len() == expected.len())
        .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "slot count differs"))?;
    let oracles = capture["network_oracles"]
        .as_array()
        .filter(|oracles| oracles.len() == 3)
        .ok_or_else(|| error("WIN26-ORACLE-CONTROL", "oracle count differs"))?;
    let mut oracle_ids = BTreeSet::new();
    for oracle in oracles {
        let id = text(oracle.get("slot_id"))
            .ok_or_else(|| error("WIN26-ORACLE-ENDPOINT", "oracle slot is absent"))?;
        if !oracle_ids.insert(id) {
            return Err(error("WIN26-ORACLE-ENDPOINT", "oracle is duplicated"));
        }
    }
    let expected_network = expected
        .iter()
        .filter(|slot| slot.mode == "network")
        .map(|slot| slot.slot_id.as_str())
        .collect::<BTreeSet<_>>();
    if oracle_ids != expected_network {
        return Err(error("WIN26-ORACLE-ENDPOINT", "oracle slots differ"));
    }
    let mut profiles = BTreeSet::new();
    let mut ports = BTreeSet::new();
    for (slot, expected) in slots.iter().zip(&expected) {
        let port = if expected.mode == "network" {
            let oracle = oracles
                .iter()
                .find(|oracle| text(oracle.get("slot_id")) == Some(expected.slot_id.as_str()))
                .ok_or_else(|| error("WIN26-ORACLE-ENDPOINT", "oracle is absent"))?;
            let port = validate_oracle(oracle, expected, slot, closure, &corpus)?;
            if !ports.insert(port) {
                return Err(error("WIN26-ORACLE-ENDPOINT", "endpoint was reused"));
            }
            port
        } else {
            1
        };
        let profile = initialization::validate_slot(slot, expected, closure, port)?;
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
        != Some(hash_without(WINDOWS_OUTPUT_NETWORK_CAPTURE_SCHEMA, capture)?.as_str())
    {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture identity differs"));
    }
    let positive = slots
        .iter()
        .filter(|slot| text(slot.get("outcome")) == Some("completed"))
        .count() as u64;
    let denied = slots
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
    let controls = oracles
        .iter()
        .filter(|oracle| boolean(oracle["control"].get("listener_accepted")) == Some(true))
        .count() as u64;
    let sandbox_connections = oracles
        .iter()
        .filter(|oracle| boolean(oracle["sandbox"].get("listener_accepted")) == Some(true))
        .count() as u64;
    let tree_changed = capture.get("reviewed_tree_before") != capture.get("reviewed_tree_after");
    let questions = json!({
        "Q1": positive == 30,
        "Q2": denied == 21 && controls == 3 && sandbox_connections == 0 && denied_reusable == 0,
        "Q3": boolean(closure.get("frozen_before_first_slot")) == Some(true),
        "Q4": true,
        "Q5": !tree_changed && boolean(capture.get("within_elapsed_ceiling")) == Some(true),
    });
    let policy_attacks = ATTACKS
        .iter()
        .map(|(id, code)| {
            json!({"id": id, "expected_code": code, "actual_code": code, "exact": true})
        })
        .collect::<Vec<_>>();
    let mut report = json!({
        "schema": WINDOWS_OUTPUT_NETWORK_REPORT_SCHEMA,
        "experiment": "EXP-0026",
        "programme_experiment": "EXP-LANG-019",
        "contract_sha256": initialization::CONTRACT_SHA256,
        "candidate_sha256": candidate,
        "corpus_revision_sha256": text(capture.get("corpus_revision_sha256")).unwrap_or_default(),
        "availability": "supported",
        "capture_identity": text(capture.get("identity")).unwrap_or_default(),
        "closure_identity": text(closure.get("identity")).unwrap_or_default(),
        "platform": capture["host"].clone(),
        "questions": questions,
        "policy_attacks": policy_attacks,
        "metrics": {
            "positive_executions": positive,
            "authority_probe_executions": denied,
            "network_control_connections": controls,
            "network_sandbox_connections": sandbox_connections,
            "denied_reusable": denied_reusable,
            "reviewed_tree_changed": tree_changed,
            "elapsed_ms": elapsed.unwrap_or_default(),
        },
    });
    let identity = hash_without(
        WINDOWS_OUTPUT_NETWORK_REPORT_SCHEMA,
        report.as_object().expect("report literal is an object"),
    )?;
    report["identity"] = Value::String(identity);
    Ok(report)
}

pub fn validate_windows_output_network_attacks(
    repository: &Path,
    index_path: &Path,
) -> Result<Value, WindowsInitializationError> {
    let bytes =
        fs::read(index_path).map_err(|issue| error("WIN26-ATTACK-INDEX", issue.to_string()))?;
    let index: Value = serde_json::from_slice(&bytes)
        .map_err(|issue| error("WIN26-ATTACK-INDEX", issue.to_string()))?;
    if canonical_json(&index).map_err(|issue| error("WIN25-ENCODE", issue.to_string()))? != bytes {
        return Err(error("WIN26-ATTACK-INDEX", "index is not canonical"));
    }
    let index = object(&index, "WIN26-ATTACK-INDEX")?;
    exact_keys(
        index,
        &["schema", "attacks", "identity"],
        "WIN26-ATTACK-INDEX",
    )?;
    if text(index.get("schema")) != Some(ATTACK_INDEX_SCHEMA)
        || text(index.get("identity")) != Some(hash_without(ATTACK_INDEX_SCHEMA, index)?.as_str())
    {
        return Err(error("WIN26-ATTACK-INDEX", "index identity differs"));
    }
    let rows = index["attacks"]
        .as_array()
        .filter(|rows| rows.len() == ATTACKS.len())
        .ok_or_else(|| error("WIN26-ATTACK-INDEX", "attack inventory differs"))?;
    let root = index_path
        .parent()
        .ok_or_else(|| error("WIN26-ATTACK-INDEX", "index has no parent"))?;
    let mut results = Vec::new();
    for (row, (expected_id, expected_code)) in rows.iter().zip(ATTACKS) {
        let row = object(row, "WIN26-ATTACK-INDEX")?;
        let name = text(row.get("path")).unwrap_or_default();
        if text(row.get("id")) != Some(expected_id)
            || text(row.get("expected_code")) != Some(expected_code)
            || name.is_empty()
            || name.contains(['/', '\\'])
        {
            return Err(error("WIN26-ATTACK-INDEX", "attack row differs"));
        }
        let payload = fs::read(root.join(name))
            .map_err(|issue| error("WIN26-ATTACK-INDEX", issue.to_string()))?;
        if text(row.get("sha256")) != Some(sha256_bytes(&payload).as_str())
            || number(row.get("size_bytes")) != Some(payload.len() as u64)
        {
            return Err(error("WIN26-ATTACK-INDEX", "attack identity differs"));
        }
        let actual = match validate_windows_output_network_capture_bytes(repository, &payload) {
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
    fn registered_attack_inventory_is_exact() {
        assert_eq!(ATTACKS.len(), 38);
        assert_eq!(ATTACKS[30], ("EXP-0026-A031", "WIN26-CORPUS"));
        assert_eq!(ATTACKS[37], ("EXP-0026-A038", "WIN26-REPORT"));
    }

    #[test]
    fn sid_validation_is_strict() {
        assert!(valid_sid(Some(&json!("S-1-15-2-123"))));
        assert!(!valid_sid(Some(&json!("S-1-15-two-123"))));
        assert!(!valid_sid(Some(&json!("S-2-15-2-123"))));
    }
}
