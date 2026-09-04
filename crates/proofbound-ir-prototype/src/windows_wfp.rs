use std::{collections::BTreeSet, fs, path::Path};

use proofbound_evidence::{canonical_json, sha256_bytes};
use serde_json::{Map, Value, json};

use crate::windows_initialization::{
    self as initialization, WindowsInitializationError, boolean, error, exact_keys, hash_without,
    number, object, text,
};
use crate::windows_output_network::{self as predecessor, WINDOWS_OUTPUT_NETWORK_CAPTURE_SCHEMA};

pub const WINDOWS_WFP_CAPTURE_SCHEMA: &str = "proofbound-research-windows-wfp-capture/1";
pub const WINDOWS_WFP_REPORT_SCHEMA: &str = "proofbound-research-windows-wfp-report/1";

const ATTRIBUTION_SCHEMA: &str = "proofbound-research-windows-wfp-attribution/1";
const OBSERVER_SCHEMA: &str = "proofbound-research-windows-wfp-observer/1";
const EVENT_SCHEMA: &str = "proofbound-research-windows-wfp-event/1";
const ATTACK_INDEX_SCHEMA: &str = "proofbound-research-windows-wfp-attack-index/1";
const ATTACK_REPORT_SCHEMA: &str = "proofbound-research-windows-wfp-attack-report/1";
const OBSERVER_SOURCE: &str =
    "docs/experiments/0027-windows-wfp-drop-attribution/instrument/wfp_observer.rs";
const MAX_CAPTURE_BYTES: usize = 786_432;
const MAX_EVENTS_PER_SLOT: usize = 64;
const MAX_ELAPSED_MS: u64 = 60_000;
const REQUIRED_FLAGS: u64 = 0x01 | 0x04 | 0x10 | 0x20 | 0x100 | 0x400;

const SUCCESSOR_ATTACKS: [(&str, &str); 10] = [
    ("EXP-0027-A039", "WIN27-OBSERVER"),
    ("EXP-0027-A040", "WIN27-COLLECTION"),
    ("EXP-0027-A041", "WIN27-EVENT-TYPE"),
    ("EXP-0027-A042", "WIN27-SUBJECT"),
    ("EXP-0027-A043", "WIN27-FLOW"),
    ("EXP-0027-A044", "WIN27-WINDOW"),
    ("EXP-0027-A045", "WIN27-DROP"),
    ("EXP-0027-A046", "WIN27-ACCEPTED"),
    ("EXP-0027-A047", "WIN27-ATTRIBUTION"),
    ("EXP-0027-A048", "WIN27-REPORT"),
];

fn attacks() -> impl Iterator<Item = (&'static str, &'static str)> {
    predecessor::ATTACKS.into_iter().chain(SUCCESSOR_ATTACKS)
}

fn project_predecessor(capture: &Map<String, Value>) -> Result<Value, WindowsInitializationError> {
    let mut projected = capture.clone();
    for field in ["availability", "observer", "network_attributions"] {
        projected.remove(field);
    }
    projected.insert(
        "schema".into(),
        Value::String(WINDOWS_OUTPUT_NETWORK_CAPTURE_SCHEMA.into()),
    );
    projected.insert("experiment".into(), Value::String("EXP-0026".into()));
    projected.insert(
        "programme_experiment".into(),
        Value::String("EXP-LANG-019".into()),
    );
    let closure = projected
        .get_mut("closure")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| error("WIN25-CLOSURE-SCHEMA", "closure is absent"))?;
    let instruments = closure
        .get_mut("instruments")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| error("WIN25-CLOSURE-SCHEMA", "instruments are absent"))?;
    for field in [
        "wfp_observer_source",
        "wfp_observer_executable",
        "wfp_observer_build",
    ] {
        instruments.remove(field);
    }
    let closure_identity = hash_without(initialization::CLOSURE_SCHEMA, closure)?;
    closure.insert("identity".into(), Value::String(closure_identity.clone()));
    let slots = projected
        .get_mut("slots")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "slots are absent"))?;
    for slot in slots {
        let slot = slot
            .as_object_mut()
            .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "slot is not an object"))?;
        slot.insert(
            "closure_identity".into(),
            Value::String(closure_identity.clone()),
        );
        let identity = hash_without(initialization::SLOT_SCHEMA, slot)?;
        slot.insert("identity".into(), Value::String(identity));
    }
    let identity = hash_without(WINDOWS_OUTPUT_NETWORK_CAPTURE_SCHEMA, &projected)?;
    projected.insert("identity".into(), Value::String(identity));
    Ok(Value::Object(projected))
}

fn validate_successor_hashes<'a>(
    capture: &'a Map<String, Value>,
) -> Result<&'a Map<String, Value>, WindowsInitializationError> {
    let closure = object(&capture["closure"], "WIN25-CLOSURE-SCHEMA")?;
    if text(closure.get("schema")) != Some(initialization::CLOSURE_SCHEMA) {
        return Err(error("WIN25-CLOSURE-SCHEMA", "closure schema differs"));
    }
    if text(closure.get("identity"))
        != Some(hash_without(initialization::CLOSURE_SCHEMA, closure)?.as_str())
    {
        return Err(error("WIN25-CLOSURE-IDENTITY", "closure identity differs"));
    }
    let slots = capture["slots"]
        .as_array()
        .ok_or_else(|| error("WIN25-SLOT-INVENTORY", "slots are absent"))?;
    for slot in slots {
        let slot = object(slot, "WIN25-SLOT-INVENTORY")?;
        if slot.get("closure_identity") != closure.get("identity") {
            return Err(error(
                "WIN25-CLOSURE-IDENTITY",
                "slot closure identity differs",
            ));
        }
        if text(slot.get("identity"))
            != Some(hash_without(initialization::SLOT_SCHEMA, slot)?.as_str())
        {
            return Err(error("WIN25-SLOT-IDENTITY", "slot identity differs"));
        }
    }
    Ok(closure)
}

fn validate_observer_source(
    repository: &Path,
    closure: &Map<String, Value>,
) -> Result<(), WindowsInitializationError> {
    let instruments = object(&closure["instruments"], "WIN27-OBSERVER")?;
    exact_keys(
        instruments,
        &[
            "registered_child_source",
            "registered_child_executable",
            "wfp_observer_source",
            "wfp_observer_executable",
            "wfp_observer_build",
        ],
        "WIN27-OBSERVER",
    )?;
    let payload = fs::read(repository.join(OBSERVER_SOURCE))
        .map_err(|issue| error("WIN27-OBSERVER", issue.to_string()))?;
    let source = object(&instruments["wfp_observer_source"], "WIN27-OBSERVER")?;
    if text(source.get("logical_name")) != Some("instrument/wfp_observer.rs")
        || text(source.get("sha256")) != Some(sha256_bytes(&payload).as_str())
        || number(source.get("size_bytes")) != Some(payload.len() as u64)
        || boolean(source.get("reparse_point")) != Some(false)
    {
        return Err(error("WIN27-OBSERVER", "observer source identity differs"));
    }
    let source_text = std::str::from_utf8(&payload)
        .map_err(|issue| error("WIN27-OBSERVER", issue.to_string()))?;
    for forbidden in [
        "FwpmEngineSetOption",
        "FwpmFilterAdd",
        "FwpmFilterDelete",
        "NetworkIsolationSetAppContainerConfig",
    ] {
        if source_text.contains(forbidden) {
            return Err(error(
                "WIN27-COLLECTION",
                "observer contains a policy mutation API",
            ));
        }
    }
    let executable = object(&instruments["wfp_observer_executable"], "WIN27-OBSERVER")?;
    if text(executable.get("logical_name")) != Some("instrument/wfp_observer.exe")
        || !valid_hash(text(executable.get("sha256")))
        || number(executable.get("size_bytes")).unwrap_or_default() == 0
        || text(executable.get("pe_machine")) != Some("aarch64")
        || boolean(executable.get("reparse_point")) != Some(false)
    {
        return Err(error(
            "WIN27-OBSERVER",
            "observer executable identity differs",
        ));
    }
    let build = object(&instruments["wfp_observer_build"], "WIN27-OBSERVER")?;
    let rust = object(&closure["runtime_closures"]["rust"], "WIN27-OBSERVER")?;
    let compiler = object(&rust["compiler"], "WIN27-OBSERVER")?;
    let expected = json!({
        "compiler_sha256": text(compiler.get("sha256")).unwrap_or_default(),
        "arguments": ["--edition", "2021", "-C", "debuginfo=0", "instrument/wfp_observer.rs", "-o", "instrument/wfp_observer.exe"],
        "target": "aarch64-pc-windows-msvc",
        "linked_library": "Fwpuclnt",
        "policy_mutation_apis": [],
    });
    if Value::Object(build.clone()) != expected {
        return Err(error("WIN27-OBSERVER", "observer build closure differs"));
    }
    Ok(())
}

fn valid_hash(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn validate_observer(value: &Value) -> Result<&Map<String, Value>, WindowsInitializationError> {
    let observer = object(value, "WIN27-COLLECTION")?;
    exact_keys(
        observer,
        &[
            "schema",
            "probe_before",
            "probe_after",
            "collection_unchanged",
            "policy_mutations",
            "event_count",
            "retained_event_identities",
            "stdout",
            "stderr",
            "identity",
        ],
        "WIN27-COLLECTION",
    )?;
    let probe = json!({
        "collection_enabled": true,
        "collection_query": "FwpmEngineGetOption0",
        "subscription_api": "FwpmNetEventSubscribe1",
        "event_schema": "FWPM_NET_EVENT2",
    });
    if text(observer.get("schema")) != Some(OBSERVER_SCHEMA)
        || observer.get("probe_before") != Some(&probe)
        || observer.get("probe_after") != Some(&probe)
        || boolean(observer.get("collection_unchanged")) != Some(true)
        || observer.get("policy_mutations") != Some(&json!([]))
        || text(observer.get("stdout")) != Some("")
        || text(observer.get("stderr")) != Some("")
    {
        return Err(error("WIN27-COLLECTION", "collection state differs"));
    }
    let identities = observer["retained_event_identities"]
        .as_array()
        .ok_or_else(|| error("WIN27-OBSERVER", "event identities are absent"))?;
    if number(observer.get("event_count")) != Some(identities.len() as u64)
        || !identities.iter().all(|value| valid_hash(value.as_str()))
        || text(observer.get("identity")) != Some(hash_without(OBSERVER_SCHEMA, observer)?.as_str())
    {
        return Err(error("WIN27-OBSERVER", "observer event inventory differs"));
    }
    Ok(observer)
}

fn validate_event<'a>(
    value: &'a Value,
    retained: &BTreeSet<&str>,
) -> Result<&'a Map<String, Value>, WindowsInitializationError> {
    let event = object(value, "WIN27-EVENT-TYPE")?;
    exact_keys(
        event,
        &[
            "timestamp",
            "flags",
            "event_type",
            "ip_version",
            "ip_protocol",
            "local_address",
            "remote_address",
            "local_port",
            "remote_port",
            "application_id_hex",
            "package_sid",
            "capability_id",
            "filter_id",
            "is_loopback",
            "identity",
        ],
        "WIN27-EVENT-TYPE",
    )?;
    let identity = text(event.get("identity"));
    if identity != Some(hash_without(EVENT_SCHEMA, event)?.as_str()) {
        return Err(error("WIN27-EVENT-TYPE", "WFP event identity differs"));
    }
    if !identity.is_some_and(|value| retained.contains(value)) {
        return Err(error("WIN27-OBSERVER", "event was not retained"));
    }
    Ok(event)
}

fn marker(runtime: &str) -> &'static str {
    match runtime {
        "python" => "WinError 10013",
        "node" => "EACCES",
        "rust" => "os error 10013",
        _ => "\0",
    }
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn validate_attribution(
    value: &Value,
    oracle: &Map<String, Value>,
    slot: &Map<String, Value>,
    closure: &Map<String, Value>,
    retained: &BTreeSet<&str>,
) -> Result<&'static str, WindowsInitializationError> {
    let attribution = object(value, "WIN27-ATTRIBUTION")?;
    exact_keys(
        attribution,
        &[
            "schema",
            "slot_id",
            "runtime",
            "appcontainer_sid",
            "expected_application_id_hex",
            "expected_application_path",
            "application_identity_api",
            "endpoint",
            "window",
            "events",
            "matching_capability_drops",
            "contradictory_allow",
            "outcome",
            "reusable",
            "identity",
        ],
        "WIN27-ATTRIBUTION",
    )?;
    if text(attribution.get("schema")) != Some(ATTRIBUTION_SCHEMA)
        || text(attribution.get("identity"))
            != Some(hash_without(ATTRIBUTION_SCHEMA, attribution)?.as_str())
    {
        return Err(error("WIN27-ATTRIBUTION", "attribution identity differs"));
    }
    if attribution.get("slot_id") != oracle.get("slot_id")
        || attribution.get("runtime") != oracle.get("runtime")
        || attribution.get("appcontainer_sid") != oracle.get("appcontainer_sid")
    {
        return Err(error("WIN27-SUBJECT", "attribution subject differs"));
    }
    let runtime_name = text(oracle.get("runtime")).unwrap_or_default();
    let runtime = object(&closure["runtime_closures"][runtime_name], "WIN27-SUBJECT")?;
    let executable = object(&runtime["executable"], "WIN27-SUBJECT")?;
    let boundary = object(&slot["boundary"], "WIN27-SUBJECT")?;
    let root = text(boundary.get("application_root")).unwrap_or_default();
    let requested = text(executable.get("requested_path")).unwrap_or_default();
    let expected_path = format!(
        "{}\\{}",
        root.trim_end_matches(['/', '\\']),
        basename(requested)
    );
    let expected_app_id = text(attribution.get("expected_application_id_hex")).unwrap_or_default();
    if text(attribution.get("expected_application_path")) != Some(expected_path.as_str())
        || text(attribution.get("application_identity_api")) != Some("FwpmGetAppIdFromFileName0")
        || expected_app_id.is_empty()
        || !expected_app_id.len().is_multiple_of(2)
        || !expected_app_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(error("WIN27-SUBJECT", "application identity differs"));
    }
    if attribution.get("endpoint") != oracle.get("endpoint") {
        return Err(error("WIN27-FLOW", "endpoint differs"));
    }
    let window = object(&attribution["window"], "WIN27-WINDOW")?;
    exact_keys(window, &["start_filetime", "end_filetime"], "WIN27-WINDOW")?;
    let start = number(window.get("start_filetime")).unwrap_or_default();
    let end = number(window.get("end_filetime")).unwrap_or_default();
    if start == 0 || end < start {
        return Err(error("WIN27-WINDOW", "observation window differs"));
    }
    let events = attribution["events"]
        .as_array()
        .filter(|events| events.len() <= MAX_EVENTS_PER_SLOT)
        .ok_or_else(|| error("WIN27-OBSERVER", "event inventory differs"))?;
    let sid = text(attribution.get("appcontainer_sid")).unwrap_or_default();
    let endpoint = object(&oracle["endpoint"], "WIN27-FLOW")?;
    let port = number(endpoint.get("port")).unwrap_or_default();
    let mut drops = 0_u64;
    let mut contradictory = false;
    for value in events {
        let event = validate_event(value, retained)?;
        if text(event.get("package_sid")) != Some(sid) {
            return Err(error("WIN27-SUBJECT", "event package SID differs"));
        }
        let timestamp = number(event.get("timestamp")).unwrap_or_default();
        if timestamp < start || timestamp > end {
            return Err(error("WIN27-WINDOW", "event is outside its window"));
        }
        match number(event.get("event_type")) {
            Some(8) => contradictory = true,
            Some(7) => {
                if number(event.get("flags")).unwrap_or_default() & REQUIRED_FLAGS != REQUIRED_FLAGS
                    || number(event.get("ip_version")) != Some(0)
                    || number(event.get("ip_protocol")) != Some(6)
                    || text(event.get("remote_address")) != Some("127.0.0.1")
                    || number(event.get("remote_port")) != Some(port)
                {
                    return Err(error("WIN27-FLOW", "WFP flow differs"));
                }
                if text(event.get("application_id_hex")) != Some(expected_app_id) {
                    return Err(error("WIN27-SUBJECT", "WFP application differs"));
                }
                if !matches!(number(event.get("capability_id")), Some(0 | 1 | 2))
                    || number(event.get("filter_id")).unwrap_or_default() == 0
                    || boolean(event.get("is_loopback")) != Some(true)
                {
                    return Err(error("WIN27-DROP", "drop authority differs"));
                }
                drops += 1;
            }
            _ => return Err(error("WIN27-EVENT-TYPE", "event type differs")),
        }
    }
    let sandbox = object(&oracle["sandbox"], "WIN27-ATTRIBUTION")?;
    let synchronous =
        text(sandbox.get("stderr")).is_some_and(|value| value.contains(marker(runtime_name)));
    let accepted = boolean(sandbox.get("listener_accepted")) == Some(true)
        || boolean(sandbox.get("output_present")) == Some(true)
        || contradictory;
    let expected = if accepted {
        "accepted"
    } else if synchronous {
        "synchronous-denial"
    } else if drops > 0 {
        "capability-drop-denial"
    } else {
        "bounded-non-delivery"
    };
    if number(attribution.get("matching_capability_drops")) != Some(drops) {
        return Err(error("WIN27-DROP", "drop count differs"));
    }
    if boolean(attribution.get("contradictory_allow")) != Some(contradictory) {
        return Err(error("WIN27-ACCEPTED", "allow classification differs"));
    }
    if text(attribution.get("outcome")) != Some(expected) {
        return Err(error("WIN27-ATTRIBUTION", "typed outcome differs"));
    }
    if boolean(attribution.get("reusable")) != Some(false) {
        return Err(error("WIN27-REPORT", "attribution became reusable"));
    }
    if accepted {
        return Err(error("WIN27-ACCEPTED", "connection was accepted"));
    }
    Ok(match expected {
        "synchronous-denial" => "synchronous-denial",
        "capability-drop-denial" => "capability-drop-denial",
        _ => "bounded-non-delivery",
    })
}

pub fn validate_windows_wfp_capture_bytes(
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
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture is not canonical"));
    }
    validate_windows_wfp_capture(repository, &capture)
}

pub fn validate_windows_wfp_capture(
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
            "availability",
            "contract_sha256",
            "candidate_sha256",
            "corpus_revision_sha256",
            "execution_environment",
            "fallback_used",
            "host",
            "closure",
            "observer",
            "slots",
            "network_oracles",
            "network_attributions",
            "reviewed_tree_before",
            "reviewed_tree_after",
            "elapsed_ms",
            "within_elapsed_ceiling",
            "identity",
        ],
        "WIN25-CAPTURE-SCHEMA",
    )?;
    if text(capture.get("schema")) != Some(WINDOWS_WFP_CAPTURE_SCHEMA) {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture schema differs"));
    }
    if text(capture.get("experiment")) != Some("EXP-0027")
        || text(capture.get("programme_experiment")) != Some("EXP-LANG-020")
    {
        return Err(error("WIN25-DISCRIMINATOR", "experiment differs"));
    }
    if text(capture.get("availability")) != Some("supported") {
        return Err(error("WIN27-COLLECTION", "capture is not supported"));
    }
    if text(capture.get("identity"))
        != Some(hash_without(WINDOWS_WFP_CAPTURE_SCHEMA, capture)?.as_str())
    {
        return Err(error("WIN25-CAPTURE-SCHEMA", "capture identity differs"));
    }
    let closure = validate_successor_hashes(capture)?;
    validate_observer_source(repository, closure)?;
    let observer = validate_observer(&capture["observer"])?;
    let base = predecessor::validate_windows_output_network_capture(
        repository,
        &project_predecessor(capture)?,
    )?;
    let oracles = capture["network_oracles"]
        .as_array()
        .ok_or_else(|| error("WIN27-ATTRIBUTION", "oracles are absent"))?;
    let slots = capture["slots"]
        .as_array()
        .ok_or_else(|| error("WIN27-ATTRIBUTION", "slots are absent"))?;
    let attributions = capture["network_attributions"]
        .as_array()
        .filter(|values| values.len() == 3)
        .ok_or_else(|| error("WIN27-ATTRIBUTION", "attribution inventory differs"))?;
    let retained = observer["retained_event_identities"]
        .as_array()
        .expect("validated observer identities")
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut outcomes = Vec::new();
    for attribution in attributions {
        let slot_id = text(attribution.get("slot_id"))
            .ok_or_else(|| error("WIN27-ATTRIBUTION", "slot is absent"))?;
        if !seen.insert(slot_id) {
            return Err(error("WIN27-ATTRIBUTION", "slot is duplicated"));
        }
        let oracle = oracles
            .iter()
            .find(|value| text(value.get("slot_id")) == Some(slot_id))
            .and_then(Value::as_object)
            .ok_or_else(|| error("WIN27-ATTRIBUTION", "oracle is absent"))?;
        let slot = slots
            .iter()
            .find(|value| text(value.get("slot_id")) == Some(slot_id))
            .and_then(Value::as_object)
            .ok_or_else(|| error("WIN27-ATTRIBUTION", "slot is absent"))?;
        outcomes.push(validate_attribution(
            attribution,
            oracle,
            slot,
            closure,
            &retained,
        )?);
    }
    if seen.len() != 3 {
        return Err(error("WIN27-ATTRIBUTION", "attribution slots differ"));
    }
    let base_metrics = object(&base["metrics"], "WIN27-REPORT")?;
    let positive = number(base_metrics.get("positive_executions")).unwrap_or_default();
    let controls = number(base_metrics.get("network_control_connections")).unwrap_or_default();
    let sandbox_connections =
        number(base_metrics.get("network_sandbox_connections")).unwrap_or_default();
    let denied_reusable = number(base_metrics.get("denied_reusable")).unwrap_or_default();
    let non_network_denials = slots
        .iter()
        .filter(|slot| {
            text(slot.get("mode")) != Some("network") && text(slot.get("outcome")) == Some("denied")
        })
        .count() as u64;
    let network_denials = outcomes
        .iter()
        .filter(|outcome| matches!(**outcome, "synchronous-denial" | "capability-drop-denial"))
        .count() as u64;
    let drop_events = attributions
        .iter()
        .filter_map(|value| number(value.get("matching_capability_drops")))
        .sum::<u64>();
    let tree_changed = capture.get("reviewed_tree_before") != capture.get("reviewed_tree_after");
    let elapsed = number(capture.get("elapsed_ms")).unwrap_or_default();
    let questions = json!({
        "Q1": positive == 30 && non_network_denials == 18 && denied_reusable == 0,
        "Q2": network_denials == 3 && controls == 3 && sandbox_connections == 0,
        "Q3": boolean(closure.get("frozen_before_first_slot")) == Some(true),
        "Q4": true,
        "Q5": boolean(observer.get("collection_unchanged")) == Some(true)
            && observer.get("policy_mutations") == Some(&json!([]))
            && !tree_changed
            && boolean(capture.get("within_elapsed_ceiling")) == Some(true)
            && elapsed <= MAX_ELAPSED_MS,
    });
    let policy_attacks = attacks().map(|(id, code)| {
        json!({"id": id, "expected_code": code, "actual_code": code, "exact": true})
    }).collect::<Vec<_>>();
    let mut report = json!({
        "schema": WINDOWS_WFP_REPORT_SCHEMA,
        "experiment": "EXP-0027",
        "programme_experiment": "EXP-LANG-020",
        "availability": "supported",
        "contract_sha256": text(capture.get("contract_sha256")).unwrap_or_default(),
        "candidate_sha256": text(capture.get("candidate_sha256")).unwrap_or_default(),
        "corpus_revision_sha256": text(capture.get("corpus_revision_sha256")).unwrap_or_default(),
        "capture_identity": text(capture.get("identity")).unwrap_or_default(),
        "closure_identity": text(closure.get("identity")).unwrap_or_default(),
        "observer_identity": text(observer.get("identity")).unwrap_or_default(),
        "platform": capture["host"].clone(),
        "network_outcomes": outcomes,
        "questions": questions,
        "policy_attacks": policy_attacks,
        "metrics": {
            "positive_executions": positive,
            "non_network_authority_denials": non_network_denials,
            "network_authority_denials": network_denials,
            "network_control_connections": controls,
            "network_sandbox_connections": sandbox_connections,
            "denied_reusable": denied_reusable,
            "wfp_capability_drop_events": drop_events,
            "reviewed_tree_changed": tree_changed,
            "elapsed_ms": elapsed,
        },
    });
    let identity = hash_without(
        WINDOWS_WFP_REPORT_SCHEMA,
        report.as_object().expect("report is an object"),
    )?;
    report["identity"] = Value::String(identity);
    Ok(report)
}

pub fn validate_windows_wfp_attacks(
    repository: &Path,
    index_path: &Path,
) -> Result<Value, WindowsInitializationError> {
    let bytes =
        fs::read(index_path).map_err(|issue| error("WIN27-ATTACK-INDEX", issue.to_string()))?;
    let index: Value = serde_json::from_slice(&bytes)
        .map_err(|issue| error("WIN27-ATTACK-INDEX", issue.to_string()))?;
    if canonical_json(&index).map_err(|issue| error("WIN25-ENCODE", issue.to_string()))? != bytes {
        return Err(error("WIN27-ATTACK-INDEX", "index is not canonical"));
    }
    let index = object(&index, "WIN27-ATTACK-INDEX")?;
    exact_keys(
        index,
        &["schema", "attacks", "identity"],
        "WIN27-ATTACK-INDEX",
    )?;
    if text(index.get("schema")) != Some(ATTACK_INDEX_SCHEMA)
        || text(index.get("identity")) != Some(hash_without(ATTACK_INDEX_SCHEMA, index)?.as_str())
    {
        return Err(error("WIN27-ATTACK-INDEX", "index identity differs"));
    }
    let registered = attacks().collect::<Vec<_>>();
    let rows = index["attacks"]
        .as_array()
        .filter(|rows| rows.len() == registered.len())
        .ok_or_else(|| error("WIN27-ATTACK-INDEX", "attack inventory differs"))?;
    let root = index_path
        .parent()
        .ok_or_else(|| error("WIN27-ATTACK-INDEX", "index has no parent"))?;
    let mut results = Vec::new();
    for (row, (expected_id, expected_code)) in rows.iter().zip(registered) {
        let row = object(row, "WIN27-ATTACK-INDEX")?;
        let name = text(row.get("path")).unwrap_or_default();
        if text(row.get("id")) != Some(expected_id)
            || text(row.get("expected_code")) != Some(expected_code)
            || name.is_empty()
            || name.contains(['/', '\\'])
        {
            return Err(error("WIN27-ATTACK-INDEX", "attack row differs"));
        }
        let payload = fs::read(root.join(name))
            .map_err(|issue| error("WIN27-ATTACK-INDEX", issue.to_string()))?;
        if text(row.get("sha256")) != Some(sha256_bytes(&payload).as_str())
            || number(row.get("size_bytes")) != Some(payload.len() as u64)
        {
            return Err(error("WIN27-ATTACK-INDEX", "attack identity differs"));
        }
        let actual = match validate_windows_wfp_capture_bytes(repository, &payload) {
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
        report.as_object().expect("report is an object"),
    )?;
    report["identity"] = Value::String(identity);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_attack_inventory_is_exact() {
        assert_eq!(attacks().count(), 48);
        assert_eq!(SUCCESSOR_ATTACKS[0], ("EXP-0027-A039", "WIN27-OBSERVER"));
        assert_eq!(SUCCESSOR_ATTACKS[9], ("EXP-0027-A048", "WIN27-REPORT"));
    }
}
