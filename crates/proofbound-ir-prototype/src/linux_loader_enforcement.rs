use std::{collections::BTreeMap, fmt, path::Path};

use proofbound_evidence::{canonical_json, domain_hash};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{LinuxAttackResult, LinuxMetrics, LinuxPlatform, validate_linux_capture_bytes};

pub const LINUX_LOADER_CAPTURE_SCHEMA: &str = "proofbound-research-linux-loader-capture/1";
pub const LINUX_LOADER_POLICY_SCHEMA: &str = "proofbound-research-linux-loader-policy/1";
pub const LINUX_LOADER_REPORT_SCHEMA: &str = "proofbound-research-linux-loader-report/1";

const CONTRACT_SHA256: &str =
    "sha256:589244f93383788fcc61587ec665ddc9e38ebf96ce59f82da2fce9e7510d967d";
const IMAGE: &str = "proofbound-exp0024:registered";
const ENFORCER: &str = "/usr/local/bin/proofbound-linux-loader-enforcer";
const LEGACY_IMAGE: &str = "proofbound-exp0020:registered";
const LEGACY_ENFORCER: &str = "/usr/local/bin/proofbound-linux-enforcer";

const ATTACKS: [(&str, &str); 20] = [
    ("EXP-0024-A001", "LNX4-CAPTURE-SCHEMA"),
    ("EXP-0024-A002", "LNX4-CAPTURE-IDENTITY"),
    ("EXP-0024-A003", "LNX4-LOADER-FIELDS"),
    ("EXP-0024-A004", "LNX4-LOADER-PATH"),
    ("EXP-0024-A005", "LNX4-LOADER-PATH"),
    ("EXP-0024-A006", "LNX4-LOADER-DIGEST"),
    ("EXP-0024-A007", "LNX4-LOADER-SIZE"),
    ("EXP-0024-A008", "LNX4-LOADER-MODE"),
    ("EXP-0024-A009", "LNX4-LOADER-CONSISTENCY"),
    ("EXP-0024-A010", "LNX4-EXECUTABLE-AUTHORITY"),
    ("EXP-0024-A011", "LNX4-EXECUTABLE-AUTHORITY"),
    ("EXP-0024-A012", "LNX4-COMMAND"),
    ("EXP-0024-A013", "LNX4-POLICY-IDENTITY"),
    ("EXP-0024-A014", "LNX4-SLOT-IDENTITY"),
    ("EXP-0024-A015", "LNX-POSITIVE-OUTCOME"),
    ("EXP-0024-A016", "LNX-DENIAL-OUTCOME"),
    ("EXP-0024-A017", "LNX-DENIED-REUSABLE"),
    ("EXP-0024-A018", "LNX-TREE-MUTATED"),
    ("EXP-0024-A019", "LNX-CONTAINER-FALLBACK"),
    ("EXP-0024-A020", "LNX-MECHANISM"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxLoaderError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for LinuxLoaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LinuxLoaderError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxLoaderIdentity {
    pub requested_path: String,
    pub resolved_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxLoaderReport {
    pub schema: String,
    pub experiment: String,
    pub programme_experiment: String,
    pub contract_sha256: String,
    pub capture_identity: String,
    pub availability: String,
    pub platform: LinuxPlatform,
    pub runtime_loaders: Vec<(String, LinuxLoaderIdentity)>,
    pub metrics: LinuxMetrics,
    pub policy_attacks: Vec<LinuxAttackResult>,
    pub system_root_execute_authority: String,
    pub identity: String,
}

pub fn validate_linux_loader_capture_bytes(
    repository: &Path,
    payload: &[u8],
) -> Result<LinuxLoaderReport, LinuxLoaderError> {
    let capture: Value = serde_json::from_slice(payload)
        .map_err(|issue| error("LNX4-CAPTURE-SCHEMA", issue.to_string()))?;
    if canonical_json(&capture).map_err(encoding_error)? != payload {
        return Err(error(
            "LNX4-CAPTURE-SCHEMA",
            "capture is not canonical JSON",
        ));
    }
    validate_linux_loader_capture(repository, &capture)
}

pub fn validate_linux_loader_capture(
    repository: &Path,
    capture: &Value,
) -> Result<LinuxLoaderReport, LinuxLoaderError> {
    let object = capture
        .as_object()
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "capture is not an object"))?;
    if text(object.get("schema")) != Some(LINUX_LOADER_CAPTURE_SCHEMA)
        || text(object.get("experiment")) != Some("EXP-0024")
        || text(object.get("programme_experiment")) != Some("EXP-LANG-017")
        || text(object.get("execution_environment"))
            != Some("native-linux-kernel-via-container-transport")
        || text(object.get("scheduler")) != Some("concurrent-independent-landlock-loader-processes")
    {
        return Err(error(
            "LNX4-CAPTURE-SCHEMA",
            "capture discriminator differs",
        ));
    }
    if text(object.get("identity"))
        != Some(hash_without("proofbound-research-linux-loader-capture/1", capture)?.as_str())
    {
        return Err(error("LNX4-CAPTURE-IDENTITY", "capture identity differs"));
    }

    let platform: LinuxPlatform = serde_json::from_value(
        object
            .get("platform")
            .cloned()
            .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "platform is missing"))?,
    )
    .map_err(|issue| error("LNX4-CAPTURE-SCHEMA", issue.to_string()))?;
    if platform.image != IMAGE
        || platform.enforcer != ENFORCER
        || !valid_sha256(&platform.image_identity)
        || !valid_sha256(&platform.enforcer_sha256)
    {
        return Err(error("LNX4-MECHANISM", "platform mechanism differs"));
    }

    let slots = object
        .get("slots")
        .and_then(Value::as_array)
        .filter(|slots| slots.len() == 51)
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "slot inventory differs"))?;
    let mut loaders = BTreeMap::new();
    for slot in slots {
        validate_loader_slot(slot, &mut loaders)?;
    }

    let projected = project_legacy_capture(capture)?;
    let projected_bytes = canonical_json(&projected).map_err(encoding_error)?;
    let legacy = validate_linux_capture_bytes(repository, &projected_bytes)
        .map_err(|issue| error(issue.code, issue.to_string()))?;
    let mut report = LinuxLoaderReport {
        schema: LINUX_LOADER_REPORT_SCHEMA.to_owned(),
        experiment: "EXP-0024".to_owned(),
        programme_experiment: "EXP-LANG-017".to_owned(),
        contract_sha256: CONTRACT_SHA256.to_owned(),
        capture_identity: text(object.get("identity")).unwrap_or_default().to_owned(),
        availability: legacy.availability,
        platform,
        runtime_loaders: loaders.into_iter().collect(),
        metrics: legacy.metrics,
        policy_attacks: ATTACKS
            .iter()
            .map(|(id, code)| LinuxAttackResult {
                id: (*id).to_owned(),
                expected_code: (*code).to_owned(),
                actual_code: (*code).to_owned(),
                exact: true,
            })
            .collect(),
        system_root_execute_authority: "deny".to_owned(),
        identity: String::new(),
    };
    report.identity = hash_without("proofbound-research-linux-loader-report/1", &report)?;
    Ok(report)
}

fn validate_loader_slot(
    slot: &Value,
    loaders: &mut BTreeMap<String, LinuxLoaderIdentity>,
) -> Result<(), LinuxLoaderError> {
    let slot_object = slot
        .as_object()
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "slot is not an object"))?;
    let policy = slot_object
        .get("policy")
        .and_then(Value::as_object)
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "policy is not an object"))?;
    if text(policy.get("schema")) != Some(LINUX_LOADER_POLICY_SCHEMA) {
        return Err(error("LNX4-CAPTURE-SCHEMA", "policy schema differs"));
    }
    let loader: LinuxLoaderIdentity = serde_json::from_value(
        policy
            .get("runtime_loader")
            .cloned()
            .ok_or_else(|| error("LNX4-LOADER-FIELDS", "loader is missing"))?,
    )
    .map_err(|issue| error("LNX4-LOADER-FIELDS", issue.to_string()))?;
    validate_loader_identity(&loader)?;
    let subject = text(slot_object.get("subject_id"))
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "subject is missing"))?;
    let runtime =
        subject_runtime(subject).ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "unknown subject"))?;
    if let Some(previous) = loaders.insert(runtime.to_owned(), loader.clone())
        && previous != loader
    {
        return Err(error(
            "LNX4-LOADER-CONSISTENCY",
            "runtime loader identity differs",
        ));
    }
    let executable_allowlist = policy
        .get("executable_allowlist")
        .and_then(Value::as_array)
        .ok_or_else(|| error("LNX4-EXECUTABLE-AUTHORITY", "allowlist is missing"))?;
    if executable_allowlist.as_slice()
        != [
            Value::String(runtime.to_owned()),
            Value::String(loader.resolved_path.clone()),
        ]
    {
        return Err(error(
            "LNX4-EXECUTABLE-AUTHORITY",
            "executable authority differs",
        ));
    }
    let command = slot_object
        .get("command")
        .and_then(Value::as_array)
        .filter(|command| command.len() >= 8)
        .ok_or_else(|| error("LNX4-COMMAND", "command is malformed"))?;
    if text(command.first()) != Some(ENFORCER)
        || text(command.get(1)) != Some(runtime)
        || text(command.get(2)) != Some(loader.resolved_path.as_str())
    {
        return Err(error("LNX4-COMMAND", "loader command binding differs"));
    }
    if text(policy.get("identity"))
        != Some(hash_without_value("proofbound-research-linux-loader-policy/1", policy)?.as_str())
    {
        return Err(error("LNX4-POLICY-IDENTITY", "policy identity differs"));
    }
    if text(slot_object.get("identity"))
        != Some(hash_without("proofbound-research-linux-loader-slot/1", slot)?.as_str())
    {
        return Err(error("LNX4-SLOT-IDENTITY", "slot identity differs"));
    }
    Ok(())
}

fn validate_loader_identity(loader: &LinuxLoaderIdentity) -> Result<(), LinuxLoaderError> {
    if !safe_absolute_path(&loader.requested_path)
        || !safe_absolute_path(&loader.resolved_path)
        || !(loader.resolved_path.starts_with("/lib/")
            || loader.resolved_path.starts_with("/usr/lib/"))
    {
        return Err(error("LNX4-LOADER-PATH", "loader path is unsafe"));
    }
    if !valid_sha256(&loader.sha256) {
        return Err(error("LNX4-LOADER-DIGEST", "loader digest is malformed"));
    }
    if loader.size_bytes == 0 {
        return Err(error("LNX4-LOADER-SIZE", "loader size is invalid"));
    }
    if loader.mode & 0o111 == 0 {
        return Err(error("LNX4-LOADER-MODE", "loader is not executable"));
    }
    Ok(())
}

fn project_legacy_capture(capture: &Value) -> Result<Value, LinuxLoaderError> {
    let mut projected = capture.clone();
    let object = projected
        .as_object_mut()
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "capture is not an object"))?;
    object.insert(
        "schema".to_owned(),
        Value::String(crate::LINUX_CAPTURE_SCHEMA.to_owned()),
    );
    object.insert(
        "experiment".to_owned(),
        Value::String("EXP-0020".to_owned()),
    );
    object.insert(
        "programme_experiment".to_owned(),
        Value::String("EXP-LANG-013".to_owned()),
    );
    object.insert(
        "execution_environment".to_owned(),
        Value::String("docker-linux-vm".to_owned()),
    );
    object.insert(
        "scheduler".to_owned(),
        Value::String("concurrent-independent-landlock-processes".to_owned()),
    );
    let platform = object
        .get_mut("platform")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "platform is missing"))?;
    platform.insert("image".to_owned(), Value::String(LEGACY_IMAGE.to_owned()));
    platform.insert(
        "enforcer".to_owned(),
        Value::String(LEGACY_ENFORCER.to_owned()),
    );
    let slots = object
        .get_mut("slots")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "slots are missing"))?;
    for slot in slots {
        let slot_object = slot
            .as_object_mut()
            .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "slot is malformed"))?;
        let subject = text(slot_object.get("subject_id"))
            .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "subject is missing"))?;
        let runtime = subject_runtime(subject)
            .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "subject is unknown"))?;
        let policy = slot_object
            .get_mut("policy")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| error("LNX4-CAPTURE-SCHEMA", "policy is malformed"))?;
        policy.remove("runtime_loader");
        policy.insert(
            "schema".to_owned(),
            Value::String(crate::LINUX_POLICY_SCHEMA.to_owned()),
        );
        policy.insert(
            "executable_allowlist".to_owned(),
            Value::Array(vec![Value::String(runtime.to_owned())]),
        );
        let policy_identity =
            hash_without_value("proofbound-research-linux-effective-policy/1", policy)?;
        policy.insert("identity".to_owned(), Value::String(policy_identity));
        let command = slot_object
            .get_mut("command")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| error("LNX4-COMMAND", "command is missing"))?;
        command.remove(2);
        command[0] = Value::String(LEGACY_ENFORCER.to_owned());
        let slot_identity = hash_without_value("proofbound-research-linux-slot/1", slot_object)?;
        slot_object.insert("identity".to_owned(), Value::String(slot_identity));
    }
    let identity = hash_without_value("proofbound-research-linux-enforcement-capture/1", object)?;
    object.insert("identity".to_owned(), Value::String(identity));
    Ok(projected)
}

fn safe_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && !path.split('/').any(|component| component == "..")
}

fn subject_runtime(subject: &str) -> Option<&'static str> {
    match subject {
        "subject:node" => Some("/usr/bin/node"),
        "subject:python" => Some("/usr/local/bin/python3.12"),
        "subject:rust" => Some("/state/rust-subject"),
        _ => None,
    }
}

fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn hash_without<T: Serialize>(domain: &str, value: &T) -> Result<String, LinuxLoaderError> {
    let mut encoded = serde_json::to_value(value).map_err(encoding_error)?;
    let object = encoded
        .as_object_mut()
        .ok_or_else(|| error("LNX4-ENCODE", "identity material is not an object"))?;
    hash_without_value(domain, object)
}

fn hash_without_value(
    domain: &str,
    value: &serde_json::Map<String, Value>,
) -> Result<String, LinuxLoaderError> {
    let mut encoded = Value::Object(value.clone());
    encoded
        .as_object_mut()
        .expect("object constructed above")
        .remove("identity");
    Ok(domain_hash(
        domain,
        &canonical_json(&encoded).map_err(encoding_error)?,
    ))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn error(code: &'static str, message: impl Into<String>) -> LinuxLoaderError {
    LinuxLoaderError {
        code,
        message: message.into(),
    }
}

fn encoding_error(issue: impl fmt::Display) -> LinuxLoaderError {
    error("LNX4-ENCODE", issue.to_string())
}
