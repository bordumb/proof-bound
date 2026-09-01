use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use anyhow::{Context, Result, bail};
use proofbound_evidence::{canonical_json, sha256_bytes};
use proofbound_manifest::{AdapterKind, AdapterRequest, AdapterResponse, EvidenceUnitManifest};

const MAX_ADAPTER_OUTPUT: u64 = 16 << 20;

pub(crate) fn invoke(
    root: &Path,
    unit: &EvidenceUnitManifest,
    operation: &str,
    request_unit: serde_json::Value,
) -> Result<AdapterResponse> {
    if !matches!(
        operation,
        "doctor" | "inventory" | "check" | "reproduce" | "update"
    ) {
        bail!("PB-ADAPTER-0001: unsupported adapter operation {operation:?}");
    }
    let executable = unit.adapter.executable();
    let protocol_adapter = adapter_name(unit.adapter);
    let seed = canonical_json(&serde_json::json!({
        "adapter": protocol_adapter,
        "operation": operation,
        "unit": request_unit,
    }))?;
    let request_id = sha256_bytes(&seed)
        .strip_prefix("sha256:")
        .expect("internal digest has prefix")[..32]
        .to_owned();
    let request = AdapterRequest {
        schema: "proofbound-adapter-protocol/1".into(),
        message_type: "request".into(),
        request_id: request_id.clone(),
        adapter: protocol_adapter.into(),
        operation: operation.into(),
        project_root: ".".into(),
        unit: request_unit,
    };
    let bytes = canonical_json(&request)?;

    let program = locate_adapter(executable);
    let mut command = Command::new(&program);
    command
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for name in &unit.environment_allowlist {
        if name.is_empty() || name.contains('=') || name.as_bytes().contains(&0) {
            bail!("PB-ADAPTER-0002: invalid environment allowlist name {name:?}");
        }
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    // The adapter executable is already resolved, but child tool lookup is
    // allowed only when PATH was explicitly registered.
    let mut child = command
        .spawn()
        .with_context(|| format!("PB-ADAPTER-0003: could not start {}", program.display()))?;
    child
        .stdin
        .take()
        .context("adapter stdin unavailable")?
        .write_all(&bytes)?;

    let stdout_pipe = child.stdout.take().context("adapter stdout unavailable")?;
    let stderr_pipe = child.stderr.take().context("adapter stderr unavailable")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout_pipe));
    let stderr_reader = thread::spawn(move || read_bounded(stderr_pipe));
    let status = child.wait()?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("PB-ADAPTER-0004: adapter stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("PB-ADAPTER-0004: adapter stderr reader panicked"))??;
    if stdout.len() as u64 > MAX_ADAPTER_OUTPUT || stderr.len() as u64 > MAX_ADAPTER_OUTPUT {
        bail!("PB-ADAPTER-0004: adapter output exceeded 16 MiB");
    }
    if !status.success() {
        bail!(
            "PB-ADAPTER-0005: {executable} exited with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    parse_response(&stdout, &stderr, &request_id, &request.adapter, operation)
}

fn parse_response(
    stdout: &[u8],
    stderr: &[u8],
    request_id: &str,
    request_adapter: &str,
    request_operation: &str,
) -> Result<AdapterResponse> {
    let value: serde_json::Value = serde_json::from_slice(stdout).with_context(|| {
        format!(
            "PB-ADAPTER-0006: adapter emitted invalid protocol JSON: {}",
            String::from_utf8_lossy(stderr).trim()
        )
    })?;
    if canonical_json(&value)? != stdout {
        bail!("PB-ADAPTER-0006: adapter response JSON is not canonical");
    }
    let response: AdapterResponse = serde_json::from_value(value.clone()).with_context(|| {
        format!(
            "PB-ADAPTER-0006: adapter response violates the protocol schema: {}",
            String::from_utf8_lossy(stderr).trim()
        )
    })?;
    if response.schema != "proofbound-adapter-protocol/1"
        || response.message_type != "response"
        || response.request_id != request_id
        || response.adapter != request_adapter
    {
        bail!("PB-ADAPTER-0007: adapter response identity does not match its request");
    }
    let object = value
        .as_object()
        .context("PB-ADAPTER-0008: adapter response must be a JSON object")?;
    if !object.contains_key("evidence") {
        bail!("PB-ADAPTER-0008: adapter response omitted required evidence field");
    }
    validate_response_schema(&response, request_operation)?;
    Ok(response)
}

fn validate_response_schema(response: &AdapterResponse, request_operation: &str) -> Result<()> {
    if response.inventory.len() > 100_000
        || !response.inventory.windows(2).all(|pair| pair[0] < pair[1])
        || response.inventory.iter().any(|item| {
            item.trim().is_empty()
                || item.chars().count() > 4096
                || item.chars().any(char::is_control)
        })
    {
        bail!(
            "PB-ADAPTER-0008: adapter inventory must be a bounded strict-lexical set of valid targets"
        );
    }
    if response.diagnostics.len() > 4_096 {
        bail!("PB-ADAPTER-0008: adapter diagnostics exceed the protocol limit");
    }
    for diagnostic in &response.diagnostics {
        if !valid_diagnostic_code(&diagnostic.code)
            || diagnostic.message.len() > 8_192
            || diagnostic
                .path
                .as_ref()
                .is_some_and(|path| path.len() > 4_096)
            || diagnostic
                .remediation
                .as_ref()
                .is_some_and(|remediation| remediation.len() > 8_192)
        {
            bail!("PB-ADAPTER-0008: adapter diagnostic violates the protocol schema");
        }
    }
    if let Some(evidence) = &response.evidence {
        let schema = evidence
            .as_object()
            .and_then(|object| object.get("schema"))
            .and_then(serde_json::Value::as_str);
        if !matches!(
            schema,
            Some("proofbound-evidence/3" | "proofbound-adapter-observation/2")
        ) {
            bail!("PB-ADAPTER-0008: adapter evidence has an unsupported schema");
        }
    }
    validate_operation_response(response, request_operation)?;
    Ok(())
}

fn validate_operation_response(response: &AdapterResponse, operation: &str) -> Result<()> {
    if !response.success {
        if response.evidence.is_some() || !response.inventory.is_empty() {
            bail!(
                "PB-ADAPTER-0008: failed adapter response must carry null evidence and an empty inventory"
            );
        }
        return Ok(());
    }

    match operation {
        "doctor" if response.evidence.is_some() || !response.inventory.is_empty() => bail!(
            "PB-ADAPTER-0008: successful doctor response must carry null evidence and an empty inventory"
        ),
        "inventory" if response.evidence.is_some() || response.inventory.is_empty() => bail!(
            "PB-ADAPTER-0008: successful inventory response must carry null evidence and an exact nonempty inventory"
        ),
        "check" | "reproduce" => {
            let evidence = response.evidence.as_ref().context(
                "PB-ADAPTER-0008: successful evidence response omitted passing evidence",
            )?;
            if response.inventory.is_empty() || !evidence_reports_passed(evidence)? {
                bail!(
                    "PB-ADAPTER-0008: successful evidence response must carry passing evidence and an exact nonempty inventory"
                );
            }
        }
        "update" => {
            if let Some(evidence) = &response.evidence
                && evidence_reports_passed(evidence)?
            {
                bail!("PB-ADAPTER-0008: update response must not carry passing evidence");
            }
        }
        _ => {}
    }
    Ok(())
}

fn evidence_reports_passed(evidence: &serde_json::Value) -> Result<bool> {
    let object = evidence
        .as_object()
        .context("PB-ADAPTER-0008: adapter evidence must be an object")?;
    match object.get("schema").and_then(serde_json::Value::as_str) {
        Some("proofbound-evidence/3") => {
            let status = object
                .get("status")
                .and_then(serde_json::Value::as_str)
                .context("PB-ADAPTER-0008: adapter evidence omitted its typed status")?;
            match status {
                "passed" => Ok(true),
                "failed" | "missing" | "drifted" | "unregistered" | "ambiguous" | "corrupt"
                | "skipped" | "unavailable" => Ok(false),
                _ => bail!("PB-ADAPTER-0008: adapter evidence has an invalid typed status"),
            }
        }
        Some("proofbound-adapter-observation/2") => {
            match object.get("outcome").and_then(serde_json::Value::as_str) {
                Some("passed") => Ok(true),
                Some("failed") => Ok(false),
                _ => bail!("PB-ADAPTER-0008: adapter observation has an invalid typed outcome"),
            }
        }
        _ => bail!("PB-ADAPTER-0008: adapter evidence has an unsupported schema"),
    }
}

fn valid_diagnostic_code(code: &str) -> bool {
    let Some(rest) = code.strip_prefix("PB-") else {
        return false;
    };
    let mut segments = rest.split('-');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some(family), Some(number), None)
            if !family.is_empty()
                && family.bytes().all(|byte| byte.is_ascii_uppercase())
                && number.len() == 4
                && number.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = (MAX_ADAPTER_OUTPUT as usize + 1).saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(bytes)
}

const fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Lean => "lean",
        AdapterKind::CharonAeneas => "charon-aeneas",
        AdapterKind::Kani => "kani",
        AdapterKind::RustTest => "rust-test",
        AdapterKind::PythonTest => "python-test",
        AdapterKind::NodeTest => "node-test",
        AdapterKind::CanonicalArtifact => "canonical-artifact",
        AdapterKind::SourceClosure => "source-closure",
        AdapterKind::IndependentCheck => "independent-check",
        AdapterKind::HumanReview => "human-review",
        AdapterKind::TrustedTranscription => "trusted-transcription",
    }
}

fn locate_adapter(name: &str) -> PathBuf {
    if let Some(directory) = env::var_os("PROOFBOUND_ADAPTER_DIR") {
        let path = PathBuf::from(directory).join(name);
        if regular_executable(&path) {
            return path;
        }
    }
    if let Ok(current) = env::current_exe()
        && let Some(parent) = current.parent()
    {
        let sibling = parent.join(name);
        if regular_executable(&sibling) {
            return sibling;
        }
    }
    PathBuf::from(name)
}

pub(crate) fn cache_identities(
    root: &Path,
    adapter: AdapterKind,
) -> Result<BTreeMap<String, String>> {
    let mut identities = BTreeMap::new();
    let adapter_name = adapter.executable();
    identities.insert(
        format!("adapter:{adapter_name}"),
        optional_program_identity(adapter_name)?,
    );
    let programs: &[&str] = match adapter {
        AdapterKind::Lean => &["lake"],
        AdapterKind::CharonAeneas => &["cargo", "charon", "aeneas"],
        AdapterKind::Kani => &["cargo", "cargo-kani"],
        AdapterKind::RustTest => &["cargo", "rustc"],
        AdapterKind::NodeTest => &["node", "npm"],
        AdapterKind::PythonTest
        | AdapterKind::CanonicalArtifact
        | AdapterKind::IndependentCheck
        | AdapterKind::TrustedTranscription => &["python3"],
        AdapterKind::SourceClosure | AdapterKind::HumanReview => &[],
    };
    for program in programs {
        identities.insert(
            format!("tool:{program}"),
            optional_program_identity(program)?,
        );
    }
    if adapter == AdapterKind::Lean {
        let audit = root.join(".lake/build/bin/proofbound_lean_audit");
        identities.insert(
            "tool:proofbound_lean_audit".into(),
            if audit.is_file() {
                hash_regular(&audit)?
            } else {
                sha256_bytes(b"unavailable:proofbound_lean_audit")
            },
        );
    }
    Ok(identities)
}

fn optional_program_identity(name: &str) -> Result<String> {
    let Some(path) = resolved_adapter(name) else {
        return Ok(sha256_bytes(format!("unavailable:{name}").as_bytes()));
    };
    hash_regular(&path)
}

fn resolved_adapter(name: &str) -> Option<PathBuf> {
    let candidate = locate_adapter(name);
    if candidate.components().count() > 1 {
        return candidate.canonicalize().ok();
    }
    resolve_path_program(name)
}

fn resolve_path_program(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|directory| {
        let candidate = directory.join(name);
        candidate
            .is_file()
            .then(|| candidate.canonicalize().ok())
            .flatten()
    })
}

fn hash_regular(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("PB-CACHE-0004: cannot stat {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 512 << 20 {
        bail!(
            "PB-CACHE-0004: tool identity is not a bounded regular file: {}",
            path.display()
        );
    }
    Ok(sha256_bytes(&fs::read(path)?))
}

fn regular_executable(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_names_are_protocol_names() {
        assert_eq!(adapter_name(AdapterKind::Lean), "lean");
        assert_eq!(adapter_name(AdapterKind::CharonAeneas), "charon-aeneas");
        assert_eq!(adapter_name(AdapterKind::RustTest), "rust-test");
    }

    #[test]
    fn diagnostic_codes_follow_the_public_schema() {
        assert!(valid_diagnostic_code("PB-LEAN-0001"));
        assert!(!valid_diagnostic_code("PB-Lean-0001"));
        assert!(!valid_diagnostic_code("PB-LEAN-1"));
        assert!(!valid_diagnostic_code("PB-LEAN-0001-extra"));
    }

    fn protocol_value(success: bool, evidence: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema": "proofbound-adapter-protocol/1",
            "type": "response",
            "request_id": "0123456789abcdef0123456789abcdef",
            "adapter": "lean",
            "success": success,
            "evidence": evidence,
            "inventory": ["Demo.claim"],
            "diagnostics": [],
        })
    }

    #[test]
    fn response_boundary_requires_canonical_json() {
        let value = protocol_value(true, serde_json::json!({"schema": "proofbound-evidence/3"}));
        let mut noncanonical = serde_json::to_vec_pretty(&value).unwrap();
        noncanonical.push(b'\n');
        assert!(
            parse_response(
                &noncanonical,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );
    }

    #[test]
    fn failed_response_cannot_smuggle_evidence() {
        let value = protocol_value(
            false,
            serde_json::json!({"schema": "proofbound-evidence/3"}),
        );
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        let mut inventoried_failure = protocol_value(false, serde_json::Value::Null);
        let bytes = canonical_json(&inventoried_failure).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );
        inventoried_failure["inventory"] = serde_json::json!([]);
        let bytes = canonical_json(&inventoried_failure).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_ok()
        );
    }

    #[test]
    fn successful_operations_have_disjoint_evidence_and_inventory_shapes() {
        let parse = |value: &serde_json::Value, operation: &str| {
            parse_response(
                &canonical_json(value).unwrap(),
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                operation,
            )
        };

        let mut doctor = protocol_value(true, serde_json::Value::Null);
        doctor["inventory"] = serde_json::json!([]);
        assert!(parse(&doctor, "doctor").is_ok());
        doctor["inventory"] = serde_json::json!(["Demo.claim"]);
        assert!(parse(&doctor, "doctor").is_err());

        let inventory = protocol_value(true, serde_json::Value::Null);
        assert!(parse(&inventory, "inventory").is_ok());
        assert!(
            parse(
                &protocol_value(true, serde_json::json!({"schema": "proofbound-evidence/3"})),
                "inventory"
            )
            .is_err()
        );

        let evidence = protocol_value(
            true,
            serde_json::json!({
                "schema": "proofbound-evidence/3",
                "status": "passed"
            }),
        );
        assert!(parse(&evidence, "check").is_ok());
        assert!(parse(&evidence, "reproduce").is_ok());
        assert!(parse(&protocol_value(true, serde_json::Value::Null), "check").is_err());
        assert!(
            parse(
                &protocol_value(
                    true,
                    serde_json::json!({
                        "schema": "proofbound-evidence/3",
                        "status": "failed"
                    })
                ),
                "check"
            )
            .is_err()
        );

        assert!(
            parse(
                &protocol_value(
                    true,
                    serde_json::json!({
                        "schema": "proofbound-evidence/3",
                        "status": "passed"
                    })
                ),
                "update"
            )
            .is_err()
        );
        assert!(
            parse(
                &protocol_value(
                    true,
                    serde_json::json!({
                        "schema": "proofbound-evidence/3",
                        "status": "drifted"
                    })
                ),
                "update"
            )
            .is_ok()
        );
        assert!(parse(&protocol_value(true, serde_json::Value::Null), "update").is_ok());
    }

    #[test]
    fn successful_inventory_is_nonempty_valid_unique_and_strictly_sorted() {
        let mut value = protocol_value(
            true,
            serde_json::json!({
                "schema": "proofbound-evidence/3",
                "status": "passed"
            }),
        );
        value["inventory"] = serde_json::json!([]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        value["inventory"] = serde_json::json!(["b", "a"]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        value["inventory"] = serde_json::json!(["a", "a"]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        value["inventory"] = serde_json::json!(["bad\nname"]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );
    }
}
