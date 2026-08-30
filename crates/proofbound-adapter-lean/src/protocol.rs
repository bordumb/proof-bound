use std::{io::Read, path::Path};

use proofbound_core::{EvidenceRecord, EvidenceStatus};
use proofbound_evidence::canonical_json;
use proofbound_manifest::{AdapterDiagnostic, AdapterRequest};
use serde::{Deserialize, Serialize};

use crate::{
    audit::{observe_audit, validate_unit, verify_audit},
    error::{AdapterError, PROTOCOL},
    model::{AuditSource, LeanAdapterUnit},
    receipt::build_theorem_evidence,
    runtime::{AuditRun, doctor, execute_audit, validate_captured_execution},
};

pub const ADAPTER_PROTOCOL_SCHEMA: &str = "proofbound-adapter-protocol/1";
pub const ADAPTER_NAME: &str = "lean";
const MAX_REQUEST_BYTES: usize = 64 << 20;
const FALLBACK_REQUEST_ID: &str = "00000000000000000000000000000000";

/// Response envelope whose evidence member is directly deserializable as the
/// core receipt type. The outer shape is the language-neutral adapter protocol.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeanAdapterResponse {
    pub schema: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub request_id: String,
    pub adapter: String,
    pub success: bool,
    pub evidence: Option<EvidenceRecord>,
    #[serde(default)]
    pub inventory: Vec<String>,
    pub diagnostics: Vec<AdapterDiagnostic>,
}

pub fn run_stdio() -> Result<(), std::io::Error> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(u64::try_from(MAX_REQUEST_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut input)?;
    let output = handle_bytes(&input, Path::new("."));
    use std::io::Write as _;
    std::io::stdout().write_all(&output)
}

/// Process exactly one request and always return one canonical response value.
pub fn handle_bytes(bytes: &[u8], root: &Path) -> Vec<u8> {
    let response = match parse_request(bytes) {
        Ok(request) => match handle_request(&request, root) {
            Ok(response) => response,
            Err(error) => failure(&request.request_id, &error),
        },
        Err((request_id, error)) => failure(&request_id, &error),
    };
    canonical_json(&response).unwrap_or_else(|_| {
        // Every response field is JSON-native and EvidenceRecord serialization
        // is infallible. This literal is the final fail-closed boundary.
        br#"{"adapter":"lean","diagnostics":[{"code":"PB-LEAN-0001","message":"response serialization failed"}],"evidence":null,"inventory":[],"request_id":"00000000000000000000000000000000","schema":"proofbound-adapter-protocol/1","success":false,"type":"response"}"#.to_vec()
    })
}

fn parse_request(bytes: &[u8]) -> Result<AdapterRequest, (String, AdapterError)> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err((
            FALLBACK_REQUEST_ID.to_owned(),
            AdapterError::new(
                PROTOCOL,
                format!("adapter request exceeds {MAX_REQUEST_BYTES} bytes"),
            ),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let request = AdapterRequest::deserialize(&mut deserializer).map_err(|error| {
        (
            recover_request_id(bytes),
            AdapterError::new(PROTOCOL, format!("malformed adapter request: {error}")),
        )
    })?;
    deserializer.end().map_err(|error| {
        (
            valid_or_fallback(&request.request_id),
            AdapterError::new(PROTOCOL, format!("trailing request bytes: {error}")),
        )
    })?;
    let canonical = canonical_json(&request).map_err(|error| {
        (
            valid_or_fallback(&request.request_id),
            AdapterError::new(
                PROTOCOL,
                format!("cannot canonicalize adapter request: {error}"),
            ),
        )
    })?;
    if canonical != bytes {
        return Err((
            valid_or_fallback(&request.request_id),
            AdapterError::new(
                PROTOCOL,
                "adapter request is not canonical JSON (sorted keys, compact encoding, no trailing newline)",
            ),
        ));
    }
    validate_request_envelope(&request)
        .map_err(|error| (valid_or_fallback(&request.request_id), error))?;
    Ok(request)
}

fn validate_request_envelope(request: &AdapterRequest) -> Result<(), AdapterError> {
    if request.schema != ADAPTER_PROTOCOL_SCHEMA
        || request.message_type != "request"
        || request.adapter != ADAPTER_NAME
        || request.project_root != "."
        || !valid_request_id(&request.request_id)
    {
        return Err(AdapterError::new(
            PROTOCOL,
            "unsupported or non-canonical adapter request envelope",
        ));
    }
    if !matches!(
        request.operation.as_str(),
        "doctor" | "inventory" | "check" | "reproduce" | "update"
    ) {
        return Err(AdapterError::new(
            PROTOCOL,
            format!("unsupported adapter operation '{}'", request.operation),
        ));
    }
    Ok(())
}

fn handle_request(
    request: &AdapterRequest,
    root: &Path,
) -> Result<LeanAdapterResponse, AdapterError> {
    let unit: LeanAdapterUnit = serde_json::from_value(request.unit.clone()).map_err(|error| {
        AdapterError::new(
            crate::error::CONFIGURATION,
            format!("invalid Lean adapter unit: {error}"),
        )
    })?;
    validate_unit(&unit)?;

    match request.operation.as_str() {
        "doctor" => {
            match &unit.audit {
                AuditSource::Execute => doctor(root)?,
                AuditSource::Captured { execution, .. } => {
                    validate_captured_execution(execution, budget_ms(&unit)?)?;
                }
            }
            Ok(success(request, None, Vec::new()))
        }
        "inventory" => {
            let run = acquire_audit(root, &unit)?;
            let verified = verify_audit(&unit, &run.output, false)?;
            Ok(success(
                request,
                None,
                verified.inventory.into_iter().collect(),
            ))
        }
        "check" | "reproduce" => {
            let run = acquire_audit(root, &unit)?;
            let verified = verify_audit(&unit, &run.output, true)?;
            let inventory = verified.inventory.iter().cloned().collect();
            let evidence = build_theorem_evidence(
                root,
                &unit,
                &verified,
                &run.execution,
                EvidenceStatus::Passed,
            )?;
            Ok(success(request, Some(evidence), inventory))
        }
        "update" => {
            let run = acquire_audit(root, &unit)?;
            let verified = observe_audit(&unit, &run.output)?;
            let inventory = verified.inventory.iter().cloned().collect();
            let evidence = build_theorem_evidence(
                root,
                &unit,
                &verified,
                &run.execution,
                EvidenceStatus::Drifted,
            )?;
            Ok(success(request, Some(evidence), inventory))
        }
        _ => Err(AdapterError::new(PROTOCOL, "unreachable adapter operation")),
    }
}

fn acquire_audit(root: &Path, unit: &LeanAdapterUnit) -> Result<AuditRun, AdapterError> {
    match &unit.audit {
        AuditSource::Execute => execute_audit(root, unit),
        AuditSource::Captured { output, execution } => {
            validate_captured_execution(execution, budget_ms(unit)?)?;
            Ok(AuditRun {
                output: (**output).clone(),
                execution: (**execution).clone(),
            })
        }
    }
}

fn budget_ms(unit: &LeanAdapterUnit) -> Result<u64, AdapterError> {
    unit.evidence_unit
        .resource_budget
        .time_seconds
        .checked_mul(1_000)
        .ok_or_else(|| {
            AdapterError::new(crate::error::RESOURCE, "time budget overflows milliseconds")
        })
}

fn success(
    request: &AdapterRequest,
    evidence: Option<EvidenceRecord>,
    inventory: Vec<String>,
) -> LeanAdapterResponse {
    LeanAdapterResponse {
        schema: ADAPTER_PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: request.request_id.clone(),
        adapter: ADAPTER_NAME.to_owned(),
        success: true,
        evidence,
        inventory,
        diagnostics: Vec::new(),
    }
}

fn failure(request_id: &str, error: &AdapterError) -> LeanAdapterResponse {
    LeanAdapterResponse {
        schema: ADAPTER_PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: valid_or_fallback(request_id),
        adapter: ADAPTER_NAME.to_owned(),
        success: false,
        evidence: None,
        inventory: Vec::new(),
        diagnostics: vec![error.diagnostic()],
    }
}

fn recover_request_id(bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| value.get("request_id")?.as_str().map(ToOwned::to_owned))
        .filter(|value| valid_request_id(value))
        .unwrap_or_else(|| FALLBACK_REQUEST_ID.to_owned())
}

fn valid_or_fallback(value: &str) -> String {
    if valid_request_id(value) {
        value.to_owned()
    } else {
        FALLBACK_REQUEST_ID.to_owned()
    }
}

fn valid_request_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use proofbound_evidence::canonical_json;
    use serde_json::json;

    use super::*;

    #[test]
    fn request_boundary_rejects_noncanonical_json() {
        let request = json!({
            "schema": ADAPTER_PROTOCOL_SCHEMA,
            "type": "request",
            "request_id": "0123456789abcdef0123456789abcdef",
            "adapter": ADAPTER_NAME,
            "operation": "doctor",
            "project_root": ".",
            "unit": {}
        });
        let mut noncanonical = serde_json::to_vec_pretty(&request).unwrap();
        noncanonical.push(b'\n');
        let response: LeanAdapterResponse =
            serde_json::from_slice(&handle_bytes(&noncanonical, Path::new("."))).unwrap();
        assert!(!response.success);
        assert_eq!(response.diagnostics[0].code, PROTOCOL);
    }

    #[test]
    fn response_bytes_are_canonical_even_for_malformed_input() {
        let bytes = handle_bytes(b"not json", Path::new("."));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, canonical_json(&value).unwrap());
        assert_eq!(value["success"], false);
    }
}
