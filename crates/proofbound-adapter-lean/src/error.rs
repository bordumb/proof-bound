use proofbound_manifest::AdapterDiagnostic;
use thiserror::Error;

/// Stable, protocol-safe adapter failure. Messages may include untrusted tool
/// text, but stdout always remains a single response envelope.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct AdapterError {
    pub code: &'static str,
    pub message: String,
    pub path: Option<String>,
    pub remediation: Option<String>,
}

impl AdapterError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            path: None,
            remediation: None,
        }
    }

    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn remediate(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn diagnostic(&self) -> AdapterDiagnostic {
        AdapterDiagnostic {
            code: self.code.to_owned(),
            message: self.message.clone(),
            path: self.path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}

pub const PROTOCOL: &str = "PB-LEAN-0001";
pub const CONFIGURATION: &str = "PB-LEAN-0002";
pub const TOOL: &str = "PB-LEAN-0003";
pub const AUDIT_OUTPUT: &str = "PB-LEAN-0004";
pub const INVENTORY: &str = "PB-LEAN-0005";
pub const DECLARATION: &str = "PB-LEAN-0006";
pub const AXIOM: &str = "PB-LEAN-0007";
pub const STATEMENT_DRIFT: &str = "PB-LEAN-0008";
pub const EXPR_WIRE: &str = "PB-LEAN-0009";
pub const PROVENANCE: &str = "PB-LEAN-0010";
pub const RESOURCE: &str = "PB-LEAN-0011";
pub const READ_ONLY: &str = "PB-LEAN-0012";
pub const ARTIFACT_BINDING: &str = "PB-LEAN-0013";
