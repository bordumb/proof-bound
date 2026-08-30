//! Stable, structured errors suitable for both CLI and JSON reports.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ClaimId, UnitId};

/// Stable error codes. Variant spelling is part of the machine contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    PbCoreUnsupportedSchema,
    PbCoreDuplicateId,
    PbCoreMissingTarget,
    PbCoreInvalidNode,
    PbCoreInvalidEdge,
    PbCoreInvalidCycle,
    PbCoreInvalidMutualTheoremGroup,
    PbCoreInvalidEvidence,
    PbCoreEvidenceFailed,
    PbCoreEvidenceMissing,
    PbCoreEvidenceDrifted,
    PbCoreEvidenceUnregistered,
    PbCoreEvidenceAmbiguous,
    PbCoreEvidenceCorrupt,
    PbCoreEvidenceSkipped,
    PbCoreEvidenceUnavailable,
    PbCoreTierExceeded,
    PbCorePolicyViolation,
    PbCoreAmbiguousLinkage,
    PbCoreMissingAssumption,
    PbCoreMissingPremise,
    PbCoreInvalidDischarge,
    PbCoreGraphMismatch,
}

/// Complete error payload required by Specification 0001 section 12.3.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<ClaimId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_id: Option<UnitId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_claims: Vec<ClaimId>,
    pub remediation: String,
}

impl StructuredError {
    /// Creates an error with all optional location fields initially empty.
    #[must_use]
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            claim_id: None,
            unit_id: None,
            file: None,
            logical_path: None,
            byte_offset: None,
            expected: None,
            actual: None,
            affected_claims: Vec::new(),
            remediation: remediation.into(),
        }
    }

    /// Associates the failure with a claim.
    #[must_use]
    pub fn for_claim(mut self, claim_id: ClaimId) -> Self {
        self.claim_id = Some(claim_id);
        self
    }

    /// Associates the failure with an evidence unit.
    #[must_use]
    pub fn for_unit(mut self, unit_id: UnitId) -> Self {
        self.unit_id = Some(unit_id);
        self
    }

    /// Adds expected and actual identities.
    #[must_use]
    pub fn identities(mut self, expected: impl Into<String>, actual: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self.actual = Some(actual.into());
        self
    }
}

/// One or more validation errors; validation intentionally accumulates useful
/// diagnostics instead of hiding later failures behind the first one.
#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(transparent)]
#[error("{count} assurance validation error(s)", count = .errors.len())]
pub struct ValidationErrors {
    pub errors: Vec<StructuredError>,
}

impl ValidationErrors {
    #[must_use]
    pub fn new(errors: Vec<StructuredError>) -> Self {
        debug_assert!(!errors.is_empty());
        Self { errors }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        formatter.write_str(encoded.as_str().ok_or(fmt::Error)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_payload_rejects_unknown_fields() {
        let input = r#"{
          "code":"PB_CORE_EVIDENCE_MISSING",
          "message":"missing",
          "remediation":"run check",
          "surprise":true
        }"#;
        assert!(serde_json::from_str::<StructuredError>(input).is_err());
    }
}
