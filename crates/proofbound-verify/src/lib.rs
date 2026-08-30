//! Independent, tool-free verification of Proofbound release receipts.
//!
//! This crate intentionally depends on no other `proofbound-*` crate. Its
//! receipt parser, canonicalization, graph checks, and section 6.3 derivation
//! are a second implementation used as the portable release trust boundary.

mod canonical;
mod format;
mod verifier;

pub use canonical::{canonical_json, domain_hash, raw_sha256};
pub use format::*;
pub use verifier::{
    NotProvedOutOfScopeReport, VerificationErrors, VerificationIssue, VerificationIssueCode,
    VerificationReport, verify_compiled_release, verify_release_dir,
};
