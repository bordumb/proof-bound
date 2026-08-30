//! Canonical, content-addressed evidence and closure storage.
//!
//! This crate deliberately does not execute proof tools. Adapters produce
//! records; this crate makes those records deterministic, immutable, and
//! independently re-checkable.

mod canonical;
mod cas;
mod closure;
mod provenance;

pub use canonical::{canonical_json, domain_hash, sha256_bytes, verify_domain_hash};
pub use cas::{ContentAddressedStore, StoreError};
pub use closure::{
    ClosureError, ClosureKind, ClosureLimits, ClosureMember, ClosureRecord, build_closure,
    merge_closures, validate_closure,
};
pub use provenance::{GitIdentity, ProvenanceError, git_identity};
