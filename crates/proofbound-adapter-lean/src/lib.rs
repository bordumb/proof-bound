//! Hardened adapter for compiled Lean public-claim audits.
//!
//! This crate never scans Lean source for declarations or attributes. It runs
//! (or consumes a captured result from) `proofbound_lean_audit`, reconciles the
//! complete compiled attribute inventory, and hashes the elaborated ExprWire
//! statement using the normative canonical CBOR encoding.

pub mod audit;
pub mod error;
pub mod model;
pub mod protocol;
pub mod receipt;
pub mod runtime;
pub mod wire;

pub use protocol::{LeanAdapterResponse, handle_bytes, run_stdio};
