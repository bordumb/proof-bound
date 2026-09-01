//! Domain-neutral assurance graph and status derivation for Proofbound.
//!
//! This crate deliberately contains no project semantics and executes no tools.
//! It accepts already materialized evidence, validates its graph-shaped closure,
//! and derives the three status facets defined by Specification 0001 section 6.3.

pub mod digest;
pub mod error;
pub mod evidence;
pub mod graph;
pub mod ids;
pub mod policy;
pub mod statement_wire;
pub mod status;
pub mod types;

pub use digest::{DigestParseError, Sha256Digest};
pub use error::{ErrorCode, StructuredError, ValidationErrors};
pub use evidence::*;
pub use graph::*;
pub use ids::*;
pub use policy::*;
pub use statement_wire::*;
pub use status::*;
pub use types::*;
