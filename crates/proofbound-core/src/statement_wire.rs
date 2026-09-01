//! Independent validation of Proofbound's canonical Lean statement wire form.
//!
//! The Lean adapter transports an elaborated expression as JSON.  Status
//! derivation must not trust an adapter-authored summary of that expression,
//! so core validates the complete wire tree, recomputes its canonical digest,
//! and recognizes the artifact-binding marker only at the exact expression
//! root.

use std::str::FromStr;

use serde_json::Value;
use thiserror::Error;

use crate::{ArtifactLogicalName, BindingMode, ClaimId, Sha256Digest};

/// Canonical encoding identifier for elaborated Lean theorem statements.
pub const LEAN_STATEMENT_ENCODING_V1: &str = "lean-expr-cbor/1";

/// The only elaborated theorem head that can confer digest binding.
pub const ARTIFACT_DIGEST_BINDING_MARKER_V1: &str = "Proofbound.Artifact.DigestBindingV1";

const HASH_DOMAIN_WITH_NUL: &[u8] = b"proofbound:lean-expr-cbor/1\0";
const MAX_DEPTH: usize = 256;
const MAX_NODES: usize = 1_000_000;
const MAX_TEXT_BYTES: usize = 16 << 20;
const MAX_CBOR_BYTES: usize = 64 << 20;

/// Artifact identity extracted from the exact root of an elaborated theorem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedArtifactDigestBinding {
    pub mode: BindingMode,
    pub artifact_schema: String,
    pub artifact_logical_name: ArtifactLogicalName,
    pub artifact_sha256: Sha256Digest,
}

/// A malformed statement wire or a theorem that is not an exact binding.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StatementWireError {
    #[error("{path}: expected {expected}")]
    Type {
        path: String,
        expected: &'static str,
    },
    #[error("{path}: expected array length {expected}, found {actual}")]
    Length {
        path: String,
        expected: usize,
        actual: usize,
    },
    #[error("{path}: unknown {kind} tag {tag}")]
    UnknownTag {
        path: String,
        kind: &'static str,
        tag: u64,
    },
    #[error("{path}: non-canonical transported natural number '{value}'")]
    Natural { path: String, value: String },
    #[error("{path}: empty or oversized Lean name")]
    Name { path: String },
    #[error("expression exceeds nesting limit {MAX_DEPTH}")]
    TooDeep,
    #[error("expression exceeds node limit {MAX_NODES}")]
    TooManyNodes,
    #[error("expression exceeds text limit {MAX_TEXT_BYTES} bytes")]
    TooMuchText,
    #[error("canonical CBOR exceeds limit {MAX_CBOR_BYTES} bytes")]
    TooManyBytes,
    #[error("statement digest does not match the canonical wire digest")]
    DigestMismatch,
    #[error("the theorem statement is not an exact {ARTIFACT_DIGEST_BINDING_MARKER_V1} root")]
    BindingRoot,
    #[error("the artifact binding marker requires exactly six arguments")]
    BindingArity,
    #[error("artifact binding argument {index} must be a direct string literal")]
    BindingLiteral { index: usize },
    #[error(
        "the theorem statement must contain exactly one artifact binding marker, found {actual}"
    )]
    BindingOccurrenceCount { actual: usize },
    #[error("artifact binding claim '{actual}' does not equal '{expected}'")]
    BindingClaim { expected: ClaimId, actual: String },
    #[error("artifact binding schema must be non-empty and at most 4096 characters")]
    BindingSchema,
    #[error("artifact binding logical name is invalid: {0}")]
    BindingLogicalName(String),
    #[error("artifact binding digest must be canonical sha256: lowercase hex")]
    BindingDigest,
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
    nodes: usize,
    text_bytes: usize,
}

impl Encoder {
    fn ensure_room(&self, additional: usize) -> Result<(), StatementWireError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|size| size > MAX_CBOR_BYTES)
        {
            return Err(StatementWireError::TooManyBytes);
        }
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), StatementWireError> {
        self.ensure_room(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), StatementWireError> {
        self.ensure_room(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn major_uint(&mut self, major: u8, value: u64) -> Result<(), StatementWireError> {
        let prefix = major << 5;
        match value {
            0..=23 => self.byte(prefix | u8::try_from(value).expect("bounded by match")),
            24..=0xff => {
                self.byte(prefix | 24)?;
                self.byte(u8::try_from(value).expect("bounded by match"))
            }
            0x100..=0xffff => {
                self.byte(prefix | 25)?;
                self.extend(
                    &u16::try_from(value)
                        .expect("bounded by match")
                        .to_be_bytes(),
                )
            }
            0x1_0000..=0xffff_ffff => {
                self.byte(prefix | 26)?;
                self.extend(
                    &u32::try_from(value)
                        .expect("bounded by match")
                        .to_be_bytes(),
                )
            }
            _ => {
                self.byte(prefix | 27)?;
                self.extend(&value.to_be_bytes())
            }
        }
    }

    fn uint(&mut self, value: u64) -> Result<(), StatementWireError> {
        self.major_uint(0, value)
    }

    fn array(&mut self, length: usize) -> Result<(), StatementWireError> {
        self.major_uint(
            4,
            u64::try_from(length).map_err(|_| StatementWireError::TooManyBytes)?,
        )
    }

    fn text(&mut self, value: &str) -> Result<(), StatementWireError> {
        self.text_bytes = self
            .text_bytes
            .checked_add(value.len())
            .ok_or(StatementWireError::TooMuchText)?;
        if self.text_bytes > MAX_TEXT_BYTES {
            return Err(StatementWireError::TooMuchText);
        }
        self.major_uint(
            3,
            u64::try_from(value.len()).map_err(|_| StatementWireError::TooMuchText)?,
        )?;
        self.extend(value.as_bytes())
    }

    fn node(&mut self, depth: usize) -> Result<(), StatementWireError> {
        if depth > MAX_DEPTH {
            return Err(StatementWireError::TooDeep);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(StatementWireError::TooManyNodes)?;
        if self.nodes > MAX_NODES {
            return Err(StatementWireError::TooManyNodes);
        }
        Ok(())
    }
}

/// Validates and canonically encodes a complete `lean-expr-cbor/1` statement.
pub fn encode_lean_statement_wire(value: &Value) -> Result<Vec<u8>, StatementWireError> {
    let statement = array(value, "$statement")?;
    exact_len(statement, 2, "$statement")?;
    match statement.first() {
        Some(Value::String(version)) if version == LEAN_STATEMENT_ENCODING_V1 => {}
        _ => {
            return Err(StatementWireError::Type {
                path: "$statement[0]".into(),
                expected: "the literal string 'lean-expr-cbor/1'",
            });
        }
    }

    let mut encoder = Encoder::default();
    encoder.array(2)?;
    encoder.text(LEAN_STATEMENT_ENCODING_V1)?;
    encode_expr(
        &mut encoder,
        required(statement, 1, "$statement")?,
        0,
        "$statement[1]",
    )?;
    Ok(encoder.bytes)
}

/// Recomputes the domain-separated identity of a complete Lean statement.
pub fn lean_statement_wire_digest(value: &Value) -> Result<Sha256Digest, StatementWireError> {
    let cbor = encode_lean_statement_wire(value)?;
    let mut bytes = Vec::with_capacity(HASH_DOMAIN_WITH_NUL.len() + cbor.len());
    bytes.extend_from_slice(HASH_DOMAIN_WITH_NUL);
    bytes.extend_from_slice(&cbor);
    Ok(Sha256Digest::of_bytes(bytes))
}

/// Parses a digest-binding marker only when it is the exact elaborated root.
///
/// This function also validates the complete wire tree and checks its
/// independently recomputed digest.  It deliberately performs no reduction:
/// wrappers, aliases, and markers nested inside unrelated propositions fail.
pub fn parse_artifact_digest_binding(
    statement_wire: &Value,
    expected_statement_sha256: Sha256Digest,
    expected_claim: &ClaimId,
) -> Result<ParsedArtifactDigestBinding, StatementWireError> {
    if lean_statement_wire_digest(statement_wire)? != expected_statement_sha256 {
        return Err(StatementWireError::DigestMismatch);
    }
    let statement = array(statement_wire, "$statement")?;
    let root = required(statement, 1, "$statement")?;
    let (head, arguments) = flatten_outer_app(root)?;
    if !is_exact_const(head, ARTIFACT_DIGEST_BINDING_MARKER_V1) {
        return Err(StatementWireError::BindingRoot);
    }
    let marker_occurrences = count_marker_occurrences(root)?;
    if marker_occurrences != 1 {
        return Err(StatementWireError::BindingOccurrenceCount {
            actual: marker_occurrences,
        });
    }
    if arguments.len() != 6 {
        return Err(StatementWireError::BindingArity);
    }

    let claim = direct_string_literal(arguments[0], 1)?;
    if claim != expected_claim.as_str() {
        return Err(StatementWireError::BindingClaim {
            expected: expected_claim.clone(),
            actual: claim.to_owned(),
        });
    }
    let artifact_schema = direct_string_literal(arguments[1], 2)?;
    if artifact_schema.is_empty()
        || artifact_schema.chars().count() > 4096
        || artifact_schema.contains('\0')
    {
        return Err(StatementWireError::BindingSchema);
    }
    let artifact_logical_name =
        ArtifactLogicalName::new(direct_string_literal(arguments[2], 3)?)
            .map_err(|error| StatementWireError::BindingLogicalName(error.to_string()))?;
    let digest_text = direct_string_literal(arguments[3], 4)?;
    let artifact_sha256 = digest_text
        .strip_prefix("sha256:")
        .ok_or(StatementWireError::BindingDigest)
        .and_then(|hex| {
            Sha256Digest::from_str(hex).map_err(|_| StatementWireError::BindingDigest)
        })?;

    Ok(ParsedArtifactDigestBinding {
        mode: BindingMode::DigestTheorem,
        artifact_schema: artifact_schema.to_owned(),
        artifact_logical_name,
        artifact_sha256,
    })
}

fn flatten_outer_app(root: &Value) -> Result<(&Value, Vec<&Value>), StatementWireError> {
    let mut head = root;
    let mut reversed = Vec::new();
    loop {
        let values = array(head, "$statement[1]")?;
        if values.first().and_then(Value::as_u64) != Some(3) {
            break;
        }
        exact_len(values, 3, "$statement[1]")?;
        reversed.push(required(values, 2, "$statement[1]")?);
        head = required(values, 1, "$statement[1]")?;
    }
    reversed.reverse();
    Ok((head, reversed))
}

fn is_exact_const(value: &Value, expected_name: &str) -> bool {
    let Some(values) = value.as_array() else {
        return false;
    };
    values.len() == 3
        && values.first().and_then(Value::as_u64) == Some(2)
        && values.get(1).and_then(Value::as_str) == Some(expected_name)
        && values
            .get(2)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn count_marker_occurrences(value: &Value) -> Result<usize, StatementWireError> {
    let values = array(value, "$statement[1]")?;
    let tag = bounded_number(values.first(), "$statement[1][0]")?;
    match tag {
        0 | 1 | 7 => Ok(0),
        2 => Ok(usize::from(
            values.get(1).and_then(Value::as_str) == Some(ARTIFACT_DIGEST_BINDING_MARKER_V1),
        )),
        3 => Ok(
            count_marker_occurrences(required(values, 1, "$statement[1]")?)?.saturating_add(
                count_marker_occurrences(required(values, 2, "$statement[1]")?)?,
            ),
        ),
        4 | 5 => Ok(
            count_marker_occurrences(required(values, 2, "$statement[1]")?)?.saturating_add(
                count_marker_occurrences(required(values, 3, "$statement[1]")?)?,
            ),
        ),
        6 => {
            let mut count = 0_usize;
            for index in 1..=3 {
                count = count.saturating_add(count_marker_occurrences(required(
                    values,
                    index,
                    "$statement[1]",
                )?)?);
            }
            Ok(count)
        }
        8 => count_marker_occurrences(required(values, 1, "$statement[1]")?),
        9 => count_marker_occurrences(required(values, 3, "$statement[1]")?),
        _ => Err(StatementWireError::UnknownTag {
            path: "$statement[1][0]".into(),
            kind: "expression",
            tag,
        }),
    }
}

fn direct_string_literal(value: &Value, index: usize) -> Result<&str, StatementWireError> {
    let Some(expression) = value.as_array() else {
        return Err(StatementWireError::BindingLiteral { index });
    };
    let Some(literal) = expression.get(1).and_then(Value::as_array) else {
        return Err(StatementWireError::BindingLiteral { index });
    };
    if expression.len() != 2
        || expression.first().and_then(Value::as_u64) != Some(7)
        || literal.len() != 2
        || literal.first().and_then(Value::as_u64) != Some(1)
    {
        return Err(StatementWireError::BindingLiteral { index });
    }
    literal
        .get(1)
        .and_then(Value::as_str)
        .ok_or(StatementWireError::BindingLiteral { index })
}

fn encode_expr(
    encoder: &mut Encoder,
    value: &Value,
    depth: usize,
    path: &str,
) -> Result<(), StatementWireError> {
    encoder.node(depth)?;
    let values = array(value, path)?;
    let tag = bounded_number(values.first(), &format!("{path}[0]"))?;
    match tag {
        0 => {
            exact_len(values, 2, path)?;
            encoder.array(2)?;
            encoder.uint(0)?;
            encoder.uint(transport_nat(values.get(1), &format!("{path}[1]"))?)
        }
        1 => {
            exact_len(values, 2, path)?;
            encoder.array(2)?;
            encoder.uint(1)?;
            encode_level(
                encoder,
                required(values, 1, path)?,
                depth + 1,
                &format!("{path}[1]"),
            )
        }
        2 => {
            exact_len(values, 3, path)?;
            let name = lean_name(required(values, 1, path)?, &format!("{path}[1]"))?;
            let levels = array(required(values, 2, path)?, &format!("{path}[2]"))?;
            encoder.array(3)?;
            encoder.uint(2)?;
            encoder.text(name)?;
            encoder.array(levels.len())?;
            for (index, level) in levels.iter().enumerate() {
                encode_level(encoder, level, depth + 1, &format!("{path}[2][{index}]"))?;
            }
            Ok(())
        }
        3 => {
            exact_len(values, 3, path)?;
            encoder.array(3)?;
            encoder.uint(3)?;
            encode_expr(
                encoder,
                required(values, 1, path)?,
                depth + 1,
                &format!("{path}[1]"),
            )?;
            encode_expr(
                encoder,
                required(values, 2, path)?,
                depth + 1,
                &format!("{path}[2]"),
            )
        }
        4 | 5 => {
            exact_len(values, 4, path)?;
            let binder = bounded_number(values.get(1), &format!("{path}[1]"))?;
            if binder > 3 {
                return Err(StatementWireError::UnknownTag {
                    path: format!("{path}[1]"),
                    kind: "binder-info",
                    tag: binder,
                });
            }
            encoder.array(4)?;
            encoder.uint(tag)?;
            encoder.uint(binder)?;
            encode_expr(
                encoder,
                required(values, 2, path)?,
                depth + 1,
                &format!("{path}[2]"),
            )?;
            encode_expr(
                encoder,
                required(values, 3, path)?,
                depth + 1,
                &format!("{path}[3]"),
            )
        }
        6 => {
            exact_len(values, 4, path)?;
            encoder.array(4)?;
            encoder.uint(6)?;
            for index in 1..=3 {
                encode_expr(
                    encoder,
                    required(values, index, path)?,
                    depth + 1,
                    &format!("{path}[{index}]"),
                )?;
            }
            Ok(())
        }
        7 => {
            exact_len(values, 2, path)?;
            encoder.array(2)?;
            encoder.uint(7)?;
            encode_literal(encoder, required(values, 1, path)?, &format!("{path}[1]"))
        }
        8 => {
            exact_len(values, 2, path)?;
            encoder.array(2)?;
            encoder.uint(8)?;
            encode_expr(
                encoder,
                required(values, 1, path)?,
                depth + 1,
                &format!("{path}[1]"),
            )
        }
        9 => {
            exact_len(values, 4, path)?;
            let name = lean_name(required(values, 1, path)?, &format!("{path}[1]"))?;
            encoder.array(4)?;
            encoder.uint(9)?;
            encoder.text(name)?;
            encoder.uint(transport_nat(values.get(2), &format!("{path}[2]"))?)?;
            encode_expr(
                encoder,
                required(values, 3, path)?,
                depth + 1,
                &format!("{path}[3]"),
            )
        }
        _ => Err(StatementWireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "expression",
            tag,
        }),
    }
}

fn encode_level(
    encoder: &mut Encoder,
    value: &Value,
    depth: usize,
    path: &str,
) -> Result<(), StatementWireError> {
    encoder.node(depth)?;
    let values = array(value, path)?;
    let tag = bounded_number(values.first(), &format!("{path}[0]"))?;
    match tag {
        0 => {
            exact_len(values, 1, path)?;
            encoder.array(1)?;
            encoder.uint(0)
        }
        1 => {
            exact_len(values, 2, path)?;
            encoder.array(2)?;
            encoder.uint(1)?;
            encode_level(
                encoder,
                required(values, 1, path)?,
                depth + 1,
                &format!("{path}[1]"),
            )
        }
        2 | 3 => {
            exact_len(values, 3, path)?;
            encoder.array(3)?;
            encoder.uint(tag)?;
            encode_level(
                encoder,
                required(values, 1, path)?,
                depth + 1,
                &format!("{path}[1]"),
            )?;
            encode_level(
                encoder,
                required(values, 2, path)?,
                depth + 1,
                &format!("{path}[2]"),
            )
        }
        4 => {
            exact_len(values, 2, path)?;
            let name = lean_name(required(values, 1, path)?, &format!("{path}[1]"))?;
            encoder.array(2)?;
            encoder.uint(4)?;
            encoder.text(name)
        }
        5 => Err(StatementWireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "forbidden universe metavariable",
            tag,
        }),
        _ => Err(StatementWireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "universe level",
            tag,
        }),
    }
}

fn encode_literal(
    encoder: &mut Encoder,
    value: &Value,
    path: &str,
) -> Result<(), StatementWireError> {
    let values = array(value, path)?;
    exact_len(values, 2, path)?;
    let tag = bounded_number(values.first(), &format!("{path}[0]"))?;
    encoder.array(2)?;
    encoder.uint(tag)?;
    match tag {
        0 => encoder.uint(transport_nat(values.get(1), &format!("{path}[1]"))?),
        1 => match values.get(1) {
            Some(Value::String(text)) => encoder.text(text),
            _ => Err(StatementWireError::Type {
                path: format!("{path}[1]"),
                expected: "a UTF-8 JSON string",
            }),
        },
        _ => Err(StatementWireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "literal",
            tag,
        }),
    }
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], StatementWireError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| StatementWireError::Type {
            path: path.to_owned(),
            expected: "an array",
        })
}

fn exact_len(values: &[Value], expected: usize, path: &str) -> Result<(), StatementWireError> {
    if values.len() != expected {
        return Err(StatementWireError::Length {
            path: path.to_owned(),
            expected,
            actual: values.len(),
        });
    }
    Ok(())
}

fn required<'a>(
    values: &'a [Value],
    index: usize,
    path: &str,
) -> Result<&'a Value, StatementWireError> {
    values.get(index).ok_or_else(|| StatementWireError::Length {
        path: path.to_owned(),
        expected: index + 1,
        actual: values.len(),
    })
}

fn bounded_number(value: Option<&Value>, path: &str) -> Result<u64, StatementWireError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| StatementWireError::Type {
            path: path.to_owned(),
            expected: "an unsigned JSON integer",
        })
}

fn transport_nat(value: Option<&Value>, path: &str) -> Result<u64, StatementWireError> {
    let Some(Value::String(text)) = value else {
        return Err(StatementWireError::Type {
            path: path.to_owned(),
            expected: "a canonical decimal natural-number string",
        });
    };
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(StatementWireError::Natural {
            path: path.to_owned(),
            value: text.clone(),
        });
    }
    text.parse::<u64>()
        .map_err(|_| StatementWireError::Natural {
            path: path.to_owned(),
            value: text.clone(),
        })
}

fn lean_name<'a>(value: &'a Value, path: &str) -> Result<&'a str, StatementWireError> {
    match value {
        Value::String(name) if !name.is_empty() && name.len() <= 4096 => Ok(name),
        _ => Err(StatementWireError::Name {
            path: path.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn string(value: &str) -> Value {
        json!([7, [1, value]])
    }

    fn app(function: Value, argument: Value) -> Value {
        json!([3, function, argument])
    }

    fn binding_root(claim: &str, logical_name: &str, digest: Sha256Digest) -> Value {
        let mut root = json!([2, ARTIFACT_DIGEST_BINDING_MARKER_V1, []]);
        for argument in [
            string(claim),
            string("example-schema/1"),
            string(logical_name),
            string(&format!("sha256:{digest}")),
            json!([2, "Demo.bytes", []]),
            json!([2, "Demo.meaning", []]),
        ] {
            root = app(root, argument);
        }
        json!([LEAN_STATEMENT_ENCODING_V1, root])
    }

    #[test]
    fn exact_root_yields_audited_binding_fields() {
        let artifact = Sha256Digest::of_bytes("artifact");
        let wire = binding_root("CLAIM-1", "generated/report.json", artifact);
        let statement = lean_statement_wire_digest(&wire).unwrap();
        let parsed =
            parse_artifact_digest_binding(&wire, statement, &ClaimId::new("CLAIM-1").unwrap())
                .unwrap();
        assert_eq!(parsed.mode, BindingMode::DigestTheorem);
        assert_eq!(parsed.artifact_schema, "example-schema/1");
        assert_eq!(
            parsed.artifact_logical_name.as_str(),
            "generated/report.json"
        );
        assert_eq!(parsed.artifact_sha256, artifact);
    }

    #[test]
    fn nested_wrapped_and_alias_markers_fail_closed() {
        let artifact = Sha256Digest::of_bytes("artifact");
        let exact = binding_root("CLAIM-1", "artifact.bin", artifact);
        let exact_root = exact.as_array().unwrap()[1].clone();
        for wire in [
            json!([
                LEAN_STATEMENT_ENCODING_V1,
                app(json!([2, "And", [[0]]]), exact_root.clone())
            ]),
            json!([LEAN_STATEMENT_ENCODING_V1, [2, "Demo.BindingAlias", []]]),
            json!([
                LEAN_STATEMENT_ENCODING_V1,
                [5, 0, [2, "Prop", []], exact_root]
            ]),
        ] {
            let digest = lean_statement_wire_digest(&wire).unwrap();
            assert_eq!(
                parse_artifact_digest_binding(&wire, digest, &ClaimId::new("CLAIM-1").unwrap()),
                Err(StatementWireError::BindingRoot)
            );
        }
    }

    #[test]
    fn exact_root_with_an_extra_nested_marker_fails_closed() {
        let artifact = Sha256Digest::of_bytes("artifact");
        let mut wire = binding_root("CLAIM-1", "artifact.bin", artifact);
        let root = wire
            .as_array_mut()
            .unwrap()
            .get_mut(1)
            .unwrap()
            .as_array_mut()
            .unwrap();
        root[2] = json!([2, ARTIFACT_DIGEST_BINDING_MARKER_V1, []]);
        let digest = lean_statement_wire_digest(&wire).unwrap();
        assert_eq!(
            parse_artifact_digest_binding(&wire, digest, &ClaimId::new("CLAIM-1").unwrap()),
            Err(StatementWireError::BindingOccurrenceCount { actual: 2 })
        );
    }

    #[test]
    fn claim_digest_path_and_statement_hash_mismatches_fail_closed() {
        let artifact = Sha256Digest::of_bytes("artifact");
        let wire = binding_root("CLAIM-1", "artifact.bin", artifact);
        let statement = lean_statement_wire_digest(&wire).unwrap();
        assert!(matches!(
            parse_artifact_digest_binding(&wire, statement, &ClaimId::new("OTHER-CLAIM").unwrap()),
            Err(StatementWireError::BindingClaim { .. })
        ));
        assert_eq!(
            parse_artifact_digest_binding(
                &wire,
                Sha256Digest::of_bytes("different statement"),
                &ClaimId::new("CLAIM-1").unwrap()
            ),
            Err(StatementWireError::DigestMismatch)
        );

        let bad = binding_root("CLAIM-1", "other.bin", artifact);
        let bad_digest = lean_statement_wire_digest(&bad).unwrap();
        assert_ne!(statement, bad_digest);
    }
}
