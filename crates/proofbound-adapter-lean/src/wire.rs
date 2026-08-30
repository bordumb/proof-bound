//! Validation and deterministic CBOR encoding for `lean-expr-cbor/1`.
//!
//! The Lean audit deliberately transports unbounded `Nat` values as JSON
//! strings. This boundary accepts the subset representable by CBOR `uint`
//! without tags (`u64`) and rejects every alternative spelling. Tags and
//! binder metadata are JSON integers because they are bounded protocol enums.

use std::str::FromStr;

use proofbound_core::Sha256Digest;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const STATEMENT_ENCODING: &str = "lean-expr-cbor/1";
const HASH_DOMAIN_WITH_NUL: &[u8] = b"proofbound:lean-expr-cbor/1\0";
const MAX_DEPTH: usize = 256;
const MAX_NODES: usize = 1_000_000;
const MAX_TEXT_BYTES: usize = 16 << 20;
const MAX_CBOR_BYTES: usize = 64 << 20;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum WireError {
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
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
    nodes: usize,
    text_bytes: usize,
}

impl Encoder {
    fn ensure_room(&self, additional: usize) -> Result<(), WireError> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|size| size > MAX_CBOR_BYTES)
        {
            return Err(WireError::TooManyBytes);
        }
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), WireError> {
        self.ensure_room(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        self.ensure_room(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn major_uint(&mut self, major: u8, value: u64) -> Result<(), WireError> {
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

    fn uint(&mut self, value: u64) -> Result<(), WireError> {
        self.major_uint(0, value)
    }

    fn array(&mut self, length: usize) -> Result<(), WireError> {
        self.major_uint(
            4,
            u64::try_from(length).map_err(|_| WireError::TooManyBytes)?,
        )
    }

    fn text(&mut self, text: &str) -> Result<(), WireError> {
        self.text_bytes = self
            .text_bytes
            .checked_add(text.len())
            .ok_or(WireError::TooMuchText)?;
        if self.text_bytes > MAX_TEXT_BYTES {
            return Err(WireError::TooMuchText);
        }
        self.major_uint(
            3,
            u64::try_from(text.len()).map_err(|_| WireError::TooMuchText)?,
        )?;
        self.extend(text.as_bytes())
    }

    fn node(&mut self, depth: usize) -> Result<(), WireError> {
        if depth > MAX_DEPTH {
            return Err(WireError::TooDeep);
        }
        self.nodes = self.nodes.checked_add(1).ok_or(WireError::TooManyNodes)?;
        if self.nodes > MAX_NODES {
            return Err(WireError::TooManyNodes);
        }
        Ok(())
    }
}

/// Validate a Lean statement wire tree and encode the exact CDDL item using
/// RFC 8949 shortest integers and definite-length arrays/text strings.
pub fn encode_statement(value: &Value) -> Result<Vec<u8>, WireError> {
    let statement = array(value, "$statement")?;
    exact_len(statement, 2, "$statement")?;
    match statement.first() {
        Some(Value::String(version)) if version == STATEMENT_ENCODING => {}
        _ => {
            return Err(WireError::Type {
                path: "$statement[0]".to_owned(),
                expected: "the literal string 'lean-expr-cbor/1'",
            });
        }
    }

    let mut encoder = Encoder::default();
    encoder.array(2)?;
    encoder.text(STATEMENT_ENCODING)?;
    encode_expr(
        &mut encoder,
        statement.get(1).ok_or_else(|| WireError::Length {
            path: "$statement".to_owned(),
            expected: 2,
            actual: statement.len(),
        })?,
        0,
        "$statement[1]",
    )?;
    Ok(encoder.bytes)
}

/// The statement identity specified by `schemas/lean-expr-v1.cddl`.
pub fn statement_digest(value: &Value) -> Result<Sha256Digest, WireError> {
    let cbor = encode_statement(value)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN_WITH_NUL);
    hasher.update(&cbor);
    let hex = hex::encode(hasher.finalize());
    Ok(Sha256Digest::from_str(&hex).expect("SHA-256 always renders canonical hex"))
}

fn encode_expr(
    encoder: &mut Encoder,
    value: &Value,
    depth: usize,
    path: &str,
) -> Result<(), WireError> {
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
                return Err(WireError::UnknownTag {
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
        _ => Err(WireError::UnknownTag {
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
) -> Result<(), WireError> {
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
        5 => Err(WireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "forbidden universe metavariable",
            tag,
        }),
        _ => Err(WireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "universe level",
            tag,
        }),
    }
}

fn encode_literal(encoder: &mut Encoder, value: &Value, path: &str) -> Result<(), WireError> {
    let values = array(value, path)?;
    exact_len(values, 2, path)?;
    let tag = bounded_number(values.first(), &format!("{path}[0]"))?;
    encoder.array(2)?;
    encoder.uint(tag)?;
    match tag {
        0 => encoder.uint(transport_nat(values.get(1), &format!("{path}[1]"))?),
        1 => match values.get(1) {
            Some(Value::String(text)) => encoder.text(text),
            _ => Err(WireError::Type {
                path: format!("{path}[1]"),
                expected: "a UTF-8 JSON string",
            }),
        },
        _ => Err(WireError::UnknownTag {
            path: format!("{path}[0]"),
            kind: "literal",
            tag,
        }),
    }
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], WireError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| WireError::Type {
            path: path.to_owned(),
            expected: "an array",
        })
}

fn exact_len(values: &[Value], expected: usize, path: &str) -> Result<(), WireError> {
    if values.len() != expected {
        return Err(WireError::Length {
            path: path.to_owned(),
            expected,
            actual: values.len(),
        });
    }
    Ok(())
}

fn required<'a>(values: &'a [Value], index: usize, path: &str) -> Result<&'a Value, WireError> {
    values.get(index).ok_or_else(|| WireError::Length {
        path: path.to_owned(),
        expected: index + 1,
        actual: values.len(),
    })
}

fn bounded_number(value: Option<&Value>, path: &str) -> Result<u64, WireError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| WireError::Type {
            path: path.to_owned(),
            expected: "an unsigned JSON integer",
        })
}

fn transport_nat(value: Option<&Value>, path: &str) -> Result<u64, WireError> {
    let Some(Value::String(text)) = value else {
        return Err(WireError::Type {
            path: path.to_owned(),
            expected: "a canonical decimal natural-number string",
        });
    };
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WireError::Natural {
            path: path.to_owned(),
            value: text.clone(),
        });
    }
    text.parse::<u64>().map_err(|_| WireError::Natural {
        path: path.to_owned(),
        value: text.clone(),
    })
}

fn lean_name<'a>(value: &'a Value, path: &str) -> Result<&'a str, WireError> {
    match value {
        Value::String(name) if !name.is_empty() && name.len() <= 4096 => Ok(name),
        _ => Err(WireError::Name {
            path: path.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn alpha_equivalent_binders_have_one_name_free_encoding() {
        // `fun x : Nat => x` and `fun renamed : Nat => renamed` both arrive
        // in this de Bruijn/name-erased wire form.
        let left = json!([STATEMENT_ENCODING, [4, 0, [2, "Nat", []], [0, "0"]]]);
        let right = json!([STATEMENT_ENCODING, [4, 0, [2, "Nat", []], [0, "0"]]]);
        assert_eq!(
            encode_statement(&left).unwrap(),
            encode_statement(&right).unwrap()
        );
        assert_eq!(
            statement_digest(&left).unwrap(),
            statement_digest(&right).unwrap()
        );

        // A presentation-only binder name cannot be smuggled into the wire.
        let named = json!([STATEMENT_ENCODING, [4, "x", 0, [2, "Nat", []], [0, "0"]]]);
        assert!(matches!(
            encode_statement(&named),
            Err(WireError::Length { .. })
        ));
    }

    #[test]
    fn universe_levels_use_explicit_canonical_tags() {
        let statement = json!([
            STATEMENT_ENCODING,
            [2, "Demo.poly", [[1, [4, "u"]], [2, [0], [3, [0], [0]]]]]
        ]);
        let bytes = encode_statement(&statement).unwrap();
        assert!(!bytes.is_empty());

        let mvar = json!([STATEMENT_ENCODING, [1, [5, null]]]);
        assert!(matches!(
            encode_statement(&mvar),
            Err(WireError::UnknownTag { tag: 5, .. })
        ));
    }

    #[test]
    fn literals_and_projections_preserve_values() {
        let nat = json!([STATEMENT_ENCODING, [7, [0, "18446744073709551615"]]]);
        let string = json!([STATEMENT_ENCODING, [7, [1, "λ\u{0}proof"]]]);
        let projection = json!([
            STATEMENT_ENCODING,
            [9, "Demo.Pair", "24", [3, [7, [1, "x"]], [7, [0, "1"]]]]
        ]);
        assert_ne!(
            statement_digest(&nat).unwrap(),
            statement_digest(&string).unwrap()
        );
        assert!(!encode_statement(&projection).unwrap().is_empty());
    }

    #[test]
    fn shortest_cbor_integer_forms_are_stable() {
        let index_23 = json!([STATEMENT_ENCODING, [0, "23"]]);
        let index_24 = json!([STATEMENT_ENCODING, [0, "24"]]);
        let bytes_23 = encode_statement(&index_23).unwrap();
        let bytes_24 = encode_statement(&index_24).unwrap();
        assert!(bytes_23.ends_with(&[0x82, 0x00, 0x17]));
        assert!(bytes_24.ends_with(&[0x82, 0x00, 0x18, 0x18]));
    }

    #[test]
    fn malformed_and_ambiguous_wire_fails_closed() {
        for value in [
            json!([STATEMENT_ENCODING, [0, 0]]),
            json!([STATEMENT_ENCODING, [0, "00"]]),
            json!([STATEMENT_ENCODING, [4, 4, [1, [0]], [0, "0"]]]),
            json!([STATEMENT_ENCODING, [99]]),
            json!(["lean-expr-cbor/2", [0, "0"]]),
        ] {
            assert!(encode_statement(&value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn statement_drift_changes_domain_separated_digest() {
        let before = json!([STATEMENT_ENCODING, [7, [0, "41"]]]);
        let after = json!([STATEMENT_ENCODING, [7, [0, "42"]]]);
        assert_ne!(
            statement_digest(&before).unwrap(),
            statement_digest(&after).unwrap()
        );
    }
}
