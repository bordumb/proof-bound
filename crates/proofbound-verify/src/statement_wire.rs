//! Independent validation of the canonical Lean statement wire format.
//!
//! The portable verifier deliberately repeats this implementation instead of
//! trusting producer summaries or depending on the Lean adapter/core crates.

use serde_json::Value;

use crate::raw_sha256;

pub(crate) const LEAN_STATEMENT_ENCODING_V1: &str = "lean-expr-cbor/1";
const ARTIFACT_DIGEST_BINDING_V1: &str = "Proofbound.Artifact.DigestBindingV1";
const HASH_DOMAIN_WITH_NUL: &[u8] = b"proofbound:lean-expr-cbor/1\0";
const MAX_DEPTH: usize = 256;
const MAX_NODES: usize = 1_000_000;
const MAX_TEXT_BYTES: usize = 16 << 20;
const MAX_CBOR_BYTES: usize = 64 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedArtifactDigestBinding {
    pub(crate) logical_name: String,
    pub(crate) sha256: String,
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
    nodes: usize,
    text_bytes: usize,
}

impl Encoder {
    fn ensure_room(&self, additional: usize) -> Result<(), String> {
        if self
            .bytes
            .len()
            .checked_add(additional)
            .is_none_or(|size| size > MAX_CBOR_BYTES)
        {
            return Err(format!(
                "canonical Lean statement CBOR exceeds {MAX_CBOR_BYTES} bytes"
            ));
        }
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), String> {
        self.ensure_room(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.ensure_room(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn major_uint(&mut self, major: u8, value: u64) -> Result<(), String> {
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

    fn uint(&mut self, value: u64) -> Result<(), String> {
        self.major_uint(0, value)
    }

    fn array(&mut self, length: usize) -> Result<(), String> {
        self.major_uint(
            4,
            u64::try_from(length).map_err(|_| "array length does not fit u64".to_owned())?,
        )
    }

    fn text(&mut self, value: &str) -> Result<(), String> {
        self.text_bytes = self
            .text_bytes
            .checked_add(value.len())
            .ok_or_else(|| "Lean statement text length overflow".to_owned())?;
        if self.text_bytes > MAX_TEXT_BYTES {
            return Err(format!(
                "Lean statement text exceeds {MAX_TEXT_BYTES} bytes"
            ));
        }
        self.major_uint(
            3,
            u64::try_from(value.len()).map_err(|_| "text length does not fit u64".to_owned())?,
        )?;
        self.extend(value.as_bytes())
    }

    fn node(&mut self, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!(
                "Lean statement expression exceeds nesting limit {MAX_DEPTH}"
            ));
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| "Lean statement node count overflow".to_owned())?;
        if self.nodes > MAX_NODES {
            return Err(format!(
                "Lean statement expression exceeds node limit {MAX_NODES}"
            ));
        }
        Ok(())
    }
}

/// Validates and independently hashes a `lean-expr-cbor/1` statement wire.
pub fn statement_digest(statement_wire: &Value) -> Result<String, String> {
    let cbor = encode_statement(statement_wire)?;
    let mut hash_input = Vec::with_capacity(HASH_DOMAIN_WITH_NUL.len() + cbor.len());
    hash_input.extend_from_slice(HASH_DOMAIN_WITH_NUL);
    hash_input.extend_from_slice(&cbor);
    Ok(raw_sha256(&hash_input))
}

pub(crate) fn parse_artifact_digest_binding(
    statement_wire: &Value,
    expected_statement_sha256: &str,
    expected_claim: &str,
) -> Result<ParsedArtifactDigestBinding, String> {
    let actual_statement_sha256 = statement_digest(statement_wire)?;
    if actual_statement_sha256 != expected_statement_sha256 {
        return Err(format!(
            "statement wire digest mismatch: expected {expected_statement_sha256}, recomputed {actual_statement_sha256}"
        ));
    }

    let statement = array(statement_wire, "$statement")?;
    let root = required(statement, 1, "$statement")?;
    let (head, arguments) = flatten_outer_app(root)?;
    if !is_exact_const(head, ARTIFACT_DIGEST_BINDING_V1) {
        return Err(format!(
            "the theorem statement is not an exact {ARTIFACT_DIGEST_BINDING_V1} root"
        ));
    }
    if marker_count(root) != 1 {
        return Err(format!(
            "{ARTIFACT_DIGEST_BINDING_V1} must occur exactly once"
        ));
    }
    if arguments.len() != 6 {
        return Err(format!(
            "{ARTIFACT_DIGEST_BINDING_V1} requires exactly six arguments"
        ));
    }

    let claim = direct_string_literal(arguments[0], 1)?;
    if claim != expected_claim {
        return Err(format!(
            "artifact binding claim '{claim}' does not equal '{expected_claim}'"
        ));
    }
    let artifact_schema = direct_string_literal(arguments[1], 2)?;
    if artifact_schema.is_empty()
        || artifact_schema.chars().count() > 4096
        || artifact_schema.contains('\0')
    {
        return Err("artifact binding schema is empty, oversized, or contains NUL".into());
    }
    let logical_name = direct_string_literal(arguments[2], 3)?;
    if logical_name.is_empty() || logical_name.chars().count() > 4096 {
        return Err("artifact binding logical name is empty or oversized".into());
    }
    let sha256 = direct_string_literal(arguments[3], 4)?;
    if !valid_digest(sha256) {
        return Err("artifact binding digest is not canonical sha256: lowercase hex".into());
    }

    Ok(ParsedArtifactDigestBinding {
        logical_name: logical_name.to_owned(),
        sha256: sha256.to_owned(),
    })
}

fn encode_statement(value: &Value) -> Result<Vec<u8>, String> {
    let statement = array(value, "$statement")?;
    exact_len(statement, 2, "$statement")?;
    if statement.first().and_then(Value::as_str) != Some(LEAN_STATEMENT_ENCODING_V1) {
        return Err("$statement[0]: expected the literal string 'lean-expr-cbor/1'".into());
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

fn flatten_outer_app(root: &Value) -> Result<(&Value, Vec<&Value>), String> {
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

fn marker_count(value: &Value) -> usize {
    usize::from(is_marker_const(value))
        + value
            .as_array()
            .map_or(0, |values| values.iter().map(marker_count).sum())
}

fn is_marker_const(value: &Value) -> bool {
    let Some(values) = value.as_array() else {
        return false;
    };
    values.len() == 3
        && values.first().and_then(Value::as_u64) == Some(2)
        && values.get(1).and_then(Value::as_str) == Some(ARTIFACT_DIGEST_BINDING_V1)
}

fn direct_string_literal(value: &Value, index: usize) -> Result<&str, String> {
    let Some(expression) = value.as_array() else {
        return Err(format!(
            "artifact binding argument {index} must be a direct string literal"
        ));
    };
    let Some(literal) = expression.get(1).and_then(Value::as_array) else {
        return Err(format!(
            "artifact binding argument {index} must be a direct string literal"
        ));
    };
    if expression.len() != 2
        || expression.first().and_then(Value::as_u64) != Some(7)
        || literal.len() != 2
        || literal.first().and_then(Value::as_u64) != Some(1)
    {
        return Err(format!(
            "artifact binding argument {index} must be a direct string literal"
        ));
    }
    literal
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("artifact binding argument {index} must be a direct string literal"))
}

fn encode_expr(
    encoder: &mut Encoder,
    value: &Value,
    depth: usize,
    path: &str,
) -> Result<(), String> {
    encoder.node(depth)?;
    let values = array(value, path)?;
    let tag = unsigned(values.first(), &format!("{path}[0]"))?;
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
            let binder = unsigned(values.get(1), &format!("{path}[1]"))?;
            if binder > 3 {
                return Err(format!("{path}[1]: unknown binder-info tag {binder}"));
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
        _ => Err(format!("{path}[0]: unknown expression tag {tag}")),
    }
}

fn encode_level(
    encoder: &mut Encoder,
    value: &Value,
    depth: usize,
    path: &str,
) -> Result<(), String> {
    encoder.node(depth)?;
    let values = array(value, path)?;
    let tag = unsigned(values.first(), &format!("{path}[0]"))?;
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
        5 => Err(format!(
            "{path}[0]: forbidden universe metavariable tag {tag}"
        )),
        _ => Err(format!("{path}[0]: unknown universe level tag {tag}")),
    }
}

fn encode_literal(encoder: &mut Encoder, value: &Value, path: &str) -> Result<(), String> {
    let values = array(value, path)?;
    exact_len(values, 2, path)?;
    let tag = unsigned(values.first(), &format!("{path}[0]"))?;
    encoder.array(2)?;
    encoder.uint(tag)?;
    match tag {
        0 => encoder.uint(transport_nat(values.get(1), &format!("{path}[1]"))?),
        1 => match values.get(1) {
            Some(Value::String(text)) => encoder.text(text),
            _ => Err(format!("{path}[1]: expected a UTF-8 JSON string")),
        },
        _ => Err(format!("{path}[0]: unknown literal tag {tag}")),
    }
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], String> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path}: expected an array"))
}

fn exact_len(values: &[Value], expected: usize, path: &str) -> Result<(), String> {
    if values.len() != expected {
        return Err(format!(
            "{path}: expected array length {expected}, found {}",
            values.len()
        ));
    }
    Ok(())
}

fn required<'a>(values: &'a [Value], index: usize, path: &str) -> Result<&'a Value, String> {
    values.get(index).ok_or_else(|| {
        format!(
            "{path}: expected array length {}, found {}",
            index + 1,
            values.len()
        )
    })
}

fn unsigned(value: Option<&Value>, path: &str) -> Result<u64, String> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{path}: expected an unsigned JSON integer"))
}

fn transport_nat(value: Option<&Value>, path: &str) -> Result<u64, String> {
    let Some(Value::String(text)) = value else {
        return Err(format!(
            "{path}: expected a canonical decimal natural-number string"
        ));
    };
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "{path}: non-canonical transported natural number '{text}'"
        ));
    }
    text.parse::<u64>()
        .map_err(|_| format!("{path}: transported natural number exceeds u64"))
}

fn lean_name<'a>(value: &'a Value, path: &str) -> Result<&'a str, String> {
    match value {
        Value::String(name) if !name.is_empty() && name.len() <= 4096 => Ok(name),
        _ => Err(format!("{path}: empty or oversized Lean name")),
    }
}

fn valid_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    fn binding(claim: &str, path: &str, digest: &str) -> Value {
        let mut root = json!([2, ARTIFACT_DIGEST_BINDING_V1, []]);
        for argument in [
            string(claim),
            string("demo-artifact/1"),
            string(path),
            string(digest),
            json!([2, "Demo.bytes", []]),
            json!([2, "Demo.meaning", []]),
        ] {
            root = app(root, argument);
        }
        json!([LEAN_STATEMENT_ENCODING_V1, root])
    }

    #[test]
    fn exact_binding_is_parsed_from_canonical_statement() {
        let artifact = raw_sha256(b"artifact");
        let wire = binding("CLAIM-1", "generated/report.json", &artifact);
        let statement = statement_digest(&wire).unwrap();
        let parsed = parse_artifact_digest_binding(&wire, &statement, "CLAIM-1").unwrap();
        assert_eq!(parsed.logical_name, "generated/report.json");
        assert_eq!(parsed.sha256, artifact);
    }

    #[test]
    fn statement_hash_and_nested_marker_fail_closed() {
        let artifact = raw_sha256(b"artifact");
        let wire = binding("CLAIM-1", "artifact.bin", &artifact);
        assert!(parse_artifact_digest_binding(&wire, &raw_sha256(b"wrong"), "CLAIM-1").is_err());

        let nested = json!([
            LEAN_STATEMENT_ENCODING_V1,
            [3, [2, "And", [[0]]], wire.as_array().unwrap()[1].clone()]
        ]);
        let statement = statement_digest(&nested).unwrap();
        assert!(parse_artifact_digest_binding(&nested, &statement, "CLAIM-1").is_err());
    }
}
