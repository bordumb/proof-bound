//! Recognition of the audited Lean artifact-binding statement form.
//!
//! This parser consumes already validated `lean-expr-cbor/1` trees.  A plain
//! theorem contains no marker and remains valid.  If the marker constant is
//! present anywhere, however, it must be the exact root application with all
//! security-relevant metadata represented by literal strings.

use proofbound_core::ArtifactLogicalName;
use serde_json::Value;

use crate::{
    error::{ARTIFACT_BINDING, AdapterError},
    wire::STATEMENT_ENCODING,
};

const DIGEST_BINDING_V1: &str = "Proofbound.Artifact.DigestBindingV1";
const ARGUMENT_COUNT: usize = 6;

pub(crate) fn validate_digest_binding_v1(
    statement: &Value,
    audited_claim_id: &str,
) -> Result<(), AdapterError> {
    let Some(statement) = statement.as_array() else {
        return malformed("statement wire is not an array");
    };
    if statement.len() != 2 || statement.first().and_then(Value::as_str) != Some(STATEMENT_ENCODING)
    {
        return malformed("statement wire has no canonical encoding envelope");
    }
    let expression = &statement[1];
    let marker_count = marker_count(expression);
    if marker_count == 0 {
        return Ok(());
    }

    let (head, arguments) = application_spine(expression);
    if !is_exact_marker_constant(head) {
        return malformed(
            "DigestBindingV1 occurs below the statement root; artifact bindings must be exact root applications",
        );
    }
    if marker_count != 1 {
        return malformed("DigestBindingV1 must occur exactly once in an artifact-bound statement");
    }
    if arguments.len() != ARGUMENT_COUNT {
        return malformed(format!(
            "DigestBindingV1 requires exactly {ARGUMENT_COUNT} explicit arguments, found {}",
            arguments.len()
        ));
    }

    let claim_id = string_literal(arguments[0])
        .ok_or_else(|| binding_error("DigestBindingV1 claimId must be an exact string literal"))?;
    let artifact_schema = string_literal(arguments[1]).ok_or_else(|| {
        binding_error("DigestBindingV1 artifactSchema must be an exact string literal")
    })?;
    let artifact_logical_name = string_literal(arguments[2]).ok_or_else(|| {
        binding_error("DigestBindingV1 artifactLogicalName must be an exact string literal")
    })?;
    let expected_sha256 = string_literal(arguments[3]).ok_or_else(|| {
        binding_error("DigestBindingV1 expectedSha256 must be an exact string literal")
    })?;

    if claim_id != audited_claim_id {
        return malformed(format!(
            "DigestBindingV1 claimId '{claim_id}' differs from attributed claim '{audited_claim_id}'"
        ));
    }
    if artifact_schema.is_empty() || artifact_schema.len() > 4_096 || artifact_schema.contains('\0')
    {
        return malformed("DigestBindingV1 artifactSchema is empty, oversized, or contains NUL");
    }
    ArtifactLogicalName::new(artifact_logical_name.to_owned()).map_err(|error| {
        binding_error(format!(
            "invalid DigestBindingV1 artifactLogicalName: {error}"
        ))
    })?;
    if !is_canonical_sha256(expected_sha256) {
        return malformed(
            "DigestBindingV1 expectedSha256 must be 'sha256:' plus 64 lowercase hexadecimal digits",
        );
    }
    Ok(())
}

fn malformed<T>(message: impl Into<String>) -> Result<T, AdapterError> {
    Err(binding_error(message))
}

fn binding_error(message: impl Into<String>) -> AdapterError {
    AdapterError::new(ARTIFACT_BINDING, message).remediate(
        "use the exact Proofbound.Artifact.DigestBindingV1 root statement with literal metadata",
    )
}

fn application_spine(mut expression: &Value) -> (&Value, Vec<&Value>) {
    let mut arguments = Vec::new();
    while let Some(values) = expression.as_array() {
        if values.len() != 3 || values.first().and_then(Value::as_u64) != Some(3) {
            break;
        }
        arguments.push(&values[2]);
        expression = &values[1];
    }
    arguments.reverse();
    (expression, arguments)
}

fn is_exact_marker_constant(expression: &Value) -> bool {
    let Some(values) = expression.as_array() else {
        return false;
    };
    values.len() == 3
        && values.first().and_then(Value::as_u64) == Some(2)
        && values.get(1).and_then(Value::as_str) == Some(DIGEST_BINDING_V1)
        && values
            .get(2)
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn marker_count(expression: &Value) -> usize {
    let own = usize::from(is_marker_constant(expression));
    own + expression
        .as_array()
        .map_or(0, |values| values.iter().map(marker_count).sum())
}

fn is_marker_constant(expression: &Value) -> bool {
    let Some(values) = expression.as_array() else {
        return false;
    };
    values.len() == 3
        && values.first().and_then(Value::as_u64) == Some(2)
        && values.get(1).and_then(Value::as_str) == Some(DIGEST_BINDING_V1)
}

fn string_literal(expression: &Value) -> Option<&str> {
    let expression = expression.as_array()?;
    if expression.len() != 2 || expression.first()?.as_u64()? != 7 {
        return None;
    }
    let literal = expression.get(1)?.as_array()?;
    if literal.len() != 2 || literal.first()?.as_u64()? != 1 {
        return None;
    }
    literal.get(1)?.as_str()
}

fn is_canonical_sha256(value: &str) -> bool {
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

    const CLAIM_ID: &str = "FIXTURE-CLAIM-001";
    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn string(value: &str) -> Value {
        json!([7, [1, value]])
    }

    fn apply(function: Value, argument: Value) -> Value {
        json!([3, function, argument])
    }

    fn binding(arguments: Vec<Value>) -> Value {
        let mut expression = json!([2, DIGEST_BINDING_V1, []]);
        for argument in arguments {
            expression = apply(expression, argument);
        }
        json!([STATEMENT_ENCODING, expression])
    }

    fn exact_arguments() -> Vec<Value> {
        vec![
            string(CLAIM_ID),
            string("proofbound-example/1"),
            string("published/example.json"),
            string(DIGEST),
            json!([2, "publishedBytes", []]),
            json!([2, "meaning", []]),
        ]
    }

    #[test]
    fn accepts_plain_theorem_and_exact_root_binding() {
        let plain = json!([STATEMENT_ENCODING, [2, "True", []]]);
        validate_digest_binding_v1(&plain, CLAIM_ID).unwrap();
        validate_digest_binding_v1(&binding(exact_arguments()), CLAIM_ID).unwrap();
    }

    #[test]
    fn rejects_wrong_arity() {
        let mut arguments = exact_arguments();
        arguments.pop();
        let error = validate_digest_binding_v1(&binding(arguments), CLAIM_ID).unwrap_err();
        assert_eq!(error.code, ARTIFACT_BINDING);
        assert!(error.message.contains("exactly 6"));
    }

    #[test]
    fn rejects_nonliteral_metadata_and_noncanonical_digest() {
        let mut nonliteral = exact_arguments();
        nonliteral[1] = json!([2, "schemaFromElsewhere", []]);
        assert!(
            validate_digest_binding_v1(&binding(nonliteral), CLAIM_ID)
                .unwrap_err()
                .message
                .contains("string literal")
        );

        let mut uppercase = exact_arguments();
        uppercase[3] =
            string("sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef");
        assert!(
            validate_digest_binding_v1(&binding(uppercase), CLAIM_ID)
                .unwrap_err()
                .message
                .contains("lowercase")
        );
    }

    #[test]
    fn rejects_nested_marker() {
        let binding = binding(exact_arguments());
        let marker = binding.as_array().unwrap()[1].clone();
        let nested = json!([STATEMENT_ENCODING, [3, [2, "Not", []], marker]]);
        let error = validate_digest_binding_v1(&nested, CLAIM_ID).unwrap_err();
        assert_eq!(error.code, ARTIFACT_BINDING);
        assert!(error.message.contains("below the statement root"));
    }

    #[test]
    fn rejects_claim_literal_mismatch() {
        let mut arguments = exact_arguments();
        arguments[0] = string("OTHER-CLAIM-001");
        let error = validate_digest_binding_v1(&binding(arguments), CLAIM_ID).unwrap_err();
        assert_eq!(error.code, ARTIFACT_BINDING);
        assert!(error.message.contains("differs from attributed claim"));
    }
}
