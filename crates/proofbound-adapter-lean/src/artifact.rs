//! Recognition of the audited Lean artifact-binding statement form.
//!
//! This parser consumes already validated `lean-expr-cbor/1` trees.  A plain
//! theorem contains no marker and remains valid.  If the marker constant is
//! present anywhere, however, it must be the exact root application with all
//! security-relevant metadata represented by literal strings.

use std::collections::BTreeSet;

use proofbound_core::ArtifactLogicalName;
use serde_json::Value;

use crate::{
    error::{ARTIFACT_BINDING, AdapterError},
    wire::STATEMENT_ENCODING,
};

const DIGEST_BINDING_V1: &str = "Proofbound.Artifact.DigestBindingV1";
const DIGEST_BINDING_SET_V1: &str = "Proofbound.Artifact.DigestBindingSetV1";
const DIGEST_BINDING_MEMBER_V1: &str = "Proofbound.Artifact.DigestBindingMemberV1";
const DIGEST_BINDING_MEMBER_CTOR_V1: &str = "Proofbound.Artifact.DigestBindingMemberV1.mk";
const LIST_CONS: &str = "List.cons";
const LIST_NIL: &str = "List.nil";
const ARGUMENT_COUNT: usize = 6;
const SET_ARGUMENT_COUNT: usize = 4;
const MAX_BINDING_MEMBERS: usize = 256;

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
    let singular = is_exact_constant(head, DIGEST_BINDING_V1, &[]);
    let set = is_exact_constant(head, DIGEST_BINDING_SET_V1, &[]);
    if !singular && !set {
        return malformed(
            "artifact binding marker occurs below the statement root; bindings must be exact root applications",
        );
    }
    if marker_count != 1 {
        return malformed(
            "artifact binding marker must occur exactly once in an artifact-bound statement",
        );
    }
    if singular && arguments.len() != ARGUMENT_COUNT {
        return malformed(format!(
            "DigestBindingV1 requires exactly {ARGUMENT_COUNT} explicit arguments, found {}",
            arguments.len()
        ));
    }
    if set && arguments.len() != SET_ARGUMENT_COUNT {
        return malformed(format!(
            "DigestBindingSetV1 requires exactly {SET_ARGUMENT_COUNT} explicit arguments, found {}",
            arguments.len()
        ));
    }

    let claim_id = string_literal(arguments[0])
        .ok_or_else(|| binding_error("DigestBindingV1 claimId must be an exact string literal"))?;
    let artifact_schema = string_literal(arguments[1]).ok_or_else(|| {
        binding_error("DigestBindingV1 artifactSchema must be an exact string literal")
    })?;
    if claim_id != audited_claim_id {
        return malformed(format!(
            "artifact binding claimId '{claim_id}' differs from attributed claim '{audited_claim_id}'"
        ));
    }
    if artifact_schema.is_empty() || artifact_schema.len() > 4_096 || artifact_schema.contains('\0')
    {
        return malformed("DigestBindingV1 artifactSchema is empty, oversized, or contains NUL");
    }
    if singular {
        validate_member_literals(arguments[2], arguments[3])?;
    } else {
        validate_member_list(arguments[2])?;
    }
    Ok(())
}

fn validate_member_literals(logical_name: &Value, digest: &Value) -> Result<(), AdapterError> {
    let artifact_logical_name = string_literal(logical_name)
        .ok_or_else(|| binding_error("artifactLogicalName must be an exact string literal"))?;
    let expected_sha256 = string_literal(digest)
        .ok_or_else(|| binding_error("expectedSha256 must be an exact string literal"))?;
    ArtifactLogicalName::new(artifact_logical_name.to_owned())
        .map_err(|error| binding_error(format!("invalid artifactLogicalName: {error}")))?;
    if !is_canonical_sha256(expected_sha256) {
        return malformed("expectedSha256 must be 'sha256:' plus 64 lowercase hexadecimal digits");
    }
    Ok(())
}

fn validate_member_list(mut expression: &Value) -> Result<(), AdapterError> {
    let mut names = Vec::new();
    let mut digests = BTreeSet::new();
    loop {
        let (head, arguments) = application_spine(expression);
        if is_exact_constant(head, LIST_NIL, &[0]) {
            if arguments.len() != 1
                || !is_exact_constant(arguments[0], DIGEST_BINDING_MEMBER_V1, &[])
            {
                return malformed("List.nil has the wrong artifact-binding member type");
            }
            break;
        }
        if !is_exact_constant(head, LIST_CONS, &[0])
            || arguments.len() != 3
            || !is_exact_constant(arguments[0], DIGEST_BINDING_MEMBER_V1, &[])
        {
            return malformed("members must be a direct List.cons/List.nil spine");
        }
        let (member_head, member_arguments) = application_spine(arguments[1]);
        if !is_exact_constant(member_head, DIGEST_BINDING_MEMBER_CTOR_V1, &[])
            || member_arguments.len() != 3
        {
            return malformed("member must be an exact DigestBindingMemberV1.mk application");
        }
        validate_member_literals(member_arguments[0], member_arguments[1])?;
        let name = string_literal(member_arguments[0]).expect("validated member name");
        let digest = string_literal(member_arguments[1]).expect("validated member digest");
        names.push(name);
        if !digests.insert(digest) {
            return malformed("artifact-binding member digests must be unique");
        }
        if names.len() > MAX_BINDING_MEMBERS {
            return malformed(format!(
                "artifact-binding member count exceeds {MAX_BINDING_MEMBERS}"
            ));
        }
        expression = arguments[2];
    }
    if names.is_empty() {
        return malformed("artifact-binding member list must be nonempty");
    }
    if !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return malformed("artifact-binding members must be strictly ordered by logical name");
    }
    Ok(())
}

fn malformed<T>(message: impl Into<String>) -> Result<T, AdapterError> {
    Err(binding_error(message))
}

fn binding_error(message: impl Into<String>) -> AdapterError {
    AdapterError::new(ARTIFACT_BINDING, message)
        .remediate("use an exact Proofbound artifact-binding root statement with literal metadata")
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

fn is_exact_constant(expression: &Value, expected_name: &str, expected_levels: &[u64]) -> bool {
    let Some(values) = expression.as_array() else {
        return false;
    };
    values.len() == 3
        && values.first().and_then(Value::as_u64) == Some(2)
        && values.get(1).and_then(Value::as_str) == Some(expected_name)
        && values
            .get(2)
            .and_then(Value::as_array)
            .is_some_and(|levels| {
                levels.len() == expected_levels.len()
                    && levels.iter().zip(expected_levels).all(|(level, expected)| {
                        level.as_array().is_some_and(|items| {
                            items.len() == 1
                                && items.first().and_then(Value::as_u64) == Some(*expected)
                        })
                    })
            })
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
        && matches!(
            values.get(1).and_then(Value::as_str),
            Some(DIGEST_BINDING_V1 | DIGEST_BINDING_SET_V1)
        )
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
    use std::{fs, path::Path};

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

    fn member_with_identity(name: Value, digest: Value, bytes: &str) -> Value {
        let mut expression = json!([2, DIGEST_BINDING_MEMBER_CTOR_V1, []]);
        for argument in [name, digest, json!([2, bytes, []])] {
            expression = apply(expression, argument);
        }
        expression
    }

    fn member(name: &str, digest: &str, bytes: &str) -> Value {
        member_with_identity(string(name), string(digest), bytes)
    }

    fn binding_set(members: Vec<(&str, &str, &str)>) -> Value {
        binding_set_members(
            members
                .into_iter()
                .map(|(name, digest, bytes)| member(name, digest, bytes))
                .collect(),
        )
    }

    fn binding_set_members(members: Vec<Value>) -> Value {
        let member_type = json!([2, DIGEST_BINDING_MEMBER_V1, []]);
        let mut list = apply(json!([2, LIST_NIL, [[0]]]), member_type.clone());
        for member in members.into_iter().rev() {
            let mut cons = json!([2, LIST_CONS, [[0]]]);
            for argument in [member_type.clone(), member, list] {
                cons = apply(cons, argument);
            }
            list = cons;
        }
        let mut expression = json!([2, DIGEST_BINDING_SET_V1, []]);
        for argument in [
            string(CLAIM_ID),
            string("proofbound-example/1"),
            list,
            json!([2, "meaning", []]),
        ] {
            expression = apply(expression, argument);
        }
        json!([STATEMENT_ENCODING, expression])
    }

    #[test]
    fn accepts_plain_theorem_and_exact_root_binding() {
        let plain = json!([STATEMENT_ENCODING, [2, "True", []]]);
        validate_digest_binding_v1(&plain, CLAIM_ID).unwrap();
        validate_digest_binding_v1(&binding(exact_arguments()), CLAIM_ID).unwrap();
        validate_digest_binding_v1(
            &binding_set(vec![
                ("dist/aarch64/tool", DIGEST, "armBytes"),
                (
                    "dist/x86_64/tool",
                    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "x86Bytes",
                ),
            ]),
            CLAIM_ID,
        )
        .unwrap();
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

    #[test]
    fn rejects_empty_duplicate_and_reordered_binding_sets() {
        for value in [
            binding_set(vec![]),
            binding_set(vec![
                ("dist/a", DIGEST, "firstBytes"),
                ("dist/b", DIGEST, "secondBytes"),
            ]),
            binding_set(vec![
                (
                    "dist/b",
                    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "secondBytes",
                ),
                ("dist/a", DIGEST, "firstBytes"),
            ]),
        ] {
            let error = validate_digest_binding_v1(&value, CLAIM_ID).unwrap_err();
            assert_eq!(error.code, ARTIFACT_BINDING);
        }
    }

    #[test]
    fn frozen_contextual_binding_statement_attacks_reject_with_registered_code() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../proofbound/conformance/v2/contextual-artifact-binding-attacks.json");
        let corpus: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(
            corpus["schema"],
            "proofbound-contextual-artifact-binding-attacks/1"
        );
        let cases = corpus["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 10);
        let mut seen = BTreeSet::new();
        let mut executed = BTreeSet::new();

        for case in cases {
            let id = case["id"].as_str().unwrap();
            assert!(seen.insert(id), "duplicate case {id}");
            assert!(!case["mutation"].as_str().unwrap().trim().is_empty());
            let statement = match id {
                "empty-binding-set" => binding_set(vec![]),
                "duplicate-binding-member" => binding_set(vec![
                    ("dist/a", DIGEST, "firstBytes"),
                    ("dist/b", DIGEST, "secondBytes"),
                ]),
                "noncanonical-binding-order" => binding_set(vec![
                    (
                        "dist/b",
                        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                        "secondBytes",
                    ),
                    ("dist/a", DIGEST, "firstBytes"),
                ]),
                "computed-member-identity" => binding_set_members(vec![member_with_identity(
                    json!([2, "Demo.computedName", []]),
                    string(DIGEST),
                    "computedBytes",
                )]),
                "context-kind-substitution"
                | "inactive-binding-smuggling"
                | "member-omission"
                | "member-substitution"
                | "receipt-context-substitution"
                | "observation-promotion" => continue,
                unknown => panic!("unimplemented frozen contextual binding attack {unknown}"),
            };
            executed.insert(id);
            let error = validate_digest_binding_v1(&statement, CLAIM_ID).unwrap_err();
            assert_eq!(error.code, case["expected_code"].as_str().unwrap(), "{id}");
        }
        assert_eq!(
            executed,
            BTreeSet::from([
                "computed-member-identity",
                "duplicate-binding-member",
                "empty-binding-set",
                "noncanonical-binding-order",
            ])
        );
    }
}
