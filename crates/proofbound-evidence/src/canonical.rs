use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Encode JSON with recursively sorted object keys and no insignificant space.
///
/// `serde_json` rejects non-finite floats before this function sees them. We
/// still sort explicitly so the contract is independent of map implementation
/// features selected by downstream crates.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(value)?;
    sort_value(&mut value);
    serde_json::to_vec(&value)
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let old = std::mem::take(map);
            let mut pairs: Vec<_> = old.into_iter().collect();
            pairs.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut sorted = Map::new();
            for (key, mut child) in pairs {
                sort_value(&mut child);
                sorted.insert(key, child);
            }
            *map = sorted;
        }
        Value::Array(values) => values.iter_mut().for_each(sort_value),
        _ => {}
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Hash a record with an explicit UTF-8 domain separator and NUL boundary.
pub fn domain_hash(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn verify_domain_hash(domain: &str, bytes: &[u8], expected: &str) -> bool {
    domain_hash(domain, bytes) == expected
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let value = json!({"z": {"b": 2, "a": 1}, "a": [ {"d": 4, "c": 3} ]});
        assert_eq!(
            String::from_utf8(canonical_json(&value).unwrap()).unwrap(),
            r#"{"a":[{"c":3,"d":4}],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn domains_separate_equal_bytes() {
        assert_ne!(domain_hash("a/1", b"same"), domain_hash("b/1", b"same"));
    }
}
