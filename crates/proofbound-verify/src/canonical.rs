//! Independent canonical JSON and digest implementation.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Recursively sorts object keys and emits compact UTF-8 JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(value)?;
    sort_value(&mut value);
    serde_json::to_vec(&value)
}

fn sort_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let old = std::mem::take(map);
            let mut pairs = old.into_iter().collect::<Vec<_>>();
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

/// SHA-256 with a UTF-8 domain and NUL separator.
#[must_use]
pub fn domain_hash(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Ordinary SHA-256 for sealed release files.
#[must_use]
pub fn raw_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn independently_canonicalizes_nested_json() {
        let value = json!({"z":{"b":2,"a":1},"a":[{"d":4,"c":3}]});
        assert_eq!(
            canonical_json(&value).unwrap(),
            br#"{"a":[{"c":3,"d":4}],"z":{"a":1,"b":2}}"#
        );
        assert_ne!(domain_hash("one/1", b"x"), domain_hash("two/1", b"x"));
    }
}
