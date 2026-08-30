//! Canonical SHA-256 identities.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A parsing failure for a canonical lowercase SHA-256 digest.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DigestParseError {
    #[error("a SHA-256 digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidLengthOrCase,
    #[error("invalid hexadecimal digit at byte {0}")]
    InvalidHex(usize),
}

/// Exactly 32 bytes, serialized as `sha256:` plus 64 lowercase hexadecimal
/// characters at public JSON boundaries.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Hashes bytes with SHA-256.
    #[must_use]
    pub fn of_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl FromStr for Sha256Digest {
    type Err = DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii_hexdigit())
        {
            return Err(DigestParseError::InvalidLengthOrCase);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(DigestParseError::InvalidHex(index * 2))?;
            let low = decode_hex(pair[1]).ok_or(DigestParseError::InvalidHex(index * 2 + 1))?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("sha256:{}", self.to_hex()))
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value
            .strip_prefix("sha256:")
            .ok_or_else(|| de::Error::custom("a SHA-256 digest must start with 'sha256:'"))?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_canonical_lowercase_hex() {
        let digest = Sha256Digest::of_bytes(b"proofbound");
        let encoded = serde_json::to_string(&digest).unwrap();
        assert_eq!(encoded.len(), 73);
        assert!(encoded.starts_with("\"sha256:"));
        assert_eq!(
            serde_json::from_str::<Sha256Digest>(&encoded).unwrap(),
            digest
        );
        assert!(serde_json::from_str::<Sha256Digest>(&encoded.to_uppercase()).is_err());
    }
}
