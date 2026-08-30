//! Validated stable identifiers used at graph and manifest boundaries.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// Why a stable identifier was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StableIdError {
    #[error("an identifier must not be empty")]
    Empty,
    #[error("an identifier must be at most 255 bytes")]
    TooLong,
    #[error("an identifier must start with an ASCII letter or digit")]
    InvalidStart,
    #[error("identifier contains a forbidden character at byte {0}")]
    InvalidCharacter(usize),
    #[error("identifier contains the ambiguous '..' sequence")]
    ParentSequence,
}

fn validate_id(value: &str) -> Result<(), StableIdError> {
    if value.is_empty() {
        return Err(StableIdError::Empty);
    }
    if value.len() > 255 {
        return Err(StableIdError::TooLong);
    }
    if !value.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(StableIdError::InvalidStart);
    }
    for (offset, byte) in value.bytes().enumerate() {
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')) {
            return Err(StableIdError::InvalidCharacter(offset));
        }
    }
    if value.contains("..") {
        return Err(StableIdError::ParentSequence);
    }
    Ok(())
}

macro_rules! stable_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Constructs and validates an identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, StableIdError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            /// Borrows the canonical identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = StableIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = StableIdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

stable_id!(ClaimId, "Stable identity of a registered public claim.");
stable_id!(EvidenceId, "Stable identity of an evidence record.");
stable_id!(AssumptionId, "Stable identity of an explicit assumption.");
stable_id!(PremiseId, "Stable identity of a theorem premise.");
stable_id!(NodeId, "Stable identity of an assurance-graph node.");
stable_id!(PolicyId, "Stable identity of a trust policy.");
stable_id!(EnvironmentId, "Stable identity of one proof environment.");
stable_id!(UnitId, "Stable identity of an adapter or evidence unit.");
stable_id!(
    ObligationId,
    "Stable identity of an open obligation or exclusion."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_strict_at_deserialization_boundary() {
        let id: ClaimId = serde_json::from_str("\"DEMO-TRANSFER-001\"").unwrap();
        assert_eq!(id.as_str(), "DEMO-TRANSFER-001");
        assert!(serde_json::from_str::<ClaimId>("\"../escape\"").is_err());
        assert!(serde_json::from_str::<ClaimId>("\"has space\"").is_err());
        assert!(serde_json::from_str::<ClaimId>("\"\"").is_err());
    }
}
