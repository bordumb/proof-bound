#![forbid(unsafe_code)]

use std::{error::Error, fmt};

pub const MAGIC: [u8; 4] = *b"PBCT";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 8;
pub const MAX_PAYLOAD_LEN: usize = 4_096;
pub const MAX_ENVELOPE_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    payload: Vec<u8>,
}

impl Certificate {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let length = u16::try_from(self.payload.len())
            .expect("a decoded payload always fits the two-byte length field");
        let mut output = Vec::with_capacity(HEADER_LEN + self.payload.len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.push(0);
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(&self.payload);
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InputTooLarge,
    Truncated,
    BadMagic,
    UnsupportedVersion,
    ReservedFlags,
    EmptyPayload,
    PayloadTooLarge,
    TrailingBytes,
}

impl DecodeError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputTooLarge => "PBCT-E-INPUT-TOO-LARGE",
            Self::Truncated => "PBCT-E-TRUNCATED",
            Self::BadMagic => "PBCT-E-BAD-MAGIC",
            Self::UnsupportedVersion => "PBCT-E-UNSUPPORTED-VERSION",
            Self::ReservedFlags => "PBCT-E-RESERVED-FLAGS",
            Self::EmptyPayload => "PBCT-E-EMPTY-PAYLOAD",
            Self::PayloadTooLarge => "PBCT-E-PAYLOAD-TOO-LARGE",
            Self::TrailingBytes => "PBCT-E-TRAILING-BYTES",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for DecodeError {}

/// Decode one complete canonical PBCT envelope.
///
/// This function never normalizes invalid input. Callers should apply their
/// bounded, domain-specific payload checker only after this returns `Ok`.
pub fn decode(input: &[u8]) -> Result<Certificate, DecodeError> {
    if input.len() > MAX_ENVELOPE_LEN {
        return Err(DecodeError::InputTooLarge);
    }
    if input.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    if input[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if input[4] != VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    if input[5] != 0 {
        return Err(DecodeError::ReservedFlags);
    }

    let payload_len = usize::from(u16::from_be_bytes([input[6], input[7]]));
    if payload_len == 0 {
        return Err(DecodeError::EmptyPayload);
    }
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(DecodeError::PayloadTooLarge);
    }

    let expected = HEADER_LEN + payload_len;
    match input.len().cmp(&expected) {
        std::cmp::Ordering::Less => Err(DecodeError::Truncated),
        std::cmp::Ordering::Greater => Err(DecodeError::TrailingBytes),
        std::cmp::Ordering::Equal => Ok(Certificate {
            payload: input[HEADER_LEN..].to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).unwrap();
        let mut bytes = Vec::from(MAGIC);
        bytes.extend_from_slice(&[VERSION, 0]);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn accepted_inputs_round_trip_byte_for_byte() {
        for size in [1, 2, 255, 256, MAX_PAYLOAD_LEN - 1, MAX_PAYLOAD_LEN] {
            let bytes = envelope(&vec![0xa5; size]);
            let certificate = decode(&bytes).unwrap();
            assert_eq!(certificate.payload(), &bytes[HEADER_LEN..]);
            assert_eq!(certificate.canonical_bytes(), bytes);
        }
    }

    #[test]
    fn rejects_noncanonical_envelopes_with_stable_errors() {
        let valid = envelope(b"x");
        let cases = [
            (&valid[..HEADER_LEN - 1], DecodeError::Truncated),
            (&b"NOPE\x01\x00\x00\x01x"[..], DecodeError::BadMagic),
            (
                &b"PBCT\x02\x00\x00\x01x"[..],
                DecodeError::UnsupportedVersion,
            ),
            (&b"PBCT\x01\x01\x00\x01x"[..], DecodeError::ReservedFlags),
            (&b"PBCT\x01\x00\x00\x00"[..], DecodeError::EmptyPayload),
            (&b"PBCT\x01\x00\x00\x02x"[..], DecodeError::Truncated),
            (&b"PBCT\x01\x00\x00\x01xy"[..], DecodeError::TrailingBytes),
        ];
        for (bytes, expected) in cases {
            let error = decode(bytes).unwrap_err();
            assert_eq!(error, expected);
            assert!(error.code().starts_with("PBCT-E-"));
            assert_eq!(error.to_string(), error.code());
        }
    }

    #[test]
    fn enforces_bounds_before_copying_payload() {
        let oversized_declared = b"PBCT\x01\x00\x10\x01";
        assert_eq!(
            decode(oversized_declared),
            Err(DecodeError::PayloadTooLarge)
        );

        let oversized_input = vec![0; MAX_ENVELOPE_LEN + 1];
        assert_eq!(decode(&oversized_input), Err(DecodeError::InputTooLarge));
    }
}
