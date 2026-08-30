//! Strict checker for the bounded PBAC version-1 certificate format.
//!
//! This crate deliberately contains no producer or search implementation. It
//! treats every byte as untrusted and exposes stable rejection codes.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const MAX_BYTES: usize = 64;
pub const MAX_ENTRIES: usize = 8;
pub const MAX_VALUE: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    TooLarge,
    Truncated,
    BadMagic,
    UnsupportedVersion,
    NonzeroFlags,
    CountRange,
    VarintOverflow,
    NoncanonicalVarint,
    ValueRange,
    IdZero,
    IdOrder,
    TrailingBytes,
    SumMismatch,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "PBAC_E_TOO_LARGE",
            Self::Truncated => "PBAC_E_TRUNCATED",
            Self::BadMagic => "PBAC_E_BAD_MAGIC",
            Self::UnsupportedVersion => "PBAC_E_UNSUPPORTED_VERSION",
            Self::NonzeroFlags => "PBAC_E_NONZERO_FLAGS",
            Self::CountRange => "PBAC_E_COUNT_RANGE",
            Self::VarintOverflow => "PBAC_E_VARINT_OVERFLOW",
            Self::NoncanonicalVarint => "PBAC_E_NONCANONICAL_VARINT",
            Self::ValueRange => "PBAC_E_VALUE_RANGE",
            Self::IdZero => "PBAC_E_ID_ZERO",
            Self::IdOrder => "PBAC_E_ID_ORDER",
            Self::TrailingBytes => "PBAC_E_TRAILING_BYTES",
            Self::SumMismatch => "PBAC_E_SUM_MISMATCH",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckError {
    pub code: ErrorCode,
    pub offset: usize,
}

impl CheckError {
    const fn new(code: ErrorCode, offset: usize) -> Self {
        Self { code, offset }
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.code.as_str(), self.offset)
    }
}

impl std::error::Error for CheckError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub id: u8,
    pub value: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub target: u32,
    pub entries: Vec<Entry>,
}

impl Certificate {
    pub fn total(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| u64::from(entry.value))
            .sum()
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, CheckError> {
        let offset = self.offset;
        let byte = self
            .bytes
            .get(offset)
            .copied()
            .ok_or_else(|| CheckError::new(ErrorCode::Truncated, offset))?;
        self.offset += 1;
        Ok(byte)
    }

    fn expect(&mut self, expected: u8, code: ErrorCode) -> Result<(), CheckError> {
        let offset = self.offset;
        if self.byte()? == expected {
            Ok(())
        } else {
            Err(CheckError::new(code, offset))
        }
    }

    /// Decode a minimal unsigned LEB128 value bounded to `u32`.
    fn uleb128(&mut self) -> Result<u32, CheckError> {
        let start = self.offset;
        let mut value = 0_u32;

        for index in 0..5 {
            let byte = self.byte()?;
            let payload = byte & 0x7f;
            if index == 4 && payload > 0x0f {
                return Err(CheckError::new(ErrorCode::VarintOverflow, start));
            }
            value |= u32::from(payload) << (index * 7);

            if byte & 0x80 == 0 {
                if index > 0 && payload == 0 {
                    return Err(CheckError::new(ErrorCode::NoncanonicalVarint, start));
                }
                return Ok(value);
            }
        }

        Err(CheckError::new(ErrorCode::VarintOverflow, start))
    }
}

/// Parse canonical bytes. Mathematical validity is checked separately by
/// [`check`], so callers can diagnose structural and semantic failures.
pub fn parse(bytes: &[u8]) -> Result<Certificate, CheckError> {
    if bytes.len() > MAX_BYTES {
        return Err(CheckError::new(ErrorCode::TooLarge, MAX_BYTES));
    }

    let mut reader = Reader::new(bytes);
    for expected in *b"PBAC" {
        reader.expect(expected, ErrorCode::BadMagic)?;
    }
    reader.expect(1, ErrorCode::UnsupportedVersion)?;
    reader.expect(0, ErrorCode::NonzeroFlags)?;

    let count_offset = reader.offset;
    let count = usize::from(reader.byte()?);
    if !(1..=MAX_ENTRIES).contains(&count) {
        return Err(CheckError::new(ErrorCode::CountRange, count_offset));
    }

    let target_offset = reader.offset;
    let target = reader.uleb128()?;
    if target > MAX_VALUE {
        return Err(CheckError::new(ErrorCode::ValueRange, target_offset));
    }

    let mut entries = Vec::with_capacity(count);
    let mut previous_id = 0_u8;
    for _ in 0..count {
        let id_offset = reader.offset;
        let id = reader.byte()?;
        if id == 0 {
            return Err(CheckError::new(ErrorCode::IdZero, id_offset));
        }
        if id <= previous_id {
            return Err(CheckError::new(ErrorCode::IdOrder, id_offset));
        }
        previous_id = id;

        let value_offset = reader.offset;
        let value = reader.uleb128()?;
        if value > MAX_VALUE {
            return Err(CheckError::new(ErrorCode::ValueRange, value_offset));
        }
        entries.push(Entry { id, value });
    }

    if reader.offset != bytes.len() {
        return Err(CheckError::new(ErrorCode::TrailingBytes, reader.offset));
    }

    Ok(Certificate { target, entries })
}

/// Accept exactly canonical certificates whose entries add to the stated
/// target.
pub fn check(bytes: &[u8]) -> Result<Certificate, CheckError> {
    let certificate = parse(bytes)?;
    if certificate.total() != u64::from(certificate.target) {
        return Err(CheckError::new(ErrorCode::SumMismatch, 0));
    }
    Ok(certificate)
}

/// Read no more than one byte beyond the public resource limit. This avoids
/// allocating an attacker-selected file size before the checker can reject it.
pub fn check_path(path: impl AsRef<Path>) -> Result<Certificate, PathCheckError> {
    let mut file = File::open(path).map_err(PathCheckError::Io)?;
    let mut bytes = Vec::with_capacity(MAX_BYTES + 1);
    file.by_ref()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(PathCheckError::Io)?;
    check(&bytes).map_err(PathCheckError::Rejected)
}

#[derive(Debug)]
pub enum PathCheckError {
    Io(io::Error),
    Rejected(CheckError),
}

impl fmt::Display for PathCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Rejected(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PathCheckError {}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = &[
        0x50, 0x42, 0x41, 0x43, 0x01, 0x00, 0x03, 0xfd, 0x07, 0x01, 0x03, 0x04, 0x80, 0x01, 0x09,
        0xfa, 0x06,
    ];

    fn code(bytes: &[u8]) -> ErrorCode {
        check(bytes).expect_err("input must be rejected").code
    }

    #[test]
    fn accepts_canonical_certificate() {
        let certificate = check(VALID).expect("canonical fixture");
        assert_eq!(certificate.target, 1_021);
        assert_eq!(certificate.total(), 1_021);
        assert_eq!(certificate.entries.len(), 3);
    }

    #[test]
    fn rejects_noncanonical_target() {
        let bytes = [
            0x50, 0x42, 0x41, 0x43, 0x01, 0x00, 0x03, 0xfd, 0x87, 0x00, 0x01, 0x03, 0x04, 0x80,
            0x01, 0x09, 0xfa, 0x06,
        ];
        assert_eq!(code(&bytes), ErrorCode::NoncanonicalVarint);
    }

    #[test]
    fn rejects_each_envelope_fault() {
        let mut input = VALID.to_vec();
        input[0] = b'X';
        assert_eq!(code(&input), ErrorCode::BadMagic);

        let mut input = VALID.to_vec();
        input[4] = 2;
        assert_eq!(code(&input), ErrorCode::UnsupportedVersion);

        let mut input = VALID.to_vec();
        input[5] = 1;
        assert_eq!(code(&input), ErrorCode::NonzeroFlags);

        let mut input = VALID.to_vec();
        input[6] = 0;
        assert_eq!(code(&input), ErrorCode::CountRange);

        let mut input = VALID.to_vec();
        input.push(0);
        assert_eq!(code(&input), ErrorCode::TrailingBytes);
    }

    #[test]
    fn rejects_order_value_sum_and_varint_faults() {
        let mut duplicate = VALID.to_vec();
        duplicate[11] = 1;
        assert_eq!(code(&duplicate), ErrorCode::IdOrder);

        let mut mismatch = VALID.to_vec();
        mismatch[7] = 0xfc;
        assert_eq!(code(&mismatch), ErrorCode::SumMismatch);

        let overflow = [
            0x50, 0x42, 0x41, 0x43, 1, 0, 1, 0x80, 0x80, 0x80, 0x80, 0x10, 1, 0,
        ];
        assert_eq!(code(&overflow), ErrorCode::VarintOverflow);

        let too_large_value = [0x50, 0x42, 0x41, 0x43, 1, 0, 1, 0xc1, 0x84, 0x3d, 1, 0];
        assert_eq!(code(&too_large_value), ErrorCode::ValueRange);
    }

    #[test]
    fn truncation_and_resource_limits_are_fail_closed() {
        for length in 0..VALID.len() {
            assert!(check(&VALID[..length]).is_err(), "prefix {length} accepted");
        }
        assert_eq!(code(&[0; MAX_BYTES + 1]), ErrorCode::TooLarge);
    }
}
