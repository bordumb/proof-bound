#![no_std]
#![forbid(unsafe_code)]

//! Pure, deterministic transfer-decision kernel for the Proofbound allowance demo.
//!
//! The kernel has no I/O, allocation, ambient state, or panicking arithmetic. Its
//! canonical input is exactly [`REQUEST_LEN`] bytes and its public decision codes
//! have an explicit, stable numeric representation.

/// Four-byte domain separator at the start of every canonical request.
pub const REQUEST_MAGIC: [u8; 4] = *b"PBAL";
/// Canonical request schema version.
pub const REQUEST_VERSION: u8 = 1;
/// Exact encoded length of a version-1 request.
pub const REQUEST_LEN: usize = 38;

/// A bounded request as seen by the shipping decision kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub from_balance: u64,
    pub to_balance: u64,
    pub amount: u64,
    pub cap: u64,
    pub authorized: bool,
}

impl Request {
    /// Encode this value using `proofbound-allowance-request/1`.
    #[must_use]
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut encoded = [0_u8; REQUEST_LEN];
        encoded[0..4].copy_from_slice(&REQUEST_MAGIC);
        encoded[4] = REQUEST_VERSION;
        encoded[5] = u8::from(self.authorized);
        encoded[6..14].copy_from_slice(&self.from_balance.to_be_bytes());
        encoded[14..22].copy_from_slice(&self.to_balance.to_be_bytes());
        encoded[22..30].copy_from_slice(&self.amount.to_be_bytes());
        encoded[30..38].copy_from_slice(&self.cap.to_be_bytes());
        encoded
    }
}

/// Stable error codes for canonical request decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DecodeError {
    InvalidLength = 1,
    InvalidMagic = 2,
    UnsupportedVersion = 3,
    NonCanonicalAuthorization = 4,
}

impl DecodeError {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Decode an exact, canonical `proofbound-allowance-request/1` byte string.
///
/// Short, oversized, trailing, wrongly versioned, and non-canonical Boolean
/// encodings are rejected.
pub fn decode_request(encoded: &[u8]) -> Result<Request, DecodeError> {
    if encoded.len() != REQUEST_LEN {
        return Err(DecodeError::InvalidLength);
    }
    if encoded[0..4] != REQUEST_MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    if encoded[4] != REQUEST_VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }

    let authorized = match encoded[5] {
        0 => false,
        1 => true,
        _ => return Err(DecodeError::NonCanonicalAuthorization),
    };

    Ok(Request {
        from_balance: read_u64_be(encoded, 6),
        to_balance: read_u64_be(encoded, 14),
        amount: read_u64_be(encoded, 22),
        cap: read_u64_be(encoded, 30),
        authorized,
    })
}

fn read_u64_be(encoded: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        encoded[offset],
        encoded[offset + 1],
        encoded[offset + 2],
        encoded[offset + 3],
        encoded[offset + 4],
        encoded[offset + 5],
        encoded[offset + 6],
        encoded[offset + 7],
    ])
}

/// Stable transfer outcomes. Numeric values are part of the demo protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DecisionCode {
    Accepted = 0,
    DeniedUnauthorized = 1,
    DeniedZeroAmount = 2,
    DeniedCapExceeded = 3,
    DeniedInsufficientFunds = 4,
    DeniedDestinationOverflow = 5,
}

impl DecisionCode {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The kernel always returns a decision and a complete state projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub code: DecisionCode,
    pub from_balance: u64,
    pub to_balance: u64,
}

impl Decision {
    const fn denied(request: Request, code: DecisionCode) -> Self {
        Self {
            code,
            from_balance: request.from_balance,
            to_balance: request.to_balance,
        }
    }
}

mod decision;

/// Decide one transfer using the registered decision implementation.
///
/// This concrete public entry point is intentionally retained instead of a
/// re-export so extraction tools select an actual local function definition.
#[must_use]
pub fn decide_transfer(request: Request) -> Decision {
    decision::decide_transfer(request)
}

#[cfg(kani)]
mod kani_harnesses {
    use super::{DecisionCode, Request, decide_transfer};

    fn arbitrary_request() -> Request {
        let from_balance: u8 = kani::any();
        let to_seed: u8 = kani::any();
        let amount: u8 = kani::any();
        let cap: u8 = kani::any();
        let high_destination: bool = kani::any();
        Request {
            from_balance: u64::from(from_balance),
            to_balance: if high_destination {
                u64::MAX - u64::from(to_seed)
            } else {
                u64::from(to_seed)
            },
            amount: u64::from(amount),
            cap: u64::from(cap),
            authorized: kani::any(),
        }
    }

    #[kani::proof]
    fn accepted_conserves_value() {
        let request = arbitrary_request();
        let decision = decide_transfer(request);
        if decision.code == DecisionCode::Accepted {
            assert_eq!(
                u128::from(decision.from_balance) + u128::from(decision.to_balance),
                u128::from(request.from_balance) + u128::from(request.to_balance)
            );
        }
    }

    #[kani::proof]
    fn accepted_never_overdraws() {
        let request = arbitrary_request();
        let decision = decide_transfer(request);
        if decision.code == DecisionCode::Accepted {
            assert!(request.amount <= request.from_balance);
            assert_eq!(decision.from_balance, request.from_balance - request.amount);
        }
    }

    #[kani::proof]
    fn accepted_respects_cap() {
        let request = arbitrary_request();
        let decision = decide_transfer(request);
        if decision.code == DecisionCode::Accepted {
            assert!(request.amount <= request.cap);
        }
    }

    #[kani::proof]
    fn denial_returns_unchanged_state() {
        let request = arbitrary_request();
        let decision = decide_transfer(request);
        if decision.code != DecisionCode::Accepted {
            assert_eq!(decision.from_balance, request.from_balance);
            assert_eq!(decision.to_balance, request.to_balance);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DecisionCode, Request, decide_transfer, decode_request};

    fn accepted_request() -> Request {
        Request {
            from_balance: 100,
            to_balance: 25,
            amount: 30,
            cap: 40,
            authorized: true,
        }
    }

    #[test]
    fn accepted_transfer_uses_checked_arithmetic() {
        let decision = decide_transfer(accepted_request());
        assert_eq!(decision.code, DecisionCode::Accepted);
        assert_eq!((decision.from_balance, decision.to_balance), (70, 55));
    }

    #[test]
    fn canonical_encoding_round_trips() {
        let request = accepted_request();
        assert_eq!(decode_request(&request.encode()), Ok(request));
    }
}
