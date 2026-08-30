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

/// Decide one transfer using explicit guards and checked fixed-width arithmetic.
///
/// Guard order is observable through the stable decision code. Every denial
/// returns the original balances.
#[must_use]
pub fn decide_transfer(request: Request) -> Decision {
    if !request.authorized {
        return Decision::denied(request, DecisionCode::DeniedUnauthorized);
    }
    if request.amount == 0 {
        return Decision::denied(request, DecisionCode::DeniedZeroAmount);
    }
    if request.amount > request.cap {
        return Decision::denied(request, DecisionCode::DeniedCapExceeded);
    }

    let Some(from_balance) = request.from_balance.checked_sub(request.amount) else {
        return Decision::denied(request, DecisionCode::DeniedInsufficientFunds);
    };
    let Some(to_balance) = request.to_balance.checked_add(request.amount) else {
        return Decision::denied(request, DecisionCode::DeniedDestinationOverflow);
    };

    Decision {
        code: DecisionCode::Accepted,
        from_balance,
        to_balance,
    }
}

/// Deliberately incorrect kernels used only by registered mutation checks.
#[cfg(any(test, feature = "mutation-testing"))]
pub mod mutations {
    use super::{Decision, DecisionCode, Request};

    /// Removes the authorization guard.
    #[must_use]
    pub fn without_authorization_guard(request: Request) -> Decision {
        if request.amount == 0 {
            return Decision::denied(request, DecisionCode::DeniedZeroAmount);
        }
        if request.amount > request.cap {
            return Decision::denied(request, DecisionCode::DeniedCapExceeded);
        }
        let Some(from_balance) = request.from_balance.checked_sub(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedInsufficientFunds);
        };
        let Some(to_balance) = request.to_balance.checked_add(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedDestinationOverflow);
        };
        Decision {
            code: DecisionCode::Accepted,
            from_balance,
            to_balance,
        }
    }

    /// Removes the positive-amount guard.
    #[must_use]
    pub fn without_positive_amount_guard(request: Request) -> Decision {
        if !request.authorized {
            return Decision::denied(request, DecisionCode::DeniedUnauthorized);
        }
        if request.amount > request.cap {
            return Decision::denied(request, DecisionCode::DeniedCapExceeded);
        }
        let Some(from_balance) = request.from_balance.checked_sub(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedInsufficientFunds);
        };
        let Some(to_balance) = request.to_balance.checked_add(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedDestinationOverflow);
        };
        Decision {
            code: DecisionCode::Accepted,
            from_balance,
            to_balance,
        }
    }

    /// Removes the configured-cap guard.
    #[must_use]
    pub fn without_cap_guard(request: Request) -> Decision {
        if !request.authorized {
            return Decision::denied(request, DecisionCode::DeniedUnauthorized);
        }
        if request.amount == 0 {
            return Decision::denied(request, DecisionCode::DeniedZeroAmount);
        }
        let Some(from_balance) = request.from_balance.checked_sub(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedInsufficientFunds);
        };
        let Some(to_balance) = request.to_balance.checked_add(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedDestinationOverflow);
        };
        Decision {
            code: DecisionCode::Accepted,
            from_balance,
            to_balance,
        }
    }

    /// Removes checked subtraction, exposing wrapping underflow.
    #[must_use]
    pub fn without_source_balance_guard(request: Request) -> Decision {
        if !request.authorized {
            return Decision::denied(request, DecisionCode::DeniedUnauthorized);
        }
        if request.amount == 0 {
            return Decision::denied(request, DecisionCode::DeniedZeroAmount);
        }
        if request.amount > request.cap {
            return Decision::denied(request, DecisionCode::DeniedCapExceeded);
        }
        let from_balance = request.from_balance.wrapping_sub(request.amount);
        let Some(to_balance) = request.to_balance.checked_add(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedDestinationOverflow);
        };
        Decision {
            code: DecisionCode::Accepted,
            from_balance,
            to_balance,
        }
    }

    /// Removes checked addition, exposing wrapping destination overflow.
    #[must_use]
    pub fn without_destination_overflow_guard(request: Request) -> Decision {
        if !request.authorized {
            return Decision::denied(request, DecisionCode::DeniedUnauthorized);
        }
        if request.amount == 0 {
            return Decision::denied(request, DecisionCode::DeniedZeroAmount);
        }
        if request.amount > request.cap {
            return Decision::denied(request, DecisionCode::DeniedCapExceeded);
        }
        let Some(from_balance) = request.from_balance.checked_sub(request.amount) else {
            return Decision::denied(request, DecisionCode::DeniedInsufficientFunds);
        };
        Decision {
            code: DecisionCode::Accepted,
            from_balance,
            to_balance: request.to_balance.wrapping_add(request.amount),
        }
    }
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
    use super::mutations::{
        without_authorization_guard, without_cap_guard, without_destination_overflow_guard,
        without_positive_amount_guard, without_source_balance_guard,
    };
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

    #[test]
    fn authorization_mutation_is_detected() {
        let request = Request {
            authorized: false,
            ..accepted_request()
        };
        assert_eq!(
            decide_transfer(request).code,
            DecisionCode::DeniedUnauthorized
        );
        assert_eq!(
            without_authorization_guard(request).code,
            DecisionCode::Accepted
        );
    }

    #[test]
    fn positive_amount_mutation_is_detected() {
        let request = Request {
            amount: 0,
            ..accepted_request()
        };
        assert_eq!(
            decide_transfer(request).code,
            DecisionCode::DeniedZeroAmount
        );
        assert_eq!(
            without_positive_amount_guard(request).code,
            DecisionCode::Accepted
        );
    }

    #[test]
    fn cap_mutation_is_detected() {
        let request = Request {
            amount: 41,
            ..accepted_request()
        };
        assert_eq!(
            decide_transfer(request).code,
            DecisionCode::DeniedCapExceeded
        );
        assert_eq!(without_cap_guard(request).code, DecisionCode::Accepted);
    }

    #[test]
    fn source_balance_mutation_is_detected() {
        let request = Request {
            from_balance: 20,
            ..accepted_request()
        };
        assert_eq!(
            decide_transfer(request).code,
            DecisionCode::DeniedInsufficientFunds
        );
        assert_eq!(
            without_source_balance_guard(request).code,
            DecisionCode::Accepted
        );
    }

    #[test]
    fn destination_overflow_mutation_is_detected() {
        let request = Request {
            to_balance: u64::MAX - 10,
            amount: 20,
            ..accepted_request()
        };
        assert_eq!(
            decide_transfer(request).code,
            DecisionCode::DeniedDestinationOverflow
        );
        assert_eq!(
            without_destination_overflow_guard(request).code,
            DecisionCode::Accepted
        );
    }
}
