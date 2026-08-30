use allowance_kernel::{DecisionCode, Request, decide_transfer, decode_request};

const ACCEPTED: &[u8] = include_bytes!("../../../fixtures/v1/accepted.bin");
const UNAUTHORIZED: &[u8] = include_bytes!("../../../fixtures/v1/unauthorized.bin");
const ZERO_AMOUNT: &[u8] = include_bytes!("../../../fixtures/v1/zero-amount.bin");
const CAP_EXCEEDED: &[u8] = include_bytes!("../../../fixtures/v1/cap-exceeded.bin");
const INSUFFICIENT: &[u8] = include_bytes!("../../../fixtures/v1/insufficient-funds.bin");
const OVERFLOW: &[u8] = include_bytes!("../../../fixtures/v1/destination-overflow.bin");

#[test]
fn accepted_fixture_decodes_and_evaluates() {
    let request = decode_request(ACCEPTED).expect("registered fixture must decode");
    assert_eq!(
        request,
        Request {
            from_balance: 100,
            to_balance: 25,
            amount: 30,
            cap: 40,
            authorized: true,
        }
    );
    let decision = decide_transfer(request);
    assert_eq!(decision.code, DecisionCode::Accepted);
    assert_eq!((decision.from_balance, decision.to_balance), (70, 55));
}

#[test]
fn denied_fixtures_have_stable_codes_and_unchanged_state() {
    let cases = [
        (UNAUTHORIZED, DecisionCode::DeniedUnauthorized),
        (ZERO_AMOUNT, DecisionCode::DeniedZeroAmount),
        (CAP_EXCEEDED, DecisionCode::DeniedCapExceeded),
        (INSUFFICIENT, DecisionCode::DeniedInsufficientFunds),
        (OVERFLOW, DecisionCode::DeniedDestinationOverflow),
    ];

    for (bytes, expected_code) in cases {
        let request = decode_request(bytes).expect("registered fixture must decode");
        let decision = decide_transfer(request);
        assert_eq!(decision.code, expected_code);
        assert_eq!(decision.from_balance, request.from_balance);
        assert_eq!(decision.to_balance, request.to_balance);
        assert_eq!(request.encode().as_slice(), bytes);
    }
}

#[test]
fn decoder_rejects_noncanonical_and_trailing_inputs() {
    let mut noncanonical_authorization = ACCEPTED.to_vec();
    noncanonical_authorization[5] = 2;
    assert!(decode_request(&noncanonical_authorization).is_err());

    let mut trailing = ACCEPTED.to_vec();
    trailing.push(0);
    assert!(decode_request(&trailing).is_err());
}
