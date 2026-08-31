use allowance_kernel::{DecisionCode, Request, decide_transfer};

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
fn authorization_guard_is_enforced() {
    let request = Request {
        authorized: false,
        ..accepted_request()
    };
    assert_eq!(
        decide_transfer(request).code,
        DecisionCode::DeniedUnauthorized
    );
}

#[test]
fn positive_amount_guard_is_enforced() {
    let request = Request {
        amount: 0,
        ..accepted_request()
    };
    assert_eq!(
        decide_transfer(request).code,
        DecisionCode::DeniedZeroAmount
    );
}

#[test]
fn cap_guard_is_enforced() {
    let request = Request {
        amount: 41,
        cap: 40,
        ..accepted_request()
    };
    assert_eq!(
        decide_transfer(request).code,
        DecisionCode::DeniedCapExceeded
    );
}

#[test]
fn source_balance_guard_is_enforced() {
    let request = Request {
        from_balance: 20,
        ..accepted_request()
    };
    assert_eq!(
        decide_transfer(request).code,
        DecisionCode::DeniedInsufficientFunds
    );
}

#[test]
fn destination_overflow_guard_is_enforced() {
    let request = Request {
        to_balance: u64::MAX - 10,
        amount: 20,
        ..accepted_request()
    };
    assert_eq!(
        decide_transfer(request).code,
        DecisionCode::DeniedDestinationOverflow
    );
}
