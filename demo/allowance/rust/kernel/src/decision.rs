use crate::{Decision, DecisionCode, Request};

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
