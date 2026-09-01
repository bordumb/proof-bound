use crate::{Decision, DecisionCode, Request};

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

    Decision {
        code: DecisionCode::Accepted,
        from_balance,
        to_balance: request.to_balance.wrapping_add(request.amount),
    }
}
