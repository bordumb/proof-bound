use crate::{Decision, DecisionCode, Request};

#[must_use]
pub fn decide_transfer(request: Request) -> Decision {
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
