use allowance_kernel::{DecisionCode, Request, decide_transfer};
use proptest::{arbitrary::any, strategy::Strategy};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct RequestSample {
    from_balance: u8,
    to_balance: u8,
    amount: u8,
    cap: u8,
    authorized: bool,
}

impl RequestSample {
    fn request(&self) -> Request {
        Request {
            from_balance: u64::from(self.from_balance),
            to_balance: u64::from(self.to_balance),
            amount: u64::from(self.amount),
            cap: u64::from(self.cap),
            authorized: self.authorized,
        }
    }
}

pub fn strategy() -> impl Strategy<Value = RequestSample> {
    any::<(u8, u8, u8, u8, bool)>().prop_map(
        |(from_balance, to_balance, amount, cap, authorized)| RequestSample {
            from_balance,
            to_balance,
            amount,
            cap,
            authorized,
        },
    )
}

pub fn accepted_transfer_respects_cap(sample: &RequestSample) -> bool {
    let decision = decide_transfer(sample.request());
    decision.code != DecisionCode::Accepted || u64::from(sample.amount) <= sample.request().cap
}

pub fn deliberately_false(_sample: &RequestSample) -> bool {
    false
}
