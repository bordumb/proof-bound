#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Accepted { remaining: u64 },
    Denied,
}

/// Pure source subject: no I/O, allocation, unsafe code, or ambient state.
#[must_use]
pub fn withdraw(balance: u64, amount: u64) -> Decision {
    if amount == 0 || amount > balance {
        Decision::Denied
    } else {
        Decision::Accepted {
            remaining: balance - amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_positive_affordable_amounts() {
        assert_eq!(withdraw(10, 4), Decision::Accepted { remaining: 6 });
        assert_eq!(withdraw(10, 0), Decision::Denied);
        assert_eq!(withdraw(10, 11), Decision::Denied);
    }
}
