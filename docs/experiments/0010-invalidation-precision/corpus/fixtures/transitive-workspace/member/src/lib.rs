#[path = "../../shared.rs"]
mod shared;

pub fn registered_value() -> u8 {
    shared::value()
}

#[cfg(test)]
mod tests {
    #[test]
    fn consumes_the_workspace_level_source() {
        assert_eq!(super::registered_value(), 11);
    }
}
