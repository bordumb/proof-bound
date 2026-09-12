use artifact_certificate_checker::{ErrorCode, check};

#[test]
fn committed_valid_fixtures_are_accepted() {
    for (name, bytes) in [
        (
            "valid-basic.pbac",
            include_bytes!("../../../fixtures/valid-basic.pbac").as_slice(),
        ),
        (
            "valid-boundary.pbac",
            include_bytes!("../../../fixtures/valid-boundary.pbac").as_slice(),
        ),
    ] {
        check(bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn committed_mutations_have_stable_codes() {
    let cases = [
        (
            "invalid-bad-version.pbac",
            include_bytes!("../../../fixtures/invalid-bad-version.pbac").as_slice(),
            ErrorCode::UnsupportedVersion,
        ),
        (
            "invalid-count-zero.pbac",
            include_bytes!("../../../fixtures/invalid-count-zero.pbac").as_slice(),
            ErrorCode::CountRange,
        ),
        (
            "invalid-duplicate-id.pbac",
            include_bytes!("../../../fixtures/invalid-duplicate-id.pbac").as_slice(),
            ErrorCode::IdOrder,
        ),
        (
            "invalid-noncanonical-target.pbac",
            include_bytes!("../../../fixtures/invalid-noncanonical-target.pbac").as_slice(),
            ErrorCode::NoncanonicalVarint,
        ),
        (
            "invalid-overflow-target.pbac",
            include_bytes!("../../../fixtures/invalid-overflow-target.pbac").as_slice(),
            ErrorCode::VarintOverflow,
        ),
        (
            "invalid-oversized.pbac",
            include_bytes!("../../../fixtures/invalid-oversized.pbac").as_slice(),
            ErrorCode::TooLarge,
        ),
        (
            "invalid-sum.pbac",
            include_bytes!("../../../fixtures/invalid-sum.pbac").as_slice(),
            ErrorCode::SumMismatch,
        ),
        (
            "invalid-trailing.pbac",
            include_bytes!("../../../fixtures/invalid-trailing.pbac").as_slice(),
            ErrorCode::TrailingBytes,
        ),
        (
            "invalid-truncated.pbac",
            include_bytes!("../../../fixtures/invalid-truncated.pbac").as_slice(),
            ErrorCode::Truncated,
        ),
    ];

    for (name, bytes, expected) in cases {
        let actual = check(bytes).expect_err(name).code;
        assert_eq!(actual, expected, "{name}");
    }
}
