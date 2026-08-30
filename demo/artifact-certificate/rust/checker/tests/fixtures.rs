use std::fs;
use std::path::{Path, PathBuf};

use artifact_certificate_checker::{ErrorCode, check};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn committed_valid_fixtures_are_accepted() {
    for name in ["valid-basic.pbac", "valid-boundary.pbac"] {
        let bytes = fs::read(fixture_dir().join(name)).expect("read fixture");
        check(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn committed_mutations_have_stable_codes() {
    let cases = [
        ("invalid-bad-version.pbac", ErrorCode::UnsupportedVersion),
        ("invalid-count-zero.pbac", ErrorCode::CountRange),
        ("invalid-duplicate-id.pbac", ErrorCode::IdOrder),
        (
            "invalid-noncanonical-target.pbac",
            ErrorCode::NoncanonicalVarint,
        ),
        ("invalid-overflow-target.pbac", ErrorCode::VarintOverflow),
        ("invalid-oversized.pbac", ErrorCode::TooLarge),
        ("invalid-sum.pbac", ErrorCode::SumMismatch),
        ("invalid-trailing.pbac", ErrorCode::TrailingBytes),
        ("invalid-truncated.pbac", ErrorCode::Truncated),
    ];

    for (name, expected) in cases {
        let bytes = fs::read(fixture_dir().join(name)).expect("read fixture");
        let actual = check(&bytes).expect_err(name).code;
        assert_eq!(actual, expected, "{name}");
    }
}
