use artifact_certificate_checker::{MAX_BYTES, check};

const VALID: &[u8] = &[
    0x50, 0x42, 0x41, 0x43, 0x01, 0x00, 0x03, 0xfd, 0x07, 0x01, 0x03, 0x04, 0x80, 0x01, 0x09, 0xfa,
    0x06,
];

#[test]
fn deterministic_mutation_corpus_never_panics_or_accepts_false_meaning() {
    for length in 0..=VALID.len() {
        let _ = check(&VALID[..length]);
    }

    for offset in 0..VALID.len() {
        for replacement in 0_u8..=u8::MAX {
            let mut bytes = VALID.to_vec();
            bytes[offset] = replacement;
            if let Ok(certificate) = check(&bytes) {
                assert_eq!(certificate.total(), u64::from(certificate.target));
            }
        }
    }

    for suffix in 0_u8..=u8::MAX {
        let mut bytes = VALID.to_vec();
        bytes.push(suffix);
        assert!(check(&bytes).is_err());
    }

    let mut state = 0x9e37_79b9_u32;
    for length in 0..=(MAX_BYTES + 8) {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes.push(state as u8);
        }
        if let Ok(certificate) = check(&bytes) {
            assert_eq!(certificate.total(), u64::from(certificate.target));
        }
    }
}
