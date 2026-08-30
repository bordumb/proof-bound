use std::io::{self, Read as _, Write as _};

fn main() {
    let mut input = Vec::new();
    if io::stdin()
        .take(proofbound_adapter_aeneas::MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)
        .is_err()
    {
        input.clear();
    }
    let response = proofbound_adapter_aeneas::handle_request_bytes(&input);
    match proofbound_evidence::canonical_json(&response) {
        Ok(bytes) => {
            let _ = io::stdout().write_all(&bytes);
        }
        Err(error) => {
            let _ = write!(io::stderr(), "failed to encode adapter response: {error}");
            std::process::exit(2);
        }
    }
}
