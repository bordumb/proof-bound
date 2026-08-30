fn main() {
    if let Err(error) = proofbound_adapter_lean::run_stdio() {
        eprintln!("proofbound Lean adapter I/O failure: {error}");
        std::process::exit(2);
    }
}
