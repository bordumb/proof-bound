use std::process::Command;

fn main() {
    let status = Command::new("./mode_gate.sh")
        .status()
        .expect("mode gate must execute");
    assert!(status.success(), "mode gate must pass");
}
