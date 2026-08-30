use std::process::ExitCode;

use artifact_certificate_checker::{PathCheckError, check_path};

fn escaped(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control <= '\u{001f}' => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", u32::from(control)).expect("write to String");
            }
            ordinary => output.push(ordinary),
        }
    }
    output
}

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(path) = arguments.next() else {
        eprintln!("usage: artifact-certificate-check FILE.pbac");
        return ExitCode::from(64);
    };
    if arguments.next().is_some() {
        eprintln!("usage: artifact-certificate-check FILE.pbac");
        return ExitCode::from(64);
    }

    match check_path(&path) {
        Ok(certificate) => {
            println!(
                "{{\"schema\":\"pbac-check-result/1\",\"accepted\":true,\"target\":{},\"entries\":{}}}",
                certificate.target,
                certificate.entries.len()
            );
            ExitCode::SUCCESS
        }
        Err(PathCheckError::Rejected(error)) => {
            println!(
                "{{\"schema\":\"pbac-check-result/1\",\"accepted\":false,\"code\":\"{}\",\"offset\":{}}}",
                error.code.as_str(),
                error.offset
            );
            ExitCode::from(2)
        }
        Err(PathCheckError::Io(error)) => {
            println!(
                "{{\"schema\":\"pbac-check-result/1\",\"accepted\":false,\"code\":\"PBAC_E_IO\",\"message\":\"{}\"}}",
                escaped(&error.to_string())
            );
            ExitCode::from(3)
        }
    }
}
