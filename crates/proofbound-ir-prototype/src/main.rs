use std::{
    env,
    io::{Read as _, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use proofbound_ir_prototype::{project_corpus, validate_case_program};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let first = args.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("validate")) {
        if args.next().is_some() {
            eprintln!("usage: proofbound-ir-prototype validate");
            return ExitCode::from(2);
        }
        let mut bytes = Vec::new();
        if let Err(error) = std::io::stdin().lock().read_to_end(&mut bytes) {
            eprintln!("IR-DECODE-INVALID: failed to read case: {error}");
            return ExitCode::from(2);
        }
        return match validate_case_program(&bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    let Some(root) = first.map(PathBuf::from) else {
        eprintln!("usage: proofbound-ir-prototype <repository-root> <corpus.json>");
        return ExitCode::from(2);
    };
    let Some(corpus) = args.next().map(PathBuf::from) else {
        eprintln!("usage: proofbound-ir-prototype <repository-root> <corpus.json>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("unexpected extra argument");
        return ExitCode::from(2);
    }

    match project_corpus(&root, &corpus).and_then(|projection| {
        proofbound_evidence::canonical_json(&projection).map_err(anyhow::Error::from)
    }) {
        Ok(bytes) => {
            if let Err(error) = std::io::stdout().lock().write_all(&bytes) {
                eprintln!("failed to write projection: {error}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("projection failed: {error:#}");
            ExitCode::from(1)
        }
    }
}
