use std::{env, io::Write as _, path::PathBuf, process::ExitCode};

use proofbound_ir_prototype::project_corpus;

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(root) = args.next().map(PathBuf::from) else {
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
