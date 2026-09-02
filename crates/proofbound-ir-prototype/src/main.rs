use std::{
    env,
    io::{Read as _, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use proofbound_ir_prototype::{
    project_corpus, project_portable_families, validate_case_program,
    validate_layered_sampling_case, validate_sampling_observation,
};

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
    if first.as_deref() == Some(std::ffi::OsStr::new("project-portable-families")) {
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype project-portable-families <repository-root> <capture-index.json>"
            );
            return ExitCode::from(2);
        };
        let Some(index) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype project-portable-families <repository-root> <capture-index.json>"
            );
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        return match project_portable_families(&root, &index).and_then(|projection| {
            proofbound_evidence::canonical_json(&projection).map_err(anyhow::Error::from)
        }) {
            Ok(bytes) => match std::io::stdout().lock().write_all(&bytes) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("failed to write projection: {error}");
                    ExitCode::from(1)
                }
            },
            Err(error) => {
                eprintln!("projection failed: {error:#}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-sampling")) {
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype validate-sampling <repository-root> <contract.json> <observation.json>"
            );
            return ExitCode::from(2);
        };
        let Some(contract) = args.next().map(PathBuf::from) else {
            eprintln!("missing sampling contract");
            return ExitCode::from(2);
        };
        let Some(observation) = args.next().map(PathBuf::from) else {
            eprintln!("missing sampling observation");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let outcome = std::fs::read(&contract)
            .map_err(|error| error.to_string())
            .and_then(|contract_bytes| {
                std::fs::read(&observation)
                    .map_err(|error| error.to_string())
                    .and_then(|observation_bytes| {
                        validate_sampling_observation(&root, &contract_bytes, &observation_bytes)
                            .map_err(|error| error.to_string())
                    })
            });
        return match outcome.and_then(|report| {
            proofbound_evidence::canonical_json(&report).map_err(|error| error.to_string())
        }) {
            Ok(bytes) => match std::io::stdout().lock().write_all(&bytes) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("failed to write validation: {error}");
                    ExitCode::from(1)
                }
            },
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-layered-sampling")) {
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype validate-layered-sampling <repository-root> <case.json>"
            );
            return ExitCode::from(2);
        };
        let Some(case) = args.next().map(PathBuf::from) else {
            eprintln!("missing layered sampling case");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let outcome = std::fs::read(&case)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                validate_layered_sampling_case(&root, &bytes).map_err(|error| error.to_string())
            });
        return match outcome.and_then(|report| {
            proofbound_evidence::canonical_json(&report).map_err(|error| error.to_string())
        }) {
            Ok(bytes) => match std::io::stdout().lock().write_all(&bytes) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("failed to write validation: {error}");
                    ExitCode::from(1)
                }
            },
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
