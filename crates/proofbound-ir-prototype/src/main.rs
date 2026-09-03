use std::{
    env,
    io::{Read as _, Write as _},
    path::PathBuf,
    process::ExitCode,
};

use proofbound_ir_prototype::{
    audit_artifact_roles, compile_dsl_frontend, compile_pkl_frontend, compile_toml_frontend,
    derive_release_trace_bundle, format_dsl_frontend, generate_derivation_corpus, project_corpus,
    project_portable_families, project_portable_families_with_sampling, validate_case_program,
    validate_derivation_program, validate_effective_programme_bytes,
    validate_frontend_compilation_bytes, validate_invalidation_execution_report,
    validate_layered_sampling_case, validate_pkl_frontend_source, validate_release_trace_bundle,
    validate_sampling_observation,
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
    if first.as_deref()
        == Some(std::ffi::OsStr::new(
            "project-portable-families-with-sampling",
        ))
    {
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype project-portable-families-with-sampling <repository-root> <capture-index.json> <sampling-extensions.json>"
            );
            return ExitCode::from(2);
        };
        let Some(index) = args.next().map(PathBuf::from) else {
            eprintln!("missing capture index");
            return ExitCode::from(2);
        };
        let Some(extensions) = args.next().map(PathBuf::from) else {
            eprintln!("missing sampling extension index");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        return match project_portable_families_with_sampling(&root, &index, &extensions).and_then(
            |projection| {
                proofbound_evidence::canonical_json(&projection).map_err(anyhow::Error::from)
            },
        ) {
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
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-derivation")) {
        let Some(program) = args.next().map(PathBuf::from) else {
            eprintln!("usage: proofbound-ir-prototype validate-derivation <program.json>");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let outcome = std::fs::read(program)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                validate_derivation_program(&bytes).map_err(|error| error.to_string())
            });
        return write_canonical_result(outcome);
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("derive-release-trace")) {
        let Some(receipt) = args.next().map(PathBuf::from) else {
            eprintln!("usage: proofbound-ir-prototype derive-release-trace <receipt.json>");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(receipt)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                derive_release_trace_bundle(&bytes).map_err(|error| error.to_string())
            });
        return write_canonical_result(result);
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("audit-artifact-roles")) {
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype audit-artifact-roles <repository-root> <project-root> <receipt.json>"
            );
            return ExitCode::from(2);
        };
        let Some(project_root) = args.next().map(PathBuf::from) else {
            eprintln!("missing project root");
            return ExitCode::from(2);
        };
        let Some(receipt) = args.next().map(PathBuf::from) else {
            eprintln!("missing receipt");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(receipt)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                audit_artifact_roles(&root, &project_root, &bytes)
                    .map_err(|error| error.to_string())
            });
        return write_canonical_result(result);
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-release-trace")) {
        let Some(receipt) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype validate-release-trace <receipt.json> <trace.json>"
            );
            return ExitCode::from(2);
        };
        let Some(trace) = args.next().map(PathBuf::from) else {
            eprintln!("missing trace bundle");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(receipt)
            .map_err(|error| error.to_string())
            .and_then(|receipt_bytes| {
                std::fs::read(trace)
                    .map_err(|error| error.to_string())
                    .and_then(|trace_bytes| {
                        validate_release_trace_bundle(&receipt_bytes, &trace_bytes)
                            .map_err(|error| error.to_string())
                    })
            });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-invalidation-execution")) {
        let Some(report) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype validate-invalidation-execution <report.json>"
            );
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(report)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                validate_invalidation_execution_report(&bytes)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("generate-derivations")) {
        let Some(templates) = args.next().map(PathBuf::from) else {
            eprintln!(
                "usage: proofbound-ir-prototype generate-derivations <templates.json> <count>"
            );
            return ExitCode::from(2);
        };
        let Some(count) = args
            .next()
            .and_then(|value| value.to_str().and_then(|text| text.parse::<usize>().ok()))
        else {
            eprintln!("missing or invalid generated-case count");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        return write_canonical_result(
            generate_derivation_corpus(&templates, count).map_err(|error| error.to_string()),
        );
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("compile-frontend")) {
        let Some(frontend) = args.next().and_then(|value| value.into_string().ok()) else {
            eprintln!("missing frontend");
            return ExitCode::from(2);
        };
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!("missing repository root");
            return ExitCode::from(2);
        };
        let Some(corpus) = args.next().map(PathBuf::from) else {
            eprintln!("missing frontend corpus");
            return ExitCode::from(2);
        };
        let Some(subject) = args.next().and_then(|value| value.into_string().ok()) else {
            eprintln!("missing subject ID");
            return ExitCode::from(2);
        };
        let result = match frontend.as_str() {
            "toml" => {
                if args.next().is_some() {
                    eprintln!("unexpected extra argument");
                    return ExitCode::from(2);
                }
                compile_toml_frontend(&root, &corpus, &subject)
            }
            "proofbound-dsl" => {
                if args.next().is_some() {
                    eprintln!("unexpected extra argument");
                    return ExitCode::from(2);
                }
                compile_dsl_frontend(&root, &corpus, &subject)
            }
            "pkl" => {
                let Some(rendered) = args.next().map(PathBuf::from) else {
                    eprintln!("missing rendered Pkl JSON");
                    return ExitCode::from(2);
                };
                let Some(executable) = args.next().map(PathBuf::from) else {
                    eprintln!("missing Pkl executable");
                    return ExitCode::from(2);
                };
                if args.next().is_some() {
                    eprintln!("unexpected extra argument");
                    return ExitCode::from(2);
                }
                std::fs::read(rendered)
                    .map_err(|error| proofbound_ir_prototype::FrontendError {
                        code: "FRONTEND-DEPENDENCY-DRIFT",
                        message: error.to_string(),
                        path: None,
                        start: None,
                        end: None,
                    })
                    .and_then(|bytes| {
                        compile_pkl_frontend(&root, &corpus, &subject, &bytes, &executable)
                    })
            }
            _ => {
                eprintln!("unknown frontend");
                return ExitCode::from(2);
            }
        };
        return write_canonical_result(result.map_err(|error| error.to_string()));
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-frontend")) {
        let Some(root) = args.next().map(PathBuf::from) else {
            eprintln!("missing repository root");
            return ExitCode::from(2);
        };
        let Some(compilation) = args.next().map(PathBuf::from) else {
            eprintln!("missing frontend compilation");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(compilation)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                validate_frontend_compilation_bytes(&root, &bytes)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("validate-effective-frontend")) {
        let Some(effective) = args.next().map(PathBuf::from) else {
            eprintln!("missing effective programme");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(effective)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                validate_effective_programme_bytes(&bytes)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("format-frontend-dsl")) {
        let Some(source) = args.next().map(PathBuf::from) else {
            eprintln!("missing DSL source");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(&source)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                format_dsl_frontend(&bytes, &source).map_err(|error| error.to_string())
            });
        return match result {
            Ok(bytes) => match std::io::stdout().lock().write_all(&bytes) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("failed to write formatted DSL: {error}");
                    ExitCode::from(1)
                }
            },
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(1)
            }
        };
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("preflight-frontend-pkl")) {
        let Some(source) = args.next().map(PathBuf::from) else {
            eprintln!("missing Pkl source");
            return ExitCode::from(2);
        };
        if args.next().is_some() {
            eprintln!("unexpected extra argument");
            return ExitCode::from(2);
        }
        let result = std::fs::read(&source)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                validate_pkl_frontend_source(&bytes, &source).map_err(|error| error.to_string())
            });
        return match result {
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

fn write_canonical_result<T: serde::Serialize>(result: Result<T, String>) -> ExitCode {
    match result.and_then(|value| {
        proofbound_evidence::canonical_json(&value).map_err(|error| error.to_string())
    }) {
        Ok(bytes) => match std::io::stdout().lock().write_all(&bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("failed to write result: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
