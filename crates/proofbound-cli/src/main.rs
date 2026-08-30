use std::{env, path::PathBuf, process::ExitCode};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use proofbound_cli::{
    CheckOptions, check_project, diff_revisions, doctor, find_project_root, init_project,
    load_compiled, release_project, release_smoke, render_assumptions, render_claim,
    render_explanation, render_graph, render_status, run_demo, update_unit,
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "proofbound",
    version,
    about = "Executable assurance boundaries for software claims"
)]
struct Arguments {
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Check {
        #[arg(long)]
        claim: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        fresh: bool,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Claim {
        id: String,
        #[arg(long)]
        graph: bool,
        #[arg(long)]
        json: bool,
    },
    Explain {
        id: String,
    },
    Reproduce {
        unit: String,
    },
    Assumptions {
        #[arg(long)]
        claim: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Graph {
        #[arg(long, value_enum, default_value_t = GraphFormat::Dot)]
        format: GraphFormat,
    },
    Diff {
        range: String,
        #[arg(long)]
        json: bool,
    },
    Update {
        unit: String,
    },
    Demo {
        name: String,
    },
    Release {
        #[arg(long, value_name = "DIR")]
        output: Option<PathBuf>,
    },
    #[command(hide = true)]
    ReleaseSmoke {
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GraphFormat {
    Dot,
    Json,
    Html,
}

impl GraphFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Dot => "dot",
            Self::Json => "json",
            Self::Html => "html",
        }
    }
}

fn main() -> ExitCode {
    let json_errors = env::args_os().any(|argument| argument == "--json");
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let failure = CliFailure::from_error(&format!("{error:#}"));
            if json_errors {
                eprintln!(
                    "{}",
                    serde_json::to_string(&failure)
                        .unwrap_or_else(|_| "{\"schema\":\"proofbound-error/1\",\"code\":\"PB-CLI-0001\",\"message\":\"could not serialize error\",\"claim_id\":null,\"unit_id\":null,\"file\":null,\"logical_path\":null,\"byte_offset\":null,\"expected_identity\":null,\"actual_identity\":null,\"affected_claims\":[],\"remediation\":\"Inspect the command inputs and retry.\"}".to_owned())
                );
            } else {
                eprintln!("{}: {}", failure.code, failure.message);
                eprintln!("remediation: {}", failure.remediation);
            }
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Serialize)]
struct CliFailure {
    schema: &'static str,
    code: String,
    message: String,
    claim_id: Option<String>,
    unit_id: Option<String>,
    file: Option<String>,
    logical_path: Option<String>,
    byte_offset: Option<u64>,
    expected_identity: Option<String>,
    actual_identity: Option<String>,
    affected_claims: Vec<String>,
    remediation: String,
}

impl CliFailure {
    fn from_error(error: &str) -> Self {
        let code = error
            .split(|character: char| character.is_whitespace() || character == ':')
            .find(|token| valid_error_code(token))
            .unwrap_or("PB-CLI-0001")
            .to_owned();
        let message = error
            .strip_prefix(&format!("{code}:"))
            .map(str::trim)
            .unwrap_or(error)
            .to_owned();
        let remediation = match code.split('-').nth(1) {
            Some("MANIFEST") => "Correct the referenced manifest or schema violation and retry.",
            Some("ADAPTER") | Some("LEAN") => {
                "Inspect the registered unit and adapter diagnostics; do not accept partial evidence."
            }
            Some("RECEIPT") | Some("CACHE") => {
                "Run proofbound check --fresh to reconstruct independently validated state."
            }
            Some("RELEASE") => {
                "Use a clean reviewed tree, run a full fresh check, then create the release again."
            }
            Some("CHECK") => {
                "Restore unexpected reviewed-tree changes and rerun the verify-only check."
            }
            Some("UPDATE") => {
                "Inspect the rejected output diff, restore unrelated changes, and retry explicitly."
            }
            _ => "Inspect the command inputs and reported cause, correct it, and retry.",
        }
        .to_owned();
        Self {
            schema: "proofbound-error/1",
            code,
            message,
            claim_id: None,
            unit_id: None,
            file: None,
            logical_path: None,
            byte_offset: None,
            expected_identity: None,
            actual_identity: None,
            affected_claims: Vec::new(),
            remediation,
        }
    }
}

fn valid_error_code(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("PB-") else {
        return false;
    };
    let Some((family, number)) = rest.rsplit_once('-') else {
        return false;
    };
    !family.is_empty()
        && family
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        && number.len() == 4
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn run() -> Result<u8> {
    let arguments = Arguments::parse();
    let start = arguments.root.unwrap_or(env::current_dir()?);
    if matches!(arguments.command, Command::Init) {
        init_project(&start)?;
        println!(
            "Initialized a Tier-0 ledger at {}. Edit PROJECT-CLAIM-001; no proof assistant is required.",
            start.display()
        );
        return Ok(0);
    }
    let root = find_project_root(&start)?;
    match arguments.command {
        Command::Init => unreachable!(),
        Command::Doctor { json } => doctor(&root, json)?,
        Command::Check {
            claim,
            profile,
            fresh,
            json,
        } => {
            let compiled = check_project(
                &root,
                &CheckOptions {
                    claim,
                    profile,
                    fresh,
                    reproduce_unit: None,
                },
            )?;
            render_status(&compiled, json)?;
            return Ok(status_exit(&compiled));
        }
        Command::Status { json } => {
            let compiled = load_compiled(&root)?;
            render_status(&compiled, json)?;
            return Ok(status_exit(&compiled));
        }
        Command::Claim { id, graph, json } => {
            let compiled = load_compiled(&root)?;
            render_claim(&compiled, &id, graph, json)?;
            let blocked = compiled
                .statuses
                .iter()
                .find(|status| status.claim_id.as_str() == id)
                .is_some_and(proofbound_core::ClaimStatus::is_build_failure);
            return Ok(if blocked { 3 } else { 0 });
        }
        Command::Explain { id } => {
            render_explanation(&load_compiled(&root)?, &id)?;
        }
        Command::Reproduce { unit } => {
            let compiled = check_project(
                &root,
                &CheckOptions {
                    reproduce_unit: Some(unit.clone()),
                    ..CheckOptions::default()
                },
            )?;
            render_status(&compiled, false)?;
            let reproduced = compiled
                .unit_runs
                .iter()
                .any(|run| run.unit_id == unit && matches!(run.outcome.as_str(), "verified-now"));
            return Ok(if reproduced { 0 } else { 3 });
        }
        Command::Assumptions { claim, json } => {
            render_assumptions(&load_compiled(&root)?, claim.as_deref(), json)?;
        }
        Command::Graph { format } => {
            render_graph(&load_compiled(&root)?, format.as_str())?;
        }
        Command::Diff { range, json } => diff_revisions(&root, &range, json)?,
        Command::Update { unit } => update_unit(&root, &unit)?,
        Command::Demo { name } => run_demo(&root, &name)?,
        Command::Release { output } => {
            let destination = release_project(&root, output.as_deref())?;
            println!("Portable release written to {}", destination.display());
            println!(
                "Verify it independently with: proofbound-verify --release {}",
                destination.display()
            );
        }
        Command::ReleaseSmoke { output } => {
            let destination = release_smoke(&output)?;
            println!(
                "Deterministic release smoke fixture written to {}",
                destination.display()
            );
        }
    }
    Ok(0)
}

fn status_exit(compiled: &proofbound_cli::CompiledProject) -> u8 {
    if compiled
        .statuses
        .iter()
        .any(proofbound_core::ClaimStatus::is_build_failure)
    {
        3
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_failure_preserves_stable_code_and_remediation() {
        let failure = CliFailure::from_error(
            "PB-RECEIPT-0001: no compiled result exists; run proofbound check first",
        );
        assert_eq!(failure.code, "PB-RECEIPT-0001");
        assert_eq!(
            failure.message,
            "no compiled result exists; run proofbound check first"
        );
        assert!(failure.remediation.contains("check --fresh"));
        assert_eq!(
            serde_json::to_value(&failure).unwrap()["schema"],
            "proofbound-error/1"
        );
    }

    #[test]
    fn unstructured_failure_gets_cli_code() {
        let failure = CliFailure::from_error("unexpected host failure");
        assert_eq!(failure.code, "PB-CLI-0001");
        assert_eq!(failure.message, "unexpected host failure");
    }
}
