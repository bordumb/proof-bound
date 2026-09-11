//! Standalone, tool-free Proofbound release verifier.

use std::{fs, path::PathBuf, process::ExitCode};

use clap::Parser;
use proofbound_verify::{
    AssumptionFacet, ExternalObservationInput, ExternalObservationInputs, FormalFacet,
    LinkageFacet, OBSERVATION_INPUTS_SCHEMA_V1, verify_release_dir,
    verify_release_dir_with_observations,
};

#[derive(Debug, Parser)]
#[command(name = "proofbound-verify", version, about)]
struct Arguments {
    /// Directory containing canonical release.json and its compiled payload.
    #[arg(long, value_name = "DIR")]
    release: PathBuf,

    /// JSON manifest supplying bytes for exact observations not sealed in the release.
    #[arg(long, value_name = "FILE")]
    observation_inputs: Option<PathBuf>,

    /// Emit the complete machine-readable verification report.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let inputs = match arguments.observation_inputs.as_deref() {
        Some(path) => match load_observation_inputs(path) {
            Ok(inputs) => Some(inputs),
            Err(error) => {
                eprintln!("proofbound-verify: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let result = inputs.as_deref().map_or_else(
        || verify_release_dir(&arguments.release),
        |inputs| verify_release_dir_with_observations(&arguments.release, inputs),
    );
    match result {
        Ok(report) => {
            if arguments.json {
                match serde_json::to_string(&report) {
                    Ok(encoded) => println!("{encoded}"),
                    Err(error) => {
                        eprintln!("proofbound-verify: cannot encode report: {error}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                println!(
                    "{}: {}@{} ({} claim(s))",
                    report.verdict,
                    report.project,
                    report.project_revision,
                    report.claims.len()
                );
                println!("{}", report.trust_boundary);
                for claim in &report.claims {
                    println!(
                        "claim {}: {} · {} · {}",
                        claim.claim_id,
                        formal_name(claim.formal),
                        linkage_name(claim.linkage),
                        assumption_name(claim.assumption)
                    );
                    println!("  {}", claim.public_statement);
                    let gaps = report
                        .not_proved_out_of_scope
                        .iter()
                        .find(|item| item.claim_id == claim.claim_id)
                        .expect("verified report has one mandatory gap section per claim");
                    println!("not proved / out of scope [{}]", claim.claim_id);
                    println!("  open obligations: {:?}", gaps.open_obligations);
                    println!("  undischarged premises: {:?}", gaps.undischarged_premises);
                    println!("  explicit assumptions: {:?}", gaps.assumptions);
                    println!("  registered exclusions: {:?}", gaps.out_of_scope);
                }
                if report.publication_blocked {
                    println!("publication policy: BLOCKED");
                } else {
                    println!("publication policy: ADMITTED");
                }
            }
            if report.publication_blocked {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(errors) => {
            if arguments.json {
                match serde_json::to_string(&errors) {
                    Ok(encoded) => eprintln!("{encoded}"),
                    Err(error) => eprintln!("proofbound-verify: cannot encode errors: {error}"),
                }
            } else {
                for issue in errors.issues {
                    let location = issue
                        .claim_id
                        .or(issue.path)
                        .map_or_else(String::new, |value| format!(" [{value}]"));
                    eprintln!("{}{}: {}", issue.code, location, issue.message);
                }
            }
            ExitCode::from(2)
        }
    }
}

fn load_observation_inputs(
    path: &std::path::Path,
) -> Result<Vec<ExternalObservationInput>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot stat observation input manifest: {error}"))?;
    if metadata.len() > 1 << 20 {
        return Err("observation input manifest exceeds 1 MiB".into());
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read observation input manifest: {error}"))?;
    let mut manifest: ExternalObservationInputs = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse observation input manifest: {error}"))?;
    if manifest.schema != OBSERVATION_INPUTS_SCHEMA_V1 {
        return Err(format!(
            "unsupported observation input manifest schema '{}'",
            manifest.schema
        ));
    }
    if manifest.observations.len() > 100_000 {
        return Err("observation input manifest contains too many entries".into());
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    for input in &mut manifest.observations {
        if input.artifact_path.is_relative() {
            input.artifact_path = parent.join(&input.artifact_path);
        }
        if input.procedure_path.is_relative() {
            input.procedure_path = parent.join(&input.procedure_path);
        }
    }
    Ok(manifest.observations)
}

const fn formal_name(value: FormalFacet) -> &'static str {
    match value {
        FormalFacet::Proved => "PROVED",
        FormalFacet::BoundedChecked => "BOUNDED_CHECKED",
        FormalFacet::Tested => "TESTED",
        FormalFacet::Open => "OPEN",
        FormalFacet::Invalid => "INVALID",
    }
}

const fn linkage_name(value: Option<LinkageFacet>) -> &'static str {
    match value {
        Some(LinkageFacet::Refined) => "REFINED",
        Some(LinkageFacet::ArtifactBound) => "ARTIFACT_BOUND",
        Some(LinkageFacet::Transcribed) => "TRANSCRIBED",
        Some(LinkageFacet::ModelOnly) => "MODEL_ONLY",
        None => "N/A",
    }
}

const fn assumption_name(value: AssumptionFacet) -> &'static str {
    match value {
        AssumptionFacet::None => "NONE",
        AssumptionFacet::Assumed => "ASSUMED",
    }
}
