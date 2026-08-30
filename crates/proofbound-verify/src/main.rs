//! Standalone, tool-free Proofbound release verifier.

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use proofbound_verify::{AssumptionFacet, FormalFacet, LinkageFacet, verify_release_dir};

#[derive(Debug, Parser)]
#[command(name = "proofbound-verify", version, about)]
struct Arguments {
    /// Directory containing canonical release.json and its compiled payload.
    #[arg(long, value_name = "DIR")]
    release: PathBuf,

    /// Emit the complete machine-readable verification report.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match verify_release_dir(&arguments.release) {
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
                    "receipt-consistent: {}@{} ({} claim(s))",
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
