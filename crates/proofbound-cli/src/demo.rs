use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};
use proofbound_manifest::{DemoRunner, ProjectBundle};

use crate::{CheckOptions, check_project, load_compiled, render_claim};

pub fn run_demo(root: &Path, name: &str) -> Result<()> {
    let bundle = ProjectBundle::load(root)?;
    let (_, registry) = bundle
        .demos
        .as_ref()
        .context("PB-DEMO-0001: this project has no demo registry")?;
    let demo = registry
        .demos
        .iter()
        .find(|demo| demo.name == name)
        .with_context(|| format!("PB-DEMO-0002: unknown demo {name}"))?;
    println!("{} — {}", demo.name, demo.description);
    let status = match demo.runner {
        DemoRunner::AllowancePython => Command::new("python3")
            .args(["-m", "proofbound_demo.allowance"])
            .env("PYTHONPATH", "demo/allowance/python")
            .current_dir(root)
            .status()
            .context("PB-DEMO-0003: could not run allowance demo")?,
        DemoRunner::ArtifactRust => Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "artifact-certificate-checker",
                "--",
                "demo/artifact-certificate/fixtures/valid-basic.pbac",
            ])
            .current_dir(root)
            .status()
            .context("PB-DEMO-0004: could not run artifact demo")?,
    };
    if !status.success() {
        bail!("PB-DEMO-0005: demo runner exited with {status}");
    }
    // Reuse a current full-project compilation when the caller (notably xtask)
    // has just completed the one registered fresh check. A standalone demo
    // still compiles when no complete state exists. Never silently replace a
    // stale compiled snapshot: `load_compiled` must reject that drift first.
    let compiled_path = root.join(".proofbound/compiled/project.json");
    let compiled = if compiled_path.is_file() {
        let current = load_compiled(root)?;
        if current.inputs.len() == bundle.claims.len() {
            current
        } else {
            check_project(root, &CheckOptions::default())?
        }
    } else {
        check_project(root, &CheckOptions::default())?
    };
    for claim in &demo.claims {
        render_claim(&compiled, claim, false, false)?;
    }
    let blocked = demo.claims.iter().any(|claim| {
        compiled
            .statuses
            .iter()
            .find(|status| status.claim_id.as_str() == claim)
            .is_none_or(proofbound_core::ClaimStatus::is_build_failure)
    });
    if blocked {
        bail!("PB-DEMO-0006: one or more registered demo claims failed assurance policy");
    }
    Ok(())
}
