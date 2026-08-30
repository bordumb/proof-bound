use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use proofbound_core::ClaimStatus;
use serde::Serialize;

use crate::CompiledProject;

#[derive(Serialize)]
struct StatusProjection<'a> {
    schema: &'static str,
    project: &'a str,
    project_revision: &'a str,
    claims: &'a [ClaimStatus],
    publication_blocked: bool,
    not_proved_out_of_scope: AggregateGaps,
}

#[derive(Default, Serialize)]
struct AggregateGaps {
    open_obligations: BTreeSet<String>,
    undischarged_premises: BTreeSet<String>,
    assumptions: BTreeSet<String>,
    exclusions: BTreeSet<String>,
}

pub fn render_status(compiled: &CompiledProject, json: bool) -> Result<()> {
    let gaps = aggregate_gaps(&compiled.statuses);
    let blocked = compiled
        .statuses
        .iter()
        .any(proofbound_core::ClaimStatus::is_build_failure);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&StatusProjection {
                schema: "proofbound-report/1",
                project: &compiled.project,
                project_revision: &compiled.project_revision,
                claims: &compiled.statuses,
                publication_blocked: blocked,
                not_proved_out_of_scope: gaps,
            })?
        );
        return Ok(());
    }
    println!(
        "{} @ {} ({})",
        compiled.project, compiled.project_revision, compiled.tree_state
    );
    for status in &compiled.statuses {
        println!(
            "{:28} {:17} {:16} {:8} {}",
            status.claim_id,
            enum_text(&status.formal)?,
            status
                .linkage
                .as_ref()
                .map(enum_text)
                .transpose()?
                .unwrap_or_else(|| "-".into()),
            if status.policy.admitted {
                "ADMITTED"
            } else {
                "BLOCKED"
            },
            freshness(compiled, status)
        );
    }
    println!(
        "publication: {}",
        if blocked { "BLOCKED" } else { "ADMITTED" }
    );
    render_aggregate_gaps(&gaps);
    Ok(())
}

pub fn render_claim(
    compiled: &CompiledProject,
    id: &str,
    include_graph: bool,
    json: bool,
) -> Result<()> {
    let status = compiled
        .statuses
        .iter()
        .find(|status| status.claim_id.as_str() == id)
        .with_context(|| format!("PB-CLAIM-0003: no compiled claim {id}"))?;
    let input = compiled
        .inputs
        .iter()
        .find(|input| input.claim.id.as_str() == id)
        .context("PB-CLAIM-0004: claim has no derivation input")?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": "proofbound-claim-report/1",
                "status": status,
                "input": input,
                "graph": include_graph.then_some(&input.graph),
                "not_proved_out_of_scope": status.not_proved_out_of_scope,
            }))?
        );
        return Ok(());
    }
    println!("{} — {}", status.claim_id, input.claim.title);
    println!("{}", status.public_statement);
    println!(
        "formal={} linkage={} assumptions={} policy={} freshness={}",
        enum_text(&status.formal)?,
        status
            .linkage
            .as_ref()
            .map(enum_text)
            .transpose()?
            .unwrap_or_else(|| "-".into()),
        enum_text(&status.assumption.standing)?,
        if status.policy.admitted {
            "ADMITTED"
        } else {
            "BLOCKED"
        },
        freshness(compiled, status),
    );
    println!("evidence");
    for evidence in &status.evidence {
        println!(
            "  {} ({}, {}, {})",
            evidence.id,
            enum_text(&evidence.kind)?,
            enum_text(&evidence.status)?,
            if evidence.policy_admitted {
                "policy-admitted"
            } else {
                "not policy-admitted"
            }
        );
        for reason in &evidence.reasons {
            println!("    - {reason}");
        }
    }
    if include_graph {
        println!("graph");
        for edge in &input.graph.edges {
            println!(
                "  {} --{}--> {}",
                edge.from(),
                enum_text(&edge.kind())?,
                edge.to()
            );
        }
    }
    render_claim_gaps(status);
    Ok(())
}

pub fn render_explanation(compiled: &CompiledProject, id: &str) -> Result<()> {
    let status = compiled
        .statuses
        .iter()
        .find(|status| status.claim_id.as_str() == id)
        .with_context(|| format!("PB-CLAIM-0003: no compiled claim {id}"))?;
    println!(
        "{} is {} with {} linkage.",
        id,
        enum_text(&status.formal)?,
        status
            .linkage
            .as_ref()
            .map(enum_text)
            .transpose()?
            .unwrap_or_else(|| "no valid".into())
    );
    if status.errors.is_empty() && status.policy.admitted {
        println!("Its registered evidence and policy are internally consistent.");
    } else {
        for error in &status.errors {
            println!("{}: {}", enum_text(&error.code)?, error.message);
            println!("  remediation: {}", error.remediation);
        }
        for blocker in &status.policy.blockers {
            println!("{}: {}", blocker.code, blocker.message);
            println!("  remediation: {}", blocker.remediation);
        }
    }
    render_claim_gaps(status);
    Ok(())
}

pub fn render_assumptions(
    compiled: &CompiledProject,
    claim: Option<&str>,
    json: bool,
) -> Result<()> {
    let statuses = compiled
        .statuses
        .iter()
        .filter(|status| claim.is_none_or(|id| status.claim_id.as_str() == id))
        .collect::<Vec<_>>();
    if statuses.is_empty() {
        bail!("PB-CLAIM-0003: no matching compiled claim");
    }
    if json {
        let values = statuses
            .iter()
            .map(|status| {
                serde_json::json!({
                    "claim_id": status.claim_id,
                    "assumptions": status.assumption.assumptions,
                    "undischarged_premises": status.assumption.undischarged_premises,
                    "not_proved_out_of_scope": status.not_proved_out_of_scope,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&values)?);
        return Ok(());
    }
    for status in statuses {
        println!("{}", status.claim_id);
        for assumption in &status.assumption.assumptions {
            println!(
                "  assumption {} ({}): {}",
                assumption.id,
                enum_text(&assumption.category)?,
                assumption.statement
            );
        }
        for premise in &status.assumption.undischarged_premises {
            println!("  premise {}: {}", premise.id, premise.statement);
        }
        render_claim_gaps(status);
    }
    Ok(())
}

pub fn render_graph(compiled: &CompiledProject, format: &str) -> Result<()> {
    let (nodes, edges) = merged_graph(compiled);
    let gaps = aggregate_gaps(&compiled.statuses);
    let projection = serde_json::json!({
        "schema": "proofbound-graph-export/1",
        "project": compiled.project,
        "revision": compiled.project_revision,
        "nodes": nodes.values().collect::<Vec<_>>(),
        "edges": edges,
        "claims": compiled.statuses,
    });
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&projection)?),
        "dot" => {
            println!("digraph proofbound {{");
            println!("  rankdir=LR;");
            for node in nodes.values() {
                println!(
                    "  {:?} [label={:?}, shape={}];",
                    node.id.as_str(),
                    node.id.as_str(),
                    match node.kind {
                        proofbound_core::NodeKind::Claim => "box",
                        proofbound_core::NodeKind::Assumption
                        | proofbound_core::NodeKind::Premise => "octagon",
                        _ => "ellipse",
                    }
                );
            }
            for edge in &edges {
                println!(
                    "  {:?} -> {:?} [label={:?}];",
                    edge.from().as_str(),
                    edge.to().as_str(),
                    enum_text(&edge.kind())?
                );
            }
            println!("}}");
            println!("// not proved / out of scope");
            for line in aggregate_gap_lines(&gaps) {
                println!("// {}", line.replace(['\r', '\n'], " "));
            }
        }
        "html" => {
            let data = html_escape(&serde_json::to_string_pretty(&projection)?);
            let gap_items = aggregate_gap_lines(&gaps)
                .into_iter()
                .map(|line| format!("<li>{}</li>", html_escape(&line)))
                .collect::<String>();
            println!(
                "<!doctype html><meta charset=\"utf-8\"><title>Proofbound graph</title><style>body{{font:15px system-ui;margin:2rem;background:#111827;color:#e5e7eb}}pre{{white-space:pre-wrap}}code{{color:#bfdbfe}}</style><h1>Proofbound assurance graph</h1><p>Receipt projection for {} at {}.</p><pre><code>{}</code></pre><h2>not proved / out of scope</h2><ul>{}</ul>",
                html_escape(&compiled.project),
                html_escape(&compiled.project_revision),
                data,
                gap_items,
            );
        }
        other => bail!("PB-GRAPH-0002: unsupported graph format {other}"),
    }
    Ok(())
}

fn merged_graph(
    compiled: &CompiledProject,
) -> (
    BTreeMap<String, proofbound_core::GraphNode>,
    Vec<proofbound_core::GraphEdge>,
) {
    let mut nodes = BTreeMap::new();
    let mut edge_keys = BTreeSet::new();
    let mut edges = Vec::new();
    for input in &compiled.inputs {
        for node in &input.graph.nodes {
            nodes.insert(node.id.to_string(), node.clone());
        }
        for edge in &input.graph.edges {
            let key = (edge.from().clone(), edge.to().clone(), edge.kind());
            if edge_keys.insert(key) {
                edges.push(edge.clone());
            }
        }
    }
    edges.sort_by(|left, right| {
        (left.from(), left.to(), left.kind()).cmp(&(right.from(), right.to(), right.kind()))
    });
    (nodes, edges)
}

fn aggregate_gaps(statuses: &[ClaimStatus]) -> AggregateGaps {
    let mut gaps = AggregateGaps::default();
    for status in statuses {
        gaps.open_obligations.extend(
            status
                .not_proved_out_of_scope
                .open_obligations
                .iter()
                .map(|item| format!("{}: {}", status.claim_id, item.statement)),
        );
        gaps.undischarged_premises.extend(
            status
                .not_proved_out_of_scope
                .undischarged_premises
                .iter()
                .map(|item| format!("{}: {} — {}", status.claim_id, item.id, item.statement)),
        );
        gaps.assumptions.extend(
            status
                .not_proved_out_of_scope
                .explicit_assumptions
                .iter()
                .map(|item| format!("{}: {} — {}", status.claim_id, item.id, item.statement)),
        );
        gaps.exclusions.extend(
            status
                .not_proved_out_of_scope
                .exclusions
                .iter()
                .map(|item| format!("{}: {}", status.claim_id, item.statement)),
        );
    }
    gaps
}

fn render_claim_gaps(status: &ClaimStatus) {
    println!("not proved / out of scope");
    let gaps = &status.not_proved_out_of_scope;
    if gaps.open_obligations.is_empty()
        && gaps.undischarged_premises.is_empty()
        && gaps.explicit_assumptions.is_empty()
        && gaps.exclusions.is_empty()
    {
        println!("  none registered");
    }
    for item in &gaps.open_obligations {
        println!("  OPEN {}: {}", item.id, item.statement);
    }
    for item in &gaps.undischarged_premises {
        println!("  PREMISE {}: {}", item.id, item.statement);
    }
    for item in &gaps.explicit_assumptions {
        println!("  ASSUMPTION {}: {}", item.id, item.statement);
    }
    for item in &gaps.exclusions {
        println!("  OUT OF SCOPE {}: {}", item.id, item.statement);
    }
}

fn render_aggregate_gaps(gaps: &AggregateGaps) {
    println!("not proved / out of scope");
    for line in aggregate_gap_lines(gaps) {
        println!("  {line}");
    }
}

fn aggregate_gap_lines(gaps: &AggregateGaps) -> Vec<String> {
    let mut lines = Vec::new();
    lines.extend(
        gaps.open_obligations
            .iter()
            .map(|item| format!("OPEN {item}")),
    );
    lines.extend(
        gaps.undischarged_premises
            .iter()
            .map(|item| format!("PREMISE {item}")),
    );
    lines.extend(
        gaps.assumptions
            .iter()
            .map(|item| format!("ASSUMPTION {item}")),
    );
    lines.extend(
        gaps.exclusions
            .iter()
            .map(|item| format!("OUT OF SCOPE {item}")),
    );
    if lines.is_empty() {
        lines.push("none registered".into());
    }
    lines
}

fn freshness(compiled: &CompiledProject, status: &ClaimStatus) -> &'static str {
    let evidence = status
        .evidence
        .iter()
        .map(|item| item.id.as_str().rsplit(':').next().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    if compiled
        .unit_runs
        .iter()
        .any(|run| evidence.contains(run.unit_id.as_str()) && run.outcome == "verified-now")
    {
        "verified-now"
    } else if compiled
        .unit_runs
        .iter()
        .any(|run| evidence.contains(run.unit_id.as_str()) && run.outcome == "verified-from-cache")
    {
        "verified-from-cache"
    } else {
        "not-checked"
    }
}

fn enum_text<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    Ok(value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string()))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_projection_gap_lines_are_mandatory_and_enumerated() {
        let empty = aggregate_gap_lines(&AggregateGaps::default());
        assert_eq!(empty, ["none registered"]);

        let mut gaps = AggregateGaps::default();
        gaps.open_obligations
            .insert("TEST-CLAIM-001: prove the remaining case".into());
        gaps.undischarged_premises
            .insert("TEST-CLAIM-001: TEST-PREMISE-001 — representation matches".into());
        gaps.assumptions
            .insert("TEST-CLAIM-001: TEST-AXIOM-001 — runtime is faithful".into());
        gaps.exclusions
            .insert("TEST-CLAIM-001: compiler correctness".into());
        let lines = aggregate_gap_lines(&gaps).join("\n");
        assert!(lines.contains("OPEN TEST-CLAIM-001"));
        assert!(lines.contains("PREMISE TEST-CLAIM-001"));
        assert!(lines.contains("ASSUMPTION TEST-CLAIM-001"));
        assert!(lines.contains("OUT OF SCOPE TEST-CLAIM-001"));
    }
}
