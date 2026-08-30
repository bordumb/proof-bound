use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

use anyhow::{Context, Result, bail};
use proofbound_evidence::{canonical_json, domain_hash};
use proofbound_manifest::{
    AssumptionManifest, BindingMode, BoundedDomain, ClaimManifest, EvaluationMode, EvidenceKind,
    EvidenceUnitManifest, ModelCheckUnitManifest, PolicyManifest, ProjectBundle, ProjectManifest,
    RegressionKind, ReviewManifest, TranslationUnitManifest,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
struct Change {
    path: String,
    kind: String,
}

#[derive(Clone, Debug, Serialize)]
struct Regression {
    id: String,
    claim_id: String,
    kind: RegressionKind,
    detail: String,
    approved_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct DiffReport {
    schema: &'static str,
    base_revision: String,
    head_revision: String,
    changes: Vec<Change>,
    regressions: Vec<Regression>,
    approval_complete: bool,
}

pub fn diff_revisions(root: &Path, range: &str, json: bool) -> Result<()> {
    let (base, head) = range
        .split_once("..")
        .context("PB-DIFF-0001: range must be BASE..HEAD")?;
    if base.is_empty() || head.is_empty() || head.contains("..") {
        bail!("PB-DIFF-0001: range must contain exactly BASE..HEAD");
    }
    let base_revision = git_text(root, &["rev-parse", "--verify", base])?;
    let head_revision = git_text(root, &["rev-parse", "--verify", head])?;
    let names = git_text(
        root,
        &[
            "diff",
            "--name-status",
            "--no-renames",
            &base_revision,
            &head_revision,
        ],
    )?;
    // A repository with no project manifest at the base has no prior
    // assurance contract to weaken.  Its first ledger is a baseline, not an
    // assurance regression; subsequent revisions are compared normally.
    let base_has_project = git_file(root, &base_revision, "proofbound.toml").is_ok();
    let base_claims = revision_claims(root, &base_revision)?;
    let head_claims = revision_claims(root, &head_revision)?;
    let all_claim_ids = base_claims
        .keys()
        .chain(head_claims.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let base_project = revision_project(root, &base_revision)?;
    let head_project = revision_project(root, &head_revision)?;
    let registered_toolchains = base_project
        .iter()
        .chain(head_project.iter())
        .flat_map(project_toolchain_paths)
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    let mut regressions = Vec::new();
    for line in names.lines() {
        let mut fields = line.splitn(2, '\t');
        let _status = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        changes.push(Change {
            path: path.into(),
            kind: classify_change(path).into(),
        });
        if base_has_project {
            compare_manifest_path(
                root,
                &base_revision,
                &head_revision,
                path,
                &base_claims,
                &head_claims,
                &mut regressions,
            )?;
            if is_tcb_path(path) || registered_toolchains.contains(path) {
                add_for_claims(
                    &mut regressions,
                    &all_claim_ids,
                    RegressionKind::EnlargedTcb,
                    format!(
                        "TCB or registered toolchain bytes changed at {path}; the change is not statically orderable"
                    ),
                )?;
            }
        }
    }
    let base_digest = domain_hash("proofbound-revision/1", base_revision.as_bytes());
    let head_digest = domain_hash("proofbound-revision/1", head_revision.as_bytes());
    apply_approvals(root, &base_digest, &head_digest, &mut regressions)?;
    let report = DiffReport {
        schema: "proofbound-assurance-diff/1",
        base_revision,
        head_revision,
        approval_complete: regressions
            .iter()
            .all(|regression| regression.approved_by.is_some()),
        changes,
        regressions,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}..{}", report.base_revision, report.head_revision);
        for change in &report.changes {
            println!("  {:12} {}", change.kind, change.path);
        }
        println!("assurance regressions");
        if report.regressions.is_empty() {
            println!("  none");
        }
        for regression in &report.regressions {
            println!(
                "  {:?} {}: {} [{}]",
                regression.kind,
                regression.claim_id,
                regression.detail,
                regression.approved_by.as_deref().unwrap_or("UNAPPROVED")
            );
        }
    }
    if !report.approval_complete {
        bail!("PB-DIFF-0002: assurance regressions require exact base/head-bound approval");
    }
    Ok(())
}

fn compare_manifest_path(
    root: &Path,
    base_revision: &str,
    head_revision: &str,
    path: &str,
    base_claims: &BTreeMap<String, ClaimManifest>,
    head_claims: &BTreeMap<String, ClaimManifest>,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    if !path.ends_with(".toml") {
        return Ok(());
    }
    let old_text = git_file(root, base_revision, path).ok();
    let new_text = git_file(root, head_revision, path).ok();
    let old_schema = old_text.as_deref().and_then(manifest_schema);
    let new_schema = new_text.as_deref().and_then(manifest_schema);
    let schema = old_schema.as_deref().or(new_schema.as_deref());
    match schema {
        Some("proofbound-claim/1") => compare_claim_manifests(
            parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?,
            parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?,
            path,
            regressions,
        ),
        Some("proofbound-assumption/1") => compare_assumption_manifests(
            parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?,
            parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?,
            path,
            regressions,
        ),
        Some("proofbound-evidence-unit/1") => compare_evidence_manifests(
            parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?,
            parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?,
            path,
            regressions,
        ),
        Some("proofbound-model-check-unit/1") => compare_model_check_manifests(
            parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?,
            parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?,
            path,
            regressions,
        ),
        Some("proofbound-policy/1") => {
            let old: Option<PolicyManifest> =
                parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?;
            let new: Option<PolicyManifest> =
                parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?;
            let policy_ids = old
                .iter()
                .map(|policy| policy.id.as_str())
                .chain(new.iter().map(|policy| policy.id.as_str()))
                .collect::<BTreeSet<_>>();
            let claims = base_claims
                .values()
                .chain(head_claims.values())
                .filter(|claim| policy_ids.contains(claim.profile.as_str()))
                .map(|claim| claim.id.clone())
                .collect::<BTreeSet<_>>();
            compare_policy_manifests(old.as_ref(), new.as_ref(), path, &claims, regressions)
        }
        Some("proofbound-translation-unit/1") => compare_translation_manifests(
            parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?,
            parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?,
            path,
            regressions,
        ),
        Some("proofbound-project/1") => compare_project_manifests(
            parse_at_schema(old_text.as_deref(), old_schema.as_deref(), path)?,
            parse_at_schema(new_text.as_deref(), new_schema.as_deref(), path)?,
            path,
            &base_claims
                .keys()
                .chain(head_claims.keys())
                .cloned()
                .collect(),
            regressions,
        ),
        _ => Ok(()),
    }
}

fn compare_claim_manifests(
    old: Option<ClaimManifest>,
    new: Option<ClaimManifest>,
    path: &str,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(old) = old.as_ref() else {
        return Ok(());
    };
    let Some(new) = new.as_ref() else {
        add_regression(
            regressions,
            old.id.clone(),
            RegressionKind::FormalDowngrade,
            format!("registered claim was removed or changed schema at {path}"),
        )?;
        return Ok(());
    };
    if old.id != new.id {
        add_regression(
            regressions,
            old.id.clone(),
            RegressionKind::FormalDowngrade,
            format!(
                "registered claim identity changed from {} to {} at {path}",
                old.id, new.id
            ),
        )?;
        return Ok(());
    }

    for assumption in added_strings(&old.assumptions, &new.assumptions) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::NewAssumption,
            format!("claim added explicit assumption {assumption}"),
        )?;
    }
    for premise in added_strings(&old.premises, &new.premises) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::UndischargedPremise,
            format!("claim added registered premise {premise}"),
        )?;
    }
    for evidence in removed_strings(&old.evidence, &new.evidence) {
        let (kind, label) = if evidence.starts_with("mutation:") {
            (RegressionKind::MutationCoverageRemoved, "mutation coverage")
        } else if evidence.starts_with("artifact:")
            || evidence.starts_with("refinement:")
            || evidence.starts_with("transcription:")
        {
            (RegressionKind::LinkageDowngrade, "linkage evidence")
        } else {
            (
                RegressionKind::FormalDowngrade,
                "formal or empirical evidence",
            )
        };
        add_regression(
            regressions,
            new.id.clone(),
            kind,
            format!("claim removed {label} citation {evidence}"),
        )?;
    }
    if new.profile != old.profile {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::FormalDowngrade,
            format!(
                "trust profile changed from {} to {}; profiles are not statically orderable",
                old.profile, new.profile
            ),
        )?;
    }
    if new.tier != old.tier {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::FormalDowngrade,
            format!("claim tier changed from {:?} to {:?}", old.tier, new.tier),
        )?;
    }
    if old.formal_declaration.is_some()
        && (new.formal_declaration != old.formal_declaration
            || new.statement_encoding != old.statement_encoding
            || new.statement_sha256 != old.statement_sha256)
    {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::FormalDowngrade,
            "formal declaration or canonical theorem-statement identity changed".into(),
        )?;
    }
    for axiom in added_strings(&old.foundational_axioms, &new.foundational_axioms) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::EnlargedTcb,
            format!("claim added foundational axiom {axiom}"),
        )?;
    }
    for axiom in removed_strings(&old.foundational_axioms, &new.foundational_axioms) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::FormalDowngrade,
            format!(
                "claim removed expected compiled axiom {axiom}; theorem inventory must be revalidated"
            ),
        )?;
    }
    for obligation in added_strings(&old.open_obligations, &new.open_obligations) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::FormalDowngrade,
            format!("claim added open obligation {obligation:?}"),
        )?;
    }
    for exclusion in added_strings(&old.out_of_scope, &new.out_of_scope) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::FormalDowngrade,
            format!("claim added out-of-scope exclusion {exclusion:?}"),
        )?;
    }
    if linkage_rank(new.primary_linkage) < linkage_rank(old.primary_linkage) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::LinkageDowngrade,
            format!(
                "primary linkage changed from {:?} to {:?}",
                old.primary_linkage, new.primary_linkage
            ),
        )?;
    }
    compare_bounded_domain(
        &new.id,
        "claim",
        old.bounded_domain.as_ref(),
        new.bounded_domain.as_ref(),
        regressions,
    )?;
    if old.subject != new.subject {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::LinkageDowngrade,
            format!(
                "claim subject changed from {:?} to {:?}",
                old.subject, new.subject
            ),
        )?;
    }
    if old.subject_closure.is_some() && old.subject_closure != new.subject_closure {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::SourceClosureWeakened,
            format!(
                "reviewed subject-closure pin changed from {:?} to {:?}",
                old.subject_closure, new.subject_closure
            ),
        )?;
    }
    for root in removed_strings(&old.source_roots, &new.source_roots) {
        add_regression(
            regressions,
            new.id.clone(),
            RegressionKind::SourceClosureWeakened,
            format!("claim removed semantic source root {root}"),
        )?;
    }
    Ok(())
}

fn compare_assumption_manifests(
    old: Option<AssumptionManifest>,
    new: Option<AssumptionManifest>,
    path: &str,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(new) = new.as_ref() else {
        if let Some(old) = old.as_ref() {
            add_for_claims(
                regressions,
                &string_set(&old.affected_claims),
                RegressionKind::FormalDowngrade,
                format!("registered assumption {} was removed at {path}", old.id),
            )?;
        }
        return Ok(());
    };
    let affected = string_set(&new.affected_claims);
    let Some(old) = old.as_ref() else {
        return add_for_claims(
            regressions,
            &affected,
            RegressionKind::NewAssumption,
            format!("new assumption manifest {} at {path}", new.id),
        );
    };
    for claim in added_strings(&old.affected_claims, &new.affected_claims) {
        add_regression(
            regressions,
            claim.clone(),
            RegressionKind::NewAssumption,
            format!("assumption {} newly affects claim {claim}", new.id),
        )?;
    }
    if old.status != new.status || old.statement != new.statement || old.category != new.category {
        add_for_claims(
            regressions,
            &affected,
            RegressionKind::NewAssumption,
            format!("assumption {} meaning, category, or status changed", new.id),
        )?;
    }
    Ok(())
}

fn compare_evidence_manifests(
    old: Option<EvidenceUnitManifest>,
    new: Option<EvidenceUnitManifest>,
    path: &str,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(old) = old.as_ref() else {
        return Ok(());
    };
    let old_claims = string_set(&old.claims);
    let Some(new) = new.as_ref() else {
        let kind = if old.kind == EvidenceKind::MutationWitness {
            RegressionKind::MutationCoverageRemoved
        } else {
            RegressionKind::FormalDowngrade
        };
        return add_for_claims(
            regressions,
            &old_claims,
            kind,
            format!("registered evidence unit {} was removed at {path}", old.id),
        );
    };
    let claims = old_claims
        .union(&string_set(&new.claims))
        .cloned()
        .collect::<BTreeSet<_>>();
    for claim in removed_strings(&old.claims, &new.claims) {
        add_regression(
            regressions,
            claim.clone(),
            RegressionKind::FormalDowngrade,
            format!("evidence unit {} stopped covering claim {claim}", old.id),
        )?;
    }
    if old.kind == EvidenceKind::MutationWitness && new.kind != old.kind {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::MutationCoverageRemoved,
            format!("evidence unit {} is no longer a mutation witness", old.id),
        )?;
    } else if old.kind != new.kind {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::FormalDowngrade,
            format!(
                "evidence unit {} kind changed from {:?} to {:?}",
                old.id, old.kind, new.kind
            ),
        )?;
    }
    if old.evaluation_mode == Some(EvaluationMode::Kernel)
        && new.evaluation_mode != Some(EvaluationMode::Kernel)
    {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::EvaluationDowngrade,
            format!(
                "evidence unit {} evaluation changed from kernel to {:?}",
                old.id, new.evaluation_mode
            ),
        )?;
    }
    if old.theorem.is_some() && old.theorem != new.theorem {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::FormalDowngrade,
            format!("evidence unit {} theorem inventory changed", old.id),
        )?;
    }
    if old.refinement_theorem.is_some() && old.refinement_theorem != new.refinement_theorem {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::LinkageDowngrade,
            format!("evidence unit {} refinement theorem changed", old.id),
        )?;
    }
    for target in removed_strings(&old.expected_inventory, &new.expected_inventory) {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::FormalDowngrade,
            format!(
                "evidence unit {} removed inventoried target {target}",
                old.id
            ),
        )?;
    }
    for assumption in added_strings(&old.assumptions, &new.assumptions) {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::NewAssumption,
            format!("evidence unit {} added assumption {assumption}", old.id),
        )?;
    }
    for premise in added_strings(&old.premises, &new.premises) {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::UndischargedPremise,
            format!("evidence unit {} added premise {premise}", old.id),
        )?;
    }
    for input in removed_strings(&old.inputs, &new.inputs) {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::SourceClosureWeakened,
            format!("evidence unit {} removed registered input {input}", old.id),
        )?;
    }
    for variable in added_strings(&old.environment_allowlist, &new.environment_allowlist) {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::EnlargedTcb,
            format!(
                "evidence unit {} added environment input {variable}",
                old.id
            ),
        )?;
    }
    if old.adapter != new.adapter || old.operation != new.operation {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::EnlargedTcb,
            format!("evidence unit {} adapter or typed command changed", old.id),
        )?;
    }
    if binding_rank(new.binding_mode) < binding_rank(old.binding_mode) {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::LinkageDowngrade,
            format!("evidence unit {} binding mode weakened", old.id),
        )?;
    }
    if new.tier < old.tier {
        add_for_claims(
            regressions,
            &claims,
            RegressionKind::FormalDowngrade,
            format!(
                "evidence unit {} tier decreased from {} to {}",
                old.id, old.tier, new.tier
            ),
        )?;
    }
    for claim in &claims {
        compare_bounded_domain(
            claim,
            &format!("evidence unit {}", old.id),
            old.bounded_domain.as_ref(),
            new.bounded_domain.as_ref(),
            regressions,
        )?;
    }
    Ok(())
}

fn compare_model_check_manifests(
    old: Option<ModelCheckUnitManifest>,
    new: Option<ModelCheckUnitManifest>,
    path: &str,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(old) = old.as_ref() else {
        return Ok(());
    };
    let claims = string_set(&old.claims);
    let Some(new) = new.as_ref() else {
        return add_for_claims(
            regressions,
            &claims,
            RegressionKind::BoundedDomainNarrowed,
            format!("model-check unit {} was removed at {path}", old.id),
        );
    };
    for claim in removed_strings(&old.claims, &new.claims) {
        add_regression(
            regressions,
            claim.clone(),
            RegressionKind::BoundedDomainNarrowed,
            format!("model-check unit {} stopped covering claim {claim}", old.id),
        )?;
    }
    let all_claims = claims
        .union(&string_set(&new.claims))
        .cloned()
        .collect::<BTreeSet<_>>();
    for harness in removed_strings(&old.harnesses, &new.harnesses) {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::BoundedDomainNarrowed,
            format!("model-check unit {} removed harness {harness}", old.id),
        )?;
    }
    for assumption in added_strings(&old.assumptions, &new.assumptions) {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::NewAssumption,
            format!("model-check unit {} added assumption {assumption}", old.id),
        )?;
    }
    if new.unwind < old.unwind {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::BoundedDomainNarrowed,
            format!(
                "model-check unit {} unwind bound decreased from {} to {}",
                old.id, old.unwind, new.unwind
            ),
        )?;
    }
    if new.solver != old.solver || new.adapter != old.adapter {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::EnlargedTcb,
            format!("model-check unit {} solver or adapter changed", old.id),
        )?;
    }
    for claim in &all_claims {
        compare_bounded_domain(
            claim,
            &format!("model-check unit {}", old.id),
            Some(&old.domain),
            Some(&new.domain),
            regressions,
        )?;
    }
    Ok(())
}

fn compare_policy_manifests(
    old: Option<&PolicyManifest>,
    new: Option<&PolicyManifest>,
    path: &str,
    claims: &BTreeSet<String>,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(old) = old else {
        return Ok(());
    };
    let Some(new) = new else {
        return add_for_claims(
            regressions,
            claims,
            RegressionKind::FormalDowngrade,
            format!("registered policy {} was removed at {path}", old.id),
        );
    };
    if old.extends != new.extends
        || (old.require_registered_premises && !new.require_registered_premises)
        || (!old.allow_exhaustive_as_proved && new.allow_exhaustive_as_proved)
        || (!old.publication_allows_open && new.publication_allows_open)
        || old.native_premise_count != new.native_premise_count
    {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::FormalDowngrade,
            format!("policy {} changed a formal-admission rule", old.id),
        )?;
    }
    if !old.allow_native && new.allow_native {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::EvaluationDowngrade,
            format!("policy {} newly admits native evaluation", old.id),
        )?;
    }
    if (!old.allow_project_axioms && new.allow_project_axioms)
        || !added_strings(&old.allowed_project_axioms, &new.allowed_project_axioms).is_empty()
        || !added_strings(
            &old.allowed_foundational_axioms,
            &new.allowed_foundational_axioms,
        )
        .is_empty()
    {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::EnlargedTcb,
            format!("policy {} enlarged its admitted axiom inventory", old.id),
        )?;
    }
    if old.required_binding != new.required_binding {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::LinkageDowngrade,
            format!(
                "policy {} required binding changed from {:?} to {:?}; the values are not statically orderable",
                old.id, old.required_binding, new.required_binding
            ),
        )?;
    }
    Ok(())
}

fn compare_translation_manifests(
    old: Option<TranslationUnitManifest>,
    new: Option<TranslationUnitManifest>,
    path: &str,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(old) = old.as_ref() else {
        return Ok(());
    };
    let claims = string_set(&old.claims);
    let Some(new) = new.as_ref() else {
        return add_for_claims(
            regressions,
            &claims,
            RegressionKind::LinkageDowngrade,
            format!("translation unit {} was removed at {path}", old.id),
        );
    };
    for claim in removed_strings(&old.claims, &new.claims) {
        add_regression(
            regressions,
            claim.clone(),
            RegressionKind::LinkageDowngrade,
            format!("translation unit {} stopped refining claim {claim}", old.id),
        )?;
    }
    let all_claims = claims
        .union(&string_set(&new.claims))
        .cloned()
        .collect::<BTreeSet<_>>();
    for symbol in removed_strings(&old.start_from, &new.start_from) {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::LinkageDowngrade,
            format!("translation unit {} removed source symbol {symbol}", old.id),
        )?;
    }
    if old.handwritten_refinement != new.handwritten_refinement
        || old.import_mapping != new.import_mapping
        || old.determinism_runs != new.determinism_runs
        || old.determinism_normalization != new.determinism_normalization
    {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::SourceClosureWeakened,
            format!(
                "translation unit {} changed its refinement or deterministic source binding",
                old.id
            ),
        )?;
    }
    if (old.forbid_generated_axioms && !new.forbid_generated_axioms)
        || old.adapter != new.adapter
        || !old
            .external_bridges
            .iter()
            .all(|item| new.external_bridges.contains(item))
        || !old
            .template_axioms
            .iter()
            .all(|item| new.template_axioms.contains(item))
        || !old
            .warning_inventory
            .iter()
            .all(|item| new.warning_inventory.contains(item))
    {
        add_for_claims(
            regressions,
            &all_claims,
            RegressionKind::EnlargedTcb,
            format!(
                "translation unit {} weakened or changed its TCB inventory",
                old.id
            ),
        )?;
    }
    Ok(())
}

fn compare_project_manifests(
    old: Option<ProjectManifest>,
    new: Option<ProjectManifest>,
    path: &str,
    claims: &BTreeSet<String>,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    let Some(old) = old.as_ref() else {
        return Ok(());
    };
    let Some(new) = new.as_ref() else {
        return add_for_claims(
            regressions,
            claims,
            RegressionKind::FormalDowngrade,
            format!("project assurance manifest was removed at {path}"),
        );
    };
    if new.tier < old.tier {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::FormalDowngrade,
            format!("project tier decreased from {} to {}", old.tier, new.tier),
        )?;
    }
    for root in removed_strings(&old.source.semantic, &new.source.semantic) {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::SourceClosureWeakened,
            format!("project removed semantic source pattern {root}"),
        )?;
    }
    for root in removed_strings(&old.source.runner, &new.source.runner) {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::EnlargedTcb,
            format!("project removed runner closure pattern {root}"),
        )?;
    }
    for root in removed_strings(&old.source.external_evidence, &new.source.external_evidence) {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::SourceClosureWeakened,
            format!("project removed external-evidence closure pattern {root}"),
        )?;
    }
    if old.toolchains != new.toolchains {
        add_for_claims(
            regressions,
            claims,
            RegressionKind::EnlargedTcb,
            "registered toolchain descriptor set changed; the TCB change is not statically orderable".into(),
        )?;
    }
    for (label, old_items, new_items) in [
        ("claim manifest", &old.claim_manifests, &new.claim_manifests),
        (
            "assumption manifest",
            &old.assumption_manifests,
            &new.assumption_manifests,
        ),
        ("evidence unit", &old.evidence_units, &new.evidence_units),
        (
            "translation unit",
            &old.translation_units,
            &new.translation_units,
        ),
        (
            "model-check unit",
            &old.model_check_units,
            &new.model_check_units,
        ),
        (
            "policy manifest",
            &old.policy_manifests,
            &new.policy_manifests,
        ),
    ] {
        for removed in removed_strings(old_items, new_items) {
            add_for_claims(
                regressions,
                claims,
                RegressionKind::FormalDowngrade,
                format!("project stopped registering {label} pattern {removed}"),
            )?;
        }
    }
    Ok(())
}

fn compare_bounded_domain(
    claim_id: &str,
    owner: &str,
    old: Option<&BoundedDomain>,
    new: Option<&BoundedDomain>,
    regressions: &mut Vec<Regression>,
) -> Result<()> {
    match (old, new) {
        (Some(_), None) => add_regression(
            regressions,
            claim_id.to_owned(),
            RegressionKind::BoundedDomainNarrowed,
            format!("{owner} removed its registered bounded domain"),
        ),
        (Some(old), Some(new)) if old == new => Ok(()),
        (Some(old), Some(new))
            if old.id == new.id
                && old.description == new.description
                && old.ordering_key == new.ordering_key
                && new.cardinality < old.cardinality =>
        {
            add_regression(
                regressions,
                claim_id.to_owned(),
                RegressionKind::BoundedDomainNarrowed,
                format!(
                    "{owner} bounded-domain cardinality narrowed from {} to {}",
                    old.cardinality, new.cardinality
                ),
            )
        }
        (Some(old), Some(new))
            if old.id == new.id
                && old.description == new.description
                && old.ordering_key == new.ordering_key
                && new.cardinality > old.cardinality =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => add_regression(
            regressions,
            claim_id.to_owned(),
            RegressionKind::BoundedDomainIncomparable,
            format!("{owner} bounded-domain registrations are not order-comparable"),
        ),
        _ => Ok(()),
    }
}

fn add_for_claims(
    regressions: &mut Vec<Regression>,
    claims: &BTreeSet<String>,
    kind: RegressionKind,
    detail: String,
) -> Result<()> {
    for claim in claims {
        add_regression(regressions, claim.clone(), kind, detail.clone())?;
    }
    Ok(())
}

fn string_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn added_strings<'a>(old: &'a [String], new: &'a [String]) -> Vec<&'a String> {
    let old = old.iter().collect::<BTreeSet<_>>();
    new.iter().filter(|item| !old.contains(item)).collect()
}

fn removed_strings<'a>(old: &'a [String], new: &'a [String]) -> Vec<&'a String> {
    let new = new.iter().collect::<BTreeSet<_>>();
    old.iter().filter(|item| !new.contains(item)).collect()
}

fn add_regression(
    values: &mut Vec<Regression>,
    claim_id: String,
    kind: RegressionKind,
    detail: String,
) -> Result<()> {
    let identity = domain_hash(
        "proofbound-regression/1",
        &canonical_json(&serde_json::json!({
            "claim_id": claim_id,
            "kind": kind,
            "detail": detail,
        }))?,
    );
    if let Some(existing) = values.iter().find(|value| value.id == identity) {
        if existing.claim_id == claim_id && existing.kind == kind && existing.detail == detail {
            return Ok(());
        }
        bail!("PB-DIFF-0005: regression identity collision");
    }
    values.push(Regression {
        id: identity,
        claim_id,
        kind,
        detail,
        approved_by: None,
    });
    Ok(())
}

fn apply_approvals(
    root: &Path,
    base: &str,
    head: &str,
    regressions: &mut [Regression],
) -> Result<()> {
    let bundle = ProjectBundle::load(root)?;
    let reviews = bundle
        .reviews
        .values()
        .map(|(_, review)| review)
        .collect::<Vec<_>>();
    apply_review_approvals(base, head, regressions, &reviews)
}

fn apply_review_approvals(
    base: &str,
    head: &str,
    regressions: &mut [Regression],
    reviews: &[&ReviewManifest],
) -> Result<()> {
    let mut seen_approval_ids = BTreeSet::new();
    for review in reviews {
        if review.base_revision != base || review.head_revision != head {
            continue;
        }
        for approved in &review.regressions {
            if !seen_approval_ids.insert(approved.id.clone()) {
                bail!(
                    "PB-DIFF-0003: regression approval {} is duplicated across matching reviews",
                    approved.id
                );
            }
            if let Some(regression) = regressions.iter_mut().find(|regression| {
                regression.id == approved.id
                    && regression.claim_id == approved.claim_id
                    && regression.kind == approved.kind
                    && regression.detail == approved.detail
            }) {
                if regression.approved_by.is_some() {
                    bail!(
                        "PB-DIFF-0003: regression approval {} is duplicated",
                        approved.id
                    );
                }
                regression.approved_by = Some(review.id.clone());
            } else {
                bail!(
                    "PB-DIFF-0003: review {} contains a stale or mismatched approval {}",
                    review.id,
                    approved.id
                );
            }
        }
    }
    Ok(())
}

fn linkage_rank(value: Option<proofbound_manifest::PrimaryLinkage>) -> u8 {
    match value {
        Some(proofbound_manifest::PrimaryLinkage::Refined) => 4,
        Some(proofbound_manifest::PrimaryLinkage::ArtifactBound) => 3,
        Some(proofbound_manifest::PrimaryLinkage::Transcribed) => 2,
        Some(proofbound_manifest::PrimaryLinkage::ModelOnly) | None => 1,
    }
}

fn binding_rank(value: Option<BindingMode>) -> u8 {
    match value {
        Some(BindingMode::BytesInTheorem | BindingMode::DigestTheorem) => 2,
        Some(BindingMode::ExternalRoundTrip) => 1,
        None => 0,
    }
}

fn manifest_schema(text: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(text).ok()?;
    value.get("schema")?.as_str().map(str::to_owned)
}

fn parse_at_schema<T: serde::de::DeserializeOwned>(
    text: Option<&str>,
    schema: Option<&str>,
    path: &str,
) -> Result<Option<T>> {
    let Some(text) = text else {
        return Ok(None);
    };
    if schema.is_none() {
        bail!("PB-DIFF-0005: changed manifest {path} has no readable schema");
    }
    toml::from_str(text)
        .with_context(|| format!("PB-DIFF-0005: changed manifest {path} is invalid"))
        .map(Some)
}

fn revision_claims(root: &Path, revision: &str) -> Result<BTreeMap<String, ClaimManifest>> {
    let paths = git_text(root, &["ls-tree", "-r", "--name-only", revision])?;
    let mut claims = BTreeMap::new();
    for path in paths.lines().filter(|path| path.ends_with(".toml")) {
        let text = git_file(root, revision, path)?;
        if manifest_schema(&text).as_deref() != Some("proofbound-claim/1") {
            continue;
        }
        let claim: ClaimManifest = toml::from_str(&text).with_context(|| {
            format!("PB-DIFF-0005: claim manifest {path} is invalid at {revision}")
        })?;
        if claims.insert(claim.id.clone(), claim).is_some() {
            bail!("PB-DIFF-0005: duplicate claim identity at {revision}");
        }
    }
    Ok(claims)
}

fn revision_project(root: &Path, revision: &str) -> Result<Option<ProjectManifest>> {
    let Ok(text) = git_file(root, revision, "proofbound.toml") else {
        return Ok(None);
    };
    toml::from_str(&text)
        .with_context(|| format!("PB-DIFF-0005: invalid project manifest at {revision}"))
        .map(Some)
}

fn project_toolchain_paths(project: &ProjectManifest) -> impl Iterator<Item = String> + '_ {
    [
        project.toolchains.rust.as_ref(),
        project.toolchains.lean.as_ref(),
        project.toolchains.python.as_ref(),
        project.toolchains.translation.as_ref(),
    ]
    .into_iter()
    .flatten()
    .cloned()
}

fn is_tcb_path(path: &str) -> bool {
    path.split('/')
        .any(|component| component.eq_ignore_ascii_case("tcb") || component.contains("toolchain"))
        || path.ends_with("tcb.toml")
}

fn classify_change(path: &str) -> &'static str {
    if path.contains("claims/") {
        "claim"
    } else if path.contains("assumptions/") {
        "axiom"
    } else if path.contains("tcb") || path.contains("toolchain") {
        "tcb"
    } else if path.contains("closure") {
        "closure"
    } else if path.ends_with(".lean") {
        "theorem"
    } else {
        "supporting"
    }
}

fn git_file(root: &Path, revision: &str, path: &str) -> Result<String> {
    let spec = format!("{revision}:{path}");
    let output = Command::new("git")
        .args(["show", &spec])
        .current_dir(root)
        .output()?;
    if !output.status.success() || output.stdout.len() > 2 << 20 {
        bail!("git object is missing or too large");
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn git_text(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    if !output.status.success() || output.stdout.len() > 32 << 20 {
        bail!(
            "PB-DIFF-0004: git failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use proofbound_manifest::{ApprovedRegression, ReviewManifest};
    use serde_json::json;

    use super::*;

    fn claim() -> ClaimManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-claim/1",
            "id": "TEST-CLAIM-001",
            "title": "Claim",
            "statement": "Exact statement",
            "public_language": null,
            "formal_declaration": "Test.claim",
            "statement_encoding": "lean-expr-cbor/1",
            "statement_sha256": format!("sha256:{}", "11".repeat(32)),
            "foundational_axioms": ["propext"],
            "subject": "rust:test::claim",
            "subject_closure": format!("sha256:{}", "22".repeat(32)),
            "profile": "kernel",
            "tier": 2,
            "primary_linkage": "model-only",
            "evidence": ["theorem:claim", "mutation:old"],
            "assumptions": ["TEST-AXIOM-OLD"],
            "premises": ["TEST-PREMISE-OLD"],
            "open_obligations": [],
            "out_of_scope": [],
            "bounded_domain": {
                "id": "domain",
                "description": "registered values",
                "cardinality": 8,
                "ordering_key": [0, 1]
            },
            "source_roots": ["src/old.rs"]
        }))
        .unwrap()
    }

    fn evidence() -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "claim-proof",
            "adapter": "lean",
            "kind": "theorem",
            "claims": ["TEST-CLAIM-001"],
            "tier": 2,
            "operation": {
                "type": "lean-audit",
                "package": null,
                "targets": [],
                "paths": [],
                "manifest": "lean/audit.json",
                "inventory": null,
                "checker": null,
                "arguments": []
            },
            "evaluation_mode": "kernel",
            "binding_mode": null,
            "theorem": "Test.claim",
            "refinement_theorem": null,
            "premises": [],
            "assumptions": [],
            "expected_inventory": ["Test.claim"],
            "inputs": ["lean/Test.lean"],
            "outputs": [],
            "environment_allowlist": [],
            "bounded_domain": null,
            "resource_budget": {"time_seconds": 10, "disk_bytes": 100, "memory_bytes": 100}
        }))
        .unwrap()
    }

    #[test]
    fn exact_set_comparisons_detect_same_count_replacements() {
        let old = claim();
        let mut new = old.clone();
        new.assumptions = vec!["TEST-AXIOM-NEW".into()];
        new.premises = vec!["TEST-PREMISE-NEW".into()];
        new.evidence = vec!["theorem:claim".into(), "mutation:new".into()];
        new.source_roots = vec!["src/new.rs".into()];
        let mut regressions = Vec::new();
        compare_claim_manifests(Some(old), Some(new), "claims/test.toml", &mut regressions)
            .unwrap();
        let kinds = regressions.iter().map(|item| item.kind).collect::<Vec<_>>();
        assert!(kinds.contains(&RegressionKind::NewAssumption));
        assert!(kinds.contains(&RegressionKind::UndischargedPremise));
        assert!(kinds.contains(&RegressionKind::MutationCoverageRemoved));
        assert!(kinds.contains(&RegressionKind::SourceClosureWeakened));
    }

    #[test]
    fn formal_axiom_and_evaluation_downgrades_are_conservative() {
        let old_claim = claim();
        let mut new_claim = old_claim.clone();
        new_claim.profile = "ledger".into();
        new_claim.formal_declaration = None;
        new_claim.statement_encoding = None;
        new_claim.statement_sha256 = None;
        new_claim.foundational_axioms = vec!["Classical.choice".into()];
        let mut regressions = Vec::new();
        compare_claim_manifests(
            Some(old_claim),
            Some(new_claim),
            "claims/test.toml",
            &mut regressions,
        )
        .unwrap();

        let old_evidence = evidence();
        let mut new_evidence = old_evidence.clone();
        new_evidence.evaluation_mode = Some(EvaluationMode::Native);
        new_evidence.theorem = Some("Test.weaker".into());
        new_evidence.expected_inventory = vec!["Test.weaker".into()];
        compare_evidence_manifests(
            Some(old_evidence),
            Some(new_evidence),
            "proofbound/evidence/test.toml",
            &mut regressions,
        )
        .unwrap();

        assert!(
            regressions
                .iter()
                .any(|item| item.kind == RegressionKind::FormalDowngrade)
        );
        assert!(
            regressions
                .iter()
                .any(|item| item.kind == RegressionKind::EnlargedTcb)
        );
        assert!(
            regressions
                .iter()
                .any(|item| item.kind == RegressionKind::EvaluationDowngrade)
        );
        assert!(
            regressions
                .iter()
                .any(|item| item.detail.contains("inventoried target"))
        );
    }

    #[test]
    fn bounded_domain_identity_changes_are_incomparable_and_pin_changes_weaken_closure() {
        let old = claim();
        let mut new = old.clone();
        new.bounded_domain.as_mut().unwrap().id = "different-domain".into();
        new.subject_closure = Some(format!("sha256:{}", "33".repeat(32)));
        let mut regressions = Vec::new();
        compare_claim_manifests(Some(old), Some(new), "claims/test.toml", &mut regressions)
            .unwrap();
        assert!(
            regressions
                .iter()
                .any(|item| item.kind == RegressionKind::BoundedDomainIncomparable)
        );
        assert!(regressions.iter().any(|item| {
            item.kind == RegressionKind::SourceClosureWeakened
                && item.detail.contains("subject-closure pin")
        }));
    }

    #[test]
    fn approvals_match_every_field_and_reject_stale_or_duplicate_entries() {
        let mut regressions = Vec::new();
        add_regression(
            &mut regressions,
            "TEST-CLAIM-001".into(),
            RegressionKind::FormalDowngrade,
            "exact downgrade".into(),
        )
        .unwrap();
        let approved = ApprovedRegression {
            id: regressions[0].id.clone(),
            claim_id: regressions[0].claim_id.clone(),
            kind: regressions[0].kind,
            detail: regressions[0].detail.clone(),
        };
        let review = ReviewManifest {
            schema: "proofbound-review/1".into(),
            id: "TEST-REVIEW-001".into(),
            reviewer: "Reviewer".into(),
            statement: "Exact approval".into(),
            scope: "One regression".into(),
            reviewed_at: "2026-08-30T00:00:00Z".into(),
            base_revision: "base".into(),
            head_revision: "head".into(),
            regressions: vec![approved.clone()],
            signature: None,
        };
        apply_review_approvals("base", "head", &mut regressions, &[&review]).unwrap();
        assert_eq!(
            regressions[0].approved_by.as_deref(),
            Some("TEST-REVIEW-001")
        );

        let mut stale_regressions = regressions.clone();
        stale_regressions[0].approved_by = None;
        let mut stale = review.clone();
        stale.regressions[0].detail = "not exact".into();
        assert!(apply_review_approvals("base", "head", &mut stale_regressions, &[&stale]).is_err());

        let mut duplicate_regressions = regressions;
        duplicate_regressions[0].approved_by = None;
        let mut second = review.clone();
        second.id = "TEST-REVIEW-002".into();
        assert!(
            apply_review_approvals(
                "base",
                "head",
                &mut duplicate_regressions,
                &[&review, &second],
            )
            .is_err()
        );
    }
}
