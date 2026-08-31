//! Normative faceted status derivation from validated evidence.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    AssumptionCategory, AssumptionId, AssumptionRecord, AssumptionStanding, AssumptionStatus,
    AssuranceGraph, BoundedDomain, CLAIM_SCHEMA_V1, ClaimDefinition, ClaimId, EdgeKind, ErrorCode,
    EvidenceId, EvidenceKind, EvidenceRecord, EvidenceStatus, FlowScope, FormalFacet, LinkageFacet,
    NodeId, NodeKind, OpenObligation, OutOfScope, PolicyDefinition, PremiseId, PremiseRecord,
    StructuredError, TheoremAdmission, Tier, parse_artifact_digest_binding,
};

pub const CLAIM_STATUS_SCHEMA_V1: &str = "proofbound-claim-status/1";

/// Fully resolved input to the core derivation function.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimEvaluationInput {
    pub project_tier: Tier,
    pub claim: ClaimDefinition,
    pub policy: PolicyDefinition,
    pub graph: AssuranceGraph,
    #[serde(default)]
    pub evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub assumptions: Vec<AssumptionRecord>,
    #[serde(default)]
    pub premises: Vec<PremiseRecord>,
}

/// Why one evidence record appears in a claim's detailed closure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRole {
    Formal,
    Linkage,
    AssumptionReview,
    PremiseDischarge,
    OpenObligation,
    Supporting,
}

/// Evidence is never discarded merely because stronger evidence wins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAssessment {
    pub id: EvidenceId,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub policy_admitted: bool,
    pub roles: BTreeSet<EvidenceRole>,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub budget_exceeded: bool,
}

/// Assumption information rendered in both the facet and mandatory gap report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssumptionSummary {
    pub id: AssumptionId,
    pub statement: String,
    pub category: AssumptionCategory,
    pub owner: String,
    pub status: AssumptionStatus,
}

/// Premise status, including a successful discharge when one exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PremiseSummary {
    pub id: PremiseId,
    pub statement: String,
    pub category: AssumptionCategory,
    pub scope: FlowScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discharged_by: Option<EvidenceId>,
    #[serde(default)]
    pub discharge_rejection_reasons: Vec<String>,
}

/// Structured assumption facet; no unenumerated `ASSUMED` state is possible.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssumptionFacetReport {
    pub standing: AssumptionStanding,
    #[serde(default)]
    pub assumptions: Vec<AssumptionSummary>,
    #[serde(default)]
    pub undischarged_premises: Vec<PremiseSummary>,
}

/// Mandatory data behind every human report's “not proved / out of scope”
/// section. This field is non-optional even when every collection is empty.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotProvedOutOfScope {
    #[serde(default)]
    pub open_obligations: Vec<OpenObligation>,
    #[serde(default)]
    pub undischarged_premises: Vec<PremiseSummary>,
    #[serde(default)]
    pub explicit_assumptions: Vec<AssumptionSummary>,
    #[serde(default)]
    pub exclusions: Vec<OutOfScope>,
}

/// One policy blocker, separate from malformed evidence and graph errors.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBlocker {
    pub code: String,
    pub message: String,
    pub remediation: String,
}

/// Publication-policy result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVerdict {
    pub admitted: bool,
    #[serde(default)]
    pub blockers: Vec<PolicyBlocker>,
}

/// Complete derived result for one claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimStatus {
    pub schema: String,
    pub claim_id: ClaimId,
    pub public_statement: String,
    pub formal: FormalFacet,
    /// Absent when `formal` is `INVALID`, because invalidity overrides linkage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkage: Option<LinkageFacet>,
    pub assumption: AssumptionFacetReport,
    pub policy: PolicyVerdict,
    #[serde(default)]
    pub evidence: Vec<EvidenceAssessment>,
    #[serde(default)]
    pub bounded_domains: Vec<BoundedDomain>,
    #[serde(default)]
    pub premises: Vec<PremiseSummary>,
    pub not_proved_out_of_scope: NotProvedOutOfScope,
    #[serde(default)]
    pub errors: Vec<StructuredError>,
}

impl ClaimStatus {
    /// `INVALID` is always a build failure independently of policy verdict.
    #[must_use]
    pub const fn is_build_failure(&self) -> bool {
        matches!(self.formal, FormalFacet::Invalid) || !self.policy.admitted
    }
}

/// Implements Specification 0001 section 6.3. It never accepts a caller-
/// supplied status field; every facet is recomputed from closure records.
#[must_use]
pub fn derive_claim_status(input: &ClaimEvaluationInput) -> ClaimStatus {
    let claim_id = &input.claim.id;
    let mut errors = Vec::new();
    let effective_tier = input
        .claim
        .tier
        .map_or(input.project_tier, |tier| tier.min(input.project_tier));

    if input.claim.schema != CLAIM_SCHEMA_V1 {
        errors.push(
            claim_error(
                claim_id,
                ErrorCode::PbCoreUnsupportedSchema,
                format!("unsupported claim schema '{}'", input.claim.schema),
                "migrate the claim to proofbound-claim/1",
            )
            .identities(CLAIM_SCHEMA_V1, &input.claim.schema),
        );
    }
    if input.claim.title.trim().is_empty() || input.claim.statement.trim().is_empty() {
        errors.push(claim_error(
            claim_id,
            ErrorCode::PbCoreInvalidEvidence,
            "claim title and exact statement must be non-empty",
            "register exact human and formal claim language",
        ));
    }
    if input
        .claim
        .public_language
        .as_ref()
        .is_some_and(|language| language.trim().is_empty())
    {
        errors.push(claim_error(
            claim_id,
            ErrorCode::PbCoreInvalidEvidence,
            "claim public language must be nonblank when present",
            "remove public_language or register a nonblank reader-facing statement",
        ));
    }
    if input.claim.policy != input.policy.id {
        errors.push(
            claim_error(
                claim_id,
                ErrorCode::PbCorePolicyViolation,
                "resolved policy identity does not match the claim",
                "resolve exactly the policy named by the claim manifest",
            )
            .identities(input.claim.policy.to_string(), input.policy.id.to_string()),
        );
    }
    if input
        .claim
        .tier
        .is_some_and(|tier| !input.project_tier.admits(tier))
    {
        errors.push(claim_error(
            claim_id,
            ErrorCode::PbCoreTierExceeded,
            format!(
                "claim tier {} exceeds project tier {}",
                input.claim.tier.expect("checked as present").number(),
                input.project_tier.number()
            ),
            "lower the claim tier to the project tier or raise the project tier",
        ));
    }
    if !effective_tier.admits(input.policy.minimum_tier()) {
        errors.push(
            claim_error(
                claim_id,
                ErrorCode::PbCoreTierExceeded,
                format!(
                    "policy '{}' requires tier {}, above effective claim tier {}",
                    input.policy.id,
                    input.policy.minimum_tier().number(),
                    effective_tier.number()
                ),
                "raise the claim ceiling and project tier or select a lower-tier policy",
            )
            .identities(
                input.policy.minimum_tier().number().to_string(),
                effective_tier.number().to_string(),
            ),
        );
    }
    if let Err(policy_errors) = input.policy.validate() {
        errors.extend(
            policy_errors
                .errors
                .into_iter()
                .map(|error| attach_claim(error, claim_id)),
        );
    }
    if let Err(graph_errors) = input.graph.validate() {
        errors.extend(
            graph_errors
                .errors
                .into_iter()
                .map(|error| attach_claim(error, claim_id)),
        );
    }
    require_node_kind(
        &input.graph,
        &input.claim.node_id,
        &[NodeKind::Claim],
        claim_id,
        "claim",
        &mut errors,
    );
    require_node_kind(
        &input.graph,
        &input.claim.subject,
        &[NodeKind::Subject, NodeKind::Artifact],
        claim_id,
        "shipping subject",
        &mut errors,
    );
    require_node_kind(
        &input.graph,
        &input.policy.node_id,
        &[NodeKind::Policy],
        claim_id,
        "policy",
        &mut errors,
    );

    let evidence_catalog = unique_catalog(
        &input.evidence,
        |record| record.id.clone(),
        claim_id,
        "evidence",
        &mut errors,
    );
    let assumption_catalog = unique_catalog(
        &input.assumptions,
        |record| record.id.clone(),
        claim_id,
        "assumption",
        &mut errors,
    );
    let premise_catalog = unique_catalog(
        &input.premises,
        |record| record.id.clone(),
        claim_id,
        "premise",
        &mut errors,
    );

    let mut relevant_evidence = input.claim.cited_evidence.clone();
    let mut assumption_ids = input.claim.assumptions.clone();
    // `ClaimEvaluationInput::premises` is the claim's registered premise
    // ledger.  A directly cited premise must remain visible even when no
    // evidence record happens to mention it (that absence is precisely what
    // makes the premise undischarged).  Evidence and graph traversal below
    // can only add transitive premises to this direct set.
    let mut premise_ids = input
        .premises
        .iter()
        .map(|premise| premise.id.clone())
        .collect::<BTreeSet<_>>();

    // Anything in the supplied assumption ledger that says it affects this
    // claim is included even if the claim forgot the reverse reference.
    for assumption in &input.assumptions {
        if assumption.affected_claims.contains(claim_id) {
            assumption_ids.insert(assumption.id.clone());
        }
    }

    // A premise attached to a cited theorem is transitive claim closure.
    for premise in &input.premises {
        if premise
            .theorem_evidence
            .as_ref()
            .is_some_and(|owner| input.claim.cited_evidence.contains(owner))
        {
            premise_ids.insert(premise.id.clone());
        }
    }

    // Resolve the direct and transitive closure to a fixed point. In
    // particular, a discharging theorem's own premises and assumptions must
    // not disappear merely because that theorem was reached indirectly.
    loop {
        let before = (
            relevant_evidence.len(),
            assumption_ids.len(),
            premise_ids.len(),
        );
        for evidence_id in relevant_evidence.clone() {
            if let Some(record) = evidence_catalog.get(&evidence_id) {
                assumption_ids.extend(record.assumptions.iter().cloned());
                premise_ids.extend(record.premises.iter().cloned());
                if let Some(theorem) = &record.theorem {
                    assumption_ids.extend(theorem.project_axioms.iter().cloned());
                }
                if let Some(refinement) = &record.source_refinement {
                    premise_ids.extend(refinement.representation_premises.iter().cloned());
                }
            }
        }

        // Graph `assumes` edges cannot be hidden by leaving an ID out of a
        // manifest. They add to, but never replace, receipt references.
        let evidence_nodes = relevant_evidence
            .iter()
            .filter_map(|id| {
                evidence_catalog
                    .get(id)
                    .map(|record| record.node_id.clone())
            })
            .chain(std::iter::once(input.claim.node_id.clone()))
            .collect::<BTreeSet<_>>();
        for edge in &input.graph.edges {
            if edge.kind() != EdgeKind::Assumes || !evidence_nodes.contains(edge.from()) {
                continue;
            }
            if let Some(assumption) = input
                .assumptions
                .iter()
                .find(|item| &item.node_id == edge.to())
            {
                assumption_ids.insert(assumption.id.clone());
            }
            if let Some(premise) = input
                .premises
                .iter()
                .find(|item| &item.node_id == edge.to())
            {
                premise_ids.insert(premise.id.clone());
            }
        }

        for premise_id in premise_ids.clone() {
            if let Some(discharge) = premise_catalog.get(&premise_id).and_then(|premise| {
                premise
                    .theorem_evidence
                    .as_ref()
                    .and(premise.discharge.as_ref())
            }) {
                relevant_evidence.insert(discharge.theorem_evidence.clone());
            }
        }
        expand_assumption_closure(
            &mut assumption_ids,
            &assumption_catalog,
            &mut relevant_evidence,
        );
        let after = (
            relevant_evidence.len(),
            assumption_ids.len(),
            premise_ids.len(),
        );
        if before == after {
            break;
        }
    }

    for premise_id in &premise_ids {
        if !premise_catalog.contains_key(premise_id) {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreMissingPremise,
                format!("registered premise '{premise_id}' has no record"),
                "materialize the premise record; an absent discharge can only leave it assumed",
            ));
        }
    }

    // Extra records that claim applicability but are outside the registered
    // direct/transitive closure are ungated discoveries and fail closed.
    for record in &input.evidence {
        if record.claims.contains(claim_id) && !relevant_evidence.contains(&record.id) {
            errors.push(
                claim_error(
                    claim_id,
                    ErrorCode::PbCoreEvidenceUnregistered,
                    format!(
                        "evidence '{}' targets the claim but is not registered in its closure",
                        record.id
                    ),
                    "add the evidence to the claim or remove the stale claim mapping",
                )
                .for_unit(record.unit_id.clone()),
            );
        }
    }

    let mut valid_evidence = BTreeSet::new();
    for evidence_id in &relevant_evidence {
        let Some(record) = evidence_catalog.get(evidence_id) else {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreEvidenceMissing,
                format!("cited evidence '{evidence_id}' is missing"),
                "run the registered evidence unit or remove the stale citation",
            ));
            continue;
        };
        if record.status != EvidenceStatus::Passed {
            errors.push(
                claim_error(
                    claim_id,
                    evidence_status_error(record.status),
                    format!("evidence '{}' has status {:?}", record.id, record.status),
                    "refresh the exact evidence unit; do not publish from stale or failed evidence",
                )
                .for_unit(record.unit_id.clone()),
            );
            continue;
        }
        let mut locally_valid = true;
        if let Err(record_errors) = record.validate(claim_id) {
            errors.extend(record_errors.errors);
            locally_valid = false;
        }
        if !effective_tier.admits(record.kind.minimum_tier()) {
            errors.push(
                claim_error(
                    claim_id,
                    ErrorCode::PbCoreTierExceeded,
                    format!(
                        "evidence '{}' of kind {:?} requires tier {}, above effective claim tier {}",
                        record.id,
                        record.kind,
                        record.kind.minimum_tier().number(),
                        effective_tier.number()
                    ),
                    "raise the claim ceiling and project tier or remove the unsupported evidence citation",
                )
                .for_unit(record.unit_id.clone()),
            );
            locally_valid = false;
        }
        if !validate_evidence_graph_node(record, &input.graph, claim_id, &mut errors) {
            locally_valid = false;
        }
        if locally_valid {
            valid_evidence.insert(record.id.clone());
        }
    }

    let mut active_assumptions = BTreeMap::new();
    for assumption_id in &assumption_ids {
        let Some(record) = assumption_catalog.get(assumption_id) else {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreMissingAssumption,
                format!("assumption '{assumption_id}' has no ledger record"),
                "register the exact assumption before citing it",
            ));
            continue;
        };
        errors.extend(record.validate_for_claim(claim_id));
        require_node_kind(
            &input.graph,
            &record.node_id,
            &[NodeKind::Assumption],
            claim_id,
            "assumption",
            &mut errors,
        );
        match record.status {
            AssumptionStatus::Active => {
                active_assumptions.insert(record.id.clone(), *record);
            }
            AssumptionStatus::Discharged => {
                // A ledger label is not itself discharge evidence. Keeping the
                // assumption active makes a missing proof weaken, never
                // strengthen, the status.
                active_assumptions.insert(record.id.clone(), *record);
                errors.push(claim_error(
                    claim_id,
                    ErrorCode::PbCoreInvalidDischarge,
                    format!(
                        "assumption '{}' is marked discharged without a first-class discharge record",
                        record.id
                    ),
                    "replace the status label with policy-admitted discharge evidence and a discharged-by edge",
                ));
            }
            AssumptionStatus::Retired => errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreMissingAssumption,
                format!(
                    "retired assumption '{}' still declares that it affects this claim",
                    record.id
                ),
                "remove the stale affected-claim reference only after replacing its dependency",
            )),
        }
    }

    let native_premise_count = active_assumptions
        .values()
        .filter(|record| record.category == AssumptionCategory::NativeEvaluation)
        .count();
    let native_premises_admitted = input
        .policy
        .native_premise_rule
        .as_ref()
        .is_none_or(|rule| rule.accepts(native_premise_count));

    let mut theorem_admissions = BTreeMap::new();
    for evidence_id in &valid_evidence {
        let record = evidence_catalog[evidence_id];
        if record.kind == EvidenceKind::Theorem {
            let mut admission = input.policy.theorem_admission(record);
            let record_native_premise_count = record
                .assumptions
                .iter()
                .filter(|id| {
                    active_assumptions.get(*id).is_some_and(|assumption| {
                        assumption.category == AssumptionCategory::NativeEvaluation
                    })
                })
                .count();
            let record_native_premises_admitted = input
                .policy
                .native_premise_rule
                .as_ref()
                .is_none_or(|rule| rule.accepts(record_native_premise_count));
            if admission.is_admitted()
                && (!native_premises_admitted || !record_native_premises_admitted)
            {
                admission = TheoremAdmission::Rejected {
                    reasons: vec![format!(
                        "native-evaluation premise counts (claim {native_premise_count}, theorem {record_native_premise_count}) violate policy"
                    )],
                };
            }
            theorem_admissions.insert(record.id.clone(), admission);
        }
    }
    let admitted_theorems = theorem_admissions
        .iter()
        .filter_map(|(id, admission)| admission.is_admitted().then_some(id.clone()))
        .collect::<BTreeSet<_>>();

    // Every project axiom in any cited theorem must resolve to an active,
    // visible assumption record even when the theorem itself is inadmissible.
    for evidence_id in &relevant_evidence {
        if let Some(theorem) = evidence_catalog
            .get(evidence_id)
            .and_then(|record| record.theorem.as_ref())
        {
            for axiom in &theorem.project_axioms {
                if !active_assumptions.contains_key(axiom) {
                    errors.push(claim_error(
                        claim_id,
                        ErrorCode::PbCoreMissingAssumption,
                        format!("project axiom '{axiom}' is not an active explicit assumption"),
                        "register and allowlist the project axiom or remove it from the theorem closure",
                    ));
                }
            }
        }
    }

    let mut all_premises = Vec::new();
    let mut undischarged_premises = Vec::new();
    let mut discharge_evidence = BTreeSet::new();
    for premise_id in &premise_ids {
        let Some(premise) = premise_catalog.get(premise_id) else {
            continue;
        };
        if premise.statement.trim().is_empty() {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreInvalidEvidence,
                format!("premise '{}' has an empty statement", premise.id),
                "record the exact theorem hypothesis",
            ));
        }
        require_node_kind(
            &input.graph,
            &premise.node_id,
            &[NodeKind::Premise],
            claim_id,
            "premise",
            &mut errors,
        );
        match &premise.theorem_evidence {
            Some(owner) => match evidence_catalog.get(owner) {
                Some(record)
                    if record.kind == EvidenceKind::Theorem
                        && relevant_evidence.contains(owner) => {}
                Some(record) if record.kind != EvidenceKind::Theorem => {
                    errors.push(claim_error(
                        claim_id,
                        ErrorCode::PbCoreInvalidEvidence,
                        format!(
                            "premise '{}' owner '{}' is not theorem evidence",
                            premise.id, owner
                        ),
                        "bind the premise to its exact registered theorem evidence",
                    ));
                }
                _ => {
                    errors.push(claim_error(
                        claim_id,
                        ErrorCode::PbCoreInvalidEvidence,
                        format!(
                            "premise '{}' is detached from its registered theorem '{}'",
                            premise.id, owner
                        ),
                        "cite and register the owning theorem, or omit the owner and add an exact claim-to-premise assumes edge",
                    ));
                }
            },
            None => {
                if !input
                    .graph
                    .has_edge(&input.claim.node_id, &premise.node_id, EdgeKind::Assumes)
                {
                    errors.push(claim_error(
                        claim_id,
                        ErrorCode::PbCoreInvalidEvidence,
                        format!(
                            "direct premise '{}' has no exact claim-to-premise assumes edge",
                            premise.id
                        ),
                        "add an assumes edge from this claim node to the premise node",
                    ));
                }
                if premise.discharge.is_some() {
                    errors.push(claim_error(
                        claim_id,
                        ErrorCode::PbCoreInvalidDischarge,
                        format!(
                            "direct ownerless premise '{}' cannot declare a discharge",
                            premise.id
                        ),
                        "keep the direct premise undischarged until it is attached to registered owning theorem evidence",
                    ));
                }
            }
        }
        let mut discharge_rejection_reasons = Vec::new();
        let discharged_by = premise.discharge.as_ref().and_then(|discharge| {
            if premise.theorem_evidence.is_none() {
                discharge_rejection_reasons
                    .push("a direct ownerless premise is necessarily undischarged".into());
                return None;
            }
            let Some(theorem) = evidence_catalog.get(&discharge.theorem_evidence) else {
                discharge_rejection_reasons.push("discharging theorem evidence is missing".into());
                return None;
            };
            if !admitted_theorems.contains(&discharge.theorem_evidence) {
                discharge_rejection_reasons
                    .push("discharging theorem is not admitted under the claim policy".into());
            }
            if !input
                .graph
                .has_edge(&premise.node_id, &theorem.node_id, EdgeKind::DischargedBy)
            {
                discharge_rejection_reasons
                    .push("graph has no discharged-by edge to the theorem".into());
            }
            if !premise.discharge_covers(discharge, &input.claim.registered_inputs) {
                discharge_rejection_reasons
                    .push("discharge scope does not cover the premise scope".into());
            }
            if discharge_rejection_reasons.is_empty() {
                discharge_evidence.insert(discharge.theorem_evidence.clone());
                Some(discharge.theorem_evidence.clone())
            } else {
                None
            }
        });
        let summary = PremiseSummary {
            id: premise.id.clone(),
            statement: premise.statement.clone(),
            category: premise.category,
            scope: premise.scope.clone(),
            discharged_by,
            discharge_rejection_reasons,
        };
        if summary.discharged_by.is_none() {
            undischarged_premises.push(summary.clone());
        }
        all_premises.push(summary);
    }
    all_premises.sort_by(|left, right| left.id.cmp(&right.id));
    undischarged_premises.sort_by(|left, right| left.id.cmp(&right.id));

    let mut used_exhaustive_as_proof = false;
    let mut formal = if input.policy.is_ledger() {
        if valid_evidence
            .iter()
            .any(|id| is_empirical_for_status(evidence_catalog[id]))
        {
            FormalFacet::Tested
        } else {
            FormalFacet::Open
        }
    } else if !admitted_theorems.is_empty() {
        FormalFacet::Proved
    } else if input.policy.admit_exhaustive_as_proved
        && valid_evidence
            .iter()
            .any(|id| evidence_catalog[id].kind == EvidenceKind::ExhaustiveCheck)
    {
        used_exhaustive_as_proof = true;
        FormalFacet::Proved
    } else if valid_evidence
        .iter()
        .any(|id| evidence_catalog[id].kind == EvidenceKind::BoundedCheck)
    {
        FormalFacet::BoundedChecked
    } else if valid_evidence
        .iter()
        .any(|id| is_empirical_for_status(evidence_catalog[id]))
    {
        FormalFacet::Tested
    } else {
        FormalFacet::Open
    };

    let bounded_domains = valid_evidence
        .iter()
        .filter_map(|id| evidence_catalog[id].bounded_domain().cloned())
        .collect::<Vec<_>>();
    if (formal == FormalFacet::BoundedChecked || used_exhaustive_as_proof)
        && input
            .claim
            .registered_domain_language
            .as_ref()
            .is_none_or(|language| language.trim().is_empty())
    {
        errors.push(claim_error(
            claim_id,
            ErrorCode::PbCoreInvalidEvidence,
            "bounded or exhaustive evidence has no registered finite-domain public language",
            "state the exact finite domain in the claim's public language",
        ));
    }

    let mut linkage_candidates = BTreeSet::new();
    let mut linkage_evidence = BTreeSet::new();
    for evidence_id in &valid_evidence {
        let record = evidence_catalog[evidence_id];
        match record.kind {
            EvidenceKind::SourceRefinement => {
                if let Some(refinement) = &record.source_refinement {
                    if !input
                        .claim
                        .cited_evidence
                        .contains(&refinement.refinement_theorem)
                    {
                        errors.push(claim_error(
                            claim_id,
                            ErrorCode::PbCoreEvidenceUnregistered,
                            format!(
                                "source refinement '{}' names theorem '{}' outside the claim evidence list",
                                record.id, refinement.refinement_theorem
                            ),
                            "cite the named refinement theorem explicitly",
                        ));
                    } else if !input.policy.is_ledger()
                        && admitted_theorems.contains(&refinement.refinement_theorem)
                        && refinement
                            .representation_premises
                            .iter()
                            .all(|premise| premise_catalog.contains_key(premise))
                    {
                        linkage_candidates.insert(LinkageFacet::Refined);
                        linkage_evidence.insert(record.id.clone());
                    }
                }
            }
            EvidenceKind::ArtifactSoundness => {
                if let Some(binding) = &record.artifact_binding {
                    if !input.claim.cited_evidence.contains(&binding.theorem) {
                        errors.push(claim_error(
                            claim_id,
                            ErrorCode::PbCoreEvidenceUnregistered,
                            format!(
                                "artifact binding '{}' names theorem '{}' outside the claim evidence list",
                                record.id, binding.theorem
                            ),
                            "cite the named artifact theorem explicitly",
                        ));
                    } else if !input.policy.is_ledger()
                        && admitted_theorems.contains(&binding.theorem)
                        && input.policy.artifact_evaluation_admitted(record)
                    {
                        let parsed = evidence_catalog
                            .get(&binding.theorem)
                            .and_then(|theorem_record| theorem_record.theorem.as_ref())
                            .ok_or_else(|| {
                                format!(
                                    "artifact binding '{}' references evidence '{}' without a compiled theorem statement",
                                    record.id, binding.theorem
                                )
                            })
                            .and_then(|theorem| {
                                parse_artifact_digest_binding(
                                    &theorem.statement_wire,
                                    theorem.statement_sha256,
                                    claim_id,
                                )
                                .map_err(|error| {
                                    format!(
                                        "artifact binding '{}' is not derived from the exact audited theorem root: {error}",
                                        record.id
                                    )
                                })
                            });
                        match parsed {
                            Ok(parsed)
                                if record.binding_mode == Some(parsed.mode)
                                    && parsed.artifact_logical_name
                                        == binding.artifact.logical_name
                                    && parsed.artifact_sha256 == binding.artifact.sha256 =>
                            {
                                linkage_candidates.insert(LinkageFacet::ArtifactBound);
                                linkage_evidence.insert(record.id.clone());
                            }
                            Ok(_) => errors.push(
                                claim_error(
                                    claim_id,
                                    ErrorCode::PbCoreInvalidEvidence,
                                    format!(
                                        "artifact binding '{}' disagrees with its audited theorem marker",
                                        record.id
                                    ),
                                    "make binding mode, logical name, and digest equal the exact elaborated theorem marker",
                                )
                                .for_unit(record.unit_id.clone()),
                            ),
                            Err(message) => errors.push(
                                claim_error(
                                    claim_id,
                                    ErrorCode::PbCoreInvalidEvidence,
                                    message,
                                    "use an exact Proofbound.Artifact.DigestBindingV1 theorem root with literal audited identity fields",
                                )
                                .for_unit(record.unit_id.clone()),
                            ),
                        }
                    }
                }
            }
            EvidenceKind::TrustedTranscription => {
                if !input.policy.is_ledger() {
                    linkage_candidates.insert(LinkageFacet::Transcribed);
                    linkage_evidence.insert(record.id.clone());
                }
            }
            _ => {}
        }
    }

    let linkage = choose_primary_linkage(
        &linkage_candidates,
        input.claim.primary_linkage,
        claim_id,
        &mut errors,
    );

    let assumption_summaries = active_assumptions
        .values()
        .map(|record| AssumptionSummary {
            id: record.id.clone(),
            statement: record.statement.clone(),
            category: record.category,
            owner: record.owner.clone(),
            status: record.status,
        })
        .collect::<Vec<_>>();
    let assumption = AssumptionFacetReport {
        standing: if assumption_summaries.is_empty() && undischarged_premises.is_empty() {
            AssumptionStanding::None
        } else {
            AssumptionStanding::Assumed
        },
        assumptions: assumption_summaries.clone(),
        undischarged_premises: undischarged_premises.clone(),
    };

    let mut open_obligations = input
        .claim
        .open_obligations
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    for evidence_id in &valid_evidence {
        if let Some(obligation) = &evidence_catalog[evidence_id].open_obligation {
            open_obligations.push(obligation.clone());
        }
    }
    open_obligations.sort();
    open_obligations.dedup();

    let mut policy_blockers = policy_blockers(
        input,
        formal,
        linkage,
        assumption.standing,
        &valid_evidence,
        &evidence_catalog,
        native_premise_count,
    );

    if !errors.is_empty() {
        formal = FormalFacet::Invalid;
        policy_blockers.push(PolicyBlocker {
            code: "invalid-claim-closure".into(),
            message: "the claim closure contains malformed, missing, failed, drifted, or ambiguous evidence".into(),
            remediation: "resolve every structured error before publication".into(),
        });
    }

    let evidence_assessments = evidence_assessments(
        &relevant_evidence,
        &evidence_catalog,
        &valid_evidence,
        &theorem_admissions,
        formal,
        &linkage_evidence,
        &discharge_evidence,
    );

    let reader_statement = input
        .claim
        .public_language
        .as_ref()
        .unwrap_or(&input.claim.statement);
    let public_statement =
        if matches!(formal, FormalFacet::BoundedChecked) || used_exhaustive_as_proof {
            input.claim.registered_domain_language.as_ref().map_or_else(
                || reader_statement.clone(),
                |domain| format!("{} Registered finite domain: {}", reader_statement, domain),
            )
        } else {
            reader_statement.clone()
        };

    let exclusions = input.claim.out_of_scope.iter().cloned().collect::<Vec<_>>();
    let not_proved_out_of_scope = NotProvedOutOfScope {
        open_obligations,
        undischarged_premises: undischarged_premises.clone(),
        explicit_assumptions: assumption_summaries,
        exclusions,
    };

    ClaimStatus {
        schema: CLAIM_STATUS_SCHEMA_V1.into(),
        claim_id: claim_id.clone(),
        public_statement,
        formal,
        linkage: (formal != FormalFacet::Invalid).then_some(linkage),
        assumption,
        policy: PolicyVerdict {
            admitted: policy_blockers.is_empty(),
            blockers: policy_blockers,
        },
        evidence: evidence_assessments,
        bounded_domains,
        premises: all_premises,
        not_proved_out_of_scope,
        errors,
    }
}

fn unique_catalog<'a, T, Id, F>(
    values: &'a [T],
    id: F,
    claim_id: &ClaimId,
    label: &str,
    errors: &mut Vec<StructuredError>,
) -> BTreeMap<Id, &'a T>
where
    Id: Clone + std::fmt::Display + Ord,
    F: Fn(&T) -> Id,
{
    let mut result = BTreeMap::new();
    for value in values {
        let value_id = id(value);
        if result.insert(value_id.clone(), value).is_some() {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreDuplicateId,
                format!("duplicate {label} ID '{value_id}'"),
                "give every record one stable, unique identity",
            ));
        }
    }
    result
}

fn expand_assumption_closure(
    assumption_ids: &mut BTreeSet<AssumptionId>,
    catalog: &BTreeMap<AssumptionId, &AssumptionRecord>,
    relevant_evidence: &mut BTreeSet<EvidenceId>,
) {
    let mut queue = assumption_ids.iter().cloned().collect::<VecDeque<_>>();
    while let Some(id) = queue.pop_front() {
        let Some(record) = catalog.get(&id) else {
            continue;
        };
        relevant_evidence.extend(record.review_evidence.iter().cloned());
        for dependency in &record.depends_on {
            if assumption_ids.insert(dependency.clone()) {
                queue.push_back(dependency.clone());
            }
        }
    }
}

fn validate_evidence_graph_node(
    record: &EvidenceRecord,
    graph: &AssuranceGraph,
    claim_id: &ClaimId,
    errors: &mut Vec<StructuredError>,
) -> bool {
    let expected: &[NodeKind] = match record.kind {
        EvidenceKind::Theorem => &[NodeKind::Theorem],
        EvidenceKind::ArtifactSoundness | EvidenceKind::TrustedTranscription => {
            &[NodeKind::Artifact]
        }
        EvidenceKind::SourceRefinement => &[NodeKind::TranslationUnit],
        EvidenceKind::BoundedCheck => &[NodeKind::ModelCheckUnit],
        EvidenceKind::IndependentCheck
        | EvidenceKind::ExhaustiveCheck
        | EvidenceKind::PropertyTest
        | EvidenceKind::ExampleTest
        | EvidenceKind::MutationWitness => &[NodeKind::TestSuite, NodeKind::ModelCheckUnit],
        EvidenceKind::Review => &[NodeKind::Review],
        EvidenceKind::Assumption => &[NodeKind::Assumption],
        EvidenceKind::Open => &[NodeKind::Claim],
    };
    let before = errors.len();
    require_node_kind(
        graph,
        &record.node_id,
        expected,
        claim_id,
        "evidence",
        errors,
    );
    if let (Some(theorem), Some(node)) = (&record.theorem, graph.node(&record.node_id))
        && node.proof_environment.as_ref() != Some(&theorem.environment)
    {
        errors.push(claim_error(
            claim_id,
            ErrorCode::PbCoreGraphMismatch,
            format!(
                "theorem evidence '{}' disagrees with its graph environment",
                record.id
            ),
            "recompile theorem identity and graph from the same Lean environment",
        ));
    }
    if let Some(transcription) = &record.trusted_transcription {
        require_node_kind(
            graph,
            &transcription.transcriber.tcb_node,
            &[NodeKind::TcbComponent],
            claim_id,
            "transcriber TCB component",
            errors,
        );
        require_node_kind(
            graph,
            &transcription.reencoder.tcb_node,
            &[NodeKind::TcbComponent],
            claim_id,
            "re-encoder TCB component",
            errors,
        );
    }
    before == errors.len()
}

fn require_node_kind(
    graph: &AssuranceGraph,
    node_id: &NodeId,
    expected: &[NodeKind],
    claim_id: &ClaimId,
    label: &str,
    errors: &mut Vec<StructuredError>,
) {
    match graph.node(node_id) {
        Some(node) if expected.contains(&node.kind) => {}
        Some(node) => errors.push(
            claim_error(
                claim_id,
                ErrorCode::PbCoreGraphMismatch,
                format!("{label} node '{node_id}' has kind {:?}", node.kind),
                "rebuild the graph with the registered typed node",
            )
            .identities(format!("one of {expected:?}"), format!("{:?}", node.kind)),
        ),
        None => errors.push(claim_error(
            claim_id,
            ErrorCode::PbCoreMissingTarget,
            format!("{label} node '{node_id}' is missing from the graph"),
            "materialize every node in the claim closure",
        )),
    }
}

fn choose_primary_linkage(
    candidates: &BTreeSet<LinkageFacet>,
    primary: Option<LinkageFacet>,
    claim_id: &ClaimId,
    errors: &mut Vec<StructuredError>,
) -> LinkageFacet {
    if candidates.is_empty() {
        if primary.is_some_and(|linkage| linkage != LinkageFacet::ModelOnly) {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreGraphMismatch,
                "claim selects a primary shipping linkage with no valid binding evidence",
                "supply the binding evidence or select MODEL_ONLY",
            ));
        }
        return LinkageFacet::ModelOnly;
    }
    if candidates.len() == 1 {
        let only = *candidates.first().expect("one candidate exists");
        if primary.is_some_and(|selected| selected != only) {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreGraphMismatch,
                format!("primary linkage does not match the only validated linkage {only:?}"),
                "select the validated binding or correct its evidence",
            ));
        }
        return only;
    }
    match primary {
        Some(selected) if selected != LinkageFacet::ModelOnly && candidates.contains(&selected) => {
            selected
        }
        _ => {
            errors.push(claim_error(
                claim_id,
                ErrorCode::PbCoreAmbiguousLinkage,
                format!(
                    "multiple valid shipping linkages require a primary selection: {candidates:?}"
                ),
                "select one validated linkage for the summary; all bindings remain in detail",
            ));
            LinkageFacet::ModelOnly
        }
    }
}

fn policy_blockers(
    input: &ClaimEvaluationInput,
    formal: FormalFacet,
    linkage: LinkageFacet,
    assumption: AssumptionStanding,
    valid_evidence: &BTreeSet<EvidenceId>,
    catalog: &BTreeMap<EvidenceId, &EvidenceRecord>,
    native_premise_count: usize,
) -> Vec<PolicyBlocker> {
    let mut blockers = Vec::new();
    let mut block = |code: &str, message: String, remediation: &str| {
        blockers.push(PolicyBlocker {
            code: code.into(),
            message,
            remediation: remediation.into(),
        });
    };
    let effective_tier = input
        .claim
        .tier
        .map_or(input.project_tier, |tier| tier.min(input.project_tier));
    if !effective_tier.admits(input.policy.minimum_tier()) {
        block(
            "tier-ceiling",
            format!(
                "effective claim tier {} does not admit policy tier {}",
                effective_tier.number(),
                input.policy.minimum_tier().number()
            ),
            "raise the claim ceiling and project tier or select a lower-tier policy",
        );
    }
    if input.policy.requires_theorem() && formal != FormalFacet::Proved {
        block(
            "theorem-required",
            "policy requires a policy-admitted theorem".into(),
            "supply a compiled theorem and passing axiom audit under this policy",
        );
    }
    if input.policy.requires_artifact_binding() && linkage != LinkageFacet::ArtifactBound {
        block(
            "artifact-binding-required",
            "artifact-bound policy rejects transcription or an unbound model".into(),
            "bind canonical bytes with bytes-in-theorem or digest-theorem evidence",
        );
    }
    if input.policy.requires_trusted_transcription() && linkage != LinkageFacet::Transcribed {
        block(
            "trusted-transcription-required",
            "transcribed policy requires a derived external round trip".into(),
            "supply valid trusted-transcription evidence with both exact input/output byte pairs and distinct TCB roles",
        );
    }
    if input.policy.requires_source_refinement() && linkage != LinkageFacet::Refined {
        block(
            "source-refinement-required",
            "source-refined policy requires a named refinement theorem and registered premises"
                .into(),
            "supply deterministic source-refinement evidence",
        );
    }
    if input.policy.requires_bounded_check()
        && !valid_evidence
            .iter()
            .any(|id| catalog[id].kind == EvidenceKind::BoundedCheck)
    {
        block(
            "bounded-check-required",
            "bounded policy requires an inventoried bounded check".into(),
            "run every registered harness over the explicit finite domain",
        );
    }
    if input.policy.require_no_assumptions && assumption == AssumptionStanding::Assumed {
        block(
            "assumptions-forbidden",
            "policy requires an empty transitive assumption set".into(),
            "discharge every premise and remove or replace every explicit assumption",
        );
    }
    if let Some(rule) = &input.policy.native_premise_rule
        && !rule.accepts(native_premise_count)
    {
        block(
            "native-premise-count",
            format!(
                "{native_premise_count} active native-evaluation premise(s) violate the configured rule"
            ),
            "register the exact certificate-specific native-evaluation premise set",
        );
    }
    for kind in &input.policy.additional_required_evidence {
        if !valid_evidence.iter().any(|id| catalog[id].kind == *kind) {
            block(
                "required-evidence-missing",
                format!("policy requires evidence kind {kind:?}"),
                "materialize and cite the additional required evidence",
            );
        }
    }
    blockers
}

fn evidence_assessments(
    relevant: &BTreeSet<EvidenceId>,
    catalog: &BTreeMap<EvidenceId, &EvidenceRecord>,
    valid: &BTreeSet<EvidenceId>,
    theorem_admissions: &BTreeMap<EvidenceId, TheoremAdmission>,
    formal: FormalFacet,
    linkage_evidence: &BTreeSet<EvidenceId>,
    discharge_evidence: &BTreeSet<EvidenceId>,
) -> Vec<EvidenceAssessment> {
    relevant
        .iter()
        .filter_map(|id| catalog.get(id))
        .map(|record| {
            let mut roles = BTreeSet::from([EvidenceRole::Supporting]);
            let mut reasons = Vec::new();
            let policy_admitted = if let Some(admission) = theorem_admissions.get(&record.id) {
                reasons.extend(admission.reasons().iter().cloned());
                admission.is_admitted()
            } else {
                valid.contains(&record.id)
            };
            let contributes_formal = match formal {
                FormalFacet::Proved => {
                    (record.kind == EvidenceKind::Theorem && policy_admitted)
                        || record.kind == EvidenceKind::ExhaustiveCheck
                }
                FormalFacet::BoundedChecked => record.kind == EvidenceKind::BoundedCheck,
                FormalFacet::Tested => is_empirical_for_status(record),
                FormalFacet::Open | FormalFacet::Invalid => false,
            };
            if contributes_formal {
                roles.insert(EvidenceRole::Formal);
            }
            if linkage_evidence.contains(&record.id) {
                roles.insert(EvidenceRole::Linkage);
            }
            if discharge_evidence.contains(&record.id) {
                roles.insert(EvidenceRole::PremiseDischarge);
            }
            if record.kind == EvidenceKind::Review {
                roles.insert(EvidenceRole::AssumptionReview);
            }
            if record.kind == EvidenceKind::Open {
                roles.insert(EvidenceRole::OpenObligation);
            }
            EvidenceAssessment {
                id: record.id.clone(),
                kind: record.kind,
                status: record.status,
                policy_admitted,
                roles,
                reasons,
                budget_exceeded: record.provenance.exceeded_budget(),
            }
        })
        .collect()
}

const fn evidence_status_error(status: EvidenceStatus) -> ErrorCode {
    match status {
        EvidenceStatus::Passed => ErrorCode::PbCoreInvalidEvidence,
        EvidenceStatus::Failed => ErrorCode::PbCoreEvidenceFailed,
        EvidenceStatus::Missing => ErrorCode::PbCoreEvidenceMissing,
        EvidenceStatus::Drifted => ErrorCode::PbCoreEvidenceDrifted,
        EvidenceStatus::Unregistered => ErrorCode::PbCoreEvidenceUnregistered,
        EvidenceStatus::Ambiguous => ErrorCode::PbCoreEvidenceAmbiguous,
        EvidenceStatus::Corrupt => ErrorCode::PbCoreEvidenceCorrupt,
        EvidenceStatus::Skipped => ErrorCode::PbCoreEvidenceSkipped,
        EvidenceStatus::Unavailable => ErrorCode::PbCoreEvidenceUnavailable,
    }
}

fn is_empirical_for_status(record: &EvidenceRecord) -> bool {
    record.kind.is_empirical()
        && !(record.kind == EvidenceKind::MutationWitness
            && record
                .mutation_witness
                .as_ref()
                .is_some_and(|witness| witness.proof_term_theorem.is_some()))
}

fn claim_error(
    claim_id: &ClaimId,
    code: ErrorCode,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> StructuredError {
    StructuredError::new(code, message, remediation).for_claim(claim_id.clone())
}

fn attach_claim(mut error: StructuredError, claim_id: &ClaimId) -> StructuredError {
    if error.claim_id.is_none() {
        error.claim_id = Some(claim_id.clone());
    }
    error
}

#[cfg(test)]
mod tests;
