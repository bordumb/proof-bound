//! Immutable built-in trust-profile semantics and stricter composition.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    AssumptionId, BuiltInProfile, ErrorCode, EvaluationMode, EvidenceKind, EvidenceRecord, NodeId,
    PolicyId, StructuredError, Tier, ValidationErrors,
};

pub const POLICY_SCHEMA_V1: &str = "proofbound-policy/1";

/// Certificate-specific native-evaluation premise rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NativePremiseRule {
    AtLeastOne,
    Exactly { count: usize },
}

impl NativePremiseRule {
    #[must_use]
    pub const fn accepts(&self, count: usize) -> bool {
        match self {
            Self::AtLeastOne => count >= 1,
            Self::Exactly { count: expected } => count == *expected,
        }
    }
}

/// An effective trust policy. A custom policy composes built-in components;
/// this lets it add requirements without changing what any built-in name means.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDefinition {
    pub schema: String,
    pub id: PolicyId,
    pub node_id: NodeId,
    #[serde(default)]
    pub components: BTreeSet<BuiltInProfile>,
    #[serde(default)]
    pub allowed_foundational_axioms: BTreeSet<String>,
    #[serde(default)]
    pub allowed_project_axioms: BTreeSet<AssumptionId>,
    pub admit_exhaustive_as_proved: bool,
    pub require_no_assumptions: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_premise_rule: Option<NativePremiseRule>,
    #[serde(default)]
    pub additional_required_evidence: BTreeSet<EvidenceKind>,
}

impl PolicyDefinition {
    /// Constructs one built-in profile with project-configured axiom allowlists.
    pub fn built_in(
        profile: BuiltInProfile,
        allowed_foundational_axioms: BTreeSet<String>,
        allowed_project_axioms: BTreeSet<AssumptionId>,
    ) -> Result<Self, ValidationErrors> {
        let policy = Self {
            schema: POLICY_SCHEMA_V1.into(),
            id: PolicyId::new(profile.as_str()).expect("built-in IDs are valid"),
            node_id: NodeId::new(format!("policy:{}", profile.as_str()))
                .expect("built-in node IDs are valid"),
            components: BTreeSet::from([profile]),
            allowed_foundational_axioms,
            allowed_project_axioms,
            admit_exhaustive_as_proved: false,
            require_no_assumptions: false,
            native_premise_rule: (profile == BuiltInProfile::NativeEvaluated)
                .then_some(NativePremiseRule::Exactly { count: 1 }),
            additional_required_evidence: BTreeSet::new(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Constructs an honest Tier-0 ledger policy capped at empirical standing.
    #[must_use]
    pub fn ledger(id: PolicyId) -> Self {
        let node_id = NodeId::new(format!("policy:{id}"))
            .expect("a validated policy ID produces a validated policy node ID");
        Self {
            schema: POLICY_SCHEMA_V1.into(),
            id,
            node_id,
            components: BTreeSet::from([BuiltInProfile::Ledger]),
            allowed_foundational_axioms: BTreeSet::new(),
            allowed_project_axioms: BTreeSet::new(),
            admit_exhaustive_as_proved: false,
            require_no_assumptions: false,
            native_premise_rule: None,
            additional_required_evidence: BTreeSet::new(),
        }
    }

    /// Validates that built-in names retain exact component meanings and that
    /// custom component combinations are coherent.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if self.schema != POLICY_SCHEMA_V1 {
            errors.push(
                StructuredError::new(
                    ErrorCode::PbCoreUnsupportedSchema,
                    format!("unsupported policy schema '{}'", self.schema),
                    "migrate the policy to proofbound-policy/1",
                )
                .identities(POLICY_SCHEMA_V1, &self.schema),
            );
        }

        let matching_builtin = [
            BuiltInProfile::Ledger,
            BuiltInProfile::Transcribed,
            BuiltInProfile::Kernel,
            BuiltInProfile::KernelWithAssumptions,
            BuiltInProfile::ArtifactBound,
            BuiltInProfile::SourceRefined,
            BuiltInProfile::NativeEvaluated,
            BuiltInProfile::Bounded,
        ]
        .into_iter()
        .find(|profile| self.id.as_str() == profile.as_str());
        if let Some(profile) = matching_builtin
            && (self.components != BTreeSet::from([profile])
                || self.admit_exhaustive_as_proved
                || self.require_no_assumptions
                || !self.additional_required_evidence.is_empty()
                || (profile == BuiltInProfile::Transcribed
                    && (!self.allowed_foundational_axioms.is_empty()
                        || !self.allowed_project_axioms.is_empty())))
        {
            errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                format!("policy '{}' attempts to redefine a built-in profile", self.id),
                "use the immutable built-in definition or give a stricter composite policy a new ID",
            ));
        }

        let kernel_evaluation = self.components.contains(&BuiltInProfile::Kernel)
            || self
                .components
                .contains(&BuiltInProfile::KernelWithAssumptions);
        let native_evaluation = self.components.contains(&BuiltInProfile::NativeEvaluated);
        let ledger = self.components.contains(&BuiltInProfile::Ledger);
        if ledger
            && (self.components.len() != 1
                || !self.allowed_foundational_axioms.is_empty()
                || !self.allowed_project_axioms.is_empty()
                || self.admit_exhaustive_as_proved
                || self.additional_required_evidence.iter().any(|kind| {
                    matches!(
                        kind,
                        EvidenceKind::Theorem
                            | EvidenceKind::ArtifactSoundness
                            | EvidenceKind::TrustedTranscription
                            | EvidenceKind::SourceRefinement
                            | EvidenceKind::BoundedCheck
                    )
                }))
        {
            errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "the ledger profile cannot compose axiom, formal, bounded, or subject-binding requirements",
                "use the ledger component alone without formal allowlists or select a higher-tier trust profile",
            ));
        }
        if kernel_evaluation && native_evaluation {
            errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "a policy cannot require both kernel and native evaluation modes",
                "separate the claims or choose one explicit evaluation boundary",
            ));
        }
        if self.components.contains(&BuiltInProfile::Kernel)
            && !self.allowed_project_axioms.is_empty()
        {
            errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "the kernel profile cannot allow project axioms",
                "remove the project-axiom allowlist or select kernel-with-assumptions",
            ));
        }
        let can_admit_project_axioms = self.components.iter().any(|profile| {
            matches!(
                profile,
                BuiltInProfile::KernelWithAssumptions
                    | BuiltInProfile::ArtifactBound
                    | BuiltInProfile::SourceRefined
                    | BuiltInProfile::NativeEvaluated
            )
        });
        if !can_admit_project_axioms && !self.allowed_project_axioms.is_empty() {
            errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "a policy without an assumption-capable theorem component cannot allow project axioms",
                "remove the project-axiom allowlist or compose an assumption-capable theorem profile",
            ));
        }
        match (native_evaluation, &self.native_premise_rule) {
            (true, None) => errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "native-evaluated policy has no premise-count rule",
                "state whether at least one or exactly N native-evaluation premises are required",
            )),
            (false, Some(_)) => errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "a non-native policy declares a native-evaluation premise rule",
                "remove the rule or add the native-evaluated component under a new policy ID",
            )),
            _ => {}
        }
        if matches!(
            self.native_premise_rule,
            Some(NativePremiseRule::Exactly { count: 0 })
        ) {
            errors.push(StructuredError::new(
                ErrorCode::PbCorePolicyViolation,
                "native evaluation cannot require exactly zero native premises",
                "register at least one certificate-specific native-evaluation premise",
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::new(errors))
        }
    }

    /// Highest adoption tier required by any composed profile.
    #[must_use]
    pub fn minimum_tier(&self) -> Tier {
        self.components
            .iter()
            .map(|profile| profile.minimum_tier())
            .max()
            .unwrap_or(Tier::Ledger)
    }

    #[must_use]
    pub fn requires_theorem(&self) -> bool {
        self.components.iter().any(|profile| {
            matches!(
                profile,
                BuiltInProfile::Kernel
                    | BuiltInProfile::KernelWithAssumptions
                    | BuiltInProfile::ArtifactBound
                    | BuiltInProfile::SourceRefined
                    | BuiltInProfile::NativeEvaluated
            )
        })
    }

    /// Whether this policy caps formal standing at empirical `TESTED`.
    #[must_use]
    pub fn is_ledger(&self) -> bool {
        self.components.contains(&BuiltInProfile::Ledger)
    }

    #[must_use]
    pub fn requires_artifact_binding(&self) -> bool {
        self.components.contains(&BuiltInProfile::ArtifactBound)
    }

    #[must_use]
    pub fn requires_trusted_transcription(&self) -> bool {
        self.components.contains(&BuiltInProfile::Transcribed)
    }

    #[must_use]
    pub fn requires_source_refinement(&self) -> bool {
        self.components.contains(&BuiltInProfile::SourceRefined)
    }

    #[must_use]
    pub fn requires_bounded_check(&self) -> bool {
        self.components.contains(&BuiltInProfile::Bounded)
    }

    #[must_use]
    pub fn requires_native_evaluation(&self) -> bool {
        self.components.contains(&BuiltInProfile::NativeEvaluated)
    }

    /// Whether this policy admits the audited theorem. Reasons are returned so
    /// reports retain rejected stronger evidence instead of discarding it.
    #[must_use]
    pub fn theorem_admission(&self, record: &EvidenceRecord) -> TheoremAdmission {
        let mut reasons = Vec::new();
        if record.kind != EvidenceKind::Theorem {
            reasons.push("record is not theorem evidence".into());
            return TheoremAdmission::Rejected { reasons };
        }
        if !self.requires_theorem() {
            reasons.push("policy does not admit theorem evidence at this tier/profile".into());
        }
        let expected_mode = if self.requires_native_evaluation() {
            EvaluationMode::Native
        } else {
            EvaluationMode::Kernel
        };
        if record.evaluation_mode != Some(expected_mode) {
            reasons.push(format!("policy requires {expected_mode:?} evaluation"));
        }
        match &record.theorem {
            Some(theorem) => {
                if !theorem.axiom_audit_passed || theorem.contains_sorry_ax {
                    reasons.push("compiled axiom audit failed or contains sorryAx".into());
                }
                let unexpected_foundational = theorem
                    .foundational_axioms
                    .difference(&self.allowed_foundational_axioms)
                    .cloned()
                    .collect::<Vec<_>>();
                if !unexpected_foundational.is_empty() {
                    reasons.push(format!(
                        "foundational axioms are not allowlisted: {}",
                        unexpected_foundational.join(", ")
                    ));
                }
                if self.components.contains(&BuiltInProfile::Kernel)
                    && !theorem.project_axioms.is_empty()
                {
                    reasons.push("kernel profile forbids project axioms".into());
                } else {
                    let unexpected_project = theorem
                        .project_axioms
                        .difference(&self.allowed_project_axioms)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    if !unexpected_project.is_empty() {
                        reasons.push(format!(
                            "project axioms are not explicitly allowlisted: {}",
                            unexpected_project.join(", ")
                        ));
                    }
                }
            }
            None => reasons.push("compiled theorem audit is absent".into()),
        }
        if reasons.is_empty() {
            TheoremAdmission::Admitted
        } else {
            TheoremAdmission::Rejected { reasons }
        }
    }

    /// Evaluation-mode admission for an artifact-soundness record.
    #[must_use]
    pub fn artifact_evaluation_admitted(&self, record: &EvidenceRecord) -> bool {
        self.artifact_evaluation_mode_admitted(record.evaluation_mode)
    }

    fn artifact_evaluation_mode_admitted(&self, evaluation_mode: Option<EvaluationMode>) -> bool {
        if self.requires_native_evaluation() {
            evaluation_mode == Some(EvaluationMode::Native)
        } else if self.requires_artifact_binding() {
            matches!(
                evaluation_mode,
                Some(EvaluationMode::Kernel | EvaluationMode::Native)
            )
        } else {
            evaluation_mode == Some(EvaluationMode::Kernel)
        }
    }
}

/// Policy decision for one theorem record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TheoremAdmission {
    Admitted,
    Rejected { reasons: Vec<String> },
}

impl TheoremAdmission {
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted)
    }

    #[must_use]
    pub fn reasons(&self) -> &[String] {
        match self {
            Self::Admitted => &[],
            Self::Rejected { reasons } => reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_names_cannot_be_redefined() {
        let mut policy =
            PolicyDefinition::built_in(BuiltInProfile::Bounded, BTreeSet::new(), BTreeSet::new())
                .unwrap();
        policy.admit_exhaustive_as_proved = true;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn ledger_is_an_exact_tier_zero_builtin_without_formal_requirements() {
        let ledger = PolicyDefinition::ledger(PolicyId::new("tier-zero-ci").unwrap());
        assert_eq!(ledger.components, BTreeSet::from([BuiltInProfile::Ledger]));
        assert_eq!(ledger.minimum_tier(), Tier::Ledger);
        assert!(ledger.is_ledger());
        assert!(!ledger.requires_theorem());
        assert!(!ledger.requires_bounded_check());
        assert!(!ledger.requires_artifact_binding());
        assert!(!ledger.requires_source_refinement());
        assert!(ledger.validate().is_ok());
    }

    #[test]
    fn transcribed_is_an_exact_tier_one_builtin_without_a_theorem_requirement() {
        let transcribed = PolicyDefinition::built_in(
            BuiltInProfile::Transcribed,
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(transcribed.minimum_tier(), Tier::Bounded);
        assert!(!transcribed.requires_theorem());
        assert!(transcribed.requires_trusted_transcription());
        assert!(!transcribed.requires_artifact_binding());
        assert!(transcribed.validate().is_ok());

        let mut redefined = transcribed;
        redefined
            .allowed_foundational_axioms
            .insert("Classical.choice".into());
        assert!(redefined.validate().is_err());
    }

    #[test]
    fn ledger_rejects_formal_composition_requirements_and_axiom_allowlists() {
        let mut composed = PolicyDefinition::ledger(PolicyId::new("ledger-composed").unwrap());
        composed.components.insert(BuiltInProfile::Kernel);
        assert!(composed.validate().is_err());

        let mut required = PolicyDefinition::ledger(PolicyId::new("ledger-required").unwrap());
        required
            .additional_required_evidence
            .insert(EvidenceKind::BoundedCheck);
        assert!(required.validate().is_err());

        let mut axiomatic = PolicyDefinition::ledger(PolicyId::new("ledger-axiomatic").unwrap());
        axiomatic
            .allowed_foundational_axioms
            .insert("Classical.choice".into());
        assert!(axiomatic.validate().is_err());
    }

    #[test]
    fn artifact_bound_accepts_native_binding_but_native_composition_requires_it() {
        let artifact = PolicyDefinition::built_in(
            BuiltInProfile::ArtifactBound,
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap();
        assert!(artifact.artifact_evaluation_mode_admitted(Some(EvaluationMode::Kernel)));
        assert!(artifact.artifact_evaluation_mode_admitted(Some(EvaluationMode::Native)));

        let mut native_artifact = artifact;
        native_artifact.id = PolicyId::new("native-artifact").unwrap();
        native_artifact.node_id = NodeId::new("policy:native-artifact").unwrap();
        native_artifact
            .components
            .insert(BuiltInProfile::NativeEvaluated);
        native_artifact.native_premise_rule = Some(NativePremiseRule::Exactly { count: 1 });
        assert!(native_artifact.validate().is_ok());
        assert!(!native_artifact.artifact_evaluation_mode_admitted(Some(EvaluationMode::Kernel)));
        assert!(native_artifact.artifact_evaluation_mode_admitted(Some(EvaluationMode::Native)));
    }

    #[test]
    fn stricter_composition_has_the_maximum_tier() {
        let policy = PolicyDefinition {
            schema: POLICY_SCHEMA_V1.into(),
            id: PolicyId::new("strict-release").unwrap(),
            node_id: NodeId::new("policy:strict-release").unwrap(),
            components: BTreeSet::from([BuiltInProfile::ArtifactBound, BuiltInProfile::Bounded]),
            allowed_foundational_axioms: BTreeSet::new(),
            allowed_project_axioms: BTreeSet::new(),
            admit_exhaustive_as_proved: false,
            require_no_assumptions: true,
            native_premise_rule: None,
            additional_required_evidence: BTreeSet::from([EvidenceKind::MutationWitness]),
        };
        assert!(policy.validate().is_ok());
        assert_eq!(policy.minimum_tier(), Tier::Bound);
        assert!(policy.requires_artifact_binding());
        assert!(policy.requires_bounded_check());
    }
}
