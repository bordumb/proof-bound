//! Closed vocabularies from Specification 0001.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// The highest assurance tier a project has opted into.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Tier {
    Ledger = 0,
    Bounded = 1,
    Model = 2,
    Bound = 3,
}

impl Tier {
    /// Numeric representation used by project manifests.
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Whether evidence requiring `required` is available at this tier.
    #[must_use]
    pub const fn admits(self, required: Self) -> bool {
        self.number() >= required.number()
    }
}

impl TryFrom<u8> for Tier {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ledger),
            1 => Ok(Self::Bounded),
            2 => Ok(Self::Model),
            3 => Ok(Self::Bound),
            _ => Err("a Proofbound tier must be an integer from 0 through 3"),
        }
    }
}

impl Serialize for Tier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.number())
    }
}

impl<'de> Deserialize<'de> for Tier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(u8::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Typed nodes allowed in a compiled assurance graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    Claim,
    Theorem,
    Subject,
    Artifact,
    SourceClosure,
    TranslationUnit,
    ModelCheckUnit,
    TestSuite,
    Assumption,
    Premise,
    Toolchain,
    TcbComponent,
    Review,
    Policy,
}

/// Typed edges allowed in a compiled assurance graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    Proves,
    Refines,
    Decodes,
    Checks,
    GeneratedFrom,
    DependsOn,
    Assumes,
    DischargedBy,
    CrossChecks,
    CoversBoundedDomain,
    BindsDigest,
    ReviewedBy,
    AdmittedByPolicy,
}

/// Evidence meanings that must never be conflated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Theorem,
    ArtifactSoundness,
    TrustedTranscription,
    SourceRefinement,
    BoundedCheck,
    IndependentCheck,
    ExhaustiveCheck,
    PropertyTest,
    ExampleTest,
    MutationWitness,
    Review,
    Assumption,
    Open,
}

impl EvidenceKind {
    /// Minimum project tier capable of citing this evidence kind.
    #[must_use]
    pub const fn minimum_tier(self) -> Tier {
        match self {
            Self::Theorem => Tier::Model,
            Self::ArtifactSoundness | Self::SourceRefinement => Tier::Bound,
            Self::TrustedTranscription => Tier::Bounded,
            Self::BoundedCheck | Self::IndependentCheck | Self::ExhaustiveCheck => Tier::Bounded,
            Self::PropertyTest
            | Self::ExampleTest
            | Self::MutationWitness
            | Self::Review
            | Self::Assumption
            | Self::Open => Tier::Ledger,
        }
    }

    /// Whether the kind supports only an empirical formal standing by itself.
    #[must_use]
    pub const fn is_empirical(self) -> bool {
        matches!(
            self,
            Self::IndependentCheck
                | Self::ExhaustiveCheck
                | Self::PropertyTest
                | Self::ExampleTest
                | Self::MutationWitness
        )
    }
}

/// How Lean evaluated a theorem or artifact theorem.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationMode {
    Kernel,
    Native,
}

/// How an artifact is connected to bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingMode {
    BytesInTheorem,
    DigestTheorem,
    ExternalRoundTrip,
}

/// Built-in trust-profile components. Composite custom policies may contain
/// more than one component without redefining any component's meaning.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuiltInProfile {
    Ledger,
    Transcribed,
    Kernel,
    KernelWithAssumptions,
    ArtifactBound,
    SourceRefined,
    NativeEvaluated,
    Bounded,
}

impl BuiltInProfile {
    /// Stable manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Transcribed => "transcribed",
            Self::Kernel => "kernel",
            Self::KernelWithAssumptions => "kernel-with-assumptions",
            Self::ArtifactBound => "artifact-bound",
            Self::SourceRefined => "source-refined",
            Self::NativeEvaluated => "native-evaluated",
            Self::Bounded => "bounded",
        }
    }

    /// Minimum project tier needed to select the profile.
    #[must_use]
    pub const fn minimum_tier(self) -> Tier {
        match self {
            Self::Ledger => Tier::Ledger,
            Self::Bounded | Self::Transcribed => Tier::Bounded,
            Self::Kernel | Self::KernelWithAssumptions | Self::NativeEvaluated => Tier::Model,
            Self::ArtifactBound | Self::SourceRefined => Tier::Bound,
        }
    }
}

impl fmt::Display for BuiltInProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Formal status facet, serialized using the public uppercase vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FormalFacet {
    Proved,
    BoundedChecked,
    Tested,
    Open,
    Invalid,
}

/// Subject linkage facet.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinkageFacet {
    Refined,
    ArtifactBound,
    Transcribed,
    ModelOnly,
}

/// Assumption facet label.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssumptionStanding {
    None,
    Assumed,
}

/// Receipt result state. Every non-passing state fails closed when cited.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceStatus {
    Passed,
    Failed,
    Missing,
    Drifted,
    Unregistered,
    Ambiguous,
    Corrupt,
    Skipped,
    Unavailable,
}

/// Whether a receipt was executed now or inherited from an exact cache key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheOrigin {
    Executed,
    Reused,
}

/// Git/worktree state bound into evidence provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TreeState {
    Clean,
    Dirty,
}

/// Source-closure facets prevent presentation changes invalidating semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClosureKind {
    Semantic,
    Runner,
    Presentation,
    ExternalEvidence,
    Toolchain,
}

/// Categories for explicit assumptions and theorem premises.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssumptionCategory {
    MathematicalHypothesis,
    RepresentationPremise,
    TranslatorTcb,
    CompilerTcb,
    RuntimeEnvironment,
    ExternalProvider,
    CryptographicLibrary,
    HumanAttestation,
    NativeEvaluation,
}

/// Lifecycle of an assumption ledger entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssumptionStatus {
    Active,
    Discharged,
    Retired,
}

/// Strength of a handwritten source-refinement adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterStrength {
    FieldForField,
    DecisionAdequate,
}

/// Whether purported cross-checking really is independent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndependenceMode {
    Independent,
    CommonOrigin,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_enums_reject_unknown_values() {
        assert!(serde_json::from_str::<NodeKind>("\"claim-ish\"").is_err());
        assert!(serde_json::from_str::<EvidenceKind>("\"verified\"").is_err());
        assert!(serde_json::from_str::<Tier>("4").is_err());
    }

    #[test]
    fn public_facets_use_normative_spelling() {
        assert_eq!(
            serde_json::to_string(&FormalFacet::BoundedChecked).unwrap(),
            "\"BOUNDED_CHECKED\""
        );
        assert_eq!(
            serde_json::to_string(&LinkageFacet::ArtifactBound).unwrap(),
            "\"ARTIFACT_BOUND\""
        );
    }
}
