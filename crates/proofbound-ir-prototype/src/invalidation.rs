use std::collections::{BTreeMap, BTreeSet};

use proofbound_evidence::{canonical_json, domain_hash};
use serde::{Deserialize, Serialize};

use crate::IrValidationError;
use crate::assurance::decode_strict_json;

pub const DEPENDENCY_PROJECTION_SCHEMA: &str = "proofbound-ir-dependency-projection/1";
pub const DEPENDENCY_PROJECTION_DOMAIN: &str = "proofbound-ir-dependency-projection/1";
pub const INVALIDATION_TRACE_SCHEMA: &str = "proofbound-ir-invalidation-trace/1";
pub const INVALIDATION_TRACE_DOMAIN: &str = "proofbound-ir-invalidation-trace/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyProjection {
    pub schema: String,
    pub unit: String,
    pub route: String,
    pub source_revision: String,
    pub claims: Vec<String>,
    pub nodes: Vec<DependencyNode>,
    pub uses: Vec<DependencyUse>,
    pub reuse_allowed: bool,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DependencyNode {
    Artifact {
        id: String,
        selector: String,
        sha256: String,
        size_bytes: u64,
        permissions: PermissionModel,
    },
    Resolution {
        id: String,
        selector: String,
        candidates: Vec<ResolutionCandidate>,
    },
    Environment {
        id: String,
        selector: String,
        state: EnvironmentState,
    },
    Tool {
        id: String,
        selector: String,
        executable_sha256: String,
        version_identity: String,
    },
    Contract {
        id: String,
        selector: String,
        contract_schema: String,
        contract_identity: String,
    },
    Platform {
        id: String,
        selector: String,
        operating_system: String,
        architecture: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "model", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PermissionModel {
    UnixMode { mode: u32 },
    Readonly { readonly: bool },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionCandidate {
    pub path: String,
    pub state: PathState,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PathState {
    Absent,
    Present {
        sha256: String,
        size_bytes: u64,
        permissions: PermissionModel,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EnvironmentState {
    Absent,
    ValueDigest { sha256: String },
    SecretPresentNoReuse { identity: String },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyRole {
    Semantic,
    Execution,
    GeneratedBaseline,
    ExternalContract,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyUse {
    pub node: String,
    pub role: DependencyRole,
    pub purpose: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CacheDependencyEvidence {
    Complete { projection: DependencyProjection },
    LegacyOpaqueCache { key: String },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangedNodeKind {
    Artifact,
    Resolution,
    Environment,
    Tool,
    Contract,
    Platform,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedNode {
    pub kind: ChangedNodeKind,
    pub selector: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationPath {
    pub dependency: String,
    pub unit: String,
    pub claim: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationTrace {
    pub schema: String,
    pub changed_nodes: Vec<ChangedNode>,
    pub invalidated_units: Vec<String>,
    pub affected_claims: Vec<String>,
    pub paths: Vec<InvalidationPath>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationExecutionReport {
    pub schema: String,
    pub experiment: String,
    pub programme_experiment: String,
    pub source_revision: String,
    pub projection_count: usize,
    pub scenario_count: usize,
    pub projections: Vec<DependencyProjection>,
    pub scenarios: Vec<InvalidationScenarioResult>,
    pub metrics: InvalidationMetrics,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationScenarioResult {
    pub scenario: String,
    pub class: String,
    pub scope: String,
    pub scope_units: Vec<String>,
    pub predicted_invalidated: Vec<String>,
    pub registered_invalidated: Vec<String>,
    pub exact: bool,
    pub precision: ExactRatio,
    pub recall: ExactRatio,
    pub avoided_units: usize,
    pub trace: InvalidationTrace,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidationMetrics {
    pub exact_scenarios: usize,
    pub stale_retention: usize,
    pub overinvalidating_scenarios: usize,
    pub invalidated_unit_events: usize,
    pub explanation_coverage: ExactRatio,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactRatio {
    pub numerator: usize,
    pub denominator: usize,
}

impl DependencyNode {
    pub fn id(&self) -> &str {
        match self {
            Self::Artifact { id, .. }
            | Self::Resolution { id, .. }
            | Self::Environment { id, .. }
            | Self::Tool { id, .. }
            | Self::Contract { id, .. }
            | Self::Platform { id, .. } => id,
        }
    }

    pub fn selector(&self) -> &str {
        match self {
            Self::Artifact { selector, .. }
            | Self::Resolution { selector, .. }
            | Self::Environment { selector, .. }
            | Self::Tool { selector, .. }
            | Self::Contract { selector, .. }
            | Self::Platform { selector, .. } => selector,
        }
    }

    pub fn changed_kind(&self) -> ChangedNodeKind {
        match self {
            Self::Artifact { .. } => ChangedNodeKind::Artifact,
            Self::Resolution { .. } => ChangedNodeKind::Resolution,
            Self::Environment { .. } => ChangedNodeKind::Environment,
            Self::Tool { .. } => ChangedNodeKind::Tool,
            Self::Contract { .. } => ChangedNodeKind::Contract,
            Self::Platform { .. } => ChangedNodeKind::Platform,
        }
    }
}

impl DependencyProjection {
    pub fn new(
        unit: impl Into<String>,
        route: impl Into<String>,
        source_revision: impl Into<String>,
        mut claims: Vec<String>,
        mut nodes: Vec<DependencyNode>,
        mut uses: Vec<DependencyUse>,
    ) -> Result<Self, IrValidationError> {
        claims.sort();
        nodes.sort_by(|left, right| left.id().cmp(right.id()));
        uses.sort();
        let reuse_allowed = !nodes.iter().any(|node| {
            matches!(
                node,
                DependencyNode::Environment {
                    state: EnvironmentState::SecretPresentNoReuse { .. },
                    ..
                }
            )
        });
        let mut projection = Self {
            schema: DEPENDENCY_PROJECTION_SCHEMA.to_owned(),
            unit: unit.into(),
            route: route.into(),
            source_revision: source_revision.into(),
            claims,
            nodes,
            uses,
            reuse_allowed,
            identity: String::new(),
        };
        projection.identity = projection.derived_identity()?;
        validate_dependency_projection(&projection)?;
        Ok(projection)
    }

    pub fn derived_identity(&self) -> Result<String, IrValidationError> {
        let mut value = serde_json::to_value(self).map_err(json_error)?;
        value
            .as_object_mut()
            .expect("serialized projection is an object")
            .remove("identity");
        let bytes = canonical_json(&value).map_err(json_error)?;
        Ok(domain_hash(DEPENDENCY_PROJECTION_DOMAIN, &bytes))
    }
}

impl InvalidationTrace {
    pub fn derived_identity(&self) -> Result<String, IrValidationError> {
        let mut value = serde_json::to_value(self).map_err(json_error)?;
        value
            .as_object_mut()
            .expect("serialized trace is an object")
            .remove("identity");
        let bytes = canonical_json(&value).map_err(json_error)?;
        Ok(domain_hash(INVALIDATION_TRACE_DOMAIN, &bytes))
    }
}

pub fn dependency_node_id(kind: ChangedNodeKind, selector: &str) -> String {
    let kind = serde_json::to_string(&kind).expect("changed-node kind serializes");
    domain_hash(
        "proofbound-ir-dependency-node/1",
        format!("{}\0{selector}", kind.trim_matches('"')).as_bytes(),
    )
}

pub fn validate_dependency_projection(
    projection: &DependencyProjection,
) -> Result<(), IrValidationError> {
    if projection.schema != DEPENDENCY_PROJECTION_SCHEMA {
        return invalid(
            "IR-DEPENDENCY-OPAQUE",
            "unknown dependency projection schema",
        );
    }
    bounded_text(&projection.unit)?;
    bounded_text(&projection.route)?;
    require_digest(&projection.source_revision)?;
    require_sorted_unique_text(&projection.claims)?;
    if projection.claims.is_empty() {
        return invalid("IR-DEPENDENCY-BINDING-MISMATCH", "projection has no claims");
    }
    if projection.nodes.is_empty() {
        return invalid(
            "IR-DEPENDENCY-OMITTED",
            "projection has no dependency nodes",
        );
    }
    if projection
        .nodes
        .windows(2)
        .any(|pair| pair[0].id() == pair[1].id())
    {
        return invalid("IR-DEPENDENCY-DUPLICATE", "duplicate dependency node");
    }
    if projection
        .nodes
        .windows(2)
        .any(|pair| pair[0].id() > pair[1].id())
    {
        return invalid(
            "IR-DEPENDENCY-NONCANONICAL",
            "dependency nodes must be sorted and unique by ID",
        );
    }
    let mut node_ids = BTreeSet::new();
    for node in &projection.nodes {
        validate_node(node)?;
        if !node_ids.insert(node.id()) {
            return invalid("IR-DEPENDENCY-DUPLICATE", "duplicate dependency node");
        }
    }
    if projection.uses.is_empty() {
        return invalid("IR-DEPENDENCY-OMITTED", "projection has no dependency uses");
    }
    if projection.uses.windows(2).any(|pair| pair[0] == pair[1]) {
        return invalid("IR-DEPENDENCY-DUPLICATE", "duplicate dependency use");
    }
    if projection.uses.windows(2).any(|pair| pair[0] > pair[1]) {
        return invalid(
            "IR-DEPENDENCY-NONCANONICAL",
            "dependency uses must be sorted and unique",
        );
    }
    for dependency_use in &projection.uses {
        if !node_ids.contains(dependency_use.node.as_str()) {
            return invalid(
                "IR-DEPENDENCY-OMITTED",
                "dependency use references a missing node",
            );
        }
        bounded_text(&dependency_use.purpose)?;
    }
    let secret_present = projection.nodes.iter().any(|node| {
        matches!(
            node,
            DependencyNode::Environment {
                state: EnvironmentState::SecretPresentNoReuse { .. },
                ..
            }
        )
    });
    if secret_present && projection.reuse_allowed {
        return invalid(
            "IR-DEPENDENCY-SECRET-REUSE",
            "secret-bearing environment state cannot be reusable",
        );
    }
    if projection.identity != projection.derived_identity()? {
        return invalid(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "dependency projection identity does not match its content",
        );
    }
    Ok(())
}

pub fn validate_cache_dependency_evidence(
    evidence: &CacheDependencyEvidence,
    reuse_requested: bool,
) -> Result<(), IrValidationError> {
    match evidence {
        CacheDependencyEvidence::Complete { projection } => {
            validate_dependency_projection(projection)?;
            if reuse_requested && !projection.reuse_allowed {
                return invalid(
                    "IR-DEPENDENCY-SECRET-REUSE",
                    "projection is explicitly ineligible for reuse",
                );
            }
        }
        CacheDependencyEvidence::LegacyOpaqueCache { key } => {
            require_digest(key)?;
            if reuse_requested {
                return invalid(
                    "IR-DEPENDENCY-OPAQUE",
                    "an opaque legacy cache key cannot independently authorize reuse",
                );
            }
        }
    }
    Ok(())
}

pub fn validate_projection_against_source(
    source: &DependencyProjection,
    claimed: &DependencyProjection,
) -> Result<(), IrValidationError> {
    validate_dependency_projection(source)?;
    validate_dependency_projection(claimed)?;
    if source.unit != claimed.unit
        || source.route != claimed.route
        || source.source_revision != claimed.source_revision
        || source.claims != claimed.claims
    {
        return invalid(
            "IR-DEPENDENCY-BINDING-MISMATCH",
            "projection binding differs from its source",
        );
    }
    let source_nodes = source
        .nodes
        .iter()
        .map(|node| (node.id(), node))
        .collect::<BTreeMap<_, _>>();
    let claimed_nodes = claimed
        .nodes
        .iter()
        .map(|node| (node.id(), node))
        .collect::<BTreeMap<_, _>>();
    let source_ids = source_nodes.keys().copied().collect::<BTreeSet<_>>();
    let claimed_ids = claimed_nodes.keys().copied().collect::<BTreeSet<_>>();
    if source_ids.is_subset(&claimed_ids) && source_ids != claimed_ids {
        return invalid(
            "IR-DEPENDENCY-OVERINVALIDATION",
            "claimed projection adds a dependency absent from its source",
        );
    }
    if claimed_ids.is_subset(&source_ids) && source_ids != claimed_ids {
        return invalid(
            "IR-DEPENDENCY-OMITTED",
            "claimed projection omits a source dependency",
        );
    }
    if source_ids != claimed_ids {
        return invalid(
            "IR-DEPENDENCY-ROLE-MISMATCH",
            "claimed projection substitutes its dependency inventory",
        );
    }
    for (id, source_node) in source_nodes {
        let claimed_node = claimed_nodes[id];
        if source_node.changed_kind() != claimed_node.changed_kind()
            || source_node.selector() != claimed_node.selector()
        {
            return invalid(
                "IR-DEPENDENCY-ROLE-MISMATCH",
                "dependency kind or selector differs from its source",
            );
        }
        if source_node != claimed_node {
            return invalid(
                node_mismatch_code(source_node, claimed_node),
                "dependency value differs from source",
            );
        }
    }
    if source.uses != claimed.uses {
        return invalid(
            "IR-DEPENDENCY-ROLE-MISMATCH",
            "dependency uses differ from their source",
        );
    }
    if source.reuse_allowed != claimed.reuse_allowed {
        return invalid(
            "IR-DEPENDENCY-SECRET-REUSE",
            "reuse eligibility differs from its source",
        );
    }
    Ok(())
}

pub fn derive_invalidation_trace(
    projections: &[DependencyProjection],
    mut changed_nodes: Vec<ChangedNode>,
) -> Result<InvalidationTrace, IrValidationError> {
    if changed_nodes.is_empty() {
        return invalid("IR-DEPENDENCY-OMITTED", "invalidation has no changed node");
    }
    changed_nodes.sort();
    if changed_nodes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(
            "IR-DEPENDENCY-DUPLICATE",
            "changed-node set contains a duplicate",
        );
    }
    let changed_ids = changed_nodes
        .iter()
        .map(|changed| dependency_node_id(changed.kind.clone(), &changed.selector))
        .collect::<BTreeSet<_>>();
    let mut invalidated_units = BTreeSet::new();
    let mut affected_claims = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for projection in projections {
        validate_dependency_projection(projection)?;
        let used = projection
            .uses
            .iter()
            .filter(|dependency_use| changed_ids.contains(&dependency_use.node))
            .map(|dependency_use| dependency_use.node.clone())
            .collect::<BTreeSet<_>>();
        if used.is_empty() {
            continue;
        }
        invalidated_units.insert(projection.unit.clone());
        for claim in &projection.claims {
            affected_claims.insert(claim.clone());
            for dependency in &used {
                paths.insert(InvalidationPath {
                    dependency: dependency.clone(),
                    unit: projection.unit.clone(),
                    claim: claim.clone(),
                });
            }
        }
    }
    let mut trace = InvalidationTrace {
        schema: INVALIDATION_TRACE_SCHEMA.to_owned(),
        changed_nodes,
        invalidated_units: invalidated_units.into_iter().collect(),
        affected_claims: affected_claims.into_iter().collect(),
        paths: paths.into_iter().collect(),
        identity: String::new(),
    };
    trace.identity = trace.derived_identity()?;
    validate_invalidation_trace(projections, &trace)?;
    Ok(trace)
}

pub fn validate_invalidation_trace(
    projections: &[DependencyProjection],
    trace: &InvalidationTrace,
) -> Result<(), IrValidationError> {
    if trace.schema != INVALIDATION_TRACE_SCHEMA {
        return invalid("IR-DEPENDENCY-OPAQUE", "unknown invalidation trace schema");
    }
    let derived = derive_trace_without_validation(projections, trace.changed_nodes.clone())?;
    if derived.invalidated_units != trace.invalidated_units
        || derived.affected_claims != trace.affected_claims
        || derived.paths != trace.paths
    {
        return invalid(
            "IR-DEPENDENCY-STALE-KEY",
            "reported invalidation differs from dependency-derived invalidation",
        );
    }
    if trace.identity != trace.derived_identity()? {
        return invalid(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "invalidation trace identity does not match its content",
        );
    }
    Ok(())
}

pub fn validate_invalidation_execution_report(
    bytes: &[u8],
) -> Result<InvalidationExecutionReport, IrValidationError> {
    let value = decode_strict_json(bytes)?;
    if canonical_json(&value).map_err(json_error)? != bytes {
        return invalid(
            "IR-DEPENDENCY-NONCANONICAL",
            "invalidation execution report is not canonical JSON",
        );
    }
    let report: InvalidationExecutionReport = serde_json::from_value(value)
        .map_err(|error| IrValidationError::new("IR-DEPENDENCY-OPAQUE", error.to_string()))?;
    if report.schema != "proofbound-research-invalidation-execution/1"
        || report.experiment != "EXP-0010"
        || report.programme_experiment != "EXP-LANG-003"
    {
        return invalid(
            "IR-DEPENDENCY-OPAQUE",
            "unknown invalidation execution report",
        );
    }
    require_digest(&report.source_revision)?;
    if report.projection_count != report.projections.len()
        || report.scenario_count != report.scenarios.len()
    {
        return invalid(
            "IR-DEPENDENCY-BINDING-MISMATCH",
            "reported corpus counts differ from retained records",
        );
    }
    let mut projections = BTreeMap::new();
    for projection in &report.projections {
        validate_dependency_projection(projection)?;
        if projections.insert(&projection.unit, projection).is_some() {
            return invalid("IR-DEPENDENCY-DUPLICATE", "duplicate projected unit");
        }
    }
    if report
        .projections
        .windows(2)
        .any(|pair| pair[0].unit >= pair[1].unit)
    {
        return invalid(
            "IR-DEPENDENCY-NONCANONICAL",
            "projected units are not in canonical order",
        );
    }

    let mut exact_scenarios = 0;
    let mut stale_retention = 0;
    let mut overinvalidating_scenarios = 0;
    let mut invalidated_unit_events = 0;
    let mut explained_unit_events = 0;
    for scenario in &report.scenarios {
        bounded_text(&scenario.scenario)?;
        bounded_text(&scenario.class)?;
        bounded_text(&scenario.scope)?;
        require_sorted_unique_text(&scenario.scope_units)?;
        require_sorted_unique_text(&scenario.predicted_invalidated)?;
        require_sorted_unique_text(&scenario.registered_invalidated)?;
        let scoped = scenario
            .scope_units
            .iter()
            .map(|unit| {
                projections.get(unit).copied().ok_or_else(|| {
                    IrValidationError::new(
                        "IR-DEPENDENCY-BINDING-MISMATCH",
                        "scenario scope references an unknown unit",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let scoped = scoped.into_iter().cloned().collect::<Vec<_>>();
        validate_invalidation_trace(&scoped, &scenario.trace)?;
        if scenario.predicted_invalidated != scenario.trace.invalidated_units {
            return invalid(
                "IR-DEPENDENCY-STALE-KEY",
                "predicted invalidation differs from the retained trace",
            );
        }
        let predicted = scenario
            .predicted_invalidated
            .iter()
            .collect::<BTreeSet<_>>();
        let registered = scenario
            .registered_invalidated
            .iter()
            .collect::<BTreeSet<_>>();
        let intersection = predicted.intersection(&registered).count();
        let precision = exact_ratio(intersection, predicted.len());
        let recall = exact_ratio(intersection, registered.len());
        let exact = predicted == registered;
        if scenario.exact != exact
            || scenario.precision != precision
            || scenario.recall != recall
            || scenario.avoided_units != scenario.scope_units.len() - predicted.len()
        {
            return invalid(
                "IR-DEPENDENCY-STALE-KEY",
                "scenario metrics differ from retained invalidation sets",
            );
        }
        exact_scenarios += usize::from(exact);
        stale_retention += usize::from(!registered.is_subset(&predicted));
        overinvalidating_scenarios += usize::from(!predicted.is_subset(&registered));
        invalidated_unit_events += predicted.len();
        let explained_units = scenario
            .trace
            .paths
            .iter()
            .map(|path| &path.unit)
            .collect::<BTreeSet<_>>();
        explained_unit_events += predicted.intersection(&explained_units).count();
    }
    if report
        .scenarios
        .windows(2)
        .any(|pair| pair[0].scenario >= pair[1].scenario)
    {
        return invalid(
            "IR-DEPENDENCY-NONCANONICAL",
            "scenario results are not in canonical order",
        );
    }
    let explanation_coverage = exact_ratio(explained_unit_events, invalidated_unit_events);
    let expected_metrics = InvalidationMetrics {
        exact_scenarios,
        stale_retention,
        overinvalidating_scenarios,
        invalidated_unit_events,
        explanation_coverage,
    };
    if report.metrics != expected_metrics {
        return invalid(
            "IR-DEPENDENCY-STALE-KEY",
            "summary metrics differ from independently recomputed results",
        );
    }
    Ok(report)
}

fn exact_ratio(numerator: usize, denominator: usize) -> ExactRatio {
    if denominator == 0 {
        ExactRatio {
            numerator: 1,
            denominator: 1,
        }
    } else {
        ExactRatio {
            numerator,
            denominator,
        }
    }
}

fn derive_trace_without_validation(
    projections: &[DependencyProjection],
    changed_nodes: Vec<ChangedNode>,
) -> Result<InvalidationTrace, IrValidationError> {
    let changed_ids = changed_nodes
        .iter()
        .map(|changed| dependency_node_id(changed.kind.clone(), &changed.selector))
        .collect::<BTreeSet<_>>();
    let mut units = BTreeSet::new();
    let mut claims = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for projection in projections {
        validate_dependency_projection(projection)?;
        for dependency_use in &projection.uses {
            if !changed_ids.contains(&dependency_use.node) {
                continue;
            }
            units.insert(projection.unit.clone());
            for claim in &projection.claims {
                claims.insert(claim.clone());
                paths.insert(InvalidationPath {
                    dependency: dependency_use.node.clone(),
                    unit: projection.unit.clone(),
                    claim: claim.clone(),
                });
            }
        }
    }
    let mut result = InvalidationTrace {
        schema: INVALIDATION_TRACE_SCHEMA.to_owned(),
        changed_nodes,
        invalidated_units: units.into_iter().collect(),
        affected_claims: claims.into_iter().collect(),
        paths: paths.into_iter().collect(),
        identity: String::new(),
    };
    result.identity = result.derived_identity()?;
    Ok(result)
}

fn validate_node(node: &DependencyNode) -> Result<(), IrValidationError> {
    bounded_selector(node.selector())?;
    let expected = dependency_node_id(node.changed_kind(), node.selector());
    if node.id() != expected {
        return invalid(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "dependency node ID does not match kind and selector",
        );
    }
    match node {
        DependencyNode::Artifact {
            sha256,
            permissions,
            ..
        } => {
            require_digest(sha256)?;
            validate_permissions(permissions)?;
        }
        DependencyNode::Resolution { candidates, .. } => {
            if candidates.is_empty() {
                return invalid(
                    "IR-DEPENDENCY-RESOLUTION-MISMATCH",
                    "resolution node has no candidates",
                );
            }
            if candidates.windows(2).any(|pair| pair[0] >= pair[1]) {
                return invalid(
                    "IR-DEPENDENCY-NONCANONICAL",
                    "resolution candidates must be sorted and unique",
                );
            }
            for candidate in candidates {
                bounded_selector(&candidate.path)?;
                if let PathState::Present {
                    sha256,
                    permissions,
                    ..
                } = &candidate.state
                {
                    require_digest(sha256)?;
                    validate_permissions(permissions)?;
                }
            }
        }
        DependencyNode::Environment { state, .. } => match state {
            EnvironmentState::Absent => {}
            EnvironmentState::ValueDigest { sha256 } => require_digest(sha256)?,
            EnvironmentState::SecretPresentNoReuse { identity } => require_digest(identity)?,
        },
        DependencyNode::Tool {
            executable_sha256,
            version_identity,
            ..
        } => {
            require_digest(executable_sha256)?;
            require_digest(version_identity)?;
        }
        DependencyNode::Contract {
            contract_schema,
            contract_identity,
            ..
        } => {
            bounded_text(contract_schema)?;
            require_digest(contract_identity)?;
        }
        DependencyNode::Platform {
            operating_system,
            architecture,
            ..
        } => {
            bounded_text(operating_system)?;
            bounded_text(architecture)?;
        }
    }
    Ok(())
}

fn node_mismatch_code(source: &DependencyNode, claimed: &DependencyNode) -> &'static str {
    match (source, claimed) {
        (
            DependencyNode::Artifact {
                permissions: source_permissions,
                ..
            },
            DependencyNode::Artifact {
                permissions: claimed_permissions,
                ..
            },
        ) if source_permissions != claimed_permissions => "IR-DEPENDENCY-PERMISSION-MISMATCH",
        (DependencyNode::Artifact { .. }, DependencyNode::Artifact { .. })
        | (DependencyNode::Contract { .. }, DependencyNode::Contract { .. })
        | (DependencyNode::Platform { .. }, DependencyNode::Platform { .. }) => {
            "IR-DEPENDENCY-IDENTITY-MISMATCH"
        }
        (DependencyNode::Resolution { .. }, DependencyNode::Resolution { .. }) => {
            "IR-DEPENDENCY-RESOLUTION-MISMATCH"
        }
        (DependencyNode::Environment { .. }, DependencyNode::Environment { .. }) => {
            "IR-DEPENDENCY-ENVIRONMENT-MISMATCH"
        }
        (DependencyNode::Tool { .. }, DependencyNode::Tool { .. }) => "IR-DEPENDENCY-TOOL-MISMATCH",
        _ => "IR-DEPENDENCY-ROLE-MISMATCH",
    }
}

fn validate_permissions(permissions: &PermissionModel) -> Result<(), IrValidationError> {
    if let PermissionModel::UnixMode { mode } = permissions
        && *mode > 0o7777
    {
        return invalid(
            "IR-DEPENDENCY-PERMISSION-MISMATCH",
            "Unix permission mode exceeds 0o7777",
        );
    }
    Ok(())
}

fn bounded_text(value: &str) -> Result<(), IrValidationError> {
    if value.trim().is_empty()
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return invalid("IR-DEPENDENCY-OPAQUE", "invalid bounded dependency text");
    }
    Ok(())
}

fn bounded_selector(value: &str) -> Result<(), IrValidationError> {
    bounded_text(value)?;
    if value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return invalid("IR-DEPENDENCY-UNSAFE-PATH", "unsafe dependency selector");
    }
    Ok(())
}

fn require_digest(value: &str) -> Result<(), IrValidationError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return invalid(
            "IR-DEPENDENCY-IDENTITY-MISMATCH",
            "invalid SHA-256 identity",
        );
    }
    Ok(())
}

fn require_sorted_unique_text(values: &[String]) -> Result<(), IrValidationError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(
            "IR-DEPENDENCY-NONCANONICAL",
            "set-like text must be sorted and unique",
        );
    }
    for value in values {
        bounded_text(value)?;
    }
    Ok(())
}

fn invalid<T>(code: &'static str, message: &str) -> Result<T, IrValidationError> {
    Err(IrValidationError::new(code, message))
}

fn json_error(error: impl std::fmt::Display) -> IrValidationError {
    IrValidationError::new("IR-DEPENDENCY-OPAQUE", error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde_json::Value;

    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn artifact(selector: &str) -> DependencyNode {
        DependencyNode::Artifact {
            id: dependency_node_id(ChangedNodeKind::Artifact, selector),
            selector: selector.to_owned(),
            sha256: digest('1'),
            size_bytes: 7,
            permissions: PermissionModel::UnixMode { mode: 0o644 },
        }
    }

    fn projection() -> DependencyProjection {
        let node = artifact("python-controlled/src/value.py");
        DependencyProjection::new(
            "unit-a",
            "python-pytest",
            digest('2'),
            vec!["CLAIM-A".to_owned()],
            vec![node.clone()],
            vec![DependencyUse {
                node: node.id().to_owned(),
                role: DependencyRole::Semantic,
                purpose: "execute registered test".to_owned(),
            }],
        )
        .unwrap()
    }

    fn rich_projection() -> DependencyProjection {
        let artifact = artifact("python-controlled/src/value.py");
        let resolution_selector = "python-controlled/python-module:plugin";
        let resolution = DependencyNode::Resolution {
            id: dependency_node_id(ChangedNodeKind::Resolution, resolution_selector),
            selector: resolution_selector.to_owned(),
            candidates: vec![ResolutionCandidate {
                path: "python-controlled/plugin.py".to_owned(),
                state: PathState::Absent,
            }],
        };
        let environment_selector = "python-controlled/PATH";
        let environment = DependencyNode::Environment {
            id: dependency_node_id(ChangedNodeKind::Environment, environment_selector),
            selector: environment_selector.to_owned(),
            state: EnvironmentState::Absent,
        };
        let tool_selector = "python-controlled/python";
        let tool = DependencyNode::Tool {
            id: dependency_node_id(ChangedNodeKind::Tool, tool_selector),
            selector: tool_selector.to_owned(),
            executable_sha256: digest('7'),
            version_identity: digest('8'),
        };
        let contract_selector = "python-controlled/unit#artifact-sha256";
        let contract = DependencyNode::Contract {
            id: dependency_node_id(ChangedNodeKind::Contract, contract_selector),
            selector: contract_selector.to_owned(),
            contract_schema: "proofbound-contract/1".to_owned(),
            contract_identity: digest('9'),
        };
        let platform_selector = "python-controlled/platform";
        let platform = DependencyNode::Platform {
            id: dependency_node_id(ChangedNodeKind::Platform, platform_selector),
            selector: platform_selector.to_owned(),
            operating_system: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
        };
        let nodes = vec![artifact, resolution, environment, tool, contract, platform];
        let uses = nodes
            .iter()
            .map(|node| DependencyUse {
                node: node.id().to_owned(),
                role: DependencyRole::Execution,
                purpose: "execute registered unit".to_owned(),
            })
            .collect();
        DependencyProjection::new(
            "unit-a",
            "python-pytest",
            digest('2'),
            vec!["CLAIM-A".to_owned()],
            nodes,
            uses,
        )
        .unwrap()
    }

    fn refresh(projection: &mut DependencyProjection) {
        projection.identity = projection.derived_identity().unwrap();
    }

    #[test]
    fn derives_exact_invalidation_paths() {
        let projection = projection();
        let trace = derive_invalidation_trace(
            &[projection],
            vec![ChangedNode {
                kind: ChangedNodeKind::Artifact,
                selector: "python-controlled/src/value.py".to_owned(),
            }],
        )
        .unwrap();
        assert_eq!(trace.invalidated_units, ["unit-a"]);
        assert_eq!(trace.affected_claims, ["CLAIM-A"]);
        assert_eq!(trace.paths.len(), 1);
    }

    #[test]
    fn legacy_cache_never_authorizes_independent_reuse() {
        let legacy = CacheDependencyEvidence::LegacyOpaqueCache { key: digest('3') };
        validate_cache_dependency_evidence(&legacy, false).unwrap();
        assert_eq!(
            validate_cache_dependency_evidence(&legacy, true)
                .unwrap_err()
                .code,
            "IR-DEPENDENCY-OPAQUE"
        );
    }

    #[test]
    fn rejects_registered_source_substitutions() {
        let source = projection();

        let mut omitted = source.clone();
        omitted.nodes.clear();
        omitted.uses.clear();
        refresh(&mut omitted);
        assert_eq!(
            validate_projection_against_source(&source, &omitted)
                .unwrap_err()
                .code,
            "IR-DEPENDENCY-OMITTED"
        );

        let mut rebound = source.clone();
        rebound.unit = "unit-b".to_owned();
        refresh(&mut rebound);
        assert_eq!(
            validate_projection_against_source(&source, &rebound)
                .unwrap_err()
                .code,
            "IR-DEPENDENCY-BINDING-MISMATCH"
        );

        let mut changed = source.clone();
        if let DependencyNode::Artifact { sha256, .. } = &mut changed.nodes[0] {
            *sha256 = digest('4');
        }
        refresh(&mut changed);
        assert_eq!(
            validate_projection_against_source(&source, &changed)
                .unwrap_err()
                .code,
            "IR-DEPENDENCY-IDENTITY-MISMATCH"
        );
    }

    #[test]
    fn secret_environment_forces_non_reuse() {
        let node = DependencyNode::Environment {
            id: dependency_node_id(ChangedNodeKind::Environment, "project/API_TOKEN"),
            selector: "project/API_TOKEN".to_owned(),
            state: EnvironmentState::SecretPresentNoReuse {
                identity: digest('5'),
            },
        };
        let projection = DependencyProjection::new(
            "unit-secret",
            "independent-check",
            digest('6'),
            vec!["CLAIM-A".to_owned()],
            vec![node.clone()],
            vec![DependencyUse {
                node: node.id().to_owned(),
                role: DependencyRole::Execution,
                purpose: "read secret".to_owned(),
            }],
        )
        .unwrap();
        assert!(!projection.reuse_allowed);
    }

    #[test]
    fn rejects_all_preregistered_invalidation_attacks_with_exact_codes() {
        let source = rich_projection();
        let mut actual = BTreeMap::new();

        let mut omitted = source.clone();
        let removed = omitted.nodes.remove(0);
        omitted.uses.retain(|item| item.node != removed.id());
        refresh(&mut omitted);
        actual.insert(
            "INV-001",
            validate_projection_against_source(&source, &omitted)
                .unwrap_err()
                .code,
        );

        let mut role = source.clone();
        role.uses[0].role = DependencyRole::Semantic;
        role.uses.sort();
        refresh(&mut role);
        actual.insert(
            "INV-002",
            validate_projection_against_source(&source, &role)
                .unwrap_err()
                .code,
        );

        let mut bytes = source.clone();
        let changed_artifact = bytes
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Artifact { .. }))
            .unwrap();
        if let DependencyNode::Artifact { sha256, .. } = changed_artifact {
            *sha256 = digest('a');
        }
        refresh(&mut bytes);
        actual.insert(
            "INV-003",
            validate_projection_against_source(&source, &bytes)
                .unwrap_err()
                .code,
        );

        let mut mode = source.clone();
        let mode_artifact = mode
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Artifact { .. }))
            .unwrap();
        if let DependencyNode::Artifact { permissions, .. } = mode_artifact {
            *permissions = PermissionModel::UnixMode { mode: 0o755 };
        }
        refresh(&mut mode);
        actual.insert(
            "INV-004",
            validate_projection_against_source(&source, &mode)
                .unwrap_err()
                .code,
        );

        let mut resolution = source.clone();
        let node = resolution
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Resolution { .. }))
            .unwrap();
        if let DependencyNode::Resolution { candidates, .. } = node {
            candidates[0].state = PathState::Present {
                sha256: digest('b'),
                size_bytes: 3,
                permissions: PermissionModel::UnixMode { mode: 0o644 },
            };
        }
        refresh(&mut resolution);
        actual.insert(
            "INV-005",
            validate_projection_against_source(&source, &resolution)
                .unwrap_err()
                .code,
        );

        let mut environment = source.clone();
        let node = environment
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Environment { .. }))
            .unwrap();
        if let DependencyNode::Environment { state, .. } = node {
            *state = EnvironmentState::ValueDigest {
                sha256: digest('c'),
            };
        }
        refresh(&mut environment);
        actual.insert(
            "INV-006",
            validate_projection_against_source(&source, &environment)
                .unwrap_err()
                .code,
        );

        let mut tool = source.clone();
        let node = tool
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Tool { .. }))
            .unwrap();
        if let DependencyNode::Tool {
            executable_sha256, ..
        } = node
        {
            *executable_sha256 = digest('d');
        }
        refresh(&mut tool);
        actual.insert(
            "INV-007",
            validate_projection_against_source(&source, &tool)
                .unwrap_err()
                .code,
        );

        let mut duplicate = source.clone();
        duplicate.nodes.push(duplicate.nodes[0].clone());
        duplicate
            .nodes
            .sort_by(|left, right| left.id().cmp(right.id()));
        refresh(&mut duplicate);
        actual.insert(
            "INV-008",
            validate_dependency_projection(&duplicate).unwrap_err().code,
        );

        let mut reordered = source.clone();
        reordered.nodes.swap(0, 1);
        refresh(&mut reordered);
        actual.insert(
            "INV-009",
            validate_dependency_projection(&reordered).unwrap_err().code,
        );

        let mut extra = source.clone();
        let extra_node = artifact("python-controlled/docs/presentation.md");
        extra.uses.push(DependencyUse {
            node: extra_node.id().to_owned(),
            role: DependencyRole::Execution,
            purpose: "invented execution input".to_owned(),
        });
        extra.nodes.push(extra_node);
        extra.nodes.sort_by(|left, right| left.id().cmp(right.id()));
        extra.uses.sort();
        refresh(&mut extra);
        actual.insert(
            "INV-010",
            validate_projection_against_source(&source, &extra)
                .unwrap_err()
                .code,
        );

        let mut rebound = source.clone();
        rebound.claims = vec!["CLAIM-B".to_owned()];
        refresh(&mut rebound);
        actual.insert(
            "INV-011",
            validate_projection_against_source(&source, &rebound)
                .unwrap_err()
                .code,
        );

        actual.insert(
            "INV-012",
            validate_cache_dependency_evidence(
                &CacheDependencyEvidence::LegacyOpaqueCache { key: digest('e') },
                true,
            )
            .unwrap_err()
            .code,
        );

        let mut trace = derive_invalidation_trace(
            std::slice::from_ref(&source),
            vec![ChangedNode {
                kind: ChangedNodeKind::Artifact,
                selector: "python-controlled/src/value.py".to_owned(),
            }],
        )
        .unwrap();
        trace.invalidated_units.clear();
        trace.identity = trace.derived_identity().unwrap();
        actual.insert(
            "INV-013",
            validate_invalidation_trace(std::slice::from_ref(&source), &trace)
                .unwrap_err()
                .code,
        );

        let mut secret = source.clone();
        let node = secret
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Environment { .. }))
            .unwrap();
        if let DependencyNode::Environment { state, .. } = node {
            *state = EnvironmentState::SecretPresentNoReuse {
                identity: digest('f'),
            };
        }
        secret.reuse_allowed = true;
        refresh(&mut secret);
        actual.insert(
            "INV-014",
            validate_dependency_projection(&secret).unwrap_err().code,
        );

        let mut unsafe_path = source;
        let node = unsafe_path
            .nodes
            .iter_mut()
            .find(|node| matches!(node, DependencyNode::Artifact { .. }))
            .unwrap();
        if let DependencyNode::Artifact { id, selector, .. } = node {
            *selector = "../escape".to_owned();
            *id = dependency_node_id(ChangedNodeKind::Artifact, selector);
        }
        unsafe_path
            .nodes
            .sort_by(|left, right| left.id().cmp(right.id()));
        refresh(&mut unsafe_path);
        actual.insert(
            "INV-015",
            validate_dependency_projection(&unsafe_path)
                .unwrap_err()
                .code,
        );

        let preregistration_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/experiments/0010-invalidation-precision/preregistration.json");
        let preregistration: Value =
            serde_json::from_slice(&fs::read(preregistration_path).unwrap()).unwrap();
        let expected = preregistration["attacks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|attack| {
                (
                    attack["id"].as_str().unwrap(),
                    attack["expected_code"].as_str().unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn matches_independent_python_canonical_vector() {
        let projection = rich_projection();
        assert_eq!(
            projection.identity,
            "sha256:b96828804e3089507d3302aa98cf62853a4fa007932bd158bd89ac639a53f953"
        );
        let trace = derive_invalidation_trace(
            &[projection],
            vec![ChangedNode {
                kind: ChangedNodeKind::Artifact,
                selector: "python-controlled/src/value.py".to_owned(),
            }],
        )
        .unwrap();
        assert_eq!(
            trace.identity,
            "sha256:6c74e55ab257d8cd3995652ed770b1ccd0e0d71068d57a2157c950ab72dcc005"
        );
    }

    #[test]
    fn independently_validates_retained_invalidation_execution() {
        let report = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/experiments/0010-invalidation-precision/results/execution.json");
        let bytes = fs::read(report).unwrap();
        let execution = validate_invalidation_execution_report(&bytes).unwrap();
        assert_eq!(execution.projection_count, 19);
        assert_eq!(execution.scenario_count, 26);
        assert_eq!(execution.metrics.exact_scenarios, 26);
    }
}
