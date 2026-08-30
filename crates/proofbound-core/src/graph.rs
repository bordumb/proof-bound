//! Typed assurance graph and fail-closed cycle validation.

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

use crate::{
    EdgeKind, EnvironmentId, ErrorCode, NodeId, NodeKind, StructuredError, ValidationErrors,
};

pub const GRAPH_SCHEMA_V1: &str = "proofbound-graph/1";

/// One typed graph node. Proof-environment identity is required only for
/// theorem nodes and is what bounds the sole allowed cycle form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub id: NodeId,
    pub kind: NodeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_environment: Option<EnvironmentId>,
}

mod sealed {
    pub trait NodeMarker {}
    pub trait EdgeMarker {}
}

/// A compile-time marker for one [`NodeKind`].
///
/// This trait is sealed: callers can use the marker types in
/// [`node_types`], but cannot invent a marker that lies about its runtime
/// node kind.
pub trait NodeMarker: sealed::NodeMarker {
    const KIND: NodeKind;
}

/// A compile-time marker for one [`EdgeKind`].
///
/// This trait is sealed for the same reason as [`NodeMarker`].
pub trait EdgeMarker: sealed::EdgeMarker {
    const KIND: EdgeKind;
}

/// Compile-time evidence that edge marker `Self` permits `From -> To`.
///
/// Implementations are supplied only by Proofbound's central endpoint table.
pub trait AllowedEdge<From: NodeMarker, To: NodeMarker>: EdgeMarker {}

macro_rules! define_node_markers {
    ($($marker:ident => $kind:ident),+ $(,)?) => {
        /// Marker types used by the construction-time graph API.
        pub mod node_types {
            use super::{NodeKind, NodeMarker, sealed};

            $(
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub struct $marker;

                impl sealed::NodeMarker for $marker {}

                impl NodeMarker for $marker {
                    const KIND: NodeKind = NodeKind::$kind;
                }
            )+
        }
    };
}

define_node_markers! {
    Claim => Claim,
    Theorem => Theorem,
    Subject => Subject,
    Artifact => Artifact,
    SourceClosure => SourceClosure,
    TranslationUnit => TranslationUnit,
    ModelCheckUnit => ModelCheckUnit,
    TestSuite => TestSuite,
    Assumption => Assumption,
    Premise => Premise,
    Toolchain => Toolchain,
    TcbComponent => TcbComponent,
    Review => Review,
    Policy => Policy,
}

macro_rules! define_edge_markers {
    ($($marker:ident => $kind:ident),+ $(,)?) => {
        /// Marker types used to select an edge in [`GraphEdge::typed`].
        pub mod edge_types {
            use super::{EdgeKind, EdgeMarker, sealed};

            $(
                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                pub struct $marker;

                impl sealed::EdgeMarker for $marker {}

                impl EdgeMarker for $marker {
                    const KIND: EdgeKind = EdgeKind::$kind;
                }
            )+
        }
    };
}

define_edge_markers! {
    Proves => Proves,
    Refines => Refines,
    Decodes => Decodes,
    Checks => Checks,
    GeneratedFrom => GeneratedFrom,
    DependsOn => DependsOn,
    Assumes => Assumes,
    DischargedBy => DischargedBy,
    CrossChecks => CrossChecks,
    CoversBoundedDomain => CoversBoundedDomain,
    BindsDigest => BindsDigest,
    ReviewedBy => ReviewedBy,
    AdmittedByPolicy => AdmittedByPolicy,
}

macro_rules! edge_endpoint_table {
    ($($edge:ident => [$(($from:ident, $to:ident)),+ $(,)?]),+ $(,)?) => {
        impl EdgeKind {
            /// Whether this edge kind may connect the two runtime node kinds.
            ///
            /// This match is intentionally exhaustive over `EdgeKind`: adding
            /// a new edge vocabulary item cannot compile until its endpoint
            /// contract is decided here.
            #[must_use]
            pub const fn allows_endpoints(self, from: NodeKind, to: NodeKind) -> bool {
                match self {
                    $(
                        Self::$edge => matches!(
                            (from, to),
                            $((NodeKind::$from, NodeKind::$to))|+
                        ),
                    )+
                }
            }
        }

        /// The canonical runtime projection of the typed endpoint contract.
        pub const EDGE_ENDPOINT_RULES: &[(EdgeKind, NodeKind, NodeKind)] = &[
            $($(
                (EdgeKind::$edge, NodeKind::$from, NodeKind::$to),
            )+)+
        ];

        $($(
            impl AllowedEdge<node_types::$from, node_types::$to>
                for edge_types::$edge {}
        )+)+
    };
}

edge_endpoint_table! {
    Proves => [(Theorem, Claim)],
    Refines => [(TranslationUnit, Claim)],
    Decodes => [(Artifact, Claim)],
    Checks => [(TestSuite, Claim), (ModelCheckUnit, Claim)],
    GeneratedFrom => [(Artifact, Subject)],
    DependsOn => [(Claim, Subject), (Subject, Artifact), (Theorem, Theorem)],
    Assumes => [
        (Claim, Assumption),
        (Claim, Premise),
        (Theorem, Premise),
        (Assumption, Claim),
        (Claim, Claim),
    ],
    DischargedBy => [(Premise, Theorem)],
    CrossChecks => [(TestSuite, Claim), (ModelCheckUnit, Claim)],
    CoversBoundedDomain => [(ModelCheckUnit, Claim)],
    BindsDigest => [(Artifact, Claim)],
    ReviewedBy => [(Review, Claim), (Assumption, Review)],
    AdmittedByPolicy => [(Claim, Policy)],
}

/// A node reference whose runtime kind has been checked against marker `K`.
#[derive(Clone, Copy, Debug)]
pub struct TypedNodeRef<'a, K: NodeMarker> {
    node: &'a GraphNode,
    marker: PhantomData<K>,
}

impl<'a, K: NodeMarker> TypedNodeRef<'a, K> {
    #[must_use]
    pub fn node(self) -> &'a GraphNode {
        self.node
    }
}

impl GraphNode {
    /// Obtains a typed view only when this node has marker `K`'s runtime kind.
    #[must_use]
    pub fn typed<K: NodeMarker>(&self) -> Option<TypedNodeRef<'_, K>> {
        (self.kind == K::KIND).then_some(TypedNodeRef {
            node: self,
            marker: PhantomData,
        })
    }
}

/// A rejected dynamic edge construction.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("edge {kind:?} cannot connect {from_kind:?} node '{from}' to {to_kind:?} node '{to}'")]
pub struct InvalidEdgeEndpoints {
    pub from: NodeId,
    pub from_kind: NodeKind,
    pub to: NodeId,
    pub to_kind: NodeKind,
    pub kind: EdgeKind,
}

/// One directed, typed graph edge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    from: NodeId,
    to: NodeId,
    kind: EdgeKind,
}

impl GraphEdge {
    /// Constructs an edge from compile-time typed endpoints.
    ///
    /// Illegal endpoint pairs have no [`AllowedEdge`] implementation and
    /// therefore fail to compile:
    ///
    /// ```compile_fail
    /// use proofbound_core::{
    ///     GraphEdge, GraphNode, NodeId, NodeKind, edge_types, node_types,
    /// };
    ///
    /// let tests = GraphNode {
    ///     id: NodeId::new("tests:unit").unwrap(),
    ///     kind: NodeKind::TestSuite,
    ///     proof_environment: None,
    /// };
    /// let toolchain = GraphNode {
    ///     id: NodeId::new("toolchain:rust").unwrap(),
    ///     kind: NodeKind::Toolchain,
    ///     proof_environment: None,
    /// };
    /// let tests = tests.typed::<node_types::TestSuite>().unwrap();
    /// let toolchain = toolchain.typed::<node_types::Toolchain>().unwrap();
    /// let _illegal = GraphEdge::typed::<edge_types::Proves, _, _>(tests, toolchain);
    /// ```
    #[must_use]
    pub fn typed<E, From, To>(from: TypedNodeRef<'_, From>, to: TypedNodeRef<'_, To>) -> Self
    where
        E: AllowedEdge<From, To>,
        From: NodeMarker,
        To: NodeMarker,
    {
        Self {
            from: from.node.id.clone(),
            to: to.node.id.clone(),
            kind: E::KIND,
        }
    }

    /// Constructs an edge from dynamic nodes after checking the same canonical
    /// endpoint table used by the typed API.
    pub fn checked(
        from: &GraphNode,
        to: &GraphNode,
        kind: EdgeKind,
    ) -> Result<Self, InvalidEdgeEndpoints> {
        if !kind.allows_endpoints(from.kind, to.kind) {
            return Err(InvalidEdgeEndpoints {
                from: from.id.clone(),
                from_kind: from.kind,
                to: to.id.clone(),
                to_kind: to.kind,
                kind,
            });
        }
        Ok(Self {
            from: from.id.clone(),
            to: to.id.clone(),
            kind,
        })
    }

    #[must_use]
    pub fn from(&self) -> &NodeId {
        &self.from
    }

    #[must_use]
    pub fn to(&self) -> &NodeId {
        &self.to
    }

    #[must_use]
    pub const fn kind(&self) -> EdgeKind {
        self.kind
    }
}

/// Explicit declaration of theorem nodes that are mutually dependent inside
/// one proof environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutualTheoremGroup {
    pub id: NodeId,
    pub proof_environment: EnvironmentId,
    pub members: BTreeSet<NodeId>,
}

/// Complete compiled assurance graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceGraph {
    pub schema: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(default)]
    pub mutual_theorem_groups: Vec<MutualTheoremGroup>,
}

impl AssuranceGraph {
    /// Validates node identity, all targets, mutual-group declarations, and
    /// every strongly connected component.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if self.schema != GRAPH_SCHEMA_V1 {
            errors.push(
                StructuredError::new(
                    ErrorCode::PbCoreUnsupportedSchema,
                    format!("unsupported assurance graph schema '{}'", self.schema),
                    "migrate the compiled graph to proofbound-graph/1",
                )
                .identities(GRAPH_SCHEMA_V1, &self.schema),
            );
        }

        let mut nodes = BTreeMap::new();
        for node in &self.nodes {
            if nodes.insert(node.id.clone(), node).is_some() {
                errors.push(StructuredError::new(
                    ErrorCode::PbCoreDuplicateId,
                    format!("duplicate graph node '{}'", node.id),
                    "give every graph node one unique stable ID",
                ));
            }
            match (node.kind, &node.proof_environment) {
                (NodeKind::Theorem, None) => errors.push(StructuredError::new(
                    ErrorCode::PbCoreInvalidNode,
                    format!("theorem node '{}' has no proof environment", node.id),
                    "bind every theorem to its compiled proof environment",
                )),
                (NodeKind::Theorem, Some(_)) | (_, None) => {}
                (_, Some(_)) => errors.push(StructuredError::new(
                    ErrorCode::PbCoreInvalidNode,
                    format!(
                        "non-theorem node '{}' declares a proof environment",
                        node.id
                    ),
                    "remove proof-environment metadata from non-theorem nodes",
                )),
            }
        }

        let mut edge_keys = BTreeSet::new();
        for edge in &self.edges {
            let (Some(from), Some(to)) = (nodes.get(&edge.from), nodes.get(&edge.to)) else {
                errors.push(StructuredError::new(
                    ErrorCode::PbCoreMissingTarget,
                    format!(
                        "edge '{} --{:?}--> {}' names a missing endpoint",
                        edge.from, edge.kind, edge.to
                    ),
                    "materialize both graph nodes before compiling the edge",
                ));
                continue;
            };
            if !edge.kind.allows_endpoints(from.kind, to.kind) {
                errors.push(StructuredError::new(
                    ErrorCode::PbCoreInvalidEdge,
                    format!(
                        "edge '{} --{:?}--> {}' illegally connects {:?} to {:?}",
                        edge.from, edge.kind, edge.to, from.kind, to.kind
                    ),
                    "construct the edge through Proofbound's typed or checked graph API",
                ));
            }
            if !edge_keys.insert((edge.from.clone(), edge.to.clone(), edge.kind)) {
                errors.push(StructuredError::new(
                    ErrorCode::PbCoreDuplicateId,
                    format!(
                        "duplicate graph edge '{} --{:?}--> {}'",
                        edge.from, edge.kind, edge.to
                    ),
                    "emit each semantic edge exactly once",
                ));
            }
        }

        let mut groups = BTreeMap::new();
        let mut grouped_members = BTreeSet::new();
        for group in &self.mutual_theorem_groups {
            if groups.insert(group.id.clone(), group).is_some() {
                errors.push(StructuredError::new(
                    ErrorCode::PbCoreDuplicateId,
                    format!("duplicate mutual theorem group '{}'", group.id),
                    "give every mutual theorem group a unique stable ID",
                ));
            }
            if group.members.len() < 2 {
                errors.push(StructuredError::new(
                    ErrorCode::PbCoreInvalidMutualTheoremGroup,
                    format!(
                        "mutual theorem group '{}' contains fewer than two members",
                        group.id
                    ),
                    "remove the declaration or enumerate the complete mutual dependency group",
                ));
            }
            for member in &group.members {
                if !grouped_members.insert(member.clone()) {
                    errors.push(StructuredError::new(
                        ErrorCode::PbCoreInvalidMutualTheoremGroup,
                        format!("theorem node '{member}' occurs in more than one mutual group"),
                        "declare one exact mutual-dependency group per theorem node",
                    ));
                }
                match nodes.get(member) {
                    Some(GraphNode {
                        kind: NodeKind::Theorem,
                        proof_environment: Some(environment),
                        ..
                    }) if environment == &group.proof_environment => {}
                    _ => errors.push(StructuredError::new(
                        ErrorCode::PbCoreInvalidMutualTheoremGroup,
                        format!(
                            "member '{member}' is missing, is not a theorem, or belongs to another proof environment"
                        ),
                        "restrict the group to theorem nodes in the declared environment",
                    )),
                }
            }
        }

        if errors
            .iter()
            .all(|error| error.code != ErrorCode::PbCoreMissingTarget)
        {
            let components = strongly_connected_components(&self.nodes, &self.edges);
            for component in components {
                let self_loop = component.len() == 1
                    && self
                        .edges
                        .iter()
                        .any(|edge| edge.from == component[0] && edge.to == component[0]);
                if component.len() == 1 && !self_loop {
                    continue;
                }
                let members = component.iter().cloned().collect::<BTreeSet<_>>();
                let allowed_group = self
                    .mutual_theorem_groups
                    .iter()
                    .find(|group| group.members == members);
                let all_dependency_edges = self
                    .edges
                    .iter()
                    .filter(|edge| members.contains(&edge.from) && members.contains(&edge.to))
                    .all(|edge| edge.kind == EdgeKind::DependsOn);
                let all_theorems_in_environment = allowed_group.is_some_and(|group| {
                    component.iter().all(|id| {
                        nodes.get(id).is_some_and(|node| {
                            node.kind == NodeKind::Theorem
                                && node.proof_environment.as_ref() == Some(&group.proof_environment)
                        })
                    })
                });

                if self_loop || !all_dependency_edges || !all_theorems_in_environment {
                    errors.push(StructuredError::new(
                        ErrorCode::PbCoreInvalidCycle,
                        format!(
                            "undeclared or non-theorem graph cycle contains [{}]",
                            component
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        "break provenance cycles; only exact declared mutual theorem dependencies in one environment are allowed",
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::new(errors))
        }
    }

    /// Looks up a graph node by stable identity.
    #[must_use]
    pub fn node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.nodes.iter().find(|node| &node.id == id)
    }

    /// Tests for one exact typed edge.
    #[must_use]
    pub fn has_edge(&self, from: &NodeId, to: &NodeId, kind: EdgeKind) -> bool {
        self.edges
            .iter()
            .any(|edge| &edge.from == from && &edge.to == to && edge.kind == kind)
    }
}

fn strongly_connected_components(nodes: &[GraphNode], edges: &[GraphEdge]) -> Vec<Vec<NodeId>> {
    struct Tarjan {
        next_index: usize,
        indices: BTreeMap<NodeId, usize>,
        low_links: BTreeMap<NodeId, usize>,
        stack: Vec<NodeId>,
        on_stack: BTreeSet<NodeId>,
        adjacency: BTreeMap<NodeId, Vec<NodeId>>,
        components: Vec<Vec<NodeId>>,
    }

    impl Tarjan {
        fn visit(&mut self, node: NodeId) {
            let index = self.next_index;
            self.next_index += 1;
            self.indices.insert(node.clone(), index);
            self.low_links.insert(node.clone(), index);
            self.stack.push(node.clone());
            self.on_stack.insert(node.clone());

            let neighbors = self.adjacency.get(&node).cloned().unwrap_or_default();
            for neighbor in neighbors {
                if !self.indices.contains_key(&neighbor) {
                    self.visit(neighbor.clone());
                    let neighbor_low = self.low_links[&neighbor];
                    let node_low = self.low_links[&node];
                    self.low_links
                        .insert(node.clone(), node_low.min(neighbor_low));
                } else if self.on_stack.contains(&neighbor) {
                    let neighbor_index = self.indices[&neighbor];
                    let node_low = self.low_links[&node];
                    self.low_links
                        .insert(node.clone(), node_low.min(neighbor_index));
                }
            }

            if self.low_links[&node] == self.indices[&node] {
                let mut component = Vec::new();
                while let Some(member) = self.stack.pop() {
                    self.on_stack.remove(&member);
                    component.push(member.clone());
                    if member == node {
                        break;
                    }
                }
                component.sort();
                self.components.push(component);
            }
        }
    }

    let mut adjacency = nodes
        .iter()
        .map(|node| (node.id.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for edge in edges {
        if let Some(targets) = adjacency.get_mut(&edge.from) {
            targets.push(edge.to.clone());
        }
    }
    let mut state = Tarjan {
        next_index: 0,
        indices: BTreeMap::new(),
        low_links: BTreeMap::new(),
        stack: Vec::new(),
        on_stack: BTreeSet::new(),
        adjacency,
        components: Vec::new(),
    };
    for node in nodes {
        if !state.indices.contains_key(&node.id) {
            state.visit(node.id.clone());
        }
    }
    state.components
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_NODE_KINDS: [NodeKind; 14] = [
        NodeKind::Claim,
        NodeKind::Theorem,
        NodeKind::Subject,
        NodeKind::Artifact,
        NodeKind::SourceClosure,
        NodeKind::TranslationUnit,
        NodeKind::ModelCheckUnit,
        NodeKind::TestSuite,
        NodeKind::Assumption,
        NodeKind::Premise,
        NodeKind::Toolchain,
        NodeKind::TcbComponent,
        NodeKind::Review,
        NodeKind::Policy,
    ];

    const ALL_EDGE_KINDS: [EdgeKind; 13] = [
        EdgeKind::Proves,
        EdgeKind::Refines,
        EdgeKind::Decodes,
        EdgeKind::Checks,
        EdgeKind::GeneratedFrom,
        EdgeKind::DependsOn,
        EdgeKind::Assumes,
        EdgeKind::DischargedBy,
        EdgeKind::CrossChecks,
        EdgeKind::CoversBoundedDomain,
        EdgeKind::BindsDigest,
        EdgeKind::ReviewedBy,
        EdgeKind::AdmittedByPolicy,
    ];

    fn node(id: &str, kind: NodeKind) -> GraphNode {
        GraphNode {
            id: NodeId::new(id).unwrap(),
            kind,
            proof_environment: (kind == NodeKind::Theorem)
                .then(|| EnvironmentId::new("lean:main").unwrap()),
        }
    }

    #[test]
    fn missing_targets_and_provenance_cycles_fail() {
        let graph = AssuranceGraph {
            schema: GRAPH_SCHEMA_V1.into(),
            nodes: vec![
                node("artifact:a", NodeKind::Artifact),
                node("subject:s", NodeKind::Subject),
            ],
            edges: vec![
                GraphEdge {
                    from: NodeId::new("artifact:a").unwrap(),
                    to: NodeId::new("subject:s").unwrap(),
                    kind: EdgeKind::GeneratedFrom,
                },
                GraphEdge {
                    from: NodeId::new("subject:s").unwrap(),
                    to: NodeId::new("artifact:a").unwrap(),
                    kind: EdgeKind::DependsOn,
                },
                GraphEdge {
                    from: NodeId::new("artifact:a").unwrap(),
                    to: NodeId::new("missing:x").unwrap(),
                    kind: EdgeKind::Checks,
                },
            ],
            mutual_theorem_groups: vec![],
        };
        let errors = graph.validate().unwrap_err();
        assert!(
            errors
                .errors
                .iter()
                .any(|e| e.code == ErrorCode::PbCoreMissingTarget)
        );

        let mut without_missing = graph;
        without_missing.edges.pop();
        assert!(
            without_missing
                .validate()
                .unwrap_err()
                .errors
                .iter()
                .any(|e| e.code == ErrorCode::PbCoreInvalidCycle)
        );
    }

    #[test]
    fn exact_declared_mutual_theorems_are_the_only_allowed_cycle() {
        let a = NodeId::new("theorem:a").unwrap();
        let b = NodeId::new("theorem:b").unwrap();
        let environment = EnvironmentId::new("lean:main").unwrap();
        let graph = AssuranceGraph {
            schema: GRAPH_SCHEMA_V1.into(),
            nodes: vec![
                node("theorem:a", NodeKind::Theorem),
                node("theorem:b", NodeKind::Theorem),
            ],
            edges: vec![
                GraphEdge {
                    from: a.clone(),
                    to: b.clone(),
                    kind: EdgeKind::DependsOn,
                },
                GraphEdge {
                    from: b.clone(),
                    to: a.clone(),
                    kind: EdgeKind::DependsOn,
                },
            ],
            mutual_theorem_groups: vec![MutualTheoremGroup {
                id: NodeId::new("group:mutual").unwrap(),
                proof_environment: environment,
                members: BTreeSet::from([a, b]),
            }],
        };
        assert!(graph.validate().is_ok());

        let mut not_dependency = graph;
        not_dependency.edges[0].kind = EdgeKind::GeneratedFrom;
        assert!(not_dependency.validate().is_err());
    }

    #[test]
    fn unknown_node_and_edge_kinds_fail_during_deserialization() {
        let graph = r#"{
          "schema":"proofbound-graph/1",
          "nodes":[{"id":"n:1","kind":"mystery"}],
          "edges":[],
          "mutual_theorem_groups":[]
        }"#;
        assert!(serde_json::from_str::<AssuranceGraph>(graph).is_err());
    }

    #[test]
    fn runtime_endpoint_predicate_exactly_matches_the_authoritative_table() {
        let unique = EDGE_ENDPOINT_RULES.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), EDGE_ENDPOINT_RULES.len());

        for edge in ALL_EDGE_KINDS {
            assert!(
                EDGE_ENDPOINT_RULES
                    .iter()
                    .any(|(listed, _, _)| *listed == edge),
                "{edge:?} has no endpoint rule"
            );
            for from in ALL_NODE_KINDS {
                for to in ALL_NODE_KINDS {
                    let listed = EDGE_ENDPOINT_RULES.contains(&(edge, from, to));
                    assert_eq!(
                        edge.allows_endpoints(from, to),
                        listed,
                        "runtime endpoint decision drifted for {from:?} --{edge:?}--> {to:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn typed_and_checked_construction_share_the_endpoint_contract() {
        let theorem = node("theorem:legal", NodeKind::Theorem);
        let claim = node("claim:legal", NodeKind::Claim);
        let typed = GraphEdge::typed::<edge_types::Proves, _, _>(
            theorem.typed::<node_types::Theorem>().unwrap(),
            claim.typed::<node_types::Claim>().unwrap(),
        );
        let checked = GraphEdge::checked(&theorem, &claim, EdgeKind::Proves).unwrap();
        assert_eq!(typed, checked);

        let tests = node("tests:illegal", NodeKind::TestSuite);
        let toolchain = node("toolchain:illegal", NodeKind::Toolchain);
        assert_eq!(
            GraphEdge::checked(&tests, &toolchain, EdgeKind::Proves)
                .unwrap_err()
                .kind,
            EdgeKind::Proves
        );
    }

    #[test]
    fn hostile_raw_edge_is_representable_but_validation_rejects_it() {
        let raw = r#"{
          "schema":"proofbound-graph/1",
          "nodes":[
            {"id":"tests:unit","kind":"test-suite"},
            {"id":"toolchain:rust","kind":"toolchain"}
          ],
          "edges":[{
            "from":"tests:unit",
            "to":"toolchain:rust",
            "kind":"proves"
          }],
          "mutual_theorem_groups":[]
        }"#;
        let graph = serde_json::from_str::<AssuranceGraph>(raw).unwrap();
        let errors = graph.validate().unwrap_err();
        assert!(
            errors
                .errors
                .iter()
                .any(|error| error.code == ErrorCode::PbCoreInvalidEdge)
        );
    }
}
