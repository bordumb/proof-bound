//! Independent release parsing, integrity checks, and status recomputation.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt, fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{
    ASSUMPTION_SCHEMA_V1, ArtifactBindingReceipt, AssumptionCategory, AssumptionFacet,
    AssumptionReceipt, AssumptionState, AssuranceGraph, BindingMode, BuiltInProfile,
    CLAIM_SCHEMA_V1, CLOSURE_SCHEMA_V1, COMPILED_RELEASE_SCHEMA_V1, ClaimReceipt, ClosureKind,
    CompiledRelease, EVIDENCE_SCHEMA_V1, EdgeKind, EvaluationMode, EvidenceKind, EvidenceOutcome,
    EvidenceReceipt, Exclusion, FlowScope, FormalFacet, GRAPH_SCHEMA_V1, GraphNode, HashedRecord,
    IndependenceMode, LinkageFacet, NodeKind, OpenObligation, POLICY_SCHEMA_V1, PolicyReceipt,
    PremiseReceipt, RELEASE_ENVELOPE_SCHEMA_V1, ReleaseEnvelope, ReportedClaimStatus,
    SourceClosureReceipt, Tier, TreeState, canonical_json, domain_hash, raw_sha256,
};

const MAX_ENVELOPE_BYTES: u64 = 1 << 20;
const MAX_PAYLOAD_BYTES: u64 = 64 << 20;
const MAX_TCB_LEDGER_BYTES: u64 = 64 << 20;
const MAX_SEALED_FILE_BYTES: u64 = 1 << 30;
const MAX_COLLECTION_ITEMS: usize = 1_000_000;
const TCB_LEDGER_SCHEMA_V1: &str = "proofbound-tcb-ledger/1";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct TcbComponent {
    name: String,
    version: String,
    identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TcbLedger {
    schema: String,
    components: Vec<TcbComponent>,
}

/// Stable independent-verifier issue codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationIssueCode {
    PbvIo,
    PbvUnsafePath,
    PbvSymlink,
    PbvSizeLimit,
    PbvJson,
    PbvNonCanonical,
    PbvSchema,
    PbvDigest,
    PbvDuplicateId,
    PbvMissingReference,
    PbvInvalidGraph,
    PbvInvalidEvidence,
    PbvTierExceeded,
    PbvInvalidPolicy,
    PbvInvalidAssumption,
    PbvInvalidPremise,
    PbvAmbiguousLinkage,
    PbvStatusMismatch,
}

/// One portable verifier diagnostic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationIssue {
    pub code: VerificationIssueCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_identity: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub affected_downstream_claims: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl VerificationIssue {
    fn new(code: VerificationIssueCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            path: None,
            claim_id: None,
            unit_id: None,
            byte_offset: None,
            expected_identity: None,
            actual_identity: None,
            affected_downstream_claims: BTreeSet::new(),
            remediation: None,
        }
    }

    fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    fn for_claim(mut self, claim: impl Into<String>) -> Self {
        self.claim_id = Some(claim.into());
        self
    }
}

/// Aggregated verification failure.
#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[error("{count} receipt-consistency error(s)", count = .issues.len())]
pub struct VerificationErrors {
    pub schema: String,
    pub issues: Vec<VerificationIssue>,
}

impl VerificationErrors {
    fn one(issue: VerificationIssue) -> Self {
        Self {
            schema: "proofbound-verification-errors/1".into(),
            issues: vec![issue],
        }
    }

    fn many(issues: Vec<VerificationIssue>) -> Self {
        Self {
            schema: "proofbound-verification-errors/1".into(),
            issues,
        }
    }
}

/// Independently recomputed status returned to CI and third-party reviewers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotProvedOutOfScopeReport {
    pub claim_id: String,
    pub open_obligations: BTreeSet<OpenObligation>,
    pub undischarged_premises: BTreeSet<String>,
    pub assumptions: BTreeSet<String>,
    pub out_of_scope: BTreeSet<Exclusion>,
}

/// Independently recomputed status returned to CI and third-party reviewers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub schema: String,
    pub verdict: String,
    pub project: String,
    pub project_revision: String,
    pub payload_sha256: String,
    pub publication_blocked: bool,
    pub claims: Vec<ReportedClaimStatus>,
    /// Mandatory report projection; present even when every set is empty.
    pub not_proved_out_of_scope: Vec<NotProvedOutOfScopeReport>,
    pub trust_boundary: String,
}

/// Verifies `<dir>/release.json`, its canonical payload, sealed files, and all
/// recomputed status/policy output. It never executes an external process.
pub fn verify_release_dir(release_dir: &Path) -> Result<VerificationReport, VerificationErrors> {
    reject_root_symlink(release_dir)?;
    let root = fs::canonicalize(release_dir).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvIo,
                format!("cannot open release directory: {error}"),
            )
            .at(release_dir.display().to_string()),
        )
    })?;
    if !root.is_dir() {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvUnsafePath,
                "release path is not a directory",
            )
            .at(root.display().to_string()),
        ));
    }

    let envelope_path = root.join("release.json");
    let (envelope, _) = read_canonical::<ReleaseEnvelope>(&envelope_path, MAX_ENVELOPE_BYTES)?;
    if envelope.schema != RELEASE_ENVELOPE_SCHEMA_V1 {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvSchema,
                format!("unsupported release envelope schema '{}'", envelope.schema),
            )
            .at("release.json"),
        ));
    }
    check_digest(&envelope.payload_sha256, "release payload digest")?;
    let payload_path = resolve_sealed_path(&root, &envelope.payload)?;
    if payload_path == envelope_path {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvUnsafePath,
                "release envelope cannot be its own payload",
            )
            .at(&envelope.payload),
        ));
    }
    let (release, payload_bytes) =
        read_canonical::<CompiledRelease>(&payload_path, MAX_PAYLOAD_BYTES)?;
    let actual_payload = domain_hash(COMPILED_RELEASE_SCHEMA_V1, &payload_bytes);
    if actual_payload != envelope.payload_sha256 {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvDigest,
                format!(
                    "payload digest mismatch: expected {}, recomputed {actual_payload}",
                    envelope.payload_sha256
                ),
            )
            .at(&envelope.payload),
        ));
    }

    let mut report = verify_compiled_release_internal(&release, Some(&root))?;
    report.payload_sha256 = actual_payload;
    Ok(report)
}

/// Verifies an already parsed payload. Sealed physical files are syntactically
/// checked here and byte-checked by [`verify_release_dir`].
pub fn verify_compiled_release(
    release: &CompiledRelease,
) -> Result<VerificationReport, VerificationErrors> {
    verify_compiled_release_internal(release, None)
}

fn verify_compiled_release_internal(
    release: &CompiledRelease,
    release_root: Option<&Path>,
) -> Result<VerificationReport, VerificationErrors> {
    let mut issues = Vec::new();
    if release.schema != COMPILED_RELEASE_SCHEMA_V1 {
        issues.push(VerificationIssue::new(
            VerificationIssueCode::PbvSchema,
            format!("unsupported compiled release schema '{}'", release.schema),
        ));
    }
    if release.project.trim().is_empty() || release.project_revision.trim().is_empty() {
        issues.push(VerificationIssue::new(
            VerificationIssueCode::PbvSchema,
            "project and project_revision must be non-empty",
        ));
    }
    if release.tree_state != TreeState::Clean {
        issues.push(VerificationIssue::new(
            VerificationIssueCode::PbvInvalidEvidence,
            "a portable release must bind a clean tree",
        ));
    }
    for (label, count) in [
        ("claims", release.claims.len()),
        ("evidence", release.evidence.len()),
        ("assumptions", release.assumptions.len()),
        ("premises", release.premises.len()),
        ("policies", release.policies.len()),
        ("closures", release.closures.len()),
        ("sealed_files", release.sealed_files.len()),
    ] {
        if count > MAX_COLLECTION_ITEMS {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvSizeLimit,
                format!("{label} contains {count} entries, above the verifier limit"),
            ));
        }
    }

    validate_graph_hash(release, &mut issues);
    validate_graph(&release.graph, &mut issues);
    let closure_ids = validate_closures(&release.closures, &mut issues);
    let invalid_evidence = validate_evidence_records(release, &closure_ids, &mut issues);
    validate_sealed_files(release, release_root, &mut issues);
    if let Some(root) = release_root {
        validate_tcb_ledger(release, root, &mut issues);
    }

    let claims = index_unique(
        &release.claims,
        |claim| claim.id.as_str(),
        "claim",
        &mut issues,
    );
    let policies = index_unique(
        &release.policies,
        |policy| policy.id.as_str(),
        "policy",
        &mut issues,
    );
    let assumptions = index_unique(
        &release.assumptions,
        |assumption| assumption.id.as_str(),
        "assumption",
        &mut issues,
    );
    let premises = index_unique(
        &release.premises,
        |premise| premise.id.as_str(),
        "premise",
        &mut issues,
    );
    let evidence = index_hashed(&release.evidence, "evidence", &mut issues);
    validate_closed_references(
        release,
        &claims,
        &policies,
        &assumptions,
        &premises,
        &evidence,
        &mut issues,
    );
    for policy in &release.policies {
        validate_policy(policy, &mut issues);
    }

    let reported = index_unique(
        &release.reported_statuses,
        |status| status.claim_id.as_str(),
        "reported claim status",
        &mut issues,
    );
    for reported_id in reported.keys() {
        if !claims.contains_key(reported_id) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvMissingReference,
                format!("reported status exists for unknown claim '{reported_id}'"),
            ));
        }
    }

    let mut recomputed = Vec::new();
    for claim in &release.claims {
        let (status, mut claim_issues) = derive_claim(
            release,
            claim,
            &policies,
            &assumptions,
            &premises,
            &evidence,
            &invalid_evidence,
        );
        match reported.get(claim.id.as_str()) {
            Some(output) if **output == status => {}
            Some(output) => claim_issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvStatusMismatch,
                    format!(
                        "reported status does not exactly match independent recomputation; reported {}, recomputed {}",
                        compact_status(output),
                        compact_status(&status)
                    ),
                )
                .for_claim(&claim.id),
            ),
            None => claim_issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvMissingReference,
                    "claim has no reported status",
                )
                .for_claim(&claim.id),
            ),
        }
        issues.extend(claim_issues);
        recomputed.push(status);
    }

    if !issues.is_empty() {
        return Err(VerificationErrors::many(issues));
    }
    recomputed.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    let not_proved_out_of_scope = recomputed
        .iter()
        .map(|status| {
            let claim = claims[status.claim_id.as_str()];
            NotProvedOutOfScopeReport {
                claim_id: status.claim_id.clone(),
                open_obligations: claim.open_obligations.clone(),
                undischarged_premises: status.undischarged_premises.clone(),
                assumptions: status.assumptions.clone(),
                out_of_scope: claim.out_of_scope.clone(),
            }
        })
        .collect();
    Ok(VerificationReport {
        schema: "proofbound-verification-report/1".into(),
        verdict: "receipt-consistent".into(),
        project: release.project.clone(),
        project_revision: release.project_revision.clone(),
        payload_sha256: String::new(),
        publication_blocked: recomputed.iter().any(|status| !status.policy_admitted),
        claims: recomputed,
        not_proved_out_of_scope,
        trust_boundary: "Receipt-consistent only: this independently checks recorded identities, graph facts, facets, assumptions, and policies; it does not attest that external tools ran honestly.".into(),
    })
}

fn read_canonical<T: DeserializeOwned + Serialize>(
    path: &Path,
    max_bytes: u64,
) -> Result<(T, Vec<u8>), VerificationErrors> {
    reject_file_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvIo,
                format!("cannot stat receipt file: {error}"),
            )
            .at(path.display().to_string()),
        )
    })?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvSizeLimit,
                format!("receipt file is not regular or exceeds {max_bytes} bytes"),
            )
            .at(path.display().to_string()),
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvIo,
                format!("cannot read receipt file: {error}"),
            )
            .at(path.display().to_string()),
        )
    })?;
    let value = serde_json::from_slice::<T>(&bytes).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvJson,
                format!("strict JSON decoding failed: {error}"),
            )
            .at(path.display().to_string()),
        )
    })?;
    let canonical = canonical_json(&value).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvJson,
                format!("canonical JSON encoding failed: {error}"),
            )
            .at(path.display().to_string()),
        )
    })?;
    if canonical != bytes {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvNonCanonical,
                "receipt is not canonical compact JSON with recursively sorted object keys",
            )
            .at(path.display().to_string()),
        ));
    }
    Ok((value, bytes))
}

fn reject_root_symlink(path: &Path) -> Result<(), VerificationErrors> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvIo,
                format!("cannot inspect release directory: {error}"),
            )
            .at(path.display().to_string()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvSymlink,
                "release directory is a symlink",
            )
            .at(path.display().to_string()),
        ));
    }
    Ok(())
}

fn reject_file_symlink(path: &Path) -> Result<(), VerificationErrors> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvIo,
                format!("cannot inspect sealed file: {error}"),
            )
            .at(path.display().to_string()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvSymlink,
                "sealed file is a symlink",
            )
            .at(path.display().to_string()),
        ));
    }
    Ok(())
}

fn resolve_sealed_path(root: &Path, relative: &str) -> Result<PathBuf, VerificationErrors> {
    let relative_path = Path::new(relative);
    if !safe_relative(relative) {
        return Err(VerificationErrors::one(
            VerificationIssue::new(
                VerificationIssueCode::PbvUnsafePath,
                "sealed path must be a non-empty normalized relative path",
            )
            .at(relative),
        ));
    }
    let mut current = root.to_path_buf();
    let components = relative_path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            unreachable!("safe_relative accepted only normal components");
        };
        current.push(part);
        if index + 1 < components.len() {
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                VerificationErrors::one(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvIo,
                        format!("cannot inspect sealed path component: {error}"),
                    )
                    .at(relative),
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(VerificationErrors::one(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvSymlink,
                        "sealed path crosses a symlink",
                    )
                    .at(relative),
                ));
            }
        }
    }
    reject_file_symlink(&current)?;
    Ok(current)
}

fn safe_relative(path: &str) -> bool {
    let value = Path::new(path);
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || value.is_absolute()
    {
        return false;
    }
    let parts = value
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    !parts.is_empty() && parts.len() == value.components().count() && parts.join("/") == path
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        && !value.contains("..")
}

fn check_digest(value: &str, label: &str) -> Result<(), VerificationErrors> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(VerificationErrors::one(VerificationIssue::new(
            VerificationIssueCode::PbvDigest,
            format!("{label} is not canonical sha256:<64 lowercase hex>: '{value}'"),
        )))
    }
}

fn index_unique<'a, T, F>(
    values: &'a [T],
    id: F,
    label: &str,
    issues: &mut Vec<VerificationIssue>,
) -> BTreeMap<String, &'a T>
where
    F: Fn(&T) -> &str,
{
    let mut map = BTreeMap::new();
    for value in values {
        let key = id(value).to_owned();
        if !valid_id(&key) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvSchema,
                format!("invalid {label} ID '{key}'"),
            ));
        }
        if map.insert(key.clone(), value).is_some() {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!("duplicate {label} ID '{key}'"),
            ));
        }
    }
    map
}

fn index_hashed<'a, T>(
    values: &'a [HashedRecord<T>],
    label: &str,
    issues: &mut Vec<VerificationIssue>,
) -> BTreeMap<String, &'a T> {
    let mut map = BTreeMap::new();
    for value in values {
        if map.insert(value.sha256.clone(), &value.record).is_some() {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!("duplicate {label} digest '{}'", value.sha256),
            ));
        }
    }
    map
}

fn validate_graph_hash(release: &CompiledRelease, issues: &mut Vec<VerificationIssue>) {
    if release.graph.schema != GRAPH_SCHEMA_V1 {
        issues.push(VerificationIssue::new(
            VerificationIssueCode::PbvSchema,
            format!("unsupported graph schema '{}'", release.graph.schema),
        ));
    }
    if !valid_digest(&release.graph_sha256) {
        issues.push(VerificationIssue::new(
            VerificationIssueCode::PbvDigest,
            "graph_sha256 is not a canonical SHA-256 digest",
        ));
        return;
    }
    match canonical_json(&release.graph) {
        Ok(bytes) => {
            let actual = domain_hash(GRAPH_SCHEMA_V1, &bytes);
            if actual != release.graph_sha256 {
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvDigest,
                    format!(
                        "graph digest mismatch: expected {}, recomputed {actual}",
                        release.graph_sha256
                    ),
                ));
            }
        }
        Err(error) => issues.push(VerificationIssue::new(
            VerificationIssueCode::PbvJson,
            format!("cannot canonicalize graph: {error}"),
        )),
    }
}

fn validate_graph(graph: &AssuranceGraph, issues: &mut Vec<VerificationIssue>) {
    let nodes = index_unique(&graph.nodes, |node| node.id.as_str(), "graph node", issues);
    for node in &graph.nodes {
        match (node.kind, node.proof_environment.as_deref()) {
            (NodeKind::Theorem, Some(environment)) if valid_id(environment) => {}
            (NodeKind::Theorem, _) => issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvInvalidGraph,
                format!("theorem node '{}' has no proof environment", node.id),
            )),
            (_, Some(_)) => issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvInvalidGraph,
                format!(
                    "non-theorem node '{}' declares a proof environment",
                    node.id
                ),
            )),
            (_, None) => {}
        }
    }

    let mut edge_ids = BTreeSet::new();
    let mut endpoints_complete = true;
    for edge in &graph.edges {
        match (nodes.get(&edge.from), nodes.get(&edge.to)) {
            (Some(from), Some(to)) => {
                if !legal_edge_endpoints(edge.kind, from.kind, to.kind) {
                    issues.push(VerificationIssue::new(
                        VerificationIssueCode::PbvInvalidGraph,
                        format!(
                            "graph edge '{} ({:?}) --{:?}--> {} ({:?})' has illegal endpoint kinds",
                            edge.from, from.kind, edge.kind, edge.to, to.kind
                        ),
                    ));
                }
            }
            _ => {
                endpoints_complete = false;
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvMissingReference,
                    format!(
                        "graph edge '{} --{:?}--> {}' has a missing endpoint",
                        edge.from, edge.kind, edge.to
                    ),
                ));
            }
        }
        if !edge_ids.insert((edge.from.as_str(), edge.to.as_str(), edge.kind)) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!(
                    "duplicate graph edge '{} --{:?}--> {}'",
                    edge.from, edge.kind, edge.to
                ),
            ));
        }
    }

    let mut group_ids = BTreeSet::new();
    let mut grouped_nodes = BTreeSet::new();
    for group in &graph.mutual_theorem_groups {
        if !valid_id(&group.id) || !valid_id(&group.proof_environment) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvInvalidGraph,
                format!(
                    "mutual theorem group '{}' has an invalid identity",
                    group.id
                ),
            ));
        }
        if !group_ids.insert(group.id.as_str()) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!("duplicate mutual theorem group '{}'", group.id),
            ));
        }
        if group.proof_environment.trim().is_empty() || group.members.len() < 2 {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvInvalidGraph,
                format!(
                    "mutual theorem group '{}' needs an environment and at least two members",
                    group.id
                ),
            ));
        }
        for member in &group.members {
            if !grouped_nodes.insert(member.as_str()) {
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidGraph,
                    format!("node '{member}' belongs to multiple mutual theorem groups"),
                ));
            }
            if !nodes.get(member).is_some_and(|node| {
                node.kind == NodeKind::Theorem
                    && node.proof_environment.as_deref() == Some(&group.proof_environment)
            }) {
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidGraph,
                    format!(
                        "mutual group '{}' member '{member}' is not a theorem in environment '{}'",
                        group.id, group.proof_environment
                    ),
                ));
            }
        }
    }

    if endpoints_complete {
        for component in graph_components(graph) {
            let self_loop = component.len() == 1
                && graph
                    .edges
                    .iter()
                    .any(|edge| edge.from == component[0] && edge.to == component[0]);
            if component.len() == 1 && !self_loop {
                continue;
            }
            let members = component.iter().cloned().collect::<BTreeSet<_>>();
            let declared = graph
                .mutual_theorem_groups
                .iter()
                .find(|group| group.members == members);
            let only_dependencies = graph
                .edges
                .iter()
                .filter(|edge| members.contains(&edge.from) && members.contains(&edge.to))
                .all(|edge| edge.kind == EdgeKind::DependsOn);
            let exact_environment = declared.is_some_and(|group| {
                component.iter().all(|member| {
                    nodes.get(member).is_some_and(|node| {
                        node.kind == NodeKind::Theorem
                            && node.proof_environment.as_deref()
                                == Some(group.proof_environment.as_str())
                    })
                })
            });
            if self_loop || !only_dependencies || !exact_environment {
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidGraph,
                    format!(
                        "undeclared or non-theorem graph cycle contains [{}]",
                        component.join(", ")
                    ),
                ));
            }
        }
    }
}

// This is intentionally independent of `proofbound-core`: the standalone
// verifier must fail closed even if a producer serializes a graph without
// going through the core crate's typed edge constructors.
const LEGAL_EDGE_ENDPOINTS: &[(EdgeKind, NodeKind, NodeKind)] = &[
    (EdgeKind::Proves, NodeKind::Theorem, NodeKind::Claim),
    (
        EdgeKind::Refines,
        NodeKind::TranslationUnit,
        NodeKind::Claim,
    ),
    (EdgeKind::Decodes, NodeKind::Artifact, NodeKind::Claim),
    (EdgeKind::Checks, NodeKind::TestSuite, NodeKind::Claim),
    (EdgeKind::Checks, NodeKind::ModelCheckUnit, NodeKind::Claim),
    (
        EdgeKind::GeneratedFrom,
        NodeKind::Artifact,
        NodeKind::Subject,
    ),
    (EdgeKind::DependsOn, NodeKind::Claim, NodeKind::Subject),
    (EdgeKind::DependsOn, NodeKind::Subject, NodeKind::Artifact),
    (EdgeKind::DependsOn, NodeKind::Theorem, NodeKind::Theorem),
    (EdgeKind::Assumes, NodeKind::Claim, NodeKind::Assumption),
    (EdgeKind::Assumes, NodeKind::Claim, NodeKind::Premise),
    (EdgeKind::Assumes, NodeKind::Theorem, NodeKind::Premise),
    (EdgeKind::Assumes, NodeKind::Assumption, NodeKind::Claim),
    (EdgeKind::Assumes, NodeKind::Claim, NodeKind::Claim),
    (EdgeKind::DischargedBy, NodeKind::Premise, NodeKind::Theorem),
    (EdgeKind::CrossChecks, NodeKind::TestSuite, NodeKind::Claim),
    (
        EdgeKind::CrossChecks,
        NodeKind::ModelCheckUnit,
        NodeKind::Claim,
    ),
    (
        EdgeKind::CoversBoundedDomain,
        NodeKind::ModelCheckUnit,
        NodeKind::Claim,
    ),
    (EdgeKind::BindsDigest, NodeKind::Artifact, NodeKind::Claim),
    (EdgeKind::ReviewedBy, NodeKind::Review, NodeKind::Claim),
    (EdgeKind::ReviewedBy, NodeKind::Assumption, NodeKind::Review),
    (
        EdgeKind::AdmittedByPolicy,
        NodeKind::Claim,
        NodeKind::Policy,
    ),
];

fn legal_edge_endpoints(kind: EdgeKind, from: NodeKind, to: NodeKind) -> bool {
    LEGAL_EDGE_ENDPOINTS.contains(&(kind, from, to))
}

fn graph_components(graph: &AssuranceGraph) -> Vec<Vec<String>> {
    struct State {
        next: usize,
        index: BTreeMap<String, usize>,
        low: BTreeMap<String, usize>,
        stack: Vec<String>,
        stacked: BTreeSet<String>,
        adjacency: BTreeMap<String, Vec<String>>,
        output: Vec<Vec<String>>,
    }
    fn visit(state: &mut State, node: String) {
        let current = state.next;
        state.next += 1;
        state.index.insert(node.clone(), current);
        state.low.insert(node.clone(), current);
        state.stack.push(node.clone());
        state.stacked.insert(node.clone());
        for neighbor in state.adjacency.get(&node).cloned().unwrap_or_default() {
            if !state.index.contains_key(&neighbor) {
                visit(state, neighbor.clone());
                let candidate = state.low[&neighbor];
                state
                    .low
                    .entry(node.clone())
                    .and_modify(|low| *low = (*low).min(candidate));
            } else if state.stacked.contains(&neighbor) {
                let candidate = state.index[&neighbor];
                state
                    .low
                    .entry(node.clone())
                    .and_modify(|low| *low = (*low).min(candidate));
            }
        }
        if state.low[&node] == state.index[&node] {
            let mut component = Vec::new();
            while let Some(member) = state.stack.pop() {
                state.stacked.remove(&member);
                component.push(member.clone());
                if member == node {
                    break;
                }
            }
            component.sort();
            state.output.push(component);
        }
    }

    let mut state = State {
        next: 0,
        index: BTreeMap::new(),
        low: BTreeMap::new(),
        stack: Vec::new(),
        stacked: BTreeSet::new(),
        adjacency: graph
            .nodes
            .iter()
            .map(|node| (node.id.clone(), Vec::new()))
            .collect(),
        output: Vec::new(),
    };
    for edge in &graph.edges {
        if let Some(neighbors) = state.adjacency.get_mut(&edge.from) {
            neighbors.push(edge.to.clone());
        }
    }
    for node in &graph.nodes {
        if !state.index.contains_key(&node.id) {
            visit(&mut state, node.id.clone());
        }
    }
    state.output
}

fn validate_closures(
    closures: &[HashedRecord<SourceClosureReceipt>],
    issues: &mut Vec<VerificationIssue>,
) -> BTreeMap<String, ClosureKind> {
    let mut result = BTreeMap::new();
    for closure in closures {
        if !valid_digest(&closure.sha256) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDigest,
                format!("invalid closure digest '{}'", closure.sha256),
            ));
        }
        if closure.record.schema != CLOSURE_SCHEMA_V1 {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvSchema,
                format!("unsupported closure schema '{}'", closure.record.schema),
            ));
        }
        if closure.record.members.is_empty() {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvSchema,
                format!("closure '{}' has no members", closure.sha256),
            ));
        }
        if let Ok(bytes) = canonical_json(&closure.record) {
            let actual = domain_hash(CLOSURE_SCHEMA_V1, &bytes);
            if actual != closure.sha256 {
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvDigest,
                    format!(
                        "closure digest mismatch: expected {}, recomputed {actual}",
                        closure.sha256
                    ),
                ));
            }
        }
        if result
            .insert(closure.sha256.clone(), closure.record.kind)
            .is_some()
        {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!("duplicate closure digest '{}'", closure.sha256),
            ));
        }
        let mut prior: Option<&str> = None;
        for member in &closure.record.members {
            if !safe_relative(&member.path) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvUnsafePath,
                        "closure member path is not normalized and relative",
                    )
                    .at(&member.path),
                );
            }
            if !valid_digest(&member.sha256) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvDigest,
                        "closure member digest is invalid",
                    )
                    .at(&member.path),
                );
            }
            if prior.is_some_and(|path| path >= member.path.as_str()) {
                issues.push(VerificationIssue::new(
                    VerificationIssueCode::PbvDuplicateId,
                    "closure members must be strictly sorted by unique path",
                ));
            }
            prior = Some(&member.path);
        }
    }
    result
}

fn validate_evidence_records(
    release: &CompiledRelease,
    closures: &BTreeMap<String, ClosureKind>,
    issues: &mut Vec<VerificationIssue>,
) -> BTreeSet<String> {
    let graph_nodes = release
        .graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut invalid = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for wrapper in &release.evidence {
        let evidence = &wrapper.record;
        let before = issues.len();
        if !valid_digest(&wrapper.sha256) {
            evidence_issue(issues, &wrapper.sha256, "record digest is not canonical");
        }
        if !ids.insert(wrapper.sha256.as_str()) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!("duplicate evidence digest '{}'", wrapper.sha256),
            ));
        }
        if let Ok(bytes) = canonical_json(evidence) {
            let actual = domain_hash(EVIDENCE_SCHEMA_V1, &bytes);
            if actual != wrapper.sha256 {
                evidence_issue(
                    issues,
                    &wrapper.sha256,
                    format!("record digest mismatch; recomputed {actual}"),
                );
            }
        }
        if evidence.schema != EVIDENCE_SCHEMA_V1 {
            evidence_issue(
                issues,
                &wrapper.sha256,
                format!("unsupported evidence schema '{}'", evidence.schema),
            );
        }
        if evidence.unit_id.trim().is_empty() {
            evidence_issue(issues, &wrapper.sha256, "unit_id is empty");
        }
        if evidence.provenance.project_revision != release.project_revision
            || evidence.provenance.tree_state != release.tree_state
        {
            evidence_issue(
                issues,
                &wrapper.sha256,
                "evidence provenance does not match the release revision and tree state",
            );
        }
        if closures
            .get(&evidence.provenance.semantic_closure)
            .is_none_or(|kind| *kind != ClosureKind::Semantic)
        {
            evidence_issue(
                issues,
                &wrapper.sha256,
                "semantic_closure does not name a registered semantic closure",
            );
        }
        let mut additional = BTreeSet::new();
        for reference in &evidence.provenance.additional_closures {
            if !valid_digest(&reference.sha256)
                || closures
                    .get(&reference.sha256)
                    .is_none_or(|kind| *kind != reference.kind)
            {
                evidence_issue(
                    issues,
                    &wrapper.sha256,
                    "additional closure does not name a registered closure of the declared kind",
                );
            }
            if reference.sha256 == evidence.provenance.semantic_closure
                || !additional.insert(reference.sha256.as_str())
            {
                evidence_issue(
                    issues,
                    &wrapper.sha256,
                    "additional closures must be unique and distinct from semantic_closure",
                );
            }
        }
        validate_provenance(&wrapper.sha256, evidence, issues);
        validate_evidence_shape(&wrapper.sha256, evidence, &graph_nodes, issues);
        if issues.len() != before {
            invalid.insert(wrapper.sha256.clone());
        }
    }
    invalid
}

fn evidence_issue(issues: &mut Vec<VerificationIssue>, digest: &str, message: impl Into<String>) {
    issues.push(
        VerificationIssue::new(VerificationIssueCode::PbvInvalidEvidence, message).at(digest),
    );
}

fn validate_provenance(id: &str, evidence: &EvidenceReceipt, issues: &mut Vec<VerificationIssue>) {
    let provenance = &evidence.provenance;
    for (label, digest) in [
        ("tool identity", provenance.tool.identity_sha256.as_str()),
        (
            "adapter identity",
            provenance.adapter.identity_sha256.as_str(),
        ),
        ("result", provenance.deterministic_result_sha256.as_str()),
        (
            "unit configuration",
            provenance.unit_configuration_sha256.as_str(),
        ),
        ("cache key", provenance.cache_key.as_str()),
    ]
    .into_iter()
    .chain(
        provenance
            .input_artifacts
            .values()
            .map(|digest| ("input artifact", digest.as_str())),
    )
    .chain(
        provenance
            .generated_artifacts
            .values()
            .map(|digest| ("generated artifact", digest.as_str())),
    ) {
        if !valid_digest(digest) {
            evidence_issue(issues, id, format!("{label} digest is invalid: '{digest}'"));
        }
    }
    if provenance.tool.name.trim().is_empty()
        || provenance.tool.version.trim().is_empty()
        || provenance.adapter.name.trim().is_empty()
        || provenance.adapter.version.trim().is_empty()
        || provenance.command.is_empty()
        || provenance.command.iter().any(|arg| arg.is_empty())
        || provenance.reproduction_command.is_empty()
        || provenance
            .reproduction_command
            .iter()
            .any(|arg| arg.is_empty())
    {
        evidence_issue(
            issues,
            id,
            "tool identities and reproduction commands must be complete",
        );
    }
    if provenance
        .environment_allowlist
        .iter()
        .any(|name| name.trim().is_empty())
        || provenance
            .input_artifacts
            .keys()
            .chain(provenance.generated_artifacts.keys())
            .any(|name| name.trim().is_empty())
    {
        evidence_issue(
            issues,
            id,
            "environment and artifact logical names must be non-empty",
        );
    }
    if provenance.started_unix_ms > provenance.completed_unix_ms {
        evidence_issue(issues, id, "evidence completion precedes its start");
    }
    if let Some(reused) = &provenance.reused_from
        && !valid_digest(reused)
    {
        evidence_issue(issues, id, "reused_from is not a canonical digest");
    }
    match canonical_json(&provenance.cache_material()) {
        Ok(bytes) => {
            let actual = domain_hash("proofbound-cache-key/1", &bytes);
            if actual != provenance.cache_key {
                evidence_issue(
                    issues,
                    id,
                    format!("cache key mismatch; recomputed {actual}"),
                );
            }
        }
        Err(error) => evidence_issue(issues, id, format!("cache material is invalid: {error}")),
    }
}

fn validate_evidence_shape(
    id: &str,
    evidence: &EvidenceReceipt,
    nodes: &BTreeMap<&str, &GraphNode>,
    issues: &mut Vec<VerificationIssue>,
) {
    let expected_nodes: &[NodeKind] = match evidence.kind {
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
    let node = nodes.get(evidence.node_id.as_str());
    if !node.is_some_and(|node| expected_nodes.contains(&node.kind)) {
        evidence_issue(
            issues,
            id,
            format!(
                "node '{}' is absent or has the wrong kind",
                evidence.node_id
            ),
        );
    }
    let shape = [
        evidence.theorem.is_some(),
        evidence.artifact_binding.is_some(),
        evidence.trusted_transcription.is_some(),
        evidence.source_refinement.is_some(),
        evidence.bounded_check.is_some(),
        evidence.exhaustive_check.is_some(),
        evidence.mutation_witness.is_some(),
    ];
    let expected_slot = match evidence.kind {
        EvidenceKind::Theorem => Some(0),
        EvidenceKind::ArtifactSoundness => Some(1),
        EvidenceKind::TrustedTranscription => Some(2),
        EvidenceKind::SourceRefinement => Some(3),
        EvidenceKind::BoundedCheck => Some(4),
        EvidenceKind::ExhaustiveCheck => Some(5),
        EvidenceKind::MutationWitness => Some(6),
        _ => None,
    };
    if shape
        .iter()
        .enumerate()
        .any(|(slot, present)| *present != expected_slot.is_some_and(|expected| expected == slot))
    {
        evidence_issue(
            issues,
            id,
            "evidence kind/detail blocks do not match exactly",
        );
    }

    match evidence.kind {
        EvidenceKind::Theorem => {
            if evidence.evaluation_mode.is_none() || evidence.binding_mode.is_some() {
                evidence_issue(
                    issues,
                    id,
                    "theorem requires evaluation mode and no binding mode",
                );
            }
            if let Some(theorem) = &evidence.theorem
                && (theorem.declaration.trim().is_empty()
                    || theorem.statement_encoding != "lean-expr-cbor/1"
                    || !valid_digest(&theorem.statement_sha256)
                    || theorem.attributed_claim.trim().is_empty()
                    || !evidence.claim_ids.contains(&theorem.attributed_claim)
                    || !theorem.axiom_audit_passed
                    || theorem.contains_sorry_ax
                    || theorem.proof_environment.trim().is_empty()
                    || node.and_then(|node| node.proof_environment.as_deref())
                        != Some(theorem.proof_environment.as_str()))
            {
                evidence_issue(
                    issues,
                    id,
                    "theorem identity or compiled axiom audit is invalid",
                );
            }
        }
        EvidenceKind::ArtifactSoundness => {
            if evidence.evaluation_mode.is_none()
                || !matches!(
                    evidence.binding_mode,
                    Some(BindingMode::BytesInTheorem | BindingMode::DigestTheorem)
                )
                || !evidence
                    .artifact_binding
                    .as_ref()
                    .is_some_and(strong_binding)
            {
                evidence_issue(
                    issues,
                    id,
                    "artifact evidence does not strongly bind canonical bytes",
                );
            }
        }
        EvidenceKind::TrustedTranscription => {
            let valid_tcb = evidence.trusted_transcription.as_ref().is_some_and(|item| {
                item.round_trip_passed
                    && nodes
                        .get(item.transcriber_tcb_node.as_str())
                        .is_some_and(|node| node.kind == NodeKind::TcbComponent)
                    && nodes
                        .get(item.reencoder_tcb_node.as_str())
                        .is_some_and(|node| node.kind == NodeKind::TcbComponent)
            });
            if evidence.binding_mode != Some(BindingMode::ExternalRoundTrip)
                || evidence.evaluation_mode.is_some()
                || !valid_tcb
            {
                evidence_issue(
                    issues,
                    id,
                    "trusted transcription lacks a complete external round trip",
                );
            }
        }
        EvidenceKind::SourceRefinement => {
            if evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
                || !evidence.source_refinement.as_ref().is_some_and(|item| {
                    item.deterministic_translation
                        && item.pinned_toolchain
                        && item.generated_axioms_clean
                        && !item.refinement_theorem_evidence.is_empty()
                        && !item.representation_premises.is_empty()
                        && item.representation_premises.is_subset(&evidence.premises)
                })
            {
                evidence_issue(issues, id, "source refinement qualifiers are incomplete");
            }
        }
        EvidenceKind::BoundedCheck => {
            if evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
                || !evidence.bounded_check.as_ref().is_some_and(|item| {
                    !item.domain.id.trim().is_empty()
                        && !item.domain.description.trim().is_empty()
                        && valid_digest(&item.domain.registration_sha256)
                        && !item.solver.trim().is_empty()
                        && !item.harnesses.is_empty()
                })
            {
                evidence_issue(
                    issues,
                    id,
                    "bounded check has no explicit domain, solver, or harness inventory",
                );
            }
        }
        EvidenceKind::ExhaustiveCheck => {
            if evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
                || !evidence.exhaustive_check.as_ref().is_some_and(|item| {
                    !item.domain.id.trim().is_empty()
                        && !item.domain.description.trim().is_empty()
                        && valid_digest(&item.domain.registration_sha256)
                        && item.domain.cardinality == Some(item.evaluated_members)
                })
            {
                evidence_issue(
                    issues,
                    id,
                    "exhaustive check does not cover its exact registered cardinality",
                );
            }
        }
        EvidenceKind::IndependentCheck => {
            if evidence.independence != Some(IndependenceMode::Independent)
                || evidence.inventoried_targets.is_empty()
                || evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
            {
                evidence_issue(
                    issues,
                    id,
                    "independent check is not independently implemented or inventoried",
                );
            }
        }
        EvidenceKind::PropertyTest | EvidenceKind::ExampleTest => {
            if evidence.inventoried_targets.is_empty()
                || evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
                || evidence.independence.is_some()
            {
                evidence_issue(
                    issues,
                    id,
                    "test evidence has no inventoried target or has incompatible qualifiers",
                );
            }
        }
        EvidenceKind::MutationWitness => {
            if evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
                || !evidence.mutation_witness.as_ref().is_some_and(|item| {
                    valid_digest(&item.mutation_sha256) && !item.check_id.trim().is_empty()
                })
            {
                evidence_issue(issues, id, "mutation witness is incomplete");
            }
        }
        EvidenceKind::Open => {
            if evidence.evaluation_mode.is_some()
                || evidence.binding_mode.is_some()
                || evidence.open_obligation.as_ref().is_none_or(|item| {
                    item.id.trim().is_empty() || item.statement.trim().is_empty()
                })
            {
                evidence_issue(issues, id, "open evidence has no exact obligation");
            }
        }
        EvidenceKind::Review | EvidenceKind::Assumption => {
            if evidence.evaluation_mode.is_some() || evidence.binding_mode.is_some() {
                evidence_issue(issues, id, "evidence kind has incompatible mode qualifiers");
            }
        }
    }
    if evidence.kind != EvidenceKind::IndependentCheck && evidence.independence.is_some() {
        evidence_issue(
            issues,
            id,
            "independence qualifier appears on the wrong evidence kind",
        );
    }
    if evidence.kind != EvidenceKind::Open && evidence.open_obligation.is_some() {
        evidence_issue(
            issues,
            id,
            "open obligation appears on the wrong evidence kind",
        );
    }
}

fn strong_binding(binding: &ArtifactBindingReceipt) -> bool {
    !binding.theorem_evidence.is_empty()
        && binding.canonical_payload
        && binding.schema_bound
        && binding.literal_claim_bound
        && binding.digest_bound
        && binding.reencoding_passed
        && binding.trailing_bytes_rejected
}

fn validate_sealed_files(
    release: &CompiledRelease,
    root: Option<&Path>,
    issues: &mut Vec<VerificationIssue>,
) {
    let mut paths = BTreeSet::new();
    for sealed in &release.sealed_files {
        if !paths.insert(sealed.path.as_str()) {
            issues.push(VerificationIssue::new(
                VerificationIssueCode::PbvDuplicateId,
                format!("duplicate sealed file path '{}'", sealed.path),
            ));
        }
        if sealed.path == "release.json" || !safe_relative(&sealed.path) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvUnsafePath,
                    "sealed file path must be normalized, relative, and not release.json",
                )
                .at(&sealed.path),
            );
            continue;
        }
        if !valid_digest(&sealed.sha256) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvDigest,
                    "sealed file digest is invalid",
                )
                .at(&sealed.path),
            );
        }
        let Some(root) = root else { continue };
        let path = match resolve_sealed_path(root, &sealed.path) {
            Ok(path) => path,
            Err(error) => {
                issues.extend(error.issues);
                continue;
            }
        };
        match fs::metadata(&path) {
            Ok(metadata)
                if !metadata.is_file()
                    || metadata.len() > MAX_SEALED_FILE_BYTES
                    || sealed.size_bytes > MAX_SEALED_FILE_BYTES =>
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvSizeLimit,
                        "sealed file is not regular or exceeds the verifier size limit",
                    )
                    .at(&sealed.path),
                );
                continue;
            }
            Err(error) => {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvIo,
                        format!("cannot stat sealed file: {error}"),
                    )
                    .at(&sealed.path),
                );
                continue;
            }
            Ok(_) => {}
        }
        match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() as u64 != sealed.size_bytes {
                    issues.push(
                        VerificationIssue::new(
                            VerificationIssueCode::PbvDigest,
                            format!(
                                "sealed file size mismatch: expected {}, got {}",
                                sealed.size_bytes,
                                bytes.len()
                            ),
                        )
                        .at(&sealed.path),
                    );
                }
                let actual = raw_sha256(&bytes);
                if actual != sealed.sha256 {
                    issues.push(
                        VerificationIssue::new(
                            VerificationIssueCode::PbvDigest,
                            format!("sealed file digest mismatch; recomputed {actual}"),
                        )
                        .at(&sealed.path),
                    );
                }
            }
            Err(error) => issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvIo,
                    format!("cannot read sealed file: {error}"),
                )
                .at(&sealed.path),
            ),
        }
    }
}

fn validate_tcb_ledger(
    release: &CompiledRelease,
    root: &Path,
    issues: &mut Vec<VerificationIssue>,
) {
    let sealed_count = release
        .sealed_files
        .iter()
        .filter(|sealed| sealed.path == "tcb-ledger.json")
        .count();
    if sealed_count == 0 {
        issues.push(
            VerificationIssue::new(
                VerificationIssueCode::PbvMissingReference,
                "release does not seal the mandatory TCB ledger",
            )
            .at("tcb-ledger.json"),
        );
        return;
    }
    if sealed_count > 1 {
        // `validate_sealed_files` also reports the duplicate path. Avoid parsing
        // an ambiguously sealed trust-boundary record.
        return;
    }

    let path = match resolve_sealed_path(root, "tcb-ledger.json") {
        Ok(path) => path,
        Err(error) => {
            issues.extend(error.issues);
            return;
        }
    };
    let (ledger, _) = match read_canonical::<TcbLedger>(&path, MAX_TCB_LEDGER_BYTES) {
        Ok(value) => value,
        Err(error) => {
            issues.extend(error.issues);
            return;
        }
    };
    if ledger.schema != TCB_LEDGER_SCHEMA_V1 {
        issues.push(
            VerificationIssue::new(
                VerificationIssueCode::PbvSchema,
                format!("unsupported TCB ledger schema '{}'", ledger.schema),
            )
            .at("tcb-ledger.json"),
        );
    }
    if ledger.components.len() > MAX_COLLECTION_ITEMS {
        issues.push(
            VerificationIssue::new(
                VerificationIssueCode::PbvSizeLimit,
                format!(
                    "TCB ledger contains {} components, above the verifier limit",
                    ledger.components.len()
                ),
            )
            .at("tcb-ledger.json"),
        );
    }

    let mut declared = BTreeSet::new();
    let mut declared_identities = BTreeMap::<(String, String), String>::new();
    let mut previous: Option<&TcbComponent> = None;
    for component in &ledger.components {
        if previous.is_some_and(|prior| prior >= component) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvNonCanonical,
                    "TCB components must be strictly sorted by name, version, and identity",
                )
                .at("tcb-ledger.json"),
            );
        }
        previous = Some(component);

        if component.name.is_empty()
            || component.name.len() > 512
            || component.version.is_empty()
            || component.version.len() > 512
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvSchema,
                    "TCB component names and versions must contain 1 through 512 bytes",
                )
                .at("tcb-ledger.json"),
            );
        }
        if !valid_digest(&component.identity_sha256) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvDigest,
                    format!(
                        "TCB component {}@{} has a non-canonical identity digest",
                        component.name, component.version
                    ),
                )
                .at("tcb-ledger.json"),
            );
        }
        if !declared.insert(component.clone()) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvDuplicateId,
                    format!(
                        "duplicate TCB component {}@{} with identity {}",
                        component.name, component.version, component.identity_sha256
                    ),
                )
                .at("tcb-ledger.json"),
            );
        }
        let key = (component.name.clone(), component.version.clone());
        if let Some(identity) = declared_identities.insert(key, component.identity_sha256.clone())
            && identity != component.identity_sha256
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvDuplicateId,
                    format!(
                        "TCB component {}@{} has conflicting identities",
                        component.name, component.version
                    ),
                )
                .at("tcb-ledger.json"),
            );
        }
    }

    let mut expected = BTreeSet::new();
    let mut expected_identities = BTreeMap::<(String, String), String>::new();
    for evidence in &release.evidence {
        for identity in [
            &evidence.record.provenance.tool,
            &evidence.record.provenance.adapter,
        ] {
            let component = TcbComponent {
                name: identity.name.clone(),
                version: identity.version.clone(),
                identity_sha256: identity.identity_sha256.clone(),
            };
            let key = (component.name.clone(), component.version.clone());
            if let Some(old) = expected_identities.insert(key, component.identity_sha256.clone())
                && old != component.identity_sha256
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvInvalidEvidence,
                        format!(
                            "evidence assigns conflicting identities to TCB component {}@{}",
                            component.name, component.version
                        ),
                    )
                    .at(&evidence.sha256),
                );
            }
            expected.insert(component);
        }
    }

    for missing in expected.difference(&declared) {
        issues.push(
            VerificationIssue::new(
                VerificationIssueCode::PbvMissingReference,
                format!(
                    "TCB ledger omits evidence component {}@{} ({})",
                    missing.name, missing.version, missing.identity_sha256
                ),
            )
            .at("tcb-ledger.json"),
        );
    }
    for unknown in declared.difference(&expected) {
        issues.push(
            VerificationIssue::new(
                VerificationIssueCode::PbvInvalidEvidence,
                format!(
                    "TCB ledger contains unreferenced component {}@{} ({})",
                    unknown.name, unknown.version, unknown.identity_sha256
                ),
            )
            .at("tcb-ledger.json"),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_closed_references(
    release: &CompiledRelease,
    claims: &BTreeMap<String, &ClaimReceipt>,
    policies: &BTreeMap<String, &PolicyReceipt>,
    assumptions: &BTreeMap<String, &AssumptionReceipt>,
    premises: &BTreeMap<String, &PremiseReceipt>,
    evidence: &BTreeMap<String, &EvidenceReceipt>,
    issues: &mut Vec<VerificationIssue>,
) {
    for claim in &release.claims {
        if claim.schema != CLAIM_SCHEMA_V1 {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvSchema,
                    format!("unsupported claim schema '{}'", claim.schema),
                )
                .for_claim(&claim.id),
            );
        }
        if !policies.contains_key(&claim.policy) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvMissingReference,
                    format!("claim refers to absent policy '{}'", claim.policy),
                )
                .for_claim(&claim.id),
            );
        }
        for evidence_id in &claim.cited_evidence {
            if !valid_digest(evidence_id) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvDigest,
                        format!("claim citation '{evidence_id}' is not a canonical digest"),
                    )
                    .for_claim(&claim.id),
                );
            }
        }
        for assumption_id in &claim.assumptions {
            if !valid_id(assumption_id) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvSchema,
                        format!("claim assumption ID '{assumption_id}' is invalid"),
                    )
                    .for_claim(&claim.id),
                );
            }
        }
        let mut obligation_ids = BTreeSet::new();
        for obligation in &claim.open_obligations {
            if !obligation_ids.insert(obligation.id.as_str())
                || !valid_id(&obligation.id)
                || obligation.statement.trim().is_empty()
                || obligation.remediation.trim().is_empty()
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvSchema,
                        "open obligation must include ID, statement, and remediation",
                    )
                    .for_claim(&claim.id),
                );
            }
        }
        let mut exclusion_ids = BTreeSet::new();
        for exclusion in &claim.out_of_scope {
            if !exclusion_ids.insert(exclusion.id.as_str())
                || !valid_id(&exclusion.id)
                || exclusion.statement.trim().is_empty()
                || exclusion.rationale.trim().is_empty()
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvSchema,
                        "out-of-scope record must include ID, statement, and rationale",
                    )
                    .for_claim(&claim.id),
                );
            }
        }
    }
    for (id, record) in evidence {
        if !valid_id(&record.unit_id) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvSchema,
                    format!("evidence unit ID '{}' is invalid", record.unit_id),
                )
                .at(id),
            );
        }
        if record.claim_ids.is_empty() {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidEvidence,
                    "evidence has no affected claim",
                )
                .at(id),
            );
        }
        for claim in &record.claim_ids {
            if !claims.contains_key(claim) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!("evidence names absent claim '{claim}'"),
                    )
                    .at(id),
                );
            }
        }
        for assumption in &record.assumptions {
            if !valid_id(assumption) || !assumptions.contains_key(assumption) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!("evidence names absent assumption '{assumption}'"),
                    )
                    .at(id),
                );
            }
        }
        for premise in &record.premises {
            if !valid_id(premise) || !premises.contains_key(premise) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!("evidence names absent premise '{premise}'"),
                    )
                    .at(id),
                );
            }
        }
        if let Some(theorem) = &record.theorem
            && !claims.contains_key(&theorem.attributed_claim)
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvMissingReference,
                    format!(
                        "theorem attribution names absent claim '{}'",
                        theorem.attributed_claim
                    ),
                )
                .at(id),
            );
        }
        if let Some(theorem) = &record.theorem {
            if theorem
                .foundational_axioms
                .iter()
                .any(|axiom| axiom.trim().is_empty())
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvInvalidEvidence,
                        "theorem has an empty foundational axiom identity",
                    )
                    .at(id),
                );
            }
            for axiom in &theorem.project_axioms {
                if !valid_id(axiom)
                    || !assumptions.contains_key(axiom)
                    || !record.assumptions.contains(axiom)
                {
                    issues.push(
                        VerificationIssue::new(
                            VerificationIssueCode::PbvInvalidAssumption,
                            format!(
                                "theorem project axiom '{axiom}' is not a registered evidence assumption"
                            ),
                        )
                        .at(id),
                    );
                }
            }
        }
        for (label, theorem_id) in record
            .artifact_binding
            .iter()
            .map(|binding| ("artifact", binding.theorem_evidence.as_str()))
            .chain(record.source_refinement.iter().map(|refinement| {
                (
                    "source-refinement",
                    refinement.refinement_theorem_evidence.as_str(),
                )
            }))
        {
            if !valid_digest(theorem_id)
                || evidence
                    .get(theorem_id)
                    .is_none_or(|theorem| theorem.kind != EvidenceKind::Theorem)
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!(
                            "{label} evidence names absent or non-theorem evidence '{theorem_id}'"
                        ),
                    )
                    .at(id),
                );
            }
        }
    }
    for assumption in &release.assumptions {
        if assumption.schema != ASSUMPTION_SCHEMA_V1 {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvSchema,
                    format!("unsupported assumption schema '{}'", assumption.schema),
                )
                .at(&assumption.id),
            );
        }
        if assumption.statement.trim().is_empty()
            || assumption.owner.trim().is_empty()
            || assumption.rationale.trim().is_empty()
            || assumption.scope.trim().is_empty()
            || assumption.falsification_or_discharge_plan.trim().is_empty()
            || assumption
                .source_citation
                .as_deref()
                .is_some_and(|citation| citation.trim().is_empty())
            || assumption.review_evidence.is_empty()
            || !graph_node_is(&release.graph, &assumption.node_id, NodeKind::Assumption)
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidAssumption,
                    "assumption ledger record is incomplete",
                )
                .at(&assumption.id),
            );
        }
        for claim in &assumption.affected_claims {
            if !claims.contains_key(claim) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!("assumption affects absent claim '{claim}'"),
                    )
                    .at(&assumption.id),
                );
            }
        }
        for dependency in &assumption.depends_on {
            if !valid_id(dependency) || !assumptions.contains_key(dependency) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!("assumption depends on absent assumption '{dependency}'"),
                    )
                    .at(&assumption.id),
                );
            }
        }
        for review in &assumption.review_evidence {
            if !valid_digest(review)
                || evidence
                    .get(review)
                    .is_none_or(|record| record.kind != EvidenceKind::Review)
            {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvMissingReference,
                        format!("assumption review '{review}' is absent or has the wrong kind"),
                    )
                    .at(&assumption.id),
                );
            }
        }
    }
    for premise in &release.premises {
        if !graph_node_is(&release.graph, &premise.node_id, NodeKind::Premise) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidPremise,
                    "premise node is absent or has the wrong graph kind",
                )
                .at(&premise.id),
            );
        }
        match &premise.theorem_evidence {
            Some(owner)
                if valid_digest(owner)
                    && evidence
                        .get(owner)
                        .is_some_and(|record| record.kind == EvidenceKind::Theorem) => {}
            Some(_) => issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidPremise,
                    "premise is detached from a registered theorem",
                )
                .at(&premise.id),
            ),
            None => {
                let directly_bound = release.claims.iter().any(|claim| {
                    release.graph.edges.iter().any(|edge| {
                        edge.from == claim.node_id
                            && edge.to == premise.node_id
                            && edge.kind == EdgeKind::Assumes
                    })
                });
                if !directly_bound {
                    issues.push(
                        VerificationIssue::new(
                            VerificationIssueCode::PbvInvalidPremise,
                            "ownerless premise has no exact claim-to-premise assumes edge",
                        )
                        .at(&premise.id),
                    );
                }
                if premise.discharge.is_some() {
                    issues.push(
                        VerificationIssue::new(
                            VerificationIssueCode::PbvInvalidPremise,
                            "direct ownerless premise cannot declare a discharge",
                        )
                        .at(&premise.id),
                    );
                }
            }
        }
        if let Some(discharge) = &premise.discharge
            && (!valid_digest(&discharge.theorem_evidence)
                || evidence
                    .get(&discharge.theorem_evidence)
                    .is_none_or(|record| record.kind != EvidenceKind::Theorem))
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvMissingReference,
                    format!(
                        "premise discharge names absent or non-theorem evidence '{}'",
                        discharge.theorem_evidence
                    ),
                )
                .at(&premise.id),
            );
        }
    }
    for policy in &release.policies {
        if !graph_node_is(&release.graph, &policy.node_id, NodeKind::Policy) {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidPolicy,
                    "policy node is absent or has the wrong graph kind",
                )
                .at(&policy.id),
            );
        }
        if policy
            .allowed_foundational_axioms
            .iter()
            .any(|axiom| axiom.trim().is_empty())
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvInvalidPolicy,
                    "policy has an empty foundational axiom identity",
                )
                .at(&policy.id),
            );
        }
        for axiom in &policy.allowed_project_axioms {
            if !valid_id(axiom) || !assumptions.contains_key(axiom) {
                issues.push(
                    VerificationIssue::new(
                        VerificationIssueCode::PbvInvalidPolicy,
                        format!("policy allowlists absent project assumption '{axiom}'"),
                    )
                    .at(&policy.id),
                );
            }
        }
    }
}

fn validate_policy(policy: &PolicyReceipt, issues: &mut Vec<VerificationIssue>) {
    let issue = |message: String| {
        VerificationIssue::new(VerificationIssueCode::PbvInvalidPolicy, message)
            .at(policy.id.clone())
    };
    if policy.schema != POLICY_SCHEMA_V1 {
        issues.push(issue(format!(
            "unsupported policy schema '{}'",
            policy.schema
        )));
    }
    if policy.id.trim().is_empty() || policy.node_id.trim().is_empty() {
        issues.push(issue("policy identity is empty".into()));
    }
    let profiles = [
        BuiltInProfile::Ledger,
        BuiltInProfile::Kernel,
        BuiltInProfile::KernelWithAssumptions,
        BuiltInProfile::ArtifactBound,
        BuiltInProfile::SourceRefined,
        BuiltInProfile::NativeEvaluated,
        BuiltInProfile::Bounded,
    ];
    if let Some(profile) = profiles
        .into_iter()
        .find(|profile| policy.id == profile.name())
        && (policy.components != BTreeSet::from([profile])
            || policy.admit_exhaustive_as_proved
            || policy.require_no_assumptions
            || !policy.additional_required_evidence.is_empty())
    {
        issues.push(issue("built-in policy semantics were redefined".into()));
    }
    let kernel = policy.components.contains(&BuiltInProfile::Kernel);
    let kernel_eval = kernel
        || policy
            .components
            .contains(&BuiltInProfile::KernelWithAssumptions);
    let native = policy.components.contains(&BuiltInProfile::NativeEvaluated);
    let ledger = policy.components.contains(&BuiltInProfile::Ledger);
    if ledger
        && (policy.components.len() != 1
            || !policy.allowed_foundational_axioms.is_empty()
            || !policy.allowed_project_axioms.is_empty()
            || policy.admit_exhaustive_as_proved
            || policy.additional_required_evidence.iter().any(|kind| {
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
        issues.push(issue(
            "ledger cannot compose axiom, formal, bounded, or subject-binding requirements".into(),
        ));
    }
    if kernel_eval && native {
        issues.push(issue(
            "kernel and native evaluation cannot be composed".into(),
        ));
    }
    if kernel && !policy.allowed_project_axioms.is_empty() {
        issues.push(issue("kernel policy cannot allow project axioms".into()));
    }
    let assumption_capable = policy.components.iter().any(|profile| {
        matches!(
            profile,
            BuiltInProfile::KernelWithAssumptions
                | BuiltInProfile::ArtifactBound
                | BuiltInProfile::SourceRefined
                | BuiltInProfile::NativeEvaluated
        )
    });
    if !assumption_capable && !policy.allowed_project_axioms.is_empty() {
        issues.push(issue("policy cannot admit project axioms".into()));
    }
    match (native, &policy.native_premise_rule) {
        (true, None) => issues.push(issue("native policy requires a premise-count rule".into())),
        (false, Some(_)) => {
            issues.push(issue("non-native policy has a native premise rule".into()))
        }
        (_, Some(crate::NativePremiseRule::Exactly { count: 0 })) => {
            issues.push(issue(
                "native policy cannot require exactly zero premises".into(),
            ));
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_claim(
    release: &CompiledRelease,
    claim: &ClaimReceipt,
    policies: &BTreeMap<String, &PolicyReceipt>,
    assumptions: &BTreeMap<String, &AssumptionReceipt>,
    premises: &BTreeMap<String, &PremiseReceipt>,
    evidence: &BTreeMap<String, &EvidenceReceipt>,
    invalid_evidence: &BTreeSet<String>,
) -> (ReportedClaimStatus, Vec<VerificationIssue>) {
    let mut issues = Vec::new();
    let effective_tier = claim
        .tier
        .map_or(release.project_tier, |tier| tier.min(release.project_tier));
    macro_rules! claim_issue {
        ($code:expr, $message:expr $(,)?) => {
            issues.push(VerificationIssue::new($code, $message).for_claim(&claim.id))
        };
    }
    if claim.id.trim().is_empty()
        || claim.title.trim().is_empty()
        || claim.statement.trim().is_empty()
    {
        claim_issue!(
            VerificationIssueCode::PbvSchema,
            "claim identity, title, and exact statement must be non-empty",
        );
    }
    require_claim_node(
        &release.graph,
        &claim.node_id,
        &[NodeKind::Claim],
        "claim",
        &claim.id,
        &mut issues,
    );
    require_claim_node(
        &release.graph,
        &claim.subject,
        &[NodeKind::Subject, NodeKind::Artifact],
        "shipping subject",
        &claim.id,
        &mut issues,
    );
    let Some(policy) = policies.get(&claim.policy).copied() else {
        claim_issue!(
            VerificationIssueCode::PbvMissingReference,
            format!("claim policy '{}' is absent", claim.policy),
        );
        return (
            ReportedClaimStatus {
                claim_id: claim.id.clone(),
                formal: FormalFacet::Invalid,
                linkage: None,
                assumption: AssumptionFacet::None,
                assumptions: BTreeSet::new(),
                undischarged_premises: BTreeSet::new(),
                policy_admitted: false,
            },
            issues,
        );
    };
    require_claim_node(
        &release.graph,
        &policy.node_id,
        &[NodeKind::Policy],
        "policy",
        &claim.id,
        &mut issues,
    );
    if claim
        .tier
        .is_some_and(|tier| !release.project_tier.admits(tier))
    {
        claim_issue!(
            VerificationIssueCode::PbvTierExceeded,
            format!(
                "claim tier {} exceeds project tier {}",
                claim.tier.expect("checked as present").number(),
                release.project_tier.number()
            ),
        );
    }
    if !effective_tier.admits(policy_minimum_tier(policy)) {
        claim_issue!(
            VerificationIssueCode::PbvTierExceeded,
            format!(
                "policy '{}' needs tier {}, above effective claim tier {}",
                policy.id,
                policy_minimum_tier(policy).number(),
                effective_tier.number()
            ),
        );
    }

    let mut relevant = claim.cited_evidence.clone();
    let mut assumption_ids = claim.assumptions.clone();
    let mut premise_ids = BTreeSet::new();
    for record in assumptions.values() {
        if record.affected_claims.contains(&claim.id) {
            assumption_ids.insert(record.id.clone());
        }
    }

    loop {
        let before = (relevant.len(), assumption_ids.len(), premise_ids.len());
        for id in relevant.clone() {
            if let Some(record) = evidence.get(&id) {
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
        for premise in premises.values() {
            if premise
                .theorem_evidence
                .as_ref()
                .is_some_and(|owner| relevant.contains(owner))
            {
                premise_ids.insert(premise.id.clone());
            }
        }
        let evidence_nodes = relevant
            .iter()
            .filter_map(|id| evidence.get(id).map(|record| record.node_id.as_str()))
            .chain(std::iter::once(claim.node_id.as_str()))
            .collect::<BTreeSet<_>>();
        for edge in &release.graph.edges {
            if edge.kind != EdgeKind::Assumes || !evidence_nodes.contains(edge.from.as_str()) {
                continue;
            }
            for assumption in assumptions.values() {
                if assumption.node_id == edge.to {
                    assumption_ids.insert(assumption.id.clone());
                }
            }
            for premise in premises.values() {
                if premise.node_id == edge.to {
                    premise_ids.insert(premise.id.clone());
                }
            }
        }
        for premise_id in premise_ids.clone() {
            if let Some(discharge) = premises.get(&premise_id).and_then(|premise| {
                premise
                    .theorem_evidence
                    .as_ref()
                    .and(premise.discharge.as_ref())
            }) {
                relevant.insert(discharge.theorem_evidence.clone());
            }
        }
        let mut queue = assumption_ids.iter().cloned().collect::<VecDeque<_>>();
        while let Some(id) = queue.pop_front() {
            if let Some(record) = assumptions.get(&id) {
                relevant.extend(record.review_evidence.iter().cloned());
                for dependency in &record.depends_on {
                    if assumption_ids.insert(dependency.clone()) {
                        queue.push_back(dependency.clone());
                    }
                }
            }
        }
        if before == (relevant.len(), assumption_ids.len(), premise_ids.len()) {
            break;
        }
    }

    for (id, record) in evidence {
        if record.claim_ids.contains(&claim.id) && !relevant.contains(id) {
            claim_issue!(
                VerificationIssueCode::PbvInvalidEvidence,
                format!(
                    "evidence unit '{}' targets the claim but is outside its registered closure",
                    record.unit_id
                ),
            );
        }
    }

    let mut valid = BTreeSet::new();
    for id in &relevant {
        let Some(record) = evidence.get(id).copied() else {
            claim_issue!(
                VerificationIssueCode::PbvMissingReference,
                format!("cited evidence '{id}' is absent"),
            );
            continue;
        };
        if record.outcome != EvidenceOutcome::Passed {
            claim_issue!(
                VerificationIssueCode::PbvInvalidEvidence,
                format!("cited evidence '{id}' has outcome {:?}", record.outcome),
            );
            continue;
        }
        if invalid_evidence.contains(id) {
            claim_issue!(
                VerificationIssueCode::PbvInvalidEvidence,
                format!("cited evidence '{id}' is structurally invalid"),
            );
            continue;
        }
        if !record.claim_ids.contains(&claim.id) {
            claim_issue!(
                VerificationIssueCode::PbvInvalidEvidence,
                format!(
                    "cited evidence '{id}' does not identify claim '{}'",
                    claim.id
                ),
            );
            continue;
        }
        if record
            .theorem
            .as_ref()
            .is_some_and(|theorem| theorem.attributed_claim != claim.id)
        {
            claim_issue!(
                VerificationIssueCode::PbvInvalidEvidence,
                format!("theorem evidence '{id}' is attributed to another claim"),
            );
            continue;
        }
        if !effective_tier.admits(record.kind.minimum_tier()) {
            claim_issue!(
                VerificationIssueCode::PbvTierExceeded,
                format!(
                    "evidence '{id}' needs tier {}, above effective claim tier {}",
                    record.kind.minimum_tier().number(),
                    effective_tier.number()
                ),
            );
            continue;
        }
        valid.insert(id.clone());
    }

    let mut active_assumptions = BTreeSet::new();
    for id in &assumption_ids {
        let Some(record) = assumptions.get(id).copied() else {
            claim_issue!(
                VerificationIssueCode::PbvInvalidAssumption,
                format!("assumption '{id}' has no ledger record"),
            );
            continue;
        };
        let malformed = record.schema != ASSUMPTION_SCHEMA_V1
            || record.statement.trim().is_empty()
            || record.owner.trim().is_empty()
            || record.rationale.trim().is_empty()
            || record.scope.trim().is_empty()
            || record.falsification_or_discharge_plan.trim().is_empty()
            || record.review_evidence.is_empty()
            || !record.affected_claims.contains(&claim.id)
            || !graph_node_is(&release.graph, &record.node_id, NodeKind::Assumption);
        if malformed {
            claim_issue!(
                VerificationIssueCode::PbvInvalidAssumption,
                format!("assumption '{id}' is incomplete or does not affect this claim"),
            );
        }
        match record.state {
            AssumptionState::Active => {
                active_assumptions.insert(id.clone());
            }
            AssumptionState::Discharged => {
                active_assumptions.insert(id.clone());
                claim_issue!(
                    VerificationIssueCode::PbvInvalidAssumption,
                    format!("assumption '{id}' is manually marked discharged without proof"),
                );
            }
            AssumptionState::Retired => claim_issue!(
                VerificationIssueCode::PbvInvalidAssumption,
                format!("retired assumption '{id}' still affects the claim"),
            ),
        }
    }

    let native_count = active_assumptions
        .iter()
        .filter(|id| {
            assumptions
                .get(*id)
                .is_some_and(|record| record.category == AssumptionCategory::NativeEvaluation)
        })
        .count();
    let mut admitted_theorems = BTreeSet::new();
    for id in &valid {
        let record = evidence[id];
        if record.kind == EvidenceKind::Theorem
            && theorem_admitted(
                policy,
                record,
                assumptions,
                &active_assumptions,
                native_count,
            )
        {
            admitted_theorems.insert(id.clone());
        }
    }
    for id in &relevant {
        if let Some(theorem) = evidence.get(id).and_then(|record| record.theorem.as_ref()) {
            for axiom in &theorem.project_axioms {
                if !active_assumptions.contains(axiom) {
                    claim_issue!(
                        VerificationIssueCode::PbvInvalidAssumption,
                        format!("project axiom '{axiom}' is not an active explicit assumption"),
                    );
                }
            }
        }
    }

    let mut undischarged = BTreeSet::new();
    for id in &premise_ids {
        let Some(premise) = premises.get(id).copied() else {
            claim_issue!(
                VerificationIssueCode::PbvInvalidPremise,
                format!("premise '{id}' has no ledger record"),
            );
            continue;
        };
        let owner_bound = match &premise.theorem_evidence {
            Some(owner) => {
                relevant.contains(owner)
                    && evidence
                        .get(owner)
                        .is_some_and(|record| record.kind == EvidenceKind::Theorem)
            }
            None => release.graph.edges.iter().any(|edge| {
                edge.from == claim.node_id
                    && edge.to == premise.node_id
                    && edge.kind == EdgeKind::Assumes
            }),
        };
        if premise.statement.trim().is_empty()
            || !graph_node_is(&release.graph, &premise.node_id, NodeKind::Premise)
            || !owner_bound
        {
            claim_issue!(
                VerificationIssueCode::PbvInvalidPremise,
                format!(
                    "premise '{id}' is incomplete or detached from its theorem or direct claim edge"
                ),
            );
        }
        if premise.theorem_evidence.is_none() && premise.discharge.is_some() {
            claim_issue!(
                VerificationIssueCode::PbvInvalidPremise,
                format!("direct ownerless premise '{id}' cannot declare a discharge"),
            );
        }
        let discharged = premise.theorem_evidence.is_some()
            && premise.discharge.as_ref().is_some_and(|discharge| {
                evidence
                    .get(&discharge.theorem_evidence)
                    .is_some_and(|record| {
                        admitted_theorems.contains(&discharge.theorem_evidence)
                            && release.graph.edges.iter().any(|edge| {
                                edge.from == premise.node_id
                                    && edge.to == record.node_id
                                    && edge.kind == EdgeKind::DischargedBy
                            })
                            && scope_covers(
                                &discharge.scope,
                                &premise.scope,
                                &claim.registered_inputs,
                            )
                    })
            });
        if !discharged {
            undischarged.insert(id.clone());
        }
    }

    let exhaustive_as_proof = !policy_ledger(policy)
        && policy.admit_exhaustive_as_proved
        && valid
            .iter()
            .any(|id| evidence[id].kind == EvidenceKind::ExhaustiveCheck);
    let mut formal = if policy_ledger(policy) {
        if valid.iter().any(|id| empirical(evidence[id])) {
            FormalFacet::Tested
        } else {
            FormalFacet::Open
        }
    } else if !admitted_theorems.is_empty() || exhaustive_as_proof {
        FormalFacet::Proved
    } else if valid
        .iter()
        .any(|id| evidence[id].kind == EvidenceKind::BoundedCheck)
    {
        FormalFacet::BoundedChecked
    } else if valid.iter().any(|id| empirical(evidence[id])) {
        FormalFacet::Tested
    } else {
        FormalFacet::Open
    };
    if (matches!(formal, FormalFacet::BoundedChecked) || exhaustive_as_proof)
        && claim
            .registered_domain_language
            .as_deref()
            .is_none_or(|language| language.trim().is_empty())
    {
        claim_issue!(
            VerificationIssueCode::PbvInvalidEvidence,
            "bounded standing has no registered finite-domain public language",
        );
    }

    let mut linkages = BTreeSet::new();
    for id in &valid {
        let record = evidence[id];
        match record.kind {
            EvidenceKind::SourceRefinement => {
                if let Some(refinement) = &record.source_refinement {
                    if !claim
                        .cited_evidence
                        .contains(&refinement.refinement_theorem_evidence)
                    {
                        claim_issue!(
                            VerificationIssueCode::PbvInvalidEvidence,
                            format!("source refinement '{id}' names an uncited theorem"),
                        );
                    } else if !policy_ledger(policy)
                        && admitted_theorems.contains(&refinement.refinement_theorem_evidence)
                        && refinement
                            .representation_premises
                            .iter()
                            .all(|premise| premises.contains_key(premise))
                    {
                        linkages.insert(LinkageFacet::Refined);
                    }
                }
            }
            EvidenceKind::ArtifactSoundness => {
                if let Some(binding) = &record.artifact_binding {
                    if !claim.cited_evidence.contains(&binding.theorem_evidence) {
                        claim_issue!(
                            VerificationIssueCode::PbvInvalidEvidence,
                            format!("artifact binding '{id}' names an uncited theorem"),
                        );
                    } else if !policy_ledger(policy)
                        && admitted_theorems.contains(&binding.theorem_evidence)
                        && artifact_evaluation_admitted(policy, record.evaluation_mode)
                    {
                        linkages.insert(LinkageFacet::ArtifactBound);
                    }
                }
            }
            EvidenceKind::TrustedTranscription => {
                if !policy_ledger(policy) {
                    linkages.insert(LinkageFacet::Transcribed);
                }
            }
            _ => {}
        }
    }
    let linkage = choose_linkage(claim, &linkages, &mut issues);

    if !issues.is_empty() {
        formal = FormalFacet::Invalid;
    }
    let standing = if active_assumptions.is_empty() && undischarged.is_empty() {
        AssumptionFacet::None
    } else {
        AssumptionFacet::Assumed
    };
    let policy_admitted = formal != FormalFacet::Invalid
        && effective_tier.admits(policy_minimum_tier(policy))
        && (!policy_requires_theorem(policy) || formal == FormalFacet::Proved)
        && (!policy.components.contains(&BuiltInProfile::ArtifactBound)
            || linkage == LinkageFacet::ArtifactBound)
        && (!policy.components.contains(&BuiltInProfile::SourceRefined)
            || linkage == LinkageFacet::Refined)
        && (!policy.components.contains(&BuiltInProfile::Bounded)
            || valid
                .iter()
                .any(|id| evidence[id].kind == EvidenceKind::BoundedCheck))
        && (!policy.require_no_assumptions || standing == AssumptionFacet::None)
        && policy
            .native_premise_rule
            .as_ref()
            .is_none_or(|rule| rule.accepts(native_count))
        && policy
            .additional_required_evidence
            .iter()
            .all(|kind| valid.iter().any(|id| evidence[id].kind == *kind));
    (
        ReportedClaimStatus {
            claim_id: claim.id.clone(),
            formal,
            linkage: (formal != FormalFacet::Invalid).then_some(linkage),
            assumption: standing,
            assumptions: active_assumptions,
            undischarged_premises: undischarged,
            policy_admitted,
        },
        issues,
    )
}

fn graph_node_is(graph: &AssuranceGraph, id: &str, kind: NodeKind) -> bool {
    graph
        .nodes
        .iter()
        .any(|node| node.id == id && node.kind == kind)
}

fn require_claim_node(
    graph: &AssuranceGraph,
    id: &str,
    expected: &[NodeKind],
    label: &str,
    claim: &str,
    issues: &mut Vec<VerificationIssue>,
) {
    if !graph
        .nodes
        .iter()
        .any(|node| node.id == id && expected.contains(&node.kind))
    {
        issues.push(
            VerificationIssue::new(
                VerificationIssueCode::PbvInvalidGraph,
                format!("{label} node '{id}' is absent or has the wrong kind"),
            )
            .for_claim(claim),
        );
    }
}

fn policy_minimum_tier(policy: &PolicyReceipt) -> Tier {
    policy
        .components
        .iter()
        .map(|profile| profile.minimum_tier())
        .max()
        .unwrap_or(Tier::Ledger)
}

fn policy_requires_theorem(policy: &PolicyReceipt) -> bool {
    policy.components.iter().any(|profile| {
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

fn policy_native(policy: &PolicyReceipt) -> bool {
    policy.components.contains(&BuiltInProfile::NativeEvaluated)
}

fn policy_ledger(policy: &PolicyReceipt) -> bool {
    policy.components.contains(&BuiltInProfile::Ledger)
}

fn artifact_evaluation_admitted(
    policy: &PolicyReceipt,
    evaluation_mode: Option<EvaluationMode>,
) -> bool {
    if policy_native(policy) {
        evaluation_mode == Some(EvaluationMode::Native)
    } else if policy.components.contains(&BuiltInProfile::ArtifactBound) {
        matches!(
            evaluation_mode,
            Some(EvaluationMode::Kernel | EvaluationMode::Native)
        )
    } else {
        evaluation_mode == Some(EvaluationMode::Kernel)
    }
}

fn theorem_admitted(
    policy: &PolicyReceipt,
    evidence: &EvidenceReceipt,
    assumptions: &BTreeMap<String, &AssumptionReceipt>,
    active: &BTreeSet<String>,
    claim_native_count: usize,
) -> bool {
    if evidence.kind != EvidenceKind::Theorem || !policy_requires_theorem(policy) {
        return false;
    }
    let expected = if policy_native(policy) {
        EvaluationMode::Native
    } else {
        EvaluationMode::Kernel
    };
    if evidence.evaluation_mode != Some(expected) {
        return false;
    }
    let Some(theorem) = &evidence.theorem else {
        return false;
    };
    if !theorem.axiom_audit_passed
        || theorem.contains_sorry_ax
        || !theorem
            .foundational_axioms
            .is_subset(&policy.allowed_foundational_axioms)
        || !theorem
            .project_axioms
            .is_subset(&policy.allowed_project_axioms)
        || !theorem.project_axioms.is_subset(active)
        || (policy.components.contains(&BuiltInProfile::Kernel)
            && !theorem.project_axioms.is_empty())
    {
        return false;
    }
    let theorem_native_count = evidence
        .assumptions
        .iter()
        .filter(|id| {
            active.contains(*id)
                && assumptions
                    .get(*id)
                    .is_some_and(|item| item.category == AssumptionCategory::NativeEvaluation)
        })
        .count();
    policy
        .native_premise_rule
        .as_ref()
        .is_none_or(|rule| rule.accepts(claim_native_count) && rule.accepts(theorem_native_count))
}

fn scope_covers(discharge: &FlowScope, premise: &FlowScope, registered: &BTreeSet<String>) -> bool {
    let required = match premise {
        FlowScope::AllRegisteredInputs => registered,
        FlowScope::Flows { flows } => flows,
    };
    match discharge {
        FlowScope::AllRegisteredInputs => true,
        FlowScope::Flows { flows } => !required.is_empty() && flows.is_superset(required),
    }
}

fn empirical(evidence: &EvidenceReceipt) -> bool {
    matches!(
        evidence.kind,
        EvidenceKind::PropertyTest
            | EvidenceKind::ExampleTest
            | EvidenceKind::IndependentCheck
            | EvidenceKind::ExhaustiveCheck
    ) || (evidence.kind == EvidenceKind::MutationWitness
        && evidence
            .mutation_witness
            .as_ref()
            .is_some_and(|witness| !witness.proof_term_witness))
}

fn choose_linkage(
    claim: &ClaimReceipt,
    candidates: &BTreeSet<LinkageFacet>,
    issues: &mut Vec<VerificationIssue>,
) -> LinkageFacet {
    if candidates.is_empty() {
        if claim
            .primary_linkage
            .is_some_and(|linkage| linkage != LinkageFacet::ModelOnly)
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvAmbiguousLinkage,
                    "primary linkage has no validated binding evidence",
                )
                .for_claim(&claim.id),
            );
        }
        return LinkageFacet::ModelOnly;
    }
    if candidates.len() == 1 {
        let only = *candidates.first().expect("one linkage candidate");
        if claim
            .primary_linkage
            .is_some_and(|selected| selected != only)
        {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvAmbiguousLinkage,
                    "primary linkage does not match the only validated binding",
                )
                .for_claim(&claim.id),
            );
        }
        return only;
    }
    match claim.primary_linkage {
        Some(selected) if selected != LinkageFacet::ModelOnly && candidates.contains(&selected) => {
            selected
        }
        _ => {
            issues.push(
                VerificationIssue::new(
                    VerificationIssueCode::PbvAmbiguousLinkage,
                    format!("multiple binding paths require a primary selection: {candidates:?}"),
                )
                .for_claim(&claim.id),
            );
            LinkageFacet::ModelOnly
        }
    }
}

fn compact_status(status: &ReportedClaimStatus) -> String {
    format!(
        "{:?}/{:?}/{:?}; policy={}; assumptions={:?}; premises={:?}",
        status.formal,
        status.linkage,
        status.assumption,
        status.policy_admitted,
        status.assumptions,
        status.undischarged_premises
    )
}

impl fmt::Display for VerificationIssueCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        formatter.write_str(value.as_str().ok_or(fmt::Error)?)
    }
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

    fn policy(components: BTreeSet<BuiltInProfile>) -> PolicyReceipt {
        PolicyReceipt {
            schema: POLICY_SCHEMA_V1.into(),
            id: "artifact-test".into(),
            node_id: "policy:artifact-test".into(),
            components,
            allowed_foundational_axioms: BTreeSet::new(),
            allowed_project_axioms: BTreeSet::new(),
            admit_exhaustive_as_proved: false,
            require_no_assumptions: false,
            native_premise_rule: None,
            additional_required_evidence: BTreeSet::new(),
        }
    }

    #[test]
    fn artifact_bound_accepts_native_binding_but_native_composition_requires_it() {
        let artifact = policy(BTreeSet::from([BuiltInProfile::ArtifactBound]));
        assert!(artifact_evaluation_admitted(
            &artifact,
            Some(EvaluationMode::Kernel)
        ));
        assert!(artifact_evaluation_admitted(
            &artifact,
            Some(EvaluationMode::Native)
        ));

        let native_artifact = policy(BTreeSet::from([
            BuiltInProfile::ArtifactBound,
            BuiltInProfile::NativeEvaluated,
        ]));
        assert!(!artifact_evaluation_admitted(
            &native_artifact,
            Some(EvaluationMode::Kernel)
        ));
        assert!(artifact_evaluation_admitted(
            &native_artifact,
            Some(EvaluationMode::Native)
        ));
    }

    #[test]
    fn endpoint_legality_table_is_complete_unique_and_fail_closed() {
        assert_eq!(LEGAL_EDGE_ENDPOINTS.len(), 22);
        let unique = LEGAL_EDGE_ENDPOINTS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), LEGAL_EDGE_ENDPOINTS.len());

        for edge_kind in ALL_EDGE_KINDS {
            assert!(
                LEGAL_EDGE_ENDPOINTS
                    .iter()
                    .any(|(kind, _, _)| *kind == edge_kind),
                "missing endpoint rule for {edge_kind:?}"
            );
        }

        for edge_kind in ALL_EDGE_KINDS {
            for from_kind in ALL_NODE_KINDS {
                for to_kind in ALL_NODE_KINDS {
                    let listed = LEGAL_EDGE_ENDPOINTS.contains(&(edge_kind, from_kind, to_kind));
                    assert_eq!(
                        legal_edge_endpoints(edge_kind, from_kind, to_kind),
                        listed,
                        "unexpected legality for {from_kind:?} --{edge_kind:?}--> {to_kind:?}"
                    );
                }
            }
        }

        assert!(LEGAL_EDGE_ENDPOINTS.iter().all(|(_, from, to)| {
            !matches!(from, NodeKind::Toolchain | NodeKind::TcbComponent)
                && !matches!(to, NodeKind::Toolchain | NodeKind::TcbComponent)
        }));
    }
}
