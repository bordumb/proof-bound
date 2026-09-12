use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
    str::FromStr,
};

use proofbound_core::{AssumptionId, Sha256Digest};
use proofbound_evidence::canonical_json;
use proofbound_manifest::{AdapterKind, EvidenceKind, OperationKind};
use sha2::{Digest as _, Sha256};

use crate::{
    artifact::validate_digest_binding_v1,
    error::{
        AUDIT_OUTPUT, AXIOM, AdapterError, CONFIGURATION, DECLARATION, EXPR_WIRE, INVENTORY,
        STATEMENT_DRIFT,
    },
    model::{
        AuditClaim, AuditOutput, DeclarationKind, ExpectedClaim, LEAN_ADAPTER_UNIT_SCHEMA,
        LEAN_AUDIT_SCHEMA, LeanAdapterUnit, VerifiedAudit,
    },
    wire::{STATEMENT_ENCODING, statement_digest},
};

const MAX_AUDIT_BYTES: usize = 64 << 20;
const MAX_CLAIMS: usize = 100_000;
const MAX_AXIOMS: usize = 4_096;
const MAX_EXEMPTIONS: usize = 100_000;

/// Parse exactly one strict `proofbound_lean_audit` JSON value. Tool output is
/// normalized before receipt hashing, so the Lean executable is not required
/// to order JSON object keys itself.
pub fn parse_audit_bytes(bytes: &[u8]) -> Result<AuditOutput, AdapterError> {
    if bytes.len() > MAX_AUDIT_BYTES {
        return Err(AdapterError::new(
            AUDIT_OUTPUT,
            format!("Lean audit output exceeds {MAX_AUDIT_BYTES} bytes"),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let output = AuditOutput::deserialize(&mut deserializer).map_err(|error| {
        AdapterError::new(AUDIT_OUTPUT, format!("malformed Lean audit JSON: {error}"))
    })?;
    deserializer.end().map_err(|error| {
        AdapterError::new(
            AUDIT_OUTPUT,
            format!("trailing bytes after Lean audit JSON: {error}"),
        )
    })?;
    Ok(output)
}

/// Validate the compiled audit, reconcile its complete attributed inventory in
/// both directions, and select the theorem represented by this evidence unit.
pub fn verify_audit(
    unit: &LeanAdapterUnit,
    output: &AuditOutput,
    require_target_digest: bool,
) -> Result<VerifiedAudit, AdapterError> {
    verify_audit_with_policy(unit, output, require_target_digest, true)
}

/// Validate all compiled facts while deliberately observing (rather than
/// accepting) the current statement digest. Used only by the explicit update
/// operation; the resulting receipt is marked `drifted` and cannot satisfy a
/// claim until a subsequent pinned check passes.
pub fn observe_audit(
    unit: &LeanAdapterUnit,
    output: &AuditOutput,
) -> Result<VerifiedAudit, AdapterError> {
    verify_audit_with_policy(unit, output, false, false)
}

fn verify_audit_with_policy(
    unit: &LeanAdapterUnit,
    output: &AuditOutput,
    require_target_digest: bool,
    compare_pinned_digests: bool,
) -> Result<VerifiedAudit, AdapterError> {
    validate_unit(unit)?;
    validate_output(output)?;

    let expected = expected_inventory(&unit.claim_inventory)?;
    let actual = actual_inventory(output)?;

    let expected_ids: BTreeSet<_> = expected.keys().cloned().collect();
    let actual_ids: BTreeSet<_> = actual.keys().cloned().collect();
    if expected_ids != actual_ids {
        let missing: Vec<_> = expected_ids.difference(&actual_ids).cloned().collect();
        let unknown: Vec<_> = actual_ids.difference(&expected_ids).cloned().collect();
        return Err(AdapterError::new(
            INVENTORY,
            format!(
                "compiled attributed claim inventory differs from registration; missing={missing:?}, unknown={unknown:?}"
            ),
        )
        .remediate(
            "register every compiled proofbound_claim and ensure every registered claim is imported",
        ));
    }
    let configured: BTreeSet<_> = unit
        .evidence_unit
        .expected_inventory
        .iter()
        .cloned()
        .collect();
    let compiled: BTreeSet<_> = output
        .claims
        .iter()
        .map(|claim| claim.declaration.clone())
        .collect();
    if configured != compiled {
        return Err(AdapterError::new(
            INVENTORY,
            format!(
                "evidence_unit.expected_inventory differs from compiled declarations; configured={configured:?}, compiled={compiled:?}"
            ),
        ));
    }

    let mut target_verified = None;
    let target_id = unit
        .evidence_unit
        .claims
        .first()
        .expect("validate_unit establishes exactly one claim");
    for claim_id in &expected_ids {
        let expected_claim = expected
            .get(claim_id)
            .expect("key originates from expected map");
        let actual_claim = actual.get(claim_id).expect("sets were proven equal");
        let verified = verify_claim(expected_claim, actual_claim)?;
        if compare_pinned_digests && let Some(expected_digest) = &expected_claim.statement_sha256 {
            let pinned = parse_prefixed_digest(expected_digest).map_err(|message| {
                AdapterError::new(CONFIGURATION, message)
                    .at(format!("claim_inventory[{claim_id}].statement_sha256"))
            })?;
            if pinned != verified.0 {
                return Err(AdapterError::new(
                    STATEMENT_DRIFT,
                    format!(
                        "statement digest drift for '{claim_id}': expected sha256:{pinned}, computed sha256:{}",
                        verified.0
                    ),
                )
                .remediate(
                    "review the elaborated theorem change and update the claim digest explicitly",
                ));
            }
        } else if compare_pinned_digests && require_target_digest && claim_id == target_id {
            return Err(AdapterError::new(
                STATEMENT_DRIFT,
                format!("registered target claim '{claim_id}' has no statement_sha256"),
            )
            .remediate(
                "pin the domain-separated lean-expr-cbor/1 digest before checking the claim",
            ));
        }

        if claim_id == target_id {
            target_verified = Some(((*actual_claim).clone(), verified));
        }
    }

    let (target, (statement_sha256, foundational_axioms, project_axioms)) = target_verified
        .ok_or_else(|| {
            AdapterError::new(
                INVENTORY,
                format!("unit target claim '{target_id}' is absent from the compiled inventory"),
            )
        })?;

    let configured_theorem = unit
        .evidence_unit
        .theorem
        .as_deref()
        .expect("validate_unit establishes a theorem name");
    if target.declaration != configured_theorem {
        return Err(AdapterError::new(
            DECLARATION,
            format!(
                "unit theorem mismatch for '{target_id}': configured '{configured_theorem}', attributed '{}'",
                target.declaration
            ),
        ));
    }

    let configured_assumptions: BTreeSet<_> = unit
        .evidence_unit
        .assumptions
        .iter()
        .map(|value| {
            AssumptionId::new(value.clone()).map_err(|error| {
                AdapterError::new(
                    CONFIGURATION,
                    format!("invalid assumption ID '{value}': {error}"),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let native_evaluation = matches!(
        unit.evidence_unit.evaluation_mode,
        Some(proofbound_manifest::EvaluationMode::Native)
    );
    let non_project_assumptions = configured_assumptions
        .difference(&project_axioms)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !project_axioms.is_subset(&configured_assumptions)
        || (!native_evaluation && !non_project_assumptions.is_empty())
        || (native_evaluation && non_project_assumptions.is_empty())
    {
        return Err(AdapterError::new(
            AXIOM,
            format!(
                "unit assumptions do not classify the audited project axioms and native-evaluation boundary exactly; configured={configured_assumptions:?}, audited_project_axioms={project_axioms:?}, evaluation_mode={:?}",
                unit.evidence_unit.evaluation_mode
            ),
        )
        .remediate("map every project axiom to a registered assumption; kernel units permit no extras, while native units require at least one explicit non-project native-evaluation premise"));
    }

    let inventory = output
        .claims
        .iter()
        .map(|claim| claim.declaration.clone())
        .collect();
    let mut normalized = output.clone();
    normalized
        .exemptions
        .sort_by(|left, right| left.declaration.cmp(&right.declaration));
    let audit_identity = domain_digest(
        b"proofbound:lean-audit-output/1\0",
        &canonical_json(&normalized).map_err(|error| {
            AdapterError::new(
                AUDIT_OUTPUT,
                format!("cannot canonicalize Lean audit output: {error}"),
            )
        })?,
    );

    Ok(VerifiedAudit {
        target,
        statement_sha256,
        foundational_axioms,
        project_axioms,
        inventory,
        audit_identity,
    })
}

pub(crate) fn validate_unit(unit: &LeanAdapterUnit) -> Result<(), AdapterError> {
    if unit.schema != LEAN_ADAPTER_UNIT_SCHEMA {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("unsupported Lean adapter unit schema '{}'", unit.schema),
        ));
    }
    let evidence = &unit.evidence_unit;
    if evidence.schema != "proofbound-evidence-unit/1" {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("unsupported evidence unit schema '{}'", evidence.schema),
        ));
    }
    if evidence.adapter != AdapterKind::Lean
        || evidence.kind != EvidenceKind::Theorem
        || evidence.operation.kind != OperationKind::LeanAudit
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            "the Lean adapter accepts only adapter=lean, kind=theorem, type=lean-audit units",
        ));
    }
    validate_local_id(&evidence.id)?;
    if evidence.claims.len() != 1 {
        return Err(AdapterError::new(
            CONFIGURATION,
            "one Lean theorem evidence unit must cite exactly one claim",
        ));
    }
    if !(2..=3).contains(&evidence.tier) {
        return Err(AdapterError::new(
            CONFIGURATION,
            "Lean theorem evidence requires project tier 2 or 3",
        ));
    }
    if evidence.evaluation_mode.is_none() || evidence.theorem.as_deref().is_none_or(str::is_empty) {
        return Err(AdapterError::new(
            CONFIGURATION,
            "Lean theorem evidence requires evaluation_mode and an exact theorem declaration",
        ));
    }
    if evidence.binding_mode.is_some()
        || evidence.refinement_theorem.is_some()
        || evidence.bounded_domain.is_some()
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            "plain Lean theorem evidence contains qualifiers belonging to another evidence kind",
        ));
    }
    if evidence.operation.package.is_some()
        || evidence.operation.manifest.is_some()
        || evidence.operation.inventory.is_some()
        || evidence.operation.checker.is_some()
        || !evidence.operation.arguments.is_empty()
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            "Lean audit contains unsupported operation qualifiers",
        ));
    }
    if evidence.operation.targets.len() != 1 || evidence.operation.paths.is_empty() {
        return Err(AdapterError::new(
            CONFIGURATION,
            "one Lean theorem audit requires exactly one typed target and non-empty source paths",
        ));
    }
    let theorem = evidence
        .theorem
        .as_deref()
        .expect("theorem presence was checked above");
    if !evidence
        .operation
        .targets
        .iter()
        .any(|target| theorem == target || theorem.starts_with(&format!("{target}.")))
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("configured theorem '{theorem}' is not covered by operation.targets"),
        ));
    }
    if evidence.resource_budget.time_seconds == 0
        || evidence.resource_budget.disk_bytes == 0
        || evidence.resource_budget.memory_bytes == 0
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            "Lean audit resource budgets must all be non-zero",
        ));
    }
    require_sorted_unique("claims", &evidence.claims)?;
    require_sorted_unique("operation.targets", &evidence.operation.targets)?;
    require_sorted_unique("operation.paths", &evidence.operation.paths)?;
    require_sorted_unique("expected_inventory", &evidence.expected_inventory)?;
    require_sorted_unique("inputs", &evidence.inputs)?;
    require_sorted_unique("outputs", &evidence.outputs)?;
    require_sorted_unique("assumptions", &evidence.assumptions)?;
    require_sorted_unique("premises", &evidence.premises)?;
    require_sorted_unique("environment_allowlist", &evidence.environment_allowlist)?;
    if evidence.inputs.is_empty() {
        return Err(AdapterError::new(
            CONFIGURATION,
            "Lean theorem evidence requires at least one semantic input",
        ));
    }
    for path in evidence
        .operation
        .paths
        .iter()
        .chain(&evidence.inputs)
        .chain(&evidence.outputs)
    {
        validate_relative_file(path)?;
    }
    for target in evidence
        .operation
        .targets
        .iter()
        .chain(&evidence.expected_inventory)
    {
        validate_name(target, "configured Lean target")?;
    }
    for assumption in &evidence.assumptions {
        validate_claim_id(assumption)?;
    }
    for premise in &evidence.premises {
        validate_claim_id(premise)?;
    }
    for variable in &evidence.environment_allowlist {
        if variable.is_empty()
            || !variable.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_uppercase() || byte == b'_'
                } else {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
        {
            return Err(AdapterError::new(
                CONFIGURATION,
                format!("invalid environment allowlist name '{variable}'"),
            ));
        }
    }
    for claim_id in &evidence.claims {
        validate_claim_id(claim_id)?;
    }
    if unit.claim_inventory.is_empty() || unit.claim_inventory.len() > MAX_CLAIMS {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("claim_inventory must contain 1..={MAX_CLAIMS} entries"),
        ));
    }
    if !unit
        .claim_inventory
        .windows(2)
        .all(|pair| pair[0].claim_id < pair[1].claim_id)
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            "claim_inventory must be strictly sorted by claim_id",
        ));
    }
    let registered = expected_inventory(&unit.claim_inventory)?
        .into_values()
        .map(|claim| claim.declaration.clone())
        .collect::<BTreeSet<_>>();
    let configured = evidence
        .expected_inventory
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if evidence.expected_inventory.is_empty() || configured != registered {
        return Err(AdapterError::new(
            INVENTORY,
            format!(
                "evidence_unit.expected_inventory must be nonempty and exactly equal the registered Lean declarations; configured={configured:?}, registered={registered:?}"
            ),
        ));
    }
    Ok(())
}

fn validate_output(output: &AuditOutput) -> Result<(), AdapterError> {
    if output.schema != LEAN_AUDIT_SCHEMA || output.statement_encoding != STATEMENT_ENCODING {
        return Err(AdapterError::new(
            AUDIT_OUTPUT,
            format!(
                "unsupported Lean audit schema/encoding '{}'/ '{}'",
                output.schema, output.statement_encoding
            ),
        ));
    }
    if output.claims.len() > MAX_CLAIMS || output.exemptions.len() > MAX_EXEMPTIONS {
        return Err(AdapterError::new(
            AUDIT_OUTPUT,
            "Lean audit collection exceeds configured limits",
        ));
    }
    if !output
        .claims
        .windows(2)
        .all(|pair| pair[0].declaration < pair[1].declaration)
    {
        return Err(AdapterError::new(
            AUDIT_OUTPUT,
            "Lean audit claims are duplicated or not strictly sorted by declaration",
        ));
    }

    let mut exemptions = BTreeSet::new();
    let attributed: BTreeSet<_> = output
        .claims
        .iter()
        .map(|claim| claim.declaration.as_str())
        .collect();
    for exemption in &output.exemptions {
        validate_name(&exemption.declaration, "exemption declaration")?;
        validate_name(&exemption.module, "exemption module")?;
        if exemption.reason.trim().is_empty() || exemption.reason.len() > 8_192 {
            return Err(AdapterError::new(
                AUDIT_OUTPUT,
                format!(
                    "exemption '{}' has an empty or oversized reason",
                    exemption.declaration
                ),
            ));
        }
        if !exemptions.insert(exemption.declaration.as_str()) {
            return Err(AdapterError::new(
                AUDIT_OUTPUT,
                format!("duplicate exemption for '{}'", exemption.declaration),
            ));
        }
        if attributed.contains(exemption.declaration.as_str()) {
            return Err(AdapterError::new(
                AUDIT_OUTPUT,
                format!(
                    "declaration '{}' is both attributed and exempt",
                    exemption.declaration
                ),
            ));
        }
    }
    Ok(())
}

fn expected_inventory(
    claims: &[ExpectedClaim],
) -> Result<BTreeMap<String, &ExpectedClaim>, AdapterError> {
    let mut by_id = BTreeMap::new();
    let mut declarations = BTreeSet::new();
    for claim in claims {
        validate_claim_id(&claim.claim_id)?;
        validate_name(&claim.declaration, "expected declaration")?;
        if claim.declaration_kind != DeclarationKind::Theorem {
            return Err(AdapterError::new(
                DECLARATION,
                format!(
                    "public claim '{}' expects non-theorem declaration kind {:?}",
                    claim.claim_id, claim.declaration_kind
                ),
            ));
        }
        if by_id.insert(claim.claim_id.clone(), claim).is_some() {
            return Err(AdapterError::new(
                INVENTORY,
                format!("duplicate registered claim ID '{}'", claim.claim_id),
            ));
        }
        if !declarations.insert(claim.declaration.as_str()) {
            return Err(AdapterError::new(
                INVENTORY,
                format!("duplicate registered declaration '{}'", claim.declaration),
            ));
        }
        if !claim
            .foundational_axioms
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(AdapterError::new(
                AXIOM,
                format!(
                    "foundational axioms for '{}' are duplicated or not strictly sorted",
                    claim.claim_id
                ),
            ));
        }
        for axiom in &claim.foundational_axioms {
            validate_name(axiom, "foundational axiom")?;
            if claim.project_axioms.contains_key(axiom) {
                return Err(AdapterError::new(
                    AXIOM,
                    format!("axiom '{axiom}' has two classifications"),
                ));
            }
        }
        if let Some(digest) = &claim.statement_sha256 {
            parse_prefixed_digest(digest).map_err(|message| {
                AdapterError::new(CONFIGURATION, message).at(format!(
                    "claim_inventory[{}].statement_sha256",
                    claim.claim_id
                ))
            })?;
        }
        for (axiom, assumption) in &claim.project_axioms {
            validate_name(axiom, "project axiom")?;
            validate_claim_id(assumption)?;
            AssumptionId::new(assumption.clone()).map_err(|error| {
                AdapterError::new(
                    CONFIGURATION,
                    format!("invalid assumption ID '{assumption}': {error}"),
                )
            })?;
        }
    }
    Ok(by_id)
}

fn actual_inventory(output: &AuditOutput) -> Result<BTreeMap<String, &AuditClaim>, AdapterError> {
    let mut by_id = BTreeMap::new();
    let mut declarations = BTreeSet::new();
    for claim in &output.claims {
        validate_claim_id(&claim.claim_id)?;
        validate_name(&claim.declaration, "attributed declaration")?;
        validate_name(&claim.module, "declaring module")?;
        if by_id.insert(claim.claim_id.clone(), claim).is_some() {
            return Err(AdapterError::new(
                INVENTORY,
                format!("duplicate attributed claim ID '{}'", claim.claim_id),
            ));
        }
        if !declarations.insert(claim.declaration.as_str()) {
            return Err(AdapterError::new(
                INVENTORY,
                format!("duplicate attributed declaration '{}'", claim.declaration),
            ));
        }
        if claim.axioms.len() > MAX_AXIOMS || !claim.axioms.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(AdapterError::new(
                AUDIT_OUTPUT,
                format!(
                    "axioms for '{}' exceed limits or are not strictly sorted and unique",
                    claim.declaration
                ),
            ));
        }
        for axiom in &claim.axioms {
            validate_name(axiom, "audited axiom")?;
        }
        statement_digest(&claim.expr_wire).map_err(|error| {
            AdapterError::new(
                EXPR_WIRE,
                format!("invalid ExprWire for '{}': {error}", claim.declaration),
            )
        })?;
    }
    Ok(by_id)
}

fn verify_claim(
    expected: &ExpectedClaim,
    actual: &AuditClaim,
) -> Result<(Sha256Digest, BTreeSet<String>, BTreeSet<AssumptionId>), AdapterError> {
    if expected.declaration != actual.declaration || expected.declaration_kind != actual.kind {
        return Err(AdapterError::new(
            DECLARATION,
            format!(
                "compiled declaration identity drift for '{}': expected '{}' ({:?}), found '{}' ({:?})",
                expected.claim_id,
                expected.declaration,
                expected.declaration_kind,
                actual.declaration,
                actual.kind
            ),
        ));
    }
    if actual
        .axioms
        .iter()
        .any(|name| name == "sorryAx" || name.ends_with(".sorryAx"))
    {
        return Err(AdapterError::new(
            AXIOM,
            format!("'{}' transitively depends on sorryAx", actual.declaration),
        ));
    }

    let expected_axioms: BTreeSet<_> = expected
        .foundational_axioms
        .iter()
        .chain(expected.project_axioms.keys())
        .cloned()
        .collect();
    let actual_axioms: BTreeSet<_> = actual.axioms.iter().cloned().collect();
    if expected_axioms != actual_axioms {
        let missing: Vec<_> = expected_axioms
            .difference(&actual_axioms)
            .cloned()
            .collect();
        let unknown: Vec<_> = actual_axioms
            .difference(&expected_axioms)
            .cloned()
            .collect();
        return Err(AdapterError::new(
            AXIOM,
            format!(
                "exact transitive axiom inventory differs for '{}'; missing={missing:?}, unknown={unknown:?}",
                actual.declaration
            ),
        )
        .remediate("classify every compiled axiom explicitly and remove stale classifications"));
    }

    let project_axioms = expected
        .project_axioms
        .values()
        .map(|assumption| {
            AssumptionId::new(assumption.clone()).map_err(|error| {
                AdapterError::new(
                    CONFIGURATION,
                    format!("invalid assumption ID '{assumption}': {error}"),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let digest = statement_digest(&actual.expr_wire).map_err(|error| {
        AdapterError::new(
            EXPR_WIRE,
            format!("invalid ExprWire for '{}': {error}", actual.declaration),
        )
    })?;
    validate_digest_binding_v1(&actual.expr_wire, &actual.claim_id)?;
    Ok((
        digest,
        expected.foundational_axioms.iter().cloned().collect(),
        project_axioms,
    ))
}

fn parse_prefixed_digest(value: &str) -> Result<Sha256Digest, String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("statement_sha256 must use canonical 'sha256:<hex>' spelling".to_owned());
    };
    Sha256Digest::from_str(hex).map_err(|error| format!("invalid statement_sha256: {error}"))
}

fn domain_digest(domain_with_nul: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain_with_nul);
    hasher.update(bytes);
    Sha256Digest::from_str(&hex::encode(hasher.finalize()))
        .expect("SHA-256 always renders canonical hex")
}

fn validate_name(value: &str, kind: &str) -> Result<(), AdapterError> {
    if value.trim().is_empty() || value.len() > 4_096 || value.contains('\0') {
        return Err(AdapterError::new(
            AUDIT_OUTPUT,
            format!("{kind} is empty, oversized, or contains NUL"),
        ));
    }
    Ok(())
}

fn validate_claim_id(value: &str) -> Result<(), AdapterError> {
    if value.len() > 160
        || !value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        || !value.contains('-')
        || value.split('-').any(str::is_empty)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("invalid canonical claim ID '{value}'"),
        ));
    }
    Ok(())
}

fn require_sorted_unique(field: &str, values: &[String]) -> Result<(), AdapterError> {
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("{field} must be strictly sorted and duplicate-free"),
        ));
    }
    Ok(())
}

fn validate_local_id(value: &str) -> Result<(), AdapterError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("invalid canonical evidence unit ID '{value}'"),
        ));
    }
    Ok(())
}

fn validate_relative_file(value: &str) -> Result<(), AdapterError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{'))
    {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("Lean evidence path must be an exact canonical relative file: '{value}'"),
        ));
    }
    Ok(())
}

use serde::Deserialize as _;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proofbound_manifest::{
        AdapterKind, AdapterOperation, EvaluationMode, EvidenceKind, EvidenceUnitManifest,
        OperationKind, ResourceBudget,
    };
    use serde_json::json;

    use super::*;
    use crate::model::{AuditExemption, AuditSource};

    fn unit(expected_digest: Option<String>) -> LeanAdapterUnit {
        LeanAdapterUnit {
            schema: LEAN_ADAPTER_UNIT_SCHEMA.to_owned(),
            evidence_unit: EvidenceUnitManifest {
                schema: "proofbound-evidence-unit/1".to_owned(),
                id: "demo-theorem".to_owned(),
                adapter: AdapterKind::Lean,
                kind: EvidenceKind::Theorem,
                claims: vec!["DEMO-CLAIM-001".to_owned()],
                tier: 2,
                operation: AdapterOperation {
                    kind: OperationKind::LeanAudit,
                    package: None,
                    targets: vec!["Demo.claim".to_owned()],
                    paths: vec!["lean/Demo.lean".to_owned()],
                    manifest: None,
                    inventory: None,
                    checker: None,
                    arguments: Vec::new(),
                    plugins: Vec::new(),
                    configuration: None,
                },
                evaluation_mode: Some(EvaluationMode::Kernel),
                binding_mode: None,
                theorem: Some("Demo.claim".to_owned()),
                refinement_theorem: None,
                premises: Vec::new(),
                assumptions: Vec::new(),
                expected_inventory: vec!["Demo.claim".to_owned()],
                inputs: vec!["lean/Demo.lean".to_owned()],
                outputs: Vec::new(),
                environment_allowlist: Vec::new(),
                bounded_domain: None,
                transcription: None,
                mutation: None,
                property: None,
                distribution: None,
                resource_budget: ResourceBudget {
                    time_seconds: 10,
                    disk_bytes: 1024,
                    memory_bytes: 1024,
                },
            },
            environment_id: proofbound_core::EnvironmentId::new("lean:test").unwrap(),
            claim_inventory: vec![ExpectedClaim {
                claim_id: "DEMO-CLAIM-001".to_owned(),
                declaration: "Demo.claim".to_owned(),
                declaration_kind: DeclarationKind::Theorem,
                statement_sha256: expected_digest,
                foundational_axioms: Vec::new(),
                project_axioms: BTreeMap::new(),
            }],
            audit: AuditSource::Execute,
        }
    }

    fn output() -> AuditOutput {
        AuditOutput {
            schema: LEAN_AUDIT_SCHEMA.to_owned(),
            statement_encoding: STATEMENT_ENCODING.to_owned(),
            claims: vec![AuditClaim {
                axioms: Vec::new(),
                claim_id: "DEMO-CLAIM-001".to_owned(),
                declaration: "Demo.claim".to_owned(),
                expr_wire: json!([STATEMENT_ENCODING, [5, 0, [1, [0]], [1, [0]]]]),
                kind: DeclarationKind::Theorem,
                module: "Demo".to_owned(),
            }],
            exemptions: vec![AuditExemption {
                declaration: "Demo.helper".to_owned(),
                module: "Demo".to_owned(),
                reason: "internal helper".to_owned(),
            }],
        }
    }

    #[test]
    fn complete_inventory_and_digest_match_pass() {
        let audit = output();
        let digest = statement_digest(&audit.claims[0].expr_wire).unwrap();
        let verified = verify_audit(&unit(Some(format!("sha256:{digest}"))), &audit, true).unwrap();
        assert_eq!(verified.target.declaration, "Demo.claim");
    }

    #[test]
    fn expected_inventory_is_nonempty_and_exact_before_audit_execution() {
        let mut empty = unit(None);
        empty.evidence_unit.expected_inventory.clear();
        assert_eq!(validate_unit(&empty).unwrap_err().code, INVENTORY);

        let mut wrong = unit(None);
        wrong.evidence_unit.expected_inventory = vec!["Demo.other".to_owned()];
        assert_eq!(validate_unit(&wrong).unwrap_err().code, INVENTORY);
    }

    #[test]
    fn digest_drift_fails_closed() {
        let error = verify_audit(
            &unit(Some(format!("sha256:{}", Sha256Digest::of_bytes(b"wrong")))),
            &output(),
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, STATEMENT_DRIFT);
    }

    #[test]
    fn unknown_duplicate_and_missing_attributions_fail() {
        let mut unknown = output();
        unknown.claims[0].claim_id = "UNKNOWN-CLAIM-001".to_owned();
        assert_eq!(
            verify_audit(&unit(None), &unknown, false).unwrap_err().code,
            INVENTORY
        );

        let mut duplicate = output();
        duplicate.claims.push(duplicate.claims[0].clone());
        assert_eq!(
            verify_audit(&unit(None), &duplicate, false)
                .unwrap_err()
                .code,
            AUDIT_OUTPUT
        );

        let mut missing = output();
        missing.claims.clear();
        assert_eq!(
            verify_audit(&unit(None), &missing, false).unwrap_err().code,
            INVENTORY
        );
    }

    #[test]
    fn exact_kind_and_axiom_classification_are_enforced() {
        let mut wrong_kind = output();
        wrong_kind.claims[0].kind = DeclarationKind::Opaque;
        assert_eq!(
            verify_audit(&unit(None), &wrong_kind, false)
                .unwrap_err()
                .code,
            DECLARATION
        );

        let mut axiom = output();
        axiom.claims[0].axioms = vec!["Demo.axiom".to_owned()];
        assert_eq!(
            verify_audit(&unit(None), &axiom, false).unwrap_err().code,
            AXIOM
        );
    }

    #[test]
    fn native_evaluation_requires_an_explicit_non_project_premise() {
        let mut native = unit(None);
        native.evidence_unit.evaluation_mode = Some(EvaluationMode::Native);
        assert_eq!(
            verify_audit(&native, &output(), false).unwrap_err().code,
            AXIOM
        );

        native
            .evidence_unit
            .assumptions
            .push("DEMO-NATIVE-EVALUATION-001".to_owned());
        verify_audit(&native, &output(), false).unwrap();

        let mut kernel_with_unused_assumption = unit(None);
        kernel_with_unused_assumption
            .evidence_unit
            .assumptions
            .push("DEMO-NATIVE-EVALUATION-001".to_owned());
        assert_eq!(
            verify_audit(&kernel_with_unused_assumption, &output(), false)
                .unwrap_err()
                .code,
            AXIOM
        );
    }

    #[test]
    fn strict_parser_rejects_unknown_fields_and_trailing_data() {
        let valid = serde_json::to_vec(&output()).unwrap();
        assert_eq!(parse_audit_bytes(&valid).unwrap(), output());

        let mut trailing = valid.clone();
        trailing.extend_from_slice(b" null");
        assert!(parse_audit_bytes(&trailing).is_err());

        let malformed = br#"{"schema":"proofbound-lean-audit/1","statement_encoding":"lean-expr-cbor/1","claims":[],"exemptions":[],"extra":true}"#;
        assert!(parse_audit_bytes(malformed).is_err());
    }
}
