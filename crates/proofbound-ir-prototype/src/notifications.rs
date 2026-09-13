use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use proofbound_evidence::{canonical_json, domain_hash};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const NOTIFICATION_CORPUS_SCHEMA: &str = "proofbound-research-notification-corpus/1";
pub const NOTIFICATION_REPORT_SCHEMA: &str = "proofbound-research-notification-report/1";
pub const NOTIFICATION_MODEL_REPORT_SCHEMA: &str =
    "proofbound-research-notification-model-report/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationCorpus {
    pub schema: String,
    pub scenarios: Vec<NotificationScenario>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationScenario {
    pub id: String,
    pub claims: Vec<NotificationClaim>,
    pub facts: Vec<UncertaintyFact>,
    pub findings: Vec<ToolFinding>,
    pub paths: Vec<NotificationImpactPath>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationClaim {
    pub id: String,
    pub title: String,
    pub publication_gate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyFact {
    pub id: String,
    pub kind: UncertaintyKind,
    pub owner: String,
    pub scope: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub expires_at: Option<String>,
    pub consequence: FactConsequence,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UncertaintyKind {
    Assumption,
    Exclusion,
    Uncertainty,
    Contradiction,
    StaleEvidence,
    MissingEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactConsequence {
    MayWeaken,
    DoesNotStrengthen,
    BlocksPublication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFinding {
    pub id: String,
    pub tool: String,
    pub code: String,
    pub severity: FindingSeverity,
    pub fact: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationImpactPath {
    pub id: String,
    pub finding: String,
    pub fact: String,
    pub claim: String,
    pub nodes: Vec<String>,
    pub consumed: bool,
    pub requested_action: String,
    pub publication_consequence: PublicationConsequence,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationConsequence {
    Block,
    Warn,
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDecisionReport {
    pub schema: String,
    pub baseline_alerts: Vec<BaselineAlert>,
    pub notifications: Vec<DecisionNotification>,
    pub graph_updates: Vec<GraphUpdate>,
    pub fact_kinds: Vec<UncertaintyKind>,
    pub scenario_identities: Vec<ScenarioIdentity>,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineAlert {
    pub identity: String,
    pub scenario: String,
    pub finding: String,
    pub fact: String,
    pub tool: String,
    pub code: String,
    pub severity: FindingSeverity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionNotification {
    pub identity: String,
    pub scenario: String,
    pub claim: String,
    pub kind: UncertaintyKind,
    pub requested_action: String,
    pub publication_consequence: PublicationConsequence,
    pub findings: Vec<String>,
    pub paths: Vec<NotificationImpactPath>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphUpdate {
    pub scenario: String,
    pub finding: String,
    pub fact: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioIdentity {
    pub id: String,
    pub identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAttackCorpus {
    pub schema: String,
    pub attacks: Vec<NotificationAttack>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAttack {
    pub id: String,
    pub base: String,
    pub code: String,
    pub action: NotificationAttackAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NotificationAttackAction {
    SubstituteKind { fact: String, value: String },
    SubstituteConsequence { fact: String, value: String },
    DropNotification { scenario: String },
    DropFinding { finding: String },
    RemovePath { path: String },
    SubstitutePathNode { path: String, value: String },
    SubstituteClaim { path: String, claim: String },
    RemoveOwner { fact: String },
    RemoveAction { path: String },
    RemovePublication { path: String },
    RemoveExpiry { fact: String },
    MergeNotifications { scenarios: Vec<String> },
    DuplicateFinding { finding: String },
    DuplicateNotification { scenario: String },
    ForgeReportIdentity { value: String },
    ReverseFindings,
    EscalateUnrelated { finding: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAttackResult {
    pub id: String,
    pub expected_code: String,
    pub actual_code: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationModelReport {
    pub schema: String,
    pub decision_report: NotificationDecisionReport,
    pub attacks: Vec<NotificationAttackResult>,
    pub repetition_report_identities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationError {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for NotificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NotificationError {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GroupKey {
    scenario: String,
    claim: String,
    kind: UncertaintyKind,
    requested_action: String,
    publication_consequence: PublicationConsequence,
}

fn invalid(code: &'static str, message: impl Into<String>) -> NotificationError {
    NotificationError {
        code,
        message: message.into(),
    }
}

pub fn load_notification_corpus(
    root: &Path,
    corpus_dir: &Path,
) -> Result<(NotificationCorpus, NotificationAttackCorpus), NotificationError> {
    let corpus: NotificationCorpus = decode(&read(root, &corpus_dir.join("scenarios.json"))?)?;
    let attacks: NotificationAttackCorpus = decode(&read(root, &corpus_dir.join("attacks.json"))?)?;
    validate_notification_corpus(&corpus)?;
    if attacks.schema != "proofbound-research-notification-attacks/1" {
        return Err(invalid("UNCERTAINTY-SCHEMA", "unexpected attack schema"));
    }
    let mut attack_ids = BTreeSet::new();
    if attacks.attacks.is_empty()
        || attacks.attacks.iter().any(|attack| {
            validate_id(&attack.id, "attack").is_err()
                || !attack_ids.insert(attack.id.as_str())
                || validate_id(&attack.base, "attack base").is_err()
                || validate_id(&attack.code, "attack code").is_err()
        })
    {
        return Err(invalid(
            "UNCERTAINTY-NONCANONICAL",
            "attacks are empty, duplicated, or malformed",
        ));
    }
    Ok((corpus, attacks))
}

pub fn validate_notification_corpus(corpus: &NotificationCorpus) -> Result<(), NotificationError> {
    if corpus.schema != NOTIFICATION_CORPUS_SCHEMA || corpus.scenarios.is_empty() {
        return Err(invalid("UNCERTAINTY-SCHEMA", "invalid corpus schema"));
    }
    let mut scenarios = BTreeSet::new();
    for scenario in &corpus.scenarios {
        if !scenarios.insert(scenario.id.as_str()) {
            return Err(invalid("UNCERTAINTY-NONCANONICAL", "duplicate scenario ID"));
        }
        validate_scenario(scenario)?;
    }
    Ok(())
}

pub fn derive_notification_report(
    corpus: &NotificationCorpus,
) -> Result<NotificationDecisionReport, NotificationError> {
    validate_notification_corpus(corpus)?;
    let mut baseline_alerts = Vec::new();
    let mut groups: BTreeMap<GroupKey, Vec<NotificationImpactPath>> = BTreeMap::new();
    let mut graph_updates = Vec::new();
    let mut fact_kinds = BTreeSet::new();
    let mut scenario_identities = Vec::new();
    for scenario in &corpus.scenarios {
        let facts: BTreeMap<_, _> = scenario
            .facts
            .iter()
            .map(|fact| (fact.id.as_str(), fact))
            .collect();
        for fact in &scenario.facts {
            fact_kinds.insert(fact.kind.clone());
        }
        scenario_identities.push(ScenarioIdentity {
            id: scenario.id.clone(),
            identity: domain_hash(
                "proofbound-research-notification-scenario/1",
                &canonical_json(scenario)
                    .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?,
            ),
        });
        for finding in &scenario.findings {
            let mut alert = BaselineAlert {
                identity: String::new(),
                scenario: scenario.id.clone(),
                finding: finding.id.clone(),
                fact: finding.fact.clone(),
                tool: finding.tool.clone(),
                code: finding.code.clone(),
                severity: finding.severity.clone(),
            };
            alert.identity = domain_hash(
                "proofbound-research-tool-alert/1",
                &canonical_json(&alert_material(&alert))
                    .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?,
            );
            baseline_alerts.push(alert);
            let consumed: Vec<_> = scenario
                .paths
                .iter()
                .filter(|path| path.finding == finding.id && path.consumed)
                .collect();
            if consumed.is_empty() {
                graph_updates.push(GraphUpdate {
                    scenario: scenario.id.clone(),
                    finding: finding.id.clone(),
                    fact: finding.fact.clone(),
                    reason: "no-consumed-claim-path".to_owned(),
                });
            }
            for path in consumed {
                let fact = facts
                    .get(path.fact.as_str())
                    .ok_or_else(|| invalid("UNCERTAINTY-PATH-FORGED", "fact is missing"))?;
                groups
                    .entry(GroupKey {
                        scenario: scenario.id.clone(),
                        claim: path.claim.clone(),
                        kind: fact.kind.clone(),
                        requested_action: path.requested_action.clone(),
                        publication_consequence: path.publication_consequence.clone(),
                    })
                    .or_default()
                    .push(path.clone());
            }
        }
    }
    baseline_alerts.sort();
    graph_updates.sort();
    scenario_identities.sort();
    let mut notifications = Vec::new();
    for (key, mut paths) in groups {
        paths.sort();
        let findings: Vec<_> = paths
            .iter()
            .map(|path| path.finding.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut notification = DecisionNotification {
            identity: String::new(),
            scenario: key.scenario,
            claim: key.claim,
            kind: key.kind,
            requested_action: key.requested_action,
            publication_consequence: key.publication_consequence,
            findings,
            paths,
        };
        notification.identity = notification_identity(&notification)?;
        notifications.push(notification);
    }
    notifications.sort_by(|left, right| left.identity.cmp(&right.identity));
    let mut report = NotificationDecisionReport {
        schema: NOTIFICATION_REPORT_SCHEMA.to_owned(),
        baseline_alerts,
        notifications,
        graph_updates,
        fact_kinds: fact_kinds.into_iter().collect(),
        scenario_identities,
        identity: String::new(),
    };
    report.identity = report_identity(&report)?;
    Ok(report)
}

pub fn validate_notification_report(
    corpus: &NotificationCorpus,
    report: &NotificationDecisionReport,
) -> Result<(), NotificationError> {
    validate_notification_corpus(corpus)?;
    if report.schema != NOTIFICATION_REPORT_SCHEMA || report.identity != report_identity(report)? {
        return Err(invalid(
            "UNCERTAINTY-IDENTITY-FORGED",
            "report identity is invalid",
        ));
    }
    if report
        .notifications
        .windows(2)
        .any(|pair| pair[0].identity >= pair[1].identity)
    {
        return Err(invalid(
            "UNCERTAINTY-NOTIFICATION-DUPLICATE",
            "notifications are not a strict set",
        ));
    }
    if report
        .baseline_alerts
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid(
            "UNCERTAINTY-NONCANONICAL",
            "baseline findings are not canonical",
        ));
    }
    for notification in &report.notifications {
        if notification.identity != notification_identity(notification)? {
            return Err(invalid(
                "UNCERTAINTY-IDENTITY-FORGED",
                "notification identity is invalid",
            ));
        }
    }
    let expected = derive_notification_report(corpus)?;
    if report == &expected {
        return Ok(());
    }
    classify_report_difference(&expected, report)
}

pub fn execute_notification_corpus(
    root: &Path,
    corpus_dir: &Path,
    repetitions: usize,
) -> Result<NotificationModelReport, NotificationError> {
    if repetitions == 0 || repetitions > 100 {
        return Err(invalid(
            "UNCERTAINTY-REPETITIONS",
            "invalid repetition count",
        ));
    }
    let (corpus, attacks) = load_notification_corpus(root, corpus_dir)?;
    let decision_report = derive_notification_report(&corpus)?;
    validate_notification_report(&corpus, &decision_report)?;
    let mut repetition_report_identities = Vec::new();
    for _ in 0..repetitions {
        let repeated = derive_notification_report(&corpus)?;
        if repeated != decision_report {
            return Err(invalid("UNCERTAINTY-NONDETERMINISTIC", "report changed"));
        }
        repetition_report_identities.push(repeated.identity);
    }
    let scenarios: BTreeMap<_, _> = corpus
        .scenarios
        .iter()
        .map(|scenario| (scenario.id.as_str(), scenario))
        .collect();
    let mut attack_results = Vec::new();
    for attack in &attacks.attacks {
        let scenario = scenarios
            .get(attack.base.as_str())
            .ok_or_else(|| invalid("UNCERTAINTY-SCENARIO", "attack scenario is missing"))?;
        attack_results.push(evaluate_attack(&corpus, scenario, attack));
    }
    Ok(NotificationModelReport {
        schema: NOTIFICATION_MODEL_REPORT_SCHEMA.to_owned(),
        decision_report,
        attacks: attack_results,
        repetition_report_identities,
    })
}

fn validate_scenario(scenario: &NotificationScenario) -> Result<(), NotificationError> {
    validate_id(&scenario.id, "scenario")?;
    strict_ids(&scenario.claims, |claim| &claim.id)?;
    strict_ids(&scenario.facts, |fact| &fact.id)?;
    strict_ids(&scenario.findings, |finding| &finding.id)?;
    strict_ids(&scenario.paths, |path| &path.id)?;
    let claims: BTreeSet<_> = scenario
        .claims
        .iter()
        .map(|claim| claim.id.as_str())
        .collect();
    let facts: BTreeMap<_, _> = scenario
        .facts
        .iter()
        .map(|fact| (fact.id.as_str(), fact))
        .collect();
    let findings: BTreeMap<_, _> = scenario
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect();
    for claim in &scenario.claims {
        validate_id(&claim.id, "claim")?;
        validate_text(&claim.title, "claim title")?;
    }
    for fact in &scenario.facts {
        validate_fact(fact)?;
    }
    for finding in &scenario.findings {
        validate_id(&finding.id, "finding")?;
        validate_id(&finding.tool, "tool")?;
        validate_id(&finding.code, "finding code")?;
        if !facts.contains_key(finding.fact.as_str()) {
            return Err(invalid(
                "UNCERTAINTY-PATH-FORGED",
                "finding references an unknown fact",
            ));
        }
    }
    for path in &scenario.paths {
        validate_id(&path.id, "path")?;
        validate_id(&path.requested_action, "action")?;
        let finding = findings
            .get(path.finding.as_str())
            .ok_or_else(|| invalid("UNCERTAINTY-PATH-MISSING", "path finding is missing"))?;
        if finding.fact != path.fact
            || !facts.contains_key(path.fact.as_str())
            || !claims.contains(path.claim.as_str())
        {
            return Err(invalid(
                "UNCERTAINTY-CLAIM-UNKNOWN",
                "path join references an unknown or mismatched record",
            ));
        }
        let expected_first = format!("finding:{}", path.finding);
        let expected_second = format!("fact:{}", path.fact);
        let expected_last = format!("claim:{}", path.claim);
        if path.nodes.len() < 3
            || path.nodes.first() != Some(&expected_first)
            || path.nodes.get(1) != Some(&expected_second)
            || path.nodes.last() != Some(&expected_last)
            || path.nodes.iter().collect::<BTreeSet<_>>().len() != path.nodes.len()
        {
            return Err(invalid(
                "UNCERTAINTY-PATH-FORGED",
                "dependency path is not exact",
            ));
        }
        for node in &path.nodes {
            validate_text(node, "path node")?;
        }
    }
    Ok(())
}

fn validate_fact(fact: &UncertaintyFact) -> Result<(), NotificationError> {
    validate_id(&fact.id, "fact")?;
    validate_text(&fact.owner, "owner")
        .map_err(|_| invalid("UNCERTAINTY-OWNER-MISSING", "fact owner is missing"))?;
    validate_text(&fact.scope, "scope")?;
    if let Some(expiry) = &fact.expires_at {
        validate_timestamp(expiry)?;
    }
    if fact.evidence.windows(2).any(|pair| pair[0] >= pair[1])
        || fact
            .evidence
            .iter()
            .any(|identity| validate_digest(identity).is_err())
    {
        return Err(invalid(
            "UNCERTAINTY-EVIDENCE-SET",
            "fact evidence is not a strict identity set",
        ));
    }
    match fact.kind {
        UncertaintyKind::Assumption => {
            if fact.expires_at.is_none() || fact.consequence != FactConsequence::MayWeaken {
                return Err(invalid(
                    "UNCERTAINTY-EXPIRY-MISSING",
                    "assumption expiry or consequence is invalid",
                ));
            }
        }
        UncertaintyKind::Exclusion => {
            if fact.consequence != FactConsequence::DoesNotStrengthen {
                return Err(invalid(
                    "UNCERTAINTY-EXCLUSION-STRENGTH",
                    "exclusion cannot strengthen assurance",
                ));
            }
        }
        UncertaintyKind::Contradiction => {
            if fact.evidence.len() < 2 || fact.consequence != FactConsequence::BlocksPublication {
                return Err(invalid(
                    "UNCERTAINTY-CONTRADICTION-INVALID",
                    "contradiction is not evidence-backed and blocking",
                ));
            }
        }
        UncertaintyKind::StaleEvidence => {
            if fact.evidence.len() != 1 || fact.consequence != FactConsequence::MayWeaken {
                return Err(invalid(
                    "UNCERTAINTY-STALE-CURRENT",
                    "stale evidence semantics are invalid",
                ));
            }
        }
        UncertaintyKind::MissingEvidence => {
            if !fact.evidence.is_empty() || fact.consequence != FactConsequence::BlocksPublication {
                return Err(invalid(
                    "UNCERTAINTY-MISSING-SUPPRESSED",
                    "missing evidence semantics are invalid",
                ));
            }
        }
        UncertaintyKind::Uncertainty => {}
    }
    Ok(())
}

fn evaluate_attack(
    corpus: &NotificationCorpus,
    scenario: &NotificationScenario,
    attack: &NotificationAttack,
) -> NotificationAttackResult {
    let actual_code = run_attack(corpus, scenario, &attack.action)
        .err()
        .map_or_else(|| "ACCEPTED".to_owned(), |error| error.code.to_owned());
    NotificationAttackResult {
        id: attack.id.clone(),
        expected_code: attack.code.clone(),
        exact: actual_code == attack.code,
        actual_code,
    }
}

fn run_attack(
    corpus: &NotificationCorpus,
    scenario: &NotificationScenario,
    action: &NotificationAttackAction,
) -> Result<(), NotificationError> {
    match action {
        NotificationAttackAction::SubstituteKind { fact, value } => {
            let code = match value.as_str() {
                "evidence" => "UNCERTAINTY-ASSUMPTION-EVIDENCE",
                "current-evidence" => "UNCERTAINTY-STALE-CURRENT",
                _ => "UNCERTAINTY-KIND-ALIAS",
            };
            let mut value_scenario = serde_json::to_value(scenario)
                .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?;
            replace_fact_field(
                &mut value_scenario,
                fact,
                "kind",
                Value::String(value.clone()),
            )?;
            serde_json::from_value::<NotificationScenario>(value_scenario)
                .map(|_| ())
                .map_err(|_| invalid(code, "uncertainty kind substitution accepted"))
        }
        NotificationAttackAction::SubstituteConsequence { fact, value } => {
            let mut mutated = scenario.clone();
            let target = mutated
                .facts
                .iter_mut()
                .find(|item| item.id == *fact)
                .ok_or_else(|| invalid("UNCERTAINTY-FACT", "fact is missing"))?;
            if value == "strengthens" {
                target.consequence = FactConsequence::MayWeaken;
            }
            validate_scenario(&mutated)
        }
        NotificationAttackAction::DropFinding { finding } => {
            let mut mutated = scenario.clone();
            mutated.findings.retain(|item| item.id != *finding);
            validate_scenario(&mutated).map_err(|_| {
                invalid(
                    "UNCERTAINTY-CRITICAL-DROPPED",
                    "critical finding was removed",
                )
            })
        }
        NotificationAttackAction::RemovePath { path } => {
            let mut mutated = scenario.clone();
            mutated.paths.retain(|item| item.id != *path);
            let base = derive_notification_report(&NotificationCorpus {
                schema: corpus.schema.clone(),
                scenarios: vec![scenario.clone()],
            })?;
            let changed = derive_notification_report(&NotificationCorpus {
                schema: corpus.schema.clone(),
                scenarios: vec![mutated],
            })?;
            if changed.notifications == base.notifications {
                Ok(())
            } else {
                Err(invalid(
                    "UNCERTAINTY-PATH-MISSING",
                    "consumed impact path was removed",
                ))
            }
        }
        NotificationAttackAction::SubstitutePathNode { path, value } => {
            let mut mutated = scenario.clone();
            let target = find_path_mut(&mut mutated, path)?;
            if let Some(last) = target.nodes.last_mut() {
                last.clone_from(value);
            }
            validate_scenario(&mutated)
        }
        NotificationAttackAction::SubstituteClaim { path, claim } => {
            let mut mutated = scenario.clone();
            find_path_mut(&mut mutated, path)?.claim.clone_from(claim);
            validate_scenario(&mutated)
        }
        NotificationAttackAction::RemoveOwner { fact } => {
            let mut value_scenario = serde_json::to_value(scenario)
                .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?;
            remove_fact_field(&mut value_scenario, fact, "owner")?;
            serde_json::from_value::<NotificationScenario>(value_scenario)
                .map(|_| ())
                .map_err(|_| invalid("UNCERTAINTY-OWNER-MISSING", "owner was omitted"))
        }
        NotificationAttackAction::RemoveAction { path } => {
            remove_path_field_attack(scenario, path, "requested_action")
                .map_err(|_| invalid("UNCERTAINTY-ACTION-MISSING", "requested action was omitted"))
        }
        NotificationAttackAction::RemovePublication { path } => {
            remove_path_field_attack(scenario, path, "publication_consequence").map_err(|_| {
                invalid(
                    "UNCERTAINTY-PUBLICATION-MISSING",
                    "publication consequence was omitted",
                )
            })
        }
        NotificationAttackAction::RemoveExpiry { fact } => {
            let mut value_scenario = serde_json::to_value(scenario)
                .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?;
            remove_fact_field(&mut value_scenario, fact, "expires_at")?;
            serde_json::from_value::<NotificationScenario>(value_scenario)
                .map(|_| ())
                .map_err(|_| invalid("UNCERTAINTY-EXPIRY-MISSING", "expiry was omitted"))
        }
        NotificationAttackAction::DuplicateFinding { finding } => {
            let mut mutated = scenario.clone();
            let duplicate = mutated
                .findings
                .iter()
                .find(|item| item.id == *finding)
                .cloned()
                .ok_or_else(|| invalid("UNCERTAINTY-FINDING", "finding is missing"))?;
            mutated.findings.push(duplicate);
            validate_scenario(&mutated)
                .map_err(|_| invalid("UNCERTAINTY-FINDING-DUPLICATE", "finding was duplicated"))
        }
        NotificationAttackAction::ReverseFindings => {
            let mut mutated = scenario.clone();
            mutated.findings.reverse();
            validate_scenario(&mutated)
        }
        NotificationAttackAction::DropNotification { scenario: target } => {
            let mut report = derive_notification_report(corpus)?;
            report.notifications.retain(|item| item.scenario != *target);
            report.identity = report_identity(&report)?;
            validate_notification_report(corpus, &report)
        }
        NotificationAttackAction::MergeNotifications { scenarios } => {
            let mut report = derive_notification_report(corpus)?;
            let indices: Vec<_> = report
                .notifications
                .iter()
                .enumerate()
                .filter(|(_, item)| scenarios.contains(&item.scenario))
                .map(|(index, _)| index)
                .collect();
            if indices.len() >= 2 {
                let second = report.notifications.remove(indices[1]);
                report.notifications[indices[0]]
                    .findings
                    .extend(second.findings);
                report.notifications[indices[0]].findings.sort();
                report.notifications[indices[0]].paths.extend(second.paths);
                report.notifications[indices[0]].paths.sort();
                report.notifications[indices[0]].identity =
                    notification_identity(&report.notifications[indices[0]])?;
                report
                    .notifications
                    .sort_by(|left, right| left.identity.cmp(&right.identity));
            }
            report.identity = report_identity(&report)?;
            validate_notification_report(corpus, &report)
        }
        NotificationAttackAction::DuplicateNotification { scenario: target } => {
            let mut report = derive_notification_report(corpus)?;
            let duplicate = report
                .notifications
                .iter()
                .find(|item| item.scenario == *target)
                .cloned()
                .ok_or_else(|| invalid("UNCERTAINTY-NOTIFICATION", "notification missing"))?;
            report.notifications.push(duplicate);
            report
                .notifications
                .sort_by(|left, right| left.identity.cmp(&right.identity));
            report.identity = report_identity(&report)?;
            validate_notification_report(corpus, &report)
        }
        NotificationAttackAction::ForgeReportIdentity { value } => {
            let mut report = derive_notification_report(corpus)?;
            report.identity.clone_from(value);
            validate_notification_report(corpus, &report)
        }
        NotificationAttackAction::EscalateUnrelated { finding } => {
            let mut report = derive_notification_report(corpus)?;
            let update = report
                .graph_updates
                .iter()
                .find(|item| item.finding == *finding)
                .cloned()
                .ok_or_else(|| invalid("UNCERTAINTY-UPDATE", "graph update is missing"))?;
            let mut notification = DecisionNotification {
                identity: String::new(),
                scenario: update.scenario,
                claim: "RELEASE-001".to_owned(),
                kind: UncertaintyKind::Uncertainty,
                requested_action: "investigate".to_owned(),
                publication_consequence: PublicationConsequence::Warn,
                findings: vec![update.finding],
                paths: Vec::new(),
            };
            notification.identity = notification_identity(&notification)?;
            report.notifications.push(notification);
            report
                .notifications
                .sort_by(|left, right| left.identity.cmp(&right.identity));
            report.identity = report_identity(&report)?;
            validate_notification_report(corpus, &report)
        }
    }
}

fn classify_report_difference(
    expected: &NotificationDecisionReport,
    actual: &NotificationDecisionReport,
) -> Result<(), NotificationError> {
    let actual_findings: BTreeSet<_> = actual
        .notifications
        .iter()
        .flat_map(|item| item.findings.iter().map(String::as_str))
        .collect();
    for notification in &expected.notifications {
        if actual.notifications.iter().any(|item| {
            item.scenario == notification.scenario
                && item.claim == notification.claim
                && item.kind == notification.kind
                && item.requested_action == notification.requested_action
                && item.publication_consequence == notification.publication_consequence
        }) {
            continue;
        }
        return Err(match notification.kind {
            UncertaintyKind::Contradiction => invalid(
                "UNCERTAINTY-CONTRADICTION-SUPPRESSED",
                "contradiction notification is missing",
            ),
            UncertaintyKind::MissingEvidence => invalid(
                "UNCERTAINTY-MISSING-SUPPRESSED",
                "missing-evidence notification is missing",
            ),
            _ if notification
                .findings
                .iter()
                .any(|finding| !actual_findings.contains(finding.as_str())) =>
            {
                invalid(
                    "UNCERTAINTY-CRITICAL-DROPPED",
                    "consumed finding is missing",
                )
            }
            _ => invalid(
                "UNCERTAINTY-GROUPING-LOSS",
                "distinct notification groups were merged",
            ),
        });
    }
    if actual
        .notifications
        .iter()
        .any(|item| item.paths.is_empty())
    {
        return Err(invalid(
            "UNCERTAINTY-UNRELATED-ESCALATED",
            "unrelated finding became an interruption",
        ));
    }
    Err(invalid(
        "UNCERTAINTY-REPORT-MISMATCH",
        "report differs from derivation",
    ))
}

fn notification_identity(notification: &DecisionNotification) -> Result<String, NotificationError> {
    let material = serde_json::json!({
        "scenario": notification.scenario,
        "claim": notification.claim,
        "kind": notification.kind,
        "requested_action": notification.requested_action,
        "publication_consequence": notification.publication_consequence,
        "findings": notification.findings,
        "paths": notification.paths,
    });
    Ok(domain_hash(
        "proofbound-research-notification/1",
        &canonical_json(&material)
            .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?,
    ))
}

fn report_identity(report: &NotificationDecisionReport) -> Result<String, NotificationError> {
    let mut material = serde_json::to_value(report)
        .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?;
    material
        .as_object_mut()
        .expect("serialized report is an object")
        .remove("identity");
    Ok(domain_hash(
        NOTIFICATION_REPORT_SCHEMA,
        &canonical_json(&material)
            .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?,
    ))
}

fn alert_material(alert: &BaselineAlert) -> Value {
    serde_json::json!({
        "scenario": alert.scenario,
        "finding": alert.finding,
        "fact": alert.fact,
        "tool": alert.tool,
        "code": alert.code,
        "severity": alert.severity,
    })
}

fn strict_ids<T>(values: &[T], id: impl Fn(&T) -> &String) -> Result<(), NotificationError> {
    if values.is_empty() || values.windows(2).any(|pair| id(&pair[0]) >= id(&pair[1])) {
        return Err(invalid(
            "UNCERTAINTY-NONCANONICAL",
            "record IDs are not a strict lexical set",
        ));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), NotificationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid("UNCERTAINTY-ID", format!("invalid {label} ID")));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), NotificationError> {
    if value.trim().is_empty()
        || value.chars().count() > 4096
        || value.chars().any(char::is_control)
    {
        return Err(invalid("UNCERTAINTY-TEXT", format!("invalid {label}")));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), NotificationError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("UNCERTAINTY-IDENTITY", "invalid SHA-256 identity"));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), NotificationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(invalid(
            "UNCERTAINTY-EXPIRY-MISSING",
            "expiry is not canonical UTC RFC 3339",
        ));
    }
    Ok(())
}

fn replace_fact_field(
    scenario: &mut Value,
    fact: &str,
    field: &str,
    value: Value,
) -> Result<(), NotificationError> {
    let facts = scenario
        .get_mut("facts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("UNCERTAINTY-DECODE", "facts are missing"))?;
    let target = facts
        .iter_mut()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(fact))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("UNCERTAINTY-FACT", "fact is missing"))?;
    target.insert(field.to_owned(), value);
    Ok(())
}

fn remove_fact_field(
    scenario: &mut Value,
    fact: &str,
    field: &str,
) -> Result<(), NotificationError> {
    let facts = scenario
        .get_mut("facts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("UNCERTAINTY-DECODE", "facts are missing"))?;
    let target = facts
        .iter_mut()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(fact))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("UNCERTAINTY-FACT", "fact is missing"))?;
    target.remove(field);
    Ok(())
}

fn remove_path_field_attack(
    scenario: &NotificationScenario,
    path: &str,
    field: &str,
) -> Result<(), NotificationError> {
    let mut value = serde_json::to_value(scenario)
        .map_err(|error| invalid("UNCERTAINTY-ENCODE", error.to_string()))?;
    let paths = value
        .get_mut("paths")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("UNCERTAINTY-DECODE", "paths are missing"))?;
    let target = paths
        .iter_mut()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(path))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("UNCERTAINTY-PATH-MISSING", "path is missing"))?;
    target.remove(field);
    serde_json::from_value::<NotificationScenario>(value)
        .map(|_| ())
        .map_err(|error| invalid("UNCERTAINTY-DECODE", error.to_string()))
}

fn find_path_mut<'a>(
    scenario: &'a mut NotificationScenario,
    path: &str,
) -> Result<&'a mut NotificationImpactPath, NotificationError> {
    scenario
        .paths
        .iter_mut()
        .find(|item| item.id == path)
        .ok_or_else(|| invalid("UNCERTAINTY-PATH-MISSING", "path is missing"))
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, NotificationError> {
    serde_json::from_slice(bytes).map_err(|error| invalid("UNCERTAINTY-DECODE", error.to_string()))
}

fn read(root: &Path, path: &Path) -> Result<Vec<u8>, NotificationError> {
    let full = if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    };
    fs::read(&full)
        .map_err(|error| invalid("UNCERTAINTY-IO", format!("{}: {error}", full.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(
            "docs/experiments/0013-claim-oriented-notification-precision/corpus",
        )
    }

    #[test]
    fn derives_frozen_notification_counts_and_categories() {
        let report = execute_notification_corpus(&root(), &corpus(), 10).unwrap();
        assert_eq!(report.decision_report.baseline_alerts.len(), 20);
        assert_eq!(report.decision_report.notifications.len(), 7);
        assert_eq!(report.decision_report.graph_updates.len(), 9);
        assert_eq!(report.decision_report.fact_kinds.len(), 6);
        assert_eq!(report.repetition_report_identities.len(), 10);
    }

    #[test]
    fn rejects_all_frozen_attacks_exactly() {
        let report = execute_notification_corpus(&root(), &corpus(), 10).unwrap();
        assert_eq!(report.attacks.len(), 20);
        assert!(report.attacks.iter().all(|attack| attack.exact));
    }

    #[test]
    fn low_severity_consumed_finding_remains_interrupting() {
        let report = execute_notification_corpus(&root(), &corpus(), 10).unwrap();
        assert!(
            report
                .decision_report
                .notifications
                .iter()
                .any(|notification| notification.findings.contains(&"DEP-001".to_owned()))
        );
        assert!(
            !report
                .decision_report
                .graph_updates
                .iter()
                .any(|update| update.finding == "DEP-001")
        );
    }
}
