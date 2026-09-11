//! Strict Node and TypeScript evidence adapter.
//!
//! The adapter owns every executable shape. It installs only from a v3 npm
//! lockfile with lifecycle scripts disabled, inventories tools through their
//! machine-readable metadata, and executes each registered test separately.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use flate2::read::GzDecoder;
use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use proofbound_manifest::{
    AdapterDiagnostic, AdapterKind, AdapterRequest, AdapterResponse, DistributionFormat,
    DistributionReproductionSchema, EvidenceKind, EvidenceUnitManifest, MutationRegistry,
    MutationReplaySchema, OperationKind,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
const PROTOCOL_SCHEMA: &str = "proofbound-adapter-protocol/1";
const OBSERVATION_SCHEMA: &str = "proofbound-adapter-observation/2";
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_INVENTORY: usize = 100_000;
const VITEST_FLOOR: &str = "2.1.0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterObservation {
    schema: String,
    unit_id: String,
    evidence_kind: String,
    outcome: ObservationOutcome,
    input_artifacts: Vec<ArtifactObservation>,
    generated_artifacts: Vec<ArtifactObservation>,
    tool: ToolObservation,
    adapter: ToolObservation,
    commands: Vec<CommandObservation>,
    runs: Vec<RunObservation>,
    started_unix_ms: u64,
    completed_unix_ms: u64,
    deterministic_result_sha256: String,
    unit_configuration_sha256: String,
    resource_budget: BudgetObservation,
    resource_usage: UsageObservation,
    inventory: Vec<String>,
    normalization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    static_check: Option<StaticCheckObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distribution_reproduction: Option<DistributionObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation_replay: Option<MutationReplayObservation>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ObservationOutcome {
    Passed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactObservation {
    logical_name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolObservation {
    name: String,
    version: String,
    identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CommandObservation {
    program: String,
    args: Vec<String>,
    environment_allowlist: Vec<EnvironmentObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentObservation {
    name: String,
    value_sha256: Option<String>,
    secret: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RunObservation {
    command_index: usize,
    exit_code: Option<i32>,
    stdout_sha256: String,
    stderr_sha256: String,
    normalized_output_sha256: String,
    output_truncated: bool,
    duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BudgetObservation {
    time_ms: u64,
    disk_bytes: u64,
    memory_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UsageObservation {
    time_ms: u64,
    peak_disk_bytes: u64,
    peak_memory_bytes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticCheckObservation {
    schema: String,
    tool: String,
    tool_version: String,
    configuration_sha256: String,
    targets: Vec<String>,
    diagnostics: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DistributionObservation {
    schema: String,
    format: String,
    run_digests: Vec<String>,
    registered_digest: String,
    source_date_epoch: u64,
    build_backend_name: String,
    build_backend_version: String,
    npm_integrity: Option<String>,
    member_inventory: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MutationReplayObservation {
    schema: String,
    mutation_id: String,
    registry: ArtifactObservation,
    target_preimage: ArtifactObservation,
    mutant_artifact: ArtifactObservation,
    target_postimage: ArtifactObservation,
    witness_source: ArtifactObservation,
    check_id: String,
    affected_claims: Vec<String>,
    baseline_run_index: usize,
    expected_failure: ExpectedFailureObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFailureObservation {
    run_index: usize,
    allowed_exit_codes: Vec<i32>,
}

#[derive(Clone, Debug)]
struct ProcessSpec {
    program: PathBuf,
    args: Vec<String>,
}

#[derive(Clone, Debug)]
struct ProcessOutput {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    duration_ms: u64,
}

#[derive(Clone, Copy)]
struct Deadline {
    started: Instant,
    budget_ms: u64,
}

impl Deadline {
    fn remaining(self) -> Result<Duration, NodeError> {
        let elapsed = self.started.elapsed();
        let budget = Duration::from_millis(self.budget_ms);
        budget
            .checked_sub(elapsed)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(NodeError::Budget("time budget exhausted".to_owned()))
    }
}

trait Executor {
    fn run(
        &mut self,
        spec: &ProcessSpec,
        cwd: &Path,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<ProcessOutput, NodeError>;
}

struct RealExecutor;

impl Executor for RealExecutor {
    fn run(
        &mut self,
        spec: &ProcessSpec,
        cwd: &Path,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<ProcessOutput, NodeError> {
        let started = Instant::now();
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .current_dir(cwd)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| NodeError::ToolUnavailable {
                tool: spec.program.display().to_string(),
                source,
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| NodeError::Internal("child stdout unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| NodeError::Internal("child stderr unavailable".to_owned()))?;
        let stdout_reader = thread::spawn(move || drain_bounded(stdout));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr));
        let status: ExitStatus = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(NodeError::Budget("child command timed out".to_owned()));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| NodeError::Internal("stdout reader panicked".to_owned()))??;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| NodeError::Internal("stderr reader panicked".to_owned()))??;
        Ok(ProcessOutput {
            status: status.code(),
            stdout,
            stderr,
            truncated: stdout_truncated || stderr_truncated,
            duration_ms: elapsed_ms(started),
        })
    }
}

#[derive(Debug, Error)]
enum NodeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tool `{tool}` is unavailable: {source}")]
    ToolUnavailable {
        tool: String,
        source: std::io::Error,
    },
    #[error("invalid request: {0}")]
    Request(String),
    #[error("invalid Node evidence unit: {0}")]
    Unit(String),
    #[error("unsupported Node capability: {0}")]
    Unsupported(String),
    #[error("unsafe path `{0}`")]
    UnsafePath(String),
    #[error("Node inventory mismatch: {0}")]
    Inventory(String),
    #[error("Node tool failed: {0}")]
    ToolFailed(String),
    #[error("resource budget exceeded: {0}")]
    Budget(String),
    #[error("internal adapter error: {0}")]
    Internal(String),
}

impl NodeError {
    fn diagnostic(&self) -> AdapterDiagnostic {
        let (code, remediation) = match self {
            Self::ToolUnavailable { .. } => (
                "PB-NODE-1001",
                "install Node and npm and keep the registered package dependencies available",
            ),
            Self::Unsupported(_) => (
                "PB-NODE-1002",
                "use a capability admitted by Specification 0003 or revise the specification",
            ),
            Self::Request(_) => (
                "PB-NODE-1003",
                "send canonical proofbound-adapter-protocol/1 JSON",
            ),
            Self::Unit(_) => ("PB-NODE-1004", "use a strict typed node-test evidence unit"),
            Self::UnsafePath(_) => (
                "PB-NODE-1005",
                "use regular repository-relative files without symlink escapes",
            ),
            Self::Inventory(_) => (
                "PB-NODE-1006",
                "make the registered inventory exactly match tool metadata",
            ),
            Self::ToolFailed(_) => (
                "PB-NODE-1007",
                "reproduce the exact typed operation and fix its failure",
            ),
            Self::Budget(_) => (
                "PB-NODE-1008",
                "review the workload and raise the registered budget if justified",
            ),
            Self::Io(_) | Self::Internal(_) => (
                "PB-NODE-1099",
                "inspect the diagnostic and retry from a clean checkout",
            ),
        };
        AdapterDiagnostic {
            code: code.to_owned(),
            message: self.to_string().chars().take(8192).collect(),
            path: match self {
                Self::UnsafePath(path) => Some(path.clone()),
                _ => None,
            },
            remediation: Some(remediation.to_owned()),
        }
    }
}

/// Handle one canonical adapter protocol request.
#[must_use]
pub fn handle_request_bytes(input: &[u8]) -> AdapterResponse {
    let fallback = AdapterResponse {
        schema: PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: "00000000000000000000000000000000".to_owned(),
        adapter: "node-test".to_owned(),
        success: false,
        evidence: None,
        inventory: Vec::new(),
        diagnostics: Vec::new(),
    };
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return failed(
            fallback,
            NodeError::Request("request exceeds 2 MiB".to_owned()),
        );
    }
    let request: AdapterRequest = match serde_json::from_slice(input) {
        Ok(request) => request,
        Err(error) => return failed(fallback, NodeError::Request(error.to_string())),
    };
    let mut base = AdapterResponse {
        request_id: request.request_id.clone(),
        adapter: request.adapter.clone(),
        ..fallback
    };
    if let Err(error) = validate_request(&request, input) {
        return failed(base, error);
    }
    let mut executor = RealExecutor;
    match execute_request(&request, Path::new("."), &mut executor) {
        Ok((observation, inventory)) => {
            base.success = true;
            base.evidence = observation
                .map(|value| serde_json::to_value(value).expect("adapter observation serializes"));
            base.inventory = inventory;
            base
        }
        Err(error) => failed(base, error),
    }
}

fn failed(mut response: AdapterResponse, error: NodeError) -> AdapterResponse {
    response.success = false;
    response.evidence = None;
    response.inventory.clear();
    response.diagnostics = vec![error.diagnostic()];
    response
}

fn validate_request(request: &AdapterRequest, original: &[u8]) -> Result<(), NodeError> {
    if request.schema != PROTOCOL_SCHEMA
        || request.message_type != "request"
        || request.adapter != "node-test"
        || request.project_root != "."
    {
        return Err(NodeError::Request(
            "protocol constants do not match the Node adapter".to_owned(),
        ));
    }
    if request.request_id.len() != 32
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NodeError::Request(
            "request_id must be 32 lowercase hexadecimal characters".to_owned(),
        ));
    }
    if !matches!(
        request.operation.as_str(),
        "doctor" | "inventory" | "check" | "reproduce"
    ) {
        return Err(NodeError::Request(
            "Node update and unknown operations are unsupported".to_owned(),
        ));
    }
    if canonical_json(request).map_err(|error| NodeError::Request(error.to_string()))? != original {
        return Err(NodeError::Request(
            "request JSON is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn drain_bounded(mut reader: impl Read) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let take = MAX_OUTPUT_BYTES.saturating_sub(kept.len()).min(count);
        kept.extend_from_slice(&buffer[..take]);
        truncated |= take < count;
    }
    Ok((kept, truncated))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    Vitest,
    Tsc,
    NpmPackage,
    Mutation,
}

struct RouteResult {
    inventory: Vec<String>,
    tool_version: String,
    static_check: Option<StaticCheckObservation>,
    distribution: Option<DistributionObservation>,
    mutation: Option<MutationReplayObservation>,
    generated_artifacts: Vec<ArtifactObservation>,
}

fn execute_request<E: Executor>(
    request: &AdapterRequest,
    project_root: &Path,
    executor: &mut E,
) -> Result<(Option<AdapterObservation>, Vec<String>), NodeError> {
    let root = project_root.canonicalize()?;
    let unit: EvidenceUnitManifest = serde_json::from_value(request.unit.clone())
        .map_err(|error| NodeError::Unit(error.to_string()))?;
    let route = validate_unit(&unit)?;
    validate_node_metadata(&root, &unit)?;
    let environment = child_environment(&unit.environment_allowlist)?;
    let environment_observation = observe_environment(&environment);
    let budget = BudgetObservation {
        time_ms: unit.resource_budget.time_seconds.saturating_mul(1000),
        disk_bytes: unit.resource_budget.disk_bytes,
        memory_bytes: unit.resource_budget.memory_bytes,
    };
    let started = Instant::now();
    let started_unix_ms = unix_ms()?;
    let deadline = Deadline {
        started,
        budget_ms: budget.time_ms,
    };
    let node = resolve_path_program("node")?;
    let npm = resolve_path_program("npm")?;
    let node_identity = executable_identity(&node)?;
    let npm_identity = executable_identity(&npm)?;
    let mut specs = Vec::new();
    let mut outputs = Vec::new();
    for spec in [
        ProcessSpec {
            program: node.clone(),
            args: vec!["--version".to_owned()],
        },
        ProcessSpec {
            program: npm.clone(),
            args: vec!["--version".to_owned()],
        },
    ] {
        let output = executor.run(&spec, &root, &environment, deadline.remaining()?)?;
        require_exit(&spec, &output, 0)?;
        specs.push(spec);
        outputs.push(output);
    }
    let node_version = single_line_identity(&outputs[0])?;
    let npm_version = single_line_identity(&outputs[1])?;
    if request.operation == "doctor" {
        if matches!(route, Route::Vitest | Route::Mutation) {
            resolve_local_tool(&root, "vitest")?;
        } else if route == Route::Tsc {
            resolve_local_tool(&root, "tsc")?;
        }
        return Ok((None, Vec::new()));
    }

    let shadow_count = usize::from(matches!(route, Route::NpmPackage | Route::Mutation)) + 1;
    let mut shadows = (0..shadow_count)
        .map(|_| Shadow::new(&root, budget.disk_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    for shadow in &shadows {
        install_dependencies(
            shadow,
            &npm,
            &environment,
            &environment_observation,
            executor,
            deadline,
            &mut specs,
            &mut outputs,
        )?;
    }
    let result = match route {
        Route::Vitest => run_vitest(
            &unit,
            &mut shadows[0],
            &environment,
            &environment_observation,
            executor,
            deadline,
            &mut specs,
            &mut outputs,
        )?,
        Route::Tsc => run_tsc(
            &unit,
            &shadows[0],
            &environment,
            &environment_observation,
            executor,
            deadline,
            &mut specs,
            &mut outputs,
        )?,
        Route::NpmPackage => run_npm_package(
            &unit,
            &mut shadows,
            &npm,
            &npm_version,
            &environment,
            &environment_observation,
            executor,
            deadline,
            &mut specs,
            &mut outputs,
        )?,
        Route::Mutation => run_mutation(
            &root,
            &unit,
            &mut shadows,
            &environment,
            &environment_observation,
            executor,
            deadline,
            &mut specs,
            &mut outputs,
        )?,
    };
    if request.operation == "inventory" {
        return Ok((None, result.inventory));
    }
    let allowed_failure = result
        .mutation
        .as_ref()
        .map(|mutation| mutation.expected_failure.run_index);
    if outputs.iter().enumerate().any(|(index, output)| {
        if Some(index) == allowed_failure {
            output.status != Some(1)
        } else {
            output.status != Some(0)
        }
    }) {
        return Err(NodeError::Internal(
            "successful observation contains an unregistered exit status".to_owned(),
        ));
    }
    if specs.len() != outputs.len() {
        return Err(NodeError::Internal(
            "command and run inventories diverged".to_owned(),
        ));
    }
    let disk_bytes = shadows.iter().try_fold(0_u64, |total, shadow| {
        let shadow_bytes = directory_size(shadow.base.path())?;
        total
            .checked_add(shadow_bytes)
            .ok_or_else(|| NodeError::Budget("disk accounting overflowed".to_owned()))
    })?;
    if disk_bytes > budget.disk_bytes {
        return Err(NodeError::Budget(format!(
            "shadow execution used {disk_bytes} bytes, limit is {}",
            budget.disk_bytes
        )));
    }
    let time_ms = elapsed_ms(started);
    if time_ms > budget.time_ms {
        return Err(NodeError::Budget(format!(
            "adapter execution used {time_ms} ms, limit is {}",
            budget.time_ms
        )));
    }
    let commands = specs
        .iter()
        .map(|spec| observe_command(spec, &root, &shadows, &environment_observation))
        .collect::<Vec<_>>();
    let runs = observe_runs(&outputs, &root, &shadows);
    let unit_bytes =
        canonical_json(&request.unit).map_err(|error| NodeError::Internal(error.to_string()))?;
    let result_identity = canonical_json(&serde_json::json!({
        "inventory": result.inventory,
        "static_check": result.static_check,
        "distribution_reproduction": result.distribution,
        "mutation_replay": result.mutation,
        "runs": runs.iter().map(|run| &run.normalized_output_sha256).collect::<Vec<_>>(),
    }))
    .map_err(|error| NodeError::Internal(error.to_string()))?;
    let tool_version = format!(
        "node {node_version}; npm {npm_version}; {}",
        result.tool_version
    );
    let tool_identity_bytes = format!(
        "{node_identity}\0{node_version}\0{npm_identity}\0{npm_version}\0{}",
        result.tool_version
    );
    let observation = AdapterObservation {
        schema: OBSERVATION_SCHEMA.to_owned(),
        unit_id: unit.id.clone(),
        evidence_kind: evidence_kind_name(unit.kind).to_owned(),
        outcome: ObservationOutcome::Passed,
        input_artifacts: collect_input_artifacts(&root, &unit.inputs)?,
        generated_artifacts: result.generated_artifacts,
        tool: ToolObservation {
            name: "Node/npm registered toolchain".to_owned(),
            version: tool_version,
            identity_sha256: domain_hash(
                "proofbound-tool-identity/1",
                tool_identity_bytes.as_bytes(),
            ),
        },
        adapter: adapter_identity(),
        commands,
        runs,
        started_unix_ms,
        completed_unix_ms: unix_ms()?,
        deterministic_result_sha256: domain_hash("proofbound-adapter-result/1", &result_identity),
        unit_configuration_sha256: domain_hash("proofbound-unit-configuration/1", &unit_bytes),
        resource_budget: budget,
        resource_usage: UsageObservation {
            time_ms,
            peak_disk_bytes: disk_bytes,
            peak_memory_bytes: None,
        },
        inventory: result.inventory.clone(),
        normalization: "stable-node-output/1; network-boundary-not-platform-enforced".to_owned(),
        static_check: result.static_check,
        distribution_reproduction: result.distribution,
        mutation_replay: result.mutation,
    };
    Ok((Some(observation), result.inventory))
}

fn validate_unit(unit: &EvidenceUnitManifest) -> Result<Route, NodeError> {
    if unit.adapter != AdapterKind::NodeTest {
        return Err(NodeError::Unit("adapter must be node-test".to_owned()));
    }
    let route = match (unit.schema.as_str(), unit.operation.kind, unit.kind) {
        (
            "proofbound-evidence-unit/1",
            OperationKind::Vitest,
            EvidenceKind::ExampleTest | EvidenceKind::PropertyTest,
        ) => Route::Vitest,
        ("proofbound-evidence-unit/1", OperationKind::Tsc, EvidenceKind::StaticCheck) => Route::Tsc,
        ("proofbound-evidence-unit/4", OperationKind::NpmPackage, EvidenceKind::ExampleTest) => {
            Route::NpmPackage
        }
        ("proofbound-evidence-unit/3", OperationKind::Vitest, EvidenceKind::MutationWitness) => {
            Route::Mutation
        }
        (_, OperationKind::Tsgo, _) => {
            return Err(NodeError::Unsupported(
                "tsgo is reserved until a specification revision admits it".to_owned(),
            ));
        }
        _ => {
            return Err(NodeError::Unit(
                "adapter, schema, operation, and evidence kind do not form a TypeScript route"
                    .to_owned(),
            ));
        }
    };
    if unit.id.is_empty()
        || unit.claims.is_empty()
        || unit.expected_inventory.is_empty()
        || unit.resource_budget.time_seconds == 0
        || unit.resource_budget.disk_bytes == 0
        || unit.resource_budget.memory_bytes == 0
    {
        return Err(NodeError::Unit(
            "identities, claims, inventory, and budgets must be nonempty".to_owned(),
        ));
    }
    for values in [
        &unit.claims,
        &unit.expected_inventory,
        &unit.inputs,
        &unit.outputs,
        &unit.environment_allowlist,
    ] {
        require_strict_set(values)?;
    }
    if !unit.outputs.is_empty() {
        return Err(NodeError::Unit(
            "Node evidence units do not declare committed outputs".to_owned(),
        ));
    }
    if unit.operation.package.is_some()
        || !unit.operation.targets.is_empty()
        || !unit.operation.paths.is_empty()
        || unit.operation.manifest.is_some()
        || unit.operation.inventory.is_some()
        || unit.operation.checker.is_some()
        || !unit.operation.arguments.is_empty()
        || !unit.operation.plugins.is_empty()
        || unit.property.is_some()
        || unit.transcription.is_some()
    {
        return Err(NodeError::Unit(
            "Node operations admit only their typed configuration blocks".to_owned(),
        ));
    }
    for input in &unit.inputs {
        validate_relative_path(input)?;
    }
    for required in ["package.json", "package-lock.json"] {
        if !unit.inputs.iter().any(|input| input == required) {
            return Err(NodeError::Unit(format!(
                "every Node unit must byte-pin {required}"
            )));
        }
    }
    match route {
        Route::Vitest => {
            if unit.distribution.is_some() || unit.mutation.is_some() {
                return Err(NodeError::Unit(
                    "ordinary vitest units cannot configure distribution or mutation".to_owned(),
                ));
            }
            if let Some(configuration) = &unit.operation.configuration {
                validate_registered_configuration(unit, configuration)?;
            }
            for node in &unit.expected_inventory {
                parse_node_id(node)?;
            }
        }
        Route::Tsc => {
            if unit.distribution.is_some() || unit.mutation.is_some() {
                return Err(NodeError::Unit(
                    "tsc units cannot configure distribution or mutation".to_owned(),
                ));
            }
            let configuration = unit.operation.configuration.as_deref().ok_or_else(|| {
                NodeError::Unit("tsc requires operation.configuration".to_owned())
            })?;
            validate_registered_configuration(unit, configuration)?;
        }
        Route::NpmPackage => {
            if unit.operation.configuration.is_some() || unit.mutation.is_some() {
                return Err(NodeError::Unit(
                    "npm-package accepts only its distribution block".to_owned(),
                ));
            }
            let distribution = unit
                .distribution
                .as_ref()
                .ok_or_else(|| NodeError::Unit("npm-package requires [distribution]".to_owned()))?;
            if distribution.schema != DistributionReproductionSchema::Version1
                || distribution.format != DistributionFormat::NpmPackage
                || distribution.source_date_epoch != 0
                || !valid_digest(&distribution.artifact_sha256)
                || !safe_filename(&distribution.artifact_name)
                || unit.expected_inventory != [distribution.artifact_name.as_str()]
            {
                return Err(NodeError::Unit(
                    "invalid npm-package distribution registration".to_owned(),
                ));
            }
        }
        Route::Mutation => {
            if unit.operation.configuration.is_some() || unit.distribution.is_some() {
                return Err(NodeError::Unit(
                    "vitest mutation accepts only its mutation block".to_owned(),
                ));
            }
            let mutation = unit.mutation.as_ref().ok_or_else(|| {
                NodeError::Unit("mutation-witness requires [mutation]".to_owned())
            })?;
            if mutation.schema != MutationReplaySchema::Version1 {
                return Err(NodeError::Unit(
                    "unsupported mutation replay schema".to_owned(),
                ));
            }
            validate_relative_path(&mutation.registry)?;
        }
    }
    Ok(route)
}

fn validate_registered_configuration(
    unit: &EvidenceUnitManifest,
    configuration: &str,
) -> Result<(), NodeError> {
    validate_relative_path(configuration)?;
    if !unit.inputs.iter().any(|input| input == configuration) {
        return Err(NodeError::Unit(format!(
            "configuration `{configuration}` must be byte-pinned in inputs"
        )));
    }
    Ok(())
}

fn require_strict_set(values: &[String]) -> Result<(), NodeError> {
    if values.len() > MAX_INVENTORY
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|value| value.is_empty())
    {
        return Err(NodeError::Unit(
            "manifest collections must be bounded strict lexical sets".to_owned(),
        ));
    }
    Ok(())
}

fn validate_node_metadata(root: &Path, _unit: &EvidenceUnitManifest) -> Result<(), NodeError> {
    let package_bytes = read_safe_file(root, "package.json", MAX_JSON_BYTES)?;
    let lock_bytes = read_safe_file(root, "package-lock.json", MAX_JSON_BYTES)?;
    let package: Value = serde_json::from_slice(&package_bytes)
        .map_err(|error| NodeError::Unsupported(format!("package.json is not JSON: {error}")))?;
    let lock: Value = serde_json::from_slice(&lock_bytes).map_err(|error| {
        NodeError::Unsupported(format!("package-lock.json is not JSON: {error}"))
    })?;
    let package = package
        .as_object()
        .ok_or_else(|| NodeError::Unsupported("package.json must be a JSON object".to_owned()))?;
    if package.contains_key("workspaces") {
        return Err(NodeError::Unsupported(
            "npm workspaces are not admitted in this version".to_owned(),
        ));
    }
    if let Some(manager) = package.get("packageManager").and_then(Value::as_str)
        && !manager.starts_with("npm@")
    {
        return Err(NodeError::Unsupported(format!(
            "package manager `{manager}` is not npm"
        )));
    }
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(dependencies) = package.get(section).and_then(Value::as_object) {
            for (name, specification) in dependencies {
                let specification = specification.as_str().ok_or_else(|| {
                    NodeError::Unsupported(format!(
                        "{section}.{name} must be a string dependency specification"
                    ))
                })?;
                if forbidden_dependency(specification) {
                    return Err(NodeError::Unsupported(format!(
                        "{section}.{name} uses unsupported dependency `{specification}`"
                    )));
                }
            }
        }
    }
    let lock = lock.as_object().ok_or_else(|| {
        NodeError::Unsupported("package-lock.json must be a JSON object".to_owned())
    })?;
    let version = lock
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            NodeError::Unsupported("package-lock.json omits lockfileVersion".to_owned())
        })?;
    if version < 3 {
        return Err(NodeError::Unsupported(format!(
            "package-lock lockfileVersion {version} is below 3"
        )));
    }
    let packages = lock
        .get("packages")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            NodeError::Unsupported("package-lock.json omits the packages map".to_owned())
        })?;
    if !packages.contains_key("") {
        return Err(NodeError::Unsupported(
            "package-lock.json omits the root package entry".to_owned(),
        ));
    }
    for (path, entry) in packages {
        if path.is_empty() {
            continue;
        }
        validate_relative_path(path)?;
        if !path.split('/').any(|component| component == "node_modules") {
            return Err(NodeError::Unsupported(format!(
                "lockfile package entry `{path}` is a workspace or local package"
            )));
        }
        let entry = entry.as_object().ok_or_else(|| {
            NodeError::Unsupported(format!("lockfile package entry `{path}` is not an object"))
        })?;
        if entry.get("link").and_then(Value::as_bool) == Some(true) {
            return Err(NodeError::Unsupported(format!(
                "lockfile package entry `{path}` is a link"
            )));
        }
        if entry.get("integrity").and_then(Value::as_str).is_none()
            && !bundled_entry_is_bound(path, entry, packages)
        {
            return Err(NodeError::Unsupported(format!(
                "lockfile package entry `{path}` omits integrity"
            )));
        }
        if let Some(resolved) = entry.get("resolved").and_then(Value::as_str)
            && forbidden_dependency(resolved)
        {
            return Err(NodeError::Unsupported(format!(
                "lockfile package entry `{path}` resolves through unsupported `{resolved}`"
            )));
        }
    }
    Ok(())
}

fn bundled_entry_is_bound(
    path: &str,
    entry: &serde_json::Map<String, Value>,
    packages: &serde_json::Map<String, Value>,
) -> bool {
    entry.get("inBundle").and_then(Value::as_bool) == Some(true)
        && packages.iter().any(|(parent_path, parent)| {
            !parent_path.is_empty()
                && path.starts_with(&format!("{parent_path}/node_modules/"))
                && parent.get("integrity").and_then(Value::as_str).is_some()
        })
}

fn forbidden_dependency(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("git:")
        || lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("http:")
}

fn child_environment(allowlist: &[String]) -> Result<BTreeMap<String, String>, NodeError> {
    let mut environment = BTreeMap::new();
    for name in allowlist {
        if name.is_empty()
            || name.contains('=')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(NodeError::Unit(format!(
                "invalid environment variable `{name}`"
            )));
        }
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.clone(), value);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        environment
            .entry("PATH".to_owned())
            .or_insert_with(|| path.to_string_lossy().into_owned());
    }
    environment.insert("CI".to_owned(), "1".to_owned());
    environment.insert("NO_COLOR".to_owned(), "1".to_owned());
    environment.insert("TERM".to_owned(), "dumb".to_owned());
    Ok(environment)
}

struct Shadow {
    base: TempDir,
    project: PathBuf,
    cache: PathBuf,
}

impl Shadow {
    fn new(source: &Path, disk_budget: u64) -> Result<Self, NodeError> {
        let base = tempfile::Builder::new()
            .prefix("proofbound-node-")
            .tempdir()?;
        let project = base.path().join("project");
        let cache = base.path().join("npm-cache");
        fs::create_dir(&project)?;
        fs::create_dir(&cache)?;
        let mut copied = 0_u64;
        let walker = WalkDir::new(source)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| {
                entry
                    .path()
                    .strip_prefix(source)
                    .ok()
                    .is_none_or(|relative| !excluded_path(relative))
            });
        for entry in walker {
            let entry = entry.map_err(walk_error)?;
            let relative = entry
                .path()
                .strip_prefix(source)
                .map_err(|_| NodeError::UnsafePath(entry.path().display().to_string()))?;
            if relative.as_os_str().is_empty() {
                continue;
            }
            if entry.file_type().is_symlink() {
                return Err(NodeError::UnsafePath(relative.display().to_string()));
            }
            if entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                return Err(NodeError::UnsafePath(relative.display().to_string()));
            }
            let size = entry.metadata().map_err(walk_error)?.len();
            copied = copied
                .checked_add(size)
                .ok_or_else(|| NodeError::Budget("copy size overflowed".to_owned()))?;
            if copied > disk_budget {
                return Err(NodeError::Budget(format!(
                    "reviewed tree exceeds {disk_budget} bytes"
                )));
            }
            let destination = project.join(relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), destination)?;
        }
        Ok(Self {
            base,
            project: project.canonicalize()?,
            cache: cache.canonicalize()?,
        })
    }
}

fn excluded_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                ".git"
                    | ".proofbound"
                    | "node_modules"
                    | "target"
                    | ".lake"
                    | "__pycache__"
                    | ".pytest_cache"
                    | ".mypy_cache"
                    | ".ruff_cache"
            )
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn install_dependencies<E: Executor>(
    shadow: &Shadow,
    npm: &Path,
    base_environment: &BTreeMap<String, String>,
    environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
) -> Result<(), NodeError> {
    let before = snapshot_source_tree(&shadow.project)?;
    let mut environment = base_environment.clone();
    environment.insert(
        "NPM_CONFIG_CACHE".to_owned(),
        shadow.cache.to_string_lossy().into_owned(),
    );
    for args in [
        vec!["--version".to_owned()],
        vec![
            "ci".to_owned(),
            "--ignore-scripts".to_owned(),
            "--no-audit".to_owned(),
            "--no-fund".to_owned(),
        ],
    ] {
        let spec = ProcessSpec {
            program: npm.to_owned(),
            args,
        };
        let output = executor.run(&spec, &shadow.project, &environment, deadline.remaining()?)?;
        require_exit(&spec, &output, 0)?;
        let _ = environment_observation;
        specs.push(spec);
        outputs.push(output);
    }
    let after = snapshot_source_tree(&shadow.project)?;
    if before != after {
        return Err(NodeError::ToolFailed(
            "npm installation modified reviewed source bytes".to_owned(),
        ));
    }
    Ok(())
}

fn snapshot_source_tree(root: &Path) -> Result<Vec<(String, String)>, NodeError> {
    let mut snapshot = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .ok()
                .is_none_or(|relative| !excluded_path(relative))
        })
    {
        let entry = entry.map_err(walk_error)?;
        if entry.file_type().is_symlink() {
            return Err(NodeError::UnsafePath(entry.path().display().to_string()));
        }
        if entry.file_type().is_file() {
            let relative = logical_path(root, entry.path())?;
            snapshot.push((relative, sha256_bytes(&fs::read(entry.path())?)));
        }
    }
    Ok(snapshot)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct VitestNode {
    file: String,
    name: String,
}

impl VitestNode {
    fn id(&self) -> String {
        format!("{}::{}", self.file, self.name)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_vitest<E: Executor>(
    unit: &EvidenceUnitManifest,
    shadow: &mut Shadow,
    base_environment: &BTreeMap<String, String>,
    environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
) -> Result<RouteResult, NodeError> {
    let tool = resolve_local_tool(&shadow.project, "vitest")?;
    let mut environment = base_environment.clone();
    environment.insert("NPM_CONFIG_OFFLINE".to_owned(), "true".to_owned());
    let version = vitest_version(
        &tool,
        &shadow.project,
        &environment,
        environment_observation,
        executor,
        deadline,
        specs,
        outputs,
    )?;
    let registered = unit
        .expected_inventory
        .iter()
        .map(|node| parse_node_id(node))
        .collect::<Result<Vec<_>, _>>()?;
    discover_vitest(
        unit,
        shadow,
        &tool,
        &environment,
        environment_observation,
        executor,
        deadline,
        specs,
        outputs,
        &registered,
    )?;
    for node in &registered {
        execute_vitest_node(
            unit,
            &shadow.project,
            &tool,
            &environment,
            environment_observation,
            executor,
            deadline,
            specs,
            outputs,
            node,
            true,
        )?;
    }
    Ok(RouteResult {
        inventory: registered.iter().map(VitestNode::id).collect(),
        tool_version: format!("vitest {version}"),
        static_check: None,
        distribution: None,
        mutation: None,
        generated_artifacts: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
fn vitest_version<E: Executor>(
    tool: &Path,
    root: &Path,
    environment: &BTreeMap<String, String>,
    _environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
) -> Result<Version, NodeError> {
    let spec = ProcessSpec {
        program: tool.to_owned(),
        args: vec!["--version".to_owned()],
    };
    let output = executor.run(&spec, root, environment, deadline.remaining()?)?;
    require_exit(&spec, &output, 0)?;
    let text = single_line_identity(&output)?;
    let version = parse_vitest_version(&text)?;
    let floor = Version::parse(VITEST_FLOOR).expect("constant is a semantic version");
    if version < floor {
        return Err(NodeError::Unsupported(format!(
            "vitest {version} is below the required {VITEST_FLOOR} floor"
        )));
    }
    specs.push(spec);
    outputs.push(output);
    Ok(version)
}

fn parse_vitest_version(text: &str) -> Result<Version, NodeError> {
    text.split_ascii_whitespace()
        .find_map(|token| {
            Version::parse(
                token
                    .strip_prefix("vitest/")
                    .unwrap_or(token)
                    .trim_start_matches('v'),
            )
            .ok()
        })
        .ok_or_else(|| {
            NodeError::Unsupported(format!("vitest reported unparseable version `{text}`"))
        })
}

#[allow(clippy::too_many_arguments)]
fn discover_vitest<E: Executor>(
    unit: &EvidenceUnitManifest,
    shadow: &mut Shadow,
    tool: &Path,
    environment: &BTreeMap<String, String>,
    _environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
    registered: &[VitestNode],
) -> Result<(), NodeError> {
    let list_path = shadow.base.path().join("vitest-list.json");
    let mut args = vec![
        "list".to_owned(),
        format!("--json={}", list_path.to_string_lossy()),
    ];
    append_configuration(&mut args, unit);
    let spec = ProcessSpec {
        program: tool.to_owned(),
        args,
    };
    let output = executor.run(&spec, &shadow.project, environment, deadline.remaining()?)?;
    require_exit(&spec, &output, 0)?;
    if output.truncated {
        return Err(NodeError::Inventory(
            "vitest listing output was truncated".to_owned(),
        ));
    }
    let listed = parse_vitest_listing(&list_path, &shadow.project)?;
    let registered_files = registered
        .iter()
        .map(|node| node.file.as_str())
        .collect::<BTreeSet<_>>();
    let discovered = listed
        .into_iter()
        .filter(|node| registered_files.contains(node.file.as_str()))
        .collect::<Vec<_>>();
    if discovered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(NodeError::Inventory(
            "vitest returned a duplicate node in a registered file".to_owned(),
        ));
    }
    if discovered != registered {
        return Err(NodeError::Inventory(format!(
            "registered nodes {:?} do not equal discovered nodes {:?}",
            registered.iter().map(VitestNode::id).collect::<Vec<_>>(),
            discovered.iter().map(VitestNode::id).collect::<Vec<_>>()
        )));
    }
    specs.push(spec);
    outputs.push(output);
    Ok(())
}

fn parse_vitest_listing(path: &Path, root: &Path) -> Result<Vec<VitestNode>, NodeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| NodeError::Inventory("vitest did not create its JSON listing".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_JSON_BYTES {
        return Err(NodeError::Inventory(
            "vitest listing is not a bounded regular file".to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(&fs::read(path)?)
        .map_err(|error| NodeError::Inventory(format!("invalid vitest listing JSON: {error}")))?;
    let entries = value
        .as_array()
        .ok_or_else(|| NodeError::Inventory("vitest listing must be a JSON array".to_owned()))?;
    if entries.is_empty() || entries.len() > MAX_INVENTORY {
        return Err(NodeError::Inventory(
            "vitest listing must be nonempty and bounded".to_owned(),
        ));
    }
    let mut nodes = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object().ok_or_else(|| {
            NodeError::Inventory("vitest listing entry is not an object".to_owned())
        })?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| NodeError::Inventory("vitest listing entry omits name".to_owned()))?;
        let file = object
            .get("file")
            .and_then(|file| {
                file.as_str().or_else(|| {
                    file.as_object()
                        .and_then(|object| object.get("filepath"))
                        .and_then(Value::as_str)
                })
            })
            .ok_or_else(|| NodeError::Inventory("vitest listing entry omits file".to_owned()))?;
        let file = repository_relative_tool_path(root, file)?;
        let node = VitestNode {
            file,
            name: name.to_owned(),
        };
        validate_node(&node)?;
        nodes.push(node);
    }
    nodes.sort();
    Ok(nodes)
}

#[allow(clippy::too_many_arguments)]
fn execute_vitest_node<E: Executor>(
    unit: &EvidenceUnitManifest,
    root: &Path,
    tool: &Path,
    environment: &BTreeMap<String, String>,
    _environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
    node: &VitestNode,
    expect_pass: bool,
) -> Result<usize, NodeError> {
    let runner_name = node.name.replace(" > ", " ");
    let pattern = format!("^{}$", regex_escape(&runner_name));
    let mut args = vec![
        "run".to_owned(),
        node.file.clone(),
        "--reporter=json".to_owned(),
        "--testNamePattern".to_owned(),
        pattern,
    ];
    append_configuration(&mut args, unit);
    let spec = ProcessSpec {
        program: tool.to_owned(),
        args,
    };
    let output = executor.run(&spec, root, environment, deadline.remaining()?)?;
    let expected_exit = if expect_pass { 0 } else { 1 };
    require_exit(&spec, &output, expected_exit)?;
    validate_vitest_report(&output, root, node, expect_pass)?;
    let index = outputs.len();
    specs.push(spec);
    outputs.push(output);
    Ok(index)
}

fn validate_vitest_report(
    output: &ProcessOutput,
    root: &Path,
    expected: &VitestNode,
    expect_pass: bool,
) -> Result<(), NodeError> {
    if output.truncated {
        return Err(NodeError::Inventory(
            "vitest execution report was truncated".to_owned(),
        ));
    }
    let report: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| NodeError::Inventory(format!("invalid vitest report JSON: {error}")))?;
    let total = report.get("numTotalTests").and_then(Value::as_u64);
    let selected = if expect_pass {
        report.get("numPassedTests").and_then(Value::as_u64)
    } else {
        report.get("numFailedTests").and_then(Value::as_u64)
    };
    if selected != Some(1) {
        return Err(NodeError::Inventory(format!(
            "vitest executed total={total:?}, selected-outcome={selected:?}; expected one selected assertion"
        )));
    }
    let test_results = report
        .get("testResults")
        .and_then(Value::as_array)
        .ok_or_else(|| NodeError::Inventory("vitest report omits testResults".to_owned()))?;
    let mut assertions = Vec::new();
    for test in test_results {
        let file = test
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| NodeError::Inventory("vitest test result omits file name".to_owned()))?;
        let file = repository_relative_tool_path(root, file)?;
        for assertion in test
            .get("assertionResults")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                NodeError::Inventory("vitest result omits assertionResults".to_owned())
            })?
        {
            let full_name = assertion
                .get("fullName")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    NodeError::Inventory("vitest assertion omits fullName".to_owned())
                })?;
            let ancestors = assertion
                .get("ancestorTitles")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    NodeError::Inventory("vitest assertion omits ancestorTitles".to_owned())
                })?
                .iter()
                .map(|value| {
                    value.as_str().ok_or_else(|| {
                        NodeError::Inventory(
                            "vitest assertion has a non-string ancestor".to_owned(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let title = assertion
                .get("title")
                .and_then(Value::as_str)
                .ok_or_else(|| NodeError::Inventory("vitest assertion omits title".to_owned()))?;
            let mut components = ancestors;
            components.push(title);
            if full_name != components.join(" ") {
                return Err(NodeError::Inventory(
                    "vitest assertion name fields disagree".to_owned(),
                ));
            }
            let node = VitestNode {
                file: file.clone(),
                name: components.join(" > "),
            };
            let expected_status = if expect_pass { "passed" } else { "failed" };
            let status = assertion.get("status").and_then(Value::as_str);
            if node == *expected && status != Some(expected_status) {
                return Err(NodeError::Inventory(format!(
                    "vitest assertion did not report `{expected_status}`"
                )));
            }
            if node != *expected && status != Some("skipped") {
                return Err(NodeError::Inventory(format!(
                    "vitest executed unselected assertion `{}` with status {status:?}",
                    node.id()
                )));
            }
            assertions.push((node, status));
        }
    }
    let selected_assertions = assertions
        .iter()
        .filter(|(_, status)| *status != Some("skipped"))
        .map(|(node, _)| node.clone())
        .collect::<Vec<_>>();
    if total != u64::try_from(assertions.len()).ok() || selected_assertions != [expected.clone()] {
        return Err(NodeError::Inventory(format!(
            "vitest report selected {:?}, expected `{}`",
            selected_assertions
                .iter()
                .map(VitestNode::id)
                .collect::<Vec<_>>(),
            expected.id()
        )));
    }
    Ok(())
}

fn append_configuration(args: &mut Vec<String>, unit: &EvidenceUnitManifest) {
    if let Some(configuration) = &unit.operation.configuration {
        args.push("--config".to_owned());
        args.push(configuration.clone());
    }
}

fn parse_node_id(value: &str) -> Result<VitestNode, NodeError> {
    let (file, name) = value
        .split_once("::")
        .ok_or_else(|| NodeError::Inventory(format!("vitest node `{value}` must be FILE::NAME")))?;
    let node = VitestNode {
        file: file.to_owned(),
        name: name.to_owned(),
    };
    validate_node(&node)?;
    Ok(node)
}

fn validate_node(node: &VitestNode) -> Result<(), NodeError> {
    validate_relative_path(&node.file)?;
    if node.name.is_empty()
        || node.name.len() > 1024
        || !node.name.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        || node.name.starts_with('-')
    {
        return Err(NodeError::Inventory(format!(
            "vitest node `{}` has an unsafe test name",
            node.id()
        )));
    }
    Ok(())
}

fn regex_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn validate_tsc_configuration(bytes: &[u8]) -> Result<(), NodeError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        NodeError::Unsupported(format!(
            "tsconfig must be plain JSON without comments or trailing commas: {error}"
        ))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| NodeError::Unsupported("tsconfig must contain a JSON object".to_owned()))?;
    if object.contains_key("extends") {
        return Err(NodeError::Unsupported(
            "tsconfig extends chains are unsupported; flatten the configuration".to_owned(),
        ));
    }
    if object
        .get("compilerOptions")
        .and_then(Value::as_object)
        .and_then(|options| options.get("strict"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(NodeError::Unsupported(
            "tsconfig compilerOptions.strict must be true".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_tsc<E: Executor>(
    unit: &EvidenceUnitManifest,
    shadow: &Shadow,
    base_environment: &BTreeMap<String, String>,
    _environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
) -> Result<RouteResult, NodeError> {
    let configuration = unit
        .operation
        .configuration
        .as_deref()
        .ok_or_else(|| NodeError::Unit("tsc configuration is missing".to_owned()))?;
    let configuration_bytes = read_safe_file(&shadow.project, configuration, MAX_JSON_BYTES)?;
    validate_tsc_configuration(&configuration_bytes)?;

    let tool = resolve_local_tool(&shadow.project, "tsc")?;
    let mut environment = base_environment.clone();
    environment.insert("NPM_CONFIG_OFFLINE".to_owned(), "true".to_owned());
    let version_spec = ProcessSpec {
        program: tool.clone(),
        args: vec!["--version".to_owned()],
    };
    let version_output = executor.run(
        &version_spec,
        &shadow.project,
        &environment,
        deadline.remaining()?,
    )?;
    require_exit(&version_spec, &version_output, 0)?;
    let version = single_line_identity(&version_output)?;
    specs.push(version_spec);
    outputs.push(version_output);

    let list_spec = ProcessSpec {
        program: tool.clone(),
        args: vec![
            "--project".to_owned(),
            configuration.to_owned(),
            "--listFilesOnly".to_owned(),
        ],
    };
    let list_output = executor.run(
        &list_spec,
        &shadow.project,
        &environment,
        deadline.remaining()?,
    )?;
    require_exit(&list_spec, &list_output, 0)?;
    if list_output.truncated || !list_output.stderr.is_empty() {
        return Err(NodeError::Inventory(
            "tsc --listFilesOnly was truncated or wrote diagnostics".to_owned(),
        ));
    }
    let inventory = parse_tsc_inventory(&list_output.stdout, &shadow.project)?;
    if inventory != unit.expected_inventory {
        return Err(NodeError::Inventory(format!(
            "registered targets {:?} do not equal tsc targets {inventory:?}",
            unit.expected_inventory
        )));
    }
    specs.push(list_spec);
    outputs.push(list_output);

    let check_spec = ProcessSpec {
        program: tool,
        args: vec![
            "--project".to_owned(),
            configuration.to_owned(),
            "--noEmit".to_owned(),
            "--pretty".to_owned(),
            "false".to_owned(),
        ],
    };
    let check_output = executor.run(
        &check_spec,
        &shadow.project,
        &environment,
        deadline.remaining()?,
    )?;
    require_exit(&check_spec, &check_output, 0)?;
    if check_output.truncated || !check_output.stdout.is_empty() || !check_output.stderr.is_empty()
    {
        let diagnostic = first_diagnostic(&check_output);
        return Err(NodeError::ToolFailed(format!(
            "tsc produced a diagnostic despite a successful exit: {diagnostic}"
        )));
    }
    specs.push(check_spec);
    outputs.push(check_output);
    Ok(RouteResult {
        inventory: inventory.clone(),
        tool_version: version.clone(),
        static_check: Some(StaticCheckObservation {
            schema: "proofbound-static-check/1".to_owned(),
            tool: "tsc".to_owned(),
            tool_version: version,
            configuration_sha256: sha256_bytes(&configuration_bytes),
            targets: inventory,
            diagnostics: 0,
        }),
        distribution: None,
        mutation: None,
        generated_artifacts: Vec::new(),
    })
}

fn parse_tsc_inventory(bytes: &[u8], root: &Path) -> Result<Vec<String>, NodeError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| NodeError::Inventory(format!("tsc file list is not UTF-8: {error}")))?;
    let mut targets = Vec::new();
    let mut saw_member = false;
    for line in text.lines() {
        if line.is_empty() || line.trim() != line {
            return Err(NodeError::Inventory(
                "tsc returned a blank or padded file-list line".to_owned(),
            ));
        }
        let relative = repository_relative_tool_path(root, line)?;
        saw_member = true;
        if !relative
            .split('/')
            .any(|component| component == "node_modules")
        {
            targets.push(relative);
        }
    }
    if !saw_member || targets.is_empty() || targets.len() > MAX_INVENTORY {
        return Err(NodeError::Inventory(
            "tsc analyzed inventory must include at least one repository file".to_owned(),
        ));
    }
    targets.sort();
    if targets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(NodeError::Inventory(
            "tsc returned duplicate repository files".to_owned(),
        ));
    }
    Ok(targets)
}

#[derive(Debug)]
struct PackResult {
    digest: String,
    size_bytes: u64,
    integrity: String,
    members: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn run_npm_package<E: Executor>(
    unit: &EvidenceUnitManifest,
    shadows: &mut [Shadow],
    npm: &Path,
    npm_version: &str,
    base_environment: &BTreeMap<String, String>,
    _environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
) -> Result<RouteResult, NodeError> {
    let distribution = unit
        .distribution
        .as_ref()
        .ok_or_else(|| NodeError::Unit("npm distribution registration is missing".to_owned()))?;
    if shadows.len() != 2 {
        return Err(NodeError::Internal(
            "npm reproduction requires two shadows".to_owned(),
        ));
    }
    let mut results = Vec::with_capacity(2);
    for shadow in shadows {
        let destination = shadow.base.path().join("distribution");
        fs::create_dir(&destination)?;
        let mut environment = base_environment.clone();
        environment.insert("NPM_CONFIG_OFFLINE".to_owned(), "true".to_owned());
        environment.insert("NPM_CONFIG_IGNORE_SCRIPTS".to_owned(), "true".to_owned());
        environment.insert(
            "NPM_CONFIG_CACHE".to_owned(),
            shadow.cache.to_string_lossy().into_owned(),
        );
        let spec = ProcessSpec {
            program: npm.to_owned(),
            args: vec![
                "pack".to_owned(),
                "--ignore-scripts".to_owned(),
                "--json".to_owned(),
                "--pack-destination".to_owned(),
                destination.to_string_lossy().into_owned(),
            ],
        };
        let output = executor.run(&spec, &shadow.project, &environment, deadline.remaining()?)?;
        require_exit(&spec, &output, 0)?;
        let result = validate_pack_result(
            &output,
            &shadow.project,
            &destination,
            &distribution.artifact_name,
            distribution.source_date_epoch,
            unit.resource_budget.disk_bytes,
        )?;
        specs.push(spec);
        outputs.push(output);
        results.push(result);
    }
    let first = &results[0];
    let second = &results[1];
    if first.digest != second.digest
        || first.digest != distribution.artifact_sha256
        || first.members != second.members
        || first.integrity != second.integrity
    {
        return Err(NodeError::Inventory(format!(
            "npm package reproduction mismatch: first={}, second={}, registered={}",
            first.digest, second.digest, distribution.artifact_sha256
        )));
    }
    let generated_artifacts = results
        .iter()
        .enumerate()
        .map(|(index, result)| ArtifactObservation {
            logical_name: format!("distribution/{}/candidate-{}", unit.id, index + 1),
            sha256: result.digest.clone(),
            size_bytes: result.size_bytes,
        })
        .collect();
    Ok(RouteResult {
        inventory: vec![distribution.artifact_name.clone()],
        tool_version: "npm package".to_owned(),
        static_check: None,
        distribution: Some(DistributionObservation {
            schema: "proofbound-distribution-reproduction/1".to_owned(),
            format: "npm-package".to_owned(),
            run_digests: vec![first.digest.clone(), second.digest.clone()],
            registered_digest: distribution.artifact_sha256.clone(),
            source_date_epoch: 0,
            build_backend_name: "npm".to_owned(),
            build_backend_version: npm_version.to_owned(),
            npm_integrity: Some(first.integrity.clone()),
            member_inventory: first.members.clone(),
        }),
        mutation: None,
        generated_artifacts,
    })
}

fn validate_pack_result(
    output: &ProcessOutput,
    source_root: &Path,
    destination: &Path,
    artifact_name: &str,
    source_date_epoch: u64,
    disk_budget: u64,
) -> Result<PackResult, NodeError> {
    if source_date_epoch != 0 {
        return Err(NodeError::Unit(
            "npm source_date_epoch must be zero".to_owned(),
        ));
    }
    if output.truncated || !output.stderr.is_empty() {
        return Err(NodeError::Inventory(
            "npm pack report was truncated or wrote to stderr".to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| NodeError::Inventory(format!("invalid npm pack JSON: {error}")))?;
    let reports = value
        .as_array()
        .ok_or_else(|| NodeError::Inventory("npm pack report must be a JSON array".to_owned()))?;
    if reports.len() != 1 {
        return Err(NodeError::Inventory(format!(
            "npm pack reported {} tarballs, expected one",
            reports.len()
        )));
    }
    let report = reports[0]
        .as_object()
        .ok_or_else(|| NodeError::Inventory("npm pack report is not an object".to_owned()))?;
    if report.get("filename").and_then(Value::as_str) != Some(artifact_name) {
        return Err(NodeError::Inventory(
            "npm pack filename does not match artifact_name".to_owned(),
        ));
    }
    let integrity = report
        .get("integrity")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha512-") && value.len() > 16)
        .ok_or_else(|| NodeError::Inventory("npm pack omitted integrity".to_owned()))?
        .to_owned();
    if report
        .get("shasum")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .is_none()
    {
        return Err(NodeError::Inventory("npm pack omitted shasum".to_owned()));
    }
    let mut reported_members = report
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| NodeError::Inventory("npm pack omitted files inventory".to_owned()))?
        .iter()
        .map(|file| {
            file.get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| NodeError::Inventory("npm pack file omitted path".to_owned()))
                .and_then(|path| {
                    validate_relative_path(path)?;
                    Ok(path.to_owned())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    reported_members.sort();
    if reported_members.is_empty()
        || reported_members.len() > MAX_INVENTORY
        || reported_members.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(NodeError::Inventory(
            "npm pack files must be a nonempty bounded set".to_owned(),
        ));
    }
    let tarball = destination.join(artifact_name);
    reject_symlink_components(destination, &tarball)?;
    let metadata = fs::symlink_metadata(&tarball)
        .map_err(|_| NodeError::Inventory("npm pack did not create the tarball".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > disk_budget {
        return Err(NodeError::Inventory(
            "npm tarball is not a bounded regular file".to_owned(),
        ));
    }
    let bytes = fs::read(&tarball)?;
    let extracted = inspect_tarball(&bytes, source_root, disk_budget)?;
    if extracted != reported_members {
        return Err(NodeError::Inventory(format!(
            "tar members {extracted:?} do not equal npm report {reported_members:?}"
        )));
    }
    Ok(PackResult {
        digest: sha256_bytes(&bytes),
        size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
        integrity,
        members: extracted,
    })
}

fn inspect_tarball(
    bytes: &[u8],
    source_root: &Path,
    disk_budget: u64,
) -> Result<Vec<String>, NodeError> {
    let decoder = GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut members = Vec::new();
    let mut extracted_bytes = 0_u64;
    for entry in archive
        .entries()
        .map_err(|error| NodeError::Inventory(format!("invalid npm tarball: {error}")))?
    {
        let mut entry = entry
            .map_err(|error| NodeError::Inventory(format!("invalid npm tar entry: {error}")))?;
        let entry_type = entry.header().entry_type();
        let path = entry
            .path()
            .map_err(|error| NodeError::Inventory(format!("invalid tar path: {error}")))?
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(NodeError::UnsafePath(path.display().to_string()));
        }
        let mut components = path.components();
        if components
            .next()
            .and_then(|component| component.as_os_str().to_str())
            != Some("package")
        {
            return Err(NodeError::UnsafePath(path.display().to_string()));
        }
        let relative = components.collect::<PathBuf>();
        if relative.as_os_str().is_empty() {
            if entry_type.is_dir() {
                continue;
            }
            return Err(NodeError::UnsafePath(path.display().to_string()));
        }
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        validate_relative_path(&relative_text)?;
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err(NodeError::Unsupported(format!(
                "npm tar member `{}` is not a regular file",
                path.display()
            )));
        }
        let size = entry.header().size().map_err(|error| {
            NodeError::Inventory(format!("invalid size for `{relative_text}`: {error}"))
        })?;
        extracted_bytes = extracted_bytes
            .checked_add(size)
            .ok_or_else(|| NodeError::Budget("tar member size overflowed".to_owned()))?;
        if extracted_bytes > disk_budget {
            return Err(NodeError::Budget(
                "unpacked npm tarball exceeds the disk budget".to_owned(),
            ));
        }
        let source = resolve_existing(source_root, &relative_text)?;
        if !source.is_file() {
            return Err(NodeError::Unsupported(format!(
                "npm tar member `{relative_text}` has no sealed source origin"
            )));
        }
        let mut member_bytes = Vec::new();
        entry.read_to_end(&mut member_bytes)?;
        if member_bytes != fs::read(&source)? {
            return Err(NodeError::Inventory(format!(
                "npm tar member `{relative_text}` differs from reviewed source bytes"
            )));
        }
        members.push(relative_text);
    }
    members.sort();
    if members.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(NodeError::Inventory(
            "npm tarball contains duplicate file members".to_owned(),
        ));
    }
    Ok(members)
}

#[allow(clippy::too_many_arguments)]
fn run_mutation<E: Executor>(
    original_root: &Path,
    unit: &EvidenceUnitManifest,
    shadows: &mut [Shadow],
    base_environment: &BTreeMap<String, String>,
    environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    deadline: Deadline,
    specs: &mut Vec<ProcessSpec>,
    outputs: &mut Vec<ProcessOutput>,
) -> Result<RouteResult, NodeError> {
    if shadows.len() != 2 {
        return Err(NodeError::Internal(
            "mutation replay requires baseline and mutant shadows".to_owned(),
        ));
    }
    let replay = unit
        .mutation
        .as_ref()
        .ok_or_else(|| NodeError::Unit("mutation replay is missing".to_owned()))?;
    let registry_bytes = read_safe_file(original_root, &replay.registry, MAX_JSON_BYTES)?;
    let registry: MutationRegistry =
        toml::from_str(std::str::from_utf8(&registry_bytes).map_err(|error| {
            NodeError::Unit(format!("mutation registry is not UTF-8: {error}"))
        })?)
        .map_err(|error| NodeError::Unit(format!("invalid mutation registry: {error}")))?;
    let mutation = &registry.mutation;
    if !valid_npm_subject(&registry.subject)
        || mutation.id != unit.id
        || mutation.affected_claims != unit.claims
        || unit.expected_inventory != [mutation.id.as_str()]
        || !valid_digest(&mutation.target_preimage_sha256)
        || !valid_digest(&mutation.mutant_sha256)
        || !valid_digest(&mutation.witness_sha256)
    {
        return Err(NodeError::Unit(
            "mutation identity, subject, claims, inventory, or digests are invalid".to_owned(),
        ));
    }
    for path in [
        &mutation.target_path,
        &mutation.mutant_path,
        &mutation.witness_path,
    ] {
        validate_relative_path(path)?;
        if !unit.inputs.iter().any(|input| input == path) {
            return Err(NodeError::Unit(format!(
                "mutation path `{path}` must be byte-pinned in inputs"
            )));
        }
    }
    if !unit.inputs.iter().any(|input| input == &replay.registry) {
        return Err(NodeError::Unit(
            "mutation registry must be byte-pinned in inputs".to_owned(),
        ));
    }
    let witness = parse_node_id(&mutation.witness)?;
    if witness.file != mutation.witness_path {
        return Err(NodeError::Unit(
            "mutation witness_path must equal the vitest node file".to_owned(),
        ));
    }
    let target_bytes = read_safe_file(original_root, &mutation.target_path, MAX_JSON_BYTES)?;
    let mutant_bytes = read_safe_file(original_root, &mutation.mutant_path, MAX_JSON_BYTES)?;
    let witness_bytes = read_safe_file(original_root, &mutation.witness_path, MAX_JSON_BYTES)?;
    for (label, bytes, expected) in [
        (
            "target preimage",
            target_bytes.as_slice(),
            mutation.target_preimage_sha256.as_str(),
        ),
        (
            "mutant",
            mutant_bytes.as_slice(),
            mutation.mutant_sha256.as_str(),
        ),
        (
            "witness",
            witness_bytes.as_slice(),
            mutation.witness_sha256.as_str(),
        ),
    ] {
        if sha256_bytes(bytes) != expected {
            return Err(NodeError::Unit(format!(
                "{label} bytes do not match the registered digest"
            )));
        }
    }
    let before = snapshot_source_tree(&shadows[1].project)?;
    let mutant_target = resolve_existing(&shadows[1].project, &mutation.target_path)?;
    fs::write(&mutant_target, &mutant_bytes)?;
    if sha256_bytes(&fs::read(&mutant_target)?) != mutation.mutant_sha256 {
        return Err(NodeError::Internal(
            "mutant postimage verification failed".to_owned(),
        ));
    }
    let after = snapshot_source_tree(&shadows[1].project)?;
    verify_single_tree_change(
        &before,
        &after,
        &mutation.target_path,
        &mutation.mutant_sha256,
    )?;

    let mut environment = base_environment.clone();
    environment.insert("NPM_CONFIG_OFFLINE".to_owned(), "true".to_owned());
    let mut versions = Vec::new();
    let baseline_tool = resolve_local_tool(&shadows[0].project, "vitest")?;
    let mutant_tool = resolve_local_tool(&shadows[1].project, "vitest")?;
    let (baseline_shadows, mutant_shadows) = shadows.split_at_mut(1);
    for (shadow, tool) in [
        (&mut baseline_shadows[0], &baseline_tool),
        (&mut mutant_shadows[0], &mutant_tool),
    ] {
        let version = vitest_version(
            tool,
            &shadow.project,
            &environment,
            environment_observation,
            executor,
            deadline,
            specs,
            outputs,
        )?;
        discover_vitest(
            unit,
            shadow,
            tool,
            &environment,
            environment_observation,
            executor,
            deadline,
            specs,
            outputs,
            std::slice::from_ref(&witness),
        )?;
        versions.push(version);
    }
    if versions[0] != versions[1] {
        return Err(NodeError::Internal(
            "baseline and mutant vitest versions diverged".to_owned(),
        ));
    }
    let baseline_run_index = execute_vitest_node(
        unit,
        &shadows[0].project,
        &baseline_tool,
        &environment,
        environment_observation,
        executor,
        deadline,
        specs,
        outputs,
        &witness,
        true,
    )?;
    let expected_failure_index = execute_vitest_node(
        unit,
        &shadows[1].project,
        &mutant_tool,
        &environment,
        environment_observation,
        executor,
        deadline,
        specs,
        outputs,
        &witness,
        false,
    )?;
    let registry_artifact = artifact_from_bytes(&replay.registry, &registry_bytes);
    let target_preimage = artifact_from_bytes(&mutation.target_path, &target_bytes);
    let mutant_artifact = artifact_from_bytes(&mutation.mutant_path, &mutant_bytes);
    let target_postimage = artifact_from_bytes(&mutation.target_path, &mutant_bytes);
    let witness_source = artifact_from_bytes(&mutation.witness_path, &witness_bytes);
    Ok(RouteResult {
        inventory: vec![mutation.id.clone()],
        tool_version: format!("vitest {}", versions[0]),
        static_check: None,
        distribution: None,
        mutation: Some(MutationReplayObservation {
            schema: "proofbound-mutation-replay-observation/1".to_owned(),
            mutation_id: mutation.id.clone(),
            registry: registry_artifact,
            target_preimage,
            mutant_artifact,
            target_postimage: target_postimage.clone(),
            witness_source,
            check_id: mutation.witness.clone(),
            affected_claims: mutation.affected_claims.clone(),
            baseline_run_index,
            expected_failure: ExpectedFailureObservation {
                run_index: expected_failure_index,
                allowed_exit_codes: vec![1],
            },
        }),
        generated_artifacts: vec![target_postimage],
    })
}

fn verify_single_tree_change(
    before: &[(String, String)],
    after: &[(String, String)],
    target: &str,
    expected_digest: &str,
) -> Result<(), NodeError> {
    let before = before.iter().cloned().collect::<BTreeMap<_, _>>();
    let after = after.iter().cloned().collect::<BTreeMap<_, _>>();
    if before.keys().ne(after.keys()) {
        return Err(NodeError::ToolFailed(
            "mutation changed the source path inventory".to_owned(),
        ));
    }
    for (path, before_digest) in before {
        let after_digest = &after[&path];
        if path == target {
            if after_digest != expected_digest || after_digest == &before_digest {
                return Err(NodeError::ToolFailed(
                    "mutation target does not have the registered postimage".to_owned(),
                ));
            }
        } else if after_digest != &before_digest {
            return Err(NodeError::ToolFailed(format!(
                "mutation changed unregistered path `{path}`"
            )));
        }
    }
    Ok(())
}

fn valid_npm_subject(value: &str) -> bool {
    let Some(subject) = value.strip_prefix("npm:") else {
        return false;
    };
    let (package, export) = subject
        .split_once("::")
        .map_or((subject, None), |(package, export)| (package, Some(export)));
    let package_valid = !package.is_empty()
        && package.len() <= 214
        && package
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && package.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    package_valid
        && export.is_none_or(|export| {
            !export.is_empty()
                && export.split('.').all(|component| {
                    let mut bytes = component.bytes();
                    bytes.next().is_some_and(|byte| {
                        byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
                    }) && bytes
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
                })
        })
}

fn resolve_path_program(name: &str) -> Result<PathBuf, NodeError> {
    let path = std::env::var_os("PATH").ok_or_else(|| NodeError::ToolUnavailable {
        tool: name.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "PATH is unset"),
    })?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            let canonical = candidate.canonicalize()?;
            if canonical.is_file() {
                return Ok(canonical);
            }
        }
    }
    Err(NodeError::ToolUnavailable {
        tool: name.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found on PATH"),
    })
}

fn resolve_local_tool(root: &Path, name: &str) -> Result<PathBuf, NodeError> {
    let bin_root = root.join("node_modules/.bin");
    let candidate = bin_root.join(name);
    let metadata =
        fs::symlink_metadata(&candidate).map_err(|source| NodeError::ToolUnavailable {
            tool: format!("node_modules/.bin/{name}"),
            source,
        })?;
    if !metadata.file_type().is_symlink() && !metadata.is_file() {
        return Err(NodeError::UnsafePath(candidate.display().to_string()));
    }
    let canonical_root = root.join("node_modules").canonicalize()?;
    let canonical = candidate.canonicalize()?;
    if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
        return Err(NodeError::UnsafePath(candidate.display().to_string()));
    }
    Ok(canonical)
}

fn executable_identity(path: &Path) -> Result<String, NodeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(NodeError::UnsafePath(path.display().to_string()));
    }
    let bytes = fs::read(path)?;
    Ok(domain_hash(
        "proofbound-executable-identity/1",
        format!("{}\0{}", path.display(), sha256_bytes(&bytes)).as_bytes(),
    ))
}

fn repository_relative_tool_path(root: &Path, value: &str) -> Result<String, NodeError> {
    let path = Path::new(value);
    let canonical = if path.is_absolute() {
        path.canonicalize()
    } else {
        root.join(path).canonicalize()
    }
    .map_err(|_| NodeError::UnsafePath(value.to_owned()))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(NodeError::UnsafePath(value.to_owned()));
    }
    logical_path(root, &canonical)
}

fn resolve_existing(root: &Path, relative: &str) -> Result<PathBuf, NodeError> {
    validate_relative_path(relative)?;
    let candidate = root.join(relative);
    reject_symlink_components(root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .map_err(|_| NodeError::UnsafePath(relative.to_owned()))?;
    if !canonical.starts_with(root) {
        return Err(NodeError::UnsafePath(relative.to_owned()));
    }
    Ok(canonical)
}

fn reject_symlink_components(root: &Path, candidate: &Path) -> Result<(), NodeError> {
    let relative = candidate
        .strip_prefix(root)
        .map_err(|_| NodeError::UnsafePath(candidate.display().to_string()))?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(NodeError::UnsafePath(current.display().to_string()));
        }
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), NodeError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        || value.contains(['\\', '*', '?', '[', ']', '{', '}'])
        || value.contains("//")
        || value.ends_with('/')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value
            .split('/')
            .any(|component| component.is_empty() || component.starts_with('-'))
    {
        return Err(NodeError::UnsafePath(value.to_owned()));
    }
    Ok(())
}

fn read_safe_file(root: &Path, relative: &str, max: u64) -> Result<Vec<u8>, NodeError> {
    let path = resolve_existing(root, relative)?;
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() > max {
        return Err(NodeError::UnsafePath(relative.to_owned()));
    }
    Ok(fs::read(path)?)
}

fn collect_input_artifacts(
    root: &Path,
    inputs: &[String],
) -> Result<Vec<ArtifactObservation>, NodeError> {
    let mut artifacts = Vec::new();
    for input in inputs {
        let path = resolve_existing(root, input)?;
        if !path.is_file() {
            return Err(NodeError::Unsupported(format!(
                "Node input `{input}` must be an exact regular file"
            )));
        }
        let bytes = fs::read(path)?;
        artifacts.push(artifact_from_bytes(input, &bytes));
    }
    artifacts.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    Ok(artifacts)
}

fn artifact_from_bytes(logical_name: &str, bytes: &[u8]) -> ArtifactObservation {
    ArtifactObservation {
        logical_name: logical_name.to_owned(),
        sha256: sha256_bytes(bytes),
        size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
    }
}

fn require_exit(
    spec: &ProcessSpec,
    output: &ProcessOutput,
    expected: i32,
) -> Result<(), NodeError> {
    if output.truncated {
        return Err(NodeError::ToolFailed(format!(
            "{} output exceeded {MAX_OUTPUT_BYTES} bytes",
            spec.program.display()
        )));
    }
    if output.status != Some(expected) {
        return Err(NodeError::ToolFailed(format!(
            "{} {:?} exited {:?}, expected {expected}: {}",
            spec.program.display(),
            spec.args,
            output.status,
            first_diagnostic(output)
        )));
    }
    Ok(())
}

fn single_line_identity(output: &ProcessOutput) -> Result<String, NodeError> {
    let bytes = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    let text = std::str::from_utf8(bytes)
        .map_err(|error| NodeError::Inventory(format!("identity is not UTF-8: {error}")))?
        .trim_end_matches(['\r', '\n']);
    if text.is_empty()
        || text.len() > 2048
        || text.contains(['\r', '\n'])
        || text.trim() != text
        || text.chars().any(char::is_control)
    {
        return Err(NodeError::Inventory(
            "tool identity must be one bounded unpadded line".to_owned(),
        ));
    }
    Ok(text.to_owned())
}

fn first_diagnostic(output: &ProcessOutput) -> String {
    let bytes = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("no diagnostic")
        .chars()
        .take(2048)
        .collect()
}

fn observe_environment(environment: &BTreeMap<String, String>) -> Vec<EnvironmentObservation> {
    environment
        .iter()
        .map(|(name, value)| EnvironmentObservation {
            name: name.clone(),
            value_sha256: Some(domain_hash(
                "proofbound-environment-value/1",
                value.as_bytes(),
            )),
            secret: is_secret_name(name),
        })
        .collect()
}

fn observe_command(
    spec: &ProcessSpec,
    root: &Path,
    shadows: &[Shadow],
    environment: &[EnvironmentObservation],
) -> CommandObservation {
    let logicalize = |value: &str| logicalize_value(value, root, shadows);
    CommandObservation {
        program: logicalize(&spec.program.to_string_lossy()),
        args: spec
            .args
            .iter()
            .map(|argument| logicalize(argument))
            .collect(),
        environment_allowlist: environment.to_vec(),
    }
}

fn observe_runs(outputs: &[ProcessOutput], root: &Path, shadows: &[Shadow]) -> Vec<RunObservation> {
    outputs
        .iter()
        .enumerate()
        .map(|(command_index, output)| {
            let mut normalized = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
            normalized.push('\n');
            normalized.push_str(&String::from_utf8_lossy(&output.stderr).replace("\r\n", "\n"));
            let normalized = logicalize_value(&normalized, root, shadows);
            RunObservation {
                command_index,
                exit_code: output.status,
                stdout_sha256: sha256_bytes(&output.stdout),
                stderr_sha256: sha256_bytes(&output.stderr),
                normalized_output_sha256: domain_hash(
                    "proofbound-normalized-tool-output/1",
                    normalized.as_bytes(),
                ),
                output_truncated: output.truncated,
                duration_ms: output.duration_ms,
            }
        })
        .collect()
}

fn logicalize_value(value: &str, root: &Path, shadows: &[Shadow]) -> String {
    let mut result = value.replace(&root.to_string_lossy().to_string(), "$PROJECT");
    for shadow in shadows {
        result = result
            .replace(&shadow.project.to_string_lossy().to_string(), "$PROJECT")
            .replace(
                &shadow.base.path().to_string_lossy().to_string(),
                "$PROOFBOUND_WORK",
            );
    }
    result
}

fn adapter_identity() -> ToolObservation {
    let version = env!("CARGO_PKG_VERSION").to_owned();
    ToolObservation {
        name: "proofbound-adapter-node".to_owned(),
        identity_sha256: domain_hash(
            "proofbound-adapter-identity/1",
            format!("proofbound-adapter-node\0{version}").as_bytes(),
        ),
        version,
    }
}

fn evidence_kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::ExampleTest => "example-test",
        EvidenceKind::PropertyTest => "property-test",
        EvidenceKind::MutationWitness => "mutation-witness",
        EvidenceKind::StaticCheck => "static-check",
        _ => "unsupported",
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && !value.contains(['/', '\\'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value.ends_with(".tgz")
}

fn logical_path(root: &Path, path: &Path) -> Result<String, NodeError> {
    path.strip_prefix(root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|_| NodeError::UnsafePath(path.display().to_string()))
}

fn directory_size(root: &Path) -> Result<u64, NodeError> {
    let mut total = 0_u64;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(walk_error)?;
        if entry.file_type().is_file() {
            total = total
                .checked_add(entry.metadata().map_err(walk_error)?.len())
                .ok_or_else(|| NodeError::Budget("directory size overflowed".to_owned()))?;
        }
    }
    Ok(total)
}

fn walk_error(error: walkdir::Error) -> NodeError {
    NodeError::Io(
        error.into_io_error().unwrap_or_else(|| {
            std::io::Error::other("walk failed without an underlying I/O error")
        }),
    )
}

fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "PRIVATE",
        "AUTH",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn unix_ms() -> Result<u64, NodeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| NodeError::Internal(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| NodeError::Internal("wall clock overflowed".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    fn write_node_metadata(root: &Path, dependency: &str, integrity: Option<&str>) {
        fs::write(
            root.join("package.json"),
            format!(
                "{{\"name\":\"fixture\",\"version\":\"1.0.0\",\"devDependencies\":{{\"vitest\":{dependency:?}}}}}"
            ),
        )
        .unwrap();
        let mut locked_dependency = serde_json::json!({"version": "2.1.0"});
        if let Some(integrity) = integrity {
            locked_dependency["integrity"] = Value::String(integrity.to_owned());
        }
        fs::write(
            root.join("package-lock.json"),
            serde_json::to_vec(&serde_json::json!({
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/vitest": locked_dependency}
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn node_unit(operation: &str, kind: &str, schema: &str) -> EvidenceUnitManifest {
        serde_json::from_value(serde_json::json!({
            "schema": schema,
            "id": "node-route",
            "adapter": "node-test",
            "kind": kind,
            "claims": ["CLAIM-001"],
            "tier": 0,
            "operation": {
                "type": operation,
                "package": null,
                "targets": [],
                "paths": [],
                "manifest": null,
                "inventory": null,
                "checker": null,
                "configuration": null,
                "plugins": [],
                "arguments": []
            },
            "evaluation_mode": null,
            "binding_mode": null,
            "theorem": null,
            "refinement_theorem": null,
            "premises": [],
            "assumptions": [],
            "expected_inventory": ["src/example.test.ts::rejects trailing bytes"],
            "inputs": ["package-lock.json", "package.json", "src/example.test.ts"],
            "outputs": [],
            "environment_allowlist": ["PATH"],
            "bounded_domain": null,
            "transcription": null,
            "mutation": null,
            "property": null,
            "distribution": null,
            "resource_budget": {
                "time_seconds": 60,
                "disk_bytes": 10000000,
                "memory_bytes": 10000000
            }
        }))
        .unwrap()
    }

    #[test]
    fn typed_routes_reject_reserved_and_untyped_shapes() {
        let vitest = node_unit("vitest", "example-test", "proofbound-evidence-unit/1");
        assert_eq!(validate_unit(&vitest).unwrap(), Route::Vitest);

        let mut tsc = node_unit("tsc", "static-check", "proofbound-evidence-unit/1");
        tsc.operation.configuration = Some("tsconfig.json".to_owned());
        tsc.inputs.push("tsconfig.json".to_owned());
        tsc.inputs.sort();
        tsc.expected_inventory = vec!["src/example.ts".to_owned()];
        assert_eq!(validate_unit(&tsc).unwrap(), Route::Tsc);

        let mut reserved = tsc;
        reserved.operation.kind = OperationKind::Tsgo;
        assert!(matches!(
            validate_unit(&reserved),
            Err(NodeError::Unsupported(message)) if message.contains("reserved")
        ));
    }

    #[test]
    fn node_ids_are_literal_bounded_values() {
        assert_eq!(
            parse_node_id("src/a.test.ts::suite > handles [brackets]")
                .unwrap()
                .name,
            "suite > handles [brackets]"
        );
        assert!(parse_node_id("src/a.test.ts::-reporter=evil").is_err());
        assert!(parse_node_id("../a.test.ts::test").is_err());
        assert_eq!(regex_escape("a.*[b]?"), "a\\.\\*\\[b\\]\\?");
    }

    #[test]
    fn current_vitest_identity_is_parsed_without_weakening_the_floor() {
        assert_eq!(
            parse_vitest_version("vitest/3.2.4 darwin-arm64 node-v22.22.2").unwrap(),
            Version::new(3, 2, 4)
        );
        assert!(parse_vitest_version("vitest unknown").is_err());
    }

    #[test]
    fn tsc_configuration_requires_literal_strict_json() {
        validate_tsc_configuration(br#"{"compilerOptions":{"strict":true}}"#).unwrap();
        for invalid in [
            br#"{"compilerOptions":{"strict":false}}"#.as_slice(),
            br#"{"compilerOptions":{"strict":true},"extends":"./base.json"}"#.as_slice(),
            br#"{"compilerOptions":{"strict":true},}"#.as_slice(),
        ] {
            assert!(matches!(
                validate_tsc_configuration(invalid),
                Err(NodeError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn lockfile_validation_requires_integrity_and_rejects_local_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let unit = node_unit("vitest", "example-test", "proofbound-evidence-unit/1");
        write_node_metadata(&root, "2.1.0", Some("sha512-Zml4dHVyZQ=="));
        validate_node_metadata(&root, &unit).unwrap();

        write_node_metadata(&root, "2.1.0", None);
        assert!(matches!(
            validate_node_metadata(&root, &unit),
            Err(NodeError::Unsupported(message)) if message.contains("integrity")
        ));

        write_node_metadata(&root, "file:../vitest", Some("sha512-Zml4dHVyZQ=="));
        assert!(matches!(
            validate_node_metadata(&root, &unit),
            Err(NodeError::Unsupported(message)) if message.contains("unsupported dependency")
        ));

        let packages =
            serde_json::from_value::<serde_json::Map<String, Value>>(serde_json::json!({
                "node_modules/npm": {"integrity": "sha512-parent"},
                "node_modules/npm/node_modules/child": {"inBundle": true}
            }))
            .unwrap();
        let child = packages["node_modules/npm/node_modules/child"]
            .as_object()
            .unwrap();
        assert!(bundled_entry_is_bound(
            "node_modules/npm/node_modules/child",
            child,
            &packages
        ));
    }

    #[test]
    fn tarball_members_must_be_regular_reviewed_source_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/index.ts"), b"export const value = 7;\n").unwrap();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(24);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                "package/src/index.ts",
                &b"export const value = 7;\n"[..],
            )
            .unwrap();
        let encoder = archive.into_inner().unwrap();
        let tarball = encoder.finish().unwrap();
        assert_eq!(
            inspect_tarball(&tarball, &root, 1024).unwrap(),
            ["src/index.ts"]
        );

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../../escape").unwrap();
        header.set_cksum();
        archive
            .append_data(&mut header, "package/src/link", std::io::empty())
            .unwrap();
        let tarball = archive.into_inner().unwrap().finish().unwrap();
        assert!(matches!(
            inspect_tarball(&tarball, &root, 1024),
            Err(NodeError::Unsupported(message)) if message.contains("not a regular file")
        ));
    }

    #[test]
    fn vitest_report_requires_exactly_the_registered_assertion() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("src")).unwrap();
        let file = root.join("src/a.test.ts");
        fs::write(&file, b"test\n").unwrap();
        let expected = VitestNode {
            file: "src/a.test.ts".to_owned(),
            name: "suite > exact".to_owned(),
        };
        let report = serde_json::json!({
            "numTotalTests": 1,
            "numPassedTests": 1,
            "numFailedTests": 0,
            "testResults": [{
                "name": file,
                "assertionResults": [{
                    "ancestorTitles": ["suite"],
                    "fullName": "suite exact",
                    "status": "passed",
                    "title": "exact"
                }]
            }]
        });
        let output = ProcessOutput {
            status: Some(0),
            stdout: serde_json::to_vec(&report).unwrap(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        };
        validate_vitest_report(&output, &root, &expected, true).unwrap();
        let mut filtered = report.clone();
        filtered["numTotalTests"] = serde_json::json!(2);
        filtered["numPendingTests"] = serde_json::json!(1);
        filtered["testResults"][0]["assertionResults"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "ancestorTitles": ["suite"],
                "fullName": "suite other",
                "status": "skipped",
                "title": "other"
            }));
        let filtered_output = ProcessOutput {
            stdout: serde_json::to_vec(&filtered).unwrap(),
            ..output.clone()
        };
        validate_vitest_report(&filtered_output, &root, &expected, true).unwrap();
        filtered["testResults"][0]["assertionResults"][1]["status"] = serde_json::json!("passed");
        let unselected_output = ProcessOutput {
            stdout: serde_json::to_vec(&filtered).unwrap(),
            ..output.clone()
        };
        assert!(validate_vitest_report(&unselected_output, &root, &expected, true).is_err());
        let mut extra = report;
        extra["numTotalTests"] = serde_json::json!(2);
        let output = ProcessOutput {
            stdout: serde_json::to_vec(&extra).unwrap(),
            ..output
        };
        assert!(validate_vitest_report(&output, &root, &expected, true).is_err());
    }

    struct RecordingExecutor {
        args: Vec<Vec<String>>,
    }

    impl Executor for RecordingExecutor {
        fn run(
            &mut self,
            spec: &ProcessSpec,
            _cwd: &Path,
            _environment: &BTreeMap<String, String>,
            _timeout: Duration,
        ) -> Result<ProcessOutput, NodeError> {
            self.args.push(spec.args.clone());
            Ok(ProcessOutput {
                status: Some(0),
                stdout: b"10.9.0\n".to_vec(),
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            })
        }
    }

    #[test]
    fn installation_never_enables_lifecycle_scripts() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("package.json"), b"{}\n").unwrap();
        let shadow = Shadow::new(temp.path(), 1024 * 1024).unwrap();
        let mut executor = RecordingExecutor { args: Vec::new() };
        let deadline = Deadline {
            started: Instant::now(),
            budget_ms: 10_000,
        };
        install_dependencies(
            &shadow,
            Path::new("/usr/bin/npm"),
            &BTreeMap::new(),
            &[],
            &mut executor,
            deadline,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            executor.args,
            [
                vec!["--version"],
                vec!["ci", "--ignore-scripts", "--no-audit", "--no-fund"]
            ]
        );
    }
}
