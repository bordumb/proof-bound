//! Manifest-driven Kani adapter.
//!
//! The adapter accepts exactly one canonical `proofbound-adapter-protocol/1`
//! request on stdin and writes exactly one canonical response on stdout.  It
//! never interprets a shell string: every process is a fixed program plus a
//! validated argument vector derived from the supplied evidence/model-check
//! manifests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use proofbound_manifest::{
    AdapterDiagnostic, AdapterKind, AdapterRequest, AdapterResponse, EvidenceKind,
    EvidenceUnitManifest, ModelCheckUnitManifest, OperationKind,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

pub const PROTOCOL_SCHEMA: &str = "proofbound-adapter-protocol/1";
pub const OBSERVATION_SCHEMA: &str = "proofbound-adapter-observation/2";
pub const ADAPTER_ID: &str = "kani";
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INVENTORY: usize = 100_000;

/// Common adapter observation envelope.  The test and Aeneas adapters use the
/// same field-for-field shape so the orchestrator can add claim provenance and
/// construct a full `proofbound_core::EvidenceRecord` without guessing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterObservation {
    pub schema: String,
    pub unit_id: String,
    pub evidence_kind: String,
    pub outcome: ObservationOutcome,
    pub input_artifacts: Vec<ArtifactObservation>,
    pub generated_artifacts: Vec<ArtifactObservation>,
    pub tool: ToolObservation,
    pub adapter: ToolObservation,
    pub commands: Vec<CommandObservation>,
    pub runs: Vec<RunObservation>,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub deterministic_result_sha256: String,
    pub unit_configuration_sha256: String,
    pub resource_budget: BudgetObservation,
    pub resource_usage: UsageObservation,
    pub inventory: Vec<String>,
    pub normalization: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationOutcome {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactObservation {
    pub logical_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObservation {
    pub name: String,
    pub version: String,
    pub identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandObservation {
    pub program: String,
    pub args: Vec<String>,
    pub environment_allowlist: Vec<EnvironmentObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentObservation {
    pub name: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub value_sha256: Option<String>,
    pub secret: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservation {
    pub command_index: usize,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub normalized_output_sha256: String,
    pub output_truncated: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetObservation {
    pub time_ms: u64,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsageObservation {
    pub time_ms: u64,
    pub peak_disk_bytes: u64,
    /// `None` is explicit: portable process-tree RSS metering is not available
    /// from `std`.  The declared memory limit is still recorded for an outer
    /// sandbox/cgroup to enforce; adapters never invent a zero measurement.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub peak_memory_bytes: Option<u64>,
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug)]
struct ProcessSpec {
    program: String,
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

trait Executor {
    fn run(
        &mut self,
        spec: &ProcessSpec,
        cwd: &Path,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<ProcessOutput, AdapterError>;
}

struct RealExecutor;

impl Executor for RealExecutor {
    fn run(
        &mut self,
        spec: &ProcessSpec,
        cwd: &Path,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<ProcessOutput, AdapterError> {
        let started = Instant::now();
        let executable =
            resolve_executable(&spec.program).map_err(|source| AdapterError::ToolUnavailable {
                program: spec.program.clone(),
                source,
            })?;
        let mut command = Command::new(executable);
        command
            .args(&spec.args)
            .current_dir(cwd)
            .env_clear()
            .envs(environment)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env("TERM", "dumb")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|source| AdapterError::ToolUnavailable {
                program: spec.program.clone(),
                source,
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdapterError::Internal("child stdout was not piped".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AdapterError::Internal("child stderr was not piped".to_owned()))?;
        let stdout_thread = thread::spawn(move || drain_bounded(stdout));
        let stderr_thread = thread::spawn(move || drain_bounded(stderr));

        let exit_status: ExitStatus = loop {
            if let Some(status) = child.try_wait().map_err(AdapterError::Io)? {
                break status;
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(AdapterError::Timeout(
                    timeout.as_millis().try_into().unwrap_or(u64::MAX),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_truncated) = stdout_thread
            .join()
            .map_err(|_| AdapterError::Internal("stdout reader panicked".to_owned()))??;
        let (stderr, stderr_truncated) = stderr_thread
            .join()
            .map_err(|_| AdapterError::Internal("stderr reader panicked".to_owned()))??;
        Ok(ProcessOutput {
            status: exit_status.code(),
            stdout,
            stderr,
            truncated: stdout_truncated || stderr_truncated,
            duration_ms: elapsed_ms(started),
        })
    }
}

fn resolve_executable(program: &str) -> std::io::Result<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() || path.components().count() > 1 {
        return if path.is_file() {
            Ok(path.to_path_buf())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{program} is not a file"),
            ))
        };
    }
    let search = std::env::var_os("PATH")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "parent PATH is unset"))?;
    std::env::split_paths(&search)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{program} was not found on parent PATH"),
            )
        })
}

fn drain_bounded<R: Read>(mut reader: R) -> Result<(Vec<u8>, bool), AdapterError> {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(AdapterError::Io)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_TOOL_OUTPUT_BYTES.saturating_sub(kept.len());
        let take = remaining.min(count);
        kept.extend_from_slice(&buffer[..take]);
        truncated |= take < count;
    }
    Ok((kept, truncated))
}

#[derive(Debug, Error)]
enum AdapterError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tool `{program}` is unavailable: {source}")]
    ToolUnavailable {
        program: String,
        source: std::io::Error,
    },
    #[error("tool exceeded its {0} ms time budget")]
    Timeout(u64),
    #[error("invalid request: {0}")]
    Request(String),
    #[error("invalid unit: {0}")]
    Unit(String),
    #[error("unsafe path `{0}`")]
    UnsafePath(String),
    #[error("tool output was invalid: {0}")]
    ToolOutput(String),
    #[error("tool failed: {0}")]
    ToolFailed(String),
    #[error("resource budget exceeded: {0}")]
    Budget(String),
    #[error("internal adapter error: {0}")]
    Internal(String),
}

impl AdapterError {
    fn diagnostic(&self) -> AdapterDiagnostic {
        let (code, remediation) = match self {
            Self::ToolUnavailable { .. } => (
                "PB-KANI-1001",
                "install the pinned Kani toolchain and ensure `cargo` is on the allowed PATH",
            ),
            Self::Timeout(_) | Self::Budget(_) => (
                "PB-KANI-1002",
                "increase the unit budget only after review, or reduce the bounded workload",
            ),
            Self::Request(_) => (
                "PB-KANI-1003",
                "send canonical proofbound-adapter-protocol/1 JSON with no unknown fields",
            ),
            Self::Unit(_) => (
                "PB-KANI-1004",
                "make the evidence unit and referenced model-check manifest agree exactly",
            ),
            Self::UnsafePath(_) => (
                "PB-KANI-1005",
                "use a relative, non-symlink path contained by the project root",
            ),
            Self::ToolOutput(_) => (
                "PB-KANI-1006",
                "use the pinned supported Kani metadata format and inspect the complete tool output",
            ),
            Self::ToolFailed(_) => (
                "PB-KANI-1007",
                "reproduce the typed Kani invocation and fix the failing harness",
            ),
            Self::Io(_) | Self::Internal(_) => (
                "PB-KANI-1099",
                "inspect the adapter diagnostic and retry from a clean checkout",
            ),
        };
        AdapterDiagnostic {
            code: code.to_owned(),
            message: truncate_message(&self.to_string()),
            path: match self {
                Self::UnsafePath(path) => Some(path.clone()),
                _ => None,
            },
            remediation: Some(remediation.to_owned()),
        }
    }
}

pub fn handle_request_bytes(input: &[u8]) -> AdapterResponse {
    let fallback = fallback_response();
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return failed_response(
            fallback,
            AdapterError::Request("request exceeds 2 MiB".to_owned()),
        );
    }
    let request: AdapterRequest = match serde_json::from_slice(input) {
        Ok(request) => request,
        Err(error) => return failed_response(fallback, AdapterError::Request(error.to_string())),
    };
    let response_base = AdapterResponse {
        schema: PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: request.request_id.clone(),
        adapter: ADAPTER_ID.to_owned(),
        success: false,
        evidence: None,
        inventory: Vec::new(),
        diagnostics: Vec::new(),
    };
    if let Err(error) = validate_request(&request, input) {
        return failed_response(response_base, error);
    }
    let mut executor = RealExecutor;
    match execute_request(&request, Path::new("."), &mut executor) {
        Ok((observation, inventory)) => AdapterResponse {
            success: true,
            evidence: observation
                .map(|value| serde_json::to_value(value).expect("observation is serializable")),
            inventory,
            ..response_base
        },
        Err(error) => failed_response(response_base, error),
    }
}

fn fallback_response() -> AdapterResponse {
    AdapterResponse {
        schema: PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: "00000000000000000000000000000000".to_owned(),
        adapter: ADAPTER_ID.to_owned(),
        success: false,
        evidence: None,
        inventory: Vec::new(),
        diagnostics: Vec::new(),
    }
}

fn failed_response(mut response: AdapterResponse, error: AdapterError) -> AdapterResponse {
    response.success = false;
    response.evidence = None;
    response.inventory.clear();
    response.diagnostics = vec![error.diagnostic()];
    response
}

fn validate_request(request: &AdapterRequest, original: &[u8]) -> Result<(), AdapterError> {
    if request.schema != PROTOCOL_SCHEMA
        || request.message_type != "request"
        || request.adapter != ADAPTER_ID
        || request.project_root != "."
    {
        return Err(AdapterError::Request(
            "protocol constants do not match the Kani adapter".to_owned(),
        ));
    }
    if request.request_id.len() != 32
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AdapterError::Request(
            "request_id must be exactly 32 lowercase hexadecimal characters".to_owned(),
        ));
    }
    if !matches!(
        request.operation.as_str(),
        "doctor" | "inventory" | "check" | "reproduce" | "update"
    ) {
        return Err(AdapterError::Request("unsupported operation".to_owned()));
    }
    let canonical =
        canonical_json(request).map_err(|error| AdapterError::Request(error.to_string()))?;
    if canonical != original {
        return Err(AdapterError::Request(
            "request JSON is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn execute_request<E: Executor>(
    request: &AdapterRequest,
    project_root: &Path,
    executor: &mut E,
) -> Result<(Option<AdapterObservation>, Vec<String>), AdapterError> {
    if request.operation == "update" {
        return Err(AdapterError::Request(
            "Kani has no committed generated artifacts; update is unsupported".to_owned(),
        ));
    }
    let root = project_root.canonicalize().map_err(AdapterError::Io)?;
    let evidence: EvidenceUnitManifest = serde_json::from_value(request.unit.clone())
        .map_err(|error| AdapterError::Unit(error.to_string()))?;
    validate_evidence_unit(&evidence)?;
    let model_path = evidence.operation.manifest.as_deref().ok_or_else(|| {
        AdapterError::Unit("Kani operation requires a model-check manifest path".to_owned())
    })?;
    let model_bytes = read_safe_file(&root, model_path, MAX_REQUEST_BYTES)?;
    let model: ModelCheckUnitManifest = toml::from_str(
        std::str::from_utf8(&model_bytes).map_err(|error| AdapterError::Unit(error.to_string()))?,
    )
    .map_err(|error| AdapterError::Unit(error.to_string()))?;
    validate_model_unit(&evidence, &model)?;

    let mut environment = allowed_environment(&evidence.environment_allowlist)?;
    if let Some(path) = std::env::var_os("PATH") {
        environment
            .entry("PATH".to_owned())
            .or_insert_with(|| path.to_string_lossy().into_owned());
    }
    environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    environment.insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
    environment.insert("TERM".to_owned(), "dumb".to_owned());
    let environment_observation = environment_observation(&environment);
    let budget = BudgetObservation {
        time_ms: model.resource_budget.time_seconds.saturating_mul(1000),
        disk_bytes: model.resource_budget.disk_bytes,
        memory_bytes: model.resource_budget.memory_bytes,
    };

    let started_unix_ms = unix_ms()?;
    let started = Instant::now();
    let version_spec = ProcessSpec {
        program: "cargo".to_owned(),
        args: vec!["kani".to_owned(), "--version".to_owned()],
    };
    let version_output = executor.run(
        &version_spec,
        &root,
        &environment,
        Duration::from_millis(budget.time_ms.min(20_000)),
    )?;
    ensure_success(&version_spec, &version_output)?;
    let version = parse_version(&version_output.stdout, &version_output.stderr)?;
    let tool = ToolObservation {
        name: "Kani Rust Verifier".to_owned(),
        identity_sha256: domain_hash("proofbound-tool-identity/1", version.as_bytes()),
        version,
    };
    if request.operation == "doctor" {
        return Ok((None, Vec::new()));
    }

    let shadow = shadow_project(&root, budget.disk_bytes)?;
    let shadow_root = shadow.path().join("project").canonicalize()?;

    let metadata_spec = ProcessSpec {
        program: "cargo".to_owned(),
        args: vec![
            "metadata".to_owned(),
            "--format-version".to_owned(),
            "1".to_owned(),
            "--no-deps".to_owned(),
        ],
    };
    let remaining = remaining_time(started, budget.time_ms)?;
    let metadata_output = executor.run(&metadata_spec, &shadow_root, &environment, remaining)?;
    ensure_success(&metadata_spec, &metadata_output)?;
    let package_dir = package_directory(&metadata_output.stdout, &model.package, &shadow_root)?;

    let inventory_spec = ProcessSpec {
        program: "cargo".to_owned(),
        args: vec![
            "kani".to_owned(),
            "list".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ],
    };
    let metadata_file = package_dir.join("kani-list.json");
    require_absent_inventory_output(&metadata_file)?;
    let remaining = remaining_time(started, budget.time_ms)?;
    let inventory_output = executor.run(&inventory_spec, &package_dir, &environment, remaining)?;
    ensure_success(&inventory_spec, &inventory_output)?;
    if inventory_output.truncated {
        return Err(AdapterError::ToolOutput(
            "Kani inventory output exceeded 8 MiB".to_owned(),
        ));
    }
    let metadata_bytes = read_fresh_inventory_output(&metadata_file, &package_dir)?;
    let (inventory, metadata_version) = parse_kani_inventory(&metadata_bytes)?;
    if metadata_version != tool.version {
        return Err(AdapterError::ToolOutput(format!(
            "Kani version metadata `{metadata_version}` differs from executable `{}`",
            tool.version
        )));
    }
    exact_inventory(&model.harnesses, &inventory)?;

    let check_spec = ProcessSpec {
        program: "cargo".to_owned(),
        args: build_check_args(&model, shadow.path()),
    };
    let mut commands = vec![
        observe_command(&version_spec, &environment_observation),
        observe_command(&metadata_spec, &environment_observation),
        observe_command(&inventory_spec, &environment_observation),
    ];
    let mut outputs = vec![version_output, metadata_output, inventory_output];
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        let remaining = remaining_time(started, budget.time_ms)?;
        let output = executor.run(&check_spec, &package_dir, &environment, remaining)?;
        ensure_success(&check_spec, &output)?;
        if output.truncated {
            return Err(AdapterError::ToolOutput(
                "Kani verification output exceeded 8 MiB".to_owned(),
            ));
        }
        commands.push(observe_command(&check_spec, &environment_observation));
        outputs.push(output);
    }
    let disk_bytes = directory_size(shadow.path())?;
    if disk_bytes > budget.disk_bytes {
        return Err(AdapterError::Budget(format!(
            "shadow execution used {disk_bytes} disk bytes, limit is {}",
            budget.disk_bytes
        )));
    }
    if outputs.iter().any(|output| output.status != Some(0)) {
        return Err(AdapterError::Internal(
            "successful observation contains a non-zero or missing process exit status".to_owned(),
        ));
    }
    let runs = observe_runs(&outputs, &shadow_root, &root);
    let input_artifacts = collect_input_artifacts(&root, &evidence.inputs)?;
    let unit_bytes =
        canonical_json(&request.unit).map_err(|error| AdapterError::Internal(error.to_string()))?;
    let result_value = serde_json::json!({
        "inventory": inventory,
        "run_hashes": runs.iter().map(|run| run.normalized_output_sha256.clone()).collect::<Vec<_>>(),
    });
    let deterministic_result_sha256 = domain_hash(
        "proofbound-adapter-result/1",
        &canonical_json(&result_value)
            .map_err(|error| AdapterError::Internal(error.to_string()))?,
    );
    let completed_unix_ms = unix_ms()?;
    let observation = AdapterObservation {
        schema: OBSERVATION_SCHEMA.to_owned(),
        unit_id: evidence.id,
        evidence_kind: "bounded-check".to_owned(),
        outcome: ObservationOutcome::Passed,
        input_artifacts,
        generated_artifacts: Vec::new(),
        tool,
        adapter: adapter_identity(),
        commands,
        runs,
        started_unix_ms,
        completed_unix_ms,
        deterministic_result_sha256,
        unit_configuration_sha256: domain_hash("proofbound-unit-configuration/1", &unit_bytes),
        resource_budget: budget,
        resource_usage: UsageObservation {
            time_ms: elapsed_ms(started),
            peak_disk_bytes: disk_bytes,
            peak_memory_bytes: None,
        },
        inventory: inventory.clone(),
        normalization: "stable-tool-output/1".to_owned(),
    };
    let evidence = (request.operation != "inventory").then_some(observation);
    Ok((evidence, inventory))
}

fn validate_evidence_unit(unit: &EvidenceUnitManifest) -> Result<(), AdapterError> {
    if unit.schema != "proofbound-evidence-unit/1"
        || unit.adapter != AdapterKind::Kani
        || unit.operation.kind != OperationKind::Kani
        || unit.kind != EvidenceKind::BoundedCheck
    {
        return Err(AdapterError::Unit(
            "expected a proofbound-evidence-unit/1 bounded-check Kani operation".to_owned(),
        ));
    }
    require_unique("claims", &unit.claims)?;
    require_unique("expected_inventory", &unit.expected_inventory)?;
    require_unique("operation.targets", &unit.operation.targets)?;
    require_unique("inputs", &unit.inputs)?;
    require_unique("environment_allowlist", &unit.environment_allowlist)?;
    if unit.resource_budget.time_seconds == 0
        || unit.resource_budget.disk_bytes == 0
        || unit.resource_budget.memory_bytes == 0
    {
        return Err(AdapterError::Unit(
            "resource budgets must all be non-zero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_model_unit(
    evidence: &EvidenceUnitManifest,
    model: &ModelCheckUnitManifest,
) -> Result<(), AdapterError> {
    if model.schema != "proofbound-model-check-unit/1" || model.adapter != ADAPTER_ID {
        return Err(AdapterError::Unit(
            "referenced manifest is not a Kani model-check unit".to_owned(),
        ));
    }
    require_unique("model harnesses", &model.harnesses)?;
    require_unique("model claims", &model.claims)?;
    if model.harnesses.is_empty() || model.claims.is_empty() {
        return Err(AdapterError::Unit(
            "model-check unit requires at least one harness and claim".to_owned(),
        ));
    }
    if evidence.id != model.id
        || evidence.operation.package.as_deref() != Some(model.package.as_str())
        || evidence.operation.targets != model.harnesses
        || evidence.expected_inventory != model.harnesses
        || evidence.claims != model.claims
        || evidence.resource_budget != model.resource_budget
        || evidence.bounded_domain.as_ref() != Some(&model.domain)
    {
        return Err(AdapterError::Unit("evidence and model-check manifests disagree on id, package, harnesses, claims, domain, or budget".to_owned()));
    }
    if model.unwind == 0
        || model.solver.trim().is_empty()
        || !safe_atom(&model.package)
        || !safe_atom(&model.solver)
    {
        return Err(AdapterError::Unit(
            "package, solver, and unwind are invalid".to_owned(),
        ));
    }
    for harness in &model.harnesses {
        if !safe_symbol(harness) {
            return Err(AdapterError::Unit(format!(
                "invalid harness name `{harness}`"
            )));
        }
    }
    Ok(())
}

fn build_check_args(model: &ModelCheckUnitManifest, run_root: &Path) -> Vec<String> {
    let mut args = vec![
        "kani".to_owned(),
        "--package".to_owned(),
        model.package.clone(),
        "--exact".to_owned(),
    ];
    for harness in &model.harnesses {
        args.push("--harness".to_owned());
        args.push(harness.clone());
    }
    args.extend([
        "--solver".to_owned(),
        model.solver.clone(),
        "--unwind".to_owned(),
        model.unwind.to_string(),
        "--target-dir".to_owned(),
        run_root.join("kani-target").to_string_lossy().into_owned(),
    ]);
    args
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KaniList {
    #[serde(rename = "kani-version")]
    kani_version: String,
    #[serde(rename = "file-version")]
    file_version: String,
    #[serde(
        rename = "standard-harnesses",
        deserialize_with = "deserialize_unique_harness_map"
    )]
    standard_harnesses: BTreeMap<String, Vec<String>>,
    #[serde(rename = "contract-harnesses")]
    contract_harnesses: BTreeMap<String, Vec<String>>,
    contracts: Vec<Value>,
    totals: KaniTotals,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KaniTotals {
    #[serde(rename = "standard-harnesses")]
    standard_harnesses: usize,
    #[serde(rename = "contract-harnesses")]
    contract_harnesses: usize,
    #[serde(rename = "functions-under-contract")]
    functions_under_contract: usize,
}

fn deserialize_unique_harness_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueHarnessMap;

    impl<'de> Visitor<'de> for UniqueHarnessMap {
        type Value = BTreeMap<String, Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a standard-harnesses object with unique source keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut harnesses = BTreeMap::new();
            while let Some((source, entries)) = map.next_entry::<String, Vec<String>>()? {
                if harnesses.insert(source.clone(), entries).is_some() {
                    return Err(de::Error::custom(format!(
                        "duplicate standard-harnesses source key `{source}`"
                    )));
                }
            }
            Ok(harnesses)
        }
    }

    deserializer.deserialize_map(UniqueHarnessMap)
}

fn parse_kani_inventory(bytes: &[u8]) -> Result<(Vec<String>, String), AdapterError> {
    if bytes.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(AdapterError::ToolOutput(
            "kani-list.json exceeds 8 MiB".to_owned(),
        ));
    }
    let list: KaniList = serde_json::from_slice(bytes)
        .map_err(|error| AdapterError::ToolOutput(error.to_string()))?;
    if list.file_version != "0.1" {
        return Err(AdapterError::ToolOutput(format!(
            "unsupported Kani list file version `{}`",
            list.file_version
        )));
    }
    if !list.contract_harnesses.is_empty()
        || !list.contracts.is_empty()
        || list.totals.contract_harnesses != 0
        || list.totals.functions_under_contract != 0
    {
        return Err(AdapterError::ToolOutput(
            "contract harnesses are outside the initial adapter profile".to_owned(),
        ));
    }
    let mut inventory = Vec::new();
    for (source, harnesses) in list.standard_harnesses {
        validate_metadata_path(&source)?;
        inventory.extend(harnesses);
    }
    inventory.sort();
    if inventory.len() != list.totals.standard_harnesses {
        return Err(AdapterError::ToolOutput(
            "Kani metadata totals do not match its harness list".to_owned(),
        ));
    }
    if inventory.len() > MAX_INVENTORY || inventory.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AdapterError::ToolOutput(
            "Kani metadata contains too many or duplicate harnesses".to_owned(),
        ));
    }
    for harness in &inventory {
        if !safe_symbol(harness) {
            return Err(AdapterError::ToolOutput(format!(
                "invalid metadata harness `{harness}`"
            )));
        }
    }
    Ok((inventory, list.kani_version))
}

fn require_absent_inventory_output(path: &Path) -> Result<(), AdapterError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(AdapterError::ToolOutput(format!(
            "refusing pre-existing Kani inventory output `{}`",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AdapterError::Io(error)),
    }
}

fn read_fresh_inventory_output(path: &Path, package_dir: &Path) -> Result<Vec<u8>, AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AdapterError::ToolOutput(format!(
            "Kani did not create fresh inventory output `{}`: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TOOL_OUTPUT_BYTES as u64 {
        return Err(AdapterError::ToolOutput(
            "fresh Kani inventory output must be a bounded regular file".to_owned(),
        ));
    }
    let canonical = path.canonicalize().map_err(AdapterError::Io)?;
    let package_dir = package_dir.canonicalize().map_err(AdapterError::Io)?;
    if !canonical.starts_with(&package_dir) {
        return Err(AdapterError::ToolOutput(
            "fresh Kani inventory output escaped the selected package".to_owned(),
        ));
    }
    fs::read(canonical).map_err(AdapterError::Io)
}

fn exact_inventory(expected: &[String], actual: &[String]) -> Result<(), AdapterError> {
    if expected.is_empty() || actual.is_empty() {
        return Err(AdapterError::ToolOutput(
            "Kani requires a nonempty registered and observed harness inventory".to_owned(),
        ));
    }
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort();
    if expected_sorted != actual {
        let missing: Vec<_> = expected_sorted
            .iter()
            .filter(|item| !actual.contains(item))
            .cloned()
            .collect();
        let extra: Vec<_> = actual
            .iter()
            .filter(|item| !expected_sorted.contains(item))
            .cloned()
            .collect();
        return Err(AdapterError::ToolOutput(format!(
            "Kani harness inventory mismatch; missing={missing:?}, extra={extra:?}"
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    manifest_path: PathBuf,
}

fn package_directory(
    bytes: &[u8],
    package: &str,
    shadow_root: &Path,
) -> Result<PathBuf, AdapterError> {
    let metadata: CargoMetadata = serde_json::from_slice(bytes)
        .map_err(|error| AdapterError::ToolOutput(format!("cargo metadata: {error}")))?;
    let matches: Vec<_> = metadata
        .packages
        .into_iter()
        .filter(|candidate| candidate.name == package)
        .collect();
    if matches.len() != 1 {
        return Err(AdapterError::ToolOutput(format!(
            "cargo metadata found {} packages named `{package}`",
            matches.len()
        )));
    }
    let manifest = matches.into_iter().next().expect("one match").manifest_path;
    let canonical = manifest.canonicalize().map_err(AdapterError::Io)?;
    if !canonical.starts_with(shadow_root)
        || canonical.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml")
    {
        return Err(AdapterError::ToolOutput(
            "cargo metadata returned a manifest outside the shadow project".to_owned(),
        ));
    }
    canonical
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| AdapterError::ToolOutput("package manifest has no parent".to_owned()))
}

fn ensure_success(spec: &ProcessSpec, output: &ProcessOutput) -> Result<(), AdapterError> {
    if output.truncated {
        return Err(AdapterError::ToolOutput(format!(
            "`{}` output exceeded 8 MiB",
            spec.program
        )));
    }
    if output.status != Some(0) {
        let detail = format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(AdapterError::ToolFailed(format!(
            "{} {:?} exited {:?}: {}",
            spec.program,
            spec.args,
            output.status,
            truncate_message(detail.trim())
        )));
    }
    Ok(())
}

fn parse_version(stdout: &[u8], stderr: &[u8]) -> Result<String, AdapterError> {
    let combined = if stdout.is_empty() { stderr } else { stdout };
    let text = std::str::from_utf8(combined)
        .map_err(|error| AdapterError::ToolOutput(error.to_string()))?
        .trim();
    let version = text
        .split_whitespace()
        .find(|part| part.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .ok_or_else(|| {
            AdapterError::ToolOutput("Kani --version did not contain a version".to_owned())
        })?;
    if !version.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
        return Err(AdapterError::ToolOutput(format!(
            "unsupported Kani version token `{version}`"
        )));
    }
    Ok(version.to_owned())
}

fn observe_command(
    spec: &ProcessSpec,
    environment: &[EnvironmentObservation],
) -> CommandObservation {
    CommandObservation {
        program: logicalize_temp_path(&spec.program),
        args: spec
            .args
            .iter()
            .map(|arg| logicalize_temp_path(arg))
            .collect(),
        environment_allowlist: environment.to_vec(),
    }
}

fn logicalize_temp_path(value: &str) -> String {
    let Some(marker) = value.find("/proofbound-kani-") else {
        return value.to_owned();
    };
    let suffix = &value[marker..];
    if let Some(project) = suffix.find("/workspace/project") {
        return format!(
            "$PROJECT{}",
            &suffix[project + "/workspace/project".len()..]
        );
    }
    if let Some(workspace) = suffix.find("/workspace") {
        return format!(
            "$PROOFBOUND_WORK{}",
            &suffix[workspace + "/workspace".len()..]
        );
    }
    "$PROOFBOUND_WORK".to_owned()
}

fn observe_runs(
    outputs: &[ProcessOutput],
    shadow_root: &Path,
    project_root: &Path,
) -> Vec<RunObservation> {
    outputs
        .iter()
        .enumerate()
        .map(|(command_index, output)| {
            let normalized =
                normalize_output(&output.stdout, &output.stderr, shadow_root, project_root);
            RunObservation {
                command_index,
                exit_code: output.status,
                stdout_sha256: sha256_bytes(&output.stdout),
                stderr_sha256: sha256_bytes(&output.stderr),
                normalized_output_sha256: domain_hash(
                    "proofbound-normalized-tool-output/1",
                    &normalized,
                ),
                output_truncated: output.truncated,
                duration_ms: output.duration_ms,
            }
        })
        .collect()
}

fn normalize_output(
    stdout: &[u8],
    stderr: &[u8],
    shadow_root: &Path,
    project_root: &Path,
) -> Vec<u8> {
    let mut text = String::from_utf8_lossy(stdout).replace("\r\n", "\n");
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(stderr).replace("\r\n", "\n"));
    let text = strip_ansi(&text)
        .replace(&shadow_root.to_string_lossy().to_string(), "$PROJECT")
        .replace(&project_root.to_string_lossy().to_string(), "$PROJECT");
    let mut lines: Vec<_> = text
        .lines()
        .filter(|line| {
            !(line.contains("Finished `")
                && line.contains(" in ")
                && line.trim_end().ends_with('s'))
        })
        .map(|line| normalize_timing_line(line.trim_end()))
        .collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines.join("\n").into_bytes()
}

fn normalize_timing_line(line: &str) -> String {
    for marker in [
        "; finished in ",
        "Verification Time: ",
        "Runtime decision procedure: ",
    ] {
        if let Some(index) = line.find(marker) {
            return format!("{}<TIME>", &line[..index + marker.len()]);
        }
    }
    line.to_owned()
}

fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn adapter_identity() -> ToolObservation {
    let version = env!("CARGO_PKG_VERSION").to_owned();
    let identity = format!("{ADAPTER_ID}\0{version}");
    ToolObservation {
        name: "proofbound-adapter-kani".to_owned(),
        version,
        identity_sha256: domain_hash("proofbound-adapter-identity/1", identity.as_bytes()),
    }
}

fn allowed_environment(names: &[String]) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut result = BTreeMap::new();
    for name in names {
        if !valid_environment_name(name) {
            return Err(AdapterError::Unit(format!(
                "invalid environment variable name `{name}`"
            )));
        }
        if let Ok(value) = std::env::var(name) {
            result.insert(name.clone(), value);
        }
    }
    Ok(result)
}

fn environment_observation(environment: &BTreeMap<String, String>) -> Vec<EnvironmentObservation> {
    environment
        .iter()
        .map(|(name, value)| {
            let secret = is_secret_name(name);
            let value_sha256 = Some(domain_hash(
                "proofbound-environment-value/1",
                value.as_bytes(),
            ));
            EnvironmentObservation {
                name: name.clone(),
                value_sha256,
                secret,
            }
        })
        .collect()
}

fn valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('A'..='Z' | '_'))
        && chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn is_secret_name(name: &str) -> bool {
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn collect_input_artifacts(
    root: &Path,
    inputs: &[String],
) -> Result<Vec<ArtifactObservation>, AdapterError> {
    let mut artifacts = Vec::new();
    for input in inputs {
        let path = resolve_existing(root, input)?;
        if path.is_file() {
            artifacts.push(hash_artifact(root, &path)?);
        } else if path.is_dir() {
            for entry in WalkDir::new(&path).follow_links(false).sort_by_file_name() {
                let entry = entry.map_err(|error| AdapterError::Io(error.into()))?;
                if entry.file_type().is_symlink() {
                    return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
                }
                if entry.file_type().is_file() {
                    artifacts.push(hash_artifact(root, entry.path())?);
                }
            }
        } else {
            return Err(AdapterError::UnsafePath(input.clone()));
        }
    }
    artifacts.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    if artifacts
        .windows(2)
        .any(|pair| pair[0].logical_name == pair[1].logical_name)
    {
        return Err(AdapterError::Unit(
            "input paths overlap and name the same artifact twice".to_owned(),
        ));
    }
    Ok(artifacts)
}

fn hash_artifact(root: &Path, path: &Path) -> Result<ArtifactObservation, AdapterError> {
    let bytes = fs::read(path)?;
    let logical_name = path
        .strip_prefix(root)
        .map_err(|_| AdapterError::UnsafePath(path.display().to_string()))?
        .to_string_lossy()
        .replace('\\', "/");
    Ok(ArtifactObservation {
        logical_name,
        sha256: sha256_bytes(&bytes),
        size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
    })
}

fn read_safe_file(root: &Path, relative: &str, max_bytes: u64) -> Result<Vec<u8>, AdapterError> {
    let path = resolve_existing(root, relative)?;
    if !path.is_file() {
        return Err(AdapterError::UnsafePath(relative.to_owned()));
    }
    let metadata = path.metadata()?;
    if metadata.len() > max_bytes {
        return Err(AdapterError::Unit(format!(
            "manifest `{relative}` exceeds {max_bytes} bytes"
        )));
    }
    fs::read(path).map_err(AdapterError::Io)
}

fn resolve_existing(root: &Path, relative: &str) -> Result<PathBuf, AdapterError> {
    validate_relative_path(relative)?;
    let candidate = root.join(relative);
    reject_symlink_components(root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .map_err(|_| AdapterError::UnsafePath(relative.to_owned()))?;
    if !canonical.starts_with(root) {
        return Err(AdapterError::UnsafePath(relative.to_owned()));
    }
    Ok(canonical)
}

fn validate_relative_path(path: &str) -> Result<(), AdapterError> {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') {
        return Err(AdapterError::UnsafePath(path.to_owned()));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AdapterError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, candidate: &Path) -> Result<(), AdapterError> {
    let relative = candidate
        .strip_prefix(root)
        .map_err(|_| AdapterError::UnsafePath(candidate.display().to_string()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            return Err(AdapterError::UnsafePath(current.display().to_string()));
        }
    }
    Ok(())
}

struct ShadowProject {
    _temp: TempDir,
    root: PathBuf,
}

impl ShadowProject {
    fn path(&self) -> &Path {
        &self.root
    }
}

fn shadow_project(source: &Path, disk_budget: u64) -> Result<ShadowProject, AdapterError> {
    let temp = tempfile::Builder::new()
        .prefix("proofbound-kani-")
        .tempdir()?;
    let destination = temp.path().join("workspace");
    let project = destination.join("project");
    fs::create_dir_all(&project)?;
    let mut copied = 0_u64;
    for entry in WalkDir::new(source).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|error| AdapterError::Io(error.into()))?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|_| AdapterError::UnsafePath(entry.path().display().to_string()))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if should_exclude(relative) {
            if entry.file_type().is_dir() { /* descendants are filtered by component too */ }
            continue;
        }
        if entry.file_type().is_symlink() {
            return Err(AdapterError::UnsafePath(relative.display().to_string()));
        }
        let target = project.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            let size = entry
                .metadata()
                .map_err(|error| AdapterError::Io(error.into()))?
                .len();
            copied = copied
                .checked_add(size)
                .ok_or_else(|| AdapterError::Budget("copied byte count overflowed".to_owned()))?;
            if copied > disk_budget {
                return Err(AdapterError::Budget(format!(
                    "project shadow requires more than {disk_budget} bytes"
                )));
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
        } else {
            return Err(AdapterError::UnsafePath(relative.display().to_string()));
        }
    }
    Ok(ShadowProject {
        _temp: temp,
        root: destination,
    })
}

fn should_exclude(relative: &Path) -> bool {
    relative.components().any(|component| {
        let name = component.as_os_str();
        name == ".git"
            || name == "target"
            || name == ".lake"
            || name == ".proofbound"
            || name == ".venv"
            || name == "node_modules"
            || name == "__pycache__"
            || name == ".pytest_cache"
            || name == ".mypy_cache"
            || name == ".ruff_cache"
    })
}

fn directory_size(path: &Path) -> Result<u64, AdapterError> {
    let mut size = 0_u64;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry.map_err(|error| AdapterError::Io(error.into()))?;
        if entry.file_type().is_file() {
            size = size
                .checked_add(
                    entry
                        .metadata()
                        .map_err(|error| AdapterError::Io(error.into()))?
                        .len(),
                )
                .ok_or_else(|| AdapterError::Budget("disk usage overflowed".to_owned()))?;
        }
    }
    Ok(size)
}

fn validate_metadata_path(path: &str) -> Result<(), AdapterError> {
    let path = path.strip_prefix("./").unwrap_or(path);
    validate_relative_path(path).map_err(|_| {
        AdapterError::ToolOutput(format!("unsafe source path in Kani metadata: `{path}`"))
    })
}

fn safe_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        && !value.starts_with('-')
}

fn safe_symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.split("::").all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        })
}

fn require_unique(label: &str, values: &[String]) -> Result<(), AdapterError> {
    if values.len() > MAX_INVENTORY {
        return Err(AdapterError::Unit(format!(
            "{label} exceeds {MAX_INVENTORY} entries"
        )));
    }
    let unique: BTreeSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        return Err(AdapterError::Unit(format!("{label} contains duplicates")));
    }
    Ok(())
}

fn remaining_time(started: Instant, budget_ms: u64) -> Result<Duration, AdapterError> {
    let used = elapsed_ms(started);
    if used >= budget_ms {
        return Err(AdapterError::Timeout(budget_ms));
    }
    Ok(Duration::from_millis(budget_ms - used))
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn unix_ms() -> Result<u64, AdapterError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AdapterError::Internal(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| AdapterError::Internal("timestamp overflowed".to_owned()))
}

fn truncate_message(message: &str) -> String {
    message.chars().take(8192).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Default)]
    struct FakeExecutor {
        outputs: std::collections::VecDeque<ProcessOutput>,
        seen: Vec<ProcessSpec>,
    }

    impl Executor for FakeExecutor {
        fn run(
            &mut self,
            spec: &ProcessSpec,
            _cwd: &Path,
            _environment: &BTreeMap<String, String>,
            _timeout: Duration,
        ) -> Result<ProcessOutput, AdapterError> {
            self.seen.push(spec.clone());
            self.outputs
                .pop_front()
                .ok_or_else(|| AdapterError::Internal("fake executor exhausted".to_owned()))
        }
    }

    #[derive(Default)]
    struct InventoryExecutor {
        calls: usize,
    }

    impl Executor for InventoryExecutor {
        fn run(
            &mut self,
            _spec: &ProcessSpec,
            cwd: &Path,
            _environment: &BTreeMap<String, String>,
            _timeout: Duration,
        ) -> Result<ProcessOutput, AdapterError> {
            let stdout = match self.calls {
                0 => b"Kani Rust Verifier 0.67.0\n".to_vec(),
                1 => serde_json::to_vec(&json!({
                    "packages": [{
                        "name": "fixture",
                        "manifest_path": cwd.join("Cargo.toml")
                    }]
                }))
                .unwrap(),
                2 => {
                    fs::write(cwd.join("kani-list.json"), kani_metadata(&["crate::h"]))?;
                    Vec::new()
                }
                _ => {
                    return Err(AdapterError::Internal(
                        "unexpected inventory call".to_owned(),
                    ));
                }
            };
            self.calls += 1;
            Ok(ProcessOutput {
                status: Some(0),
                stdout,
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            })
        }
    }

    fn kani_metadata(harnesses: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "kani-version": "0.67.0",
            "file-version": "0.1",
            "standard-harnesses": {"src/lib.rs": harnesses},
            "contract-harnesses": {},
            "contracts": [],
            "totals": {"standard-harnesses": harnesses.len(), "contract-harnesses": 0, "functions-under-contract": 0}
        })).unwrap()
    }

    #[test]
    fn nullable_observation_fields_are_required_and_accept_explicit_null() {
        let environment = json!({"name":"PATH","value_sha256":null,"secret":false});
        let parsed: EnvironmentObservation = serde_json::from_value(environment.clone()).unwrap();
        assert_eq!(parsed.value_sha256, None);
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["value_sha256"],
            Value::Null
        );
        let mut missing = environment;
        missing.as_object_mut().unwrap().remove("value_sha256");
        assert!(serde_json::from_value::<EnvironmentObservation>(missing).is_err());

        let run = json!({
            "command_index":0,"exit_code":null,"stdout_sha256":"sha256:00",
            "stderr_sha256":"sha256:01","normalized_output_sha256":"sha256:02",
            "output_truncated":false,"duration_ms":1
        });
        let parsed: RunObservation = serde_json::from_value(run.clone()).unwrap();
        assert_eq!(parsed.exit_code, None);
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["exit_code"],
            Value::Null
        );
        let mut missing = run;
        missing.as_object_mut().unwrap().remove("exit_code");
        assert!(serde_json::from_value::<RunObservation>(missing).is_err());

        let usage = json!({"time_ms":1,"peak_disk_bytes":2,"peak_memory_bytes":null});
        let parsed: UsageObservation = serde_json::from_value(usage.clone()).unwrap();
        assert_eq!(parsed.peak_memory_bytes, None);
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["peak_memory_bytes"],
            Value::Null
        );
        let mut missing = usage;
        missing.as_object_mut().unwrap().remove("peak_memory_bytes");
        assert!(serde_json::from_value::<UsageObservation>(missing).is_err());
    }

    #[test]
    fn parses_exact_json_metadata_without_source_scanning() {
        let (inventory, version) =
            parse_kani_inventory(&kani_metadata(&["crate::h2", "crate::h1"])).unwrap();
        assert_eq!(inventory, ["crate::h1", "crate::h2"]);
        assert_eq!(version, "0.67.0");
    }

    #[test]
    fn rejects_unknown_or_inconsistent_metadata() {
        let mut value: Value = serde_json::from_slice(&kani_metadata(&["crate::h"])).unwrap();
        value["unexpected"] = json!(true);
        assert!(parse_kani_inventory(&serde_json::to_vec(&value).unwrap()).is_err());
        value.as_object_mut().unwrap().remove("unexpected");
        value["totals"]["standard-harnesses"] = json!(2);
        assert!(parse_kani_inventory(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn rejects_duplicate_raw_standard_harness_source_keys() {
        let duplicate_source = br#"{
            "kani-version":"0.67.0",
            "file-version":"0.1",
            "standard-harnesses":{
                "src/lib.rs":["crate::first"],
                "src/lib.rs":["crate::second"]
            },
            "contract-harnesses":{},
            "contracts":[],
            "totals":{
                "standard-harnesses":1,
                "contract-harnesses":0,
                "functions-under-contract":0
            }
        }"#;
        let error = parse_kani_inventory(duplicate_source).unwrap_err();
        assert!(error.to_string().contains("duplicate standard-harnesses"));
    }

    #[test]
    fn inventory_comparison_reports_missing_and_extra() {
        let error = exact_inventory(&["crate::wanted".to_owned()], &["crate::extra".to_owned()])
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("wanted"));
        assert!(message.contains("extra"));
        assert!(exact_inventory(&["crate::wanted".to_owned()], &[]).is_err());
    }

    #[test]
    fn kani_inventory_file_must_be_fresh_regular_and_package_local() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("kani-list.json");
        fs::write(&output, b"stale").unwrap();
        assert!(require_absent_inventory_output(&output).is_err());
        fs::remove_file(&output).unwrap();
        assert!(require_absent_inventory_output(&output).is_ok());
        fs::write(&output, kani_metadata(&["crate::h"])).unwrap();
        assert!(read_fresh_inventory_output(&output, temp.path()).is_ok());

        #[cfg(unix)]
        {
            fs::remove_file(&output).unwrap();
            fs::write(temp.path().join("elsewhere.json"), b"{}").unwrap();
            std::os::unix::fs::symlink("elsewhere.json", &output).unwrap();
            assert!(read_fresh_inventory_output(&output, temp.path()).is_err());
        }
    }

    #[test]
    fn kani_rejects_evidence_kind_relabeling() {
        let mut unit: EvidenceUnitManifest = serde_json::from_value(json!({
            "schema":"proofbound-evidence-unit/1",
            "id":"bounded-unit",
            "adapter":"kani",
            "kind":"bounded-check",
            "claims":["CLAIM-ONE"],
            "tier":1,
            "operation":{"type":"kani","targets":["crate::h"],"manifest":"model.toml"},
            "expected_inventory":["crate::h"],
            "inputs":["model.toml"],
            "outputs":[],
            "environment_allowlist":["PATH"],
            "bounded_domain":{"id":"domain","description":"one case","cardinality":1,"ordering_key":[0]},
            "resource_budget":{"time_seconds":1,"disk_bytes":1,"memory_bytes":1}
        }))
        .unwrap();
        assert!(validate_evidence_unit(&unit).is_ok());
        unit.kind = EvidenceKind::SourceRefinement;
        assert!(validate_evidence_unit(&unit).is_err());
    }

    #[test]
    fn inventory_returns_exact_targets_without_assurance_evidence() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("Cargo.toml"),
            b"[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(
            root.path().join("model.toml"),
            br#"schema = "proofbound-model-check-unit/1"
id = "bounded-unit"
adapter = "kani"
package = "fixture"
harnesses = ["crate::h"]
claims = ["CLAIM-ONE"]
solver = "cadical"
unwind = 1
assumptions = []

[domain]
id = "domain"
description = "one case"
cardinality = 1
ordering_key = [0]

[resource_budget]
time_seconds = 60
disk_bytes = 10485760
memory_bytes = 1
"#,
        )
        .unwrap();
        let request: AdapterRequest = serde_json::from_value(json!({
            "schema": PROTOCOL_SCHEMA,
            "type": "request",
            "request_id": "0123456789abcdef0123456789abcdef",
            "adapter": ADAPTER_ID,
            "operation": "inventory",
            "project_root": ".",
            "unit": {
                "schema":"proofbound-evidence-unit/1",
                "id":"bounded-unit",
                "adapter":"kani",
                "kind":"bounded-check",
                "claims":["CLAIM-ONE"],
                "tier":1,
                "operation":{
                    "type":"kani",
                    "package":"fixture",
                    "targets":["crate::h"],
                    "manifest":"model.toml"
                },
                "expected_inventory":["crate::h"],
                "inputs":["model.toml"],
                "outputs":[],
                "environment_allowlist":[],
                "bounded_domain":{
                    "id":"domain",
                    "description":"one case",
                    "cardinality":1,
                    "ordering_key":[0]
                },
                "resource_budget":{
                    "time_seconds":60,
                    "disk_bytes":10485760,
                    "memory_bytes":1
                }
            }
        }))
        .unwrap();
        let mut executor = InventoryExecutor::default();
        let (evidence, inventory) = execute_request(&request, root.path(), &mut executor).unwrap();
        assert!(evidence.is_none());
        assert_eq!(inventory, ["crate::h"]);
        assert_eq!(
            executor.calls, 3,
            "inventory must not run the Kani proof phase"
        );
    }

    #[test]
    fn argv_is_typed_and_manifest_driven() {
        let model: ModelCheckUnitManifest = serde_json::from_value(json!({
            "schema":"proofbound-model-check-unit/1", "id":"unit", "adapter":"kani",
            "package":"safe-package", "harnesses":["crate::one", "crate::two"], "claims":["TEST-ONE"],
            "domain":{"id":"domain", "description":"d", "cardinality":2, "ordering_key":[0]},
            "solver":"cadical", "unwind":7, "assumptions":[],
            "resource_budget":{"time_seconds":1,"disk_bytes":1,"memory_bytes":1}
        })).unwrap();
        let args = build_check_args(&model, Path::new("/tmp/run"));
        assert_eq!(&args[..4], ["kani", "--package", "safe-package", "--exact"]);
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--harness", "crate::one"])
        );
        assert!(args.windows(2).any(|pair| pair == ["--solver", "cadical"]));
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains(';') || arg.contains("$("))
        );
    }

    #[test]
    fn rejects_traversal_and_symlinks() {
        assert!(validate_relative_path("../secret").is_err());
        assert!(validate_relative_path("/absolute").is_err());
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("real"), b"ok").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("real", temp.path().join("link")).unwrap();
            assert!(resolve_existing(&temp.path().canonicalize().unwrap(), "link").is_err());
        }
    }

    #[test]
    fn canonical_protocol_rejects_whitespace_and_unknown_fields() {
        let request = json!({
            "schema":PROTOCOL_SCHEMA,"type":"request","request_id":"0123456789abcdef0123456789abcdef",
            "adapter":ADAPTER_ID,"operation":"check","project_root":".","unit":{}
        });
        let canonical = canonical_json(&request).unwrap();
        let parsed: AdapterRequest = serde_json::from_slice(&canonical).unwrap();
        assert!(validate_request(&parsed, &canonical).is_ok());
        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        assert!(validate_request(&parsed, &noncanonical).is_err());
        let mut unknown = request;
        unknown["unexpected"] = json!(true);
        let response = handle_request_bytes(&canonical_json(&unknown).unwrap());
        assert!(!response.success);
        assert_eq!(response.diagnostics[0].code, "PB-KANI-1003");
    }

    #[test]
    fn normalization_removes_paths_timing_and_ansi() {
        let normalized = normalize_output(
            b"\x1b[31mresult\x1b[0m /tmp/shadow\r\n",
            b"Finished `dev` profile in 0.42s\n",
            Path::new("/tmp/shadow"),
            Path::new("/real/project"),
        );
        assert_eq!(String::from_utf8(normalized).unwrap(), "result $PROJECT");
    }

    #[test]
    fn common_observation_shape_round_trips_strictly() {
        let observation = AdapterObservation {
            schema: OBSERVATION_SCHEMA.to_owned(),
            unit_id: "u".to_owned(),
            evidence_kind: "bounded-check".to_owned(),
            outcome: ObservationOutcome::Passed,
            input_artifacts: vec![],
            generated_artifacts: vec![],
            tool: ToolObservation {
                name: "kani".to_owned(),
                version: "1".to_owned(),
                identity_sha256: sha256_bytes(b"t"),
            },
            adapter: adapter_identity(),
            commands: vec![],
            runs: vec![],
            started_unix_ms: 1,
            completed_unix_ms: 2,
            deterministic_result_sha256: sha256_bytes(b"r"),
            unit_configuration_sha256: sha256_bytes(b"u"),
            resource_budget: BudgetObservation {
                time_ms: 1,
                disk_bytes: 1,
                memory_bytes: 1,
            },
            resource_usage: UsageObservation {
                time_ms: 1,
                peak_disk_bytes: 1,
                peak_memory_bytes: None,
            },
            inventory: vec![],
            normalization: "stable-tool-output/1".to_owned(),
        };
        let bytes = canonical_json(&observation).unwrap();
        assert_eq!(
            serde_json::from_slice::<AdapterObservation>(&bytes).unwrap(),
            observation
        );
    }

    #[test]
    fn fake_tool_reports_typed_version_without_a_shell() {
        let mut fake = FakeExecutor::default();
        fake.outputs.push_back(ProcessOutput {
            status: Some(0),
            stdout: b"Kani Rust Verifier 0.67.0\n".to_vec(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        });
        let spec = ProcessSpec {
            program: "cargo".to_owned(),
            args: vec!["kani".to_owned(), "--version".to_owned()],
        };
        let output = fake
            .run(
                &spec,
                Path::new("."),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            parse_version(&output.stdout, &output.stderr).unwrap(),
            "0.67.0"
        );
        assert_eq!(fake.seen[0].program, "cargo");
        assert_eq!(fake.seen[0].args, ["kani", "--version"]);
    }
}
