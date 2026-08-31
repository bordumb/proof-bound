//! Manifest-driven Rust/Python test and Python checker adapter.
//!
//! Collection is performed through Cargo/libtest and pytest metadata.  Source
//! text is never searched for test names.  Configured tests are resolved to one
//! and only one collected node and then executed individually, preventing a
//! successful command from silently skipping a target.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use proofbound_evidence::{canonical_json, domain_hash, sha256_bytes};
use proofbound_manifest::{
    AdapterDiagnostic, AdapterKind, AdapterRequest, AdapterResponse, EvidenceKind,
    EvidenceUnitManifest, OperationKind,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

pub const PROTOCOL_SCHEMA: &str = "proofbound-adapter-protocol/1";
pub const OBSERVATION_SCHEMA: &str = "proofbound-adapter-observation/1";
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INVENTORY: usize = 100_000;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_binding: Option<ArtifactBindingObservation>,
}

/// Facts reported by a canonical artifact checker and independently validated
/// against the registered unit and input bytes by this adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBindingObservation {
    pub artifact_logical_name: String,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactCheckerReport {
    schema: String,
    accepted: bool,
    artifact_logical_name: String,
    artifact_sha256: String,
    inventory: Vec<String>,
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

type TestRunResult = (Vec<CommandObservation>, Vec<ProcessOutput>, Vec<String>);

#[derive(Clone, Copy)]
struct Deadline {
    started: Instant,
    budget_ms: u64,
}

impl Deadline {
    fn remaining(self) -> Result<Duration, AdapterError> {
        remaining_time(self.started, self.budget_ms)
    }
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
        let mut child = Command::new(executable)
            .args(&spec.args)
            .current_dir(cwd)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
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
            if let Some(status) = child.try_wait()? {
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
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let take = MAX_TOOL_OUTPUT_BYTES.saturating_sub(kept.len()).min(count);
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
    #[error("test inventory is invalid: {0}")]
    Inventory(String),
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
                "PB-TEST-1001",
                "install the pinned Rust/Python test toolchain and expose it through the declared environment",
            ),
            Self::Timeout(_) | Self::Budget(_) => (
                "PB-TEST-1002",
                "review the workload and increase the evidence-unit budget if justified",
            ),
            Self::Request(_) => (
                "PB-TEST-1003",
                "send canonical proofbound-adapter-protocol/1 JSON with no unknown fields",
            ),
            Self::Unit(_) => (
                "PB-TEST-1004",
                "use a supported strict evidence unit with a typed operation and arguments",
            ),
            Self::UnsafePath(_) => (
                "PB-TEST-1005",
                "use only relative, non-symlink paths contained by the project root",
            ),
            Self::Inventory(_) => (
                "PB-TEST-1006",
                "make the configured target inventory exactly match collected test metadata",
            ),
            Self::ToolFailed(_) => (
                "PB-TEST-1007",
                "reproduce the individually selected test and fix its failure",
            ),
            Self::Io(_) | Self::Internal(_) => (
                "PB-TEST-1099",
                "inspect the diagnostic and retry from a clean checkout",
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
        Ok(value) => value,
        Err(error) => return failed_response(fallback, AdapterError::Request(error.to_string())),
    };
    let base = AdapterResponse {
        schema: PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: request.request_id.clone(),
        adapter: request.adapter.clone(),
        success: false,
        evidence: None,
        inventory: Vec::new(),
        diagnostics: Vec::new(),
    };
    if let Err(error) = validate_request(&request, input) {
        return failed_response(base, error);
    }
    let mut executor = RealExecutor;
    match execute_request(&request, Path::new("."), &mut executor) {
        Ok((observation, inventory)) => AdapterResponse {
            success: true,
            evidence: observation
                .map(|value| serde_json::to_value(value).expect("observation serializes")),
            inventory,
            ..base
        },
        Err(error) => failed_response(base, error),
    }
}

fn fallback_response() -> AdapterResponse {
    AdapterResponse {
        schema: PROTOCOL_SCHEMA.to_owned(),
        message_type: "response".to_owned(),
        request_id: "00000000000000000000000000000000".to_owned(),
        adapter: "rust-test".to_owned(),
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
        || request.project_root != "."
        || !matches!(
            request.adapter.as_str(),
            "rust-test" | "python-test" | "canonical-artifact" | "independent-check"
        )
    {
        return Err(AdapterError::Request(
            "protocol constants do not match the test adapter".to_owned(),
        ));
    }
    if request.request_id.len() != 32
        || !request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AdapterError::Request(
            "request_id must be 32 lowercase hexadecimal characters".to_owned(),
        ));
    }
    if !matches!(
        request.operation.as_str(),
        "doctor" | "inventory" | "check" | "reproduce" | "update"
    ) {
        return Err(AdapterError::Request("unsupported operation".to_owned()));
    }
    if canonical_json(request).map_err(|error| AdapterError::Request(error.to_string()))?
        != original
    {
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
    let root = project_root.canonicalize()?;
    let unit: EvidenceUnitManifest = serde_json::from_value(request.unit.clone())
        .map_err(|error| AdapterError::Unit(error.to_string()))?;
    let flavor = validate_unit(request, &unit)?;
    if request.operation == "update" && flavor != TestFlavor::Generator {
        return Err(AdapterError::Request(
            "test and checker adapters have no committed generated artifacts; update is unsupported"
                .to_owned(),
        ));
    }
    let mut environment = allowed_environment(&unit.environment_allowlist)?;
    // PATH is adapter infrastructure: fixed executables are resolved before
    // env clearing, while compilers/test runners still need their own fixed
    // helper programs (linkers, xcrun, Python launchers).  Its value is hashed
    // in the observation and never serialized.
    if let Some(path) = std::env::var_os("PATH") {
        environment
            .entry("PATH".to_owned())
            .or_insert_with(|| path.to_string_lossy().into_owned());
    }
    environment.insert("TERM".to_owned(), "dumb".to_owned());
    match flavor {
        TestFlavor::Rust => {
            environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
            environment.insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
        }
        TestFlavor::Python => {
            environment.insert("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned());
            environment.insert("PYTEST_DISABLE_PLUGIN_AUTOLOAD".to_owned(), "1".to_owned());
        }
        TestFlavor::CanonicalArtifact | TestFlavor::IndependentCheck | TestFlavor::Generator => {
            environment.insert("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned());
        }
    }
    let environment_observation = observe_environment(&environment, &unit.environment_allowlist);
    let budget = BudgetObservation {
        time_ms: unit.resource_budget.time_seconds.saturating_mul(1000),
        disk_bytes: unit.resource_budget.disk_bytes,
        memory_bytes: unit.resource_budget.memory_bytes,
    };
    let started_unix_ms = unix_ms()?;
    let started = Instant::now();
    let (tool, version_runs, version_commands) = tool_identity(
        flavor,
        &root,
        &environment,
        &environment_observation,
        executor,
    )?;
    if request.operation == "doctor" {
        return Ok((None, Vec::new()));
    }
    let shadow = if request.operation == "update" && flavor == TestFlavor::Generator {
        None
    } else {
        Some(shadow_project(&root, budget.disk_bytes)?)
    };
    let execution_root = match &shadow {
        Some(shadow) => shadow.path().join("project").canonicalize()?,
        None => root.clone(),
    };
    let deadline = Deadline {
        started,
        budget_ms: budget.time_ms,
    };
    let (mut commands, mut outputs, mut inventory) = match flavor {
        TestFlavor::Rust => run_rust_tests(
            request,
            &unit,
            &root,
            &execution_root,
            &environment,
            executor,
            deadline,
        )?,
        TestFlavor::Python => run_python_tests(
            request,
            &unit,
            &execution_root,
            &environment,
            executor,
            deadline,
        )?,
        TestFlavor::CanonicalArtifact | TestFlavor::IndependentCheck => run_python_checker(
            request,
            &unit,
            &execution_root,
            &environment,
            executor,
            deadline,
        )?,
        TestFlavor::Generator => run_python_generator(
            request,
            &unit,
            &execution_root,
            &environment,
            executor,
            deadline,
        )?,
    };
    let artifact_binding = if flavor == TestFlavor::CanonicalArtifact
        && matches!(request.operation.as_str(), "check" | "reproduce")
    {
        let output = outputs.last().ok_or_else(|| {
            AdapterError::Inventory("canonical checker produced no result".to_owned())
        })?;
        let (binding, reported_inventory) =
            validate_artifact_checker_report(&output.stdout, &unit, &execution_root)?;
        inventory = reported_inventory;
        Some(binding)
    } else {
        None
    };
    // Tool version calls are deliberately not repeated in the evidence run;
    // prepend their observations so every actual subprocess is recorded.
    let mut all_commands = version_commands;
    let offset = all_commands.len();
    all_commands.append(&mut commands);
    let mut all_outputs = version_runs;
    all_outputs.append(&mut outputs);
    let disk_bytes = directory_size(
        shadow
            .as_ref()
            .map_or(execution_root.as_path(), ShadowProject::path),
    )?;
    if disk_bytes > budget.disk_bytes {
        return Err(AdapterError::Budget(format!(
            "shadow execution used {disk_bytes} bytes, limit is {}",
            budget.disk_bytes
        )));
    }
    let runs = observe_runs(&all_outputs, &execution_root, &root);
    // `observe_runs` indexes the combined list already; offset is retained as
    // an assertion against accidental command/output skew.
    debug_assert!(offset <= runs.len());
    if runs.len() != all_commands.len() {
        return Err(AdapterError::Internal(
            "command/run inventory skew".to_owned(),
        ));
    }
    if request.operation == "update" {
        return Ok((None, inventory));
    }
    let input_artifacts = collect_input_artifacts(&root, &unit.inputs)?;
    let generated_artifacts = if flavor == TestFlavor::Generator {
        collect_exact_outputs(&execution_root, &unit.outputs)?
    } else {
        Vec::new()
    };
    let unit_bytes =
        canonical_json(&request.unit).map_err(|error| AdapterError::Internal(error.to_string()))?;
    let result = serde_json::json!({"inventory":inventory,"artifact_binding":artifact_binding,"run_hashes":runs.iter().map(|run| &run.normalized_output_sha256).collect::<Vec<_>>()});
    let completed_unix_ms = unix_ms()?;
    let observation = AdapterObservation {
        schema: OBSERVATION_SCHEMA.to_owned(),
        unit_id: unit.id,
        evidence_kind: evidence_kind_name(unit.kind).to_owned(),
        outcome: ObservationOutcome::Passed,
        input_artifacts,
        generated_artifacts,
        tool,
        adapter: adapter_identity(),
        commands: all_commands,
        runs,
        started_unix_ms,
        completed_unix_ms,
        deterministic_result_sha256: domain_hash(
            "proofbound-adapter-result/1",
            &canonical_json(&result).map_err(|error| AdapterError::Internal(error.to_string()))?,
        ),
        unit_configuration_sha256: domain_hash("proofbound-unit-configuration/1", &unit_bytes),
        resource_budget: budget,
        resource_usage: UsageObservation {
            time_ms: elapsed_ms(started),
            peak_disk_bytes: disk_bytes,
            peak_memory_bytes: None,
        },
        inventory: inventory.clone(),
        normalization: "stable-tool-output/1".to_owned(),
        artifact_binding,
    };
    Ok((Some(observation), inventory))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFlavor {
    Rust,
    Python,
    Generator,
    CanonicalArtifact,
    IndependentCheck,
}

fn validate_unit(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
) -> Result<TestFlavor, AdapterError> {
    if unit.schema != "proofbound-evidence-unit/1" {
        return Err(AdapterError::Unit(
            "expected proofbound-evidence-unit/1".to_owned(),
        ));
    }
    let flavor = match (request.adapter.as_str(), unit.adapter, unit.operation.kind) {
        ("rust-test", AdapterKind::RustTest, OperationKind::CargoTest) => TestFlavor::Rust,
        ("python-test", AdapterKind::PythonTest, OperationKind::Pytest) => TestFlavor::Python,
        ("python-test", AdapterKind::PythonTest, OperationKind::Generator) => TestFlavor::Generator,
        ("canonical-artifact", AdapterKind::CanonicalArtifact, OperationKind::ArtifactCheck) => {
            TestFlavor::CanonicalArtifact
        }
        ("independent-check", AdapterKind::IndependentCheck, OperationKind::IndependentCheck) => {
            TestFlavor::IndependentCheck
        }
        _ => {
            return Err(AdapterError::Unit(
                "adapter and operation type do not agree".to_owned(),
            ));
        }
    };
    require_unique("claims", &unit.claims)?;
    require_unique("expected_inventory", &unit.expected_inventory)?;
    require_unique("targets", &unit.operation.targets)?;
    require_unique("paths", &unit.operation.paths)?;
    require_unique("inputs", &unit.inputs)?;
    require_unique("outputs", &unit.outputs)?;
    require_unique("environment_allowlist", &unit.environment_allowlist)?;
    if unit.claims.is_empty() {
        return Err(AdapterError::Unit(
            "evidence unit must name at least one claim".to_owned(),
        ));
    }
    if unit.resource_budget.time_seconds == 0
        || unit.resource_budget.disk_bytes == 0
        || unit.resource_budget.memory_bytes == 0
    {
        return Err(AdapterError::Unit(
            "resource budgets must be non-zero".to_owned(),
        ));
    }
    if flavor != TestFlavor::Generator && !unit.outputs.is_empty() {
        return Err(AdapterError::Unit(
            "adapter units may not declare committed outputs".to_owned(),
        ));
    }
    for path in unit.operation.paths.iter().chain(unit.inputs.iter()) {
        validate_relative_path(path)?;
    }
    if let Some(manifest) = &unit.operation.manifest {
        validate_relative_path(manifest)?;
    }
    validate_checker_configuration(flavor, unit)?;
    validate_arguments(flavor, &unit.operation.arguments)?;
    Ok(flavor)
}

fn validate_checker_configuration(
    flavor: TestFlavor,
    unit: &EvidenceUnitManifest,
) -> Result<(), AdapterError> {
    if !matches!(
        flavor,
        TestFlavor::CanonicalArtifact | TestFlavor::IndependentCheck | TestFlavor::Generator
    ) {
        if unit.operation.checker.is_some() {
            return Err(AdapterError::Unit(
                "test operations may not configure a checker".to_owned(),
            ));
        }
        return Ok(());
    }

    let checker = unit.operation.checker.as_deref().ok_or_else(|| {
        AdapterError::Unit("checker operation requires operation.checker".to_owned())
    })?;
    validate_relative_path(checker)?;
    if Path::new(checker)
        .extension()
        .and_then(|value| value.to_str())
        != Some("py")
    {
        return Err(AdapterError::Unit(
            "checker must be a repository-relative .py file".to_owned(),
        ));
    }
    if !unit.inputs.iter().any(|input| input == checker) {
        return Err(AdapterError::Unit(
            "checker must be registered verbatim in inputs so its bytes are bound".to_owned(),
        ));
    }
    if flavor == TestFlavor::Generator {
        if unit.outputs.is_empty() {
            return Err(AdapterError::Unit(
                "generator must declare at least one exact committed output".to_owned(),
            ));
        }
        for output in &unit.outputs {
            validate_relative_path(output)?;
            if !unit.inputs.contains(output) {
                return Err(AdapterError::Unit(format!(
                    "generator output `{output}` must also be an input so verify-only cache keys bind its committed bytes"
                )));
            }
        }
        let mut inventory = unit.expected_inventory.clone();
        inventory.sort();
        let mut outputs = unit.outputs.clone();
        outputs.sort();
        if inventory != outputs {
            return Err(AdapterError::Inventory(
                "generator expected_inventory must exactly equal its output allowlist".to_owned(),
            ));
        }
        if !unit.operation.arguments.is_empty() || !unit.operation.paths.is_empty() {
            return Err(AdapterError::Unit(
                "generator operations take no configured arguments or paths; the adapter owns the --update switch"
                    .to_owned(),
            ));
        }
    } else if let Some(argument) = unit
        .operation
        .arguments
        .iter()
        .find(|argument| !unit.inputs.iter().any(|input| input == *argument))
    {
        return Err(AdapterError::Unit(format!(
            "checker argument `{argument}` must be registered verbatim in inputs"
        )));
    }
    if unit.expected_inventory.is_empty() {
        return Err(AdapterError::Inventory(
            "checker expected_inventory must be non-empty".to_owned(),
        ));
    }
    if unit.operation.manifest.is_some()
        || unit.operation.package.is_some()
        || unit.operation.inventory.is_some()
        || !unit.operation.targets.is_empty()
    {
        return Err(AdapterError::Unit(
            "checker operations accept only checker, arguments, and optional paths".to_owned(),
        ));
    }
    match (flavor, unit.kind) {
        (TestFlavor::CanonicalArtifact, EvidenceKind::ArtifactSoundness) => {
            if unit.theorem.as_deref().is_none_or(str::is_empty) {
                return Err(AdapterError::Unit(
                    "canonical artifact unit must name the exact separately audited theorem"
                        .to_owned(),
                ));
            }
            Ok(())
        }
        (TestFlavor::IndependentCheck, EvidenceKind::IndependentCheck) => Ok(()),
        (TestFlavor::Generator, EvidenceKind::ExampleTest) => Ok(()),
        _ => Err(AdapterError::Unit(
            "checker adapter and evidence kind do not agree".to_owned(),
        )),
    }
}

fn validate_arguments(flavor: TestFlavor, arguments: &[String]) -> Result<(), AdapterError> {
    if arguments.len() > 4096 {
        return Err(AdapterError::Unit("too many arguments".to_owned()));
    }
    let forbidden_rust = [
        "--manifest-path",
        "--target-dir",
        "--config",
        "--package",
        "-p",
        "--workspace",
        "--exclude",
        "--lockfile-path",
    ];
    let forbidden_python = [
        "--rootdir",
        "--basetemp",
        "--confcutdir",
        "--override-ini",
        "--pyargs",
        "--ignore",
        "--ignore-glob",
        "-c",
        "-p",
    ];
    let forbidden = match flavor {
        TestFlavor::Rust => &forbidden_rust[..],
        TestFlavor::Python => &forbidden_python[..],
        TestFlavor::CanonicalArtifact | TestFlavor::IndependentCheck | TestFlavor::Generator => {
            &[][..]
        }
    };
    for argument in arguments {
        if argument.len() > 4096
            || argument.contains(['\0', '\n', '\r'])
            || forbidden
                .iter()
                .any(|flag| argument == flag || argument.starts_with(&format!("{flag}=")))
        {
            return Err(AdapterError::Unit(format!(
                "argument `{argument}` may escape or alter the adapter-controlled invocation"
            )));
        }
        if matches!(
            flavor,
            TestFlavor::CanonicalArtifact | TestFlavor::IndependentCheck
        ) {
            validate_relative_path(argument)?;
        }
    }
    Ok(())
}

fn tool_identity<E: Executor>(
    flavor: TestFlavor,
    root: &Path,
    environment: &BTreeMap<String, String>,
    environment_observation: &[EnvironmentObservation],
    executor: &mut E,
) -> Result<(ToolObservation, Vec<ProcessOutput>, Vec<CommandObservation>), AdapterError> {
    let specs = match flavor {
        TestFlavor::Rust => vec![ProcessSpec {
            program: "cargo".to_owned(),
            args: vec!["--version".to_owned()],
        }],
        TestFlavor::Python => vec![
            ProcessSpec {
                program: "python3".to_owned(),
                args: vec!["--version".to_owned()],
            },
            ProcessSpec {
                program: "python3".to_owned(),
                args: vec!["-m".to_owned(), "pytest".to_owned(), "--version".to_owned()],
            },
        ],
        TestFlavor::CanonicalArtifact | TestFlavor::IndependentCheck | TestFlavor::Generator => {
            vec![ProcessSpec {
                program: "python3".to_owned(),
                args: vec!["--version".to_owned()],
            }]
        }
    };
    let mut outputs = Vec::new();
    let mut versions = Vec::new();
    for spec in &specs {
        let output = executor.run(spec, root, environment, Duration::from_secs(20))?;
        ensure_success(spec, &output)?;
        let raw = if output.stdout.is_empty() {
            &output.stderr
        } else {
            &output.stdout
        };
        let text = std::str::from_utf8(raw)
            .map_err(|error| AdapterError::Inventory(error.to_string()))?
            .trim()
            .to_owned();
        if text.is_empty() {
            return Err(AdapterError::Inventory(
                "version output was empty".to_owned(),
            ));
        }
        versions.push(text);
        outputs.push(output);
    }
    let version = versions.join("; ");
    let name = match flavor {
        TestFlavor::Rust => "Cargo/libtest",
        TestFlavor::Python => "Python/pytest",
        TestFlavor::CanonicalArtifact => "Python/canonical-artifact-checker",
        TestFlavor::IndependentCheck => "Python/independent-checker",
        TestFlavor::Generator => "Python/registered-generator",
    };
    let commands = specs
        .iter()
        .map(|spec| observe_command(spec, environment_observation))
        .collect();
    Ok((
        ToolObservation {
            name: name.to_owned(),
            version: version.clone(),
            identity_sha256: domain_hash("proofbound-tool-identity/1", version.as_bytes()),
        },
        outputs,
        commands,
    ))
}

fn run_rust_tests<E: Executor>(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
    original_root: &Path,
    shadow_root: &Path,
    environment: &BTreeMap<String, String>,
    executor: &mut E,
    deadline: Deadline,
) -> Result<TestRunResult, AdapterError> {
    let manifest =
        unit.operation.manifest.as_deref().ok_or_else(|| {
            AdapterError::Unit("cargo-test requires operation.manifest".to_owned())
        })?;
    let shadow_manifest = shadow_path(shadow_root, manifest)?;
    if shadow_manifest.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml") {
        return Err(AdapterError::Unit(
            "cargo-test manifest must be named Cargo.toml".to_owned(),
        ));
    }
    let package =
        unit.operation.package.as_deref().ok_or_else(|| {
            AdapterError::Unit("cargo-test requires operation.package".to_owned())
        })?;
    if !safe_atom(package) {
        return Err(AdapterError::Unit(format!(
            "invalid Cargo package `{package}`"
        )));
    }
    let selectors: Vec<String> = unit
        .operation
        .targets
        .iter()
        .filter(|target| target.starts_with('-'))
        .cloned()
        .collect();
    let named_targets: Vec<String> = unit
        .operation
        .targets
        .iter()
        .filter(|target| !target.starts_with('-'))
        .cloned()
        .collect();
    for selector in &selectors {
        validate_cargo_selector(selector)?;
    }
    for target in &named_targets {
        if !safe_test_tail(target) {
            return Err(AdapterError::Unit(format!(
                "invalid Rust test target `{target}`"
            )));
        }
    }
    let mut args = vec![
        "test".to_owned(),
        "--no-run".to_owned(),
        "--message-format=json".to_owned(),
        "--manifest-path".to_owned(),
        shadow_manifest.to_string_lossy().into_owned(),
        "--package".to_owned(),
        package.to_owned(),
    ];
    args.extend(selectors);
    args.extend(unit.operation.arguments.clone());
    let compile_spec = ProcessSpec {
        program: "cargo".to_owned(),
        args,
    };
    let compile_output = executor.run(
        &compile_spec,
        shadow_root,
        environment,
        deadline.remaining()?,
    )?;
    ensure_success(&compile_spec, &compile_output)?;
    let binaries = parse_cargo_test_binaries(&compile_output.stdout, shadow_root)?;
    if binaries.is_empty() {
        return Err(AdapterError::Inventory(
            "Cargo produced no test executables".to_owned(),
        ));
    }

    let environment_observation = observe_environment(environment, &unit.environment_allowlist);
    let mut commands = vec![observe_command(&compile_spec, &environment_observation)];
    let mut outputs = vec![compile_output];
    let mut discovered = BTreeMap::<String, RustTestNode>::new();
    for binary in binaries {
        let spec = ProcessSpec {
            program: binary.executable.to_string_lossy().into_owned(),
            args: vec![
                "--list".to_owned(),
                "--format".to_owned(),
                "terse".to_owned(),
            ],
        };
        let output = executor.run(&spec, shadow_root, environment, deadline.remaining()?)?;
        ensure_success(&spec, &output)?;
        for test in parse_libtest_inventory(&output.stdout)? {
            let canonical = format!("{}::{test}", binary.target);
            if discovered
                .insert(
                    canonical.clone(),
                    RustTestNode {
                        canonical: canonical.clone(),
                        executable: binary.executable.clone(),
                        libtest_name: test,
                    },
                )
                .is_some()
            {
                return Err(AdapterError::Inventory(format!(
                    "duplicate collected Rust test `{canonical}`"
                )));
            }
        }
        commands.push(observe_command(&spec, &environment_observation));
        outputs.push(output);
    }
    let execution_nodes: Vec<RustTestNode>;
    let inventory: Vec<String>;
    if unit.kind == EvidenceKind::MutationWitness {
        let registry = load_mutation_registry(original_root, &unit.inputs)?;
        let ids: Vec<_> = registry
            .mutations
            .iter()
            .map(|mutation| mutation.id.clone())
            .collect();
        exact_set("mutation registry", &unit.expected_inventory, &ids)?;
        let configured_tails: Vec<_> = registry
            .mutations
            .iter()
            .map(|mutation| {
                mutation
                    .witness
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        exact_set(
            "mutation witness targets",
            &named_targets,
            &configured_tails,
        )?;
        execution_nodes = registry
            .mutations
            .iter()
            .map(|mutation| {
                discovered.get(&mutation.witness).cloned().ok_or_else(|| {
                    AdapterError::Inventory(format!(
                        "mutation `{}` witness `{}` was not collected",
                        mutation.id, mutation.witness
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        inventory = sorted_unique(ids, "mutation ids")?;
    } else {
        if !named_targets.is_empty() {
            return Err(AdapterError::Unit("named cargo targets are reserved for mutation-witness units; use expected_inventory for exact tests".to_owned()));
        }
        execution_nodes = resolve_expected_rust_tests(&unit.expected_inventory, &discovered)?;
        inventory = sorted_unique(unit.expected_inventory.clone(), "expected inventory")?;
    }
    if execution_nodes.is_empty() {
        return Err(AdapterError::Inventory(
            "configured test inventory is empty".to_owned(),
        ));
    }
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        for node in execution_nodes {
            let spec = ProcessSpec {
                program: node.executable.to_string_lossy().into_owned(),
                args: vec![
                    node.libtest_name,
                    "--exact".to_owned(),
                    "--nocapture".to_owned(),
                ],
            };
            let output = executor.run(&spec, shadow_root, environment, deadline.remaining()?)?;
            ensure_success(&spec, &output)?;
            ensure_one_rust_test_ran(&node.canonical, &output)?;
            commands.push(observe_command(&spec, &environment_observation));
            outputs.push(output);
        }
    }
    Ok((commands, outputs, inventory))
}

#[derive(Clone, Debug)]
struct RustTestBinary {
    target: String,
    executable: PathBuf,
}

#[derive(Clone, Debug)]
struct RustTestNode {
    canonical: String,
    executable: PathBuf,
    libtest_name: String,
}

fn parse_cargo_test_binaries(
    bytes: &[u8],
    shadow_root: &Path,
) -> Result<Vec<RustTestBinary>, AdapterError> {
    let shadow_root = shadow_root.canonicalize().map_err(AdapterError::Io)?;
    let mut binaries = BTreeMap::new();
    for (line_number, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_slice(line).map_err(|error| {
            AdapterError::Inventory(format!("cargo JSON line {}: {error}", line_number + 1))
        })?;
        let reason = value
            .get("reason")
            .and_then(Value::as_str)
            .ok_or_else(|| AdapterError::Inventory("cargo message has no reason".to_owned()))?;
        match reason {
            "compiler-artifact" => {
                let Some(executable) = value.get("executable").and_then(Value::as_str) else {
                    continue;
                };
                let profile_test = value
                    .pointer("/profile/test")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !profile_test {
                    continue;
                }
                let target = value
                    .pointer("/target/name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AdapterError::Inventory("Cargo test artifact has no target name".to_owned())
                    })?;
                if !safe_atom(target) {
                    return Err(AdapterError::Inventory(format!(
                        "unsafe Cargo target `{target}`"
                    )));
                }
                let executable = PathBuf::from(executable)
                    .canonicalize()
                    .map_err(AdapterError::Io)?;
                if !executable.starts_with(&shadow_root) || !executable.is_file() {
                    return Err(AdapterError::Inventory(
                        "Cargo test executable escaped the shadow project".to_owned(),
                    ));
                }
                if binaries.insert(target.to_owned(), executable).is_some() {
                    return Err(AdapterError::Inventory(format!(
                        "duplicate Cargo test target `{target}`"
                    )));
                }
            }
            "build-finished" => {
                if value.get("success").and_then(Value::as_bool) != Some(true) {
                    return Err(AdapterError::Inventory(
                        "Cargo reported an unsuccessful build".to_owned(),
                    ));
                }
            }
            "compiler-message" | "build-script-executed" | "artifact" => {}
            other => {
                return Err(AdapterError::Inventory(format!(
                    "unsupported Cargo JSON reason `{other}`"
                )));
            }
        }
    }
    Ok(binaries
        .into_iter()
        .map(|(target, executable)| RustTestBinary { target, executable })
        .collect())
}

fn parse_libtest_inventory(bytes: &[u8]) -> Result<Vec<String>, AdapterError> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| AdapterError::Inventory(error.to_string()))?;
    let mut tests = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let Some(name) = line.strip_suffix(": test") else {
            if line.ends_with(": benchmark") {
                continue;
            }
            return Err(AdapterError::Inventory(format!(
                "unrecognized libtest inventory line `{line}`"
            )));
        };
        if !safe_libtest_name(name) {
            return Err(AdapterError::Inventory(format!(
                "unsafe libtest name `{name}`"
            )));
        }
        tests.push(name.to_owned());
    }
    sorted_unique(tests, "libtest inventory")
}

fn resolve_expected_rust_tests(
    expected: &[String],
    discovered: &BTreeMap<String, RustTestNode>,
) -> Result<Vec<RustTestNode>, AdapterError> {
    expected
        .iter()
        .map(|name| {
            discovered.get(name).cloned().ok_or_else(|| {
                AdapterError::Inventory(format!("configured Rust test `{name}` was not collected"))
            })
        })
        .collect()
}

fn ensure_one_rust_test_ran(name: &str, output: &ProcessOutput) -> Result<(), AdapterError> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !(text.contains("1 passed") && text.contains("0 failed")) {
        return Err(AdapterError::Inventory(format!(
            "Rust test `{name}` did not report exactly one passing test"
        )));
    }
    Ok(())
}

fn validate_cargo_selector(selector: &str) -> Result<(), AdapterError> {
    let valid = matches!(
        selector,
        "--lib" | "--bins" | "--tests" | "--all-targets" | "--examples" | "--benches"
    ) || ["--test=", "--bin=", "--example=", "--bench="]
        .iter()
        .any(|prefix| selector.strip_prefix(prefix).is_some_and(safe_atom));
    if !valid {
        return Err(AdapterError::Unit(format!(
            "unsupported Cargo target selector `{selector}`"
        )));
    }
    Ok(())
}

fn run_python_tests<E: Executor>(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
    shadow_root: &Path,
    environment: &BTreeMap<String, String>,
    executor: &mut E,
    deadline: Deadline,
) -> Result<TestRunResult, AdapterError> {
    let manifest = unit
        .operation
        .manifest
        .as_deref()
        .ok_or_else(|| AdapterError::Unit("pytest operation requires a manifest".to_owned()))?;
    let shadow_manifest = shadow_path(shadow_root, manifest)?;
    if shadow_manifest.file_name().and_then(|name| name.to_str()) != Some("pyproject.toml") {
        return Err(AdapterError::Unit(
            "pytest manifest must be pyproject.toml".to_owned(),
        ));
    }
    if unit.operation.paths.is_empty() {
        return Err(AdapterError::Unit(
            "pytest operation requires at least one collection path".to_owned(),
        ));
    }
    let mut collection_paths = Vec::new();
    for path in &unit.operation.paths {
        collection_paths.push(
            shadow_path(shadow_root, path)?
                .to_string_lossy()
                .into_owned(),
        );
    }
    let mut args = vec![
        "-m".to_owned(),
        "pytest".to_owned(),
        "--collect-only".to_owned(),
        "-q".to_owned(),
        "-p".to_owned(),
        "no:cacheprovider".to_owned(),
        "--rootdir".to_owned(),
        shadow_manifest
            .parent()
            .expect("manifest parent")
            .to_string_lossy()
            .into_owned(),
    ];
    args.extend(collection_paths);
    args.extend(unit.operation.arguments.clone());
    let collection_spec = ProcessSpec {
        program: "python3".to_owned(),
        args,
    };
    let collection_output = executor.run(
        &collection_spec,
        shadow_root,
        environment,
        deadline.remaining()?,
    )?;
    ensure_success(&collection_spec, &collection_output)?;
    let discovered = parse_pytest_inventory(&collection_output.stdout, shadow_root)?;
    let selected = resolve_python_targets(
        &unit.operation.targets,
        &unit.expected_inventory,
        &discovered,
    )?;
    let inventory = selected
        .iter()
        .map(|node| node.canonical.clone())
        .collect::<Vec<_>>();
    let inventory = sorted_unique(inventory, "pytest selected inventory")?;
    let environment_observation = observe_environment(environment, &unit.environment_allowlist);
    let mut commands = vec![observe_command(&collection_spec, &environment_observation)];
    let mut outputs = vec![collection_output];
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        for node in selected {
            let spec = ProcessSpec {
                program: "python3".to_owned(),
                args: vec![
                    "-m".to_owned(),
                    "pytest".to_owned(),
                    "-q".to_owned(),
                    "-p".to_owned(),
                    "no:cacheprovider".to_owned(),
                    "--rootdir".to_owned(),
                    shadow_manifest
                        .parent()
                        .expect("manifest parent")
                        .to_string_lossy()
                        .into_owned(),
                    node.node_id,
                ],
            };
            let output = executor.run(&spec, shadow_root, environment, deadline.remaining()?)?;
            ensure_success(&spec, &output)?;
            ensure_one_python_test_ran(&node.canonical, &output)?;
            commands.push(observe_command(&spec, &environment_observation));
            outputs.push(output);
        }
    }
    Ok((commands, outputs, inventory))
}

fn run_python_checker<E: Executor>(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
    shadow_root: &Path,
    environment: &BTreeMap<String, String>,
    executor: &mut E,
    deadline: Deadline,
) -> Result<TestRunResult, AdapterError> {
    let checker = unit
        .operation
        .checker
        .as_deref()
        .ok_or_else(|| AdapterError::Unit("checker operation requires a checker".to_owned()))?;
    let shadow_checker = shadow_path(shadow_root, checker)?;
    if !shadow_checker.is_file()
        || shadow_checker.extension().and_then(|value| value.to_str()) != Some("py")
    {
        return Err(AdapterError::UnsafePath(checker.to_owned()));
    }

    // Arguments remain byte-for-byte the registered manifest values. Resolve
    // each one first so a checker invocation cannot be directed outside the
    // shadow checkout, including through a symlink.
    for argument in &unit.operation.arguments {
        let path = shadow_path(shadow_root, argument)?;
        if !path.is_file() && !path.is_dir() {
            return Err(AdapterError::UnsafePath(argument.clone()));
        }
    }
    for path in &unit.operation.paths {
        let _ = shadow_path(shadow_root, path)?;
    }

    let inventory = sorted_unique(unit.expected_inventory.clone(), "checker inventory")?;
    let mut commands = Vec::new();
    let mut outputs = Vec::new();
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        let mut args = vec![shadow_checker.to_string_lossy().into_owned()];
        args.extend(unit.operation.arguments.clone());
        let spec = ProcessSpec {
            program: "python3".to_owned(),
            args,
        };
        let output = executor.run(&spec, shadow_root, environment, deadline.remaining()?)?;
        ensure_success(&spec, &output)?;
        let environment_observation = observe_environment(environment, &unit.environment_allowlist);
        commands.push(observe_command(&spec, &environment_observation));
        outputs.push(output);
    }
    Ok((commands, outputs, inventory))
}

fn run_python_generator<E: Executor>(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
    execution_root: &Path,
    environment: &BTreeMap<String, String>,
    executor: &mut E,
    deadline: Deadline,
) -> Result<TestRunResult, AdapterError> {
    let checker =
        unit.operation.checker.as_deref().ok_or_else(|| {
            AdapterError::Unit("generator operation requires a checker".to_owned())
        })?;
    let checker_path = shadow_path(execution_root, checker)?;
    if !checker_path.is_file()
        || checker_path.extension().and_then(|value| value.to_str()) != Some("py")
    {
        return Err(AdapterError::UnsafePath(checker.to_owned()));
    }

    let inventory = sorted_unique(unit.outputs.clone(), "generator output inventory")?;
    if request.operation == "inventory" {
        return Ok((Vec::new(), Vec::new(), inventory));
    }

    let before = if matches!(request.operation.as_str(), "check" | "reproduce") {
        Some(collect_exact_outputs(execution_root, &unit.outputs)?)
    } else {
        None
    };
    let mut args = vec![checker_path.to_string_lossy().into_owned()];
    if request.operation == "update" {
        args.push("--update".to_owned());
    }
    let spec = ProcessSpec {
        program: "python3".to_owned(),
        args,
    };
    let output = executor.run(&spec, execution_root, environment, deadline.remaining()?)?;
    ensure_success(&spec, &output)?;
    let after = collect_exact_outputs(execution_root, &unit.outputs)?;
    if before.as_ref().is_some_and(|before| before != &after) {
        return Err(AdapterError::ToolFailed(
            "verify-only generator changed a declared output in its disposable checkout".to_owned(),
        ));
    }

    let environment_observation = observe_environment(environment, &unit.environment_allowlist);
    Ok((
        vec![observe_command(&spec, &environment_observation)],
        vec![output],
        inventory,
    ))
}

fn validate_artifact_checker_report(
    bytes: &[u8],
    unit: &EvidenceUnitManifest,
    shadow_root: &Path,
) -> Result<(ArtifactBindingObservation, Vec<String>), AdapterError> {
    if bytes.is_empty() || bytes.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(AdapterError::Inventory(
            "canonical checker result is empty or oversized".to_owned(),
        ));
    }
    let report: ArtifactCheckerReport = serde_json::from_slice(bytes).map_err(|error| {
        AdapterError::Inventory(format!("invalid canonical checker result: {error}"))
    })?;
    if canonical_json(&report).map_err(|error| AdapterError::Internal(error.to_string()))? != bytes
    {
        return Err(AdapterError::Inventory(
            "canonical checker result must be canonical JSON with no trailing bytes".to_owned(),
        ));
    }
    if report.schema != "proofbound-artifact-check-result/1" || !report.accepted {
        return Err(AdapterError::Inventory(
            "canonical checker did not return an accepted v1 result".to_owned(),
        ));
    }

    if unit.theorem.as_deref().is_none_or(str::is_empty) {
        return Err(AdapterError::Unit(
            "artifact-soundness unit must name its audited theorem".to_owned(),
        ));
    }
    let expected_inventory = sorted_unique(
        unit.expected_inventory.clone(),
        "artifact expected inventory",
    )?;
    let reported_inventory = sorted_unique(report.inventory, "artifact checker result inventory")?;
    if reported_inventory != expected_inventory {
        return Err(AdapterError::Inventory(
            "canonical checker result inventory does not match expected_inventory".to_owned(),
        ));
    }

    validate_relative_path(&report.artifact_logical_name)?;
    if !unit
        .inputs
        .iter()
        .any(|input| input == &report.artifact_logical_name)
        || !unit
            .operation
            .arguments
            .iter()
            .any(|argument| argument == &report.artifact_logical_name)
    {
        return Err(AdapterError::Inventory(
            "canonical checker artifact is not a registered input argument".to_owned(),
        ));
    }
    let artifact_path = shadow_path(shadow_root, &report.artifact_logical_name)?;
    if !artifact_path.is_file() {
        return Err(AdapterError::UnsafePath(report.artifact_logical_name));
    }
    let actual_sha256 = sha256_bytes(&fs::read(&artifact_path)?);
    if report.artifact_sha256 != actual_sha256 {
        return Err(AdapterError::Inventory(
            "canonical checker artifact digest does not match the checked input bytes".to_owned(),
        ));
    }
    Ok((
        ArtifactBindingObservation {
            artifact_logical_name: report.artifact_logical_name,
            artifact_sha256: actual_sha256,
        },
        reported_inventory,
    ))
}

#[derive(Clone, Debug)]
struct PythonTestNode {
    canonical: String,
    node_id: String,
}

fn parse_pytest_inventory(
    bytes: &[u8],
    shadow_root: &Path,
) -> Result<Vec<PythonTestNode>, AdapterError> {
    let shadow_root = shadow_root.canonicalize().map_err(AdapterError::Io)?;
    let text =
        std::str::from_utf8(bytes).map_err(|error| AdapterError::Inventory(error.to_string()))?;
    let mut result = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !line.contains("::") {
            if line.ends_with(" collected")
                || line.contains(" tests collected in ")
                || line.contains(" test collected in ")
                || line.starts_with('=')
            {
                continue;
            }
            return Err(AdapterError::Inventory(format!(
                "unrecognized pytest collection line `{line}`"
            )));
        }
        let (file, suffix) = line.split_once("::").expect("contains delimiter");
        let path = PathBuf::from(file);
        let absolute = if path.is_absolute() {
            path
        } else {
            shadow_root.join(path)
        };
        let canonical_path = absolute.canonicalize().map_err(AdapterError::Io)?;
        if !canonical_path.starts_with(&shadow_root)
            || canonical_path.extension().and_then(|value| value.to_str()) != Some("py")
        {
            return Err(AdapterError::Inventory(format!(
                "pytest node escaped shadow project: `{line}`"
            )));
        }
        let stem = canonical_path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| AdapterError::Inventory(format!("invalid pytest path `{file}`")))?;
        if !safe_pytest_suffix(suffix) || !safe_atom(stem) {
            return Err(AdapterError::Inventory(format!(
                "invalid pytest node `{line}`"
            )));
        }
        result.push(PythonTestNode {
            canonical: format!("{stem}::{suffix}"),
            node_id: format!("{}::{suffix}", canonical_path.to_string_lossy()),
        });
    }
    result.sort_by(|left, right| left.canonical.cmp(&right.canonical));
    if result
        .windows(2)
        .any(|pair| pair[0].canonical == pair[1].canonical)
    {
        return Err(AdapterError::Inventory(
            "duplicate normalized pytest node (file stems must be unique per unit)".to_owned(),
        ));
    }
    Ok(result)
}

fn resolve_python_targets(
    targets: &[String],
    expected: &[String],
    discovered: &[PythonTestNode],
) -> Result<Vec<PythonTestNode>, AdapterError> {
    if expected.is_empty() || targets.is_empty() {
        return Err(AdapterError::Inventory(
            "pytest targets and expected_inventory must be non-empty".to_owned(),
        ));
    }
    let mut selected = Vec::new();
    for target in targets {
        if !safe_test_tail(target) {
            return Err(AdapterError::Unit(format!(
                "invalid pytest target `{target}`"
            )));
        }
        let matches: Vec<_> = discovered
            .iter()
            .filter(|node| node.canonical.rsplit("::").next() == Some(target.as_str()))
            .cloned()
            .collect();
        if matches.len() != 1 {
            return Err(AdapterError::Inventory(format!(
                "pytest target `{target}` resolved to {} nodes",
                matches.len()
            )));
        }
        selected.push(matches.into_iter().next().expect("one match"));
    }
    let actual: Vec<_> = selected.iter().map(|node| node.canonical.clone()).collect();
    exact_set("pytest inventory", expected, &actual)?;
    selected.sort_by(|left, right| left.canonical.cmp(&right.canonical));
    Ok(selected)
}

fn ensure_one_python_test_ran(name: &str, output: &ProcessOutput) -> Result<(), AdapterError> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !text.contains("1 passed") || text.contains(" failed") {
        return Err(AdapterError::Inventory(format!(
            "pytest node `{name}` did not report exactly one passing test"
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationRegistry {
    schema: String,
    subject: String,
    mutations: Vec<MutationEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationEntry {
    id: String,
    guard: String,
    mutant: String,
    witness: String,
    affected_claims: Vec<String>,
}

fn load_mutation_registry(
    root: &Path,
    inputs: &[String],
) -> Result<MutationRegistry, AdapterError> {
    let mut registries = Vec::new();
    for input in inputs.iter().filter(|path| path.ends_with(".toml")) {
        let bytes = read_safe_file(root, input, MAX_REQUEST_BYTES)?;
        let Ok(value) = toml::from_str::<toml::Value>(
            std::str::from_utf8(&bytes).map_err(|error| AdapterError::Unit(error.to_string()))?,
        ) else {
            continue;
        };
        if value.get("schema").and_then(toml::Value::as_str)
            == Some("proofbound-mutation-registry/1")
        {
            registries.push(
                toml::from_str::<MutationRegistry>(std::str::from_utf8(&bytes).unwrap())
                    .map_err(|error| AdapterError::Unit(error.to_string()))?,
            );
        }
    }
    if registries.len() != 1 {
        return Err(AdapterError::Unit(format!(
            "mutation-witness unit must supply exactly one mutation registry, found {}",
            registries.len()
        )));
    }
    let registry = registries.pop().expect("one registry");
    if registry.schema != "proofbound-mutation-registry/1"
        || registry.subject.trim().is_empty()
        || registry.mutations.is_empty()
    {
        return Err(AdapterError::Unit(
            "mutation registry header is invalid".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut witnesses = BTreeSet::new();
    for mutation in &registry.mutations {
        if !safe_id(&mutation.id)
            || mutation.guard.trim().is_empty()
            || !safe_symbol(&mutation.mutant)
            || !safe_symbol(&mutation.witness)
            || mutation.affected_claims.is_empty()
            || !ids.insert(&mutation.id)
            || !witnesses.insert(&mutation.witness)
        {
            return Err(AdapterError::Unit(format!(
                "invalid or duplicate mutation entry `{}`",
                mutation.id
            )));
        }
    }
    Ok(registry)
}

fn ensure_success(spec: &ProcessSpec, output: &ProcessOutput) -> Result<(), AdapterError> {
    if output.truncated {
        return Err(AdapterError::Inventory(format!(
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

fn exact_set(label: &str, expected: &[String], actual: &[String]) -> Result<(), AdapterError> {
    let expected = sorted_unique(expected.to_vec(), label)?;
    let actual = sorted_unique(actual.to_vec(), label)?;
    if expected != actual {
        let missing: Vec<_> = expected
            .iter()
            .filter(|item| !actual.contains(item))
            .cloned()
            .collect();
        let extra: Vec<_> = actual
            .iter()
            .filter(|item| !expected.contains(item))
            .cloned()
            .collect();
        return Err(AdapterError::Inventory(format!(
            "{label} mismatch; missing={missing:?}, extra={extra:?}"
        )));
    }
    Ok(())
}

fn sorted_unique(mut values: Vec<String>, label: &str) -> Result<Vec<String>, AdapterError> {
    if values.len() > MAX_INVENTORY {
        return Err(AdapterError::Inventory(format!(
            "{label} exceeds {MAX_INVENTORY} items"
        )));
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AdapterError::Inventory(format!(
            "{label} contains duplicates"
        )));
    }
    Ok(values)
}

fn evidence_kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Theorem => "theorem",
        EvidenceKind::ArtifactSoundness => "artifact-soundness",
        EvidenceKind::TrustedTranscription => "trusted-transcription",
        EvidenceKind::SourceRefinement => "source-refinement",
        EvidenceKind::BoundedCheck => "bounded-check",
        EvidenceKind::IndependentCheck => "independent-check",
        EvidenceKind::ExhaustiveCheck => "exhaustive-check",
        EvidenceKind::PropertyTest => "property-test",
        EvidenceKind::ExampleTest => "example-test",
        EvidenceKind::MutationWitness => "mutation-witness",
        EvidenceKind::Review => "review",
        EvidenceKind::Assumption => "assumption",
        EvidenceKind::Open => "open",
    }
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
    let Some(marker) = value.find("/proofbound-test-") else {
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

fn observe_environment(
    environment: &BTreeMap<String, String>,
    declared: &[String],
) -> Vec<EnvironmentObservation> {
    let declared: BTreeSet<_> = declared.iter().map(String::as_str).collect();
    environment
        .iter()
        .map(|(name, value)| EnvironmentObservation {
            name: name.clone(),
            value_sha256: Some(domain_hash(
                "proofbound-environment-value/1",
                value.as_bytes(),
            )),
            secret: is_secret_name(name)
                || (declared.contains(name.as_str()) && is_secret_name(name)),
        })
        .collect()
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
    for marker in ["; finished in ", " passed in ", " tests collected in "] {
        if let Some(index) = line.find(marker) {
            let prefix = &line[..index + marker.len()];
            return format!("{prefix}<TIME>");
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
    ToolObservation {
        name: "proofbound-adapter-test".to_owned(),
        identity_sha256: domain_hash(
            "proofbound-adapter-identity/1",
            format!("proofbound-adapter-test\0{version}").as_bytes(),
        ),
        version,
    }
}

fn allowed_environment(names: &[String]) -> Result<BTreeMap<String, String>, AdapterError> {
    let mut result = BTreeMap::new();
    for name in names {
        if !valid_environment_name(name) {
            return Err(AdapterError::Unit(format!(
                "invalid environment variable `{name}`"
            )));
        }
        if let Ok(value) = std::env::var(name) {
            result.insert(name.clone(), value);
        }
    }
    Ok(result)
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
                let entry = entry.map_err(walk_error)?;
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
            "overlapping inputs name an artifact twice".to_owned(),
        ));
    }
    Ok(artifacts)
}

fn collect_exact_outputs(
    root: &Path,
    outputs: &[String],
) -> Result<Vec<ArtifactObservation>, AdapterError> {
    let mut artifacts = Vec::with_capacity(outputs.len());
    for output in outputs {
        let path = resolve_existing(root, output)?;
        if !path.is_file() {
            return Err(AdapterError::UnsafePath(output.clone()));
        }
        artifacts.push(hash_artifact(root, &path)?);
    }
    artifacts.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    if artifacts
        .windows(2)
        .any(|pair| pair[0].logical_name == pair[1].logical_name)
    {
        return Err(AdapterError::Unit(
            "generator output allowlist contains duplicates".to_owned(),
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

fn read_safe_file(root: &Path, relative: &str, max: u64) -> Result<Vec<u8>, AdapterError> {
    let path = resolve_existing(root, relative)?;
    if !path.is_file() || path.metadata()?.len() > max {
        return Err(AdapterError::UnsafePath(relative.to_owned()));
    }
    Ok(fs::read(path)?)
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

fn shadow_path(shadow_root: &Path, relative: &str) -> Result<PathBuf, AdapterError> {
    validate_relative_path(relative)?;
    let candidate = shadow_root.join(relative);
    reject_symlink_components(shadow_root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .map_err(|_| AdapterError::UnsafePath(relative.to_owned()))?;
    if !canonical.starts_with(shadow_root) {
        return Err(AdapterError::UnsafePath(relative.to_owned()));
    }
    Ok(canonical)
}

fn validate_relative_path(path: &str) -> Result<(), AdapterError> {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') {
        return Err(AdapterError::UnsafePath(path.to_owned()));
    }
    let path_buf = Path::new(path);
    if path_buf.is_absolute()
        || path_buf
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
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
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
        .prefix("proofbound-test-")
        .tempdir()?;
    let destination = temp.path().join("workspace");
    let project = destination.join("project");
    fs::create_dir_all(&project)?;
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
                .is_none_or(|relative| !should_exclude(relative))
        });
    for entry in walker {
        let entry = entry.map_err(walk_error)?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|_| AdapterError::UnsafePath(entry.path().display().to_string()))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            return Err(AdapterError::UnsafePath(relative.display().to_string()));
        }
        let target = project.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            let size = entry.metadata().map_err(walk_error)?.len();
            copied = copied
                .checked_add(size)
                .ok_or_else(|| AdapterError::Budget("copy size overflowed".to_owned()))?;
            if copied > disk_budget {
                return Err(AdapterError::Budget(format!(
                    "project shadow exceeds {disk_budget} bytes"
                )));
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), target)?;
        } else {
            return Err(AdapterError::UnsafePath(relative.display().to_string()));
        }
    }
    Ok(ShadowProject {
        _temp: temp,
        root: destination,
    })
}

fn should_exclude(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                ".git"
                    | "target"
                    | ".lake"
                    | ".proofbound"
                    | ".venv"
                    | "__pycache__"
                    | ".pytest_cache"
                    | ".mypy_cache"
                    | ".ruff_cache"
            )
        )
    })
}

fn directory_size(path: &Path) -> Result<u64, AdapterError> {
    let mut size = 0_u64;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry.map_err(walk_error)?;
        if entry.file_type().is_file() {
            size = size
                .checked_add(entry.metadata().map_err(walk_error)?.len())
                .ok_or_else(|| AdapterError::Budget("disk size overflowed".to_owned()))?;
        }
    }
    Ok(size)
}

fn walk_error(error: walkdir::Error) -> AdapterError {
    match error.into_io_error() {
        Some(error) => AdapterError::Io(error),
        None => AdapterError::Internal("directory traversal failed".to_owned()),
    }
}

fn safe_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}
fn safe_symbol(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.split("::").all(safe_atom)
}
fn safe_id(value: &str) -> bool {
    safe_atom(value)
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase())
}
fn safe_libtest_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.split("::").all(safe_test_tail)
}
fn safe_test_tail(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '[' | ']' | '.'))
}
fn safe_pytest_suffix(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && value.split("::").all(safe_test_tail)
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

fn require_unique(label: &str, values: &[String]) -> Result<(), AdapterError> {
    if values.len() > MAX_INVENTORY || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(AdapterError::Unit(format!(
            "{label} is too large or contains duplicates"
        )));
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

    fn checker_unit(adapter: &str, kind: &str, operation: &str) -> EvidenceUnitManifest {
        let mut value = json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "checker-unit",
            "adapter": adapter,
            "kind": kind,
            "claims": ["CLAIM-ONE"],
            "tier": 1,
            "operation": {
                "type": operation,
                "checker": "checker.py",
                "arguments": ["artifact.bin"]
            },
            "expected_inventory": ["published-artifact"],
            "inputs": ["artifact.bin", "checker.py"],
            "outputs": [],
            "environment_allowlist": [],
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1048576,
                "memory_bytes": 1048576
            }
        });
        if adapter == "canonical-artifact" {
            value["theorem"] = json!("Example.Claims.publishedMeaning");
        }
        serde_json::from_value(value).unwrap()
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

    fn generator_unit() -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/1",
            "id": "fixture-generator",
            "adapter": "python-test",
            "kind": "example-test",
            "claims": ["CLAIM-ONE"],
            "tier": 0,
            "operation": {
                "type": "generator",
                "checker": "generate.py",
                "arguments": []
            },
            "expected_inventory": ["fixtures/generated.bin"],
            "inputs": ["fixtures/generated.bin", "generate.py"],
            "outputs": ["fixtures/generated.bin"],
            "environment_allowlist": [],
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 1048576,
                "memory_bytes": 1048576
            }
        }))
        .unwrap()
    }

    fn request(adapter: &str, operation: &str, unit: &EvidenceUnitManifest) -> AdapterRequest {
        AdapterRequest {
            schema: PROTOCOL_SCHEMA.to_owned(),
            message_type: "request".to_owned(),
            request_id: "0123456789abcdef0123456789abcdef".to_owned(),
            adapter: adapter.to_owned(),
            operation: operation.to_owned(),
            project_root: ".".to_owned(),
            unit: serde_json::to_value(unit).unwrap(),
        }
    }

    #[test]
    fn parses_cargo_metadata_and_libtest_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("test-bin");
        fs::write(&executable, b"x").unwrap();
        let line = json!({"reason":"compiler-artifact","target":{"name":"crate_name"},"profile":{"test":true},"executable":executable});
        let finish = json!({"reason":"build-finished","success":true});
        let bytes = format!(
            "{}\n{}\n",
            serde_json::to_string(&line).unwrap(),
            serde_json::to_string(&finish).unwrap()
        );
        let binaries = parse_cargo_test_binaries(bytes.as_bytes(), temp.path()).unwrap();
        assert_eq!(binaries[0].target, "crate_name");
        assert_eq!(
            parse_libtest_inventory(b"module::one: test\nmodule::two: test\n").unwrap(),
            ["module::one", "module::two"]
        );
    }

    #[test]
    fn pytest_collection_is_normalized_and_exact() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("test_sample.py"), b"").unwrap();
        let nodes = parse_pytest_inventory(
            b"test_sample.py::test_one\ntest_sample.py::test_two\n",
            temp.path(),
        )
        .unwrap();
        let selected = resolve_python_targets(
            &["test_two".to_owned()],
            &["test_sample::test_two".to_owned()],
            &nodes,
        )
        .unwrap();
        assert_eq!(selected[0].canonical, "test_sample::test_two");
        assert!(
            resolve_python_targets(
                &["missing".to_owned()],
                &["test_sample::missing".to_owned()],
                &nodes
            )
            .is_err()
        );
    }

    #[test]
    fn pytest_collection_accepts_singular_summary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("test_sample.py"), b"").unwrap();
        let nodes = parse_pytest_inventory(
            b"test_sample.py::test_one\n1 test collected in 0.01s\n",
            temp.path(),
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].canonical, "test_sample::test_one");
    }

    #[test]
    fn dangerous_arguments_and_paths_fail_closed() {
        assert!(
            validate_arguments(TestFlavor::Rust, &["--target-dir=/outside".to_owned()]).is_err()
        );
        assert!(
            validate_arguments(TestFlavor::Python, &["-p".to_owned(), "evil".to_owned()]).is_err()
        );
        assert!(validate_relative_path("../outside").is_err());
        assert!(validate_cargo_selector("--manifest-path=/outside").is_err());
        assert!(
            validate_arguments(TestFlavor::IndependentCheck, &["../outside".to_owned()]).is_err()
        );
        assert!(should_exclude(Path::new(".venv/bin/python")));
        assert!(should_exclude(Path::new(
            ".proofbound/evidence/receipt.json"
        )));
    }

    #[test]
    fn checker_units_require_typed_bound_configuration() {
        let canonical = checker_unit("canonical-artifact", "artifact-soundness", "artifact-check");
        assert_eq!(
            validate_unit(
                &request("canonical-artifact", "check", &canonical),
                &canonical
            )
            .unwrap(),
            TestFlavor::CanonicalArtifact
        );
        let independent = checker_unit(
            "independent-check",
            "independent-check",
            "independent-check",
        );
        assert_eq!(
            validate_unit(
                &request("independent-check", "check", &independent),
                &independent
            )
            .unwrap(),
            TestFlavor::IndependentCheck
        );

        let mut no_inventory = independent.clone();
        no_inventory.expected_inventory.clear();
        assert!(matches!(
            validate_unit(
                &request("independent-check", "check", &no_inventory),
                &no_inventory
            ),
            Err(AdapterError::Inventory(_))
        ));

        let mut unbound_checker = independent.clone();
        unbound_checker.inputs.retain(|input| input != "checker.py");
        assert!(
            validate_unit(
                &request("independent-check", "check", &unbound_checker),
                &unbound_checker
            )
            .is_err()
        );

        let mut unbound_argument = independent.clone();
        unbound_argument
            .inputs
            .retain(|input| input != "artifact.bin");
        assert!(
            validate_unit(
                &request("independent-check", "check", &unbound_argument),
                &unbound_argument
            )
            .is_err()
        );

        let mut wrong_extension = independent.clone();
        wrong_extension.operation.checker = Some("checker.sh".to_owned());
        wrong_extension.inputs[1] = "checker.sh".to_owned();
        assert!(
            validate_unit(
                &request("independent-check", "check", &wrong_extension),
                &wrong_extension
            )
            .is_err()
        );

        let mut output = independent.clone();
        output.outputs.push("committed.json".to_owned());
        assert!(validate_unit(&request("independent-check", "check", &output), &output).is_err());
    }

    #[test]
    fn generator_unit_has_exact_outputs_and_reserved_update_switch() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("fixtures")).unwrap();
        fs::write(root.path().join("generate.py"), b"raise SystemExit(0)\n").unwrap();
        fs::write(root.path().join("fixtures/generated.bin"), b"fixture").unwrap();
        let unit = generator_unit();
        assert_eq!(
            validate_unit(&request("python-test", "check", &unit), &unit).unwrap(),
            TestFlavor::Generator
        );

        let mut fake = FakeExecutor::default();
        for stdout in [
            b"Python 3.12.0\n".as_slice(),
            b"fixtures match\n".as_slice(),
        ] {
            fake.outputs.push_back(ProcessOutput {
                status: Some(0),
                stdout: stdout.to_vec(),
                stderr: vec![],
                truncated: false,
                duration_ms: 1,
            });
        }
        let (observation, inventory) = execute_request(
            &request("python-test", "check", &unit),
            root.path(),
            &mut fake,
        )
        .unwrap();
        let observation = observation.unwrap();
        assert_eq!(inventory, ["fixtures/generated.bin"]);
        assert_eq!(observation.generated_artifacts.len(), 1);
        assert_eq!(
            observation.generated_artifacts[0].logical_name,
            inventory[0]
        );
        assert!(!fake.seen[1].args.contains(&"--update".to_owned()));

        let mut update = FakeExecutor::default();
        for stdout in [
            b"Python 3.12.0\n".as_slice(),
            b"fixtures reproduced\n".as_slice(),
        ] {
            update.outputs.push_back(ProcessOutput {
                status: Some(0),
                stdout: stdout.to_vec(),
                stderr: vec![],
                truncated: false,
                duration_ms: 1,
            });
        }
        let (observation, update_inventory) = execute_request(
            &request("python-test", "update", &unit),
            root.path(),
            &mut update,
        )
        .unwrap();
        assert!(observation.is_none(), "regeneration is not evidence");
        assert_eq!(update_inventory, inventory);
        assert_eq!(update.seen[1].args.last().unwrap(), "--update");

        let mut missing_output = unit.clone();
        missing_output.outputs.push("fixtures/extra.bin".to_owned());
        assert!(
            validate_unit(
                &request("python-test", "check", &missing_output),
                &missing_output
            )
            .is_err()
        );
    }

    #[test]
    fn mutation_registry_is_strict_and_binds_witnesses() {
        let registry: MutationRegistry = toml::from_str(
            r#"
schema = "proofbound-mutation-registry/1"
subject = "rust:crate::f"
[[mutations]]
id = "remove-guard"
guard = "guard"
mutant = "crate::mutants::without_guard"
witness = "crate::tests::detects_guard"
affected_claims = ["CLAIM-ONE"]
"#,
        )
        .unwrap();
        assert_eq!(registry.mutations[0].witness, "crate::tests::detects_guard");
        assert!(serde_json::from_value::<MutationRegistry>(json!({"schema":"proofbound-mutation-registry/1","subject":"s","mutations":[],"extra":1})).is_err());
    }

    #[test]
    fn canonical_request_rejects_whitespace_and_unknown_fields() {
        let request = json!({"schema":PROTOCOL_SCHEMA,"type":"request","request_id":"0123456789abcdef0123456789abcdef","adapter":"rust-test","operation":"check","project_root":".","unit":{}});
        let canonical = canonical_json(&request).unwrap();
        let parsed: AdapterRequest = serde_json::from_slice(&canonical).unwrap();
        assert!(validate_request(&parsed, &canonical).is_ok());
        for adapter in ["canonical-artifact", "independent-check"] {
            let mut checker_request = request.clone();
            checker_request["adapter"] = json!(adapter);
            let checker_canonical = canonical_json(&checker_request).unwrap();
            let checker_parsed: AdapterRequest =
                serde_json::from_slice(&checker_canonical).unwrap();
            assert!(validate_request(&checker_parsed, &checker_canonical).is_ok());
        }
        let mut spaced = canonical;
        spaced.push(b'\n');
        assert!(validate_request(&parsed, &spaced).is_err());
        let mut unknown = request;
        unknown["unknown"] = json!(true);
        assert_eq!(
            handle_request_bytes(&canonical_json(&unknown).unwrap()).diagnostics[0].code,
            "PB-TEST-1003"
        );
    }

    #[test]
    fn observation_shape_round_trips() {
        let observation = AdapterObservation {
            schema: OBSERVATION_SCHEMA.to_owned(),
            unit_id: "u".to_owned(),
            evidence_kind: "example-test".to_owned(),
            outcome: ObservationOutcome::Passed,
            input_artifacts: vec![],
            generated_artifacts: vec![],
            tool: ToolObservation {
                name: "pytest".to_owned(),
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
            artifact_binding: None,
        };
        let bytes = canonical_json(&observation).unwrap();
        assert_eq!(
            serde_json::from_slice::<AdapterObservation>(&bytes).unwrap(),
            observation
        );
    }

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
                .ok_or_else(|| AdapterError::Internal("fake exhausted".to_owned()))
        }
    }

    #[test]
    fn canonical_checker_runs_exact_registered_argv_without_shell() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("checker.py"), b"raise SystemExit(0)\n").unwrap();
        fs::write(root.path().join("artifact.bin"), b"artifact").unwrap();
        let unit = checker_unit("canonical-artifact", "artifact-soundness", "artifact-check");
        let mut fake = FakeExecutor::default();
        fake.outputs.push_back(ProcessOutput {
            status: Some(0),
            stdout: b"Python 3.12.0\n".to_vec(),
            stderr: vec![],
            truncated: false,
            duration_ms: 1,
        });
        fake.outputs.push_back(ProcessOutput {
            status: Some(0),
            stdout: canonical_json(&json!({
                "schema": "proofbound-artifact-check-result/1",
                "accepted": true,
                "artifact_logical_name": "artifact.bin",
                "artifact_sha256": sha256_bytes(b"artifact"),
                "inventory": ["published-artifact"]
            }))
            .unwrap(),
            stderr: vec![],
            truncated: false,
            duration_ms: 2,
        });

        let (observation, inventory) = execute_request(
            &request("canonical-artifact", "check", &unit),
            root.path(),
            &mut fake,
        )
        .unwrap();
        let observation = observation.unwrap();
        assert_eq!(inventory, ["published-artifact"]);
        assert_eq!(observation.inventory, inventory);
        assert_eq!(observation.generated_artifacts, []);
        assert_eq!(observation.input_artifacts.len(), 2);
        let binding = observation.artifact_binding.unwrap();
        assert_eq!(binding.artifact_logical_name, "artifact.bin");
        assert_eq!(binding.artifact_sha256, sha256_bytes(b"artifact"));
        assert_eq!(observation.commands.len(), 2);
        assert_eq!(observation.runs.len(), 2);
        assert_eq!(fake.seen.len(), 2);
        assert_eq!(fake.seen[0].program, "python3");
        assert_eq!(fake.seen[0].args, ["--version"]);
        assert_eq!(fake.seen[1].program, "python3");
        assert_eq!(fake.seen[1].args.len(), 2);
        assert!(fake.seen[1].args[0].ends_with("/checker.py"));
        assert_eq!(fake.seen[1].args[1], "artifact.bin");
    }

    #[test]
    fn canonical_checker_report_rejects_linkage_assertions_and_digest_drift() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("artifact.bin"), b"artifact").unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let unit = checker_unit("canonical-artifact", "artifact-soundness", "artifact-check");
        let valid = json!({
            "schema": "proofbound-artifact-check-result/1",
            "accepted": true,
            "artifact_logical_name": "artifact.bin",
            "artifact_sha256": sha256_bytes(b"artifact"),
            "inventory": ["published-artifact"]
        });
        assert!(
            validate_artifact_checker_report(
                &canonical_json(&valid).unwrap(),
                &unit,
                &canonical_root
            )
            .is_ok()
        );

        let mut wrong_digest = valid.clone();
        wrong_digest["artifact_sha256"] = json!(sha256_bytes(b"different"));
        assert!(
            validate_artifact_checker_report(
                &canonical_json(&wrong_digest).unwrap(),
                &unit,
                &canonical_root
            )
            .is_err(),
            "a checker-authored digest must match the adapter-recomputed input digest"
        );

        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("artifact_sha256");
        assert!(
            validate_artifact_checker_report(
                &canonical_json(&missing).unwrap(),
                &unit,
                &canonical_root
            )
            .is_err()
        );

        for forbidden in [
            "theorem",
            "claims",
            "canonical_payload",
            "schema_bound",
            "literal_claim_bound",
            "digest_bound",
            "reencoding_passed",
            "trailing_bytes_rejected",
        ] {
            let mut smuggled = valid.clone();
            smuggled[forbidden] = json!(true);
            assert!(
                validate_artifact_checker_report(
                    &canonical_json(&smuggled).unwrap(),
                    &unit,
                    &canonical_root
                )
                .is_err(),
                "checker-authored linkage field {forbidden} must be rejected"
            );
        }

        let mut noncanonical = canonical_json(&valid).unwrap();
        noncanonical.push(b'\n');
        assert!(validate_artifact_checker_report(&noncanonical, &unit, &canonical_root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn checker_symlink_is_rejected_before_execution() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("real.py"), b"raise SystemExit(0)\n").unwrap();
        symlink(root.path().join("real.py"), root.path().join("checker.py")).unwrap();
        fs::write(root.path().join("artifact.bin"), b"artifact").unwrap();
        let unit = checker_unit(
            "independent-check",
            "independent-check",
            "independent-check",
        );
        let mut fake = FakeExecutor::default();
        let result = run_python_checker(
            &request("independent-check", "check", &unit),
            &unit,
            root.path(),
            &BTreeMap::new(),
            &mut fake,
            Deadline {
                started: Instant::now(),
                budget_ms: 1_000,
            },
        );
        assert!(matches!(result, Err(AdapterError::UnsafePath(_))));
        assert!(fake.seen.is_empty());
    }

    #[test]
    fn fake_executor_observes_typed_argv_without_shell() {
        let mut fake = FakeExecutor::default();
        fake.outputs.push_back(ProcessOutput {
            status: Some(0),
            stdout: b"cargo 1.94.0\n".to_vec(),
            stderr: vec![],
            truncated: false,
            duration_ms: 1,
        });
        let environment = BTreeMap::new();
        let (tool, _, _) = tool_identity(
            TestFlavor::Rust,
            Path::new("."),
            &environment,
            &[],
            &mut fake,
        )
        .unwrap();
        assert!(tool.version.contains("cargo 1.94.0"));
        assert_eq!(fake.seen[0].program, "cargo");
        assert_eq!(fake.seen[0].args, ["--version"]);
    }
}
