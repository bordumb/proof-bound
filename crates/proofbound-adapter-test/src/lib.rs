//! Manifest-driven Rust/Python test, Python checker, generator, and trusted
//! transcription adapter.
//!
//! Collection is performed through Cargo/libtest and pytest metadata.  Source
//! text is never searched for test names.  Configured tests are resolved to one
//! and only one collected node and then executed individually, preventing a
//! successful command from silently skipping a target. Trusted transcription
//! uses a fixed two-command driver ABI in a disposable shadow and compares all
//! four byte identities independently.

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
    AdapterDiagnostic, AdapterKind, AdapterRequest, AdapterResponse, BindingMode, EvidenceKind,
    EvidenceUnitManifest, MutationReplaySchema, OperationKind,
    TRANSLATION_RESERVED_PATH_COMPONENTS, TranscriptionDriverAbi, TrustedTranscriptionSchema,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

pub const PROTOCOL_SCHEMA: &str = "proofbound-adapter-protocol/1";
pub const OBSERVATION_SCHEMA: &str = "proofbound-adapter-observation/2";
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INVENTORY: usize = 100_000;
const TRUSTED_TRANSCRIPTION_SCHEMA: &str = "proofbound-trusted-transcription/1";
const TRANSCRIPTION_DRIVER_ABI: &str = "proofbound-transcription-driver/1";
const TRANSCRIPTION_ROLE_DOMAIN: &str = "proofbound-transcription-tcb-role/1";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_transcription: Option<TrustedTranscriptionObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation_replay: Option<MutationReplayObservation>,
}

/// Exact facts observed while replaying one registered source mutation.
///
/// The adapter reports byte identities and run positions only. The compiler
/// independently derives the mutation registration and the expected-failure
/// policy before admitting these facts into canonical evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReplayObservation {
    pub schema: String,
    pub mutation_id: String,
    pub registry: ArtifactObservation,
    pub target_preimage: ArtifactObservation,
    pub mutant_artifact: ArtifactObservation,
    pub target_postimage: ArtifactObservation,
    pub witness_source: ArtifactObservation,
    pub check_id: String,
    pub affected_claims: Vec<String>,
    pub baseline_run_index: usize,
    pub expected_failure: ExpectedFailureObservation,
}

/// One deliberately non-zero child execution, retained truthfully in the
/// observation rather than converted into a synthetic success.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFailureObservation {
    pub run_index: usize,
    pub allowed_exit_codes: Vec<i32>,
}

/// Facts reported by a canonical artifact checker and independently validated
/// against the registered unit and input bytes by this adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBindingObservation {
    pub artifact_logical_name: String,
    pub artifact_sha256: String,
}

/// Independently observed byte identities and role-separated tool identities
/// for the degraded trusted-transcription route.
///
/// This deliberately contains no success boolean, claim identifier, binding
/// assertion, or TCB node identifier. The compiler derives validity and its
/// TCB nodes from these facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTranscriptionObservation {
    pub schema: String,
    pub source: ArtifactObservation,
    pub committed_transcription: ArtifactObservation,
    pub transcribed_candidate: ArtifactObservation,
    pub reencoded_source: ArtifactObservation,
    pub driver: ArtifactObservation,
    pub driver_abi: String,
    pub source_format: String,
    pub transcribed_format: String,
    pub transcriber_role_identity: String,
    pub reencoder_role_identity: String,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IndependentCheckerReport {
    schema: String,
    accepted: bool,
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

struct RustRunResult {
    commands: Vec<CommandObservation>,
    outputs: Vec<ProcessOutput>,
    inventory: Vec<String>,
    mutation_replay: Option<MutationReplayObservation>,
}

#[derive(Clone, Copy)]
struct RustRunContext<'a> {
    original_root: &'a Path,
    baseline_root: &'a Path,
    mutant_root: Option<&'a Path>,
    environment: &'a BTreeMap<String, String>,
    deadline: Deadline,
}

struct TranscriptionRunResult {
    commands: Vec<CommandObservation>,
    outputs: Vec<ProcessOutput>,
    inventory: Vec<String>,
    facts: TranscriptionFacts,
}

struct TranscriptionFacts {
    generated_artifacts: Vec<ArtifactObservation>,
    unit_id: String,
    source: ArtifactObservation,
    committed_transcription: ArtifactObservation,
    driver: ArtifactObservation,
    driver_abi: String,
    source_format: String,
    transcribed_format: String,
}

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
                "reproduce the exact registered operation and fix its failure",
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
            "rust-test"
                | "python-test"
                | "canonical-artifact"
                | "independent-check"
                | "trusted-transcription"
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
    let reviewed_tree_before = (unit.kind == EvidenceKind::MutationWitness)
        .then(|| snapshot_mutation_tree(&root))
        .transpose()?;
    if request.operation == "update" && flavor != TestFlavor::Generator {
        return Err(AdapterError::Request(
            "this adapter route has no committed generated artifacts; update is unsupported"
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
        TestFlavor::CanonicalArtifact
        | TestFlavor::IndependentCheck
        | TestFlavor::Generator
        | TestFlavor::TrustedTranscription => {
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
        if let Some(before) = &reviewed_tree_before {
            ensure_tree_unchanged(
                "mutation replay tool probe",
                before,
                &snapshot_mutation_tree(&root)?,
            )?;
        }
        return Ok((None, Vec::new()));
    }
    let shadow = if request.operation == "update" && flavor == TestFlavor::Generator {
        None
    } else {
        Some(shadow_project(&root, budget.disk_bytes)?)
    };
    let mutant_shadow = if unit.kind == EvidenceKind::MutationWitness {
        Some(shadow_project(&root, budget.disk_bytes)?)
    } else {
        None
    };
    let execution_root = match &shadow {
        Some(shadow) => shadow.path().join("project").canonicalize()?,
        None => root.clone(),
    };
    let mutant_execution_root = mutant_shadow
        .as_ref()
        .map(|shadow| shadow.path().join("project").canonicalize())
        .transpose()?;
    let deadline = Deadline {
        started,
        budget_ms: budget.time_ms,
    };
    let mut transcription_facts = None;
    let mut mutation_replay = None;
    let (mut commands, mut outputs, mut inventory) = match flavor {
        TestFlavor::Rust => {
            let context = RustRunContext {
                original_root: &root,
                baseline_root: &execution_root,
                mutant_root: mutant_execution_root.as_deref(),
                environment: &environment,
                deadline,
            };
            let result = run_rust_tests(request, &unit, executor, context)?;
            mutation_replay = result.mutation_replay;
            (result.commands, result.outputs, result.inventory)
        }
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
        TestFlavor::TrustedTranscription => {
            let result = run_trusted_transcription(
                request,
                &unit,
                &execution_root,
                &environment,
                executor,
                deadline,
            )?;
            transcription_facts = Some(result.facts);
            (result.commands, result.outputs, result.inventory)
        }
    };
    let artifact_binding = match flavor {
        TestFlavor::CanonicalArtifact => {
            let output = outputs.last().ok_or_else(|| {
                AdapterError::Inventory("canonical checker produced no result".to_owned())
            })?;
            let (binding, reported_inventory) =
                validate_artifact_checker_report(&output.stdout, &unit, &execution_root)?;
            inventory = reported_inventory;
            Some(binding)
        }
        TestFlavor::IndependentCheck => {
            let output = outputs.last().ok_or_else(|| {
                AdapterError::Inventory("independent checker produced no result".to_owned())
            })?;
            inventory = validate_independent_checker_report(&output.stdout, &unit)?;
            None
        }
        _ => None,
    };
    // Tool version calls are deliberately not repeated in the evidence run;
    // prepend their observations so every actual subprocess is recorded.
    let mut all_commands = version_commands;
    let offset = all_commands.len();
    all_commands.append(&mut commands);
    let mut all_outputs = version_runs;
    all_outputs.append(&mut outputs);
    if let Some(replay) = &mut mutation_replay {
        replay.baseline_run_index = replay
            .baseline_run_index
            .checked_add(offset)
            .ok_or_else(|| AdapterError::Internal("mutation run index overflowed".to_owned()))?;
        replay.expected_failure.run_index = replay
            .expected_failure
            .run_index
            .checked_add(offset)
            .ok_or_else(|| {
            AdapterError::Internal("mutation run index overflowed".to_owned())
        })?;
    }
    let expected_failure = mutation_replay
        .as_ref()
        .map(|replay| replay.expected_failure.run_index);
    if all_outputs.iter().enumerate().any(|(index, output)| {
        if Some(index) == expected_failure {
            output.status != Some(101)
        } else {
            output.status != Some(0)
        }
    }) {
        return Err(AdapterError::Internal(
            "successful observation contains an unregistered process exit status".to_owned(),
        ));
    }
    let mut disk_bytes = directory_size(
        shadow
            .as_ref()
            .map_or(execution_root.as_path(), ShadowProject::path),
    )?;
    if let Some(mutant_shadow) = &mutant_shadow {
        disk_bytes = disk_bytes
            .checked_add(directory_size(mutant_shadow.path())?)
            .ok_or_else(|| AdapterError::Budget("shadow disk use overflowed".to_owned()))?;
    }
    if disk_bytes > budget.disk_bytes {
        return Err(AdapterError::Budget(format!(
            "shadow execution used {disk_bytes} bytes, limit is {}",
            budget.disk_bytes
        )));
    }
    let time_ms = elapsed_ms(started);
    if time_ms > budget.time_ms {
        return Err(AdapterError::Budget(format!(
            "adapter execution used {time_ms} ms, limit is {}",
            budget.time_ms
        )));
    }
    let normalization_roots = mutant_execution_root.into_iter().collect::<Vec<_>>();
    let runs = observe_runs(&all_outputs, &execution_root, &normalization_roots, &root);
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
    let (generated_artifacts, trusted_transcription) = match transcription_facts {
        Some(facts) => {
            let generated_artifacts = facts.generated_artifacts.clone();
            let observation = trusted_transcription_observation(&input_artifacts, facts)?;
            (generated_artifacts, Some(observation))
        }
        None if flavor == TestFlavor::Generator => {
            (collect_exact_outputs(&execution_root, &unit.outputs)?, None)
        }
        None if mutation_replay.is_some() => (
            vec![
                mutation_replay
                    .as_ref()
                    .expect("guarded mutation replay")
                    .target_postimage
                    .clone(),
            ],
            None,
        ),
        None => (Vec::new(), None),
    };
    let unit_bytes =
        canonical_json(&request.unit).map_err(|error| AdapterError::Internal(error.to_string()))?;
    let result = serde_json::json!({"inventory":inventory,"artifact_binding":artifact_binding,"trusted_transcription":trusted_transcription,"mutation_replay":mutation_replay,"run_hashes":runs.iter().map(|run| &run.normalized_output_sha256).collect::<Vec<_>>()});
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
            time_ms,
            peak_disk_bytes: disk_bytes,
            peak_memory_bytes: None,
        },
        inventory: inventory.clone(),
        normalization: if flavor == TestFlavor::TrustedTranscription {
            "exact-transcription-bytes/1".to_owned()
        } else {
            "stable-tool-output/1".to_owned()
        },
        artifact_binding,
        trusted_transcription,
        mutation_replay,
    };
    if let Some(before) = &reviewed_tree_before {
        ensure_tree_unchanged(
            "mutation replay reviewed root",
            before,
            &snapshot_mutation_tree(&root)?,
        )?;
    }
    let evidence = (request.operation != "inventory").then_some(observation);
    Ok((evidence, inventory))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFlavor {
    Rust,
    Python,
    Generator,
    CanonicalArtifact,
    IndependentCheck,
    TrustedTranscription,
}

fn validate_unit(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
) -> Result<TestFlavor, AdapterError> {
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
        (
            "trusted-transcription",
            AdapterKind::TrustedTranscription,
            OperationKind::Transcription,
        ) => TestFlavor::TrustedTranscription,
        _ => {
            return Err(AdapterError::Unit(
                "adapter and operation type do not agree".to_owned(),
            ));
        }
    };
    let expected_schema = if unit.kind == EvidenceKind::MutationWitness {
        "proofbound-evidence-unit/3"
    } else if flavor == TestFlavor::TrustedTranscription {
        "proofbound-evidence-unit/2"
    } else {
        "proofbound-evidence-unit/1"
    };
    if unit.schema != expected_schema {
        return Err(AdapterError::Unit(format!("expected {expected_schema}")));
    }
    let kind_matches_route = match flavor {
        TestFlavor::Rust => matches!(
            unit.kind,
            EvidenceKind::ExampleTest | EvidenceKind::PropertyTest | EvidenceKind::MutationWitness
        ),
        TestFlavor::Python => matches!(
            unit.kind,
            EvidenceKind::ExampleTest | EvidenceKind::PropertyTest
        ),
        TestFlavor::Generator => unit.kind == EvidenceKind::ExampleTest,
        TestFlavor::CanonicalArtifact => unit.kind == EvidenceKind::ArtifactSoundness,
        TestFlavor::IndependentCheck => unit.kind == EvidenceKind::IndependentCheck,
        TestFlavor::TrustedTranscription => unit.kind == EvidenceKind::TrustedTranscription,
    };
    if !kind_matches_route {
        return Err(AdapterError::Unit(
            "adapter, typed operation, and evidence kind do not agree".to_owned(),
        ));
    }
    if !valid_local_id(&unit.id) {
        return Err(AdapterError::Unit(
            "unit id must use the strict lowercase segmented grammar".to_owned(),
        ));
    }
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
    if unit.expected_inventory.is_empty()
        || unit
            .expected_inventory
            .iter()
            .any(|item| !valid_inventory_item(item))
    {
        return Err(AdapterError::Inventory(
            "expected_inventory must contain at least one trim-nonempty item of at most 4096 characters with no Unicode controls"
                .to_owned(),
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
    validate_transcription_configuration(flavor, unit)?;
    validate_mutation_configuration(unit)?;
    validate_arguments(flavor, &unit.operation.arguments)?;
    Ok(flavor)
}

fn validate_mutation_configuration(unit: &EvidenceUnitManifest) -> Result<(), AdapterError> {
    match (unit.kind, unit.mutation.as_ref()) {
        (EvidenceKind::MutationWitness, Some(config))
            if config.schema == MutationReplaySchema::Version1 =>
        {
            validate_mutation_path(&config.registry)
        }
        (EvidenceKind::MutationWitness, None) => Err(AdapterError::Unit(
            "direct mutation evidence is unsupported; configure typed automatic replay".to_owned(),
        )),
        (_, Some(_)) => Err(AdapterError::Unit(
            "only mutation-witness evidence may configure mutation replay".to_owned(),
        )),
        (_, None) => Ok(()),
    }
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
        if unit.outputs.iter().any(|output| output == checker) {
            return Err(AdapterError::Unit(
                "generator checker must not also be a generated output".to_owned(),
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

fn validate_transcription_configuration(
    flavor: TestFlavor,
    unit: &EvidenceUnitManifest,
) -> Result<(), AdapterError> {
    let Some(config) = &unit.transcription else {
        return if flavor == TestFlavor::TrustedTranscription {
            Err(AdapterError::Unit(
                "trusted-transcription requires the typed transcription block".to_owned(),
            ))
        } else {
            Ok(())
        };
    };
    if flavor != TestFlavor::TrustedTranscription {
        return Err(AdapterError::Unit(
            "only trusted-transcription units may configure transcription".to_owned(),
        ));
    }
    if config.schema != TrustedTranscriptionSchema::Version1
        || config.driver_abi != TranscriptionDriverAbi::Version1
    {
        return Err(AdapterError::Unit(
            "trusted transcription requires the version-1 typed record and driver ABI".to_owned(),
        ));
    }
    for path in [
        &config.source,
        &config.committed_transcription,
        &config.driver,
    ] {
        validate_transcription_path(path)?;
    }
    if [
        &config.source,
        &config.committed_transcription,
        &config.driver,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>()
    .len()
        != 3
    {
        return Err(AdapterError::Unit(
            "source, committed transcription, and driver must be distinct paths".to_owned(),
        ));
    }
    if Path::new(&config.driver)
        .extension()
        .and_then(|value| value.to_str())
        != Some("py")
    {
        return Err(AdapterError::Unit(
            "trusted transcription driver must be a repository-relative .py file".to_owned(),
        ));
    }
    if !safe_format(&config.source_format)
        || !safe_format(&config.transcribed_format)
        || config.source_format == config.transcribed_format
    {
        return Err(AdapterError::Unit(
            "transcription format names must be safe portable tokens".to_owned(),
        ));
    }

    let mut exact_inputs = vec![
        config.source.clone(),
        config.committed_transcription.clone(),
        config.driver.clone(),
    ];
    exact_inputs.sort();
    if unit.inputs != exact_inputs {
        return Err(AdapterError::Unit(
            "trusted-transcription inputs must be the exact sorted source, committed transcription, and driver paths"
                .to_owned(),
        ));
    }
    let mut exact_inventory = vec![
        config.source.clone(),
        config.committed_transcription.clone(),
    ];
    exact_inventory.sort();
    if unit.expected_inventory != exact_inventory {
        return Err(AdapterError::Inventory(
            "trusted-transcription expected_inventory must be the exact sorted source and committed transcription paths"
                .to_owned(),
        ));
    }
    if unit.kind != EvidenceKind::TrustedTranscription
        || unit.binding_mode != Some(BindingMode::ExternalRoundTrip)
        || unit.evaluation_mode.is_some()
        || unit.theorem.is_some()
        || unit.refinement_theorem.is_some()
        || !unit.premises.is_empty()
        || !unit.assumptions.is_empty()
        || unit.bounded_domain.is_some()
        || unit.operation.package.is_some()
        || unit.operation.manifest.is_some()
        || unit.operation.inventory.is_some()
        || unit.operation.checker.is_some()
        || !unit.operation.targets.is_empty()
        || !unit.operation.paths.is_empty()
        || !unit.operation.arguments.is_empty()
        || !unit.outputs.is_empty()
        || unit.environment_allowlist != ["PATH"]
    {
        return Err(AdapterError::Unit(
            "trusted-transcription permits only its typed block, external-round-trip binding, the exact PATH allowlist, and an otherwise empty transcription operation"
                .to_owned(),
        ));
    }
    Ok(())
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
        TestFlavor::CanonicalArtifact
        | TestFlavor::IndependentCheck
        | TestFlavor::Generator
        | TestFlavor::TrustedTranscription => &[][..],
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
        TestFlavor::CanonicalArtifact
        | TestFlavor::IndependentCheck
        | TestFlavor::Generator
        | TestFlavor::TrustedTranscription => {
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
        TestFlavor::TrustedTranscription => "Python/trusted-transcription-driver",
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
    executor: &mut E,
    context: RustRunContext<'_>,
) -> Result<RustRunResult, AdapterError> {
    let manifest =
        unit.operation.manifest.as_deref().ok_or_else(|| {
            AdapterError::Unit("cargo-test requires operation.manifest".to_owned())
        })?;
    let shadow_manifest = shadow_path(context.baseline_root, manifest)?;
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

    if unit.kind == EvidenceKind::MutationWitness {
        let mutant_shadow_root = context.mutant_root.ok_or_else(|| {
            AdapterError::Internal("mutation replay has no independent mutant shadow".to_owned())
        })?;
        return run_registered_mutation(
            request,
            unit,
            mutant_shadow_root,
            &selectors,
            &named_targets,
            executor,
            context,
        );
    }
    if context.mutant_root.is_some() {
        return Err(AdapterError::Internal(
            "non-mutation test unexpectedly received a mutant shadow".to_owned(),
        ));
    }
    if !named_targets.is_empty() {
        return Err(AdapterError::Unit("named cargo targets are reserved for mutation-witness units; use expected_inventory for exact tests".to_owned()));
    }
    let mut collection = collect_rust_tests(
        unit,
        context.baseline_root,
        &selectors,
        context.environment,
        executor,
        context.deadline,
    )?;
    let execution_nodes =
        resolve_expected_rust_tests(&unit.expected_inventory, &collection.discovered)?;
    let inventory = sorted_unique(unit.expected_inventory.clone(), "expected inventory")?;
    if execution_nodes.is_empty() {
        return Err(AdapterError::Inventory(
            "configured test inventory is empty".to_owned(),
        ));
    }
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        let environment_observation =
            observe_environment(context.environment, &unit.environment_allowlist);
        for node in execution_nodes {
            let spec = exact_rust_test_spec(&node);
            let output = executor.run(
                &spec,
                context.baseline_root,
                context.environment,
                context.deadline.remaining()?,
            )?;
            ensure_success(&spec, &output)?;
            ensure_one_rust_test_ran(&node.libtest_name, &output)?;
            collection
                .commands
                .push(observe_command(&spec, &environment_observation));
            collection.outputs.push(output);
        }
    }
    Ok(RustRunResult {
        commands: collection.commands,
        outputs: collection.outputs,
        inventory,
        mutation_replay: None,
    })
}

struct RustCollection {
    commands: Vec<CommandObservation>,
    outputs: Vec<ProcessOutput>,
    discovered: BTreeMap<String, RustTestNode>,
}

fn collect_rust_tests<E: Executor>(
    unit: &EvidenceUnitManifest,
    shadow_root: &Path,
    selectors: &[String],
    environment: &BTreeMap<String, String>,
    executor: &mut E,
    deadline: Deadline,
) -> Result<RustCollection, AdapterError> {
    let manifest =
        unit.operation.manifest.as_deref().ok_or_else(|| {
            AdapterError::Unit("cargo-test requires operation.manifest".to_owned())
        })?;
    let shadow_manifest = shadow_path(shadow_root, manifest)?;
    let package =
        unit.operation.package.as_deref().ok_or_else(|| {
            AdapterError::Unit("cargo-test requires operation.package".to_owned())
        })?;
    let mut args = vec![
        "test".to_owned(),
        "--no-run".to_owned(),
        "--message-format=json".to_owned(),
        "--manifest-path".to_owned(),
        shadow_manifest.to_string_lossy().into_owned(),
        "--package".to_owned(),
        package.to_owned(),
    ];
    args.extend(selectors.iter().cloned());
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
    Ok(RustCollection {
        commands,
        outputs,
        discovered,
    })
}

fn exact_rust_test_spec(node: &RustTestNode) -> ProcessSpec {
    ProcessSpec {
        program: node.executable.to_string_lossy().into_owned(),
        args: vec![node.libtest_name.clone(), "--exact".to_owned()],
    }
}

fn run_registered_mutation<E: Executor>(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
    mutant_root: &Path,
    selectors: &[String],
    named_targets: &[String],
    executor: &mut E,
    context: RustRunContext<'_>,
) -> Result<RustRunResult, AdapterError> {
    if !matches!(
        request.operation.as_str(),
        "inventory" | "check" | "reproduce"
    ) {
        return Err(AdapterError::Request(
            "mutation replay executes only for inventory, check, or reproduce".to_owned(),
        ));
    }
    let registry_path = &unit
        .mutation
        .as_ref()
        .ok_or_else(|| AdapterError::Unit("mutation replay configuration is missing".to_owned()))?
        .registry;
    let loaded = load_mutation_registry(context.original_root, registry_path)?;
    let mutation = &loaded.registry.mutation;
    validate_mutation_unit(unit, &loaded, named_targets)?;

    let original_files = observe_mutation_files(context.original_root, &loaded)?;
    let baseline_files = observe_mutation_files(context.baseline_root, &loaded)?;
    let mutant_preimage = observe_mutation_files(mutant_root, &loaded)?;
    if original_files != baseline_files || original_files != mutant_preimage {
        return Err(AdapterError::ToolFailed(
            "fresh mutation shadows do not byte-match the registered root inputs".to_owned(),
        ));
    }
    let baseline_tree = snapshot_mutation_tree(context.baseline_root)?;
    let mutant_tree = snapshot_mutation_tree(mutant_root)?;
    if baseline_tree != mutant_tree {
        return Err(AdapterError::ToolFailed(
            "fresh baseline and mutant shadows have different reviewed trees".to_owned(),
        ));
    }

    let environment_observation =
        observe_environment(context.environment, &unit.environment_allowlist);
    let mut baseline = collect_rust_tests(
        unit,
        context.baseline_root,
        selectors,
        context.environment,
        executor,
        context.deadline,
    )?;
    let baseline_inventory = baseline.discovered.keys().cloned().collect::<Vec<_>>();
    let baseline_node = baseline
        .discovered
        .get(&mutation.witness)
        .cloned()
        .ok_or_else(|| {
            AdapterError::Inventory(format!(
                "mutation `{}` witness `{}` was not collected",
                mutation.id, mutation.witness
            ))
        })?;

    let mut baseline_run_index = None;
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        let spec = exact_rust_test_spec(&baseline_node);
        let output = executor.run(
            &spec,
            context.baseline_root,
            context.environment,
            context.deadline.remaining()?,
        )?;
        ensure_success(&spec, &output)?;
        ensure_one_rust_test_ran(&baseline_node.libtest_name, &output)?;
        baseline_run_index = Some(baseline.outputs.len());
        baseline.commands.push(observe_mutation_command(
            &spec,
            &environment_observation,
            context.baseline_root,
            "$BASELINE",
        ));
        baseline.outputs.push(output);
    }
    ensure_tree_unchanged(
        "baseline mutation witness",
        &baseline_tree,
        &snapshot_mutation_tree(context.baseline_root)?,
    )?;

    let target_postimage = apply_registered_mutant(mutant_root, &loaded)?;
    ensure_exact_mutant_tree(
        &mutant_tree,
        &snapshot_mutation_tree(mutant_root)?,
        &mutation.target_path,
        &target_postimage,
    )?;
    let mut mutant = collect_rust_tests(
        unit,
        mutant_root,
        selectors,
        context.environment,
        executor,
        context.deadline,
    )?;
    let mutant_inventory = mutant.discovered.keys().cloned().collect::<Vec<_>>();
    if mutant_inventory != baseline_inventory {
        return Err(AdapterError::Inventory(
            "mutant changed the exact collected Rust test inventory".to_owned(),
        ));
    }
    let mutant_node = mutant
        .discovered
        .get(&mutation.witness)
        .cloned()
        .ok_or_else(|| {
            AdapterError::Inventory(format!(
                "mutant omitted registered witness `{}`",
                mutation.witness
            ))
        })?;

    let mutant_command_offset = baseline.commands.len();
    baseline.commands.append(&mut mutant.commands);
    baseline.outputs.append(&mut mutant.outputs);
    let mut expected_failure_index = None;
    if matches!(request.operation.as_str(), "check" | "reproduce") {
        let spec = exact_rust_test_spec(&mutant_node);
        let output = executor.run(
            &spec,
            mutant_root,
            context.environment,
            context.deadline.remaining()?,
        )?;
        ensure_one_rust_test_failed(&mutant_node.libtest_name, &output)?;
        expected_failure_index = Some(baseline.outputs.len());
        baseline.commands.push(observe_mutation_command(
            &spec,
            &environment_observation,
            mutant_root,
            "$MUTANT",
        ));
        baseline.outputs.push(output);
    }
    debug_assert!(mutant_command_offset <= baseline.commands.len());

    if observe_file(mutant_root, &mutation.target_path)? != target_postimage
        || observe_file(mutant_root, &loaded.path)? != original_files.registry
        || observe_file(mutant_root, &mutation.mutant_path)? != original_files.mutant_artifact
        || observe_file(mutant_root, &mutation.witness_path)? != original_files.witness_source
    {
        return Err(AdapterError::ToolFailed(
            "mutant execution changed its registered replay inputs or target postimage".to_owned(),
        ));
    }
    ensure_exact_mutant_tree(
        &mutant_tree,
        &snapshot_mutation_tree(mutant_root)?,
        &mutation.target_path,
        &target_postimage,
    )?;

    if observe_mutation_files(context.original_root, &loaded)? != original_files {
        return Err(AdapterError::ToolFailed(
            "mutation replay changed a registered file in the reviewed root".to_owned(),
        ));
    }

    let mutation_replay = match (baseline_run_index, expected_failure_index) {
        (Some(baseline_run_index), Some(run_index)) => Some(MutationReplayObservation {
            schema: "proofbound-mutation-replay-observation/1".to_owned(),
            mutation_id: mutation.id.clone(),
            registry: original_files.registry,
            target_preimage: original_files.target_preimage,
            mutant_artifact: original_files.mutant_artifact,
            target_postimage,
            witness_source: original_files.witness_source,
            check_id: mutation.witness.clone(),
            affected_claims: sorted_unique(
                mutation.affected_claims.clone(),
                "mutation affected claims",
            )?,
            baseline_run_index,
            expected_failure: ExpectedFailureObservation {
                run_index,
                allowed_exit_codes: vec![101],
            },
        }),
        (None, None) => None,
        _ => {
            return Err(AdapterError::Internal(
                "mutation replay has incomplete baseline/failure run binding".to_owned(),
            ));
        }
    };
    Ok(RustRunResult {
        commands: baseline.commands,
        outputs: baseline.outputs,
        inventory: vec![mutation.id.clone()],
        mutation_replay,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MutationFileObservations {
    registry: ArtifactObservation,
    target_preimage: ArtifactObservation,
    mutant_artifact: ArtifactObservation,
    witness_source: ArtifactObservation,
}

fn observe_mutation_files(
    root: &Path,
    loaded: &LoadedMutationRegistry,
) -> Result<MutationFileObservations, AdapterError> {
    let mutation = &loaded.registry.mutation;
    let observed = MutationFileObservations {
        registry: observe_file(root, &loaded.path)?,
        target_preimage: observe_file(root, &mutation.target_path)?,
        mutant_artifact: observe_file(root, &mutation.mutant_path)?,
        witness_source: observe_file(root, &mutation.witness_path)?,
    };
    if observed.target_preimage.sha256 != mutation.target_preimage_sha256 {
        return Err(AdapterError::Unit(
            "mutation target preimage digest does not match its registration".to_owned(),
        ));
    }
    if observed.mutant_artifact.sha256 != mutation.mutant_sha256 {
        return Err(AdapterError::Unit(
            "mutant artifact digest does not match its registration".to_owned(),
        ));
    }
    if observed.witness_source.sha256 != mutation.witness_sha256 {
        return Err(AdapterError::Unit(
            "mutation witness source digest does not match its registration".to_owned(),
        ));
    }
    if observed.target_preimage.sha256 == observed.mutant_artifact.sha256 {
        return Err(AdapterError::Unit(
            "registered mutant is byte-identical to its target preimage".to_owned(),
        ));
    }
    Ok(observed)
}

fn observe_file(root: &Path, relative: &str) -> Result<ArtifactObservation, AdapterError> {
    let path = resolve_existing(root, relative)?;
    if !path.is_file() {
        return Err(AdapterError::UnsafePath(relative.to_owned()));
    }
    hash_artifact(root, &path)
}

fn apply_registered_mutant(
    mutant_root: &Path,
    loaded: &LoadedMutationRegistry,
) -> Result<ArtifactObservation, AdapterError> {
    let mutation = &loaded.registry.mutation;
    let target = resolve_existing(mutant_root, &mutation.target_path)?;
    let mutant = resolve_existing(mutant_root, &mutation.mutant_path)?;
    let mutant_bytes = fs::read(&mutant)?;
    fs::write(&target, &mutant_bytes)?;
    let postimage = hash_artifact(mutant_root, &target)?;
    if postimage.sha256 != mutation.mutant_sha256
        || postimage.size_bytes != mutant_bytes.len().try_into().unwrap_or(u64::MAX)
    {
        return Err(AdapterError::Internal(
            "mutated target postimage does not byte-match the registered mutant".to_owned(),
        ));
    }
    Ok(postimage)
}

#[derive(Clone, Debug)]
struct RustTestBinary {
    target: String,
    executable: PathBuf,
}

#[derive(Clone, Debug)]
struct RustTestNode {
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
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| AdapterError::Inventory(format!("non-UTF-8 libtest output: {error}")))?;
    let stderr = std::str::from_utf8(&output.stderr)
        .map_err(|error| AdapterError::Inventory(format!("non-UTF-8 libtest output: {error}")))?;
    let lines = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .collect::<Vec<_>>();
    let expected_result = format!("test {name} ... ok");
    let summaries = lines
        .iter()
        .filter_map(|line| line.strip_prefix("test result: "))
        .collect::<Vec<_>>();
    let exact_summary = summaries.len() == 1
        && summaries[0].strip_prefix("ok. ").is_some_and(|summary| {
            let fields = summary.split(';').map(str::trim).collect::<Vec<_>>();
            fields.len() >= 4
                && fields[0] == "1 passed"
                && fields[1] == "0 failed"
                && fields[2] == "0 ignored"
                && fields[3] == "0 measured"
        });
    if lines
        .iter()
        .filter(|line| **line == "running 1 test")
        .count()
        != 1
        || lines
            .iter()
            .filter(|line| **line == expected_result.as_str())
            .count()
            != 1
        || !exact_summary
    {
        return Err(AdapterError::Inventory(format!(
            "Rust test `{name}` did not report exactly one passing test"
        )));
    }
    Ok(())
}

fn ensure_one_rust_test_failed(name: &str, output: &ProcessOutput) -> Result<(), AdapterError> {
    if output.truncated {
        return Err(AdapterError::Inventory(
            "mutant witness output was truncated".to_owned(),
        ));
    }
    if output.status != Some(101) {
        return Err(AdapterError::ToolFailed(format!(
            "mutant witness exited {:?}; exact Rust libtest exit 101 is required",
            output.status
        )));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| AdapterError::Inventory(format!("non-UTF-8 libtest output: {error}")))?;
    let stderr = std::str::from_utf8(&output.stderr)
        .map_err(|error| AdapterError::Inventory(format!("non-UTF-8 libtest output: {error}")))?;
    let lines = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .collect::<Vec<_>>();
    let expected_result = format!("test {name} ... FAILED");
    let summaries = lines
        .iter()
        .filter_map(|line| line.strip_prefix("test result: "))
        .collect::<Vec<_>>();
    let exact_summary = summaries.len() == 1
        && summaries[0]
            .strip_prefix("FAILED. ")
            .is_some_and(|summary| {
                let fields = summary.split(';').map(str::trim).collect::<Vec<_>>();
                fields.len() >= 4
                    && fields[0] == "0 passed"
                    && fields[1] == "1 failed"
                    && fields[2] == "0 ignored"
                    && fields[3] == "0 measured"
            });
    if lines
        .iter()
        .filter(|line| **line == "running 1 test")
        .count()
        != 1
        || lines
            .iter()
            .filter(|line| **line == expected_result.as_str())
            .count()
            != 1
        || !exact_summary
    {
        return Err(AdapterError::Inventory(format!(
            "Rust mutant witness `{name}` did not report exactly one failing test"
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

    if !matches!(
        request.operation.as_str(),
        "inventory" | "check" | "reproduce"
    ) {
        return Err(AdapterError::Request(
            "checker executes only for inventory, check, or reproduce".to_owned(),
        ));
    }
    let mut args = vec![shadow_checker.to_string_lossy().into_owned()];
    args.extend(unit.operation.arguments.clone());
    let spec = ProcessSpec {
        program: "python3".to_owned(),
        args,
    };
    let output = executor.run(&spec, shadow_root, environment, deadline.remaining()?)?;
    ensure_success(&spec, &output)?;
    let environment_observation = observe_environment(environment, &unit.environment_allowlist);
    Ok((
        vec![observe_command(&spec, &environment_observation)],
        vec![output],
        Vec::new(),
    ))
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
    let committed = if request.operation == "update" {
        None
    } else {
        Some(collect_exact_outputs(execution_root, &unit.outputs)?)
    };
    let (run_root, checker_path, workspace_before) = if request.operation == "update" {
        let checker_path = shadow_path(execution_root, checker)?;
        (execution_root.to_path_buf(), checker_path, None)
    } else if matches!(
        request.operation.as_str(),
        "inventory" | "check" | "reproduce"
    ) {
        let candidate_root = assemble_generator_candidate(execution_root, unit)?;
        let checker_path = shadow_path(&candidate_root, checker)?;
        let workspace = candidate_root
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                AdapterError::Internal("generator candidate has no workspace root".to_owned())
            })?
            .to_path_buf();
        let before = snapshot_tree(&workspace)?;
        (candidate_root, checker_path, Some((workspace, before)))
    } else {
        return Err(AdapterError::Request(
            "generator executes only for inventory, check, reproduce, or update".to_owned(),
        ));
    };
    if !checker_path.is_file()
        || checker_path.extension().and_then(|value| value.to_str()) != Some("py")
    {
        return Err(AdapterError::UnsafePath(checker.to_owned()));
    }

    let args = vec![
        checker_path.to_string_lossy().into_owned(),
        "--update".to_owned(),
    ];
    let spec = ProcessSpec {
        program: "python3".to_owned(),
        args,
    };
    let output = executor.run(&spec, &run_root, environment, deadline.remaining()?)?;
    ensure_success(&spec, &output)?;
    let generated = collect_exact_outputs(&run_root, &unit.outputs)?;
    if let Some((workspace, before)) = workspace_before {
        ensure_exact_generator_changes(
            &workspace,
            &run_root,
            &unit.outputs,
            &before,
            &snapshot_tree(&workspace)?,
        )?;
    }
    if committed
        .as_ref()
        .is_some_and(|committed| &generated != committed)
    {
        return Err(AdapterError::ToolFailed(
            "freshly generated output bytes differ from the committed exact output inventory"
                .to_owned(),
        ));
    }
    let inventory = sorted_unique(
        generated
            .iter()
            .map(|artifact| artifact.logical_name.clone())
            .collect(),
        "generator observed output inventory",
    )?;

    let environment_observation = observe_environment(environment, &unit.environment_allowlist);
    Ok((
        vec![observe_command(&spec, &environment_observation)],
        vec![output],
        inventory,
    ))
}

fn assemble_generator_candidate(
    project_root: &Path,
    unit: &EvidenceUnitManifest,
) -> Result<PathBuf, AdapterError> {
    let workspace = project_root.parent().ok_or_else(|| {
        AdapterError::Internal("sealed project has no workspace parent".to_owned())
    })?;
    let candidate_root = workspace.join("generator-candidate").join(&unit.id);
    if candidate_root.exists() {
        return Err(AdapterError::Internal(
            "generator candidate root already exists".to_owned(),
        ));
    }
    fs::create_dir_all(&candidate_root)?;
    let outputs = unit.outputs.iter().collect::<BTreeSet<_>>();
    for input in &unit.inputs {
        if outputs.contains(input) {
            continue;
        }
        let source = shadow_path(project_root, input)?;
        if !source.is_file() {
            return Err(AdapterError::Unit(format!(
                "generator input `{input}` must be an exact regular file"
            )));
        }
        let destination = candidate_root.join(input);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, destination)?;
    }
    for output in &unit.outputs {
        if candidate_root.join(output).exists() {
            return Err(AdapterError::Internal(format!(
                "generator candidate output `{output}` was not initially absent"
            )));
        }
    }
    Ok(candidate_root)
}

fn ensure_exact_generator_changes(
    workspace: &Path,
    candidate_root: &Path,
    outputs: &[String],
    before: &[(PathBuf, TreeSnapshotEntry)],
    after: &[(PathBuf, TreeSnapshotEntry)],
) -> Result<(), AdapterError> {
    let candidate = candidate_root.strip_prefix(workspace).map_err(|_| {
        AdapterError::Internal("generator candidate escaped its workspace".to_owned())
    })?;
    let before = before.iter().cloned().collect::<BTreeMap<_, _>>();
    let after = after.iter().cloned().collect::<BTreeMap<_, _>>();
    if before
        .iter()
        .any(|(path, entry)| after.get(path) != Some(entry))
    {
        return Err(AdapterError::ToolFailed(
            "generator changed or removed a registered seed or sealed project file".to_owned(),
        ));
    }

    let mut allowed_new = BTreeSet::new();
    let mut output_paths = BTreeSet::new();
    for output in outputs {
        let path = candidate.join(output);
        output_paths.insert(path.to_path_buf());
        allowed_new.insert(path.to_path_buf());
        let mut parent = path.parent();
        while let Some(path) = parent {
            if path == candidate {
                break;
            }
            allowed_new.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    for (path, entry) in &after {
        if before.contains_key(path) {
            continue;
        }
        if !allowed_new.contains(path)
            || (output_paths.contains(path) && !matches!(entry, TreeSnapshotEntry::File { .. }))
            || (!output_paths.contains(path) && !matches!(entry, TreeSnapshotEntry::Directory))
        {
            return Err(AdapterError::Inventory(format!(
                "generator emitted undeclared path `{}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn run_trusted_transcription<E: Executor>(
    request: &AdapterRequest,
    unit: &EvidenceUnitManifest,
    execution_root: &Path,
    environment: &BTreeMap<String, String>,
    executor: &mut E,
    deadline: Deadline,
) -> Result<TranscriptionRunResult, AdapterError> {
    if !matches!(
        request.operation.as_str(),
        "inventory" | "check" | "reproduce"
    ) {
        return Err(AdapterError::Request(
            "trusted transcription executes only for inventory, check, or reproduce".to_owned(),
        ));
    }
    let config = unit.transcription.as_ref().ok_or_else(|| {
        AdapterError::Unit("trusted-transcription requires its typed configuration".to_owned())
    })?;
    let source = shadow_path(execution_root, &config.source)?;
    let committed = shadow_path(execution_root, &config.committed_transcription)?;
    let driver = shadow_path(execution_root, &config.driver)?;
    if !source.is_file() || !committed.is_file() || !driver.is_file() {
        return Err(AdapterError::UnsafePath(
            "trusted-transcription paths must resolve to three regular files".to_owned(),
        ));
    }
    let source_bytes = fs::read(&source)?;
    let committed_bytes = fs::read(&committed)?;
    let source_observation = artifact_from_bytes(config.source.clone(), &source_bytes);
    let committed_observation =
        artifact_from_bytes(config.committed_transcription.clone(), &committed_bytes);
    let driver_observation = artifact_from_bytes(config.driver.clone(), &fs::read(&driver)?);

    let workspace = execution_root.parent().ok_or_else(|| {
        AdapterError::Internal("sealed project has no workspace parent".to_owned())
    })?;
    let work_root = workspace.join("trusted-transcription").join(&unit.id);
    fs::create_dir_all(&work_root)?;
    let transcribe_root = work_root.join("transcribe");
    fs::create_dir(&transcribe_root)?;
    let candidate_path = transcribe_root.join("candidate.out");

    let environment_observation = observe_environment(environment, &unit.environment_allowlist);
    let project_before = snapshot_tree(execution_root)?;
    let transcribe_spec = ProcessSpec {
        program: "python3".to_owned(),
        args: vec![
            driver.to_string_lossy().into_owned(),
            "transcribe".to_owned(),
            "--source".to_owned(),
            source.to_string_lossy().into_owned(),
            "--output".to_owned(),
            candidate_path.to_string_lossy().into_owned(),
        ],
    };
    let transcribe_output = executor.run(
        &transcribe_spec,
        execution_root,
        environment,
        deadline.remaining()?,
    )?;
    ensure_silent_success(&transcribe_spec, &transcribe_output)?;
    ensure_tree_unchanged(
        "transcriber",
        &project_before,
        &snapshot_tree(execution_root)?,
    )?;
    let candidate_bytes = read_exact_stage_output(&transcribe_root, "candidate.out")?;
    if candidate_bytes != committed_bytes {
        return Err(AdapterError::ToolFailed(
            "transcribed candidate does not byte-match the exact committed transcription"
                .to_owned(),
        ));
    }

    let reencode_root = work_root.join("reencode");
    fs::create_dir(&reencode_root)?;
    let reencoded_path = reencode_root.join("source.out");
    let reencode_spec = ProcessSpec {
        program: "python3".to_owned(),
        args: vec![
            driver.to_string_lossy().into_owned(),
            "reencode".to_owned(),
            "--transcription".to_owned(),
            candidate_path.to_string_lossy().into_owned(),
            "--output".to_owned(),
            reencoded_path.to_string_lossy().into_owned(),
        ],
    };
    let reencode_output = executor.run(
        &reencode_spec,
        execution_root,
        environment,
        deadline.remaining()?,
    )?;
    ensure_silent_success(&reencode_spec, &reencode_output)?;
    ensure_tree_unchanged(
        "re-encoder",
        &project_before,
        &snapshot_tree(execution_root)?,
    )?;
    let candidate_after_reencode = read_exact_stage_output(&transcribe_root, "candidate.out")?;
    if candidate_after_reencode != candidate_bytes {
        return Err(AdapterError::ToolFailed(
            "re-encoder changed the transcribed candidate".to_owned(),
        ));
    }
    let reencoded_bytes = read_exact_stage_output(&reencode_root, "source.out")?;
    if reencoded_bytes != source_bytes {
        return Err(AdapterError::ToolFailed(
            "re-encoded bytes do not byte-match the exact source".to_owned(),
        ));
    }
    validate_transcription_work_tree(&work_root)?;

    let mut generated_artifacts = vec![
        artifact_from_bytes(
            format!("trusted-transcription/{}/transcribed-candidate", unit.id),
            &candidate_bytes,
        ),
        artifact_from_bytes(
            format!("trusted-transcription/{}/reencoded-source", unit.id),
            &reencoded_bytes,
        ),
    ];
    generated_artifacts.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    let inventory = sorted_unique(
        vec![
            source_observation.logical_name.clone(),
            committed_observation.logical_name.clone(),
        ],
        "trusted-transcription observed inventory",
    )?;
    Ok(TranscriptionRunResult {
        commands: vec![
            observe_command(&transcribe_spec, &environment_observation),
            observe_command(&reencode_spec, &environment_observation),
        ],
        outputs: vec![transcribe_output, reencode_output],
        inventory,
        facts: TranscriptionFacts {
            generated_artifacts,
            unit_id: unit.id.clone(),
            source: source_observation,
            committed_transcription: committed_observation,
            driver: driver_observation,
            driver_abi: TRANSCRIPTION_DRIVER_ABI.to_owned(),
            source_format: config.source_format.clone(),
            transcribed_format: config.transcribed_format.clone(),
        },
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeSnapshotEntry {
    Directory,
    File { sha256: String, size_bytes: u64 },
}

/// Snapshot the reviewed portion of a mutation shadow.
///
/// Compiler/test output roots are intentionally excluded: they are ephemeral
/// products of replay, not reviewed source. Every other regular file and
/// directory is part of the sealed boundary and may not change accidentally.
fn snapshot_mutation_tree(root: &Path) -> Result<Vec<(PathBuf, TreeSnapshotEntry)>, AdapterError> {
    let mut snapshot = Vec::new();
    let walker = WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .ok()
                .is_none_or(|relative| !should_exclude(relative))
        });
    for entry in walker {
        let entry = entry.map_err(walk_error)?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| AdapterError::UnsafePath(entry.path().display().to_string()))?
            .to_path_buf();
        let observed = if entry.file_type().is_dir() {
            TreeSnapshotEntry::Directory
        } else if entry.file_type().is_file() {
            let bytes = fs::read(entry.path())?;
            TreeSnapshotEntry::File {
                sha256: sha256_bytes(&bytes),
                size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
            }
        } else {
            return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
        };
        snapshot.push((relative, observed));
    }
    Ok(snapshot)
}

fn ensure_exact_mutant_tree(
    before: &[(PathBuf, TreeSnapshotEntry)],
    after: &[(PathBuf, TreeSnapshotEntry)],
    target_path: &str,
    target_postimage: &ArtifactObservation,
) -> Result<(), AdapterError> {
    if target_postimage.logical_name != target_path {
        return Err(AdapterError::Internal(
            "mutation target postimage has the wrong logical path".to_owned(),
        ));
    }
    let target = PathBuf::from(target_path);
    let mut expected = before.iter().cloned().collect::<BTreeMap<_, _>>();
    if !matches!(expected.get(&target), Some(TreeSnapshotEntry::File { .. })) {
        return Err(AdapterError::UnsafePath(target_path.to_owned()));
    }
    expected.insert(
        target,
        TreeSnapshotEntry::File {
            sha256: target_postimage.sha256.clone(),
            size_bytes: target_postimage.size_bytes,
        },
    );
    let observed = after.iter().cloned().collect::<BTreeMap<_, _>>();
    if observed != expected {
        return Err(AdapterError::ToolFailed(
            "mutant replay changed a reviewed path other than its registered target".to_owned(),
        ));
    }
    Ok(())
}

fn snapshot_tree(root: &Path) -> Result<Vec<(PathBuf, TreeSnapshotEntry)>, AdapterError> {
    let mut snapshot = Vec::new();
    for entry in WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(walk_error)?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| AdapterError::UnsafePath(entry.path().display().to_string()))?
            .to_path_buf();
        let observed = if entry.file_type().is_dir() {
            TreeSnapshotEntry::Directory
        } else if entry.file_type().is_file() {
            let bytes = fs::read(entry.path())?;
            TreeSnapshotEntry::File {
                sha256: sha256_bytes(&bytes),
                size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
            }
        } else {
            return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
        };
        snapshot.push((relative, observed));
    }
    Ok(snapshot)
}

fn ensure_tree_unchanged(
    role: &str,
    before: &[(PathBuf, TreeSnapshotEntry)],
    after: &[(PathBuf, TreeSnapshotEntry)],
) -> Result<(), AdapterError> {
    if before != after {
        return Err(AdapterError::ToolFailed(format!(
            "{role} changed files outside its adapter-owned output directory"
        )));
    }
    Ok(())
}

fn read_exact_stage_output(root: &Path, expected: &str) -> Result<Vec<u8>, AdapterError> {
    let mut found = None;
    for entry in WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(walk_error)?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| AdapterError::UnsafePath(entry.path().display().to_string()))?;
        if relative != Path::new(expected) || !entry.file_type().is_file() {
            return Err(AdapterError::Inventory(format!(
                "transcription driver emitted unexpected path `{}`",
                relative.display()
            )));
        }
        if found.is_some() {
            return Err(AdapterError::Inventory(
                "transcription driver emitted duplicate output".to_owned(),
            ));
        }
        found = Some(fs::read(entry.path())?);
    }
    found.ok_or_else(|| {
        AdapterError::Inventory(format!(
            "transcription driver did not emit required output `{expected}`"
        ))
    })
}

fn validate_transcription_work_tree(root: &Path) -> Result<(), AdapterError> {
    let expected = BTreeSet::from([
        PathBuf::from("transcribe"),
        PathBuf::from("transcribe/candidate.out"),
        PathBuf::from("reencode"),
        PathBuf::from("reencode/source.out"),
    ]);
    let mut actual = BTreeSet::new();
    for entry in WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = entry.map_err(walk_error)?;
        if !entry.file_type().is_dir() && !entry.file_type().is_file() {
            return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
        }
        actual.insert(
            entry
                .path()
                .strip_prefix(root)
                .map_err(|_| AdapterError::UnsafePath(entry.path().display().to_string()))?
                .to_path_buf(),
        );
    }
    if actual != expected {
        return Err(AdapterError::Inventory(
            "transcription work directory contains missing or extra paths".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_silent_success(spec: &ProcessSpec, output: &ProcessOutput) -> Result<(), AdapterError> {
    ensure_success(spec, output)?;
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(AdapterError::Inventory(
            "transcription driver must emit only its exact output file; stdout and stderr must be empty"
                .to_owned(),
        ));
    }
    Ok(())
}

fn artifact_from_bytes(logical_name: String, bytes: &[u8]) -> ArtifactObservation {
    ArtifactObservation {
        logical_name,
        sha256: sha256_bytes(bytes),
        size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
    }
}

fn trusted_transcription_observation(
    inputs: &[ArtifactObservation],
    facts: TranscriptionFacts,
) -> Result<TrustedTranscriptionObservation, AdapterError> {
    let find_input = |logical_name: &str| {
        inputs
            .iter()
            .find(|artifact| artifact.logical_name == logical_name)
            .cloned()
            .ok_or_else(|| {
                AdapterError::Internal(format!(
                    "registered transcription input `{logical_name}` was not observed"
                ))
            })
    };
    for execution_input in [&facts.source, &facts.committed_transcription, &facts.driver] {
        if find_input(&execution_input.logical_name)? != *execution_input {
            return Err(AdapterError::ToolFailed(format!(
                "registered input `{}` changed between sealed execution and observation",
                execution_input.logical_name
            )));
        }
    }
    let source = facts.source;
    let committed_transcription = facts.committed_transcription;
    let driver = facts.driver;
    let candidate_name = format!(
        "trusted-transcription/{}/transcribed-candidate",
        facts.unit_id
    );
    let reencoded_name = format!("trusted-transcription/{}/reencoded-source", facts.unit_id);
    let find_generated = |logical_name: &str| {
        facts
            .generated_artifacts
            .iter()
            .find(|artifact| artifact.logical_name == logical_name)
            .cloned()
            .ok_or_else(|| {
                AdapterError::Internal(format!(
                    "generated transcription artifact `{logical_name}` was not observed"
                ))
            })
    };
    let transcribed_candidate = find_generated(&candidate_name)?;
    let reencoded_source = find_generated(&reencoded_name)?;
    let role_identity = |role: &str| -> Result<String, AdapterError> {
        let value = serde_json::json!({
            "abi": &facts.driver_abi,
            "driver": &driver,
            "role": role,
        });
        Ok(domain_hash(
            TRANSCRIPTION_ROLE_DOMAIN,
            &canonical_json(&value).map_err(|error| AdapterError::Internal(error.to_string()))?,
        ))
    };
    let transcriber_role_identity = role_identity("transcriber")?;
    let reencoder_role_identity = role_identity("reencoder")?;
    Ok(TrustedTranscriptionObservation {
        schema: TRUSTED_TRANSCRIPTION_SCHEMA.to_owned(),
        source,
        committed_transcription,
        transcribed_candidate,
        reencoded_source,
        driver: driver.clone(),
        driver_abi: facts.driver_abi.clone(),
        source_format: facts.source_format,
        transcribed_format: facts.transcribed_format,
        transcriber_role_identity,
        reencoder_role_identity,
    })
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

    if !valid_inventory_item(&report.artifact_logical_name) {
        return Err(AdapterError::Inventory(
            "canonical checker artifact logical name violates the result ABI".to_owned(),
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

fn validate_independent_checker_report(
    bytes: &[u8],
    unit: &EvidenceUnitManifest,
) -> Result<Vec<String>, AdapterError> {
    if bytes.is_empty() || bytes.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(AdapterError::Inventory(
            "independent checker result is empty or oversized".to_owned(),
        ));
    }
    let report: IndependentCheckerReport = serde_json::from_slice(bytes).map_err(|error| {
        AdapterError::Inventory(format!("invalid independent checker result: {error}"))
    })?;
    if canonical_json(&report).map_err(|error| AdapterError::Internal(error.to_string()))? != bytes
    {
        return Err(AdapterError::Inventory(
            "independent checker result must be canonical JSON with no trailing bytes".to_owned(),
        ));
    }
    if report.schema != "proofbound-independent-check-result/1" || !report.accepted {
        return Err(AdapterError::Inventory(
            "independent checker did not return an accepted v1 result".to_owned(),
        ));
    }
    let expected = sorted_unique(
        unit.expected_inventory.clone(),
        "independent expected inventory",
    )?;
    let actual = sorted_unique(report.inventory, "independent checker result inventory")?;
    if actual.is_empty() || actual != expected {
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
            "independent checker inventory mismatch; missing={missing:?}, extra={extra:?}"
        )));
    }
    Ok(actual)
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
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|error| AdapterError::Inventory(format!("non-UTF-8 pytest output: {error}")))?;
    let stderr = std::str::from_utf8(&output.stderr)
        .map_err(|error| AdapterError::Inventory(format!("non-UTF-8 pytest output: {error}")))?;
    let summaries = stdout
        .lines()
        .chain(stderr.lines())
        .map(str::trim)
        .filter(|line| {
            let mut words = line.split_whitespace();
            words
                .next()
                .is_some_and(|count| count.bytes().all(|byte| byte.is_ascii_digit()))
                && words.next() == Some("passed")
        })
        .collect::<Vec<_>>();
    if summaries.len() != 1
        || !summaries[0].starts_with("1 passed")
        || summaries[0]
            .as_bytes()
            .get("1 passed".len())
            .is_some_and(|byte| !matches!(byte, b' ' | b','))
        || summaries[0].contains(" failed")
        || summaries[0].contains(" error")
    {
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
    mutation: MutationEntry,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationEntry {
    id: String,
    guard: String,
    target_path: String,
    target_preimage_sha256: String,
    mutant_path: String,
    mutant_sha256: String,
    witness: String,
    witness_path: String,
    witness_sha256: String,
    affected_claims: Vec<String>,
}

struct LoadedMutationRegistry {
    path: String,
    registry: MutationRegistry,
}

fn load_mutation_registry(
    root: &Path,
    registry_path: &str,
) -> Result<LoadedMutationRegistry, AdapterError> {
    validate_mutation_path(registry_path)?;
    if Path::new(registry_path)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("toml")
    {
        return Err(AdapterError::Unit(
            "mutation registry must be a .toml file".to_owned(),
        ));
    }
    let bytes = read_safe_file(root, registry_path, MAX_REQUEST_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| AdapterError::Unit(format!("mutation registry is not UTF-8: {error}")))?;
    let value = toml::from_str::<toml::Value>(text)
        .map_err(|error| AdapterError::Unit(format!("invalid mutation registry: {error}")))?;
    if value.get("schema").and_then(toml::Value::as_str) != Some("proofbound-mutation-registry/2") {
        return Err(AdapterError::Unit(
            "direct/manual mutation evidence is unsupported; use proofbound-mutation-registry/2 replay"
                .to_owned(),
        ));
    }
    let loaded = LoadedMutationRegistry {
        path: registry_path.to_owned(),
        registry: toml::from_str::<MutationRegistry>(text)
            .map_err(|error| AdapterError::Unit(error.to_string()))?,
    };
    if loaded.registry.schema != "proofbound-mutation-registry/2"
        || loaded.registry.subject.trim().is_empty()
        || loaded.registry.subject.chars().count() > 4096
    {
        return Err(AdapterError::Unit(
            "mutation registry must contain exactly one typed replay".to_owned(),
        ));
    }
    let mutation = &loaded.registry.mutation;
    if !safe_id(&mutation.id)
        || mutation.guard.trim().is_empty()
        || mutation.guard.chars().count() > 8192
        || !safe_symbol(&mutation.witness)
        || mutation.affected_claims.is_empty()
        || mutation.affected_claims.len() > 4096
        || mutation
            .affected_claims
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != mutation.affected_claims.len()
        || !valid_sha256_text(&mutation.target_preimage_sha256)
        || !valid_sha256_text(&mutation.mutant_sha256)
        || !valid_sha256_text(&mutation.witness_sha256)
    {
        return Err(AdapterError::Unit(format!(
            "invalid mutation replay entry `{}`",
            mutation.id
        )));
    }
    for path in [
        loaded.path.as_str(),
        mutation.target_path.as_str(),
        mutation.mutant_path.as_str(),
        mutation.witness_path.as_str(),
    ] {
        validate_mutation_path(path)?;
    }
    if [
        loaded.path.as_str(),
        mutation.target_path.as_str(),
        mutation.mutant_path.as_str(),
        mutation.witness_path.as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>()
    .len()
        != 4
    {
        return Err(AdapterError::Unit(
            "mutation registry, target, mutant, and witness paths must be distinct".to_owned(),
        ));
    }
    Ok(loaded)
}

fn validate_mutation_unit(
    unit: &EvidenceUnitManifest,
    loaded: &LoadedMutationRegistry,
    named_targets: &[String],
) -> Result<(), AdapterError> {
    let mutation = &loaded.registry.mutation;
    if unit.id != mutation.id
        || unit.expected_inventory != [mutation.id.as_str()]
        || unit.claims != mutation.affected_claims
        || !mutation
            .affected_claims
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || !named_targets.is_empty()
        || !unit.operation.targets.is_empty()
        || !unit.operation.paths.is_empty()
        || unit.operation.inventory.is_some()
        || unit.operation.checker.is_some()
        || !unit.operation.arguments.is_empty()
        || !unit.outputs.is_empty()
        || unit.evaluation_mode.is_some()
        || unit.binding_mode.is_some()
        || unit.theorem.is_some()
        || unit.refinement_theorem.is_some()
        || !unit.premises.is_empty()
        || !unit.assumptions.is_empty()
        || unit.bounded_domain.is_some()
        || unit.transcription.is_some()
    {
        return Err(AdapterError::Unit(
            "mutation replay unit does not exactly match its singleton registration".to_owned(),
        ));
    }
    let mut exact_inputs = vec![
        loaded.path.clone(),
        mutation.target_path.clone(),
        mutation.mutant_path.clone(),
        mutation.witness_path.clone(),
    ];
    exact_inputs.sort();
    if unit.inputs != exact_inputs {
        return Err(AdapterError::Unit(
            "mutation replay inputs must be the exact sorted registry, target, mutant, and witness paths"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_mutation_path(path: &str) -> Result<(), AdapterError> {
    validate_transcription_path(path)?;
    if Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_none()
    {
        return Err(AdapterError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn valid_sha256_text(value: &str) -> bool {
    value.len() == "sha256:".len() + 64
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn valid_inventory_item(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= 4096
        && !value.chars().any(char::is_control)
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

fn observe_mutation_command(
    spec: &ProcessSpec,
    environment: &[EnvironmentObservation],
    execution_root: &Path,
    logical_root: &str,
) -> CommandObservation {
    let logicalize = |value: &str| {
        let path = Path::new(value);
        path.strip_prefix(execution_root).map_or_else(
            |_| logicalize_temp_path(value),
            |relative| {
                if relative.as_os_str().is_empty() {
                    logical_root.to_owned()
                } else {
                    format!(
                        "{logical_root}/{}",
                        relative.to_string_lossy().replace('\\', "/")
                    )
                }
            },
        )
    };
    CommandObservation {
        program: logicalize(&spec.program),
        args: spec.args.iter().map(|arg| logicalize(arg)).collect(),
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
    additional_shadow_roots: &[PathBuf],
    project_root: &Path,
) -> Vec<RunObservation> {
    outputs
        .iter()
        .enumerate()
        .map(|(command_index, output)| {
            let mut normalized =
                normalize_output(&output.stdout, &output.stderr, shadow_root, project_root);
            for additional_root in additional_shadow_roots {
                normalized = String::from_utf8_lossy(&normalized)
                    .replace(&additional_root.to_string_lossy().to_string(), "$PROJECT")
                    .into_bytes();
                if let Some(workspace) = additional_root.parent() {
                    normalized = String::from_utf8_lossy(&normalized)
                        .replace(&workspace.to_string_lossy().to_string(), "$PROOFBOUND_WORK")
                        .into_bytes();
                }
            }
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
    let mut text = strip_ansi(&text)
        .replace(&shadow_root.to_string_lossy().to_string(), "$PROJECT")
        .replace(&project_root.to_string_lossy().to_string(), "$PROJECT");
    if let Some(workspace) = shadow_root.parent() {
        text = text.replace(&workspace.to_string_lossy().to_string(), "$PROOFBOUND_WORK");
    }
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

fn validate_transcription_path(path: &str) -> Result<(), AdapterError> {
    validate_relative_path(path)?;
    if !path.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        || path.contains(['\\', '*', '?', '[', ']', '{', '}'])
        || path.contains("//")
        || path.ends_with('/')
        || path.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || TRANSLATION_RESERVED_PATH_COMPONENTS.contains(&component)
        })
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
        if entry.file_type().is_dir() {
            // Directories are execution scaffolding, not reviewed inputs.
            // Derive only the parents needed by copied files so empty
            // directory topology cannot affect a fresh shadow.
            continue;
        }
        if !entry.file_type().is_file() {
            return Err(AdapterError::UnsafePath(relative.display().to_string()));
        }
        let target = project.join(relative);
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
fn safe_format(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let Some((name, version)) = value.split_once('/') else {
        return false;
    };
    !name.contains('/')
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && name.split(['-', '_', '.', '+']).all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
        && version
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit() && byte != b'0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
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
fn valid_local_id(value: &str) -> bool {
    value.len() <= 128
        && value.split('-').enumerate().all(|(index, segment)| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && (index != 0
                    || segment
                        .bytes()
                        .next()
                        .is_some_and(|byte| byte.is_ascii_lowercase()))
        })
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

    fn transcription_unit() -> EvidenceUnitManifest {
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/2",
            "id": "round-trip",
            "adapter": "trusted-transcription",
            "kind": "trusted-transcription",
            "claims": ["CLAIM-ONE"],
            "tier": 1,
            "operation": { "type": "transcription" },
            "binding_mode": "external-round-trip",
            "expected_inventory": ["committed.txt", "source.bin"],
            "inputs": ["committed.txt", "driver.py", "source.bin"],
            "outputs": [],
            "environment_allowlist": ["PATH"],
            "transcription": {
                "schema": "proofbound-trusted-transcription/1",
                "source": "source.bin",
                "committed_transcription": "committed.txt",
                "driver": "driver.py",
                "source_format": "subject-bytes/1",
                "transcribed_format": "typed-literals/1",
                "driver_abi": "proofbound-transcription-driver/1"
            },
            "resource_budget": {
                "time_seconds": 30,
                "disk_bytes": 16777216,
                "memory_bytes": 16777216
            }
        }))
        .unwrap()
    }

    fn write_transcription_fixture(root: &Path, driver: &str) {
        fs::write(root.join("source.bin"), b"source bytes\n").unwrap();
        fs::write(root.join("committed.txt"), b"typed:source bytes\n").unwrap();
        fs::write(root.join("driver.py"), driver).unwrap();
    }

    const VALID_TRANSCRIPTION_DRIVER: &str = r#"import argparse
from pathlib import Path

p = argparse.ArgumentParser()
sub = p.add_subparsers(dest="mode", required=True)
t = sub.add_parser("transcribe")
t.add_argument("--source", required=True)
t.add_argument("--output", required=True)
r = sub.add_parser("reencode")
r.add_argument("--transcription", required=True)
r.add_argument("--output", required=True)
a = p.parse_args()
if a.mode == "transcribe":
    Path(a.output).write_bytes(b"typed:" + Path(a.source).read_bytes())
else:
    data = Path(a.transcription).read_bytes()
    if not data.startswith(b"typed:"):
        raise SystemExit(2)
    Path(a.output).write_bytes(data[len(b"typed:"):])
"#;

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
    fn runner_summaries_require_exactly_one_selected_test() {
        let rust = ProcessOutput {
            status: Some(0),
            stdout: b"running 1 test\ntest module::one ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n".to_vec(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        };
        assert!(ensure_one_rust_test_ran("module::one", &rust).is_ok());
        let mut eleven = rust.clone();
        eleven.stdout = b"running 11 tests\ntest module::one ... ok\n\ntest result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n".to_vec();
        assert!(ensure_one_rust_test_ran("module::one", &eleven).is_err());

        let failed = ProcessOutput {
            status: Some(101),
            stdout: b"running 1 test\ntest module::one ... FAILED\n\nfailures:\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n".to_vec(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        };
        assert!(ensure_one_rust_test_failed("module::one", &failed).is_ok());
        let mut wrong_exit = failed.clone();
        wrong_exit.status = Some(1);
        assert!(ensure_one_rust_test_failed("module::one", &wrong_exit).is_err());
        let mut forged_pass = failed;
        forged_pass.stdout = rust.stdout.clone();
        assert!(ensure_one_rust_test_failed("module::one", &forged_pass).is_err());

        let python = ProcessOutput {
            status: Some(0),
            stdout: b".                                                                        [100%]\n1 passed in 0.01s\n".to_vec(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        };
        assert!(ensure_one_python_test_ran("test_sample::test_one", &python).is_ok());
        let mut eleven = python.clone();
        eleven.stdout = b"...........                                                              [100%]\n11 passed in 0.01s\n".to_vec();
        assert!(ensure_one_python_test_ran("test_sample::test_one", &eleven).is_err());
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
    fn shadow_derives_directory_topology_only_from_copied_files() {
        let source = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("empty/nested")).unwrap();
        fs::create_dir_all(source.path().join("populated/nested")).unwrap();
        let copied_file = source.path().join("populated/nested/helper.sh");
        fs::write(&copied_file, b"#!/bin/sh\nexit 0\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&copied_file, fs::Permissions::from_mode(0o751)).unwrap();
        }

        let shadow = shadow_project(source.path(), 1024).unwrap();
        let project = shadow.path().join("project");
        assert!(!project.join("empty").exists());
        assert_eq!(
            fs::read(project.join("populated/nested/helper.sh")).unwrap(),
            b"#!/bin/sh\nexit 0\n"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(project.join("populated/nested/helper.sh"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o751
            );
        }
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
    fn every_route_rejects_empty_inventory_before_tool_execution() {
        let mut unit = checker_unit(
            "independent-check",
            "independent-check",
            "independent-check",
        );
        unit.expected_inventory.clear();
        assert!(matches!(
            validate_unit(&request("independent-check", "check", &unit), &unit),
            Err(AdapterError::Inventory(_))
        ));
    }

    #[test]
    fn inventory_preflight_uses_character_limits_and_rejects_unicode_controls() {
        let mut unit = checker_unit(
            "independent-check",
            "independent-check",
            "independent-check",
        );

        for invalid in [
            "   ".to_owned(),
            "registered\u{0085}item".to_owned(),
            "x".repeat(4097),
        ] {
            unit.expected_inventory = vec![invalid];
            assert!(matches!(
                validate_unit(&request("independent-check", "check", &unit), &unit),
                Err(AdapterError::Inventory(_))
            ));
        }

        unit.expected_inventory = vec!["é".repeat(4096)];
        assert!(validate_unit(&request("independent-check", "check", &unit), &unit).is_ok());
    }

    #[test]
    fn test_runners_reject_exhaustive_kind_relabeling() {
        let mut rust = generator_unit();
        rust.adapter = AdapterKind::RustTest;
        rust.kind = EvidenceKind::ExhaustiveCheck;
        rust.operation.kind = OperationKind::CargoTest;
        assert!(validate_unit(&request("rust-test", "check", &rust), &rust).is_err());

        let mut python = generator_unit();
        python.kind = EvidenceKind::ExhaustiveCheck;
        python.operation.kind = OperationKind::Pytest;
        assert!(validate_unit(&request("python-test", "check", &python), &python).is_err());
    }

    #[test]
    fn trusted_transcription_requires_exact_typed_configuration() {
        let unit = transcription_unit();
        assert_eq!(
            validate_unit(&request("trusted-transcription", "check", &unit), &unit).unwrap(),
            TestFlavor::TrustedTranscription
        );

        let mut v1 = unit.clone();
        v1.schema = "proofbound-evidence-unit/1".to_owned();
        assert!(validate_unit(&request("trusted-transcription", "check", &v1), &v1).is_err());

        let mut strong_binding = unit.clone();
        strong_binding.binding_mode = Some(BindingMode::DigestTheorem);
        assert!(
            validate_unit(
                &request("trusted-transcription", "check", &strong_binding),
                &strong_binding
            )
            .is_err()
        );

        let mut extra_input = unit.clone();
        extra_input.inputs.push("unreviewed.txt".to_owned());
        assert!(
            validate_unit(
                &request("trusted-transcription", "check", &extra_input),
                &extra_input
            )
            .is_err()
        );

        let mut empty_inventory = unit.clone();
        empty_inventory.expected_inventory.clear();
        assert!(matches!(
            validate_unit(
                &request("trusted-transcription", "check", &empty_inventory),
                &empty_inventory
            ),
            Err(AdapterError::Inventory(_))
        ));

        let mut escaped = unit.clone();
        escaped.transcription.as_mut().unwrap().source = "../source.bin".to_owned();
        assert!(matches!(
            validate_unit(
                &request("trusted-transcription", "check", &escaped),
                &escaped
            ),
            Err(AdapterError::UnsafePath(_))
        ));
        for unsafe_path in [
            "a//source.bin",
            ".proofbound/source.bin",
            "glob/*.bin",
            "unicode/é.bin",
            "back\\slash.bin",
        ] {
            let mut unsafe_unit = unit.clone();
            unsafe_unit.transcription.as_mut().unwrap().source = unsafe_path.to_owned();
            assert!(matches!(
                validate_unit(
                    &request("trusted-transcription", "check", &unsafe_unit),
                    &unsafe_unit
                ),
                Err(AdapterError::UnsafePath(_))
            ));
        }

        let mut arbitrary_arguments = unit.clone();
        arbitrary_arguments.operation.arguments = vec!["--smuggle".to_owned()];
        assert!(
            validate_unit(
                &request("trusted-transcription", "check", &arbitrary_arguments),
                &arbitrary_arguments
            )
            .is_err()
        );

        let mut no_path = unit.clone();
        no_path.environment_allowlist.clear();
        assert!(
            validate_unit(
                &request("trusted-transcription", "check", &no_path),
                &no_path
            )
            .is_err(),
            "the sealed adapter process must receive its exact PATH capability"
        );

        let mut extra_environment = unit.clone();
        extra_environment
            .environment_allowlist
            .push("HOME".to_owned());
        assert!(
            validate_unit(
                &request("trusted-transcription", "check", &extra_environment),
                &extra_environment
            )
            .is_err(),
            "transcription must not gain undeclared ambient environment"
        );
    }

    #[test]
    fn trusted_transcription_observes_connected_raw_byte_round_trip() {
        let root = tempfile::tempdir().unwrap();
        write_transcription_fixture(root.path(), VALID_TRANSCRIPTION_DRIVER);
        let unit = transcription_unit();
        let (observation, inventory) = execute_request(
            &request("trusted-transcription", "check", &unit),
            root.path(),
            &mut RealExecutor,
        )
        .unwrap();
        let observation = observation.unwrap();
        assert_eq!(inventory, ["committed.txt", "source.bin"]);
        assert_eq!(observation.inventory, inventory);
        assert_eq!(observation.commands.len(), 3);
        assert_eq!(observation.runs.len(), 3);
        assert_eq!(observation.generated_artifacts.len(), 2);
        assert_eq!(observation.normalization, "exact-transcription-bytes/1");
        assert!(observation.artifact_binding.is_none());

        for forbidden in ["accepted", "tcb_node", "claim_id", "binding_valid"] {
            let mut smuggled = serde_json::to_value(&observation).unwrap();
            smuggled["trusted_transcription"][forbidden] = json!(true);
            assert!(
                serde_json::from_value::<AdapterObservation>(smuggled).is_err(),
                "checker-authored `{forbidden}` must have no observation representation"
            );
        }

        let facts = observation.trusted_transcription.unwrap();
        assert_eq!(facts.schema, "proofbound-trusted-transcription/1");
        assert_eq!(facts.source.logical_name, "source.bin");
        assert_eq!(facts.committed_transcription.logical_name, "committed.txt");
        assert_eq!(facts.driver.logical_name, "driver.py");
        assert_eq!(
            facts.transcribed_candidate.sha256,
            facts.committed_transcription.sha256
        );
        assert_eq!(
            facts.transcribed_candidate.size_bytes,
            facts.committed_transcription.size_bytes
        );
        assert_eq!(facts.reencoded_source.sha256, facts.source.sha256);
        assert_eq!(facts.reencoded_source.size_bytes, facts.source.size_bytes);
        assert_ne!(
            facts.transcriber_role_identity,
            facts.reencoder_role_identity
        );
        assert_eq!(
            observation.commands[2].args[2], "--transcription",
            "the second fixed ABI call must consume the candidate"
        );
        assert!(
            observation.commands[2].args[3]
                .ends_with("/trusted-transcription/round-trip/transcribe/candidate.out")
        );
    }

    #[test]
    fn trusted_transcription_inventory_executes_but_is_not_assurance_evidence() {
        let root = tempfile::tempdir().unwrap();
        write_transcription_fixture(root.path(), VALID_TRANSCRIPTION_DRIVER);
        let unit = transcription_unit();
        let (observation, inventory) = execute_request(
            &request("trusted-transcription", "inventory", &unit),
            root.path(),
            &mut RealExecutor,
        )
        .unwrap();
        assert_eq!(inventory, ["committed.txt", "source.bin"]);
        assert!(observation.is_none());
    }

    #[test]
    fn trusted_transcription_rejects_missing_extra_partial_and_trailing_outputs() {
        let cases = [
            (
                "missing",
                r#"import argparse
p=argparse.ArgumentParser(); p.add_argument("mode"); p.add_argument("--source"); p.add_argument("--output"); p.parse_args()
"#,
            ),
            (
                "extra",
                r#"import argparse
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("mode"); p.add_argument("--source"); p.add_argument("--output"); a=p.parse_args(); Path(a.output).write_bytes(b"typed:"+Path(a.source).read_bytes()); Path(a.output).with_name("extra").write_bytes(b"smuggled")
"#,
            ),
            (
                "partial",
                r#"import argparse
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("mode"); p.add_argument("--source"); p.add_argument("--output"); a=p.parse_args(); Path(a.output).write_bytes(b"typed:source")
"#,
            ),
            (
                "trailing",
                r#"import argparse
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument("mode"); p.add_argument("--source"); p.add_argument("--output"); a=p.parse_args(); Path(a.output).write_bytes(b"typed:"+Path(a.source).read_bytes()+b"trailing")
"#,
            ),
        ];
        for (label, driver) in cases {
            let root = tempfile::tempdir().unwrap();
            write_transcription_fixture(root.path(), driver);
            let result = execute_request(
                &request("trusted-transcription", "check", &transcription_unit()),
                root.path(),
                &mut RealExecutor,
            );
            assert!(result.is_err(), "{label} output must fail closed");
        }
    }

    #[test]
    fn trusted_transcription_rejects_stream_output_and_shadow_mutation() {
        for (label, driver) in [
            (
                "stdout",
                VALID_TRANSCRIPTION_DRIVER.replace(
                    "if a.mode == \"transcribe\":",
                    "print('unframed trailing output')\nif a.mode == \"transcribe\":",
                ),
            ),
            (
                "mutation",
                VALID_TRANSCRIPTION_DRIVER.replace(
                    "if a.mode == \"transcribe\":",
                    "Path(a.source).write_bytes(b'mutated')\nif a.mode == \"transcribe\":",
                ),
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            write_transcription_fixture(root.path(), &driver);
            let result = execute_request(
                &request("trusted-transcription", "check", &transcription_unit()),
                root.path(),
                &mut RealExecutor,
            );
            assert!(result.is_err(), "{label} must fail closed");
            assert_eq!(
                fs::read(root.path().join("source.bin")).unwrap(),
                b"source bytes\n",
                "execution must remain confined to the disposable shadow"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_transcription_rejects_symlinked_inputs() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        write_transcription_fixture(root.path(), VALID_TRANSCRIPTION_DRIVER);
        fs::rename(
            root.path().join("source.bin"),
            root.path().join("real-source.bin"),
        )
        .unwrap();
        symlink("real-source.bin", root.path().join("source.bin")).unwrap();
        let result = execute_request(
            &request("trusted-transcription", "check", &transcription_unit()),
            root.path(),
            &mut RealExecutor,
        );
        assert!(matches!(result, Err(AdapterError::UnsafePath(_))));
    }

    #[test]
    fn generator_unit_has_exact_outputs_and_reserved_update_switch() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("fixtures")).unwrap();
        fs::write(
            root.path().join("generate.py"),
            br#"import argparse
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--update", action="store_true")
a = p.parse_args()
if not a.update:
    raise SystemExit(2)
path = Path("fixtures/generated.bin")
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(b"fixture")
"#,
        )
        .unwrap();
        fs::write(root.path().join("fixtures/generated.bin"), b"fixture").unwrap();
        let unit = generator_unit();
        assert_eq!(
            validate_unit(&request("python-test", "check", &unit), &unit).unwrap(),
            TestFlavor::Generator
        );

        let (observation, inventory) = execute_request(
            &request("python-test", "check", &unit),
            root.path(),
            &mut RealExecutor,
        )
        .unwrap();
        let observation = observation.unwrap();
        assert_eq!(inventory, ["fixtures/generated.bin"]);
        assert_eq!(observation.generated_artifacts.len(), 1);
        assert_eq!(
            observation.generated_artifacts[0].logical_name,
            inventory[0]
        );
        assert_eq!(
            observation.commands.last().unwrap().args.last().unwrap(),
            "--update",
            "verification regenerates into an output-free candidate"
        );

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
    fn generator_candidate_rejects_noop_missing_extra_drift_and_escape() {
        let cases = [
            (
                "noop",
                "import argparse\np=argparse.ArgumentParser(); p.add_argument('--update', action='store_true'); p.parse_args()\n",
            ),
            (
                "missing",
                "import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser(); p.add_argument('--update', action='store_true'); p.parse_args(); Path('fixtures').mkdir(parents=True, exist_ok=True)\n",
            ),
            (
                "extra",
                "import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser(); p.add_argument('--update', action='store_true'); p.parse_args(); Path('fixtures').mkdir(parents=True, exist_ok=True); Path('fixtures/generated.bin').write_bytes(b'fixture'); Path('fixtures/extra.bin').write_bytes(b'extra')\n",
            ),
            (
                "drift",
                "import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser(); p.add_argument('--update', action='store_true'); p.parse_args(); Path('fixtures').mkdir(parents=True, exist_ok=True); Path('fixtures/generated.bin').write_bytes(b'drift')\n",
            ),
            (
                "escape",
                "import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser(); p.add_argument('--update', action='store_true'); p.parse_args(); Path('fixtures').mkdir(parents=True, exist_ok=True); Path('fixtures/generated.bin').write_bytes(b'fixture'); Path('../escaped.bin').write_bytes(b'escape')\n",
            ),
        ];
        for (label, script) in cases {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("fixtures")).unwrap();
            fs::write(root.path().join("generate.py"), script).unwrap();
            fs::write(root.path().join("fixtures/generated.bin"), b"fixture").unwrap();
            let result = execute_request(
                &request("python-test", "check", &generator_unit()),
                root.path(),
                &mut RealExecutor,
            );
            assert!(result.is_err(), "{label} generator must fail closed");
            assert_eq!(
                fs::read(root.path().join("fixtures/generated.bin")).unwrap(),
                b"fixture",
                "candidate execution must not modify the committed output"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn generator_candidate_rejects_symlinked_output() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("fixtures")).unwrap();
        fs::write(
            root.path().join("generate.py"),
            "import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser(); p.add_argument('--update', action='store_true'); p.parse_args(); Path('fixtures').mkdir(parents=True, exist_ok=True); Path('fixtures/generated.bin').symlink_to('../generate.py')\n",
        )
        .unwrap();
        fs::write(root.path().join("fixtures/generated.bin"), b"fixture").unwrap();
        assert!(
            execute_request(
                &request("python-test", "check", &generator_unit()),
                root.path(),
                &mut RealExecutor,
            )
            .is_err()
        );
    }

    #[test]
    fn mutation_registry_is_strict_and_binds_witnesses() {
        let registry: MutationRegistry = toml::from_str(
            r#"
schema = "proofbound-mutation-registry/2"
subject = "rust:crate::f"
[mutation]
id = "remove-guard"
guard = "guard"
target_path = "src/lib.rs"
target_preimage_sha256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
mutant_path = "mutants/lib.rs"
mutant_sha256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
witness = "crate::tests::detects_guard"
witness_path = "tests/guard.rs"
witness_sha256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
affected_claims = ["CLAIM-ONE"]
"#,
        )
        .unwrap();
        assert_eq!(registry.mutation.witness, "crate::tests::detects_guard");
        assert!(serde_json::from_value::<MutationRegistry>(json!({"schema":"proofbound-mutation-registry/2","subject":"s","mutation":{},"extra":1})).is_err());
    }

    fn mutation_replay_fixture(root: &Path) -> EvidenceUnitManifest {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::create_dir_all(root.join("mutations/mutants/remove-guard")).unwrap();
        let target = b"pub fn guarded(value: bool) -> bool {\n    if !value { return false; }\n    true\n}\n";
        let mutant = b"pub fn guarded(_value: bool) -> bool {\n    true\n}\n";
        let witness = b"use mutation_fixture::guarded;\n\n#[test]\nfn guard_is_enforced() { assert!(!guarded(false)); }\n";
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"mutation-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"mutation-fixture\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), target).unwrap();
        fs::write(
            root.join("src/unrelated.rs"),
            b"pub const REVIEWED: bool = true;\n",
        )
        .unwrap();
        fs::write(root.join("mutations/mutants/remove-guard/lib.rs"), mutant).unwrap();
        fs::write(root.join("tests/witness.rs"), witness).unwrap();
        let registry = format!(
            r#"schema = "proofbound-mutation-registry/2"
subject = "rust:mutation-fixture::guarded"

[mutation]
id = "remove-guard"
guard = "false values must be rejected"
target_path = "src/lib.rs"
target_preimage_sha256 = "{}"
mutant_path = "mutations/mutants/remove-guard/lib.rs"
mutant_sha256 = "{}"
witness = "witness::guard_is_enforced"
witness_path = "tests/witness.rs"
witness_sha256 = "{}"
affected_claims = ["CLAIM-ONE"]
"#,
            sha256_bytes(target),
            sha256_bytes(mutant),
            sha256_bytes(witness),
        );
        fs::write(root.join("mutations/remove-guard.toml"), registry).unwrap();
        serde_json::from_value(json!({
            "schema": "proofbound-evidence-unit/3",
            "id": "remove-guard",
            "adapter": "rust-test",
            "kind": "mutation-witness",
            "claims": ["CLAIM-ONE"],
            "tier": 0,
            "operation": {
                "type": "cargo-test",
                "package": "mutation-fixture",
                "manifest": "Cargo.toml"
            },
            "expected_inventory": ["remove-guard"],
            "inputs": [
                "mutations/mutants/remove-guard/lib.rs",
                "mutations/remove-guard.toml",
                "src/lib.rs",
                "tests/witness.rs"
            ],
            "outputs": [],
            "environment_allowlist": ["CARGO_HOME", "PATH", "RUSTUP_HOME"],
            "mutation": {
                "schema": "proofbound-mutation-replay/1",
                "registry": "mutations/remove-guard.toml"
            },
            "resource_budget": {
                "time_seconds": 60,
                "disk_bytes": 536870912,
                "memory_bytes": 1073741824
            }
        }))
        .unwrap()
    }

    #[test]
    fn registered_mutation_replays_in_two_shadows_and_preserves_root() {
        let root = tempfile::tempdir().unwrap();
        let unit = mutation_replay_fixture(root.path());
        let root_target = fs::read(root.path().join("src/lib.rs")).unwrap();
        let mutant = fs::read(root.path().join("mutations/mutants/remove-guard/lib.rs")).unwrap();

        let (observation, inventory) = execute_request(
            &request("rust-test", "check", &unit),
            root.path(),
            &mut RealExecutor,
        )
        .unwrap();
        let observation = observation.unwrap();
        let replay = observation.mutation_replay.as_ref().unwrap();
        assert_eq!(observation.schema, "proofbound-adapter-observation/2");
        assert_eq!(inventory, ["remove-guard"]);
        assert_eq!(replay.mutation_id, "remove-guard");
        assert_eq!(replay.target_preimage.logical_name, "src/lib.rs");
        assert_eq!(replay.target_postimage.logical_name, "src/lib.rs");
        assert_eq!(replay.target_postimage.sha256, sha256_bytes(&mutant));
        assert_eq!(
            replay.mutant_artifact.sha256,
            replay.target_postimage.sha256
        );
        assert_eq!(observation.input_artifacts.len(), 4);
        assert_eq!(
            observation.generated_artifacts.as_slice(),
            std::slice::from_ref(&replay.target_postimage)
        );
        assert_eq!(replay.expected_failure.allowed_exit_codes, [101]);
        assert_eq!(
            observation.runs[replay.baseline_run_index].exit_code,
            Some(0)
        );
        assert_eq!(
            observation.runs[replay.expected_failure.run_index].exit_code,
            Some(101)
        );
        let baseline_program = &observation.commands[replay.baseline_run_index].program;
        let mutant_program = &observation.commands[replay.expected_failure.run_index].program;
        assert_ne!(baseline_program, mutant_program);
        assert!(baseline_program.starts_with("$BASELINE/target/"));
        assert!(mutant_program.starts_with("$MUTANT/target/"));
        assert_eq!(
            fs::read(root.path().join("src/lib.rs")).unwrap(),
            root_target
        );
    }

    #[test]
    fn mutation_replay_rejects_legacy_direct_units_and_unsafe_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut unit = mutation_replay_fixture(root.path());
        unit.schema = "proofbound-evidence-unit/1".to_owned();
        unit.mutation = None;
        assert!(validate_unit(&request("rust-test", "check", &unit), &unit).is_err());
        for path in [
            "../src/lib.rs",
            "target/mutant.rs",
            ".proofbound/mutant.rs",
            "mutations//mutant.rs",
            "mutations/mutant",
            "mutations/é.rs",
        ] {
            assert!(validate_mutation_path(path).is_err(), "accepted {path:?}");
        }
    }

    enum AdversarialMutationLocation {
        Shadow,
        ReviewedRoot(PathBuf),
    }

    struct TreeMutatingExecutor {
        inner: RealExecutor,
        location: AdversarialMutationLocation,
        mutated: bool,
    }

    impl Executor for TreeMutatingExecutor {
        fn run(
            &mut self,
            spec: &ProcessSpec,
            cwd: &Path,
            environment: &BTreeMap<String, String>,
            timeout: Duration,
        ) -> Result<ProcessOutput, AdapterError> {
            let output = self.inner.run(spec, cwd, environment, timeout)?;
            if !self.mutated && spec.args.last().is_some_and(|arg| arg == "--exact") {
                let path = match &self.location {
                    AdversarialMutationLocation::Shadow => cwd.join("src/unrelated.rs"),
                    AdversarialMutationLocation::ReviewedRoot(root) => {
                        root.join("src/unrelated.rs")
                    }
                };
                fs::write(path, b"pub const REVIEWED: bool = false;\n")?;
                self.mutated = true;
            }
            Ok(output)
        }
    }

    #[test]
    fn mutation_replay_rejects_unrelated_reviewed_shadow_changes() {
        let root = tempfile::tempdir().unwrap();
        let unit = mutation_replay_fixture(root.path());
        let result = execute_request(
            &request("rust-test", "check", &unit),
            root.path(),
            &mut TreeMutatingExecutor {
                inner: RealExecutor,
                location: AdversarialMutationLocation::Shadow,
                mutated: false,
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("baseline mutation witness")
        );
        assert_eq!(
            fs::read(root.path().join("src/unrelated.rs")).unwrap(),
            b"pub const REVIEWED: bool = true;\n"
        );
    }

    #[test]
    fn mutation_replay_rejects_unrelated_reviewed_root_changes() {
        let root = tempfile::tempdir().unwrap();
        let unit = mutation_replay_fixture(root.path());
        let result = execute_request(
            &request("rust-test", "check", &unit),
            root.path(),
            &mut TreeMutatingExecutor {
                inner: RealExecutor,
                location: AdversarialMutationLocation::ReviewedRoot(root.path().to_owned()),
                mutated: false,
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mutation replay reviewed root")
        );
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
            trusted_transcription: None,
            mutation_replay: None,
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

        let mut controlled_name = valid.clone();
        controlled_name["artifact_logical_name"] = json!("artifact\u{0085}.bin");
        let error = validate_artifact_checker_report(
            &canonical_json(&controlled_name).unwrap(),
            &unit,
            &canonical_root,
        )
        .unwrap_err();
        assert!(error.to_string().contains("result ABI"));

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

    #[test]
    fn independent_checker_report_is_canonical_nonempty_and_exact() {
        let unit = checker_unit(
            "independent-check",
            "independent-check",
            "independent-check",
        );
        let valid = json!({
            "schema": "proofbound-independent-check-result/1",
            "accepted": true,
            "inventory": ["published-artifact"]
        });
        assert_eq!(
            validate_independent_checker_report(&canonical_json(&valid).unwrap(), &unit).unwrap(),
            ["published-artifact"]
        );

        for invalid in [
            json!({
                "schema": "proofbound-independent-check-result/1",
                "accepted": true,
                "inventory": []
            }),
            json!({
                "schema": "proofbound-independent-check-result/1",
                "accepted": true,
                "inventory": ["extra"]
            }),
            json!({
                "schema": "proofbound-independent-check-result/1",
                "accepted": true,
                "inventory": ["published-artifact", "published-artifact"]
            }),
            json!({
                "schema": "proofbound-independent-check-result/1",
                "accepted": false,
                "inventory": ["published-artifact"]
            }),
        ] {
            assert!(
                validate_independent_checker_report(&canonical_json(&invalid).unwrap(), &unit)
                    .is_err()
            );
        }

        let mut unknown = valid.clone();
        unknown["claims"] = json!(["CLAIM-ONE"]);
        assert!(
            validate_independent_checker_report(&canonical_json(&unknown).unwrap(), &unit).is_err()
        );
        let mut trailing = canonical_json(&valid).unwrap();
        trailing.push(b'\n');
        assert!(validate_independent_checker_report(&trailing, &unit).is_err());
    }

    #[test]
    fn independent_inventory_runs_checker_and_rejects_exit_status_only() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("checker.py"), b"raise SystemExit(0)\n").unwrap();
        fs::write(root.path().join("artifact.bin"), b"artifact").unwrap();
        let unit = checker_unit(
            "independent-check",
            "independent-check",
            "independent-check",
        );

        let mut exit_only = FakeExecutor::default();
        for stdout in [b"Python 3.12.0\n".as_slice(), b"".as_slice()] {
            exit_only.outputs.push_back(ProcessOutput {
                status: Some(0),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
                truncated: false,
                duration_ms: 1,
            });
        }
        assert!(matches!(
            execute_request(
                &request("independent-check", "inventory", &unit),
                root.path(),
                &mut exit_only,
            ),
            Err(AdapterError::Inventory(_))
        ));
        assert_eq!(exit_only.seen.len(), 2, "inventory must run the checker");

        let mut exact = FakeExecutor::default();
        exact.outputs.push_back(ProcessOutput {
            status: Some(0),
            stdout: b"Python 3.12.0\n".to_vec(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        });
        exact.outputs.push_back(ProcessOutput {
            status: Some(0),
            stdout: canonical_json(&json!({
                "schema": "proofbound-independent-check-result/1",
                "accepted": true,
                "inventory": ["published-artifact"]
            }))
            .unwrap(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        });
        let (observation, inventory) = execute_request(
            &request("independent-check", "inventory", &unit),
            root.path(),
            &mut exact,
        )
        .unwrap();
        assert_eq!(inventory, ["published-artifact"]);
        assert!(observation.is_none());
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
