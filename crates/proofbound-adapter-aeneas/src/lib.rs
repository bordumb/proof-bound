//! Manifest-driven Charon/Aeneas translation adapter.
//!
//! The translation unit is authoritative.  Extraction and translation are
//! performed twice in an isolated shadow checkout, pretty-printed LLBC and
//! normalized generated artifacts must agree byte-for-byte, and `check` never
//! writes the reviewed tree.  Missing or unpinned tools are an explicit
//! non-success response, never evidence.

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
    AdapterDiagnostic, AdapterKind, AdapterRequest, AdapterResponse, EvidenceUnitManifest,
    ExternalBridge, ImportMappingMode, OperationKind, ProjectManifest, TemplateAxiom,
    TranslationUnitManifest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

pub const PROTOCOL_SCHEMA: &str = "proofbound-adapter-protocol/1";
pub const OBSERVATION_SCHEMA: &str = "proofbound-adapter-observation/1";
pub const ADAPTER_ID: &str = "charon-aeneas";
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
    pub value_sha256: Option<String>,
    pub secret: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunObservation {
    pub command_index: usize,
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
    pub peak_memory_bytes: Option<u64>,
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
    #[error("translation tool `{program}` is unavailable: {source}")]
    ToolUnavailable {
        program: String,
        source: std::io::Error,
    },
    #[error("translation toolchain is unavailable or unpinned: {0}")]
    Toolchain(String),
    #[error("tool exceeded its {0} ms time budget")]
    Timeout(u64),
    #[error("invalid request: {0}")]
    Request(String),
    #[error("invalid translation unit: {0}")]
    Unit(String),
    #[error("unsafe path `{0}`")]
    UnsafePath(String),
    #[error("translation inventory is invalid: {0}")]
    Inventory(String),
    #[error("deterministic translation check failed: {0}")]
    Determinism(String),
    #[error("generated artifact audit failed: {0}")]
    Generated(String),
    #[error("translation tool failed: {0}")]
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
                "PB-AENEAS-1001",
                "install the manifest-pinned Charon and Aeneas executables and expose them through PATH",
            ),
            Self::Toolchain(_) => (
                "PB-AENEAS-1002",
                "pin concrete Charon/Aeneas revisions and matching Rust/Lean toolchains before translating",
            ),
            Self::Timeout(_) | Self::Budget(_) => (
                "PB-AENEAS-1003",
                "review the workload and increase the manifest budget only if justified",
            ),
            Self::Request(_) => (
                "PB-AENEAS-1004",
                "send canonical proofbound-adapter-protocol/1 JSON with no unknown fields",
            ),
            Self::Unit(_) => (
                "PB-AENEAS-1005",
                "make the evidence, translation, project, and toolchain manifests agree exactly",
            ),
            Self::UnsafePath(_) => (
                "PB-AENEAS-1006",
                "use relative non-symlink paths contained by their declared ownership tree",
            ),
            Self::Inventory(_) => (
                "PB-AENEAS-1007",
                "make translated symbol/report inventory match the authoritative translation manifest",
            ),
            Self::Determinism(_) => (
                "PB-AENEAS-1008",
                "reproduce both runs and remove nondeterminism before accepting generated output",
            ),
            Self::Generated(_) => (
                "PB-AENEAS-1009",
                "regenerate with update after reviewing bridge, axiom, warning, and ownership changes",
            ),
            Self::ToolFailed(_) => (
                "PB-AENEAS-1010",
                "reproduce the typed Charon/Aeneas invocation and fix extraction or translation",
            ),
            Self::Io(_) | Self::Internal(_) => (
                "PB-AENEAS-1099",
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TranslationToolchainLock {
    schema: String,
    charon_revision: String,
    aeneas_revision: String,
    rust_toolchain: String,
    lean_toolchain: String,
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
        adapter: ADAPTER_ID.to_owned(),
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
            "protocol constants do not match the Charon/Aeneas adapter".to_owned(),
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
    let evidence: EvidenceUnitManifest = serde_json::from_value(request.unit.clone())
        .map_err(|error| AdapterError::Unit(error.to_string()))?;
    validate_evidence_unit(&evidence)?;
    let translation_path = evidence.operation.manifest.as_deref().ok_or_else(|| {
        AdapterError::Unit("translation operation requires operation.manifest".to_owned())
    })?;
    let translation_bytes = read_safe_file(&root, translation_path, MAX_REQUEST_BYTES)?;
    let translation: TranslationUnitManifest = toml::from_str(
        std::str::from_utf8(&translation_bytes)
            .map_err(|error| AdapterError::Unit(error.to_string()))?,
    )
    .map_err(|error| AdapterError::Unit(error.to_string()))?;
    validate_translation_unit(&root, &evidence, &translation)?;

    let project_path = root.join("proofbound.toml");
    reject_symlink_components(&root, &project_path)?;
    let project_bytes = fs::read(&project_path)
        .map_err(|error| AdapterError::Unit(format!("could not read proofbound.toml: {error}")))?;
    if project_bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(AdapterError::Unit(
            "proofbound.toml exceeds 2 MiB".to_owned(),
        ));
    }
    let project: ProjectManifest = toml::from_str(
        std::str::from_utf8(&project_bytes)
            .map_err(|error| AdapterError::Unit(error.to_string()))?,
    )
    .map_err(|error| AdapterError::Unit(format!("proofbound.toml: {error}")))?;
    if project.schema != "proofbound-project/1" {
        return Err(AdapterError::Unit(
            "project manifest schema is not proofbound-project/1".to_owned(),
        ));
    }
    let lock_path = project.toolchains.translation.as_deref().ok_or_else(|| {
        AdapterError::Toolchain("project manifest does not pin a translation toolchain".to_owned())
    })?;
    let lock_bytes = read_safe_file(&root, lock_path, MAX_REQUEST_BYTES)?;
    let lock: TranslationToolchainLock = toml::from_str(
        std::str::from_utf8(&lock_bytes)
            .map_err(|error| AdapterError::Toolchain(error.to_string()))?,
    )
    .map_err(|error| AdapterError::Toolchain(error.to_string()))?;
    validate_toolchain_lock(&root, &lock)?;
    validate_external_boundaries(&root, &translation)?;

    let mut environment = allowed_environment(&evidence.environment_allowlist)?;
    if let Some(path) = std::env::var_os("PATH") {
        environment
            .entry("PATH".to_owned())
            .or_insert_with(|| path.to_string_lossy().into_owned());
    }
    environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    environment.insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
    environment.insert("TERM".to_owned(), "dumb".to_owned());
    let environment_observation = observe_environment(&environment);
    let started_unix_ms = unix_ms()?;
    let started = Instant::now();
    let (tool, mut commands, mut outputs) = translation_tool_identity(
        &root,
        &lock,
        &environment,
        &environment_observation,
        executor,
    )?;
    if request.operation == "doctor" {
        return Ok((None, Vec::new()));
    }

    let budget = BudgetObservation {
        time_ms: translation
            .resource_budget
            .time_seconds
            .saturating_mul(1000),
        disk_bytes: translation.resource_budget.disk_bytes,
        memory_bytes: translation.resource_budget.memory_bytes,
    };
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
    let metadata_output = executor.run(
        &metadata_spec,
        &shadow_root,
        &environment,
        remaining_time(started, budget.time_ms)?,
    )?;
    ensure_success(&metadata_spec, &metadata_output)?;
    let packages =
        parse_package_manifests(&metadata_output.stdout, &translation.packages, &shadow_root)?;
    commands.push(observe_command(&metadata_spec, &environment_observation));
    outputs.push(metadata_output);

    let first = execute_translation_run(
        1,
        &translation,
        &lock,
        &packages,
        &shadow_root,
        shadow.path(),
        &environment,
        &environment_observation,
        executor,
        started,
        budget.time_ms,
    )?;
    let second = execute_translation_run(
        2,
        &translation,
        &lock,
        &packages,
        &shadow_root,
        shadow.path(),
        &environment,
        &environment_observation,
        executor,
        started,
        budget.time_ms,
    )?;
    commands.extend(first.commands.clone());
    outputs.extend(first.outputs.clone());
    commands.extend(second.commands.clone());
    outputs.extend(second.outputs.clone());
    if first.normalized != second.normalized {
        let difference = first_difference(&first.normalized, &second.normalized);
        return Err(AdapterError::Determinism(format!(
            "two normalized runs differ at {difference}"
        )));
    }
    exact_symbol_inventory(&translation.start_from, &first.translated_symbols)?;
    audit_generated_inventory(&first.generated, &translation)?;

    let committed_dir = resolve_output_path(&root, &translation.generated_dir)?;
    match request.operation.as_str() {
        "inventory" | "check" | "reproduce" => {
            compare_committed_generated(&committed_dir, &first.generated)?
        }
        "update" => {
            ensure_clean_tree(&root)?;
            update_generated_directory(&committed_dir, &first.generated)?;
        }
        other => {
            return Err(AdapterError::Request(format!(
                "unexpected operation `{other}`"
            )));
        }
    }

    let disk_bytes = directory_size(shadow.path())?;
    if disk_bytes > budget.disk_bytes {
        return Err(AdapterError::Budget(format!(
            "shadow translation used {disk_bytes} bytes, limit is {}",
            budget.disk_bytes
        )));
    }
    if outputs.len() != commands.len() {
        return Err(AdapterError::Internal(
            "command/run inventory skew".to_owned(),
        ));
    }
    let runs = observe_runs(&outputs, &shadow_root, &root);
    let mut input_paths = evidence.inputs.clone();
    input_paths.extend([
        translation_path.to_owned(),
        "proofbound.toml".to_owned(),
        lock_path.to_owned(),
    ]);
    for bridge in &translation.external_bridges {
        input_paths.push(bridge.file.clone());
    }
    input_paths.push(translation.handwritten_refinement.clone());
    input_paths.sort();
    input_paths.dedup();
    let input_artifacts = collect_input_artifacts(&root, &input_paths)?;
    let generated_artifacts =
        artifact_map_observations(&first.generated, &translation.generated_dir);
    let unit_configuration =
        serde_json::json!({"evidence":request.unit,"translation":translation,"toolchain":lock});
    let unit_configuration_bytes = canonical_json(&unit_configuration)
        .map_err(|error| AdapterError::Internal(error.to_string()))?;
    let inventory = sorted_unique(translation.start_from.clone(), "translation symbols")?;
    let result = serde_json::json!({
        "artifacts": first.normalized.iter().map(|(path, bytes)| (path, sha256_bytes(bytes))).collect::<BTreeMap<_,_>>(),
        "inventory": inventory,
        "run_hashes": runs.iter().map(|run| &run.normalized_output_sha256).collect::<Vec<_>>(),
    });
    let completed_unix_ms = unix_ms()?;
    let observation = AdapterObservation {
        schema: OBSERVATION_SCHEMA.to_owned(),
        unit_id: evidence.id,
        evidence_kind: "source-refinement".to_owned(),
        outcome: ObservationOutcome::Passed,
        input_artifacts,
        generated_artifacts,
        tool,
        adapter: adapter_identity(),
        commands,
        runs,
        started_unix_ms,
        completed_unix_ms,
        deterministic_result_sha256: domain_hash(
            "proofbound-adapter-result/1",
            &canonical_json(&result).map_err(|error| AdapterError::Internal(error.to_string()))?,
        ),
        unit_configuration_sha256: domain_hash(
            "proofbound-unit-configuration/1",
            &unit_configuration_bytes,
        ),
        resource_budget: budget,
        resource_usage: UsageObservation {
            time_ms: elapsed_ms(started),
            peak_disk_bytes: disk_bytes,
            peak_memory_bytes: None,
        },
        inventory: inventory.clone(),
        normalization: translation.determinism_normalization,
    };
    Ok((Some(observation), inventory))
}

fn validate_evidence_unit(unit: &EvidenceUnitManifest) -> Result<(), AdapterError> {
    if unit.schema != "proofbound-evidence-unit/1"
        || unit.adapter != AdapterKind::CharonAeneas
        || unit.operation.kind != OperationKind::Translation
    {
        return Err(AdapterError::Unit(
            "expected a proofbound-evidence-unit/1 charon-aeneas translation operation".to_owned(),
        ));
    }
    require_unique("claims", &unit.claims)?;
    require_unique("targets", &unit.operation.targets)?;
    require_unique("inputs", &unit.inputs)?;
    require_unique("outputs", &unit.outputs)?;
    require_unique("environment", &unit.environment_allowlist)?;
    if unit.claims.is_empty() || unit.refinement_theorem.as_deref().is_none_or(str::is_empty) {
        return Err(AdapterError::Unit(
            "source-refinement evidence requires claims and refinement_theorem".to_owned(),
        ));
    }
    if !unit.outputs.is_empty() {
        return Err(AdapterError::Unit(
            "translation outputs are owned by the translation manifest, not the evidence unit"
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
    Ok(())
}

fn validate_translation_unit(
    root: &Path,
    evidence: &EvidenceUnitManifest,
    unit: &TranslationUnitManifest,
) -> Result<(), AdapterError> {
    if unit.schema != "proofbound-translation-unit/1"
        || unit.adapter != ADAPTER_ID
        || unit.determinism_runs != 2
        || unit.determinism_normalization != "pretty-printed-llbc/1"
        || !unit.forbid_generated_axioms
    {
        return Err(AdapterError::Unit("translation requires schema v1, two runs, pretty-printed-llbc/1, and forbidden generated axioms".to_owned()));
    }
    for (label, values) in [
        ("packages", &unit.packages),
        ("start_from", &unit.start_from),
        ("opaque", &unit.opaque),
        ("include", &unit.include),
        ("claims", &unit.claims),
    ] {
        require_unique(label, values)?;
    }
    if unit.packages.is_empty() || unit.start_from.is_empty() || unit.claims.is_empty() {
        return Err(AdapterError::Unit(
            "translation packages, start_from, and claims must be non-empty".to_owned(),
        ));
    }
    if evidence.operation.targets != unit.start_from
        || evidence.claims != unit.claims
        || evidence.resource_budget != unit.resource_budget
    {
        return Err(AdapterError::Unit(
            "evidence and translation manifests disagree on targets, claims, or budget".to_owned(),
        ));
    }
    for package in &unit.packages {
        if !safe_atom(package) {
            return Err(AdapterError::Unit(format!("invalid package `{package}`")));
        }
    }
    for symbol in unit
        .start_from
        .iter()
        .chain(&unit.opaque)
        .chain(&unit.include)
    {
        if !safe_symbol(symbol) {
            return Err(AdapterError::Unit(format!(
                "invalid translation symbol `{symbol}`"
            )));
        }
    }
    validate_relative_path(&unit.generated_dir)?;
    validate_relative_path(&unit.handwritten_refinement)?;
    if Path::new(&unit.generated_dir).components().count() < 2 {
        return Err(AdapterError::Unit(
            "generated_dir must not be a top-level project path".to_owned(),
        ));
    }
    if path_contains(&unit.generated_dir, &unit.handwritten_refinement) {
        return Err(AdapterError::Unit(
            "handwritten refinement must remain outside generated_dir".to_owned(),
        ));
    }
    resolve_existing(root, &unit.handwritten_refinement)?;
    if unit.import_mapping.is_none() {
        return Err(AdapterError::Unit(
            "translation unit requires an explicit import_mapping".to_owned(),
        ));
    }
    if let Some(mapping) = &unit.import_mapping {
        match mapping.mode {
            ImportMappingMode::ExternalSourceRoot => {
                if mapping.source_roots.is_empty() || mapping.rewrite_digest.is_some() {
                    return Err(AdapterError::Unit(
                        "external-source-root mapping requires roots and no rewrite digest"
                            .to_owned(),
                    ));
                }
                for path in &mapping.source_roots {
                    validate_relative_path(path)?;
                    resolve_existing(root, path)?;
                }
            }
            ImportMappingMode::AuditedRewrite => {
                if mapping.source_roots.is_empty()
                    || mapping
                        .rewrite_digest
                        .as_deref()
                        .is_none_or(|digest| !valid_digest(digest))
                {
                    return Err(AdapterError::Unit(
                        "audited-rewrite mapping requires roots and a sha256 rewrite digest"
                            .to_owned(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_toolchain_lock(
    root: &Path,
    lock: &TranslationToolchainLock,
) -> Result<(), AdapterError> {
    if lock.schema != "proofbound-translation-toolchain/1" {
        return Err(AdapterError::Toolchain(
            "unsupported lock schema".to_owned(),
        ));
    }
    for (name, revision) in [
        ("Charon", &lock.charon_revision),
        ("Aeneas", &lock.aeneas_revision),
    ] {
        if revision.trim().is_empty()
            || revision.starts_with("unavailable")
            || !revision
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() || matches!(ch, '.' | '-' | '_' | 'v'))
        {
            return Err(AdapterError::Toolchain(format!(
                "{name} revision `{revision}` is not a concrete pin"
            )));
        }
    }
    let rust = read_safe_file(root, "rust-toolchain.toml", MAX_REQUEST_BYTES)?;
    let rust_value: toml::Value = toml::from_str(
        std::str::from_utf8(&rust).map_err(|error| AdapterError::Toolchain(error.to_string()))?,
    )
    .map_err(|error| AdapterError::Toolchain(error.to_string()))?;
    let actual_rust = rust_value
        .get("toolchain")
        .and_then(|value| value.get("channel"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            AdapterError::Toolchain("rust-toolchain.toml has no toolchain.channel".to_owned())
        })?;
    let lean = std::str::from_utf8(&read_safe_file(root, "lean-toolchain", 1024)?)
        .map_err(|error| AdapterError::Toolchain(error.to_string()))?
        .trim()
        .to_owned();
    if actual_rust != lock.rust_toolchain || lean != lock.lean_toolchain {
        return Err(AdapterError::Toolchain(format!(
            "toolchain lock expects Rust `{}` / Lean `{}`, found `{actual_rust}` / `{lean}`",
            lock.rust_toolchain, lock.lean_toolchain
        )));
    }
    Ok(())
}

fn translation_tool_identity<E: Executor>(
    root: &Path,
    lock: &TranslationToolchainLock,
    environment: &BTreeMap<String, String>,
    environment_observation: &[EnvironmentObservation],
    executor: &mut E,
) -> Result<(ToolObservation, Vec<CommandObservation>, Vec<ProcessOutput>), AdapterError> {
    let specs = [
        ProcessSpec {
            program: "charon".to_owned(),
            args: vec!["--version".to_owned()],
        },
        ProcessSpec {
            program: "aeneas".to_owned(),
            args: vec!["--version".to_owned()],
        },
    ];
    let pins = [&lock.charon_revision, &lock.aeneas_revision];
    let mut outputs = Vec::new();
    let mut versions = Vec::new();
    for (spec, pin) in specs.iter().zip(pins) {
        let output = executor.run(spec, root, environment, Duration::from_secs(20))?;
        ensure_success(spec, &output)?;
        let bytes = if output.stdout.is_empty() {
            &output.stderr
        } else {
            &output.stdout
        };
        let version = std::str::from_utf8(bytes)
            .map_err(|error| AdapterError::Toolchain(error.to_string()))?
            .trim()
            .to_owned();
        if version.is_empty() || !version.contains(pin) {
            return Err(AdapterError::Toolchain(format!(
                "{} version `{version}` does not contain pinned revision `{pin}`",
                spec.program
            )));
        }
        versions.push(version);
        outputs.push(output);
    }
    let version = versions.join("; ");
    let commands = specs
        .iter()
        .map(|spec| observe_command(spec, environment_observation))
        .collect();
    Ok((
        ToolObservation {
            name: "Charon/Aeneas".to_owned(),
            version: version.clone(),
            identity_sha256: domain_hash("proofbound-tool-identity/1", version.as_bytes()),
        },
        commands,
        outputs,
    ))
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}
#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    manifest_path: PathBuf,
}

fn parse_package_manifests(
    bytes: &[u8],
    expected: &[String],
    shadow_root: &Path,
) -> Result<BTreeMap<String, PathBuf>, AdapterError> {
    let root = shadow_root.canonicalize()?;
    let metadata: CargoMetadata = serde_json::from_slice(bytes)
        .map_err(|error| AdapterError::Inventory(format!("cargo metadata: {error}")))?;
    let expected_set: BTreeSet<_> = expected.iter().map(String::as_str).collect();
    let mut result = BTreeMap::new();
    for package in metadata
        .packages
        .into_iter()
        .filter(|package| expected_set.contains(package.name.as_str()))
    {
        let manifest = package.manifest_path.canonicalize()?;
        if !manifest.starts_with(&root)
            || manifest.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml")
        {
            return Err(AdapterError::Inventory(format!(
                "package `{}` manifest escaped shadow project",
                package.name
            )));
        }
        if result.insert(package.name.clone(), manifest).is_some() {
            return Err(AdapterError::Inventory(format!(
                "duplicate package `{}`",
                package.name
            )));
        }
    }
    let actual: Vec<_> = result.keys().cloned().collect();
    exact_set("translation packages", expected, &actual)?;
    Ok(result)
}

#[derive(Clone, Debug)]
struct TranslationRun {
    commands: Vec<CommandObservation>,
    outputs: Vec<ProcessOutput>,
    normalized: BTreeMap<String, Vec<u8>>,
    generated: BTreeMap<String, Vec<u8>>,
    translated_symbols: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn execute_translation_run<E: Executor>(
    run_number: u8,
    unit: &TranslationUnitManifest,
    lock: &TranslationToolchainLock,
    package_manifests: &BTreeMap<String, PathBuf>,
    shadow_root: &Path,
    work_root: &Path,
    environment: &BTreeMap<String, String>,
    environment_observation: &[EnvironmentObservation],
    executor: &mut E,
    started: Instant,
    budget_ms: u64,
) -> Result<TranslationRun, AdapterError> {
    let run_root = work_root.join(format!("run-{run_number}"));
    fs::create_dir_all(&run_root)?;
    let llbc_dir = run_root.join("llbc");
    let generated_dir = run_root.join("generated");
    fs::create_dir_all(&llbc_dir)?;
    fs::create_dir_all(&generated_dir)?;
    let starts = group_start_symbols(&unit.packages, &unit.start_from)?;
    let mut commands = Vec::new();
    let mut outputs = Vec::new();
    for package in &unit.packages {
        let package_file = package.replace('-', "_");
        let llbc = llbc_dir.join(format!("{package_file}.llbc"));
        let manifest = package_manifests
            .get(package)
            .expect("validated package map");
        let charon_spec = ProcessSpec {
            program: "charon".to_owned(),
            args: build_charon_args(
                unit,
                starts.get(package).expect("grouped starts"),
                &llbc,
                manifest,
            ),
        };
        let output = executor.run(
            &charon_spec,
            shadow_root,
            environment,
            remaining_time(started, budget_ms)?,
        )?;
        ensure_success(&charon_spec, &output)?;
        if !llbc.is_file() {
            return Err(AdapterError::Inventory(format!(
                "Charon did not produce {}",
                llbc.display()
            )));
        }
        commands.push(observe_command(&charon_spec, environment_observation));
        outputs.push(output);

        let pretty_spec = ProcessSpec {
            program: "charon".to_owned(),
            args: vec![
                "pretty-print".to_owned(),
                llbc.to_string_lossy().into_owned(),
            ],
        };
        let pretty_output = executor.run(
            &pretty_spec,
            shadow_root,
            environment,
            remaining_time(started, budget_ms)?,
        )?;
        ensure_success(&pretty_spec, &pretty_output)?;
        if pretty_output.stdout.is_empty() {
            return Err(AdapterError::Determinism(format!(
                "Charon pretty-print for `{package}` was empty"
            )));
        }
        fs::write(
            llbc_dir.join(format!("{package_file}.llbc.pretty")),
            normalize_text_bytes(&pretty_output.stdout),
        )?;
        commands.push(observe_command(&pretty_spec, environment_observation));
        outputs.push(pretty_output);

        let package_output = if unit.packages.len() == 1 {
            generated_dir.clone()
        } else {
            generated_dir.join(&package_file)
        };
        fs::create_dir_all(&package_output)?;
        let aeneas_spec = ProcessSpec {
            program: "aeneas".to_owned(),
            args: build_aeneas_args(&llbc, &package_output),
        };
        let aeneas_output = executor.run(
            &aeneas_spec,
            shadow_root,
            environment,
            remaining_time(started, budget_ms)?,
        )?;
        ensure_success(&aeneas_spec, &aeneas_output)?;
        commands.push(observe_command(&aeneas_spec, environment_observation));
        outputs.push(aeneas_output);
    }
    let generated = collect_normalized_generated(&generated_dir, lock)?;
    if generated.is_empty() {
        return Err(AdapterError::Generated(
            "Aeneas produced no generated artifacts".to_owned(),
        ));
    }
    let mut normalized = BTreeMap::new();
    for entry in WalkDir::new(&llbc_dir)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(walk_error)?;
        if entry.file_type().is_symlink() {
            return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
        }
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("pretty")
        {
            let relative = entry
                .path()
                .strip_prefix(&run_root)
                .map_err(|_| AdapterError::Internal("LLBC path escaped run root".to_owned()))?
                .to_string_lossy()
                .replace('\\', "/");
            normalized.insert(relative, fs::read(entry.path())?);
        }
    }
    for (path, bytes) in &generated {
        normalized.insert(format!("generated/{path}"), bytes.clone());
    }
    let translated_symbols = translation_report_inventory(&generated, unit, lock)?;
    Ok(TranslationRun {
        commands,
        outputs,
        normalized,
        generated,
        translated_symbols,
    })
}

fn group_start_symbols(
    packages: &[String],
    starts: &[String],
) -> Result<BTreeMap<String, Vec<String>>, AdapterError> {
    let mut result: BTreeMap<String, Vec<String>> = packages
        .iter()
        .map(|package| (package.clone(), Vec::new()))
        .collect();
    for symbol in starts {
        let prefix = symbol.split("::").next().unwrap_or("");
        let matches: Vec<_> = packages
            .iter()
            .filter(|package| package.replace('-', "_") == prefix)
            .collect();
        if matches.len() != 1 {
            return Err(AdapterError::Unit(format!(
                "start symbol `{symbol}` maps to {} configured packages",
                matches.len()
            )));
        }
        result
            .get_mut(matches[0].as_str())
            .expect("configured package")
            .push(symbol.clone());
    }
    for (package, symbols) in &result {
        if symbols.is_empty() {
            return Err(AdapterError::Unit(format!(
                "package `{package}` has no start_from symbol"
            )));
        }
    }
    Ok(result)
}

fn build_charon_args(
    unit: &TranslationUnitManifest,
    starts: &[String],
    destination: &Path,
    manifest: &Path,
) -> Vec<String> {
    let mut args = vec![
        "cargo".to_owned(),
        "--preset".to_owned(),
        "aeneas".to_owned(),
        "--start-from".to_owned(),
        starts.join(","),
        "--error-on-warnings".to_owned(),
        "--dest-file".to_owned(),
        destination.to_string_lossy().into_owned(),
        "--format".to_owned(),
        "json".to_owned(),
    ];
    for opaque in &unit.opaque {
        args.push("--opaque".to_owned());
        args.push(opaque.clone());
    }
    for include in &unit.include {
        args.push("--include".to_owned());
        args.push(include.clone());
    }
    args.extend([
        "--".to_owned(),
        "--manifest-path".to_owned(),
        manifest.to_string_lossy().into_owned(),
    ]);
    args
}

fn build_aeneas_args(llbc: &Path, destination: &Path) -> Vec<String> {
    vec![
        "-backend".to_owned(),
        "lean".to_owned(),
        "-split-files".to_owned(),
        "-emit-json".to_owned(),
        "-warnings-as-errors".to_owned(),
        "-dest".to_owned(),
        destination.to_string_lossy().into_owned(),
        llbc.to_string_lossy().into_owned(),
    ]
}

fn collect_normalized_generated(
    root: &Path,
    lock: &TranslationToolchainLock,
) -> Result<BTreeMap<String, Vec<u8>>, AdapterError> {
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(walk_error)?;
        if entry.file_type().is_symlink() {
            return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| AdapterError::Internal("generated file escaped run root".to_owned()))?
            .to_string_lossy()
            .replace('\\', "/");
        validate_relative_path(&relative)?;
        let bytes = fs::read(entry.path())?;
        if bytes.len() > MAX_TOOL_OUTPUT_BYTES {
            return Err(AdapterError::Generated(format!(
                "generated artifact `{relative}` exceeds 8 MiB"
            )));
        }
        let normalized =
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                normalize_translation_json(&bytes, lock)?
            } else {
                normalize_text_bytes(&bytes)
            };
        if files.insert(relative.clone(), normalized).is_some() {
            return Err(AdapterError::Generated(format!(
                "duplicate generated artifact `{relative}`"
            )));
        }
        if files.len() > MAX_INVENTORY {
            return Err(AdapterError::Generated(
                "too many generated artifacts".to_owned(),
            ));
        }
    }
    Ok(files)
}

fn normalize_translation_json(
    bytes: &[u8],
    lock: &TranslationToolchainLock,
) -> Result<Vec<u8>, AdapterError> {
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|error| AdapterError::Generated(format!("invalid generated JSON: {error}")))?;
    if let Some(object) = value.as_object_mut() {
        if let Some(actual) = object.get("aeneas_version").and_then(Value::as_str) {
            if !actual.contains(&lock.aeneas_revision) {
                return Err(AdapterError::Toolchain(format!(
                    "translation report Aeneas version `{actual}` does not match pin `{}`",
                    lock.aeneas_revision
                )));
            }
            object.insert(
                "aeneas_version".to_owned(),
                Value::String(lock.aeneas_revision.clone()),
            );
        }
        if let Some(actual) = object.get("charon_version").and_then(Value::as_str) {
            if !actual.contains(&lock.charon_revision) {
                return Err(AdapterError::Toolchain(format!(
                    "translation report Charon version `{actual}` does not match pin `{}`",
                    lock.charon_revision
                )));
            }
            object.insert(
                "charon_version".to_owned(),
                Value::String(lock.charon_revision.clone()),
            );
        }
    }
    canonical_json(&value).map_err(|error| AdapterError::Generated(error.to_string()))
}

fn normalize_text_bytes(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let mut lines: Vec<_> = text.lines().map(str::trim_end).collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let mut result = lines.join("\n").into_bytes();
    if !result.is_empty() {
        result.push(b'\n');
    }
    result
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranslationReport {
    aeneas_version: String,
    charon_version: String,
    #[serde(rename = "crate")]
    crate_name: String,
    functions: Vec<TranslationFunction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TranslationFunction {
    rust_name: String,
    is_local: bool,
    is_opaque: bool,
}

fn translation_report_inventory(
    generated: &BTreeMap<String, Vec<u8>>,
    unit: &TranslationUnitManifest,
    lock: &TranslationToolchainLock,
) -> Result<Vec<String>, AdapterError> {
    let mut reports = Vec::new();
    for (path, bytes) in generated
        .iter()
        .filter(|(path, _)| path.ends_with("translation.json"))
    {
        let report: TranslationReport = serde_json::from_slice(bytes)
            .map_err(|error| AdapterError::Inventory(format!("{path}: {error}")))?;
        if report.aeneas_version != lock.aeneas_revision
            || report.charon_version != lock.charon_revision
        {
            return Err(AdapterError::Toolchain(format!(
                "normalized translation report `{path}` has unpinned tool versions"
            )));
        }
        if !unit.packages.iter().any(|package| {
            package == &report.crate_name || package.replace('-', "_") == report.crate_name
        }) {
            return Err(AdapterError::Inventory(format!(
                "translation report names unexpected crate `{}`",
                report.crate_name
            )));
        }
        reports.push(report);
    }
    if reports.len() != unit.packages.len() {
        return Err(AdapterError::Inventory(format!(
            "expected {} translation reports, found {}",
            unit.packages.len(),
            reports.len()
        )));
    }
    let explicit_opaque: BTreeSet<_> = unit.opaque.iter().map(String::as_str).collect();
    let mut local = BTreeSet::new();
    for report in reports {
        for function in report.functions {
            if !safe_symbol(&function.rust_name) {
                return Err(AdapterError::Inventory(format!(
                    "invalid translated symbol `{}`",
                    function.rust_name
                )));
            }
            if function.is_local {
                if function.is_opaque && !explicit_opaque.contains(function.rust_name.as_str()) {
                    return Err(AdapterError::Inventory(format!(
                        "unregistered opaque local function `{}`",
                        function.rust_name
                    )));
                }
                if !function.is_opaque {
                    local.insert(function.rust_name);
                }
            }
        }
    }
    for symbol in &unit.start_from {
        if !local.contains(symbol) {
            return Err(AdapterError::Inventory(format!(
                "start_from symbol `{symbol}` is absent or opaque in translation reports"
            )));
        }
    }
    Ok(unit.start_from.clone())
}

fn validate_external_boundaries(
    root: &Path,
    unit: &TranslationUnitManifest,
) -> Result<(), AdapterError> {
    let generated = normalized_relative(&unit.generated_dir)?;
    let mut bridge_paths = BTreeSet::new();
    let mut modules = BTreeSet::new();
    for bridge in &unit.external_bridges {
        validate_bridge(root, &generated, bridge)?;
        if !bridge_paths.insert(&bridge.file) {
            return Err(AdapterError::Unit(format!(
                "duplicate external bridge `{}`",
                bridge.file
            )));
        }
        if let Some(module) = &bridge.module
            && (!safe_symbol(module) || !modules.insert(module))
        {
            return Err(AdapterError::Unit(format!(
                "invalid or duplicate bridge module `{module}`"
            )));
        }
    }
    let mut template_paths = BTreeSet::new();
    for template in &unit.template_axioms {
        validate_template_declaration(&generated, template)?;
        if !template_paths.insert(&template.file) {
            return Err(AdapterError::Unit(format!(
                "duplicate template axiom file `{}`",
                template.file
            )));
        }
    }
    let mut warnings = BTreeSet::new();
    for warning in &unit.warning_inventory {
        validate_relative_path(&warning.artifact)?;
        let warning_path = normalized_relative(&warning.artifact)?;
        if !warning_path.starts_with(&generated)
            || warning.line == 0
            || warning.kind.trim().is_empty()
        {
            return Err(AdapterError::Unit(format!(
                "warning `{}` is outside generated_dir or malformed",
                warning.artifact
            )));
        }
        if !warnings.insert((&warning.artifact, warning.line, &warning.kind)) {
            return Err(AdapterError::Unit(
                "duplicate warning inventory entry".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_bridge(
    root: &Path,
    generated: &Path,
    bridge: &ExternalBridge,
) -> Result<(), AdapterError> {
    validate_relative_path(&bridge.file)?;
    let relative = normalized_relative(&bridge.file)?;
    if relative.starts_with(generated) {
        return Err(AdapterError::Unit(format!(
            "external bridge `{}` must remain outside generated_dir",
            bridge.file
        )));
    }
    if !valid_digest(&bridge.reviewed_sha256) {
        return Err(AdapterError::Unit(format!(
            "bridge `{}` has an invalid digest",
            bridge.file
        )));
    }
    let bytes = read_safe_file(root, &bridge.file, MAX_TOOL_OUTPUT_BYTES as u64)?;
    let actual = sha256_bytes(&bytes);
    if actual != bridge.reviewed_sha256 {
        return Err(AdapterError::Generated(format!(
            "bridge `{}` digest mismatch: expected {}, found {actual}",
            bridge.file, bridge.reviewed_sha256
        )));
    }
    Ok(())
}

fn validate_template_declaration(
    generated: &Path,
    template: &TemplateAxiom,
) -> Result<(), AdapterError> {
    validate_relative_path(&template.file)?;
    let path = normalized_relative(&template.file)?;
    if !path.starts_with(generated) || template.compiled {
        return Err(AdapterError::Unit(format!(
            "template `{}` must be uncompiled and inside generated_dir",
            template.file
        )));
    }
    Ok(())
}

fn audit_generated_inventory(
    generated: &BTreeMap<String, Vec<u8>>,
    unit: &TranslationUnitManifest,
) -> Result<(), AdapterError> {
    let generated_root = normalized_relative(&unit.generated_dir)?;
    let templates: BTreeMap<String, usize> = unit
        .template_axioms
        .iter()
        .map(|template| {
            let relative = normalized_relative(&template.file).expect("validated template path");
            let local = relative
                .strip_prefix(&generated_root)
                .expect("template below generated root")
                .to_string_lossy()
                .trim_start_matches('/')
                .to_owned();
            (local, template.count)
        })
        .collect();
    let expected_warnings: BTreeSet<(String, usize, String)> = unit
        .warning_inventory
        .iter()
        .map(|warning| {
            let relative = normalized_relative(&warning.artifact).expect("validated warning path");
            let local = relative
                .strip_prefix(&generated_root)
                .expect("warning below generated root")
                .to_string_lossy()
                .trim_start_matches('/')
                .to_owned();
            (local, warning.line, warning.kind.clone())
        })
        .collect();
    let mut actual_warnings = BTreeSet::new();
    for (path, bytes) in generated.iter().filter(|(path, _)| path.ends_with(".lean")) {
        let text = std::str::from_utf8(bytes).map_err(|error| {
            AdapterError::Generated(format!("generated Lean `{path}` is not UTF-8: {error}"))
        })?;
        let axiom_count = lean_token_locations(text, "axiom").len();
        match templates.get(path) {
            Some(expected) if *expected == axiom_count => {}
            Some(expected) => {
                return Err(AdapterError::Generated(format!(
                    "template `{path}` axiom count is {axiom_count}, expected {expected}"
                )));
            }
            None if axiom_count == 0 => {}
            None => {
                return Err(AdapterError::Generated(format!(
                    "generated Lean `{path}` contains {axiom_count} unregistered axiom declarations"
                )));
            }
        }
        for line in lean_token_locations(text, "sorry") {
            actual_warnings.insert((path.clone(), line, "upstream-sorry".to_owned()));
        }
        for line in lean_token_locations(text, "sorryAx") {
            actual_warnings.insert((path.clone(), line, "upstream-sorry-ax".to_owned()));
        }
    }
    for template in templates.keys() {
        if !generated.contains_key(template) {
            return Err(AdapterError::Generated(format!(
                "declared template `{template}` was not generated"
            )));
        }
    }
    if actual_warnings != expected_warnings {
        let missing: Vec<_> = expected_warnings
            .difference(&actual_warnings)
            .cloned()
            .collect();
        let extra: Vec<_> = actual_warnings
            .difference(&expected_warnings)
            .cloned()
            .collect();
        return Err(AdapterError::Generated(format!(
            "warning inventory mismatch; missing={missing:?}, extra={extra:?}"
        )));
    }
    Ok(())
}

fn lean_token_locations(source: &str, wanted: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    let mut line = 1;
    let mut block_depth = 0_u32;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            line += 1;
            index += 1;
            continue;
        }
        if block_depth > 0 {
            if bytes.get(index..index + 2) == Some(b"/-") {
                block_depth += 1;
                index += 2;
                continue;
            }
            if bytes.get(index..index + 2) == Some(b"-/") {
                block_depth -= 1;
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"--") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/-") {
            block_depth = 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    if bytes[index] == b'\n' {
                        line += 1;
                    }
                    index += 1;
                }
            }
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if &source[start..index] == wanted {
                result.push(line);
            }
            continue;
        }
        index += 1;
    }
    result
}

fn compare_committed_generated(
    committed_dir: &Path,
    produced: &BTreeMap<String, Vec<u8>>,
) -> Result<(), AdapterError> {
    if !committed_dir.is_dir() {
        return Err(AdapterError::Generated(format!(
            "committed generated directory is missing: {}",
            committed_dir.display()
        )));
    }
    let committed = collect_committed_files(committed_dir)?;
    if committed != *produced {
        let committed_keys: BTreeSet<_> = committed.keys().cloned().collect();
        let produced_keys: BTreeSet<_> = produced.keys().cloned().collect();
        let missing: Vec<_> = produced_keys.difference(&committed_keys).cloned().collect();
        let extra: Vec<_> = committed_keys.difference(&produced_keys).cloned().collect();
        let changed: Vec<_> = committed_keys
            .intersection(&produced_keys)
            .filter(|path| committed.get(*path) != produced.get(*path))
            .cloned()
            .collect();
        return Err(AdapterError::Generated(format!(
            "committed generated tree drifted; missing={missing:?}, extra={extra:?}, changed={changed:?}"
        )));
    }
    Ok(())
}

fn collect_committed_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, AdapterError> {
    let canonical = root.canonicalize()?;
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(&canonical)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(walk_error)?;
        if entry.file_type().is_symlink() {
            return Err(AdapterError::UnsafePath(entry.path().display().to_string()));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&canonical)
            .map_err(|_| {
                AdapterError::Internal("committed generated path escaped root".to_owned())
            })?
            .to_string_lossy()
            .replace('\\', "/");
        validate_relative_path(&relative)?;
        let bytes = fs::read(entry.path())?;
        let normalized =
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                // Produced JSON is already canonical.  Committed output must be the
                // exact same canonical bytes; accepting a second normalization here
                // would hide drift in reviewed artifacts.
                bytes
            } else {
                normalize_text_bytes(&bytes)
            };
        files.insert(relative, normalized);
    }
    Ok(files)
}

fn update_generated_directory(
    committed_dir: &Path,
    produced: &BTreeMap<String, Vec<u8>>,
) -> Result<(), AdapterError> {
    let parent = committed_dir
        .parent()
        .ok_or_else(|| AdapterError::UnsafePath(committed_dir.display().to_string()))?;
    fs::create_dir_all(parent)?;
    let file_name = committed_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AdapterError::UnsafePath(committed_dir.display().to_string()))?;
    let staging = parent.join(format!(".{file_name}.proofbound-staging"));
    let backup = parent.join(format!(".{file_name}.proofbound-backup"));
    if staging.exists() || backup.exists() {
        return Err(AdapterError::Generated(
            "stale update staging/backup directory exists".to_owned(),
        ));
    }
    fs::create_dir(&staging)?;
    for (relative, bytes) in produced {
        validate_relative_path(relative)?;
        let target = staging.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, bytes)?;
    }
    if committed_dir.exists() {
        fs::rename(committed_dir, &backup)?;
        if let Err(error) = fs::rename(&staging, committed_dir) {
            let _ = fs::rename(&backup, committed_dir);
            return Err(AdapterError::Io(error));
        }
        fs::remove_dir_all(backup)?;
    } else {
        fs::rename(staging, committed_dir)?;
    }
    Ok(())
}

fn ensure_clean_tree(root: &Path) -> Result<(), AdapterError> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|source| AdapterError::ToolUnavailable {
            program: "git".to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(AdapterError::Generated(format!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    if !output.stdout.is_empty() {
        return Err(AdapterError::Generated(
            "update requires a completely clean Git tree".to_owned(),
        ));
    }
    Ok(())
}

fn first_difference(left: &BTreeMap<String, Vec<u8>>, right: &BTreeMap<String, Vec<u8>>) -> String {
    let keys: BTreeSet<_> = left.keys().chain(right.keys()).collect();
    for key in keys {
        match (left.get(key), right.get(key)) {
            (None, Some(_)) => return format!("missing first-run artifact `{key}`"),
            (Some(_), None) => return format!("missing second-run artifact `{key}`"),
            (Some(left), Some(right)) if left != right => {
                let offset = left
                    .iter()
                    .zip(right)
                    .position(|(a, b)| a != b)
                    .unwrap_or(left.len().min(right.len()));
                return format!("artifact `{key}` byte {offset}");
            }
            _ => {}
        }
    }
    "unknown location".to_owned()
}

fn exact_symbol_inventory(expected: &[String], actual: &[String]) -> Result<(), AdapterError> {
    exact_set("translated start symbols", expected, actual)
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

fn artifact_map_observations(
    files: &BTreeMap<String, Vec<u8>>,
    generated_dir: &str,
) -> Vec<ArtifactObservation> {
    files
        .iter()
        .map(|(relative, bytes)| ArtifactObservation {
            logical_name: format!("{}/{relative}", generated_dir.trim_end_matches('/')),
            sha256: sha256_bytes(bytes),
            size_bytes: bytes.len().try_into().unwrap_or(u64::MAX),
        })
        .collect()
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
            logical_args(&spec.args),
            output.status,
            truncate_message(detail.trim())
        )));
    }
    Ok(())
}

fn logical_args(args: &[String]) -> Vec<String> {
    args.iter().map(|arg| logicalize_temp_path(arg)).collect()
}

fn logicalize_temp_path(value: &str) -> String {
    let Some(marker) = value.find("/proofbound-aeneas-") else {
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

fn observe_command(
    spec: &ProcessSpec,
    environment: &[EnvironmentObservation],
) -> CommandObservation {
    CommandObservation {
        program: logicalize_temp_path(&spec.program),
        args: logical_args(&spec.args),
        environment_allowlist: environment.to_vec(),
    }
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
                normalize_process_output(&output.stdout, &output.stderr, shadow_root, project_root);
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

fn normalize_process_output(
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
    for marker in ["; finished in ", " completed in ", " elapsed: "] {
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
    ToolObservation {
        name: "proofbound-adapter-aeneas".to_owned(),
        identity_sha256: domain_hash(
            "proofbound-adapter-identity/1",
            format!("{ADAPTER_ID}\0{version}").as_bytes(),
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
    let metadata = path.metadata()?;
    if !path.is_file() || metadata.len() > max {
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

fn resolve_output_path(root: &Path, relative: &str) -> Result<PathBuf, AdapterError> {
    validate_relative_path(relative)?;
    let candidate = root.join(relative);
    reject_symlink_components(root, &candidate)?;
    let parent = candidate
        .parent()
        .ok_or_else(|| AdapterError::UnsafePath(relative.to_owned()))?;
    let mut existing = parent;
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| AdapterError::UnsafePath(relative.to_owned()))?;
    }
    if !existing.canonicalize()?.starts_with(root) {
        return Err(AdapterError::UnsafePath(relative.to_owned()));
    }
    Ok(candidate)
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
        if fs::symlink_metadata(&current).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(AdapterError::UnsafePath(current.display().to_string()));
        }
    }
    Ok(())
}

fn normalized_relative(path: &str) -> Result<PathBuf, AdapterError> {
    validate_relative_path(path)?;
    Ok(Path::new(path).components().collect())
}

fn path_contains(parent: &str, child: &str) -> bool {
    normalized_relative(child)
        .ok()
        .zip(normalized_relative(parent).ok())
        .is_some_and(|(child, parent)| child.starts_with(parent))
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
        .prefix("proofbound-aeneas-")
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

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
fn sorted_unique(mut values: Vec<String>, label: &str) -> Result<Vec<String>, AdapterError> {
    if values.len() > MAX_INVENTORY {
        return Err(AdapterError::Inventory(format!(
            "{label} exceeds {MAX_INVENTORY} entries"
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

    fn sample_translation() -> TranslationUnitManifest {
        serde_json::from_value(json!({
            "schema":"proofbound-translation-unit/1","id":"kernel","adapter":"charon-aeneas","packages":["demo-kernel"],
            "start_from":["demo_kernel::decide"],"opaque":["external_crate"],"include":["external_crate::Type"],
            "generated_dir":"lean/Generated/Demo","handwritten_refinement":"lean/Demo/Refinement.lean","determinism_runs":2,
            "determinism_normalization":"pretty-printed-llbc/1","forbid_generated_axioms":true,"external_bridges":[],"template_axioms":[],"warning_inventory":[],
            "import_mapping":{"mode":"external-source-root","source_roots":["lean"]},
            "resource_budget":{"time_seconds":60,"disk_bytes":1000000,"memory_bytes":1000000},"claims":["DEMO-ONE"]
        })).unwrap()
    }

    #[test]
    fn typed_argv_is_manifest_driven_and_has_no_shell() {
        let unit = sample_translation();
        let manifest = Path::new("/shadow/Cargo.toml");
        let destination = Path::new("/run/demo.llbc");
        let args = build_charon_args(&unit, &unit.start_from, destination, manifest);
        assert_eq!(
            &args[..5],
            [
                "cargo",
                "--preset",
                "aeneas",
                "--start-from",
                "demo_kernel::decide"
            ]
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--opaque", "external_crate"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--manifest-path", "/shadow/Cargo.toml"])
        );
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains(';') || arg.contains("$("))
        );
    }

    #[test]
    fn unavailable_lock_fails_explicitly() {
        let lock = TranslationToolchainLock {
            schema: "proofbound-translation-toolchain/1".to_owned(),
            charon_revision: "unavailable-until-pinned-update".to_owned(),
            aeneas_revision: "abc123".to_owned(),
            rust_toolchain: "1".to_owned(),
            lean_toolchain: "v1".to_owned(),
        };
        let temp = tempfile::tempdir().unwrap();
        let error = validate_toolchain_lock(temp.path(), &lock).unwrap_err();
        assert!(matches!(error, AdapterError::Toolchain(_)));
        assert_eq!(error.diagnostic().code, "PB-AENEAS-1002");
    }

    #[test]
    fn normalization_is_deterministic_and_reports_first_difference() {
        assert_eq!(normalize_text_bytes(b"a  \r\n\r\n"), b"a\n");
        let left = BTreeMap::from([("x".to_owned(), b"one".to_vec())]);
        let right = BTreeMap::from([("x".to_owned(), b"two".to_vec())]);
        assert!(first_difference(&left, &right).contains("byte 0"));
    }

    #[test]
    fn lean_scanner_ignores_comments_and_strings() {
        let source = "-- axiom hidden\n/- sorry nested /- axiom -/ -/\n#check \"sorry\"\naxiom real : True\nby sorry\n";
        assert_eq!(lean_token_locations(source, "axiom"), [4]);
        assert_eq!(lean_token_locations(source, "sorry"), [5]);
    }

    #[test]
    fn generated_audit_enforces_axioms_templates_and_warnings() {
        let mut unit = sample_translation();
        unit.template_axioms.push(TemplateAxiom {
            file: "lean/Generated/Demo/Templates.lean".to_owned(),
            count: 1,
            compiled: false,
        });
        unit.warning_inventory
            .push(proofbound_manifest::WarningInventory {
                artifact: "lean/Generated/Demo/Funs.lean".to_owned(),
                line: 1,
                kind: "upstream-sorry".to_owned(),
            });
        let generated = BTreeMap::from([
            (
                "Templates.lean".to_owned(),
                b"axiom placeholder : True\n".to_vec(),
            ),
            ("Funs.lean".to_owned(), b"by sorry\n".to_vec()),
        ]);
        assert!(audit_generated_inventory(&generated, &unit).is_ok());
        let bad = BTreeMap::from([("Funs.lean".to_owned(), b"axiom surprise : True\n".to_vec())]);
        assert!(audit_generated_inventory(&bad, &sample_translation()).is_err());
    }

    #[test]
    fn bridge_must_be_outside_generator_and_byte_pinned() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("lean/Bridges")).unwrap();
        fs::write(temp.path().join("lean/Bridges/B.lean"), b"def b := true\n").unwrap();
        let digest = sha256_bytes(b"def b := true\n");
        let bridge = ExternalBridge {
            file: "lean/Bridges/B.lean".to_owned(),
            module: Some("Bridges.B".to_owned()),
            reviewed_sha256: digest,
        };
        assert!(
            validate_bridge(
                &temp.path().canonicalize().unwrap(),
                Path::new("lean/Generated"),
                &bridge
            )
            .is_ok()
        );
        let inside = ExternalBridge {
            file: "lean/Generated/B.lean".to_owned(),
            ..bridge
        };
        assert!(
            validate_bridge(
                &temp.path().canonicalize().unwrap(),
                Path::new("lean/Generated"),
                &inside
            )
            .is_err()
        );
    }

    #[test]
    fn generated_tree_comparison_rejects_missing_extra_and_changed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("A.lean"), b"def a := 1\n").unwrap();
        let same = BTreeMap::from([("A.lean".to_owned(), b"def a := 1\n".to_vec())]);
        assert!(compare_committed_generated(temp.path(), &same).is_ok());
        let changed = BTreeMap::from([("A.lean".to_owned(), b"def a := 2\n".to_vec())]);
        assert!(compare_committed_generated(temp.path(), &changed).is_err());
    }

    #[test]
    fn canonical_protocol_rejects_whitespace_and_unknown_fields() {
        let request = json!({"schema":PROTOCOL_SCHEMA,"type":"request","request_id":"0123456789abcdef0123456789abcdef","adapter":ADAPTER_ID,"operation":"check","project_root":".","unit":{}});
        let canonical = canonical_json(&request).unwrap();
        let parsed: AdapterRequest = serde_json::from_slice(&canonical).unwrap();
        assert!(validate_request(&parsed, &canonical).is_ok());
        let mut spaced = canonical;
        spaced.push(b'\n');
        assert!(validate_request(&parsed, &spaced).is_err());
        let mut unknown = request;
        unknown["unknown"] = json!(true);
        assert_eq!(
            handle_request_bytes(&canonical_json(&unknown).unwrap()).diagnostics[0].code,
            "PB-AENEAS-1004"
        );
    }

    #[test]
    fn observation_shape_round_trips() {
        let observation = AdapterObservation {
            schema: OBSERVATION_SCHEMA.to_owned(),
            unit_id: "u".to_owned(),
            evidence_kind: "source-refinement".to_owned(),
            outcome: ObservationOutcome::Passed,
            input_artifacts: vec![],
            generated_artifacts: vec![],
            tool: ToolObservation {
                name: "aeneas".to_owned(),
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
            normalization: "pretty-printed-llbc/1".to_owned(),
        };
        let bytes = canonical_json(&observation).unwrap();
        assert_eq!(
            serde_json::from_slice::<AdapterObservation>(&bytes).unwrap(),
            observation
        );
    }

    #[test]
    fn fake_tools_must_report_both_pinned_revisions() {
        let lock = TranslationToolchainLock {
            schema: "proofbound-translation-toolchain/1".to_owned(),
            charon_revision: "abc123".to_owned(),
            aeneas_revision: "def456".to_owned(),
            rust_toolchain: "1.94.0".to_owned(),
            lean_toolchain: "v4.33.0".to_owned(),
        };
        let success = |text: &[u8]| ProcessOutput {
            status: Some(0),
            stdout: text.to_vec(),
            stderr: Vec::new(),
            truncated: false,
            duration_ms: 1,
        };
        let mut fake = FakeExecutor::default();
        fake.outputs.push_back(success(b"charon abc123\n"));
        fake.outputs.push_back(success(b"aeneas def456\n"));
        let (identity, _, _) =
            translation_tool_identity(Path::new("."), &lock, &BTreeMap::new(), &[], &mut fake)
                .unwrap();
        assert!(identity.version.contains("abc123"));
        assert!(identity.version.contains("def456"));
        assert_eq!(fake.seen[0].program, "charon");
        assert_eq!(fake.seen[1].program, "aeneas");

        let mut mismatched = FakeExecutor::default();
        mismatched.outputs.push_back(success(b"charon wrong\n"));
        assert!(
            translation_tool_identity(
                Path::new("."),
                &lock,
                &BTreeMap::new(),
                &[],
                &mut mismatched,
            )
            .is_err()
        );
    }
}
