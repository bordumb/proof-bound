use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use proofbound_core::{
    CommandSpec, EnvironmentVariable, EnvironmentVariableName, ResourceUsage, Sha256Digest,
    ToolIdentity,
};
use sha2::{Digest as _, Sha256};

use crate::{
    audit::parse_audit_bytes,
    error::{AdapterError, CONFIGURATION, RESOURCE, TOOL},
    model::{AuditOutput, CapturedExecution, LeanAdapterUnit},
};

const MAX_TOOL_OUTPUT: usize = 64 << 20;
const MAX_TOOL_IDENTITY_BYTES: u64 = 512 << 20;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug)]
pub struct AuditRun {
    pub output: AuditOutput,
    pub execution: CapturedExecution,
}

pub fn execute_audit(root: &Path, unit: &LeanAdapterUnit) -> Result<AuditRun, AdapterError> {
    let root = root.canonicalize().map_err(|error| {
        AdapterError::new(TOOL, format!("cannot resolve project root: {error}"))
    })?;
    if !root.is_dir() {
        return Err(AdapterError::new(TOOL, "project root is not a directory"));
    }

    if !unit.evidence_unit.operation.arguments.is_empty() {
        return Err(AdapterError::new(
            CONFIGURATION,
            "Lean audit operation.arguments is unsupported; modules and surfaces derive from registered paths and theorem identity",
        ));
    }
    let theorem = unit
        .evidence_unit
        .theorem
        .as_deref()
        .ok_or_else(|| AdapterError::new(CONFIGURATION, "Lean theorem is missing"))?;
    let target = unit
        .evidence_unit
        .operation
        .targets
        .first()
        .ok_or_else(|| AdapterError::new(CONFIGURATION, "Lean audit target is missing"))?;
    let surface = module_from_target(target, theorem)?;

    let lake = resolve_program("lake")?;
    let mut args = vec!["exe".to_owned(), "proofbound_lean_audit".to_owned()];
    args.push(surface.clone());
    args.push(format!("--surface={surface}"));
    let environment = environment_allowlist(&unit.evidence_unit.environment_allowlist)?;
    let command = CommandSpec {
        program: lake.to_string_lossy().into_owned(),
        args,
        environment_allowlist: environment,
    };

    let time_limit = Duration::from_secs(unit.evidence_unit.resource_budget.time_seconds);
    let result = run_bounded(&root, &command, time_limit)?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(AdapterError::new(
            TOOL,
            format!(
                "proofbound_lean_audit failed with {}: {}",
                result.status,
                truncate(&stderr, 8_192)
            ),
        ));
    }
    let output = parse_audit_bytes(&result.stdout)?;

    let audit_binary = root.join(".lake/build/bin/proofbound_lean_audit");
    let identity = hash_regular_file(&audit_binary)?;
    let version = lake_version(&root, &lake)?;
    let tool = ToolIdentity {
        name: "proofbound_lean_audit".to_owned(),
        version,
        identity_sha256: identity,
    };

    Ok(AuditRun {
        output,
        execution: CapturedExecution {
            tool,
            command,
            started_unix_ms: result.started_unix_ms,
            completed_unix_ms: result.completed_unix_ms,
            resource_usage: ResourceUsage {
                time_ms: result.elapsed_ms,
                peak_disk_bytes: 0,
                peak_memory_bytes: 0,
            },
        },
    })
}

pub fn adapter_identity() -> Result<ToolIdentity, AdapterError> {
    let executable = env::current_exe().map_err(|error| {
        AdapterError::new(TOOL, format!("cannot identify adapter executable: {error}"))
    })?;
    Ok(ToolIdentity {
        name: env!("CARGO_PKG_NAME").to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        identity_sha256: hash_regular_file(&executable)?,
    })
}

pub fn doctor(root: &Path) -> Result<(), AdapterError> {
    let root = root.canonicalize().map_err(|error| {
        AdapterError::new(TOOL, format!("cannot resolve project root: {error}"))
    })?;
    let lake = resolve_program("lake")?;
    lake_version(&root, &lake)?;
    hash_regular_file(&root.join(".lake/build/bin/proofbound_lean_audit"))?;
    adapter_identity()?;
    Ok(())
}

pub fn validate_captured_execution(
    execution: &CapturedExecution,
    budget_ms: u64,
) -> Result<(), AdapterError> {
    if execution.tool.name.trim().is_empty()
        || execution.tool.version.trim().is_empty()
        || execution.command.program.trim().is_empty()
    {
        return Err(AdapterError::new(
            TOOL,
            "captured audit execution has an incomplete tool or command identity",
        ));
    }
    if execution.completed_unix_ms < execution.started_unix_ms {
        return Err(AdapterError::new(
            TOOL,
            "captured audit completion precedes its start",
        ));
    }
    if execution.resource_usage.time_ms > budget_ms {
        return Err(AdapterError::new(
            RESOURCE,
            format!(
                "captured audit used {} ms, exceeding declared budget {budget_ms} ms",
                execution.resource_usage.time_ms
            ),
        ));
    }
    Ok(())
}

pub fn hash_regular_file(path: &Path) -> Result<Sha256Digest, AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AdapterError::new(
            TOOL,
            format!("cannot stat identity file '{}': {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_TOOL_IDENTITY_BYTES
    {
        return Err(AdapterError::new(
            TOOL,
            format!(
                "identity file '{}' is not a bounded regular file",
                path.display()
            ),
        ));
    }
    let mut file = fs::File::open(path).map_err(|error| {
        AdapterError::new(
            TOOL,
            format!("cannot open identity file '{}': {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 << 10];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            AdapterError::new(
                TOOL,
                format!("cannot hash identity file '{}': {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_str(&hex::encode(hasher.finalize()))
        .expect("SHA-256 always renders canonical hex"))
}

fn module_from_target(target: &str, theorem: &str) -> Result<String, AdapterError> {
    let module = if target == theorem {
        target.rsplit_once('.').map(|(module, _)| module)
    } else if theorem.starts_with(&format!("{target}.")) {
        Some(target)
    } else {
        None
    }
    .ok_or_else(|| {
        AdapterError::new(
            CONFIGURATION,
            format!("cannot derive theorem module from target '{target}' and theorem '{theorem}'"),
        )
    })?;
    if module.split('.').any(|part| {
        part.is_empty()
            || part
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
    }) {
        return Err(AdapterError::new(
            CONFIGURATION,
            format!("unsupported Lean module name '{module}'"),
        ));
    }
    Ok(module.to_owned())
}

fn environment_allowlist(names: &[String]) -> Result<Vec<EnvironmentVariable>, AdapterError> {
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| {
            let secret = ["SECRET", "TOKEN", "PASSWORD", "KEY"]
                .iter()
                .any(|marker| name.contains(marker));
            let value_sha256 = if secret {
                None
            } else {
                env::var_os(&name)
                    .map(|value| Sha256Digest::of_bytes(value.to_string_lossy().as_bytes()))
            };
            Ok(EnvironmentVariable {
                name: EnvironmentVariableName::new(name).map_err(|error| {
                    AdapterError::new(
                        CONFIGURATION,
                        format!("invalid environment allowlist name: {error}"),
                    )
                })?,
                value_sha256,
                secret,
            })
        })
        .collect()
}

fn resolve_program(program: &str) -> Result<PathBuf, AdapterError> {
    let path = env::var_os("PATH").ok_or_else(|| {
        AdapterError::new(TOOL, format!("cannot resolve '{program}': PATH is absent"))
    })?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|error| {
                AdapterError::new(
                    TOOL,
                    format!("cannot canonicalize '{}': {error}", candidate.display()),
                )
            });
        }
    }
    Err(AdapterError::new(
        TOOL,
        format!("required program '{program}' is not available"),
    ))
}

fn lake_version(root: &Path, lake: &Path) -> Result<String, AdapterError> {
    let output = Command::new(lake)
        .arg("--version")
        .current_dir(root)
        .env_clear()
        .output()
        .map_err(|error| AdapterError::new(TOOL, format!("cannot query Lake version: {error}")))?;
    if !output.status.success() || output.stdout.len() > 4_096 {
        return Err(AdapterError::new(
            TOOL,
            "Lake/Lean version query failed or produced oversized output",
        ));
    }
    let version = String::from_utf8(output.stdout)
        .map_err(|error| AdapterError::new(TOOL, format!("Lake version is not UTF-8: {error}")))?;
    let version = version.trim();
    if version.is_empty() {
        return Err(AdapterError::new(TOOL, "Lake version is empty"));
    }
    Ok(version.to_owned())
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    started_unix_ms: u64,
    completed_unix_ms: u64,
    elapsed_ms: u64,
}

fn run_bounded(
    root: &Path,
    command: &CommandSpec,
    timeout: Duration,
) -> Result<BoundedOutput, AdapterError> {
    let started_unix_ms = unix_ms()?;
    let started = Instant::now();
    let mut process = Command::new(&command.program);
    process
        .args(&command.args)
        .current_dir(root)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for variable in &command.environment_allowlist {
        if let Some(value) = env::var_os(variable.name.as_str()) {
            process.env(variable.name.as_str(), value);
        }
    }
    let mut child = process
        .spawn()
        .map_err(|error| AdapterError::new(TOOL, format!("cannot start Lean audit: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AdapterError::new(TOOL, "cannot capture Lean audit stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AdapterError::new(TOOL, "cannot capture Lean audit stderr"))?;
    let stdout_reader = thread::spawn(move || read_limited(stdout, MAX_TOOL_OUTPUT));
    let stderr_reader = thread::spawn(move || read_limited(stderr, MAX_TOOL_OUTPUT));

    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| AdapterError::new(TOOL, format!("cannot poll Lean audit: {error}")))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(AdapterError::new(
                RESOURCE,
                format!(
                    "Lean audit exceeded time budget of {} ms",
                    timeout.as_millis()
                ),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| AdapterError::new(TOOL, "Lean audit stdout reader panicked"))?
        .map_err(|error| {
            AdapterError::new(TOOL, format!("cannot read Lean audit stdout: {error}"))
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| AdapterError::new(TOOL, "Lean audit stderr reader panicked"))?
        .map_err(|error| {
            AdapterError::new(TOOL, format!("cannot read Lean audit stderr: {error}"))
        })?;
    if stdout.len() > MAX_TOOL_OUTPUT || stderr.len() > MAX_TOOL_OUTPUT {
        return Err(AdapterError::new(
            RESOURCE,
            format!("Lean audit output exceeds {MAX_TOOL_OUTPUT} bytes"),
        ));
    }
    let completed_unix_ms = unix_ms()?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
        started_unix_ms,
        completed_unix_ms,
        elapsed_ms,
    })
}

fn read_limited(mut reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 64 << 10];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if output.len() <= limit {
            let remaining = limit.saturating_add(1).saturating_sub(output.len());
            output.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    Ok(output)
}

fn unix_ms() -> Result<u64, AdapterError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            AdapterError::new(TOOL, format!("system clock predates Unix epoch: {error}"))
        })?;
    u64::try_from(duration.as_millis())
        .map_err(|_| AdapterError::new(TOOL, "Unix timestamp exceeds u64"))
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_derives_from_exact_declaration_or_module_target() {
        assert_eq!(
            module_from_target(
                "ProofboundDemo.Claims.Transfer.accept_conserves",
                "ProofboundDemo.Claims.Transfer.accept_conserves"
            )
            .unwrap(),
            "ProofboundDemo.Claims.Transfer"
        );
        assert_eq!(
            module_from_target(
                "ProofboundArtifactDemo.Claims",
                "ProofboundArtifactDemo.Claims.publishedTotal"
            )
            .unwrap(),
            "ProofboundArtifactDemo.Claims"
        );
        assert!(module_from_target("Other", "Demo.claim").is_err());
    }

    #[test]
    fn bounded_reader_marks_oversize_without_blocking_the_pipe() {
        let data = vec![7_u8; 100];
        let output = read_limited(data.as_slice(), 10).unwrap();
        assert_eq!(output.len(), 11);
    }
}
