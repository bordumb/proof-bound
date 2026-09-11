use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
};

use anyhow::{Context, Result, bail};
use proofbound_evidence::{canonical_json, sha256_bytes};
use proofbound_manifest::{
    AdapterKind, AdapterRequest, AdapterResponse, EvidenceUnitManifest, OperationKind,
};
use serde::Deserialize;

const MAX_ADAPTER_OUTPUT: u64 = 16 << 20;

pub(crate) fn invoke(
    root: &Path,
    unit: &EvidenceUnitManifest,
    operation: &str,
    request_unit: serde_json::Value,
) -> Result<AdapterResponse> {
    if !matches!(
        operation,
        "doctor" | "inventory" | "check" | "reproduce" | "update"
    ) {
        bail!("PB-ADAPTER-0001: unsupported adapter operation {operation:?}");
    }
    let executable = unit.adapter.executable();
    let protocol_adapter = adapter_name(unit.adapter);
    let seed = canonical_json(&serde_json::json!({
        "adapter": protocol_adapter,
        "operation": operation,
        "unit": request_unit,
    }))?;
    let request_id = sha256_bytes(&seed)
        .strip_prefix("sha256:")
        .expect("internal digest has prefix")[..32]
        .to_owned();
    let request = AdapterRequest {
        schema: "proofbound-adapter-protocol/1".into(),
        message_type: "request".into(),
        request_id: request_id.clone(),
        adapter: protocol_adapter.into(),
        operation: operation.into(),
        project_root: ".".into(),
        unit: request_unit,
    };
    let bytes = canonical_json(&request)?;

    let program = locate_adapter(executable);
    let mut command = Command::new(&program);
    command
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for name in &unit.environment_allowlist {
        if name.is_empty() || name.contains('=') || name.as_bytes().contains(&0) {
            bail!("PB-ADAPTER-0002: invalid environment allowlist name {name:?}");
        }
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    // The adapter executable is already resolved, but child tool lookup is
    // allowed only when PATH was explicitly registered.
    let mut child = command
        .spawn()
        .with_context(|| format!("PB-ADAPTER-0003: could not start {}", program.display()))?;
    child
        .stdin
        .take()
        .context("adapter stdin unavailable")?
        .write_all(&bytes)?;

    let stdout_pipe = child.stdout.take().context("adapter stdout unavailable")?;
    let stderr_pipe = child.stderr.take().context("adapter stderr unavailable")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout_pipe));
    let stderr_reader = thread::spawn(move || read_bounded(stderr_pipe));
    let status = child.wait()?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("PB-ADAPTER-0004: adapter stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("PB-ADAPTER-0004: adapter stderr reader panicked"))??;
    if stdout.len() as u64 > MAX_ADAPTER_OUTPUT || stderr.len() as u64 > MAX_ADAPTER_OUTPUT {
        bail!("PB-ADAPTER-0004: adapter output exceeded 16 MiB");
    }
    if !status.success() {
        bail!(
            "PB-ADAPTER-0005: {executable} exited with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    parse_response(&stdout, &stderr, &request_id, &request.adapter, operation)
}

fn parse_response(
    stdout: &[u8],
    stderr: &[u8],
    request_id: &str,
    request_adapter: &str,
    request_operation: &str,
) -> Result<AdapterResponse> {
    let value: serde_json::Value = serde_json::from_slice(stdout).with_context(|| {
        format!(
            "PB-ADAPTER-0006: adapter emitted invalid protocol JSON: {}",
            String::from_utf8_lossy(stderr).trim()
        )
    })?;
    if canonical_json(&value)? != stdout {
        bail!("PB-ADAPTER-0006: adapter response JSON is not canonical");
    }
    let response: AdapterResponse = serde_json::from_value(value.clone()).with_context(|| {
        format!(
            "PB-ADAPTER-0006: adapter response violates the protocol schema: {}",
            String::from_utf8_lossy(stderr).trim()
        )
    })?;
    if response.schema != "proofbound-adapter-protocol/1"
        || response.message_type != "response"
        || response.request_id != request_id
        || response.adapter != request_adapter
    {
        bail!("PB-ADAPTER-0007: adapter response identity does not match its request");
    }
    let object = value
        .as_object()
        .context("PB-ADAPTER-0008: adapter response must be a JSON object")?;
    if !object.contains_key("evidence") {
        bail!("PB-ADAPTER-0008: adapter response omitted required evidence field");
    }
    validate_response_schema(&response, request_operation)?;
    Ok(response)
}

fn validate_response_schema(response: &AdapterResponse, request_operation: &str) -> Result<()> {
    if response.inventory.len() > 100_000
        || !response.inventory.windows(2).all(|pair| pair[0] < pair[1])
        || response.inventory.iter().any(|item| {
            item.trim().is_empty()
                || item.chars().count() > 4096
                || item.chars().any(char::is_control)
        })
    {
        bail!(
            "PB-ADAPTER-0008: adapter inventory must be a bounded strict-lexical set of valid targets"
        );
    }
    if response.diagnostics.len() > 4_096 {
        bail!("PB-ADAPTER-0008: adapter diagnostics exceed the protocol limit");
    }
    for diagnostic in &response.diagnostics {
        if !valid_diagnostic_code(&diagnostic.code)
            || diagnostic.message.len() > 8_192
            || diagnostic
                .path
                .as_ref()
                .is_some_and(|path| path.len() > 4_096)
            || diagnostic
                .remediation
                .as_ref()
                .is_some_and(|remediation| remediation.len() > 8_192)
        {
            bail!("PB-ADAPTER-0008: adapter diagnostic violates the protocol schema");
        }
    }
    if let Some(evidence) = &response.evidence {
        let schema = evidence
            .as_object()
            .and_then(|object| object.get("schema"))
            .and_then(serde_json::Value::as_str);
        if !matches!(
            schema,
            Some("proofbound-evidence/3" | "proofbound-adapter-observation/2")
        ) {
            bail!("PB-ADAPTER-0008: adapter evidence has an unsupported schema");
        }
    }
    validate_operation_response(response, request_operation)?;
    Ok(())
}

fn validate_operation_response(response: &AdapterResponse, operation: &str) -> Result<()> {
    if !response.success {
        if response.evidence.is_some() || !response.inventory.is_empty() {
            bail!(
                "PB-ADAPTER-0008: failed adapter response must carry null evidence and an empty inventory"
            );
        }
        return Ok(());
    }

    match operation {
        "doctor" if response.evidence.is_some() || !response.inventory.is_empty() => bail!(
            "PB-ADAPTER-0008: successful doctor response must carry null evidence and an empty inventory"
        ),
        "inventory" if response.evidence.is_some() || response.inventory.is_empty() => bail!(
            "PB-ADAPTER-0008: successful inventory response must carry null evidence and an exact nonempty inventory"
        ),
        "check" | "reproduce" => {
            let evidence = response.evidence.as_ref().context(
                "PB-ADAPTER-0008: successful evidence response omitted passing evidence",
            )?;
            if response.inventory.is_empty() || !evidence_reports_passed(evidence)? {
                bail!(
                    "PB-ADAPTER-0008: successful evidence response must carry passing evidence and an exact nonempty inventory"
                );
            }
        }
        "update" => {
            if let Some(evidence) = &response.evidence
                && evidence_reports_passed(evidence)?
            {
                bail!("PB-ADAPTER-0008: update response must not carry passing evidence");
            }
        }
        _ => {}
    }
    Ok(())
}

fn evidence_reports_passed(evidence: &serde_json::Value) -> Result<bool> {
    let object = evidence
        .as_object()
        .context("PB-ADAPTER-0008: adapter evidence must be an object")?;
    match object.get("schema").and_then(serde_json::Value::as_str) {
        Some("proofbound-evidence/3") => {
            let status = object
                .get("status")
                .and_then(serde_json::Value::as_str)
                .context("PB-ADAPTER-0008: adapter evidence omitted its typed status")?;
            match status {
                "passed" => Ok(true),
                "failed" | "missing" | "drifted" | "unregistered" | "ambiguous" | "corrupt"
                | "skipped" | "unavailable" => Ok(false),
                _ => bail!("PB-ADAPTER-0008: adapter evidence has an invalid typed status"),
            }
        }
        Some("proofbound-adapter-observation/2") => {
            match object.get("outcome").and_then(serde_json::Value::as_str) {
                Some("passed") => Ok(true),
                Some("failed") => Ok(false),
                _ => bail!("PB-ADAPTER-0008: adapter observation has an invalid typed outcome"),
            }
        }
        _ => bail!("PB-ADAPTER-0008: adapter evidence has an unsupported schema"),
    }
}

fn valid_diagnostic_code(code: &str) -> bool {
    let Some(rest) = code.strip_prefix("PB-") else {
        return false;
    };
    let mut segments = rest.split('-');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some(family), Some(number), None)
            if !family.is_empty()
                && family.bytes().all(|byte| byte.is_ascii_uppercase())
                && number.len() == 4
                && number.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = (MAX_ADAPTER_OUTPUT as usize + 1).saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(bytes)
}

const fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Lean => "lean",
        AdapterKind::CharonAeneas => "charon-aeneas",
        AdapterKind::Kani => "kani",
        AdapterKind::RustTest => "rust-test",
        AdapterKind::PythonTest => "python-test",
        AdapterKind::NodeTest => "node-test",
        AdapterKind::CanonicalArtifact => "canonical-artifact",
        AdapterKind::SourceClosure => "source-closure",
        AdapterKind::IndependentCheck => "independent-check",
        AdapterKind::HumanReview => "human-review",
        AdapterKind::TrustedTranscription => "trusted-transcription",
    }
}

fn locate_adapter(name: &str) -> PathBuf {
    if let Some(directory) = env::var_os("PROOFBOUND_ADAPTER_DIR") {
        let path = PathBuf::from(directory).join(name);
        if regular_executable(&path) {
            return path;
        }
    }
    if let Ok(current) = env::current_exe()
        && let Some(parent) = current.parent()
    {
        let sibling = parent.join(name);
        if regular_executable(&sibling) {
            return sibling;
        }
    }
    PathBuf::from(name)
}

pub(crate) fn cache_identities(
    root: &Path,
    unit: &EvidenceUnitManifest,
) -> Result<BTreeMap<String, String>> {
    let mut identities = BTreeMap::new();
    let adapter = unit.adapter;
    let adapter_name = adapter.executable();
    identities.insert(
        format!("adapter:{adapter_name}"),
        optional_program_identity(adapter_name)?,
    );
    let programs: &[&str] = match adapter {
        AdapterKind::Lean => &["lake"],
        AdapterKind::CharonAeneas => &["cargo", "charon", "aeneas"],
        AdapterKind::Kani => &["cargo", "cargo-kani"],
        AdapterKind::RustTest => &["cargo", "rustc"],
        AdapterKind::NodeTest => &["node", "npm"],
        AdapterKind::PythonTest
        | AdapterKind::CanonicalArtifact
        | AdapterKind::IndependentCheck
        | AdapterKind::TrustedTranscription => &["python3"],
        AdapterKind::SourceClosure | AdapterKind::HumanReview => &[],
    };
    for program in programs {
        identities.insert(
            format!("tool:{program}"),
            optional_program_identity(program)?,
        );
    }
    if adapter == AdapterKind::Lean {
        let audit = root.join(".lake/build/bin/proofbound_lean_audit");
        identities.insert(
            "tool:proofbound_lean_audit".into(),
            if audit.is_file() {
                hash_regular(&audit)?
            } else {
                sha256_bytes(b"unavailable:proofbound_lean_audit")
            },
        );
    }
    if adapter == AdapterKind::PythonTest {
        let modules = python_runtime_modules(root, unit)?;
        if !modules.is_empty() {
            identities.insert(
                "tool:python-runtime-dependencies".into(),
                python_runtime_dependency_identity(root, unit, &modules)?,
            );
        }
    }
    Ok(identities)
}

fn python_runtime_modules(root: &Path, unit: &EvidenceUnitManifest) -> Result<Vec<String>> {
    let mut modules = match unit.operation.kind {
        OperationKind::Pytest => vec!["pytest".to_owned()],
        OperationKind::Mypy => vec!["mypy".to_owned()],
        OperationKind::PythonDistribution => {
            let manifest = unit
                .operation
                .manifest
                .as_deref()
                .unwrap_or("pyproject.toml");
            let bytes = fs::read(root.join(manifest)).with_context(|| {
                format!("PB-CACHE-0004: cannot read Python build manifest {manifest}")
            })?;
            if bytes.len() as u64 > 16 << 20 {
                bail!("PB-CACHE-0004: Python build manifest exceeds 16 MiB");
            }
            let document: toml::Value = toml::from_str(
                std::str::from_utf8(&bytes)
                    .context("PB-CACHE-0004: Python build manifest is not UTF-8")?,
            )
            .context("PB-CACHE-0004: Python build manifest is invalid TOML")?;
            let backend = document
                .get("build-system")
                .and_then(|value| value.get("build-backend"))
                .and_then(toml::Value::as_str)
                .and_then(|value| value.split(':').next())
                .filter(|value| valid_python_module(value))
                .context("PB-CACHE-0004: Python build backend is not a valid module")?;
            vec!["build".to_owned(), backend.to_owned()]
        }
        _ => Vec::new(),
    };
    modules.extend(unit.operation.plugins.iter().cloned());
    modules.sort();
    modules.dedup();
    if modules.iter().any(|module| !valid_python_module(module)) {
        bail!("PB-CACHE-0004: Python runtime dependency names must be valid modules");
    }
    Ok(modules)
}

fn valid_python_module(module: &str) -> bool {
    !module.is_empty()
        && module.len() <= 512
        && module.split('.').all(|segment| {
            !segment.is_empty()
                && segment.len() <= 128
                && segment.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
        })
}

const PYTHON_RUNTIME_DEPENDENCY_SCRIPT: &str = r#"import hashlib, importlib.metadata as m, importlib.util, json, os, pathlib, re, stat, sys
modules=json.loads(sys.argv[1])
if not isinstance(modules,list) or not modules or modules != sorted(set(modules)) or any(not isinstance(x,str) for x in modules): raise RuntimeError('invalid module request')
providers=m.packages_distributions()
queue=[]
origins=[]
for name in modules:
 spec=importlib.util.find_spec(name)
 if spec is None or spec.origin is None: raise RuntimeError('module is unavailable: '+name)
 matches=sorted(set(providers.get(name.split('.')[0],[])))
 if len(matches) != 1: raise RuntimeError('module must have one provider: '+name)
 queue.extend(matches)
 origins.append((name,str(pathlib.Path(spec.origin).resolve(strict=True))))
seen={}
requirements={}
while queue:
 name=queue.pop(0)
 dist=m.distribution(name)
 canonical=dist.metadata['Name']
 key=canonical.lower().replace('_','-')
 if key in seen: continue
 seen[key]=dist
 reqs=sorted(dist.requires or [])
 requirements[key]=reqs
 for requirement in reqs:
  match=re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)',requirement)
  if not match: raise RuntimeError('invalid dependency metadata')
  try: dependency=m.distribution(match.group(1))
  except m.PackageNotFoundError: continue
  queue.append(dependency.metadata['Name'])
rows=[]
listed=set()
total=0
for key,dist in sorted(seen.items()):
 files=dist.files
 if files is None: raise RuntimeError('distribution has no installed file inventory: '+key)
 for relative in sorted(str(item) for item in files):
  path=pathlib.Path(dist.locate_file(relative))
  metadata=path.lstat()
  if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode): raise RuntimeError('distribution member is not a regular file')
  data=path.read_bytes()
  total += len(data)
  if len(rows) >= 100000 or total > 1073741824: raise RuntimeError('dependency closure exceeds bounds')
  resolved=str(path.resolve(strict=True))
  listed.add(resolved)
  rows.append((key,dist.version,relative,hashlib.sha256(data).hexdigest(),stat.S_IMODE(metadata.st_mode)))
for name,origin in origins:
 if origin not in listed: raise RuntimeError('module origin is outside its provider inventory: '+name)
material={'schema':'proofbound-python-runtime-dependencies/1','modules':modules,'origins':origins,'requirements':requirements,'files':rows}
encoded=json.dumps(material,sort_keys=True,separators=(',',':')).encode()
result={'schema':'proofbound-python-runtime-dependencies/1','modules':modules,'distributions':sorted(seen),'file_count':len(rows),'total_bytes':total,'sha256':'sha256:'+hashlib.sha256(b'proofbound-python-runtime-dependencies/1\0'+encoded).hexdigest()}
sys.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':')))
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonRuntimeDependencyReport {
    schema: String,
    modules: Vec<String>,
    distributions: Vec<String>,
    file_count: u64,
    total_bytes: u64,
    sha256: String,
}

fn python_runtime_dependency_identity(
    root: &Path,
    unit: &EvidenceUnitManifest,
    modules: &[String],
) -> Result<String> {
    let python = resolved_invocation_program("python3")
        .context("PB-CACHE-0004: python3 is unavailable for dependency discovery")?;
    let python_identity = python
        .canonicalize()
        .context("PB-CACHE-0004: python3 identity cannot be resolved")?;
    let root = root
        .canonicalize()
        .context("PB-CACHE-0004: Python project root cannot be resolved")?;
    let environment = unit
        .environment_allowlist
        .iter()
        .map(|name| (name, env::var_os(name)))
        .collect::<Vec<_>>();
    let memo_key = canonical_json(&serde_json::json!({
        "python_invocation": python,
        "python_identity": python_identity,
        "root": root,
        "modules": modules,
        "environment": environment.iter().map(|(name, value)| {
            (name, value.as_ref().map(|item| item.to_string_lossy()))
        }).collect::<Vec<_>>(),
    }))?;
    static IDENTITIES: OnceLock<Mutex<BTreeMap<Vec<u8>, String>>> = OnceLock::new();
    let identities = IDENTITIES.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(identity) = identities
        .lock()
        .map_err(|_| anyhow::anyhow!("PB-CACHE-0004: Python identity memo is poisoned"))?
        .get(&memo_key)
        .cloned()
    {
        return Ok(identity);
    }
    let identity =
        discover_python_runtime_dependency_identity(&root, modules, &python, &environment)?;
    identities
        .lock()
        .map_err(|_| anyhow::anyhow!("PB-CACHE-0004: Python identity memo is poisoned"))?
        .insert(memo_key, identity.clone());
    Ok(identity)
}

fn discover_python_runtime_dependency_identity(
    root: &Path,
    modules: &[String],
    python: &Path,
    environment: &[(&String, Option<std::ffi::OsString>)],
) -> Result<String> {
    let modules_json = String::from_utf8(canonical_json(&modules.to_vec())?)?;
    let mut command = Command::new(python);
    command
        .current_dir(root)
        .args(["-c", PYTHON_RUNTIME_DEPENDENCY_SCRIPT, &modules_json])
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = env::var_os("PATH") {
        command.env("PATH", path);
    }
    for (name, value) in environment {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
    let mut child = command
        .spawn()
        .context("PB-CACHE-0004: Python dependency discovery could not start")?;
    let stdout_pipe = child
        .stdout
        .take()
        .context("PB-CACHE-0004: Python dependency discovery stdout is unavailable")?;
    let stderr_pipe = child
        .stderr
        .take()
        .context("PB-CACHE-0004: Python dependency discovery stderr is unavailable")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout_pipe));
    let stderr_reader = thread::spawn(move || read_bounded(stderr_pipe));
    let status = child.wait()?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("PB-CACHE-0004: stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("PB-CACHE-0004: stderr reader panicked"))??;
    if !status.success()
        || !stderr.is_empty()
        || stdout.is_empty()
        || stdout.len() as u64 > MAX_ADAPTER_OUTPUT
    {
        bail!(
            "PB-CACHE-0004: Python dependency discovery failed closed: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    let report: PythonRuntimeDependencyReport = serde_json::from_slice(&stdout)
        .context("PB-CACHE-0004: Python dependency discovery emitted invalid JSON")?;
    if canonical_json(&report_as_value(&report)?)? != stdout
        || report.schema != "proofbound-python-runtime-dependencies/1"
        || report.modules != modules
        || report.distributions.is_empty()
        || !report
            .distributions
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || report.file_count == 0
        || report.file_count > 100_000
        || report.total_bytes > 1_073_741_824
        || !valid_sha256(&report.sha256)
    {
        bail!("PB-CACHE-0004: Python dependency discovery violated its typed contract");
    }
    Ok(report.sha256)
}

fn report_as_value(report: &PythonRuntimeDependencyReport) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "schema": report.schema,
        "modules": report.modules,
        "distributions": report.distributions,
        "file_count": report.file_count,
        "total_bytes": report.total_bytes,
        "sha256": report.sha256,
    }))
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn optional_program_identity(name: &str) -> Result<String> {
    let Some(path) = resolved_adapter(name) else {
        return Ok(sha256_bytes(format!("unavailable:{name}").as_bytes()));
    };
    hash_regular(&path)
}

fn resolved_adapter(name: &str) -> Option<PathBuf> {
    let candidate = locate_adapter(name);
    if candidate.components().count() > 1 {
        return candidate.canonicalize().ok();
    }
    resolve_path_program(name)
}

fn resolved_invocation_program(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|directory| {
        let candidate = directory.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn resolve_path_program(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|directory| {
        let candidate = directory.join(name);
        candidate
            .is_file()
            .then(|| candidate.canonicalize().ok())
            .flatten()
    })
}

fn hash_regular(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("PB-CACHE-0004: cannot stat {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 512 << 20 {
        bail!(
            "PB-CACHE-0004: tool identity is not a bounded regular file: {}",
            path.display()
        );
    }
    Ok(sha256_bytes(&fs::read(path)?))
}

fn regular_executable(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python_unit(source: &str) -> EvidenceUnitManifest {
        toml::from_str(source).expect("test evidence unit must parse")
    }

    #[test]
    fn adapter_names_are_protocol_names() {
        assert_eq!(adapter_name(AdapterKind::Lean), "lean");
        assert_eq!(adapter_name(AdapterKind::CharonAeneas), "charon-aeneas");
        assert_eq!(adapter_name(AdapterKind::RustTest), "rust-test");
    }

    #[test]
    fn python_runtime_module_selection_is_route_typed() {
        let root = Path::new(".");
        let mypy = python_unit(include_str!(
            "../../../demo/python-inventory-service/evidence/reservation-types.toml"
        ));
        assert_eq!(python_runtime_modules(root, &mypy).unwrap(), ["mypy"]);

        let property = python_unit(include_str!(
            "../../../demo/python-inventory-service/evidence/reservation-property.toml"
        ));
        assert_eq!(
            python_runtime_modules(root, &property).unwrap(),
            ["_hypothesis_pytestplugin", "pytest"]
        );

        let distribution = python_unit(include_str!(
            "../../../demo/python-inventory-service/evidence/wheel-reproduction.toml"
        ));
        let demo_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/python-inventory-service");
        assert_eq!(
            python_runtime_modules(&demo_root, &distribution).unwrap(),
            ["build", "setuptools.build_meta"]
        );
    }

    #[test]
    #[cfg(unix)]
    fn python_runtime_dependency_identity_binds_bytes_modes_and_resolution() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("cache_probe.py"), b"value = 1\n").unwrap();
        let metadata = root.join("cache_probe-1.0.dist-info");
        fs::create_dir(&metadata).unwrap();
        fs::write(
            metadata.join("METADATA"),
            b"Metadata-Version: 2.1\nName: cache-probe\nVersion: 1.0\n",
        )
        .unwrap();
        fs::write(metadata.join("top_level.txt"), b"cache_probe\n").unwrap();
        fs::write(
            metadata.join("RECORD"),
            b"cache_probe.py,,\ncache_probe-1.0.dist-info/METADATA,,\ncache_probe-1.0.dist-info/top_level.txt,,\ncache_probe-1.0.dist-info/RECORD,,\n",
        )
        .unwrap();
        let modules = vec!["cache_probe".to_owned()];
        let python = resolved_adapter("python3").unwrap();
        let environment = Vec::new();

        let first =
            discover_python_runtime_dependency_identity(root, &modules, &python, &environment)
                .unwrap();
        fs::write(root.join("cache_probe.py"), b"value = 2\n").unwrap();
        let changed_bytes =
            discover_python_runtime_dependency_identity(root, &modules, &python, &environment)
                .unwrap();
        assert_ne!(first, changed_bytes);

        let mut permissions = fs::metadata(root.join("cache_probe.py"))
            .unwrap()
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(root.join("cache_probe.py"), permissions).unwrap();
        let changed_mode =
            discover_python_runtime_dependency_identity(root, &modules, &python, &environment)
                .unwrap();
        assert_ne!(changed_bytes, changed_mode);

        let second = root.join("other_probe-1.0.dist-info");
        fs::create_dir(&second).unwrap();
        fs::write(
            second.join("METADATA"),
            b"Metadata-Version: 2.1\nName: other-probe\nVersion: 1.0\n",
        )
        .unwrap();
        fs::write(second.join("top_level.txt"), b"cache_probe\n").unwrap();
        fs::write(
            second.join("RECORD"),
            b"other_probe-1.0.dist-info/METADATA,,\nother_probe-1.0.dist-info/top_level.txt,,\nother_probe-1.0.dist-info/RECORD,,\n",
        )
        .unwrap();
        assert!(
            discover_python_runtime_dependency_identity(root, &modules, &python, &environment)
                .is_err()
        );
        fs::remove_dir_all(&second).unwrap();

        fs::remove_file(root.join("cache_probe.py")).unwrap();
        fs::write(root.join("real_probe.py"), b"value = 2\n").unwrap();
        symlink("real_probe.py", root.join("cache_probe.py")).unwrap();
        assert!(
            discover_python_runtime_dependency_identity(root, &modules, &python, &environment)
                .is_err()
        );
    }

    #[test]
    fn diagnostic_codes_follow_the_public_schema() {
        assert!(valid_diagnostic_code("PB-LEAN-0001"));
        assert!(!valid_diagnostic_code("PB-Lean-0001"));
        assert!(!valid_diagnostic_code("PB-LEAN-1"));
        assert!(!valid_diagnostic_code("PB-LEAN-0001-extra"));
    }

    fn protocol_value(success: bool, evidence: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema": "proofbound-adapter-protocol/1",
            "type": "response",
            "request_id": "0123456789abcdef0123456789abcdef",
            "adapter": "lean",
            "success": success,
            "evidence": evidence,
            "inventory": ["Demo.claim"],
            "diagnostics": [],
        })
    }

    #[test]
    fn response_boundary_requires_canonical_json() {
        let value = protocol_value(true, serde_json::json!({"schema": "proofbound-evidence/3"}));
        let mut noncanonical = serde_json::to_vec_pretty(&value).unwrap();
        noncanonical.push(b'\n');
        assert!(
            parse_response(
                &noncanonical,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );
    }

    #[test]
    fn failed_response_cannot_smuggle_evidence() {
        let value = protocol_value(
            false,
            serde_json::json!({"schema": "proofbound-evidence/3"}),
        );
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        let mut inventoried_failure = protocol_value(false, serde_json::Value::Null);
        let bytes = canonical_json(&inventoried_failure).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );
        inventoried_failure["inventory"] = serde_json::json!([]);
        let bytes = canonical_json(&inventoried_failure).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_ok()
        );
    }

    #[test]
    fn successful_operations_have_disjoint_evidence_and_inventory_shapes() {
        let parse = |value: &serde_json::Value, operation: &str| {
            parse_response(
                &canonical_json(value).unwrap(),
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                operation,
            )
        };

        let mut doctor = protocol_value(true, serde_json::Value::Null);
        doctor["inventory"] = serde_json::json!([]);
        assert!(parse(&doctor, "doctor").is_ok());
        doctor["inventory"] = serde_json::json!(["Demo.claim"]);
        assert!(parse(&doctor, "doctor").is_err());

        let inventory = protocol_value(true, serde_json::Value::Null);
        assert!(parse(&inventory, "inventory").is_ok());
        assert!(
            parse(
                &protocol_value(true, serde_json::json!({"schema": "proofbound-evidence/3"})),
                "inventory"
            )
            .is_err()
        );

        let evidence = protocol_value(
            true,
            serde_json::json!({
                "schema": "proofbound-evidence/3",
                "status": "passed"
            }),
        );
        assert!(parse(&evidence, "check").is_ok());
        assert!(parse(&evidence, "reproduce").is_ok());
        assert!(parse(&protocol_value(true, serde_json::Value::Null), "check").is_err());
        assert!(
            parse(
                &protocol_value(
                    true,
                    serde_json::json!({
                        "schema": "proofbound-evidence/3",
                        "status": "failed"
                    })
                ),
                "check"
            )
            .is_err()
        );

        assert!(
            parse(
                &protocol_value(
                    true,
                    serde_json::json!({
                        "schema": "proofbound-evidence/3",
                        "status": "passed"
                    })
                ),
                "update"
            )
            .is_err()
        );
        assert!(
            parse(
                &protocol_value(
                    true,
                    serde_json::json!({
                        "schema": "proofbound-evidence/3",
                        "status": "drifted"
                    })
                ),
                "update"
            )
            .is_ok()
        );
        assert!(parse(&protocol_value(true, serde_json::Value::Null), "update").is_ok());
    }

    #[test]
    fn successful_inventory_is_nonempty_valid_unique_and_strictly_sorted() {
        let mut value = protocol_value(
            true,
            serde_json::json!({
                "schema": "proofbound-evidence/3",
                "status": "passed"
            }),
        );
        value["inventory"] = serde_json::json!([]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        value["inventory"] = serde_json::json!(["b", "a"]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        value["inventory"] = serde_json::json!(["a", "a"]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );

        value["inventory"] = serde_json::json!(["bad\nname"]);
        let bytes = canonical_json(&value).unwrap();
        assert!(
            parse_response(
                &bytes,
                &[],
                "0123456789abcdef0123456789abcdef",
                "lean",
                "check",
            )
            .is_err()
        );
    }
}
