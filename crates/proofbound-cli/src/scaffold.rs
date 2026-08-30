use std::{
    collections::BTreeMap,
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use walkdir::WalkDir;

const CLAIM_ID: &str = "PROJECT-CLAIM-001";
const ASSUMPTION_ID: &str = "PROJECT-RUNTIME-ASSUMPTION-001";
const EVIDENCE_ID: &str = "existing-tests";
const MAX_DISCOVERY_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_DISCOVERY_COPY_BYTES: u64 = 1 << 30;

/// Create the smallest useful Tier-0 ledger. This is the only place where the
/// CLI writes initial committed manifests without an existing project.
pub fn init_project(root: &Path) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("could not resolve {}", root.display()))?;
    let project_path = root.join("proofbound.toml");
    let claim_path = root.join(format!("claims/{CLAIM_ID}.toml"));
    let assumption_path = root.join(format!("assumptions/{ASSUMPTION_ID}.toml"));
    let evidence_path = root.join(format!("proofbound/evidence/{EVIDENCE_ID}.toml"));
    for path in [&project_path, &claim_path, &assumption_path, &evidence_path] {
        if path.exists() {
            bail!("PB-INIT-0001: refusing to overwrite {}", path.display());
        }
    }

    // Inventory occurs in an isolated copy before any Proofbound file is
    // written. A failed discovery therefore cannot leave a partial scaffold
    // or modify a Cargo lockfile / pytest cache in the user's project.
    let discovered = discover_test(&root)?;
    let source = path_text(&discovered.source);
    let manifest = path_text(&discovered.manifest);
    let mut inputs = vec![manifest.clone(), source.clone()];
    if discovered.adapter == "rust-test" && manifest != "Cargo.toml" {
        inputs.push("Cargo.toml".to_owned());
    }
    for lock in discovered.lockfiles(&root) {
        inputs.push(path_text(&lock));
    }
    inputs.sort();
    inputs.dedup();

    let mut semantic = inputs.clone();
    semantic.extend([
        "assumptions/**".to_owned(),
        "claims/**".to_owned(),
        "proofbound/evidence/**".to_owned(),
    ]);
    semantic.sort();
    semantic.dedup();
    let presentation = root
        .join("README.md")
        .is_file()
        .then(|| "README.md".to_owned())
        .into_iter()
        .collect::<Vec<_>>();

    let project_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("existing-project");
    let project = format!(
        "schema = \"proofbound-project/1\"\nproject = {project_name:?}\ntier = 0\nclaim_manifests = [\"claims/*.toml\"]\nassumption_manifests = [\"assumptions/*.toml\"]\nevidence_units = [\"proofbound/evidence/*.toml\"]\ntranslation_units = []\nmodel_check_units = []\npolicy_manifests = []\nreview_manifests = []\n\n[source]\nsemantic = {}\nrunner = []\npresentation = {}\n\n[toolchains]\n\n[limits]\nmax_manifest_bytes = 2097152\nmax_files = 100000\nmax_total_bytes = 4294967296\n",
        toml_array(&semantic),
        toml_array(&presentation),
    );
    let claim = format!(
        "schema = \"proofbound-claim/1\"\nid = \"{CLAIM_ID}\"\ntitle = \"Worked Tier-0 placeholder bound to an existing test\"\nstatement = \"Replace this exact statement with one important behavior already exercised by the registered test.\"\npublic_language = \"This is a placeholder ledger entry, not a proved domain claim.\"\nsubject = {source:?}\nprofile = \"ledger\"\ntier = 0\nprimary_linkage = \"model-only\"\nevidence = [\"example-test:{EVIDENCE_ID}\"]\nassumptions = [\"{ASSUMPTION_ID}\"]\npremises = []\nopen_obligations = [\"Replace the placeholder language with the exact behavior the existing test supports.\"]\nout_of_scope = [\"Formal proof, source refinement, and artifact binding have not been adopted at Tier 0.\"]\nsource_roots = {}\n",
        toml_array(&inputs),
    );
    let assumption = format!(
        "schema = \"proofbound-assumption/1\"\nid = \"{ASSUMPTION_ID}\"\nstatement = \"The registered test and its host runtime are representative of the behavior described by the placeholder claim.\"\ncategory = \"runtime-environment\"\nowner = \"project maintainer\"\nrationale = \"A passing test observes one configured execution; it does not prove that the test is representative or that every deployment has the same runtime behavior.\"\nscope = \"Only the interpretation of {CLAIM_ID} from the registered test result.\"\naffected_claims = [\"{CLAIM_ID}\"]\nreview_evidence = [{review:?}]\ndischarge_plan = \"Replace or narrow this assumption when stronger evidence and an exact shipping-environment binding are registered.\"\nsource_citation = {review:?}\nstatus = \"active\"\n",
        review = format!("{source}#L1"),
    );
    let package = discovered
        .package
        .as_ref()
        .map_or_else(String::new, |package| format!("package = {package:?}\n"));
    let unit = format!(
        "schema = \"proofbound-evidence-unit/1\"\nid = \"{EVIDENCE_ID}\"\nadapter = {:?}\nkind = \"example-test\"\nclaims = [\"{CLAIM_ID}\"]\ntier = 0\nassumptions = [\"{ASSUMPTION_ID}\"]\nexpected_inventory = {}\ninputs = {}\noutputs = []\nenvironment_allowlist = [\"PATH\"]\n\n[operation]\ntype = {:?}\nmanifest = {manifest:?}\n{package}targets = {}\npaths = {}\narguments = {}\n\n[resource_budget]\ntime_seconds = 300\ndisk_bytes = 1073741824\nmemory_bytes = 2147483648\n",
        discovered.adapter,
        toml_array(std::slice::from_ref(&discovered.inventory)),
        toml_array(&inputs),
        discovered.operation,
        toml_array(&discovered.targets),
        toml_array(&discovered.paths),
        toml_array(&discovered.arguments),
    );

    write_scaffold(&[
        (&project_path, project.as_str()),
        (&claim_path, claim.as_str()),
        (&assumption_path, assumption.as_str()),
        (&evidence_path, unit.as_str()),
    ])
}

#[derive(Debug)]
struct DiscoveredTest {
    adapter: &'static str,
    operation: &'static str,
    manifest: PathBuf,
    package: Option<String>,
    targets: Vec<String>,
    paths: Vec<String>,
    arguments: Vec<String>,
    inventory: String,
    source: PathBuf,
}

impl DiscoveredTest {
    fn lockfiles(&self, root: &Path) -> Vec<PathBuf> {
        let candidates: &[&str] = match self.adapter {
            "rust-test" => &["Cargo.lock"],
            "python-test" => &["uv.lock", "poetry.lock"],
            _ => &[],
        };
        candidates
            .iter()
            .map(PathBuf::from)
            .filter(|path| root.join(path).is_file())
            .collect()
    }
}

fn discover_test(root: &Path) -> Result<DiscoveredTest> {
    let shadow = DiscoveryShadow::new(root)?;
    let mut failures = Vec::new();

    if root.join("Cargo.toml").is_file() {
        match discover_rust_test(root, shadow.path()) {
            Ok(Some(test)) => return Ok(test),
            Ok(None) => failures.push("Cargo collected no libtest tests".to_owned()),
            Err(error) => failures.push(format!("Rust discovery: {error:#}")),
        }
    }
    if root.join("pyproject.toml").is_file() {
        match discover_python_test(root, shadow.path()) {
            Ok(Some(test)) => return Ok(test),
            Ok(None) => failures.push("pytest collected no uniquely selectable tests".to_owned()),
            Err(error) => failures.push(format!("Python discovery: {error:#}")),
        }
    }

    let detail = if failures.is_empty() {
        "a root Cargo.toml or pyproject.toml and at least one ordinary test are required".to_owned()
    } else {
        failures.join("; ")
    };
    bail!(
        "PB-INIT-0002: no usable Rust or Python test surface was found; {detail}. Add or repair one ordinary passing test before initializing the Tier-0 ledger"
    )
}

#[derive(Debug)]
struct RustArtifact {
    target: String,
    selector: String,
    source: PathBuf,
    executable: PathBuf,
    priority: u8,
}

fn discover_rust_test(_root: &Path, shadow: &Path) -> Result<Option<DiscoveredTest>> {
    let root_manifest = shadow.join("Cargo.toml");
    let mut metadata_command = discovery_command("cargo", shadow, DiscoveryFlavor::Rust);
    metadata_command.args(["metadata", "--format-version", "1", "--no-deps"]);
    metadata_command.arg("--manifest-path").arg(&root_manifest);
    let output = run_discovery(metadata_command, "Cargo workspace metadata")?;
    let packages = parse_workspace_packages(&output.stdout, shadow)?;
    let mut failures = Vec::new();

    for package in packages {
        let mut command = discovery_command("cargo", shadow, DiscoveryFlavor::Rust);
        command
            .arg("test")
            .arg("--no-run")
            .arg("--message-format=json")
            .arg("--manifest-path")
            .arg(shadow.join(&package.manifest))
            .arg("--package")
            .arg(&package.name);
        let output = match run_discovery(command, "Cargo test inventory compilation") {
            Ok(output) => output,
            Err(error) => {
                failures.push(format!("{}: {error:#}", package.name));
                continue;
            }
        };
        let mut artifacts = parse_cargo_artifacts(&output.stdout, shadow, &package.id)?;
        artifacts.sort_by(|left, right| {
            (left.priority, &left.target, &left.selector).cmp(&(
                right.priority,
                &right.target,
                &right.selector,
            ))
        });
        for artifact in artifacts {
            let mut list = discovery_command(&artifact.executable, shadow, DiscoveryFlavor::Rust);
            list.args(["--list", "--format", "terse"]);
            let output = run_discovery(list, "libtest inventory")?;
            let Some(test) = parse_libtest_inventory(&output.stdout)?.into_iter().next() else {
                continue;
            };
            return Ok(Some(DiscoveredTest {
                adapter: "rust-test",
                operation: "cargo-test",
                manifest: package.manifest,
                package: Some(package.name),
                targets: vec![artifact.selector],
                paths: Vec::new(),
                arguments: Vec::new(),
                inventory: format!("{}::{test}", artifact.target),
                source: artifact.source,
            }));
        }
    }
    if failures.is_empty() {
        Ok(None)
    } else {
        bail!(
            "workspace member test discovery failed: {}",
            failures.join("; ")
        )
    }
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoMetadataPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

#[derive(Debug)]
struct WorkspacePackage {
    id: String,
    name: String,
    manifest: PathBuf,
}

fn parse_workspace_packages(bytes: &[u8], shadow: &Path) -> Result<Vec<WorkspacePackage>> {
    let metadata: CargoMetadata =
        serde_json::from_slice(bytes).context("Cargo metadata is not valid typed metadata")?;
    let shadow = shadow.canonicalize()?;
    if metadata.workspace_root.canonicalize()? != shadow {
        bail!("Cargo metadata workspace root escaped the discovery shadow");
    }
    let members = metadata
        .workspace_members
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut packages = Vec::new();
    for package in metadata
        .packages
        .into_iter()
        .filter(|package| members.contains(&package.id))
    {
        if !safe_atom(&package.name) {
            bail!("Cargo metadata returned an unsafe package name");
        }
        let manifest = package.manifest_path.canonicalize()?;
        if !manifest.starts_with(&shadow)
            || manifest.file_name().and_then(OsStr::to_str) != Some("Cargo.toml")
        {
            bail!("Cargo workspace member manifest escaped the discovery shadow");
        }
        packages.push(WorkspacePackage {
            id: package.id,
            name: package.name,
            manifest: manifest.strip_prefix(&shadow)?.to_owned(),
        });
    }
    packages.sort_by(|left, right| {
        (&left.manifest, &left.name, &left.id).cmp(&(&right.manifest, &right.name, &right.id))
    });
    if packages.is_empty() {
        bail!("Cargo metadata reported no ordinary workspace members");
    }
    Ok(packages)
}

#[derive(Debug, Deserialize)]
struct CargoArtifactMessage {
    reason: String,
    package_id: Option<String>,
    profile: Option<CargoArtifactProfile>,
    target: Option<CargoArtifactTarget>,
    executable: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct CargoArtifactProfile {
    test: bool,
}

#[derive(Debug, Deserialize)]
struct CargoArtifactTarget {
    name: String,
    kind: Vec<String>,
    src_path: PathBuf,
}

fn parse_cargo_artifacts(
    bytes: &[u8],
    shadow: &Path,
    expected_package_id: &str,
) -> Result<Vec<RustArtifact>> {
    let mut artifacts = BTreeMap::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let value: CargoArtifactMessage = serde_json::from_slice(line)
            .with_context(|| format!("invalid Cargo JSON message at line {}", index + 1))?;
        if value.reason != "compiler-artifact"
            || value.package_id.as_deref() != Some(expected_package_id)
            || value.profile.as_ref().is_none_or(|profile| !profile.test)
        {
            continue;
        }
        let Some(executable) = value.executable else {
            continue;
        };
        let Some(target) = value.target else {
            continue;
        };
        if !safe_atom(&target.name) {
            continue;
        }
        let Some((priority, selector)) = cargo_selector(&target) else {
            continue;
        };
        let source = target.src_path.canonicalize()?;
        let executable = executable.canonicalize()?;
        if !source.starts_with(shadow) || !executable.starts_with(shadow) {
            continue;
        }
        let source = source.strip_prefix(shadow)?.to_owned();
        artifacts.insert(
            (target.name.clone(), selector.clone()),
            RustArtifact {
                target: target.name,
                selector,
                source,
                executable,
                priority,
            },
        );
    }
    Ok(artifacts.into_values().collect())
}

fn cargo_selector(target: &CargoArtifactTarget) -> Option<(u8, String)> {
    let contains = |kind: &str| target.kind.iter().any(|value| value == kind);
    if contains("lib") || contains("proc-macro") {
        Some((0, "--lib".to_owned()))
    } else if contains("test") {
        Some((1, format!("--test={}", target.name)))
    } else if contains("bin") {
        Some((2, format!("--bin={}", target.name)))
    } else if contains("example") {
        Some((3, format!("--example={}", target.name)))
    } else if contains("bench") {
        Some((4, format!("--bench={}", target.name)))
    } else {
        None
    }
}

fn parse_libtest_inventory(bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(bytes).context("libtest inventory is not UTF-8")?;
    let mut tests = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if line.ends_with(": benchmark") {
            continue;
        }
        let test = line
            .strip_suffix(": test")
            .with_context(|| format!("unrecognized libtest inventory line {line:?}"))?;
        if !safe_libtest_name(test) {
            bail!("libtest returned an unsafe test name {test:?}");
        }
        tests.push(test.to_owned());
    }
    tests.sort();
    tests.dedup();
    Ok(tests)
}

#[derive(Clone, Debug)]
struct PythonNode {
    canonical: String,
    target: String,
}

fn discover_python_test(root: &Path, shadow: &Path) -> Result<Option<DiscoveredTest>> {
    let candidates = python_test_files(root)?;
    let manifest = shadow.join("pyproject.toml");
    let mut failures = Vec::new();
    for source in candidates {
        let collection_path = shadow.join(&source);
        let mut command = discovery_command("python3", shadow, DiscoveryFlavor::Python);
        command
            .args([
                "-m",
                "pytest",
                "--collect-only",
                "-p",
                "no:cacheprovider",
                "-q",
            ])
            .arg("--rootdir")
            .arg(manifest.parent().expect("manifest has a parent"))
            .arg(&collection_path);
        let output = command
            .output()
            .with_context(|| "could not execute python3 for pytest inventory")?;
        check_output_size(&output)?;
        if !output.status.success() {
            failures.push(format!(
                "{}: {}",
                source.display(),
                concise_process_failure(&output)
            ));
            continue;
        }
        let nodes = parse_pytest_inventory(&output.stdout, shadow)?;
        let mut target_counts = BTreeMap::<String, usize>::new();
        for node in &nodes {
            *target_counts.entry(node.target.clone()).or_default() += 1;
        }
        let Some(node) = nodes
            .into_iter()
            .find(|node| target_counts.get(&node.target) == Some(&1))
        else {
            continue;
        };
        let source_text = path_text(&source);
        return Ok(Some(DiscoveredTest {
            adapter: "python-test",
            operation: "pytest",
            manifest: PathBuf::from("pyproject.toml"),
            package: None,
            targets: vec![node.target],
            paths: vec![source_text],
            arguments: Vec::new(),
            inventory: node.canonical,
            source,
        }));
    }
    if !failures.is_empty() {
        bail!("pytest collection failed: {}", failures.join("; "));
    }
    Ok(None)
}

fn python_test_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || entry
                    .path()
                    .strip_prefix(root)
                    .ok()
                    .is_none_or(|path| !excluded_from_shadow(path))
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if path.extension().and_then(OsStr::to_str) == Some("py")
            && (name.starts_with("test_") || name.ends_with("_test.py"))
        {
            paths.push(path.strip_prefix(root)?.to_owned());
        }
    }
    Ok(paths)
}

fn parse_pytest_inventory(bytes: &[u8], shadow: &Path) -> Result<Vec<PythonNode>> {
    let text = std::str::from_utf8(bytes).context("pytest inventory is not UTF-8")?;
    let mut nodes = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !line.contains("::") {
            if line.ends_with(" collected")
                || line.contains(" tests collected in ")
                || line.contains(" test collected in ")
                || line.starts_with('=')
            {
                continue;
            }
            bail!("unrecognized pytest inventory line {line:?}");
        }
        let (file, suffix) = line.split_once("::").expect("delimiter checked");
        let path = PathBuf::from(file);
        let absolute = if path.is_absolute() {
            path
        } else {
            shadow.join(path)
        };
        let absolute = absolute.canonicalize()?;
        if !absolute.starts_with(shadow)
            || absolute.extension().and_then(OsStr::to_str) != Some("py")
            || !safe_pytest_suffix(suffix)
        {
            bail!("pytest returned an unsafe node {line:?}");
        }
        let stem = absolute
            .file_stem()
            .and_then(OsStr::to_str)
            .filter(|stem| safe_atom(stem))
            .context("pytest returned an unsafe file stem")?;
        let target = suffix
            .rsplit("::")
            .next()
            .filter(|target| safe_test_tail(target))
            .context("pytest returned an unsafe target")?;
        nodes.push(PythonNode {
            canonical: format!("{stem}::{suffix}"),
            target: target.to_owned(),
        });
    }
    nodes.sort_by(|left, right| left.canonical.cmp(&right.canonical));
    if nodes
        .windows(2)
        .any(|pair| pair[0].canonical == pair[1].canonical)
    {
        bail!("pytest returned duplicate normalized nodes");
    }
    Ok(nodes)
}

#[derive(Clone, Copy)]
enum DiscoveryFlavor {
    Rust,
    Python,
}

fn discovery_command(program: impl AsRef<OsStr>, cwd: &Path, flavor: DiscoveryFlavor) -> Command {
    let mut command = Command::new(program);
    command.current_dir(cwd).env_clear().env("TERM", "dumb");
    if let Some(path) = env::var_os("PATH") {
        command.env("PATH", path);
    }
    match flavor {
        DiscoveryFlavor::Rust => {
            command
                .env("CARGO_NET_OFFLINE", "true")
                .env("CARGO_TERM_COLOR", "never");
        }
        DiscoveryFlavor::Python => {
            command
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .env("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1");
        }
    }
    command
}

fn run_discovery(mut command: Command, label: &str) -> Result<Output> {
    let output = command
        .output()
        .with_context(|| format!("could not execute {label}"))?;
    check_output_size(&output)?;
    if !output.status.success() {
        bail!("{label} failed: {}", concise_process_failure(&output));
    }
    Ok(output)
}

fn check_output_size(output: &Output) -> Result<()> {
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_DISCOVERY_OUTPUT {
        bail!("test inventory output exceeded {MAX_DISCOVERY_OUTPUT} bytes");
    }
    Ok(())
}

fn concise_process_failure(output: &Output) -> String {
    let text = format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    text.chars().take(2048).collect()
}

struct DiscoveryShadow {
    directory: PathBuf,
    project: PathBuf,
}

impl DiscoveryShadow {
    fn new(source: &Path) -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = env::temp_dir();
        let mut directory = None;
        for attempt in 0..100_u8 {
            let candidate = base.join(format!(
                "proofbound-init-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    directory = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.context("could not allocate an isolated discovery directory")?;
        let project = directory.join("project");
        fs::create_dir(&project)?;
        // macOS exposes the temporary directory through `/var` while
        // canonicalized compiler/pytest paths use `/private/var`. Keep the
        // trust-boundary prefix in the same canonical form as tool output.
        let project = project.canonicalize()?;
        if let Err(error) = copy_shadow(source, &project) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        Ok(Self { directory, project })
    }

    fn path(&self) -> &Path {
        &self.project
    }
}

impl Drop for DiscoveryShadow {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn copy_shadow(source: &Path, destination: &Path) -> Result<()> {
    let mut copied = 0_u64;
    let walker = WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || entry
                    .path()
                    .strip_prefix(source)
                    .ok()
                    .is_none_or(|path| !excluded_from_shadow(path))
        });
    for entry in walker {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "PB-INIT-0003: test discovery rejects symlink {} to match the adapter boundary",
                relative.display()
            );
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            copied = copied
                .checked_add(entry.metadata()?.len())
                .context("test discovery copy size overflow")?;
            if copied > MAX_DISCOVERY_COPY_BYTES {
                bail!("PB-INIT-0003: test discovery copy exceeds {MAX_DISCOVERY_COPY_BYTES} bytes");
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), target)?;
        } else {
            bail!(
                "PB-INIT-0003: unsupported file type at {}",
                relative.display()
            );
        }
    }
    Ok(())
}

fn excluded_from_shadow(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                ".git"
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

fn safe_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn safe_libtest_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.split("::").all(safe_test_tail)
}

fn safe_test_tail(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '[' | ']' | '.')
        })
}

fn safe_pytest_suffix(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2048 && value.split("::").all(safe_test_tail)
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn toml_array(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("{value:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn write_new(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Install the scaffold as a transaction. Discovery and rendering have
/// already completed before this function runs; if any create-new write
/// loses a race or fails, every file and directory created by this call is
/// removed while pre-existing paths are left untouched.
fn write_scaffold(files: &[(&Path, &str)]) -> Result<()> {
    let mut created_directories = Vec::new();
    let mut created_files = Vec::new();
    let result = (|| {
        for (path, _) in files {
            let parent = path.parent().context("scaffold output has no parent")?;
            let mut missing = Vec::new();
            let mut cursor = parent;
            while !cursor.exists() {
                missing.push(cursor.to_owned());
                cursor = cursor.parent().context("scaffold directory escaped root")?;
            }
            for directory in missing.into_iter().rev() {
                match fs::create_dir(&directory) {
                    Ok(()) => created_directories.push(directory),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        for (path, contents) in files {
            write_new(path, contents)?;
            created_files.push((*path).to_owned());
        }
        Ok(())
    })();
    if result.is_err() {
        for path in created_files.into_iter().rev() {
            let _ = fs::remove_file(path);
        }
        for path in created_directories.into_iter().rev() {
            let _ = fs::remove_dir(path);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_evidence::canonical_json;
    use proofbound_manifest::{AdapterKind, AdapterRequest, OperationKind, ProjectBundle};

    const ADAPTER_CHILD_REQUEST: &str = "PROOFBOUND_SCAFFOLD_ADAPTER_CHILD_REQUEST";

    #[test]
    fn init_rust_binds_exact_collected_test_and_adapter_accepts_it() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 7 }\n#[cfg(test)] mod tests { #[test] fn existing() { assert_eq!(super::value(), 7); } }\n",
        )
        .unwrap();

        init_project(temp.path()).unwrap();
        let bundle = ProjectBundle::load(temp.path()).unwrap();
        let unit = &bundle.evidence_units[EVIDENCE_ID].1;
        assert_eq!(unit.adapter, AdapterKind::RustTest);
        assert_eq!(unit.operation.kind, OperationKind::CargoTest);
        assert_eq!(unit.operation.manifest.as_deref(), Some("Cargo.toml"));
        assert_eq!(unit.operation.package.as_deref(), Some("sample"));
        assert_eq!(unit.operation.targets, ["--lib"]);
        assert!(unit.operation.paths.is_empty());
        assert_eq!(unit.expected_inventory, ["sample::tests::existing"]);
        assert_eq!(unit.assumptions, [ASSUMPTION_ID]);
        assert_eq!(bundle.assumptions.len(), 1);
        let assumption = &bundle.assumptions[ASSUMPTION_ID].1;
        assert_eq!(assumption.affected_claims, [CLAIM_ID]);
        assert_eq!(assumption.review_evidence, ["src/lib.rs#L1"]);
        assert_adapter_accepts(temp.path(), &bundle);
    }

    #[test]
    fn init_virtual_cargo_workspace_selects_a_typed_member_test() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = [\"member\"]\n",
        )
        .unwrap();
        fs::create_dir_all(temp.path().join("member/src")).unwrap();
        fs::write(
            temp.path().join("member/Cargo.toml"),
            "[package]\nname = \"workspace-member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("member/src/lib.rs"),
            "pub fn value() -> u8 { 9 }\n#[cfg(test)] mod tests { #[test] fn existing() { assert_eq!(super::value(), 9); } }\n",
        )
        .unwrap();

        init_project(temp.path()).unwrap();
        let bundle = ProjectBundle::load(temp.path()).unwrap();
        let unit = &bundle.evidence_units[EVIDENCE_ID].1;
        assert_eq!(
            unit.operation.manifest.as_deref(),
            Some("member/Cargo.toml")
        );
        assert_eq!(unit.operation.package.as_deref(), Some("workspace-member"));
        assert_eq!(
            unit.expected_inventory,
            ["workspace_member::tests::existing"]
        );
        assert!(unit.inputs.contains(&"Cargo.toml".to_owned()));
        assert!(unit.inputs.contains(&"member/Cargo.toml".to_owned()));
        assert!(unit.inputs.contains(&"member/src/lib.rs".to_owned()));
        assert_adapter_accepts(temp.path(), &bundle);
    }

    #[test]
    fn init_python_binds_exact_collected_node_and_adapter_accepts_it() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("pyproject.toml"),
            "[project]\nname = \"sample-python\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::create_dir(temp.path().join("tests")).unwrap();
        fs::write(
            temp.path().join("tests/test_sample.py"),
            "def test_existing():\n    assert 3 + 4 == 7\n",
        )
        .unwrap();

        init_project(temp.path()).unwrap();
        let bundle = ProjectBundle::load(temp.path()).unwrap();
        let unit = &bundle.evidence_units[EVIDENCE_ID].1;
        assert_eq!(unit.adapter, AdapterKind::PythonTest);
        assert_eq!(unit.operation.kind, OperationKind::Pytest);
        assert_eq!(unit.operation.manifest.as_deref(), Some("pyproject.toml"));
        assert_eq!(unit.operation.package, None);
        assert_eq!(unit.operation.paths, ["tests/test_sample.py"]);
        assert_eq!(unit.operation.targets, ["test_existing"]);
        assert_eq!(unit.expected_inventory, ["test_sample::test_existing"]);
        assert_adapter_accepts(temp.path(), &bundle);
    }

    #[test]
    fn init_refuses_every_output_collision_without_writing_project_manifest() {
        for collision in [
            "proofbound.toml".to_owned(),
            format!("claims/{CLAIM_ID}.toml"),
            format!("assumptions/{ASSUMPTION_ID}.toml"),
            format!("proofbound/evidence/{EVIDENCE_ID}.toml"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            fs::write(
                temp.path().join("Cargo.toml"),
                "[package]\nname='sample'\nversion='0.1.0'\n",
            )
            .unwrap();
            let path = temp.path().join(&collision);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "owned by the user\n").unwrap();

            let error = init_project(temp.path()).unwrap_err().to_string();
            assert!(error.contains("PB-INIT-0001"));
            assert_eq!(fs::read_to_string(path).unwrap(), "owned by the user\n");
            for output in [
                "proofbound.toml".to_owned(),
                format!("claims/{CLAIM_ID}.toml"),
                format!("assumptions/{ASSUMPTION_ID}.toml"),
                format!("proofbound/evidence/{EVIDENCE_ID}.toml"),
            ] {
                if output != collision {
                    assert!(!temp.path().join(output).exists());
                }
            }
        }
    }

    #[test]
    fn scaffold_transaction_rolls_back_files_created_before_a_late_collision() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("new/first.toml");
        let collision = temp.path().join("existing.toml");
        fs::write(&collision, "owned by the user\n").unwrap();

        assert!(write_scaffold(&[(&first, "new\n"), (&collision, "replacement\n")]).is_err());
        assert!(!first.exists());
        assert!(!temp.path().join("new").exists());
        assert_eq!(
            fs::read_to_string(collision).unwrap(),
            "owned by the user\n"
        );
    }

    #[test]
    fn init_without_a_supported_test_surface_writes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("README.md"), "no tests yet\n").unwrap();
        let error = init_project(temp.path()).unwrap_err().to_string();
        assert!(error.contains("PB-INIT-0002"));
        assert!(!temp.path().join("proofbound.toml").exists());
        assert!(!temp.path().join("claims").exists());
        assert!(!temp.path().join("proofbound").exists());
    }

    #[test]
    fn adapter_contract_child() {
        let Some(request_path) = env::var_os(ADAPTER_CHILD_REQUEST) else {
            return;
        };
        let request = fs::read(request_path).unwrap();
        let response = proofbound_adapter_test::handle_request_bytes(&request);
        assert!(
            response.success,
            "adapter diagnostics: {:?}",
            response.diagnostics
        );
        assert_eq!(response.inventory.len(), 1);
    }

    fn assert_adapter_accepts(root: &Path, bundle: &ProjectBundle) {
        let unit = &bundle.evidence_units[EVIDENCE_ID].1;
        let adapter = match unit.adapter {
            AdapterKind::RustTest => "rust-test",
            AdapterKind::PythonTest => "python-test",
            other => panic!("unexpected scaffold adapter {other:?}"),
        };
        let request = AdapterRequest {
            schema: "proofbound-adapter-protocol/1".into(),
            message_type: "request".into(),
            request_id: "0123456789abcdef0123456789abcdef".into(),
            adapter: adapter.into(),
            operation: "check".into(),
            project_root: ".".into(),
            unit: serde_json::to_value(unit).unwrap(),
        };
        let request_path = root.join("adapter-request.json");
        fs::write(&request_path, canonical_json(&request).unwrap()).unwrap();
        let output = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "scaffold::tests::adapter_contract_child",
                "--nocapture",
            ])
            .current_dir(root)
            .env(ADAPTER_CHILD_REQUEST, &request_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "adapter child failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
