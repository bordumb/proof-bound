use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tempfile::{Builder, TempDir};

#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    version,
    about = "Typed, cheap-first Proofbound development gates"
)]
struct Arguments {
    /// Start repository discovery at this directory instead of the current directory.
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Run formatting, linting, unit tests, schema tests, and the Lean build.
    Preflight,
    /// Construct and independently verify a deterministic, proof-free smoke release.
    ReleaseSmoke,
    /// Build binaries and exercise adapter protocols plus the Lean declaration audit.
    Adapters,
    /// Run the complete gate in a disposable one-commit repository without creating history evidence.
    BootstrapCi,
    /// Run cheap gates first, then one fresh check, release it, and verify it independently.
    Ci {
        /// Exact Git revision range whose assurance regressions require approval.
        #[arg(long, value_name = "BASE..HEAD")]
        diff: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    SyntaxPrecheck,
    Environment,
    Stage01,
    Stage02,
    Stage03,
    Stage04,
    Stage05,
    ReleaseSmoke,
    ApprovalDiff,
    Stages06To09,
    Stage10,
    Stage11,
    Stage12,
}

impl Phase {
    const fn banners(self) -> &'static [&'static str] {
        match self {
            Self::SyntaxPrecheck => &["cheap precheck · Rust formatting"],
            Self::Environment => &["locked environment bootstrap"],
            Self::Stage01 => &["§18 stage 1/12 · manifest/schema validation"],
            Self::Stage02 => &["§18 stage 2/12 · source-closure validation"],
            Self::Stage03 => &["§18 stage 3/12 · Rust format, build, lint, and test"],
            Self::Stage04 => &["§18 stage 4/12 · Python lock and focused tests"],
            Self::Stage05 => &["§18 stage 5/12 · Lean build and compiled axiom audit"],
            Self::ReleaseSmoke => &["cheap precheck · release construction round-trip"],
            Self::ApprovalDiff => &["§18.1 · exact assurance-regression approval diff"],
            Self::Stages06To09 => &[
                "§18 stage 6/12 · Charon/Aeneas deterministic translation",
                "§18 stage 7/12 · Kani inventory and bounded checks",
                "§18 stage 8/12 · cross-language fixture conformance",
                "§18 stage 9/12 · assurance-graph compilation",
            ],
            Self::Stage10 => &["§18 stage 10/12 · demo end-to-end verification"],
            Self::Stage11 => &["§18 stage 11/12 · release receipt reproduction"],
            Self::Stage12 => {
                &["§18 stage 12/12 · independent receipt verification (final verdict)"]
            }
        }
    }

    const fn context(self) -> &'static str {
        self.banners()[0]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Ordinary,
    ReleaseSmokeConstruction,
    ReleaseSmokeVerifier,
    ApprovalDiff,
    FreshCheck,
    CurrentRelease,
    FinalVerifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessStep {
    phase: Phase,
    role: Role,
    label: &'static str,
    program: OsString,
    args: Vec<OsString>,
    stdout_file: Option<PathBuf>,
}

impl ProcessStep {
    fn new(
        phase: Phase,
        role: Role,
        label: &'static str,
        program: impl Into<OsString>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            phase,
            role,
            label,
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            stdout_file: None,
        }
    }

    fn with_stdout_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.stdout_file = Some(path.into());
        self
    }

    fn command_display(&self) -> String {
        let mut rendered = format_os(&self.program);
        for argument in &self.args {
            rendered.push(' ');
            rendered.push_str(&format_os(argument));
        }
        rendered
    }
}

#[derive(Debug)]
struct Plan {
    steps: Vec<ProcessStep>,
    _scratch: TempDir,
}

impl Plan {
    fn for_task(task: Task, root: &Path) -> Result<Self> {
        let scratch = Builder::new()
            .prefix("proofbound-xtask-")
            .tempdir()
            .context("could not create the xtask scratch directory")?;
        let steps = match task {
            Task::Preflight => preflight_steps(),
            Task::Adapters => adapter_steps(),
            Task::ReleaseSmoke => release_smoke_steps(root, scratch.path()),
            Task::Ci { diff } => ci_steps(root, scratch.path(), diff.as_deref()),
            Task::BootstrapCi => unreachable!("bootstrap-ci has a dedicated snapshot runner"),
        };
        Ok(Self {
            steps,
            _scratch: scratch,
        })
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    let start = arguments.root.unwrap_or(
        env::current_dir()
            .context("could not determine the current directory for repository discovery")?,
    );
    let root = discover_repo_root(&start)?;
    match arguments.command {
        Task::BootstrapCi => run_bootstrap_ci(&root),
        task => {
            let plan = Plan::for_task(task, &root)?;
            execute(&root, &plan.steps)
        }
    }
}

fn discover_repo_root(start: &Path) -> Result<PathBuf> {
    let start = start.canonicalize().with_context(|| {
        format!(
            "cannot resolve repository search path `{}`",
            start.display()
        )
    })?;
    let mut candidate = if start.is_file() {
        start
            .parent()
            .context("repository search path has no parent")?
            .to_path_buf()
    } else {
        start.clone()
    };

    loop {
        if is_repo_root(&candidate) {
            return Ok(candidate);
        }
        if !candidate.pop() {
            bail!(
                "could not find the Proofbound repository root above `{}` (expected Cargo.toml, proofbound.toml, and justfile)",
                start.display()
            );
        }
    }
}

fn is_repo_root(path: &Path) -> bool {
    path.join("Cargo.toml").is_file()
        && path.join("proofbound.toml").is_file()
        && path.join("justfile").is_file()
}

const BOOTSTRAP_COMMIT_MESSAGE: &str =
    "TEST-ONLY bootstrap CI snapshot; NO PROJECT HISTORY EVIDENCE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapRole {
    Enumerate,
    Init,
    ConfigureHooks,
    ConfigureName,
    ConfigureEmail,
    DisableSigning,
    Add,
    Commit,
    Ci,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BootstrapCommand {
    role: BootstrapRole,
    label: &'static str,
    cwd: PathBuf,
    program: OsString,
    args: Vec<OsString>,
}

impl BootstrapCommand {
    fn new<const N: usize>(
        role: BootstrapRole,
        label: &'static str,
        cwd: &Path,
        program: &'static str,
        args: [&'static str; N],
    ) -> Self {
        Self {
            role,
            label,
            cwd: cwd.to_path_buf(),
            program: OsString::from(program),
            args: args.into_iter().map(OsString::from).collect(),
        }
    }

    fn command_display(&self) -> String {
        let mut rendered = format_os(&self.program);
        for argument in &self.args {
            rendered.push(' ');
            rendered.push_str(&format_os(argument));
        }
        rendered
    }
}

fn bootstrap_command_plan(source: &Path, checkout: &Path) -> Vec<BootstrapCommand> {
    vec![
        BootstrapCommand::new(
            BootstrapRole::Enumerate,
            "enumerate tracked and nonignored untracked source files",
            source,
            "git",
            ["ls-files", "-co", "--exclude-standard", "-z"],
        ),
        BootstrapCommand::new(
            BootstrapRole::Init,
            "initialize an unrelated disposable repository",
            checkout,
            "git",
            ["init", "--quiet", "--initial-branch", "bootstrap-ci"],
        ),
        BootstrapCommand::new(
            BootstrapRole::ConfigureHooks,
            "configure an empty repository-local hooks directory",
            checkout,
            "git",
            [
                "config",
                "--local",
                "core.hooksPath",
                ".git/proofbound-empty-hooks",
            ],
        ),
        BootstrapCommand::new(
            BootstrapRole::ConfigureName,
            "configure the synthetic local author name",
            checkout,
            "git",
            ["config", "--local", "user.name", "Proofbound Bootstrap CI"],
        ),
        BootstrapCommand::new(
            BootstrapRole::ConfigureEmail,
            "configure the synthetic local author email",
            checkout,
            "git",
            [
                "config",
                "--local",
                "user.email",
                "proofbound-bootstrap-ci@invalid.local",
            ],
        ),
        BootstrapCommand::new(
            BootstrapRole::DisableSigning,
            "disable signing for the synthetic local commit",
            checkout,
            "git",
            ["config", "--local", "commit.gpgsign", "false"],
        ),
        BootstrapCommand::new(
            BootstrapRole::Add,
            "stage the complete copied source snapshot",
            checkout,
            "git",
            ["add", "--all"],
        ),
        BootstrapCommand::new(
            BootstrapRole::Commit,
            "create the sole explicitly non-evidentiary commit",
            checkout,
            "git",
            [
                "commit",
                "--quiet",
                "--no-verify",
                "--message",
                BOOTSTRAP_COMMIT_MESSAGE,
            ],
        ),
        BootstrapCommand::new(
            BootstrapRole::Ci,
            "run the complete project gate in the disposable repository",
            checkout,
            "just",
            ["ci"],
        ),
    ]
}

fn run_bootstrap_ci(source: &Path) -> Result<()> {
    let scratch = Builder::new()
        .prefix("proofbound-bootstrap-ci-")
        .tempdir()
        .context("could not create the disposable bootstrap repository directory")?;
    let checkout = scratch.path().join("checkout");
    let empty_git_config = scratch.path().join("empty-gitconfig");
    let empty_git_template = scratch.path().join("empty-git-template");
    fs::create_dir(&checkout).with_context(|| {
        format!(
            "could not create disposable checkout `{}`",
            checkout.display()
        )
    })?;
    File::create(&empty_git_config).with_context(|| {
        format!(
            "could not create isolated Git config `{}`",
            empty_git_config.display()
        )
    })?;
    fs::create_dir(&empty_git_template).with_context(|| {
        format!(
            "could not create isolated Git template directory `{}`",
            empty_git_template.display()
        )
    })?;

    let plan = bootstrap_command_plan(source, &checkout);
    println!("==> proofbound xtask :: bootstrap-ci source snapshot");
    println!("  -> 01 · {}", plan[0].label);
    io::stdout()
        .flush()
        .context("could not flush bootstrap-ci phase output")?;
    let paths = enumerate_source_files(&plan[0])?;
    copy_source_snapshot(source, &checkout, &paths)?;
    println!("     copied · {} source file(s)", paths.len());

    println!("==> proofbound xtask :: bootstrap-ci disposable repository");
    for (index, command) in plan.iter().enumerate().skip(1) {
        println!("  -> {index:02} · {}", command.label);
        io::stdout()
            .flush()
            .context("could not flush bootstrap-ci command output")?;
        execute_bootstrap_command(command, &checkout, &empty_git_config, &empty_git_template)?;
    }

    println!(
        "bootstrap-ci passed in a disposable repository; its test-only commit is not project history evidence"
    );
    Ok(())
}

fn enumerate_source_files(command: &BootstrapCommand) -> Result<Vec<PathBuf>> {
    if command.role != BootstrapRole::Enumerate {
        bail!("internal bootstrap error: source enumeration command has the wrong role");
    }
    let display = command.command_display();
    let output = Command::new(&command.program)
        .args(&command.args)
        .current_dir(&command.cwd)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .with_context(|| format!("could not start source enumeration `{display}`"))?;
    if !output.status.success() {
        bail!(
            "source enumeration failed with {}: `{display}`: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_source_listing(&output.stdout)
}

fn parse_source_listing(bytes: &[u8]) -> Result<Vec<PathBuf>> {
    if bytes.is_empty() {
        bail!("source enumeration returned no files");
    }
    if bytes.last() != Some(&0) {
        bail!("source enumeration was not terminated by NUL");
    }

    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for encoded in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        let encoded = std::str::from_utf8(encoded)
            .context("source enumeration contained a non-UTF-8 path")?;
        let path = validate_relative_source_path(encoded)?;
        if !seen.insert(path.clone()) {
            bail!(
                "source enumeration returned duplicate path `{}`",
                path.display()
            );
        }
        paths.push(path);
    }
    Ok(paths)
}

fn validate_relative_source_path(encoded: &str) -> Result<PathBuf> {
    if encoded.is_empty() {
        bail!("source enumeration contained an empty path");
    }
    if encoded.contains('\\') {
        bail!("source path `{encoded}` contains a noncanonical path separator");
    }
    if encoded.chars().any(char::is_control) {
        bail!("source path contains a control character");
    }

    let path = Path::new(encoded);
    if path.is_absolute() {
        bail!("source path `{encoded}` is absolute");
    }
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) if value != OsStr::new(".git") => {}
            std::path::Component::Normal(_) => {
                bail!("source path `{encoded}` crosses a Git metadata directory");
            }
            _ => bail!("source path `{encoded}` is not normalized and relative"),
        }
    }
    Ok(path.to_path_buf())
}

fn copy_source_snapshot(source: &Path, checkout: &Path, paths: &[PathBuf]) -> Result<()> {
    for relative in paths {
        let metadata = validate_listed_file(source, relative)?;
        let source_file = source.join(relative);
        let destination = checkout.join(relative);
        let parent = destination
            .parent()
            .context("copied source path has no parent")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "could not create copied source directory `{}`",
                parent.display()
            )
        })?;
        let bytes = fs::read(&source_file)
            .with_context(|| format!("could not read source file `{}`", source_file.display()))?;
        validate_listed_file(source, relative).with_context(|| {
            format!(
                "source file `{}` changed type while it was being copied",
                relative.display()
            )
        })?;
        fs::write(&destination, bytes).with_context(|| {
            format!(
                "could not write copied source file `{}`",
                destination.display()
            )
        })?;
        fs::set_permissions(&destination, metadata.permissions()).with_context(|| {
            format!(
                "could not preserve permissions for `{}`",
                destination.display()
            )
        })?;
    }
    Ok(())
}

fn validate_listed_file(root: &Path, relative: &Path) -> Result<fs::Metadata> {
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        bail!("source file path is empty");
    }

    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            bail!(
                "source path `{}` is not normalized and relative",
                relative.display()
            );
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "Git-listed source path `{}` does not exist",
                relative.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "Git-listed source path `{}` crosses symlink `{}`",
                relative.display(),
                current.display()
            );
        }
        if index + 1 == components.len() {
            if !metadata.is_file() {
                bail!(
                    "Git-listed source path `{}` is not a regular file",
                    relative.display()
                );
            }
            return Ok(metadata);
        }
        if !metadata.is_dir() {
            bail!(
                "Git-listed source path `{}` crosses non-directory `{}`",
                relative.display(),
                current.display()
            );
        }
    }
    unreachable!("nonempty component list returns from its final component")
}

fn execute_bootstrap_command(
    command: &BootstrapCommand,
    checkout: &Path,
    empty_git_config: &Path,
    empty_git_template: &Path,
) -> Result<()> {
    if command.role == BootstrapRole::ConfigureHooks {
        let hooks = command.cwd.join(".git/proofbound-empty-hooks");
        fs::create_dir(&hooks).with_context(|| {
            format!(
                "could not create repository-local empty hooks directory `{}`",
                hooks.display()
            )
        })?;
    }
    let display = command.command_display();
    let status = Command::new(&command.program)
        .args(&command.args)
        .current_dir(&command.cwd)
        .env("PATH", python_first_path(checkout)?)
        .env("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
        .env("CI", "true")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", empty_git_config)
        .env("GIT_TEMPLATE_DIR", empty_git_template)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .status()
        .with_context(|| format!("could not start bootstrap command `{display}`"))?;
    if !status.success() {
        bail!(
            "bootstrap command `{}` failed with {status}: `{display}`",
            command.label
        );
    }
    Ok(())
}

fn preflight_steps() -> Vec<ProcessStep> {
    vec![
        step(
            Phase::SyntaxPrecheck,
            "check workspace Rust formatting",
            "cargo",
            ["fmt", "--all", "--", "--check"],
        ),
        step(
            Phase::SyntaxPrecheck,
            "check artifact-checker template formatting",
            "cargo",
            [
                "fmt",
                "--manifest-path",
                "templates/artifact-checker/rust/Cargo.toml",
                "--",
                "--check",
            ],
        ),
        step(
            Phase::SyntaxPrecheck,
            "check refinement template formatting",
            "cargo",
            [
                "fmt",
                "--manifest-path",
                "templates/rust-aeneas-refinement/rust/Cargo.toml",
                "--",
                "--check",
            ],
        ),
        step(
            Phase::Environment,
            "synchronize the locked Python environment",
            "uv",
            ["sync", "--frozen"],
        ),
        step(
            Phase::Stage01,
            "validate the repository manifest and schema bundle",
            "cargo",
            [
                "test",
                "--locked",
                "-p",
                "proofbound-manifest",
                "--test",
                "repository_bundle",
            ],
        ),
        step(
            Phase::Stage02,
            "validate registered source closures",
            "cargo",
            [
                "test",
                "--locked",
                "-p",
                "proofbound-manifest",
                "--test",
                "repository_closures",
            ],
        ),
        step(
            Phase::Stage03,
            "build every workspace target",
            "cargo",
            ["build", "--workspace", "--all-targets", "--locked"],
        ),
        step(
            Phase::Stage03,
            "lint every workspace target",
            "cargo",
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ),
        step(
            Phase::Stage03,
            "lint the artifact-checker template",
            "cargo",
            [
                "clippy",
                "--manifest-path",
                "templates/artifact-checker/rust/Cargo.toml",
                "--locked",
                "--all-targets",
                "--target-dir",
                "target/template-artifact-checker",
                "--",
                "-D",
                "warnings",
            ],
        ),
        step(
            Phase::Stage03,
            "lint the refinement template",
            "cargo",
            [
                "clippy",
                "--manifest-path",
                "templates/rust-aeneas-refinement/rust/Cargo.toml",
                "--locked",
                "--all-targets",
                "--target-dir",
                "target/template-rust-aeneas",
                "--",
                "-D",
                "warnings",
            ],
        ),
        step(
            Phase::Stage03,
            "run workspace Rust tests",
            "cargo",
            ["test", "--workspace", "--locked"],
        ),
        step(
            Phase::Stage03,
            "test the artifact-checker template",
            "cargo",
            [
                "test",
                "--manifest-path",
                "templates/artifact-checker/rust/Cargo.toml",
                "--locked",
                "--target-dir",
                "target/template-artifact-checker",
            ],
        ),
        step(
            Phase::Stage03,
            "test the refinement template",
            "cargo",
            [
                "test",
                "--manifest-path",
                "templates/rust-aeneas-refinement/rust/Cargo.toml",
                "--locked",
                "--target-dir",
                "target/template-rust-aeneas",
            ],
        ),
        step(
            Phase::Stage04,
            "run locked Python and public-schema tests",
            "uv",
            ["run", "--frozen", "pytest", "-q"],
        ),
        step(Phase::Stage05, "build all Lean modules", "lake", ["build"]),
    ]
}

fn adapter_steps() -> Vec<ProcessStep> {
    vec![
        step(
            Phase::Stage03,
            "build workspace binaries",
            "cargo",
            ["build", "--workspace", "--locked", "--bins"],
        ),
        step(
            Phase::Stage03,
            "run adapter protocol tests",
            "cargo",
            [
                "test",
                "--locked",
                "-p",
                "proofbound-adapter-test",
                "-p",
                "proofbound-adapter-lean",
                "-p",
                "proofbound-adapter-kani",
                "-p",
                "proofbound-adapter-aeneas",
            ],
        ),
        ProcessStep::new(
            Phase::Stage05,
            Role::Ordinary,
            "audit compiled Lean declarations",
            "lake",
            [
                OsString::from("exe"),
                OsString::from("proofbound_lean_audit"),
                OsString::from("ProofboundDemo.Claims.Transfer"),
                OsString::from("ProofboundDemo.Claims.Canonical"),
                OsString::from("ProofboundDemo.Claims.Refinement"),
                OsString::from("ProofboundArtifactDemo.Claims"),
                OsString::from("--surface=ProofboundDemo.Claims.Transfer"),
                OsString::from("--surface=ProofboundDemo.Claims.Canonical"),
                OsString::from("--surface=ProofboundDemo.Claims.Refinement"),
                OsString::from("--surface=ProofboundArtifactDemo.Claims"),
            ],
        )
        .with_stdout_file(".proofbound/xtask/lean-audit.json"),
    ]
}

fn release_smoke_steps(root: &Path, scratch: &Path) -> Vec<ProcessStep> {
    let smoke_release = scratch.join("smoke-release");
    vec![
        step(
            Phase::ReleaseSmoke,
            "build release and verifier binaries",
            "cargo",
            ["build", "--workspace", "--locked", "--bins"],
        ),
        step(
            Phase::ReleaseSmoke,
            "run independent verifier conformance tests",
            "cargo",
            [
                "test",
                "--locked",
                "-p",
                "proofbound-verify",
                "--test",
                "conformance",
            ],
        ),
        ProcessStep::new(
            Phase::ReleaseSmoke,
            Role::ReleaseSmokeVerifier,
            "verify the committed conformance release",
            workspace_binary(root, "proofbound-verify"),
            [
                OsString::from("--release"),
                root.join("proofbound/conformance/v1/release-valid")
                    .into_os_string(),
            ],
        ),
        ProcessStep::new(
            Phase::ReleaseSmoke,
            Role::ReleaseSmokeConstruction,
            "construct a deterministic proof-free smoke release",
            workspace_binary(root, "proofbound"),
            [
                OsString::from("release-smoke"),
                OsString::from("--output"),
                smoke_release.clone().into_os_string(),
            ],
        ),
        ProcessStep::new(
            Phase::ReleaseSmoke,
            Role::ReleaseSmokeVerifier,
            "independently verify the constructed smoke release",
            workspace_binary(root, "proofbound-verify"),
            [OsString::from("--release"), smoke_release.into_os_string()],
        ),
    ]
}

fn ci_steps(root: &Path, scratch: &Path, diff: Option<&str>) -> Vec<ProcessStep> {
    let mut steps = preflight_steps();
    steps.extend(release_smoke_steps(root, scratch));
    steps.extend(adapter_steps());

    if let Some(range) = diff {
        steps.push(ProcessStep::new(
            Phase::ApprovalDiff,
            Role::ApprovalDiff,
            "enforce approvals for this exact base/head range",
            workspace_binary(root, "proofbound"),
            [
                OsString::from("diff"),
                OsString::from(range),
                OsString::from("--json"),
            ],
        ));
    }

    steps.push(ProcessStep::new(
        Phase::Stages06To09,
        Role::FreshCheck,
        "compile the complete assurance graph exactly once",
        workspace_binary(root, "proofbound"),
        [OsString::from("check"), OsString::from("--fresh")],
    ));

    steps.push(ProcessStep::new(
        Phase::Stage10,
        Role::Ordinary,
        "verify the allowance demo end to end",
        workspace_binary(root, "proofbound"),
        [OsString::from("demo"), OsString::from("allowance")],
    ));
    steps.push(ProcessStep::new(
        Phase::Stage10,
        Role::Ordinary,
        "verify the artifact-certificate demo end to end",
        workspace_binary(root, "proofbound"),
        [
            OsString::from("demo"),
            OsString::from("artifact-certificate"),
        ],
    ));

    let current_release = scratch.join("current-release");
    steps.push(ProcessStep::new(
        Phase::Stage11,
        Role::CurrentRelease,
        "release the receipts from the immediately preceding fresh check",
        workspace_binary(root, "proofbound"),
        [
            OsString::from("release"),
            OsString::from("--output"),
            current_release.clone().into_os_string(),
        ],
    ));
    steps.push(ProcessStep::new(
        Phase::Stage12,
        Role::FinalVerifier,
        "produce the final verdict with the standalone verifier",
        workspace_binary(root, "proofbound-verify"),
        [
            OsString::from("--release"),
            current_release.into_os_string(),
        ],
    ));
    steps
}

fn step<const N: usize>(
    phase: Phase,
    label: &'static str,
    program: &'static str,
    args: [&'static str; N],
) -> ProcessStep {
    ProcessStep::new(phase, Role::Ordinary, label, program, args)
}

fn workspace_binary(root: &Path, name: &str) -> PathBuf {
    root.join("target")
        .join("debug")
        .join(format!("{name}{}", env::consts::EXE_SUFFIX))
}

fn execute(root: &Path, steps: &[ProcessStep]) -> Result<()> {
    let path = python_first_path(root)?;
    let mut active_phase = None;
    let mut phase_step = 0usize;

    for process in steps {
        if active_phase != Some(process.phase) {
            active_phase = Some(process.phase);
            phase_step = 0;
            for banner in process.phase.banners() {
                println!("==> proofbound xtask :: {banner}");
            }
        }
        phase_step += 1;
        println!("  -> {phase_step:02} · {}", process.label);
        io::stdout()
            .flush()
            .context("could not flush xtask phase output")?;

        let display = process.command_display();
        let mut command = Command::new(&process.program);
        command
            .args(&process.args)
            .current_dir(root)
            .env("PATH", &path)
            .env("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1");
        if let Some(output) = &process.stdout_file {
            let output = root.join(output);
            let parent = output.parent().context("xtask output path has no parent")?;
            fs::create_dir_all(parent).with_context(|| {
                format!("could not create output directory `{}`", parent.display())
            })?;
            let file = File::create(&output)
                .with_context(|| format!("could not create `{}`", output.display()))?;
            command.stdout(Stdio::from(file));
        }
        let status = command.status().with_context(|| {
            format!(
                "{} / {}: could not start `{display}`",
                process.phase.context(),
                process.label
            )
        })?;

        if !status.success() {
            bail!(
                "{} / {} failed with {status}: `{display}`",
                process.phase.context(),
                process.label
            );
        }
        if let Some(output) = &process.stdout_file {
            println!("     output · {}", output.display());
        }
    }
    Ok(())
}

fn python_first_path(root: &Path) -> Result<OsString> {
    let mut entries = vec![root.join(".venv").join("bin")];
    if let Some(existing) = env::var_os("PATH") {
        entries.extend(env::split_paths(&existing));
    }
    env::join_paths(entries).context("could not construct PATH with .venv/bin first")
}

fn format_os(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_=./:".contains(&byte))
    {
        value.into_owned()
    } else {
        let mut rendered = String::from("\"");
        for character in value.chars() {
            match character {
                '\\' => rendered.push_str("\\\\"),
                '"' => rendered.push_str("\\\""),
                _ => rendered.push(character),
            }
        }
        rendered.push('"');
        rendered
    }
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString, fs};

    use super::*;

    #[test]
    fn ci_runs_release_smoke_before_one_fresh_check_and_verifier_last() {
        let root = Path::new("/checkout/proof-bound");
        let scratch = Path::new("/tmp/xtask-test");
        let plan = ci_steps(root, scratch, None);

        let smoke = position(&plan, Role::ReleaseSmokeConstruction);
        let fresh = position(&plan, Role::FreshCheck);
        assert!(
            smoke < fresh,
            "the cheap release round-trip must precede Kani"
        );
        assert_eq!(
            plan.iter()
                .filter(|step| step.role == Role::FreshCheck)
                .count(),
            1,
            "the expensive fresh graph must be compiled exactly once"
        );
        assert_eq!(plan.last().map(|step| step.role), Some(Role::FinalVerifier));
        assert!(
            Path::new(&plan.last().unwrap().program).ends_with("target/debug/proofbound-verify")
        );
    }

    #[test]
    fn ci_places_the_exact_optional_diff_before_the_fresh_check() {
        let plan = ci_steps(
            Path::new("/checkout/proof-bound"),
            Path::new("/tmp/xtask-test"),
            Some("base-revision..head-revision"),
        );
        let diff = position(&plan, Role::ApprovalDiff);
        let fresh = position(&plan, Role::FreshCheck);

        assert!(position(&plan, Role::ReleaseSmokeConstruction) < diff);
        assert!(diff < fresh);
        assert_eq!(
            plan[diff].args,
            ["diff", "base-revision..head-revision", "--json"]
                .map(OsString::from)
                .to_vec()
        );
    }

    #[test]
    fn ci_plan_exposes_all_twelve_normative_stage_banners() {
        let plan = ci_steps(
            Path::new("/checkout/proof-bound"),
            Path::new("/tmp/xtask-test"),
            None,
        );
        let banners = plan
            .iter()
            .flat_map(|step| step.phase.banners())
            .copied()
            .collect::<Vec<_>>();

        for number in 1..=12 {
            let marker = format!("stage {number}/12");
            assert!(
                banners.iter().any(|banner| banner.contains(&marker)),
                "missing §18 {marker} banner"
            );
        }
    }

    #[test]
    fn preflight_contains_no_fresh_check_or_proof_tool_invocation() {
        let plan = preflight_steps();
        assert!(plan.iter().all(|step| step.role == Role::Ordinary));
        let rendered = plan
            .iter()
            .map(ProcessStep::command_display)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!rendered.contains("check --fresh"));
        assert!(!rendered.contains("cargo kani"));
        assert!(!rendered.contains(" reproduce "));
        assert!(rendered.contains("uv sync --frozen"));
        assert!(rendered.contains("cargo clippy --workspace --all-targets --locked"));
        assert!(rendered.contains("cargo test --workspace --locked"));
        assert!(rendered.contains("uv run --frozen pytest -q"));
        assert!(rendered.contains("lake build"));
    }

    #[test]
    fn release_smoke_constructs_then_uses_the_independent_verifier() {
        let root = Path::new("/checkout/proof-bound");
        let scratch = Path::new("/tmp/xtask-test");
        let plan = release_smoke_steps(root, scratch);
        let construction = position(&plan, Role::ReleaseSmokeConstruction);
        let verifiers = plan
            .iter()
            .enumerate()
            .filter(|(_, step)| step.role == Role::ReleaseSmokeVerifier)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        assert_eq!(verifiers.len(), 2);
        assert!(verifiers[0] < construction);
        assert!(construction < verifiers[1]);
        assert_eq!(plan[construction].args[0], OsString::from("release-smoke"));
        assert!(
            plan[verifiers[0]]
                .args
                .iter()
                .any(|arg| Path::new(arg).ends_with("proofbound/conformance/v1/release-valid"))
        );
    }

    #[test]
    fn lean_audit_is_captured_under_generated_state_without_a_shell() {
        let plan = adapter_steps();
        let audit = plan
            .iter()
            .find(|step| step.label == "audit compiled Lean declarations")
            .unwrap();

        assert_eq!(
            audit.stdout_file.as_deref(),
            Some(Path::new(".proofbound/xtask/lean-audit.json"))
        );
        assert_eq!(audit.program, "lake");
        assert_eq!(audit.args[0], "exe");
    }

    #[test]
    fn bootstrap_plan_has_one_non_evidentiary_commit_and_ci_is_last() {
        let plan = bootstrap_command_plan(
            Path::new("/checkout/proof-bound"),
            Path::new("/tmp/bootstrap-copy"),
        );
        let roles = plan.iter().map(|command| command.role).collect::<Vec<_>>();
        assert_eq!(
            roles,
            vec![
                BootstrapRole::Enumerate,
                BootstrapRole::Init,
                BootstrapRole::ConfigureHooks,
                BootstrapRole::ConfigureName,
                BootstrapRole::ConfigureEmail,
                BootstrapRole::DisableSigning,
                BootstrapRole::Add,
                BootstrapRole::Commit,
                BootstrapRole::Ci,
            ]
        );
        assert_eq!(
            plan[0].args,
            ["ls-files", "-co", "--exclude-standard", "-z"]
                .map(OsString::from)
                .to_vec()
        );
        let commits = plan
            .iter()
            .filter(|command| command.role == BootstrapRole::Commit)
            .collect::<Vec<_>>();
        assert_eq!(commits.len(), 1);
        assert!(
            commits[0].args.iter().any(|arg| {
                arg == "TEST-ONLY bootstrap CI snapshot; NO PROJECT HISTORY EVIDENCE"
            })
        );
        let last = plan.last().unwrap();
        assert_eq!(last.role, BootstrapRole::Ci);
        assert_eq!(last.program, "just");
        assert_eq!(last.args, [OsString::from("ci")]);
        assert!(plan.iter().all(|command| command.program != "sh"));
        assert!(plan.iter().all(|command| command.program != "bash"));
    }

    #[test]
    fn bootstrap_path_parser_rejects_unsafe_and_ambiguous_paths() {
        for path in [
            "",
            "../escape",
            "./ambiguous",
            "/absolute",
            ".git/config",
            "nested/.git/config",
            "windows\\separator",
            "line\nbreak",
        ] {
            assert!(
                validate_relative_source_path(path).is_err(),
                "unsafe path unexpectedly accepted: {path:?}"
            );
        }
        assert!(parse_source_listing(b"not-nul-terminated").is_err());
        assert!(parse_source_listing(b"same\0same\0").is_err());
        assert!(parse_source_listing(&[0xff, 0]).is_err());
    }

    #[test]
    fn bootstrap_git_listing_excludes_ignored_untracked_files_but_keeps_cached_files() {
        let repository = Builder::new()
            .prefix("proofbound-bootstrap-list-test-")
            .tempdir()
            .unwrap();
        git_ok(repository.path(), ["init", "--quiet"]);
        fs::write(repository.path().join(".gitignore"), "ignored/\n").unwrap();
        fs::write(repository.path().join("visible-source.txt"), "visible").unwrap();
        fs::create_dir(repository.path().join("ignored")).unwrap();
        fs::write(
            repository.path().join("ignored/untracked.txt"),
            "must not be copied",
        )
        .unwrap();
        fs::write(
            repository.path().join("ignored/cached.txt"),
            "cached files remain source",
        )
        .unwrap();
        git_ok(repository.path(), ["add", "--force", "ignored/cached.txt"]);

        let plan = bootstrap_command_plan(repository.path(), Path::new("/tmp/unused"));
        let paths = enumerate_source_files(&plan[0])
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert!(paths.contains(Path::new(".gitignore")));
        assert!(paths.contains(Path::new("visible-source.txt")));
        assert!(paths.contains(Path::new("ignored/cached.txt")));
        assert!(!paths.contains(Path::new("ignored/untracked.txt")));
    }

    #[test]
    fn bootstrap_copy_preserves_nested_bytes_and_rejects_non_files() {
        let source = Builder::new()
            .prefix("proofbound-bootstrap-copy-source-")
            .tempdir()
            .unwrap();
        let destination = Builder::new()
            .prefix("proofbound-bootstrap-copy-destination-")
            .tempdir()
            .unwrap();
        fs::create_dir(source.path().join("nested")).unwrap();
        fs::write(source.path().join("nested/data.bin"), [0, 1, 0xfe, 0xff]).unwrap();
        copy_source_snapshot(
            source.path(),
            destination.path(),
            &[PathBuf::from("nested/data.bin")],
        )
        .unwrap();
        assert_eq!(
            fs::read(destination.path().join("nested/data.bin")).unwrap(),
            [0, 1, 0xfe, 0xff]
        );
        assert!(validate_listed_file(source.path(), Path::new("nested")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_copy_rejects_symlink_files_and_ancestors() {
        use std::os::unix::fs::symlink;

        let source = Builder::new()
            .prefix("proofbound-bootstrap-symlink-test-")
            .tempdir()
            .unwrap();
        fs::write(source.path().join("real.txt"), "real").unwrap();
        symlink("real.txt", source.path().join("link.txt")).unwrap();
        assert!(validate_listed_file(source.path(), Path::new("link.txt")).is_err());

        fs::create_dir(source.path().join("real-dir")).unwrap();
        fs::write(source.path().join("real-dir/file.txt"), "real").unwrap();
        symlink("real-dir", source.path().join("linked-dir")).unwrap();
        assert!(validate_listed_file(source.path(), Path::new("linked-dir/file.txt")).is_err());
    }

    #[test]
    fn repository_discovery_walks_up_from_a_file() {
        let fixture = Builder::new()
            .prefix("proofbound-xtask-root-test-")
            .tempdir()
            .unwrap();
        fs::write(fixture.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(fixture.path().join("proofbound.toml"), "[project]\n").unwrap();
        fs::write(fixture.path().join("justfile"), "ci:\n").unwrap();
        fs::create_dir_all(fixture.path().join("a/b")).unwrap();
        let file = fixture.path().join("a/b/file.rs");
        fs::write(&file, "").unwrap();

        assert_eq!(
            discover_repo_root(&file).unwrap(),
            fixture.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn python_environment_directory_is_the_first_path_entry() {
        let root = Path::new("/checkout/proof-bound");
        let joined = python_first_path(root).unwrap();
        let first = env::split_paths(&joined).next().unwrap();
        assert_eq!(first, root.join(".venv/bin"));
    }

    fn position(plan: &[ProcessStep], role: Role) -> usize {
        plan.iter()
            .position(|step| step.role == role)
            .unwrap_or_else(|| panic!("missing role {role:?}"))
    }

    fn git_ok<const N: usize>(directory: &Path, args: [&str; N]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(directory)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
