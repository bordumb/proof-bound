use std::{collections::BTreeMap, fs, path::Path, process::Command};

use anyhow::{Context, Result};
use proofbound_manifest::{AdapterKind, ProjectBundle, ResourceBudget};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize)]
struct ToolProbe {
    tool: &'static str,
    available: bool,
    identity: String,
}

#[derive(Clone, Serialize)]
struct CapabilityProbe {
    capability: String,
    available: bool,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct CapacityProbe {
    bytes: Option<u64>,
    method: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct HostCapacity {
    disk_available: CapacityProbe,
    memory_capacity: CapacityProbe,
}

#[derive(Serialize)]
struct UnitAffordability {
    manifest_kind: &'static str,
    unit: String,
    required_capabilities: Vec<String>,
    declared_time_seconds: u64,
    declared_disk_bytes: u64,
    declared_memory_bytes: u64,
    runnable_here: bool,
    reason: String,
}

#[derive(Serialize)]
struct DoctorReport {
    schema: &'static str,
    tools: Vec<ToolProbe>,
    capabilities: Vec<CapabilityProbe>,
    host_capacity: HostCapacity,
    units: Vec<UnitAffordability>,
}

#[derive(Clone)]
struct UnitRequirement {
    manifest_kind: &'static str,
    id: String,
    budget: ResourceBudget,
    capabilities: Vec<&'static str>,
}

pub fn doctor(root: &Path, json: bool) -> Result<()> {
    let bundle = ProjectBundle::load(root).context("manifest validation failed")?;
    let tools = vec![
        probe("git", "git", &["--version"]),
        probe("rustc", "rustc", &["--version"]),
        probe("cargo", "cargo", &["--version"]),
        probe("lean", "lean", &["--version"]),
        probe("lake", "lake", &["--version"]),
        probe("python3", "python3", &["--version"]),
        // Kani is a Cargo subcommand; there is intentionally no `kani`
        // executable in a standard installation.
        probe("kani", "cargo", &["kani", "--version"]),
        probe("charon", "charon", &["--version"]),
        probe("aeneas", "aeneas", &["--version"]),
    ];
    let capabilities = vec![translation_lock_capability(root, &bundle, &tools)];
    let host_capacity = HostCapacity {
        disk_available: probe_disk_available(root),
        memory_capacity: probe_memory_capacity(),
    };
    let units = collect_requirements(&bundle)
        .into_iter()
        .map(|requirement| assess_unit(requirement, &tools, &capabilities, &host_capacity))
        .collect();
    let report = DoctorReport {
        schema: "proofbound-doctor/1",
        tools,
        capabilities,
        host_capacity,
        units,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Proofbound doctor");
        for tool in &report.tools {
            let marker = if tool.available { "ok" } else { "missing" };
            println!("  {marker:7} {:12} {}", tool.tool, tool.identity);
        }
        for capability in &report.capabilities {
            let marker = if capability.available {
                "ok"
            } else {
                "missing"
            };
            println!(
                "  {marker:7} {:28} {}",
                capability.capability, capability.detail
            );
        }
        println!("Host capacity");
        print_capacity("disk available", &report.host_capacity.disk_available);
        print_capacity("memory capacity", &report.host_capacity.memory_capacity);
        println!("Unit affordability");
        for unit in &report.units {
            let marker = if unit.runnable_here {
                "ready"
            } else {
                "blocked"
            };
            println!(
                "  {marker:7} {:11} {:30} {:>5}s  {}",
                unit.manifest_kind, unit.unit, unit.declared_time_seconds, unit.reason
            );
        }
    }
    Ok(())
}

fn collect_requirements(bundle: &ProjectBundle) -> Vec<UnitRequirement> {
    let mut requirements = Vec::new();
    for (_, unit) in bundle.evidence_units.values() {
        let capabilities = match unit.adapter {
            AdapterKind::Lean => vec!["lean", "lake"],
            AdapterKind::CharonAeneas => {
                vec!["cargo", "charon", "aeneas", "translation-toolchain-lock"]
            }
            AdapterKind::Kani => vec!["cargo", "kani"],
            AdapterKind::PythonTest
            | AdapterKind::CanonicalArtifact
            | AdapterKind::IndependentCheck => vec!["python3"],
            AdapterKind::RustTest => vec!["cargo", "rustc"],
            AdapterKind::SourceClosure | AdapterKind::HumanReview => vec!["git"],
        };
        requirements.push(UnitRequirement {
            manifest_kind: "evidence",
            id: unit.id.clone(),
            budget: unit.resource_budget,
            capabilities,
        });
    }
    for (_, unit) in bundle.translation_units.values() {
        requirements.push(UnitRequirement {
            manifest_kind: "translation",
            id: unit.id.clone(),
            budget: unit.resource_budget,
            capabilities: vec!["cargo", "charon", "aeneas", "translation-toolchain-lock"],
        });
    }
    for (_, unit) in bundle.model_check_units.values() {
        requirements.push(UnitRequirement {
            manifest_kind: "model-check",
            id: unit.id.clone(),
            budget: unit.resource_budget,
            capabilities: vec!["cargo", "kani"],
        });
    }
    requirements.sort_by(|left, right| {
        (left.manifest_kind, &left.id).cmp(&(right.manifest_kind, &right.id))
    });
    requirements
}

fn assess_unit(
    requirement: UnitRequirement,
    tools: &[ToolProbe],
    capabilities: &[CapabilityProbe],
    host: &HostCapacity,
) -> UnitAffordability {
    let tool_availability = tools
        .iter()
        .map(|probe| (probe.tool, probe.available))
        .collect::<BTreeMap<_, _>>();
    let capability_availability = capabilities
        .iter()
        .map(|probe| (probe.capability.as_str(), probe.available))
        .collect::<BTreeMap<_, _>>();
    let mut blockers = Vec::new();
    for capability in &requirement.capabilities {
        let available = tool_availability
            .get(capability)
            .copied()
            .or_else(|| capability_availability.get(capability).copied())
            .unwrap_or(false);
        if !available {
            blockers.push(format!("required capability '{capability}' is unavailable"));
        }
    }
    compare_capacity(
        "disk",
        requirement.budget.disk_bytes,
        &host.disk_available,
        &mut blockers,
    );
    compare_capacity(
        "memory",
        requirement.budget.memory_bytes,
        &host.memory_capacity,
        &mut blockers,
    );
    let runnable_here = blockers.is_empty();
    UnitAffordability {
        manifest_kind: requirement.manifest_kind,
        unit: requirement.id,
        required_capabilities: requirement
            .capabilities
            .into_iter()
            .map(str::to_owned)
            .collect(),
        declared_time_seconds: requirement.budget.time_seconds,
        declared_disk_bytes: requirement.budget.disk_bytes,
        declared_memory_bytes: requirement.budget.memory_bytes,
        runnable_here,
        reason: if runnable_here {
            "required capabilities and declared disk/memory budgets fit this host".to_owned()
        } else {
            blockers.join("; ")
        },
    }
}

fn compare_capacity(
    label: &str,
    required: u64,
    capacity: &CapacityProbe,
    blockers: &mut Vec<String>,
) {
    match capacity.bytes {
        Some(bytes) if required <= bytes => {}
        Some(bytes) => blockers.push(format!(
            "declared {label} budget {required} bytes exceeds probed host capacity {bytes} bytes"
        )),
        None => blockers.push(format!(
            "host {label} capacity is unknown ({})",
            capacity.detail
        )),
    }
}

fn print_capacity(label: &str, probe: &CapacityProbe) {
    match probe.bytes {
        Some(bytes) => println!("  {label:16} {bytes:>14} bytes via {}", probe.method),
        None => println!("  {label:16} unknown ({})", probe.detail),
    }
}

fn probe(tool: &'static str, program: &str, args: &[&str]) -> ToolProbe {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            ToolProbe {
                tool,
                available: true,
                identity: truncate(if stdout.is_empty() { stderr } else { stdout }),
            }
        }
        Ok(output) => ToolProbe {
            tool,
            available: false,
            identity: truncate(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
        },
        Err(error) => ToolProbe {
            tool,
            available: false,
            identity: error.to_string(),
        },
    }
}

fn truncate(value: String) -> String {
    value.chars().take(2048).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranslationToolchainLock {
    schema: String,
    charon_revision: String,
    aeneas_revision: String,
    rust_toolchain: String,
    lean_toolchain: String,
}

fn translation_lock_capability(
    root: &Path,
    bundle: &ProjectBundle,
    tools: &[ToolProbe],
) -> CapabilityProbe {
    let failure = |detail: String| CapabilityProbe {
        capability: "translation-toolchain-lock".to_owned(),
        available: false,
        detail,
    };
    let Some(relative) = bundle.project.toolchains.translation.as_deref() else {
        return failure("no translation toolchain lock is configured".to_owned());
    };
    let path = root.join(relative);
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return failure(format!("{} is a symlink", path.display()));
    }
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return failure(format!("cannot read {}: {error}", path.display())),
    };
    let lock: TranslationToolchainLock = match toml::from_str(&text) {
        Ok(lock) => lock,
        Err(error) => return failure(format!("invalid strict lock manifest: {error}")),
    };
    if lock.schema != "proofbound-translation-toolchain/1" {
        return failure(format!("unsupported lock schema '{}'", lock.schema));
    }
    for (name, pin) in [
        ("Charon", lock.charon_revision.as_str()),
        ("Aeneas", lock.aeneas_revision.as_str()),
    ] {
        if !concrete_revision(pin) {
            return failure(format!("{name} revision '{pin}' is not a concrete pin"));
        }
    }
    for (tool, pin) in [
        ("charon", lock.charon_revision.as_str()),
        ("aeneas", lock.aeneas_revision.as_str()),
    ] {
        let Some(identity) = tools
            .iter()
            .find(|probe| probe.tool == tool && probe.available)
            .map(|probe| probe.identity.as_str())
        else {
            return failure(format!("{tool} is unavailable"));
        };
        if !identity.contains(pin) {
            return failure(format!(
                "{tool} identity does not contain pinned revision '{pin}'"
            ));
        }
    }
    let rust_path = bundle
        .project
        .toolchains
        .rust
        .as_deref()
        .unwrap_or("rust-toolchain.toml");
    let actual_rust = read_rust_toolchain(&root.join(rust_path));
    if actual_rust.as_deref() != Some(lock.rust_toolchain.as_str()) {
        return failure(format!(
            "Rust toolchain pin '{}' does not match {}",
            lock.rust_toolchain, rust_path
        ));
    }
    let lean_path = bundle
        .project
        .toolchains
        .lean
        .as_deref()
        .unwrap_or("lean-toolchain");
    let actual_lean = fs::read_to_string(root.join(lean_path))
        .ok()
        .map(|value| value.trim().to_owned());
    if actual_lean.as_deref() != Some(lock.lean_toolchain.as_str()) {
        return failure(format!(
            "Lean toolchain pin '{}' does not match {}",
            lock.lean_toolchain, lean_path
        ));
    }
    CapabilityProbe {
        capability: "translation-toolchain-lock".to_owned(),
        available: true,
        detail: format!(
            "Charon {} and Aeneas {} match the declared Rust/Lean toolchains",
            lock.charon_revision, lock.aeneas_revision
        ),
    }
}

fn concrete_revision(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with("unavailable")
        && value.chars().all(|character| {
            character.is_ascii_hexdigit() || matches!(character, '.' | '-' | '_' | 'v')
        })
}

fn read_rust_toolchain(path: &Path) -> Option<String> {
    let value: toml::Value = fs::read_to_string(path).ok()?.parse().ok()?;
    value
        .get("toolchain")?
        .get("channel")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(unix)]
fn probe_disk_available(root: &Path) -> CapacityProbe {
    let output = Command::new("df").args(["-Pk"]).arg(root).output();
    match output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            match parse_df_available_bytes(&text) {
                Some(bytes) => CapacityProbe {
                    bytes: Some(bytes),
                    method: "df -Pk",
                    detail: "available bytes on the project filesystem".to_owned(),
                },
                None => unknown_capacity("df -Pk", "df output could not be parsed"),
            }
        }
        Ok(output) => unknown_capacity(
            "df -Pk",
            &format!(
                "df failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ),
        Err(error) => unknown_capacity("df -Pk", &format!("could not execute df: {error}")),
    }
}

#[cfg(windows)]
fn probe_disk_available(root: &Path) -> CapacityProbe {
    let script = "$p=$args[0]; $d=[IO.Path]::GetPathRoot($p).TrimEnd('\\').TrimEnd(':'); (Get-PSDrive -Name $d).Free";
    probe_powershell_bytes(
        script,
        root.to_string_lossy().as_ref(),
        "PowerShell Get-PSDrive",
    )
}

#[cfg(not(any(unix, windows)))]
fn probe_disk_available(_root: &Path) -> CapacityProbe {
    unknown_capacity(
        "unsupported-platform",
        "no disk-capacity probe for this platform",
    )
}

#[cfg(target_os = "linux")]
fn probe_memory_capacity() -> CapacityProbe {
    match fs::read_to_string("/proc/meminfo") {
        Ok(text) => match parse_linux_memory_bytes(&text) {
            Some(bytes) => CapacityProbe {
                bytes: Some(bytes),
                method: "/proc/meminfo MemTotal",
                detail: "total physical memory".to_owned(),
            },
            None => unknown_capacity("/proc/meminfo", "MemTotal could not be parsed"),
        },
        Err(error) => unknown_capacity("/proc/meminfo", &format!("cannot read: {error}")),
    }
}

#[cfg(target_os = "macos")]
fn probe_memory_capacity() -> CapacityProbe {
    let sysctl = probe_command_bytes("sysctl", &["-n", "hw.memsize"], "sysctl hw.memsize");
    if sysctl.bytes.is_some() {
        return sysctl;
    }
    match Command::new("hostinfo").output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            match parse_hostinfo_memory_bytes(&text) {
                Some(bytes) => CapacityProbe {
                    bytes: Some(bytes),
                    method: "hostinfo",
                    detail: "total physical memory".to_owned(),
                },
                None => unknown_capacity(
                    "sysctl/hostinfo",
                    "sysctl failed and hostinfo output could not be parsed",
                ),
            }
        }
        Ok(output) => unknown_capacity(
            "sysctl/hostinfo",
            &format!(
                "sysctl failed and hostinfo failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ),
        Err(error) => unknown_capacity(
            "sysctl/hostinfo",
            &format!("sysctl failed and hostinfo could not execute: {error}"),
        ),
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn probe_memory_capacity() -> CapacityProbe {
    probe_command_bytes("sysctl", &["-n", "hw.physmem"], "sysctl hw.physmem")
}

#[cfg(windows)]
fn probe_memory_capacity() -> CapacityProbe {
    let script = "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize * 1KB";
    probe_powershell_bytes(script, "", "PowerShell CIM physical memory")
}

#[cfg(not(any(unix, windows)))]
fn probe_memory_capacity() -> CapacityProbe {
    unknown_capacity(
        "unsupported-platform",
        "no physical-memory probe for this platform",
    )
}

#[cfg(any(
    target_os = "macos",
    all(unix, not(any(target_os = "linux", target_os = "macos")))
))]
fn probe_command_bytes(program: &str, args: &[&str], method: &'static str) -> CapacityProbe {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            match String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u64>()
            {
                Ok(bytes) if bytes > 0 => CapacityProbe {
                    bytes: Some(bytes),
                    method,
                    detail: "total physical memory".to_owned(),
                },
                _ => unknown_capacity(method, "capacity output was not a positive integer"),
            }
        }
        Ok(output) => unknown_capacity(
            method,
            &format!(
                "capacity probe failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ),
        Err(error) => unknown_capacity(method, &format!("capacity probe failed: {error}")),
    }
}

#[cfg(windows)]
fn probe_powershell_bytes(script: &str, argument: &str, method: &'static str) -> CapacityProbe {
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    if !argument.is_empty() {
        command.arg(argument);
    }
    match command.output() {
        Ok(output) if output.status.success() => {
            match String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u64>()
            {
                Ok(bytes) if bytes > 0 => CapacityProbe {
                    bytes: Some(bytes),
                    method,
                    detail: "host capacity".to_owned(),
                },
                _ => unknown_capacity(method, "capacity output was not a positive integer"),
            }
        }
        Ok(output) => unknown_capacity(
            method,
            &format!(
                "capacity probe failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ),
        Err(error) => unknown_capacity(method, &format!("capacity probe failed: {error}")),
    }
}

fn parse_df_available_bytes(text: &str) -> Option<u64> {
    let line = text.lines().rfind(|line| !line.trim().is_empty())?;
    line.split_whitespace()
        .nth(3)?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

#[cfg(target_os = "macos")]
fn parse_hostinfo_memory_bytes(text: &str) -> Option<u64> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("Primary memory available:"))?;
    let mut fields = line.split_whitespace();
    let value = fields.nth(3)?.parse::<f64>().ok()?;
    let unit = fields.next()?;
    let multiplier = match unit {
        "bytes" => 1_f64,
        "kilobytes" => 1024_f64,
        "megabytes" => 1024_f64.powi(2),
        "gigabytes" => 1024_f64.powi(3),
        "terabytes" => 1024_f64.powi(4),
        _ => return None,
    };
    let bytes = value * multiplier;
    (bytes.is_finite() && bytes > 0_f64 && bytes <= u64::MAX as f64).then_some(bytes as u64)
}

#[cfg(target_os = "linux")]
fn parse_linux_memory_bytes(text: &str) -> Option<u64> {
    let kibibytes = text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    kibibytes.checked_mul(1024)
}

fn unknown_capacity(method: &'static str, detail: &str) -> CapacityProbe {
    CapacityProbe {
        bytes: None,
        method,
        detail: truncate(detail.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_posix_disk_capacity() {
        let output = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk 1000 250 750 25% /tmp\n";
        assert_eq!(parse_df_available_bytes(output), Some(750 * 1024));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_hostinfo_physical_memory() {
        assert_eq!(
            parse_hostinfo_memory_bytes("Primary memory available: 64.00 gigabytes\n"),
            Some(64 * 1024 * 1024 * 1024)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_physical_memory_capacity() {
        assert_eq!(
            parse_linux_memory_bytes("MemTotal:       16384 kB\nMemFree: 1 kB\n"),
            Some(16_384 * 1024)
        );
    }

    #[test]
    fn unknown_or_insufficient_capacity_fails_closed() {
        let requirement = UnitRequirement {
            manifest_kind: "translation",
            id: "unit".to_owned(),
            budget: ResourceBudget {
                time_seconds: 1,
                disk_bytes: 101,
                memory_bytes: 1,
            },
            capabilities: vec!["cargo"],
        };
        let tools = [ToolProbe {
            tool: "cargo",
            available: true,
            identity: "cargo test".to_owned(),
        }];
        let host = HostCapacity {
            disk_available: CapacityProbe {
                bytes: Some(100),
                method: "test",
                detail: String::new(),
            },
            memory_capacity: unknown_capacity("test", "probe unavailable"),
        };
        let result = assess_unit(requirement, &tools, &[], &host);
        assert!(!result.runnable_here);
        assert!(result.reason.contains("exceeds probed host capacity"));
        assert!(result.reason.contains("memory capacity is unknown"));
    }
}
