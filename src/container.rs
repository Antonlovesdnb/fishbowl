use std::env;
use std::ffi::OsString;
use std::fmt::{self, Display};
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use include_dir::{Dir, include_dir};
use serde_json::{Map, Value, json};

/// Container build assets (Dockerfile + watchers + entrypoint scripts) embedded
/// at compile time so prebuilt binaries are self-contained. Extracted to a
/// per-version cache dir on first use.
static CONTAINER_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/container");

use crate::agent_runtime;
use crate::discovery::{HostScanReport, scan_host_credentials};
use crate::ebpf::utc_now_iso;
use crate::monitor::{
    MonitorMode, MonitoringRequest, monitoring_request_for_mode, run_with_monitoring,
    select_monitoring_backend,
};

const AGENTFENCE_CONTAINER_HOME: &str = "/agentfence/home";
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Agent {
    Shell,
    Codex,
    ClaudeCode,
    Cursor,
    Windsurf,
    Copilot,
}

impl Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Agent::Shell => "shell",
            Agent::Codex => "codex",
            Agent::ClaudeCode => "claude-code",
            Agent::Cursor => "cursor",
            Agent::Windsurf => "windsurf",
            Agent::Copilot => "copilot",
        };

        f.write_str(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum NetworkMode {
    Bridge,
    Host,
}

impl Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            NetworkMode::Bridge => "bridge",
            NetworkMode::Host => "host",
        };

        f.write_str(value)
    }
}

#[derive(Debug)]
pub struct RunOptions {
    pub project_dir: PathBuf,
    pub image: String,
    pub build_image: bool,
    pub agent: Option<Agent>,
    pub ssh_mounts: Vec<PathBuf>,
    pub cred_mounts: Vec<PathBuf>,
    pub env_vars: Vec<String>,
    pub container_name: Option<String>,
    pub logs_dir: Option<PathBuf>,
    pub network_mode: NetworkMode,
    pub monitor: MonitorMode,
    pub ebpf_exec: bool,
    pub ebpf_net: bool,
    pub ebpf_file: bool,
    pub command: Vec<String>,
}

pub fn build_image(image: &str) -> Result<()> {
    check_docker_available()?;
    let container_dir = container_dir()?;

    println!(
        "[AgentFence] Building images for host architecture: {} (images are platform-specific; rebuild after cloning to a different host).",
        std::env::consts::ARCH
    );

    let status = Command::new("docker")
        .arg("build")
        .arg("--tag")
        .arg(image)
        .arg(&container_dir)
        .status()
        .context("failed to execute `docker build`")?;

    if !status.success() {
        bail!("docker build exited with status {status}");
    }

    // The collector image rebuilds the AgentFence binary inside a container,
    // so it needs the full Rust source tree as build context. That's only
    // available in source-tree installs (`cargo install --path .`); prebuilt
    // binary installs skip this step. The collector is currently only used by
    // `--monitor strong` on Linux, so binary installs lose nothing on macOS
    // and lose strong host-side eBPF monitoring on Linux.
    match dev_source_root() {
        Some(src_root) => {
            let helper_image = collector_image_tag(image);
            let status = Command::new("docker")
                .arg("build")
                .arg("--file")
                .arg(src_root.join("container").join("Collector.Dockerfile"))
                .arg("--tag")
                .arg(&helper_image)
                .arg(&src_root)
                .status()
                .context("failed to execute collector image `docker build`")?;

            if !status.success() {
                bail!("collector image docker build exited with status {status}");
            }
        }
        None => {
            let helper_image = collector_image_tag(image);
            if docker_image_exists(&helper_image)? {
                println!("[AgentFence] Collector image already loaded: {helper_image}");
            } else if load_collector_from_saved_tarball(&helper_image)? {
                println!("[AgentFence] Loaded collector image from saved tarball.");
            } else {
                println!(
                    "[AgentFence] Collector image not available (prebuilt binary install). Strong monitoring requires the collector image — re-run install.sh or download the collector tarball from the GitHub release."
                );
            }
        }
    }

    Ok(())
}

fn agentfence_images_exist(image: &str) -> Result<bool> {
    Ok(docker_image_exists(image)? && docker_image_exists(&collector_image_tag(image))?)
}

fn docker_image_exists(image: &str) -> Result<bool> {
    let status = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("failed to inspect docker image `{image}`"))?;
    Ok(status.success())
}

pub fn run_container(options: RunOptions) -> Result<()> {
    check_docker_available()?;
    let monitoring_request = if options.ebpf_exec || options.ebpf_net || options.ebpf_file {
        MonitoringRequest {
            ebpf_exec: options.ebpf_exec,
            ebpf_net: options.ebpf_net,
            ebpf_file: options.ebpf_file,
        }
    } else {
        monitoring_request_for_mode(options.monitor)
    };
    let monitoring_plan = select_monitoring_backend(monitoring_request, options.monitor)?;

    let project_dir = canonical_dir(&options.project_dir, "--project")?;
    let logs_dir = prepare_logs_dir(options.logs_dir)?;
    prepare_session_log_files(&logs_dir)?;
    let runtime_auth_dir = prepare_runtime_auth_dir(&logs_dir)?;
    let runtime_container_home = prepare_runtime_container_home(&runtime_auth_dir)?;
    let host_scan = scan_host_credentials(&project_dir, &logs_dir)?;
    let selected_agent = match options.agent {
        Some(agent) => {
            println!("[AgentFence] Agent override requested: {agent}");
            agent
        }
        None => {
            let detection = agent_runtime::detect_agent(&project_dir, &host_scan);
            println!(
                "[AgentFence] Auto-selected agent: {} ({})",
                detection.agent, detection.reason
            );
            detection.agent
        }
    };
    let auto_ssh_mounts = auto_discovered_ssh_mounts(&host_scan)?;

    println!("[AgentFence] Starting credential discovery on host...");
    if host_scan.findings.is_empty() {
        println!("[AgentFence] Host scan complete. No credential candidates found.");
    } else {
        for finding in &host_scan.findings {
            println!(
                "[AgentFence] Found: {} ({})",
                finding.classification, finding.path
            );
        }
        println!(
            "[AgentFence] Host scan complete. {} credential candidates found.",
            host_scan.findings.len()
        );
    }
    println!(
        "[AgentFence] Host scan report: {}",
        logs_dir.join("host_scan.json").display()
    );
    if let Some(notice) = monitoring_plan.startup_notice() {
        println!("{notice}");
    }
    if !auto_ssh_mounts.is_empty() {
        println!(
            "[AgentFence] Auto-mounting {} discovered SSH key(s) for auditing.",
            auto_ssh_mounts.len()
        );
    }

    if options.build_image || !agentfence_images_exist(&options.image)? {
        build_image(&options.image)?;
    }

    let container_name = options
        .container_name
        .unwrap_or_else(|| default_container_name(&project_dir));
    let workspace_path = container_workspace_path(&project_dir);

    // Seed the runtime credential registry from the host scan findings before
    // the bpftrace file collector starts. Without this, host_scan finds the
    // project's .env (and the agent's auth store under ~) but the registry
    // stays empty, lookup_monitored_path in the file collector returns None
    // for every observed openat, and zero credential-access events get
    // recorded for files that AgentFence already knows about. Project-scan
    // findings translate cleanly to the in-container workspace path;
    // host-scan findings under the user home are mapped via the auto-auth
    // alias table for the selected agent.
    if let Err(err) = seed_registry_from_host_scan(
        &logs_dir,
        &host_scan,
        &project_dir,
        &workspace_path,
        selected_agent,
    ) {
        eprintln!("[AgentFence] Failed to seed credential registry from host scan: {err:#}");
    }

    // host_scan.json contains the full credential path enumeration of the
    // host — ~/.aws/credentials, ~/.docker/config.json, etc. The seed
    // function already consumed the findings from the in-memory struct, and
    // agentfence audit doesn't read this file. Remove it from the
    // container-visible logs dir before the container starts so a prompt-
    // injected agent can't enumerate credential locations it wouldn't
    // otherwise know about. Move to a host-only location for manual review.
    relocate_host_scan_report(&logs_dir);

    let mut command = Command::new("docker");
    command.arg("run").arg("--rm");

    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        command.arg("-it");
    }
    command.arg("--name").arg(&container_name);
    command.arg("--hostname").arg("agentfence");
    command.arg("--network").arg(options.network_mode.to_string());
    if options.network_mode == NetworkMode::Host {
        println!(
            "[AgentFence] Network mode: host (container shares the host network namespace)"
        );
        if cfg!(target_os = "macos") {
            println!(
                "[AgentFence] Note: on macOS, --network host shares the Docker Desktop VM network, not the Mac host network."
            );
        }
    }
    command.arg("--cap-drop").arg("ALL");
    command.arg("--security-opt").arg("no-new-privileges");
    command.arg("--read-only");
    command.arg("--tmpfs").arg("/tmp:rw,nosuid");
    command.arg("--tmpfs").arg("/run:rw,nosuid");
    if let Some(user) = current_host_user_spec() {
        command.arg("--user").arg(user);
    }

    add_bind_mount(&mut command, &project_dir, &workspace_path, false);
    if workspace_path != "/workspace" {
        add_bind_mount(&mut command, &project_dir, "/workspace", false);
    }
    // Mount the session logs directory READ-ONLY into the agent container.
    // This protects the eBPF event logs (written by the helper container via
    // its own RW mount), ebpf_scope.json, and any other host-written data from
    // being tampered with by a compromised agent. The in-container watchers get
    // a nested RW mount at /var/log/agentfence/watcher/ for their output files
    // (audit.jsonl, registry.json). After the container exits, the watcher
    // output is merged back into the session logs directory.
    let watcher_dir = logs_dir.join("watcher");
    fs::create_dir_all(&watcher_dir)
        .with_context(|| format!("failed to create watcher dir {}", watcher_dir.display()))?;
    // Copy the seeded registry into the watcher dir so watchers can update it.
    let seeded_registry = logs_dir.join("registry.json");
    let watcher_registry = watcher_dir.join("registry.json");
    if seeded_registry.is_file() {
        fs::copy(&seeded_registry, &watcher_registry)
            .with_context(|| format!("failed to copy seeded registry to {}", watcher_registry.display()))?;
    }
    // Create empty audit.jsonl for watchers to append to.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(watcher_dir.join("audit.jsonl"))
        .context("failed to create watcher audit.jsonl")?;

    add_bind_mount(&mut command, &logs_dir, "/var/log/agentfence", true);
    add_bind_mount(&mut command, &watcher_dir, "/var/log/agentfence/watcher", false);
    add_bind_mount(
        &mut command,
        &runtime_container_home,
        AGENTFENCE_CONTAINER_HOME,
        false,
    );

    let mut ssh_sources = options.ssh_mounts.clone();
    for path in auto_ssh_mounts {
        if !ssh_sources.iter().any(|existing| existing == &path) {
            ssh_sources.push(path);
        }
    }

    for mount in materialize_mounts(&ssh_sources, MountKind::Ssh)? {
        add_bind_mount(
            &mut command,
            &mount.host_path,
            &mount.container_path,
            mount.readonly,
        );
    }

    for mount in materialize_mounts(&options.cred_mounts, MountKind::Cred)? {
        add_bind_mount(
            &mut command,
            &mount.host_path,
            &mount.container_path,
            mount.readonly,
        );
    }

    let auto_agent_auth_mounts =
        auto_discovered_agent_auth_mounts(selected_agent, &project_dir, &runtime_auth_dir)?;
    if !auto_agent_auth_mounts.is_empty() {
        let mounted_targets = auto_agent_auth_mounts
            .iter()
            .map(|mount| mount.container_path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "[AgentFence] Auto-mounting {} agent auth artifact(s): {}",
            auto_agent_auth_mounts.len(),
            mounted_targets
        );
    }
    if selected_agent == Agent::ClaudeCode && !auto_agent_auth_mounts.is_empty() {
        println!(
            "[AgentFence] Note: workspace trust auto-accepted for container session."
        );
    }
    for mount in auto_agent_auth_mounts {
        add_bind_mount(
            &mut command,
            &mount.host_path,
            &mount.container_path,
            mount.readonly,
        );
    }

    let auto_agent_runtime_mounts = auto_discovered_agent_runtime_mounts(selected_agent)?;
    if !auto_agent_runtime_mounts.is_empty() {
        let mounted_targets = auto_agent_runtime_mounts
            .iter()
            .map(|mount| mount.container_path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "[AgentFence] Auto-mounting {} agent runtime artifact(s): {}",
            auto_agent_runtime_mounts.len(),
            mounted_targets
        );
    }
    for mount in auto_agent_runtime_mounts {
        add_bind_mount(
            &mut command,
            &mount.host_path,
            &mount.container_path,
            mount.readonly,
        );
    }

    let auto_env_vars = auto_discovered_env_vars(&host_scan, selected_agent);
    if !auto_env_vars.is_empty() {
        println!(
            "[AgentFence] Auto-passing through {} host credential env var(s): {}",
            auto_env_vars.len(),
            auto_env_vars.join(", ")
        );
    }

    let mut env_vars = options.env_vars.clone();
    for name in auto_env_vars {
        if !env_vars.iter().any(|existing| existing == &name) {
            env_vars.push(name);
        }
    }

    for name in &env_vars {
        let value = env::var(name)
            .with_context(|| format!("environment variable `{name}` is not set on the host"))?;
        command.arg("--env").arg(format!("{name}={value}"));
    }

    command
        .arg("--env")
        .arg(format!("AGENTFENCE_AGENT={}", selected_agent));
    command
        .arg("--env")
        .arg(format!("AGENTFENCE_WORKSPACE={workspace_path}"));
    command
        .arg("--env")
        .arg(format!("HOME={AGENTFENCE_CONTAINER_HOME}"));
    command.arg("--env").arg(format!(
        "PATH={AGENTFENCE_CONTAINER_HOME}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ));
    if let Ok(term) = env::var("TERM") {
        if !term.is_empty() {
            command.arg("--env").arg(format!("TERM={term}"));
        }
    }
    if let Ok(colorterm) = env::var("COLORTERM") {
        if !colorterm.is_empty() {
            command.arg("--env").arg(format!("COLORTERM={colorterm}"));
        }
    }
    if monitoring_request.ebpf_net {
        command
            .arg("--env")
            .arg("AGENTFENCE_DISABLE_NETWORK_WATCHER=1");
    }
    if monitoring_request.ebpf_file {
        command
            .arg("--env")
            .arg("AGENTFENCE_DISABLE_FILE_ACCESS_AUDIT=1");
    }
    if monitoring_request.any_host_collectors() {
        command
            .arg("--env")
            .arg("AGENTFENCE_MONITORING_STARTUP_GRACE_MS=1000");
    }
    if monitoring_request.ebpf_exec {
        command
            .arg("--env")
            .arg("AGENTFENCE_HOST_EXEC_ENV_AUDIT=1");
    }
    command.arg(&options.image);

    let launch_command = if options.command.is_empty() {
        default_launch_command(selected_agent, &project_dir, &workspace_path)?
    } else {
        options.command.clone()
    };

    if !launch_command.is_empty() {
        command.args(&launch_command);
    }

    if monitoring_request.any_host_collectors() {
        if monitoring_request.ebpf_exec {
            println!("[AgentFence] Host eBPF exec collector: requested");
            println!(
                "[AgentFence] Host eBPF exec log: {}",
                logs_dir.join("ebpf_exec.jsonl").display()
            );
        }
        if monitoring_request.ebpf_net {
            println!("[AgentFence] Host eBPF connect collector: requested");
            println!(
                "[AgentFence] Host eBPF connect log: {}",
                logs_dir.join("ebpf_connect.jsonl").display()
            );
        }
        if monitoring_request.ebpf_file {
            println!("[AgentFence] Host eBPF file collector: requested");
            println!(
                "[AgentFence] Host eBPF file log: {}",
                logs_dir.join("ebpf_file.jsonl").display()
            );
        }
        let status = run_with_monitoring(
            monitoring_plan,
            command,
            &options.image,
            &container_name,
            &logs_dir,
        )?;
        merge_watcher_output(&logs_dir);
        return finalize_and_cleanup_session(selected_agent, &project_dir, &runtime_auth_dir, status);
    }

    let status = run_with_monitoring(
        monitoring_plan,
        command,
        &options.image,
        &container_name,
        &logs_dir,
    )?;

    merge_watcher_output(&logs_dir);
    finalize_and_cleanup_session(selected_agent, &project_dir, &runtime_auth_dir, status)
}

fn finalize_and_cleanup_session(
    agent: Agent,
    project_dir: &Path,
    runtime_auth_dir: &Path,
    status: std::process::ExitStatus,
) -> Result<()> {
    let finalize_result = finalize_session(agent, project_dir, runtime_auth_dir, status);
    let cleanup_result = cleanup_runtime_auth_dir(runtime_auth_dir);

    match (finalize_result, cleanup_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn finalize_session(
    agent: Agent,
    project_dir: &Path,
    runtime_auth_dir: &Path,
    status: std::process::ExitStatus,
) -> Result<()> {
    if !status.success() {
        bail!("docker run exited with status {status}");
    }

    if agent == Agent::ClaudeCode {
        sync_claude_project_session_back(project_dir, runtime_auth_dir)?;
    }
    if agent == Agent::Codex {
        sync_codex_session_back(project_dir, runtime_auth_dir)?;
    }

    Ok(())
}

fn auto_discovered_ssh_mounts(
    report: &crate::discovery::HostScanReport,
) -> Result<Vec<PathBuf>> {
    // Only auto-mount SSH keys that are explicitly referenced in the user's
    // ~/.ssh/config via IdentityFile directives. Previously this also had a
    // "GitHub fallback" that auto-mounted id_ed25519/id_rsa when the project
    // had a github.com remote — but that let a malicious repo with a fake
    // GitHub remote silently import the user's SSH private key into the
    // container. Removed: users should --mount their SSH keys explicitly,
    // or put them in .agentfence.toml.
    let mut paths = Vec::new();

    // Filter key_hints to only those from ~/.ssh/config (user-controlled),
    // not from project text scanning (project-controlled).
    let user_key_hints = user_ssh_config_identity_files();

    for finding in &report.findings {
        if finding.mount_kind.as_deref() != Some("ssh") {
            continue;
        }
        let path = PathBuf::from(&finding.path);
        if !path.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if user_key_hints.iter().any(|hint| hint == file_name) {
            paths.push(path);
        }
    }

    // Print recommendation for keys that were found but not auto-mounted.
    let remote_hosts = &report.project_context.git_remote_hosts;
    if paths.is_empty() && !remote_hosts.is_empty() {
        let ssh_keys: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.mount_kind.as_deref() == Some("ssh"))
            .filter_map(|f| {
                Path::new(&f.path)
                    .file_name()
                    .and_then(|n| n.to_str())
            })
            .collect();
        if !ssh_keys.is_empty() {
            println!(
                "[AgentFence] SSH keys found on host ({}) but not auto-mounted. Use --mount ~/.ssh/<key> to pass them explicitly.",
                ssh_keys.join(", ")
            );
        }
    }

    Ok(paths)
}

/// Returns SSH key file names referenced in the user's ~/.ssh/config via
/// IdentityFile directives. These are user-controlled (the user wrote their
/// SSH config) and safe to auto-mount. Project text file references are
/// excluded because project content is untrusted.
fn user_ssh_config_identity_files() -> Vec<String> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    let ssh_config = home.join(".ssh").join("config");
    if !ssh_config.is_file() {
        return Vec::new();
    }
    let Ok(text) = fs::read_to_string(&ssh_config) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().starts_with("identityfile ") {
            if let Some(value) = trimmed.split_whitespace().nth(1) {
                let path = value.trim_matches('"').trim_matches('\'');
                if let Some(name) = Path::new(path).file_name().and_then(|n| n.to_str()) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Env vars that are safe to auto-pass because they're needed for core agent
/// workflows (git operations) and are compiled into AgentFence, not derived
/// from project text. These are auto-passed regardless of what the project
/// text says — the trust is in the AgentFence source code.
const SAFE_AUTO_PASS_ENV_VARS: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN"];

fn auto_discovered_env_vars(
    report: &crate::discovery::HostScanReport,
    agent: Agent,
) -> Vec<String> {
    // Auto-pass env vars from two trusted sources:
    //
    // 1. Agent-specific hints (compiled into AgentFence, e.g. Cursor needs
    //    OPENAI_API_KEY). The user chose the agent, so this is user-controlled.
    //
    // 2. Core workflow vars (GH_TOKEN, GITHUB_TOKEN) that agents commonly
    //    need for git operations. These are hardcoded here, not derived from
    //    project text.
    //
    // Everything else discovered in project text files (e.g., a README that
    // mentions AWS_SECRET_ACCESS_KEY) is printed as a recommendation but NOT
    // auto-passed. This prevents a malicious repo from silently importing
    // host secrets.
    let mut names: Vec<String> = agent_auth_env_hints(agent)
        .iter()
        .chain(SAFE_AUTO_PASS_ENV_VARS.iter())
        .map(|name| (*name).to_string())
        .filter(|name| env::var_os(name).is_some())
        .collect();
    names.sort();
    names.dedup();

    // Print recommendation for project-referenced vars that are set on the
    // host but NOT auto-passed.
    let project_vars: Vec<&String> = report
        .project_context
        .referenced_env_vars
        .iter()
        .filter(|name| env::var_os(name).is_some())
        .filter(|name| !names.contains(name))
        .collect();
    if !project_vars.is_empty() {
        let var_list = project_vars
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "[AgentFence] Project references credential env vars set on this host: {var_list}"
        );
        println!(
            "[AgentFence] These are NOT auto-passed into the container. Use --mount <NAME> to pass them explicitly."
        );
    }

    names
}

fn auto_discovered_agent_runtime_mounts(agent: Agent) -> Result<Vec<MaterializedMount>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(Vec::new());
    };

    let mut mounts = Vec::new();
    if agent == Agent::ClaudeCode && cfg!(target_os = "linux") {
        let native_claude = home.join(".local").join("bin").join("claude");
        if native_claude.exists() {
            let host_path = canonical_file(&native_claude)?;
            mounts.push(MaterializedMount {
                host_path: host_path.clone(),
                container_path: format!("{AGENTFENCE_CONTAINER_HOME}/.local/bin/claude"),
                readonly: true,
            });
            mounts.push(MaterializedMount {
                host_path,
                container_path: "/usr/local/bin/claude".to_string(),
                readonly: true,
            });
        }
    }
    if agent == Agent::Codex && cfg!(target_os = "linux") {
        if let Some(codex_binary) = host_codex_native_binary()? {
            mounts.push(MaterializedMount {
                host_path: codex_binary,
                container_path: "/usr/local/bin/codex".to_string(),
                readonly: true,
            });
        }
        if let Some(rg_binary) = host_codex_native_rg()? {
            mounts.push(MaterializedMount {
                host_path: rg_binary,
                container_path: "/usr/local/bin/rg".to_string(),
                readonly: true,
            });
        }
    }

    Ok(mounts)
}

fn host_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn host_codex_package_root() -> Result<Option<PathBuf>> {
    let Some(codex) = host_executable("codex") else {
        return Ok(None);
    };
    let codex = canonical_file(&codex)?;
    if codex.file_name().and_then(|name| name.to_str()) != Some("codex.js") {
        return Ok(None);
    }
    Ok(codex
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf))
}

fn host_codex_native_binary() -> Result<Option<PathBuf>> {
    let Some(package_root) = host_codex_package_root()? else {
        return Ok(None);
    };
    let candidate = package_root
        .join("node_modules")
        .join("@openai")
        .join("codex-linux-x64")
        .join("vendor")
        .join("x86_64-unknown-linux-musl")
        .join("codex")
        .join("codex");

    if candidate.is_file() {
        return Ok(Some(canonical_file(&candidate)?));
    }
    Ok(None)
}

fn host_codex_native_rg() -> Result<Option<PathBuf>> {
    let Some(package_root) = host_codex_package_root()? else {
        return Ok(None);
    };
    let candidate = package_root
        .join("node_modules")
        .join("@openai")
        .join("codex-linux-x64")
        .join("vendor")
        .join("x86_64-unknown-linux-musl")
        .join("path")
        .join("rg");

    if candidate.is_file() {
        return Ok(Some(canonical_file(&candidate)?));
    }
    Ok(None)
}

fn auto_discovered_agent_auth_mounts(
    agent: Agent,
    project_dir: &Path,
    logs_dir: &Path,
) -> Result<Vec<MaterializedMount>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(Vec::new());
    };

    match agent {
        Agent::ClaudeCode => materialize_claude_auth_mounts(&home, project_dir, logs_dir),
        Agent::Codex => materialize_codex_auth_mounts(&home, project_dir, logs_dir),
        _ => Ok(Vec::new()),
    }
}

fn materialize_codex_auth_mounts(
    home: &Path,
    project_dir: &Path,
    runtime_auth_dir: &Path,
) -> Result<Vec<MaterializedMount>> {
    let source_dir = home.join(".codex");
    let target_dir = runtime_auth_dir.join("codex").join(".codex");
    if !source_dir.is_dir() {
        return Ok(Vec::new());
    }

    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;
    for file_name in ["auth.json", "config.toml", "version.json"] {
        copy_file_if_exists(&source_dir.join(file_name), &target_dir.join(file_name))?;
    }
    copy_codex_project_history(
        &source_dir.join("history.jsonl"),
        &target_dir.join("history.jsonl"),
        &project_dir.display().to_string(),
        &container_workspace_path(project_dir),
    )?;
    copy_codex_project_sessions(
        &source_dir.join("sessions"),
        &target_dir.join("sessions"),
        &project_dir.display().to_string(),
        &container_workspace_path(project_dir),
    )?;
    set_codex_auth_permissions(&target_dir)?;

    Ok(vec![MaterializedMount {
        host_path: canonical_dir(&target_dir, "session Codex auth mount")?,
        container_path: format!("{AGENTFENCE_CONTAINER_HOME}/.codex"),
        readonly: false,
    }])
}

fn materialize_claude_auth_mounts(
    home: &Path,
    project_dir: &Path,
    runtime_auth_dir: &Path,
) -> Result<Vec<MaterializedMount>> {
    let source_dir = home.join(".claude");
    let source_config = home.join(".claude.json");
    let session_root = runtime_auth_dir.join("claude");
    let target_dir = session_root.join(".claude");
    let target_config = session_root.join(".claude.json");

    if source_dir.is_dir() {
        fs::create_dir_all(&target_dir)
            .with_context(|| format!("failed to create {}", target_dir.display()))?;
        copy_file_if_exists(
            &source_dir.join(".credentials.json"),
            &target_dir.join(".credentials.json"),
        )?;
        copy_file_if_exists(
            &source_dir.join(".current-session"),
            &target_dir.join(".current-session"),
        )?;
        copy_file_if_exists(
            &source_dir.join("history.jsonl"),
            &target_dir.join("history.jsonl"),
        )?;
        fs::create_dir_all(target_dir.join("session-env"))
            .with_context(|| format!("failed to create {}", target_dir.join("session-env").display()))?;
        mirror_claude_project_sessions(&source_dir, &target_dir, project_dir)?;
        set_claude_auth_permissions(&target_dir, project_dir)?;
    }

    if source_config.is_file() {
        if let Some(parent) = target_config.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(&source_config, &target_config).with_context(|| {
            format!(
                "failed to copy Claude config {} -> {}",
                source_config.display(),
                target_config.display()
            )
        })?;
        seed_workspace_trust(&target_config, project_dir)?;
        #[cfg(unix)]
        set_private_file(&target_config)?;
    }

    let mut mounts = Vec::new();
    if target_dir.is_dir() {
        mounts.push(MaterializedMount {
            host_path: canonical_dir(&target_dir, "session Claude auth mount")?,
            container_path: format!("{AGENTFENCE_CONTAINER_HOME}/.claude"),
            readonly: false,
        });
    }
    if target_config.is_file() {
        mounts.push(MaterializedMount {
            host_path: canonical_file(&target_config)?,
            container_path: format!("{AGENTFENCE_CONTAINER_HOME}/.claude.json"),
            readonly: false,
        });
    }

    Ok(mounts)
}

fn default_launch_command(
    agent: Agent,
    project_dir: &Path,
    container_project_path: &str,
) -> Result<Vec<String>> {
    if agent == Agent::ClaudeCode {
        if let Some(session_id) = host_claude_last_session_id(project_dir)? {
            println!(
                "[AgentFence] Auto-resuming Claude session for {} as {}: {}",
                project_dir.display(),
                container_project_path,
                session_id
            );
            return Ok(vec![
                "claude".to_string(),
                "--resume".to_string(),
                session_id,
            ]);
        }
    }

    Ok(agent_runtime::default_command(agent).unwrap_or_default())
}

fn host_claude_last_session_id(project_dir: &Path) -> Result<Option<String>> {
    let Some(home) = dirs::home_dir() else {
        return Ok(None);
    };

    if let Some(session_id) = host_claude_latest_history_session_id(&home, project_dir)? {
        return Ok(Some(session_id));
    }

    let config_path = home.join(".claude.json");
    if !config_path.is_file() {
        return Ok(None);
    }

    let content = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let root: Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;
    let source_key = project_dir.display().to_string();

    Ok(root
        .get("projects")
        .and_then(Value::as_object)
        .and_then(|projects| projects.get(&source_key))
        .and_then(Value::as_object)
        .and_then(|project| project.get("lastSessionId"))
        .and_then(Value::as_str)
        .map(str::to_string))
}

fn host_claude_latest_history_session_id(
    home: &Path,
    project_dir: &Path,
) -> Result<Option<String>> {
    let history_path = home.join(".claude").join("history.jsonl");
    if !history_path.is_file() {
        return Ok(None);
    }

    let source_key = project_dir.display().to_string();
    let content = fs::read_to_string(&history_path)
        .with_context(|| format!("failed to read {}", history_path.display()))?;
    let mut latest: Option<(u64, String)> = None;

    for line in content.lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if record.get("project").and_then(Value::as_str) != Some(source_key.as_str()) {
            continue;
        }
        let Some(session_id) = record.get("sessionId").and_then(Value::as_str) else {
            continue;
        };
        let timestamp = record.get("timestamp").and_then(Value::as_u64).unwrap_or(0);

        if latest
            .as_ref()
            .is_none_or(|(latest_timestamp, _)| timestamp >= *latest_timestamp)
        {
            latest = Some((timestamp, session_id.to_string()));
        }
    }

    Ok(latest.map(|(_, session_id)| session_id))
}

fn mirror_claude_project_sessions(
    source_claude_dir: &Path,
    target_claude_dir: &Path,
    project_dir: &Path,
) -> Result<()> {
    let source_key = project_dir.display().to_string();
    let container_key = container_workspace_path(project_dir);
    let source_dir = source_claude_dir
        .join("projects")
        .join(claude_project_slug(&source_key));
    let container_project_dir = target_claude_dir
        .join("projects")
        .join(claude_project_slug(&container_key));

    if !source_dir.is_dir() {
        return Ok(());
    }

    copy_dir_recursive(&source_dir, &container_project_dir)
        .with_context(|| format!("failed to mirror Claude project session files from {}", source_dir.display()))?;

    let workspace_alias_dir = target_claude_dir
        .join("projects")
        .join(claude_project_slug("/workspace"));
    if workspace_alias_dir != container_project_dir {
        copy_dir_recursive(&source_dir, &workspace_alias_dir).with_context(|| {
            format!(
                "failed to mirror Claude workspace-alias session files from {}",
                source_dir.display()
            )
        })?;
    }

    Ok(())
}

fn sync_claude_project_session_back(project_dir: &Path, runtime_auth_dir: &Path) -> Result<()> {
    let Some(home) = dirs::home_dir() else {
        return Ok(());
    };

    let session_claude_dir = runtime_auth_dir.join("claude").join(".claude");
    let session_config = runtime_auth_dir.join("claude").join(".claude.json");
    if !session_claude_dir.is_dir() {
        return Ok(());
    }

    let host_project_slug = claude_project_slug(&project_dir.display().to_string());
    let container_slug = claude_project_slug(&container_workspace_path(project_dir));
    let session_container_dir = session_claude_dir.join("projects").join(container_slug);
    let fallback_workspace_dir = session_claude_dir
        .join("projects")
        .join(claude_project_slug("/workspace"));
    let host_project_dir = home.join(".claude").join("projects").join(host_project_slug);

    let sync_source_dir = if session_container_dir.is_dir() {
        Some(session_container_dir)
    } else if fallback_workspace_dir.is_dir() {
        Some(fallback_workspace_dir)
    } else {
        None
    };

    if let Some(sync_source_dir) = sync_source_dir {
        fs::create_dir_all(&host_project_dir)
            .with_context(|| format!("failed to create {}", host_project_dir.display()))?;
        copy_dir_recursive(&sync_source_dir, &host_project_dir).with_context(|| {
            format!(
                "failed to sync Claude workspace session files back to {}",
                host_project_dir.display()
            )
        })?;
    }

    sync_claude_project_config_back(&session_config, project_dir)?;

    println!(
        "[AgentFence] Synced Claude project session state back to {}",
        project_dir.display()
    );

    Ok(())
}

fn sync_claude_project_config_back(session_config: &Path, project_dir: &Path) -> Result<()> {
    if !session_config.is_file() {
        return Ok(());
    }

    let Some(home) = dirs::home_dir() else {
        return Ok(());
    };
    let host_config = home.join(".claude.json");
    if !host_config.is_file() {
        return Ok(());
    }

    let session_content = fs::read_to_string(session_config)
        .with_context(|| format!("failed to read {}", session_config.display()))?;
    let host_content = fs::read_to_string(&host_config)
        .with_context(|| format!("failed to read {}", host_config.display()))?;
    let session_root: Value = serde_json::from_str(&session_content)
        .with_context(|| format!("failed to parse {}", session_config.display()))?;
    let mut host_root: Value = serde_json::from_str(&host_content)
        .with_context(|| format!("failed to parse {}", host_config.display()))?;

    let container_key = container_workspace_path(project_dir);
    let Some(session_project) = session_root
        .get("projects")
        .and_then(Value::as_object)
        .and_then(|projects| {
            projects
                .get(&container_key)
                .or_else(|| projects.get("/workspace"))
        })
        .cloned()
    else {
        return Ok(());
    };

    let Some(host_obj) = host_root.as_object_mut() else {
        return Ok(());
    };
    let projects = host_obj
        .entry("projects")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(projects_obj) = projects.as_object_mut() else {
        return Ok(());
    };

    projects_obj.insert(project_dir.display().to_string(), session_project);

    fs::write(
        &host_config,
        serde_json::to_string_pretty(&host_root)
            .context("failed to serialize host Claude config")?
            + "\n",
    )
    .with_context(|| format!("failed to write {}", host_config.display()))?;

    Ok(())
}

fn sync_codex_session_back(project_dir: &Path, runtime_auth_dir: &Path) -> Result<()> {
    let Some(home) = dirs::home_dir() else {
        return Ok(());
    };
    let session_codex_dir = runtime_auth_dir.join("codex").join(".codex");
    if !session_codex_dir.is_dir() {
        return Ok(());
    }

    let host_codex_dir = home.join(".codex");
    fs::create_dir_all(&host_codex_dir)
        .with_context(|| format!("failed to create {}", host_codex_dir.display()))?;

    append_codex_project_history_back(
        &session_codex_dir.join("history.jsonl"),
        &host_codex_dir.join("history.jsonl"),
        &container_workspace_path(project_dir),
        &project_dir.display().to_string(),
    )?;
    sync_codex_project_sessions_back(
        &session_codex_dir.join("sessions"),
        &host_codex_dir.join("sessions"),
        &container_workspace_path(project_dir),
        &project_dir.display().to_string(),
    )?;

    println!(
        "[AgentFence] Synced Codex project session state back to {}",
        project_dir.display()
    );

    Ok(())
}

fn copy_codex_project_history(source: &Path, target: &Path, host_project: &str, container_project: &str) -> Result<()> {
    if !source.is_file() {
        return Ok(());
    }

    let content = fs::read_to_string(source)
        .with_context(|| format!("failed to read Codex history {}", source.display()))?;
    let mut output = String::new();
    for line in content.lines() {
        if codex_record_references_cwd(line, host_project) {
            output.push_str(&line.replace(host_project, container_project));
            output.push('\n');
        }
    }

    if output.is_empty() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(target, output)
        .with_context(|| format!("failed to write Codex project history {}", target.display()))
}

fn append_codex_project_history_back(source: &Path, target: &Path, container_project: &str, host_project: &str) -> Result<()> {
    if !source.is_file() {
        return Ok(());
    }

    let source_content = fs::read_to_string(source)
        .with_context(|| format!("failed to read Codex session history {}", source.display()))?;
    let target_content = fs::read_to_string(target).unwrap_or_default();
    let mut seen = target_content.lines().map(str::to_string).collect::<std::collections::HashSet<_>>();
    let mut additions = String::new();

    for line in source_content.lines() {
        if !codex_record_references_cwd(line, container_project) {
            continue;
        }
        let rewritten = line.replace(container_project, host_project);
        if seen.insert(rewritten.clone()) {
            additions.push_str(&rewritten);
            additions.push('\n');
        }
    }

    if additions.is_empty() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(target)
        .with_context(|| format!("failed to open Codex history {}", target.display()))?;
    file.write_all(additions.as_bytes())
        .with_context(|| format!("failed to append Codex history {}", target.display()))
}

fn copy_codex_project_sessions(source: &Path, target: &Path, host_project: &str, container_project: &str) -> Result<()> {
    copy_codex_project_session_tree(source, source, target, host_project, container_project)
}

fn copy_codex_project_session_tree(
    root: &Path,
    current: &Path,
    target_root: &Path,
    host_project: &str,
    container_project: &str,
) -> Result<()> {
    if !current.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(current).with_context(|| format!("failed to read {}", current.display()))? {
        let entry = entry.with_context(|| format!("failed to read directory entry in {}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            copy_codex_project_session_tree(root, &path, target_root, host_project, container_project)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        if !codex_session_file_references_cwd(&path, host_project)? {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let target = target_root.join(relative);
        copy_text_file_replacing(&path, &target, host_project, container_project)?;
    }
    Ok(())
}

fn sync_codex_project_sessions_back(source: &Path, target: &Path, container_project: &str, host_project: &str) -> Result<()> {
    copy_codex_project_session_tree(source, source, target, container_project, host_project)
}

fn codex_session_file_references_cwd(path: &Path, cwd: &str) -> Result<bool> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read Codex session {}", path.display()))?;
    Ok(content.lines().any(|line| codex_record_references_cwd(line, cwd)))
}

fn codex_record_references_cwd(line: &str, cwd: &str) -> bool {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|record| {
            record
                .get("payload")
                .and_then(|payload| payload.get("cwd"))
                .and_then(Value::as_str)
                .map(|value| value == cwd)
        })
        .unwrap_or(false)
}

fn copy_text_file_replacing(source: &Path, target: &Path, from: &str, to: &str) -> Result<()> {
    let content = fs::read_to_string(source)
        .with_context(|| format!("failed to read {}", source.display()))?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(target, content.replace(from, to))
        .with_context(|| format!("failed to write {}", target.display()))
}

fn claude_project_slug(path: &str) -> String {
    path.replace('/', "-")
}

fn seed_workspace_trust(config_path: &Path, project_dir: &Path) -> Result<()> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut root: Value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    let Some(root_obj) = root.as_object_mut() else {
        return Ok(());
    };

    let projects = root_obj
        .entry("projects")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(projects_obj) = projects.as_object_mut() else {
        return Ok(());
    };

    let source_key = project_dir.display().to_string();
    let mut workspace_entry = projects_obj
        .get(&source_key)
        .cloned()
        .unwrap_or_else(default_workspace_project_state);

    let Some(workspace_obj) = workspace_entry.as_object_mut() else {
        return Ok(());
    };
    workspace_obj.insert("hasTrustDialogAccepted".to_string(), Value::Bool(true));
    workspace_obj.insert("projectOnboardingSeenCount".to_string(), json!(1));
    workspace_obj.insert("hasCompletedProjectOnboarding".to_string(), Value::Bool(true));

    projects_obj.insert(container_workspace_path(project_dir), workspace_entry.clone());
    projects_obj.insert("/workspace".to_string(), workspace_entry);

    fs::write(
        config_path,
        serde_json::to_string_pretty(&root)
            .context("failed to serialize seeded Claude config")?
            + "\n",
    )
    .with_context(|| format!("failed to write {}", config_path.display()))?;

    Ok(())
}

fn default_workspace_project_state() -> Value {
    json!({
        "allowedTools": [],
        "mcpContextUris": [],
        "mcpServers": {},
        "enabledMcpjsonServers": [],
        "disabledMcpjsonServers": [],
        "hasTrustDialogAccepted": true,
        "projectOnboardingSeenCount": 1,
        "hasClaudeMdExternalIncludesApproved": false,
        "hasClaudeMdExternalIncludesWarningShown": false,
        "hasCompletedProjectOnboarding": true
    })
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)
        .with_context(|| format!("failed to create {}", target.display()))?;

    for entry in fs::read_dir(source)
        .with_context(|| format!("failed to read directory {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read directory entry in {}", source.display()))?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to stat {}", source_path.display()))?;

        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &target_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::copy(&source_path, &target_path).with_context(|| {
                format!(
                    "failed to copy auth/session artifact {} -> {}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
        }
    }

    Ok(())
}

fn copy_file_if_exists(source: &Path, target: &Path) -> Result<()> {
    if !source.is_file() {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::copy(source, target)
        .with_context(|| format!("failed to copy {} -> {}", source.display(), target.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_claude_auth_permissions(claude_dir: &Path, project_dir: &Path) -> Result<()> {
    set_private_dir(claude_dir)?;
    set_private_file(&claude_dir.join(".credentials.json"))?;
    set_private_file(&claude_dir.join(".current-session"))?;
    set_private_file(&claude_dir.join("history.jsonl"))?;
    set_recursive_permissions(&claude_dir.join("session-env"), 0o700, 0o600)?;

    let project_root = claude_dir.join("projects");
    set_private_dir(&project_root)?;
    let container_project_dir = project_root.join(claude_project_slug(&container_workspace_path(project_dir)));
    if container_project_dir.exists() {
        set_recursive_permissions(&container_project_dir, 0o700, 0o600)?;
    }
    let workspace_alias_dir = project_root.join(claude_project_slug("/workspace"));
    if workspace_alias_dir.exists() {
        set_recursive_permissions(&workspace_alias_dir, 0o700, 0o600)?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn set_claude_auth_permissions(_claude_dir: &Path, _project_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_codex_auth_permissions(codex_dir: &Path) -> Result<()> {
    set_recursive_permissions(codex_dir, 0o700, 0o600)?;
    set_private_file(&codex_dir.join("auth.json"))?;
    set_private_file(&codex_dir.join("config.toml"))?;
    set_private_file(&codex_dir.join("version.json"))?;
    set_private_file(&codex_dir.join("history.jsonl"))?;
    set_recursive_permissions(&codex_dir.join("sessions"), 0o700, 0o600)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_codex_auth_permissions(_codex_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    if path.is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_recursive_permissions(path: &Path, dir_mode: u32, file_mode: u32) -> Result<()> {
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(dir_mode))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to read directory {}", path.display()))?
        {
            let entry = entry
                .with_context(|| format!("failed to read directory entry in {}", path.display()))?;
            set_recursive_permissions(&entry.path(), dir_mode, file_mode)?;
        }
    } else if path.is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_recursive_permissions(_path: &Path, _dir_mode: u32, _file_mode: u32) -> Result<()> {
    Ok(())
}

fn agent_auth_env_hints(agent: Agent) -> &'static [&'static str] {
    match agent {
        Agent::Shell => &[],
        Agent::Codex => &[],
        Agent::ClaudeCode => &[],
        Agent::Cursor => &["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN", "GITHUB_TOKEN"],
        Agent::Windsurf => &["OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
        Agent::Copilot => &["GH_TOKEN", "GITHUB_TOKEN"],
    }
}

/// Returns the project source root if AgentFence is running from a source-tree
/// install (e.g. `cargo install --path .` or `cargo run`). For prebuilt binary
/// installs the compile-time `CARGO_MANIFEST_DIR` path no longer exists on the
/// host, so this returns `None` and callers fall back to the embedded assets.
fn dev_source_root() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if path.join("Cargo.toml").is_file() && path.join("container").is_dir() {
        Some(path)
    } else {
        None
    }
}

/// Extracts the embedded `container/` assets to a per-version cache directory
/// and returns the extraction path. Source-tree installs short-circuit to the
/// live on-disk copy so dev edits take effect immediately.
fn extract_container_assets() -> Result<PathBuf> {
    if let Some(src) = dev_source_root() {
        return Ok(src.join("container"));
    }

    let cache_dir = dirs::cache_dir()
        .context("could not determine user cache directory for container assets")?
        .join("agentfence")
        .join("container")
        .join(env!("CARGO_PKG_VERSION"));

    // Re-extract every time. The asset payload is small (~50KB) and this avoids
    // any cache-staleness footguns when versions or contents change.
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)
            .with_context(|| format!("failed to clear stale cache dir {}", cache_dir.display()))?;
    }
    fs::create_dir_all(&cache_dir)
        .with_context(|| format!("failed to create cache dir {}", cache_dir.display()))?;

    CONTAINER_ASSETS
        .extract(&cache_dir)
        .with_context(|| format!("failed to extract container assets to {}", cache_dir.display()))?;

    // include_dir does not preserve file modes; restore +x on shell scripts so
    // the in-container entrypoint and bash hooks are executable when COPY'd
    // into the image.
    #[cfg(unix)]
    {
        for entry in fs::read_dir(&cache_dir)
            .with_context(|| format!("failed to read cache dir {}", cache_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("sh") {
                let mut perms = fs::metadata(&path)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&path, perms)?;
            }
        }
    }

    Ok(cache_dir)
}

pub(crate) fn collector_image_tag(image: &str) -> String {
    match image.rsplit_once(':') {
        Some((repo, tag)) => format!("{repo}-collector:{tag}"),
        None => format!("{image}-collector:dev"),
    }
}

fn check_docker_available() -> Result<()> {
    match Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => bail!(
            "Docker daemon is not running. Start Docker Desktop or the Docker service and try again."
        ),
        Err(_) => bail!(
            "Docker is not installed or not in PATH. Install Docker from https://docs.docker.com/get-docker/ and try again."
        ),
    }
}

fn container_dir() -> Result<PathBuf> {
    extract_container_assets()
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve {label} path {}", path.display()))?;

    if !canonical.is_dir() {
        bail!("{label} must reference a directory: {}", canonical.display());
    }

    Ok(canonical)
}

fn canonical_file(path: &Path) -> Result<PathBuf> {
    let canonical =
        fs::canonicalize(path).with_context(|| format!("failed to resolve {}", path.display()))?;

    if !canonical.is_file() {
        bail!("mount source must be a file: {}", canonical.display());
    }

    Ok(canonical)
}

fn prepare_logs_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let path = match explicit {
        Some(path) => path,
        None => default_logs_dir()?,
    };

    fs::create_dir_all(&path)
        .with_context(|| format!("failed to create logs directory {}", path.display()))?;

    ensure_logs_dir_permissions(&path)?;

    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("failed to resolve logs directory {}", path.display()))?;
    update_latest_logs_link(&canonical)?;
    println!("[AgentFence] Session logs: {}", canonical.display());

    Ok(canonical)
}

fn update_latest_logs_link(logs_dir: &Path) -> Result<()> {
    let Some(parent) = logs_dir.parent() else {
        return Ok(());
    };
    let latest = parent.join("latest");
    if latest.exists() {
        let metadata = fs::symlink_metadata(&latest)
            .with_context(|| format!("failed to stat {}", latest.display()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            return Ok(());
        }
        fs::remove_file(&latest)
            .with_context(|| format!("failed to replace {}", latest.display()))?;
    }

    #[cfg(unix)]
    std::os::unix::fs::symlink(logs_dir, &latest)
        .with_context(|| format!("failed to create {}", latest.display()))?;

    Ok(())
}

/// Returns the (host source path, in-container path) pairs for credential
/// files that the auto-auth mount logic for `agent` will copy/bind into
/// `/agentfence/home`. Used by the registry seeder to translate `host_scan`
/// findings under `~` to the paths the file collector will actually see.
///
/// This duplicates a small amount of knowledge from
/// `materialize_codex_auth_mounts` and `materialize_claude_auth_mounts` —
/// keep the two in sync when adding new auto-mounted files. The trade-off
/// vs. refactoring those functions to expose source/target pairs is
/// localization: the alias table is short, agent-scoped, and the materialize
/// functions stay focused on copying files into the runtime dir.
fn auto_auth_path_aliases(agent: Agent, home: &Path) -> Vec<(PathBuf, String)> {
    let mut aliases = Vec::new();
    // Keep in sync with materialize_codex_auth_mounts and
    // materialize_claude_auth_mounts — when a new file is added to either
    // materialize function, add it here too so the registry seed picks it up.
    match agent {
        Agent::Codex => {
            for file_name in ["auth.json", "config.toml", "version.json"] {
                aliases.push((
                    home.join(".codex").join(file_name),
                    format!("{AGENTFENCE_CONTAINER_HOME}/.codex/{file_name}"),
                ));
            }
        }
        Agent::ClaudeCode => {
            for file_name in [".credentials.json", ".current-session", "history.jsonl"] {
                aliases.push((
                    home.join(".claude").join(file_name),
                    format!("{AGENTFENCE_CONTAINER_HOME}/.claude/{file_name}"),
                ));
            }
            aliases.push((
                home.join(".claude.json"),
                format!("{AGENTFENCE_CONTAINER_HOME}/.claude.json"),
            ));
        }
        Agent::Shell | Agent::Cursor | Agent::Windsurf | Agent::Copilot => {}
    }
    aliases
}

/// Seeds the runtime credential registry with host scan findings that will be
/// visible to the file collector inside the container.
///
/// Without this, `lookup_monitored_path` in the file collector only matches
/// the hard-coded `/agentfence/{creds,ssh}/` prefixes plus whatever explicit
/// `--mount` invocations have written via `registry_update.py`. Auto-discovered
/// credentials (project `.env` files via `project_scan`, and the selected
/// agent's auth store via `host_scan`) land in `host_scan.json` but never
/// reach the runtime registry, so the file collector silently misses every
/// access.
///
/// Two source classes are handled:
///
/// - `project_scan` — host path is under `project_dir`; rewrite to
///   `<workspace_path>/<relative>`. The file collector's
///   `workspace_paths_equivalent` helper matches observations on either the
///   auto-detected workspace path or the `/workspace` alias.
/// - `host_scan` under `~` — looked up against `auto_auth_path_aliases` for
///   the selected agent. Findings under `~` that aren't auto-mounted by the
///   current agent are skipped (they wouldn't be visible inside the
///   container, so the file collector couldn't observe them anyway).
fn seed_registry_from_host_scan(
    logs_dir: &Path,
    host_scan: &HostScanReport,
    project_dir: &Path,
    workspace_path: &str,
    agent: Agent,
) -> Result<()> {
    let registry_path = logs_dir.join("registry.json");
    let content = fs::read_to_string(&registry_path)
        .with_context(|| format!("failed to read {}", registry_path.display()))?;
    let mut registry: Value = if content.trim().is_empty() {
        json!({"credentials": []})
    } else {
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", registry_path.display()))?
    };

    if registry.get("credentials").is_none() {
        registry["credentials"] = json!([]);
    }
    let credentials = registry
        .get_mut("credentials")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("registry.json credentials field is not an array"))?;

    let now = utc_now_iso();
    let auth_aliases = dirs::home_dir()
        .map(|home| auto_auth_path_aliases(agent, &home))
        .unwrap_or_default();

    let mut project_added = 0usize;
    let mut auth_added = 0usize;

    for finding in &host_scan.findings {
        let host_path = Path::new(&finding.path);

        let (container_path, discovery_method) = match finding.source.as_str() {
            "project_scan" => {
                let Ok(rel) = host_path.strip_prefix(project_dir) else {
                    continue;
                };
                let rel_str = rel.to_string_lossy();
                if rel_str.is_empty() {
                    continue;
                }
                (
                    format!("{}/{}", workspace_path.trim_end_matches('/'), rel_str),
                    "project_scan",
                )
            }
            "host_scan" => {
                let Some((_, container_path)) =
                    auth_aliases.iter().find(|(h, _)| h == host_path)
                else {
                    continue;
                };
                (container_path.clone(), "host_scan")
            }
            _ => continue,
        };

        let registry_id = format!("file::{container_path}");
        if credentials
            .iter()
            .any(|entry| entry.get("id").and_then(Value::as_str) == Some(&registry_id))
        {
            continue;
        }

        credentials.push(json!({
            "id": registry_id,
            "classification": finding.classification,
            "discovery_method": discovery_method,
            "discovered_at": now,
            "last_seen_at": now,
            "source_command": Value::Null,
            "type": "file",
            "path": container_path,
            "kind": "credential_file",
            "mount_mode": "read-only",
            "access_count": 0,
            "last_accessed_at": Value::Null,
            "expected_destinations": [],
        }));

        match discovery_method {
            "project_scan" => project_added += 1,
            "host_scan" => auth_added += 1,
            _ => {}
        }
    }

    let total = project_added + auth_added;
    if total > 0 {
        let serialized = serde_json::to_string_pretty(&registry)
            .context("failed to serialize seeded registry")?;
        fs::write(&registry_path, format!("{serialized}\n"))
            .with_context(|| format!("failed to write {}", registry_path.display()))?;
        println!(
            "[AgentFence] Seeded credential registry: {project_added} workspace + {auth_added} agent-auth from host scan."
        );
    }

    Ok(())
}

/// Moves host_scan.json out of the container-visible session logs directory
/// into a host-only location. The file enumerates every credential path found
/// on the host (including things NOT mounted into the container), so exposing
/// it to the agent is an information leak that AgentFence itself creates.
///
/// The host-only copy lives at `~/.agentfence/host-scans/<session-name>.json`
/// and is preserved for manual inspection or future audit enhancements.
/// Merges in-container watcher output from the protected watcher subdirectory
/// back into the main session logs directory after the container exits.
///
/// The watcher/ subdir was the only writable mount inside the agent container.
/// The main logs dir was read-only, protecting eBPF event logs and host-written
/// data from tampering. After the agent exits, we merge the watcher output so
/// `agentfence audit` and human reviewers see everything in one place.
fn merge_watcher_output(logs_dir: &Path) {
    let watcher_dir = logs_dir.join("watcher");
    if !watcher_dir.is_dir() {
        return;
    }

    // Append watcher audit events to the main audit log.
    let watcher_audit = watcher_dir.join("audit.jsonl");
    if watcher_audit.is_file() {
        if let Ok(content) = fs::read_to_string(&watcher_audit) {
            if !content.trim().is_empty() {
                let main_audit = logs_dir.join("audit.jsonl");
                if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&main_audit) {
                    let _ = file.write_all(content.as_bytes());
                    if !content.ends_with('\n') {
                        let _ = file.write_all(b"\n");
                    }
                }
            }
        }
    }

    // The watcher registry may have access_count updates and new credential
    // discoveries from the in-container watchers. Overwrite the main registry
    // with the watcher's version since it's a superset (seeded from the host
    // copy at container start, then updated by watchers during the session).
    let watcher_registry = watcher_dir.join("registry.json");
    if watcher_registry.is_file() {
        let main_registry = logs_dir.join("registry.json");
        let _ = fs::copy(&watcher_registry, &main_registry);
    }
}

fn relocate_host_scan_report(logs_dir: &Path) {
    let src = logs_dir.join("host_scan.json");
    if !src.exists() {
        return;
    }

    let session_name = logs_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown-session");

    let host_scans_dir = match agentfence_data_root() {
        Ok(root) => root.join("host-scans"),
        Err(_) => {
            // Can't determine host-scans dir; just delete the file.
            let _ = fs::remove_file(&src);
            return;
        }
    };

    if fs::create_dir_all(&host_scans_dir).is_ok() {
        let dst = host_scans_dir.join(format!("{session_name}.json"));
        if fs::rename(&src, &dst).is_err() {
            // rename fails across filesystems; fall back to copy + delete
            if fs::copy(&src, &dst).is_ok() {
                let _ = fs::remove_file(&src);
            }
        }
    } else {
        // Can't create host-scans dir; just delete the file.
        let _ = fs::remove_file(&src);
    }
}

fn prepare_session_log_files(logs_dir: &Path) -> Result<()> {
    for file_name in [
        "audit.jsonl",
        "registry.json",
        "findings.jsonl",
        "ebpf_exec.jsonl",
        "ebpf_exec.stderr.log",
        "ebpf_connect.jsonl",
        "ebpf_connect.stderr.log",
        "ebpf_file.jsonl",
        "ebpf_file.stderr.log",
        "ebpf_helper.stdout.log",
        "ebpf_helper.stderr.log",
    ] {
        let path = logs_dir.join(file_name);
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to create session log file {}", path.display()))?;
    }

    let registry = logs_dir.join("registry.json");
    if registry.metadata().map(|metadata| metadata.len() == 0).unwrap_or(false) {
        fs::write(&registry, "{\"credentials\":[]}\n")
            .with_context(|| format!("failed to initialize {}", registry.display()))?;
    }

    Ok(())
}

fn prepare_runtime_auth_dir(logs_dir: &Path) -> Result<PathBuf> {
    cleanup_stale_runtime_auth_dirs(Duration::from_secs(6 * 60 * 60))?;

    let session_name = logs_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("session");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_nanos();
    let path = agentfence_runtime_root()?
        .join(format!("{session_name}-{nonce}"))
        .join("agent-auth");

    if path.exists() {
        cleanup_runtime_auth_dir(&path)
            .with_context(|| format!("failed to clean stale runtime auth dir {}", path.display()))?;
    }
    fs::create_dir_all(&path)
        .with_context(|| format!("failed to create runtime auth dir {}", path.display()))?;

    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))?;

    Ok(path)
}

fn prepare_runtime_container_home(runtime_auth_dir: &Path) -> Result<PathBuf> {
    let path = runtime_auth_dir.join("home");
    fs::create_dir_all(path.join(".local").join("bin"))
        .with_context(|| format!("failed to create runtime container home {}", path.display()))?;
    fs::create_dir_all(path.join(".ssh"))
        .with_context(|| format!("failed to create runtime .ssh dir {}", path.join(".ssh").display()))?;

    #[cfg(unix)]
    {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        fs::set_permissions(path.join(".local"), fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set permissions on {}", path.join(".local").display()))?;
        fs::set_permissions(path.join(".local").join("bin"), fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "failed to set permissions on {}",
                    path.join(".local").join("bin").display()
                )
            })?;
    }

    Ok(path)
}

fn cleanup_runtime_auth_dir(runtime_auth_dir: &Path) -> Result<()> {
    if runtime_auth_dir.exists() {
        if let Err(first_error) = fs::remove_dir_all(runtime_auth_dir) {
            cleanup_runtime_auth_dir_with_docker(runtime_auth_dir).with_context(|| {
                format!(
                    "failed to remove runtime auth dir {} after local cleanup failed: {}",
                    runtime_auth_dir.display(),
                    first_error
                )
            })?;
            fs::remove_dir_all(runtime_auth_dir).with_context(|| {
                format!("failed to remove runtime auth dir {}", runtime_auth_dir.display())
            })?;
        }
    }
    Ok(())
}

fn cleanup_runtime_auth_dir_with_docker(runtime_auth_dir: &Path) -> Result<()> {
    let mut mount = OsString::from("type=bind,source=");
    mount.push(runtime_auth_dir.as_os_str());
    mount.push(",target=/cleanup");

    let status = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("--mount")
        .arg(mount)
        .arg("--entrypoint")
        .arg("/usr/bin/find")
        .arg("agentfence:dev")
        .arg("/cleanup")
        .arg("-mindepth")
        .arg("1")
        .arg("-depth")
        .arg("-exec")
        .arg("rm")
        .arg("-rf")
        .arg("{}")
        .arg("+")
        .status()
        .context("failed to execute docker cleanup for runtime auth dir")?;

    if !status.success() {
        bail!("docker cleanup for runtime auth dir exited with status {status}");
    }

    Ok(())
}

fn cleanup_stale_runtime_auth_dirs(max_age: Duration) -> Result<()> {
    let root = agentfence_runtime_root()?;
    if !root.is_dir() {
        return Ok(());
    }

    let now = SystemTime::now();
    for entry in fs::read_dir(&root)
        .with_context(|| format!("failed to read runtime auth root {}", root.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read runtime auth entry in {}", root.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if now.duration_since(modified).is_ok_and(|age| age >= max_age) {
            cleanup_runtime_auth_dir(&path).with_context(|| {
                format!("failed to remove stale runtime auth dir {}", path.display())
            })?;
        }
    }

    Ok(())
}

/// Attempts to load the collector image from a pre-saved tarball at
/// `~/.agentfence/collector-images/agentfence-collector-<arch>.tar.gz`.
/// The install.sh script downloads this tarball from the GitHub release
/// alongside the host binary, so prebuilt-binary installs get the
/// collector image without needing the Rust source tree.
fn load_collector_from_saved_tarball(target_tag: &str) -> Result<bool> {
    let data_root = agentfence_data_root()?;
    let arch = std::env::consts::ARCH;
    let docker_arch = match arch {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => other,
    };
    let tarball = data_root
        .join("collector-images")
        .join(format!("agentfence-collector-linux-{docker_arch}.tar.gz"));

    if !tarball.is_file() {
        return Ok(false);
    }

    println!(
        "[AgentFence] Loading collector image from {}",
        tarball.display()
    );
    let status = Command::new("docker")
        .arg("load")
        .arg("--input")
        .arg(&tarball)
        .status()
        .context("failed to execute `docker load`")?;

    if !status.success() {
        eprintln!(
            "[AgentFence] docker load failed for {}",
            tarball.display()
        );
        return Ok(false);
    }

    // The saved image may have a version-tagged name; re-tag as the expected dev tag
    let loaded_name = "agentfence-collector:dev";
    if loaded_name != target_tag {
        let _ = Command::new("docker")
            .arg("tag")
            .arg(loaded_name)
            .arg(target_tag)
            .status();
    }

    Ok(true)
}

fn agentfence_data_root() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not locate home directory"))?;
    Ok(home.join(".agentfence"))
}

fn agentfence_runtime_root() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not locate home directory"))?;
    let root = home.join(".agentfence").join("runtime");
    fs::create_dir_all(&root)
        .with_context(|| format!("failed to create runtime directory {}", root.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", root.display()))?;
    Ok(root)
}

fn default_logs_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not locate home directory"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs();

    Ok(home
        .join(".agentfence")
        .join("logs")
        .join(format!("session-{timestamp}")))
}

#[cfg(unix)]
fn ensure_logs_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read logs directory metadata {}", path.display()))?;
    let mut permissions = metadata.permissions();

    if permissions.mode() & 0o777 != 0o700 {
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).with_context(|| {
            format!(
                "failed to set private permissions on logs directory {}",
                path.display()
            )
        })?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn ensure_logs_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn current_host_user_spec() -> Option<String> {
    // Linux: read UID/GID from /proc/self
    if let Ok(metadata) = fs::metadata("/proc/self") {
        use std::os::unix::fs::MetadataExt;
        return Some(format!("{}:{}", metadata.uid(), metadata.gid()));
    }
    // macOS: fall back to `id` command
    let uid = Command::new("id").arg("-u").output().ok()?;
    let gid = Command::new("id").arg("-g").output().ok()?;
    let uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
    let gid = String::from_utf8_lossy(&gid.stdout).trim().to_string();
    if uid.is_empty() || gid.is_empty() {
        return None;
    }
    Some(format!("{uid}:{gid}"))
}

#[cfg(not(unix))]
fn current_host_user_spec() -> Option<String> {
    None
}

fn default_container_name(project_dir: &Path) -> String {
    let project = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace");

    format!("agentfence-{}", sanitize_name(project))
}

fn container_workspace_path(project_dir: &Path) -> String {
    let project = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace");
    let mut name = sanitize_workspace_segment(project);
    if is_reserved_workspace_segment(&name) {
        name.push_str("-project");
    }

    if name.is_empty() {
        "/workspace".to_string()
    } else {
        format!("/{name}")
    }
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect()
}

fn sanitize_workspace_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | 'A'..='Z' => ch,
            _ => '-',
        })
        .collect()
}

fn is_reserved_workspace_segment(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "agentfence" | "root" | "tmp" | "var" | "usr" | "bin" | "etc"
    )
}

fn add_bind_mount(command: &mut Command, source: &Path, target: &str, readonly: bool) {
    let mut spec = OsString::from("type=bind,source=");
    spec.push(source.as_os_str());
    spec.push(",target=");
    spec.push(target);

    if readonly {
        spec.push(",readonly");
    }

    command.arg("--mount").arg(spec);
}

#[derive(Clone, Copy)]
enum MountKind {
    Ssh,
    Cred,
}

struct MaterializedMount {
    host_path: PathBuf,
    container_path: String,
    readonly: bool,
}

fn materialize_mounts(paths: &[PathBuf], kind: MountKind) -> Result<Vec<MaterializedMount>> {
    let mut mounts = Vec::with_capacity(paths.len());

    for path in paths {
        let host_path = canonical_file(path)?;
        let file_name = host_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("mount source must have a valid file name: {}", host_path.display()))?;

        let container_path = match kind {
            MountKind::Ssh => format!("/agentfence/ssh/{file_name}"),
            MountKind::Cred => format!("/agentfence/creds/{file_name}"),
        };

        mounts.push(MaterializedMount {
            host_path,
            container_path,
            readonly: true,
        });
    }

    Ok(mounts)
}
