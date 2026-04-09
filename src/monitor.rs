use std::env;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::ValueEnum;

use crate::container::collector_image_tag;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum MonitorMode {
    Auto,
    Basic,
    Strong,
}

#[derive(Clone, Copy, Debug)]
pub struct MonitoringRequest {
    pub ebpf_exec: bool,
    pub ebpf_net: bool,
    pub ebpf_file: bool,
}

impl MonitoringRequest {
    pub fn any_host_collectors(self) -> bool {
        self.ebpf_exec || self.ebpf_net || self.ebpf_file
    }

    pub fn strong_defaults() -> Self {
        Self {
            ebpf_exec: true,
            ebpf_net: true,
            ebpf_file: true,
        }
    }

    pub fn basic() -> Self {
        Self {
            ebpf_exec: false,
            ebpf_net: false,
            ebpf_file: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitoringBackend {
    ContainerLocal,
    LinuxHostEbpf,
    /// Privileged sidecar container running inside the local Docker VM.
    /// Used on macOS with Docker Desktop, Colima, OrbStack, or Rancher Desktop.
    DockerVmHelper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerProvider {
    DockerDesktop,
    Colima,
    OrbStack,
    RancherDesktop,
    Unknown,
}

impl DockerProvider {
    pub fn display_name(self) -> &'static str {
        match self {
            DockerProvider::DockerDesktop => "Docker Desktop",
            DockerProvider::Colima => "Colima",
            DockerProvider::OrbStack => "OrbStack",
            DockerProvider::RancherDesktop => "Rancher Desktop",
            DockerProvider::Unknown => "an unrecognized Docker-in-VM provider",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MonitoringPlan {
    pub backend: MonitoringBackend,
    pub request: MonitoringRequest,
    pub mode: MonitorMode,
}

impl MonitoringPlan {
    pub fn startup_notice(self) -> Option<String> {
        match self.backend {
            MonitoringBackend::ContainerLocal if self.request.any_host_collectors() => Some(format!(
                "[AgentFence] Strong host monitoring is unavailable on {}. Running with container-local telemetry only.",
                env::consts::OS
            )),
            MonitoringBackend::DockerVmHelper => {
                let provider = detect_docker_provider();
                Some(format!(
                    "[AgentFence] Selected Docker-in-VM helper monitoring backend ({}).",
                    provider.display_name()
                ))
            }
            MonitoringBackend::LinuxHostEbpf => Some(
                "[AgentFence] Strong host monitoring enabled with Linux eBPF collectors.".to_string(),
            ),
            _ => None,
        }
    }
}

pub fn monitoring_request_for_mode(mode: MonitorMode) -> MonitoringRequest {
    match mode {
        MonitorMode::Basic => MonitoringRequest::basic(),
        MonitorMode::Strong | MonitorMode::Auto => MonitoringRequest::strong_defaults(),
    }
}

pub fn select_monitoring_backend(request: MonitoringRequest, mode: MonitorMode) -> Result<MonitoringPlan> {
    if request.any_host_collectors() {
        if host_supports_linux_ebpf() {
            return Ok(MonitoringPlan {
                backend: MonitoringBackend::LinuxHostEbpf,
                request,
                mode,
            });
        }

        if cfg!(target_os = "macos") {
            return Ok(MonitoringPlan {
                backend: MonitoringBackend::DockerVmHelper,
                request,
                mode,
            });
        }

        if mode == MonitorMode::Auto {
            return Ok(MonitoringPlan {
                backend: MonitoringBackend::ContainerLocal,
                request,
                mode,
            });
        }

        bail!(
            "strong host monitoring is currently supported only on Linux hosts; rerun with --monitor basic on {}",
            env::consts::OS
        );
    }

    Ok(MonitoringPlan {
        backend: MonitoringBackend::ContainerLocal,
        request,
        mode,
    })
}

pub fn host_supports_linux_ebpf() -> bool {
    cfg!(target_os = "linux")
}

pub fn run_with_monitoring(
    plan: MonitoringPlan,
    docker_command: Command,
    image: &str,
    container_name: &str,
    logs_dir: &Path,
) -> Result<ExitStatus> {
    match plan.backend {
        MonitoringBackend::ContainerLocal => run_container_local(docker_command),
        MonitoringBackend::LinuxHostEbpf => run_with_linux_ebpf_helper(
            docker_command,
            container_name,
            logs_dir,
            plan.request,
        ),
        MonitoringBackend::DockerVmHelper => run_with_docker_vm_helper(
            docker_command,
            image,
            container_name,
            logs_dir,
            plan.request,
            plan.mode,
        ),
    }
}

fn run_container_local(mut docker_command: Command) -> Result<ExitStatus> {
    docker_command
        .status()
        .context("failed to execute `docker run`")
}

fn run_with_linux_ebpf_helper(
    mut docker_command: Command,
    container_name: &str,
    logs_dir: &Path,
    request: MonitoringRequest,
) -> Result<ExitStatus> {
    docker_command.stdin(Stdio::inherit());
    docker_command.stdout(Stdio::inherit());
    docker_command.stderr(Stdio::inherit());

    let mut helper_child = spawn_linux_ebpf_helper(
        container_name,
        logs_dir,
        request.ebpf_exec,
        request.ebpf_net,
        request.ebpf_file,
    )?;

    // Same defense-in-depth check as the DockerVmHelper backend: bpftrace
    // can silently fail to attach probes (kernel config gap, missing tracefs
    // mount, etc) and the user would otherwise get empty JSONL files with
    // no warning. The Linux backend doesn't have the lenient/strict mode
    // machinery so we surface the failure as a loud stderr warning rather
    // than falling back — the run still proceeds but the operator knows
    // the strong telemetry is missing.
    thread::sleep(Duration::from_millis(750));
    if let Some(probe_failures) = scan_collector_attach_failures(logs_dir, request) {
        eprintln!(
            "[AgentFence] WARNING: strong host monitoring is degraded.\n{probe_failures}\n[AgentFence] Continuing with whatever telemetry is available; check the ebpf_*.stderr.log files in the session directory."
        );
    }

    let mut docker_child = match docker_command.spawn() {
        Ok(child) => child,
        Err(err) => {
            stop_linux_helper(&mut helper_child);
            return Err(err).context("failed to execute `docker run`");
        }
    };

    let status = docker_child.wait().context("failed to wait on `docker run`")?;
    stop_linux_helper(&mut helper_child);
    Ok(status)
}

fn run_with_docker_vm_helper(
    docker_command: Command,
    image: &str,
    container_name: &str,
    logs_dir: &Path,
    request: MonitoringRequest,
    mode: MonitorMode,
) -> Result<ExitStatus> {
    // Try to spawn the helper container.
    let spawn_result = spawn_docker_vm_helper_container(image, container_name, logs_dir, request);

    let mut helper = match spawn_result {
        Ok(helper) => helper,
        Err(err) => {
            return handle_helper_failure(
                docker_command,
                mode,
                "Could not start strong monitoring helper",
                &err.to_string(),
                None,
            );
        }
    };

    // Give bpftrace a moment to either come up or crash.
    thread::sleep(Duration::from_millis(750));

    if !is_helper_alive(&helper) {
        let logs = collect_helper_logs(&helper);
        stop_docker_vm_helper(&mut helper);
        return handle_helper_failure(
            docker_command,
            mode,
            "Strong monitoring helper crashed during startup",
            "helper container exited unexpectedly",
            logs.as_deref(),
        );
    }

    // The helper container can stay "alive" while bpftrace silently fails to
    // attach its probes (e.g. missing tracefs mount, kernel config gap). When
    // that happens the ebpf_*.jsonl files end up empty and the user gets a
    // false sense of monitoring. Surface those failures by inspecting each
    // collector's stderr log before letting the agent container start.
    if let Some(probe_failures) = scan_collector_attach_failures(logs_dir, request) {
        let helper_logs = collect_helper_logs(&helper);
        stop_docker_vm_helper(&mut helper);
        return handle_helper_failure(
            docker_command,
            mode,
            "Strong monitoring helper started but bpftrace probes did not attach",
            &probe_failures,
            helper_logs.as_deref(),
        );
    }

    // Helper is alive — run the target container alongside it.
    run_with_alive_helper(docker_command, &mut helper)
}

/// Inspects each requested collector's stderr log for known bpftrace
/// attach-failure markers. Returns a multi-line summary if any probes failed,
/// or `None` if everything looks attached. Called after the helper alive
/// check so bpftrace has had time to either error or settle into its event
/// loop.
fn scan_collector_attach_failures(
    logs_dir: &Path,
    request: MonitoringRequest,
) -> Option<String> {
    let collectors: &[(bool, &str, &str)] = &[
        (request.ebpf_exec, "ebpf_exec.stderr.log", "exec"),
        (request.ebpf_net, "ebpf_connect.stderr.log", "connect"),
        (request.ebpf_file, "ebpf_file.stderr.log", "file"),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (requested, fname, label) in collectors {
        if !requested {
            continue;
        }
        let path = logs_dir.join(fname);
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("ERROR:")
                || trimmed.contains("Unable to attach probe")
                || trimmed.contains("Could not read symbols")
                || trimmed.contains("not available for your kernel")
            {
                failures.push(format!("{label}: {trimmed}"));
                break;
            }
        }
    }

    if failures.is_empty() {
        None
    } else {
        Some(format!("bpftrace probe attach failed:\n  - {}", failures.join("\n  - ")))
    }
}

fn run_with_alive_helper(
    mut docker_command: Command,
    helper: &mut DockerVmHelperHandle,
) -> Result<ExitStatus> {
    docker_command.stdin(Stdio::inherit());
    docker_command.stdout(Stdio::inherit());
    docker_command.stderr(Stdio::inherit());

    let mut docker_child = match docker_command.spawn() {
        Ok(child) => child,
        Err(err) => {
            stop_docker_vm_helper(helper);
            return Err(err).context("failed to execute `docker run`");
        }
    };

    let status = docker_child.wait().context("failed to wait on `docker run`")?;
    stop_docker_vm_helper(helper);
    Ok(status)
}

fn handle_helper_failure(
    docker_command: Command,
    mode: MonitorMode,
    headline: &str,
    detail: &str,
    helper_logs: Option<&str>,
) -> Result<ExitStatus> {
    if mode == MonitorMode::Auto {
        eprintln!(
            "[AgentFence] {headline} ({detail}); falling back to container-local telemetry."
        );
        if let Some(logs) = helper_logs {
            let trimmed = logs.trim();
            if !trimmed.is_empty() {
                eprintln!("[AgentFence] Helper logs:\n{trimmed}");
            }
        }
        run_container_local(docker_command)
    } else {
        let mut msg = format!("{headline}: {detail}");
        if let Some(logs) = helper_logs {
            let trimmed = logs.trim();
            if !trimmed.is_empty() {
                msg.push_str("\nHelper logs:\n");
                msg.push_str(trimmed);
            }
        }
        bail!(msg);
    }
}

fn requested_collectors(request: MonitoringRequest) -> String {
    let mut items = Vec::new();
    if request.ebpf_exec {
        items.push("exec");
    }
    if request.ebpf_net {
        items.push("net");
    }
    if request.ebpf_file {
        items.push("file");
    }
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(",")
    }
}

fn spawn_linux_ebpf_helper(
    container_name: &str,
    logs_dir: &Path,
    enable_exec: bool,
    enable_net: bool,
    enable_file: bool,
) -> Result<Child> {
    ensure_sudo_session()?;

    let current_exe = env::current_exe().context("failed to resolve current agentfence binary")?;
    let mut command = Command::new("sudo");
    command
        .arg("-n")
        .arg("--preserve-env=PATH")
        .arg(current_exe)
        .arg("collect-ebpf")
        .arg("--container-name")
        .arg(container_name)
        .arg("--logs-dir")
        .arg(logs_dir);

    if enable_exec {
        command.arg("--exec");
    }
    if enable_net {
        command.arg("--net");
    }
    if enable_file {
        command.arg("--file");
    }
    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs_dir.join("ebpf_helper.stdout.log"))
        .context("failed to open eBPF helper stdout log")?;
    let stderr_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs_dir.join("ebpf_helper.stderr.log"))
        .context("failed to open eBPF helper stderr log")?;

    command.stdin(Stdio::null());
    command.stdout(Stdio::from(stdout_log));
    command.stderr(Stdio::from(stderr_log));

    println!("[AgentFence] Starting privileged host eBPF helper via sudo.");

    command
        .spawn()
        .context("failed to execute privileged eBPF helper via `sudo`")
}

fn ensure_sudo_session() -> Result<()> {
    let status = Command::new("sudo")
        .arg("-v")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to validate sudo session for privileged eBPF helper")?;

    if !status.success() {
        bail!("sudo authentication failed for privileged eBPF helper");
    }

    Ok(())
}

fn stop_linux_helper(helper_child: &mut Child) {
    let pid = helper_child.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let _ = helper_child.wait();
}

struct DockerVmHelperHandle {
    container_name: String,
}

fn spawn_docker_vm_helper_container(
    image: &str,
    target_container_name: &str,
    logs_dir: &Path,
    request: MonitoringRequest,
) -> Result<DockerVmHelperHandle> {
    let helper_name = format!("{target_container_name}-agentfence-vm-helper");
    let helper_image = collector_image_tag(image);
    let requested = requested_collectors(request);

    if !docker_image_present(&helper_image) {
        bail!(
            "collector image `{}` not found locally. Run `agentfence build-image` first to build it on this host (images must be built per host architecture).",
            helper_image
        );
    }

    let mut command = Command::new("docker");
    command
        .arg("run")
        .arg("-d")
        .arg("--rm")
        .arg("--name")
        .arg(&helper_name)
        .arg("--privileged")
        .arg("--pid=host")
        .arg("--cgroupns=host")
        .arg("--mount")
        .arg(format!(
            "type=bind,source={},target={},readonly=false",
            logs_dir.display(),
            logs_dir.display()
        ))
        .arg("--mount")
        .arg("type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock")
        .arg("--mount")
        .arg("type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup,readonly")
        // bpftrace reads tracepoint definitions from tracefs and uses debugfs
        // for some kernel symbol resolution. Without these mounts the helper
        // container has no /sys/kernel/tracing/events tree, so the tracepoints
        // appear "not found" even though the host kernel exposes them. This is
        // the root cause of bpftrace's silent attach failures inside the
        // sidecar — required for every macOS Docker provider (Lima/Colima/etc).
        .arg("--mount")
        .arg("type=bind,source=/sys/kernel/tracing,target=/sys/kernel/tracing")
        .arg("--mount")
        .arg("type=bind,source=/sys/kernel/debug,target=/sys/kernel/debug")
        .arg(&helper_image)
        .arg("collect-ebpf")
        .arg("--container-name")
        .arg(target_container_name)
        .arg("--logs-dir")
        .arg(logs_dir);

    if request.ebpf_exec {
        command.arg("--exec");
    }
    if request.ebpf_net {
        command.arg("--net");
    }
    if request.ebpf_file {
        command.arg("--file");
    }

    println!(
        "[AgentFence] Starting Docker-in-VM helper container for collectors: {}.",
        requested
    );
    let output = command
        .output()
        .context("failed to start Docker-in-VM helper container")?;

    if !output.status.success() {
        bail!(
            "failed to start Docker-in-VM helper container: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(DockerVmHelperHandle {
        container_name: helper_name,
    })
}

fn stop_docker_vm_helper(helper: &mut DockerVmHelperHandle) {
    let _ = Command::new("docker")
        .arg("rm")
        .arg("-f")
        .arg(&helper.container_name)
        .status();
}

fn is_helper_alive(helper: &DockerVmHelperHandle) -> bool {
    let output = Command::new("docker")
        .args([
            "ps",
            "-q",
            "--filter",
            &format!("name=^{}$", helper.container_name),
        ])
        .output();
    match output {
        Ok(output) => !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        Err(_) => false,
    }
}

fn collect_helper_logs(helper: &DockerVmHelperHandle) -> Option<String> {
    let output = Command::new("docker")
        .args(["logs", "--tail", "30", &helper.container_name])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    if combined.trim().is_empty() {
        None
    } else {
        Some(combined)
    }
}

fn docker_image_present(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn detect_docker_provider() -> DockerProvider {
    let output = Command::new("docker")
        .args([
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ])
        .output();

    if let Ok(output) = output
        && output.status.success()
    {
        let endpoint = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
        return classify_docker_endpoint(&endpoint);
    }

    DockerProvider::Unknown
}

fn classify_docker_endpoint(endpoint: &str) -> DockerProvider {
    if endpoint.contains("colima") {
        DockerProvider::Colima
    } else if endpoint.contains("orbstack") {
        DockerProvider::OrbStack
    } else if endpoint.contains(".rd/") || endpoint.contains("rancher-desktop") {
        DockerProvider::RancherDesktop
    } else if endpoint.contains("/.docker/run/")
        || endpoint.contains("docker-desktop")
        || endpoint.contains("desktop-linux")
    {
        DockerProvider::DockerDesktop
    } else {
        DockerProvider::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_colima_endpoint() {
        assert_eq!(
            classify_docker_endpoint("unix:///users/anton/.colima/default/docker.sock"),
            DockerProvider::Colima
        );
    }

    #[test]
    fn classify_docker_desktop_endpoint() {
        assert_eq!(
            classify_docker_endpoint("unix:///users/anton/.docker/run/docker.sock"),
            DockerProvider::DockerDesktop
        );
    }

    #[test]
    fn classify_docker_desktop_context_name() {
        assert_eq!(
            classify_docker_endpoint("desktop-linux"),
            DockerProvider::DockerDesktop
        );
    }

    #[test]
    fn classify_orbstack_endpoint() {
        assert_eq!(
            classify_docker_endpoint("unix:///users/anton/.orbstack/run/docker.sock"),
            DockerProvider::OrbStack
        );
    }

    #[test]
    fn classify_rancher_desktop_endpoint() {
        assert_eq!(
            classify_docker_endpoint("unix:///users/anton/.rd/docker.sock"),
            DockerProvider::RancherDesktop
        );
    }

    #[test]
    fn classify_native_linux_socket() {
        assert_eq!(
            classify_docker_endpoint("unix:///var/run/docker.sock"),
            DockerProvider::Unknown
        );
    }

    #[test]
    fn select_backend_basic_returns_container_local() {
        let plan = select_monitoring_backend(MonitoringRequest::basic(), MonitorMode::Basic).unwrap();
        assert_eq!(plan.backend, MonitoringBackend::ContainerLocal);
        assert_eq!(plan.mode, MonitorMode::Basic);
    }

    #[test]
    fn select_backend_strong_on_linux_picks_ebpf() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let plan = select_monitoring_backend(MonitoringRequest::strong_defaults(), MonitorMode::Strong)
            .unwrap();
        assert_eq!(plan.backend, MonitoringBackend::LinuxHostEbpf);
        assert_eq!(plan.mode, MonitorMode::Strong);
    }
}
