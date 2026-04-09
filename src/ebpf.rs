use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
    Mutex, OnceLock,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};

const MOUNTED_CREDENTIAL_PREFIXES: [&str; 2] = ["/agentfence/creds/", "/agentfence/ssh/"];
const CORRELATION_WINDOW_MS: u128 = 2 * 60 * 1000;
static RECENT_CREDENTIAL_ACCESSES: OnceLock<Mutex<Vec<RecentCredentialAccess>>> = OnceLock::new();
static RECENT_FINDINGS: OnceLock<Mutex<VecDeque<RecentFindingKey>>> = OnceLock::new();

#[derive(Debug, Serialize)]
struct ScopeMetadata {
    container_name: String,
    container_pid: i32,
    host_logs_dir: String,
    pid_namespace: String,
    cgroup_paths: Vec<String>,
    host_cgroup_path: String,
    started_at_unix: u64,
}

#[derive(Debug, Serialize)]
struct ExecEventRecord {
    timestamp_unix_ms: u128,
    event: &'static str,
    container_name: String,
    container_pid: i32,
    observed_pid: i32,
    observed_ppid: i32,
    process_name: String,
    filename: String,
    cmdline: String,
    process_chain: String,
    cgroup_paths: Vec<String>,
    pid_namespace: String,
    collector: &'static str,
    env_findings: Vec<EnvFinding>,
}

#[derive(Debug, Serialize)]
struct EnvFinding {
    variable: String,
    classification: String,
    value_preview: String,
}

#[derive(Debug, Serialize)]
struct ConnectEventRecord {
    timestamp_unix_ms: u128,
    event: &'static str,
    container_name: String,
    container_pid: i32,
    observed_pid: i32,
    observed_ppid: i32,
    process_name: String,
    socket_fd: i32,
    cmdline: String,
    process_chain: String,
    destinations: Vec<String>,
    cgroup_paths: Vec<String>,
    pid_namespace: String,
    collector: &'static str,
}

#[derive(Debug, Serialize)]
struct FileAccessEventRecord {
    timestamp_unix_ms: u128,
    event: &'static str,
    container_name: String,
    container_pid: i32,
    observed_pid: i32,
    observed_ppid: i32,
    process_name: String,
    raw_path: String,
    resolved_path: String,
    cmdline: String,
    process_chain: String,
    cgroup_paths: Vec<String>,
    pid_namespace: String,
    collector: &'static str,
    operation: String,
    registry_id: String,
    classification: String,
    reason: String,
}

#[derive(Clone)]
struct RecentCredentialAccess {
    timestamp_unix_ms: u128,
    observed_pid: i32,
    path: String,
    registry_id: String,
    classification: String,
    process_name: String,
    cmdline: String,
}

struct RecentFindingKey {
    timestamp_unix_ms: u128,
    key: String,
}

pub struct CollectorHandle {
    pub name: &'static str,
    child: Child,
    worker: Option<JoinHandle<()>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    pub events_path: PathBuf,
}

impl CollectorHandle {
    pub fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        Ok(())
    }
}

pub fn validate_bpftrace_prerequisites() -> Result<()> {
    if !is_running_as_root() {
        bail!("`--ebpf-exec` and `--ebpf-net` currently require running AgentFence as root because `bpftrace` needs elevated privileges");
    }

    let status = Command::new("bpftrace")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to execute `bpftrace --version`")?;

    if !status.success() {
        bail!("`bpftrace` is installed but not usable");
    }

    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("host-side eBPF scoping currently requires cgroup v2 mounted at /sys/fs/cgroup");
    }

    Ok(())
}

pub fn start_collectors(
    container_name: &str,
    logs_dir: &Path,
    enable_exec: bool,
    enable_net: bool,
    enable_file: bool,
) -> Result<Vec<CollectorHandle>> {
    let container_pid = container_pid(container_name)?;
    if container_pid <= 0 {
        bail!("container `{container_name}` is not running yet");
    }

    let scope = resolve_scope(container_name, container_pid, logs_dir)?;
    write_scope_metadata(logs_dir, &scope)?;

    let mut handles = Vec::new();
    if enable_exec {
        handles.push(spawn_exec_collector(logs_dir, &scope)?);
    }
    if enable_net {
        handles.push(spawn_connect_collector(logs_dir, &scope)?);
    }
    if enable_file {
        handles.push(spawn_file_collector(logs_dir, &scope)?);
    }

    wait_for_bpftrace_ready(container_name)?;
    Ok(handles)
}

pub fn run_privileged_helper(
    container_name: &str,
    logs_dir: &Path,
    enable_exec: bool,
    enable_net: bool,
    enable_file: bool,
) -> Result<()> {
    if !enable_exec && !enable_net && !enable_file {
        bail!("at least one eBPF collector must be enabled");
    }

    validate_bpftrace_prerequisites()?;

    let mut last_error = None;
    let mut collectors = None;
    for _ in 0..50 {
        match start_collectors(container_name, logs_dir, enable_exec, enable_net, enable_file) {
            Ok(handles) => {
                collectors = Some(handles);
                break;
            }
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    let mut collectors = collectors.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow!("container did not become ready for eBPF collection"))
    })?;

    for handle in &collectors {
        println!(
            "[AgentFence] Host eBPF collector enabled: {} ({})",
            handle.name,
            handle.events_path.display()
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::SeqCst);
    })
    .context("failed to install signal handler for eBPF helper")?;

    while !shutdown.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
    }

    for handle in collectors.drain(..) {
        let _ = handle.stop();
    }

    Ok(())
}

fn spawn_exec_collector(logs_dir: &Path, scope: &ScopeMetadata) -> Result<CollectorHandle> {
    let script = build_exec_script(scope);
    let mut child = Command::new("bpftrace")
        .arg("-q")
        .arg("-e")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start `bpftrace` exec collector")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture `bpftrace` exec stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture `bpftrace` exec stderr"))?;

    let events_path = logs_dir.join("ebpf_exec.jsonl");
    let errors_path = logs_dir.join("ebpf_exec.stderr.log");
    let audit_path = logs_dir.join("audit.jsonl");
    let scope = clone_scope(scope);
    let worker = spawn_worker(
        stdout,
        stderr,
        events_path.clone(),
        errors_path,
        audit_path,
        scope,
        parse_exec_record,
        exec_audit_record,
    );

    Ok(CollectorHandle {
        name: "exec",
        child,
        worker: Some(worker.0),
        shutdown_tx: Some(worker.1),
        events_path,
    })
}

fn spawn_connect_collector(logs_dir: &Path, scope: &ScopeMetadata) -> Result<CollectorHandle> {
    let script = build_connect_script(scope);
    let mut child = Command::new("bpftrace")
        .arg("-q")
        .arg("-e")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start `bpftrace` connect collector")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture `bpftrace` connect stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture `bpftrace` connect stderr"))?;

    let events_path = logs_dir.join("ebpf_connect.jsonl");
    let errors_path = logs_dir.join("ebpf_connect.stderr.log");
    let audit_path = logs_dir.join("audit.jsonl");
    let findings_path = logs_dir.join("findings.jsonl");
    let scope = clone_scope(scope);
    let worker = spawn_connect_worker(
        stdout,
        stderr,
        events_path.clone(),
        errors_path,
        audit_path,
        findings_path,
        scope,
    );

    Ok(CollectorHandle {
        name: "connect",
        child,
        worker: Some(worker.0),
        shutdown_tx: Some(worker.1),
        events_path,
    })
}

fn spawn_file_collector(logs_dir: &Path, scope: &ScopeMetadata) -> Result<CollectorHandle> {
    let script = build_file_script(scope);
    let mut child = Command::new("bpftrace")
        .arg("-q")
        .arg("-e")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start `bpftrace` file collector")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture `bpftrace` file stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture `bpftrace` file stderr"))?;

    let events_path = logs_dir.join("ebpf_file.jsonl");
    let errors_path = logs_dir.join("ebpf_file.stderr.log");
    let audit_path = logs_dir.join("audit.jsonl");
    let findings_path = logs_dir.join("findings.jsonl");
    let scope = clone_scope(scope);
    let worker = spawn_file_worker(
        stdout,
        stderr,
        events_path.clone(),
        errors_path,
        audit_path,
        findings_path,
        scope,
    );

    Ok(CollectorHandle {
        name: "file",
        child,
        worker: Some(worker.0),
        shutdown_tx: Some(worker.1),
        events_path,
    })
}

fn spawn_worker<T, F>(
    stdout: impl std::io::Read + Send + 'static,
    stderr: impl std::io::Read + Send + 'static,
    events_path: PathBuf,
    errors_path: PathBuf,
    audit_path: PathBuf,
    scope: ScopeMetadata,
    parser: F,
    audit_mapper: fn(&T) -> Value,
) -> (JoinHandle<()>, mpsc::Sender<()>)
where
    T: Serialize + 'static,
    F: Fn(&str, &ScopeMetadata) -> Option<T> + Send + Sync + 'static + Copy,
{
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut events_file = match open_append_file(&events_path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut audit_file = match open_append_file(&audit_path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut errors_file = match open_append_file(&errors_path) {
            Ok(file) => file,
            Err(_) => return,
        };

        let stderr_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let _ = errors_file.write_all(line.as_bytes());
                    }
                    Err(_) => break,
                }
            }
        });

        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => thread::sleep(Duration::from_millis(50)),
                Ok(_) => {
                    if let Some(record) = parser(line.trim_end(), &scope) {
                        let _ = writeln!(
                            events_file,
                            "{}",
                            serde_json::to_string(&record).unwrap_or_default()
                        );
                        let _ = writeln!(
                            audit_file,
                            "{}",
                            serde_json::to_string(&audit_mapper(&record)).unwrap_or_default()
                        );
                    }
                }
                Err(_) => break,
            }
        }

        let _ = stderr_thread.join();
    });

    (worker, shutdown_tx)
}

fn spawn_connect_worker(
    stdout: impl std::io::Read + Send + 'static,
    stderr: impl std::io::Read + Send + 'static,
    events_path: PathBuf,
    errors_path: PathBuf,
    audit_path: PathBuf,
    findings_path: PathBuf,
    scope: ScopeMetadata,
) -> (JoinHandle<()>, mpsc::Sender<()>)
{
    spawn_correlating_worker(
        stdout,
        stderr,
        events_path,
        errors_path,
        audit_path,
        Some(findings_path),
        scope,
        parse_connect_record,
        connect_audit_record,
        correlate_connect_event,
    )
}

fn spawn_file_worker(
    stdout: impl std::io::Read + Send + 'static,
    stderr: impl std::io::Read + Send + 'static,
    events_path: PathBuf,
    errors_path: PathBuf,
    audit_path: PathBuf,
    findings_path: PathBuf,
    scope: ScopeMetadata,
) -> (JoinHandle<()>, mpsc::Sender<()>)
{
    spawn_correlating_worker(
        stdout,
        stderr,
        events_path,
        errors_path,
        audit_path,
        Some(findings_path),
        scope,
        parse_file_record,
        file_audit_record,
        |record, scope, _findings_file| record_file_access_for_correlation(record, scope),
    )
}

fn spawn_correlating_worker<T, F, C>(
    stdout: impl std::io::Read + Send + 'static,
    stderr: impl std::io::Read + Send + 'static,
    events_path: PathBuf,
    errors_path: PathBuf,
    audit_path: PathBuf,
    findings_path: Option<PathBuf>,
    scope: ScopeMetadata,
    parser: F,
    audit_mapper: fn(&T) -> Value,
    correlator: C,
) -> (JoinHandle<()>, mpsc::Sender<()>)
where
    T: Serialize + 'static,
    F: Fn(&str, &ScopeMetadata) -> Option<T> + Send + Sync + 'static + Copy,
    C: Fn(&T, &ScopeMetadata, Option<&mut File>) + Send + Sync + 'static + Copy,
{
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut events_file = match open_append_file(&events_path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut audit_file = match open_append_file(&audit_path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut findings_file = findings_path
            .as_ref()
            .and_then(|path| open_append_file(path).ok());
        let mut errors_file = match open_append_file(&errors_path) {
            Ok(file) => file,
            Err(_) => return,
        };

        let stderr_thread = thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let _ = errors_file.write_all(line.as_bytes());
                    }
                    Err(_) => break,
                }
            }
        });

        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => thread::sleep(Duration::from_millis(50)),
                Ok(_) => {
                    if let Some(record) = parser(line.trim_end(), &scope) {
                        let _ = writeln!(
                            events_file,
                            "{}",
                            serde_json::to_string(&record).unwrap_or_default()
                        );
                        let _ = writeln!(
                            audit_file,
                            "{}",
                            serde_json::to_string(&audit_mapper(&record)).unwrap_or_default()
                        );
                        correlator(&record, &scope, findings_file.as_mut());
                    }
                }
                Err(_) => break,
            }
        }

        let _ = stderr_thread.join();
    });

    (worker, shutdown_tx)
}

fn clone_scope(scope: &ScopeMetadata) -> ScopeMetadata {
    ScopeMetadata {
        container_name: scope.container_name.clone(),
        container_pid: scope.container_pid,
        host_logs_dir: scope.host_logs_dir.clone(),
        pid_namespace: scope.pid_namespace.clone(),
        cgroup_paths: scope.cgroup_paths.clone(),
        host_cgroup_path: scope.host_cgroup_path.clone(),
        started_at_unix: scope.started_at_unix,
    }
}

fn is_running_as_root() -> bool {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid() == 0)
        .unwrap_or(false)
}

fn container_pid(container_name: &str) -> Result<i32> {
    let output = Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{.State.Pid}}")
        .arg(container_name)
        .output()
        .with_context(|| format!("failed to inspect docker container `{container_name}`"))?;

    if !output.status.success() {
        bail!(
            "failed to inspect running container `{container_name}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let pid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()?;
    Ok(pid)
}

fn resolve_scope(container_name: &str, container_pid: i32, logs_dir: &Path) -> Result<ScopeMetadata> {
    let pid_namespace = fs::read_link(format!("/proc/{container_pid}/ns/pid"))
        .with_context(|| format!("failed to read pid namespace for container pid {container_pid}"))?
        .to_string_lossy()
        .to_string();
    let cgroup_paths = read_cgroup_paths(container_pid)?;
    let host_cgroup_path = resolve_host_cgroup_path(&cgroup_paths)?;

    Ok(ScopeMetadata {
        container_name: container_name.to_string(),
        container_pid,
        host_logs_dir: logs_dir.to_string_lossy().to_string(),
        pid_namespace,
        cgroup_paths,
        host_cgroup_path,
        started_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

fn read_cgroup_paths(pid: i32) -> Result<Vec<String>> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("failed to read cgroup metadata for pid {pid}"))?;
    let mut paths = Vec::new();
    for line in content.lines() {
        if let Some(path) = line.rsplit(':').next() {
            paths.push(path.to_string());
        }
    }
    Ok(paths)
}

fn write_scope_metadata(logs_dir: &Path, scope: &ScopeMetadata) -> Result<()> {
    let path = logs_dir.join("ebpf_scope.json");
    fs::write(&path, serde_json::to_string_pretty(scope)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn resolve_host_cgroup_path(cgroup_paths: &[String]) -> Result<String> {
    let relative_path = cgroup_paths
        .iter()
        .find(|path| !path.trim().is_empty() && path.as_str() != "/")
        .ok_or_else(|| anyhow!("could not determine a concrete cgroup path for the target container"))?;

    let host_path = Path::new("/sys/fs/cgroup").join(relative_path.trim_start_matches('/'));
    if !host_path.exists() {
        bail!(
            "target container cgroup path is not visible on the host: {}",
            host_path.display()
        );
    }

    Ok(host_path.to_string_lossy().to_string())
}

fn build_exec_script(scope: &ScopeMetadata) -> String {
    let predicate = cgroup_predicate(scope);
    format!(
        r#"
tracepoint:syscalls:sys_enter_execve {predicate}
{{
  printf("%d\t%s\t%s\n", pid, comm, str(args->filename));
}}

tracepoint:syscalls:sys_enter_execveat {predicate}
{{
  printf("%d\t%s\t%s\n", pid, comm, str(args->filename));
}}
"#
    )
}

fn build_connect_script(scope: &ScopeMetadata) -> String {
    let predicate = cgroup_predicate(scope);
    format!(
        r#"
tracepoint:syscalls:sys_enter_connect {predicate}
{{
  printf("%d\t%s\t%d\n", pid, comm, args->fd);
}}
"#
    )
}

fn build_file_script(scope: &ScopeMetadata) -> String {
    let predicate = cgroup_predicate(scope);
    format!(
        r#"
tracepoint:syscalls:sys_enter_open {predicate}
{{
  printf("open\t%d\t%s\t%s\n", pid, comm, str(args->filename));
}}

tracepoint:syscalls:sys_enter_openat {predicate}
{{
  printf("openat\t%d\t%s\t%s\n", pid, comm, str(args->filename));
}}

tracepoint:syscalls:sys_enter_openat2 {predicate}
{{
  printf("openat2\t%d\t%s\t%s\n", pid, comm, str(args->filename));
}}
"#
    )
}

fn cgroup_predicate(scope: &ScopeMetadata) -> String {
    format!(
        r#"/cgroup == cgroupid("{}")/"#,
        escape_bpftrace_string(&scope.host_cgroup_path)
    )
}

fn escape_bpftrace_string(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

fn wait_for_bpftrace_ready(container_name: &str) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        let pid = container_pid(container_name)?;
        if pid > 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    bail!("timed out waiting for eBPF collector readiness")
}

fn open_append_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn parse_exec_record(line: &str, scope: &ScopeMetadata) -> Option<ExecEventRecord> {
    if line.is_empty() || line.starts_with("Attaching ") {
        return None;
    }

    let mut parts = line.splitn(3, '\t');
    let observed_pid = parts.next()?.parse::<i32>().ok()?;
    let process_name = parts.next()?.to_string();
    let filename = parts.next()?.to_string();
    let observed_ppid = read_ppid(observed_pid).unwrap_or_default();

    if !process_in_scope(observed_pid, &scope.pid_namespace) {
        return None;
    }

    let cmdline = read_cmdline(observed_pid).unwrap_or_else(|| filename.clone());
    let process_chain = build_process_chain(observed_pid);
    let cgroup_paths = read_cgroup_paths(observed_pid).unwrap_or_default();
    let env_findings = read_env_findings(observed_pid);

    Some(ExecEventRecord {
        timestamp_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        event: "process_exec",
        container_name: scope.container_name.clone(),
        container_pid: scope.container_pid,
        observed_pid,
        observed_ppid,
        process_name,
        filename,
        cmdline,
        process_chain,
        cgroup_paths,
        pid_namespace: scope.pid_namespace.clone(),
        collector: "bpftrace_exec",
        env_findings,
    })
}

fn parse_connect_record(line: &str, scope: &ScopeMetadata) -> Option<ConnectEventRecord> {
    if line.is_empty() || line.starts_with("Attaching ") {
        return None;
    }

    let mut parts = line.splitn(3, '\t');
    let observed_pid = parts.next()?.parse::<i32>().ok()?;
    let process_name = parts.next()?.to_string();
    let socket_fd = parts.next()?.parse::<i32>().ok()?;
    let observed_ppid = read_ppid(observed_pid).unwrap_or_default();

    if !process_in_scope(observed_pid, &scope.pid_namespace) {
        return None;
    }

    let cmdline = read_cmdline(observed_pid).unwrap_or_else(|| process_name.clone());
    let process_chain = build_process_chain(observed_pid);
    let cgroup_paths = read_cgroup_paths(observed_pid).unwrap_or_default();
    let mut destinations = collect_socket_destinations_with_retry(observed_pid, socket_fd);
    if destinations.is_empty() {
        destinations.push(format!("unresolved-fd:{socket_fd}"));
    }

    Some(ConnectEventRecord {
        timestamp_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        event: "network_connect",
        container_name: scope.container_name.clone(),
        container_pid: scope.container_pid,
        observed_pid,
        observed_ppid,
        process_name,
        socket_fd,
        cmdline,
        process_chain,
        destinations,
        cgroup_paths,
        pid_namespace: scope.pid_namespace.clone(),
        collector: "bpftrace_connect",
    })
}

fn collect_socket_destinations_with_retry(pid: i32, socket_fd: i32) -> Vec<String> {
    for attempt in 0..5 {
        let destinations = collect_socket_destinations(pid, socket_fd);
        if !destinations.is_empty() {
            return destinations;
        }
        if attempt < 4 {
            thread::sleep(Duration::from_millis(10));
        }
    }
    Vec::new()
}

fn parse_file_record(line: &str, scope: &ScopeMetadata) -> Option<FileAccessEventRecord> {
    if line.is_empty() || line.starts_with("Attaching ") {
        return None;
    }

    let mut parts = line.splitn(4, '\t');
    let operation = parts.next()?.to_string();
    let observed_pid = parts.next()?.parse::<i32>().ok()?;
    let process_name = parts.next()?.to_string();
    let raw_path = parts.next()?.to_string();

    if !process_in_scope(observed_pid, &scope.pid_namespace) {
        return None;
    }

    let observed_ppid = read_ppid(observed_pid).unwrap_or_default();
    let observed_path = resolve_open_path(observed_pid, &raw_path).unwrap_or_else(|| raw_path.clone());
    let cmdline = read_cmdline(observed_pid).unwrap_or_else(|| process_name.clone());
    if is_internal_agentfence_process(&process_name, &cmdline) {
        return None;
    }
    let monitored = lookup_monitored_path(scope, &observed_path)?;
    let resolved_path = monitored.canonical_path.clone();
    let process_chain = build_process_chain(observed_pid);
    let cgroup_paths = read_cgroup_paths(observed_pid).unwrap_or_default();
    update_registry_access_metadata(scope, &monitored.registry_id, &resolved_path);

    Some(FileAccessEventRecord {
        timestamp_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        event: "credential_access",
        container_name: scope.container_name.clone(),
        container_pid: scope.container_pid,
        observed_pid,
        observed_ppid,
        process_name,
        raw_path,
        resolved_path,
        cmdline,
        process_chain,
        cgroup_paths,
        pid_namespace: scope.pid_namespace.clone(),
        collector: "bpftrace_file",
        operation,
        registry_id: monitored.registry_id,
        classification: monitored.classification,
        reason: monitored.reason,
    })
}

fn exec_audit_record(record: &ExecEventRecord) -> Value {
    let severity = if record.env_findings.is_empty() {
        "info"
    } else {
        "medium"
    };
    let env_variables = record
        .env_findings
        .iter()
        .map(|finding| finding.variable.as_str())
        .collect::<Vec<_>>();
    let reason = if record.env_findings.is_empty() {
        format!(
            "host eBPF exec collector observed process exec inside container {}",
            record.container_name
        )
    } else {
        format!(
            "host eBPF exec collector observed process exec with credential-like or dangerous environment variables inside container {}",
            record.container_name
        )
    };

    json!({
        "timestamp": utc_now_iso(),
        "event": "process_exec",
        "severity": severity,
        "shell": "host-ebpf",
        "pid": 0,
        "ppid": 0,
        "cwd": Value::Null,
        "agent": "host-ebpf",
        "command": record.cmdline,
        "variable": Value::Null,
        "old_value": Value::Null,
        "new_value": Value::Null,
        "classification": Value::Null,
        "discovery_method": "host_ebpf_exec",
        "registry_id": Value::Null,
        "path": record.filename,
        "operation": "execve",
        "process_name": record.process_name,
        "process_cmdline": record.cmdline,
        "observed_pid": record.observed_pid.to_string(),
        "observed_ppid": record.observed_ppid.to_string(),
        "process_chain": record.process_chain,
        "destination": Value::Null,
        "destination_port": Value::Null,
        "protocol": Value::Null,
        "active_credential_count": record.env_findings.len(),
        "matched_registry_ids": env_variables.join(","),
        "verdict": "observed",
        "env_findings": record.env_findings,
        "reason": reason,
    })
}

fn connect_audit_record(record: &ConnectEventRecord) -> Value {
    let primary_destination = record.destinations.first().cloned().unwrap_or_default();
    let (destination, destination_port) = split_destination(&primary_destination);
    json!({
        "timestamp": utc_now_iso(),
        "event": "network_egress",
        "severity": "info",
        "shell": "host-ebpf",
        "pid": 0,
        "ppid": 0,
        "cwd": Value::Null,
        "agent": "host-ebpf",
        "command": record.cmdline,
        "variable": Value::Null,
        "old_value": Value::Null,
        "new_value": Value::Null,
        "classification": Value::Null,
        "discovery_method": "host_ebpf_connect",
        "registry_id": Value::Null,
        "path": Value::Null,
        "operation": "connect",
        "process_name": record.process_name,
        "process_cmdline": record.cmdline,
        "observed_pid": record.observed_pid.to_string(),
        "observed_ppid": record.observed_ppid.to_string(),
        "process_chain": record.process_chain,
        "destination": destination,
        "destination_port": destination_port,
        "protocol": "tcp",
        "active_credential_count": Value::Null,
        "matched_registry_ids": Value::Null,
        "verdict": "observed",
        "reason": format!(
            "host eBPF connect collector observed outbound connect inside container {}; destinations={}",
            record.container_name,
            record.destinations.join(",")
        ),
    })
}

fn record_file_access_for_correlation(record: &FileAccessEventRecord, _scope: &ScopeMetadata) {
    let recent = RECENT_CREDENTIAL_ACCESSES.get_or_init(|| Mutex::new(Vec::new()));
    let Ok(mut recent) = recent.lock() else {
        return;
    };
    prune_recent_accesses(&mut recent, record.timestamp_unix_ms);
    if recent.iter().any(|access| {
        access.observed_pid == record.observed_pid
            && access.path == record.resolved_path
            && access.registry_id == record.registry_id
            && record.timestamp_unix_ms.saturating_sub(access.timestamp_unix_ms) <= 1_000
    }) {
        return;
    }
    recent.push(RecentCredentialAccess {
        timestamp_unix_ms: record.timestamp_unix_ms,
        observed_pid: record.observed_pid,
        path: record.resolved_path.clone(),
        registry_id: record.registry_id.clone(),
        classification: record.classification.clone(),
        process_name: record.process_name.clone(),
        cmdline: record.cmdline.clone(),
    });
}

fn correlate_connect_event(
    record: &ConnectEventRecord,
    scope: &ScopeMetadata,
    findings_file: Option<&mut File>,
) {
    let Some(findings_file) = findings_file else {
        return;
    };
    let recent = RECENT_CREDENTIAL_ACCESSES.get_or_init(|| Mutex::new(Vec::new()));
    let Ok(mut recent) = recent.lock() else {
        return;
    };
    prune_recent_accesses(&mut recent, record.timestamp_unix_ms);

    let mut matches = recent
        .iter()
        .filter(|access| credential_access_matches_connect(access, record))
        .cloned()
        .collect::<Vec<_>>();
    dedupe_credential_accesses(&mut matches);
    if matches.is_empty() {
        return;
    }

    if finding_was_recently_emitted(record, &matches) {
        return;
    }

    let finding = credential_egress_finding(record, scope, &matches);
    let _ = writeln!(
        findings_file,
        "{}",
        serde_json::to_string(&finding).unwrap_or_default()
    );
}

fn prune_recent_accesses(recent: &mut Vec<RecentCredentialAccess>, now_ms: u128) {
    recent.retain(|access| now_ms.saturating_sub(access.timestamp_unix_ms) <= CORRELATION_WINDOW_MS);
}

fn dedupe_credential_accesses(accesses: &mut Vec<RecentCredentialAccess>) {
    let mut seen = HashSet::new();
    accesses.retain(|access| {
        seen.insert(format!(
            "{}\t{}\t{}",
            access.observed_pid, access.path, access.registry_id
        ))
    });
}

fn finding_was_recently_emitted(
    record: &ConnectEventRecord,
    matches: &[RecentCredentialAccess],
) -> bool {
    let key = finding_key(record, matches);
    let recent = RECENT_FINDINGS.get_or_init(|| Mutex::new(VecDeque::new()));
    let Ok(mut recent) = recent.lock() else {
        return false;
    };
    while recent
        .front()
        .is_some_and(|entry| record.timestamp_unix_ms.saturating_sub(entry.timestamp_unix_ms) > 30_000)
    {
        recent.pop_front();
    }
    if recent.iter().any(|entry| entry.key == key) {
        return true;
    }
    recent.push_back(RecentFindingKey {
        timestamp_unix_ms: record.timestamp_unix_ms,
        key,
    });
    false
}

fn finding_key(record: &ConnectEventRecord, matches: &[RecentCredentialAccess]) -> String {
    let mut paths = matches
        .iter()
        .map(|access| access.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();
    format!(
        "{}\t{}\t{}",
        record.observed_pid,
        record.destinations.join(","),
        paths.join(",")
    )
}

fn credential_access_matches_connect(
    access: &RecentCredentialAccess,
    record: &ConnectEventRecord,
) -> bool {
    access.observed_pid == record.observed_pid
}

fn credential_egress_finding(
    record: &ConnectEventRecord,
    scope: &ScopeMetadata,
    matches: &[RecentCredentialAccess],
) -> Value {
    json!({
        "timestamp": utc_now_iso(),
        "timestamp_unix_ms": record.timestamp_unix_ms,
        "event": "credential_egress_correlation",
        "severity": "critical",
        "container_name": scope.container_name,
        "container_pid": scope.container_pid,
        "observed_pid": record.observed_pid,
        "observed_ppid": record.observed_ppid,
        "process_name": record.process_name,
        "process_cmdline": record.cmdline,
        "process_chain": record.process_chain,
        "destinations": record.destinations,
        "credential_accesses": matches.iter().map(|access| json!({
            "timestamp_unix_ms": access.timestamp_unix_ms,
            "observed_pid": access.observed_pid,
            "process_name": access.process_name,
            "process_cmdline": access.cmdline,
            "path": access.path,
            "registry_id": access.registry_id,
            "classification": access.classification,
        })).collect::<Vec<_>>(),
        "correlation_window_ms": CORRELATION_WINDOW_MS,
        "reason": "same process accessed credential material and then opened a network connection inside the correlation window",
    })
}

fn file_audit_record(record: &FileAccessEventRecord) -> Value {
    json!({
        "timestamp": utc_now_iso(),
        "event": "credential_access",
        "severity": "info",
        "shell": "host-ebpf",
        "pid": 0,
        "ppid": 0,
        "cwd": Value::Null,
        "agent": "host-ebpf",
        "command": record.cmdline,
        "variable": Value::Null,
        "old_value": Value::Null,
        "new_value": Value::Null,
        "classification": record.classification,
        "discovery_method": "host_ebpf_file",
        "registry_id": record.registry_id,
        "path": record.resolved_path,
        "operation": record.operation,
        "process_name": record.process_name,
        "process_cmdline": record.cmdline,
        "observed_pid": record.observed_pid.to_string(),
        "observed_ppid": record.observed_ppid.to_string(),
        "process_chain": record.process_chain,
        "destination": Value::Null,
        "destination_port": Value::Null,
        "protocol": Value::Null,
        "active_credential_count": Value::Null,
        "matched_registry_ids": Value::Null,
        "verdict": "observed",
        "reason": record.reason,
    })
}

fn utc_now_iso() -> String {
    format_system_time_iso(SystemTime::now())
}

fn format_system_time_iso(now: SystemTime) -> String {
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = duration.as_secs() as i64;
    let nanos = duration.subsec_nanos();
    let datetime = chrono_like_utc(seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}+00:00",
        datetime.year,
        datetime.month,
        datetime.day,
        datetime.hour,
        datetime.minute,
        datetime.second,
        nanos
    )
}

struct SimpleUtcDateTime {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

fn chrono_like_utc(mut timestamp: i64) -> SimpleUtcDateTime {
    let second = timestamp.rem_euclid(60) as u32;
    timestamp = (timestamp - second as i64) / 60;
    let minute = timestamp.rem_euclid(60) as u32;
    timestamp = (timestamp - minute as i64) / 60;
    let hour = timestamp.rem_euclid(24) as u32;
    let days = (timestamp - hour as i64) / 24;
    let (year, month, day) = civil_from_days(days);
    SimpleUtcDateTime { year, month, day, hour, minute, second }
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn split_destination(value: &str) -> (Value, Value) {
    if let Some((host, port)) = value.rsplit_once(':') {
        (json!(host), json!(port))
    } else {
        (Value::Null, Value::Null)
    }
}

fn process_in_scope(pid: i32, target_pid_namespace: &str) -> bool {
    fs::read_link(format!("/proc/{pid}/ns/pid"))
        .map(|link| link.to_string_lossy() == target_pid_namespace)
        .unwrap_or(false)
}

struct MonitoredPath {
    registry_id: String,
    classification: String,
    reason: String,
    canonical_path: String,
}

fn resolve_open_path(pid: i32, raw_path: &str) -> Option<String> {
    if raw_path.is_empty() {
        return None;
    }
    if raw_path.starts_with('/') {
        return Some(raw_path.to_string());
    }

    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
    Some(cwd.join(raw_path).to_string_lossy().to_string())
}

fn lookup_monitored_path(scope: &ScopeMetadata, path: &str) -> Option<MonitoredPath> {
    if path.starts_with(MOUNTED_CREDENTIAL_PREFIXES[0]) {
        return Some(MonitoredPath {
            registry_id: format!("file::{path}"),
            classification: "Mounted Credential File".to_string(),
            reason: "host eBPF file collector observed mounted credential access".to_string(),
            canonical_path: path.to_string(),
        });
    }
    if path.starts_with(MOUNTED_CREDENTIAL_PREFIXES[1]) {
        return Some(MonitoredPath {
            registry_id: format!("file::{path}"),
            classification: "SSH Private Key".to_string(),
            reason: "host eBPF file collector observed mounted SSH credential access".to_string(),
            canonical_path: path.to_string(),
        });
    }

    let registry = load_registry(scope).ok()?;
    let credentials = registry.get("credentials")?.as_array()?;
    for item in credentials {
        let item_path = item.get("path")?.as_str()?;
        if !workspace_paths_equivalent(item_path, path) {
            continue;
        }
        let classification = item
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("Workspace Credential File")
            .to_string();
        let registry_id = item
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("file::{path}"));
        return Some(MonitoredPath {
            registry_id,
            classification,
            reason: "host eBPF file collector observed workspace credential file access".to_string(),
            canonical_path: item_path.to_string(),
        });
    }

    None
}

fn workspace_paths_equivalent(registered_path: &str, observed_path: &str) -> bool {
    if registered_path == observed_path {
        return true;
    }

    let Some(alias_suffix) = observed_path.strip_prefix("/workspace/") else {
        return false;
    };
    registered_path
        .strip_prefix('/')
        .and_then(|registered| registered.split_once('/'))
        .map(|(_, registered_suffix)| registered_suffix == alias_suffix)
        .unwrap_or(false)
}

fn load_registry(scope: &ScopeMetadata) -> Result<Value> {
    let path_buf = PathBuf::from(&scope.host_logs_dir).join("registry.json");
    let path = path_buf.as_path();
    if !path.exists() {
        return Ok(json!({ "credentials": [] }));
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if content.trim().is_empty() {
        return Ok(json!({ "credentials": [] }));
    }

    serde_json::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
}

fn update_registry_access_metadata(scope: &ScopeMetadata, registry_id: &str, path: &str) {
    let registry_path = PathBuf::from(&scope.host_logs_dir).join("registry.json");
    let Ok(mut registry) = load_registry(scope) else {
        return;
    };
    let Some(credentials) = registry.get_mut("credentials").and_then(Value::as_array_mut) else {
        return;
    };

    let mut changed = false;
    for item in credentials {
        let item_id = item.get("id").and_then(Value::as_str);
        let item_path = item.get("path").and_then(Value::as_str);
        if item_id != Some(registry_id) && item_path != Some(path) {
            continue;
        }

        let access_count = item.get("access_count").and_then(Value::as_u64).unwrap_or(0) + 1;
        item["access_count"] = json!(access_count);
        item["last_accessed_at"] = json!(utc_now_iso());
        changed = true;
        break;
    }

    if changed {
        let _ = fs::write(
            registry_path,
            serde_json::to_string_pretty(&registry).unwrap_or_default() + "\n",
        );
    }
}

fn read_cmdline(pid: i32) -> Option<String> {
    let content = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let rendered = content
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8_lossy(segment).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if rendered.is_empty() {
        None
    } else {
        Some(rendered)
    }
}

fn read_env_findings(pid: i32) -> Vec<EnvFinding> {
    let content = match fs::read(format!("/proc/{pid}/environ")) {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for segment in content.split(|byte| *byte == 0).filter(|segment| !segment.is_empty()) {
        let Some((name, value)) = split_env_assignment(segment) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if !is_credential_env_name(&name) && !is_dangerous_env_name(&name) {
            continue;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        findings.push(EnvFinding {
            classification: classify_env_name(&name).to_string(),
            value_preview: redact_env_value(&value),
            variable: name,
        });
    }
    findings
}

fn split_env_assignment(bytes: &[u8]) -> Option<(String, String)> {
    let index = bytes.iter().position(|byte| *byte == b'=')?;
    let name = String::from_utf8_lossy(&bytes[..index]).to_string();
    let value = String::from_utf8_lossy(&bytes[index + 1..]).to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, value))
}

fn is_credential_env_name(name: &str) -> bool {
    matches!(
        name,
        "AWS_SECRET_ACCESS_KEY"
            | "AWS_ACCESS_KEY_ID"
            | "GH_TOKEN"
            | "GITHUB_TOKEN"
            | "GITHUB_PAT"
            | "OPENAI_API_KEY"
            | "ANTHROPIC_API_KEY"
            | "ANTHROPIC_AUTH_TOKEN"
            | "SPLUNK_HEC_TOKEN"
            | "SPLUNK_PASSWORD"
    ) || name.ends_with("_TOKEN")
        || name.ends_with("_KEY")
        || name.ends_with("_SECRET")
        || name.ends_with("_PASSWORD")
        || name.ends_with("_CREDENTIAL")
        || name.ends_with("_API_KEY")
}

fn is_dangerous_env_name(name: &str) -> bool {
    matches!(
        name,
        "PAGER"
            | "GIT_ASKPASS"
            | "EDITOR"
            | "VISUAL"
            | "LD_PRELOAD"
            | "PYTHONWARNINGS"
            | "BROWSER"
            | "PERL5OPT"
            | "NODE_OPTIONS"
            | "BASH_ENV"
            | "ENV"
            | "PROMPT_COMMAND"
            | "GIT_CONFIG_GLOBAL"
            | "CURL_HOME"
            | "NPM_CONFIG_REGISTRY"
            | "PIP_INDEX_URL"
    )
}

fn classify_env_name(name: &str) -> &'static str {
    match name {
        "AWS_SECRET_ACCESS_KEY" => "AWS Secret Access Key",
        "AWS_ACCESS_KEY_ID" => "AWS Access Key ID",
        "GH_TOKEN" | "GITHUB_TOKEN" | "GITHUB_PAT" => "GitHub Token",
        "OPENAI_API_KEY" => "OpenAI API Key",
        "ANTHROPIC_API_KEY" | "ANTHROPIC_AUTH_TOKEN" => "Anthropic Credential",
        "SPLUNK_HEC_TOKEN" => "Splunk HEC Token",
        "SPLUNK_PASSWORD" => "Splunk Password",
        "LD_PRELOAD" | "BASH_ENV" | "ENV" | "NODE_OPTIONS" | "PERL5OPT" => "Dangerous Execution Environment Variable",
        _ if name.ends_with("_PASSWORD") => "Generic Password",
        _ if name.ends_with("_API_KEY") => "Generic API Key",
        _ if name.ends_with("_TOKEN") => "Generic Token",
        _ if name.ends_with("_SECRET") || name.ends_with("_KEY") || name.ends_with("_CREDENTIAL") => "Generic Secret",
        _ => "Dangerous Environment Variable",
    }
}

fn redact_env_value(value: &str) -> String {
    let length = value.chars().count();
    if length <= 4 {
        return format!("REDACTED(len={length})");
    }
    let prefix = value.chars().take(4).collect::<String>();
    format!("{prefix}...(redacted,len={length})")
}

fn read_ppid(pid: i32) -> Option<i32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let closing = stat.rfind(')')?;
    let rest = stat.get(closing + 2..)?;
    let mut parts = rest.split_whitespace();
    let _state = parts.next()?;
    parts.next()?.parse::<i32>().ok()
}

fn is_internal_agentfence_process(process_name: &str, cmdline: &str) -> bool {
    let normalized_name = process_name.rsplit('/').next().unwrap_or(process_name);
    if normalized_name == "inotifywait" {
        return true;
    }

    [
        "agentfence-file-watcher",
        "agentfence-workspace-watcher",
        "agentfence-network-watcher",
        "agentfence-audit",
        "agentfence-registry",
        "workspace_watcher.py",
        "file_watcher.py",
        "network_watcher.py",
        "audit_log.py",
        "registry_update.py",
    ]
    .iter()
    .any(|needle| cmdline.contains(needle))
}

fn build_process_chain(pid: i32) -> String {
    let mut chain = Vec::new();
    let mut current = pid;
    let mut seen = HashSet::new();
    while current > 0 && seen.insert(current) {
        let proc_dir = PathBuf::from(format!("/proc/{current}"));
        let Ok(comm) = fs::read_to_string(proc_dir.join("comm")) else {
            break;
        };
        let Ok(stat) = fs::read_to_string(proc_dir.join("stat")) else {
            break;
        };
        let parts: Vec<&str> = stat.split_whitespace().collect();
        let parent = parts
            .get(3)
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(0);
        chain.push(format!("{}(pid={},ppid={})", comm.trim(), current, parent));
        if parent <= 0 || parent == current {
            break;
        }
        current = parent;
    }
    chain.join(" <- ")
}

fn collect_socket_destinations(pid: i32, socket_fd: i32) -> Vec<String> {
    for _ in 0..10 {
        if let Some(inode) = read_socket_inode(pid, socket_fd) {
            let mut destinations = Vec::new();
            for (filename, ipv6) in [("tcp", false), ("tcp6", true), ("udp", false), ("udp6", true)] {
                if let Some(destination) = read_proc_net_destination_for_inode(pid, filename, ipv6, &inode) {
                    destinations.push(destination);
                }
            }
            destinations.sort();
            destinations.dedup();
            if !destinations.is_empty() {
                return destinations;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    Vec::new()
}

fn read_socket_inode(pid: i32, socket_fd: i32) -> Option<String> {
    let link = fs::read_link(format!("/proc/{pid}/fd/{socket_fd}")).ok()?;
    let link = link.to_string_lossy();
    link.strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .map(str::to_string)
}

fn read_proc_net_destination_for_inode(
    pid: i32,
    filename: &str,
    ipv6: bool,
    inode: &str,
) -> Option<String> {
    let path = format!("/proc/{pid}/net/{filename}");
    let contents = fs::read_to_string(path).ok()?;

    for line in contents.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 10 || columns[9] != inode {
            continue;
        }
        let remote = columns[2];
        let state = columns[3];
        if state == "0A" {
            continue;
        }
        let Some((address_hex, port_hex)) = remote.split_once(':') else {
            continue;
        };
        let Some(port) = parse_port_hex(port_hex) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let address = if ipv6 {
            parse_ipv6_hex(address_hex)
        } else {
            parse_ipv4_hex(address_hex)
        };
        let Some(address) = address else {
            continue;
        };
        return Some(format!("{address}:{port}"));
    }
    None
}

fn parse_port_hex(value: &str) -> Option<u16> {
    u16::from_str_radix(value, 16).ok()
}

fn parse_ipv4_hex(value: &str) -> Option<String> {
    if value.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(value, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(std::net::Ipv4Addr::from(bytes).to_string())
}

fn parse_ipv6_hex(value: &str) -> Option<String> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        bytes[index] = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(std::net::Ipv6Addr::from(bytes).to_string())
}
