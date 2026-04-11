use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::{
    audit,
    config,
    container::{Agent, NetworkMode, RunOptions, build_image, run_container},
    ebpf,
    monitor::MonitorMode,
};

#[derive(Debug, Parser)]
#[command(name = "agentfence", version, about = "Docker launcher for AgentFence sessions")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build the AgentFence container image.
    BuildImage(BuildImageArgs),
    /// Run an interactive AgentFence container around a project.
    Run(RunArgs),
    /// Review the audit log from a session.
    Audit(AuditArgs),
    #[command(hide = true)]
    CollectEbpf(CollectEbpfArgs),
}

#[derive(Debug, Args)]
struct BuildImageArgs {
    /// Docker image tag to build.
    #[arg(long, default_value = "agentfence:dev")]
    image: String,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Project directory to wrap. Defaults to the current directory.
    #[arg(value_name = "PATH", default_value = ".")]
    project: PathBuf,

    /// Mount a credential into the container. Accepts file paths (SSH keys,
    /// credential files) or environment variable names (e.g. GH_TOKEN).
    /// Type is auto-detected: uppercase names are env vars, paths under
    /// ~/.ssh/ or named id_* are SSH keys, everything else is a credential file.
    #[arg(long = "mount", value_name = "PATH_OR_ENV")]
    mounts: Vec<String>,

    /// Docker network namespace mode. Use `host` when lab/VPN routes must match the host.
    #[arg(long, value_enum)]
    network: Option<NetworkMode>,

    /// Monitoring level. Defaults to auto, which uses the strongest available
    /// monitoring for the current OS and falls back clearly when it is not
    /// available. Hidden because the default behavior is correct for almost
    /// all users; `--monitor basic` skips the helper container for faster
    /// startup, `--monitor strong` hard-errors if strong monitoring is
    /// unavailable (useful for CI).
    #[arg(long, value_enum, hide = true)]
    monitor: Option<MonitorMode>,

    /// Docker image tag to run.
    #[arg(long, default_value = "agentfence:dev", hide = true)]
    image: String,

    /// Force a docker build before launch.
    #[arg(long, hide = true)]
    build: bool,

    /// Override the detected agent runtime.
    #[arg(long, value_enum, hide = true)]
    agent: Option<Agent>,

    /// Mount an SSH credential file (legacy alias for --mount).
    #[arg(long = "mount-ssh", value_name = "PATH", hide = true)]
    ssh_mounts: Vec<PathBuf>,

    /// Mount a credential file (legacy alias for --mount).
    #[arg(long = "mount-cred", value_name = "PATH", hide = true)]
    cred_mounts: Vec<PathBuf>,

    /// Pass through an environment variable (legacy alias for --mount).
    #[arg(long = "mount-env", value_name = "NAME", hide = true)]
    env_vars: Vec<String>,

    /// Container name override.
    #[arg(long, hide = true)]
    name: Option<String>,

    /// Host directory for exported audit logs.
    #[arg(long, value_name = "PATH", hide = true)]
    logs_dir: Option<PathBuf>,

    /// Start the experimental host-side eBPF exec collector for this session.
    #[arg(long, hide = true)]
    ebpf_exec: bool,

    /// Start the experimental host-side eBPF connect collector for this session.
    #[arg(long, hide = true)]
    ebpf_net: bool,

    /// Start the experimental host-side eBPF file collector for credential access coverage.
    #[arg(long, hide = true)]
    ebpf_file: bool,

    /// Skip reading .agentfence.toml from the project directory.
    #[arg(long, hide = true)]
    no_config: bool,

    /// Trust and apply mounts from the project's .agentfence.toml. Without
    /// this flag, config mounts are printed as recommendations but not applied
    /// — the project repo is untrusted input and could request ~/.ssh/id_rsa.
    #[arg(long, hide = true)]
    trust_config: bool,

    /// Command to execute inside the container instead of the default shell.
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct AuditArgs {
    /// Path to a specific session log directory. Defaults to the most recent session.
    #[arg(value_name = "SESSION_DIR")]
    session: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CollectEbpfArgs {
    /// Container name to monitor from the host.
    #[arg(long, value_name = "NAME")]
    container_name: String,

    /// Host directory for exported audit logs.
    #[arg(long, value_name = "PATH")]
    logs_dir: PathBuf,

    /// Enable the host-side exec collector.
    #[arg(long)]
    exec: bool,

    /// Enable the host-side connect collector.
    #[arg(long)]
    net: bool,

    /// Enable the host-side file collector.
    #[arg(long)]
    file: bool,

}

enum MountKind {
    Ssh,
    Cred,
    Env,
}

fn classify_mount(value: &str) -> MountKind {
    if !value.contains('/') && !value.contains('\\') && !value.starts_with('.') && is_env_var_name(value) {
        return MountKind::Env;
    }

    let expanded = expand_tilde(value);
    let path_str = expanded.to_string_lossy();
    let file_name = expanded
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if path_str.contains("/.ssh/") || file_name.starts_with("id_") || file_name.ends_with("_key") {
        return MountKind::Ssh;
    }

    MountKind::Cred
}

fn is_env_var_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn expand_tilde(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(value)
}

fn add_mount(entry: &str, ssh: &mut Vec<PathBuf>, creds: &mut Vec<PathBuf>, envs: &mut Vec<String>) {
    match classify_mount(entry) {
        MountKind::Env => {
            if !envs.iter().any(|e| e == entry) {
                envs.push(entry.to_string());
            }
        }
        MountKind::Ssh => {
            let path = expand_tilde(entry);
            if !ssh.iter().any(|e| *e == path) {
                ssh.push(path);
            }
        }
        MountKind::Cred => {
            let path = expand_tilde(entry);
            if !creds.iter().any(|e| *e == path) {
                creds.push(path);
            }
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::BuildImage(args) => build_image(&args.image),
        Command::Audit(args) => audit::run_audit(args.session),
        Command::Run(args) => {
            let project_dir = &args.project;
            let project_config = if args.no_config {
                None
            } else {
                config::load_project_config(project_dir)
            };

            let (mut ssh_mounts, mut cred_mounts, mut env_vars) =
                (args.ssh_mounts, args.cred_mounts, args.env_vars);

            // Config file mounts are only applied with --trust-config. The
            // project repo is untrusted input — a malicious .agentfence.toml
            // could request mounts like ~/.ssh/id_rsa or ~/.aws/credentials.
            // Without --trust-config, mounts are printed as recommendations.
            if let Some(ref config) = project_config {
                if !config.mounts.is_empty() {
                    if args.trust_config {
                        for entry in &config.mounts {
                            add_mount(entry, &mut ssh_mounts, &mut cred_mounts, &mut env_vars);
                        }
                    } else {
                        println!(
                            "[AgentFence] Project config requests mounts: {}",
                            config.mounts.join(", ")
                        );
                        println!(
                            "[AgentFence] NOT applied (project config is untrusted). Use --trust-config or --mount on the CLI."
                        );
                    }
                }
            }

            // CLI --mount entries override / extend.
            for entry in &args.mounts {
                add_mount(entry, &mut ssh_mounts, &mut cred_mounts, &mut env_vars);
            }

            // Network and monitor: CLI flags only. Project config values are
            // intentionally ignored (printed as warnings in config.rs).
            let network_mode = args.network.unwrap_or(NetworkMode::Bridge);
            let monitor = args.monitor.unwrap_or(MonitorMode::Auto);

            let options = RunOptions {
                project_dir: args.project,
                image: args.image,
                build_image: args.build,
                agent: args.agent,
                ssh_mounts,
                cred_mounts,
                env_vars,
                container_name: args.name,
                logs_dir: args.logs_dir,
                network_mode,
                monitor,
                ebpf_exec: args.ebpf_exec,
                ebpf_net: args.ebpf_net,
                ebpf_file: args.ebpf_file,
                command: args.command,
            };

            run_container(options)
        }
        Command::CollectEbpf(args) => {
            ebpf::run_privileged_helper(
                &args.container_name,
                &args.logs_dir,
                args.exec,
                args.net,
                args.file,
            )
        }
    }
}
