# AgentFence

Minimal implementation of the AgentFence container launcher described in `AgentFence.md`.

Linux is the primary supported host platform today. macOS can use the container wrapping flow, but the host-side eBPF collectors in this repo are Linux-only.

## Current scope

- Rust CLI to build and run the AgentFence container
- Containerized execution boundary for the agent workload
- Controlled project, credential, and audit-log mounts
- Explicit host environment variable passthrough
- Minimal container image with a development shell entrypoint
- Bash-based audit logging for dangerous environment variable mutations
- Automatic discovery of credential-like environment variables
- JSONL audit log at `/var/log/agentfence/audit.jsonl`
- Live registry at `/var/log/agentfence/registry.json`
- File access auditing for mounted credentials under `/agentfence/creds` and `/agentfence/ssh`
- Workspace credential discovery and auditing under the mounted project path
- Outbound TCP connection logging
- Experimental host-side eBPF collectors for stronger exec, network, and file-access visibility

## Security Model

AgentFence has two separate roles:

- The container is the isolation boundary. It limits what the agent can see and use to the mounted workspace, selected credentials, and session logs.
- The host is where stronger observation belongs. The optional eBPF collectors watch the container from outside the container boundary.

The current in-container watchers are useful session telemetry, but they are not the long-term source of truth for comprehensive credential coverage. `agentfence run` now chooses monitoring automatically by default and clearly reports when strong host monitoring is unavailable.

## Platform Support

- **Linux host**: full feature set, including host-side eBPF exec, network, and file collectors via a privileged sudo helper.
- **macOS host**: strong monitoring runs through a "Docker-in-VM helper" backend that launches the eBPF collectors as a privileged sidecar container inside the local Docker VM. The same code path works with **Docker Desktop**, **Colima**, **OrbStack**, and **Rancher Desktop** — the provider is auto-detected from `docker context inspect` and reported in the startup notice.
- `--monitor auto` (the default) is lenient on macOS: if the helper container fails to start or crashes during startup, AgentFence prints the helper logs to stderr and continues with container-local telemetry. `--monitor strong` is strict and hard-errors if the helper can't run.
- **Container images are platform-specific.** When cloning the repo to a host with a different CPU architecture (e.g. Linux x86_64 → macOS aarch64), run `agentfence build-image` again on the new host before `agentfence run`. The build command prints the host architecture so you can see what was built.

## Install

### Quick install (prebuilt binary)

macOS (Intel + Apple Silicon) and Linux (x86_64 + arm64) binaries are published with each tagged release:

```bash
curl -fsSL https://raw.githubusercontent.com/Antonlovesdnb/AgentFence/main/install.sh | sh
```

The installer auto-detects your OS/arch, verifies the SHA256, and installs to `/usr/local/bin` (falling back to `~/.local/bin`). Pin a version with `AGENTFENCE_VERSION=v0.1.0` or override the install dir with `AGENTFENCE_BIN_DIR=...`.

You still need a container runtime — Docker Desktop, Colima, OrbStack, or Rancher Desktop — running before `agentfence run`.

### From source

```bash
cargo install --path .
```

Requires Rust ≥ 1.85 (edition 2024).

## Usage

Build the images from source:

```bash
agentfence build-image
```

Run a project in the container:

```bash
agentfence run ~/projects/my-app
```

Run the current directory with the default wrapped-session flow:

```bash
agentfence run
```

Run a Claude or Codex-style wrapped session with automatic host env passthrough inference:

```bash
agentfence run ~/projects/my-app --agent claude-code
```

```bash
agentfence run ~/projects/my-app --agent codex
```

When `--mount-env` is omitted, AgentFence now auto-passes through matching host credential env vars based on the selected agent and credential env names referenced by the project.

For Claude-style local auth, AgentFence also auto-mounts host auth files from `~/.claude` when `--agent claude-code` is selected. That means a project can use Claude inside the container without requiring `ANTHROPIC_API_KEY` in the host environment if Claude is already authenticated locally via `~/.claude/.credentials.json`.

Mount specific credentials:

```bash
agentfence run \
  ~/projects/my-app \
  --mount-ssh ~/.ssh/lab_key \
  --mount-cred ~/secrets/service-account.json \
  --mount-env GH_TOKEN
```

Mounted credential files are exposed inside the container under `/agentfence/ssh` and `/agentfence/creds`. The project itself is mounted at a path derived from the project folder name, such as `/my-app` for `~/projects/my-app`; `/workspace` remains as a compatibility bind-mount alias.

Use host networking when the wrapped agent must reach the same host-only lab, VPN, or local service routes that the host can reach:

```bash
agentfence run ~/projects/my-app --network host
```

`--network bridge` is the default and keeps Docker's normal network isolation. `--network host` gives the container the host network namespace, which improves parity with the host but weakens network isolation.

Control monitoring behavior explicitly when needed:

```bash
agentfence run ~/projects/my-app --monitor auto
```

```bash
agentfence run ~/projects/my-app --monitor basic
```

```bash
agentfence run ~/projects/my-app --monitor strong
```

`auto` is the default. When strong monitoring is not available on the current host, AgentFence will say so clearly in the console and continue with container-local telemetry when appropriate.

## Smoke test

Run the end-to-end launcher smoke test:

```bash
make test-launch
```

This builds the image, launches the container with a temporary credential file and env var, verifies the expected mount points from inside the container, and confirms audit-log volume writes reach the host.

Run the minimal audit test:

```bash
make test-audit
```

This launches a shell inside the container, mutates `PAGER`, runs `printenv`, and prints the resulting `audit.jsonl` entries.

Run the env credential discovery test:

```bash
make test-discovery
```

This exports `OPENAI_API_KEY` and `GH_TOKEN` inside the container, then prints both the live registry and the audit events created by discovery.

Run the mounted credential access test:

```bash
make test-file-access
```

This mounts a temporary credential file, reads it inside the container, and verifies that both the registry and `audit.jsonl` record the access.

Run the workspace discovery and access test:

```bash
make test-workspace
```

Run the outbound network watcher test:

```bash
make test-network
```

Linux-only low-level collector flags still exist for debugging, but normal usage should prefer `--monitor auto|basic|strong`:

```bash
agentfence run . --ebpf-exec --ebpf-net --ebpf-file
```

These flags currently use a small privileged helper launched via `sudo` because they rely on `bpftrace` from the host to observe the container. The main launcher remains unprivileged. When `--ebpf-file` is enabled, the in-container file access audit emitters stay available for discovery and registry updates, but file-access events themselves are emitted by the host eBPF collector to avoid duplicate audit records.

You can manually test env credential discovery with:

```bash
agentfence run .
```

Then inside the container:

```bash
export OPENAI_API_KEY=demo-key
export GH_TOKEN=demo-token
cat /var/log/agentfence/registry.json
cat /var/log/agentfence/audit.jsonl
```

## Minimal audit behavior

Interactive shells inside the container now log:

- dangerous environment variable mutations such as `PAGER`, `LD_PRELOAD`, `GIT_ASKPASS`, `PROMPT_COMMAND`
- environment enumeration commands such as `env`, `printenv`, and `set`
- credential discovery events for variable names like `OPENAI_API_KEY`, `GH_TOKEN`, `*_TOKEN`, `*_SECRET`, and `*_PASSWORD`
- access events for mounted credential files under `/agentfence/creds` and `/agentfence/ssh`
- discovery and access events for credential-bearing files inside the mounted project path
- outbound TCP connection events with destination and process context

The events are written to:

```bash
/var/log/agentfence/audit.jsonl
```

Discovered env credentials are persisted to:

```bash
/var/log/agentfence/registry.json
```

## Correlation

AgentFence correlates credential-access events with subsequent network connects from the same process and writes high-severity findings to:

```bash
/var/log/agentfence/findings.jsonl
```

These findings are audit signals. AgentFence no longer attempts to terminate or block the process automatically.
