# CLAUDE.md

Project instructions for any Claude session working in this repo. Read this before making changes.

## What this is

AgentFence is a Rust CLI that wraps AI coding agents (Claude Code, Codex, Cursor, Windsurf, Copilot) in a Docker container. It audits credential access, environment-variable mutations, and outbound network egress during agent runs. The full spec lives in `AgentFence.md`; this file is a fast-orientation cheat sheet.

## Threat model — read this first

AgentFence is designed to provide **visibility into opportunistic credential exfiltration**, not to defend against determined adversaries. This narrower goal is load-bearing — over-engineering against sophisticated attacks is the wrong direction.

**In scope:**
- Malicious npm/pip postinstall scripts and generic credential stealers
- Environment-variable poisoning (CVE-2026-22708)
- MCP config tampering via prompt injection (CVE-2025-54135/54136)
- Prompt injection that runs `curl`/`wget` to exfiltrate credentials

**Out of scope:**
- Determined adversaries who specifically target the monitoring stack
- The agent encoding credentials into its own API channel (e.g., to `api.anthropic.com`)
- Sophisticated multi-step exfil chains

**AgentFence is observation-only at runtime.** The only "enforcement" is the static container boundary itself (Docker namespaces, `--cap-drop ALL`, `--security-opt no-new-privileges`). AgentFence does not block, terminate, or interfere with the agent at runtime — no `iptables` rules, no process kills, no `docker stop` on findings. Every layer (in-container watchers, host eBPF collectors) is audit/telemetry. `--monitor strong` gives *stronger observation* via Linux host-side eBPF, **not** dynamic enforcement. Don't add blocking — Codex removed it deliberately and `README.md` + `AgentFence.md` say so explicitly.

## Architecture (3 layers)

**1. Host CLI (Rust, `src/`)** — orchestration, mounts, agent detection, session lifecycle
- `main.rs` — entry
- `cli.rs` — clap subcommands: `build-image`, `run`, `audit`, hidden `collect-ebpf`
- `container.rs` — Docker orchestration, mount setup, agent auth handling (largest file)
- `discovery.rs` — host credential scanning before launch
- `monitor.rs` — backend selection (`ContainerLocal` / `LinuxHostEbpf` / `DockerDesktopVm`)
- `ebpf.rs` — bpftrace exec/net/file collectors and credential-access correlation
- `agent_runtime.rs` — Claude/Codex/Cursor/Windsurf/Copilot auto-detection
- `audit.rs` — `agentfence audit` report generator
- `config.rs` — `.agentfence.toml` loader

**2. Container (`container/`)** — in-container watchers
- `Dockerfile`, `Collector.Dockerfile`, `entrypoint.sh`, `bashrc`
- `bash_env.sh` — DEBUG trap + PROMPT_COMMAND hooks for env-var monitoring
- `file_watcher.py` — inotify on `/agentfence/creds/` and `/agentfence/ssh/`
- `workspace_watcher.py` — inotify + scan of mounted project for `.env`/keys
- `network_watcher.py` — `ss -tupnH` polling every 50ms with credential correlation
- `audit_log.py`, `registry_update.py` — legacy CLI audit writers; watchers now write inline

**3. Optional host eBPF** — bpftrace scripts via `sudo` helper, cgroupid-scoped, Linux + root + `--monitor strong` only

Key paths:
- Logs: `~/.agentfence/logs/session-{timestamp}/{audit,registry,findings}.jsonl`
- Runtime auth dirs: `~/.agentfence/runtime/{session-nonce}/` (0o700)
- Container HOME: `/agentfence/home` (bind-mounted from host runtime dir, 0o700)

## Build / run / test

```bash
cargo install --path .                                          # install agentfence binary
agentfence build-image                                          # build image (skipped if it exists)
agentfence run ~/projects/my-app                                # default invocation
agentfence run . --mount ~/.ssh/key --mount GH_TOKEN            # --mount auto-detects type
agentfence run . --network host --monitor strong                # host net + Linux eBPF
agentfence audit [SESSION]                                      # review session logs

make build | test-launch | test-audit | test-discovery | test-file-access | test-workspace | test-network
```

`.env.agentfence-test` holds test env vars used by `make test-*` scripts.

## Key conventions

- **CLI surface is intentionally minimal.** Anton wants ~3 visible flags. Hide power-user/legacy flags with `#[arg(hide = true)]` rather than removing them. New features should auto-detect or live in `.agentfence.toml` before getting a flag.
- **Codex writes, Claude reviews, Codex applies fixes.** Don't assume files match prior memory — re-read before acting. Review docs are versioned (`SECURITY_REVIEW.md` → `_4.md`); new passes reference prior IDs (S1–S15, N1–N12).
- **`AgentFence.md` is intent, not a contract.** Implementation diverges in places — check the code, not the spec.
- **Dangerous-var lists are duplicated** in `container/bash_env.sh` and `src/ebpf.rs` (finding N5). Keep both in sync when editing either.
- **Two backends, one CLI.** `monitor.rs` selects `ContainerLocal` / `LinuxHostEbpf` / `DockerDesktopVm` based on platform + `--monitor`. Don't add Linux-only logic outside `ebpf.rs`.
- **Container runs as host UID:GID** via `--user`. The host-side runtime dir is bind-mounted over `/agentfence/home` so the non-root container user has a writable 0o700 home.

## Gotchas

- **Bash hooks only fire for bash.** `sh`/`dash`/`python3`/`node -e` bypass env-var auditing entirely (finding S7, still open).
- **Network watcher polls `ss` every 50ms.** Sub-50ms `curl` exfiltration evades it (S6). UDP/DNS coverage is best-effort (S5).
- **Registry must be `{"credentials":[]}`, not `{}`.** Python handles either; Rust silently skips updates on `{}` (N9, fixed Pass 4).
- **`seed_workspace_trust` auto-accepts Claude's trust dialog** (S4, still open). When working on this code, don't make it more aggressive without an opt-out.
- **`PROMPT_COMMAND` is itself a watched dangerous var** but is also how AgentFence installs its hooks (S15). Edits must preserve the existing hook chain.
- **Double bind-mount** of the project dir at both the computed workspace path and `/workspace` when they differ (N8/N12). Produces duplicate inotify events.
- **macOS strong monitoring works on source installs, not prebuilt binaries** (validated 2026-04-09 on Colima 6.8.0-100-generic aarch64). The `DockerVmHelper` backend is end-to-end functional: provider auto-detect, privileged sidecar spawn with tracefs/debugfs bind-mounts, bpftrace probe attach, exec/connect/file event capture, credential-access registry updates. But the host's `build_image()` skips the collector image when `dev_source_root()` is `None`, and the GitHub release workflow doesn't publish the collector image to a registry. So prebuilt-binary installs on macOS can't use `--monitor strong` today — they fall back to `--monitor basic`. To use strong monitoring on macOS: `cargo install --path .` + `agentfence build-image`. Long-term fix is publishing `agentfence-collector` to GHCR so prebuilt-binary installs can `docker pull` it.

## Where to look next

- `AgentFence.md` — full spec & threat model
- `README.md` — quick-start
- `MEMORY.md` — consolidated findings snapshot from 4 review passes
- `SECURITY_REVIEW.md` → `SECURITY_REVIEW_4.md` — full review history
- `.agentfence.toml` — project-level config; loader at `src/config.rs`
