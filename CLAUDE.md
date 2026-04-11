# CLAUDE.md

Project instructions for any Claude session working in this repo. Read this before making changes.

## What this is

AgentFence is a Rust CLI that wraps AI coding agents in a Docker container. It audits credential access, environment-variable mutations, and outbound network egress during agent runs. **Validated end-to-end with Codex and Claude Code today.** Cursor / Windsurf / Copilot have scaffolded `Agent` enum variants and detection branches in `agent_runtime.rs` but are not exercised — the wrapped-session flow, auto-auth mounts, and session sync-back have only been tested for the two validated agents. Don't make claims about untested agents in user-facing copy. The full spec lives in `AgentFence.md`; this file is a fast-orientation cheat sheet.

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
- `agent_runtime.rs` — agent auto-detection (Codex + Claude Code validated; Cursor/Windsurf/Copilot scaffolded only)
- `audit.rs` — `agentfence audit` report generator
- `config.rs` — `.agentfence.toml` loader

**2. Container (`container/`)** — in-container watchers
- `Dockerfile`, `Collector.Dockerfile`, `entrypoint.sh`, `bashrc`
- `bash_env.sh` — DEBUG trap + PROMPT_COMMAND hooks for env-var monitoring
- `file_watcher.py` — inotify on `/agentfence/creds/` and `/agentfence/ssh/`
- `workspace_watcher.py` — inotify + scan of mounted project for `.env`/keys
- `network_watcher.py` — `ss -tupnH` polling every 50ms with credential correlation
- `audit_log.py`, `registry_update.py` — legacy CLI audit writers; watchers now write inline

**3. Host eBPF collectors** — bpftrace scripts, cgroupid-scoped
- **Linux:** via `sudo` helper running on the host kernel directly
- **macOS:** via privileged sidecar container inside the Docker VM (Colima/Docker Desktop/OrbStack/Rancher). Requires tracefs + debugfs bind-mounts (added 2026-04-09). Validated end-to-end on Colima 6.8.0-100-generic aarch64.
- Both paths require the collector image (`agentfence-collector:dev`), which is built from `Collector.Dockerfile`. Source installs build it via `agentfence build-image`; prebuilt-binary installs skip it (no source tree) and fall back to container-local telemetry.

Key paths:
- Session logs: `~/.agentfence/logs/session-{timestamp}/`
  - `audit.jsonl` — all events (JSONL, one object per line)
  - `registry.json` — live credential registry (seeded from host scan + updated at runtime)
  - `findings.jsonl` — credential-egress correlation findings
  - `ebpf_{exec,connect,file}.jsonl` — host eBPF collector events
  - `ebpf_*.stderr.log` — bpftrace stderr (empty = probes attached OK)
  - `ebpf_scope.json` — container scope metadata (cgroup, PID namespace, etc.)
- Host scan reports: `~/.agentfence/host-scans/session-{timestamp}.json` — credential path enumeration, host-only (NOT mounted into the container as of v0.1.8)
- Runtime auth dirs: `~/.agentfence/runtime/{session-nonce}/` (0o700, cleaned up after 6h)
- Container HOME: `/agentfence/home` (bind-mounted from host runtime dir, 0o700)

**Credential values are never logged.** Env var previews are redacted to 4 chars + length in `redact_env_value()` (`ebpf.rs`). The `host_scan.json` file lists credential PATHS only (no contents) and is relocated out of the container-visible mount before the agent starts.

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
- **Codex writes, Claude reviews, Codex applies fixes.** Don't assume files match prior memory — re-read before acting. Review docs are versioned (`SECURITY_REVIEW.md` → `_4.md`); new passes reference prior IDs (S1–S16, N1–N14).
- **`auto_auth_path_aliases` duplicates file lists** from `materialize_codex_auth_mounts` and `materialize_claude_auth_mounts`. When adding new auto-mounted files to either materialize function, also update `auto_auth_path_aliases` so the registry seed picks them up.
- **`AgentFence.md` is intent, not a contract.** Implementation diverges in places — check the code, not the spec.
- **Dangerous-var lists are duplicated** in `container/bash_env.sh` and `src/ebpf.rs` (finding N5). Keep both in sync when editing either.
- **Two backends, one CLI.** `monitor.rs` selects `ContainerLocal` / `LinuxHostEbpf` / `DockerDesktopVm` based on platform + `--monitor`. Don't add Linux-only logic outside `ebpf.rs`.
- **Container runs as host UID:GID** via `--user`. The host-side runtime dir is bind-mounted over `/agentfence/home` so the non-root container user has a writable 0o700 home.

## Gotchas

- **Bash hooks only fire for bash.** `sh`/`dash`/`python3`/`node -e` bypass env-var auditing entirely (finding S7, still open).
- **Network watcher polls `ss` every 50ms.** Sub-50ms `curl` exfiltration evades it (S6). UDP/DNS coverage is best-effort (S5).
- **Registry must be `{"credentials":[]}`, not `{}`.** Python handles either; Rust silently skips updates on `{}` (N9, fixed Pass 4).
- **`seed_workspace_trust` auto-accepts Claude's trust dialog** (S4, still open). When working on this code, don't make it more aggressive without an opt-out.
- **Project content must never control security posture.** Three rules:
  1. Env vars found by scanning project text are printed as recommendations but NOT auto-passed (a malicious repo could mention `AWS_SECRET_ACCESS_KEY` in its README). Only `GH_TOKEN`/`GITHUB_TOKEN` (hardcoded in `SAFE_AUTO_PASS_ENV_VARS`) and agent-specific hints are auto-passed.
  2. SSH keys are only auto-mounted from `~/.ssh/config` IdentityFile directives (user-controlled), not from project text or git remote heuristics.
  3. `.agentfence.toml` in the project can add mounts (printed visibly) but CANNOT override `network` or `monitor` — those are security posture changes that only come from CLI flags. A malicious repo could set `network = "host"` to bypass isolation or `monitor = "basic"` to disable strong monitoring. Use `--no-config` to skip project config entirely.
- **`PROMPT_COMMAND` is itself a watched dangerous var** but is also how AgentFence installs its hooks (S15). Edits must preserve the existing hook chain.
- **Double bind-mount** of the project dir at both the computed workspace path and `/workspace` when they differ (N8/N12). Produces duplicate inotify events.
- **macOS strong monitoring works on source installs, not prebuilt binaries** (validated 2026-04-09 on Colima 6.8.0-100-generic aarch64). The `DockerVmHelper` backend is end-to-end functional: provider auto-detect, privileged sidecar spawn with tracefs/debugfs bind-mounts, bpftrace probe attach, exec/connect/file event capture, credential-access registry updates. But the host's `build_image()` skips the collector image when `dev_source_root()` is `None`, and the GitHub release workflow doesn't publish the collector image to a registry. So prebuilt-binary installs on macOS can't use `--monitor strong` today — they fall back to `--monitor basic`. To use strong monitoring on macOS: `cargo install --path .` + `agentfence build-image`. Long-term fix is publishing `agentfence-collector` to GHCR so prebuilt-binary installs can `docker pull` it.

## Known security trade-offs

- **Writable audit trail.** The session logs dir is bind-mounted RW into the agent container because the Python watchers need write access to `audit.jsonl` and `registry.json`. A compromised agent could tamper with its own audit trail. The eBPF logs (`ebpf_*.jsonl`) are written by the helper container but share the same mount. Mitigation path: split into separate RO/RW mount paths, or add hash-chain integrity to the audit log.
- **host_scan.json is relocated out of the container mount** (v0.1.8+). Before v0.1.8 it was readable inside the container, which leaked the host's credential path enumeration to the agent.

## Where to look next

- `AgentFence.md` — full spec & threat model
- `README.md` — usage, log format, session review, known limitations
- `MEMORY.md` — consolidated findings snapshot from review passes + 2026-04-09 runtime validation
- `SECURITY_REVIEW.md` → `SECURITY_REVIEW_4.md` — full review history
- `.agentfence.toml` — project-level config; loader at `src/config.rs`
