# AGENTS.md

Instructions for AI coding agents working in this repo. If you're a human, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick orientation

AgentFence is a Rust CLI (~2500 LOC) that wraps AI coding agents in a Docker container and audits credential access via eBPF. Read these before making changes:

- **[CLAUDE.md](CLAUDE.md)** — detailed project conventions, architecture, gotchas, and trust boundary rules. This is the primary instruction file.
- **[README.md](README.md)** — what the tool does, how it works, install, usage, session log format, known limitations.
- **[docs/credential-scanning.md](docs/credential-scanning.md)** — every credential path and env var the scanner checks.
- **[docs/agent-detection.md](docs/agent-detection.md)** — how agent auto-detection works and what each agent gets.

## Build and test

```bash
# Compile-check (no Rust needed on host — uses Docker)
docker run --rm -v "$PWD":/src -w /src rust:slim cargo check

# Build the container images
cargo install --path .
agentfence build-image

# Run smoke test
agentfence run ~/some-project -- /bin/bash -lc 'echo hello'

# Run the test suite
make test-launch
make test-audit
make test-discovery
make test-file-access
make test-workspace
make test-network
```

## Key rules

1. **AgentFence is observation-only.** Don't add blocking, killing, or enforcement. Every layer is audit/telemetry. This is deliberate.

2. **Project content is untrusted.** Nothing from project text files, `.agentfence.toml`, or git remotes should silently import host credentials into the container. Env vars from project text are printed as recommendations. SSH keys require interactive approval. Config mounts require `--trust-config`. See CLAUDE.md trust boundary rules.

3. **Credential values must never be logged.** Use `redact_env_value()` for env var previews (4 chars + length). Use `summarize_config_change()` for config sync-back audit events. No raw tokens, URLs, or env maps in audit.jsonl.

4. **CLI surface is minimal.** Hide power-user flags with `#[arg(hide = true)]`. Don't add visible flags without good reason.

5. **Keep dangerous-var lists in sync.** `container/bash_env.sh` and `src/ebpf.rs` both have lists of credential/dangerous env var names. Edit both when changing either.

6. **Keep `auto_auth_path_aliases` in sync.** When adding files to `materialize_codex_auth_mounts` or `materialize_claude_auth_mounts`, also add them to `auto_auth_path_aliases` so the registry seed picks them up.

## File layout

```
src/
  main.rs            — entry point
  cli.rs             — clap subcommands (build-image, run, audit)
  container.rs       — Docker orchestration, mounts, registry seeding (largest file)
  discovery.rs       — host credential scanning (140+ paths)
  monitor.rs         — monitoring backend selection (ContainerLocal / LinuxHostEbpf / DockerVmHelper)
  ebpf.rs            — bpftrace collectors and credential-access correlation
  agent_runtime.rs   — agent auto-detection (Codex, Claude Code)
  audit.rs           — agentfence audit report generator
  config.rs          — .agentfence.toml loader

container/
  Dockerfile         — agent container image
  Collector.Dockerfile — eBPF collector sidecar image
  entrypoint.sh      — container entrypoint
  bash_env.sh        — DEBUG trap + PROMPT_COMMAND hooks
  file_watcher.py    — inotify on /agentfence/creds/ and /agentfence/ssh/
  workspace_watcher.py — inotify + scan of mounted project
  network_watcher.py — ss polling for outbound connections
  audit_log.py       — CLI audit event writer
  registry_update.py — credential registry updater

docs/
  credential-scanning.md — full path inventory
  agent-detection.md     — detection cascade docs
  DESIGN_SPEC.md         — historical design spec (diverges from implementation)
```

## PR expectations

- `cargo check` must pass (zero warnings)
- Don't modify CLAUDE.md conventions without discussing
- Don't add new auto-import paths for host credentials without considering the trust boundary
- Update docs when changing behavior
