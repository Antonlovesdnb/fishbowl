# MEMORY.md — AgentFence findings snapshot

Consolidated state of security, usability, and performance findings across 4 review passes performed by Claude Opus 4.6 on 2026-04-07. Source files: `SECURITY_REVIEW.md`, `SECURITY_REVIEW_2.md`, `SECURITY_REVIEW_3.md`, `SECURITY_REVIEW_4.md`. This file is a snapshot — for full context on any finding, read the source review file.

## Threat model

- **In scope:** opportunistic credential theft (malicious deps, env-var poisoning, MCP tampering, prompt-injection-driven curl/wget exfil)
- **Out of scope:** determined adversaries, attacks on the monitoring stack itself, agent encoding creds into its own API channel
- **Runtime posture:** observation-only. AgentFence does not block, terminate, or interfere with the agent — every layer is audit/telemetry. The only "enforcement" is the static container boundary (`--cap-drop ALL`, namespaces, `--security-opt no-new-privileges`). `--monitor strong` enables *stronger observation* via Linux host-side eBPF, not dynamic enforcement. Blocking was deliberately removed (`README.md:216`, `AgentFence.md:347`).

## Review history

| Pass | Source file | New finding IDs | Items fixed in this pass |
|------|-------------|-----------------|--------------------------|
| 1 | `SECURITY_REVIEW.md` | S1–S15, U1–U7, P1–P5, A1–A4 | — |
| 2 | `SECURITY_REVIEW_2.md` | N1–N5 | S2, S3, U3 (S1 partial) |
| 3 | `SECURITY_REVIEW_3.md` | N6–N9 | S1 (full), N1, N2, N4 |
| 4 | `SECURITY_REVIEW_4.md` | N10–N12 | N6, N7, N9 |

## Cumulative fix status (from `SECURITY_REVIEW_4.md`)

| ID | Finding | Status |
|----|---------|--------|
| S1 | Logs dir world-writable | FIXED (Pass 2 + 3) |
| S2 | Plaintext credentials in audit log | FIXED (Pass 2) |
| S3 | Runtime auth in /tmp with predictable names | FIXED (Pass 2 + 3) |
| N1 | Logs dir 0o1733 usability/security | FIXED (Pass 3) |
| N2 | Auto-build on every run | FIXED (Pass 3) |
| N4 | Redaction subshell overhead | FIXED (Pass 3) |
| N6 | `/agentfence/home` 0o777 exposing auth files | FIXED (Pass 4) |
| N7 | `--user` breaks `npm install -g` | FIXED (Pass 4, code path is dead) |
| N9 | `registry.json` initialized as `{}` | FIXED (Pass 4) |
| U3 | No auto-build on first run | FIXED (Pass 3) |

## Open security findings

### HIGH
| ID | File | Summary |
|----|------|---------|
| S4 | `src/container.rs:1124` | `seed_workspace_trust` auto-accepts Claude's trust dialog without consent |
| S5 | `container/network_watcher.py` | DNS/UDP exfiltration unmonitored — only TCP via `ss -tpnH` |
| S6 | `container/network_watcher.py` | Short-lived connections evade `ss` polling window |
| S7 | `container/bash_env.sh` | Shell hook bypass — `sh` / `dash` / `python` / `node` skip env auditing |

### MEDIUM
| ID | File | Summary |
|----|------|---------|
| S8 | `src/container.rs:219` | Container filesystem is read-write (no `--read-only`) |
| S9 | `src/container.rs:228` | `--network host` warning is too subtle |
| S10 | `container/audit_log.py` | No audit log integrity protection (no HMAC, sequence, or hash chain) |
| S11 | `container/entrypoint.sh:23` | `npm install -g` runs as root with suppressed output (dead per N11, still present) |
| S12 | `container/file_watcher.py:76` | inotifywait process-attribution race (inherent — eBPF solves) |
| N3 | `src/ebpf.rs:1472` | eBPF exec env audit reads `/proc/PID/environ` on every execve |
| N10 | `container/Dockerfile:6` | `/tmp/agentfence-npm/bin` in PATH is binary-hijack vector |

### LOW
| ID | File | Summary |
|----|------|---------|
| S13 | `container/network_watcher.py:227` | `seen` dedup set grows unboundedly |
| S14 | `container/workspace_watcher.py` | Workspace 1 MB scan limit |
| S15 | `container/bash_env.sh:297` | `PROMPT_COMMAND` self-protection lacking — attacker can strip hook |
| N5 | `bash_env.sh` + `ebpf.rs` | Dangerous/credential var lists duplicated, can drift |
| N8 / N12 | `src/container.rs:259` | Double bind-mount of project dir when workspace path differs |
| N11 | `src/agent_runtime.rs:174` | Dead code: `package_names()` returns `&[]`, agent install never triggers |

## Open usability findings

| ID | Summary |
|----|---------|
| U1 | No `agentfence audit` subcommand for reviewing sessions |
| U2 | No real-time alerts during sessions (watcher output to `/dev/null`) |
| U4 | No config file support |
| U5 | Learning mode never transitions to enforcement |
| U6 | No false-positive suppression (allowlist/ignorelist) |
| U7 | Opaque error messages (Docker missing, image not found, etc.) |

> **Note:** U1 (`agentfence audit`) and U4 (`.agentfence.toml`) appear to have been implemented in code (`src/audit.rs`, `src/config.rs`) since Pass 4 was written. A future review pass should re-evaluate their status.

## Open performance findings

| ID | Summary |
|----|---------|
| P1 | Registry JSON read from disk every poll cycle |
| P2 | Subprocess fork (Python) per audit event |
| P3 | Full recursive workspace scan on startup |
| P4 | No inotify watch limit management (`fs.inotify.max_user_watches` exhaustion) |
| P5 | No process chain caching — walks `/proc` per event |

## Architecture observations (Pass 1, non-blocking)

- **A1** — Dual monitoring story (container-local + host eBPF) is sound but communication is unclear; users may assume protection when they only get telemetry
- **A2** — No seccomp profile beyond `--cap-drop ALL`
- **A3** — Dockerfile installs `bubblewrap`, `iptables`, `npm` which aren't used by container code
- **A4** — No Docker base image digest pinning (`debian:bookworm-slim`, `alpine:3.22`)

## Latest priority recommendations (from Pass 4)

| # | ID | Summary | Effort |
|---|----|---------|--------|
| 1 | N10 | Remove `/tmp/agentfence-npm/bin` from PATH (binary hijack vector) | Trivial |
| 2 | S5 | Add UDP/DNS monitoring | Medium |
| 3 | S6 | Replace `ss` polling with event-based network monitoring | Medium |
| 4 | U2 | Add real-time credential alerts during sessions | Medium |
| 5 | S4 | Don't auto-accept trust dialog without explicit opt-in | Small |
| 6 | S8 | Add `--read-only` and `--tmpfs` to docker run | Trivial |
| 7 | P1 | Cache registry reads with mtime check | Small |
| 8 | P2 | Eliminate subprocess fork per audit event | Medium |
| 9 | S7 | Complementary env monitoring for non-bash shells | Medium |
| 10 | N11 | Clean up dead npm install code and PATH entries | Trivial |

## Review workflow

1. Codex writes code; Anton runs Claude (Opus 4.6, `/effort max`) for review
2. Claude produces `SECURITY_REVIEW_N.md` with new finding IDs and a cumulative status table
3. Anton has Codex apply fixes between passes
4. Next review pass references prior IDs and updates cumulative status — never re-lists items already marked FIXED
5. Architecture observations and non-blocking notes go in their own section within each review file
