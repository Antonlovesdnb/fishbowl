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
| Runtime validation 2026-04-09 | (this file, `Notes from 2026-04-09 runtime validation` below) | — | macOS strong monitoring made functional end-to-end on Colima; binary distribution unblocked; collector image build path repaired |

## Notes from 2026-04-09 runtime validation

A runtime test pass on macOS + Colima 6.8.0-100-generic aarch64. None of these are security findings — they're functional gaps in in-progress features that surfaced when the path was actually exercised end-to-end. All shipped in v0.1.0–v0.1.4.

**Binary distribution path unblocked.**

- Added `.github/workflows/release.yml`: 4 native targets (macOS x86_64+arm64, Linux x86_64+arm64 musl-static), SHA256SUMS, GitHub Releases on `v*` tag push.
- Added `install.sh`: OS/arch-detect, checksum verify, install to `/usr/local/bin` (or `~/.local/bin`).
- `src/container.rs:manifest_dir()` was hardcoded to `env!("CARGO_MANIFEST_DIR")`, baking the build-time path into the binary and breaking every prebuilt-binary install with `container assets directory is missing at /Users/runner/work/...`. Replaced with `include_dir!()` embedding + extraction to `dirs::cache_dir()/agentfence/container/<version>/` at runtime. Source-tree installs short-circuit to the live on-disk copy so dev edits still take effect.
- `build_image()` skips the collector image when `dev_source_root().is_none()` (prebuilt-binary case), with a clear log line. The collector image rebuilds the agentfence binary inside a Docker container and needs the full Rust source tree as build context, which prebuilt-binary installs don't have.
- `container/Collector.Dockerfile` had two latent bugs: pinned at `rust:1.86-alpine` while `monitor.rs` uses let-chains (Rust ≥ 1.88), and didn't `COPY container ./container` so the new `include_dir!()` macro failed at compile time. Switched to `rust:alpine` + added the COPY. The fact that #1 was latent strongly suggests nobody had built the collector image since let-chains landed in `monitor.rs`.

**macOS strong monitoring made functional.**

Before today: empty `ebpf_*.jsonl` files on every macOS run, with errors buried in `<session>/ebpf_*.stderr.log` and a positive-sounding `Selected Docker-in-VM helper monitoring backend` startup message giving the appearance of working monitoring. Six independent issues stacked on each other, all in the helper container path:

1. **No tracefs/debugfs mounts in the helper container.** Lima/Colima VM kernels DO have `CONFIG_FTRACE_SYSCALLS` and the syscall tracepoints — the helper container just had no `/sys/kernel/tracing` tree mounted, so bpftrace's `available_events` lookup failed and reported the symptom as "tracepoint not found". Fix in `monitor.rs:spawn_docker_vm_helper_container`: add `-v /sys/kernel/tracing:/sys/kernel/tracing` and `-v /sys/kernel/debug:/sys/kernel/debug`.
2. **`tracepoint:syscalls:sys_enter_open` doesn't exist on arm64** (only `openat`/`openat2`). bpftrace fails the entire script when one probe is unattachable, taking the survivors with it. On arm64 the file collector silently captured nothing because of one stale probe. Fix in `ebpf.rs:build_file_script`: drop the bare-`open` probe entirely. `openat` covers it on every modern Linux because glibc compiles `open()` to `openat(AT_FDCWD, ...)`.
3. **bpftrace stdout was libc-fully-buffered** (default for non-tty pipes). Sparse workloads — a couple of cats, a getent — never filled the 4-8KB buffer, and SIGKILL on shutdown preempted the exit-time flush. Fix: `bpftrace -B line` in all three `spawn_*_collector` functions.
4. **`CollectorHandle::stop()` SIGKILLed bpftrace** before it could flush remaining events from the perf ring buffer or libc stdio. Fix in `ebpf.rs:CollectorHandle::stop`: send SIGINT via `libc::kill`, wait up to 1.5s for graceful exit, then escalate to SIGKILL. New direct dep: `libc`.
5. **`stop_docker_vm_helper()` ran `docker rm -f`** which SIGKILLs PID 1 of the helper container — preempting the SIGINT-drain logic from #4 before it could even start. Fix in `monitor.rs`: `docker stop -t 5` instead. The helper was started with `--rm` so it self-cleans.
6. **`ctrlc = "3.4"` without the `termination` feature only handles SIGINT, not SIGTERM.** `docker stop` sends SIGTERM, the handler in `run_privileged_helper` never fired, the main loop never saw `shutdown=true`, and SIGKILL kicked in after the 5s docker stop timeout — bypassing the entire graceful shutdown chain. Fix in `Cargo.toml`: `ctrlc = { version = "3.4", features = ["termination"] }`.
7. **`parse_file_record` had a process-lifetime race.** It called `process_in_scope` as a userspace double-check after bpftrace's kernel-level cgroup filter. For short-lived processes like `cat` (which is exactly the pattern of a credential read), the process exits between bpftrace firing the event and the parser thread reading it — `fs::read_link("/proc/<pid>/ns/pid")` returns ENOENT, `process_in_scope` returns false, the event is dropped. Even though bpftrace correctly captured it inside the agent container's cgroup. Fix in `ebpf.rs:parse_file_record`: drop the redundant check; trust the bpftrace cgroup predicate, which is authoritative. The same race exists in `parse_exec_record` and `parse_connect_record` but is harder to hit (calling process is alive at the moment exec/connect probes fire) — left as future work.

**Defense in depth: silent-failure detection.** Even with all the above fixed, the bpftrace probes could silently fail attachment on a future kernel or Docker provider. Added `monitor.rs:scan_collector_attach_failures()` that scans each `ebpf_*.stderr.log` after the helper alive check, looks for known bpftrace failure markers (`ERROR:`, `Unable to attach probe`, `Could not read symbols`, `not available for your kernel`), and routes them through `handle_helper_failure` so `--monitor strong` hard-errors with the actual probe-failure detail and `--monitor auto` downgrades cleanly with the message printed. Linux backend gets the same scan as a loud stderr warning (no fallback machinery).

**End-to-end validation result on Colima:**

```
agentfence run --monitor strong --mount ~/test-cred.txt ~/agentfence-smoke -- \
  /bin/bash -lc 'for i in 1 2 3; do cat /agentfence/creds/test-cred.txt; done'
```
- exec collector: 4 events captured ✓
- connect collector: 1 event captured ✓
- file collector: 3 events captured ✓
- registry `access_count` for `/agentfence/creds/test-cred.txt`: **3** (matches the 3 cats)
- All `ebpf_*.stderr.log` files empty (no probe-attach failures)

**Open follow-ups from this pass (all functional/in-progress, not security findings):**

- Publish `agentfence-collector` image to GHCR so prebuilt-binary installs on macOS can `docker pull` it instead of needing a source-tree install. This is the only thing keeping `--monitor strong` from working out of the box for binary installs.
- Apply the same `process_in_scope` race fix to `parse_exec_record` and `parse_connect_record` for completeness.
- Connect collector currently records `unresolved-fd:N` for destinations — the bpftrace script captures only `args->fd`, not the user-space sockaddr. Enhancement: read the sockaddr from `args->uservaddr` and decode IP/port in the script.
- Colima default mounts don't include `/var/folders` (macOS native `$TMPDIR`), so any `mktemp -d` project path fails with `bind source path does not exist`. Document in README quick-start, or add a preflight check in `agentfence run`.
- The README's "macOS host" platform-support paragraph and the in-binary `Skipping collector image build` notice should agree on the source-install requirement; both updated this pass but worth keeping in sync as the registry-publish work lands.

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
| U1 | No `agentfence audit` subcommand | FIXED (implemented in `src/audit.rs`) |
| U3 | No auto-build on first run | FIXED (Pass 3) |
| U4 | No config file support | FIXED (`.agentfence.toml` loader in `src/config.rs`) |
| S8 | Container filesystem is read-write | FIXED (`--read-only` + `--tmpfs /tmp` + `--tmpfs /run` in `container.rs`) |

## Open security findings

### HIGH
| ID | Summary |
|----|---------|
| S4 | `seed_workspace_trust` auto-accepts Claude's trust dialog without consent |
| S5 | DNS/UDP exfiltration unmonitored — only TCP via `ss -tpnH` (container-local watcher gap; eBPF covers it) |
| S6 | Short-lived connections evade `ss` polling window (container-local watcher gap; eBPF covers it) |
| S7 | Shell hook bypass — `sh` / `dash` / `python` / `node` skip env auditing (container-local watcher gap; eBPF covers it) |

### MEDIUM
| ID | Summary |
|----|---------|
| S9 | `--network host` warning is too subtle |
| S10 | No audit log integrity protection (no HMAC, sequence, or hash chain) |
| S11 | `npm install -g` runs as root with suppressed output in entrypoint (dead per N11, still present) |
| S12 | inotifywait process-attribution race (inherent — eBPF solves) |
| N3 | eBPF exec env audit reads `/proc/PID/environ` on every execve |
| N10 | `/tmp/agentfence-npm/bin` in PATH is binary-hijack vector |

### LOW
| ID | Summary |
|----|---------|
| S13 | `seen` dedup set in network_watcher grows unboundedly |
| S14 | Workspace 1 MB scan limit |
| S15 | `PROMPT_COMMAND` self-protection lacking — attacker can strip hook |
| N5 | Dangerous/credential var lists duplicated between `bash_env.sh` and `ebpf.rs`, can drift |
| N8 / N12 | Double bind-mount of project dir when workspace path differs |
| N11 | Dead code: `package_names()` returns `&[]`, agent install never triggers |

## Open usability findings

| ID | Summary |
|----|---------|
| U2 | No real-time alerts during sessions (watcher output to `/dev/null`) |
| U5 | Learning mode never transitions to enforcement |
| U6 | No false-positive suppression (allowlist/ignorelist) |
| U7 | Opaque error messages (Docker missing, image not found, etc.) |

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
