# Credential Scanning

AgentFence scans for credentials in two passes before the container starts. The results seed the runtime credential registry so the file collector knows which `openat()` events are interesting.

## Host scan (`source: "host_scan"`)

Walks well-known credential locations under `~/`. Only checks if files exist — never reads their contents.

### Cloud & infrastructure

| Path | Classification |
|---|---|
| `~/.aws/credentials` | AWS Credentials File |
| `~/.aws/config` | AWS Config File |
| `~/.kube/config` | Kubernetes Config |
| `~/.docker/config.json` | Docker Config |
| `~/.config/gcloud/application_default_credentials.json` | GCP Application Default Credentials |
| `~/.config/gcloud/access_tokens.db` | GCP Access Token Cache |
| `~/.config/gcloud/credentials.db` | GCP Credentials Database |
| `~/.config/gcloud/legacy_credentials/*.[json\|db]` | GCP Legacy Credential Artifact |
| `~/.azure/*.[json\|pem\|key\|bin]` | Azure Credential Artifact |

### Developer tools

| Path | Classification |
|---|---|
| `~/.config/gh/hosts.yml` | GitHub CLI Auth Store |
| `~/.npmrc` | NPM Token Config |
| `~/.netrc` | Netrc Credential File |
| `~/.pypirc` | Python Package Index Credential File |

### AI agent auth

| Path | Classification |
|---|---|
| `~/.claude/.credentials.json` | Claude OAuth Credentials |
| `~/.claude.json` | Claude Local Config |
| `~/.codex/auth.json` | Codex Auth Store |
| `~/.codex/config.toml` | Codex Local Config |

### SSH keys

All files under `~/.ssh/` are checked. A file is classified as an SSH private key if:
- Its name starts with `id_` (and doesn't end with `.pub`), OR
- It contains a PEM header (`-----BEGIN`)

Excluded: `known_hosts`, `config`, `authorized_keys`, `*.pub`.

### Other

| Path | Classification |
|---|---|
| `~/ludus.conf` | Ludus Config |
| `~/.ludus/config[.yml\|.yaml]` | Ludus Config |
| `~/.config/ludus/config[.yml\|.yaml]` | Ludus Config |

## Project scan (`source: "project_scan"`)

Walks the project directory for credential-bearing files. Excludes `.git`, `node_modules`, `target`, `.venv`, `dist`, `build`.

### Explicit candidates (checked in project root)

| Filename | Classification |
|---|---|
| `.env`, `.env.local`, `.env.development`, `.env.production` | Project .env Credential File |
| `.npmrc` | Project NPM Token Config |
| `.pypirc` | Project Python Package Index Credential File |
| `.netrc` | Project Netrc Credential File |
| `ludus.conf` | Project Ludus Config |
| `.claude/settings.local.json` | Claude Project Settings |
| `.codex/config.toml` | Codex Project Config |
| `.aws/credentials` | Project AWS Credentials File |
| `.kube/config` | Project Kubernetes Config |
| `id_ed25519`, `id_rsa`, `id_ecdsa`, `id_dsa` | Project Private Key File |

### Generated secret candidates (recursive)

Files matching any of these patterns are classified as potential secrets:

- Names starting with `.env` (any suffix)
- `.npmrc`, `.pypirc`, `.netrc`
- `credentials`, `config`, `config.json`, `secrets.json`, `secret.json`
- `ludus.conf`, `kubeconfig`, `terraform.tfvars`, `terraform.tfvars.json`
- Names starting with `id_` (not `.pub`)
- Names containing `secret`, `credential`, or `kubeconfig`
- Extensions `.tfvars`, `.pem`, `.key`

## Environment variable detection

The project scan also extracts environment variable names from project text files (`.md`, `.json`, `.yaml`, `.toml`, `.sh`, `.conf`, etc.) and checks whether they look like credentials. A variable name is considered credential-like if it:

- Is in the hardcoded list: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY`, `GH_TOKEN`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AZURE_OPENAI_API_KEY`, `GOOGLE_API_KEY`, `GEMINI_API_KEY`, `XAI_API_KEY`
- OR ends with `_TOKEN`, `_KEY`, `_SECRET`, `_PASSWORD`, or `_API_KEY`

Matching variables that are set on the host are auto-passed through to the container.

## What happens with the results

1. The scan report is printed to the console during startup
2. `host_scan.json` is written to a **host-only location** (`~/.agentfence/host-scans/`) — it is NOT visible inside the container
3. `project_scan` findings are translated to in-container paths and seeded into `registry.json` so the bpftrace file collector can match observed `openat()` calls
4. `host_scan` findings for the selected agent's auth files (e.g. `~/.codex/auth.json` for Codex) are also seeded via the `auto_auth_path_aliases` table
5. Auto-discovered SSH keys that match the project's git remote hosts are bind-mounted into `/agentfence/ssh/`
6. Auto-discovered credential env vars are passed through to the container

Source: `src/discovery.rs`
