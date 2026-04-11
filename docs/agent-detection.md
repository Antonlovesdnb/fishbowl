# Agent Auto-Detection

AgentFence auto-detects which AI coding agent to wrap based on signals from the project directory and host environment. The detected agent determines which auth files are auto-mounted, which default command is launched, and how session state is synced back after the run.

## Detection priority

Detection follows a cascade — first match wins:

| Priority | Signal | Result | Reason |
|---|---|---|---|
| 1 | `CLAUDE.md` in project OR `~/.claude/` exists | Claude Code | "project has Claude marker" |
| 1 | `AGENTS.md` in project OR `~/.codex/` exists | Codex | "project has Codex marker" |
| 1 | Both markers present | Shell (fallback) | "project has both Claude and Codex markers" |
| 2 | Prior Codex session history matches this project's cwd | Codex | "prior Codex session cwd matched this project" |
| 3 | Project text files reference `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` | Claude Code | "project references Claude/Anthropic auth environment variables" |
| 3 | Project text files reference `OPENAI_API_KEY` | Codex | "project references Codex/OpenAI auth environment variables" |
| 3 | Both env var families referenced | Shell (fallback) | "project references both Claude and Codex auth environment variables" |
| 4 | `~/.claude/.credentials.json` exists on host | Claude Code | "only Claude auth was found on the host" |
| 4 | `~/.codex/auth.json` exists OR `OPENAI_API_KEY` env set | Codex | "only Codex auth was found on the host" |
| 4 | Both auth present | Shell (fallback) | "both Claude and Codex auth were found on the host" |
| 5 | No signals | Shell | "no supported agent marker, project session, or auth signal was found" |

The detected agent and reason are printed at startup: `[AgentFence] Auto-selected agent: codex (only Codex auth was found on the host)`.

You can override detection with `--agent codex` or `--agent claude-code` (hidden flag).

## What each agent gets

### Claude Code

**Auth mounts** (copied to a runtime dir, then bind-mounted):
- `~/.claude/.credentials.json` -> `/agentfence/home/.claude/.credentials.json`
- `~/.claude/.current-session` -> `/agentfence/home/.claude/.current-session`
- `~/.claude/history.jsonl` -> `/agentfence/home/.claude/history.jsonl`
- `~/.claude.json` -> `/agentfence/home/.claude.json`
- Project sessions from `~/.claude/projects/<slug>/` are mirrored with path rewriting

**Workspace trust**: `~/.claude.json` is updated to auto-accept the workspace trust dialog for the container session (finding S4 — no opt-out yet).

**Default command**: `claude`

**Session sync back**: On exit, project session state is synced from the container's `~/.claude/projects/` back to the host's `~/.claude/projects/`. The host `~/.claude.json` is updated with the project config from the session. Changes to security-sensitive fields (`mcpServers`, `allowedTools`) are logged in the startup output so modifications from inside the container are visible.

**Session resume**: If a prior session exists, launches with `claude --resume <session_id>`.

### Codex

**Auth mounts** (copied to a runtime dir, then bind-mounted):
- `~/.codex/auth.json` -> `/agentfence/home/.codex/auth.json`
- `~/.codex/config.toml` -> `/agentfence/home/.codex/config.toml`
- `~/.codex/version.json` -> `/agentfence/home/.codex/version.json`
- `~/.codex/history.jsonl` -> `/agentfence/home/.codex/history.jsonl` (filtered to project)
- `~/.codex/sessions/` -> `/agentfence/home/.codex/sessions/` (filtered to project)

**Default command**: `codex`

**Session sync back**: On exit, new history entries are appended to `~/.codex/history.jsonl` (deduplicated). Project sessions are synced from the container back to `~/.codex/sessions/`. Container paths are rewritten back to host paths.

### Shell (fallback)

No auth mounts. No default command (drops to an interactive bash shell). No session sync. This is the safe default when detection is ambiguous.

### Cursor / Windsurf / Copilot (scaffolded, not validated)

The `Agent` enum has variants for these but:
- Detection returns `None` for default commands
- No auto-auth mounts
- No session sync
- `agent_auth_env_hints` returns environment variable expectations:
  - Cursor: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GH_TOKEN`, `GITHUB_TOKEN`
  - Windsurf: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
  - Copilot: `GH_TOKEN`, `GITHUB_TOKEN`

These are not tested end-to-end. Validation is on the roadmap.

Source: `src/agent_runtime.rs`, `src/container.rs`
