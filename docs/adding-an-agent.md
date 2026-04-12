# Adding a new agent

This is the contributor checklist for wiring a new AI coding agent into Fishbowl. Today the validated agents are **Codex** and **Claude Code**. **Cursor**, **Windsurf**, and **Copilot** have partial scaffolding (enum variants, Display impls, env-var hints) but the core paths — auth materialization, session sync-back, detection — are not implemented. Don't treat that scaffolding as a working template.

If you're adding an agent because you need it for your own workflow: the steps below get you a binary that launches your agent inside the sandbox with auth, registry seeding, and session sync-back. Plan on ~150–300 lines of Rust touching ~6 functions in 2 files, plus a one-line Dockerfile change.

## Before you start

1. Pick a stable identifier for the agent — short, lowercase, hyphen-separated (e.g. `aider`, `cline`).
2. Find out where the host tool stores its auth/state on disk (`~/.<tool>/` is the common pattern). You'll need to copy specific files into a per-session runtime dir, not bind-mount the whole directory.
3. Find out how the tool is distributed (npm? pip? native binary? curl-pipe-sh?). This determines the Dockerfile change and whether you can host-mount the binary on Linux.
4. Confirm the tool actually runs inside a Linux container with no display, no host networking, and read-only root filesystem. If it doesn't, stop — fix that upstream first.

## The checklist

Each step has a file/line anchor. Many of the functions take exhaustive `match` on `Agent`, so the compiler will catch most missing arms — but **two of the steps below have silent drift traps the compiler can't catch.** Those are flagged.

### 1. Add the enum variant — `src/container.rs:46`

```rust
pub enum Agent {
    Shell,
    Codex,
    ClaudeCode,
    Cursor,
    Windsurf,
    Copilot,
    YourAgent,   // ← add here
}
```

The compiler will then point you at every `match` site that needs an arm. Work outward from there.

### 2. Display impl — `src/container.rs:55`

Add a string for your agent (used in CLI output, prompts, log lines).

### 3. Default launch command — `src/agent_runtime.rs:89`

```rust
pub fn default_command(agent: Agent) -> Option<Vec<String>> {
    match agent {
        ...
        Agent::YourAgent => Some(vec!["your-agent".to_string()]),
    }
}
```

If the agent needs flags or a subcommand by default, include them here. Return `None` if you want the user to always pass a command explicitly.

### 4. Auto-detection — `src/agent_runtime.rs`

Two layers:

- **Project markers** (`has_claude_project_marker`, `has_codex_project_marker` at `agent_runtime.rs:100` and `:104`). Add a `has_youragent_project_marker` checking for whatever file or directory in the project root signals "this project uses your agent."
- **The `detect_agent` cascade higher in the same file.** Plumb your new marker (and any host-auth check) into the cascade in priority order. Read what Codex and Claude do for the precedence rules — they're not arbitrary.

### 5. Auth materialization — `src/container.rs:914` (Codex) and `:951` (Claude)

Write `materialize_youragent_auth_mounts` following one of those two as a template. The function:

- Copies specific auth files (not the whole directory) from `~/.<tool>/` into `runtime_auth_dir`.
- Sets `0o600` on file modes and `0o700` on dirs (use `set_recursive_permissions` / `set_private_file`).
- If the agent stores per-project state with absolute paths, rewrite the host project path to the container project path while copying (see `copy_codex_project_history` for the pattern).
- Returns a `Vec<MaterializedMount>` describing what to bind-mount into the container.

Then register your function in `auto_discovered_agent_auth_mounts` (around `container.rs:907`) — the compiler will force you to do this once you add the enum variant.

### 6. ⚠️ `auto_auth_path_aliases` — `src/container.rs:1925` (silent drift trap)

This function lists every host path that should be seeded into the credential registry so the file collector recognizes accesses. **It duplicates the file list from your `materialize_*_auth_mounts` function.** The compiler cannot tell you these have drifted apart. If you add a file to the materialize function and forget to add it here, accesses to that file inside the container will be silently invisible to the audit log.

```rust
match agent {
    ...
    Agent::YourAgent => {
        for file_name in ["auth.json", "..."] {  // same list as materialize_youragent_auth_mounts
            aliases.push((
                home.join(".youragent").join(file_name),
                format!("{FISHBOWL_CONTAINER_HOME}/.youragent/{file_name}"),
            ));
        }
    }
}
```

**Verification:** after wiring this up, run the agent inside Fishbowl, have it touch one of its auth files, and check `audit.jsonl` for a `credential_access` event with the expected path. If the event is missing, your alias list is wrong.

### 7. Env-var hints — `src/container.rs:1751`

`agent_auth_env_hints` returns the credential env vars Fishbowl will auto-pass through if they're set on the host (e.g., `OPENAI_API_KEY` for Cursor). **Be conservative.** Only list vars that are *actually used by this specific agent for authentication*. Don't list `GITHUB_TOKEN` unless the agent literally needs it; project-discovered env vars are surfaced separately as recommendations, not auto-passed. Project content must never control security posture (see CLAUDE.md "Project content must never control security posture" for the rules).

### 8. Session sync-back — `src/container.rs:1168` (Claude) and `:1389` (Codex)

If your agent stores session history or per-project state inside the container that the user wants persisted back to the host, write `sync_youragent_session_back` modeled on one of those two. Then add a branch in `finalize_session` (around `container.rs:627`):

```rust
if agent == Agent::YourAgent {
    sync_youragent_session_back(project_dir, runtime_auth_dir)?;
}
```

If your agent has no persistent state, skip this step entirely — there's no required hook.

### 9. Native-binary mount (Linux only, optional) — `src/container.rs:819`

On Linux, Fishbowl can bind-mount the host's installed agent binary into the container instead of using the version installed in the image. This is the existing pattern for Codex (`host_codex_native_binary` at `container.rs:860`). It's an optimization, not required — the Dockerfile install (step 10) is the source of truth. Skip this unless your agent ships a Linux native binary that's tricky to install in the image.

### 10. Dockerfile install — `container/Dockerfile`

Add your agent to the install line near `RUN npm install -g`. If your agent isn't on npm, add an appropriate `RUN` step in the same layer. Verify the binary lands in `$PATH` after the build:

```sh
docker build -t fishbowl:test container/
docker run --rm --entrypoint /bin/sh fishbowl:test -c 'which your-agent && your-agent --version'
```

### 11. Smoke test

There is no per-agent test harness today. Validate manually:

```sh
cargo install --path .
docker rmi fishbowl:dev
fishbowl run ~/some-project-using-your-agent
```

Confirm:
- The agent launches inside the container (no `exec: ... not found`).
- `~/.fishbowl/logs/session-<ts>/audit.jsonl` shows `credential_access` events when the agent touches its auth files (proves step 6 is correct).
- If your agent has session state, exit cleanly and verify the host-side state was updated (proves step 8 is correct).

### 12. Docs

- `README.md` — add to the "Validated end-to-end with..." line **only if you've actually validated it** on both Linux and macOS. Otherwise leave it out.
- `CLAUDE.md` — if you're adding the agent as scaffolding (enum variant + partial impl, untested), say so explicitly there alongside Cursor/Windsurf/Copilot. Do not let user-facing copy claim more than is true.
- `docs/agent-detection.md` — add a row describing your project markers, host-auth paths, and default command.

## Common mistakes

- **Forgetting `auto_auth_path_aliases`** (step 6). Most common silent failure mode. The agent runs, the container starts, the audit log fills up — but credential accesses are missing. Always smoke-test by triggering one credential read and grepping the audit log for it.
- **Treating Cursor/Windsurf/Copilot as a working template.** They're partial scaffolding. Use Codex and Claude as your reference implementations.
- **Auto-passing too many env vars in `agent_auth_env_hints`.** This is a security boundary. When in doubt, require the user to `--mount` it explicitly.
- **Mounting whole directories instead of specific files.** `~/.<tool>/` may contain history, cached search results, or telemetry that doesn't need to cross the trust boundary. Copy the minimum set.
- **Skipping path rewriting in session sync-back.** If the agent records absolute paths and you sync without rewriting, history entries will reference container paths (`/workspace/...`) on the host, breaking the user's resume flow.
- **Bind-mounting the host binary on macOS.** Won't work — host binaries are Mach-O, container is Linux. The Dockerfile install (step 10) is what makes the agent runnable on macOS hosts.

## When in doubt

Read both `materialize_codex_auth_mounts` and `materialize_claude_auth_mounts` end-to-end before writing your own. They diverge in important ways (Codex copies session JSONL trees with cwd filtering; Claude copies a single config + writes a workspace-trust file). Your agent's auth model probably looks more like one than the other — pick the closer one as your template.

If your agent's auth model doesn't match either pattern, open an issue describing it before writing code. There may be a structural change worth doing first.
