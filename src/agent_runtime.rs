use std::fs;
use std::path::Path;

use crate::{
    container::Agent,
    discovery::HostScanReport,
};

pub struct AgentDetection {
    /// The single-agent guess. On ambiguity this is `Shell` as a safe default,
    /// and `candidates` holds the agents the caller should choose between.
    pub agent: Agent,
    pub reason: String,
    /// Populated when the signal is genuinely ambiguous and an interactive
    /// caller should prompt. Empty on a clean single-agent detection.
    pub candidates: Vec<Agent>,
}

pub fn detect_agent(project_dir: &Path, report: &HostScanReport) -> AgentDetection {
    let claude_marker = has_claude_project_marker(project_dir);
    let codex_marker = has_codex_project_marker(project_dir);
    if claude_marker && !codex_marker {
        return detected(Agent::ClaudeCode, "project has Claude marker (CLAUDE.md or .claude/)");
    }
    if codex_marker && !claude_marker {
        return detected(Agent::Codex, "project has Codex marker (AGENTS.md or .codex/)");
    }
    if claude_marker && codex_marker {
        // Strong project-level signal for both agents — let an interactive
        // caller pick. Non-interactive callers get the previous Shell fallback.
        return ambiguous(
            vec![Agent::ClaudeCode, Agent::Codex],
            "project has both Claude and Codex markers",
        );
    }
    if host_has_codex_project_session(project_dir) && !claude_marker {
        return detected(Agent::Codex, "prior Codex session cwd matched this project");
    }

    let claude_env = references_claude_env(report);
    let codex_env = references_codex_env(report);
    if claude_env && !codex_env {
        return detected(Agent::ClaudeCode, "project references Claude/Anthropic auth environment variables");
    }
    if codex_env && !claude_env {
        return detected(Agent::Codex, "project references Codex/OpenAI auth environment variables");
    }
    if claude_env && codex_env {
        return detected(
            Agent::Shell,
            "project references both Claude and Codex auth environment variables; falling back to shell to avoid guessing",
        );
    }

    let claude_auth = host_has_claude_auth();
    let codex_auth = host_has_codex_auth();
    if claude_auth && !codex_auth {
        return detected(Agent::ClaudeCode, "only Claude auth was found on the host");
    }
    if codex_auth && !claude_auth {
        return detected(Agent::Codex, "only Codex auth was found on the host");
    }
    if claude_auth && codex_auth {
        return detected(
            Agent::Shell,
            "both Claude and Codex auth were found on the host and no project-specific signal was decisive",
        );
    }

    detected(Agent::Shell, "no supported agent marker, project session, or auth signal was found")
}

fn detected(agent: Agent, reason: &str) -> AgentDetection {
    AgentDetection {
        agent,
        reason: reason.to_string(),
        candidates: Vec::new(),
    }
}

fn ambiguous(candidates: Vec<Agent>, reason: &str) -> AgentDetection {
    AgentDetection {
        agent: Agent::Shell,
        reason: reason.to_string(),
        candidates,
    }
}

pub fn default_command(agent: Agent) -> Option<Vec<String>> {
    match agent {
        Agent::Shell => None,
        Agent::ClaudeCode => Some(vec!["claude".to_string()]),
        Agent::Codex => Some(vec!["codex".to_string()]),
        Agent::Cursor => None,
        Agent::Windsurf => None,
        Agent::Copilot => None,
    }
}

fn has_claude_project_marker(project_dir: &Path) -> bool {
    project_dir.join("CLAUDE.md").is_file() || project_dir.join(".claude").exists()
}

fn has_codex_project_marker(project_dir: &Path) -> bool {
    project_dir.join("AGENTS.md").is_file() || project_dir.join(".codex").exists()
}

fn references_claude_env(report: &HostScanReport) -> bool {
    report
        .project_context
        .referenced_env_vars
        .iter()
        .any(|name| matches!(name.as_str(), "ANTHROPIC_API_KEY" | "ANTHROPIC_AUTH_TOKEN"))
}

fn references_codex_env(report: &HostScanReport) -> bool {
    report
        .project_context
        .referenced_env_vars
        .iter()
        .any(|name| name == "OPENAI_API_KEY")
}

fn host_has_claude_auth() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    home.join(".claude").join(".credentials.json").is_file()
}

fn host_has_codex_auth() -> bool {
    let Some(home) = dirs::home_dir() else {
        return std::env::var_os("OPENAI_API_KEY").is_some();
    };
    home.join(".codex").join("auth.json").is_file() || std::env::var_os("OPENAI_API_KEY").is_some()
}

fn host_has_codex_project_session(project_dir: &Path) -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let sessions_dir = home.join(".codex").join("sessions");
    if !sessions_dir.is_dir() {
        return false;
    }

    let project = project_dir.display().to_string();
    codex_sessions_contain_cwd(&sessions_dir, &project)
}

fn codex_sessions_contain_cwd(path: &Path, project: &str) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if codex_sessions_contain_cwd(&path, project) {
                return true;
            }
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        if content.lines().take(3).any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|record| {
                    record
                        .get("payload")
                        .and_then(|payload| payload.get("cwd"))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .as_deref()
                == Some(project)
        }) {
            return true;
        }
    }

    false
}
