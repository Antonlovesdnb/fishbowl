use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HostScanReport {
    pub findings: Vec<HostCredentialFinding>,
    pub project_context: ProjectContext,
}

#[derive(Debug, Serialize)]
pub struct HostCredentialFinding {
    pub path: String,
    pub classification: String,
    pub source: String,
    pub mount_kind: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct ProjectContext {
    pub git_remote_hosts: Vec<String>,
    pub suggested_ssh_key_names: Vec<String>,
    pub explicit_identity_files: Vec<String>,
    pub referenced_env_vars: Vec<String>,
}

const COMMON_AUTH_ENV_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "OPENAI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "XAI_API_KEY",
];

pub fn scan_host_credentials(project_dir: &Path, logs_dir: &Path) -> Result<HostScanReport> {
    let mut findings = Vec::new();
    let project_context = derive_project_context(project_dir)?;
    let home = dirs::home_dir();

    if let Some(home) = &home {
        scan_ssh(home, &mut findings)?;
        push_if_exists(
            home.join(".aws").join("credentials"),
            "AWS Credentials File",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".aws").join("config"),
            "AWS Config File",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".kube").join("config"),
            "Kubernetes Config",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".docker").join("config.json"),
            "Docker Config",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".config").join("gh").join("hosts.yml"),
            "GitHub CLI Auth Store",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".npmrc"),
            "NPM Token Config",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".netrc"),
            "Netrc Credential File",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".pypirc"),
            "Python Package Index Credential File",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".claude").join(".credentials.json"),
            "Claude OAuth Credentials",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".claude.json"),
            "Claude Local Config",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".codex").join("auth.json"),
            "Codex Auth Store",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".codex").join("config.toml"),
            "Codex Local Config",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".config").join("gcloud").join("application_default_credentials.json"),
            "GCP Application Default Credentials",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".config").join("gcloud").join("access_tokens.db"),
            "GCP Access Token Cache",
            "host_scan",
            &mut findings,
        )?;
        push_if_exists(
            home.join(".config").join("gcloud").join("credentials.db"),
            "GCP Credentials Database",
            "host_scan",
            &mut findings,
        )?;
        scan_dir_files(
            home.join(".config").join("gcloud").join("legacy_credentials"),
            &["json", "db"],
            "GCP Legacy Credential Artifact",
            "host_scan",
            &mut findings,
        )?;
        scan_dir_files(
            home.join(".azure"),
            &["json", "pem", "key", "bin"],
            "Azure Credential Artifact",
            "host_scan",
            &mut findings,
        )?;
        scan_ludus_configs(home, &mut findings)?;
    }

    scan_project_candidates(project_dir, &mut findings)?;

    let report = HostScanReport {
        findings,
        project_context,
    };
    let output = logs_dir.join("host_scan.json");
    fs::write(
        &output,
        serde_json::to_string_pretty(&report).context("failed to serialize host scan report")?,
    )
    .with_context(|| format!("failed to write host scan report {}", output.display()))?;

    Ok(report)
}

fn derive_project_context(project_dir: &Path) -> Result<ProjectContext> {
    let mut context = ProjectContext::default();
    context.git_remote_hosts = git_remote_hosts(project_dir)?;
    context.explicit_identity_files = explicit_identity_files(project_dir)?;
    context.suggested_ssh_key_names = suggested_ssh_key_names(project_dir, &context.explicit_identity_files)?;
    context.referenced_env_vars = referenced_env_vars(project_dir)?;
    context.git_remote_hosts.sort();
    context.git_remote_hosts.dedup();
    context.suggested_ssh_key_names.sort();
    context.suggested_ssh_key_names.dedup();
    context.explicit_identity_files.sort();
    context.explicit_identity_files.dedup();
    context.referenced_env_vars.sort();
    context.referenced_env_vars.dedup();
    Ok(context)
}

fn git_remote_hosts(project_dir: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project_dir)
        .arg("remote")
        .arg("-v")
        .output();

    let Ok(output) = output else {
        return Ok(Vec::new());
    };
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hosts = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let remote = parts[1];
        if let Some(host) = extract_remote_host(remote) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

fn extract_remote_host(remote: &str) -> Option<String> {
    if let Some(rest) = remote.strip_prefix("git@") {
        return rest.split(':').next().map(|s| s.to_string());
    }
    if let Some(rest) = remote.strip_prefix("ssh://") {
        let rest = rest.trim_start_matches('/');
        let rest = rest.split('@').next_back().unwrap_or(rest);
        return rest
            .split(&['/', ':'][..])
            .next()
            .map(|s| s.to_string());
    }
    if let Some(rest) = remote.strip_prefix("https://") {
        return rest.split('/').next().map(|s| s.to_string());
    }
    None
}

fn explicit_identity_files(project_dir: &Path) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for candidate in [project_dir.join(".ssh").join("config"), project_dir.join(".git").join("config")] {
        if candidate.is_file() {
            if let Ok(text) = fs::read_to_string(&candidate) {
                paths.extend(parse_identity_files_from_text(&text));
                paths.extend(parse_ssh_command_identities(&text));
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let user_ssh_config = home.join(".ssh").join("config");
        if user_ssh_config.is_file() {
            if let Ok(text) = fs::read_to_string(&user_ssh_config) {
                paths.extend(parse_identity_files_from_text(&text));
            }
        }
    }

    for path in scan_project_text_files(project_dir)? {
        if let Ok(text) = fs::read_to_string(&path) {
            paths.extend(parse_identity_files_from_text(&text));
            paths.extend(parse_ssh_command_identities(&text));
        }
    }

    Ok(paths)
}

fn suggested_ssh_key_names(project_dir: &Path, explicit_identity_files: &[String]) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let common = ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"];

    for path in explicit_identity_files {
        let candidate = Path::new(path);
        if let Some(name) = candidate.file_name().and_then(|name| name.to_str()) {
            names.push(name.to_string());
        }
    }

    for name in common {
        if project_dir.join(name).is_file() {
            names.push(name.to_string());
        }
    }

    for candidate in [
        project_dir.join(".ssh").join("config"),
        project_dir.join(".git").join("config"),
        project_dir.join(".claude").join("settings.local.json"),
    ] {
        if !candidate.is_file() {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&candidate) {
            for name in common {
                if text.contains(name) {
                    names.push(name.to_string());
                }
            }
            for token in ["condef_git_key", "proxmox_key"] {
                if text.contains(token) {
                    names.push(token.to_string());
                }
            }
        }
    }

    Ok(names)
}

fn scan_project_text_files(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let allowed_exts = [
        "md", "txt", "json", "yaml", "yml", "toml", "sh", "conf", "cfg", "ini", "pem", "key", "tfvars",
    ];
    walk_dir(project_dir, &mut files, &allowed_exts)?;
    Ok(files)
}

fn referenced_env_vars(project_dir: &Path) -> Result<Vec<String>> {
    let mut vars = Vec::new();
    for path in scan_project_text_files(project_dir)? {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };

        for var in COMMON_AUTH_ENV_VARS {
            if text.contains(var) {
                vars.push((*var).to_string());
            }
        }

        for token in extract_uppercase_tokens(&text) {
            if is_credential_env_name(&token) {
                vars.push(token);
            }
        }
    }
    Ok(vars)
}

fn extract_uppercase_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_' {
            current.push(ch);
            continue;
        }
        if current.len() >= 3 {
            tokens.push(current.clone());
        }
        current.clear();
    }
    if current.len() >= 3 {
        tokens.push(current);
    }
    tokens
}

fn is_credential_env_name(value: &str) -> bool {
    COMMON_AUTH_ENV_VARS.contains(&value)
        || value.ends_with("_TOKEN")
        || value.ends_with("_KEY")
        || value.ends_with("_SECRET")
        || value.ends_with("_PASSWORD")
        || value.ends_with("_API_KEY")
}

fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>, allowed_exts: &[&str]) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if matches!(name, ".git" | "node_modules" | "target" | ".venv" | "dist" | "build") {
                continue;
            }
            walk_dir(&path, files, allowed_exts)?;
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if allowed_exts.contains(&ext) {
            files.push(path);
        }
    }

    Ok(())
}

fn parse_identity_files_from_text(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("identityfile ") {
            if let Some(value) = trimmed.split_whitespace().nth(1) {
                results.push(strip_wrapping_quotes(value));
            }
        }
    }
    results
}

fn parse_ssh_command_identities(text: &str) -> Vec<String> {
    let mut results = Vec::new();
    for token in ["ssh -i ", "scp -i ", "sftp -i ", "GIT_SSH_COMMAND=", "core.sshCommand"] {
        if !text.contains(token) {
            continue;
        }

        for segment in text.split('\n') {
            let mut remaining = segment;
            while let Some(index) = remaining.find("-i ") {
                let after = &remaining[index + 3..];
                let value = after
                    .split_whitespace()
                    .next()
                    .map(strip_wrapping_quotes)
                    .unwrap_or_default();
                if !value.is_empty() {
                    results.push(value);
                }
                remaining = after;
            }
        }
    }
    results
}

fn strip_wrapping_quotes(value: &str) -> String {
    value
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(',')
        .to_string()
}

fn scan_ssh(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    let ssh_dir = home.join(".ssh");
    if !ssh_dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(&ssh_dir).with_context(|| format!("failed to read {}", ssh_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if name.ends_with(".pub") || matches!(name, "known_hosts" | "config" | "authorized_keys") {
            continue;
        }

        if !looks_like_ssh_private_key(&path, name)? {
            continue;
        }

        push_finding(path, "SSH Private Key", "host_scan", Some("ssh"), findings);
    }

    Ok(())
}

fn scan_project_candidates(project_dir: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    let candidates = [
        (project_dir.join(".env"), "Project .env Credential File"),
        (project_dir.join(".env.local"), "Project .env Credential File"),
        (project_dir.join(".env.development"), "Project .env Credential File"),
        (project_dir.join(".env.production"), "Project .env Credential File"),
        (project_dir.join(".npmrc"), "Project NPM Token Config"),
        (project_dir.join(".pypirc"), "Project Python Package Index Credential File"),
        (project_dir.join(".netrc"), "Project Netrc Credential File"),
        (project_dir.join("ludus.conf"), "Project Ludus Config"),
        (project_dir.join(".claude").join("settings.local.json"), "Claude Project Settings"),
        (project_dir.join(".codex").join("config.toml"), "Codex Project Config"),
        (project_dir.join(".aws").join("credentials"), "Project AWS Credentials File"),
        (project_dir.join(".kube").join("config"), "Project Kubernetes Config"),
        (project_dir.join("id_ed25519"), "Project Private Key File"),
        (project_dir.join("id_rsa"), "Project Private Key File"),
        (project_dir.join("id_ecdsa"), "Project Private Key File"),
        (project_dir.join("id_dsa"), "Project Private Key File"),
    ];

    for (candidate, classification) in candidates {
        if candidate.exists() {
            push_finding(candidate, classification, "project_scan", None, findings);
        }
    }

    for path in scan_project_text_files(project_dir)? {
        if !is_project_generated_secret_candidate(&path) {
            continue;
        }
        let classification = classify_project_candidate(&path);
        push_finding(path, classification, "project_scan", None, findings);
    }

    Ok(())
}

fn is_project_generated_secret_candidate(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_documentation_file(&ext) {
        return false;
    }

    name.starts_with(".env")
        || matches!(
            name.as_str(),
            ".npmrc"
                | ".pypirc"
                | ".netrc"
                | "credentials"
                | "config"
                | "config.json"
                | "secrets.json"
                | "secret.json"
                | "ludus.conf"
                | "kubeconfig"
                | "terraform.tfvars"
                | "terraform.tfvars.json"
        )
        || (name.starts_with("id_") && !name.ends_with(".pub"))
        || name.contains("secret")
        || name.contains("credential")
        || name.contains("kubeconfig")
        || name.ends_with(".tfvars")
        || matches!(ext.as_str(), "pem" | "key")
}

fn classify_project_candidate(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.starts_with(".env") {
        return "Project .env Credential File";
    }
    if name == ".npmrc" {
        return "Project NPM Token Config";
    }
    if name == "ludus.conf" {
        return "Project Ludus Config";
    }
    if name.contains("kubeconfig") {
        return "Project Kubernetes Config";
    }
    if name.starts_with("id_") && !name.ends_with(".pub") {
        return "Project Private Key File";
    }
    if matches!(path.extension().and_then(|ext| ext.to_str()), Some("pem" | "key")) {
        return "Project Private Key File";
    }
    "Project Generated Secret Candidate"
}

fn is_documentation_file(ext: &str) -> bool {
    matches!(ext, "md" | "txt" | "rst" | "adoc")
}

fn scan_ludus_configs(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    for candidate in [
        home.join("ludus.conf"),
        home.join(".ludus").join("config"),
        home.join(".ludus").join("config.yml"),
        home.join(".ludus").join("config.yaml"),
        home.join(".config").join("ludus").join("config.yml"),
        home.join(".config").join("ludus").join("config.yaml"),
    ] {
        push_if_exists(candidate, "Ludus Config", "host_scan", findings)?;
    }

    for desktop_candidate in [
        home.join("Desktop").join("ludus.conf"),
        home.join("Documents").join("ludus.conf"),
    ] {
        push_if_exists(desktop_candidate, "Ludus Config", "host_scan", findings)?;
    }

    Ok(())
}

fn scan_dir_files(
    dir: PathBuf,
    allowed_exts: &[&str],
    classification: &str,
    source: &str,
    findings: &mut Vec<HostCredentialFinding>,
) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if !allowed_exts.is_empty() && !allowed_exts.contains(&ext) {
            continue;
        }
        push_finding(path, classification, source, None, findings);
    }

    Ok(())
}

fn push_if_exists(
    path: PathBuf,
    classification: &str,
    source: &str,
    findings: &mut Vec<HostCredentialFinding>,
) -> Result<()> {
    if path.exists() {
        push_finding(path, classification, source, None, findings);
    }

    Ok(())
}

fn push_finding(
    path: PathBuf,
    classification: &str,
    source: &str,
    mount_kind: Option<&str>,
    findings: &mut Vec<HostCredentialFinding>,
) {
    let path_string = path.display().to_string();
    if findings.iter().any(|finding| finding.path == path_string) {
        return;
    }
    findings.push(HostCredentialFinding {
        path: path_string,
        classification: classification.to_string(),
        source: source.to_string(),
        mount_kind: mount_kind.map(str::to_string),
    });
}

fn looks_like_ssh_private_key(path: &Path, file_name: &str) -> Result<bool> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };

    let text = String::from_utf8_lossy(&bytes);
    let known_headers = [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ];

    if known_headers.iter().any(|header| text.contains(header)) {
        return Ok(true);
    }

    if file_name.starts_with("id_") && !file_name.ends_with(".pub") {
        return Ok(true);
    }

    if matches!(path.extension().and_then(|e| e.to_str()), Some("pem" | "key")) && text.contains("PRIVATE KEY") {
        return Ok(true);
    }

    Ok(false)
}
