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
    // Anthropic
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    // OpenAI
    "OPENAI_API_KEY",
    // GitHub
    "GH_TOKEN",
    "GITHUB_TOKEN",
    // AWS
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    // Azure
    "AZURE_OPENAI_API_KEY",
    // Google
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    // xAI
    "XAI_API_KEY",
    // AI/ML providers
    "HUGGING_FACE_HUB_TOKEN",
    "HF_TOKEN",
    "REPLICATE_API_TOKEN",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY",
    "PERPLEXITY_API_KEY",
    // SaaS / payments / messaging
    "STRIPE_SECRET_KEY",
    "STRIPE_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_API_KEY",
    "SENDGRID_API_KEY",
    "MAILGUN_API_KEY",
    "SLACK_TOKEN",
    "SLACK_BOT_TOKEN",
    "DISCORD_TOKEN",
    "DISCORD_BOT_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    // Observability
    "DATADOG_API_KEY",
    "DD_API_KEY",
    "DD_APP_KEY",
    "SENTRY_AUTH_TOKEN",
    "SENTRY_DSN",
    "NEW_RELIC_LICENSE_KEY",
    "ELASTIC_APM_SECRET_TOKEN",
    // Hosting / PaaS
    "VERCEL_TOKEN",
    "NETLIFY_AUTH_TOKEN",
    "FLY_API_TOKEN",
    "RAILWAY_TOKEN",
    "HEROKU_API_KEY",
    "RENDER_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "CF_API_TOKEN",
    "CF_API_KEY",
    "DIGITALOCEAN_TOKEN",
    "DIGITALOCEAN_ACCESS_TOKEN",
    "LINODE_TOKEN",
    "VULTR_API_KEY",
    "HCLOUD_TOKEN",
    // HashiCorp
    "VAULT_TOKEN",
    "CONSUL_HTTP_TOKEN",
    "NOMAD_TOKEN",
    "TF_TOKEN_app_terraform_io",
    // Backend services
    "SUPABASE_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "FIREBASE_TOKEN",
    "NGROK_AUTHTOKEN",
    "ALGOLIA_API_KEY",
    "ALGOLIA_ADMIN_KEY",
    // IaC
    "PULUMI_ACCESS_TOKEN",
    "DOPPLER_TOKEN",
    "ANSIBLE_VAULT_PASSWORD",
    // Feature flags
    "LAUNCHDARKLY_SDK_KEY",
    // Productivity / project management
    "LINEAR_API_KEY",
    "NOTION_TOKEN",
    "ASANA_TOKEN",
    "JIRA_API_TOKEN",
    "CONFLUENCE_API_TOKEN",
    "PAGERDUTY_TOKEN",
    "SEGMENT_WRITE_KEY",
    // Database connection strings (often embed passwords)
    "DATABASE_URL",
    "REDIS_URL",
    "REDIS_PASSWORD",
    "PGPASSWORD",
    "MONGODB_URI",
    "MONGO_URL",
    "MYSQL_PASSWORD",
];

pub fn scan_host_credentials(project_dir: &Path, logs_dir: &Path) -> Result<HostScanReport> {
    let mut findings = Vec::new();
    let project_context = derive_project_context(project_dir)?;
    let home = dirs::home_dir();

    if let Some(home) = &home {
        scan_ssh(home, &mut findings)?;
        scan_git_credentials(home, &mut findings)?;
        scan_ai_ml(home, &mut findings)?;
        scan_cloud_providers(home, &mut findings)?;
        scan_hashicorp(home, &mut findings)?;
        scan_package_managers(home, &mut findings)?;
        scan_databases(home, &mut findings)?;
        scan_containers(home, &mut findings)?;
        scan_ci_cd(home, &mut findings)?;
        scan_saas(home, &mut findings)?;
        scan_identity(home, &mut findings)?;
        scan_iac(home, &mut findings)?;
        scan_misc(home, &mut findings)?;
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

// ---------------------------------------------------------------------------
// Host scan: category functions
// ---------------------------------------------------------------------------

fn scan_git_credentials(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    push_if_exists(home.join(".git-credentials"), "Git Credential Store", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("git").join("credentials"), "Git Credential Store (XDG)", "host_scan", findings)?;
    push_if_exists(home.join(".gitconfig"), "Git Global Config", "host_scan", findings)?;
    Ok(())
}

fn scan_ai_ml(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // Claude
    push_if_exists(home.join(".claude").join(".credentials.json"), "Claude OAuth Credentials", "host_scan", findings)?;
    push_if_exists(home.join(".claude.json"), "Claude Local Config", "host_scan", findings)?;
    // Codex
    push_if_exists(home.join(".codex").join("auth.json"), "Codex Auth Store", "host_scan", findings)?;
    push_if_exists(home.join(".codex").join("config.toml"), "Codex Local Config", "host_scan", findings)?;
    // GitHub Copilot
    push_if_exists(home.join(".config").join("github-copilot").join("hosts.json"), "GitHub Copilot Auth", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("github-copilot").join("apps.json"), "GitHub Copilot Apps", "host_scan", findings)?;
    // HuggingFace
    push_if_exists(home.join(".cache").join("huggingface").join("token"), "HuggingFace Token", "host_scan", findings)?;
    push_if_exists(home.join(".huggingface").join("token"), "HuggingFace Token", "host_scan", findings)?;
    // Replicate
    push_if_exists(home.join(".config").join("replicate").join("auth"), "Replicate Auth", "host_scan", findings)?;
    // Cohere
    push_if_exists(home.join(".config").join("cohere").join("config"), "Cohere CLI Config", "host_scan", findings)?;
    // Cursor
    push_if_exists(home.join(".cursor").join("mcp.json"), "Cursor MCP Config", "host_scan", findings)?;
    Ok(())
}

fn scan_cloud_providers(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // AWS
    push_if_exists(home.join(".aws").join("credentials"), "AWS Credentials File", "host_scan", findings)?;
    push_if_exists(home.join(".aws").join("config"), "AWS Config File", "host_scan", findings)?;
    // GCP
    push_if_exists(home.join(".config").join("gcloud").join("application_default_credentials.json"), "GCP Application Default Credentials", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("gcloud").join("access_tokens.db"), "GCP Access Token Cache", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("gcloud").join("credentials.db"), "GCP Credentials Database", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("gcloud").join("properties"), "GCP Properties Config", "host_scan", findings)?;
    push_if_exists(home.join(".boto"), "GCS Boto Config", "host_scan", findings)?;
    scan_dir_files(home.join(".config").join("gcloud").join("legacy_credentials"), &["json", "db"], "GCP Legacy Credential Artifact", "host_scan", findings)?;
    // Azure
    scan_dir_files(home.join(".azure"), &["json", "pem", "key", "bin"], "Azure Credential Artifact", "host_scan", findings)?;
    // DigitalOcean
    push_if_exists(home.join(".config").join("doctl").join("config.yaml"), "DigitalOcean CLI Config", "host_scan", findings)?;
    // Linode
    push_if_exists(home.join(".config").join("linode-cli"), "Linode CLI Config", "host_scan", findings)?;
    // Vultr
    push_if_exists(home.join(".vultr-cli.yaml"), "Vultr CLI Config", "host_scan", findings)?;
    // Hetzner
    push_if_exists(home.join(".config").join("hcloud").join("cli.toml"), "Hetzner Cloud CLI Config", "host_scan", findings)?;
    // Oracle Cloud
    push_if_exists(home.join(".oci").join("config"), "Oracle Cloud CLI Config", "host_scan", findings)?;
    // IBM Cloud
    push_if_exists(home.join(".bluemix").join("config.json"), "IBM Cloud CLI Config", "host_scan", findings)?;
    push_if_exists(home.join(".bluemix").join(".cf").join("config.json"), "IBM Cloud CF Config", "host_scan", findings)?;
    // Cloudflare / Wrangler
    push_if_exists(home.join(".wrangler").join("config").join("default.toml"), "Cloudflare Wrangler Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join(".wrangler").join("config").join("default.toml"), "Cloudflare Wrangler Config", "host_scan", findings)?;
    // Vercel
    push_if_exists(home.join(".config").join("vercel").join("auth.json"), "Vercel CLI Auth", "host_scan", findings)?;
    push_if_exists(home.join(".local").join("share").join("com.vercel.cli").join("auth.json"), "Vercel CLI Auth", "host_scan", findings)?;
    // Netlify
    push_if_exists(home.join(".netlify").join("config.json"), "Netlify CLI Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("netlify").join("config.json"), "Netlify CLI Config", "host_scan", findings)?;
    // Fly.io
    push_if_exists(home.join(".fly").join("config.yml"), "Fly.io CLI Config", "host_scan", findings)?;
    // Railway
    push_if_exists(home.join(".railway").join("config.json"), "Railway CLI Config", "host_scan", findings)?;
    // Render
    push_if_exists(home.join(".render").join("config.yaml"), "Render CLI Config", "host_scan", findings)?;
    // Heroku
    push_if_exists(home.join(".config").join("heroku").join("config.json"), "Heroku CLI Config", "host_scan", findings)?;
    // Scaleway
    push_if_exists(home.join(".config").join("scw").join("config.yaml"), "Scaleway CLI Config", "host_scan", findings)?;
    // Alibaba Cloud
    push_if_exists(home.join(".aliyun").join("config.json"), "Alibaba Cloud CLI Config", "host_scan", findings)?;
    // Tencent Cloud
    push_if_exists(home.join(".tccli").join("default.credential"), "Tencent Cloud CLI Credentials", "host_scan", findings)?;
    // OpenStack
    push_if_exists(home.join(".config").join("openstack").join("clouds.yaml"), "OpenStack Clouds Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("openstack").join("secure.yaml"), "OpenStack Secure Config", "host_scan", findings)?;
    Ok(())
}

fn scan_hashicorp(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    push_if_exists(home.join(".vault-token"), "HashiCorp Vault Token", "host_scan", findings)?;
    push_if_exists(home.join(".consul-token"), "HashiCorp Consul Token", "host_scan", findings)?;
    push_if_exists(home.join(".nomad-token"), "HashiCorp Nomad Token", "host_scan", findings)?;
    push_if_exists(home.join(".terraformrc"), "Terraform CLI Config", "host_scan", findings)?;
    push_if_exists(home.join(".terraform.d").join("credentials.tfrc.json"), "Terraform Cloud Credentials", "host_scan", findings)?;
    push_if_exists(home.join(".pulumi").join("credentials.json"), "Pulumi Credentials", "host_scan", findings)?;
    Ok(())
}

fn scan_package_managers(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // npm / yarn / pnpm
    push_if_exists(home.join(".npmrc"), "NPM Token Config", "host_scan", findings)?;
    push_if_exists(home.join(".yarnrc"), "Yarn Token Config", "host_scan", findings)?;
    push_if_exists(home.join(".yarnrc.yml"), "Yarn 2+ Token Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("pnpm").join("rc"), "pnpm Config", "host_scan", findings)?;
    // Python
    push_if_exists(home.join(".pypirc"), "Python Package Index Credential File", "host_scan", findings)?;
    push_if_exists(home.join(".pip").join("pip.conf"), "Pip Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("pip").join("pip.conf"), "Pip Config (XDG)", "host_scan", findings)?;
    // Ruby
    push_if_exists(home.join(".gem").join("credentials"), "RubyGems Credentials", "host_scan", findings)?;
    push_if_exists(home.join(".bundle").join("config"), "Bundler Config", "host_scan", findings)?;
    // Rust
    push_if_exists(home.join(".cargo").join("credentials.toml"), "Cargo Registry Token", "host_scan", findings)?;
    push_if_exists(home.join(".cargo").join("credentials"), "Cargo Registry Token", "host_scan", findings)?;
    // Java
    push_if_exists(home.join(".m2").join("settings.xml"), "Maven Settings", "host_scan", findings)?;
    push_if_exists(home.join(".m2").join("settings-security.xml"), "Maven Master Password", "host_scan", findings)?;
    push_if_exists(home.join(".gradle").join("gradle.properties"), "Gradle Properties", "host_scan", findings)?;
    // .NET
    push_if_exists(home.join(".config").join("NuGet").join("NuGet.Config"), "NuGet Config", "host_scan", findings)?;
    push_if_exists(home.join(".nuget").join("NuGet").join("NuGet.Config"), "NuGet Config", "host_scan", findings)?;
    // PHP
    push_if_exists(home.join(".composer").join("auth.json"), "Composer Auth Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("composer").join("auth.json"), "Composer Auth Config", "host_scan", findings)?;
    // Go
    push_if_exists(home.join(".config").join("go").join("env"), "Go Env Config", "host_scan", findings)?;
    // Elixir
    push_if_exists(home.join(".hex").join("hex.config"), "Hex.pm Credentials", "host_scan", findings)?;
    Ok(())
}

fn scan_databases(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    push_if_exists(home.join(".pgpass"), "PostgreSQL Password File", "host_scan", findings)?;
    push_if_exists(home.join(".pg_service.conf"), "PostgreSQL Service Config", "host_scan", findings)?;
    push_if_exists(home.join(".my.cnf"), "MySQL Config", "host_scan", findings)?;
    push_if_exists(home.join(".mylogin.cnf"), "MySQL Login Path", "host_scan", findings)?;
    push_if_exists(home.join(".mongoshrc.js"), "MongoDB Shell Config", "host_scan", findings)?;
    push_if_exists(home.join(".dbshell"), "MongoDB Legacy Shell History", "host_scan", findings)?;
    push_if_exists(home.join(".rediscli_history"), "Redis CLI History", "host_scan", findings)?;
    Ok(())
}

fn scan_containers(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // Docker
    push_if_exists(home.join(".docker").join("config.json"), "Docker Config", "host_scan", findings)?;
    scan_dir_files(home.join(".docker").join("trust").join("private"), &["key"], "Docker Content Trust Key", "host_scan", findings)?;
    // Kubernetes
    push_if_exists(home.join(".kube").join("config"), "Kubernetes Config", "host_scan", findings)?;
    // Podman / container registries
    push_if_exists(home.join(".config").join("containers").join("auth.json"), "Container Registry Auth (Podman)", "host_scan", findings)?;
    // Helm
    push_if_exists(home.join(".config").join("helm").join("registry").join("config.json"), "Helm Registry Auth", "host_scan", findings)?;
    Ok(())
}

fn scan_ci_cd(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // GitHub CLI
    push_if_exists(home.join(".config").join("gh").join("hosts.yml"), "GitHub CLI Auth Store", "host_scan", findings)?;
    // GitLab CLI
    push_if_exists(home.join(".config").join("glab-cli").join("config.yml"), "GitLab CLI Auth Store", "host_scan", findings)?;
    // CircleCI
    push_if_exists(home.join(".circleci").join("cli.yml"), "CircleCI CLI Config", "host_scan", findings)?;
    // Travis CI
    push_if_exists(home.join(".travis").join("config.yml"), "Travis CI CLI Config", "host_scan", findings)?;
    // Bitbucket
    push_if_exists(home.join(".bitbucket").join("credentials"), "Bitbucket CLI Credentials", "host_scan", findings)?;
    Ok(())
}

fn scan_saas(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // Stripe
    push_if_exists(home.join(".config").join("stripe").join("config.toml"), "Stripe CLI Config", "host_scan", findings)?;
    // Twilio
    push_if_exists(home.join(".twilio-cli").join("config.json"), "Twilio CLI Config", "host_scan", findings)?;
    // Sentry
    push_if_exists(home.join(".sentryclirc"), "Sentry CLI Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("sentry-cli").join("config.ini"), "Sentry CLI Config", "host_scan", findings)?;
    // Firebase
    push_if_exists(home.join(".config").join("configstore").join("firebase-tools.json"), "Firebase CLI Credentials", "host_scan", findings)?;
    // Supabase
    push_if_exists(home.join(".config").join("supabase").join("access-token"), "Supabase CLI Token", "host_scan", findings)?;
    // Expo
    push_if_exists(home.join(".expo").join("auth.json"), "Expo CLI Auth", "host_scan", findings)?;
    // Shopify
    push_if_exists(home.join(".config").join("shopify-cli").join("config.json"), "Shopify CLI Config", "host_scan", findings)?;
    // ngrok
    push_if_exists(home.join(".config").join("ngrok").join("ngrok.yml"), "ngrok Config", "host_scan", findings)?;
    push_if_exists(home.join(".ngrok2").join("ngrok.yml"), "ngrok Config", "host_scan", findings)?;
    // WakaTime
    push_if_exists(home.join(".wakatime.cfg"), "WakaTime Config", "host_scan", findings)?;
    // Datadog
    push_if_exists(home.join(".config").join("configstore").join("datadog-ci.json"), "Datadog CI Config", "host_scan", findings)?;
    // Slack
    push_if_exists(home.join(".config").join("slack-cli").join("config.json"), "Slack CLI Config", "host_scan", findings)?;
    // PagerDuty
    push_if_exists(home.join(".config").join("pagerduty-cli").join("config.json"), "PagerDuty CLI Config", "host_scan", findings)?;
    // Linear
    push_if_exists(home.join(".config").join("linear").join("config.json"), "Linear CLI Config", "host_scan", findings)?;
    // Segment
    push_if_exists(home.join(".config").join("segment").join("config.json"), "Segment CLI Config", "host_scan", findings)?;
    // LaunchDarkly
    push_if_exists(home.join(".config").join("launchdarkly").join("config.json"), "LaunchDarkly CLI Config", "host_scan", findings)?;
    Ok(())
}

fn scan_identity(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // Okta
    push_if_exists(home.join(".okta").join("okta.yaml"), "Okta CLI Config", "host_scan", findings)?;
    push_if_exists(home.join(".config").join("okta").join("okta.yaml"), "Okta CLI Config", "host_scan", findings)?;
    // Auth0
    push_if_exists(home.join(".config").join("auth0").join("config.json"), "Auth0 CLI Config", "host_scan", findings)?;
    // SAML2AWS
    push_if_exists(home.join(".saml2aws"), "SAML2AWS Config", "host_scan", findings)?;
    // 1Password CLI
    push_if_exists(home.join(".config").join("op").join("config"), "1Password CLI Config", "host_scan", findings)?;
    push_if_exists(home.join(".op").join("config"), "1Password CLI Config", "host_scan", findings)?;
    // Bitwarden CLI
    push_if_exists(home.join(".config").join("Bitwarden CLI").join("data.json"), "Bitwarden CLI Data", "host_scan", findings)?;
    Ok(())
}

fn scan_iac(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // Ansible
    push_if_exists(home.join(".ansible").join("galaxy_token"), "Ansible Galaxy Token", "host_scan", findings)?;
    push_if_exists(home.join(".ansible.cfg"), "Ansible Config", "host_scan", findings)?;
    // Chef
    push_if_exists(home.join(".chef").join("credentials"), "Chef Credentials", "host_scan", findings)?;
    scan_dir_files(home.join(".chef"), &["pem"], "Chef Client Key", "host_scan", findings)?;
    Ok(())
}

fn scan_misc(home: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    // Netrc (used by Heroku, curl, etc.)
    push_if_exists(home.join(".netrc"), "Netrc Credential File", "host_scan", findings)?;
    // rclone (cloud storage credentials)
    push_if_exists(home.join(".config").join("rclone").join("rclone.conf"), "rclone Config", "host_scan", findings)?;
    // S3cmd
    push_if_exists(home.join(".s3cfg"), "S3cmd Config", "host_scan", findings)?;
    // SOPS / Age encryption keys
    push_if_exists(home.join(".config").join("sops").join("age").join("keys.txt"), "SOPS/Age Encryption Keys", "host_scan", findings)?;
    // Doppler
    push_if_exists(home.join(".doppler").join(".doppler.yaml"), "Doppler CLI Config", "host_scan", findings)?;
    // mkcert local CA
    push_if_exists(home.join(".local").join("share").join("mkcert").join("rootCA-key.pem"), "mkcert Root CA Private Key", "host_scan", findings)?;
    // Homebrew
    push_if_exists(home.join(".config").join("homebrew").join("brew.env"), "Homebrew Env Config", "host_scan", findings)?;
    // Tailscale
    push_if_exists(home.join(".config").join("tailscale"), "Tailscale Config", "host_scan", findings)?;
    // Earthly
    push_if_exists(home.join(".earthly").join("config.yml"), "Earthly Config", "host_scan", findings)?;
    // Nix (may contain access-tokens)
    push_if_exists(home.join(".config").join("nix").join("nix.conf"), "Nix Config", "host_scan", findings)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Project scan
// ---------------------------------------------------------------------------

fn scan_project_candidates(project_dir: &Path, findings: &mut Vec<HostCredentialFinding>) -> Result<()> {
    let candidates: Vec<(PathBuf, &str)> = vec![
        // .env variants
        (project_dir.join(".env"), "Project .env Credential File"),
        (project_dir.join(".env.local"), "Project .env Credential File"),
        (project_dir.join(".env.development"), "Project .env Credential File"),
        (project_dir.join(".env.production"), "Project .env Credential File"),
        (project_dir.join(".env.staging"), "Project .env Credential File"),
        (project_dir.join(".env.test"), "Project .env Credential File"),
        // Package managers
        (project_dir.join(".npmrc"), "Project NPM Token Config"),
        (project_dir.join(".pypirc"), "Project Python Package Index Credential File"),
        (project_dir.join(".netrc"), "Project Netrc Credential File"),
        (project_dir.join(".yarnrc.yml"), "Project Yarn Token Config"),
        // AI agent configs
        (project_dir.join(".claude").join("settings.local.json"), "Claude Project Settings"),
        (project_dir.join(".codex").join("config.toml"), "Codex Project Config"),
        (project_dir.join(".cursor").join("mcp.json"), "Cursor MCP Config"),
        // Cloud / infra
        (project_dir.join(".aws").join("credentials"), "Project AWS Credentials File"),
        (project_dir.join(".kube").join("config"), "Project Kubernetes Config"),
        // IaC state (may contain provider credentials)
        (project_dir.join("terraform.tfstate"), "Terraform State File"),
        // Docker compose (may embed passwords in environment sections)
        (project_dir.join("docker-compose.yml"), "Docker Compose File"),
        (project_dir.join("docker-compose.yaml"), "Docker Compose File"),
        // Firebase / Vercel project configs
        (project_dir.join("firebase.json"), "Firebase Project Config"),
        (project_dir.join(".vercel").join("project.json"), "Vercel Project Config"),
        // Sentry
        (project_dir.join(".sentryclirc"), "Sentry Project Config"),
        // Ludus
        (project_dir.join("ludus.conf"), "Project Ludus Config"),
        // SSH keys (shouldn't be in project root but sometimes are)
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
                | ".yarnrc.yml"
                | "credentials"
                | "config"
                | "config.json"
                | "secrets.json"
                | "secret.json"
                | "ludus.conf"
                | "kubeconfig"
                | "terraform.tfvars"
                | "terraform.tfvars.json"
                | "terraform.tfstate"
                | "docker-compose.yml"
                | "docker-compose.yaml"
                | "firebase.json"
        )
        || (name.starts_with("id_") && !name.ends_with(".pub"))
        || name.contains("secret")
        || name.contains("credential")
        || name.contains("kubeconfig")
        || name.ends_with(".tfvars")
        || name.ends_with(".tfstate")
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
    if name.ends_with(".tfstate") {
        return "Terraform State File";
    }
    if name == "docker-compose.yml" || name == "docker-compose.yaml" {
        return "Docker Compose File";
    }
    if name == "firebase.json" {
        return "Firebase Project Config";
    }
    if name.starts_with("id_") && !name.ends_with(".pub") {
        return "Project Private Key File";
    }
    if matches!(path.extension().and_then(|ext| ext.to_str()), Some("pem" | "key")) {
        return "Project Private Key File";
    }
    "Project Generated Secret Candidate"
}

// ---------------------------------------------------------------------------
// Ludus (existing, unchanged)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Project context derivation (unchanged)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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

fn is_documentation_file(ext: &str) -> bool {
    matches!(ext, "md" | "txt" | "rst" | "adoc")
}
