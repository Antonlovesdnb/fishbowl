use std::fs;
use std::path::Path;

use serde::Deserialize;

const CONFIG_FILE_NAME: &str = ".fishbowl.toml";

#[derive(Debug, Default, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub mounts: Vec<String>,
    pub network: Option<String>,
    pub monitor: Option<String>,
}

pub fn load_project_config(project_dir: &Path) -> Option<ProjectConfig> {
    let config_path = project_dir.join(CONFIG_FILE_NAME);
    if !config_path.is_file() {
        return None;
    }
    let content = fs::read_to_string(&config_path).ok()?;
    let config: ProjectConfig = toml::from_str(&content).ok()?;
    println!(
        "[Fishbowl] Loaded project config from {}",
        config_path.display()
    );

    // Network and monitor overrides from project config are security posture
    // changes. A malicious repo could set network = "host" (bypass network
    // isolation) or monitor = "basic" (disable strong monitoring). These
    // should only come from CLI flags, not from untrusted project files.
    if config.network.is_some() {
        eprintln!(
            "[Fishbowl] WARNING: project config sets network = {:?} — ignored. Use --network on the CLI to change network mode.",
            config.network.as_deref().unwrap_or("?")
        );
    }
    if config.monitor.is_some() {
        eprintln!(
            "[Fishbowl] WARNING: project config sets monitor = {:?} — ignored. Use --monitor on the CLI to change monitoring level.",
            config.monitor.as_deref().unwrap_or("?")
        );
    }

    Some(config)
}
