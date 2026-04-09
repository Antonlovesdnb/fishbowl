use std::fs;
use std::path::Path;

use serde::Deserialize;

const CONFIG_FILE_NAME: &str = ".agentfence.toml";

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
        "[AgentFence] Loaded project config from {}",
        config_path.display()
    );
    Some(config)
}
