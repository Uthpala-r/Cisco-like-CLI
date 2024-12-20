use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::execute::Mode;

/// A structure representing the configuration for the CLI.
///
/// This struct holds the current running configuration, the startup configuration, and the hostname of the system.
#[derive(Serialize, Deserialize, Clone)]
pub struct CliConfig {
    pub running_config: HashMap<String, String>,
    pub startup_config: HashMap<String, String>,
    pub hostname: String,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            running_config: HashMap::new(),
            startup_config: HashMap::new(),
            hostname: "Router".to_string(),
        }
    }
}


pub struct CliContext {
    pub current_mode: Mode,
    pub prompt: String,
    pub config: CliConfig,
}


impl Default for CliContext {
    fn default() -> Self {
        Self {
            current_mode: Mode::UserMode,
            prompt: "Router>".into(),
            config: CliConfig::default(),
        }
    }
}