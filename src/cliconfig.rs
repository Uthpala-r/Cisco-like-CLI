/// External crates for the CLI application
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::execute::Mode;


/// Represents the configuration for the CLI application.
///
/// This structure holds the following configuration details:
/// - `running_config`: A map containing the currently active configuration settings.
/// - `startup_config`: A map containing the startup configuration settings loaded at initialization.
/// - `hostname`: The hostname of the system.
///
/// # Examples
/// ```
/// let config = CliConfig::default();
/// assert_eq!(config.hostname, "Router");
/// ```
/// 
#[derive(Serialize, Deserialize, Clone)]
pub struct CliConfig {
    pub running_config: HashMap<String, String>,
    pub startup_config: HashMap<String, String>,
    pub hostname: String,
}


impl Default for CliConfig {
    
    /// Provides the default values for `CliConfig`.
    ///
    /// - `running_config`: An empty `HashMap`.
    /// - `startup_config`: An empty `HashMap`.
    /// - `hostname`: `"Router"`.
    fn default() -> Self {
        Self {
            running_config: HashMap::new(),
            startup_config: HashMap::new(),
            hostname: "Router".to_string(),
        }
    }
}


/// Represents the current context of the CLI application.
///
/// The `CliContext` maintains the state of the CLI, including the current operational mode,
/// the system prompt, the configuration, and the currently selected interface (if any).
///
/// # Examples
/// ```
/// let context = CliContext::default();
/// assert_eq!(context.prompt, "Router>");
/// ```
/// 
pub struct CliContext {
    pub current_mode: Mode,
    pub prompt: String,
    pub config: CliConfig,
    pub selected_interface: Option<String>,
    pub selected_vlan: Option<String>,
    pub vlan_names: Option<HashMap<String, String>>,  
    pub vlan_states: Option<HashMap<u16, String>>, 
    pub switchport_mode: Option<String>, 
    pub trunk_encapsulation: Option<String>, 
    pub native_vlan: Option<u16>, 
    pub allowed_vlans: HashSet<u16>,
}


impl Default for CliContext {

    /// Provides the default values for `CliContext`.
    ///
    /// - `current_mode`: `Mode::UserMode`.
    /// - `prompt`: `"Router>"`.
    /// - `config`: The default configuration provided by `CliConfig::default()`.
    /// - `selected_interface`: `None`.
    /// - `selected_vlan`: `None`.
    /// - `vlan_names`: `None`,
    /// - `vlan_states`: `None`,
    /// - `switchport_mode`: `None`,
    /// - `trunk_encapsulation`: `None`,
    /// - `native_vlan`: `None`,
    /// - `allowed_vlans`: `HashSet::new()`,
    fn default() -> Self {
        Self {
            current_mode: Mode::UserMode,
            prompt: "Router>".into(),
            config: CliConfig::default(),
            selected_interface: None,
            selected_vlan: None,
            vlan_names: None,
            vlan_states: None,
            switchport_mode: None,
            trunk_encapsulation: None,
            native_vlan: None,
            allowed_vlans: HashSet::new(),
        }
    }
}