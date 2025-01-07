/// External crates for the CLI application
use crate::cliconfig::{CliConfig, CliContext};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use crate::network_config::{STATUS_MAP, IP_ADDRESS_STATE, ROUTE_TABLE, OSPF_CONFIG, ACL_STORE};


/// Saves the given `CliConfig` to a file named `startup-config.json`.
/// 
/// This function serializes the provided configuration into JSON format and writes it
/// to a file. If the file already exists, it will be overwritten. If the file does
/// not exist, it will be created. The JSON is formatted for readability (pretty-printed).
/// 
/// # Parameters
/// - `config`: The `CliConfig` object that contains the configuration to be saved.
/// 
/// # Returns
/// This function returns a `Result<(), std::io::Error>`. It will return `Ok(())` if the
/// file is successfully written, or an error if something goes wrong (e.g., file write failure).
/// 
/// # Example
/// ```
/// use crate::cliconfig::CliConfig;
/// let config = CliConfig::default(); // Example config
/// if let Err(e) = save_config(&config) {
///     eprintln!("Failed to save config: {}", e);
/// }
/// ```
pub fn save_config(config: &CliConfig) -> std::io::Result<()> {
    let serialized = serde_json::to_string_pretty(config)?;
    let mut file = OpenOptions::new()
        .create(true) 
        .write(true)  
        .truncate(true) 
        .open("startup-config.json")?;
    file.write_all(serialized.as_bytes())
}


/// Loads the configuration from the `startup-config.json` file.
/// 
/// This function attempts to read the `startup-config.json` file and deserialize its
/// contents into a `CliConfig` object. If the file cannot be opened, read, or parsed,
/// a default configuration will be returned.
/// 
/// # Returns
/// The function returns a `CliConfig` object. If loading the configuration fails, it
/// will return the default configuration as defined by `CliConfig::default()`.
/// 
/// # Example
/// ```
/// let config = load_config();
/// println!("Loaded config: {:?}", config);
/// ```
pub fn load_config() -> CliConfig {
    if let Ok(mut file) = File::open("startup-config.json") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            if let Ok(config) = serde_json::from_str::<CliConfig>(&contents) {
                return config;
            }
        }
    }
    CliConfig::default()
}


/// Retrieves the current running configuration of the device.
/// 
/// The running configuration is a volatile piece of information that reflects 
/// the current state of the device, including any changes made to it. This 
/// configuration is stored in memory rather than NVRAM, meaning it will be lost 
/// when the device loses power.
/// 
/// # Returns
/// A `String` representing the current running configuration of the device.
/// 
/// # Example
/// ```rust
/// let config = get_running_config();
/// println!("Running Configuration: {}", config);
/// ``` 
pub fn get_running_config(context: &CliContext) -> String {
    let hostname = &context.config.hostname;
    let encrypted_password = context.config.encrypted_password.clone().unwrap_or_default();
    let encrypted_secret = context.config.encrypted_secret.clone().unwrap_or_default();

    // Access global states
    let ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
    let status_map = STATUS_MAP.lock().unwrap();
    let route_table = ROUTE_TABLE.lock().unwrap();
    let ospf_config = OSPF_CONFIG.lock().unwrap();
    let acl_store = ACL_STORE.lock().unwrap();

    // Determine the active interface
    let interface = context
        .selected_interface
        .clone()
        .unwrap_or_else(|| "FastEthernet0/1".to_string());

    // Retrieve IP address and netmask for the interface
    let ip_address = ip_address_state
        .get(&interface)
        .map(|(ip, _)| ip.to_string())
        .unwrap_or_else(|| "no ip address".to_string());

    let mut route_entries = String::new();
    for (destination, (netmask, next_hop_or_iface)) in route_table.iter() {
        route_entries.push_str(&format!(
            "ip route {} {} {}\n",
            destination, netmask, next_hop_or_iface
        ));
    }

    let shutdown_status = if status_map.get(&interface).copied().unwrap_or(false) {
        "no shutdown"
    } else {
        "shutdown"
    };

    let ospf_process_id = ospf_config.process_id.map_or("N/A".to_string(), |id| id.to_string());
    let ospf_interface = ospf_config.passive_interfaces.join(", ");
    let mut ospf_network_configs = String::new();
    for (network_key, area_id) in ospf_config.networks.iter() {
        if let Some((ip_address, wildcard_mask)) = network_key.split_once(' ') {
            ospf_network_configs.push_str(&format!(
                "network {} {} area {}\n",
                ip_address, wildcard_mask, area_id
            ));
        }
    }

    let mut acl_configs = String::new();
    for acl in acl_store.values() {
        acl_configs.push_str(&format!("!\nip access-list extended {}\n", acl.number_or_name));
        for entry in &acl.entries {
            let protocol = entry.protocol.as_deref().unwrap_or("ip");
            let mut rule = format!(" {} {}", entry.action, protocol);
            rule.push_str(&format!(" {}", entry.source));
            if let (Some(op), Some(port)) = (&entry.source_operator, &entry.source_port) {
                rule.push_str(&format!(" {} {}", op, port));
            }
            rule.push_str(&format!(" {}", entry.destination));
            if let (Some(op), Some(port)) = (&entry.destination_operator, &entry.destination_port) {
                rule.push_str(&format!(" {} {}", op, port));
            }
            acl_configs.push_str(&format!("{}\n", rule));
        }
    }

    format!(
        r#"version 15.1
no service timestamps log datetime msec
{}
!
hostname {}
!
enable password 5 {}
enable secret 5 {}
!
interface {}
 ip address {}
 duplex auto
 speed auto
 {}
!
interface Vlan1
 no ip address
 shutdown
!
ip classes
{}
!
router ospf {}
 log-adjacency-changes
 passive-interface {}
 {}
!
{}
!
!
end
"#,
        if context.config.password_encryption {
            "service password-encryption"
        } else {
            "no service password-encryption"
        },
        hostname,
        encrypted_password,
        encrypted_secret,
        interface,
        ip_address,
        shutdown_status,
        route_entries,
        ospf_process_id,
        ospf_interface,
        ospf_network_configs,
        acl_configs,
    )
}


/// Retrieves the startup configuration of the device.
/// 
/// The startup configuration is a non-volatile piece of information that is 
/// stored in NVRAM. This configuration persists across device reboots and 
/// represents the settings that the device will use upon startup.
/// 
/// # Returns
/// A `String` representing the startup configuration of the device.
/// 
/// # Example
/// ```rust
/// let startup_config = default_startup_config();
/// println!("Startup Configuration: {}", startup_config);
/// ```
pub fn default_startup_config(_context: &mut CliContext) -> String {
    
    let startup_config = (
        
        r#"
Building configuration...

Current configuration : 0 bytes

version 15.1
no service timestamps log datetime msec
no service password-encryption
!
hostname Router
!
enable password 5 
enable secret 5 
!
interface FastEthernet0/0
no ip address
shutdown
!
!
end
"#
        .to_string()
    
);
    startup_config
}