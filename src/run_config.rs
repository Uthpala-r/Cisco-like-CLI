/// External crates for the CLI application
use crate::cliconfig::CliConfig;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};


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