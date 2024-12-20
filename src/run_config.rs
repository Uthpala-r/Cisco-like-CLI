use crate::cliconfig::CliConfig;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

pub fn save_config(config: &CliConfig) -> std::io::Result<()> {
    let serialized = serde_json::to_string_pretty(config)?;
    let mut file = OpenOptions::new()
        .create(true) 
        .write(true)  
        .truncate(true) 
        .open("startup-config.json")?;
    file.write_all(serialized.as_bytes())
}

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