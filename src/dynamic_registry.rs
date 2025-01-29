//dynamic_registry.rs

use std::collections::HashMap;
use std::sync::RwLock;
use lazy_static::lazy_static;
use crate::cliconfig::CliContext;
use crate::clock_settings::Clock;
use crate::execute::{Command, Mode};
use crate::walkup::ModeHierarchy;

lazy_static! {
    /// Global registry for dynamic commands with thread-safe access
    pub static ref DYNAMIC_COMMANDS: RwLock<HashMap<&'static str, Command>> = RwLock::new(HashMap::new());
    pub static ref MODE_PERMISSIONS: RwLock<HashMap<&'static str, Vec<Mode>>> = RwLock::new(HashMap::new());
}

/// Registers a new command dynamically with comprehensive configuration options
pub fn register_command(
    name: &'static str,
    description: &'static str,
    suggestions: Option<Vec<&'static str>>,
    suggestions1: Option<Vec<&'static str>>,
    options: Option<Vec<&'static str>>,
    execute: fn(&[&str], &mut CliContext, &mut Option<Clock>) -> Result<(), String>,
    allowed_modes: Option<Vec<Mode>>, // New parameter to specify allowed modes
) -> Result<(), String> {
    let command = Command {
        name,
        description,
        suggestions,
        suggestions1,
        options,
        execute,
    };
    
    let mut commands = DYNAMIC_COMMANDS
        .write()
        .map_err(|_| "Failed to acquire write lock")?;
    
    // Store the command with optional mode restrictions
    commands.insert(name, command);
    
    if let Some(modes) = allowed_modes {
        let mut permissions = MODE_PERMISSIONS
            .write()
            .map_err(|_| "Failed to acquire permissions write lock")?;
        permissions.insert(name, modes);
    }

    println!("Dynamic commands registry now contains: {:?}", 
        commands.keys().collect::<Vec<_>>()
    );
    // If modes are specified, you can add additional mode-based logic here
    
    Ok(())
}

/// Retrieves all registered dynamic commands
pub fn get_registered_commands() -> Result<HashMap<&'static str, Command>, String> {
    let commands = DYNAMIC_COMMANDS
        .read()
        .map_err(|_| "Failed to acquire read lock")?;
    
    Ok(commands.clone())
}

/// Checks if a command is allowed in a specific mode
pub fn is_dynamic_command_allowed_in_mode(command_name: &str, mode: &Mode) -> bool {
    let mode_hierarchy = ModeHierarchy::new();
    
    // First, check if the command exists in the dynamic registry
    let commands = match DYNAMIC_COMMANDS.read() {
        Ok(cmds) => cmds,
        Err(_) => return false,
    };
    
    // If command doesn't exist, return false
    if !commands.contains_key(command_name) {
        return false;
    }
    
    // Use the walkup method to determine command validity
    match mode_hierarchy.walkup_find_command(mode.clone(), command_name) {
        Some(_) => true,
        None => false,
    }
}

pub fn get_commands_for_mode(mode: &Mode) -> Vec<&'static str> {
    let mut allowed_commands = Vec::new();
    
    if let (Ok(permissions), Ok(commands)) = (MODE_PERMISSIONS.read(), DYNAMIC_COMMANDS.read()) {
        for (command_name, allowed_modes) in permissions.iter() {
            if allowed_modes.contains(mode) || 
               (mode == &Mode::PrivilegedMode && allowed_modes.contains(&Mode::UserMode)) ||
               (mode == &Mode::ConfigMode && (allowed_modes.contains(&Mode::UserMode) || 
                                            allowed_modes.contains(&Mode::PrivilegedMode))) ||
               (mode == &Mode::InterfaceMode && (allowed_modes.contains(&Mode::UserMode) || 
                                                allowed_modes.contains(&Mode::PrivilegedMode) ||
                                                allowed_modes.contains(&Mode::ConfigMode))) {
                if commands.contains_key(command_name) {
                    allowed_commands.push(*command_name);
                }
            }
        }
    }
    
    allowed_commands
}

pub fn get_mode_commands_FNC<'a>(commands: &'a HashMap<&str, Command>, mode: &Mode) -> Vec<&'a str> {
    if let Ok(permissions) = MODE_PERMISSIONS.read() {
        // Filter commands based on the mode permissions
        commands
            .keys()
            .filter(|&cmd_name| {
                if let Some(allowed_modes) = permissions.get(cmd_name) {
                    allowed_modes.contains(mode)
                } else {
                    false // If no permissions specified, command is not available
                }
            })
            .copied()
            .collect()
    } else {
        // Return empty vec if we can't read the permissions
        Vec::new()
    }   //.into_iter().collect()
    
}