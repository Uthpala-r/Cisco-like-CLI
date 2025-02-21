//walkup.rs

/// A module for managing and executing commands in a hierarchical mode structure.
/// This module defines the `Mode` enum, `ModeHierarchy` struct, and associated functions
/// for navigating through command modes and executing commands

use crate::execute::Mode;
use crate::dynamic_registry::{get_mode_commands_FNC, DYNAMIC_COMMANDS};
use std::collections::HashMap;
use std::fmt;

impl fmt::Display for Mode {
    /// Implements the `fmt::Display` trait for the `Mode` enum, enabling user-friendly
    /// string representation of a mode.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Represents the hierarchy of modes and their relationships.
/// Modes can have parent modes, allowing commands to be inherited
/// from higher-level modes.
pub struct ModeHierarchy {
    /// A mapping of each mode to its parent mode.
    /// If a mode has no parent, the value will be `None`.
    pub parent_map: HashMap<Mode, Option<Mode>>,
}

impl ModeHierarchy {
    /// Creates a new `ModeHierarchy` with predefined parent-child relationships
    /// between various command modes.
    ///
    /// # Returns
    /// A new instance of `ModeHierarchy` with the initialized parent map.
    pub fn new() -> Self {
        let mut parent_map = HashMap::new();
        
        parent_map.insert(Mode::UserMode, None);
        parent_map.insert(Mode::PrivilegedMode, Some(Mode::UserMode));
        parent_map.insert(Mode::ConfigMode, Some(Mode::PrivilegedMode));  
        
        Self { parent_map }
    }

    /// Finds the mode in which a given command is valid, starting from the
    /// `initial_mode` and walking up the hierarchy until the command is found
    /// or the top of the hierarchy is reached.
    ///
    /// # Arguments
    /// * `initial_mode` - The starting mode to search from.
    /// * `command` - The command to search for.
    ///
    /// # Returns
    /// * `Some(Mode)` - The mode in which the command is valid.
    /// * `None` - If the command is not valid in any mode.
    pub fn walkup_find_command(&self, initial_mode: Mode, command: &str) -> Option<Mode> {
        let mut current_mode = initial_mode;
        
        loop {
            // Try to match the command in the current mode
            if Self::is_command_allowed_in_mode(command, &current_mode) || 
                get_mode_commands_FNC(&DYNAMIC_COMMANDS.read().unwrap(), &current_mode)
                    .contains(&command){
                return Some(current_mode);
            }
            
            // If no parent mode exists, command is not valid
            let parent_mode = match self.parent_map.get(&current_mode) {
                Some(mode) => mode.clone(),
                None => return None
            };
            
            // If we've reached the top of the hierarchy, stop
            if parent_mode.is_none() {
                return None;
            }
            
            // Move to parent mode
            current_mode = parent_mode.unwrap();
        }
    }

    /// Checks if a command is allowed in a specific mode.
    ///
    /// # Arguments
    /// * `command` - The command to check.
    /// * `mode` - The mode to check the command against.
    ///
    /// # Returns
    /// * `true` - If the command is allowed in the mode.
    /// * `false` - Otherwise.
    pub fn is_command_allowed_in_mode(command: &str, mode: &Mode) -> bool {
        match mode {
            Mode::UserMode => 
                command == "enable" ||
                command == "ping" ||
                command == "help" ||
                command == "show" ||
                command == "clear" ||
                command == "reload" ||
                command == "connect" ||
                command == "disable" ||
                command == "traceroute" ||
                command == "do" ||
                command == "exit",
            Mode::PrivilegedMode => 
                command == "configure" ||
                command == "ping" || 
                command == "exit" || 
                command == "write" ||
                command == "help" ||
                command == "show" ||
                command == "copy" ||
                command == "clock" ||
                command == "clear" ||
                command == "reload" ||
                command == "debug" ||
                command == "undebug" ||
                command == "connect" ||
                command == "traceroute" ||
                command == "disable" ||
                command == "ssh" ||
                command == "do" ||
                command == "ifconfig",
            Mode::ConfigMode => 
                command == "hostname" || 
                command == "interface" ||
                command == "ping" ||
                command == "exit" ||
                command == "clear" ||
                command == "help" ||
                command == "write" ||
                command == "service" ||
                command == "enable" ||
                command == "ifconfig" ||  
                command == "ntp" ||
                command == "no" || 
                command == "reload" ||
                command == "connect" ||
                command == "traceroute" ||
                command == "do" ||
                command == "disable",
            Mode::InterfaceMode => 
                command == "shutdown" ||
                command == "no" ||
                command == "exit" ||
                command == "clear" ||
                command == "help" ||
                command == "write" ||
                command == "reload" ||
                command == "do" ||
                command == "ip" ,
    
        }
        
    }

}

/// Represents the current command context, including the current mode
/// and the hierarchy of modes.
pub struct CommandContext{
    /// The current mode of the command context.
    pub current_mode: Mode,
    /// The mode hierarchy for navigating through command modes.
    pub mode_hierarchy: ModeHierarchy,
}

impl CommandContext  {
    /// Creates a new `CommandContext` with the default starting mode (`UserMode`)
    /// and an initialized mode hierarchy.
    ///
    /// # Returns
    /// A new instance of `CommandContext`.
    fn new() -> Self {
        Self {
            current_mode: Mode::UserMode,
            mode_hierarchy: ModeHierarchy::new(),
            //commands,
        }
    }

    /// Executes a command in the current context.
    /// If the command is not valid in the current mode, the function
    /// walks up the hierarchy to find a mode in which the command is valid.
    ///
    /// # Arguments
    /// * `command` - The command to execute.
    pub fn execute_command(&mut self, command: &str) -> Result<(), String> {
        match self.mode_hierarchy.walkup_find_command(self.current_mode.clone(), command) {
            Some(valid_mode) => {
                if valid_mode != self.current_mode {
                    println!("Walkup: Command '{}' found in {} mode", command, valid_mode);
                }
                self.current_mode = valid_mode;
                self.process_command(command)
            }
            None => Err(format!("Command '{}' not valid in current mode", command)),
        }
    }

    pub fn process_command(&self, command: &str) -> Result<(), String> {
        println!("Executing command '{}' in {:?} mode", command, self.current_mode);
        Ok(())
    }
}