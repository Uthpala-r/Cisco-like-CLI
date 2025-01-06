/// External crates for the CLI application
use crate::build_command_registry;
use crate::execute::Mode;
use crate::execute::Command;

use rustyline::hint::Hinter;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::validate::{Validator, ValidationContext, ValidationResult};
use rustyline::error::ReadlineError;
use std::collections::HashMap;


/// A custom completer for the CLI application.
///
/// The `CommandCompleter` provides suggestions for commands based on user input.
/// It integrates with the `rustyline` crate to offer real-time command-line assistance.
///
/// # Fields
/// - `commands`: A vector of strings containing the list of available commands.
/// - `current_mode`: Gets the current mode of the cli
/// 
#[derive(Clone)]
pub struct CommandCompleter {
    pub commands: HashMap<String, Vec<String>>,
    pub current_mode: Mode,
}

impl CommandCompleter {
    pub fn new(commands: HashMap<String, Vec<String>>, current_mode: Mode) -> Self {
        CommandCompleter {
            commands,
            current_mode,
        }
    }

}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    /// Generates a list of command suggestions based on the current user input.
    ///
    /// # Arguments
    /// - `line`: The current input line from the user.
    /// - `pos`: The cursor position within the line.
    /// - `_ctx`: The rustyline context.
    ///
    /// # Returns
    /// A tuple where:
    /// - The first element is the starting position of the match in the input line.
    /// - The second element is a vector of `Pair` objects representing the suggestions.
    ///
    /// # Errors
    /// Returns a `ReadlineError` if an error occurs during completion.
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Self::Candidate>), rustyline::error::ReadlineError> {
        let suggestions = build_command_registry();
        let mut candidates = Vec::new();

        let query = if pos <= line.len() {
            &line[..pos]
        } else {
            line
        };

        let parts: Vec<&str> = query.trim_end().split_whitespace().collect();

        // Filter commands allowed in the current mode
        let allowed_commands: Vec<(&str, &Command)> = suggestions
            .iter()
            .filter(|(&command, _)| is_command_allowed_in_mode(&command.to_string(), &self.current_mode))
            .map(|(command, cmd)| (*command, cmd))
            .collect();

        if parts.is_empty() {
            // No input yet: Show all allowed commands
            for (command_name, _) in allowed_commands.iter() {
                candidates.push(Pair {
                    display: command_name.to_string(),
                    replacement: command_name.to_string(),
                });
            }
        } else if parts.len() == 1 && !query.ends_with(' ') {
            // First tab: Suggest commands matching the input
            for (command_name, _) in allowed_commands.iter() {
                if command_name.starts_with(parts[0]) {
                    candidates.push(Pair {
                        display: command_name.to_string(),
                        replacement: command_name.to_string(),
                    });
                }
            }
        } else if parts.len() == 1 && query.ends_with(' ') {
            // Suggest subcommands for the main command
            if let Some(subcommands) = suggestions.get(parts[0]) {
                for subcmd in subcommands.suggestions.iter() {
                    candidates.push(Pair {
                        display: subcmd.join(" "),
                        replacement: format!("{} {}", parts[0], subcmd.join(" ")),
                    });
                }
            }
        } else if parts.len() == 2 {
            // Suggest specific subcommands that start with the entered prefix
            if let Some(command) = suggestions.get(parts[0]) {
                if let Some(subcommands) = &command.suggestions {
                    for &subcmd in subcommands {
                        if subcmd.starts_with(parts[1]) {
                            candidates.push(Pair {
                                display: subcmd.to_string(),
                                replacement: subcmd.to_string(),
                            });
                        }
                    }
                }
            }
        }

        let new_pos = if parts.len() > 1 {
            query.rfind(' ').unwrap_or(0) + 1
        } else {
            0
        };

        Ok((new_pos, candidates))
    }
}


fn is_command_allowed_in_mode(command: &String, mode: &Mode) -> bool {
    match mode {
        Mode::UserMode => matches!(command.as_str(), "enable" | "exit" | "ping"),
        Mode::PrivilegedMode => {
            matches!(command.as_str(), "configure" | "exit" | "help" | "write" | "copy" | "clock" | "clear" | "ping") || 
            command.starts_with("show") || 
            command.starts_with("ifconfig") 
        },
        Mode::ConfigMode => {
            matches!(command.as_str(), "hostname" | "interface" | "exit" | "tunnel" | "virtual-template" | "help" | "write" | "ping" | "vlan" | "access-list" | "router" | "enable password" | "enable secret" | "ip route" | "ip domain-name" | "ip access-list" | "service" | "set") ||
            command.starts_with("ifconfig") ||  
            command.starts_with("ntp") || 
            command.starts_with("crypto") 
        },
        Mode::InterfaceMode => matches!(command.as_str(), "exit" | "shutdown" | "no" | "switchport" | "help" | "write" | "interface" | "ip address" | "ip ospf"), 
        Mode::VlanMode => matches!(command.as_str(), "name" | "exit" | "state" | "vlan"),
        Mode::RouterConfigMode => matches!(command.as_str(), "network" | "exit" | "neighbor" | "area" | "passive-interface" | "distance" | "default-information" | "router-id"),
        Mode::ConfigStdNaclMode(_) => matches!(command.as_str(), "deny" | "permit" | "exit" | "ip access-list"),
        Mode::ConfigExtNaclMode(_) => matches!(command.as_str(), "deny" | "permit" | "exit" | "ip access-list"),
        
        _ => false,
    }
}


impl Helper for CommandCompleter {}


impl Hinter for CommandCompleter {
    type Hint = String;

    /// Provides hints for the current input line.
    ///
    /// # Arguments
    /// - `_line`: The current input line from the user.
    /// - `_pos`: The cursor position within the line.
    /// - `_ctx`: The rustyline context.
    ///
    /// # Returns
    /// Always returns `None` in this implementation as hints are not used.
    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None 
    }
}


impl Highlighter for CommandCompleter {}


impl Validator for CommandCompleter {

    /// Validates the current input line.
    ///
    /// # Arguments
    /// - `_ctx`: A mutable reference to the validation context.
    ///
    /// # Returns
    /// Always returns `ValidationResult::Valid` in this implementation.
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None)) 
    }
}

