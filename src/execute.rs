//execute.rs

/// External crates for the CLI application
use std::collections::{HashMap, HashSet};
use crate::Clock;
use crate::CliContext;
use crate::commandcompleter::{CommandCompleter};

/// Represents a command in the CLI.
///
/// Each command has a name, description, optional suggestions for autocompletion,
/// and an execution function that defines the command's behavior.
/// 
pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub suggestions: Option<Vec<&'static str>>,
    pub execute: fn(&[&str], &mut CliContext, &mut Option<Clock>) -> Result<(), String>,
}


/// An Enum representing the different modes in the CLI.
///
/// Modes determine the scope of available commands and their behavior.
#[derive(Clone, Debug)]
pub enum Mode {
    UserMode,
    PrivilegedMode,
    ConfigMode,
    InterfaceMode,
    VlanMode,
    RouterConfigMode,
    ConfigStdNaclMode(String),
    ConfigExtNaclMode(String),
}



/// Executes a command or provides suggestions based on the current input.
///
/// # Arguments
/// - `input`: The user's input string.
/// - `commands`: A `HashMap` of available commands, indexed by their names.
/// - `context`: The CLI context, which holds the current mode and other state information.
/// - `clock`: An optional mutable reference to the `CustomClock` structure.
///
/// # Behavior
/// - If the input ends with `?`, it provides autocompletion suggestions based on the current mode.
/// - Otherwise, it matches the input to a command and executes it if found.
/// - Prints appropriate messages for invalid commands or execution errors.
pub fn execute_command(input: &str, commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<Clock>, completer: &mut CommandCompleter) {
    let mut normalized_input = input.trim();
    let showing_suggestions = normalized_input.ends_with('?');
    
    // If we're showing suggestions, remove the '?' for further processing
    if showing_suggestions {
        normalized_input = normalized_input.trim_end_matches('?').trim();
    }

    // Get available commands for current mode
    fn get_mode_commands<'a>(commands: &'a HashMap<&str, Command>, mode: &Mode) -> Vec<&'a str> {
        match mode {
            Mode::UserMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "enable" ||
                        cmd == "ping" ||
                        cmd == "exit"
                    })
                    .copied()
                    .collect()
            },
            Mode::PrivilegedMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "configure" ||
                        cmd == "ping" || 
                        cmd == "exit" || 
                        cmd == "write" ||
                        cmd == "help" ||
                        cmd == "show" ||
                        cmd == "copy" ||
                        cmd == "clock" ||
                        cmd == "clear" ||
                        cmd == "ifconfig"
                        
                    })
                    .copied()
                    .collect()
            },
            Mode::ConfigMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "hostname" || 
                        cmd == "interface" ||
                        cmd == "ping" ||
                        cmd == "exit" ||
                        cmd == "tunnel" ||
                        cmd == "access-list" ||
                        cmd == "router" ||
                        cmd == "virtual-template" ||
                        cmd == "help" ||
                        cmd == "write" ||
                        cmd == "vlan" ||
                        cmd == "ip" ||
                        cmd == "service" ||
                        cmd == "set" ||
                        cmd == "enable" ||
                        cmd == "ifconfig" ||  
                        cmd == "ntp" || 
                        cmd == "crypto"
                    })
                    .copied()
                    .collect()
            },
            Mode::InterfaceMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "shutdown" ||
                        cmd == "no" ||
                        cmd == "exit" ||
                        cmd == "help" ||
                        cmd == "switchport" ||
                        cmd == "write" ||
                        cmd == "ip" 

                    })
                    .copied()
                    .collect()
            }
            Mode::VlanMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "name" ||
                        cmd == "state" ||
                        cmd == "exit" ||
                        cmd == "vlan" 

                    })
                    .copied()
                    .collect()
            }
            Mode::RouterConfigMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "network" ||
                        cmd == "neighbor" ||
                        cmd == "exit" ||
                        cmd == "area" ||
                        cmd == "passive-interface" ||
                        cmd == "distance" ||
                        cmd == "default-information" ||
                        cmd == "router-id"

                    })
                    .copied()
                    .collect()
            }
            Mode::ConfigStdNaclMode(_) => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "deny" ||
                        cmd == "permit" ||
                        cmd == "exit" ||
                        cmd == "ip"

                    })
                    .copied()
                    .collect()
            }
            Mode::ConfigExtNaclMode(_) => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "deny" ||
                        cmd == "permit" ||
                        cmd == "exit" ||
                        cmd == "ip"

                    })
                    .copied()
                    .collect()
            }

        }
    }

    // Function to find a unique command match
    fn find_unique_command<'a>(partial: &str, available_commands: &[&'a str]) -> Option<&'a str> {
        let matches: Vec<&str> = available_commands
            .iter()
            .filter(|&&cmd| cmd.starts_with(partial))
            .copied()
            .collect();

        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    }

    // Function to find a unique subcommand match
    fn find_unique_subcommand<'a>(partial: &str, suggestions: &'a [&str]) -> Option<&'a str> {
        let matches: Vec<&str> = suggestions
            .iter()
            .filter(|&&s| s.starts_with(partial))
            .copied()
            .collect();

        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    }

    let parts: Vec<&str> = normalized_input.split_whitespace().collect();
    if parts.is_empty() {
        println!("No command entered.");
        return;
    }

    let available_commands = get_mode_commands(commands, &context.current_mode);

    // Handle suggestions if '?' was present
    if showing_suggestions {
        match parts.len() {
            0 => {
                println!("No commands entered.");
                return;
            },            
            1 => {
                // Handle single word with ? (e.g., "configure ?")
                let available_commands = get_mode_commands(commands, &context.current_mode);
                if available_commands.contains(&normalized_input) {
                    // If it's an exact command match, show its subcommands
                    if let Some(cmd) = commands.get(normalized_input) {
                        if let Some(suggestions) = &cmd.suggestions {
                            println!("Possible completions:");
                            for suggestion in suggestions {
                                println!("  {}", suggestion);
                            }
                        } else {
                            println!("No subcommands available");
                        }
                    }
                } else {
                    // If it's a partial command, show matching commands
                    let suggestions: Vec<&str> = available_commands
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(normalized_input))
                        .collect();

                    if !suggestions.is_empty() {
                        println!("Possible completions for '{}?':", normalized_input);
                        for suggestion in suggestions {
                            println!("  {}", suggestion);
                        }
                    } else {
                        println!("No matching commands found for '{}?'", normalized_input);
                    }
                }
            },
            2 => {
                // Command with partial subcommand (e.g., "configure t?", "configure term?")
                let available_commands = get_mode_commands(commands, &context.current_mode);
                if available_commands.contains(&parts[0]) {
                    if let Some(cmd) = commands.get(parts[0]) {
                        if let Some(suggestions) = &cmd.suggestions {
                            let partial = parts[1];
                            let matching: Vec<&str> = suggestions
                                .iter()
                                .filter(|&&s| s.starts_with(partial))
                                .map(|&s| s)
                                .collect();

                            if !matching.is_empty() {
                                println!("Possible completions:");
                                for suggestion in matching {
                                    println!("  {}", suggestion);
                                }
                            } else {
                                println!("No matching commands found");
                            }
                        } else {
                            println!("No subcommands available");
                        }
                    }
                } else {
                    println!("Command not available in current mode");
                }
            },
            _ => {
                // Full command with ? (e.g., "configure terminal ?")
                println!("No additional parameters available");
            }
        }
        return;
    }

    // Handle command execution (when no '?' is present)
    let cmd_key = if let Some(matched_cmd) = find_unique_command(parts[0], &available_commands) {
        matched_cmd
    } else {
        println!("Ambiguous command or command not available in current mode: {}", parts[0]);
        return;
    };

    if let Some(cmd) = commands.get(cmd_key) {
        if let Some(suggestions) = &cmd.suggestions {
            match parts.len() {
                1 => {
                    println!("Incomplete command. Subcommand required.");
                }
                2 => {
                    if suggestions.is_empty() {
                        if let Err(err) = (cmd.execute)(&parts[1..], context, clock) {
                            println!("Error: {}", err);
                        }
                    } else {
                        // For commands with specific subcommands, require a match
                        if let Some(matched_subcommand) = find_unique_subcommand(parts[1], suggestions) {
                            if let Err(err) = (cmd.execute)(&[matched_subcommand], context, clock) {
                                println!("Error: {}", err);
                            }
                        } else {
                            println!("Ambiguous or invalid subcommand: {}", parts[1]);
                        }
                    }
                }
                _ => {
                    if let Err(err) = (cmd.execute)(&parts[1..], context, clock) {
                        println!("Error: {}", err);
                    }
                }
            }
        } else {
            if let Err(err) = (cmd.execute)(&parts[1..], context, clock) {
                println!("Error: {}", err);
            }
        }
    }
}