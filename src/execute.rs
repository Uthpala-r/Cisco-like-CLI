/// External crates for the CLI application
use std::collections::HashMap;
use crate::CustomClock;
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
    pub execute: fn(&[&str], &mut CliContext, &mut Option<CustomClock>) -> Result<(), String>,
}


/// An Enum representing the different modes in the CLI.
///
/// Modes determine the scope of available commands and their behavior.
pub enum Mode {
    UserMode,
    PrivilegedMode,
    ConfigMode,
    InterfaceMode,
    VlanMode,
    RouterConfigMode,
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
pub fn execute_command(input: &str, commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<CustomClock>, completer: &CommandCompleter,) {
    
    // Normalize the input by trimming whitespace.
    let normalized_input = input.trim();

    // Handle subcommand suggestions if the input ends with a space.
    if input.ends_with(' ') {
        let parts: Vec<&str> = normalized_input.split_whitespace().collect();
        if let Some(suggestions) = completer.commands.get(parts[0]) {
            println!("Possible subcommands:");
            for suggestion in suggestions {
                println!("  {}", suggestion);
            }
        } else {
            println!("No subcommands available for '{}'", parts[0]);
        }
        return;
    }

    // Handle autocompletion when the input ends with `?`.
    if normalized_input.ends_with('?') {
        let prefix = normalized_input.trim_end_matches('?').trim();

        // Collect suggestions based on the current mode. 
        let suggestions: Vec<_> = match context.current_mode {
            
            Mode::UserMode => {
                commands
                    .keys()
                    // Only enable command can be executed in the User Exec Mode
                    .filter(|cmd| cmd.starts_with(prefix) && **cmd == "enable")
                    .map(|cmd| cmd.to_string())
                    .collect()
            }

            Mode::PrivilegedMode => {
                commands
                    .keys()
                    // Commands configure terminal, help, write memory, ifconfig and the show command can be ecxecuted in the Pirviledged Exec Mode
                    .filter(|cmd| cmd.starts_with(prefix) && (**cmd == "configure terminal" || **cmd == "help" || **cmd == "write memory" || cmd.starts_with("ifconfig") || cmd.starts_with("show")))
                    .map(|cmd| {
                        let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                        let fist_word = cmd.split_whitespace().nth(0).unwrap_or_default();
                        if cmd.starts_with(prefix) && (prefix.contains(' ') || prefix.contains(fist_word)){
                            let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                            if second_word.is_empty() {
                                fist_word.to_string()
                            } else {
                                second_word.to_string()
                            }
                        } else {
                            fist_word.to_string()
                        }
                    })
                    .collect()
            }

            Mode::ConfigMode => {
                commands
                    .keys()
                    // Commands hostname, interface, help, write memory, vlan and ifconfig can be executed in the Config Mode
                    .filter(|cmd| cmd.starts_with(prefix) && (**cmd == "hostname" || **cmd == "interface" || **cmd == "help" || **cmd == "write memory" || **cmd == "vlan" || cmd.starts_with("ifconfig")))
                    .map(|cmd| {
                        let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                        let fist_word = cmd.split_whitespace().nth(0).unwrap_or_default();
                        if cmd.starts_with(prefix) && (prefix.contains(' ') || prefix.contains(fist_word)){
                            let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                            if second_word.is_empty() {
                                fist_word.to_string()
                            } else {
                                second_word.to_string()
                            }
                        } else {
                            fist_word.to_string()
                        }
                    })
                    .collect()
            }

            Mode::InterfaceMode => {
                commands
                    .keys()
                    // Commands shutdown, no shutdown, help, write memory and ip address can be executed in the Interface Config Mode 
                    .filter(|cmd| cmd.starts_with(prefix) && (**cmd == "shutdown" || **cmd == "no shutdown" || **cmd == "switchport" || **cmd == "help" || **cmd == "write memory" || **cmd == "interface" || cmd.starts_with("ip address")))
                    .map(|cmd| {
                        let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                        let fist_word = cmd.split_whitespace().nth(0).unwrap_or_default();
                        if cmd.starts_with(prefix) && (prefix.contains(' ') || prefix.contains(fist_word)){
                            let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                            if second_word.is_empty() {
                                fist_word.to_string()
                            } else {
                                second_word.to_string()
                            }
                        } else {
                            fist_word.to_string()
                        }
                    })
                    .collect()
            }

            Mode::VlanMode => {
                commands
                    .keys()
                    // Commands vlan, name and state can be executed in the Vlan Mode
                    .filter(|cmd| cmd.starts_with(prefix) && (**cmd == "name" || **cmd == "state" || **cmd == "vlan" ))
                    .map(|cmd| {
                        let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                        let fist_word = cmd.split_whitespace().nth(0).unwrap_or_default();
                        if cmd.starts_with(prefix) && (prefix.contains(' ') || prefix.contains(fist_word)){
                            let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                            if second_word.is_empty() {
                                fist_word.to_string()
                            } else {
                                second_word.to_string()
                            }
                        } else {
                            fist_word.to_string()
                        }
                    })
                    .collect()
            }

            Mode::RouterConfigMode => {
                commands
                    .keys()
                    // Commands vlan, name and state can be executed in the Vlan Mode
                    .filter(|cmd| cmd.starts_with(prefix) && (**cmd == "network" ))
                    .map(|cmd| {
                        let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                        let fist_word = cmd.split_whitespace().nth(0).unwrap_or_default();
                        if cmd.starts_with(prefix) && (prefix.contains(' ') || prefix.contains(fist_word)){
                            let second_word = cmd.split_whitespace().nth(1).unwrap_or_default();
                            if second_word.is_empty() {
                                fist_word.to_string()
                            } else {
                                second_word.to_string()
                            }
                        } else {
                            fist_word.to_string()
                        }
                    })
                    .collect()
            }

            _ => Vec::new(), 
        };

        // Display suggestions or notify the user if none are found.
        if suggestions.is_empty() {
            println!("No matching commands found for '{}?'", prefix);
        } else {
            println!("Possible completions for '{}?':", prefix);
            for suggestion in suggestions {
                println!("  {}", suggestion);
            }
        }
        return;
    }

    // Attempt to match the input with a command in the registry.
    let matching_command = commands
        .keys()
        .filter(|cmd| normalized_input.starts_with(*cmd))
        .max_by_key(|cmd| cmd.len());

    if let Some(command_key) = matching_command {
        let cmd = commands.get(command_key).unwrap();

        let args = normalized_input[command_key.len()..].trim();
        let args_vec: Vec<&str> = if args.is_empty() {
            Vec::new()
        } else {
            args.split_whitespace().collect()
        };

        // Execute the command and handle the result.
        match (cmd.execute)(&args_vec, context, clock) {
            Ok(_) => println!("Command '{}' executed successfully.", cmd.name),
            Err(err) => println!("Error: {}", err),
        }
    } else {
        println!("Invalid command: {}", input);
    }
}
