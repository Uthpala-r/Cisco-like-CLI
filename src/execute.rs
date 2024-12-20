use std::collections::HashMap;
use crate::CustomClock;
use crate::CliContext;

/// A structure representing the commands in the CLI.
/// 
/// This struct holds the name, description, suggestions and execute commands 
pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub suggestions: Option<Vec<&'static str>>,
    pub execute: fn(&[&str], &mut CliContext, &mut Option<CustomClock>) -> Result<(), String>,
}


pub enum Mode {
    UserMode,
    PrivilegedMode,
    ConfigMode,
    InterfaceMode(String),
}

pub fn execute_command(input: &str, commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<CustomClock>) {
    let normalized_input = input.trim();

    if normalized_input.ends_with('?') {
        let prefix = normalized_input.trim_end_matches('?').trim();
        
        let suggestions: Vec<_> = match context.current_mode {
            Mode::UserMode => {
                commands
                    .keys()
                    .filter(|cmd| cmd.starts_with(prefix) && **cmd == "enable")
                    .map(|cmd| cmd.to_string())
                    .collect()
            }
            Mode::PrivilegedMode => {
                commands
                    .keys()
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
                    .filter(|cmd| cmd.starts_with(prefix) && (**cmd == "hostname" || **cmd == "interface" || **cmd == "help" || **cmd == "write memory" || cmd.starts_with("ifconfig")))
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

        match (cmd.execute)(&args_vec, context, clock) {
            Ok(_) => println!("Command '{}' executed successfully.", cmd.name),
            Err(err) => println!("Error: {}", err),
        }
    } else {
        println!("Invalid command: {}", input);
    }
}
