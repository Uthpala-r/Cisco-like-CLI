use crate::cliconfig::CliContext;
use crate::clock_settings::Clock;
use crate::dynamic_registry::register_command;
use crate::execute::{Command, Mode};
use std::collections::{HashMap};

/// Registers all custom commands
pub fn register_custom_commands() {
    // Use the register_command function instead of directly manipulating the HashMap
    register_command(
        "hello", 
        "Prints a greeting message",
        Some(vec!["world", "friend", "privileged", "config"]),
        Some(vec!["world", "friend", "privileged", "config"]),
        None,
        |args, context, _| {
            match args.get(0).map(|s| *s) {
                Some("world") => println!("Hello, World!"),
                Some("friend") => println!("Hello, Friend!"),
                Some("privileged") => {
                    // Only allow in Privileged Mode
                    if context.current_mode == Mode::PrivilegedMode {
                        println!("Hello in Privileged Mode!");
                    } else {
                        return Err("This 'hello privileged' is only valid in Privileged Mode".to_string());
                    }
                },
                Some("config") => {
                    // Only allow in Config Mode
                    if context.current_mode == Mode::ConfigMode {
                        println!("Hello in Config Mode!");
                    } else {
                        return Err("This 'hello config' is only valid in Config Mode".to_string());
                    }
                },
                Some(name) => println!("Hello, {}!", name),
                None => println!("Hello there!"),
            }
            Ok(())
        },
        Some(vec![Mode::UserMode, Mode::PrivilegedMode , Mode::ConfigMode])
    ).expect("Failed to register hello command");
}