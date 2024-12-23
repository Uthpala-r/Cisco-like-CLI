//! # Cisco-like Command-Line Interface (CLI) Application
//!
//! This file serves as the main module that initializes and links all other sub-modules.
//! The CLI provides a hierarchical command structure similar to Cisco's networking devices.


/// Modules included in the CLI application
mod cliconfig;
mod commandcompleter;
mod clicommands;
mod clock_settings;
mod run_config;
mod execute;
mod network_config;


/// Internal imports from the application's modules
use cliconfig::CliConfig;
use crate::cliconfig::CliContext;
use commandcompleter::CommandCompleter;
use clicommands::build_command_registry;
use execute::execute_command;
use clock_settings::CustomClock;
use crate::execute::Mode;


/// External crates for the CLI application
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::history::DefaultHistory;


/// The main function serves as the entry point of the CLI application.
/// 
/// It initializes the environment, sets up the command-line editor, and enters the REPL loop.
fn main() {

    // Build the registry of commands and retrieve their names
    let commands = build_command_registry();
    let command_names: Vec<String> = commands.keys().cloned().map(String::from).collect();
    
    // Define the initial hostname as "Router"
    let initial_hostname = "Router".to_string();
    
    // Define the context for the CLI
    let mut context = CliContext {
        current_mode: Mode::UserMode,
        config: CliConfig::default(),
        prompt: format!("{}>", CliConfig::default().hostname),
        selected_interface: None,
    };

    // Configure the Rustyline editor with history behavior
    let config = rustyline::Config::builder()
    .history_ignore_space(true) 
    .build();

    // Initialize the command-line editor with a custom command completer
    let mut rl = Editor::<CommandCompleter, DefaultHistory>::with_config(config)
        .expect("Failed to initialize editor");
    rl.set_helper(Some(CommandCompleter { commands: command_names }));
    rl.load_history("history.txt").ok();

    // Set up the initial clock settings
    let mut clock = Some(CustomClock {
        date: "2024-06-01".into(),
        time: "12:00".into(),
    });

    // Main REPL loop for processing user input
    loop {
        
        let prompt = context.prompt.clone();
        match rl.readline(&prompt) {
            Ok(buffer) => {
                rl.add_history_entry(buffer.as_str());
                let input = buffer.trim();

                // Handle the "exit" command based on the current CLI mode. Exiting the modes in order
                if input == "exit" {
                    match context.current_mode {
                        Mode::InterfaceMode => {
                            context.current_mode = Mode::ConfigMode;
                            context.prompt = format!("{}(config)#", context.config.hostname);
                            println!("Exiting Interface Configuration Mode.");
                        }
                        Mode::ConfigMode => {
                            context.current_mode = Mode::PrivilegedMode;
                            context.prompt = format!("{}#", context.config.hostname);
                            println!("Exiting Global Configuration Mode.");
                        }
                        Mode::PrivilegedMode => {
                            context.current_mode = Mode::UserMode;
                            context.prompt = format!("{}>", context.config.hostname);
                            println!("Exiting Privileged EXEC Mode.");
                        }
                        Mode::UserMode => {
                            println!("Already at the top level.");
                        }
                    }

                } else {
                    // Else execute the execute_commands fucntion to execute other commands
                    execute_command(input, &commands, &mut context, &mut clock);
                }
            }

            // Exit the CLI if Ctrl+C is pressed
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C pressed. Exiting...");
                break;
            }


            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }

    }
    // Save the command history before exiting
    rl.save_history("history.txt").ok();
}