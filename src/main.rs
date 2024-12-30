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
use std::collections::{HashSet, HashMap};
use ctrlc;
use std::io::{self, Write};


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
        selected_vlan: None,
        vlan_names: None,
        vlan_states: None,
        switchport_mode: None,
        trunk_encapsulation: None,
        native_vlan: None,
        allowed_vlans: HashSet::new(),
        ntp_servers: HashSet::new(), 
        ntp_associations: Vec::new(),
        ntp_authentication_enabled: false,   
        ntp_authentication_keys: HashMap::new(), 
        ntp_trusted_keys: HashSet::new(),     
        ntp_master: false,   
    };

    // Configure the Rustyline editor with history behavior
    let config = rustyline::Config::builder()
    .history_ignore_space(true) 
    .build();

    // Initialize the command-line editor with a custom command completer
    let mut rl = Editor::<CommandCompleter, DefaultHistory>::with_config(config)
        .expect("Failed to initialize editor");

    let mut commands_map: HashMap<String, Vec<String>> = HashMap::new();
    for command in command_names {commands_map.insert(command.clone(), vec![command.clone()]);}
    rl.set_helper(Some(CommandCompleter { commands: commands_map }));
    rl.load_history("history.txt").ok();

    // Set up the initial clock settings
    let mut clock = Some(CustomClock {
        date: "2024-06-01".into(),
        time: "12:00".into(),
    });

    let mut exit_requested = false;

    ctrlc::set_handler(move || {
        println!("\nCtrl+C pressed, but waiting for 'exit cli' command to exit...");
    }).expect("Error setting Ctrl+C handler");

    // Main REPL loop for processing user input
    loop {
        
        let prompt = context.prompt.clone();
        match rl.readline(&prompt) {
            Ok(buffer) => {
                rl.add_history_entry(buffer.as_str());
                let input = buffer.trim();
                let completer = rl.helper().unwrap() as &CommandCompleter;

                if input == "exit cli" {
                    println!("Exiting CLI...");
                    break;
                }

                execute_command(input, &commands, &mut context, &mut clock, completer);
                      
            }

            Err(ReadlineError::Interrupted) => {
                println!("Ctrl+C pressed, but waiting for 'exit cli' command to exit...");
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