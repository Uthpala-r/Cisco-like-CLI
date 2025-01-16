//! # PNF Command-Line Interface (CLI) Application
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
use clock_settings::Clock;
use crate::execute::Mode;


/// External crates for the CLI application
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::history::DefaultHistory;
use std::collections::{HashSet, HashMap};
use ctrlc;


/// Main function of the CLI application.
///
/// This function initializes the Command-Line Interface (CLI) environment, processes user input,
/// and manages the interaction loop. The CLI supports commands for various configurations and
/// operations, with features such as command completion, history, and real-time mode switching.
///
/// # Functionality
/// - Builds a registry of commands and retrieves their names for command completion.
/// - Configures the CLI context, including hostname, modes, and other configurations.
/// - Sets up a Rustyline editor for user input with custom history and completion behavior.
/// - Configures signal handling for `Ctrl+C`, ensuring the CLI does not exit abruptly.
/// - Processes user input in a loop, executing commands, handling history, and responding to errors.
///
/// # Key Components
/// - **Command Registry**: A collection of available CLI commands, dynamically used for completion.
/// - **CLI Context**: Contains the current CLI state, including modes, selected interfaces, and VLANs.
/// - **Rustyline Editor**: Provides user input handling with features like auto-completion and history.
/// - **Clock Settings**: Maintains an optional system clock for configuration purposes.
/// - **Graceful Exit**: Handles the `Ctrl+C` signal and waits for the user to explicitly issue the 
///   `exit cli` command to terminate the session.
///
/// # Example Usage
/// ```bash
/// > Router> enable
/// > Router# configure terminal
/// > Router(config)# exit
/// > Router# exit cli
/// Exiting CLI...
/// ```
///
/// # Signals
/// - `Ctrl+C`: Displays a message and prevents immediate exit. The user must type `exit cli` to terminate.
///
/// # Errors
/// - Any error during initialization or user input handling (e.g., `ReadlineError`) is logged and
///   terminates the CLI gracefully.
///
/// # History
/// - Command history is stored in `history.txt` and is reloaded on subsequent runs.
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
    .completion_type(rustyline::CompletionType::List)
    .build();

    // Initialize the command-line editor with a custom command completer
    let mut rl = Editor::<CommandCompleter, DefaultHistory>::with_config(config)
        .expect("Failed to initialize editor");

    let mut commands_map: HashMap<String, Vec<String>> = HashMap::new();
    for command in command_names {
        commands_map.insert(command.clone(), vec![command.clone()]);
    }
    
    let completer = CommandCompleter::new(commands_map, Mode::UserMode);
    rl.set_helper(Some(completer));
    rl.load_history("history.txt").ok();

    // Set up the initial clock settings
    let mut clock = Some(Clock::new());
    

    let mut exit_requested = false;

    ctrlc::set_handler(move || {
        println!("\nCtrl+C pressed, but waiting for 'exit cli' command to exit...");
    }).expect("Error setting Ctrl+C handler");

    // Main REPL loop for processing user input
    loop {
        
        let prompt = context.prompt.clone();
        println!();
        match rl.readline(&prompt) {
            Ok(buffer) => {
                let input = buffer.trim();
                if input.is_empty() {
                    continue;
                }

                rl.add_history_entry(input);
                
                if input == "exit cli" {
                    println!("Exiting CLI...");
                    break;
                }

                if let Some(helper) = rl.helper_mut() {
                    execute_command(input, &commands, &mut context, &mut clock, helper);
                    helper.current_mode = context.current_mode.clone();
                }
                      
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