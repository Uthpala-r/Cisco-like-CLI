/**
 * @file main.rs
 * @brief A Rust program for a Cisco-like command-line interface.
 */

mod cliconfig;
mod commandcompleter;
mod clicommands;
mod clock_settings;
mod run_config;
mod execute;
mod network_config;

use cliconfig::CliConfig;
use crate::cliconfig::CliContext;
use commandcompleter::CommandCompleter;
use clicommands::build_command_registry;
use execute::execute_command;
use clock_settings::CustomClock;
use crate::execute::Mode;

use rustyline::error::ReadlineError;
use rustyline::Editor;
use rustyline::history::DefaultHistory;


fn main() {
    let commands = build_command_registry();
    let command_names: Vec<String> = commands.keys().cloned().map(String::from).collect();
    let initial_hostname = "Router".to_string();
    let mut context = CliContext {
        current_mode: Mode::UserMode,
        config: CliConfig::default(),
        prompt: format!("{}>", CliConfig::default().hostname),
        selected_interface: None,
    };


    let config = rustyline::Config::builder()
    .history_ignore_space(true) 
    .build();


    let mut rl = Editor::<CommandCompleter, DefaultHistory>::with_config(config)
        .expect("Failed to initialize editor");
    rl.set_helper(Some(CommandCompleter { commands: command_names }));
    rl.load_history("history.txt").ok();

    let mut clock = Some(CustomClock {
        date: "2024-06-01".into(),
        time: "12:00".into(),
    });


    loop {
        
        let prompt = context.prompt.clone();
        match rl.readline(&prompt) {
            Ok(buffer) => {
                rl.add_history_entry(buffer.as_str());
                let input = buffer.trim();
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
                    execute_command(input, &commands, &mut context, &mut clock);
                }
            }
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
    rl.save_history("history.txt").ok();
}