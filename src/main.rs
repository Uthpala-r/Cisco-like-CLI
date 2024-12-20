/**
 * @file main.rs
 * @brief A Rust program for a Cisco-like command-line interface.
 */

 /// The packages installed in the program
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::{Validator, ValidationContext, ValidationResult};
use rustyline::{Editor, Helper};
use rustyline::history::DefaultHistory;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Mutex, Arc};


/// A structure representing the commands in the CLI.
/// 
/// This struct holds the name, description, suggestions and execute commands 
struct Command {
    name: &'static str,
    description: &'static str,
    suggestions: Option<Vec<&'static str>>,
    execute: fn(&[&str], &mut CliContext, &mut Option<CustomClock>) -> Result<(), String>,
}

/// A structure for the custom clock in the CLI.
/// 
/// This struct holds the date and time as strings in a specific format
struct CustomClock {
    date: String,
    time: String,
}

/// A structure representing the configuration for the CLI.
///
/// This struct holds the current running configuration, the startup configuration, and the hostname of the system.
#[derive(Serialize, Deserialize, Clone)]
struct CliConfig {
    running_config: HashMap<String, String>,
    startup_config: HashMap<String, String>,
    hostname: String,
}

struct CliContext {
    current_mode: Mode,
    prompt: String,
    config: CliConfig,
}

enum Mode {
    UserMode,
    PrivilegedMode,
    ConfigMode,
    InterfaceMode(String),
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            running_config: HashMap::new(),
            startup_config: HashMap::new(),
            hostname: "Router".to_string(),
        }
    }
}

impl Default for CliContext {
    fn default() -> Self {
        Self {
            current_mode: Mode::UserMode,
            prompt: "Router>".into(),
            config: CliConfig::default(),
        }
    }
}

struct CommandCompleter {
    commands: Vec<String>,
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

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

        for (command, _) in suggestions {
            if command.starts_with(query) {
                candidates.push(Pair {
                    display: command.clone().to_string(),     
                    replacement: command.clone().to_string(), 
                });
            }
        }

        Ok((0, candidates))
    }
}

impl Helper for CommandCompleter {}
impl Hinter for CommandCompleter {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None 
    }
}

impl Highlighter for CommandCompleter {}
impl Validator for CommandCompleter {
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None)) 
    }
}

lazy_static::lazy_static! {
    // Shared state for storing multiple network interfaces and a default interface
    static ref NETWORK_STATE: Arc<Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();

        // Insert the default interface (ens33)
        let default_interface = "ens33".to_string();
        let default_ip = Ipv4Addr::from_str("192.168.253.135").expect("Invalid IP address format");
        let default_broadcast = Ipv4Addr::from_str("192.168.253.255").expect("Invalid broadcast address");
        
        map.insert(default_interface, (default_ip, default_broadcast));
        
        map
    }));
}


fn build_command_registry() -> HashMap<&'static str, Command> {
    let mut commands = HashMap::new();

    commands.insert("enable", Command {
        name: "enable",
        description: "Enter privileged EXEC mode",
        suggestions: Some(vec!["enable"]),
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::UserMode) {
                if _args.is_empty() {
                    context.current_mode = Mode::PrivilegedMode;
                    context.prompt = format!("{}#", context.config.hostname);
                    println!("Entering privileged EXEC mode...");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'enable'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'enable' command is only available in User EXEC mode.".into())
            }
        },
    });

    commands.insert("configure terminal", Command {
        name: "configure terminal",
        description: "Enter global configuration mode",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if _args.is_empty() {
                    context.current_mode = Mode::ConfigMode;
                    context.prompt = format!("{}(config)#", context.config.hostname);
                    println!("Entering Global configuration mode...");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'configure terminal'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'configure terminal' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    commands.insert("interface", Command {
        name: "interface",
        description: "Enter Interface configuration mode",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    return Err("Please specify an interface, e.g., 'interface f0/0'.".into());
                }
                let interface = args.join(" ");
                context.current_mode = Mode::InterfaceMode(interface.clone());
                context.prompt = format!("{}(config-if)# {}", context.config.hostname, interface);
                println!("Entering Interface configuration mode for: {}", interface);
                Ok(())
            } else {
                Err("The 'interface' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("hostname", Command {
        name: "hostname",
        description: "Set the device hostname",
        suggestions: None,
        execute: |args, context, _| {
            if let Mode::ConfigMode = context.current_mode {
                if let Some(new_hostname) = args.get(0) {
                    
                    context.config.hostname = new_hostname.to_string();
    
                    match context.current_mode {
                        Mode::ConfigMode => {
                            context.prompt = format!("{}(config)#", new_hostname);
                        }
                        Mode::PrivilegedMode => {
                            context.prompt = format!("{}#", new_hostname);
                        }
                        _ => {
                            context.prompt = format!("{}>", new_hostname);
                        }
                    }
    
                    println!("Hostname changed to '{}'", new_hostname);
                    Ok(())
                } else {
                    Err("Please specify a new hostname. Usage: hostname <new_hostname>".into())
                }
            } else {
                Err("The 'hostname' command is only available in Global Configuration Mode.".into())
            }
        },
    });

    commands.insert(
        "ifconfig",
        Command {
            name: "ifconfig",
            description: "Display or configure network details of the router",
            suggestions: None,
            execute: |args, _, _| {
                let mut network_state = NETWORK_STATE.lock().unwrap();
    
                if args.is_empty() {
                    // Display all interface details
                    if network_state.is_empty() {
                        println!("No interfaces found.");
                    } else {
                        for (interface_name, (ip_address, broadcast_address)) in network_state.iter() {
                            println!("{}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", interface_name);
                            println!("    inet {}  netmask 255.255.255.0  broadcast {}", ip_address, broadcast_address);
                            println!("    inet6 fe80::6a01:72f9:adf2:3ffb  prefixlen 64  scopeid 0x20<link>");
                            println!("    ether 00:0c:29:16:30:92  txqueuelen 1000  (Ethernet)");
                        }
                    }
                } else if args.len() == 3 && args[2] == "up" {
                    // Handle 'ifconfig {interface} {new_ip} up'
                    let new_interface = &args[0];
                    let new_ip: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
    
                    // Check if the interface exists in the network state
                    if let Some((existing_ip, existing_broadcast)) = network_state.get_mut(&new_interface.to_string()) {
                        // Update the IP address for the existing interface
                        *existing_ip = new_ip;
                        println!("Updated {}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", new_interface);
                        println!("    inet {}  netmask 255.255.255.0  broadcast {}", new_ip, existing_broadcast);
                        println!("    inet6 fe80::6a01:72f9:adf2:3ffb  prefixlen 64  scopeid 0x20<link>");
                        println!("    ether 00:0c:29:16:30:92  txqueuelen 1000  (Ethernet)");
                    } else {
                        // Add a new interface if it doesn't exist
                        let broadcast_address = Ipv4Addr::from_str("192.168.253.255").expect("Invalid broadcast address");
                        network_state.insert(new_interface.to_string(), (new_ip, broadcast_address));
    
                        println!("Created new interface {}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", new_interface);
                        println!("    inet {}  netmask 255.255.255.0  broadcast {}", new_ip, broadcast_address);
                        println!("    inet6 fe80::6a01:72f9:adf2:3ffb  prefixlen 64  scopeid 0x20<link>");
                        println!("    ether 00:0c:29:16:30:92  txqueuelen 1000  (Ethernet)");
                    }
                } else {
                    // Handle invalid arguments
                    println!("Invalid arguments provided to 'ifconfig'. This command does not accept additional arguments.");
                }
    
                Ok(())  // Return Ok as the command was handled
            },
        },
    );

    commands.insert(
        "show running-config",
        Command {
            name: "show running-config",
            description: "Display the current running configuration (from JSON file)",
            suggestions: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    let file_path = Path::new("startup-config.json"); 

                    if file_path.exists() {
                        
                        match fs::read_to_string(file_path) {
                            Ok(file_content) => {
                                println!("{}", file_content); 
                                Ok(())
                            }
                            Err(err) => {
                                eprintln!("Error reading the file: {}", err); 
                                Err(err.to_string())
                            }
                        }
                    } else {
                        eprintln!("The JSON configuration file does not exist.");
                        Err("File not found".to_string())
                    }
                } else {
                    Err("The 'show running-config' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );

    commands.insert(
        "write memory",
        Command {
            name: "write memory",
            description: "Save the running configuration to the startup configuration",
            suggestions: None,
            execute: |_, context, _| {
                context.config.startup_config = context.config.running_config.clone();
                save_config(&context.config).map_err(|e| format!("Failed to save configuration: {}", e))?;
                println!("Configuration saved successfully.");
                Ok(())
            },
        },
    );

    commands.insert(
        "help",
        Command {
            name: "help",
            description: "Display available commands",
            suggestions: None,
            execute: |_, _, _| {
                println!("Available commands:");
                println!("  enable                - Enter privileged EXEC mode");
                println!("  configure terminal    - Enter Global configuration mode");
                println!("  interface <name>      - Enter Interface configuration mode");
                println!("  show running-config   - Display the running configuration");
                println!("  write memory          - Save the running configuration");
                println!("  help                  - Display this help message");
                Ok(())
            },
        },
    );

    commands.insert(
        "show version",
        Command {
            name: "show version",
            description: "Display the software version",
            suggestions: None,
            execute: |_, _, _| {
                println!("Software Version: Cisco IOS 15.2(3)T");
                println!("Compiled on: 2024-12-01");
                Ok(())
            },
        },
    );

    commands.insert(
        "clock set",
        Command {
            name: "clock set",
            description: "Change the clock date and time",
            suggestions: None,
            execute: |args, _context, clock| {
                if let Some(clock) = clock {
                    handle_clock_set(&args.join(" "), clock);
                    Ok(())
                } else {
                    Err("Clock functionality is unavailable.".to_string())
                }  
             
            },

        },
    );

    commands.insert(
        "show clock",
        Command {
            name: "show clock",
            description: "Show the current clock date and time",
            suggestions: None,
            execute: |_args, context, clock| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    if let Some(clock) = clock {
                        handle_show_clock(clock);
                        Ok(())
                    } else {
                        Err("Clock functionality is unavailable.".to_string())
                    }
                }
                else {
                    Err("The 'show clock' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );

    commands
}

fn save_config(config: &CliConfig) -> std::io::Result<()> {
    let serialized = serde_json::to_string_pretty(config)?;
    let mut file = OpenOptions::new()
        .create(true) 
        .write(true)  
        .truncate(true) 
        .open("startup-config.json")?;
    file.write_all(serialized.as_bytes())
}

fn load_config() -> CliConfig {
    if let Ok(mut file) = File::open("startup-config.json") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            if let Ok(config) = serde_json::from_str::<CliConfig>(&contents) {
                return config;
            }
        }
    }
    CliConfig::default()
}

fn execute_command(input: &str, commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<CustomClock>) {
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


fn handle_clock_set(input: &str, clock: &mut CustomClock) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() < 4 {
        println!("Usage: clock set <date> <time>");
        return;
    }
    clock.date = parts[2].to_string();
    clock.time = parts[3].to_string();
    println!("Clock set to: {} {}", clock.date, clock.time);
}


fn handle_show_clock(clock: &CustomClock) {
    println!("Current clock: {} {}", clock.date, clock.time);
}


fn main() {
    let commands = build_command_registry();
    let command_names: Vec<String> = commands.keys().cloned().map(String::from).collect();
    let initial_hostname = "Router".to_string();
    let mut context = CliContext {
        current_mode: Mode::UserMode,
        config: CliConfig::default(),
        prompt: format!("{}>", CliConfig::default().hostname),
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
                        Mode::InterfaceMode(_) => {
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