use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs;
use std::str::FromStr;

use crate::run_config::save_config;
use crate::run_config::load_config;
use crate::execute::Command;
use crate::execute::Mode;
use crate::clock_settings::handle_show_clock;
use crate::clock_settings::handle_clock_set;
use crate::network_config::NETWORK_STATE;

pub fn build_command_registry() -> HashMap<&'static str, Command> {
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
    
                        println!("Created new interface");
                        println!("{}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", new_interface);
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