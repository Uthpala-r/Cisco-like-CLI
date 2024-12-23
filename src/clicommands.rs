/// External crates for the CLI application
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
use crate::network_config::{NETWORK_STATE, calculate_broadcast};
use crate::network_config::InterfaceConfig;


/// Builds and returns a `HashMap` of available commands, each represented by a `Command` structure.
/// 
/// This function initializes a registry of commands that can be executed in different modes
/// (e.g., `UserMode`, `PrivilegedMode`, `ConfigMode`, etc.) within a router-like system.
/// Each command is associated with a name, description, suggestions for usage, and an execution
/// function that defines its behavior.
///
/// The commands registered include:
/// - `enable`: Switches from User EXEC mode to Privileged EXEC mode.
/// - `configure terminal`: Enters Global Configuration mode.
/// - `interface`: Enters Interface Configuration mode for a specified interface.
/// - `hostname`: Changes the hostname of the device.
/// - `ifconfig`: Displays or configures network details of the router.
/// - `show running-config`: Displays the current running configuration from a JSON file.
/// - `write memory`: Saves the running configuration to the startup configuration.
/// - `help`: Displays a list of available commands.
/// - `show version`: Displays the software version information.
/// - `clock set`: Changes the device's clock date and time.
/// - `show clock`: Displays the current clock date and time.
/// - `ip address`: Assigns an IP address and netmask to the selected interface.
/// - `show interfaces`: Displays statistics for all interfaces, including a brief overview or detailed information.
/// - `shutdown`: Disable a router's interface
/// - `no shutdown`: Enable a router's interface 
///
/// # Returns
/// A `HashMap` where the keys are command names (as `&'static str`) and the values are the corresponding `Command` structs.
/// Each `Command` struct contains the `name`, `description`, `suggestions`, and an `execute` function.
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
                    println!("Enter configuration commands, one per line.  End with CNTL/Z");
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
                context.current_mode = Mode::InterfaceMode;
                context.selected_interface = Some(interface.clone());
                context.prompt = format!("{}(config-if)#", context.config.hostname);
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
                    let new_interface = &args[0];
                    let new_ip: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
    
                    let new_broadcast = calculate_broadcast(new_ip, 24);
    
                    let new_interface_string = new_interface.to_string();
                    if let Some((existing_ip, existing_broadcast)) = network_state.get_mut(&new_interface_string) {
                        *existing_ip = new_ip;
                        *existing_broadcast = new_broadcast;
    
                        println!("Updated {}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", new_interface);
                        println!("    inet {}  netmask 255.255.255.0  broadcast {}", new_ip, new_broadcast);
                        println!("    inet6 fe80::6a01:72f9:adf2:3ffb  prefixlen 64  scopeid 0x20<link>");
                        println!("    ether 00:0c:29:16:30:92  txqueuelen 1000  (Ethernet)");
                    } else {
                        network_state.insert(new_interface.to_string(), (new_ip, new_broadcast));
    
                        println!("Created new interface");
                        println!("{}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", new_interface);
                        println!("    inet {}  netmask 255.255.255.0  broadcast {}", new_ip, new_broadcast);
                        println!("    inet6 fe80::6a01:72f9:adf2:3ffb  prefixlen 64  scopeid 0x20<link>");
                        println!("    ether 00:0c:29:16:30:92  txqueuelen 1000  (Ethernet)");
                    }
                } else {
                    println!("Invalid arguments provided to 'ifconfig'. This command does not accept additional arguments.");
                }
    
                Ok(())  
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

    commands.insert(
        "ip address",
        Command {
            name: "ip address",
            description: "Assign an IP address and netmask to the selected network interface",
            suggestions: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::InterfaceMode) {
                    if args.len() != 2 {
                        println!("Usage: ip address <ip> <netmask>");
                        return Err("Invalid number of arguments".into());
                    }
    
                    // Parse IP address and netmask
                    let ip_address: Ipv4Addr = args[0]
                        .parse()
                        .map_err(|_| "Invalid IP address format.".to_string())?;
                    let netmask: Ipv4Addr = args[1]
                        .parse()
                        .map_err(|_| "Invalid netmask format.".to_string())?;
    
                    let mut network_state = NETWORK_STATE.lock().unwrap();
    
                    if let Some(interface) = &context.selected_interface {
                        if let Some((existing_ip, existing_broadcast)) = network_state.get_mut(interface) {
                            *existing_ip = ip_address;
                            *existing_broadcast = netmask;
                            println!(
                                "Updated interface {} with IP {} and netmask {}",
                                interface, ip_address, netmask
                            );
                        } else {
                            network_state.insert(interface.clone(), (ip_address, netmask));
                            println!(
                                "Assigned IP {} and netmask {} to interface {}",
                                ip_address, netmask, interface
                            );
                        }
                        Ok(())
                    } else {
                        Err("No interface selected. Use the 'interface' command first.".into())
                    }
                } else {
                    Err("The 'ip address' command is only available in Interface Configuration mode.".into())
                }
            },
        },
    );
    
    commands.insert(
        "show interfaces",
        Command {
            name: "show interfaces",
            description: "Display statistics for all interfaces configured on the router",
            suggestions: None,
            execute: |args, context, _| {
                let network_state = NETWORK_STATE.lock().unwrap();
                let Some(interface_name) = &context.selected_interface else {
                    return Err("No interface selected. Use the 'interface' command first.".into());
                };
    
                if args.contains(&"brief") {
                    if network_state.is_empty() {
                        println!("No interfaces found.");
                        return Ok(()); // Return Result
                    } else {
                        println!("Interface              IP-Address      OK? Method Status                Protocol");
    
                        if let Some((ip_address, _)) = network_state.get(&interface_name.to_string()) {
                            println!(
                                "{:<22} {:<15} YES unset administratively down       down",
                                interface_name, ip_address
                            );
                        } else {
                            println!(
                                "{:<22} {:<15} NO  unset administratively down       down",
                                interface_name, "-"
                            );
                        }
                    }
                } else if args.len() == 1 {
                    let interface_name = &args[0];
                    if let Some((ip_address, _)) = network_state.get(&interface_name.to_string()) {
                        println!("{} is up, line protocol is up", interface_name);
                        println!("  Internet address is {}, subnet mask 255.255.255.0", ip_address);
                        println!("  MTU 1500 bytes, BW 10000 Kbit, DLY 100000 usec");
                        println!("  Encapsulation ARPA, loopback not set, keepalive set (10 sec)");
                    } else {
                        println!("Interface {} not found.", interface_name);
                    }
                } else {
                    // Handle "show interfaces" without arguments
                    if network_state.is_empty() {
                        println!("No interfaces found.");
                        return Ok(()); // Return Result
                    } else {
                        for (interface_name, (ip_address, _)) in network_state.iter() {
                            println!("{} is up, line protocol is up", interface_name);
                            println!("  Internet address is {}, subnet mask 255.255.255.0", ip_address);
                            println!("  MTU 1500 bytes, BW 10000 Kbit, DLY 100000 usec");
                            println!("  Encapsulation ARPA, loopback not set, keepalive set (10 sec)");
                        }
                    }
                }
    
                Ok(()) // Ensure the function returns Result
            },
        },
    );

    commands.insert(
        "shutdown",
        Command {
            name: "shutdown",
            description: "Disable the selected network interface.",
            suggestions: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::InterfaceMode) {
                    if let Some(interface) = &context.selected_interface {
                        let mut network_state = NETWORK_STATE.lock().unwrap();
                        if let Some(interface_config) = network_state.get_mut(interface) {
                            
                            let ip_address = interface_config.0.clone();
                            
                            let mut interface_config = InterfaceConfig {
                                ip_address: Ipv4Addr::new(0, 0, 0, 0),
                                is_up: false,
                            };
                            
                            interface_config.is_up = true;
    
                            println!(
                                "Interface {} has been shut down. IP address set to 0.0.0.0",
                                interface
                            );
                        } else {
                            println!("Interface {} not found.", interface);
                        }
                        Ok(())
                    } else {
                        Err("No interface selected. Use the 'interface' command first.".into())
                    }
                } else {
                    Err("The 'shutdown' command is only available in Interface Configuration mode.".into())
                }
            },
        },
    );
    
    commands.insert(
        "no shutdown",
        Command {
            name: "no shutdown",
            description: "Enable the selected network interface.",
            suggestions: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::InterfaceMode) {
                    if let Some(interface) = &context.selected_interface {
                        let mut network_state = NETWORK_STATE.lock().unwrap();
                        if let Some(interface_config) = network_state.get_mut(interface) {
                            
                            if let original_ip = interface_config.0 {
                                
                                if original_ip == Ipv4Addr::new(0, 0, 0, 0) {
                                    println!(
                                        "%LINK-5-CHANGED: Interface {}, changed state to up",
                                        interface, 
                                    );
                                    println!(
                                        "%LINEPROTO-5-UPDOWN: Line protocol on Interface {}, changed state to up",
                                        interface, 
                                    );
                                    
                                    let mut interface_config = InterfaceConfig {
                                        ip_address: Ipv4Addr::new(0, 0, 0, 0),
                                        is_up: false,
                                    };
                                
                                    
                                    interface_config.ip_address = Ipv4Addr::from_str(&interface).unwrap();
                                    interface_config.is_up = true;
                                }
                            } else {
                                println!("Interface {} not found.", interface);
                            }
                        } else {
                            println!("Interface {} not found.", interface);
                        }
                        Ok(())
                    } else {
                        Err("No interface selected. Use the 'interface' command first.".into())
                    }
                } else {
                    Err("The 'no shutdown' command is only available in Interface Configuration mode.".into())
                }
            },
        },
    );
    

    commands
}