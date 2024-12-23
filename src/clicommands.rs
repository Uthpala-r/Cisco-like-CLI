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
use crate::network_config::{calculate_broadcast, STATUS_MAP, IFCONFIG_STATE, IP_ADDRESS_STATE, ROUTE_TABLE};
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
/// - `ip route`: Define the static ip routes
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
            if matches!(context.current_mode, Mode::ConfigMode | Mode::InterfaceMode) {
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
                Err("The 'interface' command is only available in Global Configuration mode and interface configuration mode.".into())
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
                let mut ifconfig_state = IFCONFIG_STATE.lock().unwrap();
    
                if args.is_empty() {
                    if ifconfig_state.is_empty() {
                        println!("No interfaces found.");
                    } else {
                        for (interface_name, (ip_address, broadcast_address)) in ifconfig_state.iter() {
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
    
                    ifconfig_state.insert(new_interface.to_string(), (new_ip, new_broadcast));
    
                    println!("Updated {}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500", new_interface);
                    println!("    inet {}  netmask 255.255.255.0  broadcast {}", new_ip, new_broadcast);
                    println!("    inet6 fe80::6a01:72f9:adf2:3ffb  prefixlen 64  scopeid 0x20<link>");
                    println!("    ether 00:0c:29:16:30:92  txqueuelen 1000  (Ethernet)");
                } else {
                    println!("Invalid arguments provided to 'ifconfig'.");
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
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    context.config.startup_config = context.config.running_config.clone();
                    save_config(&context.config).map_err(|e| format!("Failed to save configuration: {}", e))?;
                    println!("Configuration saved successfully.");
                    Ok(())
                } else {
                    Err("The 'write memory' command is only available in Privileged EXEC mode.".into())
                }    
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
    
                    let ip_address: Ipv4Addr = args[0]
                        .parse()
                        .map_err(|_| "Invalid IP address format.".to_string())?;
                    let netmask: Ipv4Addr = args[1]
                        .parse()
                        .map_err(|_| "Invalid netmask format.".to_string())?;
    
                    let mut ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
    
                    if let Some(interface) = &context.selected_interface {
                        if let Some((existing_ip, existing_broadcast)) = ip_address_state.get_mut(interface) {
                            *existing_ip = ip_address;
                            *existing_broadcast = netmask;
                            println!(
                                "Updated interface {} with IP {} and netmask {}",
                                interface, ip_address, netmask
                            );
                        } else {
                            ip_address_state.insert(interface.clone(), (ip_address, netmask));
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
            description: "Display detailed statistics for all interfaces configured on the router",
            suggestions: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode) {
                    let ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
                    let Some(interface_name) = &context.selected_interface else {
                        return Err("No interface selected. Use the 'interface' command first.".into());
                    };
            
                    if ip_address_state.is_empty() {
                        println!("No interfaces found.");
                        return Ok(()); 
                    } else {
                        for (interface_name, (ip_address, _)) in ip_address_state.iter() {
                            println!("{} is up, line protocol is up", interface_name);
                            println!("  Internet address is {}, subnet mask 255.255.255.0", ip_address);
                            println!("  MTU 1500 bytes, BW 10000 Kbit, DLY 100000 usec");
                            println!("  Encapsulation ARPA, loopback not set, keepalive set (10 sec)");
                            println!("  Last clearing of \"show interface\" counters: never");
                            println!("  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0");
                            println!("  5 minute input rate 1000 bits/sec, 10 packets/sec");
                            println!("  5 minute output rate 500 bits/sec, 5 packets/sec");
                            println!("  100 packets input, 1000 bytes, 10 no buffer");
                            println!("  50 packets output, 500 bytes, 0 underruns");
                        }
                    }
            
                    Ok(()) 
                } else {
                    Err("The 'show interfaces' command is only available in User Exec Mode and Privileged EXEC mode.".into())
                }
            },
        },
    );
    
    commands.insert(
        "show ip interface brief",
        Command {
            name: "show ip interface brief",
            description: "Display a brief summary of IP interfaces.",
            suggestions: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode) {
                    let ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
                    let status_map = STATUS_MAP.lock().unwrap();
        
                    println!(
                        "{:<22} {:<15} {:<8} {:<20} {:<10}",
                        "Interface", "IP-Address", "OK?", "Method", "Status"
                    );
        
                    for (interface_name, (ip_address, _broadcast_address)) in ip_address_state.iter() {
                        let is_up = status_map.get(interface_name).copied().unwrap_or(false);
                        let status = if is_up {
                            "administratively up"
                        } else {
                            "administratively down"
                        };
        
                        println!(
                            "{:<22} {:<15} YES     unset               {}",
                            interface_name, ip_address, status
                        );
                    }
        
                    Ok(())
                } else {
                    Err("The 'show ip interface brief' command is only available in User Exec Mode and Privileged EXEC mode.".into())
                }
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
                        let mut network_state = IP_ADDRESS_STATE.lock().unwrap();
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
                        let mut network_state = IP_ADDRESS_STATE.lock().unwrap();
                        let mut status_map = STATUS_MAP.lock().unwrap();
    
                        // Check if the interface exists in `NETWORK_STATE`
                        if let Some((ip_address, broadcast_address)) = network_state.get(interface) {
                            // Update the administrative status to "up" in `STATUS_MAP`
                            status_map.insert(interface.clone(), true);
    
                            println!(
                                "%LINK-5-CHANGED: Interface {}, changed state to up",
                                interface
                            );
                            println!(
                                "%LINEPROTO-5-UPDOWN: Line protocol on Interface {}, changed state to up",
                                interface
                            );
                            Ok(())
                        } else {
                            println!("Interface {} not found.", interface);
                            Err("Invalid interface.".into())
                        }
                    } else {
                        Err("No interface selected. Use the 'interface' command first.".into())
                    }
                } else {
                    Err("The 'no shutdown' command is only available in Interface Configuration mode.".into())
                }
            },
        },
    );
    
    commands.insert(
        "ip route",
        Command {
            name: "ip route",
            description: "Add static routes to the routing table",
            suggestions: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::ConfigMode) {
                    let mut route_table = ROUTE_TABLE.lock().unwrap();
        
                    if args.len() == 0 {
                        // Display the current route table
                        if route_table.is_empty() {
                            println!("No static routes configured.");
                        } else {
                            for (route, (netmask, next_hop_or_iface)) in route_table.iter() {
                                println!("ip route {} {} {}", route, netmask, next_hop_or_iface);
                            }
                        }
                    } else if args.len() == 3 {
                        // Scenario 1: ip route <ip-address> <netmask> <next-hop>
                        let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&args[0]).expect("Invalid IP address format");
                        let netmask: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
                        let next_hop: Ipv4Addr = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format");
        
                        route_table.insert(destination_ip.to_string(), (netmask, next_hop.to_string()));
                        println!("Added route: ip route {} {} {}", destination_ip, netmask, next_hop);
                    } else if args.len() == 2 {
                        // Scenario 2: ip route <ip-address> <netmask> <exit interface>
                        let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&args[0]).expect("Invalid IP address format");
                        let netmask: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
        
                        // In this case, assume the exit interface is passed instead of next-hop
                        println!("Added route: ip route {} {} {}", destination_ip, netmask, "exit_interface");
        
                        route_table.insert(destination_ip.to_string(), (netmask, "exit_interface".to_string()));
                    } else if args.len() == 4 {
                        // Scenario 3: ip route <ip-address> <netmask> <exit interface> <next-hop>
                        let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&args[0]).expect("Invalid IP address format");
                        let netmask: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
                        let exit_interface: String = args[2].to_string();
                        let next_hop: Ipv4Addr = Ipv4Addr::from_str(&args[3]).expect("Invalid IP address format");
        
                        // Insert the route in the route table with exit interface and next hop
                        route_table.insert(destination_ip.to_string(), (netmask, format!("{} {}", exit_interface, next_hop)));
                        println!("Added route: ip route {} {} {} {}", destination_ip, netmask, exit_interface, next_hop);
                    } else {
                        println!("Invalid arguments provided to 'ip route'. Expected: ip route <ip-address> <netmask> <next-hop | exit-interface> <next-hop>.");
                    }
        
                    Ok(())
                } else {
                    Err("The 'ip route' command is only available in Configuration mode.".into())
                }
            },
        },
    );

    commands
}