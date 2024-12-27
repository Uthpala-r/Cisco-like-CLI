/// External crates for the CLI application
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::run_config::save_config;
use crate::run_config::load_config;
use crate::execute::Command;
use crate::execute::Mode;
use crate::clock_settings::handle_show_clock;
use crate::clock_settings::handle_clock_set;
use crate::network_config::{calculate_broadcast, STATUS_MAP, IFCONFIG_STATE, IP_ADDRESS_STATE, ROUTE_TABLE, OSPF_CONFIG};
use crate::network_config::{InterfaceConfig, OSPFConfig};


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
/// - `show ip route`: Displays the ip routes defined
/// - `vlan`: Define vlans. This will enter the Vlan Mode
/// - `name`: Define the name of the vlan
/// - `state: Define the state of the valn
/// - `show vlan`: Displays information and status of VLANs.
/// - `switchport`: Defines the switchports
/// - `router ospf`: Configures and enables an OSPF routing process on the router. Specify the process ID to distinguish between multiple OSPF instances. This will enter the RouterConfig Mode
/// - `network`: Associates a network or subnet with a specific OSPF area.
/// - `ip ospf`: Assigns OSPF-specific parameters to an interface, such as the OSPF cost or authentication settings.
/// - `neighbor`: Manually specifies a neighboring router for OSPF adjacency, usually in cases of non-broadcast networks.
/// - `area`: Defines OSPF area-specific configurations, such as authentication, stub area settings, or default-cost for stub areas.
/// - `passive-interface`: Prevents OSPF from sending hello packets on the specified interface while still advertising the interface's network in OSPF.
/// - `distance`: Configures the administrative distance for OSPF routes, which influences route preference when multiple protocols advertise the same destination.
/// - `default-information`: Configures OSPF to advertise a default route (0.0.0.0/0) to other routers in the network.
/// - `router-id`: Manually sets a unique identifier for the OSPF process, typically an IPv4 address, to distinguish the router in the OSPF domain.
/// - `clear ip ospf process`: Restarts the OSPF process, clearing the OSPF routing table and adjacencies.
/// - `show ip ospf neighbor`: Displays information about OSPF neighbors, including their state, router ID, and the interface used for adjacency.
///
/// # Returns
/// A `HashMap` where the keys are command names (as `&'static str`) and the values are the corresponding `Command` structs.
/// Each `Command` struct contains the `name`, `description`, `suggestions`, and an `execute` function.
pub fn build_command_registry() -> HashMap<&'static str, Command> {
    let mut commands = HashMap::new();

    commands.insert("enable", Command {
        name: "enable",
        description: "Enter privileged EXEC mode",
        suggestions: None,
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

    commands.insert("configure", Command {
        name: "configure terminal",
        description: "Enter global configuration mode",
        suggestions: Some(vec!["terminal"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() != 2 {
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
        description: "Enter Interface configuration mode or Interface Range configuration mode",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode | Mode::InterfaceMode) {
                if args.is_empty() {
                    return Err("Please specify an interface or range, e.g., 'interface g0/0' or 'interface range f0/0 - 24'.".into());
                }
    
                let input = args.join(" ");
                if input.starts_with("range") {
                    // Handle interface range
                    let range_args = input.strip_prefix("range").unwrap().trim();
                    let range_parts: Vec<&str> = range_args.split('-').map(|s| s.trim()).collect();
    
                    if range_parts.len() != 2 {
                        return Err("Invalid range format. Use 'interface range f0/0 - 24'.".into());
                    }
    
                    let start = range_parts[0];
                    let end = range_parts[1];
                    if start.is_empty() || end.is_empty() {
                        return Err("Invalid range format. Start and end interfaces must be specified.".into());
                    }
    
                    context.current_mode = Mode::InterfaceMode;
                    context.selected_interface = Some(format!("{} - {}", start, end));
                    context.prompt = format!("{}(config-if-range)#", context.config.hostname);
                    println!("Entering Interface Range configuration mode for: {} - {}", start, end);
                    Ok(())
                } else {
                    // Handle single interface
                    let interface = input.clone();
                    context.current_mode = Mode::InterfaceMode;
                    context.selected_interface = Some(interface.clone());
                    context.prompt = format!("{}(config-if)#", context.config.hostname);
                    println!("Entering Interface configuration mode for: {}", interface);
                    Ok(())
                }
            } else {
                Err("The 'interface' command is only available in Global Configuration mode and interface configuration mode.".into())
            }
        },
    });

    commands.insert("exit", Command {
        name: "exit",
        description: "Exit the current mode and return to the previous mode.",
        suggestions: None,
        execute: |_args, context, _| {
            if _args.is_empty() {
                match context.current_mode {
                    Mode::InterfaceMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Interface Configuration Mode...");
                        Ok(())
                    }
                    Mode::VlanMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting VLAN Mode...");
                        Ok(())
                    }
                    Mode::RouterConfigMode => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting VLAN Mode...");
                        Ok(())
                    }
                    Mode::ConfigMode => {
                        context.current_mode = Mode::PrivilegedMode;
                        context.prompt = format!("{}#", context.config.hostname);
                        println!("Exiting Global Configuration Mode...");
                        Ok(())
                    }
                    Mode::PrivilegedMode => {
                        context.current_mode = Mode::UserMode;
                        context.prompt = format!("{}>", context.config.hostname);
                        println!("Exiting Privileged EXEC Mode...");
                        Ok(())
                    }
                    Mode::UserMode => {
                        println!("Already at the top level. No mode to exit.");
                        Err("No mode to exit.".into())
                    }
                }
            } else {
                Err("Invalid arguments provided to 'exit'. This command does not accept additional arguments.".into())
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
        "write",
        Command {
            name: "write memory",
            description: "Save the running configuration to the startup configuration",
            suggestions: Some(vec!["memory"]),
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
        "clock",
        Command {
            name: "clock set",
            description: "Change the clock date and time",
            suggestions: Some(vec!["set"]),
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
            execute: |_, context, _| {
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
            execute: |_, context, _| {
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
            execute: |_, context, _| {
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
        "ip",
        Command {
            name: "ip route",
            description: "Add static routes to the routing table",
            suggestions: Some(vec!["route"]),
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
                    } 
                    
                    else if args.len() == 4 {
                        let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
                        let netmask: Ipv4Addr = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format");
                        
                        if let Ok(next_hop) = Ipv4Addr::from_str(&args[3]) {
                            // Scenario 1: ip route <ip-address> <netmask> <next-hop>
                            route_table.insert(destination_ip.to_string(), (netmask, next_hop.to_string()));
                            println!("Added route: ip route {} {} {}", destination_ip, netmask, next_hop);
                        }
                        else {
                            // Scenario 2: ip route <ip-address> <netmask> <exit interface>
                            let exit_interface: String = args[3].to_string();
                            println!("Added route: ip route {} {} {}", destination_ip, netmask, exit_interface);
                            route_table.insert(destination_ip.to_string(), (netmask, exit_interface));
                        }   
                    } 
                    
                    else if args.len() == 5 {
                        // Scenario 3: ip route <ip-address> <netmask> <exit interface> <next-hop>
                        let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
                        let netmask: Ipv4Addr = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format");
                        let exit_interface: String = args[2].to_string();
                        let next_hop: Ipv4Addr = Ipv4Addr::from_str(&args[4]).expect("Invalid IP address format");
        
                        // Insert the route in the route table with exit interface and next hop
                        route_table.insert(destination_ip.to_string(), (netmask, format!("{} {}", exit_interface, next_hop)));
                        println!("Added route: ip route {} {} {} {}", destination_ip, netmask, exit_interface, next_hop);
                    } 
                    
                    else {
                        println!("Invalid arguments provided to 'ip route'. Expected: ip route <ip-address> <netmask> <next-hop | exit-interface> <next-hop>.");
                    }
        
                    Ok(())
                } else {
                    Err("The 'ip route' command is only available in Configuration mode.".into())
                }
            },
        },
    );


    commands.insert(
        "show ip route",
        Command {
            name: "show ip route",
            description: "Display the routing table or details for a specific route",
            suggestions: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    let route_table = ROUTE_TABLE.lock().unwrap();
        
                    if args.is_empty() {
                        println!("Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP");
                        println!("       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area");
                        println!("       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2");
                        println!("       E1 - OSPF external type 1, E2 - OSPF external type 2, E - EGP");
                        println!("       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area");
                        println!("       * - candidate default, U - per-user static route, o - ODR");
                        println!("       P - periodic downloaded static route");
                        println!();
        
                        if route_table.is_empty() {
                            println!("No routes configured.");
                        } else {
                            for (destination, (netmask, next_hop_or_iface)) in route_table.iter() {
                                let route_type = if next_hop_or_iface.contains("exit_interface") {
                                    "C"
                                } else {
                                    "S"
                                };
        
                                println!(
                                    "{}\t{} {} via {}",
                                    route_type, destination, netmask, next_hop_or_iface
                                );
                            }
                        }
                    } else if args.len() == 1 {
                        let destination_ip = args[0];
                        if let Some((netmask, next_hop_or_iface)) = route_table.get(destination_ip) {
                            let route_type = if next_hop_or_iface.contains("exit_interface") {
                                "connected"
                            } else {
                                "static"
                            };
        
                            println!("Routing entry for {}/{}", destination_ip, netmask);
                            println!("Known via \"{}\"", route_type);
                            println!("  Routing Descriptor Blocks:");
                            println!("  * {}", next_hop_or_iface);
                        } else {
                            println!("No route found for {}.", destination_ip);
                        }
                    } else {
                        println!("Invalid arguments. Use 'show ip route' or 'show ip route <ip-address>'.");
                    }
        
                    Ok(())
                }
                else {
                    Err("The 'show ip route' command is only available in Priviledged Exec mode.".into())
                }
            },
        },
    );

    commands.insert("vlan", Command {
        name: "vlan",
        description: "Define VLAN or VLAN Range",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode | Mode::VlanMode) {
                if args.is_empty() {
                    return Err("Please specify a VLAN ID or VLAN range, e.g., 'vlan 5' or 'vlan range 10 - 20'.".into());
                }
    
                let input = args.join(" ");
                
                if input.starts_with("range") {
                    // Handle VLAN range
                    let range_args = input.strip_prefix("range").unwrap().trim();
                    let range_parts: Vec<&str> = range_args.split('-').map(|s| s.trim()).collect();
    
                    if range_parts.len() != 2 {
                        return Err("Invalid range format. Use 'vlan range 10 - 20'.".into());
                    }
    
                    // Validate the range
                    let start: u16 = range_parts[0].parse().map_err(|_| "Invalid VLAN ID.")?;
                    let end: u16 = range_parts[1].parse().map_err(|_| "Invalid VLAN ID.")?;
                    
                    if start < 2 || end > 4094 || start > end {
                        return Err("VLAN range must be between 2 and 4094, and the start must be less than or equal to the end.".into());
                    }
    
                    // Create the VLAN range
                    context.current_mode = Mode::VlanMode;
                    context.selected_vlan = Some(format!("{} - {}", start, end));
                    context.prompt = format!("{}(config-vlan)#", context.config.hostname);
                    println!("Entering VLAN Range configuration mode for VLANs: {} - {}", start, end);
                    Ok(())
                } else {
                    // Handle single VLAN
                    let mut vlan_args: Vec<&str> = input.split_whitespace().collect();
                    let vlan_id: u16 = input.parse().map_err(|_| "Invalid VLAN ID.")?;
    
                    if vlan_id == 1 {
                        return Err("VLAN 1 is the default VLAN and cannot be created.".into());
                    }
    
                    if vlan_id < 2 || vlan_id > 4094 {
                        return Err("VLAN ID must be between 2 and 4094.".into());
                    }

                    let vlan_name = if vlan_args.len() > 1 {
                        vlan_args[1..].join(" ")
                    } else {
                        format!("VLAN{}", vlan_id) // Default name
                    };
    
                    context.current_mode = Mode::VlanMode;
                    context.selected_vlan = Some(vlan_id.to_string());
                    context.prompt = format!("{}(config-vlan)#", context.config.hostname);
                    context.vlan_names.get_or_insert_with(HashMap::new);
                    println!("Entering VLAN configuration mode for VLAN ID: {}", vlan_id);
                    
                    if let Some(vlan_names) = &mut context.vlan_names {
                        vlan_names.insert(vlan_id.to_string(), vlan_name.clone());
                        println!("VLAN {} named: {}", vlan_id, vlan_name);
                        Ok(())
                    } else {
                        Err("VLAN names are not initialized.".into())
                    }
                    
                }
            } else {
                Err("The 'vlan' command is only available in Global Configuration mode and Vlan mode.".into())
            }
        },
    });
    
    commands.insert("name", Command {
        name: "name",
        description: "Set VLAN name",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                context.vlan_names.get_or_insert_with(HashMap::new);
                if let Some(vlan_id_str) = &context.selected_vlan {
                    // Parse vlan_id as u16 from string
                    let vlan_id: u16 = vlan_id_str.parse().map_err(|_| "Invalid VLAN ID.")?;
    
                    if args.is_empty() {
                        let vlan_name = format!("VLAN{}", vlan_id);
                    }
                    let vlan_name = args.join(" ");
                    
                    if vlan_id == 1 {
                        return Err("VLAN 1 cannot have its name changed.".into());
                    }
    
                    // Access the HashMap inside Option and insert the VLAN name
                    if let Some(vlan_names) = &mut context.vlan_names {
                        vlan_names.insert(vlan_id.to_string(), vlan_name.clone());
                        println!("VLAN {} named: {}", vlan_id, vlan_name);
                        Ok(())
                    } else {
                        Err("VLAN names are not initialized.".into())
                    }
                } else {
                    Err("Please enter a VLAN configuration mode first (e.g., 'vlan 5').".into())
                }
            } else {
                Err("The 'name' command is only available in Vlan mode.".into())
            }
        },
    });
    
    commands.insert("state", Command {
        name: "state",
        description: "Set VLAN state",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::VlanMode) {
                
                context.vlan_states.get_or_insert_with(HashMap::new);
                if let Some(vlan_id_str) = &context.selected_vlan {
                    // Parse vlan_id as u16 from string
                    let vlan_id: u16 = vlan_id_str.parse().map_err(|_| "Invalid VLAN ID.")?;
    
                    if args.is_empty() {
                        return Err("Please specify the state for the VLAN (active or suspend).".into());
                    }
    
                    let state = args[0].to_lowercase();
                    if state != "active" && state != "suspend" {
                        return Err("State must be 'active' or 'suspend'.".into());
                    }
    
                    if vlan_id == 1 {
                        return Err("VLAN 1 cannot be suspended.".into());
                    }
    
                    // Access the HashMap inside Option and insert the VLAN state
                    if let Some(vlan_states) = &mut context.vlan_states {
                        vlan_states.insert(vlan_id, state.clone());
                        println!("VLAN {} state set to: {}", vlan_id, state);
                        Ok(())
                    } else {
                        Err("VLAN states are not initialized.".into())
                    }
                } else {
                    Err("Please enter a VLAN configuration mode first (e.g., 'vlan 5').".into())
                }
            } else {
                Err("The 'state' command is only available in Vlan mode.".into())
            }
        },
    });

    commands.insert(
        "show vlan",
        Command {
            name: "show vlan",
            description: "Displays information and status of VLANs.",
            suggestions: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    if let (Some(vlan_names), Some(vlan_states)) = (&context.vlan_names, &context.vlan_states) {
                        // Display table header for VLANs
                        println!("{:<6} {:<30} {:<10} {}", "VLAN", "Name", "Status", "Ports");

                        for (vlan_id_str, vlan_name) in vlan_names {
                            let vlan_id: u16 = vlan_id_str.parse().unwrap_or_default(); 
                            let unknown_status = "active".to_string();
                            let status = vlan_states.get(&vlan_id).unwrap_or(&unknown_status); 
                            let ports = " ";  // temporary
    
                            println!("{:<6} {:<30} {:<10} {}", vlan_id, vlan_name, status, ports);
                        }
    
                        Ok(())
                    } else if let Some(vlan_names) = &context.vlan_names {
                        println!("{:<6} {:<30} {:<10} {}", "VLAN", "Name", "Status", "Ports");

                        for vlan_id_str in vlan_names.keys() {
                            let vlan_id: u16 = vlan_id_str.parse().unwrap_or_default();
                            let vlan_name = format!("VLAN{}", vlan_id);
                            let status = "active"; 
                            let ports = " "; // temporary
    
                            println!("{:<6} {:<30} {:<10} {}", vlan_id, vlan_name, status, ports);
                        }

                        Ok(())
                    } else {
                        Err("No VLAN information available.".into())
                    }
                    
                }
            
                else {
                    Err("The 'show vlan' command is only available in Priviledged Exec mode.".into())
                }
            },
        },
    );

    commands.insert("switchport", Command {
        name: "switchport",
        description: "Configure switchport settings on the interface",
        suggestions: Some(vec![
            "access", "mode", "nonegotiate", "port-security", 
            "priority", "protected", "trunk", "voice",
        ]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::InterfaceMode) {
                if args.is_empty() {
                    return Err("Please specify a switchport subcommand, e.g., 'switchport mode'.".into());
                }
    
                match args[0].as_ref() {
                    "mode" => {
                        if args.len() < 2 {
                            return Err("Usage: switchport mode [access | dynamic | trunk]".into());
                        }
                        match args[1].as_ref() {
                            "access" => {
                                println!("Switchport mode set to ACCESS.");
                                context.switchport_mode = Some("access".to_string());
                                Ok(())
                            }
                            "dynamic" => {
                                println!("Switchport mode set to DYNAMIC.");
                                context.switchport_mode = Some("dynamic".to_string());
                                Ok(())
                            }
                            "trunk" => {
                                println!("Switchport mode set to TRUNK.");
                                context.switchport_mode = Some("trunk".to_string());
                                Ok(())
                            }
                            _ => Err("Invalid mode. Use 'access', 'dynamic', or 'trunk'.".into()),
                        }
                    }
                    "trunk" => {
                        if args.len() < 2 {
                            return Err("Usage: switchport trunk [encapsulation | native vlan | allowed vlan]".into());
                        }
                        match args[1].as_ref() {
                            "encapsulation" => {
                                if args.len() < 3 || args[2] != "dot1q" {
                                    return Err("Usage: switchport trunk encapsulation dot1q".into());
                                }
                                println!("Trunk encapsulation set to DOT1Q.");
                                context.trunk_encapsulation = Some("dot1q".to_string());
                                Ok(())
                            }
                            "native" => {
                                if args.len() < 4 || args[2] != "vlan" {
                                    return Err("Usage: switchport trunk native vlan <vlan_id>".into());
                                }
                                let vlan_id: u16 = args[3].parse().map_err(|_| "Invalid VLAN ID.")?;
                                println!("Native VLAN set to {}.", vlan_id);
                                context.native_vlan = Some(vlan_id);
                                Ok(())
                            }
                            "allowed" => {
                                if args.len() < 4 || args[2] != "vlan" {
                                    return Err("Usage: switchport trunk allowed vlan <vlan_id>".into());
                                }
                                let vlan_id: u16 = args[3].parse().map_err(|_| "Invalid VLAN ID.")?;
                                println!("Allowed VLAN set to {}.", vlan_id);
                                context.allowed_vlans.insert(vlan_id);
                                Ok(())
                            }
                            _ => Err("Invalid trunk subcommand. Use 'encapsulation', 'native vlan', or 'allowed vlan'.".into()),
                        }
                    }
                    "access" => {
                        println!("Access mode characteristics set.");
                        Ok(())
                    }
                    "nonegotiate" => {
                        println!("Switchport set to NONEGOTIATE.");
                        Ok(())
                    }
                    "port-security" => {
                        println!("Port security configured.");
                        Ok(())
                    }
                    _ => Err("Invalid switchport subcommand.".into()),
                }
            } else {
                Err("The 'switchport' command is only available in Interface Configuration mode.".into())
            }
        },
    });


    commands.insert("router", Command {
        name: "router",
        description: "Enable OSPF routing and enter router configuration mode",
        suggestions: Some(vec!["ospf"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 2 {
                    let process_id = args[1].parse::<u32>();
                    match process_id {
                        Ok(id) if id > 0 => {
                            let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                            ospf_config.process_id = Some(id);
                            context.current_mode = Mode::RouterConfigMode;
                            context.prompt = format!("{}(config-router)#", context.config.hostname);
                            println!("OSPF routing enabled with process ID {}.", id);
                            Ok(())
                        }
                        _ => Err("Invalid process ID provided. It must be a positive integer.".into()),
                    }
                } else {
                    Err("The 'router ospf' command requires exactly one argument: the process ID.".into())
                }
            } else {
                Err("The 'router ospf' command is only available in Global Configuration mode.".into())
            }
        },
    });

    commands.insert("network", Command {
        name: "network",
        description: "Define an OSPF network and associate it with an area ID",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if args.len() == 4 {
                    let ip_address = args[0].clone();
                    let wildcard_mask = args[1].clone();
                    let area_id = args[3].parse::<u32>();
    
                    if area_id.is_err() || ip_address.is_empty() || wildcard_mask.is_empty() {
                        Err("Invalid arguments provided. Usage: network <ip-address> <wildcard-mask> area <area-id>".into())
                    } else {
                        let area_id = area_id.unwrap();
                        let key = format!("{} {}", ip_address, wildcard_mask);
                        let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                        ospf_config.networks.insert(key, area_id);
                        println!(
                            "Network {} {} added to OSPF area {}.",
                            ip_address, wildcard_mask, area_id
                        );
                        Ok(())
                    }
                } else {
                    Err("The 'network' command requires three arguments: <ip-address> <wildcard-mask> <area-id>.".into())
                }
            } else {
                Err("The 'network' command is only available in Router Configuration mode.".into())
            }
        },
    });

    commands.insert("ip ospf", Command {
        name: "ip ospf",
        description: "Configure OSPF-related settings on an interface",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::InterfaceMode) {
                if args.is_empty() {
                    Err("The 'ip ospf' command requires a subcommand. Available subcommands: cost, retransmit-interval, transmit-delay, priority, hello-interval, dead-interval, authentication-key, message-digest-key, authentication.".into())
                } else {
                    let subcommand = &args[0][..];
                    match subcommand {
                        "cost" => {
                            if args.len() == 2 {
                                let cost = args[1].parse::<u32>();
                                match cost {
                                    Ok(value) => {
                                        println!("OSPF cost set to {}.", value);
                                        Ok(())
                                    }
                                    _ => Err("Invalid cost value. It must be a positive integer.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf cost <cost>".into())
                            }
                        }
                        "retransmit-interval" => {
                            if args.len() == 2 {
                                let interval = args[1].parse::<u32>();
                                match interval {
                                    Ok(seconds) => {
                                        println!("OSPF retransmit interval set to {} seconds.", seconds);
                                        Ok(())
                                    }
                                    _ => Err("Invalid retransmit interval. It must be a positive integer.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf retransmit-interval <seconds>".into())
                            }
                        }
                        "transmit-delay" => {
                            if args.len() == 2 {
                                let delay = args[1].parse::<u32>();
                                match delay {
                                    Ok(seconds) => {
                                        println!("OSPF transmit delay set to {} seconds.", seconds);
                                        Ok(())
                                    }
                                    _ => Err("Invalid transmit delay. It must be a positive integer.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf transmit-delay <seconds>".into())
                            }
                        }
                        "priority" => {
                            if args.len() == 2 {
                                let priority = args[1].parse::<u8>();
                                match priority {
                                    Ok(value) => {
                                        println!("OSPF priority set to {}.", value);
                                        Ok(())
                                    }
                                    _ => Err("Invalid priority value. It must be a number between 0 and 255.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf priority <priority>".into())
                            }
                        }
                        "hello-interval" => {
                            if args.len() == 2 {
                                let interval = args[1].parse::<u32>();
                                match interval {
                                    Ok(seconds) => {
                                        println!("OSPF hello interval set to {} seconds.", seconds);
                                        Ok(())
                                    }
                                    _ => Err("Invalid hello interval. It must be a positive integer.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf hello-interval <seconds>".into())
                            }
                        }
                        "dead-interval" => {
                            if args.len() == 2 {
                                let interval = args[1].parse::<u32>();
                                match interval {
                                    Ok(seconds) => {
                                        println!("OSPF dead interval set to {} seconds.", seconds);
                                        Ok(())
                                    }
                                    _ => Err("Invalid dead interval. It must be a positive integer.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf dead-interval <seconds>".into())
                            }
                        }
                        "authentication-key" => {
                            if args.len() == 2 {
                                let key = args[1].clone();
                                println!("OSPF authentication key set to '{}'.", key);
                                Ok(())
                            } else {
                                Err("Usage: ip ospf authentication-key <key>".into())
                            }
                        }
                        "message-digest-key" => {
                            if args.len() == 4 && args[2] == "md5" {
                                let key_id = args[1].parse::<u32>();
                                let key = args[3].clone();
                                match key_id {
                                    Ok(id) => {
                                        println!("OSPF MD5 message-digest-key set with key-id {} and key '{}'.", id, key);
                                        Ok(())
                                    }
                                    _ => Err("Invalid key-id. It must be a positive integer.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf message-digest-key <key-id> md5 <key>".into())
                            }
                        }
                        "authentication" => {
                            if args.len() == 2 {
                                let auth_type = &args[1][..];
                                match auth_type {
                                    "message-digest" | "null" => {
                                        println!("OSPF authentication set to '{}'.", auth_type);
                                        Ok(())
                                    }
                                    _ => Err("Invalid authentication type. Valid options: message-digest, null.".into()),
                                }
                            } else {
                                Err("Usage: ip ospf authentication [message-digest | null]".into())
                            }
                        }
                        _ => Err(format!("Unknown subcommand '{}'. Use 'ip ospf' to see available subcommands.", subcommand).into()),
                    }
                }
            } else {
                Err("The 'ip ospf' command is only available in Interface Configuration mode.".into())
            }
        },
    });
    
    commands.insert("neighbor", Command {
        name: "neighbor",
        description: "Specify a neighbor and optionally assign a cost.",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if args.is_empty() {
                    return Err("Usage: neighbor <ip-address> [cost <number>]".into());
                }
    
                let ip_address = Ipv4Addr::from_str(&args[0]).expect("Invalid IP address format");
                let mut cost: Option<u32> = None;
    
                // Parse optional "cost <number>" arguments
                if args.len() == 3 && args[1] == "cost" {
                    match args[2].parse::<u32>() {
                        Ok(value) => {
                            cost = Some(value);
                        }
                        Err(_) => {
                            return Err("Invalid cost value. It must be a positive integer.".into());
                        }
                    }
                } else if args.len() != 1 {
                    return Err("Usage: neighbor <ip-address> [cost <number>]".into());
                }

                let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                ospf_config.neighbors.insert(ip_address, cost);
                
                if let Some(cost_value) = cost {
                    println!("Neighbor {} configured with cost {}.", ip_address, cost_value);
                } else {
                    println!("Neighbor {} configured with default cost.", ip_address);
                }
                Ok(())
                
            } else {
                Err("The 'neighbor' command is only available in Router Configuration mode.".into())
            }
        },
    });

    commands.insert("area", Command {
        name: "area",
        description: "Configure OSPF area options.",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if args.is_empty() {
                    return Err("Usage: area <area-id> <subcommand> [options]".into());
                }
    
                let area_id = args[0].clone();
                let subcommand = args.get(1).map(|s| &s[..]).unwrap_or_default();
    
                match subcommand {
                    "authentication" => {
                        if args.len() == 2 {
                            println!("Authentication enabled for area {}.", area_id);
                            Ok(())
                        } else {
                            Err("Usage: area <area-id> authentication".into())
                        }
                    }
                    "stub" => {
                        if args.len() == 2 {
                            println!("Area {} configured as a stub.", area_id);
                            Ok(())
                        } else if args.len() == 3 && args[2] == "no-summary" {
                            println!("Area {} configured as a stub with no-summary.", area_id);
                            Ok(())
                        } else {
                            Err("Usage: area <area-id> stub [no-summary]".into())
                        }
                    }
                    "default-cost" => {
                        if args.len() == 3 {
                            match args[2].parse::<u32>() {
                                Ok(cost) => {
                                    println!("Default cost for area {} set to {}.", area_id, cost);
                                    Ok(())
                                }
                                Err(_) => Err("Invalid cost value. It must be a positive integer.".into()),
                            }
                        } else {
                            Err("Usage: area <area-id> default-cost <cost>".into())
                        }
                    }
                    _ => Err("Invalid subcommand. Valid subcommands: authentication, stub, default-cost".into()),
                }
            } else {
                Err("The 'area' command is only available in Router Configuration mode.".into())
            }
        },
    });

    commands.insert("passive-interface", Command {
        name: "passive-interface",
        description: "Disables sending OSPF Hello packets on an interface",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if let Some(interface) = args.get(0) {
                    let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                    ospf_config.passive_interfaces.push(interface.to_string());
                    println!("Passive interface set on: {}", interface);
                    Ok(())
                } else {
                    Err("Usage: passive-interface <interface>".into())
                }
            } else {
                Err("The 'passive-interface' command is only available in Router OSPF mode.".into())
            }
        },
    });
    

    commands.insert("distance", Command {
        name: "distance",
        description: "Set administrative distance for OSPF",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if let Some(distance) = args.get(0) {
                    if let Ok(dist) = distance.parse::<u32>() {
                        let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                        ospf_config.distance = Some(dist);
                        println!("OSPF administrative distance set to: {}", dist);
                        Ok(())
                    } else {
                        Err("Invalid distance value. Must be a number.".into())
                    }
                } else {
                    Err("Usage: distance <value>".into())
                }
            } else {
                Err("The 'distance' command is only available in Router OSPF mode.".into())
            }
        },
    });

    commands.insert("default-information", Command {
        name: "default-information",
        description: "Originate a default route in OSPF",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if args.get(0).map(|s| &s[..]) == Some("originate") {
                    println!("Default-information originate command executed.");
                    Ok(())
                } else {
                    Err("Usage: default-information originate".into())
                }
            } else {
                Err("The 'default-information originate' command is only available in Router OSPF mode.".into())
            }
        },
    });

    commands.insert("router-id", Command {
        name: "router-id",
        description: "Set the router ID for the OSPF process",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::RouterConfigMode) {
                if let Some(router_id) = args.get(0) {
                    let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                    ospf_config.router_id = Some(router_id.to_string());
                    println!("Router ID set to: {}", router_id);
                    Ok(())
                } else {
                    Err("Usage: router-id <id>".into())
                }
            } else {
                Err("The 'router-id' command is only available in Router OSPF mode.".into())
            }
        },
    });

    commands.insert("clear ip ospf process", Command {
        name: "clear ip ospf process",
        description: "Reset all OSPF processes",
        suggestions: None,
        execute: |_, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                
                println!("Reset ALL OSPF processes? [no]: yes");
                let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                *ospf_config = OSPFConfig::new();  
                println!("All OSPF processes cleared.");
                Ok(())
            } else {
                Err("The 'clear ip ospf process' command is only available in EXEC mode.".into())
            }
        },
    });



    commands.insert("show ip ospf neighbor", Command {
        name: "show ip ospf neighbor",
        description: "Displays OSPF configuration",
        suggestions: None,
        execute: |_, _, _| {
            let mut ospf_config = OSPF_CONFIG.lock().unwrap();
            println!("Current OSPF Configuration:");
            println!("Router ID: {:?}", ospf_config.router_id.clone().unwrap_or("Not set".to_string()));
            println!("Administrative Distance: {:?}", ospf_config.distance.unwrap_or(110));
            println!("Default Information Originate: {}", ospf_config.default_information_originate);
            println!("Passive Interfaces: {:?}", ospf_config.passive_interfaces);
            Ok(())
        },
    });

    

    commands
}