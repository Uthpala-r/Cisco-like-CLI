/// External crates for the CLI application
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::{self, File};
use std::io::Write;
use std::str::FromStr;
use rpassword::read_password;

use crate::run_config::{save_config, get_running_config, default_startup_config};
//use crate::run_config::load_config;
use crate::execute::Command;
use crate::execute::Mode;
use crate::clock_settings::handle_show_clock;
use crate::clock_settings::handle_clock_set;
use crate::network_config::{calculate_broadcast, STATUS_MAP, IFCONFIG_STATE, IP_ADDRESS_STATE, ROUTE_TABLE, OSPF_CONFIG, ACL_STORE, encrypt_password, PASSWORD_STORAGE, set_enable_password, set_enable_secret, get_enable_password, get_enable_secret};
use crate::network_config::{InterfaceConfig, OSPFConfig, AclEntry, AccessControlList, NtpAssociation};


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
/// - `access-list`: Defines an ACL by creating or modifying an access control list with a specified number or name. This command is used to specify a set of rules for filtering network traffic.
/// - `ip access-list`: Used to create or modify an IP access list, specifying the version (standard or extended) and the list of rules to filter IP packets based on source/destination addresses, protocols, and ports.
/// - `show access-lists`: Displays the current configuration of all ACLs on the device, showing the list of ACL entries and their statistics (matches, actions, etc.).
/// - `permit`: An ACL action that allows network traffic that matches the rule's conditions (e.g., specific IP address or protocol) to pass through.
/// - `deny`: An ACL action that blocks network traffic matching the rule's conditions, preventing it from passing through the network.
/// - `crypto ipsec profile`: Configures and manages IPSec VPN profiles, including settings for security associations and tunnel configurations.
/// - `set tranform-set`: Specifies the transform set used in an IPSec VPN to define the cryptographic algorithms for encryption and integrity.
/// - `tunnel`: Defines and manages the settings for an IPsec tunnel, including the associated transport and security protocols.
/// - `virtual-template`: Creates a virtual template interface that can be used as a blueprint for creating virtual access interfaces, often used in VPN configurations.
/// - `ntp server`: Configures the NTP server for synchronizing time on the device, ensuring that the device’s clock is accurate.
/// - `ntp master`: Configures the device as an NTP master, meaning it will serve time to other devices in the network.
/// - `show ntp associations`: Displays the status of NTP associations with servers or clients, showing the synchronization status and other details.
/// - `ntp authenticate`: Enables NTP authentication, which allows the NTP client to authenticate time synchronization requests from servers.
/// - `ntp authentication-key`: Defines the key used for authenticating NTP messages, providing security to NTP transactions.
/// - `ntp trusted-key`: Specifies which authentication key(s) are trusted to authenticate NTP messages.
/// - `show ntp`: Displays information about the current NTP configuration, associations, and synchronization status.
/// - `service password-encryption`: Enables password encryption for storing sensitive passwords in the device’s configuration, ensuring they are not stored in plain text.
/// - `enable secret`: Sets a secret password for privileged EXEC mode access, using a stronger hash for security than the `enable password` command.
/// - `enable password`: Configures a password for privileged EXEC mode access. This password is weaker than the `enable secret` and should be avoided when possible.
/// - `ip domain-name`: Sets the domain name for the device, which is used in various operations such as DNS resolution.
/// - `crypto key`: Generates or manages cryptographic keys used in various security protocols, including VPNs and encryption.
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
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::UserMode) {
                // Retrieve stored passwords
                let storage = PASSWORD_STORAGE.lock().unwrap();
                let stored_password = storage.enable_password.clone();
                let stored_secret = storage.enable_secret.clone();
                drop(storage); // Release the lock
    
                if stored_password.is_none() && stored_secret.is_none() {
                    // No passwords stored, directly go to privileged EXEC mode
                    context.current_mode = Mode::PrivilegedMode;
                    context.prompt = format!("{}#", context.config.hostname);
                    println!("Entering privileged EXEC mode...");
                    return Ok(());
                }
    
                // Prompt for the enable password
                if stored_secret.is_none() {
                    println!("Enter password:");
                    let input_password = read_password().unwrap_or_else(|_| "".to_string());
        
                    if let Some(ref stored_password) = stored_password {
                        if input_password == *stored_password {
                            // Correct enable password, proceed to privileged mode
                            context.current_mode = Mode::PrivilegedMode;
                            context.prompt = format!("{}#", context.config.hostname);
                            println!("Entering privileged EXEC mode...");
                            return Ok(());
                        }
                    }
                }
        
                // If secret is stored, prompt for it if password check fails
                if let (Some(ref stored_secret), Some(ref stored_password)) = (stored_secret, stored_password) {
                    println!("Enter password:");
                    let input_password = read_password().unwrap_or_else(|_| "".to_string());
                    println!("Enter secret:");
                    let input_secret = read_password().unwrap_or_else(|_| "".to_string());
    
                    if input_secret == *stored_secret && input_password == *stored_password {
                        // Correct enable secret, proceed to privileged mode
                        context.current_mode = Mode::PrivilegedMode;
                        context.prompt = format!("{}#", context.config.hostname);
                        println!("Entering privileged EXEC mode...");
                        return Ok(());
                    }
                }
    
                // If neither password nor secret matches, return an error
                Err("Incorrect password or secret.".into())
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
                        println!("Exiting Router Configuration Mode Mode...");
                        Ok(())
                    }
                    Mode::ConfigStdNaclMode(_) => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Standard ACL Mode...");
                        Ok(())
                    }
                    Mode::ConfigExtNaclMode(_) => {
                        context.current_mode = Mode::ConfigMode;
                        context.prompt = format!("{}(config)#", context.config.hostname);
                        println!("Exiting Extended ACL Mode...");
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
            description: "Display the current running configuration",
            suggestions: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    println!("Building configuration...\n");
                    println!("Current configuration : 0 bytes\n");
                    let running_config = get_running_config(&context);
                    println!("{}", running_config);
                    Ok(())
                } else {
                    Err("The 'show running-config' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );

    commands.insert(
        "show startup-config",
        Command {
            name: "show startup-config",
            description: "Display the startup configuration (from memory)",
            suggestions: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    // Display the saved startup configuration
                    let startup_config = default_startup_config(context);
                        
                        println!("Building configuration...\n");
                        println!("Startup configuration : 0 bytes\n");
                        println!("{}", startup_config); 
                        Ok(())
                } else {
                    Err("The 'show startup-config' command is only available in Privileged EXEC mode.".into())
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
                    // Save the running configuration to the startup configuration using default_startup_config
                    let running_config = default_startup_config(context); 
                    //context.config.startup_config = Some(running_config.clone());
    
                    println!("Configuration saved successfully.");
                    Ok(())
                } else {
                    Err("The 'write memory' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );

    commands.insert(
        "copy running-config",
        Command {
            name: "copy running-config",
            description: "Copy the running configuration to a file",
            suggestions: Some(vec!["<file_name>"]),
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    
                    if let Some(file_name) = args.get(0) {
                        let running_config = get_running_config(context); 
                        let file_path = Path::new(file_name);
                        match File::create(file_path) {
                            Ok(mut file) => {
                                if let Err(err) = file.write_all(running_config.as_bytes()) {
                                    eprintln!("Error writing to the file: {}", err);
                                    return Err(err.to_string());
                                }
                                println!("Running configuration copied to {}", file_name);
                                Ok(())
                            }
                            Err(err) => {
                                eprintln!("Error creating the file: {}", err);
                                Err(err.to_string())
                            }
                        }
                    } else {
                        Err("No file name provided.".into())
                    }
                } else {
                    Err("The 'copy running-config' command is only available in Privileged EXEC mode.".into())
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


    commands.insert("access-list", Command {
        name: "access-list",
        description: "Configure a standard numbered ACL",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() >= 3 {
                    let acl_number = args[0].to_string();
                    let action = args[1].to_string();
                    let source = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format").to_string();
                    let destination = if args.len() > 3 { Ipv4Addr::from_str(&args[3]).expect("Invalid IP address format").to_string()} else { "any".to_string() };
                    let protocol = args.get(4).clone();
    
                    let entry = AclEntry {
                        action,
                        source,
                        destination,
                        protocol: None,     
                        source_operator: None,
                        source_port: None,
                        destination_operator: None,
                        destination_port: None,
                        matches: None,
                    };
    
                    let mut acl_store = ACL_STORE.lock().unwrap();
                    acl_store
                        .entry(acl_number.clone())
                        .or_insert(AccessControlList {
                            number_or_name: acl_number.clone(),
                            entries: vec![],
                        })
                        .entries
                        .push(entry);
    
                    println!("ACL {} updated.", acl_number);
                    Ok(())
                } else {
                    Err("Invalid syntax. Use 'access-list <number> {deny|permit} <source_ip> <wildcard_mask>'.".into())
                }
            } else {
                Err("The 'access-list' command is only available in global configuration mode.".into())
            }
        },
    });

    commands.insert("ip access-list", Command {
        name: "ip access-list",
        description: "Configure a named or numbered ACL (standard or extended)",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode | Mode::ConfigStdNaclMode(_) | Mode::ConfigExtNaclMode(_)) {
                if args.len() >= 2 {
                    let acl_type = args[0].to_lowercase(); // "standard" or "extended"
                    let acl_name_or_number = args[1].to_string(); // ACL name or number
    
                    let mut acl_store = ACL_STORE.lock().unwrap();
                    acl_store.entry(acl_name_or_number.clone()).or_insert(AccessControlList {
                        number_or_name: acl_name_or_number.clone(),
                        entries: vec![],
                    });
    
                    match acl_type.as_str() {
                        "standard" => {
                            // Transition to ConfigStdNaclMode
                            context.current_mode = Mode::ConfigStdNaclMode(acl_name_or_number.clone());
                            context.prompt = format!("{}(config-std-nacl)#", context.config.hostname);
                            println!("Standard ACL '{}' created. Enter ACL configuration mode.", acl_name_or_number);
                            Ok(())
                        }
                        "extended" => {
                            // Transition to ConfigExtNaclMode
                            context.current_mode = Mode::ConfigExtNaclMode(acl_name_or_number.clone());
                            context.prompt = format!("{}(config-ext-nacl)#", context.config.hostname);
                            println!("Extended ACL '{}' created. Enter ACL configuration mode.", acl_name_or_number);
                            Ok(())
                        }
                        _ => {
                            Err("Invalid syntax. Use 'ip access-list standard <acl_name>' or 'ip access-list extended <name_or_number>'.".into())
                        }
                    }
                } else {
                    Err("Invalid syntax. Use 'ip access-list standard <acl_name>' or 'ip access-list extended <name_or_number>'.".into())
                }
            } else {
                Err("The 'ip access-list' command is only available in global configuration mode.".into())
            }
        },
    });
    
    commands.insert("show access-lists", Command {
        name: "show access-lists",
        description: "Display all configured access lists",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                let acl_store = ACL_STORE.lock().unwrap();
                if acl_store.is_empty() {
                    println!("No access lists configured.");
                    return Ok(());
                }
    
                for (name, acl) in acl_store.iter() {
                    println!("\nAccess list: {}", acl.number_or_name);
                    for entry in &acl.entries {
                        let protocol = entry.protocol.clone().unwrap_or("ip".to_string());
                        let source_op = entry.source_operator.clone().unwrap_or_default();
                        let source_port = entry.source_port.clone().unwrap_or_default();
                        let destination_op = entry.destination_operator.clone().unwrap_or_default();
                        let destination_port = entry.destination_port.clone().unwrap_or_default();
                        let matches = entry.matches.map_or(String::new(), |m| format!("({} matches)", m));
    
                        println!(
                            "  {} {} {} {} {} {} {} {} {}",
                            entry.action,
                            protocol,
                            entry.source,
                            source_op,
                            source_port,
                            entry.destination,
                            destination_op,
                            destination_port,
                            matches
                        );
                    }
                }
    
                Ok(())
            } else {
                Err("The 'show access-lists' command is only available in privileged EXEC mode.".into())
            }
        },
    });
    

    commands.insert("deny", Command {
        name: "deny",
        description: "Add a deny entry to the ACL (standard or extended)",
        suggestions: None,
        execute: |args, context, _| {
            match &context.current_mode {
                // Standard ACL Mode
                Mode::ConfigStdNaclMode(acl_name) => {
                    if args.len() >= 1 {
                        let ip = Ipv4Addr::from_str(&args[0]).expect("Invalid IP address format").to_string();
                        let wildcard_mask = if args.len() > 1 {
                            Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format").to_string()
                        } else {
                            "0.0.0.0".to_string() // Default mask
                        };

                        // Create the ACL entry
                        let entry = AclEntry {
                            action: "deny".to_string(),
                            source: ip,
                            destination: wildcard_mask,
                            protocol: None,
                            source_operator: None,
                            source_port: None,
                            destination_operator: None,
                            destination_port: None,
                            matches: None,
                        };

                        // Add the entry to the ACL store
                        let mut acl_store = ACL_STORE.lock().unwrap();
                        if let Some(acl) = acl_store.get_mut(acl_name) {
                            acl.entries.push(entry);
                            println!("Deny entry added to standard ACL '{}'.", acl_name);
                            Ok(())
                        } else {
                            Err(format!("ACL '{}' not found.", acl_name).into())
                        }
                    } else {
                        Err("Invalid syntax. Use 'deny <ip> <wildcard mask>'.".into())
                    }
                }
                // Extended ACL Mode
                Mode::ConfigExtNaclMode(acl_name) => {
                    if args.len() >= 3 {
                        let protocol = Some(args[0].to_lowercase()); // "tcp", "udp", "icmp", etc.
                        let source = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format").to_string();
                        let destination = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format").to_string();

                        let mut source_operator = None;
                        let mut source_port = None;
                        let mut destination_operator = None;
                        let mut destination_port = None;

                        if args.len() > 4 {
                            source_operator = Some(args[3].to_lowercase()); // e.g., "eq", "gt", "lt"
                            source_port = args.get(4).map(|p| p.to_string()); 
                            destination_operator = args.get(5).map(|o| o.to_lowercase()); // e.g., "eq", "gt", "lt"
                            destination_port = args.get(6).map(|p| p.to_string()); 
                        }

                        let entry = AclEntry {
                            action: "deny".to_string(),
                            protocol,
                            source,
                            source_operator,
                            source_port,
                            destination,
                            destination_operator,
                            destination_port,
                            matches: None,
                        };

                        let mut acl_store = ACL_STORE.lock().unwrap();
                        if let Some(acl) = acl_store.get_mut(acl_name) {
                            acl.entries.push(entry);
                            println!("Deny entry added to extended ACL '{}'.", acl_name);
                            Ok(())
                        } else {
                            Err(format!("ACL '{}' not found.", acl_name).into())
                        }
                    } else {
                        Err("Invalid syntax. Use 'deny <protocol> <src_ip> <dest_ip>' or 'deny <protocol> <src_ip> <eq|gt|lt> <src_port> <dest_ip> <eq|gt|lt> <dest_port>'.".into())
                    }
                }
                // Invalid Mode
                _ => Err("This command is only available in ACL configuration mode.".into()),
            }
        },
    });

   
    commands.insert("permit", Command {
        name: "permit",
        description: "Add a permit entry to the ACL (standard or extended)",
        suggestions: None,
        execute: |args, context, _| {
            match &context.current_mode {
                // Standard ACL Mode
                Mode::ConfigStdNaclMode(acl_name) => {
                    if args.len() >= 1 {
                        let ip = Ipv4Addr::from_str(&args[0]).expect("Invalid IP address format").to_string();
                        let wildcard_mask = if args.len() > 1 {
                            Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format").to_string()
                        } else {
                            "0.0.0.0".to_string() // Default mask
                        };

                        // Create the ACL entry
                        let entry = AclEntry {
                            action: "permit".to_string(),
                            source: ip,
                            destination: wildcard_mask,
                            protocol: None,
                            source_operator: None,
                            source_port: None,
                            destination_operator: None,
                            destination_port: None,
                            matches: None,
                        };

                        // Add the entry to the ACL store
                        let mut acl_store = ACL_STORE.lock().unwrap();
                        if let Some(acl) = acl_store.get_mut(acl_name) {
                            acl.entries.push(entry);
                            println!("Permit entry added to standard ACL '{}'.", acl_name);
                            Ok(())
                        } else {
                            Err(format!("ACL '{}' not found.", acl_name).into())
                        }
                    } else {
                        Err("Invalid syntax. Use 'permit <ip> <wildcard mask>'.".into())
                    }
                }
                // Extended ACL Mode
                Mode::ConfigExtNaclMode(acl_name) => {
                    if args.len() >= 3 {
                        let protocol = Some(args[0].to_lowercase()); // "tcp", "udp", "icmp", etc.
                        let source = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format").to_string();
                        let destination = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format").to_string();

                        let mut source_operator = None;
                        let mut source_port = None;
                        let mut destination_operator = None;
                        let mut destination_port = None;

                        if args.len() > 4 {
                            source_operator = Some(args[3].to_lowercase()); // e.g., "eq", "gt", "lt"
                            source_port = args.get(4).map(|p| p.to_string()); 
                            destination_operator = args.get(5).map(|o| o.to_lowercase()); // e.g., "eq", "gt", "lt"
                            destination_port = args.get(6).map(|p| p.to_string()); 
                        }

                        let entry = AclEntry {
                            action: "permit".to_string(),
                            protocol,
                            source,
                            source_operator,
                            source_port,
                            destination,
                            destination_operator,
                            destination_port,
                            matches: None,
                        };

                        let mut acl_store = ACL_STORE.lock().unwrap();
                        if let Some(acl) = acl_store.get_mut(acl_name) {
                            acl.entries.push(entry);
                            println!("Permit entry added to extended ACL '{}'.", acl_name);
                            Ok(())
                        } else {
                            Err(format!("ACL '{}' not found.", acl_name).into())
                        }
                    } else {
                        Err("Invalid syntax. Use 'permit <protocol> <src_ip> <dest_ip>' or 'permit <protocol> <src_ip> <eq|gt|lt> <src_port> <dest_ip> <eq|gt|lt> <dest_port>'.".into())
                    }
                }
                
                _ => Err("This command is only available in ACL configuration mode.".into()),
            }
        },
    });

    commands.insert("crypto ipsec profile", Command {
        name: "crypto ipsec profile",
        description: "Defines the IPsec parameters for encryption between two IPsec routers",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if _args.len() == 1 {
                    let profile_name = &_args[0];
                    context.config.crypto_ipsec_profile = Some(profile_name.to_string());
                    println!("Crypto IPsec profile '{}' defined.", profile_name);
                    Ok(())
                } else {
                    Err("Invalid arguments. Use 'crypto ipsec profile <profile-name>'.".into())
                }
            } else {
                Err("The 'crypto ipsec profile' command is only available in Config mode.".into())
            }
        },
    });
    
    commands.insert("set transform-set", Command {
        name: "set transform-set",
        description: "Specifies which transform sets can be used with the crypto map entry.",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if _args.is_empty() {
                    Err("Transform set(s) are required.".into())
                } else {
                    context.config.transform_sets = Some(_args.iter().map(|s| s.to_string()).collect());
                    println!("Transform set(s) set to: {:?}", _args);
                    Ok(())
                }
            } else {
                Err("The 'set transform-set' command is only available in Config mode.".into())
            }
        },
    });
    

    commands.insert("tunnel", Command {
        name: "tunnel",
        description: "Configures the tunnel interface with multiple parameters (mode, source, destination, protection, virtual-template).",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if _args.is_empty() {
                    return Err("Invalid arguments. Please specify a subcommand like 'mode', 'source', 'destination', 'protection', or 'virtual-template'.".into());
                }
    
                match &_args[0] as &str {
                    "mode" => {
                        if _args.len() == 3 && _args[1] == "ipsec" && _args[2] == "ipv4" {
                            context.config.tunnel_mode = Some("ipsec ipv4".to_string());
                            println!("Tunnel mode set to IPsec IPv4.");
                            Ok(())
                        } else {
                            Err("Invalid arguments for 'mode'. Use 'mode ipsec ipv4'.".into())
                        }
                    }
                    "source" => {
                        if _args.len() == 2 {
                            let source_interface = &_args[1];
                            context.config.tunnel_source = Some(source_interface.to_string());
                            println!("Tunnel source interface set to '{}'.", source_interface);
                            Ok(())
                        } else {
                            Err("Invalid arguments for 'source'. Use 'source <interface>'.".into())
                        }
                    },
                    "destination" => {
                        if _args.len() == 2 {
                            let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&_args[1]).expect("Invalid IP address format");
                            context.config.tunnel_destination = Some(destination_ip.to_string());
                            println!("Tunnel destination IP address set to '{}'.", destination_ip);
                            Ok(())
                        } else {
                            Err("Invalid arguments for 'destination'. Use 'destination <ip-address>'.".into())
                        }
                    },
                    "protection" => {
                        if _args.len() == 4 && _args[1] == "ipsec" && _args[2] == "profile" {
                            let profile_name = &_args[3];
                            context.config.tunnel_protection_profile = Some(profile_name.to_string());
                            println!("Tunnel protection associated with IPsec profile '{}'.", profile_name);
                            Ok(())
                        } else {
                            Err("Invalid arguments for 'protection'. Use 'protection ipsec profile <profile-name>'.".into())
                        }
                    },
                    
                    _ => return Err("Invalid subcommand. Use 'mode', 'source', 'destination' or 'protection'.".into()),
                }
            } else {
                Err("The 'tunnel' command is only available in Config mode.".into())
            }
        },
    });

    commands.insert("virtual-template", Command {
        name: "virtual-template",
        description: "Enter interface configuration mode for a virtual-template interface",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if _args.len() == 1 {
                    let template_number = &_args[0];
                    if template_number.parse::<u32>().is_ok() {
                        context.config.virtual_template = Some(template_number.to_string());
                        println!(
                            "Entering interface configuration mode for virtual-template interface '{}'.",
                            template_number
                        );
                        Ok(())
                    } else {
                        Err("Invalid argument for 'virtual-template'. The template number must be a valid number.".into())
                    }
                } else {
                    Err("Invalid arguments for 'virtual-template'. Use 'virtual-template <number>'.".into())
                }
            } else {
                Err("The 'virtual-template' command is only available in Configuration mode.".into())
            }
        },
    });
    
    
    commands.insert("ntp server", Command {
        name: "ntp server",
        description: "Configure an NTP server",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 1 {
                    let ip_address = args[0].to_string();
                    if ip_address.parse::<Ipv4Addr>().is_ok() {
                        context.ntp_servers.insert(ip_address.clone());
                        // Assuming once the server is configured, we add it to NTP associations
                        let association = NtpAssociation {
                            address: ip_address.clone(),
                            ref_clock: ".INIT.".to_string(),
                            st: 16,
                            when: "-".to_string(),
                            poll: 64,
                            reach: 0,
                            delay: 0.0,
                            offset: 0.0,
                            disp: 0.01,
                        };
                        context.ntp_associations.push(association); // Adding the new server to the list
                        println!("NTP server {} configured.", ip_address);
                        Ok(())
                    } else {
                        Err("Invalid IP address format.".into())
                    }
                } else if args.len() == 2 && args[0] == "no" {
                    let ip_address = args[1].to_string();
                    if context.ntp_servers.remove(&ip_address) {
                        // Remove from the associations list as well
                        context.ntp_associations.retain(|assoc| assoc.address != ip_address);
                        println!("NTP server {} removed.", ip_address);
                        Ok(())
                    } else {
                        Err("NTP server not found.".into())
                    }
                } else {
                    Err("Invalid arguments. Usage: [no] ntp server {ip-address}".into())
                }
            } else {
                Err("The 'ntp server' command is only available in configuration mode.".into())
            }
        },
    });
    
    
    commands.insert("show ntp associations", Command {
        name: "show ntp associations",
        description: "Display NTP associations",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if context.ntp_associations.is_empty() {
                    println!("No NTP associations configured.");
                } else {
                    for assoc in &context.ntp_associations {
                        println!("address         ref clock       st   when     poll    reach  delay          offset            disp");
                        println!(" ~{}       {}          {}   {}        {}      {}      {:.2}           {:.2}              {:.2}",
                            assoc.address, assoc.ref_clock, assoc.st, assoc.when, assoc.poll,
                            assoc.reach, assoc.delay, assoc.offset, assoc.disp);
                        println!(" * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured");
                    }
                }
                Ok(())
            } else {
                Err("This command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    commands.insert("ntp master", Command {
        name: "ntp master",
        description: "Configure the device as an NTP master",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                context.ntp_master = true;
                println!("Device configured as NTP master.");
                Ok(())
            } else {
                Err("The 'ntp master' command is only available in configuration mode.".into())
            }
        },
    });
    
    commands.insert("ntp authenticate", Command {
        name: "ntp authenticate",
        description: "Enable or disable NTP authentication",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    context.ntp_authentication_enabled = !context.ntp_authentication_enabled;
                    let status = if context.ntp_authentication_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    };
                    println!("NTP authentication {}", status);
                    Ok(())
                } else {
                    Err("The 'ntp authenticate' command does not accept arguments.".into())
                }
            } else {
                Err("The 'ntp authenticate' command is only available in configuration mode.".into())
            }
        },
    });
    
    commands.insert("ntp authentication-key", Command {
        name: "ntp authentication-key",
        description: "Define an NTP authentication key",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 3 && args[1] == "md5" {
                    if let Ok(key_number) = args[0].parse::<u32>() {
                        let md5_key = args[2].to_string();
                        context.ntp_authentication_keys.insert(key_number, md5_key.clone());
                        println!("NTP authentication key {} configured with MD5 key: {}", key_number, md5_key);
                        Ok(())
                    } else {
                        Err("Invalid key number.".into())
                    }
                } else {
                    Err("Usage: ntp authentication-key <number> md5 <key-string>".into())
                }
            } else {
                Err("The 'ntp authentication-key' command is only available in configuration mode.".into())
            }
        },
    });
    
    commands.insert("ntp trusted-key", Command {
        name: "ntp trusted-key",
        description: "Specify a trusted NTP authentication key",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 1 {
                    if let Ok(key_number) = args[0].parse::<u32>() {
                        context.ntp_trusted_keys.insert(key_number);
                        println!("NTP trusted key {} configured.", key_number);
                        Ok(())
                    } else {
                        Err("Invalid key number.".into())
                    }
                } else {
                    Err("Usage: ntp trusted-key <number>".into())
                }
            } else {
                Err("The 'ntp trusted-key' command is only available in configuration mode.".into())
            }
        },
    });
    
    
    commands.insert("show ntp", Command {
        name: "show ntp",
        description: "Display NTP status and configurations",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                println!("NTP Master: {}", if context.ntp_master { "Enabled" } else { "Disabled" });
                println!("NTP Authentication: {}", if context.ntp_authentication_enabled { "Enabled" } else { "Disabled" });
                
                if !context.ntp_authentication_keys.is_empty() {
                    println!("NTP Authentication Keys:");
                    for (key_number, key) in &context.ntp_authentication_keys {
                        println!("Key {}: {}", key_number, key);
                    }
                }
                
                if !context.ntp_trusted_keys.is_empty() {
                    println!("NTP Trusted Keys:");
                    for key_number in &context.ntp_trusted_keys {
                        println!("Trusted Key {}", key_number);
                    }
                }
    
                Ok(())
            } else {
                Err("This command is only available in Privileged EXEC mode.".into())
            }
        },
    });
    
    commands.insert("service password-encryption", Command {
        name: "service password-encryption",
        description: "Enable password encryption",
        suggestions: None,
        execute: |_args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                
                let storage = PASSWORD_STORAGE.lock().unwrap();
                
                let stored_password = storage.enable_password.clone();
                let stored_secret = storage.enable_secret.clone();
                drop(storage);
                
                if let Some(password) = stored_password {
                    let encrypted_password = encrypt_password(&password);
                    context.config.encrypted_password = Some(encrypted_password);
                }
                
                if let Some(secret) = stored_secret {
                    let encrypted_secret = encrypt_password(&secret);
                    context.config.encrypted_secret = Some(encrypted_secret);  // Update encrypted secret
                }
    
                context.config.password_encryption = true;
                println!("Password encryption enabled.");
                Ok(())
            } else {
                Err("The 'service password-encryption' command is only available in Privileged EXEC mode.".into())
            }
        },
    });
    
    commands.insert("enable secret", Command {
        name: "enable secret",
        description: "Set the enable secret password",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() != 1 {
                    Err("You must provide the enable secret password.".into())
                } else {
                    let secret = &args[0];
                    set_enable_secret(secret);
                    context.config.enable_secret = Some(secret.to_string());
                    println!("Enable secret password set.");
                    Ok(())
                }
            } else {
                Err("The 'enable secret' command is only available in Config mode.".into())
            }
        },
    });
    
    commands.insert("enable password", Command {
        name: "enable password",
        description: "Set the enable password for accessing privileged mode",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() != 1 {
                    Err("You must provide the enable password.".into())
                } else {
                    let password = &args[0];
                    set_enable_password(password);
                    context.config.enable_password = Some(password.to_string());
                    println!("Enable password set.");
                    Ok(())
                }
            } else {
                Err("The 'enable password' command is only available in Config mode.".into())
            }
        },
    });

    commands.insert("ip domain-name", Command {
        name: "ip domain-name",
        description: "Set the IP domain name",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.is_empty() {
                    Err("Domain name must be provided.".into())
                } else {
                    let domain_name = args[0].to_string();
                    context.config.domain_name = Some(domain_name.clone());
                    println!("Domain name set to: {}", domain_name);
                    Ok(())
                }
            } else {
                Err("The 'ip domain-name' command is only available in Config mode.".into())
            }
        },
    });

    commands.insert("crypto key", Command {
        name: "crypto key",
        description: "Crypto key management commands",
        suggestions: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                // Check for subcommands (e.g., 'generate rsa', 'delete')
                if args.is_empty() {
                    Err("Subcommand required. Use 'generate rsa' to create RSA keys, or 'delete' to delete keys.".into())
                } else if args[0] == "generate" && args.len() > 1 && args[1] == "rsa" {
                    // RSA key generation logic
                    println!("Enter key modulus size (default is 512 bits):");
                    let modulus_size = 512;  
                    let domain_name = context.config.domain_name.clone();
    
                    let key_name = format!("{}.{}", context.config.hostname, domain_name.unwrap_or("default_domain".to_string()));
                    println!("The name for the keys will be: {}", key_name);
    
                    println!("Generating {}-bit RSA keys, keys will be non-exportable...", modulus_size);
                    // Add logic here to generate the RSA keys.
                    println!("[OK] RSA keys generated successfully.");
    
                    Ok(())
                } else if args[0] == "zeroizee" && args.len() > 1 && args[1] == "rsa"{
                    let key_name = args[1].to_string(); 
                    println!("Deleting keys with the name: {}", key_name);
                    println!("[OK] Keys deleted successfully.");
    
                    Ok(())
                } else {
                    Err("Invalid subcommand. Available subcommands: 'generate rsa', 'delete <key_name>'.".into())
                }
            } else {
                Err("The 'crypto key' command is only available in Config mode.".into())
            }
        },
    });
    
    


    commands
}