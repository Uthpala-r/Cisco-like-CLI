/// External crates for the CLI application
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::{File};
use std::io::Write;
use std::io;
use std::str::FromStr;
use rpassword::read_password;
use std::process::Command as ProcessCommand;

use crate::run_config::{get_running_config, default_startup_config};
//use crate::run_config::load_config;
use crate::execute::Command;
use crate::execute::Mode;
use crate::clock_settings::{handle_clock_set, parse_clock_set_input, handle_show_clock, handle_show_uptime};
use crate::network_config::{calculate_broadcast, STATUS_MAP, IFCONFIG_STATE, IP_ADDRESS_STATE, ROUTE_TABLE, OSPF_CONFIG, ACL_STORE, encrypt_password, PASSWORD_STORAGE, set_enable_password, set_enable_secret};
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
///     - `enable secret`: Sets a secret password for privileged EXEC mode access, using a stronger hash for security than the `enable password` command.
///     - `enable password`: Configures a password for privileged EXEC mode access. This password is weaker than the `enable secret` and should be avoided when possible.
/// - `configure terminal`: Enters Global Configuration mode.
/// - `interface`: Enters Interface Configuration mode for a specified interface. Should enter the interface name as an input
///     - `interface range`: Enters the Interface Configuration mode but for the entire range.
/// - `hostname`: Changes the hostname of the device.
/// - `ifconfig`: Displays or configures network details of the router.
/// - `exit`: This command navigates through the modes in reverse order (eg: ConfigMode --> UserMode)
/// - `show`: Displays all the show commands when specific command is passed
///     - `show running-config`: Displays the current running configuration from a JSON file.
///     - `show startup-config`: Displays the initial configuration settings stored in the NVRAM of a router, which are loaded upon booting the device.
///     - `show version`: Displays the software version information.
///     - `show clock`: Displays the current clock date and time.
///     - `show interfaces`: Displays statistics for all interfaces, including a brief overview or detailed information.
///     - `show ip interfaces brief`: Displays a summary of the router interfaces
///     - `show ip route`: Displays the ip routes defined
///     - `show vlan`: Displays information and status of VLANs.
///     - `show ip ospf neighbor`: Displays information about OSPF neighbors, including their state, router ID, and the interface used for adjacency.
///     - `show access-lists`: Displays the current configuration of all ACLs on the device, showing the list of ACL entries and their statistics (matches, actions, etc.).
///     - `show ntp associations`: Displays the status of NTP associations with servers or clients, showing the synchronization status and other details.
///     - `show ntp`: Displays information about the current NTP configuration, associations, and synchronization status.
///     - `show processes`: Shows the system processes and memories
///     - `show uptime`: Shows the time from the last reboot
///     - `show login`: Shows the details about login delay
/// - `reload`: Reloads the system
/// - `debug all`: Debug all the processors
/// - `undebug all`: Undebug all the processors
/// - `write memory`: Saves the running configuration to the startup configuration.
/// - `copy running-config`: Copies the running configuration to the startup configuration or to a new file if mentioned.
/// - `help`: Displays a list of available commands.
/// - `clock set`: Changes the device's clock date and time.
/// - `ip`: Define all the ip commands
///     - `ip address`: Assigns an IP address and netmask to the selected interface.
///     - `ip route`: Define the static ip routes
///     - `ip ospf`: Assigns OSPF-specific parameters to an interface, such as the OSPF cost or authentication settings.
///     - `ip access-list`: Used to create or modify an IP access list, specifying the version (standard or extended) and the list of rules to filter IP packets based on source/destination addresses, protocols, and ports.
///     - `ip domain-name`: Sets the domain name for the device, which is used in various operations such as DNS resolution.
/// - `shutdown`: Disable a router's interface
/// - `no`: Execute the opposite of the commands
///     - `no shutdown`: Enable a router's interface 
///     - `no ntp server`: Disable NTP
/// - `vlan`: Define vlans. This will enter the Vlan Mode
/// - `name`: Define the name of the vlan
/// - `state: Define the state of the valn
/// - `switchport`: Defines the switchports
/// - `router ospf`: Configures and enables an OSPF routing process on the router. Specify the process ID to distinguish between multiple OSPF instances. This will enter the RouterConfig Mode
/// - `network`: Associates a network or subnet with a specific OSPF area.
/// - `neighbor`: Manually specifies a neighboring router for OSPF adjacency, usually in cases of non-broadcast networks.
/// - `area`: Defines OSPF area-specific configurations, such as authentication, stub area settings, or default-cost for stub areas.
/// - `passive-interface`: Prevents OSPF from sending hello packets on the specified interface while still advertising the interface's network in OSPF.
/// - `distance`: Configures the administrative distance for OSPF routes, which influences route preference when multiple protocols advertise the same destination.
/// - `default-information`: Configures OSPF to advertise a default route (0.0.0.0/0) to other routers in the network.
/// - `router-id`: Manually sets a unique identifier for the OSPF process, typically an IPv4 address, to distinguish the router in the OSPF domain.
/// - `clear ip ospf process`: Restarts the OSPF process, clearing the OSPF routing table and adjacencies.
/// - `access-list`: Defines an ACL by creating or modifying an access control list with a specified number or name. This command is used to specify a set of rules for filtering network traffic.
/// - `permit`: An ACL action that allows network traffic that matches the rule's conditions (e.g., specific IP address or protocol) to pass through.
/// - `deny`: An ACL action that blocks network traffic matching the rule's conditions, preventing it from passing through the network.
/// - `crypto`: Defined all thr crypto commands   
///     - `crypto ipsec profile`: Configures and manages IPSec VPN profiles, including settings for security associations and tunnel configurations.
///     - `crypto key`: Generates or manages cryptographic keys used in various security protocols, including VPNs and encryption.
/// - `set tranform-set`: Specifies the transform set used in an IPSec VPN to define the cryptographic algorithms for encryption and integrity.
/// - `tunnel`: Defines and manages the settings for an IPsec tunnel, including the associated transport and security protocols.
/// - `virtual-template`: Creates a virtual template interface that can be used as a blueprint for creating virtual access interfaces, often used in VPN configurations.
/// - `ntp`: Defines all the ntp commands
///     - `ntp server`: Configures the NTP server for synchronizing time on the device, ensuring that the device’s clock is accurate.
///     - `ntp master`: Configures the device as an NTP master, meaning it will serve time to other devices in the network.
///     - `ntp authenticate`: Enables NTP authentication, which allows the NTP client to authenticate time synchronization requests from servers.
///     - `ntp authentication-key`: Defines the key used for authenticating NTP messages, providing security to NTP transactions.
///     - `ntp trusted-key`: Specifies which authentication key(s) are trusted to authenticate NTP messages
/// - `service password-encryption`: Enables password encryption for storing sensitive passwords in the device’s configuration, ensuring they are not stored in plain text.
/// - `ping`: Confirms the connection between ip addresses
/// 
/// # Returns
/// A `HashMap` where the keys are command names (as `&'static str`) and the values are the corresponding `Command` structs.
/// Each `Command` struct contains the `name`, `description`, `suggestions`, and an `execute` function.
pub fn build_command_registry() -> HashMap<&'static str, Command> {
    let mut commands = HashMap::new();

    commands.insert("enable", Command {
        name: "enable",
        description: "Enter privileged EXEC mode",
        suggestions: Some(vec!["password", "secret"]),
        suggestions1: None,
        options: None,
        execute: |args, context, _| {
            if args.is_empty(){
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

                    if stored_password.is_none() {
                        println!("Enter secret:");
                        let input_secret= read_password().unwrap_or_else(|_| "".to_string());
            
                        if let Some(ref stored_secret) = stored_secret {
                            if input_secret == *stored_secret {
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
            } else {
                match &args[0][..]{
                    "password" => {
                        if matches!(context.current_mode, Mode::ConfigMode) {
                            if args.len() != 2 {
                                Err("You must provide the enable password.".into())
                            } else {
                                let password = &args[1];
                                set_enable_password(password);
                                context.config.enable_password = Some(password.to_string());
                                println!("Enable password set.");
                                Ok(())
                            }
                        } else {
                            Err("The 'enable password' command is only available in Config mode.".into())
                        }
                    },
                    "secret" => {
                        if matches!(context.current_mode, Mode::ConfigMode) {
                            if args.len() != 2 {
                                Err("You must provide the enable secret password.".into())
                            } else {
                                let secret = &args[1];
                                set_enable_secret(secret);
                                context.config.enable_secret = Some(secret.to_string());
                                println!("Enable secret password set.");
                                Ok(())
                            }
                        } else {
                            Err("The 'enable secret' command is only available in Config mode.".into())
                        }
                    },
                    _=> Err(format!("Unknown enable subcommand: {}", args[0]).into())
                }
            }
        },
    });

    commands.insert("configure", Command {
        name: "configure terminal",
        description: "Enter global configuration mode",
        suggestions: Some(vec!["terminal"]),
        suggestions1: Some(vec!["terminal"]),
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "terminal" {
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
        suggestions: Some(vec!["range"]),
        suggestions1: None,
        options: Some(vec!["range", 
            "<interface-name>    - Specify a valid interface name"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode | Mode::InterfaceMode) {
                if args.is_empty() {
                    return Err("Please specify an interface or range, e.g., 'interface g0/0' or 'interface range f0/0 - 24'.".into());
                }
    
                let input = args.join(" ");
                if input.starts_with("r") {
                    // Handle interface range
    
                    let after_range = match input.find(' ') {
                        Some(pos) => input[pos..].trim(),
                        None => return Err("Invalid range format. Use 'interface range f0/0 - 24'.".into())
                    };
    
                    let range_parts: Vec<&str> = after_range.split('-').map(|s| s.trim()).collect();

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
        suggestions1: None,
        options: None,
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
    
    commands.insert("reload", Command {
        name: "reload",
        description: "Reload the system",
        suggestions: None,
        suggestions1: None,
        options: None,
        execute: |_, context, _| {
            
            println!("System configuration has been modified. Save? [yes/no]:");
    
            let mut save_input = String::new();
            std::io::stdin().read_line(&mut save_input).expect("Failed to read input");
            let save_input = save_input.trim();
    
            if save_input.eq_ignore_ascii_case("yes") {
                println!("Building configuration...");
                println!("[OK]");
            } else if save_input.eq_ignore_ascii_case("no") {
                println!("Configuration not saved.");
            } else {
                return Err("Invalid input. Please enter 'yes' or 'no'.".into());
            }
    
            println!("Proceed with reload? [confirm]:");
            let mut reload_confirm = String::new();
            std::io::stdin().read_line(&mut reload_confirm).expect("Failed to read input");
            let reload_confirm = reload_confirm.trim();
    
            if reload_confirm.eq_ignore_ascii_case("yes") || reload_confirm.eq_ignore_ascii_case("y") {
                println!("System Bootstrap, Version 15.1(4)M4, RELEASE SOFTWARE (fc1)");
                println!("Technical Support: http://www.cisco.com/techsupport");
                println!("Copyright (c) 2010 by cisco Systems, Inc.");
                println!("Total memory size = 512 MB - On-board = 512 MB, DIMM0 = 0 MB");
    
                // Simulate reload process
                context.current_mode = Mode::UserMode;
                context.prompt = format!("{}>", context.config.hostname);
    
                println!("\nPress RETURN to get started!");
                Ok(())
            } else if reload_confirm.eq_ignore_ascii_case("no") {
                println!("Reload aborted.");
                Ok(())
            } else {
                Err("Invalid input. Please enter 'yes', 'y', or 'no'.".into())
            }
        },
    });
    
    commands.insert("debug", Command {
        name: "debug all",
        description: "To turn on all the possible debug levels",
        suggestions: Some(vec!["all"]),
        suggestions1: Some(vec!["all"]),
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "all" {
                    println!("This may severely impact network performance. Continue? (yes/[no]):");
    
                    let mut save_input = String::new();
                    std::io::stdin().read_line(&mut save_input).expect("Failed to read input");
                    let save_input = save_input.trim();
            
                    if save_input.eq_ignore_ascii_case("yes") {
                        println!("All possible debugging has been turned on");
                        Ok(())
                    } else {
                        return Err("Invalid input. Please enter 'yes' or 'no'.".into());
                    }
                } else {
                    Err("Invalid arguments provided to 'debug all'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'debug all' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    commands.insert("undebug", Command {
        name: "undebug all",
        description: "Turning off all possible debugging processes",
        suggestions: Some(vec!["all"]),
        suggestions1: Some(vec!["all"]),
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 1 && args[0] == "all" {
                    println!("All possible debugging has been turned off");
                    Ok(())
                } else {
                    Err("Invalid arguments provided to 'undebug all'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'undebug all' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    commands.insert("hostname", Command {
        name: "hostname",
        description: "Set the device hostname",
        suggestions: None,
        suggestions1: None,
        options: Some(vec!["<new-hostname>    - Enter a new hostname"]),
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
            suggestions1: None,
            options: Some(vec!["<interface      - Enter the interface you need to change the ip-address of or need to add", 
                "<ip-address>      - Enter the new ip-address"]),
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
                    println!("Invalid arguments provided to 'ifconfig'. To create an entry 'ifconfig <interface> <ip-address> up");
                }
    
                Ok(())
            },
        },
    );

    commands.insert(
        "show",
        Command {
            name: "show",
            description: "Display all the show commands when specific command is passed",
            suggestions: Some(vec![
                "running-config",
                "startup-config",
                "access-lists",
                "ip",
                "version",
                "ntp",
                "processes",
                "clock",
                "vlan",
                "interfaces",
                "uptime",
                "login"
            ]),
            suggestions1: Some(vec![
                "running-config",
                "startup-config",
                "access-lists",
                "ip",
                "version",
                "ntp",
                "processes",
                "clock",
                "vlan",
                "interfaces",
                "uptime",
                "login"
            ]),
            options: None,
            execute: |args, context, clock| {
                if matches!(context.current_mode, Mode::UserMode | Mode ::PrivilegedMode){
                    match args.get(0) {
                        Some(&"clock") => {
                            if let Some(clock) = clock {
                                handle_show_clock(clock);
                                Ok(())
                            } else {
                                Err("Clock functionality is unavailable.".to_string())
                            }
                        },
                        Some(&"uptime") => {
                            if let Some(clock) = clock {
                                handle_show_uptime(clock);
                                Ok(())
                            } else {
                                Err("Clock functionality is unavailable.".to_string())
                            }
                        },
                        Some(&"version") => {
                            println!("Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc2)");
                            println!("Compiled Thurs 5-Jan-12 15:41 by pt_team");
                            println!(" ");
                            println!("ROM: System Bootstrap, Version 15.1(4)M4, RELEASE SOFTWARE (fc1)");
                            if let Some(clock) = clock {
                                handle_show_uptime(clock);
                            } else {
                                return Err("Clock functionality is unavailable.".to_string());
                            }
                            println!(" ");
                            println!("Device Details... ");
                            println!("PNF Router");
                            Ok(())
                        },
                        Some(&"interfaces") => {
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
                        },
                        Some(&"ip") => {
                            match args.get(1) {
                                Some(&"ospf") => {
                                    match args.get(2) {
                                        Some(&"neighbor") => {
                                            let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                                            println!("Current OSPF Configuration:");
                                            println!("Router ID: {:?}", ospf_config.router_id.clone().unwrap_or("Not set".to_string()));
                                            println!("Administrative Distance: {:?}", ospf_config.distance.unwrap_or(110));
                                            println!("Default Information Originate: {}", ospf_config.default_information_originate);
                                            println!("Passive Interfaces: {:?}", ospf_config.passive_interfaces);
                                            Ok(())
                                        },
                                        _ => Err("Invalid OSPF subcommand. Use 'neighbor'".into())
                                    }
                                },
                                Some(&"route") => {
                                    let route_table = ROUTE_TABLE.lock().unwrap();
            
                                    if args.len() == 2 {
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
                                    } else if args.len() == 3 {
                                        let destination_ip = args[2];
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
                                },
                                Some(&"interface") => {
                                    match args.get(2) {
                                        Some(&"brief") => {
                                            let ip_address_state = IP_ADDRESS_STATE.lock().unwrap();
                                            let status_map = STATUS_MAP.lock().unwrap();
                                
                                            println!(
                                                "{:<22} {:<15} {:<8} {:<20} {:<20} {:<10}",
                                                "Interface", "IP-Address", "OK?", "Method", "Status", "Protocol"
                                            );
                                
                                            for (interface_name, (ip_address, _)) in ip_address_state.iter() {
                                                let is_up = status_map.get(interface_name).copied().unwrap_or(false);
                                                let status = if is_up {
                                                    "up"
                                                } else {
                                                    "administratively down"
                                                };
                                                let protocol = if is_up {
                                                    "up"
                                                } else {
                                                    "down"
                                                };
                                
                                                println!(
                                                    "{:<22} {:<15} YES     unset/manual        {}         {}",
                                                    interface_name, ip_address, status, protocol
                                                );
                                            }
                                            Ok(())
                                        },
                                        _ => Err("Invalid interface subcommand. Use 'brief'".into())
                                    }
                                },
                                _ => Err("Invalid IP subcommand. Use 'ospf neighbor', 'route', or 'interface brief'".into())
                            }
                        },
                        Some(&"vlan") => {
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
                        },
                        _ => Ok(()),
                    };
                    //.map_err(|e| println!("Error: {}", e))?;
                }
                
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                        
                    match args.get(0) {
                        Some(&"running-config") => {
                            println!("Building configuration...\n");
                            println!("Current configuration : 0 bytes\n");
                            let running_config = get_running_config(&context);
                            println!("{}", running_config);
                            Ok(())
                        },
                        Some(&"startup-config") => {
                            println!("Building configuration...\n");
                            if let Some(last_written) = &context.config.last_written {
                                println!("Startup configuration (last saved: {}):\n", last_written);
                                let startup_config = get_running_config(&context);
                                println!("{}", startup_config);
                            } else {
                                println!("Startup configuration (default):\n");
                                println!("{}", default_startup_config(context));
                            }
                            Ok(())
                        },
                        Some(&"login") => {
                            println!("A default login delay of 1 seconds is applied.");
                            println!("No Quiet-Mode access list has been configured.");
                            println!(" ");
                            println!("Router NOT enabled to watch for login Attacks");
                            Ok(())
                        },
                        
                        Some(&"ntp") => {
                            match args.get(1) {
                                Some(&"associations") => {
                                    if context.ntp_associations.is_empty() {
                                        println!("No NTP associations configured.");
                                    } else {
                                        println!("address         ref clock       st   when     poll    reach  delay          offset            disp");
                                        for assoc in &context.ntp_associations {
                                            println!(" ~{}       {}          {}   {}        {}      {}      {:.2}           {:.2}              {:.2}",
                                                assoc.address, assoc.ref_clock, assoc.st, assoc.when, assoc.poll,
                                                assoc.reach, assoc.delay, assoc.offset, assoc.disp);
                                        }
                                        println!(" * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured");
                                    }
                                    Ok(())
                                },
                                None => {
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
                                },
                                _ => Err("Invalid NTP subcommand. Use 'associations' or no subcommand".into())
                            }
                        },
                        
                        Some(&"access-lists") => {
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
                        },
                        Some(&"processes") => {
                            if args.len() == 1 {
                                
                                println!("CPU utilization for five seconds: 0%/0%; one minute: 0%; five minutes: 0%");
                                println!(
                                    " PID Q  Ty       PC  Runtime(uS)    Invoked   uSecs    Stacks TTY Process\n\
                                    1 C  sp 602F3AF0            0       1627       0 2600/3000   0 Load Meter\n\
                                    2 L  we 60C5BE00            4        136      29 5572/6000   0 CEF Scanner\n\
                                    3 L  st 602D90F8         1676        837    2002 5740/6000   0 Check heaps\n\
                                    4 C  we 602D08F8            0          1       0 5568/6000   0 Chunk Manager\n\
                                    5 C  we 602DF0E8            0          1       0 5592/6000   0 Pool Manager"
                                ); 
                                Ok(())     
                            }
        
                            else if args.len() == 2 && args[1] == "cpu"{
                                    
                                println!("CPU utilization for five seconds: 8%/4%; one minute: 6%; five minutes: 5%");
                                println!(
                                    " PID Runtime(uS)   Invoked  uSecs    5Sec   1Min   5Min TTY Process\n\
                                    1         384     32789     11   0.00%  0.00%  0.00%   0 Load Meter\n\
                                    2        2752      1179   2334   0.73%  1.06%  0.29%   0 Exec\n\
                                    3      318592      5273  60419   0.00%  0.15%  0.17%   0 Check heaps\n\
                                    4           4         1   4000   0.00%  0.00%  0.00%   0 Pool Manager\n\
                                    5        6472      6568    985   0.00%  0.00%  0.00%   0 ARP Input"
                                );
                                Ok(())
                            }
                                    
                            else if args.len() == 3 && args[1] == "cpu" && args[2] == "history"{
                                println!(
                                    "CPU% per minute (last 60 minutes)\n\
                                    100\n 90\n 80         *  *                     * *     *  * *  *\n\
                                    70  * * ***** *  ** ***** ***  **** ******  *  *******     * *\n\
                                    60  #***##*##*#***#####*#*###*****#*###*#*#*##*#*##*#*##*****#\n\
                                    50  ##########################################################\n\
                                    40  ##########################################################\n\
                                    30  ##########################################################\n\
                                    20  ##########################################################\n\
                                    10  ##########################################################\n\
                                        0....5....1....1....2....2....3....3....4....4....5....5....\n\
                                                0    5    0    5    0    5    0    5    0    5"
                                );
                                Ok(())
                            }

                            else if args.len() == 2 && args[1] == "memory"{
                                println!(
                                    "Total: 106206400, Used: 7479116, Free: 98727284\n\
                                    PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process\n\
                                    0   0      81648       1808    6577644          0          0 *Init*\n\
                                    0   0        572     123196        572          0          0 *Sched*\n\
                                    0   0   10750692    3442000       5812    2813524          0 *Dead*\n\
                                    1   0        276        276       3804          0          0 Load Meter"
                                );
                                Ok(())
                            }
                            else{
                                Err("Invalid subcommand for 'show processes'. Valid subcommands are 'cpu', 'cpu history', and 'memory'.".into())
                            }
                            
                        },
                        
                        _ => Ok(()),
                    }
                    //.map_err(|e| println!("Error: {}", e))?;
                }
                else {
                    return Err("Show commands are only available in User EXEC mode and Privileged EXEC mode.".into());
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
            suggestions1: Some(vec!["memory"]),
            options: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode | Mode::ConfigMode | Mode::InterfaceMode) {
                    if args.len() == 1 && args[0] == "memory" {
                        // Save the running configuration to the startup configuration
                        let running_config = get_running_config(context);
                        context.config.startup_config = Some(running_config.clone());
        
                        // Update the last written timestamp
                        context.config.last_written = Some(chrono::Local::now().to_string());
        
                        println!("Configuration saved successfully.");
                        Ok(())
                    } else {
                        Err("Invalid arguments provided to 'write memory'. This command does not accept additional arguments.".into())
                    }
                } else {
                    Err("The 'write memory' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );
    

    commands.insert(
        "copy",
        Command {
            name: "copy",
            description: "Copy running configuration",
            suggestions: Some(vec!["running-config"]),
            suggestions1: Some(vec!["running-config"]),
            options: Some(vec!["startup-config"]),
            execute: |args, context, _| {
                if !matches!(context.current_mode, Mode::PrivilegedMode | Mode::ConfigMode | Mode::InterfaceMode) {
                    return Err("The 'copy' command is only available in Privileged EXEC mode, Config mode and interface mode".into());
                }

                // Handle both full and abbreviated versions of 'running-config'
                let source = args[0];
                if !source.starts_with("run") {
                    return Err("Invalid source. Use 'running-config'".into());
                }

                else if args[1] == "startup-config"{
                    
                    // Save the running configuration to the startup configuration
                    let running_config = get_running_config(context);
                    context.config.startup_config = Some(running_config.clone());
        
                    // Update the last written timestamp
                    context.config.last_written = Some(chrono::Local::now().to_string());
        
                    println!("Configuration saved successfully.");
                    Ok(())
                    
                }

                else {
                    let file_name = args[1];
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
                }
            },
        },
    );

    commands.insert(
        "help",
        Command {
            name: "help",
            description: "Display available commands for current mode",
            suggestions: None,
            suggestions1: None,
            options: None,
            execute: |args, context, _| {
                println!("\n ");
                println!(r#"Help may be requested at any point in a command by entering
a question mark '?'. If nothing matches, the help list will
be empty and you must backup until entering a '?' shows the
available options.
Two styles of help are provided:
1. Full help is available when you are ready to enter a
   command argument (e.g. 'show ?') and describes each possible
   argument.
2. Partial help is provided when an abbreviated argument is entered
   and you want to know what arguments match the input
   (e.g. 'show pr?'.
"#);
                println!("\nAvailable commands");
                println!("\n ");
                
                if matches!(context.current_mode, Mode::UserMode) {
                    println!("enable            - Enter privileged mode");
                    println!("exit              - Exit current mode");
                    println!("ping              - Send ICMP echo request");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("show              - Some available show commands are present. To view enter 'show ?'");
                }
                else if matches!(context.current_mode, Mode::PrivilegedMode) {
                    println!("configure         - Enter configuration mode");
                    println!("exit              - Exit to user mode");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("copy              - Copy configuration files");
                    println!("clock             - Manage system clock");
                    println!("clear ip ospf process - Clear all the ospf processes");
                    println!("ping              - Send ICMP echo request");
                    println!("show              - Some available show commands are present. To view enter 'show ?'");
                    println!("ifconfig          - Display interface configuration");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("debug             - Debug the availbale processes");
                    println!("undebug           - Undebug the availbale processes");
                }
                else if matches!(context.current_mode, Mode::ConfigMode) {
                    println!("hostname          - Set system hostname");
                    println!("interface         - Configure interface");
                    println!("exit              - Exit to privileged mode");
                    println!("tunnel            - Configure tunnel interface");
                    println!("virtual-template  - Configure virtual template");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("ping              - Send ICMP echo request");
                    println!("vlan              - Configure VLAN");
                    println!("access-list       - Configure access list");
                    println!("router            - Configure routing protocol");
                    println!("enable            - Enter privileged mode");
                    println!("ip route          - Configure static routes");
                    println!("ip domain-name    - Configure DNS domain name");
                    println!("ip access-list    - Configure IP access list");
                    println!("service           - Configure system services");
                    println!("set               - Set system parameters");
                    println!("ifconfig          - Configure interface");
                    println!("ntp               - Configure NTP");
                    println!("crypto            - Configure encryption");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                }
                else if matches!(context.current_mode, Mode::InterfaceMode) {
                    println!("exit              - Exit to config mode");
                    println!("shutdown          - Shutdown interface");
                    println!("no                - Negate a command");
                    println!("switchport        - Configure switching parameters");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("interface         - Select another interface");
                    println!("ip address        - Set IP address");
                    println!("ip ospf           - Configure OSPF protocol");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                }
                else if matches!(context.current_mode, Mode::VlanMode) {
                    println!("name              - Set VLAN name");
                    println!("exit              - Exit to config mode");
                    println!("state             - Set VLAN state");
                    println!("vlan              - Configure VLAN parameters");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("help              - Display available commands");
                }
                else if matches!(context.current_mode, Mode::RouterConfigMode) {
                    println!("network           - Configure network");
                    println!("exit              - Exit to config mode");
                    println!("neighbor          - Configure BGP neighbor");
                    println!("area              - Configure OSPF area");
                    println!("passive-interface - Configure passive interface");
                    println!("distance          - Configure administrative distance");
                    println!("default-information - Configure default route distribution");
                    println!("router-id         - Configure router ID");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("help              - Display available commands");
                }
                else if matches!(context.current_mode, Mode::ConfigStdNaclMode(_)) {
                    println!("deny              - Deny specific traffic");
                    println!("permit            - Permit specific traffic");
                    println!("exit              - Exit to config mode");
                    println!("ip access-list    - Configure IP access list");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("help              - Display available commands");
                }
                else if matches!(context.current_mode, Mode::ConfigExtNaclMode(_)) {
                    println!("deny              - Deny specific traffic");
                    println!("permit            - Permit specific traffic");
                    println!("exit              - Exit to config mode");
                    println!("ip access-list    - Configure IP access list");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("help              - Display available commands");
                }
                println!("\n ");
                Ok(())
            }
        },
    );
    

    commands.insert(
        "clock",
        Command {
            name: "clock set",
            description: "Change the clock date and time",
            suggestions: Some(vec!["set"]),
            suggestions1: Some(vec!["set"]),
            options: Some(vec!["<hh:mm:ss>      - Enter the time in this specified format",
                "<day>      - Enter the day '1-31'",
                "<month>    - Enter a valid month",
                "<year>     - Enter the year"]),
            execute: |args, context, clock| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    if args.len() > 1 && args[0] == "set" {   
                        if let Some(clock) = clock {

                            let input = args.join(" ");
            
                            match parse_clock_set_input(&input) {
                                Ok((time, day, month, year)) => {
                        
                                    handle_clock_set(time, day, month, year, clock);
                                    Ok(())
                                }
                                Err(err) => Err(err), 
                            }
                        } else {
                            Err("Clock functionality is unavailable.".to_string())
                        }
                    } else {
                        Err("Correct Usage of 'clock set' command is 'clock set <hh:mm:ss> <day> <month> <year>'.".into())
                    }
                }
                else {
                    Err("The 'clock set' command is only available in Privileged EXEC mode.".into())
                }
            },
        },
    );
    
    commands.insert(
        "ip",
        Command {
            name: "ip",
            description: "Define all the ip commands",
            suggestions: Some(vec![
                // InterfaceMode commands
                "address",
                "ospf",
                // ConfigMode commands
                "route",
                "domain-name",
                "access-list"
            ]),
            suggestions1: Some(vec![
                // InterfaceMode commands
                "address",
                "ospf",
                // ConfigMode commands
                "route",
                "domain-name",
                "access-list"
            ]),
            options: None,
            execute: |args, context, _| {
                if args.is_empty() {
                    return Err("Incomplete command. Use 'ip ?' for help.".into());
                }
    
                match (args[0], &context.current_mode) {
                    ("address", Mode::InterfaceMode) => {
                        if args.len() == 2 && args[1] == "?" {
                            println!("<ip-address>          - IP address of the interface");
                        }
                        else if args.len() == 3 && args[2] == "?" {
                            println!("<netmask>         - Netmask of the interface");
                        }
                        else if args.len() != 3 {
                            return Err("Usage: ip address <ip_address> <netmask>".into());
                        }
                        let ip_address: Ipv4Addr = args[1]
                            .parse()
                            .map_err(|_| "Invalid IP address format.".to_string())?;
                        let netmask: Ipv4Addr = args[2]
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
                    },
                    ("ospf", Mode::InterfaceMode) => {
                        if args.len() == 1 {
                            Err("The 'ip ospf' command requires a subcommand. Available subcommands: cost, retransmit-interval, transmit-delay, priority, hello-interval, dead-interval, authentication-key, message-digest-key, authentication.".into())
                        } else {
                            let subcommand = &args[1][..];
                            match subcommand {
                                "cost" => {
                                    if args.len() == 3 {
                                        let cost = args[2].parse::<u32>();
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
                                    if args.len() == 3 {
                                        let interval = args[2].parse::<u32>();
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
                                    if args.len() == 3 {
                                        let delay = args[2].parse::<u32>();
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
                                    if args.len() == 3 {
                                        let priority = args[2].parse::<u8>();
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
                                    if args.len() == 3 {
                                        let interval = args[2].parse::<u32>();
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
                                    if args.len() == 3 {
                                        let interval = args[2].parse::<u32>();
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
                                    if args.len() == 3 {
                                        let key = args[2].clone();
                                        println!("OSPF authentication key set to '{}'.", key);
                                        Ok(())
                                    } else {
                                        Err("Usage: ip ospf authentication-key <key>".into())
                                    }
                                }
                                "message-digest-key" => {
                                    if args.len() == 5 && args[3] == "md5" {
                                        let key_id = args[2].parse::<u32>();
                                        let key = args[4].clone();
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
                                    if args.len() == 3 {
                                        let auth_type = &args[2][..];
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
                    },
                    ("route", Mode::ConfigMode) => {
                        let mut route_table = ROUTE_TABLE.lock().unwrap();
                        if args.len() == 1 {
                            println!("Invalid command. The correct command is 'ip route <destination_ip> <netmask> <next_hop>");
                        } 
                        
                        else if args.len() == 4 {
                            let destination_ip: Ipv4Addr = Ipv4Addr::from_str(&args[1]).expect("Invalid IP address format");
                            let netmask: Ipv4Addr = Ipv4Addr::from_str(&args[2]).expect("Invalid IP address format");
                            
                            if let Ok(next_hop) = Ipv4Addr::from_str(&args[3]) {
                                // Scenario 1: ip route <destination-ip> <netmask> <next-hop>
                                route_table.insert(destination_ip.to_string(), (netmask, next_hop.to_string()));
                                println!("Added route: ip route {} {} {}", destination_ip, netmask, next_hop);
                            }
                            else {
                                // Scenario 2: ip route <destination-ip> <netmask> <exit interface>
                                let exit_interface: String = args[3].to_string();
                                println!("Added route: ip route {} {} {}", destination_ip, netmask, exit_interface);
                                route_table.insert(destination_ip.to_string(), (netmask, exit_interface));
                            }   
                        } 
                        
                        else if args.len() == 5 {
                            // Scenario 3: ip route <destination-ip> <netmask> <exit interface> <next-hop>
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
                            return Err("Usage: ip route <ip-address> <netmask> <next-hop | exit-interface> <next-hop>".into());
                        }
            
                        Ok(())
                    },
                    ("domain-name", Mode::ConfigMode) => {
                        if args.len() <= 1{
                            //Err("Domain name must be provided.".into())
                            return Err("Usage: ip domain-name <name>".into());
                        } else {
                            let domain_name = args[1].to_string();
                            context.config.domain_name = Some(domain_name.clone());
                            println!("Domain name set to: {}", domain_name);
                            Ok(())
                        }
                    },
                    ("access-list", Mode::ConfigMode | Mode::ConfigStdNaclMode(_) | Mode::ConfigExtNaclMode(_)) => {
                        if args.len() >= 3 {
                            let acl_type = args[1].to_lowercase(); // "standard" or "extended"
                            let acl_name_or_number = args[2].to_string(); // ACL name or number
            
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
                            Err("Usage: ip access-list standard|extended <acl_name|number>".into())
                        }
                    },
    
                    _ => Err("Command not available in current mode or invalid command".into())
                }
            },
        }
    );


    commands.insert(
        "shutdown",
        Command {
            name: "shutdown",
            description: "Disable the selected network interface.",
            suggestions: None,
            suggestions1: None,
            options: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::InterfaceMode) {
                    if let Some(interface) = &context.selected_interface {
                        let mut network_state = IP_ADDRESS_STATE.lock().unwrap();
                        let mut status_map = STATUS_MAP.lock().unwrap();
                        if let Some(interface_config) = network_state.get_mut(interface) {
                            
                            let ip_address = interface_config.0.clone();
                            
                            let mut interface_config = InterfaceConfig {
                                ip_address: Ipv4Addr::new(0, 0, 0, 0),
                                is_up: false,
                            };
                            
                            interface_config.is_up = true;
                            status_map.insert(interface.clone(), false);
    
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
        "no",
        Command {
            name: "no shutdown",
            description: "Enable the selected network interface.",
            suggestions: Some(vec!["shutdown", "ntp"]),
            suggestions1: Some(vec!["shutdown", "ntp"]),
            options: None,
            execute: |args, context, _| {
                if args.len() == 1 && args[0] == "shutdown" {
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
                } else if args.len() == 3 && args[0] == "ntp" && args[1] == "server" {
                    if matches!(context.current_mode, Mode::ConfigMode) {
                        let ip_address = args[2].to_string();
                        if context.ntp_servers.remove(&ip_address) {
                            // Remove from the associations list as well
                            context.ntp_associations.retain(|assoc| assoc.address != ip_address);
                            println!("NTP server {} removed.", ip_address);
                            Ok(())
                        } else {
                            Err("NTP server not found.".into())
                        }
                    } else {
                        Err("The 'no ntp server' command is only available in configuration mode.".into())
                    }
                } else {
                    Err("Invalid arguments provided to 'no'.".into())
                }
                
            },
        },
    );

    commands.insert("vlan", Command {
        name: "vlan",
        description: "Define VLAN or VLAN Range",
        suggestions: None,
        suggestions1: None,
        options: Some(vec!["<vlan-id>       - Enter the vlan-id"]),
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
                    let vlan_args: Vec<&str> = input.split_whitespace().collect();
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
        suggestions1: None,
        options: Some(vec!["<vlan-name>     - Enter a name for the vlan"]),
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
        suggestions1: None,
        options: Some(vec!["<vlan-state>       - Enter a valid state ('active', 'suspend')"]),
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

    commands.insert("switchport", Command {
        name: "switchport",
        description: "Configure switchport settings on the interface",
        suggestions: Some(vec!["mode", "trunk", "access", "nonegotiate", "port-security"]),
        suggestions1: Some(vec!["mode", "trunk", "access", "nonegotiate", "port-security"]),
        options: None,
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
        suggestions1: Some(vec!["ospf"]),
        options: Some(vec!["<process-id>       - Enter the ospf process-id"]),
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 2 && args[0] == "ospf"  {
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
        suggestions1: None,
        options: Some(vec!["<ip-address>        - Enter the ip-address",
            "<wildcard-mask>      - Enter the wildcard-mask",
            "<area-id>          - Enter the area-id"]),
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
                    Err("The 'network' command requires three arguments: <ip-address> <wildcard-mask> area <area-id>.".into())
                }
            } else {
                Err("The 'network' command is only available in Router Configuration mode.".into())
            }
        },
    });

    commands.insert("neighbor", Command {
        name: "neighbor",
        description: "Specify a neighbor and optionally assign a cost.",
        suggestions: None,
        suggestions1: None,
        options: Some(vec!["<ip-address>       - Emnter the ip-address",
            "<cost>       - Enter the cost"]),
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
        suggestions: Some(vec!["authentication", "stub", "default-cost"]),
        suggestions1: None,
        options: Some(vec!["<area-id>       - Enter the area-id"]),
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
        suggestions1: None,
        options: Some(vec!["<interface>     - Enter the interface name"]),
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
        suggestions1: None,
        options: Some(vec!["<distance>      - Set the distance"]),
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
        suggestions: Some(vec!["originate"]),
        suggestions1: Some(vec!["originate"]),
        options: None,
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
        suggestions1: None,
        options: Some(vec!["<router-id>       - Enter the router-id"]),
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

    commands.insert("clear", Command {
        name: "clear",
        description: "Reset all OSPF processes",
        suggestions: Some(vec!["ip ospf process"]),
        suggestions1: None,
        options: None,
        execute: |args, context, _| {
            if args.is_empty() {
                // Cross-platform clear screen
                if cfg!(target_os = "windows") {
                    ProcessCommand::new("cmd")
                        .args(["/C", "cls"])
                        .status()
                        .unwrap();
                } else {
                    ProcessCommand::new("clear")
                        .status()
                        .unwrap();
                }
                Ok(())
            }
            else if matches!(context.current_mode, Mode::PrivilegedMode) {
                if args.len() == 3 && args[0] == "ip" && args[1] == "ospf" && args[2] == "process"  {
                    print!("Reset ALL OSPF processes? [no]: ");
                    io::stdout().flush().unwrap();
                    
                    let mut response = String::new();
                    io::stdin().read_line(&mut response).unwrap();
                    let response = response.trim().to_lowercase();
                    
                    // Check for yes/y or empty response
                    if response == "yes" || response == "y" {
                        let mut ospf_config = OSPF_CONFIG.lock().unwrap();
                        *ospf_config = OSPFConfig::new();  
                        println!("All OSPF processes cleared.");
                        Ok(())
                    } else {
                        println!("Clear process cancelled.");
                        Ok(())
                    }
                } else {
                    Err("Invalid arguments provided to 'clear ip ospf process'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'clear ip ospf process' command is only available in EXEC mode.".into())
            }
        },
    });

    commands.insert("access-list", Command {
        name: "access-list",
        description: "Configure a standard numbered ACL",
        suggestions: None,
        suggestions1: None,
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() >= 3 {
                    let acl_number = args[0].to_string();
                    let action = args[1].to_string();
                    let source = Ipv4Addr::from_str(&args[3]).expect("Invalid IP address format").to_string();
                    let destination = if args.len() > 4 { Ipv4Addr::from_str(&args[4]).expect("Invalid IP address format").to_string()} else { "any".to_string() };
                    let protocol = args.get(2).clone();
    
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
                    Err("Invalid syntax. Use 'access-list <number> <protocol> {deny|permit} <source_ip> <wildcard_mask>'.".into())
                }
            } else {
                Err("The 'access-list' command is only available in global configuration mode.".into())
            }
        },
    });


    commands.insert("deny", Command {
        name: "deny",
        description: "Add a deny entry to the ACL (standard or extended)",
        suggestions: None,
        suggestions1: None,
        options: None,
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
                        let destination = Ipv4Addr::from_str(&args[4]).expect("Invalid IP address format").to_string();

                        let mut source_operator = None;
                        let mut source_port = None;
                        let mut destination_operator = None;
                        let mut destination_port = None;

                        if args.len() > 4 {
                            source_operator = Some(args[2].to_lowercase()); // e.g., "eq", "gt", "lt"
                            source_port = args.get(3).map(|p| p.to_string()); 
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
        suggestions1: None,
        options: None,
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
                        let destination = Ipv4Addr::from_str(&args[4]).expect("Invalid IP address format").to_string();

                        let mut source_operator = None;
                        let mut source_port = None;
                        let mut destination_operator = None;
                        let mut destination_port = None;

                        if args.len() > 4 {
                            source_operator = Some(args[2].to_lowercase()); // e.g., "eq", "gt", "lt"
                            source_port = args.get(3).map(|p| p.to_string()); 
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

    commands.insert("crypto", Command {
        name: "crypto",
        description: "Crypto configuration commands",
        suggestions: Some(vec!["ipsec profile", "key"]),
        suggestions1: Some(vec!["ipsec profile", "key"]),
        options: Some(vec!["<Requirement>   - Enter 'generate' or 'zeroize' "]),
        execute: |args, context, _| {
            if !matches!(context.current_mode, Mode::ConfigMode) {
                return Err("Crypto commands are only available in Config mode.".into());
            }
    
            if args.is_empty() {
                return Err("Subcommand required. Available subcommands: 'ipsec profile', 'key'.".into());
            }
    
            match &args[0][..] {
                "ipsec" => {
                    if args.len() >= 2 && args[1] == "profile" {
                        if args.len() == 3 {
                            let profile_name = &args[2];
                            context.config.crypto_ipsec_profile = Some(profile_name.to_string());
                            println!("Crypto IPsec profile '{}' defined.", profile_name);
                            Ok(())
                        } else {
                            Err("Invalid arguments. Use 'crypto ipsec profile <profile-name>'.".into())
                        }
                    } else {
                        Err("Invalid ipsec subcommand. Use 'crypto ipsec profile <profile-name>'.".into())
                    }
                },
                "key" => {
                    if args.len() < 2 {
                        return Err("Subcommand required. Use 'generate rsa' to create RSA keys, or 'zeroize' to delete keys.".into());
                    }
    
                    match &args[1][..] {
                        "generate" => {
                            if args.len() > 2 && args[2] == "rsa" {
                                // RSA key generation logic
                                println!("Enter key modulus size (default is 512 bits):");
                                let modulus_size = 512;
                                let domain_name = context.config.domain_name.clone();
    
                                let key_name = format!("{}.{}", 
                                    context.config.hostname, 
                                    domain_name.unwrap_or("default_domain".to_string())
                                );
                                println!("The name for the keys will be: {}", key_name);
                                println!("Generating {}-bit RSA keys, keys will be non-exportable...", modulus_size);
                                // Add logic here to generate the RSA keys.
                                println!("[OK] RSA keys generated successfully.");
                                Ok(())
                            } else {
                                Err("Invalid generate command. Use 'crypto key generate rsa'.".into())
                            }
                        },
                        "zeroize" => {
                            if args.len() > 2 && args[2] == "rsa" {
                                let key_name = args[2].to_string();
                                println!("Deleting keys with the name: {}", key_name);
                                println!("[OK] Keys deleted successfully.");
                                Ok(())
                            } else {
                                Err("Invalid zeroize command. Use 'crypto key zeroize rsa'.".into())
                            }
                        },
                        _ => Err("Invalid key subcommand. Available subcommands: 'generate rsa', 'zeroize rsa'.".into())
                    }
                },
                _ => Err("Invalid crypto subcommand. Available subcommands: 'ipsec profile', 'key'.".into())
            }
        }
    });
    
    commands.insert("set", Command {
        name: "set transform-set",
        description: "Specifies which transform sets can be used with the crypto map entry.",
        suggestions: Some(vec!["transform-set"]),
        suggestions1: Some(vec!["transform-set"]),
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 1 {
                    Err("Invalid command. The command should be set transform-set <transform set name>".into())
                } else {
                    context.config.transform_sets = Some(args.iter().map(|s| s.to_string()).collect());
                    println!("Transform set(s) set to: {:?}", args[1]);
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
        suggestions: Some(vec!["mode", "source", "destination", "protection"]),
        suggestions1: Some(vec!["mode", "source", "destination", "protection"]),
        options: None,
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
        suggestions1: None,
        options: Some(vec!["<template-number>       - Enter the template number"]),
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
    
    
    commands.insert("ntp", Command {
        name: "ntp",
        description: "NTP configuration commands",
        suggestions: Some(vec!["server", "master", "authenticate", "authentication-key", "trusted-key"]),
        suggestions1: Some(vec!["server", "master", "authenticate", "authentication-key", "trusted-key"]),
        options: None,
        execute: |args, context, _| {
            if !matches!(context.current_mode, Mode::ConfigMode) {
                return Err("NTP commands are only available in configuration mode.".into());
            }
    
            if args.is_empty() {
                return Err("Subcommand required. Available subcommands: server, master, authenticate, authentication-key, trusted-key".into());
            }
    
            match &args[0][..] {
                "server" => {
                    if args.len() == 2 {
                        let ip_address = args[1].to_string();
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
                    } else {
                        Err("Invalid arguments. Usage: ntp server {ip-address}".into())
                    }
                },
                "master" => {
                    context.ntp_master = true;
                    println!("Device configured as NTP master.");
                    Ok(())
                },
                "authenticate" => {
                    if args.len() == 1 {
                        context.ntp_authentication_enabled = !context.ntp_authentication_enabled;
                        let status = if context.ntp_authentication_enabled {
                            "enabled"
                        } else {
                            "disabled"
                        };
                        println!("NTP authentication {}", status);
                        Ok(())
                    } else {
                        Err("Invalid arguments. Use 'ntp authenticate'.".into())
                    }
                },
                "authentication-key" => {
                    if args.len() == 4 && args[2] == "md5" {
                        if let Ok(key_number) = args[1].parse::<u32>() {
                            let md5_key = args[3].to_string();
                            context.ntp_authentication_keys.insert(key_number, md5_key.clone());
                            println!("NTP authentication key {} configured with MD5 key: {}", key_number, md5_key);
                            Ok(())
                        } else {
                            Err("Invalid key number. Must be a positive integer.".into())
                        }
                    } else {
                        Err("Invalid arguments. Use 'ntp authentication-key <key-number> md5 <key-value>'.".into())
                    }
                },
                "trusted-key" => {
                    if args.len() == 2 {
                        if let Ok(key_number) = args[1].parse::<u32>() {
                            context.ntp_trusted_keys.insert(key_number);
                            println!("NTP trusted key {} configured.", key_number);
                            Ok(())
                        } else {
                            Err("Invalid key number. Must be a positive integer.".into())
                        }
                    } else {
                        Err("Invalid arguments. Use 'ntp trusted-key <key-number>'.".into())
                    }
                },
                _ => Err("Invalid NTP subcommand. Available subcommands: server, master, authenticate, authentication-key, trusted-key".into())
            }
        }
    });
  
    commands.insert("service", Command {
        name: "service password-encryption",
        description: "Enable password encryption",
        suggestions: Some(vec!["password-encryption"]),
        suggestions1: Some(vec!["password-encryption"]),
        options: None,
        execute: |args, context, _| {
            if matches!(context.current_mode, Mode::ConfigMode) {
                if args.len() == 1 && args[0] == "password-encryption" {
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
                    Err("Invalid arguments provided to 'service password-encryption'. This command does not accept additional arguments.".into())
                }
            } else {
                Err("The 'service password-encryption' command is only available in Privileged EXEC mode.".into())
            }
        },
    });

    commands.insert("ping", Command {
        name: "ping",
        description: "Ping a specific IP address to check reachability",
        suggestions: None,
        suggestions1: None,
        options: Some(vec!["<ip-address>    - Enter the ip-address"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let ip: String = args[0].to_string();
                let route_table = ROUTE_TABLE.lock().unwrap();
    
                if route_table.contains_key(&ip) {
                    println!("Pinging {} with 32 bytes of data:", ip);
                    for _ in 0..4 {
                        println!("Reply from {}: bytes=32 time<1ms TTL=128", ip);
                    }
                    println!("\nPing statistics for {}:", ip);
                    println!("    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),");
                    println!("Approximate round trip times in milli-seconds:");
                    println!("    Minimum = 0ms, Maximum = 1ms, Average = 0ms");
                    Ok(())
                } else {
                    println!("Pinging {} with 32 bytes of data:", ip);
                    for _ in 0..4 {
                        println!("Request timed out.");
                    }
                    println!("\nPing statistics for {}:", ip);
                    println!("    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),");
                    Err(format!("IP address {} is not reachable.", ip).into())
                }
            } else {
                Err("Invalid syntax. Usage: ping <ip>".into())
            }
        },
    });
    


    commands
}