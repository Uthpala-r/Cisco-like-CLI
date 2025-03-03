/// External crates for the CLI application
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::File;
use std::io::{self, Write, BufRead, BufReader};
use std::str::FromStr;
use rpassword::read_password;
use std::process::Command as ProcessCommand;
use std::process::Stdio;

use crate::run_config::{get_running_config, default_startup_config};
use crate::execute::Command;
use crate::execute::Mode;
use crate::clock_settings::{handle_clock_set, parse_clock_set_input, handle_show_clock, handle_show_uptime};
use crate::network_config::{calculate_broadcast, print_interface, format_flags, get_system_interfaces, InterfaceConfig, InterfacesConfig, STATUS_MAP, IP_ADDRESS_STATE, IFCONFIG_STATE, ROUTE_TABLE, encrypt_password, PASSWORD_STORAGE, set_enable_password, set_enable_secret};
use crate::network_config::NtpAssociation;


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
/// - `disable`: Exits the privileged commands
/// - `show`: Displays all the show commands when specific command is passed
///     - `show running-config`: Displays the current running configuration from a JSON file.
///     - `show startup-config`: Displays the initial configuration settings stored in the NVRAM of a router, which are loaded upon booting the device.
///     - `show version`: Displays the software version information.
///     - `show clock`: Displays the current clock date and time.
///     - `show interfaces`: Displays statistics for all interfaces, including a brief overview or detailed information.
///     - `show ip interfaces brief`: Displays a summary of the router interfaces
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
/// - `ip address`: Assigns an IP address and netmask to the selected interface.
/// - `shutdown`: Disable a router's interface
/// - `no`: Execute the opposite of the commands
///     - `no shutdown`: Enable a router's interface 
///     - `no ntp server`: Disable NTP
/// - `ntp`: Defines all the ntp commands
///     - `ntp source`: To use a particular source address in Network Time Protocol (NTP) packets
///     - `ntp server`: Configures the NTP server for synchronizing time on the device, ensuring that the device’s clock is accurate.
///     - `ntp master`: Configures the device as an NTP master, meaning it will serve time to other devices in the network.
///     - `ntp authenticate`: Enables NTP authentication, which allows the NTP client to authenticate time synchronization requests from servers.
///     - `ntp authentication-key`: Defines the key used for authenticating NTP messages, providing security to NTP transactions.
///     - `ntp trusted-key`: Specifies which authentication key(s) are trusted to authenticate NTP messages
/// - `service password-encryption`: Enables password encryption for storing sensitive passwords in the device’s configuration, ensuring they are not stored in plain text.
/// - `ssh`: Connect to ssh or define ssh version
/// - `ping`: Confirms the connection between ip addresses
/// - `traceroute`: To track the packet transfer path
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
        suggestions2: None,
        options: Some(vec!["<password>      - Enter the password/secret>"]),
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
        suggestions2: None,
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
        suggestions2: None,
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

    commands.insert("connect", Command {
        name: "connect",
        description: "Connect to network processor or crypto module",
        suggestions: Some(vec!["network", "crypto"]),
        suggestions1: Some(vec!["network", "crypto"]),
        suggestions2: None,
        options: None,
        execute: |args, _context, _| {    
            if args.len() != 1 {
                return Err("Invalid number of arguments. Usage: connect <network|crypto>".into());
            }
    
            match args[0] {
                "network" => {
                    println!("Connecting to network processor...");
                    let status = ProcessCommand::new("ssh")
                        .args([
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "pnfcli@192.168.253.146"   // Replace with actual FRR IP
                        ])
                        .status()
                        .map_err(|e| format!("Failed to execute SSH command: {}", e))?;
    
                    if !status.success() {
                        return Err("Failed to connect to network processor".into());
                    }
                    Ok(())
                },
                "crypto" => {
                    println!("Connecting to crypto module...");
                    // Replace with actual crypto module SSH details
                    let status = ProcessCommand::new("ssh")
                        .args([
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "pnfcli@192.168.253.147"  // Replace with actual SEM IP
                        ])
                        .status()
                        .map_err(|e| format!("Failed to execute SSH command: {}", e))?;

                    if !status.success() {
                        return Err("Failed to connect to crypto module".into());
                    }
                    Ok(())
                },
                _ => Err("Invalid argument. Use 'network' or 'crypto'".into())
            }
        },
    });


    commands.insert("exit", Command {
        name: "exit",
        description: "Exit the current mode and return to the previous mode.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
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

    commands.insert("disable", Command {
        name: "disable",
        description: "Exit the Privileged EXEC mode and return to the USER EXEC mode.",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |_args, context, _| {
            if _args.is_empty() {
                match context.current_mode {
                    Mode::InterfaceMode => {
                        println!("This command only works at the Privileged Mode.");
                        Err("This command only works at the Privileged Mode.".into())
                    
                    }
                    Mode::ConfigMode => {
                        println!("This command only works at the Privileged Mode.");
                        Err("This command only works at the Privileged Mode.".into())
                    
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
        suggestions2: None,
        options: None,
        execute: |_, context, _| {
            
            println!("System configuration has been modified. Save? [yes/no]:");
    
            let mut save_input = String::new();
            std::io::stdin().read_line(&mut save_input).expect("Failed to read input");
            let save_input = save_input.trim();
    
            if ["yes", "y", ""].contains(&save_input.to_ascii_lowercase().as_str()) {
                println!("Building configuration...");
                println!("[OK]");
            } else if ["no", "n"].contains(&save_input.to_ascii_lowercase().as_str()) {
                println!("Configuration not saved.");
            } else {
                return Err("Invalid input. Please enter 'yes' or 'no'.".into());
            }
    
            println!("Proceed with reload? [yes/no]:");
            let mut reload_confirm = String::new();
            std::io::stdin().read_line(&mut reload_confirm).expect("Failed to read input");
            let reload_confirm = reload_confirm.trim();
    
            if ["yes", "y", ""].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
                println!("System Bootstrap, Version 15.1(4)M4, RELEASE SOFTWARE (fc1)");
                println!("Technical Support: http://www.cisco.com/techsupport");
                println!("Copyright (c) 2010 by cisco Systems, Inc.");
                println!("Total memory size = 512 MB - On-board = 512 MB, DIMM0 = 0 MB");
    
                // Simulate reload process
                context.current_mode = Mode::UserMode;
                context.prompt = format!("{}>", context.config.hostname);
    
                println!("\nPress RETURN to get started!");
                Ok(())
            } else if ["no", "n"].contains(&reload_confirm.to_ascii_lowercase().as_str()) {
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
        suggestions2: None,
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
        suggestions2: None,
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
        suggestions2: None,
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
            description: "Configure a network interface",
            suggestions: None,
            suggestions1: None,
            suggestions2: None,
            options: Some(vec![
                "<interface>         - Network interface name",
                "<address>           - IP address to set",
                "up|down             - Bring interface up or down",
                "netmask <mask>      - Set network mask",
                "broadcast <addr>    - Set broadcast address",
                "mtu <size>          - Set MTU size"
            ]),
            execute: |args, _, _| {
                let mut ifconfig_state = IFCONFIG_STATE.lock().unwrap();
    
                // Display all interfaces if no arguments
                if args.is_empty() {
                    println!("System Network Interfaces:");
                    println!("-------------------------");
                    println!("{}", get_system_interfaces());
                    
                    println!("\nConfigured Virtual Interfaces:");
                    println!("----------------------------");
                    if ifconfig_state.is_empty() {
                        println!("No interfaces configured.");
                        return Ok(());
                    }
        
                    for (name, config) in ifconfig_state.iter() {
                        print_interface(name, config);
                    }
                    return Ok(());
                }
    
                let interface_name = args[0].to_string();

                // Handle interface configuration
                if args.len() == 1 {
                    // Show single interface
                    if let Some(config) = ifconfig_state.get(&interface_name) {
                        print_interface(&interface_name, config);
                    } else {
                        println!("Interface {} not found", interface_name);
                    }
                } else {
                    let command = &args[1];
                    if *command == "up" || *command == "down" {
                        let is_up = *command == "up";
                        if let Some(config) = ifconfig_state.get_mut(&interface_name) {
                            config.is_up = is_up;
                            println!("{} {} {}", interface_name, 
                                if is_up { "up" } else { "down" },
                                if is_up { "and running" } else { "and stopped" });
                        }
                    } else {
                        // Configure new interface or update existing one
                        if args.len() < 3 || args[2] != "up" {
                            println!("Error: Missing 'up' command after IP address");
                            return Ok(());
                        }
    
                        match Ipv4Addr::from_str(command) {
                            Ok(ip) => {
                                let netmask = Ipv4Addr::new(255, 255, 255, 0);
                                let broadcast = calculate_broadcast(ip, netmask);
                                
                                let config = InterfaceConfig {
                                    ip_address: ip,
                                    netmask,
                                    broadcast,
                                    mac_address: "00:0c:29:16:30:92".to_string(),
                                    mtu: 1500,
                                    flags: vec!["BROADCAST".to_string(), 
                                              "RUNNING".to_string(), 
                                              "MULTICAST".to_string()],
                                    is_up: true,
                                };
    
                                ifconfig_state.insert(interface_name.clone(), config.clone());
                                print_interface(&interface_name, &config);
                            },
                            Err(_) => {
                                println!("Error: Invalid IP address format");
                            }
                        }
                    }
                }
    
                Ok(())
            },
        },
    );

    commands.insert(
        "show",
        Command {
            name: "show",
            description: "Display all the show commands when specific command is passed in the specific mode",
            suggestions: Some(vec![
                "running-config",
                "startup-config",
                "version",
                "ntp",
                "processes",
                "clock",
                "uptime",
                "controllers",
                "history",
                "sessions",
                "interfaces",
                "login"
            ]),
            suggestions1: Some(vec![
                "running-config",
                "startup-config",
                "version",
                "ntp",
                "processes",
                "clock",
                "uptime",
                "controllers",
                "history",
                "sessions",
                "interfaces",
                "login"
            ]),
            suggestions2: None,
            options: None,
            execute: |args, context, clock| {
                if matches!(context.current_mode, Mode::UserMode | Mode ::PrivilegedMode){
                    return match args.get(0) {
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
                        
                        Some(&"sessions") if matches!(context.current_mode, Mode::UserMode) => {
                            println!("% No connections open");
                            Ok(())
                        },

                        Some(&"controllers") if matches!(context.current_mode, Mode::UserMode) => {
                            if args.len() < 2 {
                                return Err("Interface type required. Usage: show controllers <interface-type> <interface-number>".into());
                            }
                            
                            let interface_type = args[1];
                            let interface_number = args.get(2).unwrap_or(&"0/0");
                            
                            // Validate interface type
                            let valid_interfaces = vec![
                                "GigabitEthernet", "FastEthernet", "Ethernet", "Serial"
                            ];
                            
                            if !valid_interfaces.contains(&interface_type) {
                                return Err(format!("Invalid interface type. Valid types are: {}", 
                                    valid_interfaces.join(", ")).into());
                            }
                            
                            println!("Interface {}{}", interface_type, interface_number);
                            println!("Hardware is PQUICC MPC860P ADDR: 80C95180, FASTSEND: 80011BA4");
                            println!("DIST ROUTE ENABLED: 0");
                            println!("Route Cache Flag: 0");
                            
                            Ok(())
                        },
                        Some(&"history") if matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode) => {
                            // Read from history.txt file
                            
                            match read_lines("history.txt") {
                                Ok(lines) => {
                                    for line in lines.flatten() {
                                        println!("{}", line);
                                    }
                                    Ok(())
                                },
                                Err(e) => Err(format!("Error reading history file: {}", e).into())
                            }
                        },
                        
                        Some(&"running-config") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            println!("Building configuration...\n");
                            println!("Current configuration : 0 bytes\n");
                            let running_config = get_running_config(&context);
                            println!("{}", running_config);
                            Ok(())
                        },

                        Some(&"startup-config") if matches!(context.current_mode, Mode::PrivilegedMode) => {
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

                        Some(&"interfaces") if matches!(context.current_mode, Mode::PrivilegedMode) => {
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
                                }
                                _ => Err("Invalid IP subcommand. Use 'interface brief'".into())
                            }
                        },

                        Some(&"login") if matches!(context.current_mode, Mode::PrivilegedMode) => {
                            println!("A default login delay of 1 seconds is applied.");
                            println!("No Quiet-Mode access list has been configured.");
                            println!(" ");
                            println!("Router NOT enabled to watch for login Attacks");
                            Ok(())
                        },
                        
                        Some(&"ntp") if matches!(context.current_mode, Mode::PrivilegedMode) => {
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
                        
                        Some(&"processes") if matches!(context.current_mode, Mode::PrivilegedMode) => {
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
                        
                        Some(cmd) => {
                            println!("Invalid show command: {}", cmd);
                            Ok(())
                        },

                        None => {
                            println!("Missing parameter. Usage: show <command>");
                            Ok(())
                        }
                    }
                }
                else {
                    return Err("Show commands are only available in User EXEC mode and Privileged EXEC mode.".into());
                }
            },
        },
    );

    commands.insert(
        "do",
        Command {
            name: "do",
            description: "Execute privileged EXEC commands from any configuration mode",
            suggestions: Some(vec!["show"]),
            suggestions1: Some(vec!["show"]),
            suggestions2: Some(vec![
                "running-config",
                "startup-config",
                "version",
                "ntp",
                "processes",
                "clock",
                "uptime",
                "controllers",
                "history",
                "sessions",
                "interfaces",
                "login"
            ]),
            options: None,
            execute: |args, context, clock| {
                // Check if the first argument is "show"
                match args.get(0) {
                    Some(&"show") => {
                        // Remove "show" from args to get the remaining arguments
                        let show_args: Vec<&str> = args.iter().skip(1).copied().collect();
                        
                        // Execute the show command logic
                        match show_args.get(0) {
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
                            Some(&"sessions") => {
                                println!("% No connections open");
                                Ok(())
                            },
                            Some(&"controllers") => {
                                if show_args.len() < 2 {
                                    return Err("Interface type required. Usage: do show controllers <interface-type> <interface-number>".into());
                                }
                                
                                let interface_type = show_args[1];
                                let interface_number = show_args.get(2).unwrap_or(&"0/0");
                                
                                let valid_interfaces = vec![
                                    "GigabitEthernet", "FastEthernet", "Ethernet", "Serial"
                                ];
                                
                                if !valid_interfaces.contains(&interface_type) {
                                    return Err(format!("Invalid interface type. Valid types are: {}", 
                                        valid_interfaces.join(", ")).into());
                                }
                                
                                println!("Interface {}{}", interface_type, interface_number);
                                println!("Hardware is PQUICC MPC860P ADDR: 80C95180, FASTSEND: 80011BA4");
                                println!("DIST ROUTE ENABLED: 0");
                                println!("Route Cache Flag: 0");
                                
                                Ok(())
                            },
                            Some(&"history") => {
                                match read_lines("history.txt") {
                                    Ok(lines) => {
                                        for line in lines.flatten() {
                                            println!("{}", line);
                                        }
                                        Ok(())
                                    },
                                    Err(e) => Err(format!("Error reading history file: {}", e).into())
                                }
                            },
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
                                match args.get(2) {
                                    Some(&"interface") => {
                                        match args.get(3) {
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
                                    }
                                    _ => Err("Invalid IP subcommand. Use 'interface brief'".into())
                                }
                            },
                            Some(&"login") => {
                                println!("A default login delay of 1 seconds is applied.");
                                println!("No Quiet-Mode access list has been configured.");
                                println!(" ");
                                println!("Router NOT enabled to watch for login Attacks");
                                Ok(())
                            },
                            Some(&"ntp") => {
                                match show_args.get(1) {
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
                            Some(&"processes") => {
                                if show_args.len() == 1 {
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
                                } else if show_args.len() == 2 && show_args[1] == "cpu" {
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
                                } else if show_args.len() == 3 && show_args[1] == "cpu" && show_args[2] == "history" {
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
                                } else if show_args.len() == 2 && show_args[1] == "memory" {
                                    println!(
                                        "Total: 106206400, Used: 7479116, Free: 98727284\n\
                                        PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process\n\
                                        0   0      81648       1808    6577644          0          0 *Init*\n\
                                        0   0        572     123196        572          0          0 *Sched*\n\
                                        0   0   10750692    3442000       5812    2813524          0 *Dead*\n\
                                        1   0        276        276       3804          0          0 Load Meter"
                                    );
                                    Ok(())
                                } else {
                                    Err("Invalid subcommand for 'do show processes'. Valid subcommands are 'cpu', 'cpu history', and 'memory'.".into())
                                }
                            },
                            Some(cmd) => {
                                println!("Invalid show command: {}", cmd);
                                Ok(())
                            },
                            None => {
                                println!("Missing parameter. Usage: do show <command>");
                                Ok(())
                            }
                        }
                    },
                    Some(cmd) => {
                        println!("Invalid do command: {}", cmd);
                        Ok(())
                    },
                    None => {
                        println!("Missing parameter. Usage: do <command>");
                        Ok(())
                    }
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
            suggestions2: None,
            options: None,
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::UserMode | Mode::PrivilegedMode | Mode::ConfigMode) {
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
            suggestions2: Some(vec!["startup-config"]),
            options: Some(vec!["<file_name>     - Enter the file name or 'startup-config'",
            "startup-config"]),
            execute: |args, context, _| {
                if !matches!(context.current_mode, Mode::PrivilegedMode | Mode::ConfigMode) {
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
            suggestions2: None,
            options: None,
            execute: |_args, context, _| {
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
                    println!("traceroute        - Display the packet transfer path");
                    println!("help              - Display available commands");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("show              - Some available show commands are present. To view enter 'show ?'");
                    println!("write             - Save the configuration");
                    println!("ifconfig          - Display interface configuration");
                    println!("connect           - Connect the Network Processor or the SEM");
                }
                else if matches!(context.current_mode, Mode::PrivilegedMode) {
                    println!("configure         - Enter configuration mode");
                    println!("exit              - Exit to user mode");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("copy              - Copy configuration files");
                    println!("clock             - Manage system clock");
                    println!("ping              - Send ICMP echo request");
                    println!("traceroute        - Display the packet transfer path");
                    println!("show              - Some available show commands are present. To view enter 'show ?'");
                    println!("ifconfig          - Display interface configuration");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
                    println!("debug             - Debug the availbale processes");
                    println!("undebug           - Undebug the availbale processes");
                    println!("connect           - Connect the Network Processor or the SEM");
                    println!("ssh               - Connect via SSH or show ssh version");
                    println!("disable           - Exit the Privileged EXEC Mode and enter the USER EXEC Mode");
                }
                else if matches!(context.current_mode, Mode::ConfigMode) {
                    println!("hostname          - Set system hostname");
                    println!("exit              - Exit to privileged mode");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("ping              - Send ICMP echo request");
                    println!("traceroute        - Display the packet transfer path");
                    println!("enable            - Enter privileged mode");
                    println!("service password encryption - Encrypt passwords defined for the device");
                    println!("ifconfig          - Configure interface");
                    println!("ntp               - Configure NTP");
                    println!("no ntp            - Remove NTP configurations");
                    println!("reload            - Reload the system");
                    println!("interface         - Select another interface");
                    println!("clear             - Clear the terminal");
                }
                else if matches!(context.current_mode, Mode::InterfaceMode) {
                    println!("exit              - Exit to config mode");
                    println!("shutdown          - Shutdown interface");
                    println!("no                - Negate a command");
                    println!("help              - Display available commands");
                    println!("write             - Save the configuration");
                    println!("interface         - Select another interface");
                    println!("ip address        - Set IP address");
                    println!("reload            - Reload the system");
                    println!("clear             - Clear the terminal");
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
            suggestions2: None,
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
            suggestions: Some(vec!["address"]),
            suggestions1: Some(vec!["address"]),
            suggestions2: None,
            options: Some(vec![
                "<IP_Address>   - Enter the IP Address",
                "<subnetmask>   - Enter the subnet mask"
            ]),
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
            suggestions2: None,
            options: None,
            execute: |_, context, _| {
                if matches!(context.current_mode, Mode::InterfaceMode) {
                    if let Some(interface) = &context.selected_interface {
                        let mut network_state = IP_ADDRESS_STATE.lock().unwrap();
                        let mut status_map = STATUS_MAP.lock().unwrap();
                        if let Some(interface_config) = network_state.get_mut(interface) {
                            
                            let ip_address = interface_config.0.clone();
                            
                            let mut interface_config = InterfacesConfig {
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
            suggestions2: Some(vec!["server"]),
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

    commands.insert("clear", Command {
        name: "clear",
        description: "Clear processes",
        suggestions: Some(vec!["ntp associations"]),
        suggestions1: None,
        suggestions2: None,
        options: None,
        execute: |args, context, _| {
            match args.get(0) {
                None => {
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
                },
                Some(&"ntp") => {
                    if !matches!(context.current_mode, Mode::PrivilegedMode) {
                        return Err("The 'clear ntp associations' command is only available in privileged EXEC mode.".into());
                    }
    
                    match args.get(1) {
                        Some(&"associations") => {
                            context.ntp_associations.clear();
                            // Reinitialize associations for configured servers
                            println!("NTP associations cleared and reinitialized.");
                            Ok(())
                        },
                        _ => Err("Invalid command. Usage: clear ntp associations".into())
                    }
                },
                _ => Err("Invalid command. Available commands: clear, clear ntp associations".into())
            }
        },
    });

    
    commands.insert("ntp", Command {
        name: "ntp",
        description: "NTP configuration commands",
        suggestions: Some(vec!["source", "server", "master", "authenticate", "authentication-key", "trusted-key"]),
        suggestions1: Some(vec!["source", "server", "master", "authenticate", "authentication-key", "trusted-key"]),
        suggestions2: None,
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
                            context.ntp_associations.push(association); 
                            println!("NTP server {} configured.", ip_address);
                            Ok(())
                        } else {
                            Err("Invalid IP address format.".into())
                        }
                    } else {
                        Err("Invalid arguments. Usage: ntp server {ip-address}".into())
                    }
                },
                "source" => {
                    if args.len() >= 2 {
                        if args.len() == 2 {
                            let interface_name = args[1].to_string();
                            context.ntp_source_interface = Some(interface_name.clone());
                            println!("NTP source interface set to {}", interface_name);
                            Ok(())
                        } else {
                            Err("Invalid arguments. Usage: ntp source interface {interface-name}".into())
                        }
                    } else {
                        Err("Invalid arguments. Usage: ntp source interface {interface-name}".into())
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
        suggestions2: None,
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

    commands.insert(
        "ssh",
        Command {
            name: "ssh",
            description: "Establish SSH connection to a remote host",
            suggestions: Some(vec![
                "-v",
                "-l",
                "-h",
                "--help"
            ]),
            suggestions1: Some(vec![
                "-v",
                "-l",
                "-h",
                "--help"
            ]),
            suggestions2: None,
            options: Some(vec![
                "<login-name>       - Enter the hostname",
                "<ip_address>       - Enter the host IP address"
            ]),
            execute: |args, context, _| {
                if matches!(context.current_mode, Mode::PrivilegedMode) {
                    match args.get(0) {
                        Some(&"-v") => {
                            println!("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022");
                            Ok(())
                        },
                        Some(&"-l") => {
                            if args.len() < 2 {
                                println!("Usage: ssh -l <username>@<ip-address>");
                                return Ok(());
                            }
    
                            let connection_string = args[1];
                            
                            // Split the connection string into username and ip
                            match connection_string.split_once('@') {
                                Some((username, ip)) => {
                                    println!("Attempting SSH connection to {} as user {}", ip, username);
                                    println!("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022");
                                    println!("debug1: Reading configuration data /etc/ssh/ssh_config");
                                    println!("debug1: Connecting to {} port 22", ip);
                                    
                                    // Simulate connection attempt
                                    println!("debug1: Connection established.");
                                    println!("debug1: Authenticating to {}:22 as '{}'", ip, username);
                                    println!("debug1: Server accepts key: /home/{}/.ssh/id_rsa", username);
                                    println!("Authenticated to {} ([{}]:22).", ip, ip);
                                    println!("debug1: channel 0: new [client-session]");
                                    println!("debug1: Entering interactive session.");
                                    println!("Last login: Wed Feb 19 03:35:18 2025");
                                    Ok(())
                                },
                                None => {
                                    println!("Invalid format. Use: ssh -l username@ip-address");
                                    println!("Example: ssh -l admin@192.168.1.1");
                                    Ok(())
                                }
                            }
                        },
                        Some(&help) if help == "-h" || help == "--help" => {
                            println!("SSH Command Usage:");
                            println!("  ssh -v                     Display SSH version");
                            println!("  ssh -l username@ip-address Login to remote server");
                            println!("\nExamples:");
                            println!("  ssh -l admin@192.168.1.1");
                            Ok(())
                        },
                        Some(cmd) => {
                            println!("Invalid SSH option: {}", cmd);
                            println!("Use 'ssh -h' for help");
                            Ok(())
                        },
                        None => {
                            println!("Missing parameters. Use 'ssh -h' for help");
                            Ok(())
                        }
                    }
                } else {
                    Err("SSH command is only available in User EXEC mode and Privileged EXEC mode.".to_string())
                }
            },
        }
    );

    commands.insert("ping", Command {
        name: "ping",
        description: "Ping a specific IP address to check reachability",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<ip-address>    - Enter the ip-address"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let ip = args[0].to_string();
                
                println!("Pinging {} with 32 bytes of data:", ip);
                
                let mut child = match ProcessCommand::new("ping")
                    .arg("-c")
                    .arg("4")  // Send 4 packets (Linux/macOS style)
                    .arg("-s")
                    .arg("32") // 32 bytes of data
                    .arg(&ip)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn() {
                        Ok(child) => child,
                        Err(e) => return Err(format!("Failed to execute ping: {}", e).into()),
                    };
                
                // Read stdout line by line
                if let Some(stdout) = child.stdout.take() {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        match line {
                            Ok(l) => println!("{}", l),
                            Err(_) => println!("Error reading output"),
                        }
                    }
                }
                
                // Wait for the process to finish
                let status = match child.wait() {
                    Ok(status) => status,
                    Err(e) => return Err(format!("Failed to wait for ping process: {}", e).into()),
                };
    
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("Ping to {} failed.", ip).into())
                }
            } else {
                Err("Invalid syntax. Usage: ping <ip>".into())
            }
        },
    });
    
    commands.insert("traceroute", Command {
        name: "traceroute",
        description: "Trace the route to a specific IP address or hostname",
        suggestions: None,
        suggestions1: None,
        suggestions2: None,
        options: Some(vec!["<ip-address/hostname>    - Enter the IP address or hostname"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let target = args[0].to_string();
    
                println!("Tracing route to {} over a maximum of 30 hops", target);
    
                // Run the traceroute command directly
                let output = match std::process::Command::new("traceroute")
                    .args(["-n", "-m", "30", &target])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn() {
                        Ok(mut child) => {
                            // Stream output in real-time
                            if let Some(stdout) = child.stdout.take() {
                                let mut reader = std::io::BufReader::new(stdout);
                                let mut line = String::new();
    
                                // Process and print output in real-time
                                use std::io::BufRead;
                                while let Ok(bytes) = reader.read_line(&mut line) {
                                    if bytes == 0 {
                                        break;
                                    }
                                    print!("{}", line);
                                    line.clear();
                                }
                            }
    
                            // Wait for the child process to finish
                            match child.wait() {
                                Ok(status) => {
                                    if status.success() {
                                        println!("Trace complete.");
                                        Ok(())
                                    } else {
                                        Err(format!("Traceroute to {} failed with status: {}", target, status).into())
                                    }
                                },
                                Err(e) => Err(format!("Error waiting for process: {}", e).into())
                            }
                        },
                        Err(e) => Err(format!("Failed to execute traceroute: {}", e).into())
                    };
    
                output
            } else {
                Err("Invalid syntax. Usage: traceroute <ip/hostname>".into())
            }
        },
    });


    commands
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
