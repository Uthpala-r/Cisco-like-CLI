/// External crates for the CLI application
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::File;
use std::io::{self, Write, BufRead};
//use std::io;
use std::str::FromStr;
use rpassword::read_password;
use std::process::Command as ProcessCommand;

use crate::run_config::{get_running_config, default_startup_config};
//use crate::run_config::load_config;
use crate::execute::Command;
use crate::execute::Mode;
use crate::clock_settings::{handle_clock_set, parse_clock_set_input, handle_show_clock, handle_show_uptime};
use crate::network_config::{calculate_broadcast, IFCONFIG_STATE, ROUTE_TABLE, ACL_STORE, encrypt_password, PASSWORD_STORAGE, set_enable_password, set_enable_secret};
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

    commands.insert("connect", Command {
        name: "connect",
        description: "Connect to network processor or crypto module",
        suggestions: Some(vec!["network", "crypto"]),
        suggestions1: Some(vec!["network", "crypto"]),
        options: None,
        execute: |args, context, _| {    
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
        options: None,
        execute: |_args, context, _| {
            if _args.is_empty() {
                match context.current_mode {
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
        description: "Exit the Privileged EXEC mode.",
        suggestions: None,
        suggestions1: None,
        options: None,
        execute: |_args, context, _| {
            if _args.is_empty() {
                match context.current_mode {
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
                "version",
                "ntp",
                "processes",
                "clock",
                "uptime",
                "controllers",
                "history",
                "sessions",
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
                "login"
            ]),
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
                        Some(&"history") if matches!(context.current_mode, Mode::UserMode) => {
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
        "write",
        Command {
            name: "write memory",
            description: "Save the running configuration to the startup configuration",
            suggestions: Some(vec!["memory"]),
            suggestions1: Some(vec!["memory"]),
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
            options: Some(vec!["startup-config"]),
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
        "no",
        Command {
            name: "no shutdown",
            description: "Enable the selected network interface.",
            suggestions: Some(vec!["shutdown", "ntp"]),
            suggestions1: Some(vec!["shutdown", "ntp"]),
            options: None,
            execute: |args, context, _| {
                if args.len() == 3 && args[0] == "ntp" && args[1] == "server" {
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
        description: "Clear the terminal",
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
            
            } else {
                Err("The 'clear ip ospf process' command is only available in EXEC mode.".into())
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
            options: Some(vec![
                "-v           - Display SSH version",
                "-l           - Login to remote server (usage: ssh -l <username>@<ip-address>)",
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
    
    commands.insert("traceroute", Command {
        name: "traceroute",
        description: "Trace the route to a specific IP address or hostname",
        suggestions: None,
        suggestions1: None,
        options: Some(vec!["<ip-address/hostname>    - Enter the IP address or hostname"]),
        execute: |args, _context, _| {
            if args.len() == 1 {
                let target: String = args[0].to_string();
                println!("\nTracing route to {} over a maximum of 30 hops\n", target);
                
                // Simulated route table with known hops
                let route_hops = vec![
                    ("172.16.0.5", true),
                    ("192.168.0.50", true),
                    ("122.56.168.186", true),
                    ("122.56.99.240", true),
                    ("122.56.99.243", true),
                    ("122.56.116.6", true),
                    ("122.56.116.5", true),
                    ("0.0.0.0", false),  // Timeout simulation
                    ("0.0.0.0", false),  // Timeout simulation
                ];
    
                // Print header spacing for the columns
                println!("  {:3} {:8} {:8} {:8} {}", 
                    "Hop", "Time 1", "Time 2", "Time 3", "Address");
                println!("  {}", "-".repeat(70));
    
                for (hop_num, (ip, reachable)) in route_hops.iter().enumerate() {
                    if *reachable {
                        // Generate random response times between 1-20ms for variation
                        let time1 = rand::random::<u8>() % 20 + 1;
                        let time2 = rand::random::<u8>() % 20 + 1;
                        let time3 = rand::random::<u8>() % 20 + 1;
                        
                        println!("  {:3} {:4}ms   {:4}ms   {:4}ms   {}", 
                            hop_num + 1,
                            time1,
                            time2,
                            time3,
                            ip
                        );
                    } else {
                        // Print timeout for unreachable hops
                        println!("  {:3} {:8} {:8} {:8} {}", 
                            hop_num + 1,
                            "*", "*", "*",
                            "Request timed out."
                        );
                    }
                }
    
                if route_hops.iter().any(|(_, reachable)| *reachable) {
                    Ok(())
                } else {
                    Err(format!("Unable to trace route to {}", target).into())
                }
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
