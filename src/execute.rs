//execute.rs

/// External crates for the CLI application
use std::collections::{HashMap, HashSet};
use crate::Clock;
use crate::CliContext;
use crate::commandcompleter::{CommandCompleter};

/// Represents a command that can be executed in the CLI.
///
/// The `Command` struct defines the properties and behavior of a CLI command. Each command includes 
/// metadata, such as its name and description, along with the logic for its execution.
///
/// # Fields
/// - `name`:  
///   The name of the command as a static string. This is the keyword used to invoke the command in the CLI.
///
/// - `description`:  
///   A brief description of the command's purpose or functionality, displayed in help menus.
///
/// - `suggestions`:  
///   An optional list of related or commonly used commands that can be suggested to the user.  
///   If `None`, no suggestions will be provided for the command.
///
/// - `execute`:  
///   A function pointer defining the command's logic. This function is executed when the command is invoked.  
///   It accepts the following arguments:
///     - `&[&str]`: The list of arguments provided with the command.
///     - `&mut CliContext`: The current CLI context, including mode, configuration, and state.
///     - `&mut Option<Clock>`: An optional mutable reference to the clock, allowing the command to manipulate system time settings if needed.  
///   Returns a `Result<(), String>`, where `Ok(())` indicates success and `Err(String)` contains an error message if execution fails.
pub struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub suggestions: Option<Vec<&'static str>>,
    pub suggestions1: Option<Vec<&'static str>>,
    pub options: Option<Vec<&'static str>>,
    pub execute: fn(&[&str], &mut CliContext, &mut Option<Clock>) -> Result<(), String>,
}


/// Represents the various operational modes for the CLI.
///
/// The `Mode` enum defines the hierarchical modes of operation in the CLI, allowing commands to be executed 
/// based on the current context. Each mode corresponds to a specific configuration or operational level.
///
/// # Variants
/// - `UserMode`:  
///   Represents the basic user mode with limited commands, primarily for non-privileged tasks.
/// - `PrivilegedMode`:  
///   Represents the privileged mode, providing access to higher-level configuration and operational commands.
/// - `ConfigMode`:  
///   Represents the global configuration mode where system-wide settings can be modified.
/// - `InterfaceMode`:  
///   Represents the interface configuration mode for managing individual network interfaces.
/// - `VlanMode`:  
///   Represents the VLAN configuration mode for managing VLANs.
/// - `RouterConfigMode`:  
///   Represents the router configuration mode for managing routing protocols such as OSPF or BGP.
/// - `ConfigStdNaclMode(String)`:  
///   Represents the configuration mode for standard Access Control Lists (ACLs). The `String` parameter 
///   specifies the ACL name or ID.
/// - `ConfigExtNaclMode(String)`:  
///   Represents the configuration mode for extended Access Control Lists (ACLs). The `String` parameter 
///   specifies the ACL name or ID.
///
/// # Example
/// ```rust
/// let mode = Mode::UserMode;
/// match mode {
///     Mode::UserMode => println!("In user mode"),
///     Mode::PrivilegedMode => println!("In privileged mode"),
///     Mode::ConfigMode => println!("In configuration mode"),
///     Mode::InterfaceMode => println!("In interface configuration mode"),
///     Mode::VlanMode => println!("In VLAN configuration mode"),
///     Mode::RouterConfigMode => println!("In router configuration mode"),
///     Mode::ConfigStdNaclMode(acl) => println!("Configuring standard ACL: {}", acl),
///     Mode::ConfigExtNaclMode(acl) => println!("Configuring extended ACL: {}", acl),
/// }
/// ```
#[derive(Clone, Debug)]
pub enum Mode {
    UserMode,
    PrivilegedMode,
    ConfigMode,
    InterfaceMode,
    VlanMode,
    RouterConfigMode,
    ConfigStdNaclMode(String),
    ConfigExtNaclMode(String),
}


/// Executes a given command in the CLI, handling suggestions and command execution.
///
/// The function processes the user's input to either show possible command completions
/// (when a '?' is used) or execute a command with its arguments. It also handles different
/// modes (e.g., user mode, privileged mode) to filter available commands accordingly.
///
/// # Arguments
/// - `input`: A string representing the user's input command (possibly with arguments or suggestions).
/// - `commands`: A `HashMap` containing all available commands, where the key is the command name
///   and the value is a `Command` struct representing the command's metadata and execution logic.
/// - `context`: A mutable reference to the `CliContext` that holds the current CLI state and mode.
/// - `clock`: A mutable reference to an optional `Clock`, which may be used by some commands for time-related operations.
/// - `completer`: A mutable reference to `CommandCompleter` which can be used for auto-completion of commands.
///
/// # Notes
/// - If the input ends with a `?`, the function will display possible command completions based on
///   the available commands for the current mode or show subcommand suggestions for a specific command.
/// - If no `?` is present, the function will attempt to execute the command, passing any additional
///   arguments to the command's `execute` function.
///
/// # Example
/// ```rust
/// let mut context = CliContext::new(Mode::UserMode);
/// let mut clock: Option<Clock> = None;
/// let mut completer = CommandCompleter::new();
/// let commands = HashMap::new(); // A filled HashMap of commands
///
/// // Example input with suggestions
/// execute_command("configure ?", &commands, &mut context, &mut clock, &mut completer);
/// 
/// // Example command execution
/// execute_command("ping 8.8.8.8", &commands, &mut context, &mut clock, &mut completer);
/// ```
///
/// # Errors
/// - If an ambiguous or unrecognized command is entered, a message will be printed indicating the error.
/// - If the command requires additional arguments or subcommands, appropriate messages will be shown.
/// - Errors encountered during command execution will be printed.
pub fn execute_command(input: &str, commands: &HashMap<&str, Command>, context: &mut CliContext, clock: &mut Option<Clock>, completer: &mut CommandCompleter) {
    let mut normalized_input = input.trim();
    let showing_suggestions = normalized_input.ends_with('?');
    
    // If we're showing suggestions, remove the '?' for further processing
    if showing_suggestions {
        normalized_input = normalized_input.trim_end_matches('?');
    }

    // Get available commands for current mode
    fn get_mode_commands<'a>(commands: &'a HashMap<&str, Command>, mode: &Mode) -> Vec<&'a str> {
        match mode {
            Mode::UserMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "enable" ||
                        cmd == "ping" ||
                        cmd == "help" ||
                        cmd == "show" ||
                        cmd == "clear" ||
                        cmd == "reload" ||
                        cmd == "exit"
                    })
                    .copied()
                    .collect()
            },
            Mode::PrivilegedMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "configure" ||
                        cmd == "ping" || 
                        cmd == "exit" || 
                        cmd == "write" ||
                        cmd == "help" ||
                        cmd == "show" ||
                        cmd == "copy" ||
                        cmd == "clock" ||
                        cmd == "clear" ||
                        cmd == "reload" ||
                        cmd == "debug" ||
                        cmd == "undebug" ||
                        cmd == "ifconfig"
                        
                    })
                    .copied()
                    .collect()
            },
            Mode::ConfigMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "hostname" || 
                        cmd == "interface" ||
                        cmd == "ping" ||
                        cmd == "exit" ||
                        cmd == "clear" ||
                        cmd == "tunnel" ||
                        cmd == "access-list" ||
                        cmd == "router" ||
                        cmd == "virtual-template" ||
                        cmd == "help" ||
                        cmd == "write" ||
                        cmd == "vlan" ||
                        cmd == "ip" ||
                        cmd == "service" ||
                        cmd == "set" ||
                        cmd == "enable" ||
                        cmd == "ifconfig" ||  
                        cmd == "ntp" ||
                        cmd == "no" || 
                        cmd == "reload" ||
                        cmd == "crypto"
                    })
                    .copied()
                    .collect()
            },
            Mode::InterfaceMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "shutdown" ||
                        cmd == "no" ||
                        cmd == "exit" ||
                        cmd == "clear" ||
                        cmd == "help" ||
                        cmd == "switchport" ||
                        cmd == "write" ||
                        cmd == "reload" ||
                        cmd == "ip" 

                    })
                    .copied()
                    .collect()
            }
            Mode::VlanMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "name" ||
                        cmd == "state" ||
                        cmd == "clear" ||
                        cmd == "exit" ||
                        cmd == "help" ||
                        cmd == "reload" ||
                        cmd == "vlan" 

                    })
                    .copied()
                    .collect()
            }
            Mode::RouterConfigMode => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "network" ||
                        cmd == "neighbor" ||
                        cmd == "exit" ||
                        cmd == "clear" ||
                        cmd == "area" ||
                        cmd == "passive-interface" ||
                        cmd == "distance" ||
                        cmd == "help" ||
                        cmd == "reload" ||
                        cmd == "default-information" ||
                        cmd == "router-id"

                    })
                    .copied()
                    .collect()
            }
            Mode::ConfigStdNaclMode(_) => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "deny" ||
                        cmd == "permit" ||
                        cmd == "help" ||
                        cmd == "exit" ||
                        cmd == "clear" ||
                        cmd == "reload" ||
                        cmd == "ip"

                    })
                    .copied()
                    .collect()
            }
            Mode::ConfigExtNaclMode(_) => {
                commands.keys()
                    .filter(|&&cmd| {
                        cmd == "deny" ||
                        cmd == "permit" ||
                        cmd == "help" ||
                        cmd == "exit" ||
                        cmd == "clear" ||
                        cmd == "reload" ||
                        cmd == "ip"

                    })
                    .copied()
                    .collect()
            }

        }
    }

    // Function to find a unique command match
    fn find_unique_command<'a>(partial: &str, available_commands: &[&'a str]) -> Option<&'a str> {
        let matches: Vec<&str> = available_commands
            .iter()
            .filter(|&&cmd| cmd.starts_with(partial))
            .copied()
            .collect();

        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    }

    // Function to find a unique subcommand match
    fn find_unique_subcommand<'a>(partial: &str, suggestions: &'a [&str]) -> Option<&'a str> {
        let matches: Vec<&str> = suggestions
            .iter()
            .filter(|&&s| s.starts_with(partial))
            .copied()
            .collect();

        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    }

     
    let parts: Vec<&str> = normalized_input.split_whitespace().collect();
   
    let available_commands = get_mode_commands(commands, &context.current_mode);

    // Handle suggestions if '?' was present
    if showing_suggestions {
        match parts.len() {
            0 => {
                // Handle single word with ? (e.g., "?")
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
                
            },            
            1 => {
                let command_name = parts[0].trim();
                // Handle single word with ? (e.g., "configure ?")
                let available_commands = get_mode_commands(commands, &context.current_mode);
                if available_commands.contains(&command_name) {
                    // If it's an exact command match, show its subcommands
                    if let Some(cmd) = commands.get(command_name) {
                        if let Some(suggestions) = &cmd.suggestions1 {
                            println!("Possible completions:");
                            for suggestion in suggestions {
                                println!("  {}", suggestion);
                            }
                        } else if let Some(options) = &cmd.options {
                            // Fall back to options if no suggestions1 are available
                            println!("Possible completions:");
                            for option in options {
                                println!("  {}", option);
                            }
                        } else {
                            println!("No subcommands or more options available");
                        }
                    }
                } else {
                    // If it's a partial command, show matching commands
                    let suggestions: Vec<&str> = available_commands
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(command_name))
                        .collect();

                    if !suggestions.is_empty() {
                        println!("Possible completions for '{}?':", command_name);
                        for suggestion in suggestions {
                            println!("  {}", suggestion);
                        }
                    } else {
                        if let Some(cmd) = commands.get(parts[0]) {
                            if let Some(options) = &cmd.options {
                                println!("Possible completions:");
                                for option in options {
                                    println!("  {}", option);
                                }
                            } else {
                                println!("No more options available");
                            }
                        }
                    }
                }
            },
            2 => {
                // Command with partial subcommand (e.g., "configure t?", "configure term?")
                let available_commands = get_mode_commands(commands, &context.current_mode);
                if available_commands.contains(&parts[0]) && !normalized_input.ends_with(' ') {
                    if let Some(cmd) = commands.get(parts[0]) {
                        if let Some(suggestions) = &cmd.suggestions1 {
                            let partial = parts[1];
                            let matching: Vec<&str> = suggestions
                                .iter()
                                .filter(|&&s| s.starts_with(partial))
                                .map(|&s| s)
                                .collect();

                            if !matching.is_empty() {
                                println!("Possible completions:");
                                for suggestion in matching {
                                    println!("  {}", suggestion);
                                }
                            } else {
                                println!("No matching commands found");
                            }
                        } else {
                            println!("No subcommands available");
                        }
                    }
                } else {
                    if let Some(cmd) = commands.get(parts[0]) {
                        if let Some(options) = &cmd.options {
                            println!("Possible completions:");
                            for option in options {
                                println!("  {}", option);
                            }
                        } else {
                            println!("No more options available");
                            //(cmd.execute)(&parts[1..], context, clock);
                        }
                    }
                }
            },
            _ => {
                // Full command with ? (e.g., "configure terminal ?")
                println!("No additional parameters available");
            }
        }
        return;
    }

    // Handle command execution (when no '?' is present)
    let cmd_key = if let Some(matched_cmd) = find_unique_command(parts[0], &available_commands) {
        matched_cmd
    } else {
        println!("Ambiguous command or command not available in current mode: {}", parts[0]);
        return;
    };

    if let Some(cmd) = commands.get(cmd_key) {
        if let Some(suggestions) = &cmd.suggestions1 {
            match parts.len() {
                1 => {
                    println!("Incomplete command. Subcommand required.");
                    //(cmd.execute)(&parts[1..], context, clock);
                }
                2 => {
                    if suggestions.is_empty() {
                        if let Err(err) = (cmd.execute)(&parts[1..], context, clock) {
                            println!("Error: {}", err);
                        }
                    } else {
                        // For commands with specific subcommands, require a match
                        if let Some(matched_subcommand) = find_unique_subcommand(parts[1], suggestions) {
                            if let Err(err) = (cmd.execute)(&[matched_subcommand], context, clock) {
                                println!("Error: {}", err);
                            }
                        } else {
                            println!("Ambiguous or invalid subcommand: {}", parts[1]);
                        }
                    }
                }
                _ => {
                    if let Err(err) = (cmd.execute)(&parts[1..], context, clock) {
                        println!("Error: {}", err);
                    }
                }
            }
        } else {
            if let Err(err) = (cmd.execute)(&parts[1..], context, clock) {
                println!("Error: {}", err);
            }
        }
    }
}