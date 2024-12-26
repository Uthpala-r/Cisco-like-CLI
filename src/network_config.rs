/// External crates for the CLI application
use std::str::FromStr;
use std::net::Ipv4Addr;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;


/// Represents the configuration of a network interface.
/// 
/// # Fields
/// - `ip_address`: The IPv4 address of the interface.
/// - `is_up`: A boolean indicating whether the interface is active.
pub struct InterfaceConfig {
    pub ip_address: Ipv4Addr,  
    pub is_up: bool,  
}


lazy_static::lazy_static! {

    /// A thread-safe, globally accessible state that stores network interface configurations.
    /// 
    /// The `NETWORK_STATE` is an `Arc<Mutex<HashMap>>` where:
    /// - The key is the name of the interface (e.g., "ens33").
    /// - The value is a tuple containing:
    ///     - The IPv4 address of the interface.
    ///     - The broadcast address for the interface, calculated based on the subnet prefix length.
    /// 
    /// By default, the `ens33` interface is initialized with the IP `192.168.253.135` 
    /// and a subnet prefix of 24.
    /// 
    pub static ref IFCONFIG_STATE: Arc<Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();

        // Default interface and its configuration
        let default_interface = "ens33".to_string();
        let default_ip = Ipv4Addr::from_str("192.168.253.135").expect("Invalid IP address format");
        let default_broadcast = calculate_broadcast(default_ip, 24);
        
        map.insert(default_interface, (default_ip, default_broadcast));
        
        map
    }));

    
    /// A thread-safe global map that tracks the administrative status of network interfaces.
    ///
    /// # Description
    /// `STATUS_MAP` is a `HashMap` wrapped in an `Arc<Mutex<...>>`, allowing
    /// safe concurrent access and modification. Each key in the map represents
    /// the name of a network interface (e.g., `"ens33"`), and the value is a
    /// `bool` indicating whether the interface is administratively up (`true`)
    /// or administratively down (`false`).
    ///
    /// # Default Behavior
    /// By default, the map is initialized with the `ens33` interface set to
    /// `false` (administratively down). You can modify the default setup
    /// based on your requirements.
    ///
    /// # Thread Safety
    /// The use of `Arc<Mutex<...>>` ensures that multiple threads can safely
    /// access and modify the map, avoiding race conditions.
    pub static ref STATUS_MAP: Arc<Mutex<HashMap<String, bool>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();
    
        // Default interface status (administratively down)
        map.insert("ens33".to_string(), false); // Modify as per your setup
    
        map
    }));

    /// A global, thread-safe state that holds the configuration of network interfaces 
    /// updated via the `ip address` command.
    ///
    /// The `IP_ADDRESS_STATE` is a `Mutex`-protected `HashMap` where:
    /// - The key (`String`) represents the name of the network interface (e.g., `g0/0`).
    /// - The value is a tuple containing:
    ///   - The IP address assigned to the interface (`Ipv4Addr`).
    ///   - The broadcast address derived from the IP and subnet mask (`Ipv4Addr`).
    ///
    /// This state ensures safe concurrent access to the configuration of interfaces 
    /// updated using the `ip address` command. Other commands like `show interfaces`
    /// rely on this data to display the status of the configured interfaces.
    ///
    /// This structure ensures separation from other interface management commands 
    /// like `ifconfig`, which uses its own state (`IFCONFIG_STATE`).
    pub static ref IP_ADDRESS_STATE: Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>> = Mutex::new(HashMap::new());


    /// A global, thread-safe container for storing static routing information.
    ///
    /// This `Mutex<HashMap<String, (Ipv4Addr, String)>>` is used to hold the static routes in a routing table, 
    /// where the key is the destination IP address (as a string) and the value is a tuple containing:
    /// - the network mask (`Ipv4Addr`), 
    /// - the next-hop IP address or the exit interface (stored as a `String`).
    /// 
    /// It is wrapped in a `Mutex` to ensure safe, mutable access from multiple threads.
    pub static ref ROUTE_TABLE: Mutex<HashMap<String, (Ipv4Addr, String)>> = Mutex::new(HashMap::new());


    pub static ref OSPF_CONFIG: Mutex<OSPFConfig> = Mutex::new(OSPFConfig::new());

}


/// Calculates the broadcast address for a given IPv4 address and subnet prefix length.
/// 
/// # Parameters
/// - `ip`: The IPv4 address of the interface.
/// - `prefix_len`: The subnet prefix length (e.g., 24 for a 255.255.255.0 mask).
/// 
/// # Returns
/// - The broadcast address as an `Ipv4Addr`.
/// 
/// # Example
/// ```
/// use std::net::Ipv4Addr;
/// let ip = Ipv4Addr::new(192, 168, 1, 1);
/// let prefix_len = 24;
/// let broadcast = calculate_broadcast(ip, prefix_len);
/// assert_eq!(broadcast, Ipv4Addr::new(192, 168, 1, 255));
/// ```
pub fn calculate_broadcast(ip: Ipv4Addr, prefix_len: u32) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);             // Convert the IP address to a 32-bit integer
    let mask = !0 << (32 - prefix_len);     // Create the subnet mask
    let broadcast_u32 = ip_u32 | !mask;     // Calculate the broadcast address
    Ipv4Addr::from(broadcast_u32)           // Convert back to an Ipv4Addr
}


#[derive(Debug, Clone)]
pub struct OSPFConfig {
    pub passive_interfaces: Vec<String>,
    pub distance: Option<u32>,
    pub default_information_originate: bool,
    pub router_id: Option<String>,
    pub areas: HashMap<String, AreaConfig>,
    pub networks: HashMap<String, u32>,
    pub neighbors: HashMap<Ipv4Addr, Option<u32>>,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AreaConfig {
    pub authentication: bool,
    pub stub: bool,
    pub default_cost: Option<u32>,
}

impl OSPFConfig {
    pub fn new() -> Self {
        Self {
            passive_interfaces: Vec::new(),
            distance: None,
            default_information_originate: false,
            router_id: None,
            areas: HashMap::new(),
            networks: HashMap::new(),
            neighbors: HashMap::new(),
            process_id: None,
        }
    }
}


