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
    pub static ref NETWORK_STATE: Arc<Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();

        // Default interface and its configuration
        let default_interface = "ens33".to_string();
        let default_ip = Ipv4Addr::from_str("192.168.253.135").expect("Invalid IP address format");
        let default_broadcast = calculate_broadcast(default_ip, 24);
        
        map.insert(default_interface, (default_ip, default_broadcast));
        
        map
    }));
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

