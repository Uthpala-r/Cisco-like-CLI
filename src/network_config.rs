use std::str::FromStr;
use std::net::Ipv4Addr;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;

pub struct InterfaceConfig {
    pub ip_address: Ipv4Addr,  
    pub is_up: bool,  
}


lazy_static::lazy_static! {
    pub static ref NETWORK_STATE: Arc<Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();

        let default_interface = "ens33".to_string();
        let default_ip = Ipv4Addr::from_str("192.168.253.135").expect("Invalid IP address format");
        let default_broadcast = calculate_broadcast(default_ip, 24);
        
        map.insert(default_interface, (default_ip, default_broadcast));
        
        map
    }));
}

pub fn calculate_broadcast(ip: Ipv4Addr, prefix_len: u32) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let mask = !0 << (32 - prefix_len);
    let broadcast_u32 = ip_u32 | !mask;
    Ipv4Addr::from(broadcast_u32)
}

