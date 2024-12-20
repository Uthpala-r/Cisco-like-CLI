use std::str::FromStr;
use std::net::Ipv4Addr;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;


lazy_static::lazy_static! {
    pub static ref NETWORK_STATE: Arc<Mutex<HashMap<String, (Ipv4Addr, Ipv4Addr)>>> = Arc::new(Mutex::new({
        let mut map = HashMap::new();

        let default_interface = "ens33".to_string();
        let default_ip = Ipv4Addr::from_str("192.168.253.135").expect("Invalid IP address format");
        let default_broadcast = Ipv4Addr::from_str("192.168.253.255").expect("Invalid broadcast address");
        
        map.insert(default_interface, (default_ip, default_broadcast));
        
        map
    }));
}