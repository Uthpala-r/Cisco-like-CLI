/// A structure for the custom clock in the CLI.
/// 
/// This struct holds the date and time as strings in a specific format
pub struct CustomClock {
    pub date: String,
    pub time: String,
}


pub fn handle_clock_set(input: &str, clock: &mut CustomClock) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() < 4 {
        println!("Usage: clock set <date> <time>");
        return;
    }
    clock.date = parts[2].to_string();
    clock.time = parts[3].to_string();
    println!("Clock set to: {} {}", clock.date, clock.time);
}


pub fn handle_show_clock(clock: &CustomClock) {
    println!("Current clock: {} {}", clock.date, clock.time);
}
