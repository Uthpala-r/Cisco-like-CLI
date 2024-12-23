/// A structure representing the custom clock in the CLI.
///
/// This struct is used to store the date and time as strings in a specific format.
///
/// # Fields
/// - `date`: A string representing the current date.
/// - `time`: A string representing the current time.
///
/// # Examples
/// ```
/// let clock = CustomClock {
///     date: "2024-06-01".to_string(),
///     time: "12:00".to_string(),
/// };
/// assert_eq!(clock.date, "2024-06-01");
/// assert_eq!(clock.time, "12:00");
/// ```
/// 
pub struct CustomClock {
    pub date: String,
    pub time: String,
}


/// Handles the `clock set` command to update the date and time in the `CustomClock` structure.
///
/// This function takes an input string in the format `clock set <date> <time>`
/// and updates the provided `CustomClock` instance with the new values.
///
/// # Arguments
/// - `input`: A string slice containing the command and parameters.
/// - `clock`: A mutable reference to the `CustomClock` instance to update.
///
/// # Usage
/// ```
/// let mut clock = CustomClock {
///     date: "2024-06-01".to_string(),
///     time: "12:00".to_string(),
/// };
/// handle_clock_set("clock set 2024-12-25 08:30", &mut clock);
/// assert_eq!(clock.date, "2024-12-25");
/// assert_eq!(clock.time, "08:30");
/// ```
///
/// # Errors
/// Prints a usage message if the input is not in the expected format.
/// 
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


/// Handles the `show clock` command to display the current date and time stored in the `CustomClock` structure.
///
/// # Arguments
/// - `clock`: A reference to the `CustomClock` instance whose date and time are to be displayed.
///
/// # Usage
/// ```
/// let clock = CustomClock {
///     date: "2024-06-01".to_string(),
///     time: "12:00".to_string(),
/// };
/// handle_show_clock(&clock);
/// // Output: Current clock: 2024-06-01 12:00
/// ```
pub fn handle_show_clock(clock: &CustomClock) {
    println!("Current clock: {} {}", clock.date, clock.time);
}
