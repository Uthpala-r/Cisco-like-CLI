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
/// let clock = Clock {
///     date: "2024-06-01".to_string(),
///     time: "12:00".to_string(),
/// };
/// assert_eq!(clock.date, "2024-06-01");
/// assert_eq!(clock.time, "12:00");
/// ```
/// 
pub struct Clock {
    pub time: String,
    pub date: String,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            time: String::new(),
            date: String::new(),
        }
    }

    pub fn set_time(&mut self, time: &str) {
        self.time = time.to_string();
    }

    pub fn set_date(&mut self, day: u8, month: &str, year: u16) {
        self.date = format!("{} {} {}", day, month, year);
    }
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
pub fn handle_clock_set(time: &str, day: u8, month: &str, year: u16, clock: &mut Clock) {
    clock.set_time(time);
    clock.set_date(day, month, year);

    println!("Clock updated successfully to {} {} {} {}.", time, day, month, year);
}


/// Parses a clock set command input and validates its components.
///
/// This function takes a command input string in the format `clock set <hh:mm:ss> <day> <month> <year>`,
/// splits the string into parts, validates each part, and returns the parsed time, day, month, and year 
/// as a tuple. If the input is invalid, it returns an error message.
///
/// # Arguments
/// 
/// * `input` - A string slice representing the clock set command. The expected format is:
///   `"clock set <hh:mm:ss> <day> <month> <year>"`.
/// 
/// # Returns
/// 
/// * `Ok` - A tuple with the parsed time (as `&str`), day (as `u8`), month (as `&str`), and year (as `u16`).
/// * `Err` - A `String` containing an error message if any part of the input is invalid.
///
/// # Errors
/// 
/// This function can return errors for:
/// * An incomplete command with fewer than 4 parts.
/// * An invalid time format (does not contain `:` or not in `hh:mm:ss` format).
/// * An invalid day (not between 1 and 31).
/// * An invalid month (not a valid month name).
/// * An invalid year (not between 1993 and 2035).
/// 
/// # Example
/// 
/// ```rust
/// let input = "clock set 12:30:45 15 January 2025";
/// let result = parse_clock_set_input(input);
/// assert_eq!(result, Ok(("12:30:45", 15, "January", 2025)));
/// ```
pub fn parse_clock_set_input(input: &str) -> Result<(&str, u8, &str, u16), String> {

    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 4 {
        return Err("Incomplete command. Usage: clock set <hh:mm:ss> <day> <month> <year>".to_string());
    }

    let time = parts[1];
    if !time.contains(':') || time.split(':').count() != 3 {
        return Err("Invalid time format. Expected hh:mm:ss.".to_string());
    }

    let day: u8 = parts[2].parse().map_err(|_| "Invalid day. Expected a number between 1 and 31.".to_string())?;
    if !(1..=31).contains(&day) {
        return Err("Invalid day. Expected a number between 1 and 31.".to_string());
    }

    let month = parts[3];
    let valid_months = [
        "January", "February", "March", "April", "May", "June", "July", "August", "September",
        "October", "November", "December",
    ];
    if !valid_months.contains(&month) {
        return Err("Invalid month. Expected a valid month name.".to_string());
    }

    let year: u16 = parts[4].parse().map_err(|_| "Invalid year. Expected a number between 1993 and 2035.".to_string())?;
    if !(1993..=2035).contains(&year) {
        return Err("Invalid year. Expected a number between 1993 and 2035.".to_string());
    }

    Ok((time, day, month, year))
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
pub fn handle_show_clock(clock: &Clock) {
    println!("Current clock: {} {}", clock.date, clock.time);
}
