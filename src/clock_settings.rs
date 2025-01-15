use chrono::{DateTime, Local, NaiveDateTime, Duration};

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
    custom_datetime: Option<DateTime<Local>>,
    start_time: DateTime<Local>,  
    device_model: String,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            time: String::new(),
            date: String::new(),
            custom_datetime: None,
            start_time: Local::now(),  
            device_model: "PNF".to_string(),
        }
    }

    pub fn set_time(&mut self, time: &str) -> Result<(), String> {
        if !time.contains(':') || time.split(':').count() != 3 {
            return Err("Invalid time format. Expected HH:MM:SS".to_string());
        }
        
        let parts: Vec<&str> = time.split(':').collect();
        let (hours, minutes, seconds) = (
            parts[0].parse::<u32>().map_err(|_| "Invalid hours")?,
            parts[1].parse::<u32>().map_err(|_| "Invalid minutes")?,
            parts[2].parse::<u32>().map_err(|_| "Invalid seconds")?
        );
        
        if hours >= 24 || minutes >= 60 || seconds >= 60 {
            return Err("Invalid time values".to_string());
        }

        // Always update the time string
        self.time = time.to_string();

        // Try to update custom_datetime if we have a date
        self.update_custom_datetime();
        
        Ok(())
    }

    pub fn set_date(&mut self, day: u8, month: &str, year: u16) -> Result<(), String>  {
        let max_days = match month {
            "February" => if year % 4 == 0 { 29 } else { 28 },
            "April" | "June" | "September" | "November" => 30,
            _ => 31
        };

        if day == 0 || day > max_days {
            return Err(format!("Invalid day {} for month {}", day, month));
        }

        // Always update the date string
        self.date = format!("{} {} {}", day, month, year);

        // Try to update custom_datetime if we have a time
        self.update_custom_datetime();
        
        Ok(())
    }

    pub fn update_custom_datetime(&mut self) {
        if !self.time.is_empty() && !self.date.is_empty() {
            if let Ok(naive_time) = NaiveDateTime::parse_from_str(
                &format!("{} {}", self.date, self.time),
                "%d %B %Y %H:%M:%S"
            ) {
                self.custom_datetime = Some(DateTime::from_naive_utc_and_offset(
                    naive_time,
                    Local::now().offset().clone()
                ));
            }
        }
    }

    pub fn get_current_datetime(&self) -> DateTime<Local> {
        self.custom_datetime.unwrap_or_else(Local::now)
    }

    pub fn get_uptime(&self) -> Duration {
        Local::now().signed_duration_since(self.start_time)
    }

    pub fn format_uptime(&self) -> String {
        let duration = self.get_uptime();
        let total_seconds = duration.num_seconds();
        
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;

        format!("{} uptime is {} hours, {} minutes, {} seconds",
            self.device_model,
            hours,
            minutes,
            seconds
        )
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
pub fn handle_clock_set(time: &str, day: u8, month: &str, year: u16, clock: &mut Clock) -> Result<(), String> {
    if !time.is_empty() {
        clock.set_time(time)?;
    }
    if day != 0 {
        clock.set_date(day, month, year)?;
    }
    
    println!("Clock updated successfully to {} {} {} {}.", time, day, month, year);
    Ok(())

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

    if parts.len() < 5 {
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
    let current = clock.get_current_datetime();
    println!(
        "Current clock: {} {}",
        current.format("%d %B %Y"),
        current.format("%H:%M:%S")
    );
}


/// Handles the display of the system's uptime.
///
/// This function retrieves the system uptime from the provided [`Clock`] instance
/// and prints the formatted uptime to the standard output.
///
/// # Arguments
///
/// * `clock` - A reference to a [`Clock`] instance used to fetch and format the system's uptime.
///
/// # Example
///
/// ```
/// let clock = Clock::new();
/// handle_show_uptime(&clock);
/// ```
///
/// # See Also
///
/// * [`Clock::format_uptime`]: The method used to format the uptime.
pub fn handle_show_uptime(clock: &Clock) {
    println!("{}", clock.format_uptime());
}
