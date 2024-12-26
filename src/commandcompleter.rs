/// External crates for the CLI application
use crate::build_command_registry;

use rustyline::hint::Hinter;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::validate::{Validator, ValidationContext, ValidationResult};
use rustyline::error::ReadlineError;
use std::collections::HashMap;


/// A custom completer for the CLI application.
///
/// The `CommandCompleter` provides suggestions for commands based on user input.
/// It integrates with the `rustyline` crate to offer real-time command-line assistance.
///
/// # Fields
/// - `commands`: A vector of strings containing the list of available commands.
/// 
pub struct CommandCompleter {
    /// A list of all available commands for auto-completion.
    pub commands: HashMap<String, Vec<String>>,
}


impl Completer for CommandCompleter {
    type Candidate = Pair;

    /// Generates a list of command suggestions based on the current user input.
    ///
    /// # Arguments
    /// - `line`: The current input line from the user.
    /// - `pos`: The cursor position within the line.
    /// - `_ctx`: The rustyline context.
    ///
    /// # Returns
    /// A tuple where:
    /// - The first element is the starting position of the match in the input line.
    /// - The second element is a vector of `Pair` objects representing the suggestions.
    ///
    /// # Errors
    /// Returns a `ReadlineError` if an error occurs during completion.
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Self::Candidate>), rustyline::error::ReadlineError> {
        
        // The suggestions for the command completion is taken from the build_command_registry function
        let suggestions = build_command_registry(); 
        let mut candidates = Vec::new();

        let query = if pos <= line.len() {
            &line[..pos]
        } else {
            line
        };

        let parts: Vec<&str> = query.trim_end().split_whitespace().collect();

        if parts.len() == 1 && !query.ends_with(' ') {
            // Suggest main commands
            for (command, _) in &suggestions {
                if command.starts_with(parts[0]) {
                    candidates.push(Pair {
                        display: command.to_string(),
                        replacement: command.to_string(),
                    });
                }
            }
        } else if parts.len() == 1 && query.ends_with(' ') {
            // Suggest subcommands for the main command
            if let Some(subcommands) = suggestions.get(parts[0]) {
                for subcmd in subcommands.suggestions.iter() {
                    candidates.push(Pair {
                        display: subcmd.join(" "),
                        replacement: format!("{} {}", parts[0], subcmd.join(" ")),
                    });
                }
            }
        } else if parts.len() == 2 {
            // Suggest specific subcommands that start with the entered prefix
            if let Some(subcommands) = suggestions.get(parts[0]) {
                for subcmd in subcommands.suggestions.iter() {
                    if subcmd.join(" ").starts_with(parts[1]) {
                        candidates.push(Pair {
                            display: subcmd.join(" "),
                            replacement: subcmd.join(" "),
                        });
                    }
                }
            }
        }

        // Determine the starting position for completions
        let pos = if parts.len() > 1 {
            query.rfind(' ').unwrap_or(0) + 1
        } else {
            0
        };

        Ok((pos, candidates))
    }
}


impl Helper for CommandCompleter {}


impl Hinter for CommandCompleter {
    type Hint = String;

    /// Provides hints for the current input line.
    ///
    /// # Arguments
    /// - `_line`: The current input line from the user.
    /// - `_pos`: The cursor position within the line.
    /// - `_ctx`: The rustyline context.
    ///
    /// # Returns
    /// Always returns `None` in this implementation as hints are not used.
    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None 
    }
}


impl Highlighter for CommandCompleter {}


impl Validator for CommandCompleter {

    /// Validates the current input line.
    ///
    /// # Arguments
    /// - `_ctx`: A mutable reference to the validation context.
    ///
    /// # Returns
    /// Always returns `ValidationResult::Valid` in this implementation.
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None)) 
    }
}

