/// External crates for the CLI application
use crate::build_command_registry;

use rustyline::hint::Hinter;
use rustyline::Helper;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::validate::{Validator, ValidationContext, ValidationResult};
use rustyline::error::ReadlineError;


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
    pub commands: Vec<String>,
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
        let suggestions = build_command_registry(); 
        let mut candidates = Vec::new();

        let query = if pos <= line.len() {
            &line[..pos]
        } else {
            line
        };

        // Match commands that start with the query and add them as suggestions.
        for (command, _) in suggestions {
            if command.starts_with(query) {
                candidates.push(Pair {
                    display: command.clone().to_string(),     
                    replacement: command.clone().to_string(), 
                });
            }
        }

        Ok((0, candidates))
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