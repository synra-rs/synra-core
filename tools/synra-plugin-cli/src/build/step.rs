//! Build command steps and their shell-safe display.

use std::path::PathBuf;

/// One command to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The program.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The directory to run it in, relative to the plugin's root.
    pub in_dir: PathBuf,
    /// What this step is for, in a sentence an author reads.
    pub why: String,
    /// Component destination relative to the package root, when this is a Cargo build.
    pub component: Option<PathBuf>,
}

impl Step {
    /// The whole command, as an author would type it.
    ///
    /// # Why quoting is not "does it contain a space"
    ///
    /// A line is printed so an author can copy it into a shell, and a shell treats more than spaces as
    /// significant — `console.log(1)` has no space and would be a syntax error pasted into `sh`. So an argument is
    /// quoted whenever it contains anything a shell would interpret, which is the property the line is for.
    #[must_use]
    pub fn command_line(&self) -> String {
        let mut line = self.program.clone();
        for arg in &self.args {
            line.push(' ');
            if needs_quoting(arg) {
                line.push_str(&format!("\"{arg}\""));
            } else {
                line.push_str(arg);
            }
        }
        line
    }
}

/// Whether a shell would interpret an argument.
///
/// The set is deliberately conservative — punctuation that is harmless in one shell is a substitution in another — and
/// the cost of being wrong is a quoted word that did not need quoting.
fn needs_quoting(arg: &str) -> bool {
    arg.is_empty()
        || arg.contains(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '"' | '\''
                        | '\\'
                        | '$'
                        | '`'
                        | '&'
                        | '|'
                        | ';'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '!'
                        | '#'
                        | '~'
                        | '='
                        | ','
                        | ':'
                )
        })
}


