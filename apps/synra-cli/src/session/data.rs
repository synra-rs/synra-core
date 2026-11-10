use std::path::PathBuf;

/// The environment variable that moves the data directory.
pub const DATA_DIR_VAR: &str = "SYNRA_DATA_DIR";

/// Where the kernel keeps its data.
///
/// The daemon's answer, so that `doctor` checks the installation the user actually has.
#[must_use]
pub fn data_root() -> PathBuf {
    data_root_from(std::env::var_os(DATA_DIR_VAR))
}

/// The data root for a given value of the environment variable.
///
/// # Why the value is a parameter
///
/// Reading an environment variable is not testable from inside a process: `std::env::set_var` is `unsafe` in edition
/// 2024, because another thread may be reading the environment at the same time, and this workspace forbids `unsafe`.
/// So the decision takes the value and the caller reads it — which leaves the interesting part, what a given value
/// *means*, as an ordinary function a test can call.
///
/// An empty value is not an answer: it falls back rather than naming the current directory, because an unset variable
/// and one set to nothing are the same intention everywhere else.
#[must_use]
pub fn data_root_from(configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("synra"),
    }
}

/// What a command produced.
///
/// # Shape and success are two different things
///
/// A command's output can be lines or one JSON value, and either can be the result of a success or of a failure. So
/// the shape and the outcome are separate fields rather than separate variants: a `Json` variant on its own said
/// nothing about whether the command worked, and an exit code derived from the shape alone returned zero for a failing
/// command that happened to print JSON — which is the one signal a script reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Lines for a person to read.
    ///
    /// A vector rather than printed, so the caller decides where it goes and a test asserts the text a user sees
    /// instead of capturing a stream.
    Lines(Vec<String>),
    /// One JSON value, for a script.
    Json {
        /// The value, as text.
        body: String,
        /// Whether the command succeeded.
        ok: bool,
    },
    /// Something the user has to fix.
    Failed(String),
}

impl CommandOutcome {
    /// A successful JSON result.
    #[must_use]
    pub fn json(body: impl Into<String>) -> Self {
        Self::Json { body: body.into(), ok: true }
    }

    /// A JSON result for a command that failed.
    ///
    /// A failure a script asked to read as JSON: it gets the detail *and* a non-zero exit code, rather than having to
    /// tell prose from JSON to know which happened.
    #[must_use]
    pub fn json_failure(body: impl Into<String>) -> Self {
        Self::Json { body: body.into(), ok: false }
    }

    /// What the process should exit with.
    ///
    /// `0` for output from a command that worked, `1` for one that did not. An empty list is a *successful* answer to
    /// "which devices are there", so lines alone are not a failure — but JSON alone is not a success either.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Lines(_) => 0,
            Self::Json { ok: true, .. } => 0,
            Self::Json { ok: false, .. } | Self::Failed(_) => 1,
        }
    }

    /// The text to print, whichever shape it is.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Lines(lines) => lines.join("\n"),
            Self::Json { body, .. } => body.clone(),
            Self::Failed(message) => message.clone(),
        }
    }

    /// Whether it is a failure, so `main` knows which stream to use.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        match self {
            Self::Lines(_) => false,
            Self::Json { ok, .. } => !*ok,
            Self::Failed(_) => true,
        }
    }

    /// Text for stderr: JSON remains directly parseable, while prose identifies the command.
    #[must_use]
    pub fn diagnostic_text(&self) -> String {
        match self {
            Self::Json { body, .. } => body.clone(),
            _ => format!("synra: {}", self.text()),
        }
    }
}
