//! The level of a log line, its parsing, and the level it does not recognise.
/// How verbose logging is.
///
/// A copy of the levels the log format supports, kept separate from the `tracing` types so that the
/// interface layer can persist and restore a level without depending on `tracing`'s API shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[non_exhaustive]
pub enum LogLevel {
    /// Everything, including per-frame detail.
    Trace,
    /// Flow detail. Only while a diagnostic session is open.
    Debug,
    /// The default: what the application did.
    #[default]
    Info,
    /// Something recovered from.
    Warn,
    /// Something the user noticed.
    Error,
    /// Logging off.
    Off,
}

impl LogLevel {
    /// The name used in configuration.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Off => "off",
        }
    }

    /// Parses a level name, case-insensitively.
    ///
    /// # Errors
    ///
    /// The unrecognised name, so a typo in a config file can be reported with the string that caused it.
    pub fn parse(name: &str) -> Result<Self, UnknownLevel> {
        let lowered = name.trim().to_ascii_lowercase();
        match lowered.as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            "off" | "none" => Ok(Self::Off),
            _ => Err(UnknownLevel { name: name.to_owned() }),
        }
    }

    /// Whether this level is written to disk by default.
    ///
    /// `DEBUG` and `TRACE` are not, because they are only ever wanted for a bounded window: keeping them
    /// would fill a disk with frame-level detail nobody reads, and keeping them *forever* is how a log
    /// directory reaches a gigabyte.
    #[must_use]
    pub const fn is_persisted(self) -> bool {
        matches!(self, Self::Info | Self::Warn | Self::Error)
    }

    /// Whether a message at `message` level is recorded when the threshold is `self`.
    #[must_use]
    pub const fn admits(self, message: Self) -> bool {
        if matches!(self, Self::Off) {
            return false;
        }
        // Ordering is declaration order: Trace < Debug < Info < Warn < Error, so a lower threshold
        // admits more.
        (message as u8) >= (self as u8)
    }
}

impl core::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A level name that is not one of the known ones.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name:?} is not a log level")]
pub struct UnknownLevel {
    /// The name that was offered.
    pub name: String,
}
