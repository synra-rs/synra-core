//! Why an action was refused.
//!
//! # Why the narrow refusals are separate types
//!
//! Because a caller's options differ. `PlatformError` is what a host returns; `UrlRefusal` and `PathRefusal` are
//! the *reasons* inside one variant, and they exist so a message can say what is wrong with the address without the
//! caller having to match on a string.

use core::fmt;

use serde::{Deserialize, Serialize};

use super::actions::PlatformAction;

/// Why a platform action was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The URL is not one the host will open.
    #[error("the address {url:?} cannot be opened: {reason}")]
    BadUrl {
        /// The URL, as supplied.
        url: String,
        /// Why not.
        reason: UrlRefusal,
    },

    /// The path is not one the host will open or reveal.
    #[error("the path {path:?} cannot be used: {reason}")]
    BadPath {
        /// The path, as supplied.
        path: String,
        /// Why not.
        reason: PathRefusal,
    },

    /// Key simulation is not granted.
    #[error("simulating keys is not enabled; the user has to turn it on in settings")]
    SimulateKeysNotGranted,

    /// The user is not interacting, so a plugin may not type on their behalf.
    #[error("keys cannot be simulated: the last interaction was {elapsed_ms}ms ago")]
    NoRecentInteraction {
        /// How long ago the user last interacted.
        elapsed_ms: u64,
    },

    /// A rate limit was hit.
    #[error("{action} was called too soon: {remaining_ms}ms to wait")]
    RateLimited {
        /// Which action.
        action: PlatformAction,
        /// How long until another call is allowed.
        remaining_ms: u64,
    },

    /// An action was requested more times than the hourly ceiling allows.
    #[error("{action} has been used {used} times this hour, and the limit is {limit}")]
    QuotaExceeded {
        /// Which action.
        action: PlatformAction,
        /// How many times it has been used.
        used: u32,
        /// The ceiling.
        limit: u32,
    },

    /// A value is too long.
    #[error("the {field} is {len} characters, and the limit is {max}")]
    TooLong {
        /// Which field.
        field: &'static str,
        /// How long it is.
        len: usize,
        /// The limit.
        max: usize,
    },

    /// The operating system refused, or the request was one the host will not pass on.
    ///
    /// A `&'static str` rather than a `String`: the variant carries a description of the operation that was
    /// refused, which is a fixed phrase in this crate, and it never carries anything a caller supplied — a message
    /// built from a plugin's input is how a refusal becomes a way to put text in front of the user.
    #[error("the system refused to {0}")]
    Unavailable(&'static str),

    /// This host cannot perform the action at all.
    ///
    /// Not a failure: a headless host has no clipboard, and a `synra doctor` run on a server-like build has no
    /// browser. The distinction matters because the caller's response differs — one is a configuration problem
    /// and the other is not.
    /// A program this platform needed could not be run.
    ///
    /// # Why this is not `Unsupported`
    ///
    /// Because the two are different facts and a user acts differently on each: `Unsupported` is "this host has no
    /// such capability", which is a property of the installation, and this is "the program that does it is missing or
    /// failed", which is a property of the machine and is usually fixable. A desktop that reported the second as the
    /// first would tell a user their system cannot open a browser when the truth is that `xdg-open` is not installed.
    #[error("`{program}` could not be run: {reason}")]
    RunnerFailed {
        /// Which program.
        program: String,
        /// What it said, or why it could not be launched.
        reason: String,
    },

    /// This host has no such capability at all, which is a property of the installation rather than of the machine.
    ///
    /// The distinction from [`Self::RunnerFailed`] is what a user acts on: a headless kernel genuinely cannot open a
    /// browser, and a desktop whose `xdg-open` is missing can be fixed.
    #[error("this host cannot {0}")]
    Unsupported(&'static str),
}

/// Why a URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum UrlRefusal {
    /// It is empty.
    Empty,
    /// It is longer than [`MAX_URL_LEN`].
    TooLong,
    /// It has no scheme.
    NoScheme,
    /// It uses a scheme that names something local.
    LocalScheme,
    /// It is plain HTTP, and insecure URLs are not allowed.
    Insecure,
    /// It has no host.
    NoHost,
    /// It contains a control character, which could be used to forge a prompt or a log line.
    ControlCharacter,
}

impl fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.explain())
    }
}

impl UrlRefusal {
    /// A sentence for the user.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Empty => "the address is empty",
            Self::TooLong => "the address is too long",
            Self::NoScheme => "the address has no scheme",
            Self::LocalScheme => "the address names something on this computer, which is not a web page",
            Self::Insecure => "the address is not secure, so what it shows could be changed in transit",
            Self::NoHost => "the address has no host",
            Self::ControlCharacter => "the address contains an invisible character",
        }
    }
}

/// Why a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PathRefusal {
    /// It is empty.
    Empty,
    /// It is not absolute, so what it names depends on the working directory.
    NotAbsolute,
    /// It has no extension and no way to tell what it is, which for `open-path` means it cannot be proven not to
    /// be a program.
    UnknownKind,
    /// Its extension marks it as executable or installable.
    Executable,
    /// It is outside the plugin's sandbox, and revealing it would disclose what exists on the disk.
    OutsideSandbox,
    /// It contains a control character.
    ControlCharacter,
    /// One of its components names a Windows device rather than a file.
    ReservedName,
    /// One of its components contains a colon, which on Windows opens an alternate data stream.
    AlternativeStream,
    /// It begins in the Windows device namespace — a `\\?\` or `\\.\` prefix, or a UNC share.
    DeviceNamespace,
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.explain())
    }
}

impl PathRefusal {
    /// A sentence for the user.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Empty => "the path is empty",
            Self::NotAbsolute => "the path is relative, so it depends on where the application is running",
            Self::UnknownKind => "the path has no extension, so there is no way to tell what it is",
            Self::Executable => "the path is a program or an installer, and opening it would run it",
            Self::OutsideSandbox => "the path is outside the plugin's own data directory",
            Self::ControlCharacter => "the path contains an invisible character",
            Self::ReservedName => {
                "the path names a device \u{2014} Windows resolves names like NUL and CON before the file system, so what \
                 it would write to is not where it says"
            }
            Self::AlternativeStream => {
                "the path names an alternate data stream, which is a hidden second file on Windows and an ordinary name \
                 everywhere else"
            }
            Self::DeviceNamespace => {
                "the path starts in the Windows device namespace, where the same text does not mean the same place"
            }
        }
    }
}
