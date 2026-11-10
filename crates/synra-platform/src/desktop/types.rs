//! Desktop identity and command selection.

/// Which desktop this is, which decides which programs exist.
///
/// # Why this is a value and not `cfg!`
///
/// Because it has to be *testable*: the command a Windows host runs for "reveal this file in the file manager" is a
/// fact worth asserting, and a compile-time branch cannot be asserted on the other platforms. It is also what makes
/// the choice a caller's: a Linux desktop running a Windows-targeted build is not a thing, but a test driving the
/// Windows command table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Desktop {
    /// Linux, and the BSDs that keep the same tools.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Desktop {
    /// The desktop this build is running on.
    ///
    /// The `cfg` is here and nowhere else, so that everything decided *from* it is ordinary code a test can drive.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }

    /// A name, for a log line and a health screen.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }

    /// The program that opens a URL or a file with whatever handles it.
    #[must_use]
    pub const fn opener(self) -> &'static str {
        match self {
            Self::Linux => "xdg-open",
            Self::MacOs => "open",
            Self::Windows => "explorer",
        }
    }

    /// The program that shows a file in the file manager, when it is not the opener.
    ///
    /// Windows is the one that differs: `explorer /select,` is how a file is highlighted rather than opened, and
    /// `xdg-open` and `open -R` would open a directory instead of showing the file inside it.
    #[must_use]
    pub const fn revealer(self) -> (&'static str, &'static str) {
        match self {
            Self::Linux => ("xdg-open", ""),
            Self::MacOs => ("open", "-R"),
            // `/select,` is one argument with a trailing comma and no space: an `explorer` invocation that separates
            // them is one Windows parses as a path called `/select`.
            Self::Windows => ("explorer", "/select,"),
        }
    }
}


