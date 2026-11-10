//! Archive entry records and their shape.

/// What an entry is.
///
/// A directory is allowed and written as a directory, because archives contain them and refusing one would refuse
/// every archive a real tool produces. Anything else — a link, a device node, a fifo — is refused, and the type is
/// what makes that a decision rather than a guess about the mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A hard link.
    HardLink,
    /// Anything else the format can express: a device node, a fifo, a socket.
    Other,
}

impl EntryKind {
    /// A name, for a message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symbolic link",
            Self::HardLink => "hard link",
            Self::Other => "entry",
        }
    }

    /// Whether the host will write it.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::File | Self::Directory)
    }
}

/// One entry of an archive, as the format describes it.
///
/// `compressed` is what the ratio is computed from, and it is `None` when the format does not say — which is the
/// honest answer for a streamed archive whose entries were not sized ahead of time. A missing compressed size is not
/// treated as zero: a ratio of infinity would refuse every entry of an archive that simply did not record one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its path, as the archive spells it.
    pub path: String,
    /// What it is.
    pub kind: EntryKind,
    /// How large it claims to be once expanded.
    pub size: u64,
    /// How large it is in the archive, when the format says.
    pub compressed: Option<u64>,
}

impl Entry {
    /// A regular file.
    #[must_use]
    pub fn file(path: impl Into<String>, size: u64) -> Self {
        Self { path: path.into(), kind: EntryKind::File, size, compressed: None }
    }

    /// A directory.
    #[must_use]
    pub fn directory(path: impl Into<String>) -> Self {
        Self { path: path.into(), kind: EntryKind::Directory, size: 0, compressed: None }
    }

    /// A symbolic link to somewhere.
    #[must_use]
    pub fn symlink(path: impl Into<String>, to: impl Into<String>) -> Self {
        // The target is documentation for the refusal; the decision refuses every link whatever it points at.
        let _ = to.into();
        Self { path: path.into(), kind: EntryKind::Symlink, size: 0, compressed: None }
    }

    /// How many components its path has, ignoring a trailing slash.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.path
            .trim_end_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .count()
    }

    /// Whether the ratio bound refuses it.
    #[must_use]
    pub fn expands_too_far(&self, limit: f64) -> bool {
        let Some(compressed) = self.compressed else {
            return false;
        };
        if self.size == 0 {
            return false;
        }
        // A zero compressed size with content behind it is not a ratio of infinity to be reasoned about; it is an
        // archive lying about a size, and the per-file and total bounds are what refuse it.
        if compressed == 0 {
            return true;
        }
        (self.size as f64) / (compressed as f64) > limit
    }
}


