//! How sound a database is, and what an integrity result means.
/// How healthy the database is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Health {
    /// The integrity check passed.
    Sound,
    /// The check found a problem.
    ///
    /// The design document's recovery path: restore from a backup, or rebuild and tell the user what was lost.
    /// This module reports; deciding is the caller's, because only the caller knows whether a backup exists.
    Corrupt {
        /// What the engine reported.
        detail: String,
    },
    /// The check could not run.
    Unknown {
        /// Why not.
        detail: String,
    },
}

impl Health {
    /// Whether the database can be used.
    #[must_use]
    pub const fn is_sound(&self) -> bool {
        matches!(self, Self::Sound)
    }

    /// Whether the user has to be told something was lost.
    #[must_use]
    pub const fn needs_user_attention(&self) -> bool {
        matches!(self, Self::Corrupt { .. })
    }

    /// A sentence for the interface or a diagnostic bundle.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::Sound => "the database passed its integrity check".to_owned(),
            Self::Corrupt { detail } => format!(
                "the database is damaged and has to be restored from a backup: {detail}"
            ),
            Self::Unknown { detail } => {
                format!("the database's integrity could not be checked: {detail}")
            }
        }
    }
}

/// Interprets the result of an integrity check.
///
/// `rusqlite` returns rows of text, the first of which is `ok` for a sound database. Anything else is a problem
/// the engine described.
#[must_use]
pub fn interpret_integrity(rows: &[String]) -> Health {
    match rows.first().map(String::as_str) {
        Some("ok") => Health::Sound,
        Some(other) => Health::Corrupt { detail: other.to_owned() },
        None => Health::Unknown {
            detail: "the check returned no rows".to_owned(),
        },
    }
}
