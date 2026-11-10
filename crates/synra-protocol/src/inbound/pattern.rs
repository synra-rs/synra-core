use core::fmt;

use crate::ids::PluginId;

/// The most wildcards a single `handles` entry may contain.
///
/// A pattern is matched against every inbound event, so its cost is paid on the hot path. A bound
/// keeps one plugin's manifest from making every event on the device slower to route.
pub const MAX_PATTERN_WILDCARDS: u8 = 4;

/// The most wildcard entries one plugin may declare.
///
/// The same reasoning one level up: an unbounded list of wildcards is an unbounded amount of matching
/// per event, paid by every other plugin too.
pub const MAX_WILDCARD_RULES: usize = 64;

/// Why a `handles` pattern is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PatternError {
    /// The pattern is empty.
    #[error("handle pattern is empty")]
    Empty,

    /// The pattern exceeds the event-name limit.
    #[error("handle pattern is {len} bytes, the limit is {max}")]
    TooLong {
        /// Observed length.
        len: usize,
        /// Maximum accepted length.
        max: usize,
    },

    /// The pattern has an empty segment.
    #[error("handle pattern {0:?} has an empty segment")]
    EmptySegment(String),

    /// A segment has a character outside the grammar.
    #[error("handle pattern {pattern:?} has an invalid event segment or package id: {segment:?}")]
    BadCharacter {
        /// The whole pattern.
        pattern: String,
        /// The offending segment.
        segment: String,
    },

    /// The pattern has too many wildcards.
    #[error("handle pattern has {found} wildcards, the limit is {max}")]
    TooManyWildcards {
        /// How many were found.
        found: u8,
        /// The limit.
        max: u8,
    },

    /// A wildcard is not the whole segment.
    #[error("handle pattern {0:?} has a wildcard mixed into a segment, which is not supported")]
    PartialWildcard(String),
}

/// What a plugin declares it wants to receive.
///
/// See the module docs for why this is not an [`EventName`]. The grammar is the event-name grammar
/// plus a standalone `*` segment, which matches exactly one segment.
///
/// ```text
/// "_plugin.@acme/chat.*"             the chat plugin's own events, one segment deep
/// "_plugin.@acme/chat.room.*"        one segment deeper
/// "_synra.transfer.completed"  a built-in, no wildcard
/// "file.transfer.*"            a data-plane family
/// ```
///
/// A trailing `*` does **not** match a name ending in a dot, and does not match multiple segments:
/// `_plugin.@acme/chat.*` matches `_plugin.@acme/chat.text` but not `_plugin.@acme/chat.room.message`. That is
/// deliberate. A pattern that could match an unbounded number of segments makes "which plugin gets
/// this event" impossible to answer by reading a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HandlePattern {
    /// The full pattern text.
    text: String,
    /// The leading segments, up to the first wildcard.
    prefix: String,
    /// How many wildcard segments the pattern ends with.
    wildcards: u8,
    /// Total segment count, so a candidate can be rejected on length alone.
    segments: usize,
}

impl HandlePattern {
    /// Parses a `handles` entry.
    ///
    /// # Errors
    ///
    /// [`PatternError`] describing the first problem.
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::Empty);
        }
        if pattern.len() > crate::event::MAX_EVENT_NAME_LEN {
            return Err(PatternError::TooLong {
                len: pattern.len(),
                max: crate::event::MAX_EVENT_NAME_LEN,
            });
        }

        let mut prefix = String::new();
        let mut wildcards: u8 = 0;
        let mut segments = 0usize;
        let mut still_prefix = true;

        for segment in pattern.split('.') {
            if segment.is_empty() {
                return Err(PatternError::EmptySegment(pattern.to_owned()));
            }
            segments += 1;

            if segment == "*" {
                wildcards += 1;
                if wildcards > MAX_PATTERN_WILDCARDS {
                    return Err(PatternError::TooManyWildcards {
                        found: wildcards,
                        max: MAX_PATTERN_WILDCARDS,
                    });
                }
                // Wildcards are only meaningful as a trailing run. A wildcard in the middle would
                // make the pattern match a set whose shape depends on the candidate's length, which
                // is exactly what "impossible to answer by reading a manifest" means.
                if !still_prefix {
                    continue;
                }
                still_prefix = false;
                continue;
            }

            if segment.contains('*') {
                // `_plugin.@acme/chat.tex*` is refused rather than treated as a prefix match: a partial
                // wildcard is a different feature, and supporting it silently would make manifests
                // mean something their authors did not intend.
                return Err(PatternError::PartialWildcard(pattern.to_owned()));
            }

            let valid = if segments == 2 && pattern.starts_with("_plugin.") {
                PluginId::validate(segment).is_ok()
            } else {
                segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            };
            if !valid {
                return Err(PatternError::BadCharacter {
                    pattern: pattern.to_owned(),
                    segment: segment.to_owned(),
                });
            }

            if still_prefix {
                if !prefix.is_empty() {
                    prefix.push('.');
                }
                prefix.push_str(segment);
            }
        }

        Ok(Self { text: pattern.to_owned(), prefix, wildcards, segments })
    }

    /// Whether this pattern is exact, with no wildcards.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        self.wildcards == 0
    }

    /// Whether a name matches.
    ///
    /// Cost is a segment count comparison in the common case, and a string comparison of the literal
    /// prefix otherwise. It never walks the candidate character by character.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        if self.wildcards == 0 {
            return self.text == name;
        }

        let candidate_segments = name.split('.').count();
        if candidate_segments != self.segments {
            return false;
        }

        // The literal prefix is everything up to the first wildcard. Empty means the pattern is all
        // wildcards, which matches any name of the right length.
        if self.prefix.is_empty() {
            return true;
        }

        name.len() > self.prefix.len()
            && name.starts_with(self.prefix.as_str())
            && name.as_bytes().get(self.prefix.len()) == Some(&b'.')
    }

    /// The pattern as declared.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// How many wildcard segments this pattern ends with.
    #[must_use]
    pub const fn wildcard_count(&self) -> u8 {
        self.wildcards
    }
}

impl fmt::Display for HandlePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl TryFrom<&str> for HandlePattern {
    type Error = PatternError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
