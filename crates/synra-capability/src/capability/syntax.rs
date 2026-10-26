//! The grammar: the limits, the errors, the parsed form, and how it is read and written.

use core::fmt;

use compact_str::CompactString;
use smallvec::SmallVec;

use crate::domain::{Domain, UnknownDomain};

use super::segment::Segment;

/// The most segments a capability may have.
///
/// Three prefixes plus three qualifier segments, which is one more than any capability in the design
/// document needs. Bounded because the length of a capability decides the cost of matching it, and
/// matching runs on every host call.
pub const MAX_SEGMENTS: usize = 6;

/// The longest a capability may be.
pub const MAX_LEN: usize = 256;

/// The longest a single prefix may be.
pub const MAX_PREFIX_LEN: usize = 64;

/// The highest segment position that is still a prefix.
///
/// Segment 0 is the domain, so the prefixes are positions `1..=MAX_PREFIXES` and the qualifier starts at
/// `MAX_PREFIXES + 1`. With a value of 1 the longest prefix form is `domain:resource`, and
/// `network:fetch:api.github.com` has `fetch` as its prefix and the hostname as its qualifier;
/// `event:emit:_plugin.@acme/chat.*` has two prefixes and an event pattern as its qualifier.
///
/// Written as the last prefix *position* rather than a count, because it is used directly in a
/// `position <= …` test and a count would have to be adjusted by one at every use — which is exactly
/// the off-by-one that made a hostname look like a prefix.
pub const MAX_PREFIXES: usize = 1;

/// Why a capability string is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CapabilityError {
    /// The string is empty.
    #[error("capability is empty")]
    Empty,

    /// The string is longer than [`MAX_LEN`].
    #[error("capability of {len} bytes exceeds the limit {max}")]
    TooLong {
        /// Observed length.
        len: usize,
        /// The limit.
        max: usize,
    },

    /// The string has more segments than [`MAX_SEGMENTS`].
    #[error("capability has {found} segments, the limit is {max}")]
    TooManySegments {
        /// How many were found.
        found: usize,
        /// The limit.
        max: usize,
    },

    /// A segment is empty, so the string has `::` or begins or ends with `:`.
    #[error("{text:?} has an empty segment at position {position}")]
    EmptySegment {
        /// The whole capability.
        text: String,
        /// Which segment was empty, counting from zero.
        position: usize,
    },

    /// The first segment is not a known domain.
    #[error(transparent)]
    UnknownDomain(#[from] UnknownDomain),

    /// A prefix is not `[a-z][a-z0-9-]*`.
    #[error("prefix {segment:?} in {text:?} is not a name, `*` or `**`")]
    BadPrefix {
        /// The whole capability.
        text: String,
        /// The offending prefix.
        segment: String,
    },

    /// A prefix is longer than [`MAX_PREFIX_LEN`].
    #[error("prefix {segment:?} exceeds {max} characters")]
    PrefixTooLong {
        /// The offending prefix.
        segment: String,
        /// The limit.
        max: usize,
    },

    /// A qualifier segment has a character outside the allowed set.
    #[error("qualifier {segment:?} in {text:?} has a character outside [A-Za-z0-9._@/*-]")]
    BadQualifier {
        /// The whole capability.
        text: String,
        /// The offending segment.
        segment: String,
    },

    /// A wildcard appears as a whole prefix where only a literal is meaningful.
    #[error("{text:?} uses a wildcard for a prefix that must name something, at position {position}")]
    WildcardPrefix {
        /// The whole capability.
        text: String,
        /// Which prefix, counting from zero.
        position: usize,
    },

    /// A capability that is nothing but `*` or `**`.
    #[error("{0:?} is not a capability: a bare wildcard would mean every capability")]
    BareWildcard(String),
}

/// A capability, or a pattern describing a family of them.
///
/// Whether a value is exact or a pattern is asked with [`Self::is_exact`]; a pattern is asked whether
/// it covers a concrete capability with [`Self::matches`]. Nothing else branches on which it is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Capability {
    /// The whole string, so it can be handed back without rebuilding it.
    text: CompactString,
    /// The domain, which every capability has.
    pub(super) domain: Domain,
    /// The prefix segments after the domain.
    pub(super) prefixes: SmallVec<[Segment; 3]>,
    /// The qualifier segments, if any. Index 0 here corresponds to segment [`MAX_PREFIXES`] overall.
    pub(super) qualifier: SmallVec<[Segment; 2]>,
    /// How many whole segments are wildcards, so `is_exact` is a field read rather than a scan.
    pub(super) wildcards: u8,
}

impl Capability {
    /// Parses a capability string.
    ///
    /// # Errors
    ///
    /// [`CapabilityError`] describing the first problem.
    pub fn parse(text: &str) -> Result<Self, CapabilityError> {
        if text.is_empty() {
            return Err(CapabilityError::Empty);
        }
        if text.len() > MAX_LEN {
            return Err(CapabilityError::TooLong { len: text.len(), max: MAX_LEN });
        }

        let segments: Vec<&str> = text.split(':').collect();
        if segments.len() > MAX_SEGMENTS {
            return Err(CapabilityError::TooManySegments { found: segments.len(), max: MAX_SEGMENTS });
        }

        for (position, segment) in segments.iter().enumerate() {
            if segment.is_empty() {
                return Err(CapabilityError::EmptySegment {
                    text: text.to_owned(),
                    position,
                });
            }
        }

        // A bare wildcard would mean "every capability". Refused at the syntax layer rather than by
        // convention, because a grammar that can express it will eventually be used to express it.
        if let [only] = segments.as_slice()
            && (*only == "*" || *only == "**")
        {
            return Err(CapabilityError::BareWildcard(text.to_owned()));
        }

        let Some(first) = segments.first() else {
            return Err(CapabilityError::Empty);
        };
        // A wildcard cannot stand in for the domain: `*:read` would be a capability in no domain, so
        // `contains` could not use the domain bitmask to refuse it.
        if *first == "*" || *first == "**" {
            return Err(CapabilityError::WildcardPrefix { text: text.to_owned(), position: 0 });
        }
        let domain = Domain::parse(first)?;

        let mut prefixes: SmallVec<[Segment; 3]> = SmallVec::new();
        let mut qualifier: SmallVec<[Segment; 2]> = SmallVec::new();
        let mut wildcards: u8 = 0;

        for (position, segment) in segments.iter().enumerate().skip(1) {
            // Preserve positions in the same prefix/qualifier split as literal segments. Moving a
            // trailing wildcard before a literal qualifier changes the permission being checked.
            if *segment == "*" || *segment == "**" {
                wildcards = wildcards.saturating_add(1);
                let wildcard = if *segment == "*" {
                    Segment::star()
                } else {
                    Segment::double_star()
                };
                if position <= MAX_PREFIXES {
                    prefixes.push(wildcard);
                } else {
                    qualifier.push(wildcard);
                }
                continue;
            }

            // Position 0 is the domain, so the prefixes are positions `1..=MAX_PREFIXES` and the
            // qualifier starts at `MAX_PREFIXES + 1`.
            if position <= MAX_PREFIXES {
                if segment.len() > MAX_PREFIX_LEN {
                    return Err(CapabilityError::PrefixTooLong {
                        segment: (*segment).to_owned(),
                        max: MAX_PREFIX_LEN,
                    });
                }
                if !is_prefix_name(segment) {
                    return Err(CapabilityError::BadPrefix {
                        text: text.to_owned(),
                        segment: (*segment).to_owned(),
                    });
                }
                prefixes.push(Segment::literal(segment));
            }
            else {
                if !is_qualifier_segment(segment) {
                    return Err(CapabilityError::BadQualifier {
                        text: text.to_owned(),
                        segment: (*segment).to_owned(),
                    });
                }
                qualifier.push(Segment::literal(segment));
            }
        }

        Ok(Self {
            text: CompactString::from(text),
            domain,
            prefixes,
            qualifier,
            wildcards,
        })
    }

    /// The whole capability as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }

    /// Which domain this belongs to.
    ///
    /// Always available, even for a pattern: a wildcard can never stand in for the domain, so the
    /// domain bitmask is a sound fast negative for every value of this type.
    #[must_use]
    pub const fn domain(&self) -> Domain {
        self.domain
    }

    /// The prefix segments after the domain.
    #[must_use]
    pub fn prefixes(&self) -> &[Segment] {
        &self.prefixes
    }

    /// The qualifier segments, if any.
    #[must_use]
    pub fn qualifier(&self) -> &[Segment] {
        &self.qualifier
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl core::str::FromStr for Capability {
    type Err = CapabilityError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Serialises as the capability string, and deserialises through the parser.
///
/// Validation on the way in is what makes this safe: a capability reconstructed from a database or a
/// configuration file is checked by the same grammar as one written in a manifest, so a stored grant cannot
/// become a value the matcher was never designed for.
impl From<Capability> for String {
    fn from(value: Capability) -> Self {
        value.text.into_string()
    }
}

impl TryFrom<String> for Capability {
    type Error = CapabilityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

/// Whether a string is a prefix name: `[a-z][a-z0-9-]{0,63}`.
fn is_prefix_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// Whether a string is usable as a qualifier segment.
///
/// One character class for every domain's qualifier, because the domains disagree about theirs and a
/// per-domain rule here would be five parsers sharing one caller. It admits domain names
/// (`api.github.com`), HTTP methods (`POST`), paths (`/data/**`), device ids (`@synra-pc`), event
/// patterns (`_plugin.@acme/chat.*`) and page keys (`settings`), and nothing that would let a qualifier
/// escape its own meaning: no colon, so it cannot forge a segment boundary; no whitespace; no
/// quotes or angle brackets, so it cannot be reinterpreted as markup.
fn is_qualifier_segment(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '/' | '*' | '-')
        })
}
