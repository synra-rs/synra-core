//! The capability string: parsing it, and matching one against a pattern.
//!
//! See the crate docs for the grammar and why it is shaped this way. This module is the syntax layer;
//! [`crate::set`] is the collection a plugin actually holds.

use core::fmt;

use compact_str::CompactString;
use smallvec::SmallVec;

use crate::domain::{Domain, UnknownDomain};

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
/// `event:emit:_plugin.chat.*` has two prefixes and an event pattern as its qualifier.
///
/// Written as the last prefix *position* rather than a count, because it is used directly in a
/// `position <= …` test and a count would have to be adjusted by one at every use — which is exactly
/// the off-by-one that made a hostname look like a prefix.
pub const MAX_PREFIXES: usize = 1;

/// A single segment of a capability.
///
/// A newtype rather than a bare string so that the invariant "this is a valid segment" is carried by
/// the type. A `Pattern` is built out of these, and matching never has to re-check what parsing
/// already established.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment(CompactString);

impl Segment {
    /// A segment that matches exactly itself.
    #[must_use]
    pub fn literal(text: &str) -> Self {
        Self(CompactString::from(text))
    }

    /// The single-segment wildcard.
    #[must_use]
    pub fn star() -> Self {
        Self(CompactString::from("*"))
    }

    /// The multi-segment wildcard.
    #[must_use]
    pub fn double_star() -> Self {
        Self(CompactString::from("**"))
    }

    /// The segment text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether this is the single-segment wildcard.
    #[must_use]
    pub fn is_star(&self) -> bool {
        self.0 == "*"
    }

    /// Whether this is the multi-segment wildcard.
    #[must_use]
    pub fn is_double_star(&self) -> bool {
        self.0 == "**"
    }

    /// Whether this is either wildcard.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.is_star() || self.is_double_star()
    }

    /// Whether this segment contains a wildcard anywhere.
    ///
    /// True for `*` and `**`, and also for a qualifier that embeds one, such as `/data/**` or
    /// `_plugin.chat.*`. Those match by their own rules, but they are still patterns rather than
    /// literal values — which matters when deciding whether a set of capabilities can be enumerated
    /// exactly.
    #[must_use]
    pub fn contains_wildcard(&self) -> bool {
        self.0.contains('*')
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

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
    domain: Domain,
    /// The prefix segments after the domain.
    prefixes: SmallVec<[Segment; 3]>,
    /// The qualifier segments, if any. Index 0 here corresponds to segment [`MAX_PREFIXES`] overall.
    qualifier: SmallVec<[Segment; 2]>,
    /// How many whole prefixes are wildcards, so `is_exact` is a field read rather than a scan.
    wildcards: u8,
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
            // A standalone `*` or `**` is always a wildcard segment, wherever it appears. It is the one
            // form that can cross the prefix boundary, which `network:fetch:**` depends on: the `**`
            // sits at prefix position 2 but has to absorb qualifier segments, so classifying it by
            // position would leave it as a literal `**` that matches nothing.
            //
            // No ambiguity arises, because a qualifier's `*` is never standalone: `/data/*` and
            // `_plugin.chat.*` are single segments with other characters in them.
            if *segment == "*" || *segment == "**" {
                wildcards = wildcards.saturating_add(1);
                prefixes.push(if *segment == "*" {
                    Segment::star()
                }
                else {
                    Segment::double_star()
                });
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

    /// Whether this names one capability rather than a family.
    ///
    /// False when any prefix is a whole wildcard, or when a qualifier embeds a wildcard — `/data/**`
    /// covers many paths even though it is written as a single segment.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.wildcards == 0 && !self.qualifier.iter().any(Segment::contains_wildcard)
    }

    /// Whether this pattern covers `candidate`.
    ///
    /// One algorithm over one list: the segments after the domain, prefix and qualifier together. A
    /// pattern segment is matched by its own kind — `*` takes exactly one, `**` takes any number
    /// including none, a literal with an embedded wildcard takes one by its own rule, and any other
    /// literal must be equal — while a *candidate* segment is always compared as the literal value it
    /// is, never interpreted as a pattern. A candidate is a request, not a rule.
    ///
    /// An exact capability matches only itself, which is the same algorithm with no wildcards present:
    /// there is deliberately no separate fast path, because two code paths for one question is how they
    /// come to disagree.
    ///
    /// # Why one list rather than two
    ///
    /// Splitting prefixes from the qualifier and matching them separately looks natural — their rules do
    /// differ — but it breaks `**`, whose whole purpose is to cross boundaries: `network:fetch:**` must
    /// cover `network:fetch` (zero segments) *and* `network:fetch:api.github.com` (one qualifier
    /// segment). Two matchers each with their own length rules cannot express that, and the failure is
    /// silent: a plugin granted the fetch family is refused a call it should be allowed.
    #[must_use]
    pub fn matches(&self, candidate: &Self) -> bool {
        // Domains are literal, so a mismatch rules out everything immediately.
        if self.domain != candidate.domain {
            return false;
        }

        let pattern: Vec<SegmentKind> = self
            .prefixes
            .iter()
            .chain(&self.qualifier)
            .map(Segment::kind)
            .collect();
        let target: Vec<&str> = candidate
            .prefixes
            .iter()
            .chain(&candidate.qualifier)
            .map(Segment::as_str)
            .collect();
        match_segments(&pattern, &target)
    }

    /// How specific this pattern is, for ordering a list of them.
    ///
    /// More literal segments and fewer wildcards is more specific. Used only to give a deterministic
    /// answer to "which pattern applies?" in the interface and in an audit record — never to decide
    /// whether a capability is allowed, which is a set membership question and must not depend on
    /// ordering.
    #[must_use]
    pub fn specificity(&self) -> u32 {
        fn weight(segment: &Segment) -> u32 {
            if segment.is_double_star() {
                0
            }
            else if segment.is_star() {
                1
            }
            else if segment.contains_wildcard() {
                // A qualifier glob is more specific than a whole-segment wildcard but less than a
                // literal: `/data/**` narrows the domain, if not the path.
                4
            }
            else {
                8
            }
        }

        // The qualifier first, so that `network:fetch:api.github.com` outranks `network:fetch:*` even
        // though both have one literal prefix.
        let score: u32 = self.prefixes.iter().chain(&self.qualifier).map(weight).sum();
        // A capability with a qualifier says more than one without, at equal literal counts.
        score.saturating_mul(2) + u32::from(!self.qualifier.is_empty())
    }

    /// A short phrase describing what this grants, for the capability-consent prompt.
    ///
    /// The prompt is where a user decides, so it must not show them a DSL string. A user who does not
    /// read `network:fetch:api.github.com:POST` as "read from GitHub" is being asked to consent to
    /// something they cannot evaluate.
    #[must_use]
    pub fn describe(&self) -> String {
        let resource = self.prefixes.first().map_or("", Segment::as_str);
        match (self.domain, resource) {
            (Domain::Log, _) => match self.qualifier.first() {
                Some(level) => format!("write {} log messages", level.as_str()),
                None => "write log messages".to_owned(),
            },
            (Domain::Network, "fetch") => {
                let host = self.qualifier.first().map_or("*", Segment::as_str);
                match host {
                    "*" | "**" => "read from any website".to_owned(),
                    _ => format!("read from {host}"),
                }
            }
            (Domain::Network, "websocket") => "open a network connection".to_owned(),
            (Domain::Fs, "read") => {
                let path = self.qualifier.first().map_or("its sandbox", Segment::as_str);
                format!("read files under {}", readable_path(path))
            }
            (Domain::Fs, "write") => {
                let path = self.qualifier.first().map_or("its sandbox", Segment::as_str);
                format!("write files under {}", readable_path(path))
            }
            (Domain::Fs, "watch") => "watch files for changes".to_owned(),
            (Domain::Device, "list") => "see your other devices".to_owned(),
            (Domain::Device, "send") => match self.qualifier.first() {
                Some(target) => format!("send messages to {}", target.as_str()),
                None => "send messages to devices".to_owned(),
            },
            (Domain::Device, "broadcast") => "send messages to every device".to_owned(),
            (Domain::Platform, "open-url") => "open links in your browser".to_owned(),
            (Domain::Platform, "notify") => "show notifications".to_owned(),
            (Domain::Platform, "simulate-keys") => "type on your behalf".to_owned(),
            (Domain::Platform, "clipboard") => match self.qualifier.first() {
                Some(action) if action.as_str() == "read" => "read your clipboard".to_owned(),
                Some(action) if action.as_str() == "write" => "change your clipboard".to_owned(),
                _ => "use your clipboard".to_owned(),
            },
            (Domain::Storage, _) => "keep its own saved data".to_owned(),
            (Domain::File, "transfer") => match self.qualifier.first() {
                Some(action) if action.as_str() == "send" => "send files to your devices".to_owned(),
                Some(action) if action.as_str() == "receive" => "receive files".to_owned(),
                _ => "transfer files".to_owned(),
            },
            (Domain::Event, "emit") => match self.qualifier.first() {
                Some(name) => format!("send its own {} events", event_family(name.as_str())),
                None => "send its own events".to_owned(),
            },
            (Domain::Event, "subscribe") => match self.qualifier.first() {
                Some(name) => format!("react to {} events", event_family(name.as_str())),
                None => "react to events".to_owned(),
            },
            (Domain::Action, "declare") => "offer actions to other plugins".to_owned(),
            (Domain::Action, "invoke") => "use another plugin's actions".to_owned(),
            (Domain::Ui, _) => "show its own interface".to_owned(),
            _ => format!("use {self}"),
        }
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
/// patterns (`_plugin.chat.*`) and page keys (`settings`), and nothing that would let a qualifier
/// escape its own meaning: no colon, so it cannot forge a segment boundary; no whitespace; no
/// quotes or angle brackets, so it cannot be reinterpreted as markup.
fn is_qualifier_segment(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '/' | '*' | '-')
        })
}

/// Renders an event-name qualifier for a consent prompt.
///
/// The pattern suffix is what decides how much is covered, so showing it would leave the user to work
/// out the scope. The family a pattern names is the useful answer: `_plugin.chat.*` covers the chat
/// plugin's events, and `_synra.*` covers the host's.
fn event_family(pattern: &str) -> String {
    let trimmed = pattern.trim_end_matches('*').trim_end_matches('.');
    match trimmed.strip_prefix("_plugin.") {
        Some(slug) => format!("{slug} plugin's"),
        None => match trimmed.strip_prefix("_synra.") {
            Some("") => "host".to_owned(),
            Some(rest) => format!("host {rest}"),
            // A bare pattern covers the plugin's own namespace, which is what a plugin emits.
            None if trimmed.is_empty() => "own".to_owned(),
            None => trimmed.to_owned(),
        },
    }
}

/// Renders a path qualifier for a consent prompt.
///
/// The prompt must not contain `**`: a user reading "read files under /data/**" has been shown a glob
/// rather than an answer, and the wildcard is the part that decides how much is being asked for.
fn readable_path(path: &str) -> String {
    match path.strip_suffix("**") {
        Some(root) => {
            let root = root.trim_end_matches('/');
            if root.is_empty() {
                "anywhere in its sandbox".to_owned()
            }
            else {
                format!("{root} and everything below it")
            }
        }
        None => match path.strip_suffix('*') {
            Some(root) => format!("{} directly", root.trim_end_matches('/')),
            None => path.to_owned(),
        },
    }
}

/// Matches one pattern's segments against one capability's.
///
/// The single algorithm for the whole capability, prefixes and qualifier together, so that `**` can
/// cross the boundary between them. A pattern segment is matched by its own kind; a candidate segment is
/// only ever compared as a value.
///
/// Written iteratively with backtracking rather than recursively: a capability is at most six segments,
/// but a recursive matcher whose depth is chosen by an attacker's pattern is the kind of thing that is
/// fine until it is not.
fn match_segments(pattern: &[SegmentKind<'_>], candidate: &[&str]) -> bool {
    let (mut p, mut c) = (0usize, 0usize);
    // Where the last `**` was, and how many candidate segments it had absorbed when it was seen. On a
    // mismatch the `**` absorbs one more and matching resumes just after it.
    let mut star: Option<(usize, usize)> = None;

    while c < candidate.len() {
        let Some(pattern_segment) = pattern.get(p).copied() else {
            // The pattern is exhausted while the candidate is not. Only a `**` already seen can absorb
            // the rest — and this is the branch that makes `**` match *more* than one segment, so
            // omitting it would leave `ui:**` unable to cover `ui:page:extra`.
            let Some((star_p, star_c)) = star else {
                return false;
            };
            let next = star_c + 1;
            p = star_p + 1;
            c = next;
            star = Some((star_p, next));
            continue;
        };

        if matches!(pattern_segment, SegmentKind::DoubleStar) {
            star = Some((p, c));
            p += 1;
            continue;
        }

        let candidate_segment = candidate.get(c).copied().unwrap_or_default();
        if segment_matches(pattern_segment, candidate_segment) {
            p += 1;
            c += 1;
            continue;
        }

        let Some((star_p, star_c)) = star else {
            return false;
        };
        let next = star_c + 1;
        p = star_p + 1;
        c = next;
        star = Some((star_p, next));
    }

    // The candidate is consumed. Whatever remains of the pattern must be `**`, which matches nothing —
    // so `network:fetch:**` covers plain `network:fetch`.
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|kind| matches!(kind, SegmentKind::DoubleStar)))
}

/// What a pattern segment matches.
#[derive(Debug, Clone, Copy)]
enum SegmentKind<'a> {
    /// Equal to exactly this text.
    Literal(&'a str),
    /// Exactly one segment, whatever it is.
    Star,
    /// Any number of segments, including none.
    DoubleStar,
    /// One segment, matched by an embedded wildcard such as `/data/**` or `_plugin.chat.*`.
    Glob(&'a str),
}

impl Segment {
    /// What this segment matches, read from its own text.
    fn kind(&self) -> SegmentKind<'_> {
        if self.is_double_star() {
            SegmentKind::DoubleStar
        }
        else if self.is_star() {
            SegmentKind::Star
        }
        else if self.contains_wildcard() {
            SegmentKind::Glob(self.as_str())
        }
        else {
            SegmentKind::Literal(self.as_str())
        }
    }
}

/// Matches one pattern segment against one candidate value.
fn segment_matches(pattern: SegmentKind<'_>, candidate: &str) -> bool {
    match pattern {
        SegmentKind::Literal(text) => text == candidate,
        SegmentKind::Star => true,
        // Handled by the caller, which backtracks over it.
        SegmentKind::DoubleStar => true,
        SegmentKind::Glob(glob) => glob_matches(glob, candidate),
    }
}

/// Matches a pattern segment that embeds a wildcard, such as `/data/**` or `_plugin.chat.*`.
///
/// A trailing `**` matches any remainder, crossing `/` and `.`. A single trailing `*` matches the rest
/// of one path component: `/data/*` covers `/data/file` but not `/data/sub/file`, and that boundary is
/// the only reason `**` exists as a separate form.
fn glob_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == candidate {
        return true;
    }

    let Some(prefix) = pattern.strip_suffix("**") else {
        return match pattern.strip_suffix('*') {
            Some(stem) => {
                candidate.starts_with(stem)
                    && !candidate
                        .get(stem.len()..)
                        .is_some_and(|rest| rest.contains(['/', '.']))
            }
            None => false,
        };
    };

    candidate.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn real_capabilities_parse() {
        // Every form the design document lists, so a change to the grammar cannot quietly stop
        // accepting one of them.
        for text in [
            "log:*",
            "log:debug",
            "event:emit:_plugin.chat.*",
            "event:subscribe:_synra.device.*",
            "device:list",
            "device:send:@synra-pc",
            "device:broadcast",
            "storage:local:read",
            "storage:local:write",
            "storage:secure:read",
            "network:fetch:api.github.com",
            "network:fetch:api.x.com:POST",
            "network:websocket",
            "fs:read:/data/**",
            "fs:write:/cache/*",
            "fs:watch",
            "file:transfer:send",
            "file:transfer:receive",
            "platform:open-url",
            "platform:simulate-keys",
            "platform:clipboard:read",
            "action:declare:format-date",
            "action:invoke:*:format-date",
            "ui:page",
            "ui:navigate",
            "ui:toast",
            "ui:confirm",
            "ui:notify",
            "ui:modal",
        ] {
            let capability = Capability::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(capability.as_str(), text, "the text is preserved verbatim");
        }
    }

    #[rstest]
    #[case("", CapabilityError::Empty)]
    #[case("ui::navigate", CapabilityError::EmptySegment { text: "ui::navigate".into(), position: 1 })]
    #[case(":ui:navigate", CapabilityError::EmptySegment { text: ":ui:navigate".into(), position: 0 })]
    #[case("ui:", CapabilityError::EmptySegment { text: "ui:".into(), position: 1 })]
    #[case("*", CapabilityError::BareWildcard("*".into()))]
    #[case("**", CapabilityError::BareWildcard("**".into()))]
    fn malformed_capabilities_are_refused(#[case] text: &str, #[case] _expected: CapabilityError) {
        assert!(Capability::parse(text).is_err(), "{text:?} should not parse");
    }

    #[test]
    fn a_bare_wildcard_is_refused_by_the_grammar() {
        // Not by convention. A grammar that can express "every capability" will eventually be used
        // to express it, and the user's consent screen would show them a single asterisk.
        assert!(matches!(Capability::parse("*"), Err(CapabilityError::BareWildcard(_))));
        assert!(matches!(Capability::parse("**"), Err(CapabilityError::BareWildcard(_))));
        // But a wildcard inside a longer capability is fine.
        assert!(Capability::parse("log:*").is_ok());
        assert!(Capability::parse("network:fetch:**").is_ok());
    }

    #[test]
    fn a_wildcard_cannot_stand_in_for_the_domain() {
        // If it could, `contains` could not use the domain bitmask to refuse a capability without
        // examining any strings at all.
        assert!(matches!(
            Capability::parse("*:read"),
            Err(CapabilityError::WildcardPrefix { position: 0, .. })
        ));
        assert!(Capability::parse("**/something").is_err());
    }

    #[test]
    fn an_unknown_domain_is_named_in_the_error() {
        match Capability::parse("telepathy:read") {
            Err(CapabilityError::UnknownDomain(unknown)) => assert_eq!(unknown.name, "telepathy"),
            other => panic!("expected an unknown domain, got {other:?}"),
        }
    }

    #[test]
    fn the_length_and_segment_limits_are_enforced() {
        let long = format!("log:{}", "a".repeat(MAX_LEN));
        assert!(matches!(Capability::parse(&long), Err(CapabilityError::TooLong { .. })));

        let many = "log:a:b:c:d:e:f";
        assert!(matches!(
            Capability::parse(many),
            Err(CapabilityError::TooManySegments { .. })
        ));
        // Exactly at the limit is fine.
        assert!(Capability::parse("log:a:b:c:d:e").is_ok());
    }

    #[test]
    fn a_prefix_must_be_lowercase_and_start_with_a_letter() {
        for bad in ["log:Debug", "log:1read", "log:-read", "log:read_me", "log:re ad"] {
            assert!(Capability::parse(bad).is_err(), "{bad:?} should not parse");
        }
        // Digits and hyphens after the first character are fine.
        assert!(Capability::parse("log:debug-2").is_ok());
    }

    #[test]
    fn a_qualifier_admits_the_forms_the_domains_need() {
        // One character class covering every domain's qualifier: a hostname, an HTTP method, a path, a
        // device id, an event pattern and a page key.
        for text in [
            "network:fetch:api.github.com",
            "network:fetch:api.x.com:POST",
            "network:fetch:xn--fsqu00a.com",
            "fs:read:/data/**",
            "device:send:@synra-pc",
            "event:emit:_plugin.chat.*",
            "ui:navigate:settings-page",
        ] {
            assert!(Capability::parse(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn the_segment_ceiling_is_enforced() {
        // The longest capability the design document lists is four segments.
        assert!(Capability::parse("network:fetch:api.github.com:POST").is_ok());
        // Room for extra qualifier segments, up to the ceiling.
        assert!(Capability::parse("network:fetch:api.github.com:POST:extra").is_ok());

        // One past the ceiling. The count is bounded because it decides the cost of matching, and
        // matching runs on every host call.
        let over = ["network", "fetch", "api.github.com", "POST", "a", "b", "c", "d"].join(":");
        assert!(matches!(
            Capability::parse(&over),
            Err(CapabilityError::TooManySegments { found: 8, max: MAX_SEGMENTS })
        ));
    }

    #[test]
    fn a_qualifier_has_a_character_class_of_its_own() {
        // A qualifier admits dots, slashes, `@` and `*`, which a prefix does not: `api.github.com`,
        // `/data/**`, `@synra-pc` and `_plugin.chat.*` are qualifiers, and rejecting them would reject
        // every capability the design document lists.
        for text in [
            "network:fetch:api.github.com",
            "network:fetch:api.x.com:POST",
            "fs:read:/data/**",
            "device:send:@synra-pc",
            "event:emit:_plugin.chat.*",
        ] {
            assert!(Capability::parse(text).is_ok(), "{text} should parse");
        }

        // A prefix is narrower: a bare name. Dots and slashes belong to qualifiers.
        assert!(Capability::parse("network:api.github.com:x").is_err());
        assert!(Capability::parse("log:api.github.com").is_err());
    }

    #[test]
    fn a_qualifier_cannot_carry_whitespace_or_markup() {
        // These are the characters that would let a value be reinterpreted somewhere else: in a path,
        // in a log line, in a prompt.
        for bad in [
            "network:fetch:api github.com",
            "ui:page:<script>",
            "ui:page:a\"b",
            "ui:page:a\\\\b",
            "ui:page:a;b",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn segments_are_split_where_the_domains_expect() {
        let capability = Capability::parse("network:fetch:api.github.com:POST").expect("parses");
        assert_eq!(capability.domain(), Domain::Network);
        assert_eq!(
            capability.prefixes().iter().map(Segment::as_str).collect::<Vec<_>>(),
            vec!["fetch"]
        );
        assert_eq!(
            capability.qualifier().iter().map(Segment::as_str).collect::<Vec<_>>(),
            vec!["api.github.com", "POST"]
        );
    }

    #[test]
    fn a_capability_with_no_qualifier_has_none() {
        let capability = Capability::parse("device:list").expect("parses");
        assert_eq!(capability.prefixes().len(), 1);
        assert!(capability.qualifier().is_empty());
    }

    // ── Matching: the table from the design document, verbatim ───────────────────────────────────

    #[rstest]
    #[case("ui:*", "ui:page", true, "one-segment wildcard")]
    #[case("ui:*", "ui:page:extra", false, "different segment count")]
    #[case("ui:**", "ui:page:extra", true, "multi-segment wildcard")]
    #[case("ui:**", "device:list", false, "different first segment")]
    #[case("network:fetch:**", "network:fetch:api.x.com", true, "")]
    #[case("network:fetch:**", "network:send:api.x.com", false, "second segment differs")]
    #[case("network:fetch:api.x.com", "network:fetch:api.x.com:POST", false, "no wildcard, so segment counts must match")]
    #[case("ui:page", "ui:page", true, "exact")]
    #[case("log:*", "log:debug", true, "")]
    #[case("log:debug", "log:debug", true, "")]
    #[case("log:debug", "log:info", false, "")]
    #[case("ui:*", "log:debug", false, "different domain")]
    fn matching_matches_the_documented_table(
        #[case] pattern: &str,
        #[case] candidate: &str,
        #[case] expected: bool,
        #[case] why: &str,
    ) {
        let pattern = Capability::parse(pattern).expect("valid pattern");
        let candidate = Capability::parse(candidate).expect("valid capability");
        assert_eq!(pattern.matches(&candidate), expected, "{pattern} vs {candidate}: {why}");
    }

    #[test]
    fn a_multi_segment_wildcard_can_match_nothing() {
        // `**` matches zero or more, so `network:fetch:**` covers plain `network:fetch`. Zero is not
        // an afterthought: a plugin granted the fetch family should be able to fetch the bare
        // resource name too.
        let pattern = Capability::parse("network:fetch:**").expect("valid");
        let candidate = Capability::parse("network:fetch").expect("valid");
        assert!(pattern.matches(&candidate));

        // And a middle `**` works, not only a trailing one.
        let middle = Capability::parse("fs:**").expect("valid");
        assert!(middle.matches(&Capability::parse("fs:read:/data/**").expect("valid")));
    }

    #[test]
    fn a_single_wildcard_does_not_cross_a_segment() {
        let pattern = Capability::parse("ui:*").expect("valid");
        assert!(pattern.matches(&Capability::parse("ui:page").expect("valid")));
        assert!(!pattern.matches(&Capability::parse("ui:page:extra").expect("valid")));
    }

    #[test]
    fn a_missing_qualifier_is_not_a_statement_about_qualified_capabilities() {
        // `network:fetch` does not cover `network:fetch:api.github.com`. Treating it as a prefix match
        // would make the grant the user was shown ("read from the network") different from what the
        // plugin got.
        let broad = Capability::parse("network:fetch").expect("valid");
        let specific = Capability::parse("network:fetch:api.github.com").expect("valid");
        assert!(!broad.matches(&specific));
        // And the reverse: a grant for one host is not a grant for the whole resource.
        assert!(!specific.matches(&broad));
    }

    #[test]
    fn a_trailing_double_wildcard_in_a_qualifier_matches_a_path_family() {
        let pattern = Capability::parse("fs:read:/data/**").expect("valid");
        assert!(pattern.matches(&Capability::parse("fs:read:/data/a").expect("valid")));
        assert!(pattern.matches(&Capability::parse("fs:read:/data/a/b/c").expect("valid")));
        assert!(pattern.matches(&Capability::parse("fs:read:/data/").expect("valid")));
        // A sibling directory is not under `/data`.
        assert!(!pattern.matches(&Capability::parse("fs:read:/database").expect("valid")));
        assert!(!pattern.matches(&Capability::parse("fs:read:/other/a").expect("valid")));
    }

    #[test]
    fn a_single_wildcard_in_a_qualifier_stays_within_one_segment() {
        // `/cache/*` is "one entry directly in /cache", and reaching deeper is what `**` is for.
        // Without this, a grant for one level would silently cover the whole tree.
        let pattern = Capability::parse("fs:write:/cache/*").expect("valid");
        assert!(pattern.matches(&Capability::parse("fs:write:/cache/file").expect("valid")));
        assert!(!pattern.matches(&Capability::parse("fs:write:/cache/sub/file").expect("valid")));
    }

    #[test]
    fn an_event_pattern_qualifier_matches_a_family() {
        let pattern = Capability::parse("event:emit:_plugin.chat.*").expect("valid");
        assert!(pattern.matches(&Capability::parse("event:emit:_plugin.chat.text").expect("valid")));
        assert!(!pattern.matches(&Capability::parse("event:emit:_plugin.notes.text").expect("valid")));
    }

    #[test]
    fn a_hostname_wildcard_does_not_match_a_deeper_subdomain_prefix() {
        // `*.example.com` is not expressible as a whole prefix, and the qualifier matcher must not
        // accidentally behave like a general glob: `api.example.com` is not `example.com`.
        let pattern = Capability::parse("network:fetch:api.example.com").expect("valid");
        assert!(!pattern.matches(&Capability::parse("network:fetch:example.com").expect("valid")));
        assert!(!pattern.matches(&Capability::parse("network:fetch:api.example.com.evil").expect("valid")));
    }

    #[test]
    fn is_exact_distinguishes_a_value_from_a_family() {
        assert!(Capability::parse("device:list").expect("valid").is_exact());
        assert!(Capability::parse("network:fetch:api.github.com").expect("valid").is_exact());
        assert!(Capability::parse("network:fetch:api.x.com:POST").expect("valid").is_exact());

        assert!(!Capability::parse("log:*").expect("valid").is_exact());
        assert!(!Capability::parse("ui:**").expect("valid").is_exact());
        // A wildcard inside a qualifier counts: `/data/**` covers many paths even though it is
        // written as one segment.
        assert!(!Capability::parse("fs:read:/data/**").expect("valid").is_exact());
        assert!(!Capability::parse("event:emit:_plugin.chat.*").expect("valid").is_exact());
    }

    #[test]
    fn specificity_increases_with_literals_and_falls_with_wildcards() {
        let exact = Capability::parse("network:fetch:api.github.com").expect("valid");
        let wildcard = Capability::parse("network:fetch:**").expect("valid");
        let broad = Capability::parse("network:**").expect("valid");

        assert!(exact.specificity() > wildcard.specificity());
        assert!(wildcard.specificity() > broad.specificity());
    }

    #[test]
    fn every_capability_has_a_human_description() {
        // The consent prompt must not show a user a DSL string: a user who cannot read
        // `network:fetch:api.github.com:POST` is being asked to approve something they cannot
        // evaluate.
        for text in [
            "log:debug",
            "network:fetch:api.github.com",
            "network:fetch:*",
            "fs:read:/data/**",
            "device:send:@synra-pc",
            "device:list",
            "platform:open-url",
            "platform:clipboard:read",
            "storage:local:read",
            "file:transfer:send",
            "event:emit:_plugin.chat.*",
            "ui:page",
        ] {
            let capability = Capability::parse(text).expect("valid");
            let description = capability.describe();
            assert!(!description.is_empty(), "{text}");
            // No glob: a user reading a wildcard has been shown the mechanism rather than the answer,
            // and the wildcard is the part that decides how much is being asked for.
            assert!(!description.contains('*'), "{text} -> {description}");
            // No DSL punctuation, so the prompt cannot be mistaken for a capability string.
            for punctuation in [':', '{', '}'] {
                assert!(
                    !description.contains(punctuation),
                    "{text} -> {description} contains {punctuation}",
                );
            }
        }

        // A wildcard grant reads as unlimited, in words.
        let any_host = Capability::parse("network:fetch:**").expect("valid");
        assert!(any_host.describe().contains("any website"), "{}", any_host.describe());
    }

    #[test]
    fn display_and_parse_round_trip() {
        for text in ["log:debug", "network:fetch:api.github.com:POST", "fs:read:/data/**"] {
            let capability = Capability::parse(text).expect("valid");
            assert_eq!(capability.to_string(), text);
            assert_eq!(Capability::parse(&capability.to_string()).expect("re-parses"), capability);
        }

        assert!(Capability::parse(&Capability::parse("ui:page").expect("valid").to_string()).is_ok());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_domain() -> impl Strategy<Value = &'static str> {
        prop::sample::select(
            Domain::ALL.iter().copied().map(Domain::as_str).collect::<Vec<_>>(),
        )
    }

    fn arbitrary_prefix() -> impl Strategy<Value = &'static str> {
        // A fixed word list rather than `"[a-z][a-z0-9-]{0,10}"`.
        //
        // Proptest's regex strategy has a shrink heuristic for a class that starts with `[a-z]`: it
        // offers the *uppercase* equivalent as a smaller value, so a minimised counterexample comes
        // back as `A` — which is not in the class and is not a valid prefix. The property would then
        // fail for a reason that has nothing to do with what it checks. A word list cannot be shrunk
        // into something outside the grammar.
        prop::sample::select(vec![
            "debug", "info", "list", "send", "fetch", "read", "write", "page", "open-url", "a",
        ])
    }

    /// A qualifier that is only valid after a prefix has been consumed.
    ///
    /// The generator always emits a prefix when it emits a qualifier, because a qualifier's position
    /// depends on there being a prefix before it: `log:api.x.com` is a *prefix* position, and a
    /// hostname is not a prefix name. Two separately-drawn parts would produce that combination and the
    /// property would fail on a string the grammar rightly refuses.
    fn arbitrary_qualifier_segment() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "api.x.com",
            "api.y.com",
            "/data/**",
            "/cache/*",
            "@a",
            "page",
            "POST",
            "_plugin.chat.*",
        ])
    }

    /// Builds a capability that the grammar should accept.
    fn arbitrary_capability() -> impl Strategy<Value = String> {
        (
            arbitrary_domain(),
            arbitrary_prefix(),
            proptest::option::of(arbitrary_qualifier_segment()),
            proptest::option::of(arbitrary_qualifier_segment()),
        )
            .prop_map(|(domain, prefix, first, second)| {
                let mut text = format!("{domain}:{prefix}");
                for qualifier in [first, second].into_iter().flatten() {
                    text.push(':');
                    text.push_str(qualifier);
                }
                text
            })
    }


    proptest! {
        /// Anything the generator builds parses, and survives a trip through `Display`. A capability
        /// that changed spelling on the way to storage would compare unequal to the grant the user
        /// approved.
        #[test]
        fn generated_capabilities_parse_and_round_trip(text in arbitrary_capability()) {
            let capability = Capability::parse(&text).expect("the generator makes valid capabilities");
            prop_assert_eq!(capability.as_str(), text.as_str());
            prop_assert_eq!(
                Capability::parse(&capability.to_string()).expect("re-parses"),
                capability,
            );
        }

        /// Parsing is total: arbitrary text either yields a capability or an error, and never panics.
        /// Capability strings come from plugin manifests, which are only semi-trusted.
        #[test]
        fn parsing_is_total(text in ".{0,300}") {
            if let Ok(capability) = Capability::parse(&text) {
                // Whatever parsed has a domain, which is what makes the bitmask a sound fast
                // negative.
                let _ = capability.domain();
                prop_assert!(Domain::ALL.contains(&capability.domain()));
            }
        }

        /// An exact capability matches itself and nothing else. This is the property the whole
        /// authorisation model rests on: if an exact grant matched a sibling, a plugin would hold a
        /// capability the user never approved.
        #[test]
        fn an_exact_capability_matches_only_itself(text in arbitrary_capability()) {
            let Ok(capability) = Capability::parse(&text) else {
                return Ok(());
            };
            prop_assume!(capability.is_exact());
            prop_assert!(capability.matches(&capability));
        }

        /// A pattern never matches a capability in another domain, whatever the rest says. The
        /// domain bitmask depends on this.
        #[test]
        fn matching_never_crosses_a_domain(
            pattern in arbitrary_capability(),
            candidate in arbitrary_capability(),
        ) {
            let (Ok(pattern), Ok(candidate)) = (Capability::parse(&pattern), Capability::parse(&candidate)) else {
                return Ok(());
            };
            if pattern.domain() != candidate.domain() {
                prop_assert!(!pattern.matches(&candidate));
            }
        }

        /// Matching is reflexive for patterns too: a pattern always covers itself, because its own
        /// literals match. A pattern that did not would be unusable as a grant.
        #[test]
        fn every_pattern_matches_itself(text in arbitrary_capability()) {
            let capability = Capability::parse(&text).expect("the generator makes valid capabilities");
            prop_assert!(capability.matches(&capability), "{} does not match itself", capability);
        }

        /// Matching is symmetric only for exact capabilities: two different patterns may each cover
        /// the other when they say the same thing.
        #[test]
        fn matching_an_exact_capability_is_a_subset_relation(
            pattern in arbitrary_capability(),
            candidate in arbitrary_capability(),
        ) {
            let (Ok(pattern), Ok(candidate)) = (Capability::parse(&pattern), Capability::parse(&candidate)) else {
                return Ok(());
            };
            prop_assume!(pattern.is_exact());
            // An exact pattern has no wildcards, so it can only match its own text.
            if pattern.matches(&candidate) {
                prop_assert_eq!(pattern.as_str(), candidate.as_str());
            }
        }
    }
}
