//! Matching: whether a pattern covers a candidate, and how specific it is.

use super::segment::Segment;
use super::syntax::Capability;

impl Capability {
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
