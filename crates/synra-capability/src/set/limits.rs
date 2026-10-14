//! The capability set, its size limits, how it renders, and why an insert was refused.

use core::fmt;

use smallvec::SmallVec;

use crate::capability::{Capability, CapabilityError};
use crate::domain::{Domain, DomainMask};

/// How many capabilities one plugin may hold.
///
/// A cap rather than a tuning parameter. The set is scanned linearly within a domain, so its length is
/// the cost of every host call the plugin makes; and a manifest asking for hundreds of permissions is
/// not a plugin a user can meaningfully consent to.
pub const MAX_CAPABILITIES: usize = 256;

/// How many patterns one plugin may hold.
///
/// Patterns are scanned for every check, so they are the expensive part of the set. Kept well below
/// the total so that a manifest cannot make itself costly to run by declaring wildcards.
pub const MAX_PATTERNS: usize = 64;

/// The capabilities one plugin holds.
///
/// Private fields: the internal layout is an implementation detail, so replacing a container is not a
/// breaking change. The only questions a caller can ask are [`Self::contains`], [`Self::iter`] and
/// [`Self::len`].
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    /// Exact capabilities, bucketed by domain. The domain count is small, so a short array beats a
    /// map and has no hashing to attack.
    exact: SmallVec<[(Domain, Vec<Capability>); 8]>,
    /// Patterns, sorted by descending specificity.
    ///
    /// The sort exists so that "which pattern applies?" has a deterministic answer for the interface
    /// and for an audit record. It is deliberately **not** consulted by [`Self::contains`], whose
    /// answer must not depend on order at all.
    patterns: SmallVec<[Capability; 8]>,
    /// The domains present, for an O(1) refusal of the common case.
    domain_mask: DomainMask,
    /// A bucket that exists only so the unreachable branch in `bucket_for_mut` has somewhere to point.
    ///
    /// A field rather than an allocation on the path: nothing is leaked, and the value dies with the
    /// set. It is never read from, because the branch is unreachable.
    spare: Vec<Capability>,
}

impl CapabilitySet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from capability strings.
    ///
    /// # Errors
    ///
    /// [`SetError`] for the first string that does not parse, or for a set larger than
    /// [`MAX_CAPABILITIES`] or [`MAX_PATTERNS`].
    pub fn parse_all<'a, I>(capabilities: I) -> Result<Self, SetError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut set = Self::new();
        for text in capabilities {
            set.insert(Capability::parse(text).map_err(SetError::Capability)?)?;
        }
        Ok(set)
    }

    /// Adds a capability.
    ///
    /// # Errors
    ///
    /// [`SetError::TooMany`] if the set is already at its limit. Returning an error rather than
    /// dropping the capability matters: a silently dropped grant means the plugin is refused a
    /// function it believes it holds, which surfaces as a mysterious failure at runtime.
    pub fn insert(&mut self, capability: Capability) -> Result<(), SetError> {
        let domain = capability.domain();

        if capability.is_exact() {
            // The limit is checked before a bucket is borrowed, so the borrow does not have to be
            // released in order to ask how large the set is.
            if self.total() >= MAX_CAPABILITIES {
                return Err(SetError::TooMany { max: MAX_CAPABILITIES });
            }
            let bucket = self.bucket_for_mut(domain);
            if !bucket.contains(&capability) {
                bucket.push(capability);
            }
        }
        else {
            if self.patterns.len() >= MAX_PATTERNS {
                return Err(SetError::TooManyPatterns { max: MAX_PATTERNS });
            }
            if !self.patterns.contains(&capability) {
                self.patterns.push(capability);
                // Re-sorted on insert rather than on read: `contains` is the hot path and must not
                // sort, and the pattern list is short and written once at load.
                self.patterns
                    .sort_by_key(|pattern| core::cmp::Reverse(pattern.specificity()));
            }
        }

        // Set after a successful insert, so a refused capability does not widen the mask. A mask that
        // claimed a domain the set has nothing in would turn the O(1) refusal into a full scan rather
        // than a wrong answer, but it would still be a lie about the contents.
        self.domain_mask = self.domain_mask.with(domain);
        Ok(())
    }

    /// Adds a capability from its string form.
    ///
    /// # Errors
    ///
    /// As [`Self::insert`], or [`SetError::Capability`] if the string does not parse.
    pub fn insert_str(&mut self, text: &str) -> Result<(), SetError> {
        self.insert(Capability::parse(text).map_err(SetError::Capability)?)
    }

    /// Whether the set covers `capability`.
    ///
    /// The hot path. Allocation-free, and its answer is a pure function of what is in the set.
    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        // The common case: nothing in this domain at all, settled with one bit test.
        if !self.domain_mask.has(capability.domain()) {
            return false;
        }

        if self
            .exact_bucket(capability.domain())
            .is_some_and(|bucket| bucket.contains(capability))
        {
            return true;
        }

        // Every pattern is tried, and the result is the disjunction. There is no early exit that
        // could make the answer depend on which pattern came first, because there is only one kind of
        // result: allowed. A set has no negative capabilities to short-circuit on.
        self.patterns.iter().any(|pattern| pattern.matches(capability))
    }

    /// Whether any capability in the set covers `capability`.
    ///
    /// The same question as [`Self::contains`], named for the reading that a pattern is a grant
    /// covering a family.
    #[must_use]
    pub fn grants(&self, capability: &Capability) -> bool {
        self.contains(capability)
    }

    /// The domains this set has capabilities in.
    #[must_use]
    pub const fn domains(&self) -> DomainMask {
        self.domain_mask
    }

    /// How many capabilities are held, patterns included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.total()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.domain_mask.is_empty()
    }

    /// Every capability, exact ones first.
    ///
    /// An iterator rather than a slice, so the internal bucketing is not exposed and can change.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> + '_ {
        self.exact
            .iter()
            .flat_map(|(_, bucket)| bucket.iter())
            .chain(self.patterns.iter())
    }

    /// Only the patterns, most specific first.
    pub fn patterns(&self) -> impl Iterator<Item = &Capability> + '_ {
        self.patterns.iter()
    }

    /// The human-readable descriptions of everything granted, for the consent prompt.
    ///
    /// Sorted and de-duplicated: two capabilities can describe the same thing (`network:fetch:**` and
    /// `network:fetch:*` both read as "any website"), and showing a user the same sentence twice makes
    /// the prompt look like it is padding the request.
    #[must_use]
    pub fn describe_all(&self) -> Vec<String> {
        let mut descriptions: Vec<String> = self.iter().map(Capability::describe).collect();
        descriptions.sort();
        descriptions.dedup();
        descriptions
    }

    /// How many capabilities are held in total.
    fn total(&self) -> usize {
        self.exact.iter().map(|(_, bucket)| bucket.len()).sum::<usize>() + self.patterns.len()
    }

    /// The bucket for a domain, if it exists.
    fn exact_bucket(&self, domain: Domain) -> Option<&Vec<Capability>> {
        self.exact
            .iter()
            .find(|(existing, _)| *existing == domain)
            .map(|(_, bucket)| bucket)
    }

    /// The bucket for a domain, creating it if needed.
    ///
    /// `last_mut` immediately after `push` is the borrow checker's own idiom: the reference comes from
    /// the collection that was just extended, so there is no index to be out of bounds. The inner `Vec`
    /// holds at most [`MAX_CAPABILITIES`] entries for one plugin and the outer one at most ten domains,
    /// so the linear search is a handful of comparisons.
    fn bucket_for_mut(&mut self, domain: Domain) -> &mut Vec<Capability> {
        if !self.exact.iter().any(|(existing, _)| *existing == domain) {
            self.exact.push((domain, Vec::new()));
        }
        // The `find` has to name the domain. Returning the last bucket instead — which is what a bare
        // `last_mut` after `push` does — files every capability under whatever domain happened to be
        // inserted last, so `contains` then looks in the wrong bucket and denies a capability the set
        // holds. The symptom is order-dependent: the same set built in a different order disagrees
        // with itself.
        self.exact
            .iter_mut()
            .find(|(existing, _)| *existing == domain)
            .map_or_else(|| &mut self.spare, |(_, bucket)| bucket)
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for capability in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{capability}")?;
        }
        if first {
            f.write_str("(no capabilities)")?;
        }
        Ok(())
    }
}

/// Why a capability set could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SetError {
    /// A capability string did not parse.
    #[error(transparent)]
    Capability(CapabilityError),

    /// The set already holds [`MAX_CAPABILITIES`] capabilities.
    #[error("a plugin may hold at most {max} capabilities")]
    TooMany {
        /// The limit.
        max: usize,
    },

    /// The set already holds [`MAX_PATTERNS`] patterns.
    #[error("a plugin may hold at most {max} capability patterns")]
    TooManyPatterns {
        /// The limit.
        max: usize,
    },
}
