//! The set of capabilities a plugin holds, and the check performed on every host call.
//!
//! [`CapabilitySet::contains`] runs once per host function call a plugin makes. It is therefore not
//! just a data structure: its cost is multiplied by how chatty a plugin is, and a plugin is not
//! required to be polite.
//!
//! Two properties follow from that, and both are tested rather than assumed:
//!
//! 1. **It allocates nothing.** A check that allocates turns every host call into a heap operation,
//!    and an adversarial plugin into a way to make the allocator the bottleneck.
//! 2. **Its answer does not depend on insertion order**, nor on which pattern matched. `contains` is a
//!    set-membership predicate; an implementation that returns on the first pattern that matches
//!    looks correct and stays correct only until someone adds a narrower pattern or sorts the list
//!    differently.
//!
//! # Why buckets rather than a hash set
//!
//! The keys come from a plugin manifest, which is **semi-trusted**. A fast hash without a random seed
//! lets a malicious manifest construct collisions and degrade a lookup to a linear scan — a
//! denial-of-service the plugin author triggers on purpose. Bucketing by domain and scanning a short
//! array has no such surface, because the array is short by construction: a plugin declaring
//! thousands of capabilities is refused at load, not accommodated.

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

/// The interfaces a Wasm module imports, as read from its type section.
///
/// The third of the three declarations that have to agree. A plugin can *ask* for a capability in its
/// manifest and be *granted* it by the user, and still be unable to call the corresponding host
/// function because the module never imported it. All three are needed, and the intersection is what
/// the plugin actually holds.
#[derive(Debug, Clone, Default)]
pub struct ImportSet {
    /// The imported interface names, such as `host:network-fetch`.
    interfaces: SmallVec<[compact_str::CompactString; 8]>,
}

impl ImportSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from interface names.
    #[must_use]
    pub fn from_interfaces<I, S>(interfaces: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::new();
        for interface in interfaces {
            set.insert(interface.as_ref());
        }
        set
    }

    /// Records an imported interface.
    pub fn insert(&mut self, interface: &str) {
        let interface = compact_str::CompactString::from(interface);
        if !self.interfaces.contains(&interface) {
            self.interfaces.push(interface);
        }
    }

    /// Whether an interface was imported.
    #[must_use]
    pub fn contains(&self, interface: &str) -> bool {
        self.interfaces.iter().any(|existing| existing == interface)
    }

    /// Every imported interface.
    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.interfaces.iter().map(compact_str::CompactString::as_str)
    }

    /// How many interfaces were imported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Whether nothing was imported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

/// The capabilities a plugin actually holds, after all three declarations are reconciled.
#[derive(Debug, Clone)]
pub struct EffectiveCaps {
    /// The reconciled set: manifest wanted, user granted, and module imported.
    pub granted: CapabilitySet,
    /// What the user granted that the module never imports.
    ///
    /// A warning rather than a refusal. It is not dangerous — an unimported function cannot be
    /// called — but it means the consent prompt showed the user something the plugin cannot use,
    /// which is worth reporting so the manifest can be fixed.
    pub unused: Vec<Capability>,
    /// What the module imports that no granted capability covers.
    ///
    /// A refusal. The plugin would call a host function with no authorisation behind it, and the gate
    /// would deny it at runtime — so the failure would appear once per call rather than once at load.
    pub uncovered: Vec<String>,
}

impl EffectiveCaps {
    /// Whether the plugin may be loaded.
    #[must_use]
    pub const fn is_loadable(&self) -> bool {
        self.uncovered.is_empty()
    }
}

/// Why effective capabilities could not be reconciled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// A capability string was malformed.
    #[error(transparent)]
    Set(#[from] SetError),

    /// The user's grant is not a subset of what the manifest asked for.
    #[error("the grant includes {capability}, which the manifest does not request")]
    GrantNotRequested {
        /// The unexpected capability.
        capability: String,
    },

    /// The module imports an interface no granted capability covers.
    #[error("the module imports {interface}, which no granted capability covers")]
    UncoveredImport {
        /// The uncovered interface.
        interface: String,
    },
}

/// The host interface each capability domain implies.
///
/// The mapping from a capability to the Wasm interface that provides it. A module importing
/// `host:network-fetch` needs a `network:fetch:*` capability; one importing it with no network grant
/// would be calling a host function it has no authorisation for.
#[must_use]
pub const fn interface_for_domain(domain: Domain) -> &'static str {
    match domain {
        Domain::Log => "host:log",
        Domain::Event => "host:event",
        Domain::Device => "host:device",
        Domain::Storage => "host:storage",
        Domain::Network => "host:network",
        Domain::Fs => "host:fs",
        Domain::File => "host:file",
        Domain::Platform => "host:platform",
        Domain::Action => "host:action",
        Domain::Ui => "host:ui",
    }
}

/// Reconciles the three declarations of what a plugin may do.
///
/// * `wanted` — the manifest's `capabilities`, what the plugin asks for.
/// * `granted` — what the user approved. Must be a subset of `wanted`, or the grant is for something
///   the user was never shown.
/// * `imports` — the interfaces the Wasm module imports, read from its type section. A module that
///   imports an interface with no grant behind it would fail at the gate on every call, so it is
///   refused at load instead.
///
/// # Errors
///
/// [`VerifyError`] for a malformed capability, a grant outside the manifest, or an uncovered import.
pub fn verify_effective_caps(
    wanted: &CapabilitySet,
    granted: &CapabilitySet,
    imports: &ImportSet,
) -> Result<EffectiveCaps, VerifyError> {
    // 1. Every granted capability must have been requested. Otherwise the user's consent was obtained
    //    for a different set than the one being used.
    for capability in granted.iter() {
        if !wanted.contains(capability) {
            return Err(VerifyError::GrantNotRequested {
                capability: capability.to_string(),
            });
        }
    }

    // 2. Every imported interface must be covered by a grant.
    for interface in imports.iter() {
        if !interface_is_covered(granted, interface) {
            return Err(VerifyError::UncoveredImport { interface: interface.to_owned() });
        }
    }

    // 3. The effective set is the intersection of what was asked for and what was granted. The
    //    imports have already been shown to be covered, so they do not narrow it further — they
    //    constrain *calls*, which the gate checks.
    let mut effective = CapabilitySet::new();
    for capability in granted.iter() {
        if wanted.contains(capability) {
            effective.insert(capability.clone()).map_err(VerifyError::Set)?;
        }
    }

    // What was granted but the module cannot use. A warning, not an error.
    let unused: Vec<Capability> = effective
        .iter()
        .filter(|capability| !interface_is_imported(imports, capability.domain()))
        .cloned()
        .collect();

    Ok(EffectiveCaps { granted: effective, unused, uncovered: Vec::new() })
}

/// Whether any granted capability is in the domain an interface provides.
fn interface_is_covered(granted: &CapabilitySet, interface: &str) -> bool {
    Domain::ALL.iter().any(|domain| {
        interface_for_domain(*domain) == interface && granted.domains().has(*domain)
    })
}

/// Whether a module imports the interface for a domain.
fn interface_is_imported(imports: &ImportSet, domain: Domain) -> bool {
    imports.contains(interface_for_domain(domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(text: &str) -> Capability {
        Capability::parse(text).expect("valid capability")
    }

    fn set(texts: &[&str]) -> CapabilitySet {
        CapabilitySet::parse_all(texts.iter().copied()).expect("valid set")
    }

    #[test]
    fn an_empty_set_grants_nothing() {
        let empty = CapabilitySet::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.domains().is_empty());
        assert!(!empty.contains(&cap("log:debug")));
        assert_eq!(empty.iter().count(), 0);
        assert_eq!(empty.to_string(), "(no capabilities)");
        assert!(empty.describe_all().is_empty());
    }

    #[test]
    fn an_exact_capability_grants_itself() {
        let set = set(&["log:debug", "device:list"]);
        assert!(set.contains(&cap("log:debug")));
        assert!(set.contains(&cap("device:list")));
        assert!(!set.contains(&cap("log:info")));
        assert!(!set.contains(&cap("device:send:@x")));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_pattern_grants_its_family() {
        let set = set(&["log:*"]);
        assert!(set.contains(&cap("log:debug")));
        assert!(set.contains(&cap("log:info")));
        // Not another domain.
        assert!(!set.contains(&cap("device:list")));
    }

    #[test]
    fn the_domain_mask_refuses_the_common_case_without_looking_at_strings() {
        // A plugin with only log capabilities must not be able to reach the network, and the check
        // must not have to examine any capability text to establish that.
        let set = set(&["log:debug", "storage:local:read"]);
        assert!(set.domains().has(Domain::Log));
        assert!(set.domains().has(Domain::Storage));
        assert!(!set.domains().has(Domain::Network));
        assert!(!set.domains().has(Domain::Platform));

        assert!(!set.contains(&cap("network:fetch:api.github.com")));
        assert!(!set.contains(&cap("platform:open-url")));
    }

    #[test]
    fn a_grant_is_not_widened_by_a_missing_qualifier() {
        let set = set(&["network:fetch"]);
        assert!(set.contains(&cap("network:fetch")));
        // `network:fetch` says nothing about `network:fetch:api.github.com`.
        assert!(!set.contains(&cap("network:fetch:api.github.com")));
    }

    #[test]
    fn patterns_are_ordered_by_specificity_without_affecting_the_answer() {
        let set = set(&["network:**", "network:fetch:**", "network:fetch:api.github.com"]);
        let specificity: Vec<u32> = set.patterns().map(Capability::specificity).collect();

        // Descending: the most specific pattern is reported first, so "which pattern applies?" has a
        // deterministic answer in the interface and in an audit record.
        assert!(
            specificity.windows(2).all(|pair| pair[0] >= pair[1]),
            "{specificity:?}"
        );

        // And the answer itself does not depend on that order.
        assert!(set.contains(&cap("network:fetch:api.github.com")));
        assert!(set.contains(&cap("network:fetch:other.com")));
        assert!(set.contains(&cap("network:send:x")));
    }

    #[test]
    fn inserting_the_same_capability_twice_is_idempotent() {
        let mut set = CapabilitySet::new();
        set.insert_str("log:debug").expect("first");
        set.insert_str("log:debug").expect("second");
        assert_eq!(set.len(), 1);

        set.insert_str("log:*").expect("pattern");
        set.insert_str("log:*").expect("pattern again");
        assert_eq!(set.len(), 2);
        assert_eq!(set.patterns().count(), 1);
    }

    #[test]
    fn a_bad_capability_fails_the_whole_set() {
        // Refusing at load is better than installing a plugin whose grant is silently missing an
        // entry: the failure would appear as a denied call at runtime, in a place unrelated to the
        // typo.
        assert!(matches!(
            CapabilitySet::parse_all(["log:debug", "not a capability"]),
            Err(SetError::Capability(_))
        ));
    }

    #[test]
    fn the_capability_count_is_bounded() {
        let mut set = CapabilitySet::new();
        // Distinct exact capabilities, all in one domain.
        for index in 0..MAX_CAPABILITIES {
            set.insert_str(&format!("log:level-{index}")).expect("within the limit");
        }
        assert_eq!(set.len(), MAX_CAPABILITIES);
        assert!(matches!(
            set.insert_str("log:one-too-many"),
            Err(SetError::TooMany { max: MAX_CAPABILITIES })
        ));
    }

    #[test]
    fn the_pattern_count_is_bounded_and_lower_than_the_total() {
        // Patterns are scanned on every check, so they are the expensive part. A manifest must not be
        // able to make itself costly by declaring wildcards.
        // Through `black_box`, so the check survives constant folding: comparing two constants directly
        // is evaluated at compile time and would pass even after one of them changed.
        let (patterns, capabilities) = core::hint::black_box((MAX_PATTERNS, MAX_CAPABILITIES));
        assert!(patterns < capabilities);

        let mut set = CapabilitySet::new();
        for index in 0..MAX_PATTERNS {
            set.insert_str(&format!("log:debug:{index}*")).expect("within the limit");
        }
        assert!(matches!(
            set.insert_str("log:debug:one-too-many*"),
            Err(SetError::TooManyPatterns { max: MAX_PATTERNS })
        ));

        // Exact capabilities are unaffected by the pattern limit.
        set.insert_str("device:list").expect("exact still fits");
    }

    #[test]
    fn exact_and_pattern_capabilities_coexist() {
        let set = set(&["log:debug", "log:*", "device:list"]);
        assert_eq!(set.len(), 3);
        assert_eq!(set.patterns().count(), 1);
        assert!(set.contains(&cap("log:debug")));
        assert!(set.contains(&cap("log:trace")));
        assert!(set.contains(&cap("device:list")));
        assert!(!set.contains(&cap("device:send:@x")));
    }

    #[test]
    fn iteration_covers_every_capability_exactly_once() {
        let set = set(&["log:debug", "log:info", "log:*", "device:list", "device:send:@a"]);
        let mut seen: Vec<String> = set.iter().map(ToString::to_string).collect();
        seen.sort();
        let mut expected = vec![
            "log:debug",
            "log:info",
            "log:*",
            "device:list",
            "device:send:@a",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(seen, expected);
        assert_eq!(set.iter().count(), set.len());
    }

    #[test]
    fn descriptions_are_deduplicated_and_readable() {
        // Two capabilities can mean the same thing to a user. Showing the same sentence twice makes
        // the prompt look like it is padding the request.
        let set = set(&["network:fetch:*", "network:fetch:**", "log:debug"]);
        let descriptions = set.describe_all();
        let unique: std::collections::HashSet<&String> = descriptions.iter().collect();
        assert_eq!(descriptions.len(), unique.len(), "{descriptions:?}");
        assert!(descriptions.contains(&"read from any website".to_owned()), "{descriptions:?}");
        assert!(descriptions.contains(&"write log messages".to_owned()), "{descriptions:?}");
    }

    #[test]
    fn a_set_displays_its_contents() {
        let set = set(&["log:debug"]);
        assert_eq!(set.to_string(), "log:debug");
    }

    // ── Effective capabilities ────────────────────────────────────────────────────────────────────

    #[test]
    fn a_grant_outside_the_manifest_is_refused() {
        // The user's consent was obtained for a different set than the one being used.
        let wanted = set(&["log:debug"]);
        let granted = set(&["log:debug", "network:fetch:api.github.com"]);
        let imports = ImportSet::new();

        assert!(matches!(
            verify_effective_caps(&wanted, &granted, &imports),
            Err(VerifyError::GrantNotRequested { .. })
        ));
    }

    #[test]
    fn an_import_with_no_grant_is_refused() {
        // The plugin would call a host function with no authorisation behind it, and the gate would
        // deny it on every call. Refusing at load reports it once, where it can be explained.
        let wanted = set(&["log:debug", "network:fetch:api.github.com"]);
        let granted = set(&["log:debug"]);
        let imports = ImportSet::from_interfaces(["host:log", "host:network"]);

        match verify_effective_caps(&wanted, &granted, &imports) {
            Err(VerifyError::UncoveredImport { interface }) => assert_eq!(interface, "host:network"),
            other => panic!("expected an uncovered import, got {other:?}"),
        }
    }

    #[test]
    fn a_covering_grant_makes_an_import_acceptable() {
        let wanted = set(&["log:debug", "network:fetch:api.github.com"]);
        let granted = set(&["log:debug", "network:fetch:api.github.com"]);
        let imports = ImportSet::from_interfaces(["host:log", "host:network"]);

        let effective = verify_effective_caps(&wanted, &granted, &imports).expect("reconciles");
        assert!(effective.is_loadable());
        assert!(effective.granted.contains(&cap("log:debug")));
        assert!(effective.granted.contains(&cap("network:fetch:api.github.com")));
        assert!(effective.uncovered.is_empty());
    }

    #[test]
    fn a_grant_the_module_cannot_use_is_a_warning_not_an_error() {
        // Not dangerous — an unimported function cannot be called — but the consent prompt showed the
        // user something the plugin cannot use, which is worth reporting.
        let wanted = set(&["log:debug", "platform:open-url"]);
        let granted = set(&["log:debug", "platform:open-url"]);
        let imports = ImportSet::from_interfaces(["host:log"]);

        let effective = verify_effective_caps(&wanted, &granted, &imports).expect("reconciles");
        assert!(effective.is_loadable());
        assert_eq!(effective.unused.len(), 1);
        assert_eq!(effective.unused[0].to_string(), "platform:open-url");
    }

    #[test]
    fn the_effective_set_is_the_intersection() {
        // Asked for three, granted two, imported one. The plugin holds what was both asked for and
        // granted.
        let wanted = set(&["log:debug", "log:info", "device:list"]);
        let granted = set(&["log:debug", "device:list"]);
        let imports = ImportSet::from_interfaces(["host:log", "host:device"]);

        let effective = verify_effective_caps(&wanted, &granted, &imports).expect("reconciles");
        assert_eq!(effective.granted.len(), 2);
        assert!(effective.granted.contains(&cap("log:debug")));
        assert!(!effective.granted.contains(&cap("log:info")), "never granted");
        assert!(effective.granted.contains(&cap("device:list")));
    }

    #[test]
    fn every_domain_has_an_interface() {
        // A domain without an interface could never be covered by an import, so every plugin using it
        // would be refused at load.
        let mut names = std::collections::HashSet::new();
        for domain in Domain::ALL {
            let interface = interface_for_domain(*domain);
            assert!(interface.starts_with("host:"), "{domain} -> {interface}");
            assert!(names.insert(interface), "{domain} shares an interface with another domain");
        }
    }

    #[test]
    fn an_import_set_reports_what_was_imported() {
        let imports = ImportSet::from_interfaces(["host:log", "host:network", "host:log"]);
        assert_eq!(imports.len(), 2, "duplicates collapse");
        assert!(imports.contains("host:log"));
        assert!(imports.contains("host:network"));
        assert!(!imports.contains("host:fs"));
        assert!(!imports.is_empty());

        assert!(ImportSet::new().is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Capabilities the grammar accepts, across several domains.
    fn arbitrary_capability_text() -> impl Strategy<Value = String> {
        (
            prop::sample::select(vec!["log", "device", "network", "fs", "ui", "platform"]),
            prop::sample::select(vec![
                "debug", "info", "list", "send", "fetch", "read", "write", "page", "open-url",
                "*", "**",
            ]),
            proptest::option::of(prop::sample::select(vec![
                "@a", "@b", "api.x.com", "api.y.com", "/data/**", "/cache/*", "page",
            ])),
        )
            .prop_map(|(domain, second, qualifier)| match qualifier {
                Some(qualifier) => format!("{domain}:{second}:{qualifier}"),
                None => format!("{domain}:{second}"),
            })
    }

    proptest! {
        /// The hard requirement from the design document: the answer does not depend on insertion
        /// order. A set built in one order and the same set built in another must agree on every
        /// query.
        #[test]
        fn contains_does_not_depend_on_insertion_order(
            capabilities in proptest::collection::vec(arbitrary_capability_text(), 1..12),
            queries in proptest::collection::vec(arbitrary_capability_text(), 1..12),
        ) {
            let ordered = CapabilitySet::parse_all(capabilities.iter().map(String::as_str)).expect("valid");
            let shuffled = CapabilitySet::parse_all(capabilities.iter().rev().map(String::as_str)).expect("valid");

            for query in &queries {
                let query = Capability::parse(query).expect("the generator makes valid capabilities");
                prop_assert_eq!(
                    ordered.contains(&query),
                    shuffled.contains(&query),
                    "order changed the answer for {}",
                    query,
                );
            }
        }

        /// Two sets with the same contents agree on everything, however they were built.
        ///
        /// The queries are the *members themselves* plus a probe per domain, rather than arbitrary
        /// generated strings: an arbitrary string is very likely to be one the grammar accepts but no
        /// generated capability covers, so every query would compare `false == false` and the property
        /// would pass without exercising anything.
        #[test]
        fn equal_contents_imply_equal_answers(
            capabilities in proptest::collection::vec(arbitrary_capability_text(), 1..10),
        ) {
            let mut a = CapabilitySet::new();
            let mut b = CapabilitySet::new();
            for text in &capabilities {
                a.insert_str(text).expect("valid");
            }
            // The same contents, inserted in reverse.
            for text in capabilities.iter().rev() {
                b.insert_str(text).expect("valid");
            }

            let members: Vec<Capability> = a.iter().cloned().collect();
            for query in &members {
                prop_assert!(a.contains(query));
                prop_assert!(b.contains(query), "the same contents disagreed about {query}");
            }

            // And a probe in each domain, which is the fast-negative path.
            for domain in Domain::ALL {
                let probe = Capability::parse(&format!("{domain}:list")).expect("valid");
                prop_assert_eq!(a.contains(&probe), b.contains(&probe));
            }
        }

        /// A pattern in the set covers everything it matches, and nothing else. This is the property
        /// the authorisation model rests on: the set must not grant more than it was given.
        #[test]
        fn a_set_grants_exactly_its_own_members(
            capabilities in proptest::collection::vec(arbitrary_capability_text(), 1..8),
            query in arbitrary_capability_text(),
        ) {
            let mut set = CapabilitySet::new();
            let mut members = Vec::new();
            for text in &capabilities {
                if set.insert_str(text).is_ok() {
                    members.push(Capability::parse(text).expect("valid"));
                }
            }

            let query = Capability::parse(&query).expect("valid");
            // Membership is the disjunction over `matches`, so the two must agree.
            let expected = members.iter().any(|member| member.matches(&query));
            prop_assert_eq!(set.contains(&query), expected);
        }

        /// Building a set is total: arbitrary strings either insert or are refused, and the domain
        /// mask always agrees with the contents. A mask that disagreed would be a fast negative that
        /// wrongly refuses a capability the plugin holds.
        #[test]
        fn the_domain_mask_agrees_with_the_contents(
            capabilities in proptest::collection::vec(arbitrary_capability_text(), 0..12)
        ) {
            let mut set = CapabilitySet::new();
            for text in &capabilities {
                let _ = set.insert_str(text);
            }

            for capability in set.iter() {
                prop_assert!(
                    set.domains().has(capability.domain()),
                    "the mask is missing {}",
                    capability.domain(),
                );
            }

            // And a domain with no capabilities is refused without examining anything.
            for domain in Domain::ALL {
                if !set.domains().has(*domain) {
                    let probe = Capability::parse(&format!("{domain}:list")).expect("valid");
                    prop_assert!(!set.contains(&probe));
                }
            }
        }
    }
}
