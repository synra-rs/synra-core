//! Event routing: which plugins a frame's event is delivered to.
//!
//! # This runs on every frame, so it cannot compare strings
//!
//! The design document puts this on the hot path for a reason: a device receiving a stream of events resolves a
//! subscription for each one. Comparing the incoming name against every plugin's every rule is O(plugins × rules) per
//! frame, and the shape of that cost is what makes an innocuous feature — a plugin that subscribes to `_synra.*` —
//! turn into a device that cannot keep up.
//!
//! So names are **numbered once**. A known event name has an [`EventId`], and routing is a table lookup by that number.
//! The string comparison happens on the first sighting of a name and never again.
//!
//! # The cache is bounded because the names come from a peer
//!
//! A remote device chooses the event names it sends. An unbounded `name → id` map is therefore a memory-growth vector:
//! a peer that sends a million distinct unknown names makes the kernel hold a million entries, and nothing about the
//! traffic looks like an attack.
//!
//! Two things bound it, and they are different defences:
//!
//! * **A cap on distinct names.** Past the cap, an unknown name is dropped rather than numbered. A dropped event is a
//!   feature that does not work; unbounded memory is a device that stops working.
//! * **A seeded hasher.** The map's keys come from a peer, so a deterministic hash would let a peer choose names that
//!   all collide — turning every lookup into a linear scan of one bucket. The seeding is what makes that impossible to
//!   arrange in advance.
//!
//! # Unregistering must remove the routes, not just the plugin
//!
//! A route table holding a handle to an unloaded plugin is a use-after-free waiting for the right event. Every route
//! is removed when a plugin goes away, and the property tests assert that no route survives an unregister for any
//! sequence of registrations.

use core::fmt;

use std::collections::HashMap;
use std::hash::RandomState;

use synra_protocol::ids::PluginId;
use synra_protocol::inbound::HandlePattern;

use crate::admission::PluginKey;

/// The most distinct unknown event names the registry will number.
///
/// A thousand. Well above any real plugin set — the kernel's own catalogue is a few dozen and a plugin's own events are
/// bounded by its manifest — and low enough that a peer streaming nonsense cannot grow the kernel's memory without
/// bound.
pub const MAX_DISTINCT_NAMES: usize = 1_024;

/// A number for a known event name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(u16);

impl EventId {
    /// The number, for a metric label or a log line.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// A number built from a value, for a test that needs a specific one.
    ///
    /// Not public beyond the crate: the registry assigns numbers, and a caller that could choose one could collide with
    /// an assignment.
    #[cfg(test)]
    const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event#{}", self.0)
    }
}

/// Why a subscription could not be registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouterError {
    /// The plugin already has a subscription to that exact rule.
    #[error("{plugin} already subscribes to {rule}")]
    Duplicate {
        /// The plugin.
        plugin: String,
        /// The rule.
        rule: String,
    },

    /// The rule is not a usable event name or pattern.
    #[error("{rule:?} is not a usable subscription")]
    BadRule {
        /// The rule that was offered.
        rule: String,
    },

    /// The registry has as many wildcard rules as it will hold.
    ///
    /// A bound rather than a limit on plugins: the wildcard rules are scanned on every frame, so their number is the
    /// per-frame cost of the registry. A plugin that needs more rules than the bound is one whose manifest is asking
    /// for something the design did not anticipate.
    #[error("the registry already holds {limit} wildcard rules")]
    TooManyWildcards {
        /// The bound.
        limit: usize,
    },

    /// Numbering an event name would exceed the identifier space.
    ///
    /// [`EventId`] is sixteen bits, so this is the ceiling on `MAX_DISTINCT_NAMES` for the whole kernel — reached only
    /// if the bound is ever raised past it. Kept as a variant rather than assumed unreachable, because the two bounds
    /// live in different places and a change to one should not silently wrap the other.
    #[error("the registry has used every event number")]
    OutOfNumbers,

    /// The registry will not number another distinct name.
    #[error("the registry already holds {distinct} distinct event names")]
    Unknown {
        /// How many it holds.
        distinct: usize,
    },
}

/// A plugin's subscription to one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Subscription {
    plugin: PluginKey,
    rule: String,
    pattern: Option<HandlePattern>,
}

/// What routing an event produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteOutcome {
    /// The event went to these plugins, in the order they were registered.
    Routed(Vec<PluginKey>),
    /// Nothing subscribes to it.
    ///
    /// Ordinary rather than an error: a plugin may subscribe to a family a peer happens not to emit, and the kernel
    /// must not treat that as a fault.
    Nobody,
    /// The name is not known and the registry will not number another.
    ///
    /// The name is dropped. The count is what the interface reports, because a device whose registry is full is a
    /// device that has been sent a great many names it does not recognise.
    Unknown {
        /// How many distinct names the registry holds.
        distinct: usize,
    },
}

/// The event registry.
///
/// Owns no runtime and performs no IO: registration is what the loader does, routing is what the frame loop does, and
/// both are pure functions of the values passed in.
pub struct EventRegistry {
    /// The names that have been numbered.
    by_name: HashMap<String, EventId, RandomState>,
    /// The name behind each number, for a log line or a diagnostic report.
    names: Vec<String>,
    /// Which plugins subscribe to each number.
    ///
    /// A `Vec<Vec<..>>` rather than a map keyed by `EventId`, because the id is dense and small: an index into a vector
    /// is one bounds check and no hashing.
    routes: Vec<Vec<PluginKey>>,
    /// The rules that need matching rather than lookup.
    wildcards: Vec<Subscription>,
    /// Every subscription, so unregistering one plugin does not have to scan the routes and guess.
    subscriptions: Vec<Subscription>,
}

impl fmt::Debug for EventRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventRegistry")
            .field("distinct_names", &self.by_name.len())
            .field("wildcard_rules", &self.wildcards.len())
            .field("subscriptions", &self.subscriptions.len())
            .finish()
    }
}

mod registry;

/// What the interface shows about the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterReport {
    /// How many distinct names are numbered.
    pub distinct_names: usize,
    /// The bound on those.
    pub max_distinct_names: usize,
    /// How many wildcard rules are held.
    pub wildcard_rules: usize,
    /// The bound on those.
    pub max_wildcard_rules: usize,
    /// How many subscriptions exist in total.
    pub subscriptions: usize,
    /// How many plugins subscribe to anything.
    pub subscribers: usize,
}

impl RouterReport {
    /// Whether the registry is close to either bound.
    ///
    /// Reported because a device that has reached a bound is one where events are being dropped, and the user's
    /// experience of that is "a plugin stopped working" with nothing to explain it.
    #[must_use]
    pub const fn is_near_a_bound(&self) -> bool {
        self.distinct_names * 10 >= self.max_distinct_names * 9
            || self.wildcard_rules * 10 >= self.max_wildcard_rules * 9
    }
}

/// Why a name could not be numbered, for a caller that wants the reason rather than the outcome.
impl From<RouterError> for RouteOutcome {
    fn from(error: RouterError) -> Self {
        match error {
            RouterError::Unknown { distinct } => Self::Unknown { distinct },
            // The other errors are about registration rather than routing, and a route that reached this point has
            // already been refused by `register`. Reporting "nobody" is the safe answer: it drops the event rather than
            // routing it somewhere it does not belong.
            _ => Self::Nobody,
        }
    }
}

/// A plugin id and its rules, as the loader supplies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The plugin.
    pub plugin: PluginId,
    /// Its `handles` rules.
    pub rules: Vec<String>,
}

impl Registration {
    /// The registration as the registry wants it.
    #[must_use]
    pub fn key(&self) -> PluginKey {
        PluginKey::from(&self.plugin)
    }
}

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
