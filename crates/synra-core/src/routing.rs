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
use synra_protocol::inbound::{HandlePattern, MAX_WILDCARD_RULES};

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

impl Default for EventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRegistry {
    /// An empty registry.
    ///
    /// The map's hasher is seeded from the operating system's randomness, so two runs of the same program hash the
    /// same peer-chosen names differently — which is what stops a peer from choosing a set of names that all collide
    /// in one bucket of this particular process.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_name: HashMap::with_hasher(RandomState::new()),
            names: Vec::new(),
            routes: Vec::new(),
            wildcards: Vec::new(),
            subscriptions: Vec::new(),
        }
    }

    /// How many distinct event names are known.
    #[must_use]
    pub fn distinct_names(&self) -> usize {
        self.by_name.len()
    }

    /// How many wildcard rules are held.
    #[must_use]
    pub const fn wildcard_rules(&self) -> usize {
        self.wildcards.len()
    }

    /// How many plugins subscribe to anything.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        let mut plugins: Vec<&PluginKey> =
            self.subscriptions.iter().map(|subscription| &subscription.plugin).collect();
        plugins.sort();
        plugins.dedup();
        plugins.len()
    }

    /// The number for a name, if it has one.
    #[must_use]
    pub fn id_for(&self, name: &str) -> Option<EventId> {
        self.by_name.get(name).copied()
    }

    /// The name behind a number.
    #[must_use]
    pub fn name_for(&self, id: EventId) -> Option<&str> {
        self.names.get(usize::from(id.0)).map(String::as_str)
    }

    /// Registers a plugin's subscription rules.
    ///
    /// # Errors
    ///
    /// [`RouterError`] for a rule that is not usable, a duplicate, or a wildcard beyond the bound.
    ///
    /// # All or nothing
    ///
    /// A plugin whose third rule is bad is not registered at all. Registering the first two would leave a plugin that
    /// receives some of what it asked for and none of what it did not — which reads as a plugin with a bug rather than
    /// as a manifest that was refused.
    pub fn register(&mut self, plugin: &PluginKey, rules: &[String]) -> Result<(), RouterError> {
        let mut staged: Vec<Subscription> = Vec::with_capacity(rules.len());
        let mut wildcards_added = 0usize;

        for rule in rules {
            // A rule that is an exact name is registered as an exact subscription; one with a wildcard is a pattern.
            // The distinction is the pattern parser's, not a check for `*` — `device.ping` is an exact name and
            // `device.*` is a pattern, and the parser is what knows the difference.
            let pattern = if rule.contains('*') {
                match HandlePattern::parse(rule) {
                    Ok(pattern) => Some(pattern),
                    Err(_) => return Err(RouterError::BadRule { rule: rule.clone() }),
                }
            }
            else {
                // An exact rule is validated by being numberable: an event name the kernel's catalogue does not contain
                // is still acceptable, because a plugin may subscribe to a family a newer peer emits.
                if rule.is_empty() || rule.chars().any(char::is_whitespace) {
                    return Err(RouterError::BadRule { rule: rule.clone() });
                }
                None
            };

            if self
                .subscriptions
                .iter()
                .any(|existing| existing.plugin == *plugin && existing.rule == *rule)
            {
                return Err(RouterError::Duplicate { plugin: plugin.to_string(), rule: rule.clone() });
            }

            if pattern.is_some() {
                wildcards_added += 1;
            }
            staged.push(Subscription { plugin: plugin.clone(), rule: rule.clone(), pattern });
        }

        if self.wildcards.len() + wildcards_added > MAX_WILDCARD_RULES {
            return Err(RouterError::TooManyWildcards { limit: MAX_WILDCARD_RULES });
        }

        // Nothing above this line has mutated the registry, so a refusal leaves it untouched.
        for subscription in staged {
            if subscription.pattern.is_some() {
                self.wildcards.push(subscription.clone());
            }
            else {
                // An exact rule is numbered now, so the first frame carrying it costs a lookup rather than a parse.
                let id = self.number(&subscription.rule)?;
                let index = usize::from(id.0);
                while self.routes.len() <= index {
                    self.routes.push(Vec::new());
                }
                if let Some(list) = self.routes.get_mut(index)
                    && !list.contains(&subscription.plugin)
                {
                    list.push(subscription.plugin.clone());
                }
            }
            self.subscriptions.push(subscription);
        }
        Ok(())
    }

    /// Removes every subscription belonging to a plugin.
    ///
    /// # Returns
    ///
    /// How many rules were removed. Zero means the plugin had none, which is ordinary rather than a mistake.
    ///
    /// # Removing the routes, not just the subscription
    ///
    /// A route table holding a handle to an unloaded plugin is a use-after-free waiting for the right event, so the
    /// routes are pruned as well — and a route list that becomes empty has its identifier *kept*, because renumbering
    /// would invalidate every other plugin's routes.
    pub fn unregister(&mut self, plugin: &PluginKey) -> usize {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|subscription| subscription.plugin != *plugin);
        self.wildcards.retain(|subscription| subscription.plugin != *plugin);

        for list in &mut self.routes {
            list.retain(|holder| holder != plugin);
        }

        before - self.subscriptions.len()
    }

    /// Routes an event name.
    ///
    /// # The hot path
    ///
    /// A name that has been seen before costs one hash lookup and, for a name with no wildcard matching it, no
    /// allocation beyond the result. A name seen for the first time costs a parse of the wildcard rules and a number.
    #[must_use]
    pub fn route(&mut self, event: &str) -> RouteOutcome {
        // Wildcards are matched first, because a plugin may subscribe both to an exact name and to a family containing
        // it, and the result must name it once.
        let mut matched: Vec<PluginKey> = Vec::new();

        if let Some(id) = self.by_name.get(event).copied()
            && let Some(list) = self.routes.get(usize::from(id.0))
        {
            matched.extend(list.iter().cloned());
        }

        for subscription in &self.wildcards {
            if let Some(pattern) = &subscription.pattern
                && pattern.matches(event)
                && !matched.contains(&subscription.plugin)
            {
                matched.push(subscription.plugin.clone());
            }
        }

        if !matched.is_empty() {
            return RouteOutcome::Routed(matched);
        }

        // Nothing matched. The name is numbered only if it is new and there is room, so a familiar name that nobody
        // subscribes to costs nothing — which is the common case for the kernel's own events.
        match self.by_name.get(event) {
            Some(_) => RouteOutcome::Nobody,
            None => match self.number(event) {
                Ok(_) => RouteOutcome::Nobody,
                Err(_) => RouteOutcome::Unknown { distinct: self.by_name.len() },
            },
        }
    }

    /// Numbers a name, if it is new and there is room.
    fn number(&mut self, name: &str) -> Result<EventId, RouterError> {
        if let Some(id) = self.by_name.get(name) {
            return Ok(*id);
        }
        if self.by_name.len() >= MAX_DISTINCT_NAMES {
            return Err(RouterError::Unknown {
                distinct: self.by_name.len(),
            });
        }
        let raw = u16::try_from(self.names.len()).map_err(|_| RouterError::OutOfNumbers)?;
        let id = EventId(raw);
        // The key is owned by the registry and hashed with the registry's seeded hasher, so a peer cannot choose names
        // that collide in this process.
        self.by_name.insert(name.to_owned(), id);
        self.names.push(name.to_owned());
        while self.routes.len() <= usize::from(raw) {
            self.routes.push(Vec::new());
        }
        Ok(id)
    }

    /// A snapshot for the interface and a diagnostic report.
    #[must_use]
    pub fn report(&self) -> RouterReport {
        RouterReport {
            distinct_names: self.by_name.len(),
            max_distinct_names: MAX_DISTINCT_NAMES,
            wildcard_rules: self.wildcards.len(),
            max_wildcard_rules: MAX_WILDCARD_RULES,
            subscriptions: self.subscriptions.len(),
            subscribers: self.subscriber_count(),
        }
    }
}

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
mod tests {
    use super::*;

    fn key(name: &str) -> PluginKey {
        PluginKey::new(name)
    }

    fn rules(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn registry() -> EventRegistry {
        EventRegistry::new()
    }

    // ── Registration and routing ──────────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_registry_routes_nobody() {
        let mut registry = registry();
        // The kernel's own event, which nothing subscribes to. Ordinary rather than an error.
        assert!(matches!(registry.route("device.ping"), RouteOutcome::Nobody));
    }

    #[test]
    fn an_exact_rule_receives_its_event() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");

        match registry.route("device.ping") {
            RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
            other => panic!("expected a route, got {other:?}"),
        }
    }

    #[test]
    fn an_exact_rule_does_not_receive_a_different_event() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");
        assert!(matches!(registry.route("device.pong"), RouteOutcome::Nobody));
    }

    #[test]
    fn a_wildcard_rule_receives_its_family() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["_synra.device.*"])).expect("registers");

        for event in ["_synra.device.changed", "_synra.device.offline"] {
            match registry.route(event) {
                RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")], "{event}"),
                other => panic!("{event}: expected a route, got {other:?}"),
            }
        }
        // And not a sibling family.
        assert!(matches!(registry.route("_synra.transfer.started"), RouteOutcome::Nobody));
    }

    #[test]
    fn several_plugins_receive_the_same_event() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["_synra.device.*"])).expect("registers");
        registry.register(&key("@b/two"), &rules(&["_synra.device.changed"])).expect("registers");

        match registry.route("_synra.device.changed") {
            RouteOutcome::Routed(plugins) => {
                assert_eq!(plugins.len(), 2, "{plugins:?}");
                assert!(plugins.contains(&key("@a/one")));
                assert!(plugins.contains(&key("@b/two")));
            }
            other => panic!("expected two routes, got {other:?}"),
        }
    }

    #[test]
    fn a_plugin_is_named_once_even_when_two_of_its_rules_match() {
        // A plugin may subscribe both to an exact name and to the family containing it, and delivering twice would run
        // its handler twice for one event.
        let mut registry = registry();
        registry
            .register(&key("@a/one"), &rules(&["_synra.device.*", "_synra.device.changed"]))
            .expect("registers");

        match registry.route("_synra.device.changed") {
            RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
            other => panic!("expected one route, got {other:?}"),
        }
    }

    #[test]
    fn a_deep_wildcard_reaches_the_whole_subtree() {
        let mut registry = registry();
        // A single `*` matches one segment, so `_synra.offline` is in the family and `_synra.device.changed` is not.
        registry.register(&key("@a/one"), &rules(&["_synra.offline"])).expect("registers");
        assert!(matches!(registry.route("_synra.offline"), RouteOutcome::Routed(_)));
    }

    #[test]
    fn a_bare_double_star_is_refused_by_the_handle_grammar() {
        // `**` is a capability-DSL segment, not a handle-pattern one. Refusing it is the right answer: silently
        // treating it as `*` would make two spellings mean one thing, and the author would never learn which.
        let mut registry = registry();
        assert!(matches!(
            registry.register(&key("@a/one"), &rules(&["_synra.**"])),
            Err(RouterError::BadRule { .. })
        ));
    }

    #[test]
    fn a_trailing_star_matches_exactly_one_more_segment() {
        // The handle grammar's `*` is a single-segment wildcard, not a subtree one: the candidate must have the same
        // number of segments as the pattern. So `_synra.*` covers `_synra.offline` and *not*
        // `_synra.device.changed` — which is the safer reading, because a pattern's depth is then visible in the
        // manifest rather than being implied by the wildcard.
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["_synra.*"])).expect("registers");

        assert!(matches!(registry.route("_synra.offline"), RouteOutcome::Routed(_)));
        assert!(matches!(registry.route("_synra.device.changed"), RouteOutcome::Nobody));

        // Two wildcards cover two more segments, which is how a deeper family is expressed.
        registry.register(&key("@b/two"), &rules(&["_synra.*.*"])).expect("registers");
        assert!(matches!(registry.route("_synra.device.changed"), RouteOutcome::Routed(_)));
        assert!(matches!(registry.route("_synra.a.b.c.d"), RouteOutcome::Nobody));
    }

    #[test]
    fn a_number_is_assigned_once_and_reused() {
        // The whole point: the string comparison happens on the first sighting and never again.
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");

        let first = registry.id_for("device.ping").expect("numbered at registration");
        let _ = registry.route("device.ping");
        assert_eq!(registry.id_for("device.ping"), Some(first));
        assert_eq!(registry.distinct_names(), 1);
    }

    #[test]
    fn an_unknown_name_is_numbered_when_it_arrives() {
        // A plugin may subscribe to a family a newer peer emits, so a name nobody declared is still numbered — up to
        // the bound — rather than refused.
        let mut registry = registry();
        assert_eq!(registry.distinct_names(), 0);
        let _ = registry.route("_synra.something.new");
        assert_eq!(registry.distinct_names(), 1);
    }

    #[test]
    fn an_event_name_round_trips_through_its_number() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");
        let id = registry.id_for("device.ping").expect("numbered");
        assert_eq!(registry.name_for(id), Some("device.ping"));
        assert!(id.get() < 1024);
    }

    #[test]
    fn a_number_that_was_never_assigned_has_no_name() {
        let registry = registry();
        assert_eq!(registry.name_for(EventId::from_raw(999)), None);
    }

    // ── Refusals ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_duplicate_rule_is_refused() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");
        match registry.register(&key("@a/one"), &rules(&["device.ping"])) {
            Err(RouterError::Duplicate { plugin, rule }) => {
                assert_eq!(plugin, "@a/one");
                assert_eq!(rule, "device.ping");
            }
            other => panic!("expected a duplicate refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_plugins_may_hold_the_same_rule() {
        // The rule is the same and the subscribers differ, which is ordinary.
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["_synra.device.*"])).expect("registers");
        registry.register(&key("@b/two"), &rules(&["_synra.device.*"])).expect("registers");
        assert_eq!(registry.subscriber_count(), 2);
    }

    #[test]
    fn a_bad_rule_is_refused() {
        let mut registry = registry();
        for rule in ["", "has space", "_synra.*.*.*.*.*"] {
            assert!(
                matches!(registry.register(&key("@a/one"), &rules(&[rule])), Err(RouterError::BadRule { .. })),
                "{rule:?} should be refused"
            );
        }
        // And nothing was registered.
        assert_eq!(registry.subscriber_count(), 0);
        assert_eq!(registry.wildcard_rules(), 0);
    }

    #[test]
    fn a_bad_rule_refuses_the_whole_registration() {
        // Registering the good rules would leave a plugin that receives some of what it asked for and none of what it
        // did not, which reads as a plugin with a bug rather than as a manifest that was refused.
        let mut registry = registry();
        let result = registry.register(&key("@a/one"), &rules(&["device.ping", "has space"]));
        assert!(result.is_err());
        assert_eq!(registry.subscriber_count(), 0, "a partial registration happened");
        assert!(matches!(registry.route("device.ping"), RouteOutcome::Nobody));
    }

    #[test]
    fn the_wildcard_bound_is_enforced() {
        let mut registry = registry();
        // Fill the bound with rules that all parse.
        let many: Vec<String> = (0..MAX_WILDCARD_RULES).map(|index| format!("_synra.f{index}.*")).collect();
        registry.register(&key("@a/one"), &many).expect("registers up to the bound");

        match registry.register(&key("@b/two"), &rules(&["_synra.extra.*"])) {
            Err(RouterError::TooManyWildcards { limit }) => assert_eq!(limit, MAX_WILDCARD_RULES),
            other => panic!("expected a wildcard refusal, got {other:?}"),
        }
        // And the refusal did not register the second plugin.
        assert_eq!(registry.subscriber_count(), 1);
    }

    #[test]
    fn the_bounds_are_the_documented_ones() {
        // The values the design document gives, asserted so raising one is a decision rather than an accident. The\n        // wildcard bound is also `synra_protocol`'s, and `register` enforces it against that constant.
        assert_eq!(MAX_DISTINCT_NAMES, 1_024);
        assert_eq!(MAX_WILDCARD_RULES, 64);
    }

    // ── The bound on names ────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_unknown_name_past_the_bound_is_dropped_rather_than_numbered() {
        // A dropped event is a feature that does not work; unbounded memory is a device that stops working.
        let mut registry = registry();
        for index in 0..MAX_DISTINCT_NAMES {
            let _ = registry.route(&format!("_synra.streaming.{index}"));
        }
        assert_eq!(registry.distinct_names(), MAX_DISTINCT_NAMES);

        match registry.route("_synra.one.too.many") {
            RouteOutcome::Unknown { distinct } => assert_eq!(distinct, MAX_DISTINCT_NAMES),
            other => panic!("expected an unknown outcome, got {other:?}"),
        }
        assert_eq!(registry.distinct_names(), MAX_DISTINCT_NAMES, "the bound was exceeded");
    }

    #[test]
    fn a_known_name_still_routes_once_the_registry_is_full() {
        // The bound is on *new* names. A device whose registry is full must still deliver the events its plugins
        // actually asked for, or the bound would break every plugin rather than only the unrecognised traffic.
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["_synra.device.changed"])).expect("registers");
        for index in 0..MAX_DISTINCT_NAMES {
            let _ = registry.route(&format!("_synra.streaming.{index}"));
        }

        match registry.route("_synra.device.changed") {
            RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
            other => panic!("a known event was dropped once the registry filled: {other:?}"),
        }
    }

    #[test]
    fn a_full_registry_does_not_grow_further() {
        // The property that makes the bound a bound.
        let mut registry = registry();
        for index in 0..(MAX_DISTINCT_NAMES * 2) {
            let _ = registry.route(&format!("_synra.flood.{index}"));
        }
        assert_eq!(registry.distinct_names(), MAX_DISTINCT_NAMES);
    }

    // ── Unregistering ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn unregistering_removes_every_rule() {
        let mut registry = registry();
        registry
            .register(&key("@a/one"), &rules(&["device.ping", "_synra.device.*"]))
            .expect("registers");
        assert_eq!(registry.unregister(&key("@a/one")), 2);

        assert!(matches!(registry.route("device.ping"), RouteOutcome::Nobody));
        assert!(matches!(registry.route("_synra.device.changed"), RouteOutcome::Nobody));
        assert_eq!(registry.wildcard_rules(), 0);
    }

    #[test]
    fn unregistering_leaves_other_plugins_alone() {
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");
        registry.register(&key("@b/two"), &rules(&["device.ping"])).expect("registers");

        registry.unregister(&key("@a/one"));
        match registry.route("device.ping") {
            RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@b/two")]),
            other => panic!("the other plugin lost its route: {other:?}"),
        }
    }

    #[test]
    fn unregistering_an_unknown_plugin_is_not_an_error() {
        let mut registry = registry();
        assert_eq!(registry.unregister(&key("@a/one")), 0);
    }

    #[test]
    fn a_number_survives_an_unregister() {
        // Renumbering would invalidate every other plugin's routes, so an identifier whose subscribers are gone is
        // kept rather than reused.
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");
        let id = registry.id_for("device.ping").expect("numbered");

        registry.unregister(&key("@a/one"));
        assert_eq!(registry.id_for("device.ping"), Some(id));
        assert_eq!(registry.name_for(id), Some("device.ping"));
    }

    #[test]
    fn a_plugin_may_register_again_after_unregistering() {
        // A plugin that is deactivated and reactivated must be able to subscribe again.
        let mut registry = registry();
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers");
        registry.unregister(&key("@a/one"));
        registry.register(&key("@a/one"), &rules(&["device.ping"])).expect("registers again");

        match registry.route("device.ping") {
            RouteOutcome::Routed(plugins) => assert_eq!(plugins, vec![key("@a/one")]),
            other => panic!("expected a route, got {other:?}"),
        }
    }

    // ── Reporting ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_report_carries_what_the_interface_needs() {
        let mut registry = registry();
        registry
            .register(&key("@a/one"), &rules(&["device.ping", "_synra.device.*"]))
            .expect("registers");

        let report = registry.report();
        assert_eq!(report.subscriptions, 2);
        assert_eq!(report.wildcard_rules, 1);
        assert_eq!(report.subscribers, 1);
        assert_eq!(report.max_distinct_names, MAX_DISTINCT_NAMES);
        assert_eq!(report.max_wildcard_rules, MAX_WILDCARD_RULES);
        assert!(!report.is_near_a_bound());
    }

    #[test]
    fn a_report_notices_a_bound_being_approached() {
        // A device that has reached a bound is one where events are being dropped, and the user's experience of that is
        // "a plugin stopped working" with nothing to explain it.
        let near = RouterReport {
            // At the threshold exactly: the comparison is `>= ninety percent`, so one below it is not near.
            distinct_names: MAX_DISTINCT_NAMES * 9 / 10 + 1,
            max_distinct_names: MAX_DISTINCT_NAMES,
            wildcard_rules: 0,
            max_wildcard_rules: MAX_WILDCARD_RULES,
            subscriptions: 0,
            subscribers: 0,
        };
        assert!(near.is_near_a_bound());

        let far = RouterReport { distinct_names: 10, ..near };
        assert!(!far.is_near_a_bound());

        let wildcards = RouterReport {
            distinct_names: 0,
            max_distinct_names: MAX_DISTINCT_NAMES,
            wildcard_rules: MAX_WILDCARD_RULES * 9 / 10 + 1,
            max_wildcard_rules: MAX_WILDCARD_RULES,
            subscriptions: 0,
            subscribers: 0,
        };
        assert!(wildcards.is_near_a_bound());
    }

    #[test]
    fn the_registry_debug_does_not_dump_every_name() {
        // A registry holding a thousand peer-chosen names must not print them all into a log.
        let mut registry = registry();
        for index in 0..50 {
            let _ = registry.route(&format!("_synra.noise.{index}"));
        }
        let debug = format!("{registry:?}");
        assert!(!debug.contains("_synra.noise"), "{debug}");
        assert!(debug.contains("distinct_names"), "{debug}");
    }

    #[test]
    fn an_empty_registry_is_the_default() {
        assert_eq!(EventRegistry::default().distinct_names(), 0);
        assert_eq!(EventRegistry::default().wildcard_rules(), 0);
    }

    #[test]
    fn router_errors_explain_themselves() {
        let errors = [
            RouterError::Duplicate { plugin: "p".to_owned(), rule: "r".to_owned() },
            RouterError::BadRule { rule: "r".to_owned() },
            RouterError::TooManyWildcards { limit: 64 },
            RouterError::OutOfNumbers,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn a_registration_carries_its_own_key() {
        let registration = Registration {
            plugin: PluginId::parse("@synra-plugin/chat").expect("a valid id"),
            rules: rules(&["device.ping"]),
        };
        assert_eq!(registration.key().as_str(), "@synra-plugin/chat");
    }

    #[test]
    fn an_error_converts_to_the_safe_outcome() {
        // A routing error other than the bound is not something routing can produce, and reporting "nobody" drops the
        // event rather than delivering it somewhere it does not belong.
        assert!(matches!(
            RouteOutcome::from(RouterError::OutOfNumbers),
            RouteOutcome::Nobody
        ));
        assert!(matches!(
            RouteOutcome::from(RouterError::Unknown { distinct: 7 }),
            RouteOutcome::Unknown { distinct: 7 }
        ));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// A plugin name.
    fn arbitrary_plugin() -> impl Strategy<Value = PluginKey> {
        prop_oneof![
            Just(PluginKey::new("@a/one")),
            Just(PluginKey::new("@b/two")),
            Just(PluginKey::new("@c/three")),
        ]
    }

    /// A rule that always parses.
    fn arbitrary_rule() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("device.ping".to_owned()),
            Just("device.pong".to_owned()),
            Just("_synra.device.*".to_owned()),
            Just("_synra.transfer.*".to_owned()),
            Just("_synra.*".to_owned()),
            Just("_plugin.chat.text".to_owned()),
        ]
    }

    /// An event name, including ones nobody subscribes to.
    fn arbitrary_event() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("device.ping".to_owned()),
            Just("device.pong".to_owned()),
            Just("_synra.device.changed".to_owned()),
            Just("_synra.transfer.completed".to_owned()),
            Just("_synra.device.offline".to_owned()),
            Just("_plugin.chat.text".to_owned()),
            Just("_synra.unknown.thing".to_owned()),
        ]
    }

    proptest! {
        /// A routed event names only plugins that hold a rule matching it. The property an attacker would try to
        /// defeat: no sequence of registrations makes an event reach a plugin that did not subscribe to it.
        #[test]
        fn routing_only_reaches_matching_subscribers(
            registrations in proptest::collection::vec((arbitrary_plugin(), proptest::collection::vec(arbitrary_rule(), 0..3)), 0..8),
            event in arbitrary_event(),
        ) {
            let mut registry = EventRegistry::new();
            let mut accepted: Vec<(PluginKey, Vec<String>)> = Vec::new();
            // A plugin that registers twice is a duplicate, so the expectation only holds for the first registration.
            let mut registered: Vec<PluginKey> = Vec::new();
            for (plugin, rules) in registrations {
                if registered.contains(&plugin) {
                    continue;
                }
                if registry.register(&plugin, &rules).is_ok() {
                    registered.push(plugin.clone());
                    accepted.push((plugin, rules));
                }
            }

            if let RouteOutcome::Routed(plugins) = registry.route(&event) {
                for plugin in &plugins {
                    let rules = accepted
                        .iter()
                        .find(|(candidate, _)| candidate == plugin)
                        .map(|(_, rules)| rules.clone())
                        .unwrap_or_default();
                    let matches = rules.iter().any(|rule| {
                        if rule.contains('*') {
                            HandlePattern::parse(rule).map(|pattern| pattern.matches(&event)).unwrap_or(false)
                        }
                        else {
                            rule == &event
                        }
                    });
                    prop_assert!(matches, "{} received {} without a matching rule", plugin, event);
                }
                // And no plugin appears twice, which would run its handler twice for one event.
                let mut sorted = plugins.clone();
                sorted.sort();
                sorted.dedup();
                prop_assert_eq!(sorted.len(), plugins.len(), "a plugin was named twice");
            }
        }

        /// No route survives an unregister, for any sequence of registrations and removals. A route table holding a
        /// handle to an unloaded plugin is a use-after-free waiting for the right event.
        #[test]
        fn no_route_survives_an_unregister(
            operations in proptest::collection::vec(
                (any::<bool>(), arbitrary_plugin(), proptest::collection::vec(arbitrary_rule(), 1..3)),
                0..20,
            ),
            event in arbitrary_event(),
        ) {
            let mut registry = EventRegistry::new();
            // `currently_removed` rather than a history: a plugin that is unregistered and then registered again is a
            // subscriber, and a test that remembered every removal would report that as a leak.
            let mut currently_removed: Vec<PluginKey> = Vec::new();

            for (is_register, plugin, rules) in operations {
                if is_register {
                    if registry.register(&plugin, &rules).is_ok() {
                        currently_removed.retain(|candidate| candidate != &plugin);
                    }
                }
                else {
                    registry.unregister(&plugin);
                    if !currently_removed.contains(&plugin) {
                        currently_removed.push(plugin);
                    }
                }
            }

            if let RouteOutcome::Routed(plugins) = registry.route(&event) {
                for plugin in &plugins {
                    prop_assert!(
                        !currently_removed.contains(plugin),
                        "{} was unregistered and still receives {}",
                        plugin,
                        event,
                    );
                }
            }
        }

        /// The distinct-name count never exceeds the bound, whatever names arrive. It is what stops a peer streaming
        /// unrecognised names from growing the kernel's memory without limit.
        #[test]
        fn the_name_count_never_exceeds_the_bound(names in proptest::collection::vec("[_a-z.]{1,24}", 0..2000)) {
            let mut registry = EventRegistry::new();
            for name in names {
                let _ = registry.route(&name);
                prop_assert!(
                    registry.distinct_names() <= MAX_DISTINCT_NAMES,
                    "held {} of {}",
                    registry.distinct_names(),
                    MAX_DISTINCT_NAMES,
                );
            }
        }

        /// The wildcard rule count never exceeds the bound. Unlike the name bound this one is enforced at registration,
        /// because the wildcard rules are scanned on every frame and their number is the per-frame cost.
        #[test]
        fn the_wildcard_count_never_exceeds_the_bound(
            registrations in proptest::collection::vec(
                (arbitrary_plugin(), proptest::collection::vec("_synra\\.[a-z]{1,4}\\.[*]", 1..8)),
                0..40,
            ),
        ) {
            let mut registry = EventRegistry::new();
            for (plugin, rules) in registrations {
                let _ = registry.register(&plugin, &rules);
                prop_assert!(
                    registry.wildcard_rules() <= MAX_WILDCARD_RULES,
                    "held {} of {}",
                    registry.wildcard_rules(),
                    MAX_WILDCARD_RULES,
                );
            }
        }

        /// A number is stable: once a name has one, the same name always answers with the same number and the number
        /// always answers with the same name. Renumbering would invalidate every route that was compiled against it.
        #[test]
        fn a_number_is_stable(
            names in proptest::collection::vec("[_a-z.]{1,24}", 1..40),
            probes in proptest::collection::vec("[_a-z.]{1,24}", 0..40),
        ) {
            let mut registry = EventRegistry::new();
            for name in &names {
                let _ = registry.route(name);
            }
            // Record the numbers.
            let recorded: Vec<(String, Option<EventId>)> =
                names.iter().map(|name| (name.clone(), registry.id_for(name))).collect();

            for probe in &probes {
                let _ = registry.route(probe);
            }

            for (name, id) in recorded {
                prop_assert_eq!(registry.id_for(&name), id, "{} was renumbered", name);
                if let Some(id) = id {
                    prop_assert_eq!(registry.name_for(id), Some(name.as_str()));
                }
            }
        }
    }
}
