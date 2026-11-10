use std::collections::HashMap;
use std::hash::RandomState;

use synra_protocol::inbound::{HandlePattern, MAX_WILDCARD_RULES};

use crate::admission::PluginKey;

use super::{
    EventId, EventRegistry, MAX_DISTINCT_NAMES, RouteOutcome, RouterError, RouterReport,
    Subscription,
};

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
        let mut plugins: Vec<&PluginKey> = self
            .subscriptions
            .iter()
            .map(|subscription| &subscription.plugin)
            .collect();
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
            } else {
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
                return Err(RouterError::Duplicate {
                    plugin: plugin.to_string(),
                    rule: rule.clone(),
                });
            }

            if pattern.is_some() {
                wildcards_added += 1;
            }
            staged.push(Subscription {
                plugin: plugin.clone(),
                rule: rule.clone(),
                pattern,
            });
        }

        if self.wildcards.len() + wildcards_added > MAX_WILDCARD_RULES {
            return Err(RouterError::TooManyWildcards {
                limit: MAX_WILDCARD_RULES,
            });
        }

        // Nothing above this line has mutated the registry, so a refusal leaves it untouched.
        for subscription in staged {
            if subscription.pattern.is_some() {
                self.wildcards.push(subscription.clone());
            } else {
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
        self.subscriptions
            .retain(|subscription| subscription.plugin != *plugin);
        self.wildcards
            .retain(|subscription| subscription.plugin != *plugin);

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
                Err(_) => RouteOutcome::Unknown {
                    distinct: self.by_name.len(),
                },
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
