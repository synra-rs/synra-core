use super::*;

impl PluginSet {
    /// The engine these plugins run on.
    #[must_use]
    pub const fn backend(&self) -> &Backend {
        &self.backend
    }

    /// How many plugins are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    /// Whether a plugin is loaded.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.loaded.contains_key(id)
    }

    /// The loaded plugins, in a stable order.
    ///
    /// Sorted rather than in insertion order because two calls that read the same table should print the same line, and
    /// a `HashMap`'s order is not a thing a reader can hold in their head.
    #[must_use]
    pub fn ids(&self) -> Vec<PluginId> {
        let mut ids: Vec<PluginId> = self.loaded.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// What a plugin has been granted.
    #[must_use]
    pub fn grants(&self, id: &PluginId) -> Option<&CapabilitySet> {
        self.loaded.get(id).map(|loaded| &loaded.authority.grants)
    }

    /// The host every plugin instance reaches.
    ///
    /// # Why this is public
    ///
    /// Because the UI channel answers some calls **through the same host the Wasm half uses** — `network.fetch` is the
    /// first. A second fetcher built in the shell would have its own in-flight limit and its own reading of the grants,
    /// so one plugin page and one plugin instance could exceed together what neither may alone, and the two could
    /// disagree about which hosts the user allowed.
    ///
    /// It is `&Arc` rather than the trait object so a caller can clone it and **drop this set's lock** before doing
    /// network work: a fetch held under the plugin lock would make every other plugin command wait for the network.
    #[must_use]
    pub fn host(&self) -> &Arc<dyn synra_plugin_host::host_calls::Host> {
        &self.host
    }
}
