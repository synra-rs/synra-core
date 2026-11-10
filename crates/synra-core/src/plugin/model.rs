/// Why one plugin was not loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Its identifier, as the database spells it.
    pub plugin_id: String,
    /// What stopped it.
    pub reason: String,
}

/// What a load pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedSummary {
    /// What is now askable, in the order it was loaded.
    pub loaded: Vec<synra_protocol::ids::PluginId>,
    /// What was not, and why.
    pub refused: Vec<Refused>,
    /// Why nothing was loaded at all, when the host chose not to start plugins.
    pub safe_mode: Option<String>,
}

impl LoadedSummary {
    /// How many plugins this host can now ask.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    /// Whether a plugin with this identifier is loaded.
    #[must_use]
    pub fn contains(&self, id: &synra_protocol::ids::PluginId) -> bool {
        self.loaded.contains(id)
    }

    /// Why a plugin of this identifier was not loaded, when it was examined and failed.
    #[must_use]
    pub fn refusal_for(&self, plugin_id: &str) -> Option<&str> {
        self.refused
            .iter()
            .find(|refused| refused.plugin_id == plugin_id)
            .map(|refused| refused.reason.as_str())
    }

    /// Records a plugin as loaded, replacing any earlier refusal for it.
    pub fn record_loaded(&mut self, id: synra_protocol::ids::PluginId) {
        self.refused
            .retain(|refused| refused.plugin_id != id.as_str());
        if !self.loaded.contains(&id) {
            self.loaded.push(id);
        }
    }

    /// Records a plugin as refused, replacing any earlier "loaded" claim for it.
    pub fn record_refused(&mut self, plugin_id: &str, reason: String) {
        self.loaded.retain(|id| id.as_str() != plugin_id);
        self.refused
            .retain(|refused| refused.plugin_id != plugin_id);
        self.refused.push(Refused {
            plugin_id: plugin_id.to_owned(),
            reason,
        });
    }

    /// Forgets a plugin entirely, for a host that has just unloaded or removed it.
    pub fn record_unloaded(&mut self, id: &synra_protocol::ids::PluginId) {
        self.loaded.retain(|loaded| loaded != id);
        self.refused
            .retain(|refused| refused.plugin_id != id.as_str());
    }
}
