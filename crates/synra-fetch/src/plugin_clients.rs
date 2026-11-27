use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use synra_core::network::NetworkGuard;
use synra_protocol::PluginId;

use crate::{Client, Limits};

/// Reuses one network budget per plugin. Each call supplies its own current grants.
#[derive(Debug, Default)]
pub struct PluginClients {
    clients: Mutex<HashMap<PluginId, Arc<Client>>>,
}

impl PluginClients {
    /// Gets the client shared by every authorized fetch from this plugin.
    #[must_use]
    pub fn get(&self, plugin: &PluginId) -> Arc<Client> {
        Arc::clone(
            self.clients
                .lock()
                .entry(plugin.clone())
                .or_insert_with(|| {
                    Arc::new(Client::new(NetworkGuard::for_hosts(&[]), Limits::default()))
                }),
        )
    }
}
