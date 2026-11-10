use serde::{Deserialize, Serialize};

use super::instance::InstancePool;
use super::policy::InstancePolicy;

impl InstancePool {
    /// A snapshot for the interface and a diagnostic report.
    #[must_use]
    pub fn report(&self) -> PoolReport {
        let instances = self.instances.lock();
        PoolReport {
            policy: match self.policy {
                InstancePolicy::Stateless => "stateless",
                InstancePolicy::Stateful => "stateful",
            }
            .to_owned(),
            limit: self.limit,
            live: u32::try_from(instances.len()).unwrap_or(u32::MAX),
            busy: u32::try_from(instances.iter().filter(|record| record.busy).count())
                .unwrap_or(u32::MAX),
            conversations: instances
                .iter()
                .filter_map(|record| record.conversation.clone())
                .collect(),
            total_calls: instances.iter().map(|record| record.calls).sum(),
        }
    }
}

/// What the interface shows about a plugin's instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolReport {
    /// Whether instances are interchangeable.
    pub policy: String,
    /// The quota.
    pub limit: u32,
    /// How many exist.
    pub live: u32,
    /// How many are serving a call.
    pub busy: u32,
    /// The conversations holding an instance, for a stateful plugin.
    pub conversations: Vec<String>,
    /// How many calls the live instances have served.
    pub total_calls: u64,
}
