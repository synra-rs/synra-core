use synra_capability::{Capability, Domain};

use crate::manifest::error::ManifestError;
use crate::manifest::types::Manifest;

impl Manifest {
    /// The capabilities, and whether this kind of plugin can use them.
    pub(super) fn check_capabilities(&self) -> Result<synra_capability::CapabilitySet, ManifestError> {
        let set = self.capability_set()?;

        for declaration in &self.capabilities {
            let capability = Capability::parse(&declaration.cap).map_err(|source| {
                ManifestError::BadCapability { cap: declaration.cap.clone(), source }
            })?;

            // A headless plugin has no interface, so a `ui:*` grant is one the user would approve at install
            // time and that nothing can ever exercise. The consent screen said something untrue.
            if !self.has_ui() && capability.domain() == Domain::Ui {
                return Err(ManifestError::UnusableCapability {
                    cap: declaration.cap.clone(),
                    kind: "headless",
                });
            }
        }
        Ok(set)
    }

    /// Whether the network declaration and the network capabilities agree.
    ///
    /// The declaration exists so the consent screen can say "read from api.github.com" rather than "use the
    /// network". Two lists that disagree produce a screen showing one thing and a plugin holding another, which
    /// is worse than either list alone.
    pub(super) fn check_network(
        &self,
        capabilities: &synra_capability::CapabilitySet,
    ) -> Result<(), ManifestError> {
        let declared_hosts: Vec<&str> = self
            .network
            .as_ref()
            .map(|network| network.outbound.iter().map(|host| host.host.as_str()).collect())
            .unwrap_or_default();

        // Every declared host must be covered by a `network:fetch:<host>` capability.
        for host in &declared_hosts {
            let capability = Capability::parse(&format!("network:fetch:{host}"));
            let covered = capability.map(|cap| capabilities.contains(&cap)).unwrap_or(false);
            if !covered {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "{host:?} is declared as reachable but no `network:fetch:{host}` capability backs it"
                    ),
                });
            }
        }

        // And every `network:fetch:<host>` capability must be described, unless it is a wildcard — a wildcard
        // has no finite description, which is exactly why the design document says the interface must spell it
        // out as "any website" rather than pretending otherwise.
        for capability in capabilities.iter() {
            if capability.domain() != Domain::Network {
                continue;
            }
            let resource = capability
                .prefixes()
                .first()
                .map(synra_capability::Segment::as_str)
                .unwrap_or_default();
            if resource != "fetch" {
                continue;
            }
            let Some(host) = capability.qualifier().first().map(synra_capability::Segment::as_str) else {
                continue;
            };
            if host.contains('*') {
                continue;
            }
            if !declared_hosts.contains(&host) {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "the capability `network:fetch:{host}` is declared but {host:?} is not in \
                         `network.outbound`"
                    ),
                });
            }
        }

        Ok(())
    }
}
