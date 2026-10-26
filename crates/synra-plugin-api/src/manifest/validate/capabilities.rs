use synra_capability::{Capability, Domain};

use crate::manifest::error::ManifestError;
use crate::manifest::types::Manifest;

impl Manifest {
    /// The capabilities, and whether this kind of plugin can use them.
    pub(super) fn check_capabilities(
        &self,
    ) -> Result<synra_capability::CapabilitySet, ManifestError> {
        let set = self.capability_set()?;

        for declaration in &self.capabilities {
            let capability = Capability::parse(&declaration.cap).map_err(|source| {
                ManifestError::BadCapability {
                    cap: declaration.cap.clone(),
                    source,
                }
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
        let outbound = self
            .network
            .as_ref()
            .map(|network| network.outbound.as_slice())
            .unwrap_or_default();

        // A finite methods list needs authority for each listed operation. An empty list means all methods.
        for declaration in outbound {
            let host = &declaration.host;
            let target = format!("network:fetch:{host}");
            let all_methods =
                Capability::parse(&target).is_ok_and(|cap| capabilities.contains(&cap));
            let covered = all_methods
                || (!declaration.methods.is_empty()
                    && declaration.methods.iter().all(|method| {
                        Capability::parse(&format!("{target}:{method}"))
                            .is_ok_and(|cap| capabilities.contains(&cap))
                    }));
            if !covered {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "{host:?} declares host or method access without matching fetch capabilities"
                    ),
                });
            }
        }

        // A concrete grant must be described, and must not authorize methods the consent declaration omits.
        for capability in capabilities.iter() {
            if capability.domain() != Domain::Network
                || capability
                    .prefixes()
                    .first()
                    .map(synra_capability::Segment::as_str)
                    != Some("fetch")
            {
                continue;
            }
            let Some(host) = capability
                .qualifier()
                .first()
                .map(synra_capability::Segment::as_str)
            else {
                continue;
            };
            let declarations: Vec<_> = outbound.iter().filter(|entry| entry.host == host).collect();
            if declarations.is_empty() {
                // Unbounded host patterns have no finite host list; consent must identify their wildcard scope.
                if host.contains('*') {
                    continue;
                }
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "the capability `{capability}` is not described in `network.outbound`"
                    ),
                });
            }
            let method = capability
                .qualifier()
                .get(1)
                .map(synra_capability::Segment::as_str);
            let described = capability.qualifier().len() <= 2
                && declarations.iter().any(|entry| {
                    entry.methods.is_empty()
                        || method.is_some_and(|method| {
                            !method.contains('*')
                                && entry.methods.iter().any(|declared| declared == method)
                        })
                });
            if !described {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "the capability `{capability}` exceeds its declared HTTP methods"
                    ),
                });
            }
        }

        Ok(())
    }
}
