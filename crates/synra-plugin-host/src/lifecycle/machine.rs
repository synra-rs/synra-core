//! One plugin's lifecycle, and the moves it permits.

use super::state::State;
use super::transition::{Transition, TransitionError};
/// A plugin's lifecycle, as a value that only moves through the transitions it permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lifecycle {
    state: State,
    /// The digest of the manifest currently loaded, which grants are recorded against.
    granted_digest: Option<String>,
}

impl Lifecycle {
    /// A lifecycle for a plugin whose artifact has just been unpacked.
    #[must_use]
    pub fn installed(version: impl Into<String>) -> Self {
        Self { state: State::Installed { version: version.into() }, granted_digest: None }
    }

    /// A lifecycle for a plugin with nothing loaded.
    #[must_use]
    pub const fn parked() -> Self {
        Self { state: State::Parked { version: None }, granted_digest: None }
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// Whether the plugin is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.state.is_running()
    }

    /// The digest the current grants were decided against.
    #[must_use]
    pub fn granted_digest(&self) -> Option<&str> {
        self.granted_digest.as_deref()
    }

    /// Applies a transition.
    ///
    /// # Errors
    ///
    /// [`TransitionError`] explaining which state refused it and whether there is a next step.
    pub fn apply(&mut self, transition: Transition) -> Result<&State, TransitionError> {
        // The name is bound before the match rather than read inside a closure, because the match *moves* the
        // transition's payloads — a closure borrowing `transition` would keep them borrowed for the whole body.
        let name = transition.as_str();
        let wrong = |state: &'static str| TransitionError::WrongState { state, transition: name };

        match transition {
            Transition::Validate { manifest_digest } => {
                let Some(version) = self.state.version().filter(|_| matches!(self.state, State::Installed { .. })) else {
                    return Err(wrong(self.state.as_str()));
                };
                self.state = State::Validated { version: version.to_owned(), manifest_digest };
            }

            Transition::Grant { partially_denied } => {
                let State::Validated { version, manifest_digest } = &self.state else {
                    return Err(match &self.state {
                        // Granting twice is not a mistake worth a distinct error: the caller re-decided.
                        State::Granted { version, manifest_digest, .. } => {
                            let (version, digest) = (version.clone(), manifest_digest.clone());
                            self.state = State::Granted { version, manifest_digest: digest, partially_denied };
                            return Ok(&self.state);
                        }
                        _ => wrong(self.state.as_str()),
                    });
                };
                self.granted_digest = Some(manifest_digest.clone());
                self.state = State::Granted {
                    version: version.clone(),
                    manifest_digest: manifest_digest.clone(),
                    partially_denied,
                };
            }

            Transition::Activate => {
                if let State::Faulted { reason, .. } = &self.state {
                    return Err(TransitionError::Faulted { reason: reason.clone() });
                }
                let (version, partially_denied) = match &self.state {
                    State::Granted { version, partially_denied, .. } => (version.clone(), *partially_denied),
                    // A deactivated plugin keeps its grants, so restarting it does not re-run the consent screen.
                    State::Deactivated { version } => (version.clone(), false),
                    _ => return Err(wrong(self.state.as_str())),
                };
                self.state = State::Active { version, partially_denied };
            }

            Transition::Deactivate => {
                let State::Active { version, .. } = &self.state else {
                    return Err(wrong(self.state.as_str()));
                };
                self.state = State::Deactivated { version: version.clone() };
            }

            Transition::Fault { reason } => {
                // Faulting anything that holds code is allowed: a trap during validation is still a reason to stop.
                let Some(version) = self.state.version() else {
                    return Err(wrong(self.state.as_str()));
                };
                self.state = State::Faulted { version: version.to_owned(), reason };
            }

            Transition::ClearFault => {
                let State::Faulted { version, .. } = &self.state else {
                    return Err(wrong(self.state.as_str()));
                };
                // Back to `Validated` rather than `Granted`: the manifest was checked before the fault, but the user
                // is being asked to re-enable a plugin that misbehaved, so the decision is theirs to make again.
                let version = version.clone();
                self.state = State::Validated {
                    version,
                    manifest_digest: self.granted_digest.clone().unwrap_or_default(),
                };
            }

            Transition::Park => {
                // Only from a state where nothing is executing. Parking an active plugin is the caller forgetting to
                // deactivate it, and doing it silently would leave the plugin running against freed state.
                if self.state.is_running() {
                    return Err(wrong(self.state.as_str()));
                }
                let version = self.state.version().map(str::to_owned);
                self.state = State::Parked { version };
            }

            Transition::Uninstall => {
                if !self.state.can_uninstall() {
                    // The distinction that matters: a caller with a step to perform is told so, rather than being
                    // told it made a mistake.
                    if self.state.holds_loaded_code() {
                        return Err(TransitionError::NeedsParking { transition: "uninstalled" });
                    }
                    return Err(wrong(self.state.as_str()));
                }
                self.state = State::Parked { version: None };
                self.granted_digest = None;
            }

            Transition::Upgrade { version } => {
                if !self.state.can_uninstall() {
                    if self.state.holds_loaded_code() {
                        return Err(TransitionError::NeedsParking { transition: "upgraded" });
                    }
                    return Err(wrong(self.state.as_str()));
                }
                // A new version invalidates the recorded digest. Whether the *grants* survive is decided by the
                // caller comparing digests — which is why the digest is exposed — but the state always returns to
                // `Installed`, because nothing about the new artifact has been checked.
                self.granted_digest = None;
                self.state = State::Installed { version };
            }
        }

        Ok(&self.state)
    }

    /// Whether a version can replace the current one without re-running the consent screen.
    ///
    /// True only when the new manifest's digest equals the one the grants were recorded against. A version bump that
    /// changed nothing is invisible to the user; one that added a capability is not.
    #[must_use]
    pub fn upgrade_keeps_grants(&self, new_manifest_digest: &str) -> bool {
        self.granted_digest.as_deref() == Some(new_manifest_digest) && self.state.can_uninstall()
    }
}
