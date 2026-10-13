//! The plugin lifecycle: what state a plugin is in, and what may happen next.
//!
//! # Every transition is named, and the ones that are forbidden are the interesting part
//!
//! A plugin is a piece of software the user installed, that runs code from a stranger, that can talk to other
//! devices. Its state machine is where the host decides what it is allowed to be doing — so the value of the type is
//! not in the states but in the transitions it *refuses*.
//!
//! Three refusals matter more than the rest:
//!
//! * **A plugin may not run before its grants are decided.** [`State::Installed`] to [`State::Active`] requires
//!   having passed through [`State::Granted`], because a plugin that runs first and asks later is one whose first
//!   action was unauthorised.
//! * **A plugin may not be activated while faulted.** The quota ladder's last rung has to mean something, and a
//!   caller that could reactivate a faulted plugin by asking again would make the rung decorative.
//! * **A plugin may not be uninstalled while active.** Uninstalling removes the artifact, and a running instance
//!   would then be executing code that no longer exists on disk — so the transition goes through
//!   [`State::Deactivated`]. This is the one the host must not shortcut, because "uninstall" is what a user does
//!   when they are worried about a plugin.
//!
//! # An upgrade is not a reinstall
//!
//! Going from version `1.0.0` to `1.1.0` keeps the plugin's data, and the user's grants are carried over — but only
//! against the **manifest digest they approved**. A new version whose capability list changed is not the plugin the
//! user agreed to, so the grants are dropped and the consent screen runs again. Comparing digests rather than
//! showing every permission again is what makes an upgrade that changed nothing invisible.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Where a plugin is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
#[non_exhaustive]
pub enum State {
    /// The artifact is on disk and has not been checked.
    ///
    /// The first state, and the only one reached without validation: the manifest has to be read before anything can
    /// be checked, and reading it is what this state means.
    Installed {
        /// The version that was unpacked.
        version: String,
    },
    /// The manifest, the artifacts and the signature have all been checked.
    Validated {
        /// The version.
        version: String,
        /// The digest of the manifest that was checked, which the grants are recorded against.
        manifest_digest: String,
    },
    /// The user has decided on every capability.
    Granted {
        /// The version.
        version: String,
        /// The digest the decision was made against.
        manifest_digest: String,
        /// Whether anything was denied.
        ///
        /// Recorded because a plugin running with some capabilities denied behaves differently from one running with
        /// all of them, and a bug report that does not say which is a bug report about a different plugin.
        partially_denied: bool,
    },
    /// Running.
    Active {
        /// The version.
        version: String,
        /// Whether it is running with fewer capabilities than it asked for.
        partially_denied: bool,
    },
    /// Stopped, but installed and still holding its grants.
    Deactivated {
        /// The version.
        version: String,
    },
    /// Unusable because of a fault.
    ///
    /// Reached from the quota ladder, and from a trap or a timeout the host could not recover from. Distinct from
    /// [`Self::Deactivated`] because the reason matters to the user: a deactivated plugin was stopped, a faulted one
    /// broke.
    Faulted {
        /// The version.
        version: String,
        /// Why, in a sentence the interface can show.
        reason: String,
    },
    /// Nothing loaded, so the plugin may be updated or removed.
    ///
    /// The state the host returns to for an upgrade or an uninstall. Also where a plugin sits after a crash severe
    /// enough that the host will not try again in this session.
    Parked {
        /// The version that was loaded, if any.
        version: Option<String>,
    },
}

impl State {
    /// Which version is loaded, if any.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Installed { version }
            | Self::Validated { version, .. }
            | Self::Granted { version, .. }
            | Self::Active { version, .. }
            | Self::Deactivated { version }
            | Self::Faulted { version, .. } => Some(version),
            Self::Parked { version } => version.as_deref(),
        }
    }

    /// Whether the plugin's code may be executing.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// Whether the plugin holds resources a package change would invalidate.
    ///
    /// True for anything that has loaded the module or holds an instance. An upgrade and an uninstall both go
    /// through [`Self::Parked`] first, so this is what says "you cannot do that yet".
    #[must_use]
    pub const fn holds_loaded_code(&self) -> bool {
        matches!(
            self,
            Self::Validated { .. }
                | Self::Granted { .. }
                | Self::Active { .. }
                | Self::Deactivated { .. }
                | Self::Faulted { .. }
        )
    }

    /// Whether the plugin may be activated from here.
    #[must_use]
    pub const fn can_activate(&self) -> bool {
        // Only from `Granted`. A plugin that runs first and asks later is one whose first action was unauthorised,
        // and a faulted plugin staying faulted is what makes the ladder's last rung mean something.
        matches!(self, Self::Granted { .. } | Self::Deactivated { .. })
    }

    /// Whether the plugin may be uninstalled from here.
    ///
    /// Only where nothing has loaded. A `Validated` plugin has had its artifacts resolved and its module read, so
    /// removing the package under it would leave the host holding a description of something that is gone — and the
    /// caller's next step is [`Transition::Park`], which is why this agrees exactly with
    /// `!holds_loaded_code()`.
    #[must_use]
    pub const fn can_uninstall(&self) -> bool {
        !self.holds_loaded_code()
    }

    /// A name for a log line, a metric label or a state column.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Installed { .. } => "installed",
            Self::Validated { .. } => "validated",
            Self::Granted { .. } => "granted",
            Self::Active { .. } => "active",
            Self::Deactivated { .. } => "deactivated",
            Self::Faulted { .. } => "faulted",
            Self::Parked { .. } => "parked",
        }
    }

    /// A sentence for the interface.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Installed { version } => format!("version {version} is installed and not yet checked"),
            Self::Validated { version, .. } => format!("version {version} has been checked"),
            Self::Granted { version, partially_denied, .. } => {
                if *partially_denied {
                    format!("version {version} may run with fewer permissions than it asked for")
                }
                else {
                    format!("version {version} may run")
                }
            }
            Self::Active { version, partially_denied } => {
                if *partially_denied {
                    format!("version {version} is running with fewer permissions than it asked for")
                }
                else {
                    format!("version {version} is running")
                }
            }
            Self::Deactivated { version } => format!("version {version} is stopped"),
            Self::Faulted { version, reason } => format!("version {version} was stopped: {reason}"),
            Self::Parked { version } => match version {
                Some(version) => format!("version {version} is parked and may be replaced"),
                None => "nothing is loaded".to_owned(),
            },
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Something that may be done to a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transition {
    /// Check the manifest, the artifacts and the signature.
    Validate {
        /// The digest the manifest hashed to.
        manifest_digest: String,
    },
    /// Record the user's decisions.
    Grant {
        /// Whether anything was denied.
        partially_denied: bool,
    },
    /// Start the plugin.
    Activate,
    /// Stop the plugin, keeping it installed.
    Deactivate,
    /// Stop it and mark it unusable.
    Fault {
        /// Why.
        reason: String,
    },
    /// Load nothing, so the package may change.
    Park,
    /// Clear a fault, returning the plugin to a usable state.
    ///
    /// The **only** way out of [`State::Faulted`]. Reached when a user re-enables a plugin that the host disabled, or
    /// when the plugin is reinstalled. It is a distinct transition rather than an implicit effect of parking or
    /// upgrading, because those are housekeeping steps a caller may take for unrelated reasons — and a fault that a
    /// package change silently cleared would make the ladder's last rung decorative.
    ClearFault,
    /// Remove it.
    Uninstall,
    /// Replace the artifact with another version.
    Upgrade {
        /// The version being installed.
        version: String,
    },
}

impl Transition {
    /// A name for a log line.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Validate { .. } => "validate",
            Self::Grant { .. } => "grant",
            Self::Activate => "activate",
            Self::Deactivate => "deactivate",
            Self::Fault { .. } => "fault",
            Self::Park => "park",
            Self::ClearFault => "clear-fault",
            Self::Uninstall => "uninstall",
            Self::Upgrade { .. } => "upgrade",
        }
    }
}

/// Why a transition was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransitionError {
    /// The plugin is in a state the transition does not apply to.
    #[error("cannot {transition} a plugin that is {state}")]
    WrongState {
        /// The state it is in.
        state: &'static str,
        /// What was attempted.
        transition: &'static str,
    },

    /// The plugin must be parked first.
    ///
    /// Reported separately from [`Self::WrongState`] because the caller's response is different: it has a step to
    /// perform, not a mistake to fix.
    #[error("the plugin is holding loaded code; it has to be parked before it can be {transition}")]
    NeedsParking {
        /// What was attempted.
        transition: &'static str,
    },

    /// A faulted plugin may not be restarted.
    #[error("the plugin is faulted ({reason}); it has to be reinstalled or re-enabled by the user")]
    Faulted {
        /// Why it was faulted.
        reason: String,
    },
}

impl TransitionError {
    /// Whether the caller can make progress by doing something else first.
    #[must_use]
    pub const fn has_a_next_step(&self) -> bool {
        matches!(self, Self::NeedsParking { .. })
    }
}

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

/// How a plugin was stopped, for the health history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopRecord {
    /// The version that was running.
    pub version: String,
    /// How many times this version has stopped unexpectedly.
    pub unexpected_stops: u32,
    /// The most recent reason.
    pub last_reason: Option<String>,
}

impl StopRecord {
    /// A record for a version that has not stopped.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self { version: version.into(), unexpected_stops: 0, last_reason: None }
    }

    /// Records a stop the host did not choose.
    ///
    /// Only unexpected stops count. Counting a user deactivating a plugin would fault it for being switched off.
    pub fn record_unexpected_stop(&mut self, reason: impl Into<String>) {
        self.unexpected_stops = self.unexpected_stops.saturating_add(1);
        self.last_reason = Some(reason.into());
    }

    /// Whether the plugin has stopped unexpectedly too often to keep loading it.
    ///
    /// Three, matching the crash-driven safe mode in the observability design: a plugin that has crashed three times
    /// in a row is not going to work on the fourth.
    #[must_use]
    pub const fn is_unstable(&self) -> bool {
        self.unexpected_stops >= UNSTABLE_THRESHOLD
    }
}

/// How many unexpected stops make a version unstable.
pub const UNSTABLE_THRESHOLD: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    /// A lifecycle taken to `Granted`.
    fn granted() -> Lifecycle {
        let mut lifecycle = Lifecycle::installed("1.0.0");
        lifecycle
            .apply(Transition::Validate { manifest_digest: "d1".to_owned() })
            .expect("validates");
        lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
        lifecycle
    }

    /// A lifecycle taken to `Active`.
    fn active() -> Lifecycle {
        let mut lifecycle = granted();
        lifecycle.apply(Transition::Activate).expect("activates");
        lifecycle
    }

    #[test]
    fn a_new_plugin_is_installed_and_not_running() {
        let lifecycle = Lifecycle::installed("1.0.0");
        assert_eq!(lifecycle.state().as_str(), "installed");
        assert_eq!(lifecycle.state().version(), Some("1.0.0"));
        assert!(!lifecycle.is_running());
        assert!(!lifecycle.state().can_activate());
    }

    #[test]
    fn the_ordinary_path_runs_through_every_state() {
        let mut lifecycle = Lifecycle::installed("1.0.0");
        assert_eq!(lifecycle.state().as_str(), "installed");

        lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
        assert_eq!(lifecycle.state().as_str(), "validated");

        lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
        assert_eq!(lifecycle.state().as_str(), "granted");
        assert_eq!(lifecycle.granted_digest(), Some("d"));

        lifecycle.apply(Transition::Activate).expect("activates");
        assert_eq!(lifecycle.state().as_str(), "active");
        assert!(lifecycle.is_running());

        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        assert_eq!(lifecycle.state().as_str(), "deactivated");
        assert!(!lifecycle.is_running());

        lifecycle.apply(Transition::Park).expect("parks");
        assert_eq!(lifecycle.state().as_str(), "parked");
    }

    #[test]
    fn a_plugin_may_not_run_before_its_grants_are_decided() {
        // A plugin that runs first and asks later is one whose first action was unauthorised.
        let mut lifecycle = Lifecycle::installed("1.0.0");
        match lifecycle.apply(Transition::Activate) {
            Err(TransitionError::WrongState { state, transition }) => {
                assert_eq!(state, "installed");
                assert_eq!(transition, "activate");
            }
            other => panic!("expected a state refusal, got {other:?}"),
        }

        // Nor after validation, before the decision.
        lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
        assert!(lifecycle.apply(Transition::Activate).is_err());
    }

    #[test]
    fn a_granted_plugin_may_run() {
        assert!(granted().state().can_activate());
        let mut lifecycle = granted();
        lifecycle.apply(Transition::Activate).expect("activates");
        assert!(lifecycle.is_running());
    }

    #[test]
    fn granting_again_replaces_the_decision_rather_than_failing() {
        // A user who changes their mind is not making a mistake.
        let mut lifecycle = granted();
        lifecycle.apply(Transition::Grant { partially_denied: true }).expect("re-grants");
        assert!(matches!(lifecycle.state(), State::Granted { partially_denied: true, .. }));
    }

    #[test]
    fn a_partially_denied_plugin_records_it() {
        // A plugin running with some capabilities denied behaves differently from one running with all of them, and a
        // bug report that does not say which is a bug report about a different plugin.
        let mut lifecycle = Lifecycle::installed("1.0.0");
        lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
        lifecycle.apply(Transition::Grant { partially_denied: true }).expect("grants");
        lifecycle.apply(Transition::Activate).expect("activates");
        assert!(matches!(lifecycle.state(), State::Active { partially_denied: true, .. }));
        assert!(lifecycle.state().describe().contains("fewer permissions"), "{}", lifecycle.state().describe());
    }

    #[test]
    fn a_deactivated_plugin_restarts_without_a_new_decision() {
        // It kept its grants, so re-running the consent screen would ask the user to decide the same thing twice.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        lifecycle.apply(Transition::Activate).expect("restarts");
        assert!(lifecycle.is_running());
        assert_eq!(lifecycle.granted_digest(), Some("d1"));
    }

    #[test]
    fn a_faulted_plugin_may_not_be_activated() {
        // The ladder's last rung has to mean something, and a caller that could reactivate by asking again would make
        // it decorative.
        let mut lifecycle = active();
        lifecycle
            .apply(Transition::Fault { reason: "exceeded its limits".to_owned() })
            .expect("faults");
        assert_eq!(lifecycle.state().as_str(), "faulted");

        match lifecycle.apply(Transition::Activate) {
            Err(TransitionError::Faulted { reason }) => assert!(reason.contains("limits")),
            other => panic!("expected a faulted refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_fault_carries_a_reason_the_interface_can_show() {
        // A faulted plugin with no explanation is a plugin the user cannot decide about.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Fault { reason: "trapped".to_owned() }).expect("faults");
        assert!(lifecycle.state().describe().contains("trapped"));
    }

    #[test]
    fn deactivating_a_plugin_that_is_not_running_is_refused() {
        let mut lifecycle = granted();
        assert!(lifecycle.apply(Transition::Deactivate).is_err());
    }

    #[test]
    fn an_active_plugin_may_not_be_parked() {
        // Parking an active plugin is the caller forgetting to deactivate it, and doing it silently would leave the
        // plugin running against freed state.
        let mut lifecycle = active();
        assert!(lifecycle.apply(Transition::Park).is_err());
        // After deactivating, it may.
        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        assert!(lifecycle.apply(Transition::Park).is_ok());
    }

    #[test]
    fn an_active_plugin_may_not_be_uninstalled() {
        // Uninstalling removes the artifact, and a running instance would then be executing code that no longer
        // exists on disk. This is the transition the host must not shortcut, because "uninstall" is what a user does
        // when they are worried about a plugin.
        let mut lifecycle = active();
        match lifecycle.apply(Transition::Uninstall) {
            Err(TransitionError::NeedsParking { transition }) => assert_eq!(transition, "uninstalled"),
            other => panic!("expected a parking requirement, got {other:?}"),
        }
        // And the error says there is a step to perform rather than that the caller made a mistake.
        assert!(TransitionError::NeedsParking { transition: "uninstalled" }.has_a_next_step());
    }

    #[test]
    fn the_way_to_uninstall_a_running_plugin_is_to_stop_it_first() {
        let mut lifecycle = active();
        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        lifecycle.apply(Transition::Park).expect("parks");
        lifecycle.apply(Transition::Uninstall).expect("uninstalls");
        assert_eq!(lifecycle.state().as_str(), "parked");
        assert_eq!(lifecycle.state().version(), None);
        assert_eq!(lifecycle.granted_digest(), None, "the grants went with the plugin");
    }

    #[test]
    fn an_installed_plugin_may_be_uninstalled_without_parking() {
        // Nothing has loaded, so there is nothing to stop.
        let mut lifecycle = Lifecycle::installed("1.0.0");
        assert!(lifecycle.apply(Transition::Uninstall).is_ok());
    }

    #[test]
    fn a_validated_plugin_must_be_parked_before_it_can_be_uninstalled() {
        // Validation resolved the artifacts and read the module, so removing the package under it would leave the
        // host holding a description of something that is gone.
        let mut lifecycle = Lifecycle::installed("1.0.0");
        lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
        assert!(lifecycle.state().holds_loaded_code());
        assert!(!lifecycle.state().can_uninstall());
        assert!(matches!(
            lifecycle.apply(Transition::Uninstall),
            Err(TransitionError::NeedsParking { .. })
        ));

        // And parking is the step that unsticks it.
        lifecycle.apply(Transition::Park).expect("parks");
        assert!(lifecycle.apply(Transition::Uninstall).is_ok());
    }

    #[test]
    fn a_fault_is_cleared_only_deliberately() {
        // Parking and upgrading are housekeeping steps a caller may take for unrelated reasons, so neither may
        // silently clear a fault — that would make the ladder's last rung decorative.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Fault { reason: "traps".to_owned() }).expect("faults");

        lifecycle.apply(Transition::Park).expect("parks");
        assert_eq!(lifecycle.state().as_str(), "parked");
        // The fault is remembered even through an upgrade: the new artifact has to be validated and granted again.
        lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }).expect("upgrades");
        lifecycle.apply(Transition::Validate { manifest_digest: "d2".to_owned() }).expect("validates");
        // Activating now is legitimate: this is a different artifact that has been through the whole path again.
        lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
        assert!(lifecycle.apply(Transition::Activate).is_ok());
    }

    #[test]
    fn clearing_a_fault_returns_to_validated() {
        // The manifest was checked before the fault, but the user is being asked to re-enable a plugin that
        // misbehaved, so the decision is theirs to make again.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Fault { reason: "traps".to_owned() }).expect("faults");

        lifecycle.apply(Transition::ClearFault).expect("clears");
        assert_eq!(lifecycle.state().as_str(), "validated");
        // And it may be granted and run again.
        lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
        assert!(lifecycle.apply(Transition::Activate).is_ok());
    }

    #[test]
    fn clearing_a_fault_that_is_not_there_is_refused() {
        // A caller that clears a fault on a healthy plugin has misunderstood the state, and silently accepting would
        // hide the misunderstanding.
        let mut lifecycle = active();
        assert!(lifecycle.apply(Transition::ClearFault).is_err());
    }

    #[test]
    fn parking_from_a_faulted_state_is_allowed() {
        // The user has to be able to remove a plugin that broke.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Fault { reason: "x".to_owned() }).expect("faults");
        assert!(lifecycle.apply(Transition::Park).is_ok());
        assert!(lifecycle.apply(Transition::Uninstall).is_ok());
    }

    #[test]
    fn an_upgrade_returns_to_installed_and_clears_the_digest() {
        // Nothing about the new artifact has been checked, so it cannot be `Validated`, and the recorded digest is
        // about the old manifest.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        lifecycle.apply(Transition::Park).expect("parks");

        lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }).expect("upgrades");
        assert_eq!(lifecycle.state().as_str(), "installed");
        assert_eq!(lifecycle.state().version(), Some("2.0.0"));
        assert_eq!(lifecycle.granted_digest(), None);
    }

    #[test]
    fn an_upgrade_of_a_running_plugin_needs_parking() {
        let mut lifecycle = active();
        match lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }) {
            Err(TransitionError::NeedsParking { transition }) => assert_eq!(transition, "upgraded"),
            other => panic!("expected a parking requirement, got {other:?}"),
        }
    }

    #[test]
    fn an_upgrade_that_changed_nothing_keeps_the_grants() {
        // Comparing digests rather than showing every permission again is what makes a version bump that changed
        // nothing invisible to the user.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        lifecycle.apply(Transition::Park).expect("parks");

        assert!(lifecycle.upgrade_keeps_grants("d1"), "an unchanged manifest should keep its grants");
        assert!(!lifecycle.upgrade_keeps_grants("d2"), "a changed manifest must ask again");
    }

    #[test]
    fn a_plugin_that_never_granted_anything_keeps_no_grants() {
        let lifecycle = Lifecycle::parked();
        assert!(!lifecycle.upgrade_keeps_grants("d1"));
        assert_eq!(lifecycle.granted_digest(), None);
    }

    #[test]
    fn only_a_parked_plugin_keeps_grants_across_an_upgrade() {
        // `upgrade_keeps_grants` requires the state to be replaceable, so a running plugin is not silently counted as
        // keeping grants it is about to have re-decided.
        let mut lifecycle = active();
        lifecycle.apply(Transition::Deactivate).expect("deactivates");
        assert!(!lifecycle.state().can_uninstall(), "deactivated still holds loaded code");
        assert!(!lifecycle.upgrade_keeps_grants("d1"));

        lifecycle.apply(Transition::Park).expect("parks");
        assert!(lifecycle.upgrade_keeps_grants("d1"));
    }

    // ── States ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_state_carries_a_version_except_an_empty_park() {
        let states = [
            State::Installed { version: "1".to_owned() },
            State::Validated { version: "1".to_owned(), manifest_digest: "d".to_owned() },
            State::Granted {
                version: "1".to_owned(),
                manifest_digest: "d".to_owned(),
                partially_denied: false,
            },
            State::Active { version: "1".to_owned(), partially_denied: false },
            State::Deactivated { version: "1".to_owned() },
            State::Faulted { version: "1".to_owned(), reason: "r".to_owned() },
            State::Parked { version: Some("1".to_owned()) },
        ];
        for state in states {
            assert_eq!(state.version(), Some("1"), "{state:?}");
            assert!(!state.describe().is_empty(), "{state:?}");
            assert!(!state.as_str().is_empty(), "{state:?}");
        }
        assert_eq!(State::Parked { version: None }.version(), None);
    }

    #[test]
    fn only_active_counts_as_running() {
        let states = [
            (State::Installed { version: "1".to_owned() }, false),
            (State::Validated { version: "1".to_owned(), manifest_digest: "d".to_owned() }, false),
            (State::Active { version: "1".to_owned(), partially_denied: false }, true),
            (State::Deactivated { version: "1".to_owned() }, false),
            (State::Faulted { version: "1".to_owned(), reason: "r".to_owned() }, false),
            (State::Parked { version: None }, false),
        ];
        for (state, running) in states {
            assert_eq!(state.is_running(), running, "{state:?}");
        }
    }

    #[test]
    fn holding_loaded_code_is_what_forces_parking() {
        assert!(!State::Installed { version: "1".to_owned() }.holds_loaded_code());
        assert!(!State::Parked { version: None }.holds_loaded_code());
        for state in [
            State::Validated { version: "1".to_owned(), manifest_digest: "d".to_owned() },
            State::Granted {
                version: "1".to_owned(),
                manifest_digest: "d".to_owned(),
                partially_denied: false,
            },
            State::Active { version: "1".to_owned(), partially_denied: false },
            State::Deactivated { version: "1".to_owned() },
            State::Faulted { version: "1".to_owned(), reason: "r".to_owned() },
        ] {
            assert!(state.holds_loaded_code(), "{state:?}");
        }
    }

    #[test]
    fn a_state_displays_its_name() {
        assert_eq!(State::Parked { version: None }.to_string(), "parked");
    }

    #[test]
    fn a_state_survives_a_round_trip() {
        // The state is persisted between runs, so its shape is part of what an upgrade has to keep readable.
        for state in [
            State::Installed { version: "1.0.0".to_owned() },
            State::Validated { version: "1.0.0".to_owned(), manifest_digest: "d".to_owned() },
            State::Active { version: "1.0.0".to_owned(), partially_denied: true },
            State::Faulted { version: "1.0.0".to_owned(), reason: "trapped".to_owned() },
            State::Parked { version: None },
        ] {
            let json = serde_json::to_string(&state).expect("serialises");
            let back: State = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, state, "{json}");
        }
    }

    #[test]
    fn a_faulted_state_survives_a_round_trip_with_its_reason() {
        let state = State::Faulted { version: "1".to_owned(), reason: "ran out of fuel".to_owned() };
        let json = serde_json::to_string(&state).expect("serialises");
        assert!(json.contains("ran out of fuel"), "{json}");
    }

    #[test]
    fn every_transition_has_a_name_for_a_log_line() {
        let transitions = [
            Transition::Validate { manifest_digest: "d".to_owned() },
            Transition::Grant { partially_denied: false },
            Transition::Activate,
            Transition::Deactivate,
            Transition::Fault { reason: "r".to_owned() },
            Transition::Park,
            Transition::Uninstall,
            Transition::Upgrade { version: "2".to_owned() },
        ];
        for transition in transitions {
            let name = transition.as_str();
            assert!(!name.is_empty(), "{transition:?}");
            assert!(!name.contains(' '), "{transition:?} -> {name}");
        }
    }

    #[test]
    fn transition_errors_explain_themselves() {
        let errors = [
            TransitionError::WrongState { state: "parked", transition: "activate" },
            TransitionError::NeedsParking { transition: "uninstalled" },
            TransitionError::Faulted { reason: "exceeded its limits".to_owned() },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    // ── Stop history ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_version_that_has_not_stopped_is_stable() {
        let record = StopRecord::new("1.0.0");
        assert!(!record.is_unstable());
        assert_eq!(record.unexpected_stops, 0);
        assert_eq!(record.last_reason, None);
    }

    #[test]
    fn three_unexpected_stops_make_a_version_unstable() {
        // A plugin that has crashed three times in a row is not going to work on the fourth.
        let mut record = StopRecord::new("1.0.0");
        for _ in 0..UNSTABLE_THRESHOLD - 1 {
            record.record_unexpected_stop("trapped");
            assert!(!record.is_unstable());
        }
        record.record_unexpected_stop("trapped");
        assert!(record.is_unstable());
        assert_eq!(record.last_reason.as_deref(), Some("trapped"));
    }

    #[test]
    fn the_stop_count_saturates_rather_than_wrapping() {
        // A wrapping count would make a plugin that crashed four billion times look like one that never crashed.
        let mut record = StopRecord::new("1.0.0");
        record.unexpected_stops = u32::MAX;
        record.record_unexpected_stop("again");
        assert_eq!(record.unexpected_stops, u32::MAX);
        assert!(record.is_unstable());
    }

    #[test]
    fn a_stop_record_survives_a_round_trip() {
        let mut record = StopRecord::new("1.0.0");
        record.record_unexpected_stop("trapped");
        let json = serde_json::to_string(&record).expect("serialises");
        assert!(json.contains("unexpectedStops"), "{json}");
        let back: StopRecord = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, record);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// A transition to try, generated without its payload.
    fn arbitrary_transition() -> impl Strategy<Value = Transition> {
        prop_oneof![
            Just(Transition::Validate { manifest_digest: "d".to_owned() }),
            Just(Transition::Grant { partially_denied: false }),
            Just(Transition::Grant { partially_denied: true }),
            Just(Transition::Activate),
            Just(Transition::Deactivate),
            Just(Transition::Fault { reason: "r".to_owned() }),
            Just(Transition::Park),
            Just(Transition::ClearFault),
            Just(Transition::Uninstall),
            Just(Transition::Upgrade { version: "2.0.0".to_owned() }),
        ]
    }

    /// What resets the fault tracker.
    ///
    /// A **new artifact** is a different program: it goes through validation and a fresh decision, which is the
    /// recovery path the type documents. Housekeeping on the *same* artifact — parking it, deactivating it, clearing
    /// the fault — does not make the faulted code work, so a plugin that reaches `Active` afterwards must have
    /// arrived through an upgrade.
    fn resets_fault(step: &Transition) -> bool {
        matches!(step, Transition::Upgrade { .. } | Transition::ClearFault)
    }

    proptest! {
        /// Whatever sequence of transitions is applied, the lifecycle never reaches a state where a plugin is running
        /// without having been granted. It is the invariant the whole type exists for: a plugin that runs before the
        /// user decides is one whose first action was unauthorised.
        #[test]
        fn a_running_plugin_was_always_granted_first(
            steps in proptest::collection::vec(arbitrary_transition(), 0..40)
        ) {
            let mut lifecycle = Lifecycle::installed("1.0.0");
            let mut ever_granted = false;

            for step in steps {
                let _ = lifecycle.apply(step);
                if matches!(lifecycle.state(), State::Granted { .. } | State::Active { .. } | State::Deactivated { .. }) {
                    ever_granted = true;
                }
                if lifecycle.is_running() {
                    prop_assert!(ever_granted, "running at {:?} without ever being granted", lifecycle.state());
                    prop_assert!(lifecycle.granted_digest().is_some(), "running with no recorded digest");
                }
            }
        }

        /// Whatever the sequence, applying a transition either moves the state or leaves it alone, and the reported
        /// state always matches what the accessors say. A state and its own predicates disagreeing is the kind of
        /// defect that shows up as a plugin that the interface says is running and the host treats as stopped.
        #[test]
        fn the_state_and_its_predicates_always_agree(
            steps in proptest::collection::vec(arbitrary_transition(), 0..40)
        ) {
            let mut lifecycle = Lifecycle::installed("1.0.0");
            for step in steps {
                let _ = lifecycle.apply(step);
                let state = lifecycle.state();
                prop_assert_eq!(lifecycle.is_running(), state.is_running());
                prop_assert_eq!(state.is_running(), matches!(state, State::Active { .. }));
                if state.can_uninstall() {
                    prop_assert!(!state.holds_loaded_code(), "uninstallable but holding code: {state:?}");
                }
                // A version is carried by everything except an empty park.
                if !matches!(state, State::Parked { version: None }) {
                    prop_assert!(state.version().is_some(), "{state:?} carries no version");
                }
            }
        }

        /// A faulted plugin never becomes active again through transitions alone. Climbing out has to be a deliberate
        /// act by a caller, or the ladder's last rung is decorative.
        #[test]
        fn faulted_never_returns_to_active_alone(
            steps in proptest::collection::vec(arbitrary_transition(), 0..40)
        ) {
            let mut lifecycle = Lifecycle::installed("1.0.0");
            let mut became_faulted = false;

            for step in steps {
                if resets_fault(&step) {
                    became_faulted = false;
                }
                let _ = lifecycle.apply(step);
                if matches!(lifecycle.state(), State::Faulted { .. }) {
                    became_faulted = true;
                }
                if became_faulted {
                    prop_assert!(
                        !lifecycle.is_running(),
                        "a faulted plugin returned to active through {:?}",
                        lifecycle.state(),
                    );
                }
            }
        }

        /// An upgrade always lands on `Installed`, so nothing about the new artifact is assumed to have been checked.
        /// Landing anywhere else would let a caller skip validation by upgrading.
        #[test]
        fn an_upgrade_always_lands_on_installed(prefix in proptest::collection::vec(arbitrary_transition(), 0..20)) {
            let mut lifecycle = Lifecycle::installed("1.0.0");
            for step in prefix {
                let _ = lifecycle.apply(step);
            }
            let _ = lifecycle.apply(Transition::Park);
            let _ = lifecycle.apply(Transition::Uninstall);

            if lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }).is_ok() {
                prop_assert!(
                    matches!(lifecycle.state(), State::Installed { .. }),
                    "an upgrade landed on {:?}",
                    lifecycle.state(),
                );
            }
        }
    }
}
