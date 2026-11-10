use super::data::Progress;
use super::moves::Move;
use super::slot::PluginSlot;
use super::source::{FailStage, Failed};
use super::super::{machine::Lifecycle, state::State, transition::{Transition, TransitionError}};

/// Why a move was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MoveError {
    /// The move does not apply to the state the plugin is in.
    #[error("cannot {attempted} a plugin that is {current}")]
    WrongState {
        /// What was attempted.
        attempted: &'static str,
        /// Where the plugin is.
        current: &'static str,
    },

    /// The source is one this build may not install from.
    #[error("a local installation is a development feature and this build does not accept one")]
    LocalInstallNotAllowed,

    /// The plugin's own lifecycle refused the move.
    ///
    /// Passed through rather than folded into [`Self::WrongState`], because the two have different next steps: the
    /// lifecycle's refusal may be a step the caller has to perform first.
    #[error(transparent)]
    Lifecycle(#[from] TransitionError),
}

impl PluginSlot {
    /// Applies a move.
    ///
    /// `now_ms` is passed in rather than read, so a failure's timestamp is a value a test can assert.
    ///
    /// # Errors
    ///
    /// [`MoveError`] naming what was attempted and where the plugin is.
    pub fn apply(&mut self, step: Move, now_ms: i64) -> Result<&Self, MoveError> {
        // The name is bound before the match for the reason `Lifecycle::apply` binds it: the match moves the step's
        // payloads, and a closure borrowing the step would keep them borrowed for the whole body.
        let name = step.as_str();
        let wrong = |current: &'static str| MoveError::WrongState { attempted: name, current };

        match step {
            Move::Install { source } => {
                if !matches!(self, Self::Available | Self::Failed(_)) {
                    return Err(wrong(self.as_str()));
                }
                if source.refuses_outside_development() && !cfg!(debug_assertions) {
                    return Err(MoveError::LocalInstallNotAllowed);
                }
                *self = Self::Resolving { source };
            }

            Move::Resolved { resolved } => {
                let Self::Resolving { source } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Downloading {
                    source: source.clone(),
                    resolved,
                    progress: Progress::default(),
                };
            }

            Move::Downloaded { progress } => {
                let Self::Downloading { progress: held, .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                // ★ Monotonic: a progress report that goes backwards is a stalled connection being retried inside a
                // request, and drawing it would make a download appear to restart. A caller that has restarted the
                // download has a new `Downloading` state, not a smaller number in this one.
                held.received = held.received.max(progress.received);
                held.total = progress.total.or(held.total);
            }

            Move::Fetched { artifact_digest } => {
                let Self::Downloading { source, resolved, .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Verifying {
                    source: source.clone(),
                    resolved: resolved.clone(),
                    artifact_digest,
                };
            }

            Move::Verified { verified } => {
                let Self::Verifying { source, .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::AwaitingConsent { source: source.clone(), verified };
            }

            Move::Consented { consent } => {
                let Self::AwaitingConsent { source, verified } = self else {
                    return Err(wrong(self.as_str()));
                };
                if consent.is_refusal() {
                    // A refusal everywhere is not a partial grant: it is the user saying no, and the pipeline ends in
                    // the state that means "a person decided against this" rather than in one that means "it broke".
                    let failed = Failed::at(
                        source.clone(),
                        FailStage::Consent,
                        "every requested permission was refused",
                        now_ms,
                    )
                    .not_retryable();
                    *self = Self::Failed(failed);
                    return Ok(self);
                }
                *self = Self::Installing {
                    source: source.clone(),
                    verified: verified.clone(),
                    consent,
                };
            }

            Move::Installed => {
                let Self::Installing { source, verified, consent } = self else {
                    return Err(wrong(self.as_str()));
                };
                let mut lifecycle = Lifecycle::installed(verified.version.clone());
                // The lifecycle's own moves, driven from the values the pipeline already produced — not from new ones,
                // so the version a plugin is recorded with is the version that was verified.
                let _ = lifecycle.apply(Transition::Validate {
                    manifest_digest: verified.manifest_digest.clone(),
                })?;
                let _ = lifecycle.apply(Transition::Grant {
                    partially_denied: consent.is_partial(),
                })?;
                *self = Self::Installed { source: source.clone(), lifecycle };
            }

            Move::Activate => {
                let Self::Installed { source, mut lifecycle } = self.clone() else {
                    return Err(wrong(self.as_str()));
                };
                // The lifecycle is moved **before** the state changes, so a refusal leaves the slot exactly where it
                // was rather than in an activating state with nothing to activate.
                let _ = lifecycle.apply(Transition::Activate)?;
                *self = Self::Activating { source, lifecycle };
            }

            Move::Activated => {
                let Self::Activating { source, lifecycle } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Active { source: source.clone(), lifecycle: lifecycle.clone() };
            }

            Move::Deactivate => {
                let Self::Active { source, lifecycle } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Deactivating { source: source.clone(), lifecycle: lifecycle.clone() };
            }

            Move::Deactivated => {
                let Self::Deactivating { source, mut lifecycle } = self.clone() else {
                    return Err(wrong(self.as_str()));
                };
                let _ = lifecycle.apply(Transition::Deactivate)?;
                *self = Self::Installed { source, lifecycle };
            }

            Move::Fault { reason } => {
                // From anything that holds loaded code, which is the same set the lifecycle faults from. A fault while
                // activating is the case that matters: the module loaded and its start function trapped.
                let (source, mut lifecycle) = match self.clone() {
                    Self::Activating { source, lifecycle }
                    | Self::Active { source, lifecycle }
                    | Self::Deactivating { source, lifecycle } => (source, lifecycle),
                    _ => return Err(wrong(self.as_str())),
                };
                let _ = lifecycle.apply(Transition::Fault { reason })?;
                *self = Self::Faulted { source, lifecycle };
            }

            Move::ClearFault => {
                let Self::Faulted { source, mut lifecycle } = self.clone() else {
                    return Err(wrong(self.as_str()));
                };
                let _ = lifecycle.apply(Transition::ClearFault)?;
                *self = Self::Installed { source, lifecycle };
            }

            Move::Remove => {
                // From anything on this device, except while something is running: the caller stops it first, and a
                // removal that skipped that would take the artifact out from under a live instance.
                let (source, lifecycle) = match self.clone() {
                    Self::Installed { source, lifecycle } | Self::Faulted { source, lifecycle } => {
                        (source, Some(lifecycle))
                    }
                    Self::Activating { .. } | Self::Active { .. } | Self::Deactivating { .. } => {
                        return Err(wrong(self.as_str()));
                    }
                    _ => return Err(wrong(self.as_str())),
                };
                *self = Self::Removing { source, lifecycle };
            }

            Move::Removed => {
                let Self::Removing { .. } = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Available;
            }

            Move::Retry => {
                let Self::Failed(failed) = self else {
                    return Err(wrong(self.as_str()));
                };
                if !failed.retryable {
                    return Err(wrong(self.as_str()));
                }
                // ★ The attempt count is *not* incremented here. A retry that has not failed yet has not been tried,
                // and counting it now would report "2 attempts" for a user who has pressed the button once.
                let source = failed.source.clone();
                *self = Self::Resolving { source };
            }

            Move::Abandon => {
                let Self::Failed(_) = self else {
                    return Err(wrong(self.as_str()));
                };
                *self = Self::Available;
            }

            Move::Fail { stage, detail, retryable } => {
                // ★ From anywhere that has a source — which is everywhere except `Available`. A second failure does
                // not replace the first's attempt count; it increments it, so a pipeline that fails four times reports
                // four rather than one.
                let Some(source) = self.source().cloned() else {
                    return Err(wrong(self.as_str()));
                };
                let mut failed = match self {
                    Self::Failed(previous) => previous.retried(now_ms),
                    _ => Failed::at(source, stage, detail.clone(), now_ms),
                };
                failed.stage = stage;
                failed.detail = detail;
                if let Some(known) = retryable {
                    failed.retryable = known;
                }
                *self = Self::Failed(failed);
            }
        }

        Ok(self)
    }

    /// The plugin's lifecycle state, when it has one.
    #[must_use]
    pub fn lifecycle_state(&self) -> Option<&State> {
        self.lifecycle().map(Lifecycle::state)
    }
}
