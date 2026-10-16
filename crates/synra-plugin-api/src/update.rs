//! Whether an available update may be applied without asking.
//!
//! # Why this is a decision rather than a flag
//!
//! Because "is there a newer version" and "should this device take it" are different questions, and the design's threshold
//! table answers the second one with five rows. Before this module there was only the first question: [`UpdateInfo`] carries
//! a version, a flag for new permissions, and the names of the capabilities — everything a screen needs to *draw* an
//! update, and nothing that decides one. `grep auto_update` and `grep update_policy` both found nothing, which is what a
//! decision nobody has made looks like.
//!
//! # The table, and the order it is read in
//!
//! | Condition | Automatic |
//! | --- | --- |
//! | the installed version is revoked | **forced** — the update is not optional |
//! | the publisher is not one this device trusted | never; notify |
//! | the publisher's key changed | ask, and warn |
//! | the update asks for a new or widened capability | ask |
//! | nothing above | yes, if the policy allows it |
//!
//! ★ **The order is a decision this module makes, not one the table states.** The design lists the rows and does not say
//! which wins when two hold at once, and they do hold at once: an update can want a new permission *and* come from a
//! publisher this device has never seen. Two rules follow, and both are reasons rather than preferences:
//!
//! * **A revocation outranks everything.** A version that is revoked must stop running, so the update is not something to
//!   ask about — the only other outcome would be disabling the plugin, and that is what
//!   [`UpdateAction::Forced`]'s message is for.
//! * **Every other blocker is reported together, not one at a time.** A caller that returned the first match would make a
//!   user fix one thing, retry, and discover the next — and would hide that the publisher key changed behind a message
//!   about permissions, which is the one a person is least equipped to notice on their own.
//!
//! # What this deliberately does not do
//!
//! It does not fetch, install, or schedule anything. A decision function that also acted would be untestable without a
//! network, and the scheduling half is the caller's: the design asks for a check every twenty-four hours, and a policy that
//! said "notify only" is exactly the case where the caller must not act on its own.

use crate::publisher::{Fingerprint, PluginTrust};

/// When an available update may be applied without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdatePolicy {
    /// Never update on its own; tell the user and let them decide.
    ///
    /// The default. A device that installs software while nobody is looking is a device whose owner cannot say what is
    /// running on it, and the design's table only ever reaches "automatic" as the **last** row.
    #[default]
    NotifyOnly,
    /// Apply patch and minor updates, ask about major ones.
    AutoMinor,
    /// Apply any update the table does not block.
    ///
    /// # Why this is still not "always"
    ///
    /// Because the table's first four rows are not about version numbers: a revoked version, an untrusted publisher, a
    /// changed key and a new permission each block an update **whatever** the policy says. A policy cannot consent on a
    /// user's behalf to something the user has not been shown.
    AutoAll,
}

impl UpdatePolicy {
    /// Whether this policy would apply a change of this size on its own.
    ///
    /// # Why the size is a parameter rather than read from the versions
    ///
    /// Because a policy is about *how much trust a change needs*, and whether a version bump is major is a fact about two
    /// versions that this module never sees — [`UpdateFacts`] is deliberately about permissions and publishers. Comparing
    /// semver here would put the version syntax in the middle of a consent decision, and the two have nothing to do with
    /// each other.
    #[must_use]
    pub const fn allows(self, change: ChangeSize) -> bool {
        match self {
            Self::NotifyOnly => false,
            Self::AutoMinor => matches!(change, ChangeSize::Patch | ChangeSize::Minor),
            Self::AutoAll => true,
        }
    }

    /// The policy's name, as the interface spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotifyOnly => "notify-only",
            Self::AutoMinor => "auto-minor",
            Self::AutoAll => "auto-all",
        }
    }
}

/// How much of a change an update is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeSize {
    /// A patch.
    Patch,
    /// A minor version.
    Minor,
    /// A major version.
    Major,
}

/// Why an update is not automatic.
///
/// Reported as a list rather than as one reason, because two of these routinely hold at once and a user who fixes one only
/// to be shown the other has been told half the truth twice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateBlocker {
    /// The publisher is not one this device has trusted.
    ///
    /// Carries the trust so a screen can say *which* kind of not-trusted: a first plugin from a known publisher is a very
    /// different message from an unsigned one, and the design's table treats them differently everywhere else.
    PublisherNotTrusted {
        /// What the verification concluded.
        trust: PluginTrust,
    },
    /// The update asks for a capability the installed version did not.
    ///
    /// # Why the names are carried and not just a count
    ///
    /// Because "this update wants `device:send:*`" is a decision a user can make and "this update wants 1 new permission" is
    /// not. It is the same reason the capability gate's refusal carries the capability rather than a flag.
    NeedsConsent {
        /// Which capabilities are new or widened.
        added: Vec<String>,
    },
    /// The publisher's signing key is not the one this plugin was trusted under.
    PublisherChanged {
        /// What the plugin was trusted under.
        from: Fingerprint,
        /// What signs it now.
        to: Fingerprint,
    },
}

impl UpdateBlocker {
    /// The blocker's name, as the interface spells its message keys.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PublisherNotTrusted { .. } => "publisher-not-trusted",
            Self::NeedsConsent { .. } => "needs-consent",
            Self::PublisherChanged { .. } => "publisher-changed",
        }
    }

    /// Whether acting on this blocker needs the user to make a decision, rather than merely to be told.
    ///
    /// ★ An untrusted publisher is the one that is only **informational**: a device that has not been told to trust a
    /// publisher cannot be asked to make an update from it automatic, and the answer is not "ask" but "no, and here is what
    /// happened". The other two are questions with a yes.
    #[must_use]
    pub const fn needs_a_decision(&self) -> bool {
        !matches!(self, Self::PublisherNotTrusted { .. })
    }
}

/// What an update check found.
///
/// Everything here is a fact the caller established — from the manifest, the signature and the store — rather than
/// something this module looks up. That is what makes the decision testable without a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFacts {
    /// What verifying the candidate's signature concluded.
    pub trust: PluginTrust,
    /// Whether the **installed** version is on the revocation list.
    pub installed_revoked: bool,
    /// Capabilities the update asks for and the installed version did not, or asks for more widely.
    pub added_capabilities: Vec<String>,
    /// The installed version's publisher key, when the candidate's differs.
    pub publisher_key_changed: Option<(Fingerprint, Fingerprint)>,
    /// How large the change is.
    pub change: ChangeSize,
}

impl UpdateFacts {
    /// The facts of an update from a trusted publisher that asks for nothing new.
    ///
    /// A `const fn` because it is the shape a caller starts from and a test writes three of: everything here is a constant,
    /// including the empty list, which is why the lint was right to ask.
    #[must_use]
    pub const fn routine(trust: PluginTrust, change: ChangeSize) -> Self {
        Self {
            trust,
            installed_revoked: false,
            added_capabilities: Vec::new(),
            publisher_key_changed: None,
            change,
        }
    }

    /// Every reason the update is not automatic, in the table's order.
    #[must_use]
    pub fn blockers(&self) -> Vec<UpdateBlocker> {
        let mut blockers = Vec::new();
        if !matches!(self.trust, PluginTrust::TrustedPublisher) {
            blockers.push(UpdateBlocker::PublisherNotTrusted {
                trust: self.trust.clone(),
            });
        }
        if let Some((from, to)) = self.publisher_key_changed.clone() {
            blockers.push(UpdateBlocker::PublisherChanged { from, to });
        }
        if !self.added_capabilities.is_empty() {
            blockers.push(UpdateBlocker::NeedsConsent {
                added: self.added_capabilities.clone(),
            });
        }
        blockers
    }
}

/// What should happen about an update, given the policy and the facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateAction {
    /// Apply it without asking.
    Auto,
    /// Apply it, and it is not a choice: the installed version is revoked.
    ///
    /// The one outcome the design marks as forced, and the reason it is separate from [`UpdateAction::Auto`] rather than a
    /// note on it: a caller that treated this as routine would leave a revoked version in place when the download failed,
    /// which is the case the row exists for. The message is what the caller shows instead.
    Forced {
        /// Why it is not optional.
        why: String,
    },
    /// Ask the user, and show them why.
    Ask {
        /// Everything that stands in the way.
        blockers: Vec<UpdateBlocker>,
    },
    /// Tell the user an update exists and take no action.
    Notify {
        /// Why it was not offered as a decision.
        blockers: Vec<UpdateBlocker>,
    },
}

/// Decides what to do about an available update.
///
/// See the module documentation for why the order is what it is.
#[must_use]
pub fn decide(policy: UpdatePolicy, facts: &UpdateFacts) -> UpdateAction {
    // ★ First, and above the policy: a revoked version is a security matter rather than a preference, and the policy is a
    // statement about convenience.
    if facts.installed_revoked {
        return UpdateAction::Forced {
            why: "the installed version has been revoked, so this update is not optional".to_owned(),
        };
    }

    let blockers = facts.blockers();

    // ★ Before the policy, and before the decision: an update from a publisher this device does not trust is not something
    // the user is being asked to approve — it is one this device has no basis to offer, and the design's answer is
    // "notify" even when the user's policy says automatic.
    if blockers.iter().any(|blocker| !blocker.needs_a_decision()) {
        return UpdateAction::Notify { blockers };
    }
    if !blockers.is_empty() {
        return UpdateAction::Ask { blockers };
    }
    if policy.allows(facts.change) {
        UpdateAction::Auto
    } else {
        UpdateAction::Notify { blockers }
    }
}

#[cfg(test)]
mod tests;
