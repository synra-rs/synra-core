//! The call gate. (Implementation follows; see design-docs/10-capability-and-sandbox.md.)

/// A decision from the call gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateOutcome {
    /// The call may proceed.
    Allowed,
    /// The call is refused.
    Refused,
}

/// Why a host call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GateRefusal {
    /// No capability covers the call.
    #[error("no granted capability covers {capability}")]
    NotGranted {
        /// What was attempted.
        capability: String,
    },
}

/// Checks host calls against a capability set.
#[derive(Debug, Clone)]
pub struct CallGate {
    /// The capabilities the plugin holds.
    granted: crate::set::CapabilitySet,
}

impl CallGate {
    /// Builds a gate over a capability set.
    #[must_use]
    pub const fn new(granted: crate::set::CapabilitySet) -> Self {
        Self { granted }
    }

    /// Checks one call.
    ///
    /// # Errors
    ///
    /// [`GateRefusal`] when nothing granted covers the call.
    pub fn check(&self, capability: &crate::capability::Capability) -> Result<GateOutcome, GateRefusal> {
        if self.granted.contains(capability) {
            return Ok(GateOutcome::Allowed);
        }
        Err(GateRefusal::NotGranted { capability: capability.to_string() })
    }

    /// The set this gate was built from.
    #[must_use]
    pub const fn granted(&self) -> &crate::set::CapabilitySet {
        &self.granted
    }
}