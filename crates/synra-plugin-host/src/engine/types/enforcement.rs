use super::outcome::CallBudget;

/// What an engine can actually enforce.
///
/// # Why this is asked rather than assumed
///
/// A backend that cannot stop a runaway guest must not be given one. `wasmi` interprets and counts instructions, so it
/// can do fuel; an engine without epoch interruption cannot end a call blocked inside a host function. A host that
/// assumed the controls existed would run third-party code with no upper bound and believe it had one — so the
/// capability is a value the backend reports, and a caller that needs a limit it cannot get is a caller that refuses
/// the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Enforcement {
    /// Instruction counting.
    pub fuel: bool,
    /// Wall-clock interruption.
    pub epoch: bool,
    /// A memory ceiling.
    pub memory: bool,
    /// AOT precompilation.
    pub precompile: bool,
}

impl Enforcement {
    /// Everything a fully featured engine offers.
    #[must_use]
    pub const fn full() -> Self {
        Self { fuel: true, epoch: true, memory: true, precompile: true }
    }

    /// Whether this backend enforces everything a budget asks for.
    ///
    /// # Returns
    ///
    /// The first limit the backend cannot honour, so a refusal names the missing control rather than saying "no".
    #[must_use]
    pub const fn first_gap(&self, budget: &CallBudget) -> Option<&'static str> {
        if budget.fuel.is_some() && !self.fuel {
            return Some("an instruction budget");
        }
        if budget.timeout.is_some() && !self.epoch {
            return Some("a wall-clock limit");
        }
        if budget.max_memory_growth.is_some() && !self.memory {
            return Some("a memory ceiling");
        }
        None
    }
}
