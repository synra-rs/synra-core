//! Why a call was refused, and what an author can do about it.
//!
//! # Why this is a module of its own
//!
//! Because the three things a refusal has to carry were, until now, answered in three places and none of them completely.
//! `CapabilityError` is a **parse** error and says nothing about a call; `GateRefusal::NotGranted` carries the capability
//! that was needed and not the ones the plugin holds; and the plugin-facing `CallError::denied` carried the needed
//! capability as a single JSON field. So an author reading a refusal learned what was missing and had no way to see it
//! against what they already had.
//!
//! # The three things
//!
//! 1. **What the call needed** — the capability, spelled the way the contract spells it.
//! 2. **What the plugin holds** — the whole set, because "you need `storage:local:write`" reads very differently to an
//!    author whose plugin already holds `storage:local:read` than to one who holds nothing in that domain.
//! 3. **What to do** — a sentence, derived from the two above rather than written by hand, because a suggestion that does
//!    not match the refusal is worse than none.
//!
//! # What the suggestion is careful about
//!
//! It never claims a capability *will* be granted. Whether a user grants one is their decision, and a message that promised
//! it would make the refusal look like a formality. What it says is which capability to ask for, and — when there is one —
//! that the plugin already holds something in the same domain, which is a fact about the two sets rather than advice.

use crate::capability::Capability;
use crate::set::CapabilitySet;

/// A refusal, with everything the author of the plugin needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDenied {
    /// The capability the call needed.
    pub needed: String,
    /// What the plugin holds, so an author can see the gap rather than guess at it.
    pub granted: Vec<String>,
    /// What to do about it.
    pub suggestion: String,
}

impl CapabilityDenied {
    /// Builds the refusal from what a call needed and what the plugin was granted.
    ///
    /// # A needed capability that will not parse
    ///
    /// The gate's capabilities come from a generated table and always parse, but this does not assume it: an unparseable
    /// one yields a suggestion with no domain hint rather than no suggestion. The alternative — refusing to build the
    /// error — would turn a bad refusal into no refusal at all, which is the one outcome a gate must never produce.
    #[must_use]
    pub fn of(needed: &str, held: &CapabilitySet) -> Self {
        Self {
            needed: needed.to_owned(),
            // ★ The **spellings**, not `describe_all`'s prose.
            //
            // `CapabilitySet::describe_all` answers "keep its own saved data", which is the right thing to show a person
            // and the wrong thing to hand a plugin: an author compares a refusal against the capability names in their own
            // manifest, and a sentence they cannot grep for is one they have to translate back.
            granted: held.iter().map(|capability| capability.as_str().to_owned()).collect(),
            suggestion: suggest(needed, held),
        }
    }

    /// The same three things as a JSON object, for the `details` a plugin reads.
    ///
    /// # Why this builds the text rather than serialising the struct
    ///
    /// Because `synra-capability` has no serialisation dependency and does not want one: this crate is about what a
    /// capability *means*, and a `serde` derive here would put a data-format concern in the middle of the matching rules.
    /// The escape is the only part of JSON this needs, and it is three lines.
    #[must_use]
    pub fn to_json(&self) -> String {
        let granted = self
            .granted
            .iter()
            .map(|capability| format!("\"{}\"", escape(capability)))
            .collect::<Vec<String>>()
            .join(",");
        format!(
            "{{\"capability\":\"{}\",\"granted\":[{granted}],\"suggestion\":\"{}\"}}",
            escape(&self.needed),
            escape(&self.suggestion)
        )
    }
}

impl std::fmt::Display for CapabilityDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "this plugin does not hold `{}`", self.needed)
    }
}

/// What to do about a refusal, derived from the two sets.
#[must_use]
fn suggest(needed: &str, held: &CapabilitySet) -> String {
    let ask = format!("ask the user to grant `{needed}` to this plugin");

    // ★ The domain hint, and the reason it is worth the code.
    //
    // A capability names a domain and then a place inside it — `storage:local:read` and `storage:local:write` are two
    // permissions over the same thing. An author whose plugin already holds one of them is looking at a **narrower**
    // problem than one who holds nothing in that domain: the user has already decided to trust this plugin with that
    // domain, and what is missing is one permission inside it.
    let Ok(parsed) = Capability::parse(needed) else {
        return ask;
    };
    let domain = parsed.domain();
    let nearest = held
        .iter()
        .find(|candidate| candidate.domain() == domain)
        .map(|candidate| candidate.as_str().to_owned());

    match nearest {
        Some(neighbour) => format!("{ask}; it already holds `{neighbour}` in the same domain"),
        None => format!("{ask}; it holds nothing in that domain"),
    }
}

/// A string with the two characters JSON needs escaped.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests;
