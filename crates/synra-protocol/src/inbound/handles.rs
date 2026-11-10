use smallvec::SmallVec;

use crate::error::{ErrorCode, SynraError};
use crate::event::EventName;

use super::{HandlePattern, PatternError, UnknownReason, MAX_WILDCARD_RULES};

/// A plugin's compiled `handles` declaration.
///
/// One exact-name index and one bounded wildcard list, which is the shape the kernel's routing table
/// needs: an exact hit is a hash lookup, and the wildcards are few enough to check linearly.
#[derive(Debug, Clone, Default)]
pub struct HandleSet {
    /// Exact names, with no wildcards.
    exact: SmallVec<[HandlePattern; 8]>,
    /// Patterns containing at least one wildcard.
    wildcards: SmallVec<[HandlePattern; 4]>,
}

impl HandleSet {
    /// Compiles a plugin's declarations.
    ///
    /// # Errors
    ///
    /// [`PatternError`] for any entry that is not a valid pattern, or [`HandleSetError`] if the
    /// plugin declares more wildcards than [`MAX_WILDCARD_RULES`].
    pub fn compile<I, S>(patterns: I) -> Result<Self, HandleSetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::default();
        for pattern in patterns {
            let pattern = HandlePattern::parse(pattern.as_ref()).map_err(HandleSetError::Pattern)?;
            if pattern.is_exact() {
                set.exact.push(pattern);
            }
            else {
                if set.wildcards.len() >= MAX_WILDCARD_RULES {
                    return Err(HandleSetError::TooManyWildcards {
                        max: MAX_WILDCARD_RULES,
                    });
                }
                set.wildcards.push(pattern);
            }
        }
        Ok(set)
    }

    /// Whether this set wants a name.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        // Exact first: it is a string comparison against a short list, and the common case for a
        // plugin that subscribes to specific built-ins.
        if self.exact.iter().any(|pattern| pattern.matches(name)) {
            return true;
        }
        self.wildcards.iter().any(|pattern| pattern.matches(name))
    }

    /// How many exact declarations there are.
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    /// How many wildcard declarations there are.
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }
}

/// Why a `handles` declaration could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandleSetError {
    /// A pattern did not parse.
    #[error(transparent)]
    Pattern(PatternError),

    /// Too many wildcard patterns.
    #[error("a plugin may declare at most {max} wildcard handle patterns")]
    TooManyWildcards {
        /// The limit.
        max: usize,
    },
}

/// Turns an inbound problem into the error a peer should receive.
#[must_use]
pub fn inbound_error_to_synra(reason: UnknownReason, event: &EventName) -> SynraError {
    match reason {
        // A data-plane name we do not recognise leaves a state machine unadvanced, so the peer has
        // to be told rather than left waiting.
        UnknownReason::UnrecognisedDataPlane => SynraError::new(
            ErrorCode::ProtocolViolation,
            format!("unrecognised data-plane event {event}"),
        ),
        // A valid name this build does not implement, or a payload it cannot read. `Unsupported`
        // rather than `ProtocolViolation`: the peer did nothing wrong, and the user-facing reading
        // is "this version cannot do that yet".
        UnknownReason::NotInCatalogue | UnknownReason::UnreadablePayload => SynraError::new(
            ErrorCode::Unsupported,
            format!("unknown event {event}"),
        ),
    }
}
