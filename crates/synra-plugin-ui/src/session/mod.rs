//! The tokens the interface issues to a UI plugin, and the decisions made about them.
//!
//! # Why this is a directory and not a file
//!
//! Because a token and the registry that holds it are different subjects. The first four modules are what a session
//! *is* — how long it lasts, why one was refused, the secret itself, and what a caller gets back once it has been
//! accepted. `UiSessionRegistry` is the map, the expiry sweep and the revocation, and `SessionReport` is what the
//! diagnostics screen shows. In one file the refusal enum sat a hundred lines above the sweep, so a reader changing
//! one had to scroll past the whole registry to find the other.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `token` | how long a session lasts, the secret, and what may be done with it |
//! | `validated` | a session a caller has already had accepted |
//! | `registry` | every live session, its expiry, and its revocation |
//! | `report` | what the diagnostics screen shows |

mod token;
mod validated;
mod registry;
mod report;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use registry::UiSessionRegistry;
pub use report::SessionReport;
pub use token::{SESSION_LIFETIME_MS, SessionRefusal, UiSessionToken};
pub use validated::ValidatedSession;
