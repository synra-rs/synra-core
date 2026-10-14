//! Reading the WIT contract, and deriving what the host must enforce.
//!
//! # Why a parser rather than a toolchain
//!
//! A WIT file has a real parser (`wit-parser`) and this module is not a replacement for it: it reads the subset this
//! contract uses — packages, interfaces, functions, the annotations that carry capabilities — and refuses anything it
//! does not understand. A full parse would be better and would be a dependency whose version has to move with the
//! interface's, for a file this repository owns and changes deliberately.
//!
//! What matters is that it **refuses rather than guesses**. A line it cannot read is an error naming the line, not a
//! function silently missing from the capability table — because the one outcome that must not be possible is a host
//! function that is reachable without a gate.
//!
//! # What it derives
//!
//! The capability table: which capability each host function needs. That table is the thing three places have to agree
//! about and the thing they would otherwise each write down:
//!
//! * the host, which checks the gate before a call runs;
//! * the plugin CLI, which refuses an artifact that imports a function the host does not provide;
//! * the manifest's validation, which checks that a plugin declaring an entry point has declared what it needs.
//!
//! # The annotations
//!
//! `@ungated` and `@capability("…")` are read from the doc comment immediately above a function. A function with
//! neither is [`ParseError::UngatedFunction`] — deliberately an error rather than a default, because defaulting to
//! ungated is a hole and defaulting to gated invents a capability nobody chose.

mod contract;
mod declarations;
mod error;
mod gate;
mod signature;
mod table;

#[cfg(test)]
mod tests;

pub use contract::Contract;
pub use declarations::{Direction, Function, Interface};
pub use error::ParseError;
pub use gate::Gate;
