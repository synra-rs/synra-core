//! The eleven checks a package passes before it is installed, in the order the design document gives them.
//!
//! # Why this is one function and not eleven call sites
//!
//! Because the order is the security argument. Every step is only meaningful if the one before it held: verifying a
//! signature over a manifest nobody has read proves nothing about what the plugin *is*, checking that a plugin's
//! imports are covered by its capabilities is meaningless if the capabilities were never parsed, and a dependency
//! graph is a graph only after every dependency has been read.
//!
//! A caller that assembled these itself would eventually assemble them in a different order, and the symptom of the
//! wrong order is not a failure — it is a package that passes. So the order is here, once, and [`Report`] names which
//! step stopped.
//!
//! # What is deliberately not decided here
//!
//! **Whether the user trusts the publisher.** That is a person's decision, and this reports what it found
//! ([`Stage::PublisherTrust`] passes for an unknown publisher) so the interface can ask. A pipeline that refused an
//! unknown publisher would make the first install from anybody impossible.
//!
//! # The two checks that are this crate's own
//!
//! Everything else delegates: digests and signatures to [`synra_plugin_api::publisher`], the manifest and the
//! capability DSL to [`synra_plugin_api::manifest`], and the import table to [`crate::host_surface`]. The dependency
//! graph and the platform applicability are here because they are about *this host* — what it can run and what it
//! already has — rather than about the package.

mod graph;
mod pipeline;
mod types;

pub use graph::DependencyGraph;
pub use pipeline::verify;
pub use types::{host_world, Candidate, HostFacts, Report, Stage, Step, Verdict, VerifyError};

#[cfg(test)]
pub(crate) use crate::host_surface;
#[cfg(test)]
pub(crate) use synra_plugin_api::publisher::PluginTrust;

#[cfg(test)]
mod tests;
