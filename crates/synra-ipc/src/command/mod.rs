//! The command registry: which commands exist, and who may call them.
//!
//! # Why a registry rather than a list in a document
//!
//! The interface's command set is a contract with two independent implementations — the shell that registers them
//! and the front end that calls them. A document describes it and drifts; a value can be *asserted*. So the set
//! lives here, and the tests in this module hold it to the properties that matter:
//!
//! * Every command in the design document's table exists.
//! * The plugin interface may not reach the host interface's commands, and vice versa.
//! * No command name is spelled two ways.
//! * Every command's domain prefix matches the group it is filed under.
//!
//! That last one is not pedantry: the prefixes are what the front end uses to organise its own modules, and a
//! command whose prefix disagrees with its group is one that ends up in the wrong file — after which the
//! interface's "devices" screen holds a pairing call and nobody notices until they need it.
//!
//! # Two interfaces, and the separation is the point
//!
//! The design document requires the plugin interface and the host interface to be separate: **different tokens,
//! different command allow-lists**. A plugin's page runs inside the same WebView as the host's own interface, so
//! without a separated list a plugin could call `plugins_uninstall` — or `identity_set_display_name`.
//!
//! [`Interface`] is that separation, expressed as a value: a command belongs to exactly one interface, and the
//! plugin interface's list is a short, deliberate subset.

mod catalog;
mod descriptor;
mod registry;

pub use catalog::COMMANDS;
pub use descriptor::{CommandDescriptor, Domain, Interface, ReturnShape};
pub use registry::{CommandRegistry, RegistryError};

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
