//! The plugin manifest: what an author declares, and the checks that hold them to it.
//!
//! # One declaration, four questions
//!
//! A manifest answers four things, and they are answered in one file because splitting them would let them
//! drift apart:
//!
//! * **What is this?** — id, version, title, publisher.
//! * **What does it need to run?** — which SDK range, which WIT world, and which artifact to load.
//! * **What may it do?** — the capability list the user is shown and asked to approve.
//! * **How does it connect?** — the actions it offers, the events it defines, and the events it wants to
//!   receive.
//!
//! # The checks are not a formality
//!
//! Every rule in [`Manifest::validate`] exists because the alternative is a failure somewhere much worse:
//!
//! * A **namespace violation** — an event named `_plugin.@synra-plugin/someone-else.thing` — is one plugin impersonating
//!   another, and it fails silently: the receiving side sees a legitimate name and routes it.
//! * A **capability the runtime cannot use** — `ui:*` on a headless plugin — is a permission the user approves
//!   at install time and that nothing can ever exercise. The consent screen said something untrue.
//! * A **`handles` entry with no `on_event`** produces a plugin that is installed, appears to work, and
//!   silently drops every message it asked for.
//! * An **unbounded `maxLength`** in an event's payload schema is a promise the host cannot keep when it
//!   validates the payload, and the promise is what the receiving side trusted.
//!
//! Each of those is a failure a user cannot diagnose, which is why they are refused at load rather than
//! tolerated.
//!
//! # What this crate does not do
//!
//! * It does not read files. [`Manifest::from_json`] takes text; finding and reading the file is the loader's
//!   job, and the loader is what knows about package roots and symlinks.
//! * It does not check that artifacts exist, or that declared methods are implemented. Both need the
//!   filesystem and the Wasm module, so they arrive as [`ManifestContext`] and [`Implementation`].
//! * It does not compile capabilities. [`synra_capability`] does that; this calls it.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds three separable jobs: the **shape** of a manifest (its types and the constants that bound them), the
//! **rules** a value must satisfy, and the **version arithmetic** those rules depend on. A reader looking for "is this
//! identifier legal" should not have to pass fifteen struct definitions to find it, and a reader looking for what a
//! manifest *is* should not have to pass the validation of one.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `types` | the manifest's shape, and the constants that bound it |
//! | `error` | what a refusal says and which check found it |
//! | `version` | plugin identifiers and version ordering |
//! | `validate` | the rules a manifest must satisfy, and what each field means |

pub mod error;
pub mod types;
pub mod validate;
pub mod version;

pub use error::ManifestError;
mod action_name;
pub use action_name::validate_action_name;

pub use types::*;
pub use version::{check_plugin_id, check_version, compare_versions, to_project_slug};

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod tests;
