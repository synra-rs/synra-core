//! The scaffold: what `new` writes, and why each file is there.
//!
//! # Why the templates are values rather than a directory of files
//!
//! A plugin author's first experience is `synra-plugin new`, and the failure that ruins it is a scaffold that does not
//! build. Templates kept as files on disk are tested by nothing — the only way to find out that one of them stopped
//! compiling is for an author to report it.
//!
//! So a template here is a *value*: a list of paths and contents, produced by a pure function. That makes three things
//! possible which a directory of files does not:
//!
//! * A test can assert that every template produces a manifest the kernel's own validator accepts, and that the
//!   runtime declaration matches the files that were written. A template whose manifest claims a `.wasm`
//!   entry point and writes none is a plugin that installs and then does nothing.
//! * The two kinds differ only in which runtime block the manifest carries and which files are written, which is
//!   the difference the design document draws between headless and hybrid — so the shared part cannot drift
//!   between them.
//! * Nothing writes to the author's disk until they ask. `new` on an existing directory is refused *before* a file is
//!   created, rather than after three of them are.
//!
//! # What the scaffold deliberately does not do
//!
//! No package manager, no bundler, no dependency. An author who wants a framework will add one, and a scaffold that
//! chose for them would be a scaffold they have to unpick. The files are the smallest thing that installs, runs, and
//! gives a place to start reading.

mod files;
mod kind;
mod scaffold;

pub use kind::TemplateKind;
pub use scaffold::{Scaffold, ScaffoldError, ScaffoldFile};

#[cfg(test)]
mod tests;
