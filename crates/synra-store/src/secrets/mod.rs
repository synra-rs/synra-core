//! Where a secret is kept, and what may be done with it.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: how a secret is named and which backend holds it, the bytes themselves and
//! the guarantee that they are wiped, the backend trait and the one backend that needs no operating system, and the
//! report a caller shows a user. In one file the wiping and redacting of the bytes sat between two enums.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `kind` | which backend and which strength, and how a secret is named |
//! | `bytes` | the secret bytes, the redacted `Debug`, and the wipe on drop |
//! | `backend` | the trait a backend implements, the memory backend, and how one is chosen |
//! | `report` | what a settings screen shows about a secret |

mod kind;
mod bytes;
mod backend;
mod report;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use backend::{MAX_SECRET_BYTES, MemoryBackend, SecretBackend, choose_backend};
pub use bytes::{SecretBytes, SecretError};
pub use kind::{SecretBackendKind, SecretKey, SecretStrength};
pub use report::SecretStorageReport;

