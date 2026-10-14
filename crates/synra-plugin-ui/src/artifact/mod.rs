//! The files a UI plugin's bundle contains, and what may be served from it.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds three separable things: the limits, the error vocabulary and one file's record; the artifact and
//! the index built from it, together with their lookups and validation; and the path rules that decide whether a
//! request may be served at all. In one file the path checks — the part where a mistake serves a file from outside the
//! bundle — sat below two hundred lines of index bookkeeping.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `limits` | the size ceilings, the error vocabulary, and one file's record |
//! | `bundle` | the artifact and its index, and the lookups and validation they support |
//! | `serving` | whether a requested path may be served, and what it is served as |

mod limits;
mod bundle;
mod serving;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use bundle::{UiArtifact, UiArtifactIndex};
pub use limits::{
    ArtifactError, ArtifactFile, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_FILE_BYTES, MAX_ARTIFACT_FILES,
    MAX_ARTIFACT_PATH_LEN, PathRefusal,
};
pub use serving::{check_path, content_type_for};
