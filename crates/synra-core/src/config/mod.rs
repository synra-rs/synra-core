//! The settings, as a bag of named values with tracked defaults.
//!
//! # Why a bag rather than a struct
//!
//! The design document is explicit about this, and the reason is worth restating because a struct is what most kernels
//! reach for: **a `synra-core` release must not force an interface release.** A struct of settings here means every
//! feature that adds a setting adds a field, and every field is a version of this crate that every interface has to be
//! rebuilt against. So the boundary carries a bag of `serde_json::Value` keyed by a dotted path, and the *screens* own
//! their own shape — which is where the knowledge of what a setting means actually lives.
//!
//! # What this module is for, then
//!
//! Three things a bag alone does not give:
//!
//! 1. **Defaults that survive.** A setting the user has never touched is not the same as one they set to the default
//!    value, and the difference is what a settings screen marks as changed and what a "reset" button restores. So the
//!    defaults are the input and the overrides are the state.
//! 2. **A patch that applies atomically.** Two screens can be open, and a whole-value write from one discards the
//!    other's change. A patch names the keys it touches, and either every key in it applies or none does.
//! 3. **A file that is read but not trusted.** A configuration file is written by a person and by a previous version of
//!    this kernel. A value it carries for a key this build does not know is *kept* rather than dropped — dropping it
//!    would make opening an old config in a new kernel silently lose settings the old one had — and a file that cannot
//!    be parsed at all is a refusal rather than an empty configuration, because the second is indistinguishable from
//!    "the user wants everything at its default".
//!
//! # Why `unset` and `set` in one patch is refused
//!
//! [`synra_ipc`]'s `ConfigPatch` already refuses it, and this repeats the refusal because the two are different
//! boundaries: a patch can reach this module from a file or from the daemon's own command line, not only over IPC. A
//! caller that named a key in both meant one of the two, and picking for them produces a setting that is the opposite
//! of what they asked for half the time.

mod catalog;
mod document;
mod error;
mod key;
mod kind;
mod setting;
mod snapshot;

pub use catalog::Catalog;
pub use document::Config;
pub use error::ConfigError;
pub use key::SettingKey;
pub use kind::SettingKind;
pub use setting::Setting;
pub use snapshot::ConfigSnapshot;

#[cfg(test)]
mod tests;
