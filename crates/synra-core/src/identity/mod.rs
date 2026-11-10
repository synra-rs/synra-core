//! Who this device is.
//!
//! # The one rule this module exists to enforce
//!
//! `synra-protocol`'s own docs put it exactly: *"Called once, when a device first runs, and then persisted. A device that
//! regenerates its id on every start appears to its peers as a new device each time, and every pairing is lost."*
//!
//! So the identifier is generated **once** and read from the database on every start after that. [`Identity::load`] is
//! the only way to get one, and it is deliberately not a constructor: a caller that could build an identity from
//! nothing is a caller that could build a second one, and the failure is silent — the device pairs, restarts, and is a
//! stranger again.
//!
//! # Why the name is separate from the identifier
//!
//! The identifier is permanent and the name is not. A user renames their laptop, and every peer they have paired with
//! learns the new name — while the identifier stays, because it is what the pairing is recorded against. Confusing the
//! two would either make a rename look like a new device or make a device keep a name its owner changed.
//!
//! # Why the name is validated here
//!
//! Because it crosses an untrusted boundary: a peer's discovery announcement carries whatever that peer decided to call
//! itself, and a kernel that accepted any string would render a control character into a device list and a newline into
//! a log line. The rules are the same ones a user would expect of a nickname, and they are checked where the value
//! enters rather than where it is drawn.

use synra_protocol::ids::DeviceId;
use synra_store::records::IdentityRow;
use synra_store::{DbError, SynraDb};

/// The name a device gives itself before its owner has chosen one.
///
/// Not the hostname: the kernel has no platform abstraction in this crate, and a name derived from a machine would be a
/// name the user cannot change on the machine's terms. A placeholder the user replaces is more honest than a guess that
/// looks like a decision.
pub const DEFAULT_DISPLAY_NAME: &str = "This device";

/// The longest a display name may be.
///
/// 64 bytes, which fits a person's name with room for an emoji and is short enough for a device list column. Longer
/// names are not a security problem; they are a *rendering* problem, and the place to prevent it is where the value
/// enters.
pub const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Why a display name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The name is empty.
    #[error("a display name cannot be empty")]
    Empty,

    /// The name is longer than [`MAX_DISPLAY_NAME_LEN`].
    #[error("a display name of {len} bytes exceeds the limit of {MAX_DISPLAY_NAME_LEN}")]
    TooLong {
        /// How long it was.
        len: usize,
    },

    /// The name holds a control character.
    ///
    /// # Why this is refused rather than stripped
    ///
    /// A newline in a name is how a log line is forged, and a carriage return is how a device list row is rewritten.
    /// Stripping them would produce a name the user did not choose, and the peer would keep sending the original — so
    /// the refusal is what makes the sender fix it.
    #[error("a display name cannot contain a control character")]
    Control,
}

/// This device's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The stable identifier, which never changes after the first start.
    pub device_id: DeviceId,
    /// What this device calls itself.
    pub display_name: String,
    /// What this device is.
    pub platform: String,
    /// When the identity was created.
    pub created_at_ms: i64,
}

impl Identity {
    /// Reads this device's identity, creating it on the first start.
    ///
    /// # Why this is not two functions
    ///
    /// Because a caller that had to check for an identity and then create one would be a caller that could create a
    /// second — and two identities is the failure the protocol's own docs name. There is one path: read, or create and
    /// store.
    ///
    /// # Errors
    ///
    /// [`DbError`] when the database cannot be read or written.
    pub fn load(db: &SynraDb, platform: &str, now_ms: i64) -> Result<Self, DbError> {
        if let Some(existing) = db.identity()? {
            // ★ The identifier is read, not regenerated. This is the line the whole module is about: a device that made
            // a new id here would appear to every peer as a new device on every start, and every pairing would be lost —
            // silently, because a new device is a legitimate thing for the kernel to see.
            return Self::from_row(existing);
        }

        let device_id = DeviceId::new();
        let identity = Self {
            device_id,
            display_name: DEFAULT_DISPLAY_NAME.to_owned(),
            platform: platform.to_owned(),
            created_at_ms: now_ms,
        };
        db.create_identity_if_absent(&IdentityRow {
            device_id: identity.device_id.to_string(),
            display_name: identity.display_name,
            platform: identity.platform,
            created_at_ms: identity.created_at_ms,
        })?;
        // A different connection may have won after our initial read. Return the persisted winner,
        // never upsert our candidate over an identity whose credentials may already be enrolled.
        let stored = db.identity()?.ok_or_else(|| DbError::Statement {
            why: "local identity disappeared during creation".to_owned(),
        })?;
        Self::from_row(stored)
    }

    fn from_row(existing: IdentityRow) -> Result<Self, DbError> {
        let device_id = existing
            .device_id
            .parse()
            .map_err(|error| DbError::Statement {
                why: format!("the stored device id is not a UUID: {error}"),
            })?;
        Ok(Self {
            device_id,
            display_name: existing.display_name,
            platform: existing.platform,
            created_at_ms: existing.created_at_ms,
        })
    }

    /// Persists metadata for this device, using retained history if its identity row must be restored.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] if another device id is already present, recovery history is missing,
    /// or persistence fails; metadata writes cannot replace the stable device id.
    pub fn store(&self, db: &SynraDb, now_ms: i64) -> Result<(), DbError> {
        db.write_identity(&IdentityRow {
            device_id: self.device_id.to_string(),
            display_name: self.display_name.clone(),
            platform: self.platform.clone(),
            created_at_ms: if self.created_at_ms == 0 {
                now_ms
            } else {
                self.created_at_ms
            },
        })
    }

    /// Renames this device.
    ///
    /// # Errors
    ///
    /// [`NameError`] when the name is not acceptable, and [`DbError`] when it cannot be stored. The name is validated
    /// **before** the write, so a refusal leaves the identity as it was rather than half-changed.
    pub fn rename(&mut self, db: &SynraDb, name: &str, now_ms: i64) -> Result<(), RenameError> {
        let checked = check_display_name(name)?;
        let previous = std::mem::replace(&mut self.display_name, checked);
        match self.store(db, now_ms) {
            Ok(()) => Ok(()),
            Err(error) => {
                // The in-memory name is put back, so the struct and the row agree after a failed write. A caller that
                // kept the new name would render one thing and have stored another.
                self.display_name = previous;
                Err(RenameError::Db(error))
            }
        }
    }

    /// What a peer is told about this device.
    ///
    /// # Why this is not `PeerProfile`
    ///
    /// `synra-protocol`'s `PeerProfile` is the wire shape and carries what the protocol needs — the kernel version, the
    /// platform kind. This is the kernel's own view, and the mapping belongs where the wire is written rather than here,
    /// so that a protocol change is not a change to the identity.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Why a rename failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RenameError {
    /// The name is not acceptable.
    #[error(transparent)]
    Name(#[from] NameError),

    /// The name could not be stored.
    #[error("the new name could not be stored: {0}")]
    Db(#[from] DbError),
}

/// Which platform kind a `std::env::consts::OS` string names.
///
/// # Why this lives here and not in the protocol
///
/// Because it is a fact about *this* build's view of the operating system, and the protocol's `PlatformKind` is three
/// variants rather than the dozen names `std::env::consts::OS` can produce. Putting the mapping in the protocol would
/// make the wire format depend on Rust's spelling of an operating system name — so a change there would be a change to
/// the protocol.
///
/// # Why the fallback is `Desktop`
///
/// Because the two other variants are phones, and calling a machine a phone is a worse default than calling a phone a
/// desktop: an interface that hides a desktop feature from a phone is a *missing* feature, and one that offers a phone a
/// desktop-only one is a broken control. The kernel's own `probe`-style reporting is where an unexpected name would be
/// noticed; the wire field has to be one of three.
#[must_use]
pub fn platform_of_os(os: &str) -> synra_protocol::session::PlatformKind {
    use synra_protocol::session::PlatformKind;
    match os {
        "android" => PlatformKind::Android,
        "ios" => PlatformKind::Ios,
        // Every desktop operating system Rust names, listed rather than matched by a catch-all so that adding a phone
        // platform above cannot be silently shadowed by a fallback that was never meant to see it.
        "windows" | "macos" | "linux" | "freebsd" | "netbsd" | "openbsd" | "dragonfly"
        | "solaris" | "illumos" | "aix" | "hurd" | "redox" | "fuchsia" | "haiku" | "vxworks" => {
            PlatformKind::Desktop
        }
        _ => PlatformKind::Desktop,
    }
}

/// Checks a display name, returning it unchanged.
///
/// # Why a peer's name goes through this too
///
/// Because the name arrives from another device, and a kernel that stored whatever it was sent would render a control
/// character into a device list and a newline into a log line. The check is on the *value*, so it applies wherever the
/// value comes from.
///
/// # Errors
///
/// [`NameError::Empty`], [`NameError::TooLong`] or [`NameError::Control`].
pub fn check_display_name(name: &str) -> Result<String, NameError> {
    // Trimmed first, because a name of spaces is empty to a reader — and the check a user sees should be about the name
    // they meant rather than about the padding they left.
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(NameError::Empty);
    }
    // Bytes rather than characters: the limit is about what a device list can render, and a name of emoji is longer in
    // bytes than it looks.
    if trimmed.len() > MAX_DISPLAY_NAME_LEN {
        return Err(NameError::TooLong { len: trimmed.len() });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(NameError::Control);
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests;
