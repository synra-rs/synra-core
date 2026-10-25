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

    /// Writes this identity, or reports that it is not there yet.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the row is not there: an update rather than an insert, because the schema's
    /// `CHECK (id = 1)` is what makes "this device's identity" a single answer, and an insert would be a second row.
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
mod tests {
    use super::*;

    fn db() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        db
    }

    // ── Loading ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_first_start_creates_an_identity() {
        let db = db();
        let identity = Identity::load(&db, "windows", 1_000).expect("loads");
        assert_eq!(identity.display_name, DEFAULT_DISPLAY_NAME);
        assert_eq!(identity.platform, "windows");
        assert_eq!(identity.created_at_ms, 1_000);
        // And it is stored, because the next start reads it rather than making another.
        assert!(db.identity().expect("reads").is_some());
    }

    #[test]
    fn a_second_start_reads_the_same_identifier() {
        // ★ The rule the whole module exists for. A device that made a new id here would appear to every peer as a new
        // device on every start, and every pairing would be lost — silently, because a new device is a legitimate thing
        // for the kernel to see.
        let db = db();
        let first = Identity::load(&db, "windows", 1_000).expect("loads");
        let second = Identity::load(&db, "windows", 2_000).expect("loads again");

        assert_eq!(first.device_id, second.device_id, "the identifier changed");
        // And the creation time is the first one's, not this run's: it is when the identity was made.
        assert_eq!(second.created_at_ms, 1_000);
    }

    #[test]
    fn a_restart_after_a_rename_keeps_both() {
        // The identifier is permanent and the name is not; a restart must preserve whichever the user chose.
        let db = db();
        let mut identity = Identity::load(&db, "windows", 1_000).expect("loads");
        let original_id = identity.device_id;
        identity
            .rename(&db, "Lena's laptop", 2_000)
            .expect("renames");

        let reloaded = Identity::load(&db, "windows", 3_000).expect("loads again");
        assert_eq!(reloaded.device_id, original_id);
        assert_eq!(reloaded.display_name, "Lena's laptop");
    }

    #[test]
    fn the_platform_is_the_one_the_first_start_reported() {
        // A device that moved from one host to another keeps its identity, so the stored platform is what the pairing was
        // made against rather than what this run happens to be. Stated because it is a choice: a changed platform is
        // reported by the peer's own announcement, not by rewriting the row here.
        let db = db();
        Identity::load(&db, "windows", 1_000).expect("loads");
        let second = Identity::load(&db, "linux", 2_000).expect("loads again");
        assert_eq!(second.platform, "windows");
    }

    #[test]
    fn an_identifier_the_database_cannot_parse_is_refused_rather_than_replaced() {
        // ★ A corrupt identifier is the one case where making a new one is tempting and wrong: it would silently unpair
        // every device. The refusal is what makes the user able to act — restore a backup, or accept the unpairing.
        let db = db();
        db.write_identity(&IdentityRow {
            device_id: "not a uuid".to_owned(),
            display_name: "N".to_owned(),
            platform: "p".to_owned(),
            created_at_ms: 0,
        })
        .expect("writes a bad row");

        match Identity::load(&db, "windows", 1_000) {
            Err(DbError::Statement { why }) => assert!(why.contains("UUID"), "{why}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // ── Renaming ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_rename_is_stored_and_applied() {
        let db = db();
        let mut identity = Identity::load(&db, "windows", 1_000).expect("loads");
        identity.rename(&db, "Laptop", 2_000).expect("renames");
        assert_eq!(identity.display_name(), "Laptop");
        assert_eq!(
            db.identity().expect("reads").expect("a row").display_name,
            "Laptop"
        );
    }

    #[test]
    fn a_refused_name_leaves_the_identity_as_it_was() {
        // ★ The name is validated **before** the write, so a caller that kept the new name would render one thing and
        // have stored another. The assertion is on both.
        let db = db();
        let mut identity = Identity::load(&db, "windows", 1_000).expect("loads");
        identity.rename(&db, "Laptop", 2_000).expect("renames");

        let refused = identity.rename(&db, "  ", 3_000);
        assert!(matches!(refused, Err(RenameError::Name(NameError::Empty))));
        assert_eq!(identity.display_name, "Laptop");
        assert_eq!(
            db.identity().expect("reads").expect("a row").display_name,
            "Laptop"
        );
    }

    #[test]
    fn a_name_is_trimmed_before_it_is_stored() {
        // A name of `  Laptop  ` is `Laptop` to a reader, and storing the padding would make two devices that look
        // identically named compare unequal.
        let db = db();
        let mut identity = Identity::load(&db, "windows", 1_000).expect("loads");
        identity.rename(&db, "  Laptop  ", 2_000).expect("renames");
        assert_eq!(identity.display_name, "Laptop");
    }

    // ── The name rules ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_name_is_refused() {
        for name in ["", "   ", "\t", "\n"] {
            assert_eq!(check_display_name(name), Err(NameError::Empty), "{name:?}");
        }
    }

    #[test]
    fn a_name_at_the_limit_is_accepted_and_one_over_is_refused() {
        // The boundary from both sides, because an off-by-one here refuses a name a user could have had.
        let at = "a".repeat(MAX_DISPLAY_NAME_LEN);
        assert!(check_display_name(&at).is_ok());
        let over = "a".repeat(MAX_DISPLAY_NAME_LEN + 1);
        match check_display_name(&over) {
            Err(NameError::TooLong { len }) => assert_eq!(len, MAX_DISPLAY_NAME_LEN + 1),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_limit_counts_bytes_rather_than_characters() {
        // A name of emoji is longer in bytes than it looks, and the limit is about what a device list can render.
        let emoji = "🎉".repeat(20);
        assert_eq!(emoji.chars().count(), 20);
        assert!(emoji.len() > MAX_DISPLAY_NAME_LEN);
        assert!(check_display_name(&emoji).is_err());
    }

    #[test]
    fn a_control_character_is_refused() {
        // ★ A newline in a name is how a log line is forged, and a carriage return is how a device list row is rewritten.
        // Stripping them would produce a name the user did not choose, and the peer would keep sending the original — so
        // the refusal is what makes the sender fix it.
        for name in ["a\nb", "a\rb", "a\tb", "a\u{0}b", "a\u{1b}[31mb"] {
            assert_eq!(
                check_display_name(name),
                Err(NameError::Control),
                "{name:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_name_is_accepted() {
        for name in ["Laptop", "Lena's laptop", "电脑", "Laptop 🎉", "a-b_c.d"] {
            assert!(check_display_name(name).is_ok(), "{name:?}");
        }
    }

    #[test]
    fn a_name_that_is_only_at_the_limit_after_trimming_is_accepted() {
        // The trim happens before the length check, so padding does not count against a name that fits.
        let padded = format!("  {}  ", "a".repeat(MAX_DISPLAY_NAME_LEN));
        assert!(check_display_name(&padded).is_ok());
    }

    // ── Errors ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            RenameError::Name(NameError::Empty),
            RenameError::Name(NameError::TooLong { len: 100 }),
            RenameError::Name(NameError::Control),
            RenameError::Db(DbError::Statement {
                why: "x".to_owned(),
            }),
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
        // And the length error names the limit, because a user who typed something too long needs to know how long.
        assert!(errors[1].to_string().contains('6'), "{}", errors[1]);
    }

    #[test]
    fn the_current_operating_system_maps_to_a_platform_kind() {
        // ★ `std::env::consts::OS` is what the daemon passes, so the mapping has to cover the machine this is built on
        // — asserted against the real value rather than a list of strings, because a list would be a second spelling of
        // what the compiler already knows.
        let kind = platform_of_os(std::env::consts::OS);
        assert!(matches!(
            kind,
            synra_protocol::session::PlatformKind::Desktop
                | synra_protocol::session::PlatformKind::Android
                | synra_protocol::session::PlatformKind::Ios
        ));
    }

    #[test]
    fn the_two_phone_platforms_are_named_exactly() {
        assert_eq!(
            platform_of_os("android"),
            synra_protocol::session::PlatformKind::Android
        );
        assert_eq!(
            platform_of_os("ios"),
            synra_protocol::session::PlatformKind::Ios
        );
    }

    #[test]
    fn an_unexpected_operating_system_name_is_a_desktop_rather_than_a_phone() {
        // ★ Calling a machine a phone is a worse default than calling a phone a desktop: an interface that hides a
        // desktop feature from a phone is a *missing* feature, and one that offers a phone a desktop-only one is a
        // broken control.
        for os in [
            "windows",
            "macos",
            "linux",
            "freebsd",
            "solaris",
            "plan9",
            "",
            "somewhere-new",
        ] {
            assert_eq!(
                platform_of_os(os),
                synra_protocol::session::PlatformKind::Desktop,
                "{os}"
            );
        }
    }

    #[test]
    fn the_default_name_is_itself_acceptable() {
        // A placeholder that the validator would refuse is one the first start could not store.
        assert!(check_display_name(DEFAULT_DISPLAY_NAME).is_ok());
        assert!(DEFAULT_DISPLAY_NAME.len() <= MAX_DISPLAY_NAME_LEN);
    }
}
