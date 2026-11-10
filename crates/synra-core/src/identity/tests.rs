use synra_store::records::IdentityRow;
use synra_store::{DbError, SynraDb};

use super::{DEFAULT_DISPLAY_NAME, Identity, MAX_DISPLAY_NAME_LEN, NameError, RenameError, check_display_name, platform_of_os};

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
