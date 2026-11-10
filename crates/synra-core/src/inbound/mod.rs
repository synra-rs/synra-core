//! What an inbound connection does when it is carrying a file.
//!
//! # Where this sits
//!
//! [`crate::listener`] owns the socket: it accepts, handshakes, and reads frames. This owns the **state** — a connection
//! that is mid-transfer is one where a `TransferRequest` has been seen and blocks are arriving, and something has to
//! remember which file they belong to. That memory is here, so the socket code stays a loop over frames.
//!
//! # Why the file name from the peer is not trusted
//!
//! Because it arrives over the network and it becomes a **path**. A name of `../../../.ssh/authorized_keys`, or one
//! containing a NUL, or one that is a Windows device like `CON`, would either escape the inbox or fail in a way the user
//! cannot diagnose. The name is passed through the store's `sanitise_component`, which is the same rule plugin identifiers
//! already follow — one sanitiser for every untrusted name that becomes part of a path, rather than a second one here that
//! would drift.
//!
//! # Why the destination is inside the data directory
//!
//! Because that is the only directory this process may certainly write to, and a kernel that guessed a user's Downloads
//! folder would be one that writes where it was not asked to. A file lands in `<data>/inbox`, and moving it from there is
//! the interface's job, where the user can be asked.

mod inbox;
mod model;
mod util;

pub use inbox::Inbox;
pub use model::{Decision, Offer, OfferCallback, OfferDecision, auto_accept};

use std::time::Duration;

/// The directory under the data root where incoming files are staged.
pub const INBOX_DIR: &str = "inbox";
const TRANSFER_PATIENCE: Duration = Duration::from_secs(120);

#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "synra-inbox-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temp directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── The name rules ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_name_that_would_escape_the_inbox_does_not() {
        // ★ The name arrives over the network and becomes a path. A traversal that survived would write wherever the peer
        // asked, which is the whole of the user's home directory.
        let dir = TempDir::new("traversal");
        let inbox = Inbox::new(dir.path());
        for hostile in [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\notepad.exe",
        ] {
            let destination = inbox.destination_for(hostile);
            assert!(
                destination.starts_with(dir.path().join(INBOX_DIR)),
                "{hostile} escaped to {}",
                destination.display()
            );
        }
    }

    #[test]
    fn a_name_is_still_recognisable_after_sanitising() {
        // Sanitising is not meant to destroy the name: the user has to recognise the file they were sent.
        let dir = TempDir::new("recognisable");
        let inbox = Inbox::new(dir.path());
        let destination = inbox.destination_for("quarterly report (final).pdf");
        let name = destination
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .into_owned();
        assert!(name.contains("quarterly"), "{name}");
        assert!(name.contains("report"), "{name}");
        assert!(name.ends_with(".pdf"), "{name}");
    }

    #[test]
    fn a_name_of_nothing_usable_still_produces_a_file() {
        // Every character rejected is possible, and a transfer that had nowhere to write would fail for a reason the user
        // cannot act on.
        let dir = TempDir::new("empty-name");
        let inbox = Inbox::new(dir.path());
        let destination = inbox.destination_for("...");
        assert!(destination.file_name().is_some());
        assert!(!destination.file_name().expect("a name").is_empty());
    }

    #[test]
    fn a_new_inbox_is_empty_and_lands_under_the_data_directory() {
        let dir = TempDir::new("new");
        let inbox = Inbox::new(dir.path());
        assert!(!inbox.is_busy());
        assert_eq!(inbox.directory(), dir.path().join(INBOX_DIR));
    }
}
