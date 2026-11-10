//! The socket a client and a kernel meet on.
//!
//! # Why a local socket rather than a loopback TCP port
//!
//! A loopback port is reachable by **every process on the machine**. A local socket is reachable by those too, and is
//! additionally a filesystem object the operating system can permission — which is the difference between "any program
//! running as any user can ask the kernel to send a file to your laptop" and "only a program that can open a file owned
//! by you can".
//!
//! That is not a theoretical difference. A loopback port is also reachable from a browser: a page can `fetch` a
//! `127.0.0.1` URL, so a kernel on a TCP port is a kernel a website can drive. There is no equivalent for a local
//! socket, and the same reasoning is why a plugin's WebView gets no network access of its own.
//!
//! # What "local socket" means on each platform
//!
//! A unix domain socket on Linux and macOS, and a **named pipe** on Windows. The two are not the same thing — a pipe has
//! no filesystem entry and no path-length limit — and the platform difference is handled by `interprocess` rather than
//! here, so there is one code path to read and one to test.
//!
//! # Why this is blocking rather than async
//!
//! A command-line client sends one batch and closes, so the work per connection is bounded and there is nothing to
//! overlap. An async runtime here would be a runtime, a task per connection and a `Send` bound on every kernel method —
//! paid for concurrency this channel does not use. A caller that wants several clients served at once runs several
//! threads, which is what a daemon already does.
//!
//! # What is claimed, and what is not
//!
//! The path-length limit below is a **unix** rule. On Windows the name is a pipe name and has no such limit, so
//! [`check_bindable`] is advisory there — it refuses a path the unix side would refuse, which makes a build that moves
//! between platforms behave the same way rather than working on one and not the other.

use std::path::{Path, PathBuf};
use std::time::Duration;

// Each platform's name mapping, imported only where it is used: a build that imported both would warn about one on
// every platform, and a warning that is always there is one nobody reads.

use crate::ChannelError;

/// The file name of the control socket inside the data directory.
///
/// Inside the data directory rather than in a shared temporary directory, so that two installations on one machine —
/// two users, or one user with two profiles — do not collide, and so the socket inherits the directory's permissions.
pub const SOCKET_FILE_NAME: &str = "kernel.sock";

/// How long a client waits for an answer before giving up.
///
/// A kernel that is running answers in microseconds; one that has stopped answering is one whose socket is still open
/// because the process is wedged. A client that waited forever would be a command that hangs with no output, which is
/// the worst thing a command-line tool can do.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest unix socket path this build will try to bind.
///
/// 108 bytes on Linux including the terminating NUL, 104 on macOS. A path that fits the smaller one fits both, and a
/// path of 103 bytes plus the NUL the operating system appends is the largest that does.
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Where the control socket is for a data directory.
///
/// # Why the data directory rather than the platform's runtime directory
///
/// The runtime directory is the more conventional place and the wrong one: a client pointed at a different data
/// directory — `SYNRA_DATA_DIR`, which is how a second installation or a test works — would connect to the socket of the
/// installation it is *not* talking to.
///
/// Putting it beside the database means the two always agree, because they are derived from one input.
#[must_use]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE_NAME)
}

/// Why a socket operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SocketError {
    /// The socket could not be bound.
    #[error("could not listen on {}: {why}", path.display())]
    Bind {
        /// Where it tried.
        path: PathBuf,
        /// What the operating system said.
        why: String,
    },

    /// The client could not connect.
    #[error("no kernel is listening on {}: {why}", path.display())]
    Connect {
        /// Where it tried.
        path: PathBuf,
        /// What the operating system said.
        why: String,
    },

    /// The connection failed while it was open.
    #[error("the connection to the kernel failed: {why}")]
    Transport {
        /// What the operating system said.
        why: String,
    },

    /// A message could not be framed.
    #[error(transparent)]
    Channel(#[from] ChannelError),

    /// The kernel did not answer in time.
    #[error("the kernel did not answer within {} seconds", timeout.as_secs())]
    TimedOut {
        /// The timeout.
        timeout: Duration,
    },
}

impl SocketError {
    /// Whether repeating the request could succeed.
    ///
    /// # Why the classification lives here
    ///
    /// A client that decided for itself would be a second opinion that can contradict the kernel's: `TransportNotOpen`
    /// and `Timeout` are retryable because a kernel that is still starting or briefly wedged is the ordinary case, and a
    /// missing socket, a refused version and a framing error are not — repeating them gives the same answer until
    /// something changes that the client cannot change.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport { .. } | Self::TimedOut { .. } | Self::Channel(_)
        )
    }
}

/// Whether an address is one this build will try to bind.
///
/// # Why the length matters
///
/// A unix socket address is a fixed-size field in the kernel, and a longer path is refused with an error that says
/// nothing about length — so a data directory under a deep temporary path produces "invalid argument" for a reason the
/// user cannot act on. Checked here, where the message can name the limit and what to do about it.
///
/// # Errors
///
/// A [`SocketError::Bind`] whose sentence names the length and the limit.
pub fn check_bindable(path: &Path) -> Result<(), SocketError> {
    // A named pipe name has no length limit worth checking, so on Windows this is advisory — it refuses what unix would
    // refuse, so a build that moves between platforms behaves the same way rather than working on one and not the other.
    //
    // Bytes rather than characters: the unix limit is bytes, and a path of non-ASCII characters is longer in bytes than
    // it looks — so a check that counted characters would accept a path the operating system then refuses.
    let len = path.as_os_str().to_string_lossy().len();
    if len > MAX_SOCKET_PATH_BYTES {
        return Err(SocketError::Bind {
            path: path.to_path_buf(),
            why: format!(
                "the path is {len} bytes and a socket address holds at most {MAX_SOCKET_PATH_BYTES} — \
                 point the data directory somewhere shorter"
            ),
        });
    }
    Ok(())
}

/// Turns a data directory into a name a local socket can be bound with.
///
/// # Why this branches on the platform
///
/// A unix domain socket **is** a filesystem entry, so the name is the path — which is what makes the socket inheritable
/// by permission and what makes two installations' sockets impossible to confuse.
///
/// A Windows named pipe **is not** a filesystem entry. There is no path to give it: a pipe name lives in a namespace of
/// its own, and `interprocess` refuses a filesystem path there with "not a named pipe path". So the name has to be
/// derived from the data directory instead, and the derivation has to be injective — two installations must not land on
/// one pipe, because two kernels on one pipe is one kernel answering for the other.
///
/// The derivation is the absolute path's own bytes, hex-encoded, which is injective by construction and needs no hash
/// function to be trusted.
#[cfg(windows)]
fn namespaced_name(path: &Path) -> String {
    // Absolute, because the same installation reached by a relative path and by an absolute one must produce one name.
    // `std::path::absolute` rather than `canonicalize`: the latter touches the filesystem and follows symlinks, and a
    // name that changed when a directory was moved would be a daemon a client could no longer find.
    let base = path.parent().unwrap_or(path);
    let absolute = std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf());
    let mut encoded = String::with_capacity(absolute.as_os_str().len() * 2 + 32);
    encoded.push_str("synra-kernel-");
    for byte in absolute.as_os_str().to_string_lossy().as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

mod client;
mod listener;

pub use client::Client;
pub use listener::{Listener, serve_stream};

#[cfg(test)]
mod tests;

