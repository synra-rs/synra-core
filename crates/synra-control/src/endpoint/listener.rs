//! Listening and serving one local control connection.

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use interprocess::local_socket::Stream;
use interprocess::local_socket::traits::Listener as _;
#[cfg(windows)]
use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};

#[cfg(windows)]
use super::namespaced_name;
use super::{SocketError, check_bindable, socket_path};
use crate::{Server, SessionState};

/// A kernel listening for clients.
#[derive(Debug)]
pub struct Listener {
    listener: interprocess::local_socket::Listener,
    path: PathBuf,
    // Release the lock after the listener has removed its socket entry on drop.
    #[cfg(unix)]
    _bind_lock: OwnedFd,
}

impl Listener {
    /// Binds the control socket for a data directory.
    ///
    /// # Why a socket that is already there is reclaimed
    ///
    /// A unix socket is a filesystem entry that outlives the process that made it: a kernel that was killed leaves one
    /// behind, and binding where it is fails with "address in use" for a kernel that is **not** running. So the name is
    /// reclaimed.
    ///
    /// The reclamation does not disturb a live kernel: a bound socket keeps its inode, and the entry that is removed is
    /// the one a *dead* kernel left. What it does take away is the state that would otherwise stop the user from
    /// starting a kernel at all.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] for a path that is too long or cannot be bound.
    pub fn bind(data_dir: &Path) -> Result<Self, SocketError> {
        let path = socket_path(data_dir);
        check_bindable(&path)?;

        let bind_error = |error: std::io::Error| SocketError::Bind {
            path: path.clone(),
            why: error.to_string(),
        };
        #[cfg(unix)]
        let (listener, bind_lock) = super::unix::bind(&path).map_err(bind_error)?;
        #[cfg(windows)]
        let listener = {
            let owned = namespaced_name(&path);
            let name = owned
                .as_str()
                .to_ns_name::<GenericNamespaced>()
                .map_err(bind_error)?;
            ListenerOptions::new()
                .name(name)
                .create_sync()
                .map_err(bind_error)?
        };

        Ok(Self {
            listener,
            path,
            #[cfg(unix)]
            _bind_lock: bind_lock,
        })
    }

    /// Where it is listening.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts one client, without serving it.
    ///
    /// # Why this is public
    ///
    /// Because serving a client and accepting one are two decisions, and a host that serves them concurrently has to make
    /// the first one outside the thread it spawns. `serve_one` remains the one-call shape for a host that serves one at a
    /// time, and is now written in terms of this.
    ///
    /// # Errors
    ///
    /// [`SocketError::Transport`] when the accept fails.
    pub fn accept(&self) -> Result<Stream, SocketError> {
        self.listener
            .accept()
            .map_err(|error| SocketError::Transport {
                why: error.to_string(),
            })
    }

    /// Accepts one client and serves it until it disconnects.
    ///
    /// # Errors
    ///
    /// [`SocketError`] when the stream fails. A client that disconnects mid-answer is **not** an error: it is the
    /// ordinary shape of a command the user interrupted.
    pub fn serve_one(&self, kernel: &impl crate::Kernel) -> Result<(), SocketError> {
        serve_stream(self.accept()?, kernel)
    }
}

/// Serves one connection to its end.
///
/// # Errors
///
/// [`SocketError`] when the stream fails.
pub fn serve_stream(mut stream: Stream, kernel: &impl crate::Kernel) -> Result<(), SocketError> {
    let mut server = Server::new();
    let mut buffer = vec![0u8; 8 * 1024];
    let mut out = Vec::new();

    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            // A client that went away mid-request is ordinary: the user pressed Ctrl-C.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Ok(());
            }
            Err(error) => {
                return Err(SocketError::Transport {
                    why: error.to_string(),
                });
            }
        };

        // `get` rather than a slice: the read count is what the operating system returned, and a slice would be an index
        // the compiler cannot prove is in range — which the workspace forbids for exactly that reason.
        let Some(chunk) = buffer.get(..read) else {
            return Err(SocketError::Transport {
                why: "a read reported more bytes than the buffer".to_owned(),
            });
        };

        out.clear();
        let state = server.feed(chunk, kernel, &mut out)?;
        if !out.is_empty() {
            stream
                .write_all(&out)
                .and_then(|()| stream.flush())
                .map_err(|error| SocketError::Transport {
                    why: error.to_string(),
                })?;
        }
        if state == SessionState::Close {
            return Ok(());
        }
    }
}


