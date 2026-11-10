//! Client-side request and response exchange over the local control socket.

use std::io::{Read, Write};
use std::path::Path;
use interprocess::local_socket::traits::Stream as _;
use interprocess::local_socket::Stream;
#[cfg(unix)]
use interprocess::local_socket::{GenericFilePath, ToFsName};
#[cfg(windows)]
use interprocess::local_socket::{GenericNamespaced, ToNsName};

use crate::{Decoder, Request, Response, encode};
use super::{REPLY_TIMEOUT, SocketError, namespaced_name, socket_path};

/// A client talking to a kernel.
#[derive(Debug)]
pub struct Client {
    stream: Stream,
    decoder: Decoder,
    buffer: Vec<u8>,
}

impl Client {
    /// Connects to a kernel's control socket.
    ///
    /// # Errors
    ///
    /// [`SocketError::Connect`], which is what a user sees when no kernel is running — so its sentence names the path
    /// and what to start.
    pub fn connect(data_dir: &Path) -> Result<Self, SocketError> {
        let path = socket_path(data_dir);
        #[cfg(unix)]
        let name = path
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .map_err(|error| SocketError::Connect {
                path: path.clone(),
                why: error.to_string(),
            })?;
        #[cfg(windows)]
        let owned = namespaced_name(&path);
        #[cfg(windows)]
        let name = owned
            .as_str()
            .to_ns_name::<GenericNamespaced>()
            .map_err(|error| SocketError::Connect {
                path: path.clone(),
                why: error.to_string(),
            })?;
        let stream = Stream::connect(name).map_err(|error| SocketError::Connect {
            path: path.clone(),
            why: error.to_string(),
        })?;
        // A read timeout rather than a write one: the failure this guards against is a kernel that accepted the
        // connection and then stopped answering, which is a wedge rather than a slow link.
        //
        // ★ Windows named pipes do not support I/O timeouts, so this fails there with "named pipes do not support I/O
        // timeouts". That is a platform limitation and not a reason to refuse the connection: a client that could not
        // connect to a healthy kernel because it could not *also* set a deadline on it would be one that never worked on
        // Windows. The consequence is stated rather than hidden — on Windows a wedged kernel leaves the command waiting
        // until the user interrupts it, which is the behaviour a command-line tool has by default.
        //
        // `WouldBlock`-family errors are treated as the timeout below, so the unix path reports the same error a user
        // would see if the platform could express one.
        let _ = stream.set_recv_timeout(Some(REPLY_TIMEOUT));

        Ok(Self {
            stream,
            decoder: Decoder::new(),
            buffer: vec![0u8; 8 * 1024],
        })
    }

    /// Sends one request and waits for its answer.
    ///
    /// # Errors
    ///
    /// [`SocketError::TimedOut`] when the kernel does not answer, and [`SocketError::Transport`] when the stream fails.
    pub fn ask(&mut self, request: &Request) -> Result<Response, SocketError> {
        let bytes = encode(request)?;
        self.stream
            .write_all(&bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|error| SocketError::Transport {
                why: error.to_string(),
            })?;
        self.read_one()
    }

    /// Reads until one message has arrived.
    fn read_one(&mut self) -> Result<Response, SocketError> {
        loop {
            // Checked before reading, because a previous read may have delivered two messages — and waiting for a third
            // would hang a client whose answer is already in the buffer.
            if let Some(response) = self.decoder.next_message::<Response>()? {
                return Ok(response);
            }

            let read = match self.stream.read(&mut self.buffer) {
                Ok(0) => {
                    return Err(SocketError::Transport {
                        why: "the kernel closed the connection without answering".to_owned(),
                    });
                }
                Ok(read) => read,
                // The receive timeout reached zero. Distinguished from a transport failure because the two have
                // different causes and different advice: one is a wedged kernel, the other a broken socket.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(SocketError::TimedOut {
                        timeout: REPLY_TIMEOUT,
                    });
                }
                Err(error) => {
                    return Err(SocketError::Transport {
                        why: error.to_string(),
                    });
                }
            };

            let Some(chunk) = self.buffer.get(..read) else {
                return Err(SocketError::Transport {
                    why: "a read reported more bytes than the buffer".to_owned(),
                });
            };
            self.decoder.push(chunk);
        }
    }

    /// Performs the handshake, refusing a kernel this client cannot talk to.
    ///
    /// # Errors
    ///
    /// [`SocketError::Transport`] when the kernel refused the version, carrying the kernel's own sentence. The client
    /// does not continue: it has been told the two cannot talk.
    pub fn handshake(&mut self) -> Result<Response, SocketError> {
        let response = self.ask(&Request::Hello {
            version: crate::PROTOCOL_VERSION,
        })?;
        if let Response::Failed { message, .. } = &response {
            return Err(SocketError::Transport {
                why: message.clone(),
            });
        }
        Ok(response)
    }
}


