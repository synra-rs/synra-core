use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_net::authentication::{AuthenticatedStream, AuthenticationError};
use synra_protocol::DeviceId;
use synra_store::SynraDb;

use super::RequestAuthority;
use crate::link::{LinkError, LinkStream};
use crate::peer_trust::PeerApproval;

pub(super) struct AuthorizedStream {
    tls: AuthenticatedStream,
    authority: RequestAuthority,
    handshaking: bool,
}

impl AuthorizedStream {
    pub(super) fn new(
        tls: AuthenticatedStream,
        approval: PeerApproval,
        db: Arc<Mutex<SynraDb>>,
    ) -> Result<Self, LinkError> {
        let authority = RequestAuthority::new(&tls, approval, db)?;
        Ok(Self {
            tls,
            authority,
            handshaking: true,
        })
    }

    pub(super) fn start_budget(&mut self, timeout: Duration) -> Result<(), AuthenticationError> {
        self.tls.start_io_budget(timeout)
    }

    pub(super) fn finish_budget(&mut self) -> Result<(), AuthenticationError> {
        self.tls.finish_io_budget()?;
        self.handshaking = false;
        Ok(())
    }

    fn check(&self) -> Result<(), LinkError> {
        self.authorize(
            self.tls.local_identity().device_id(),
            self.tls.peer_device_id(),
        )
    }

    fn check_authorization(&self, local: DeviceId, peer: DeviceId) -> Result<(), LinkError> {
        self.authority.check(local, peer)
    }
}

impl std::fmt::Debug for AuthorizedStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthorizedStream")
    }
}

impl LinkStream for AuthorizedStream {
    fn authorize(&self, local: DeviceId, peer: DeviceId) -> Result<(), LinkError> {
        if self.authority.is_denied() {
            return Err(LinkError::Unauthorized);
        }
        if !self.handshaking {
            self.tls
                .check_io_budget()
                .map_err(|error| budget_error(&error))?;
        }
        self.check_authorization(local, peer)?;
        if !self.handshaking {
            self.tls
                .check_io_budget()
                .map_err(|error| budget_error(&error))?;
        }
        Ok(())
    }

    fn request_authority(&self) -> Option<RequestAuthority> {
        (!self.handshaking).then(|| self.authority.clone())
    }

    fn set_read_deadline(&self, timeout: Duration) -> Result<(), LinkError> {
        if !self.handshaking {
            self.tls
                .start_io_budget(timeout)
                .map_err(|error| budget_error(&error))?;
        }
        self.tls
            .set_read_timeout(Some(timeout))
            .map_err(|error| LinkError::Transport {
                why: error.to_string(),
            })
    }

    fn set_write_deadline(&self, timeout: Duration) -> Result<(), LinkError> {
        if !self.handshaking {
            self.tls
                .start_io_budget(timeout)
                .map_err(|error| budget_error(&error))?;
        }
        self.tls
            .set_write_timeout(Some(timeout))
            .map_err(|error| LinkError::Transport {
                why: error.to_string(),
            })
    }
}

impl Read for AuthorizedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check().map_err(io_error)?;
        let result = self.tls.read(buffer)?;
        // Revocation while blocked on IO must be checked before returning bytes to the decoder.
        // A time budget that expires after consuming plaintext must not discard those bytes: the
        // frame gate reports the timeout after buffering them, allowing a later bounded retry.
        self.check_authorization(
            self.tls.local_identity().device_id(),
            self.tls.peer_device_id(),
        )
        .map_err(io_error)?;
        Ok(result)
    }
}

impl Write for AuthorizedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check().map_err(io_error)?;
        self.tls.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check().map_err(io_error)?;
        self.tls.flush()
    }
}

fn io_error(error: LinkError) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error)
}

fn budget_error(error: &AuthenticationError) -> LinkError {
    match error {
        AuthenticationError::TimedOut => LinkError::TimedOut,
        _ => LinkError::Transport {
            why: error.to_string(),
        },
    }
}
