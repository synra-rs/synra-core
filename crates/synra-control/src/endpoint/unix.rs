//! Binding and stale socket recovery on Unix.

use std::fs;
use std::io::{self, ErrorKind};
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt as _;
use std::path::Path;

use interprocess::local_socket::{GenericFilePath, Listener, ListenerOptions, ToFsName as _};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use rustix::io::{Errno, FdFlags, fcntl_setfd, ioctl_fionbio};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, connect, socket};

pub(super) fn bind(path: &Path) -> io::Result<(Listener, OwnedFd)> {
    let name = path.to_fs_name::<GenericFilePath>()?;
    let create = || ListenerOptions::new().name(name.borrow()).create_sync();

    // Keep the lock file on disk so each contender locks the same inode, including after a crash.
    let lock = open(
        path.with_extension("sock.lock"),
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == Errno::WOULDBLOCK {
            io::Error::new(
                ErrorKind::AddrInUse,
                "another listener holds the socket lock",
            )
        } else {
            error.into()
        }
    })?;

    let listener = match create() {
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            reclaim_stale(path, error)?;
            create()?
        }
        result => result?,
    };
    Ok((listener, lock))
}

fn reclaim_stale(path: &Path, in_use: io::Error) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {}
        Ok(_) => return Err(in_use),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }

    // A datagram probe gets a type mismatch from a live stream listener even if its accept queue is full.
    // A stream probe on some Unix systems returns ECONNREFUSED for a full queue, just as it does for a stale entry.
    let address = SocketAddrUnix::new(path)?;
    let probe = socket(AddressFamily::UNIX, SocketType::DGRAM, None)?;
    fcntl_setfd(&probe, FdFlags::CLOEXEC)?;
    ioctl_fionbio(&probe, true)?;
    match connect(&probe, &address) {
        Err(Errno::CONNREFUSED) => match fs::remove_file(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            result => result,
        },
        Err(Errno::NOENT) => Ok(()),
        _ => Err(in_use),
    }
}
