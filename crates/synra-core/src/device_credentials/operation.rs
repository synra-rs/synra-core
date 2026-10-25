//! The OS releases this sidecar lock on process death; the persistent empty file is never removed.

use std::fs::{File, OpenOptions};

use parking_lot::Mutex;
use synra_store::SynraDb;

use super::CredentialError;

pub(super) fn acquire(db: &Mutex<SynraDb>) -> Result<File, CredentialError> {
    let path = db
        .lock()
        .device_credential_lock_path()
        .map_err(|error| CredentialError::Database(error.to_string()))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| io_error(&error))?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            CredentialError::OperationBusy
        } else {
            io_error(&error)
        }
    })?;
    Ok(file)
}

fn io_error(error: &std::io::Error) -> CredentialError {
    CredentialError::Database(format!("credential operation lock failed: {error}"))
}
