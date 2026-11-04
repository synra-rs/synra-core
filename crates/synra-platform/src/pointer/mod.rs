//! Relative pointer operations. Authorization and leases belong to the input session, not this OS adapter.

use serde::{Deserialize, Serialize};

/// Receiver-side authority, independent of the controller's device:input grant.
pub const CAPABILITY: &str = "platform:control-pointer";

#[cfg(windows)]
mod windows;

/// One ordered pointer intention; a receiver validates a whole packet before applying any operation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Command {
    /// Relative cursor displacement in CSS pixels.
    Move {
        /// Horizontal relative displacement.
        dx: f64,
        /// Vertical relative displacement.
        dy: f64,
    },
    /// Relative two-finger displacement in CSS pixels; the adapter applies natural scrolling.
    Scroll {
        /// Horizontal finger displacement.
        dx: f64,
        /// Vertical finger displacement.
        dy: f64,
    },
    /// One left click.
    LeftClick,
    /// One right click.
    RightClick,
    /// Hold the left button.
    LeftDown,
    /// Release the left button.
    LeftUp,
}

impl Command {
    /// Reject non-finite and excessive deltas before touching the OS.
    #[must_use]
    pub fn valid(self) -> bool {
        match self {
            Self::Move { dx, dy } | Self::Scroll { dx, dy } => {
                dx.is_finite() && dy.is_finite() && dx.abs() <= 4096.0 && dy.abs() <= 4096.0
            }
            _ => true,
        }
    }
}

/// A pointer owned by one receiving session, on its connection thread.
pub trait Pointer: Send {
    /// Apply an intention, or end the session on failure.
    /// # Errors
    /// Returns the native failure; callers must release and stop, never retry a click.
    fn apply(&mut self, command: Command) -> Result<(), String>;
    /// Release buttons this session owns. Must also run on disconnect and lease expiry.
    /// # Errors
    /// Reports an OS refusal to release a button.
    fn release(&mut self) -> Result<(), String>;
}

/// Creates a fresh OS adapter only after the person accepted the current session.
pub type Factory = dyn Fn() -> Result<Box<dyn Pointer>, String> + Send + Sync;

/// Whether this build has a native receiving adapter.
#[must_use]
pub const fn supported() -> bool {
    cfg!(windows)
}

/// Open the native pointer adapter without moving or clicking anything.
/// # Errors
/// Unsupported platforms and native initialization failures are explicit refusals.
pub fn native() -> Result<Box<dyn Pointer>, String> {
    #[cfg(windows)]
    {
        windows::NativePointer::open().map(|pointer| Box::new(pointer) as Box<dyn Pointer>)
    }
    #[cfg(not(windows))]
    {
        Err("pointer input is not supported on this platform".to_owned())
    }
}
