//! Length-prefixed command channel types and codec.

/// The most bytes one message may be, header included.
///
/// # Why there is a ceiling at all
///
/// A length prefix is a promise the reader has to be willing to accept. Without a ceiling, one malformed frame can ask
/// the kernel to allocate as much memory as the field can express — four gigabytes — and a hostile client on the same
/// machine can do it in a loop. One megabyte is the same figure the device protocol uses for a whole frame, and it is
/// far more than a command or a device list needs.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// The bytes before the body: a `u32` length in big-endian order.
pub const HEADER_LEN: usize = 4;

/// The protocol version this build speaks.
///
/// Carried in every request, because a client and a kernel are separate binaries that may be upgraded separately: a
/// user who upgrades the kernel and not the CLI, or the reverse. A version mismatch is then one clear sentence rather
/// than a decode error several layers down.
pub const PROTOCOL_VERSION: u16 = 1;

mod codec;
mod errors;
mod request;
mod response;

pub use codec::{Decoder, check_version, encode};
pub use errors::ChannelError;
pub use request::Request;
pub use response::Response;

#[cfg(test)]
mod tests;
