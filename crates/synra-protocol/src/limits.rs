//! Every timing, size and capacity constant the protocol uses.
//!
//! # Why one module
//!
//! These values were previously — in an earlier system — spread across a dozen files, and the
//! result was that the same logical timeout had different values on different platforms. Two
//! devices then disagreed about when a link had died, and the disagreement only showed up as an
//! intermittent reconnect loop on one of them.
//!
//! So: **one definition, and it is a `const`.** A caller that needs a different value passes a
//! [`Tuning`]; the defaults live here and nowhere else.
//!
//! # Changing a value here
//!
//! A timing change is a protocol change. Two peers with different values still interoperate — the
//! timeouts are local decisions — but the *behaviour* differs, so a change here needs a note in
//! `design-docs/04-wire-protocol.md` and a `Feature` if it alters what is sent.

use core::time::Duration;

/// Default TCP port for device-to-device links.
pub const DEFAULT_TCP_PORT: u16 = 32100;

/// UDP port for LAN discovery.
pub const DISCOVERY_PORT: u16 = 32101;

/// mDNS service type for discovery fallback.
pub const MDNS_SERVICE: &str = "_synra._tcp.local";

// ─────────────────────────────────────────────────────────────────────────────
// Connection lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// How long to wait for the peer's `HelloAck` after sending `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(6);

/// How often to send a heartbeat on an idle link.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// How long a link may go without *any* inbound frame before it is declared dead.
///
/// Deliberately longer than [`HEARTBEAT_INTERVAL`] by enough to absorb two missed heartbeats: a
/// single lost ping should not tear down a working link.
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(25);

/// How long to wait for the peer's acknowledgement of a reliable message.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(6);

// ─────────────────────────────────────────────────────────────────────────────
// Frame and payload sizes
// ─────────────────────────────────────────────────────────────────────────────

/// Frame header length: `u32` big-endian total length, one kind byte, one flags byte.
pub const FRAME_HEADER_LEN: usize = 6;

/// Largest frame accepted, header included.
///
/// A frame above this closes the link rather than being skipped: see [`crate::frame`].
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Largest binary chunk in a transfer.
pub const MAX_CHUNK_LEN: usize = 256 * 1024;

/// Largest serialised envelope payload.
///
/// Above this the sender is told to use a transfer instead. Keeping the ceiling here rather than
/// relying on the frame limit matters because the payload is only one field of the envelope, and a
/// payload sized to exactly fill a frame leaves no room for the envelope around it.
pub const MAX_PAYLOAD_LEN: usize = 256 * 1024;

/// Deepest JSON nesting accepted in a payload.
pub const MAX_PAYLOAD_DEPTH: u32 = 32;

// ─────────────────────────────────────────────────────────────────────────────
// Buffers and backpressure
// ─────────────────────────────────────────────────────────────────────────────

/// Frames that may be queued for writing before a link is judged unhealthy.
///
/// Bounded on purpose. An unbounded queue turns a slow peer into gradual memory growth, and the
/// growth is far harder to diagnose than a closed link.
pub const WRITE_QUEUE_CAPACITY: usize = 256;

/// Upper bound on how long processing one frame may take before it is abandoned.
///
/// Without it a slow handler starves the read loop and the heartbeat, so a link can die from a
/// frame that was received correctly.
pub const MAX_FRAME_PROCESSING: Duration = Duration::from_millis(250);

// ─────────────────────────────────────────────────────────────────────────────
// Idempotence
// ─────────────────────────────────────────────────────────────────────────────

/// How long a `request_id` is remembered for duplicate detection.
///
/// A retry must reuse the same id, so this window has to comfortably exceed the retry schedule in
/// [`crate::limits::RECONNECT_BACKOFF`].
pub const REQUEST_DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// How long a cached reply is kept so a duplicate request can be answered without re-executing.
pub const REPLY_CACHE_TTL: Duration = Duration::from_secs(300);

// ─────────────────────────────────────────────────────────────────────────────
// Reconnection
// ─────────────────────────────────────────────────────────────────────────────

/// Backoff schedule for reconnecting to a paired peer.
///
/// Event-driven triggers (peer rediscovered, network change, foreground) fire earlier than these
/// when they can; the schedule is the floor, not the only mechanism.
pub const RECONNECT_BACKOFF: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(8),
    Duration::from_secs(20),
];

/// Backoff used after [`RECONNECT_BACKOFF`] is exhausted.
pub const RECONNECT_BASE: Duration = Duration::from_secs(30);

/// Ceiling for reconnection backoff.
pub const RECONNECT_MAX: Duration = Duration::from_secs(300);

/// Jitter applied to reconnection delays, as a percentage, so a fleet does not retry in lockstep.
pub const RECONNECT_JITTER_PERCENT: u8 = 20;

// ─────────────────────────────────────────────────────────────────────────────
// Discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Total budget for one discovery scan — how long the interface may show "searching".
pub const SCAN_TOTAL: Duration = Duration::from_millis(2500);

/// Window spent listening for broadcast and mDNS replies before probing.
pub const SCAN_PASSIVE: Duration = Duration::from_millis(1200);

/// Timeout for one TCP probe.
pub const SCAN_PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// How many probes may be in flight at once.
///
/// One value for every platform. A per-platform value is how two builds of the same program end up
/// finding different sets of devices.
pub const SCAN_PROBE_CONCURRENCY: usize = 32;

/// Interval between broadcast query retransmissions.
pub const DISCOVERY_QUERY_INTERVAL: Duration = Duration::from_millis(400);

/// How many times a discovery query is broadcast per scan.
///
/// More than one, because a single lost UDP datagram otherwise means a device is invisible for the
/// whole scan.
pub const DISCOVERY_QUERY_REPEATS: u8 = 3;

/// How many times an offline announcement is sent as the process exits.
pub const OFFLINE_ANNOUNCE_REPEATS: u8 = 3;

/// Interval between offline announcements.
pub const OFFLINE_ANNOUNCE_INTERVAL: Duration = Duration::from_millis(150);

// ─────────────────────────────────────────────────────────────────────────────
// Runtime tuning
// ─────────────────────────────────────────────────────────────────────────────

/// Timings a host may override, with the values above as defaults.
///
/// A struct rather than a pile of `set_*` functions so that a test can construct the exact tuning it
/// wants, and so that a host's configuration is visible in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuning {
    /// See [`HELLO_TIMEOUT`].
    pub hello_timeout: Duration,
    /// See [`HEARTBEAT_INTERVAL`].
    pub heartbeat_interval: Duration,
    /// See [`HEARTBEAT_TIMEOUT`].
    pub heartbeat_timeout: Duration,
    /// See [`ACK_TIMEOUT`].
    pub ack_timeout: Duration,
    /// See [`WRITE_QUEUE_CAPACITY`].
    pub write_queue_capacity: usize,
    /// See [`REQUEST_DEDUP_WINDOW`].
    pub request_dedup_window: Duration,
    /// See [`REPLY_CACHE_TTL`].
    pub reply_cache_ttl: Duration,
    /// See [`SCAN_TOTAL`].
    pub scan_total: Duration,
    /// See [`SCAN_PROBE_TIMEOUT`].
    pub scan_probe_timeout: Duration,
    /// See [`SCAN_PROBE_CONCURRENCY`].
    pub scan_probe_concurrency: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            hello_timeout: HELLO_TIMEOUT,
            heartbeat_interval: HEARTBEAT_INTERVAL,
            heartbeat_timeout: HEARTBEAT_TIMEOUT,
            ack_timeout: ACK_TIMEOUT,
            write_queue_capacity: WRITE_QUEUE_CAPACITY,
            request_dedup_window: REQUEST_DEDUP_WINDOW,
            reply_cache_ttl: REPLY_CACHE_TTL,
            scan_total: SCAN_TOTAL,
            scan_probe_timeout: SCAN_PROBE_TIMEOUT,
            scan_probe_concurrency: SCAN_PROBE_CONCURRENCY,
        }
    }
}

impl Tuning {
    /// Rejects a tuning whose values cannot work together.
    ///
    /// Checked rather than assumed because the failure mode is silent: a heartbeat timeout below
    /// the heartbeat interval makes every healthy link look dead, and the symptom — links that drop
    /// and immediately reconnect — looks like a network problem.
    ///
    /// # Errors
    ///
    /// Returns a description of the first inconsistency found.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.heartbeat_timeout <= self.heartbeat_interval {
            return Err("heartbeat_timeout must exceed heartbeat_interval, or every idle link looks dead");
        }
        if self.reply_cache_ttl > self.request_dedup_window {
            return Err("reply_cache_ttl must not exceed request_dedup_window, or a duplicate request is re-executed");
        }
        if self.write_queue_capacity == 0 {
            return Err("write_queue_capacity must be non-zero");
        }
        if self.scan_probe_concurrency == 0 {
            return Err("scan_probe_concurrency must be non-zero");
        }
        if self.scan_total < self.scan_probe_timeout {
            return Err("scan_total must be at least scan_probe_timeout, or no probe can ever finish");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tuning_is_self_consistent() {
        assert_eq!(Tuning::default().validate(), Ok(()));
    }

    #[test]
    fn heartbeat_timeout_above_interval_is_required() {
        let tuning = Tuning {
            heartbeat_timeout: HEARTBEAT_INTERVAL,
            ..Tuning::default()
        };
        assert!(tuning.validate().is_err());
    }

    #[test]
    fn reply_cache_cannot_outlive_the_dedup_window() {
        let tuning = Tuning {
            reply_cache_ttl: REQUEST_DEDUP_WINDOW + Duration::from_secs(1),
            ..Tuning::default()
        };
        assert!(tuning.validate().is_err());
    }

    #[test]
    fn zero_capacities_are_rejected() {
        for tuning in [
            Tuning { write_queue_capacity: 0, ..Tuning::default() },
            Tuning { scan_probe_concurrency: 0, ..Tuning::default() },
        ] {
            assert!(tuning.validate().is_err());
        }
    }

    #[test]
    fn scan_budget_must_admit_a_probe() {
        let tuning = Tuning {
            scan_total: SCAN_PROBE_TIMEOUT - Duration::from_millis(1),
            ..Tuning::default()
        };
        assert!(tuning.validate().is_err());
    }

    #[test]
    fn backoff_schedule_ascends() {
        let mut previous = Duration::ZERO;
        for step in RECONNECT_BACKOFF {
            assert!(*step > previous, "backoff must ascend: {step:?} after {previous:?}");
            previous = *step;
        }
    }

    #[test]
    fn reconnect_ceiling_exceeds_base() {
        assert!(RECONNECT_MAX > RECONNECT_BASE);
    }
}
