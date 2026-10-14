/// A `u64` clock reading as the `i64` the database and the discovery table use.
///
/// # Why a conversion rather than one type everywhere
///
/// The session registry's deadlines are `u64` because they are durations from a monotonic-ish start, and the discovery
/// table's times are `i64` because they go into SQLite, whose integers are signed. Saturation rather than a cast,
/// because a `u64` beyond `i64::MAX` is a reading from a clock nobody has — and a cast would produce a *negative* time,
/// which the discovery table would read as "seen in the future".
///
/// # Why this is public
///
/// Because every caller that holds one kind of reading and needs the other has to convert, and a caller that reached for
/// `as i64` would be one that wraps at the year 292 million. The daemon converts on every request.
pub const fn millis_reading(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    }
    else {
        value as i64
    }
}

/// The same reading, the other way: the `u64` a caller that counts in unsigned milliseconds needs.
///
/// # Why this belongs beside its pair rather than in each caller
///
/// Because the two directions are one subject. [`millis_reading`] exists because the discovery table and the database use
/// signed milliseconds while the session registry uses unsigned ones — so a caller holding the *signed* kind needs this
/// direction too, and without it here every such caller writes its own. That is exactly what happened: the daemon grew two
/// byte-identical copies of this function, in modules that could not see each other, each with its own near-identical
/// comment.
///
/// Two copies of a saturation rule are two places to get it wrong, and the failure is silent. A negative reading that wraps
/// instead of clamping becomes a deadline in the far future, which is a session that never expires.
///
/// Saturating at zero rather than casting, for the same reason: a clock before the epoch is not a reading anyone measured,
/// and a wrap would turn it into one.
pub const fn reading_millis(value: i64) -> u64 {
    if value < 0 {
        0
    }
    else {
        value as u64
    }
}
