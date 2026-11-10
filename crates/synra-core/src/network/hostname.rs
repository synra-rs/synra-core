/// A host as it is compared: lowercased, with one trailing dot removed.
///
/// # Why the trailing dot matters
///
/// Because `example.com.` and `example.com` are the same name — the dot is the root label, and a resolver treats them
/// identically. A comparison that did not strip it would refuse a granted host written the long way, and worse, a
/// capability granted for `example.com.` would not cover `example.com`. Normalising both sides is what makes the grant mean
/// what it says.
///
/// # Why the case matters
///
/// Because DNS names are case-insensitive, so `EXAMPLE.com` reaches the same machine as `example.com`. Comparing the raw
/// strings would be a bypass with one keystroke in it.
#[must_use]
pub fn normalise_host(host: &str) -> String {
    let lowered = host.trim().to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_owned()
}
