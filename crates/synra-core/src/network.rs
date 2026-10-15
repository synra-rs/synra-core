//! What a plugin's outbound request is allowed to reach.
//!
//! # Why this exists
//!
//! Because a request a plugin asks the kernel to make is a request the **user's network** makes, from inside whatever
//! firewall that user is behind — and the interesting targets on such a network are not the plugin's to reach. A cloud
//! instance's metadata service lives at `169.254.169.254`, a router's admin page at `192.168.0.1`, and a development
//! database at `127.0.0.1`. A plugin that can fetch any of them has a capability nobody granted it.
//!
//! The design puts the checks in a fixed order (`10 §4.4`), and this module is that order:
//!
//! 1. **the scheme**, closed rather than "anything but http" — `javascript:`, `data:` and `file:` are all things that can
//!    be written where a URL is expected;
//! 2. **the host**, normalised and then required to be one the capability granted;
//! 3. **the addresses it resolved to**, checked after resolution because that is the only moment the answer is known —
//!    and every one of them must pass, not the first;
//! 4. **each redirect**, because a redirect is a second request to a URL nobody authorised.
//!
//! # Why the resolution is a parameter and not a call
//!
//! Because this crate performs no DNS, and a guard that resolved names would be a guard that could not be tested without a
//! network. [`NetworkGuard::check_resolved`] takes what the resolver returned, so the rule that matters — *every* address
//! must pass — is testable with a list somebody wrote down.
//!
//! # What this is not
//!
//! It is not a firewall and it is not a substitute for one. It is the check that stops a plugin reaching the metadata
//! service, and it is honest about the limit the design names: a name that resolves to a public address during the check
//! and to a private one when the connection is made is a **DNS rebinding** attack, and the defence is to connect to the
//! address that was checked — see `10 §4.4` step 3 — rather than to look the name up a second time. That is the caller's
//! obligation, and [`Checked::host`] exists so it can be honoured: the connection goes to a checked address, the `Host`
//! header carries this.

use std::net::IpAddr;

use synra_protocol::error::ErrorCode;

/// How many redirects a single request may follow.
///
/// Five, as the design says. A limit rather than a ban, because a redirect is how a great deal of the web works — and a
/// limit rather than none, because each hop is a request to an address nobody authorised.
pub const MAX_REDIRECTS: u8 = 5;

/// The longest URL this guard will look at.
///
/// The same ceiling the platform guard uses, and for the same reason: a URL long enough to matter is one being used to
/// carry something other than an address.
pub const MAX_URL_LEN: usize = 2_048;

/// What a refused request is told.
///
/// A code from the contract and a sentence. The code is what a plugin branches on — `SchemeNotAllowed` is its own mistake
/// and `IpNotAllowed` is the network's shape — and the sentence is what a person reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Which refusal this is.
    pub code: ErrorCode,
    /// A sentence for a person.
    pub message: String,
}

impl Refusal {
    /// A refusal with its code and a sentence.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

/// A public address range, written `10.0.0.0/8` or `fd00::/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The network address.
    base: IpAddr,
    /// How many leading bits are the network.
    bits: u8,
}

impl Cidr {
    /// Parses `address/length`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] with [`ErrorCode::InvalidArgument`] when the address does not parse or the length is longer than the
    /// address has bits — a `/33` on IPv4 is a typo, and treating one as `/32` would silently widen a policy.
    pub fn parse(text: &str) -> Result<Self, Refusal> {
        let (address, bits) = text.split_once('/').ok_or_else(|| {
            Refusal::new(ErrorCode::InvalidArgument, format!("`{text}` is not a range: write it as address/length"))
        })?;
        let base: IpAddr = address.trim().parse().map_err(|_| {
            Refusal::new(ErrorCode::InvalidArgument, format!("`{address}` is not an IP address"))
        })?;
        let bits: u8 = bits.trim().parse().map_err(|_| {
            Refusal::new(ErrorCode::InvalidArgument, format!("`{bits}` is not a prefix length"))
        })?;
        let width = if base.is_ipv4() { 32 } else { 128 };
        if bits > width {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("`/{bits}` is longer than an address has bits ({width})"),
            ));
        }
        Ok(Self { base, bits })
    }

    /// Whether an address falls inside this range.
    ///
    /// # Why the families are compared first
    ///
    /// Because an IPv4-mapped IPv6 address compares equal to nothing useful and *contains* everything dangerous: a
    /// `::ffff:127.0.0.1` is loopback wearing a different family, and a matcher that truncated it to the low 32 bits would
    /// find `127.0.0.1` — which is exactly right — while one that compared families first would call it "not IPv4" and let
    /// it through. So the mapped form is unwrapped rather than refused, and the caller decides.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = unwrap_mapped(address);
        match (self.base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                let mask = mask32(self.bits);
                u32::from(base) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                let mask = mask128(self.bits);
                u128::from(base) & mask == u128::from(address) & mask
            }
            // A range of one family says nothing about an address of the other, so it does not contain it.
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.base, self.bits)
    }
}

/// Unwraps an IPv4-mapped IPv6 address, leaving everything else alone.
#[must_use]
fn unwrap_mapped(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// The mask for a prefix length.
#[must_use]
const fn mask32(bits: u8) -> u32 {
    if bits == 0 { 0 } else { u32::MAX << (32 - bits) }
}

/// The mask for a prefix length.
#[must_use]
const fn mask128(bits: u8) -> u128 {
    if bits == 0 { 0 } else { u128::MAX << (128 - bits) }
}

/// Which addresses a request may reach.
///
/// # Why the defaults are all `false`
///
/// Because the safe answer has to be the one nobody wrote. A policy that allowed loopback by default would make every
/// host that forgot to configure one a host where a plugin can talk to whatever is listening on the machine — and
/// forgetting is the normal case.
#[derive(Debug, Clone, Default)]
pub struct IpPolicy {
    /// Whether private ranges are reachable.
    pub allow_private: bool,
    /// Whether loopback is reachable.
    pub allow_loopback: bool,
    /// Whether link-local is reachable — `169.254.0.0/16`, which is the cloud metadata service.
    pub allow_link_local: bool,
    /// Whether IPv6 unique-local addresses are reachable.
    pub allow_ula: bool,
    /// Ranges that are reachable even when the rules above say no.
    pub allow_cidrs: Vec<Cidr>,
    /// Ranges that are never reachable, whatever the rules above say.
    pub deny_cidrs: Vec<Cidr>,
}

impl IpPolicy {
    /// Whether one address may be reached.
    ///
    /// # The order, which is the whole of the policy
    ///
    /// A denial beats a permission, and a permission beats a default. A list that could be overridden by the rules above
    /// it would be a list nobody could rely on — "I denied the metadata service" has to mean it, even for a host that also
    /// allowed all link-local addresses.
    #[must_use]
    pub fn permits(&self, address: IpAddr) -> bool {
        let address = unwrap_mapped(address);

        if self.deny_cidrs.iter().any(|range| range.contains(address)) {
            return false;
        }
        if self.allow_cidrs.iter().any(|range| range.contains(address)) {
            return true;
        }

        if address.is_loopback() {
            return self.allow_loopback;
        }
        if is_link_local(address) {
            return self.allow_link_local;
        }
        if is_unique_local(address) {
            return self.allow_ula;
        }
        // ★ The last case is "everything else is public", and the family matters here: an IPv6 address that is none of the
        // above is a global unicast address, while an IPv4 one may still be a private range.
        if address.is_ipv4() {
            return !is_private_v4(address) || self.allow_private;
        }
        true
    }
}

/// Whether an address is in a private IPv4 range.
#[must_use]
const fn is_private_v4(address: IpAddr) -> bool {
    let IpAddr::V4(v4) = address else {
        return false;
    };
    v4.is_private()
}

/// Whether an address is link-local, in either family.
#[must_use]
const fn is_link_local(address: IpAddr) -> bool {
    match address {
        // 169.254.0.0/16. Not `is_link_local` on `Ipv4Addr` alone because the whole reason this branch exists is that the
        // range is the cloud metadata service, and it deserves to be visible in the code that refuses it.
        IpAddr::V4(v4) => v4.octets()[0] == 169 && v4.octets()[1] == 254,
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Whether an address is an IPv6 unique-local address (`fc00::/7`).
#[must_use]
const fn is_unique_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 == 0xfc00,
        IpAddr::V4(_) => false,
    }
}

/// A URL that passed the checks before resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The scheme, lowercased.
    pub scheme: String,
    /// The host, normalised: lowercased, with a trailing dot removed.
    pub host: String,
    /// The port, when the URL named one.
    pub port: Option<u16>,
}

impl Checked {
    /// The port to connect to, defaulting by scheme.
    #[must_use]
    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(if self.scheme == "https" { 443 } else { 80 })
    }
}

/// The rules one plugin's outbound requests are held to.
#[derive(Debug, Clone)]
pub struct NetworkGuard {
    /// The hosts this capability granted, normalised. Empty means none.
    granted_hosts: Vec<String>,
    /// Whether plain `http` is allowed. Never by default.
    allow_insecure: bool,
    /// Which addresses may be reached.
    policy: IpPolicy,
    /// How many redirects may be followed.
    max_redirects: u8,
}

impl NetworkGuard {
    /// A guard for the hosts one capability named, and nothing else.
    ///
    /// # Why there is no `allow_all`
    ///
    /// Because a capability that named no host is a capability nobody granted. `network:fetch:*` is not a spelling the
    /// contract offers, so a guard that could be built to reach everything would be one no caller of this function could
    /// justify.
    #[must_use]
    pub fn for_hosts(hosts: &[String]) -> Self {
        Self {
            granted_hosts: hosts.iter().map(|host| normalise_host(host)).collect(),
            allow_insecure: false,
            policy: IpPolicy::default(),
            max_redirects: MAX_REDIRECTS,
        }
    }

    /// The same guard, with a different address policy.
    #[must_use]
    pub fn with_policy(mut self, policy: IpPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The same guard, allowing plain `http`.
    ///
    /// A builder rather than a default, because the insecure scheme is a decision a host makes and the design's default is
    /// `https` only.
    #[must_use]
    pub const fn allowing_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    /// The same guard, with a different redirect limit.
    #[must_use]
    pub const fn with_max_redirects(mut self, hops: u8) -> Self {
        self.max_redirects = hops;
        self
    }

    /// Steps 1 and 2: the scheme, and the host.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::SchemeNotAllowed`] for a scheme this guard does not accept, and [`ErrorCode::HostNotAllowed`] for a
    /// host the capability did not name.
    pub fn check_url(&self, url: &str) -> Result<Checked, Refusal> {
        let checked = self.parse(url)?;

        if !self.granted_hosts.contains(&checked.host) {
            return Err(Refusal::new(
                ErrorCode::HostNotAllowed,
                format!("`{}` is not one of the hosts this plugin was granted", checked.host),
            ));
        }
        Ok(checked)
    }

    /// Parses a URL and checks its scheme, without checking the host.
    ///
    /// # Why this is separate
    ///
    /// Because a redirect has to be checked in two steps for its message to be useful: a hop to a refused *scheme* and a
    /// hop to a host that was not *granted* are different problems, and the second one is the one a user has to decide
    /// about. Both are refused either way.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidArgument`] when the URL cannot be read at all, and [`ErrorCode::SchemeNotAllowed`] for a scheme
    /// this guard does not accept.
    pub fn parse(&self, url: &str) -> Result<Checked, Refusal> {
        if url.len() > MAX_URL_LEN {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("the URL is longer than {MAX_URL_LEN} bytes"),
            ));
        }
        if url.is_empty() {
            return Err(Refusal::new(ErrorCode::InvalidArgument, "there is no URL"));
        }
        // A control character could forge a consent prompt's text or split a log line, so it is refused before anything
        // else reads the string — the same rule the platform guard applies to a URL it is asked to open.
        if url.chars().any(char::is_control) {
            return Err(Refusal::new(ErrorCode::InvalidArgument, "the URL contains a control character"));
        }

        let (scheme, rest) = url.split_once(':').ok_or_else(|| {
            Refusal::new(ErrorCode::InvalidArgument, format!("`{url}` has no scheme"))
        })?;
        let scheme = scheme.to_ascii_lowercase();
        match scheme.as_str() {
            "https" => {}
            "http" if self.allow_insecure => {}
            // ★ A closed list, not "anything but http". `javascript:`, `data:`, `file:` and `ftp:` all mean something to
            // some program, and a plugin that can write one where an address is expected is a plugin that can make the host
            // do something other than fetch.
            "http" => {
                return Err(Refusal::new(
                    ErrorCode::SchemeNotAllowed,
                    "plain http is not allowed; this capability grants https",
                ));
            }
            other => {
                return Err(Refusal::new(
                    ErrorCode::SchemeNotAllowed,
                    format!("`{other}:` is not a scheme a plugin may fetch"),
                ));
            }
        }

        let authority = rest.strip_prefix("//").unwrap_or(rest);
        // Everything up to the path, the query or the fragment.
        let authority = authority
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();

        // ★ Userinfo is stripped by taking what is **after the last `@`**. `https://allowed.example@evil.example/` is a
        // request to `evil.example` carrying `allowed.example` as a username, and a reader that took the text before the
        // `@` would authorise the wrong machine. The last one wins because a host cannot contain an `@`, so any earlier one
        // is part of the userinfo.
        let host_port = authority.rsplit('@').next().unwrap_or_default();

        // A bracketed IPv6 literal, then the port.
        let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
            let (inside, after) = rest.split_once(']').ok_or_else(|| {
                Refusal::new(ErrorCode::InvalidArgument, "the IPv6 literal is not closed")
            })?;
            (inside.to_owned(), after.strip_prefix(':'))
        } else {
            match host_port.split_once(':') {
                Some((host, port)) => (host.to_owned(), Some(port)),
                None => (host_port.to_owned(), None),
            }
        };

        let host = normalise_host(&host);
        if host.is_empty() {
            return Err(Refusal::new(ErrorCode::InvalidArgument, "the URL names no host"));
        }

        let port = match port {
            None | Some("") => None,
            Some(text) => Some(text.parse::<u16>().map_err(|_| {
                Refusal::new(ErrorCode::InvalidArgument, format!("`{text}` is not a port"))
            })?),
        };

        Ok(Checked { scheme, host, port })
    }

    /// Step 3: the addresses the name resolved to.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::IpNotAllowed`] when **any** of them is an address this policy refuses. The refusal names the address,
    /// because "this host resolves somewhere it may not go" is not something a plugin author can act on and
    /// "it resolves to 169.254.169.254" is.
    pub fn check_resolved(&self, checked: &Checked, resolved: &[IpAddr]) -> Result<(), Refusal> {
        if resolved.is_empty() {
            return Err(Refusal::new(
                ErrorCode::IpNotAllowed,
                format!("`{}` resolved to nothing, so there is nowhere to send this", checked.host),
            ));
        }
        // ★ Every address, not the first. A name that resolves to one public address and one private one is a name that
        // can reach the private one — the caller does not choose which address the connection lands on, the resolver's
        // order does, and a check that stopped at the first would be a check an attacker arranges the order around.
        for address in resolved {
            if !self.policy.permits(*address) {
                return Err(Refusal::new(
                    ErrorCode::IpNotAllowed,
                    format!("`{}` resolves to {address}, which this plugin may not reach", checked.host),
                ));
            }
        }
        Ok(())
    }

    /// Step 4: one redirect hop.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::RedirectBlocked`] when the limit is reached, and otherwise whatever [`NetworkGuard::check_url`]
    /// refuses — because a redirect is a second request that must pass everything the first one did. "The first hop was
    /// allowed" is not a property a later hop inherits.
    pub fn next_hop(&self, followed: u8, location: &str) -> Result<Checked, Refusal> {
        if followed >= self.max_redirects {
            return Err(Refusal::new(
                ErrorCode::RedirectBlocked,
                format!("more than {} redirects", self.max_redirects),
            ));
        }
        self.check_url(location)
    }

    /// The hosts this guard was built for.
    #[must_use]
    pub fn granted_hosts(&self) -> &[String] {
        &self.granted_hosts
    }

    /// The address policy in force.
    #[must_use]
    pub const fn policy(&self) -> &IpPolicy {
        &self.policy
    }
}

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

#[cfg(test)]
mod tests;
