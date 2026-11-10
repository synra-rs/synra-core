use super::*;

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
        Self {
            code,
            message: message.into(),
        }
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
            Refusal::new(
                ErrorCode::InvalidArgument,
                format!("`{text}` is not a range: write it as address/length"),
            )
        })?;
        let base: IpAddr = address.trim().parse().map_err(|_| {
            Refusal::new(
                ErrorCode::InvalidArgument,
                format!("`{address}` is not an IP address"),
            )
        })?;
        let bits: u8 = bits.trim().parse().map_err(|_| {
            Refusal::new(
                ErrorCode::InvalidArgument,
                format!("`{bits}` is not a prefix length"),
            )
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
pub(super) fn unwrap_mapped(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// The mask for a prefix length.
#[must_use]
const fn mask32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

/// The mask for a prefix length.
#[must_use]
const fn mask128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    }
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
