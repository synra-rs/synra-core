use super::*;

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
