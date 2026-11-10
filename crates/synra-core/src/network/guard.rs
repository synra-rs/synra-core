use super::*;

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
        self.port
            .unwrap_or(if self.scheme == "https" { 443 } else { 80 })
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
                format!(
                    "`{}` is not one of the hosts this plugin was granted",
                    checked.host
                ),
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
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                "the URL contains a control character",
            ));
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
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();

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
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                "the URL names no host",
            ));
        }

        let port = match port {
            None | Some("") => None,
            Some(text) => Some(text.parse::<u16>().map_err(|_| {
                Refusal::new(
                    ErrorCode::InvalidArgument,
                    format!("`{text}` is not a port"),
                )
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
                format!(
                    "`{}` resolved to nothing, so there is nowhere to send this",
                    checked.host
                ),
            ));
        }
        // ★ Every address, not the first. A name that resolves to one public address and one private one is a name that
        // can reach the private one — the caller does not choose which address the connection lands on, the resolver's
        // order does, and a check that stopped at the first would be a check an attacker arranges the order around.
        for address in resolved {
            if !self.policy.permits(*address) {
                return Err(Refusal::new(
                    ErrorCode::IpNotAllowed,
                    format!(
                        "`{}` resolves to {address}, which this plugin may not reach",
                        checked.host
                    ),
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
