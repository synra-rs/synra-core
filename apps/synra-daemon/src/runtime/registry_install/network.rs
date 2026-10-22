//! Raw HTTP downloads, with loopback access granted by configuration rather than package metadata.

use super::Fetch;

/// The real network client, one guarded request at a time.
#[derive(Default)]
pub(crate) struct NetworkFetch {
    /// Loopback is enabled only for a registry the user explicitly configured on this machine.
    pub(crate) allow_loopback: bool,
}

impl Fetch for NetworkFetch {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let response = self.response(url, 64 * 1024 * 1024)?;
        if !(200..300).contains(&response.status) {
            return Err(format!("{url} answered {}", response.status));
        }
        Ok(response.body)
    }
}

impl NetworkFetch {
    /// Fetches raw bytes with a caller-selected ceiling; HTTP status remains available for mirror fallback decisions.
    pub(crate) fn response(
        &self,
        url: &str,
        max_response_bytes: u64,
    ) -> Result<synra_fetch::BinaryResponse, String> {
        let parsed = synra_core::network::NetworkGuard::for_hosts(&[])
            .allowing_insecure(true)
            .parse(url)
            .map_err(|error| error.to_string())?;
        let loopback = parsed.host == "localhost"
            || parsed
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        let guard = synra_core::network::NetworkGuard::for_hosts(&[parsed.host])
            .allowing_insecure(self.allow_loopback && loopback)
            .with_policy(synra_core::network::IpPolicy {
                allow_loopback: self.allow_loopback,
                ..synra_core::network::IpPolicy::default()
            });
        let client = synra_fetch::Client::new(
            guard,
            // A package may be 64 MiB (16 §2.1), and the fetch layer's default response ceiling is the inline-frame one.
            synra_fetch::Limits {
                max_response_bytes,
                ..synra_fetch::Limits::default()
            },
        );
        let request = synra_fetch::Request {
            method: "GET".to_owned(),
            url: url.to_owned(),
            headers: std::collections::BTreeMap::new(),
            body: None,
        };
        client
            .fetch_bytes(&request)
            .map_err(|refusal| refusal.to_string())
    }
}
