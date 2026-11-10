use std::time::Instant;

use synra_core::network::Refusal;
use synra_protocol::error::ErrorCode;

use super::transport::{body_refusal, timeout_refusal};
use super::{BodyMode, Client, Fetched, Request};

impl Client {
    /// The request itself, with the redirect loop.
    pub(super) fn send(
        &self,
        request: &Request,
        body: &str,
        mode: BodyMode,
        grants: Option<&synra_capability::CapabilitySet>,
    ) -> Result<Fetched, Refusal> {
        let started = Instant::now();
        let mut url = request.url.clone();

        for hop in 0..=self.limits.max_redirects {
            // ★ The clock starts once, at the first hop, and every hop spends from what is left. A timeout per hop would
            // let a chain of five redirects take five times the budget the caller was promised — and a chain a name
            // controls is exactly how a plugin would be made to hold one.
            let remaining = self
                .limits
                .timeout
                .checked_sub(started.elapsed())
                .ok_or_else(|| timeout_refusal(&request.url, self.limits.timeout))?;

            if let Some(grants) = grants {
                synra_plugin_host::host_calls::network_scope::authorize_request(
                    grants,
                    &url,
                    &request.method,
                )
                .map_err(|error| {
                    Refusal::new(
                        if error.code == synra_plugin_host::CallError::CAPABILITY_DENIED {
                            ErrorCode::CapabilityDenied
                        } else {
                            ErrorCode::InvalidArgument
                        },
                        error.message,
                    )
                })?;
            }
            let checked = self.guard.check_url(&url)?;
            let addresses = self.resolve(&checked)?;
            let agent = self.agent(&addresses, remaining)?;

            let mut response = self.one_request(&agent, request, body, &url)?;

            let status = response.status().as_u16();
            let status_text = response.status().canonical_reason().unwrap_or_default().to_owned();
            let headers: std::collections::BTreeMap<String, String> = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (name.as_str().to_ascii_lowercase(), value.to_str().unwrap_or_default().to_owned())
                })
                .collect();

            // A redirect is a second request to a URL nobody authorised, so it goes back through the guard — and through
            // the resolver with it, which is why the loop starts again rather than reusing this agent.
            // ★ `304 Not Modified` is not a redirect: it is the answer to a conditional request, and it has no `Location`
            // to follow. Treating it as one turned a cache hit into a protocol violation.
            if (300..400).contains(&status) && status != 304 {
                let Some(location) = headers.get("location") else {
                    return Err(Refusal::new(
                        ErrorCode::ProtocolViolation,
                        format!("{status} without a `location` header, so there is nowhere to follow"),
                    ));
                };
                let _ = self.guard.next_hop(hop, location)?;
                url = location.clone();
                continue;
            }

            // ★ The body is read only here, and read **with the ceiling applied at the read** rather than after it.
            // A limit checked once the bytes are in memory is a limit that has already been exceeded, which is the shape
            // of enforcement that does not enforce anything.
            // ★ One more than the limit, and the reason is an off-by-one in the client.
            //
            // Its reader errors when a read is attempted with nothing left, and `read_to_string` always attempts one more
            // read to see the end — so a body of **exactly** the limit is refused, and the ceiling a plugin is told about
            // is one byte tighter than the one it is held to. Passing `limit + 1` makes "more than the limit is refused"
            // mean what it says, at both boundaries.
            let ceiling = self.limits.max_response_bytes.saturating_add(1);
            let (text, bytes) = match mode {
                BodyMode::Text => {
                    let text = response
                        .body_mut()
                        .with_config()
                        .limit(ceiling)
                        .read_to_string()
                        .map_err(|error| body_refusal(&url, self.limits.max_response_bytes, &error))?;
                    (Some(text), None)
                }
                BodyMode::Bytes => {
                    let bytes = response
                        .body_mut()
                        .with_config()
                        .limit(ceiling)
                        .read_to_vec()
                        .map_err(|error| body_refusal(&url, self.limits.max_response_bytes, &error))?;
                    (None, Some(bytes))
                }
            };

            let redirected = url != request.url;
            return Ok(Fetched { status, status_text, headers, url, redirected, text, bytes });
        }

        // The loop returns on the last iteration's non-redirect, so this is reached only when every hop redirected —
        // which `next_hop` refuses before the counter gets here. A refusal rather than a panic, because this workspace
        // denies `panic` in production code and an unreachable branch is not a licence to break that.
        Err(Refusal::new(
            ErrorCode::RedirectBlocked,
            format!("more than {} redirects", self.limits.max_redirects),
        ))
    }
}
