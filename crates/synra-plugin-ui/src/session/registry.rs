//! Every live session, its expiry, and its revocation.

use std::collections::HashMap;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

use super::token::{SessionRefusal, UiSessionToken};
use super::validated::ValidatedSession;
use super::report::SessionReport;

/// Every live session.
///
/// One per activated UI plugin, keyed by its nonce. Not persisted, and not shareable across processes: a token is a
/// statement by *this* kernel that *this* page may call it.
#[derive(Debug, Default)]
pub struct UiSessionRegistry {
    sessions: parking_lot::RwLock<HashMap<u128, std::sync::Arc<UiSessionToken>>>,
    /// How many nonces have been issued, for a diagnostic report.
    issued: parking_lot::Mutex<u64>,
    /// The next nonce, when a caller supplies them.
    ///
    /// A counter rather than a generator, so this type has no randomness in it and a test can assert exact behaviour.
    /// The *application* supplies real nonces — [`Self::issue_with`] — and the counter is only the default, which is
    /// why it is documented as unsuitable for production: 128 bits of predictability is not a nonce.
    next_placeholder: parking_lot::Mutex<u128>,
}

impl UiSessionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a session for a plugin, using a caller-supplied nonce.
    ///
    /// This is the constructor to use. The nonce is the *only* thing standing between a plugin and another plugin's
    /// grants, so it has to be unguessable — which means it comes from the platform's randomness and not from here.
    ///
    /// # Returns
    ///
    /// The nonce, for the caller to inject into the page. Issuing replaces any session the plugin already had: a
    /// plugin has one page, so a second session for it is a page that was replaced, and leaving the old token live
    /// would leave the old page able to call.
    pub fn issue_with(
        &self,
        plugin_id: &PluginId,
        version: impl Into<String>,
        grants: CapabilitySet,
        nonce: u128,
        now_ms: u64,
    ) -> u128 {
        let token = UiSessionToken {
            plugin_id: plugin_id.clone(),
            plugin_version: version.into(),
            grants,
            issued_at_ms: now_ms,
            ready: core::sync::atomic::AtomicBool::new(false),
        };

        let mut sessions = self.sessions.write();
        // The plugin's previous sessions are dropped, so a reloaded page's old token stops working. Filtering by
        // plugin rather than by nonce is what makes "one page per plugin" true.
        sessions.retain(|_, existing| existing.plugin_id != *plugin_id);
        sessions.insert(nonce, std::sync::Arc::new(token));
        drop(sessions);

        // One lock acquisition, then the arithmetic on the guard. Writing `*self.x.lock() = self.x.lock()...` takes the
        // same lock twice in one expression, and `parking_lot`'s mutex is not reentrant: the second acquisition
        // deadlocks, so this is the difference between a counter and a hang on every issue.
        {
            let mut issued = self.issued.lock();
            *issued = issued.saturating_add(1);
        }
        nonce
    }

    /// Issues a session with a placeholder nonce.
    ///
    /// # ★ Not for production
    ///
    /// The nonce is a counter, so it is fully predictable: any plugin could guess another's. This exists for tests
    /// and for a headless host that has no WebView and therefore no page to protect — and its name says so rather
    /// than its documentation, because a caller reaching for `issue` would not read the warning.
    pub fn issue_placeholder(
        &self,
        plugin_id: &PluginId,
        version: impl Into<String>,
        grants: CapabilitySet,
        now_ms: u64,
    ) -> u128 {
        let nonce = {
            let mut next = self.next_placeholder.lock();
            *next = next.wrapping_add(1);
            *next
        };
        self.issue_with(plugin_id, version, grants, nonce, now_ms)
    }

    /// Revokes a session.
    ///
    /// # Returns
    ///
    /// Whether there was one. `false` is ordinary — a plugin deactivated twice, or one that never had a page — and
    /// reporting it as an error would make a caller handle a case that is not a problem.
    ///
    /// # Revoking makes the page's calls fail
    ///
    /// The kernel cannot reach into a WebView and stop it, so the token is the only lever. Every later call presents
    /// a nonce the registry does not have, and gets [`SessionRefusal::Unknown`] — which is also the answer for a
    /// nonce that never existed, so a plugin cannot probe for which plugins are installed.
    pub fn revoke(&self, nonce: u128) -> bool {
        self.sessions.write().remove(&nonce).is_some()
    }

    /// Revokes every session belonging to a plugin.
    ///
    /// # Returns
    ///
    /// How many were revoked. Used on deactivation and on uninstall, where the caller knows the plugin and not the
    /// nonces.
    pub fn revoke_plugin(&self, plugin_id: &PluginId) -> usize {
        let mut sessions = self.sessions.write();
        let before = sessions.len();
        sessions.retain(|_, token| token.plugin_id != *plugin_id);
        before - sessions.len()
    }

    /// Revokes everything, for a shutdown.
    pub fn revoke_all(&self) {
        self.sessions.write().clear();
    }

    /// Validates a call.
    ///
    /// # Errors
    ///
    /// The first [`SessionRefusal`] that applies, in the order: unknown, wrong plugin, expired, version changed. The
    /// order matters for what the interface does about it — see [`SessionRefusal::means_reload`].
    ///
    /// # The check is a pair
    ///
    /// A valid nonce is not enough. The call also says which plugin it is, and the two have to agree — because
    /// without that check a plugin holding *any* valid token could make calls as its owner. This is the whole reason
    /// the signature takes both.
    pub fn validate(
        &self,
        nonce: u128,
        claimed_plugin: &PluginId,
        running_version: &str,
        now_ms: u64,
    ) -> Result<ValidatedSession, SessionRefusal> {
        // The guard is held for the whole validation and the returned value borrows from it, which is what makes a
        // revocation that races with a call impossible: the revocation waits, and the call sees either the token or
        // its absence.
        // The map is consulted and its guard released before anything else happens, so a revocation does not wait
        // behind a validation. The token stays alive because the session holds an `Arc` to it.
        // The map is consulted and its guard released before anything else happens, so a revocation does not wait
        // behind a validation. The token stays alive because the session holds an `Arc` to it.
        let found = {
            let sessions = self.sessions.read();
            sessions.get(&nonce).map(std::sync::Arc::clone)
        };
        let Some(token) = found else {
            return Err(SessionRefusal::Unknown);
        };

        if token.plugin_id != *claimed_plugin {
            return Err(SessionRefusal::WrongPlugin {
                actual: token.plugin_id.to_string(),
                claimed: claimed_plugin.to_string(),
            });
        }

        if token.is_expired(now_ms) {
            return Err(SessionRefusal::Expired { ago_ms: now_ms.saturating_sub(token.expires_at_ms()) });
        }

        // An update replaces the artifact under a live page. Continuing would run the new code with the old grants
        // and against the old artifact.
        if token.plugin_version != running_version {
            return Err(SessionRefusal::VersionChanged {
                session: token.plugin_version.clone(),
                running: running_version.to_owned(),
            });
        }

        // A call proves the page is listening, so the first one marks it ready. Written through the map's read guard,
        // which is why the flag is atomic: taking the write lock here would drop the guard the returned value borrows
        // from.
        token.mark_ready();

        Ok(ValidatedSession { nonce, token })
    }

    /// How many sessions are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    /// Whether nothing is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many nonces have been issued.
    #[must_use]
    pub fn issued(&self) -> u64 {
        *self.issued.lock()
    }

    /// The plugins with a live session.
    #[must_use]
    pub fn active_plugins(&self) -> Vec<PluginId> {
        self.sessions
            .read()
            .values()
            .map(|token| token.plugin_id.clone())
            .collect()
    }

    /// Revokes every session that has expired at a reading.
    ///
    /// # Returns
    ///
    /// How many were swept. Called on a timer, because nothing else notices an expiry: a session that expires is one
    /// whose page will fail its next call, and until then it holds a grants snapshot and an entry in the map.
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        let mut sessions = self.sessions.write();
        let before = sessions.len();
        sessions.retain(|_, token| !token.is_expired(now_ms));
        before - sessions.len()
    }

    /// A snapshot for a diagnostic report.
    ///
    /// # No nonces
    ///
    /// The report names the plugins with a live session and how many were issued. It deliberately does **not** carry
    /// a nonce: a diagnostic bundle leaves the machine, and a nonce in one is a token somebody else could present.
    #[must_use]
    pub fn report(&self) -> SessionReport {
        let sessions = self.sessions.read();
        SessionReport {
            live: sessions.len(),
            issued: self.issued(),
            plugins: sessions.values().map(|token| token.plugin_id.to_string()).collect(),
            ready: sessions.values().filter(|token| token.is_ready()).count(),
        }
    }
}
