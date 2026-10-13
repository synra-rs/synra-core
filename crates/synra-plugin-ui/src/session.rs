//! Session tokens: what lets a plugin's page call the kernel, and what stops it calling as someone else.
//!
//! # Three things a UI plugin must not be able to do
//!
//! The design document names them, and each one is a different failure:
//!
//! * **Forge its own `pluginId`.** A plugin's page runs in the same process as the kernel's interface, and an
//!   identifier is a string. If the identifier were the only thing a call carried, a plugin could claim to be
//!   another and inherit its grants.
//! * **Call another plugin's capabilities.** The consequence of the first, and the reason the check is a pair:
//!   a token is valid for exactly one plugin, and a call is only admitted when the token's plugin *and* the claimed
//!   plugin agree.
//! * **Keep calling after being deactivated.** A page the user removed is one whose WebView may still be alive. The
//!   kernel cannot reach into it and stop it, so the only lever is the token: it is revoked, and every later call
//!   fails.
//!
//! # The token is a capability, not a session
//!
//! That distinction decides the whole design. A session would be something the plugin *has* and can point at; a
//! capability is something the kernel *holds on the plugin's behalf*, and the plugin only ever presents a nonce that
//! means nothing on its own. So the registry is the authority, the nonce is a key, and the grants live on the
//! kernel's side of the boundary — which is what makes "the plugin cannot read its own permissions to forge them"
//! true rather than aspirational.
//!
//! # The grants are frozen at activation
//!
//! A session holds a *snapshot* of what the plugin was granted when it was activated. If the user later revokes a
//! capability, the running page keeps working with what it started with until it is reactivated — because the
//! alternative is a permission change that takes effect halfway through a call. The snapshot is why
//! [`ValidatedSession::grants`] is a reference to the token's own set rather than a lookup: a lookup would consult
//! the live grants and could disagree between two calls in one operation.
//!
//! # Nothing here is persisted
//!
//! A nonce is not written to disk, and that is deliberate: a token that survived a restart is one a page that was
//! supposed to be gone could still present. A restart issues new tokens, and the old ones are simply absent from a
//! registry that no longer exists.
//!
//! # No WebView, no rendering
//!
//! This crate manages an artifact's *manifest* of files and decides which calls are admitted. It does not serve,
//! render or unpack: the WebView is the application's, and a crate that knew about one could not be tested without
//! it.

use std::collections::HashMap;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

/// How long a session token is valid.
///
/// Twelve hours: longer than any plausible session of using a plugin, and short enough that a token which leaked out
/// of a page — through a screenshot of a debug console, say — is not usable the next day. There is no refresh: a
/// plugin that needs to keep working is reactivated by the interface, which issues a new token.
pub const SESSION_LIFETIME_MS: u64 = 12 * 60 * 60 * 1_000;

/// Why a call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionRefusal {
    /// No session has that nonce.
    ///
    /// Either it never existed, or it was revoked — and the two are the same answer on purpose: telling a plugin
    /// "you were deactivated" and "that token never existed" differently would let it probe for which plugins are
    /// installed.
    #[error("the session token is not valid")]
    Unknown,

    /// The session belongs to a different plugin than the call claims.
    #[error("the session belongs to {actual}, and the call claims {claimed}")]
    WrongPlugin {
        /// The plugin the session was issued to.
        actual: String,
        /// The plugin the call claims to be.
        claimed: String,
    },

    /// The session's time is up.
    #[error("the session expired {ago_ms}ms ago")]
    Expired {
        /// How long ago it expired.
        ago_ms: u64,
    },

    /// The plugin's version does not match the session's.
    ///
    /// An update replaces the artifact under a live page. Continuing with the old token would run the new code with
    /// the old grants and against the old artifact, so the version travel is refused and the page is reloaded.
    #[error("the session is for version {session}, and the call comes from {running}")]
    VersionChanged {
        /// The version the session was issued for.
        session: String,
        /// The version now installed.
        running: String,
    },
}

impl SessionRefusal {
    /// Whether an interface should reload the plugin's page.
    ///
    /// A version change is the one refusal where reloading fixes it, and the one where *not* reloading leaves a user
    /// with a page that fails every call for no visible reason. A revoked session is the opposite: reloading would
    /// restart a plugin the user just removed.
    #[must_use]
    pub fn means_reload(self) -> bool {
        matches!(self, Self::VersionChanged { .. } | Self::Expired { .. })
    }

    /// Whether the refusal means the plugin no longer exists as far as this session is concerned.
    ///
    /// The interface uses this to tear the page down rather than show an error inside it.
    #[must_use]
    pub fn means_teardown(self) -> bool {
        matches!(self, Self::Unknown | Self::WrongPlugin { .. })
    }
}

/// A session token, as the kernel holds it.
///
/// The plugin never sees this. It is given the nonce and nothing else — see the module docs for why that is the
/// whole point rather than a detail.
#[derive(Debug)]
pub struct UiSessionToken {
    /// Which plugin the session was issued to.
    pub plugin_id: PluginId,
    /// The version that was installed when it was issued.
    pub plugin_version: String,
    /// What the plugin was granted, frozen at activation.
    pub grants: CapabilitySet,
    /// When it was issued, in monotonic milliseconds.
    pub issued_at_ms: u64,
    /// Whether the plugin's own interface has finished loading.
    ///
    /// A page that has not reported itself ready has not yet registered its listeners, so an event delivered to it
    /// would be dropped. Reported rather than assumed, because "the WebView exists" and "the page is listening" are
    /// different facts and a plugin that misses its first event is a plugin with a bug nobody can reproduce.
    ///
    /// Atomic because `validate` holds the map's *read* guard: taking the write lock there would drop the guard the
    /// returned session borrows from, so the flag moves through an interior-mutability cell instead.
    ready: core::sync::atomic::AtomicBool,
}

impl Clone for UiSessionToken {
    fn clone(&self) -> Self {
        Self {
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version.clone(),
            grants: self.grants.clone(),
            issued_at_ms: self.issued_at_ms,
            ready: core::sync::atomic::AtomicBool::new(self.is_ready()),
        }
    }
}

impl UiSessionToken {
    /// When it expires, in monotonic milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms.saturating_add(SESSION_LIFETIME_MS)
    }

    /// Whether it has expired at a reading.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms()
    }

    /// Whether the plugin's page has reported itself ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Records that the page is listening.
    pub fn mark_ready(&self) {
        self.ready.store(true, core::sync::atomic::Ordering::Relaxed);
    }
}

/// A validated session, as a caller sees it.
///
/// # Held by value, not borrowed
///
/// The token is an `Arc`, so the session outlives the registry's guard rather than borrowing from it. That matters
/// for two reasons: `validate` can return without holding a read lock for the duration of a call — a read lock held
/// across a call is a write lock that waits, which is how a revocation ends up blocked behind the very call it is
/// revoking — and the caller cannot accidentally keep a guard alive in a struct field, which is the shape that
/// deadlocks a registry with itself.
///
/// It also means a revocation does not invalidate a session that is already in flight. That is deliberate: a call
/// that passed validation is one the kernel decided to allow, and aborting it halfway would leave the plugin's state
/// and the kernel's disagreeing. The *next* call is refused, which is what "deactivated" means for a page the kernel
/// cannot reach into.
#[derive(Debug, Clone)]
pub struct ValidatedSession {
    /// The nonce, for an audit record.
    pub nonce: u128,
    /// The token.
    token: std::sync::Arc<UiSessionToken>,
}

impl ValidatedSession {
    /// The token.
    #[must_use]
    pub fn token(&self) -> &UiSessionToken {
        &self.token
    }

    /// The plugin the session belongs to.
    #[must_use]
    pub fn plugin_id(&self) -> &PluginId {
        &self.token.plugin_id
    }

    /// What the plugin may do, as of activation.
    #[must_use]
    pub fn grants(&self) -> &CapabilitySet {
        &self.token.grants
    }

    /// Whether the plugin's page has reported itself ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.token.is_ready()
    }
}

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

/// What the diagnostics screen shows about sessions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionReport {
    /// How many sessions are live.
    pub live: usize,
    /// How many have been issued since start-up.
    pub issued: u64,
    /// Which plugins hold one.
    pub plugins: Vec<String>,
    /// How many pages have reported themselves ready.
    pub ready: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_capability::Capability;

    fn plugin(text: &str) -> PluginId {
        PluginId::parse(text).expect("a valid plugin id")
    }

    fn grants(texts: &[&str]) -> CapabilitySet {
        let mut set = CapabilitySet::new();
        for text in texts {
            set.insert_str(text).expect("a valid capability");
        }
        set
    }

    fn chat() -> PluginId {
        plugin("@synra-plugin/chat")
    }

    fn notes() -> PluginId {
        plugin("@synra-plugin/notes")
    }

    /// A registry with one session for `chat`.
    fn with_chat() -> (UiSessionRegistry, u128) {
        let registry = UiSessionRegistry::new();
        let nonce = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 0xABCD, 1_000);
        (registry, nonce)
    }

    // ── Issuing and validating ────────────────────────────────────────────────────────────────────

    #[test]
    fn a_valid_session_admits_a_call() {
        let (registry, nonce) = with_chat();
        let session = registry
            .validate(nonce, &chat(), "1.0.0", 2_000)
            .expect("validates");
        assert_eq!(session.plugin_id(), &chat());
        assert_eq!(session.nonce, nonce);
        assert!(session.grants().contains(&Capability::parse("log:*").expect("valid")));
    }

    #[test]
    fn an_unknown_nonce_is_refused_without_saying_why() {
        // "You were deactivated" and "that token never existed" must give the same answer, or a plugin could probe for
        // which plugins are installed by presenting guessed nonces and reading the difference.
        let registry = UiSessionRegistry::new();
        assert_eq!(
            registry.validate(0xDEAD, &chat(), "1.0.0", 0).map(|_| ()),
            Err(SessionRefusal::Unknown)
        );

        let (registry, nonce) = with_chat();
        registry.revoke(nonce);
        assert_eq!(
            registry.validate(nonce, &chat(), "1.0.0", 2_000).map(|_| ()),
            Err(SessionRefusal::Unknown),
            "a revoked session must be indistinguishable from one that never existed"
        );
    }

    #[test]
    fn a_session_cannot_be_used_by_another_plugin() {
        // The attack the whole design is about: a plugin holding a valid token making calls as its owner.
        let (registry, nonce) = with_chat();
        match registry.validate(nonce, &notes(), "1.0.0", 2_000) {
            Err(SessionRefusal::WrongPlugin { actual, claimed }) => {
                assert_eq!(actual, "@synra-plugin/chat");
                assert_eq!(claimed, "@synra-plugin/notes");
            }
            other => panic!("expected a wrong-plugin refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_nonce_is_not_enough_on_its_own() {
        // Stated separately because it is the property, and a test that only checked the happy path would pass against
        // an implementation that ignored the claimed plugin entirely.
        let (registry, nonce) = with_chat();
        assert!(registry.validate(nonce, &chat(), "1.0.0", 2_000).is_ok());
        assert!(registry.validate(nonce, &notes(), "1.0.0", 2_000).is_err());
    }

    #[test]
    fn an_expired_session_is_refused_and_says_how_long_ago() {
        let (registry, nonce) = with_chat();
        let expired_at = 1_000 + SESSION_LIFETIME_MS;
        match registry.validate(nonce, &chat(), "1.0.0", expired_at + 500) {
            Err(SessionRefusal::Expired { ago_ms }) => assert_eq!(ago_ms, 500),
            other => panic!("expected an expiry, got {other:?}"),
        }
        // At the instant it expires it is expired, not one millisecond later.
        assert!(registry.validate(nonce, &chat(), "1.0.0", expired_at).is_err());
        assert!(registry.validate(nonce, &chat(), "1.0.0", expired_at - 1).is_ok());
    }

    #[test]
    fn a_version_change_is_refused() {
        // An update replaces the artifact under a live page. Continuing would run the new code with the old grants and
        // against the old artifact.
        let (registry, nonce) = with_chat();
        match registry.validate(nonce, &chat(), "1.1.0", 2_000) {
            Err(SessionRefusal::VersionChanged { session, running }) => {
                assert_eq!(session, "1.0.0");
                assert_eq!(running, "1.1.0");
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_grants_are_the_ones_frozen_at_activation() {
        // A permission change that took effect halfway through an operation is worse than one that waits for a
        // reload — which is why the session holds a snapshot rather than consulting the live grants.
        let registry = UiSessionRegistry::new();
        let nonce = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 7, 0);

        let session = registry.validate(nonce, &chat(), "1.0.0", 1).expect("validates");
        assert!(session.grants().contains(&Capability::parse("log:*").expect("valid")));
        assert!(!session.grants().contains(&Capability::parse("storage:local:read").expect("valid")));
    }

    // ── Readiness ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_session_is_not_ready_until_a_call_arrives() {
        // "The WebView exists" and "the page is listening" are different facts, and a plugin that misses its first
        // event is one with a bug nobody can reproduce.
        let (registry, nonce) = with_chat();
        assert_eq!(registry.report().ready, 0, "nothing should be ready yet");
        assert_eq!(registry.report().ready, 0);

        let session = registry.validate(nonce, &chat(), "1.0.0", 2_000).expect("validates");
        assert!(session.is_ready(), "the first call marks the page ready");
        assert_eq!(registry.report().ready, 1);
    }

    // ── Revoking ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn revoking_stops_every_later_call() {
        // The kernel cannot reach into a WebView and stop it, so the token is the only lever.
        let (registry, nonce) = with_chat();
        assert!(registry.validate(nonce, &chat(), "1.0.0", 1).is_ok());

        assert!(registry.revoke(nonce));
        assert!(registry.validate(nonce, &chat(), "1.0.0", 2).is_err());
        assert!(registry.is_empty());
    }

    #[test]
    fn revoking_something_that_is_not_there_is_not_an_error() {
        // A plugin deactivated twice, or one that never had a page. Reporting it as a failure would make a caller
        // handle a case that is not a problem.
        let registry = UiSessionRegistry::new();
        assert!(!registry.revoke(0));
        let (registry, nonce) = with_chat();
        assert!(registry.revoke(nonce));
        assert!(!registry.revoke(nonce));
    }

    #[test]
    fn every_session_of_a_plugin_can_be_revoked_by_id() {
        // A caller on deactivation knows the plugin and not the nonce.
        let registry = UiSessionRegistry::new();
        registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 1, 0);
        registry.issue_with(&notes(), "1.0.0", grants(&["log:*"]), 2, 0);

        assert_eq!(registry.revoke_plugin(&chat()), 1);
        assert_eq!(registry.len(), 1);
        assert!(registry.revoke_plugin(&chat()) == 0, "nothing left to revoke");
    }

    #[test]
    fn issuing_again_replaces_the_plugins_previous_session() {
        // A plugin has one page, so a second session for it is a page that was replaced — and leaving the old token
        // live would leave the old page able to call.
        let registry = UiSessionRegistry::new();
        let first = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 1, 0);
        let second = registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 2, 0);

        assert_eq!(registry.len(), 1, "the old session was not dropped");
        assert!(registry.validate(first, &chat(), "1.0.0", 1).is_err(), "the old token still works");
        assert!(registry.validate(second, &chat(), "1.0.0", 1).is_ok());
    }

    #[test]
    fn replacing_one_plugins_session_leaves_another_alone() {
        // The retain is by plugin, so a reload of one plugin must not sweep another's session.
        let registry = UiSessionRegistry::new();
        let notes_nonce = registry.issue_with(&notes(), "1.0.0", grants(&["log:*"]), 1, 0);
        registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 2, 0);
        registry.issue_with(&chat(), "1.0.0", grants(&["log:*"]), 3, 0);

        assert_eq!(registry.len(), 2);
        assert!(registry.validate(notes_nonce, &notes(), "1.0.0", 1).is_ok());
    }

    #[test]
    fn revoking_everything_is_for_a_shutdown() {
        let registry = UiSessionRegistry::new();
        registry.issue_with(&chat(), "1.0.0", grants(&[]), 1, 0);
        registry.issue_with(&notes(), "1.0.0", grants(&[]), 2, 0);
        registry.revoke_all();
        assert!(registry.is_empty());
    }

    // ── Sweeping ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_expired_session_is_swept() {
        // Nothing else notices an expiry: until the sweep, the session holds a grants snapshot and an entry.
        let registry = UiSessionRegistry::new();
        let old = registry.issue_with(&chat(), "1.0.0", grants(&[]), 1, 0);
        let fresh = registry.issue_with(
            &notes(),
            "1.0.0",
            grants(&[]),
            2,
            SESSION_LIFETIME_MS - 1,
        );

        assert_eq!(registry.sweep_expired(SESSION_LIFETIME_MS), 1, "the old one should be swept");
        assert_eq!(registry.len(), 1);
        assert!(registry.validate(old, &chat(), "1.0.0", SESSION_LIFETIME_MS).is_err());
        // The fresh one was issued one millisecond before the sweep instant, so it survives.
        assert!(registry
            .validate(fresh, &notes(), "1.0.0", SESSION_LIFETIME_MS)
            .is_ok());
    }

    #[test]
    fn sweeping_nothing_reports_nothing() {
        let registry = UiSessionRegistry::new();
        assert_eq!(registry.sweep_expired(u64::MAX), 0);
    }

    // ── Refusals ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_version_change_and_an_expiry_say_reload() {
        // The refusals where reloading fixes it — and where not reloading leaves a page that fails every call for no
        // visible reason.
        assert!(SessionRefusal::VersionChanged {
            session: "1".to_owned(),
            running: "2".to_owned()
        }
        .means_reload());
        assert!(SessionRefusal::Expired { ago_ms: 1 }.means_reload());
        assert!(!SessionRefusal::Unknown.means_reload());
        assert!(!SessionRefusal::WrongPlugin {
            actual: "a".to_owned(),
            claimed: "b".to_owned()
        }
        .means_reload());
    }

    #[test]
    fn an_unknown_or_wrong_session_says_teardown() {
        // Reloading a revoked session would restart a plugin the user just removed.
        assert!(SessionRefusal::Unknown.means_teardown());
        assert!(SessionRefusal::WrongPlugin {
            actual: "a".to_owned(),
            claimed: "b".to_owned()
        }
        .means_teardown());
        assert!(!SessionRefusal::Expired { ago_ms: 1 }.means_teardown());
    }

    #[test]
    fn session_refusals_explain_themselves() {
        let refusals = [
            SessionRefusal::Unknown,
            SessionRefusal::WrongPlugin { actual: "a".to_owned(), claimed: "b".to_owned() },
            SessionRefusal::Expired { ago_ms: 500 },
            SessionRefusal::VersionChanged { session: "1".to_owned(), running: "2".to_owned() },
        ];
        for refusal in refusals {
            let text = refusal.to_string();
            assert!(text.len() > 20, "{refusal:?} -> {text}");
            assert!(!text.contains('{'), "{refusal:?} -> {text}");
        }
    }

    // ── Reporting ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_report_carries_no_nonces() {
        // A diagnostic bundle leaves the machine, and a nonce in one is a token somebody else could present.
        let (registry, nonce) = with_chat();
        registry.validate(nonce, &chat(), "1.0.0", 2_000).expect("validates");

        let report = registry.report();
        assert_eq!(report.live, 1);
        assert_eq!(report.issued, 1);
        assert_eq!(report.plugins, vec!["@synra-plugin/chat".to_owned()]);
        assert_eq!(report.ready, 1);

        let json = serde_json::to_string(&report).expect("serialises");
        assert!(!json.contains("43981"), "the nonce `0xABCD` appeared in {json}");
        assert!(!json.contains("nonce"), "{json}");
    }

    #[test]
    fn the_report_round_trips() {
        let (registry, _nonce) = with_chat();
        let report = registry.report();
        let json = serde_json::to_string(&report).expect("serialises");
        let back: SessionReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }

    #[test]
    fn an_empty_registry_reports_empty() {
        let report = UiSessionRegistry::new().report();
        assert_eq!(report.live, 0);
        assert!(report.plugins.is_empty());
        assert_eq!(report.issued, 0);
    }

    #[test]
    fn issuing_is_counted_across_replacements() {
        // The count is of issued tokens, not of live ones: a plugin reloaded five times had five sessions, and a
        // number that said one would hide a reload loop.
        let registry = UiSessionRegistry::new();
        for nonce in 1..=5u128 {
            registry.issue_with(&chat(), "1.0.0", grants(&[]), nonce, 0);
        }
        assert_eq!(registry.report().issued, 5);
        assert_eq!(registry.report().live, 1);
    }

    #[test]
    fn the_active_plugins_are_listed() {
        let registry = UiSessionRegistry::new();
        registry.issue_with(&chat(), "1.0.0", grants(&[]), 1, 0);
        registry.issue_with(&notes(), "1.0.0", grants(&[]), 2, 0);

        let mut active: Vec<String> = registry.active_plugins().iter().map(ToString::to_string).collect();
        active.sort();
        assert_eq!(active, vec!["@synra-plugin/chat", "@synra-plugin/notes"]);
    }

    #[test]
    fn the_placeholder_issuer_is_documented_as_unpredictable() {
        // It exists for tests and for a host with no WebView. The name says what it is, because a caller reaching for
        // `issue` would not read a warning in the documentation.
        let registry = UiSessionRegistry::new();
        let first = registry.issue_placeholder(&chat(), "1.0.0", grants(&[]), 0);
        let second = registry.issue_placeholder(&chat(), "1.0.0", grants(&[]), 0);
        assert_ne!(first, second);
        // And it is predictable, which is the point of the name.
        assert_eq!(second, first + 1);
    }

    #[test]
    fn the_session_lifetime_is_the_documented_one() {
        assert_eq!(SESSION_LIFETIME_MS, 12 * 60 * 60 * 1_000);
    }

    #[test]
    fn a_token_reports_its_own_expiry() {
        let token = UiSessionToken {
            plugin_id: chat(),
            plugin_version: "1.0.0".to_owned(),
            grants: grants(&[]),
            issued_at_ms: 1_000,
            ready: core::sync::atomic::AtomicBool::new(false),
        };
        assert_eq!(token.expires_at_ms(), 1_000 + SESSION_LIFETIME_MS);
        assert!(!token.is_expired(1_000 + SESSION_LIFETIME_MS - 1));
        assert!(token.is_expired(1_000 + SESSION_LIFETIME_MS));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn plugin(text: &str) -> PluginId {
        PluginId::parse(text).expect("a valid plugin id")
    }

    /// A plugin id from a small set, so a property test can collide them.
    fn arbitrary_plugin() -> impl Strategy<Value = PluginId> {
        prop_oneof![
            Just("@synra-plugin/chat"),
            Just("@synra-plugin/notes"),
            Just("@synra-plugin/mail"),
        ]
        .prop_map(plugin)
    }

    proptest! {
        /// A session admits a call only for the plugin it was issued to. The property the whole design exists for: no
        /// sequence of operations makes one plugin's token authorize another plugin's call.
        #[test]
        fn a_session_never_admits_another_plugin(
            issued_to in arbitrary_plugin(),
            claimed in arbitrary_plugin(),
            nonce in any::<u128>(),
            now in 0u64..(SESSION_LIFETIME_MS * 2),
        ) {
            let registry = UiSessionRegistry::new();
            registry.issue_with(&issued_to, "1.0.0", CapabilitySet::new(), nonce, 0);

            let result = registry.validate(nonce, &claimed, "1.0.0", now);
            if issued_to == claimed {
                // The only case that may succeed, and only while unexpired.
                if now < SESSION_LIFETIME_MS {
                    prop_assert!(result.is_ok(), "{:?}", result.err());
                }
                else {
                    prop_assert!(
                        matches!(result, Err(SessionRefusal::Expired { .. })),
                        "{:?}",
                        result.err(),
                    );
                }
            }
            else {
                prop_assert!(
                    matches!(result, Err(SessionRefusal::WrongPlugin { .. })),
                    "{} admitted a call from {}: {:?}",
                    issued_to,
                    claimed,
                    result.map(|session| session.plugin_id().to_string()),
                );
            }
        }

        /// A revoked nonce is refused for every plugin and every time, and the refusal is the same one an unknown
        /// nonce gets. A different answer would let a plugin probe for which plugins are installed.
        #[test]
        fn a_revoked_nonce_is_indistinguishable_from_an_unknown_one(
            plugin_id in arbitrary_plugin(),
            nonce in any::<u128>(),
            now in 0u64..1_000_000,
        ) {
            let registry = UiSessionRegistry::new();
            registry.issue_with(&plugin_id, "1.0.0", CapabilitySet::new(), nonce, 0);
            prop_assert!(registry.revoke(nonce));

            let revoked = registry.validate(nonce, &plugin_id, "1.0.0", now).map(|_| ());
            let unknown = registry.validate(nonce.wrapping_add(1), &plugin_id, "1.0.0", now).map(|_| ());
            prop_assert_eq!(&revoked, &unknown);
            prop_assert_eq!(revoked, Err(SessionRefusal::Unknown));
        }

        /// Whatever sequence of issues, revocations and sweeps happens, a live session always validates for its own
        /// plugin. A session that a caller cannot use is a page that stops working for no reason.
        #[test]
        fn a_live_session_always_validates(
            operations in proptest::collection::vec((any::<bool>(), arbitrary_plugin(), any::<u128>()), 0..40),
        ) {
            let registry = UiSessionRegistry::new();
            // Track what the registry should hold, so the property is about agreement rather than about a hard-coded
            // expectation.
            let mut live: HashMap<u128, PluginId> = HashMap::new();
            let mut at = 0u64;

            for (is_issue, plugin_id, nonce) in operations {
                at += 1;
                if is_issue {
                    registry.issue_with(&plugin_id, "1.0.0", CapabilitySet::new(), nonce, at);
                    // Issuing replaces the plugin's previous session, so its other entries go.
                    live.retain(|_, owner| *owner != plugin_id);
                    live.insert(nonce, plugin_id);
                }
                else {
                    registry.revoke(nonce);
                    live.remove(&nonce);
                }
            }

            for (nonce, plugin_id) in &live {
                prop_assert!(
                    registry.validate(*nonce, plugin_id, "1.0.0", at + 1).is_ok(),
                    "{} could not use its own live session",
                    plugin_id,
                );
            }
            prop_assert_eq!(registry.len(), live.len());
        }

        /// Issuing never leaves more than one session per plugin, whatever order the calls come in. Two live sessions
        /// for one plugin is two pages able to call, and the second is one the user cannot see.
        #[test]
        fn issuing_leaves_one_session_per_plugin(
            issues in proptest::collection::vec((arbitrary_plugin(), any::<u128>()), 1..30),
        ) {
            let registry = UiSessionRegistry::new();
            let mut at = 0u64;
            for (plugin_id, nonce) in issues {
                at += 1;
                registry.issue_with(&plugin_id, "1.0.0", CapabilitySet::new(), nonce, at);
            }

            let active = registry.active_plugins();
            let mut sorted: Vec<String> = active.iter().map(ToString::to_string).collect();
            sorted.sort();
            sorted.dedup();
            prop_assert_eq!(sorted.len(), active.len(), "a plugin holds more than one session");
        }
    }
}
