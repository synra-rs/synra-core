//! Validated event names and namespace rules.

use core::fmt;

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

use crate::ids::PluginId;

use super::{INTERNAL_PREFIX, MAX_EVENT_NAME_LEN, PLUGIN_EMITTABLE, PLUGIN_PREFIX, SYSTEM_PREFIX};

/// Why an event name is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EventNameError {
    /// The name is empty.
    #[error("event name is empty")]
    Empty,

    /// The name is longer than [`MAX_EVENT_NAME_LEN`].
    #[error("event name is {len} bytes, the limit is {max}")]
    TooLong {
        /// Observed length.
        len: usize,
        /// The limit.
        max: usize,
    },

    /// The name carries no segment after its prefix, or has an empty one.
    #[error("malformed event name: {0}")]
    Malformed(String),

    /// A plugin tried to emit under a namespace that is not its own.
    #[error("plugin {attempted} may not emit under {actual}")]
    ForeignNamespace {
        /// The complete package id found in the name.
        actual: String,
        /// The complete id of the plugin that tried.
        attempted: String,
    },

    /// A plugin attempted to emit a host event that is not on the allowed list.
    #[error("plugins may not emit {0}")]
    ReservedForHost(String),
}

/// A validated event name, in one of three namespaces plus the bare data-plane form.
///
/// The only ways to obtain one are [`EventName::parse`], [`EventName::system`],
/// [`EventName::plugin`] and [`EventName::internal`], so a value of this type is always well formed.
/// Deserialisation goes through the same validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EventName(CompactString);

impl EventName {
    /// Parses any event name, checking its grammar.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Empty`], [`EventNameError::TooLong`] or [`EventNameError::Malformed`].
    pub fn parse(name: &str) -> Result<Self, EventNameError> {
        if name.is_empty() {
            return Err(EventNameError::Empty);
        }
        if name.len() > MAX_EVENT_NAME_LEN {
            return Err(EventNameError::TooLong { len: name.len(), max: MAX_EVENT_NAME_LEN });
        }

        if let Some(rest) = name.strip_prefix(PLUGIN_PREFIX) {
            let (slug, logical) = rest.split_once('.').ok_or_else(|| {
                EventNameError::Malformed(
                    "a plugin event needs a full package id and a name".to_owned(),
                )
            })?;
            PluginId::validate(slug)
                .map_err(|error| EventNameError::Malformed(error.to_string()))?;
            validate_segments(logical)?;
            return Ok(Self(CompactString::from(name)));
        }

        if let Some(rest) = name.strip_prefix(SYSTEM_PREFIX) {
            validate_segments(rest)?;
            return Ok(Self(CompactString::from(name)));
        }

        if let Some(rest) = name.strip_prefix(INTERNAL_PREFIX) {
            validate_segments(rest)?;
            return Ok(Self(CompactString::from(name)));
        }

        // `_synra.` and `_plugin.` are checked before this, so what remains is the kernel's own
        // bare namespaces: `device.*` for link and session control, `file.transfer.*` for the data
        // plane.
        //
        // The prefix list is closed on purpose. Without it, any dotted string would be a valid event
        // name, which sounds permissive and is actually worse: a typo in a constant, or a name
        // arriving from a peer, would be silently accepted as an event nobody handles. The
        // `Unknown` bucket in the inbound dispatcher is for *valid* names this version does not
        // recognise, not for arbitrary text.
        const DATA_PLANE_PREFIXES: &[&str] = &["device.", "file.transfer."];
        if let Some(prefix) = DATA_PLANE_PREFIXES.iter().find(|p| name.starts_with(**p)) {
            let logical = &name[prefix.len()..];
            validate_segments(logical)?;
            return Ok(Self(CompactString::from(name)));
        }

        Err(EventNameError::Malformed(format!(
            "event name {name:?} is not in a known namespace \
             (_synra., _plugin., synra.internal., device., file.transfer.)"
        )))
    }

    /// Builds a host event under `_synra.`.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Malformed`] if `logical` is empty or has an empty segment.
    pub fn system(logical: &str) -> Result<Self, EventNameError> {
        validate_segments(logical)?;
        Self::parse(&format!("{SYSTEM_PREFIX}{logical}"))
    }

    /// Builds an event in a plugin's own namespace.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Malformed`] if `logical` is empty or has an empty segment.
    pub fn plugin(id: &PluginId, logical: &str) -> Result<Self, EventNameError> {
        validate_segments(logical)?;
        Self::parse(&format!("{PLUGIN_PREFIX}{id}.{logical}"))
    }

    /// Builds an event that stays inside the process.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Malformed`] if `logical` is empty or has an empty segment.
    pub fn internal(logical: &str) -> Result<Self, EventNameError> {
        validate_segments(logical)?;
        Self::parse(&format!("{INTERNAL_PREFIX}{logical}"))
    }

    /// The name as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether this is a host event under `_synra.`.
    ///
    /// Carries no payload contract of its own: the host defines what each one means.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.0.starts_with(SYSTEM_PREFIX)
    }

    /// Whether this is part of the link and session protocol itself (`device.*`).
    ///
    /// Separate from [`Self::is_system`] because these are never delivered to a plugin: they are the
    /// mechanism by which links exist, and a plugin that could observe or inject them would be
    /// inside the transport rather than on top of it.
    #[must_use]
    pub fn is_transport(&self) -> bool {
        self.0.starts_with("device.")
    }

    /// Whether this is a plugin event.
    #[must_use]
    pub fn is_plugin(&self) -> bool {
        self.0.starts_with(PLUGIN_PREFIX)
    }

    /// Whether this never leaves the process.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        self.0.starts_with(INTERNAL_PREFIX)
    }

    /// Whether this is a data-plane event, such as `file.transfer.chunk`.
    ///
    /// The kernel's own payload-carrying protocol: transfers, and nothing else. `device.*` is
    /// transport rather than data plane, and `_plugin.*` belongs to an author.
    #[must_use]
    pub fn is_data_plane(&self) -> bool {
        self.0.starts_with("file.transfer.")
    }

    /// The owning plugin's complete package id and the event's own name, for a plugin event.
    #[must_use]
    pub fn plugin_scope(&self) -> Option<(&str, &str)> {
        let rest = self.0.strip_prefix(PLUGIN_PREFIX)?;
        rest.split_once('.')
    }

    /// Checks this name may be emitted by the plugin with the complete package `id`.
    ///
    /// The host calls this on every outbound plugin event. It is the difference between "plugins
    /// have their own namespace" being true and it being a sentence in a document.
    ///
    /// # Errors
    ///
    /// [`EventNameError::ForeignNamespace`] if the name belongs to another plugin,
    /// [`EventNameError::ReservedForHost`] if it is a host event a plugin may not send.
    pub fn check_emittable_by(&self, id: &PluginId) -> Result<(), EventNameError> {
        if let Some((owner, _)) = self.plugin_scope() {
            if owner == id.as_str() {
                return Ok(());
            }
            return Err(EventNameError::ForeignNamespace {
                actual: owner.to_owned(),
                attempted: id.to_string(),
            });
        }

        if PLUGIN_EMITTABLE.contains(&self.as_str()) {
            return Ok(());
        }

        Err(EventNameError::ReservedForHost(self.0.to_string()))
    }
}

impl fmt::Display for EventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for EventName {
    type Error = EventNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<EventName> for String {
    fn from(value: EventName) -> Self {
        value.0.into_string()
    }
}

/// Rejects an empty logical name, or one with an empty or malformed segment.
///
/// Each dot-separated segment must be `[A-Za-z0-9_-]+`.
///
/// Requiring a known character set keeps an event name from ever being usable as something else — a
/// path, a shell argument, a URL fragment — if some later code passes one along to another system.
///
/// # No wildcards
///
/// `*` is deliberately **not** allowed here. It belongs to `handles` patterns, which describe what a
/// plugin wants to receive, and a pattern is not a name: nothing can be *sent* as `_plugin.@acme/chat.*`.
/// Keeping the two grammars apart means an [`EventName`] is always something a peer could
/// legitimately have sent, so a routing table built from names never has to ask whether an entry is
/// a pattern. [`crate::inbound::HandlePattern`] is the grammar that accepts wildcards.
fn validate_segments(logical: &str) -> Result<(), EventNameError> {
    if logical.is_empty() {
        return Err(EventNameError::Malformed("empty event name".to_owned()));
    }

    for segment in logical.split('.') {
        if segment.is_empty() {
            return Err(EventNameError::Malformed(format!(
                "event name {logical:?} has an empty segment"
            )));
        }
        let valid = segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        if !valid {
            return Err(EventNameError::Malformed(format!(
                "event name {logical:?} has a character outside [A-Za-z0-9_-]"
            )));
        }
    }

    Ok(())
}

