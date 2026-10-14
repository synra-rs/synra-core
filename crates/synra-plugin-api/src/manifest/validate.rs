//! The rules a manifest must satisfy, and what each field means.
//!
//! # Why every rule is in one `impl` block
//!
//! Because the rules are a set: a manifest is valid when all of them hold, and read one at a time each can look redundant.
//! Keeping them together is what makes "is this field checked anywhere" answerable by reading one place.

use std::collections::HashSet;

use synra_capability::{Capability, Domain};

use super::error::ManifestError;
use super::types::{
    Manifest, ManifestContext, ValidationLevel, MANIFEST_SCHEMA,
    MAX_DESCRIPTION_LEN, MAX_NAME_LEN, MAX_TITLE_LEN,
};
use super::version::{check_plugin_id, check_version, compare_versions, to_wire_slug};


impl Manifest {
    /// Parses a manifest, rejecting anything the shape does not allow.
    ///
    /// Unknown fields are **refused**, like the wire protocol's envelopes and unlike the discovery datagrams.
    /// The reasoning is the same as for an envelope: a manifest is a contract the host enforces, and a field
    /// the host silently ignores is a field whose author believes it does something.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Malformed`] if the text does not match the shape.
    pub fn from_json(text: &str) -> Result<Self, ManifestError> {
        let mut manifest: Self =
            serde_json::from_str(text).map_err(|error| ManifestError::Malformed(error.to_string()))?;

        // The schema field is checked here rather than in `validate`, because it is about the *file* rather
        // than the plugin: a manifest that names a schema this build does not know may have fields whose
        // meaning changed, and the unknown-field rule above would not catch a field that kept its name.
        if let Some(schema) = &manifest.schema
            && schema != MANIFEST_SCHEMA
        {
            return Err(ManifestError::Malformed(format!(
                "the manifest names schema {schema:?}, and this build understands {MANIFEST_SCHEMA:?}"
            )));
        }
        // Normalised, so a later comparison does not have to remember that it is optional in the file.
        manifest.schema = Some(MANIFEST_SCHEMA.to_owned());
        Ok(manifest)
    }

    /// The wire slug this plugin's events live under.
    ///
    /// # Errors
    ///
    /// [`ManifestError::UnsluggedId`] for an id with no usable slug.
    pub fn wire_slug(&self) -> Result<String, ManifestError> {
        to_wire_slug(&self.id)
    }

    /// The event namespace this plugin owns, including the trailing dot.
    ///
    /// # Errors
    ///
    /// As [`Self::wire_slug`].
    pub fn event_namespace(&self) -> Result<String, ManifestError> {
        Ok(format!("_plugin.{}.", self.wire_slug()?))
    }

    /// The capabilities, compiled into a set.
    ///
    /// # Errors
    ///
    /// [`ManifestError::BadCapability`] for the first entry that does not parse, or a set error for a list
    /// that is too large.
    pub fn capability_set(&self) -> Result<synra_capability::CapabilitySet, ManifestError> {
        let mut set = synra_capability::CapabilitySet::new();
        for declaration in &self.capabilities {
            let parsed =
                Capability::parse(&declaration.cap).map_err(|source| ManifestError::BadCapability {
                    cap: declaration.cap.clone(),
                    source,
                })?;
            set.insert(parsed)
                .map_err(|error| ManifestError::Malformed(error.to_string()))?;
        }
        Ok(set)
    }

    /// Whether the plugin has a headless half.
    #[must_use]
    pub const fn is_headless(&self) -> bool {
        self.runtime.headless.is_some()
    }

    /// Whether the plugin has an interface half.
    #[must_use]
    pub const fn has_ui(&self) -> bool {
        self.runtime.ui.is_some()
    }

    /// Whether the plugin has both halves.
    #[must_use]
    pub const fn is_hybrid(&self) -> bool {
        self.is_headless() && self.has_ui()
    }

    /// The title in the reader's language, falling back to the default.
    ///
    /// A location is a language tag such as `zh-CN`. The fallback chain is exact match, then the primary
    /// subtag, then the default — so a manifest with only `zh-CN` still answers for `zh`.
    #[must_use]
    pub fn localised_title(&self, locale: &str) -> &str {
        self.localised("title", locale).unwrap_or(&self.title)
    }

    /// The description in the reader's language, falling back to the default.
    #[must_use]
    pub fn localised_description(&self, locale: &str) -> Option<&str> {
        self.localised("description", locale)
            .or(self.description.as_deref())
    }

    /// Looks a localised string up.
    ///
    /// The fallback chain is exact match, then the primary subtag, then nothing — and "nothing" is important:
    /// returning an empty string for a locale the manifest does not name would make a description disappear
    /// rather than fall back to the default.
    fn localised(&self, key: &str, locale: &str) -> Option<&str> {
        let locales = self.locales.as_ref()?;

        // The exact tag first, then the primary subtag so a manifest declaring `zh-CN` answers for
        // `zh-Hans-CN`. Built as a list rather than a chain of closures, because a closure returning a borrow
        // of `locales` has a lifetime the compiler cannot tie to `self`.
        let primary = locale.split(['-', '_']).next().unwrap_or(locale);
        let mut candidates: Vec<&str> = vec![locale];
        if primary != locale {
            candidates.push(primary);
        }

        candidates.into_iter().find_map(|tag| {
            locales
                .get(tag)
                .and_then(|entry| entry.as_object())
                .and_then(|entry| entry.get(key))
                .and_then(|value| value.as_str())
        })
    }

    /// Every check the manifest alone can be held to.
    ///
    /// # Errors
    ///
    /// The first [`ManifestError`] found.
    pub fn validate(&self, level: ValidationLevel, context: &ManifestContext) -> Result<(), ManifestError> {
        self.check_identity()?;
        self.check_runtime(context)?;
        let capabilities = self.check_capabilities()?;
        self.check_names()?;
        self.check_events()?;
        self.check_handles()?;
        self.check_network(&capabilities)?;
        self.check_pages()?;
        self.check_composition()?;
        self.check_size_limits()?;
        self.check_versions(context)?;

        if level >= ValidationLevel::Verify {
            self.check_implementation(context)?;
        }
        Ok(())
    }

    /// The id, the slug and the versions.
    fn check_identity(&self) -> Result<(), ManifestError> {
        check_plugin_id(self.id.as_str())?;
        self.wire_slug()?;
        check_version(&self.version)?;
        check_version(&self.sdk.min)?;
        if let Some(preferred) = &self.sdk.preferred {
            check_version(preferred)?;
        }
        Ok(())
    }

    /// The runtime's shape and its artifacts.
    fn check_runtime(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        if !self.is_headless() && !self.has_ui() {
            return Err(ManifestError::NoRuntime);
        }

        if let Some(present) = &context.present_artifacts {
            let check = |kind: &'static str, path: &str| {
                if present.iter().any(|artifact| artifact == path) {
                    Ok(())
                }
                else {
                    Err(ManifestError::MissingArtifact { kind, path: path.to_owned() })
                }
            };
            if let Some(headless) = &self.runtime.headless {
                check("headless", &headless.artifact)?;
            }
            if let Some(ui) = &self.runtime.ui {
                check("ui", &ui.artifact)?;
            }
        }

        if let Some(ui) = &self.runtime.ui
            && ui.entry.trim().is_empty()
        {
            return Err(ManifestError::Malformed(
                "the ui runtime declares an empty entry document".to_owned(),
            ));
        }
        Ok(())
    }

    /// The capabilities, and whether this kind of plugin can use them.
    fn check_capabilities(&self) -> Result<synra_capability::CapabilitySet, ManifestError> {
        let set = self.capability_set()?;

        for declaration in &self.capabilities {
            let capability = Capability::parse(&declaration.cap).map_err(|source| {
                ManifestError::BadCapability { cap: declaration.cap.clone(), source }
            })?;

            // A headless plugin has no interface, so a `ui:*` grant is one the user would approve at install
            // time and that nothing can ever exercise. The consent screen said something untrue.
            if !self.has_ui() && capability.domain() == Domain::Ui {
                return Err(ManifestError::UnusableCapability {
                    cap: declaration.cap.clone(),
                    kind: "headless",
                });
            }
        }
        Ok(set)
    }

    /// Names within the manifest.
    fn check_names(&self) -> Result<(), ManifestError> {
        let mut actions = HashSet::new();
        for action in &self.actions {
            if action.name.is_empty() {
                return Err(ManifestError::Malformed("an action has an empty name".to_owned()));
            }
            if !actions.insert(action.name.as_str()) {
                return Err(ManifestError::DuplicateName {
                    kind: "action",
                    name: action.name.clone(),
                });
            }
        }
        Ok(())
    }

    /// The event declarations and their payload schemas.
    fn check_events(&self) -> Result<(), ManifestError> {
        let namespace = self.event_namespace()?;
        let mut names = HashSet::new();

        for event in &self.events {
            if !names.insert(event.name.as_str()) {
                return Err(ManifestError::DuplicateName {
                    kind: "event",
                    name: event.name.clone(),
                });
            }

            // The namespace check is the one that stops a plugin emitting under another plugin's name. Without
            // it, a receiving side sees a legitimate name and routes it: one plugin impersonating another, with
            // nothing in any log to say so.
            if !event.name.starts_with(&namespace) || event.name.len() <= namespace.len() {
                return Err(ManifestError::ForeignEventNamespace {
                    name: event.name.clone(),
                    namespace,
                });
            }

            if let Some(payload) = &event.payload {
                check_payload_schema(&event.name, payload)?;
            }
        }
        Ok(())
    }

    /// The `handles` entries.
    fn check_handles(&self) -> Result<(), ManifestError> {
        let declared: HashSet<&str> = self.events.iter().map(|event| event.name.as_str()).collect();
        let namespace = self.event_namespace()?;

        for handle in &self.handles {
            // Four things an entry may be, and the order matters only for the message:
            //
            // 1. a known host event,
            // 2. one of this plugin's own declared names,
            // 3. a pattern in the host's namespace, which covers host events a newer build defines,
            // 4. a pattern in this plugin's own namespace, which is what a plugin uses to catch its own family.
            //
            // A pattern anywhere else is a subscription to a plugin that is not this one, or to a name that can
            // never exist — and a plugin that silently never receives anything is the hardest kind of bug to
            // find. `HandlePattern::parse` alone is not enough to tell: it validates the character class, so
            // `nonsense` is a legal pattern and a meaningless subscription.
            let entry = handle.event.as_str();
            let is_known_host_event = synra_protocol::event::builtin::ALL.contains(&entry)
                || synra_protocol::event::events::ALL.contains(&entry);
            let is_own_event = declared.contains(entry);
            let is_host_pattern =
                entry.starts_with(synra_protocol::event::SYSTEM_PREFIX) || entry.starts_with("device.");
            let is_own_pattern = entry.starts_with(&namespace);
            let is_legal_pattern = synra_protocol::inbound::HandlePattern::parse(entry).is_ok();

            let acceptable = is_known_host_event
                || is_own_event
                || ((is_host_pattern || is_own_pattern) && is_legal_pattern);

            if !acceptable {
                return Err(ManifestError::BadHandle { event: handle.event.clone() });
            }
        }
        Ok(())
    }

    /// Whether the network declaration and the network capabilities agree.
    ///
    /// The declaration exists so the consent screen can say "read from api.github.com" rather than "use the
    /// network". Two lists that disagree produce a screen showing one thing and a plugin holding another, which
    /// is worse than either list alone.
    fn check_network(
        &self,
        capabilities: &synra_capability::CapabilitySet,
    ) -> Result<(), ManifestError> {
        let declared_hosts: Vec<&str> = self
            .network
            .as_ref()
            .map(|network| network.outbound.iter().map(|host| host.host.as_str()).collect())
            .unwrap_or_default();

        // Every declared host must be covered by a `network:fetch:<host>` capability.
        for host in &declared_hosts {
            let capability = Capability::parse(&format!("network:fetch:{host}"));
            let covered = capability.map(|cap| capabilities.contains(&cap)).unwrap_or(false);
            if !covered {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "{host:?} is declared as reachable but no `network:fetch:{host}` capability backs it"
                    ),
                });
            }
        }

        // And every `network:fetch:<host>` capability must be described, unless it is a wildcard — a wildcard
        // has no finite description, which is exactly why the design document says the interface must spell it
        // out as "any website" rather than pretending otherwise.
        for capability in capabilities.iter() {
            if capability.domain() != Domain::Network {
                continue;
            }
            let resource = capability
                .prefixes()
                .first()
                .map(synra_capability::Segment::as_str)
                .unwrap_or_default();
            if resource != "fetch" {
                continue;
            }
            let Some(host) = capability.qualifier().first().map(synra_capability::Segment::as_str) else {
                continue;
            };
            if host.contains('*') {
                continue;
            }
            if !declared_hosts.contains(&host) {
                return Err(ManifestError::NetworkMismatch {
                    detail: format!(
                        "the capability `network:fetch:{host}` is declared but {host:?} is not in \
                         `network.outbound`"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Page keys.
    fn check_pages(&self) -> Result<(), ManifestError> {
        let mut keys = HashSet::new();
        for page in &self.pages {
            if !keys.insert(page.key.as_str()) {
                return Err(ManifestError::DuplicatePageKey { key: page.key.clone() });
            }
        }
        if self.pages.is_empty() {
            return Ok(());
        }
        // A headless plugin has no interface to put a page in.
        if !self.has_ui() {
            return Err(ManifestError::UnusableCapability {
                cap: "ui:page".to_owned(),
                kind: "headless",
            });
        }
        if let Some(default_page) = self.runtime.ui.as_ref().and_then(|ui| ui.default_page.as_deref())
            && !keys.contains(default_page)
        {
            return Err(ManifestError::Malformed(format!(
                "the default page {default_page:?} is not one of the declared pages"
            )));
        }
        Ok(())
    }

    /// Composition cycles.
    ///
    /// A plugin naming itself is the cycle that matters most, because it is the one an author writes by
    /// accident when copying a template. A cycle between two plugins is the loader's business, since it can see
    /// the whole set; this catches the part that is visible from one file.
    fn check_composition(&self) -> Result<(), ManifestError> {
        for dependency in &self.compose {
            if dependency.id == self.id {
                return Err(ManifestError::CompositionCycle {
                    through: vec![self.id.to_string()],
                });
            }
            check_version(dependency.version.trim_start_matches(['^', '~', '=', '>', '<', ' ']))?;
        }
        Ok(())
    }

    /// The length limits on strings that reach the interface.
    fn check_size_limits(&self) -> Result<(), ManifestError> {
        check_len("title", &self.title, MAX_TITLE_LEN)?;
        if let Some(description) = &self.description {
            check_len("description", description, MAX_DESCRIPTION_LEN)?;
        }
        for action in &self.actions {
            check_len("action name", &action.name, MAX_NAME_LEN)?;
        }
        for page in &self.pages {
            check_len("page title", &page.title, MAX_TITLE_LEN)?;
        }
        Ok(())
    }

    /// The SDK and WIT compatibility checks.
    fn check_versions(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        if let Some(host) = &context.host_sdk
            && compare_versions(&self.sdk.min, host)? == core::cmp::Ordering::Greater
        {
            return Err(ManifestError::SdkTooOld {
                min: self.sdk.min.clone(),
                host: host.clone(),
            });
        }
        if let Some(host_wit) = &context.host_wit
            && self.wit != *host_wit
        {
            return Err(ManifestError::WitMismatch {
                plugin: self.wit.clone(),
                host: host_wit.clone(),
            });
        }
        Ok(())
    }

    /// Whether the declarations and the implementation agree, in both directions.
    const fn check_implementation(&self, context: &ManifestContext) -> Result<(), ManifestError> {
        let Some(implementation) = context.implementation else {
            return Ok(());
        };

        if !self.handles.is_empty() && !implementation.on_event {
            return Err(ManifestError::MissingImplementation { declared: "`handles`" });
        }
        if self.handles.is_empty() && implementation.on_event {
            return Err(ManifestError::UndeclaredImplementation { implemented: "on_event" });
        }

        // An interface-only plugin's actions run in the interface, so `execute` is about the headless half.
        if !self.actions.is_empty() && self.is_headless() && !implementation.execute {
            return Err(ManifestError::MissingImplementation { declared: "`actions`" });
        }
        if self.actions.is_empty() && implementation.execute {
            return Err(ManifestError::UndeclaredImplementation { implemented: "execute" });
        }
        Ok(())
    }
}

/// Checks a string's length.
fn check_len(field: &'static str, value: &str, max: usize) -> Result<(), ManifestError> {
    let len = value.chars().count();
    if len > max {
        return Err(ManifestError::TooLong { field, len, max });
    }
    Ok(())
}

/// Checks an event's payload schema is one the host can enforce.
///
/// The rules are about what the *host* can do, not about JSON Schema in general. A payload is validated on
/// every inbound message, so the validator is deliberately small: no `$ref` to follow, no `format` needing a
/// library, no regex to run, and every bound a literal. A schema using something outside that subset is
/// refused rather than partially honoured, because a partial check is a promise the receiving side believes.
fn check_payload_schema(name: &str, payload: &serde_json::Value) -> Result<(), ManifestError> {
    let bad = |detail: &str| ManifestError::BadPayloadSchema {
        name: name.to_owned(),
        detail: detail.to_owned(),
    };

    let Some(object) = payload.as_object() else {
        return Err(bad("a payload schema must be a JSON object"));
    };

    // A top-level object, because a payload that is not an object cannot carry named fields and the wire
    // format's `payload` is an object everywhere else.
    match object.get("type").and_then(|value| value.as_str()) {
        Some("object") => {}
        Some(other) => return Err(bad(&format!("a payload schema must have type `object`, not {other:?}"))),
        None => {
            // `properties` without `type` is a common shorthand, and accepting it would mean two spellings of
            // one schema that the validator would have to keep in step.
            if object.contains_key("properties") {
                return Err(bad("a payload schema with `properties` must also say `type: object`"));
            }
            return Err(bad("a payload schema must say `type: object`"));
        }
    }

    walk_schema(&bad, payload, 0)?;
    Ok(())
}

/// Walks a schema, rejecting anything the host's validator cannot enforce.
fn walk_schema(bad: &impl Fn(&str) -> ManifestError, node: &serde_json::Value, depth: usize) -> Result<(), ManifestError> {
    // A schema is data, so it can be nested arbitrarily. Bounded because the loader walks it on every install
    // and a deeply nested one is either a mistake or an attempt to make the walk expensive.
    const MAX_DEPTH: usize = 16;
    if depth > MAX_DEPTH {
        return Err(bad(&format!("a payload schema nests deeper than {MAX_DEPTH} levels")));
    }

    match node {
        serde_json::Value::Object(object) => {
            for key in ["$ref", "format", "pattern", "patternProperties", "unevaluatedProperties"] {
                if object.contains_key(key) {
                    // `$ref` would need an external document, `format` a library, `pattern` a regex engine.
                    // Each is a validator the host does not have, so honouring the rest of the schema while
                    // ignoring it would be a partial check reported as a complete one.
                    return Err(bad(&format!("`{key}` is not supported in a payload schema")));
                }
            }

            // Numeric bounds must be literal numbers, so the validator never has to resolve anything.
            for key in ["maxLength", "minLength", "maximum", "minimum", "maxItems", "minItems"] {
                if let Some(value) = object.get(key)
                    && !value.is_number()
                {
                    return Err(bad(&format!("`{key}` must be a number")));
                }
            }

            // A string without a `maxLength` is a string whose length the host cannot bound, which makes it a
            // string the payload validator cannot promise anything about.
            if object.get("type").and_then(|value| value.as_str()) == Some("string")
                && !object.contains_key("maxLength")
            {
                return Err(bad("a string property must declare `maxLength`"));
            }

            for (key, value) in object {
                walk_schema(bad, value, depth + 1)?;
                let _ = key;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk_schema(bad, item, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
