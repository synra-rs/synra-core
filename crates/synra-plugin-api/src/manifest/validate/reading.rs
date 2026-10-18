use synra_capability::Capability;

use crate::manifest::error::ManifestError;
use crate::manifest::types::{Manifest, MANIFEST_SCHEMA};
use crate::manifest::version::to_wire_slug;

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

        // ★ Legacy capability spellings, corrected where the text enters the kernel.
        //
        // The generated contract has always required `platform:read-clipboard` / `platform:write-clipboard`, while this
        // workspace's documentation used `platform:clipboard:read` / `platform:clipboard:write`. A manifest written from
        // the documentation therefore declared a permission the gate never checked. Correcting it here means the
        // consent prompt, the grant row and the gate all speak one name; teaching the matcher both would make the old
        // spelling permanent instead.
        for declared in &mut manifest.capabilities {
            if let Some(canonical) = synra_capability::canonical_spelling(&declared.cap) {
                declared.cap = canonical.to_owned();
            }
        }
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
}
