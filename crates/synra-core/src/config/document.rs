use std::collections::BTreeMap;

use serde_json::Value;

use crate::config::setting::describe;

use super::{Catalog, ConfigError, ConfigSnapshot, SettingKey};

/// The settings' values: defaults, overrides, and which is which.
///
/// # The one invariant
///
/// **Every key in `overrides` is a key a caller wrote, and every key a caller wrote is in `overrides`.** That is what
/// makes "reset this setting" and "mark this as changed" answerable, and it is why `unset` removes rather than writing
/// the default: a key present with the default's value is a setting the user set to the default, which is a different
/// thing and must keep being marked.
#[derive(Debug, Clone, Default)]
pub struct Config {
    overrides: BTreeMap<SettingKey, Value>,
    catalog: Catalog,
}

impl Config {
    /// A configuration with no overrides, so every value is its default.
    #[must_use]
    pub const fn new(catalog: Catalog) -> Self {
        Self { overrides: BTreeMap::new(), catalog }
    }

    /// What this configuration knows about settings.
    #[must_use]
    pub const fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// How many keys the user has set.
    #[must_use]
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }

    /// Whether the user has set anything.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.overrides.is_empty()
    }

    /// The value of a setting: the override when there is one, the default otherwise.
    #[must_use]
    pub fn get(&self, key: &SettingKey) -> Option<&Value> {
        self.overrides
            .get(key)
            .or_else(|| self.catalog.get(key).map(|setting| &setting.default))
    }

    /// Whether a key came from an override rather than a default.
    ///
    /// # Why a key with no value is not overridden
    ///
    /// A key the catalogue does not know and no caller has written has no value and is not overridden. Answering `true`
    /// for it would make a settings screen mark a row the user has never seen.
    #[must_use]
    pub fn is_overridden(&self, key: &SettingKey) -> bool {
        self.overrides.contains_key(key)
    }

    /// Every key the user has set, in key order.
    pub fn overridden(&self) -> impl Iterator<Item = &SettingKey> {
        self.overrides.keys()
    }

    /// Every value, defaults included, as the bag the boundary carries.
    ///
    /// # Why the defaults are filled in
    ///
    /// A screen that had to know each default would be a second copy of the catalogue, and the two would disagree at
    /// the first change. The bag carries what every value *is*, and [`Config::overridden`] carries which of them the
    /// user chose.
    #[must_use]
    pub fn values(&self) -> Value {
        let mut out = serde_json::Map::new();
        for setting in self.catalog.iter() {
            out.insert(
                setting.key.as_str().to_owned(),
                self.overrides
                    .get(&setting.key)
                    .cloned()
                    .unwrap_or_else(|| setting.default.clone()),
            );
        }
        // Overrides for keys the catalogue does not know: an interface's own settings. They are the reason the boundary
        // is a bag, so they have to survive this.
        for (key, value) in &self.overrides {
            out.insert(key.as_str().to_owned(), value.clone());
        }
        Value::Object(out)
    }

    /// Applies a patch, checking every key before writing any.
    ///
    /// # Why the check is a pass of its own
    ///
    /// A patch that wrote three keys and failed on the fourth would leave the configuration in a state no caller asked
    /// for, and the caller — which received an error — has no way to know how far it got. So the check runs over the
    /// whole patch first, and a patch that fails changes nothing.
    ///
    /// # Errors
    ///
    /// [`ConfigError::SetAndUnset`], [`ConfigError::BadKey`] for a malformed key, or whatever the catalogue says about
    /// a value.
    pub fn apply(&mut self, set: &[(SettingKey, Value)], unset: &[SettingKey]) -> Result<usize, ConfigError> {
        for key in unset {
            if set.iter().any(|(candidate, _)| candidate == key) {
                return Err(ConfigError::SetAndUnset { key: key.as_str().to_owned() });
            }
        }
        for (key, value) in set {
            self.catalog.check(key, value)?;
        }

        let mut changed = 0usize;
        for key in unset {
            if self.overrides.remove(key).is_some() {
                changed += 1;
            }
        }
        for (key, value) in set {
            // Counted only when the value actually differs: a patch that writes the value a key already has is a no-op,
            // and reporting it as a change would make a screen show a save that did nothing.
            if self.overrides.get(key) != Some(value) {
                changed += 1;
            }
            self.overrides.insert(key.clone(), value.clone());
        }
        Ok(changed)
    }

    /// The snapshot the boundary carries.
    #[must_use]
    pub fn snapshot(&self) -> ConfigSnapshot {
        ConfigSnapshot {
            values: self.values(),
            overridden: self.overridden().map(ToString::to_string).collect(),
        }
    }

    /// Reads a configuration file's object into overrides.
    ///
    /// # What is kept and what is refused
    ///
    /// A key the catalogue does not know is **kept**: it is an interface's own setting, or one a newer kernel wrote and
    /// this one is too old to understand — and dropping it would make opening a config in an older build lose settings.
    ///
    /// A value that fails the catalogue is **refused**, with the key named. Keeping it would mean a screen rendering a
    /// value the kernel cannot use, and the user seeing a setting that appears set and has no effect.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Unreadable`] for text that is not JSON, [`ConfigError::NotAnObject`] for JSON that is not an
    /// object, and [`ConfigError::BadKey`] for a key or value the configuration refuses.
    pub fn load_json(&mut self, text: &str) -> Result<usize, ConfigError> {
        let parsed: Value = serde_json::from_str(text).map_err(|error| ConfigError::Unreadable {
            why: error.to_string(),
        })?;
        self.load_value(parsed)
    }

    /// The same, from a parsed value.
    ///
    /// # Errors
    ///
    /// As [`Config::load_json`], minus the parse.
    pub fn load_value(&mut self, parsed: Value) -> Result<usize, ConfigError> {
        let Value::Object(map) = parsed else {
            return Err(ConfigError::NotAnObject { found: describe(&parsed) });
        };

        // Checked first, so a file that fails partway through does not leave the configuration half-loaded — the same
        // reasoning as `apply`.
        let entries: Vec<(SettingKey, Value)> = map
            .into_iter()
            .map(|(key, value)| Ok((SettingKey::parse(&key)?, value)))
            .collect::<Result<_, ConfigError>>()?;
        for (key, value) in &entries {
            self.catalog.check(key, value)?;
        }

        let count = entries.len();
        self.overrides.extend(entries);
        Ok(count)
    }

    /// The file's text for this configuration.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Unreadable`] when the values cannot be serialised, which happens only for a value a `Value` cannot
    /// hold — a number out of range, for instance.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        let mut map = serde_json::Map::new();
        for (key, value) in &self.overrides {
            map.insert(key.as_str().to_owned(), value.clone());
        }
        let mut text =
            serde_json::to_string_pretty(&Value::Object(map)).map_err(|error| {
                ConfigError::Unreadable { why: error.to_string() }
            })?;
        text.push('\n');
        Ok(text)
    }

    /// Forgets every override, returning the configuration to its defaults.
    ///
    /// Reports how many keys were forgotten, so a screen can say what a reset did rather than only that it happened.
    pub fn reset(&mut self) -> usize {
        let count = self.overrides.len();
        self.overrides.clear();
        count
    }
}
