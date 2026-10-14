use std::collections::BTreeMap;

use serde_json::Value;

use super::{ConfigError, Setting, SettingKey};

/// The settings a build knows about.
///
/// # Why an empty catalogue is a legitimate one
///
/// The kernel's settings are the screens' business, so this build registers none and every value lives as an override.
/// What the catalogue adds when it is not empty is *checking*: a value of the wrong shape, or a write to a key the
/// kernel computes, is refused here rather than discovered by the screen that reads it.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    settings: BTreeMap<SettingKey, Setting>,
}

impl Catalog {
    /// A catalogue with no settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a setting.
    ///
    /// A key that is already registered is **replaced**, which is what a build that overrides a default wants. It is
    /// not an error because the caller is the kernel's own composition code, where a duplicate is a mistake the compiler
    /// would catch if the settings were fields.
    pub fn register(&mut self, setting: Setting) -> &mut Self {
        self.settings.insert(setting.key.clone(), setting);
        self
    }

    /// A setting by key.
    #[must_use]
    pub fn get(&self, key: &SettingKey) -> Option<&Setting> {
        self.settings.get(key)
    }

    /// Every setting, in key order.
    pub fn iter(&self) -> impl Iterator<Item = &Setting> {
        self.settings.values()
    }

    /// How many settings are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.settings.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }

    /// Checks a value against the setting, when the catalogue knows the key.
    ///
    /// # Errors
    ///
    /// Whatever [`Setting::check`] says. An unknown key is **accepted**: the catalogue is the kernel's knowledge and not
    /// a whitelist, and refusing an unknown key would mean an interface could not add a setting without a kernel release
    /// — which is the coupling this module exists to avoid.
    pub fn check(&self, key: &SettingKey, value: &Value) -> Result<(), ConfigError> {
        match self.settings.get(key) {
            Some(setting) => setting.check(value),
            None => Ok(()),
        }
    }
}
