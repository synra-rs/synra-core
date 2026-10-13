//! The settings, as a bag of named values with tracked defaults.
//!
//! # Why a bag rather than a struct
//!
//! The design document is explicit about this, and the reason is worth restating because a struct is what most kernels
//! reach for: **a `synra-core` release must not force an interface release.** A struct of settings here means every
//! feature that adds a setting adds a field, and every field is a version of this crate that every interface has to be
//! rebuilt against. So the boundary carries a bag of `serde_json::Value` keyed by a dotted path, and the *screens* own
//! their own shape — which is where the knowledge of what a setting means actually lives.
//!
//! # What this module is for, then
//!
//! Three things a bag alone does not give:
//!
//! 1. **Defaults that survive.** A setting the user has never touched is not the same as one they set to the default
//!    value, and the difference is what a settings screen marks as changed and what a "reset" button restores. So the
//!    defaults are the input and the overrides are the state.
//! 2. **A patch that applies atomically.** Two screens can be open, and a whole-value write from one discards the
//!    other's change. A patch names the keys it touches, and either every key in it applies or none does.
//! 3. **A file that is read but not trusted.** A configuration file is written by a person and by a previous version of
//!    this kernel. A value it carries for a key this build does not know is *kept* rather than dropped — dropping it
//!    would make opening an old config in a new kernel silently lose settings the old one had — and a file that cannot
//!    be parsed at all is a refusal rather than an empty configuration, because the second is indistinguishable from
//!    "the user wants everything at its default".
//!
//! # Why `unset` and `set` in one patch is refused
//!
//! [`synra_ipc`]'s `ConfigPatch` already refuses it, and this repeats the refusal because the two are different
//! boundaries: a patch can reach this module from a file or from the daemon's own command line, not only over IPC. A
//! caller that named a key in both meant one of the two, and picking for them produces a setting that is the opposite
//! of what they asked for half the time.

use std::collections::BTreeMap;

use serde_json::Value;

/// A dotted path to a setting, such as `transfer.maxConcurrent`.
///
/// Validated on the way in, because the failure a malformed key produces is silent: a patch that writes
/// `transfer..maxConcurrent` creates a second key that no screen reads, and the setting the user changed stays at its
/// default while the config file grows a line nobody can explain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettingKey(String);

impl SettingKey {
    /// Checks a key.
    ///
    /// # The three rules, and what each prevents
    ///
    /// * **Non-empty.** An empty key is one that every lookup with a missing key would find.
    /// * **No empty segment.** A double dot is two different keys spelled almost the same, and only one of them is the
    ///   one a screen reads.
    /// * **No leading or trailing dot.** A leading dot makes `.a` and `a` distinct keys for the same setting, which is
    ///   a patch that writes the wrong one and reports success.
    ///
    /// # Errors
    ///
    /// [`ConfigError::BadKey`], which names the rule that failed.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let bad = |why: &str| Err(ConfigError::BadKey { key: text.to_owned(), why: why.to_owned() });

        if text.is_empty() {
            return bad("it is empty");
        }
        if text.starts_with('.') || text.ends_with('.') {
            return bad("it starts or ends with a dot");
        }
        if text.split('.').any(str::is_empty) {
            return bad("it has an empty segment, which is a second key for the same setting");
        }
        if text.chars().any(char::is_whitespace) {
            return bad("it contains whitespace");
        }
        Ok(Self(text.to_owned()))
    }

    /// The key's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The last segment, which is the setting's own name.
    ///
    /// For a screen that groups by the first segment and labels by the last.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    /// The segments before the last, which is the group.
    ///
    /// `None` for a top-level key rather than an empty string: a setting with no group and a setting in a group named
    /// by the empty string are different, and only one of them is representable.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        self.0.rfind('.').map(|at| &self.0[..at])
    }
}

impl std::fmt::Display for SettingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for SettingKey {
    type Err = ConfigError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Why a configuration operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A key is not a dotted path.
    #[error("`{key}` is not a setting key: {why}")]
    BadKey {
        /// The key.
        key: String,
        /// Which rule it broke.
        why: String,
    },

    /// A patch names a key in both `set` and `unset`.
    #[error("`{key}` is both set and unset in one patch")]
    SetAndUnset {
        /// The key.
        key: String,
    },

    /// A configuration file could not be read as JSON.
    #[error("the configuration file is not readable: {why}")]
    Unreadable {
        /// What the parser said.
        why: String,
    },

    /// A configuration file's top level is not an object.
    #[error("the configuration file holds {found}, not an object of settings")]
    NotAnObject {
        /// What it held instead.
        found: &'static str,
    },

    /// A key is reserved and may not be written by a caller.
    #[error("`{key}` is reserved: {why}")]
    Reserved {
        /// The key.
        key: String,
        /// Why it is reserved.
        why: &'static str,
    },
}

/// What a setting's value is, for the screens that have to render it.
///
/// # Why the kernel names the type at all
///
/// Because a settings screen has to choose a control, and it cannot choose one from `serde_json::Value` alone — `1`
/// could be a toggle in a different spelling, a count, or a duration. Naming the type here means the screen renders the
/// right control from data rather than from a table of key names that drifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SettingKind {
    /// On or off.
    Bool,
    /// A whole number.
    Integer,
    /// A number that may have a fraction.
    Number,
    /// Text.
    Text,
    /// One of a fixed set of strings.
    Choice,
    /// A list of strings.
    TextList,
}

impl SettingKind {
    /// The name, for a report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Text => "text",
            Self::Choice => "choice",
            Self::TextList => "textList",
        }
    }

    /// Whether a value is of this kind.
    #[must_use]
    pub fn matches(self, value: &Value) -> bool {
        match self {
            Self::Bool => value.is_boolean(),
            // A float that happens to be whole is not an integer: `1.0` stored where an integer is expected is a value
            // that compares unequal to `1` in some languages and equal in others, which is exactly the ambiguity a
            // typed setting exists to remove.
            Self::Integer => value.is_i64() || value.is_u64(),
            Self::Number => value.is_number(),
            Self::Text | Self::Choice => value.is_string(),
            Self::TextList => {
                value.as_array().is_some_and(|items| items.iter().all(Value::is_string))
            }
        }
    }
}

/// One setting the kernel knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// Its dotted path.
    pub key: SettingKey,
    /// What its values look like.
    pub kind: SettingKind,
    /// The value it has when the user has not set it.
    pub default: Value,
    /// What it does, for the settings screen.
    pub description: String,
    /// Whether a caller may write it.
    ///
    /// Reserved for settings the kernel computes — a last-used version, a resolved path — where a write would be a
    /// value the kernel overwrites at the next start, so the user's change appears to work and then silently does not.
    pub reserved: bool,
}

impl Setting {
    /// A writable setting.
    ///
    /// # Errors
    ///
    /// [`ConfigError::BadKey`] when the key is not a dotted path, which is refused here rather than at the first write
    /// because a malformed key in the catalogue is a setting no screen can reach.
    pub fn new(
        key: &str,
        kind: SettingKind,
        default: Value,
        description: &str,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            key: SettingKey::parse(key)?,
            kind,
            default,
            description: description.to_owned(),
            reserved: false,
        })
    }

    /// A setting a caller may not write.
    #[must_use]
    pub const fn reserved(mut self) -> Self {
        self.reserved = true;
        self
    }

    /// Whether a value is acceptable for this setting.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Reserved`] for a reserved setting, and a description of the mismatch otherwise — as a
    /// [`ConfigError::BadKey`] whose `why` says what was expected, because that is the error variant that already
    /// carries "this key, and here is what is wrong with it".
    pub fn check(&self, value: &Value) -> Result<(), ConfigError> {
        if self.reserved {
            return Err(ConfigError::Reserved {
                key: self.key.as_str().to_owned(),
                why: "the kernel computes it, so a write would be overwritten at the next start",
            });
        }
        if !self.kind.matches(value) {
            return Err(ConfigError::BadKey {
                key: self.key.as_str().to_owned(),
                why: format!("expected {}, found {}", self.kind.as_str(), describe(value)),
            });
        }
        Ok(())
    }
}

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

/// The bag and the list, as the boundary carries them.
///
/// # Why this is a second type rather than the IPC one
///
/// `synra-ipc`'s `ConfigSnapshot` is the *wire* shape and carries serde attributes that belong to the wire — camelCase
/// field names, omitted empty lists. This is what the kernel computes, and the daemon maps one to the other. Sharing
/// one type would put the wire's serialisation decisions inside the kernel and make a protocol change a kernel change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    /// Every setting, defaults filled in, keyed by its dotted path.
    pub values: Value,
    /// Which keys came from an override rather than a default.
    pub overridden: Vec<String>,
}

/// A word for what a JSON value is, for a message.
fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "an integer",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(text: &str) -> SettingKey {
        SettingKey::parse(text).expect("a valid key")
    }

    fn catalog() -> Catalog {
        let mut catalog = Catalog::new();
        catalog
            .register(
                Setting::new("transfer.maxConcurrent", SettingKind::Integer, json!(2), "how many at once")
                    .expect("a valid setting"),
            )
            .register(
                Setting::new("transfer.resume", SettingKind::Bool, json!(true), "continue a broken transfer")
                    .expect("a valid setting"),
            )
            .register(
                Setting::new("ui.locale", SettingKind::Text, json!("en"), "the language")
                    .expect("a valid setting"),
            )
            .register(
                Setting::new("internal.schemaVersion", SettingKind::Integer, json!(1), "written by the kernel")
                    .expect("a valid setting")
                    .reserved(),
            );
        catalog
    }

    // ── Keys ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_key_is_a_dotted_path() {
        let parsed = key("transfer.maxConcurrent");
        assert_eq!(parsed.as_str(), "transfer.maxConcurrent");
        assert_eq!(parsed.name(), "maxConcurrent");
        assert_eq!(parsed.group(), Some("transfer"));
        assert_eq!(key("darkMode").name(), "darkMode");
    }

    #[test]
    fn a_top_level_key_has_no_group_rather_than_an_empty_one() {
        // `None` and `Some("")` are different: a setting with no group and one in a group named by the empty string are
        // not the same thing, and only one of them is representable.
        assert_eq!(key("darkMode").group(), None);
    }

    #[test]
    fn a_malformed_key_is_refused_with_the_rule_it_broke() {
        // ★ The failure a malformed key produces is silent: a patch that writes `transfer..maxConcurrent` creates a
        // second key that no screen reads, and the setting the user changed stays at its default while the config file
        // grows a line nobody can explain.
        for (text, expected) in [
            ("", "empty"),
            (".leading", "starts or ends"),
            ("trailing.", "starts or ends"),
            ("two..dots", "empty segment"),
            ("has space", "whitespace"),
        ] {
            match SettingKey::parse(text) {
                Err(ConfigError::BadKey { why, .. }) => {
                    assert!(why.contains(expected), "`{text}` gave `{why}`");
                }
                other => panic!("`{text}` was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn a_single_segment_key_is_allowed() {
        // The bag is open, and an interface's own top-level setting is not a mistake.
        assert!(SettingKey::parse("darkMode").is_ok());
        assert!(SettingKey::parse("a.b.c.d").is_ok());
    }

    #[test]
    fn a_key_parses_through_from_str() {
        // So a caller can write `let key: SettingKey = text.parse()?` and get the same validation.
        let parsed: SettingKey = "ui.locale".parse().expect("a valid key");
        assert_eq!(parsed, key("ui.locale"));
        assert!("ui..locale".parse::<SettingKey>().is_err());
    }

    // ── Kinds ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_whole_float_is_not_an_integer() {
        // ★ `1.0` stored where an integer is expected is a value that compares unequal to `1` in some languages and
        // equal in others — exactly the ambiguity a typed setting exists to remove.
        assert!(SettingKind::Integer.matches(&json!(1)));
        assert!(!SettingKind::Integer.matches(&json!(1.0)));
        assert!(SettingKind::Number.matches(&json!(1.0)));
        assert!(SettingKind::Number.matches(&json!(1)));
    }

    #[test]
    fn each_kind_accepts_what_it_names_and_refuses_the_rest() {
        assert!(SettingKind::Bool.matches(&json!(true)));
        assert!(!SettingKind::Bool.matches(&json!(1)));
        assert!(SettingKind::Text.matches(&json!("x")));
        assert!(!SettingKind::Text.matches(&json!(1)));
        assert!(SettingKind::Choice.matches(&json!("a")));
        assert!(SettingKind::TextList.matches(&json!(["a", "b"])));
        assert!(SettingKind::TextList.matches(&json!([])));
        // A list with one non-string is not a text list: the screen would render it as one and the value would fail
        // wherever it was used.
        assert!(!SettingKind::TextList.matches(&json!(["a", 1])));
        assert!(!SettingKind::TextList.matches(&json!("a")));
    }

    #[test]
    fn every_kind_has_a_name_for_a_report() {
        let kinds = [
            SettingKind::Bool,
            SettingKind::Integer,
            SettingKind::Number,
            SettingKind::Text,
            SettingKind::Choice,
            SettingKind::TextList,
        ];
        let mut names: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), kinds.len(), "a kind name repeats");
        for name in names {
            assert!(!name.is_empty());
        }
    }

    // ── Defaults and overrides ────────────────────────────────────────────────────────────────────

    #[test]
    fn a_setting_the_user_has_not_touched_reads_as_its_default() {
        let config = Config::new(catalog());
        assert_eq!(config.get(&key("transfer.maxConcurrent")), Some(&json!(2)));
        assert!(!config.is_overridden(&key("transfer.maxConcurrent")));
        assert!(config.is_default());
    }

    #[test]
    fn setting_a_value_to_its_default_still_counts_as_overridden() {
        // ★ The distinction the whole module is for. A setting the user has never touched is not the same as one they
        // set to the default value: the first is unmarked in a settings screen and restored by nothing, the second is
        // marked as changed and restored by a reset.
        let mut config = Config::new(catalog());
        config
            .apply(&[(key("transfer.maxConcurrent"), json!(2))], &[])
            .expect("apply");

        assert!(config.is_overridden(&key("transfer.maxConcurrent")));
        assert_eq!(config.get(&key("transfer.maxConcurrent")), Some(&json!(2)));
        assert!(!config.is_default());
    }

    #[test]
    fn unsetting_removes_the_override_rather_than_writing_the_default() {
        // Writing the default would leave the key overridden, so a reset would not reset it and the screen would keep
        // showing it as changed.
        let mut config = Config::new(catalog());
        config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("set");
        let changed = config.apply(&[], &[key("ui.locale")]).expect("unset");

        assert_eq!(changed, 1);
        assert!(!config.is_overridden(&key("ui.locale")));
        assert_eq!(config.get(&key("ui.locale")), Some(&json!("en")));
    }

    #[test]
    fn a_key_the_catalogue_does_not_know_lives_as_an_override() {
        // ★ The reason the boundary is a bag: an interface adds a setting without a kernel release. A catalogue that
        // whitelisted would refuse this, and every new setting would need a kernel version.
        let mut config = Config::new(catalog());
        config
            .apply(&[(key("companion.showAvatar"), json!(false))], &[])
            .expect("apply");

        assert_eq!(config.get(&key("companion.showAvatar")), Some(&json!(false)));
        assert!(config.is_overridden(&key("companion.showAvatar")));
        // And it survives into the bag, which is what the interface reads.
        let values = config.values();
        assert_eq!(values["companion.showAvatar"], json!(false));
    }

    #[test]
    fn the_bag_carries_the_defaults_as_well_as_the_overrides() {
        // A screen that had to know each default would be a second copy of the catalogue, and the two would disagree at
        // the first change.
        let mut config = Config::new(catalog());
        config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply");

        let values = config.values();
        assert_eq!(values["ui.locale"], json!("zh"));
        assert_eq!(values["transfer.maxConcurrent"], json!(2));
        assert_eq!(values["transfer.resume"], json!(true));
    }

    #[test]
    fn the_snapshot_says_which_keys_the_user_chose() {
        let mut config = Config::new(catalog());
        config
            .apply(&[(key("ui.locale"), json!("zh")), (key("transfer.resume"), json!(false))], &[])
            .expect("apply");

        let snapshot = config.snapshot();
        assert_eq!(snapshot.overridden, vec!["transfer.resume", "ui.locale"]);
        assert_eq!(snapshot.values["transfer.resume"], json!(false));
    }

    #[test]
    fn an_unknown_key_is_not_overridden() {
        // Answering `true` for a key nothing has written would make a settings screen mark a row the user has never
        // seen.
        let config = Config::new(catalog());
        assert!(!config.is_overridden(&key("nobody.setThis")));
        assert_eq!(config.get(&key("nobody.setThis")), None);
    }

    // ── Patches ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_patch_that_names_a_key_twice_is_refused() {
        // ★ A caller that named a key in both `set` and `unset` meant one of the two, and picking for them produces a
        // setting that is the opposite of what they asked for half the time.
        let mut config = Config::new(catalog());
        match config.apply(&[(key("ui.locale"), json!("zh"))], &[key("ui.locale")]) {
            Err(ConfigError::SetAndUnset { key: reported }) => assert_eq!(reported, "ui.locale"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And nothing was written.
        assert!(!config.is_overridden(&key("ui.locale")));
    }

    #[test]
    fn a_patch_with_a_bad_value_changes_nothing_at_all() {
        // ★ A patch that wrote three keys and failed on the fourth would leave the configuration in a state no caller
        // asked for, and the caller — which received an error — has no way to know how far it got.
        let mut config = Config::new(catalog());
        let result = config.apply(
            &[
                (key("ui.locale"), json!("zh")),
                (key("transfer.maxConcurrent"), json!("lots")),
            ],
            &[],
        );

        assert!(result.is_err(), "{result:?}");
        // The good key was not written either.
        assert!(!config.is_overridden(&key("ui.locale")));
        assert!(config.is_default());
    }

    #[test]
    fn a_patch_reports_only_the_keys_it_actually_changed() {
        // A patch that writes the value a key already has is a no-op, and reporting it as a change would make a screen
        // show a save that did nothing.
        let mut config = Config::new(catalog());
        assert_eq!(
            config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply"),
            1
        );
        assert_eq!(
            config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply"),
            0
        );
        assert_eq!(
            config.apply(&[(key("ui.locale"), json!("en"))], &[]).expect("apply"),
            1
        );
    }

    #[test]
    fn unsetting_a_key_that_was_never_set_changes_nothing() {
        // A reset button pressed twice, and a screen that reported a change the second time would be lying.
        let mut config = Config::new(catalog());
        assert_eq!(config.apply(&[], &[key("ui.locale")]).expect("unset"), 0);
    }

    #[test]
    fn a_reserved_setting_cannot_be_written() {
        // ★ A reserved setting is one the kernel computes, so a write would be a value the kernel overwrites at the next
        // start — the user's change appears to work and then silently does not.
        let mut config = Config::new(catalog());
        match config.apply(&[(key("internal.schemaVersion"), json!(99))], &[]) {
            Err(ConfigError::Reserved { key: reported, why }) => {
                assert_eq!(reported, "internal.schemaVersion");
                assert!(why.contains("overwritten"), "{why}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And unsetting it is allowed: removing a write nobody should have made is not a write.
        assert!(config.apply(&[], &[key("internal.schemaVersion")]).is_ok());
    }

    // ── Files ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_file_round_trips_through_the_text() {
        let mut config = Config::new(catalog());
        config
            .apply(
                &[(key("ui.locale"), json!("zh")), (key("companion.showAvatar"), json!(false))],
                &[],
            )
            .expect("apply");

        let text = config.to_json().expect("serialise");
        let mut reloaded = Config::new(catalog());
        assert_eq!(reloaded.load_json(&text).expect("load"), 2);
        assert_eq!(reloaded.get(&key("ui.locale")), Some(&json!("zh")));
        assert_eq!(reloaded.get(&key("companion.showAvatar")), Some(&json!(false)));
    }

    #[test]
    fn a_file_keeps_a_key_this_build_does_not_know() {
        // ★ Dropping it would make opening a config in an older build lose settings — and an interface's own setting is
        // exactly one this build does not know.
        let mut config = Config::new(catalog());
        config
            .load_json(r#"{"companion.showAvatar": true, "future.setting": [1, 2]}"#)
            .expect("load");

        let values = config.values();
        assert_eq!(values["companion.showAvatar"], json!(true));
        assert_eq!(values["future.setting"], json!([1, 2]));
        assert_eq!(config.override_count(), 2);
    }

    #[test]
    fn a_value_the_catalogue_refuses_stops_the_whole_file() {
        // ★ Keeping it would mean a screen rendering a value the kernel cannot use, and the user seeing a setting that
        // appears set and has no effect.
        let mut config = Config::new(catalog());
        let result = config.load_json(r#"{"ui.locale": "zh", "transfer.resume": "yes"}"#);
        assert!(result.is_err(), "{result:?}");
        // The good key was not written either — the same all-or-nothing rule as a patch.
        assert!(config.is_default());
    }

    #[test]
    fn a_file_that_is_not_json_is_refused_rather_than_treated_as_empty() {
        // ★ An empty configuration is indistinguishable from "the user wants everything at its default", so a file that
        // failed to parse would silently reset every setting the user had chosen.
        let mut config = Config::new(catalog());
        assert!(matches!(
            config.load_json("{ not json"),
            Err(ConfigError::Unreadable { .. })
        ));
        assert!(config.is_default());
    }

    #[test]
    fn a_file_whose_top_level_is_not_an_object_is_refused() {
        // A list or a string at the top level is a file that something else wrote, and reading it as settings would
        // produce one key named after the whole document.
        let mut config = Config::new(catalog());
        for text in ["[1, 2]", "\"text\"", "42", "null"] {
            match config.load_json(text) {
                Err(ConfigError::NotAnObject { found }) => assert!(!found.is_empty(), "{text}"),
                other => panic!("`{text}` was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn a_file_with_a_malformed_key_is_refused() {
        // The same rule as a patch: a second key for the same setting is one no screen reads.
        let mut config = Config::new(catalog());
        assert!(matches!(
            config.load_json(r#"{"transfer..maxConcurrent": 3}"#),
            Err(ConfigError::BadKey { .. })
        ));
    }

    #[test]
    fn an_empty_file_is_a_configuration_at_its_defaults() {
        // `{}` is a legitimate file: a user who has chosen nothing.
        let mut config = Config::new(catalog());
        assert_eq!(config.load_json("{}").expect("load"), 0);
        assert!(config.is_default());
        assert_eq!(config.get(&key("ui.locale")), Some(&json!("en")));
    }

    #[test]
    fn the_written_file_holds_only_the_overrides() {
        // ★ Not the defaults. A file that wrote every default would turn "the user has chosen nothing" into "the user
        // has chosen every value", so a default changed in a later version would never reach an existing user.
        let mut config = Config::new(catalog());
        config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply");

        let text = config.to_json().expect("serialise");
        assert!(text.contains("ui.locale"), "{text}");
        assert!(!text.contains("transfer.maxConcurrent"), "{text}");
        assert!(!text.contains("transfer.resume"), "{text}");
        // And it ends with a newline, because a file a person may edit should not be a diff waiting to happen.
        assert!(text.ends_with('\n'), "{text:?}");
    }

    #[test]
    fn loading_a_file_replaces_the_previous_overrides_for_its_keys() {
        // A file is the whole of what the user chose, so a key it carries wins over what was loaded before.
        let mut config = Config::new(catalog());
        config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply");
        config.load_json(r#"{"ui.locale": "fr"}"#).expect("load");
        assert_eq!(config.get(&key("ui.locale")), Some(&json!("fr")));
        assert_eq!(config.override_count(), 1);
    }

    #[test]
    fn a_reset_forgets_everything_and_says_how_much() {
        let mut config = Config::new(catalog());
        config
            .apply(&[(key("ui.locale"), json!("zh")), (key("a.b"), json!(1))], &[])
            .expect("apply");
        assert_eq!(config.reset(), 2);
        assert!(config.is_default());
        assert_eq!(config.get(&key("ui.locale")), Some(&json!("en")));
        // And a second reset reports nothing, because there was nothing to forget.
        assert_eq!(config.reset(), 0);
    }

    // ── The catalogue ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_catalogue_accepts_everything() {
        // ★ The kernel's settings are the screens' business, so this build registers none and every value lives as an
        // override. A catalogue that whitelisted would mean an interface could not add a setting without a kernel
        // release — which is the coupling this module exists to avoid.
        let mut config = Config::new(Catalog::new());
        config
            .apply(&[(key("anything.atAll"), json!({"nested": true}))], &[])
            .expect("apply");
        assert_eq!(config.get(&key("anything.atAll")), Some(&json!({"nested": true})));
    }

    #[test]
    fn the_catalogue_is_iterable_in_key_order() {
        // A settings screen renders the rows in the catalogue's order, and two renders have to agree.
        let catalog = catalog();
        assert_eq!(catalog.len(), 4);
        assert!(!catalog.is_empty());
        let keys: Vec<&str> = catalog.iter().map(|setting| setting.key.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn registering_the_same_key_twice_replaces_it() {
        // A build that overrides a default registers again, and that is not a mistake to refuse.
        let mut catalog = Catalog::new();
        catalog.register(
            Setting::new("a.b", SettingKind::Integer, json!(1), "first").expect("setting"),
        );
        catalog.register(
            Setting::new("a.b", SettingKind::Integer, json!(2), "second").expect("setting"),
        );
        assert_eq!(catalog.len(), 1);
        assert_eq!(
            catalog.get(&key("a.b")).expect("the setting").default,
            json!(2)
        );
    }

    #[test]
    fn a_setting_that_is_not_registered_is_not_checked() {
        // The catalogue is the kernel's knowledge and not a whitelist.
        let catalog = catalog();
        assert!(catalog.get(&key("nobody.knows")).is_none());
        assert!(catalog.check(&key("nobody.knows"), &json!({"anything": 1})).is_ok());
    }

    #[test]
    fn a_check_names_what_it_expected_and_what_it_found() {
        // The message reaches a settings screen, which has to say which value was wrong and what it should have been.
        let catalog = catalog();
        match catalog.check(&key("transfer.maxConcurrent"), &json!("lots")) {
            Err(ConfigError::BadKey { key: reported, why }) => {
                assert_eq!(reported, "transfer.maxConcurrent");
                assert!(why.contains("integer"), "{why}");
                assert!(why.contains("string"), "{why}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_description_of_a_value_is_a_word() {
        // These reach a message, and one that contained a brace would be a debugging aid that looks like a bug.
        for value in [
            json!(null),
            json!(true),
            json!(1),
            json!(1.5),
            json!("x"),
            json!([]),
            json!({}),
        ] {
            let text = describe(&value);
            assert!(!text.is_empty());
            assert!(!text.contains('{'), "{text}");
        }
    }

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            ConfigError::BadKey { key: "a..b".to_owned(), why: "it has an empty segment".to_owned() },
            ConfigError::SetAndUnset { key: "a.b".to_owned() },
            ConfigError::Unreadable { why: "expected value".to_owned() },
            ConfigError::NotAnObject { found: "a list" },
            ConfigError::Reserved { key: "a.b".to_owned(), why: "the kernel computes it" },
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
            assert!(!text.contains('}'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn a_setting_can_be_built_without_a_catalogue() {
        // The fixture's own path, asserted so a reader sees the constructor is the only way to make a well-formed one.
        let setting = Setting::new("a.b", SettingKind::Text, json!("x"), "d").expect("setting");
        assert!(!setting.reserved);
        assert!(Setting::new("a..b", SettingKind::Text, json!("x"), "d").is_err());
        assert!(setting.reserved().reserved);
    }
}
