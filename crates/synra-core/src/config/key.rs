use super::ConfigError;

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
