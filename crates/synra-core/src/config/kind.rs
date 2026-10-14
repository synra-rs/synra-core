use serde_json::Value;

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
