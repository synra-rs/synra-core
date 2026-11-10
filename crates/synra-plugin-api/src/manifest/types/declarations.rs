use serde::{Deserialize, Serialize};

use synra_protocol::PluginId;

/// One capability the plugin asks for.
///
/// A struct with a `cap` field rather than a bare string, so the list has room to grow — a justification, a
/// scope note — without changing every manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDeclaration {
    /// The capability string.
    pub cap: String,
    /// Why the plugin wants it, if the author chose to say.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

/// An action the plugin offers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionDeclaration {
    /// The action's name within the plugin.
    pub name: String,
    /// The arguments' JSON Schema.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub args: Option<serde_json::Value>,
    /// The return value's JSON Schema.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub returns: Option<serde_json::Value>,
    /// A sentence describing it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

/// A share kind the plugin handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareHandler {
    /// The kinds it accepts, such as `text` or `url`.
    pub kinds: Vec<String>,
    /// A sentence describing what it does with them.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

/// An event the plugin defines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventDeclaration {
    /// The full event name, which must be inside the plugin's own namespace.
    pub name: String,
    /// The payload's JSON Schema.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload: Option<serde_json::Value>,
}

/// An event the plugin wants delivered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandleDeclaration {
    /// An event name or a pattern.
    pub event: String,
    /// A condition on the payload, if the plugin only wants some of them.
    #[serde(rename = "match", skip_serializing_if = "Option::is_none", default)]
    pub conditions: Option<serde_json::Value>,
}

/// Another plugin this one composes with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComposeDependency {
    /// The other plugin's id.
    pub id: PluginId,
    /// A semver range.
    pub version: String,
    /// Whether the plugin works without it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub optional: Option<bool>,
}

/// The hosts a plugin may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkDeclaration {
    /// The hosts it may reach out to.
    pub outbound: Vec<OutboundHost>,
}

/// One host in the network declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutboundHost {
    /// The hostname, possibly with a leading `*.`.
    pub host: String,
    /// The methods it needs, when it needs only some.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub methods: Vec<String>,
}

/// A page the plugin adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageDeclaration {
    /// The page's key.
    pub key: String,
    /// Its title.
    pub title: String,
    /// Its route.
    pub path: String,
    /// An icon name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icon: Option<String>,
}
