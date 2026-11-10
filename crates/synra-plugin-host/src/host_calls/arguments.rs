/// The arguments `log` takes, as the JSON the glue layer passes.
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct LogArguments {
    pub(super) level: String,
    pub(super) message: String,
    #[serde(default)]
    pub(super) context: Option<String>,
}

/// The arguments `event-emit` and `device-broadcast` take.
#[derive(Debug, Deserialize)]
pub(super) struct EventArguments {
    pub(super) event: String,
    #[serde(default)]
    pub(super) payload: String,
}

/// The arguments `device-send` and `transfer-send` take.
#[derive(Debug, Deserialize)]
pub(super) struct SendArguments {
    pub(super) target: String,
    pub(super) event: String,
    #[serde(default)]
    pub(super) payload: String,
}

/// The arguments `storage-set` and `secret-set` take.
#[derive(Debug, Deserialize)]
pub(super) struct KeyValue {
    pub(super) key: String,
    pub(super) value: String,
}

/// The arguments `platform-notify` takes.
#[derive(Debug, Deserialize)]
pub(super) struct NotifyArguments {
    pub(super) title: String,
    #[serde(default)]
    pub(super) body: String,
}

/// The arguments `action-declare` takes.
#[derive(Debug, Deserialize)]
pub(super) struct DeclareArguments {
    pub(super) name: String,
    #[serde(default)]
    pub(super) schema: String,
}

/// The arguments `action-invoke` takes.
#[derive(Debug, Deserialize)]
pub(super) struct InvokeArguments {
    pub(super) plugin: String,
    pub(super) name: String,
    #[serde(default)]
    pub(super) args: String,
}
