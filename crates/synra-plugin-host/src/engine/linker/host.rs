//! WIT-generated host trait implementations; every operation uses the shared gate.

use super::{Answer, StoreData, import_name, run};
use crate::engine::wasmtime_backend::bindings::synra::plugin::{host, types};
use types::{DeviceKind, DeviceTarget, LogLevel, Outcome};

fn text(state: &mut StoreData, name: &str, argument: &str) -> wasmtime::Result<String> {
    match run(state, &import_name(name), argument) {
        Answer::Ok(value) => Ok(value),
        Answer::Denied(error) => Err(anyhow::anyhow!("{error}")),
    }
}

fn outcome(state: &mut StoreData, name: &str, argument: &str) -> Outcome {
    match run(state, &import_name(name), argument) {
        Answer::Ok(value) => Outcome::Ok(value),
        Answer::Denied(error) => Outcome::Err(types::Error {
            code: error.code.to_owned(),
            message: error.message,
            details: error.details,
        }),
    }
}

macro_rules! text_zero {
    ($($method:ident => $name:literal),* $(,)?) => {$(
        fn $method(&mut self) -> wasmtime::Result<String> { text(self, $name, "") }
    )*};
}
macro_rules! outcome_one {
    ($($method:ident => $name:literal),* $(,)?) => {$(
        fn $method(&mut self, argument: String) -> wasmtime::Result<Outcome> {
            Ok(outcome(self, $name, &argument))
        }
    )*};
}
macro_rules! outcome_pair {
    ($(($method:ident, $name:literal, $first:literal, $second:literal)),* $(,)?) => {$(
        fn $method(&mut self, first: String, second: String) -> wasmtime::Result<Outcome> {
            let argument = serde_json::json!({$first: first, $second: second}).to_string();
            Ok(outcome(self, $name, &argument))
        }
    )*};
}
macro_rules! outcome_three {
    ($(($method:ident, $name:literal, $a:literal, $b:literal, $c:literal)),* $(,)?) => {$(
        fn $method(&mut self, first: String, second: String, third: String) -> wasmtime::Result<Outcome> {
            let argument = serde_json::json!({$a: first, $b: second, $c: third}).to_string();
            Ok(outcome(self, $name, &argument))
        }
    )*};
}

impl types::Host for StoreData {}

impl host::Host for StoreData {
    text_zero! {
        env_sdk_version => "env-sdk-version",
        env_host_kind => "env-host-kind",
        env_locale => "env-locale",
        plugin_id => "plugin-id",
        action_list => "action-list",
    }

    outcome_one! {
        storage_get => "storage-get",
        storage_delete => "storage-delete",
        secret_get => "secret-get",
        secret_delete => "secret-delete",
        network_fetch => "network-fetch",
        network_websocket => "network-websocket",
        transfer_status => "transfer-status",
        platform_open_url => "platform-open-url",
        platform_open_path => "platform-open-path",
        platform_reveal_path => "platform-reveal-path",
        platform_simulate_keys => "platform-simulate-keys",
        platform_write_clipboard => "platform-write-clipboard",
    }

    outcome_pair! {
        (event_emit, "event-emit", "event", "payload"),
        (device_broadcast, "device-broadcast", "event", "payload"),
        (storage_set, "storage-set", "key", "value"),
        (secret_set, "secret-set", "key", "value"),
        (platform_notify, "platform-notify", "title", "body"),
        (action_declare, "action-declare", "name", "schema"),
    }

    outcome_three! {
        (device_send, "device-send", "target", "event", "payload"),
        (transfer_send, "transfer-send", "event", "target", "payload"),
        (action_invoke, "action-invoke", "plugin", "name", "args"),
    }

    fn env_dark_mode(&mut self) -> wasmtime::Result<bool> {
        Ok(text(self, "env-dark-mode", "")?.parse()?)
    }

    fn env_can(&mut self, capability: String) -> wasmtime::Result<bool> {
        Ok(text(self, "env-can", &capability)?.parse()?)
    }

    fn log(
        &mut self,
        level: LogLevel,
        message: String,
        context: Option<String>,
    ) -> wasmtime::Result<()> {
        let level = match level {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        let argument =
            serde_json::json!({"level": level, "message": message, "context": context}).to_string();
        text(self, "log", &argument)?;
        Ok(())
    }

    fn storage_keys(&mut self, prefix: Option<String>) -> wasmtime::Result<Vec<String>> {
        Ok(serde_json::from_str(&text(
            self,
            "storage-keys",
            prefix.as_deref().unwrap_or(""),
        )?)?)
    }

    fn storage_quota(&mut self) -> wasmtime::Result<(u64, u64)> {
        Ok(serde_json::from_str(&text(self, "storage-quota", "")?)?)
    }

    fn platform_capabilities(&mut self) -> wasmtime::Result<Vec<String>> {
        Ok(serde_json::from_str(&text(
            self,
            "platform-capabilities",
            "",
        )?)?)
    }

    fn platform_read_clipboard(&mut self) -> wasmtime::Result<Outcome> {
        Ok(outcome(self, "platform-read-clipboard", ""))
    }

    fn device_list(&mut self) -> wasmtime::Result<Vec<DeviceTarget>> {
        let rows: Vec<DeviceRow> = serde_json::from_str(&text(self, "device-list", "")?)?;
        rows.into_iter()
            .map(|row| {
                let kind = match row.kind.as_str() {
                    "desktop" => DeviceKind::Desktop,
                    "mobile" => DeviceKind::Mobile,
                    "headless" => DeviceKind::Headless,
                    _ => anyhow::bail!("host returned an invalid WIT device kind"),
                };
                Ok(DeviceTarget {
                    id: row.id,
                    name: row.name,
                    kind,
                })
            })
            .collect()
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRow {
    id: String,
    name: String,
    kind: String,
}
