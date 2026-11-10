use synra_control::{Kernel, Refusal};

use super::{Runtime, now_ms};

mod devices;
mod files;
mod intents;
mod peer;
mod plugin_install;
mod plugin_lifecycle;
mod text;

pub(super) use peer::exchange;
/// How long a dispatched action's outcome is waited for before the intent stays dispatching.
///
/// ★ **The number moved to the kernel.** It was the same arithmetic written in two hosts — this one and the desktop shell
/// — which drifts the first time the execution budget changes: one host would report an outcome while the other still
/// called the action in flight. [`synra_core::dispatch::REMOTE_RESULT_WAIT`] owns it now, derived from the budget there.
/// The reasoning and the limitation (a receiver slower than the wait answers into a closed link) live with it.
pub(super) use synra_core::dispatch::REMOTE_RESULT_WAIT;

impl Kernel for Runtime {
    fn plugin_publishers(&self) -> Result<serde_json::Value, Refusal> {
        super::publishers::list(self)
    }

    fn plugin_publisher_decide(
        &self,
        publisher_id: &str,
        fingerprint: &str,
        trust: &str,
    ) -> Result<serde_json::Value, Refusal> {
        super::publishers::decide(
            self,
            publisher_id,
            fingerprint,
            trust,
            synra_store::sqlite::now_ms(),
        )
    }

    fn plugin_registry(&self, urls: Option<&[String]>) -> Result<serde_json::Value, Refusal> {
        super::plugin_settings::registry(self, urls, synra_store::sqlite::now_ms())
    }

    fn plugin_update_policy(&self, policy: Option<&str>) -> Result<serde_json::Value, Refusal> {
        super::plugin_settings::policy(self, policy, synra_store::sqlite::now_ms())
    }

    fn plugin_check_updates(&self, plugin: Option<&str>) -> Result<serde_json::Value, Refusal> {
        super::updates::check_manually(self, plugin, synra_store::sqlite::now_ms())
    }

    fn plugin_update(
        &self,
        plugin: &str,
        version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        super::updates::update_manually(self, plugin, version, synra_store::sqlite::now_ms())
    }

    fn version(&self) -> String {
        self.version.clone()
    }

    fn status(&self) -> Result<serde_json::Value, Refusal> {
        Ok(self.status_value(now_ms()))
    }

    fn devices(
        &self,
        include_unpaired: bool,
        scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal> {
        self.command_devices(include_unpaired, scan_ms)
    }

    fn send_text(&self, to: &str, text: &str) -> Result<serde_json::Value, Refusal> {
        self.command_send_text(to, text)
    }

    fn send_file(&self, to: &str, path: &str) -> Result<serde_json::Value, Refusal> {
        self.command_send_file(to, path)
    }

    fn send_bundle(
        &self,
        to: &str,
        path: &str,
        plugin_id: &str,
        version: &str,
    ) -> Result<serde_json::Value, Refusal> {
        self.command_send_bundle(to, path, plugin_id, version)
    }

    fn catalog_search(&self, package: &str) -> Result<serde_json::Value, Refusal> {
        // ★ The one kernel command that talks to the open network, and the only one whose answer can be stale. `search`
        // carries both facts in the reply rather than in a log line, because a screen has to show them.
        super::catalog::search(self, package)
    }

    fn plugins(&self) -> Result<serde_json::Value, Refusal> {
        self.plugins_value()
    }

    fn plugin_set_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
    ) -> Result<serde_json::Value, Refusal> {
        self.command_plugin_set_enabled(plugin_id, enabled)
    }

    fn plugin_install(&self, path: &str) -> Result<serde_json::Value, Refusal> {
        self.command_plugin_install(path)
    }

    fn plugin_install_package(
        &self,
        package: &str,
        version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        self.command_plugin_install_package(package, version)
    }

    fn plugin_consent(
        &self,
        plugin_id: &str,
        granted: &[String],
    ) -> Result<serde_json::Value, Refusal> {
        self.command_plugin_consent(plugin_id, granted)
    }

    fn plugin_remove(
        &self,
        plugin_id: &str,
        remove_data: bool,
    ) -> Result<serde_json::Value, Refusal> {
        self.command_plugin_remove(plugin_id, remove_data)
    }

    fn logs(
        &self,
        lines: usize,
        verbose: bool,
        trace: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        self.logs_value(lines, verbose, trace)
    }

    fn intent_dispatch(&self, mime: &str, text: &str) -> Result<serde_json::Value, Refusal> {
        self.command_intent_dispatch(mime, text)
    }

    fn intent_snapshot(&self, intent: &str) -> Result<serde_json::Value, Refusal> {
        self.command_intent_snapshot(intent)
    }

    fn intent_decide(
        &self,
        intent: &str,
        plugin_id: Option<&str>,
        target: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        self.command_intent_decide(intent, plugin_id, target)
    }

    fn intent_cancel(&self, intent: &str) -> Result<serde_json::Value, Refusal> {
        self.command_intent_cancel(intent)
    }
}
