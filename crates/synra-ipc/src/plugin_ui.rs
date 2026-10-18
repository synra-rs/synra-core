//! The methods a plugin's page may call, and the only ones that exist.
//!
//! # Why a closed enum rather than a string allow-list
//!
//! Because the plugin page is the least trusted thing this host runs: it is somebody else's JavaScript in a WebView, and
//! the IPC surface it reaches must be a **minimum**, not "everything the kernel has minus a deny-list". A deny-list is
//! wrong the day a command is added; an enum is wrong only if somebody adds a variant on purpose, and that is a review
//! this file is small enough to get.
//!
//! The design document names the surface in `08 §7.2`. The deliberate omissions are listed there too, and they are not
//! variants here rather than being refused in a match: `platform.simulateKeys`, `fs.read`, `fs.write`, every
//! `devices_*` command, `plugins_install`/`plugins_enable`, `plugin_consent_respond` and `config_set` cannot be
//! *spelled* — a page that tries gets "this host does not know that method", which is the same answer as a typo, and
//! that is the point: the page cannot enumerate what exists by asking.
//!
//! # What being a variant means
//!
//! It means **the method is addressable**, not that this build implements it. `plugin_ui_rpc` answers an addressable but
//! unbuilt operation with `Unsupported`, because the alternative — a silent no-op or an invented answer — is how a plugin
//! author ships against a host that does not do what they think it does.

/// One method a plugin page may call through `plugin_ui_rpc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginUiOp {
    /// Read the environment facts a page's façade is built from.
    EnvGet,
    /// Ask whether a capability is held.
    EnvCan,
    /// Write a line into the host's log.
    LogWrite,
    /// Emit an event under this plugin's own namespace.
    EventEmit,
    /// Subscribe to the kernel's event channel.
    EventSubscribe,
    /// Drop a subscription.
    EventUnsubscribe,
    /// List devices this plugin may reach.
    DeviceList,
    /// Send an event to one device.
    DeviceSend,
    /// Send an event to every paired device.
    DeviceBroadcast,
    /// Ask the user to choose a device.
    DevicePick,
    /// Read this plugin's own storage.
    StorageGet,
    /// Write this plugin's own storage.
    StorageSet,
    /// Delete one of this plugin's own keys.
    StorageDelete,
    /// List this plugin's own keys.
    StorageKeys,
    /// How much of this plugin's storage quota is used.
    StorageQuota,
    /// Make a request through the host's controlled HTTP client.
    NetworkFetch,
    /// Read the clipboard.
    ClipboardRead,
    /// Write the clipboard.
    ClipboardWrite,
    /// Open a URL in the user's browser.
    PlatformOpenUrl,
    /// Show a notification.
    PlatformNotify,
    /// Send a blob as a transfer.
    TransferSend,
    /// Read a transfer's state.
    TransferStatus,
    /// Subscribe to a transfer's progress.
    TransferOnProgress,
    /// Call this plugin's own headless half.
    SelfInvoke,
    /// List this plugin's actions.
    SelfActions,
    /// The page has mounted.
    PageReady,
    /// Navigate the page.
    PageNavigate,
}

impl PluginUiOp {
    /// Every method, in the order the design document lists them.
    pub const ALL: &'static [Self] = &[
        Self::EnvGet,
        Self::EnvCan,
        Self::LogWrite,
        Self::EventEmit,
        Self::EventSubscribe,
        Self::EventUnsubscribe,
        Self::DeviceList,
        Self::DeviceSend,
        Self::DeviceBroadcast,
        Self::DevicePick,
        Self::StorageGet,
        Self::StorageSet,
        Self::StorageDelete,
        Self::StorageKeys,
        Self::StorageQuota,
        Self::NetworkFetch,
        Self::ClipboardRead,
        Self::ClipboardWrite,
        Self::PlatformOpenUrl,
        Self::PlatformNotify,
        Self::TransferSend,
        Self::TransferStatus,
        Self::TransferOnProgress,
        Self::SelfInvoke,
        Self::SelfActions,
        Self::PageReady,
        Self::PageNavigate,
    ];

    /// The string a page passes as `method`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnvGet => "env.get",
            Self::EnvCan => "env.can",
            Self::LogWrite => "log.write",
            Self::EventEmit => "event.emit",
            Self::EventSubscribe => "event.subscribe",
            Self::EventUnsubscribe => "event.unsubscribe",
            Self::DeviceList => "device.list",
            Self::DeviceSend => "device.send",
            Self::DeviceBroadcast => "device.broadcast",
            Self::DevicePick => "device.pick",
            Self::StorageGet => "storage.get",
            Self::StorageSet => "storage.set",
            Self::StorageDelete => "storage.delete",
            Self::StorageKeys => "storage.keys",
            Self::StorageQuota => "storage.quota",
            Self::NetworkFetch => "network.fetch",
            Self::ClipboardRead => "clipboard.read",
            Self::ClipboardWrite => "clipboard.write",
            Self::PlatformOpenUrl => "platform.openUrl",
            Self::PlatformNotify => "platform.notify",
            Self::TransferSend => "transfer.send",
            Self::TransferStatus => "transfer.status",
            Self::TransferOnProgress => "transfer.onProgress",
            Self::SelfInvoke => "self.invoke",
            Self::SelfActions => "self.actions",
            Self::PageReady => "page.ready",
            Self::PageNavigate => "page.navigate",
        }
    }

    /// Reads a method name, or `None` when this host has no such operation.
    ///
    /// `None` covers two cases on purpose: a name that is not on the surface at all, and a name that is deliberately not
    /// on it (`config.set`, `fs.read`, …). Telling those apart would give a page an oracle for what the host can do;
    /// the caller reports the same refusal for both.
    #[must_use]
    pub fn parse(method: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|op| op.as_str() == method)
    }
}

#[cfg(test)]
mod tests {
    use super::PluginUiOp;

    #[test]
    fn every_method_round_trips_through_its_name() {
        for op in PluginUiOp::ALL {
            assert_eq!(PluginUiOp::parse(op.as_str()), Some(*op), "{}", op.as_str());
        }
    }

    #[test]
    fn the_methods_a_plugin_may_not_call_cannot_be_spelled() {
        // ★ These are the design document's explicit refusals. They are not variants, so "not a method" and "a method
        // you may not call" are the same answer — a page cannot use the refusal to learn what else exists.
        for denied in [
            "platform.simulateKeys",
            "fs.read",
            "fs.write",
            "plugins.install",
            "plugins.enable",
            "plugins.disable",
            "plugin.consent",
            "devices.snapshot",
            "devices.scan",
            "devices.pair",
            "devices.forget",
            "config.set",
        ] {
            assert_eq!(PluginUiOp::parse(denied), None, "{denied} is callable by a plugin page");
        }
    }

    #[test]
    fn an_invented_method_is_refused() {
        assert_eq!(PluginUiOp::parse("device.explode"), None);
        assert_eq!(PluginUiOp::parse(""), None);
    }

    #[test]
    fn no_two_operations_share_a_name() {
        // A duplicate would make `parse` return whichever variant happens to be first, and the other would be
        // unreachable — a method that exists in the enum and cannot be called.
        let mut names: Vec<&'static str> = PluginUiOp::ALL.iter().map(|op| op.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }
}
