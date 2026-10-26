//! What a grant is called in front of a user.

use crate::domain::Domain;

use super::segment::Segment;
use super::syntax::Capability;

impl Capability {
    /// A short phrase describing what this grants, for the capability-consent prompt.
    ///
    /// The prompt is where a user decides, so it must not show them a DSL string. A user who does not
    /// read `network:fetch:api.github.com:POST` as "read from GitHub" is being asked to consent to
    /// something they cannot evaluate.
    #[must_use]
    pub fn describe(&self) -> String {
        let resource = self.prefixes.first().map_or("", Segment::as_str);
        match (self.domain, resource) {
            (Domain::Log, _) => match self.qualifier.first() {
                Some(level) => format!("write {} log messages", level.as_str()),
                None => "write log messages".to_owned(),
            },
            (Domain::Network, "fetch") => {
                let host = self.qualifier.first().map_or("*", Segment::as_str);
                match host {
                    "*" | "**" => "read from any website".to_owned(),
                    _ => format!("read from {host}"),
                }
            }
            (Domain::Network, "websocket") => "open a network connection".to_owned(),
            (Domain::Fs, "read") => {
                let path = self.qualifier.first().map_or("its sandbox", Segment::as_str);
                format!("read files under {}", readable_path(path))
            }
            (Domain::Fs, "write") => {
                let path = self.qualifier.first().map_or("its sandbox", Segment::as_str);
                format!("write files under {}", readable_path(path))
            }
            (Domain::Fs, "watch") => "watch files for changes".to_owned(),
            (Domain::Device, "list") => "see your other devices".to_owned(),
            (Domain::Device, "send") => match self.qualifier.first() {
                Some(target) => format!("send messages to {}", target.as_str()),
                None => "send messages to devices".to_owned(),
            },
            (Domain::Device, "broadcast") => "send messages to every device".to_owned(),
            (Domain::Platform, "open-url") => "open links in your browser".to_owned(),
            (Domain::Platform, "notify") => "show notifications".to_owned(),
            (Domain::Platform, "simulate-keys") => "type on your behalf".to_owned(),
            (Domain::Platform, "read-clipboard") => "read your clipboard".to_owned(),
            (Domain::Platform, "write-clipboard") => "change your clipboard".to_owned(),
            // Kept for a legacy declaration that reached this far without canonicalisation; the manifest reader and the
            // store migration are what make it rare, and the prompt still has to say something a user can read.
            (Domain::Platform, "clipboard") => match self.qualifier.first() {
                Some(action) if action.as_str() == "read" => "read your clipboard".to_owned(),
                Some(action) if action.as_str() == "write" => "change your clipboard".to_owned(),
                _ => "use your clipboard".to_owned(),
            },
            (Domain::Storage, _) => "keep its own saved data".to_owned(),
            (Domain::File, "transfer") => match self.qualifier.first() {
                Some(action) if action.as_str() == "send" => "send files to your devices".to_owned(),
                Some(action) if action.as_str() == "receive" => "receive files".to_owned(),
                _ => "transfer files".to_owned(),
            },
            (Domain::Event, "emit") => match self.qualifier.first() {
                Some(name) => format!("send its own {} events", event_family(name.as_str())),
                None => "send its own events".to_owned(),
            },
            (Domain::Event, "subscribe") => match self.qualifier.first() {
                Some(name) => format!("react to {} events", event_family(name.as_str())),
                None => "react to events".to_owned(),
            },
            (Domain::Action, "declare") => "offer actions to other plugins".to_owned(),
            (Domain::Action, "invoke") => "use another plugin's actions".to_owned(),
            (Domain::Ui, _) => "show its own interface".to_owned(),
            _ => format!("use {self}"),
        }
    }
}

/// Renders an event-name qualifier for a consent prompt.
///
/// The pattern suffix is what decides how much is covered, so showing it would leave the user to work
/// out the scope. The family a pattern names is the useful answer: `_plugin.@acme/chat.*` covers the chat
/// plugin's events, and `_synra.*` covers the host's.
fn event_family(pattern: &str) -> String {
    let trimmed = pattern.trim_end_matches('*').trim_end_matches('.');
    match trimmed.strip_prefix("_plugin.") {
        Some(slug) => format!("{slug} plugin's"),
        None => match trimmed.strip_prefix("_synra.") {
            Some("") => "host".to_owned(),
            Some(rest) => format!("host {rest}"),
            // A bare pattern covers the plugin's own namespace, which is what a plugin emits.
            None if trimmed.is_empty() => "own".to_owned(),
            None => trimmed.to_owned(),
        },
    }
}

/// Renders a path qualifier for a consent prompt.
///
/// The prompt must not contain `**`: a user reading "read files under /data/**" has been shown a glob
/// rather than an answer, and the wildcard is the part that decides how much is being asked for.
fn readable_path(path: &str) -> String {
    match path.strip_suffix("**") {
        Some(root) => {
            let root = root.trim_end_matches('/');
            if root.is_empty() {
                "anywhere in its sandbox".to_owned()
            }
            else {
                format!("{root} and everything below it")
            }
        }
        None => match path.strip_suffix('*') {
            Some(root) => format!("{} directly", root.trim_end_matches('/')),
            None => path.to_owned(),
        },
    }
}
