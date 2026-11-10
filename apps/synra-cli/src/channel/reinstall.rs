use synra_control::{Client, Request, Response};

use super::transport_failure;
use crate::session::CommandOutcome;

/// Reinstalls the plugins a `.synrabackup` container lists.
///
/// # Why this is a sequence rather than one request
///
/// Because an install is one request per package, and the container is a list of packages. The kernel is asked once per
/// source, in the order the container records them, and the first refusal stops the sequence and names the plugin: a
/// partial reinstall is reported as exactly that, not rolled back into a lie about having installed nothing.
///
/// # Errors
///
/// Never in the Rust sense. A container that cannot be read, a kernel that is not running, and an install the kernel
/// refuses are all [`CommandOutcome::Failed`] with the reason a user can act on.
#[must_use]
pub fn reinstall(
    args: &crate::args::PluginArgs,
    format: Option<crate::args::OutputFormat>,
) -> CommandOutcome {
    use crate::args::PluginAction;

    let PluginAction::Reinstall { from } = &args.action else {
        return CommandOutcome::Failed(
            "this command is not a reinstall".to_owned(),
        );
    };
    let entries = match synra_store::plugins_in_backup(from) {
        Ok(entries) => entries,
        Err(error) => return CommandOutcome::Failed(error.to_string()),
    };
    if entries.is_empty() {
        return CommandOutcome::Lines(vec![
            "the container lists no plugins to reinstall".to_owned(),
        ]);
    }
    let root = crate::session::data_root();
    let mut client = match Client::connect(&root) {
        Ok(client) => client,
        Err(error) => return transport_failure(&error),
    };
    if let Err(error) = client.handshake() {
        return transport_failure(&error);
    }
    reinstall_with(entries, format, |request| client.ask(request))
}

/// The loop over the container's plugin list, with the channel as a parameter.
///
/// # Why a parameter
///
/// Because the interesting part is the decision — clear this, install that, skip the one with no origin, stop and name the
/// refusal — and a test should be able to drive it without a listening kernel. `reinstall` is the thin part that connects
/// and says hello.
///
/// # Why the row is removed before the install
///
/// Because the import restored the **database** and nothing else: the plugin rows say installed while their artifact
/// directories are gone. The installer refuses an identifier it believes is already here, so a reinstall that went
/// straight to `PluginInstall` would fail for every plugin the container lists. Removing the row (keeping the sandbox) is
/// what turns "already installed" into an install that can actually happen.
fn reinstall_with(
    entries: Vec<synra_store::PluginEntry>,
    format: Option<crate::args::OutputFormat>,
    mut ask: impl FnMut(&Request) -> Result<Response, synra_control::SocketError>,
) -> CommandOutcome {
    let present = match ask(&Request::Plugins) {
        Ok(Response::Ok { value }) => installed_ids(&value),
        Ok(Response::Failed { message, .. }) => {
            return CommandOutcome::Failed(format!(
                "the installed plugins could not be listed: {message}"
            ));
        }
        Ok(other) => {
            return CommandOutcome::Failed(format!(
                "unexpected answer to the plugin list: {other:?}"
            ));
        }
        Err(error) => return transport_failure(&error),
    };

    let mut installed: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for entry in entries {
        let Some(source) = entry.source else {
            // ★ Named rather than silent: a plugin with no recorded origin cannot be reinstalled, and the user has to
            // know which one to fetch by hand.
            skipped.push(entry.plugin_id);
            continue;
        };
        if present.contains(&entry.plugin_id) {
            let response = match ask(&Request::PluginRemove {
                plugin_id: entry.plugin_id.clone(),
                // The container does not carry the sandbox either, but the import did not delete it: keeping it is what
                // the removal's default already does, and the data the user had is the data the importing device still
                // has.
                remove_data: false,
            }) {
                Ok(response) => response,
                Err(error) => return transport_failure(&error),
            };
            if let Response::Failed { message, .. } = &response {
                return CommandOutcome::Failed(format!(
                    "{} could not be cleared before reinstalling: {message}",
                    entry.plugin_id
                ));
            }
        }
        let response = match ask(&Request::PluginInstall { path: source }) {
            Ok(response) => response,
            Err(error) => return transport_failure(&error),
        };
        if let Response::Failed { message, .. } = &response {
            return CommandOutcome::Failed(format!(
                "{} could not be reinstalled: {message}",
                entry.plugin_id
            ));
        }
        // ★ The row the install wrote has no decisions, so the loader would refuse the plugin. Restoring the approvals the
        // container carries is what makes "reinstalled" mean "usable again" rather than "present on disk".
        if !entry.grants.is_empty() {
            let response = match ask(&Request::PluginConsent {
                plugin_id: entry.plugin_id.clone(),
                granted: entry.grants.clone(),
            }) {
                Ok(response) => response,
                Err(error) => return transport_failure(&error),
            };
            if let Response::Failed { message, .. } = &response {
                // ★ A half-restored plugin is worse than none: it is installed, unapproved, and listed as if the restore
                // finished. The cleanup is part of the failure, and its own failure is said rather than hidden.
                let removed = roll_back(&mut ask, &entry.plugin_id);
                return CommandOutcome::Failed(format!(
                    "{} was installed but its consent could not be restored: {message}{removed}",
                    entry.plugin_id
                ));
            }
            // ★ Enabled only after consent, and only when the container said so. A container from before the grants field
            // carries an empty list: the switch stays off rather than opening a plugin nobody approved.
            if entry.enabled {
                let response = match ask(&Request::PluginSetEnabled {
                    plugin_id: entry.plugin_id.clone(),
                    enabled: true,
                }) {
                    Ok(response) => response,
                    Err(error) => return transport_failure(&error),
                };
                if let Response::Failed { message, .. } = &response {
                    let removed = roll_back(&mut ask, &entry.plugin_id);
                    return CommandOutcome::Failed(format!(
                        "{} was installed but could not be enabled: {message}{removed}",
                        entry.plugin_id
                    ));
                }
            }
        }
        installed.push(entry.plugin_id);
    }

    match format {
        Some(crate::args::OutputFormat::Json) => CommandOutcome::json(
            serde_json::json!({ "reinstalled": installed, "skipped": skipped }).to_string(),
        ),
        _ => {
            let mut lines: Vec<String> = installed
                .iter()
                .map(|id| format!("reinstalled {id}"))
                .collect();
            lines.extend(
                skipped
                    .iter()
                    .map(|id| format!("skipped {id}: the container recorded no source")),
            );
            if lines.is_empty() {
                lines.push("nothing needed reinstalling".to_owned());
            }
            CommandOutcome::Lines(lines)
        }
    }
}

/// Removes a partially restored plugin, and says what happened in a clause the failure can carry.
///
/// # Why a clause rather than an error
///
/// Because the original failure is what the user must act on; the cleanup is the state left behind it. A cleanup that also
/// failed has to be named — a silent one would leave an installed, unapproved plugin that nothing in the output accounts
/// for.
fn roll_back(
    ask: &mut impl FnMut(&Request) -> Result<Response, synra_control::SocketError>,
    plugin_id: &str,
) -> String {
    match ask(&Request::PluginRemove {
        plugin_id: plugin_id.to_owned(),
        remove_data: false,
    }) {
        Ok(Response::Ok { .. }) => "; the partial install was removed".to_owned(),
        Ok(Response::Failed { message, .. }) => {
            format!("; the partial install could not be removed: {message}")
        }
        Ok(other) => {
            format!("; the partial install was left in place after an unexpected answer: {other:?}")
        }
        Err(error) => format!("; the partial install could not be removed: {error}"),
    }
}

///
/// An answer this build does not recognise is treated as "nothing installed", which leaves the reinstall to fail at the
/// install with the kernel's own sentence rather than inventing a reason here.
fn installed_ids(value: &serde_json::Value) -> std::collections::HashSet<String> {
    value
        .get("plugins")
        .and_then(serde_json::Value::as_array)
        .map(|plugins| {
            plugins
                .iter()
                .filter_map(|plugin| {
                    plugin
                        .get("pluginId")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
