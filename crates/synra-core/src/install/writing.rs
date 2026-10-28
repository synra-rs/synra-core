//! Commit verified bytes, keeping the previous directory until the version row lands.

use std::path::Path;

use super::{InstallRefusal, Installed, Prepared, discard, signed_publisher};

pub(super) fn write(
    db: &mut synra_store::SynraDb,
    plugins_dir: &Path,
    now_ms: i64,
    prepared: Prepared,
    replace: bool,
) -> Result<Installed, InstallRefusal> {
    let Prepared {
        manifest,
        manifest_json,
        files,
        signature,
        headless,
        artifact_digest,
        warnings,
    } = prepared;
    let plugin_id = manifest.id.to_string();
    let version = manifest.version.clone();
    // ── Writing, atomically ─────────────────────────────────────────────────────────────────────────────────────────
    //
    // A staging directory beside the destination and one rename: a plugin directory that exists is one `load_one`
    // will look at, so half an install must never be visible under the name it will be loaded from.
    // ★ The directory name is the **sanitised** identifier, not the raw one. A scoped id (`@acme/hello`) contains a
    // separator, so joining it raw produced `plugins/@acme/hello` — nested two levels deep — while `Paths::plugin_dir`,
    // the removal, the sweep and the data sandbox all name `plugins/acme+hello`. The installer was the one place that
    // disagreed, which made an uninstall delete a directory that never existed while the artifact stayed beside it.
    let destination = plugins_dir.join(synra_store::sanitise_component(&plugin_id));
    // An update replaces exactly this directory; an install has nothing to replace and refuses rather than overwriting a
    // copy the user did not ask to lose.
    if destination.exists() && !replace {
        return Err(InstallRefusal::new(
            "write",
            format!("{} already exists on disk", destination.display()),
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        InstallRefusal::new(
            "write",
            format!("{} has no parent directory", destination.display()),
        )
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|error| InstallRefusal::new("write", format!("{}: {error}", parent.display())))?;
    // ★ The staging area is **outside** `plugins/`, and that is not tidiness.
    //
    // `record_discovered_plugins` treats any directory that contains a manifest as an installed plugin, so a half-written
    // staging directory inside the plugins tree would be discovered on the next start as a plugin with a truncated
    // artifact — an install that failed would become a plugin that is broken. Under `<data>/.install-staging/` it is only
    // what it is, and it is on the same volume as the destination, so the rename below stays a rename.
    let staging_root = plugins_dir
        .parent()
        .unwrap_or(plugins_dir)
        .join(".install-staging");
    std::fs::create_dir_all(&staging_root).map_err(|error| {
        InstallRefusal::new("write", format!("{}: {error}", staging_root.display()))
    })?;
    // ★ The identifier is flattened, not used as a path: an id contains a slash (`@acme/hello`), and a staging name
    // built from it would name a directory two levels down — which is the error this line was first written with.
    let staging = staging_root.join(format!("{}.{now_ms}", plugin_id.replace(['/', '\\'], "_")));
    if staging.exists() {
        // A leftover from a crash. Refused rather than removed: the recursive delete the removal would need is the
        // sandbox's operation, not this module's, and a timestamp collision is a clock that went backwards.
        return Err(InstallRefusal::new(
            "write",
            format!("{} is left over from an earlier install", staging.display()),
        ));
    }
    std::fs::create_dir(&staging)
        .map_err(|error| InstallRefusal::new("write", format!("{}: {error}", staging.display())))?;
    let mut failure: Option<String> = None;
    for (name, bytes) in &files {
        let target = staging.join(name);
        if let Some(parent) = target.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            failure = Some(format!("{name}: {error}"));
            break;
        }
        if let Err(error) = std::fs::write(target, bytes) {
            failure = Some(format!("{name}: {error}"));
            break;
        }
    }
    if let Some(reason) = failure {
        discard(&staging, &files);
        return Err(InstallRefusal::new("write", reason));
    }
    // ── The UI half, unpacked beside the artifact ───────────────────────────────────────────────────────────────────
    //
    // The bundle's zip is already in `files` (verified like any other artifact), so this step is only "write it out where
    // the `synra-plugin://` handler will look". It runs **before** the rename, so a UI that cannot be unpacked is a failed
    // install rather than an installed plugin whose window is blank.
    if let Some(ui) = manifest.runtime.ui.as_ref() {
        let archive = staging.join(&ui.artifact);
        if let Err(error) = synra_plugin_ui::artifact::unpack(
            &archive,
            &synra_plugin_ui::artifact::bundle_dir(&staging),
            synra_plugin_ui::artifact::ArchiveLimits::artifact(),
        ) {
            // `unpack` removes what it wrote before refusing; `discard` removes the artifact files. Together they leave the
            // staging directory as empty as it started.
            discard(&staging, &files);
            return Err(InstallRefusal::new(
                "unpack",
                format!("{}: {error}", ui.artifact),
            ));
        }
    }

    let backup = if replace {
        let path = staging_root.join(format!("previous-{}", plugin_id.replace(['/', '\\'], "_")));
        // A backup left by a crash is stale by definition: the version row either landed with the new directory or the
        // update never reached this point. Removing it before the move keeps one backup, not a growing set.
        let _ = synra_store::remove_tree(&staging_root, &path);
        if let Err(error) = std::fs::rename(&destination, &path) {
            discard(&staging, &files);
            return Err(InstallRefusal::new(
                "write",
                format!("{}: {error}", destination.display()),
            ));
        }
        Some(path)
    } else {
        None
    };

    if let Err(error) = std::fs::rename(&staging, &destination) {
        discard(&staging, &files);
        if let Some(backup) = &backup {
            let _ = synra_store::remove_tree(plugins_dir, &destination);
            let _ = std::fs::rename(backup, &destination);
        }
        return Err(InstallRefusal::new(
            "write",
            format!("{}: {error}", destination.display()),
        ));
    }

    // ── The row, and the rollback if it does not land ───────────────────────────────────────────────────────────────
    //
    // The two writes — the directory and the row — cannot both be atomic together, so the directory is undone when the
    // row fails. The other order would leave a row naming files that were never written, which `load_installed` would
    // report as a broken plugin rather than as a failed install.
    //
    // An update does not insert: the row (and the user's enabled decision) already exists, and installing a new version is
    // not the moment to forget that the plugin was on — **unless it asks for more**. A new capability is a decision the
    // user made about the old package and not about this one, so the plugin comes back switched off and untrusted, and
    // the consent screen asks again. The version, enabled flag and inherited decisions commit in one transaction.
    let previous_digest = backup
        .as_deref()
        .and_then(|directory| continued_consent(directory, &manifest, signature.as_deref()));
    let manifest_digest = synra_plugin_api::manifest_digest(&manifest_json);
    let capabilities: Vec<String> = manifest
        .capabilities
        .iter()
        .map(|cap| cap.cap.clone())
        .collect();
    let active_digest = if headless.is_some() {
        artifact_digest
    } else {
        String::new()
    };
    // Read before the version row: who signed it is a column on that row, and the publisher registration below must not
    // be the only place the fact exists.
    let signed_by = signature.as_deref().and_then(signed_publisher);
    let recorded = if replace {
        db.replace_plugin_version(&synra_store::PluginReplacement {
            plugin_id: &plugin_id,
            version: &version,
            artifact: headless.as_deref().unwrap_or_default(),
            digest: &active_digest,
            manifest: &manifest_json,
            manifest_digest: &manifest_digest,
            previous_manifest_digest: previous_digest.as_deref(),
            capabilities: &capabilities,
            publisher_id: signed_by.as_ref().map(|publisher| publisher.publisher_id.as_str()),
            fingerprint: signed_by.as_ref().map(|publisher| publisher.fingerprint.as_str()),
            now_ms,
        })
    } else {
        db.insert_plugin(&plugin_id, false, false, "installed", now_ms, now_ms)
            .and_then(|()| {
                db.record_plugin_version(&synra_store::PluginVersionRecord {
                    plugin_id: &plugin_id,
                    version: &version,
                    artifact: headless.as_deref().unwrap_or_default(),
                    digest: &active_digest,
                    manifest: &manifest_json,
                    publisher_id: signed_by.as_ref().map(|publisher| publisher.publisher_id.as_str()),
                    fingerprint: signed_by.as_ref().map(|publisher| publisher.fingerprint.as_str()),
                    installed_ms: now_ms,
                })
            })
    };
    if let Err(error) = recorded {
        if let Some(backup) = &backup {
            let _ = synra_store::remove_tree(plugins_dir, &destination);
            let _ = std::fs::rename(backup, &destination);
        } else {
            let _ = db.remove_plugin(&plugin_id);
            discard(&destination, &files);
        }
        return Err(InstallRefusal::new("record", error.to_string()));
    }

    // ★ Recorded after the install succeeded, not before: a package that failed a check did not make its publisher a
    // part of this device's history, and a row written for it would make the next prompt say "seen before" about a
    // signature this device refused.
    if let Some(publisher) = &signed_by {
        let _ = db.record_publisher(
            &publisher.publisher_id,
            &publisher.fingerprint,
            &publisher.pubkey,
            now_ms,
        );
    }

    // ★ The old directory is removed only now: it was the rollback for both the move and the version row, and deleting it
    // earlier would have made a failed record unrecoverable.
    if let Some(backup) = backup {
        let _ = synra_store::remove_tree(&staging_root, &backup);
    }

    Ok(Installed {
        plugin_id,
        version,
        path: destination,
        warnings,
        signed_by,
    })
}

fn continued_consent(
    directory: &Path,
    candidate: &synra_plugin_api::Manifest,
    signature: Option<&str>,
) -> Option<String> {
    let previous_text = std::fs::read_to_string(directory.join("manifest.json")).ok()?;
    let previous = synra_plugin_api::Manifest::from_json(&previous_text).ok()?;
    if previous.publisher.id != candidate.publisher.id
        || candidate
            .capabilities
            .iter()
            .any(|cap| !previous.capabilities.iter().any(|old| old.cap == cap.cap))
    {
        return None;
    }
    let previous_signature = match std::fs::read_to_string(directory.join("signature.json")) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return None,
    };
    match (previous_signature.as_deref(), signature) {
        (None, None) => {}
        (Some(old), Some(new)) => {
            let old = signed_publisher(old)?;
            let new = signed_publisher(new)?;
            if old.publisher_id != new.publisher_id || old.fingerprint != new.fingerprint {
                return None;
            }
        }
        _ => return None,
    }
    Some(synra_plugin_api::manifest_digest(&previous_text))
}
