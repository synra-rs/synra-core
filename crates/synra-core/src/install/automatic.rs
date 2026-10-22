//! Admit automatic replacements from verified bytes, then recheck the installed version and trust before committing.

use std::path::{Path, PathBuf};

use synra_plugin_api::Manifest;
use synra_plugin_api::manifest::compare_versions;
use synra_plugin_api::publisher::Fingerprint;
use synra_plugin_api::update::{ChangeSize, UpdateAction, UpdateFacts, UpdatePolicy, decide};
use synra_plugin_host::{Backend, verify::HostFacts};

use super::{InstallRefusal, Installed, Prepared, prepare, signed_publisher, trust_store, writing};

/// Verified replacement bytes admitted by the user's automatic update policy.
///
/// The source is read once. A host can migrate and stop the old instance, then commit these same bytes without reopening
/// a mutable package directory. The installed version and publisher trust are checked again at commit time.
#[derive(Debug)]
pub struct PreparedUpdate {
    prepared: Prepared,
    plugins_dir: PathBuf,
    previous_version: String,
    policy: UpdatePolicy,
}

impl PreparedUpdate {
    /// The identifier in the verified manifest.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        self.prepared.manifest.id.as_str()
    }

    /// The version in the verified manifest.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.prepared.manifest.version
    }

    /// Commits this admitted replacement after the host has stopped the previous instance.
    ///
    /// # Errors
    ///
    /// `update-policy` if the installed version or publisher decision changed; otherwise the installer's write errors.
    pub fn install(
        self,
        db: &mut synra_store::SynraDb,
        now_ms: i64,
    ) -> Result<Installed, InstallRefusal> {
        let current = admit(db, &self.plugins_dir, &self.prepared, self.policy)?;
        if current != self.previous_version {
            return Err(refused(
                "the installed version changed while preparing the update",
            ));
        }
        writing::write(db, &self.plugins_dir, now_ms, self.prepared, true)
    }
}

/// Verifies a downloaded directory and admits it only when policy, publisher and permissions allow automatic updating.
///
/// This has no installation or lifecycle side effects. A rejected package leaves the running plugin untouched.
///
/// # Errors
///
/// The usual install verification errors, or `update-policy` when a decision requires a person.
pub fn prepare_automatic_update(
    db: &synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
    policy: UpdatePolicy,
) -> Result<PreparedUpdate, InstallRefusal> {
    let prepared = prepare(db, backend, source, now_ms, host, true)?;
    let previous_version = admit(db, plugins_dir, &prepared, policy)?;
    Ok(PreparedUpdate {
        prepared,
        plugins_dir: plugins_dir.to_owned(),
        previous_version,
        policy,
    })
}

fn refused(reason: impl Into<String>) -> InstallRefusal {
    InstallRefusal::new("update-policy", reason)
}

fn admit(
    db: &synra_store::SynraDb,
    plugins_dir: &Path,
    prepared: &Prepared,
    policy: UpdatePolicy,
) -> Result<String, InstallRefusal> {
    let candidate = &prepared.manifest;
    let current = db
        .active_plugin(candidate.id.as_str())
        .map_err(|error| refused(error.to_string()))?
        .ok_or_else(|| refused("the plugin is no longer installed"))?;
    if compare_versions(&candidate.version, &current.version)
        .map_err(|error| refused(error.to_string()))?
        != std::cmp::Ordering::Greater
    {
        return Err(refused(
            "automatic updates must advance the installed version",
        ));
    }
    if candidate
        .version
        .split('+')
        .next()
        .unwrap_or_default()
        .contains('-')
    {
        return Err(refused("prerelease versions require a manual update"));
    }
    let directory = plugins_dir.join(synra_store::sanitise_component(candidate.id.as_str()));
    let text = std::fs::read_to_string(directory.join("manifest.json"))
        .map_err(|error| refused(format!("installed manifest: {error}")))?;
    let previous = Manifest::from_json(&text).map_err(|error| refused(error.to_string()))?;
    if previous.id != candidate.id || previous.version != current.version {
        return Err(refused("the installed manifest and version row disagree"));
    }
    let previous_signature = std::fs::read_to_string(directory.join("signature.json"))
        .map_err(|error| refused(format!("installed signature: {error}")))?;
    let old = signed_publisher(&previous_signature)
        .ok_or_else(|| refused("the installed version has no valid signer"))?;
    let new = prepared
        .signature
        .as_deref()
        .and_then(signed_publisher)
        .ok_or_else(|| refused("automatic updates require a signed package"))?;
    if old.publisher_id != new.publisher_id || previous.publisher.id != candidate.publisher.id {
        return Err(refused("the publisher changed"));
    }
    let old_key =
        Fingerprint::parse(&old.fingerprint).map_err(|error| refused(error.to_string()))?;
    let new_key =
        Fingerprint::parse(&new.fingerprint).map_err(|error| refused(error.to_string()))?;
    let mut facts = UpdateFacts::routine(
        trust_store(db).classify(&new.publisher_id, &new_key),
        change_size(&previous.version, &candidate.version),
    );
    if old_key != new_key {
        facts.publisher_key_changed = Some((old_key, new_key));
    }
    facts.added_capabilities = candidate
        .capabilities
        .iter()
        .filter(|cap| !previous.capabilities.iter().any(|old| old.cap == cap.cap))
        .map(|cap| cap.cap.clone())
        .collect();
    if !matches!(decide(policy, &facts), UpdateAction::Auto) {
        return Err(refused(
            "the update requires confirmation under the selected policy",
        ));
    }
    Ok(current.version)
}

fn change_size(previous: &str, candidate: &str) -> ChangeSize {
    let mut old = previous.split('.');
    let mut new = candidate.split('.');
    if old.next() != new.next() {
        ChangeSize::Major
    } else if old.next() != new.next() {
        ChangeSize::Minor
    } else {
        ChangeSize::Patch
    }
}

#[cfg(test)]
mod tests;
