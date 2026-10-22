use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use rstest::rstest;
use std::sync::Arc;
use synra_plugin_api::publisher::{Digests, SigningSubject};

struct Fixture {
    root: PathBuf,
    db: synra_store::SynraDb,
    backend: Backend,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("synra-automatic-{}-{unique}", std::process::id()));
        let mut db = synra_store::SynraDb::open_in_memory().expect("database");
        db.migrate().expect("schema");
        let backend = Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new()));
        let fixture = Self { root, db, backend };
        fixture.source("1.0.0", 7, "@acme", false);
        fixture
    }

    fn install(&mut self) {
        crate::install::from_directory(
            &mut self.db,
            &self.backend,
            &self.root.join("plugins"),
            &self.root.join("source"),
            1,
            HostFacts::headless(),
        )
        .expect("first install");
        self.db
            .set_publisher_trust("@acme", synra_store::TRUST_TRUSTED, 2)
            .expect("trust");
    }

    fn source(&self, version: &str, seed: u8, publisher: &str, new_permission: bool) {
        let source = self.root.join("source");
        std::fs::create_dir_all(&source).expect("source");
        let caps = if new_permission {
            serde_json::json!([{"cap":"log:*"}, {"cap":"device:send:*"}])
        } else {
            serde_json::json!([{"cap":"log:*"}])
        };
        let manifest = serde_json::json!({
            "id":"@acme/hello", "version":version, "title":"Hello", "publisher":{"id":publisher},
            "sdk":{"min":"0.1.0"}, "wit":synra_plugin_host::host_world(), "capabilities":caps,
            "runtime":{"headless":{"artifact":"plugin.wasm", "stateful":false}}
        })
        .to_string();
        let wasm = b"\0asm\x01\0\0\0";
        let mut artifacts = Digests::new();
        artifacts.insert(
            "plugin.wasm",
            crate::transfer::ObjectDigest::of(wasm).as_sri().to_string(),
        );
        let subject = SigningSubject {
            manifest: synra_plugin_api::manifest_digest(&manifest),
            artifacts,
        };
        let key = SigningKey::from_bytes(&[seed; 32]);
        let document = serde_json::json!({
            "version":1, "publisher":{"id":publisher}, "algorithm":"ed25519", "signedAt":"2026-10-22T00:00:00Z",
            "pubkey":STANDARD.encode(key.verifying_key().as_bytes()),
            "subject":{"manifest":subject.manifest, "artifacts":subject.artifacts.iter().collect::<std::collections::BTreeMap<_,_>>()},
            "signature":STANDARD.encode(key.sign(&subject.canonical_bytes()).to_bytes())
        });
        std::fs::write(source.join("manifest.json"), manifest).expect("manifest");
        std::fs::write(source.join("plugin.wasm"), wasm).expect("wasm");
        std::fs::write(source.join("signature.json"), document.to_string()).expect("signature");
    }

    fn prepare(&self, policy: UpdatePolicy) -> Result<PreparedUpdate, InstallRefusal> {
        prepare_automatic_update(
            &self.db,
            &self.backend,
            &self.root.join("plugins"),
            &self.root.join("source"),
            3,
            HostFacts::headless(),
            policy,
        )
    }

    fn version(&self) -> String {
        self.db
            .active_plugin("@acme/hello")
            .expect("version")
            .expect("installed")
            .version
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[rstest]
#[case("1.0.1", UpdatePolicy::AutoMinor)]
#[case("1.2.0", UpdatePolicy::AutoMinor)]
#[case("2.0.0", UpdatePolicy::AutoAll)]
fn an_admitted_update_installs_the_verified_bytes_even_if_the_source_changes(
    #[case] version: &str,
    #[case] policy: UpdatePolicy,
) {
    let mut fixture = Fixture::new();
    fixture.install();
    fixture.source(version, 7, "@acme", false);
    let prepared = fixture.prepare(policy).expect("admitted");
    assert_eq!(prepared.plugin_id(), "@acme/hello");
    assert_eq!(prepared.version(), version);
    fixture.source("9.0.0", 9, "@other", true);
    prepared.install(&mut fixture.db, 4).expect("update");
    assert_eq!(fixture.version(), version);
    let text = std::fs::read_to_string(fixture.root.join("plugins/acme+hello/manifest.json"))
        .expect("installed bytes");
    assert_eq!(
        Manifest::from_json(&text).expect("manifest").version,
        version
    );
}

#[rstest]
#[case("2.0.0", 7, "@acme", false, UpdatePolicy::AutoMinor)]
#[case("1.0.1", 7, "@acme", false, UpdatePolicy::NotifyOnly)]
#[case("0.9.0", 7, "@acme", false, UpdatePolicy::AutoAll)]
#[case("1.0.0", 7, "@acme", false, UpdatePolicy::AutoAll)]
#[case("1.1.0-rc.1", 7, "@acme", false, UpdatePolicy::AutoAll)]
#[case("1.1.0", 9, "@acme", false, UpdatePolicy::AutoAll)]
#[case("1.1.0", 7, "@other", false, UpdatePolicy::AutoAll)]
#[case("1.1.0", 7, "@acme", true, UpdatePolicy::AutoAll)]
fn blocked_updates_leave_the_installed_copy_untouched(
    #[case] version: &str,
    #[case] seed: u8,
    #[case] publisher: &str,
    #[case] added: bool,
    #[case] policy: UpdatePolicy,
) {
    let mut fixture = Fixture::new();
    fixture.install();
    fixture.source(version, seed, publisher, added);
    assert!(fixture.prepare(policy).is_err());
    assert_eq!(fixture.version(), "1.0.0");
}

#[test]
fn revoking_trust_after_preparation_refuses_the_commit() {
    let mut fixture = Fixture::new();
    fixture.install();
    fixture.source("1.1.0", 7, "@acme", false);
    let prepared = fixture.prepare(UpdatePolicy::AutoMinor).expect("admitted");
    fixture
        .db
        .set_publisher_trust("@acme", synra_store::TRUST_REVOKED, 4)
        .expect("revoke");
    assert_eq!(
        prepared
            .install(&mut fixture.db, 5)
            .expect_err("refused")
            .stage,
        "update-policy"
    );
    assert_eq!(fixture.version(), "1.0.0");
}

#[test]
fn unsigned_updates_and_replacing_the_installed_version_are_refused() {
    let mut fixture = Fixture::new();
    fixture.install();
    fixture.source("1.1.0", 7, "@acme", false);
    std::fs::remove_file(fixture.root.join("source/signature.json")).expect("unsigned");
    assert_eq!(
        fixture
            .prepare(UpdatePolicy::AutoAll)
            .expect_err("unsigned")
            .stage,
        "update-policy"
    );
    fixture.source("1.1.0", 7, "@acme", false);
    let prepared = fixture.prepare(UpdatePolicy::AutoAll).expect("admitted");
    fixture
        .db
        .record_plugin_version("@acme/hello", "1.0.1", "plugin.wasm", "digest", "{}", 4)
        .expect("replacement");
    assert!(prepared.install(&mut fixture.db, 5).is_err());
    assert_eq!(fixture.version(), "1.0.1");
}

#[test]
fn manual_replacements_keep_verified_bytes_and_recheck_version_and_revocation() {
    for reason in ["source", "version", "revocation"] {
        let mut fixture = Fixture::new();
        fixture.install();
        fixture.source("1.1.0-beta.1", 7, "@acme", false);
        let prepared = crate::install::prepare_replacement(
            &fixture.db,
            &fixture.backend,
            &fixture.root.join("plugins"),
            &fixture.root.join("source"),
            3,
            HostFacts::headless(),
        )
        .expect("prepared manual update");
        match reason {
            "source" => std::fs::write(
                fixture.root.join("source/plugin.wasm"),
                b"corrupt after verification",
            )
            .expect("changed source"),
            "version" => fixture
                .db
                .record_plugin_version("@acme/hello", "1.0.1", "plugin.wasm", "digest", "{}", 4)
                .expect("different installed version"),
            _ => {
                fixture
                    .db
                    .set_publisher_trust("@acme", synra_store::TRUST_REVOKED, 4)
                    .expect("revoke");
            }
        }
        let outcome = prepared.install(&mut fixture.db, 5);
        if reason == "source" {
            assert!(outcome.is_ok());
            assert_eq!(
                std::fs::read(fixture.root.join("plugins/acme+hello/plugin.wasm"))
                    .expect("installed bytes"),
                b"\0asm\x01\0\0\0"
            );
            assert_eq!(fixture.version(), "1.1.0-beta.1");
        } else {
            assert!(outcome.is_err());
            assert_ne!(fixture.version(), "1.1.0-beta.1");
        }
    }
}
