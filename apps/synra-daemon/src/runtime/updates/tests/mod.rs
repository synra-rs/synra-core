//! Shared loopback registries and installed plugin fixtures for update scenarios.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use synra_control::Kernel as _;
use synra_core::plugin_updates::AUTO_UPDATE_KEY;

use super::{Cancellation, Runtime, source};

mod manual;
mod policy;
mod replacement;
mod scheduling;
mod sources;

struct Registry {
    base: String,
    document: Arc<Mutex<(u16, String)>>,
    tarball: Arc<Mutex<(u16, Vec<u8>)>>,
    requests: Arc<AtomicUsize>,
    cancel: Cancellation,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Registry {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let document = Arc::new(Mutex::new((200, String::new())));
        let tarball = Arc::new(Mutex::new((200, Vec::new())));
        let requests = Arc::new(AtomicUsize::new(0));
        let cancel = Cancellation::new();
        let (text, bytes, counted, stop) = (
            Arc::clone(&document),
            Arc::clone(&tarball),
            Arc::clone(&requests),
            cancel.clone(),
        );
        let worker = std::thread::spawn(move || {
            while !stop.is_cancelled() {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("blocking accepted socket");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read deadline");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write deadline");
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                            let mut byte = [0];
                            if stream.read_exact(&mut byte).is_err() {
                                break;
                            }
                            request.extend(byte);
                        }
                        counted.fetch_add(1, Ordering::SeqCst);
                        let (status, body) = if String::from_utf8_lossy(&request).contains(".tgz ")
                        {
                            bytes.lock().clone()
                        } else {
                            let (status, body) = text.lock().clone();
                            (status, body.into_bytes())
                        };
                        write!(stream, "HTTP/1.1 {status} Result\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()).expect("headers");
                        stream.write_all(&body).expect("body");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop.wait(Duration::from_millis(2)) {
                            break;
                        }
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            }
        });
        Self {
            base,
            document,
            tarball,
            requests,
            cancel,
            worker: Some(worker),
        }
    }

    fn publish(&self, directory: &Path, version: &str, is_static: bool) {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for file in ["manifest.json", "plugin.wasm", "signature.json"] {
            tar.append_path_with_name(directory.join(file), format!("package/{file}"))
                .expect("tar entry");
        }
        let bytes = tar.into_inner().expect("tar").finish().expect("gzip");
        let integrity = synra_core::transfer::ObjectDigest::of(&bytes)
            .as_sri()
            .to_string();
        let document = if is_static {
            serde_json::json!({"name":"@acme/hello", "latest":version,
                "versions":[{"version":version, "tarball":"hello.tgz", "integrity":integrity}]})
        } else {
            serde_json::json!({"name":"@acme/hello", "dist-tags":{"latest":version},
                "versions":{version:{"name":"@acme/hello", "version":version,
                    "dist":{"tarball":format!("{}/hello.tgz", self.base), "integrity":integrity}}}})
        };
        *self.document.lock() = (200, document.to_string());
        *self.tarball.lock() = (200, bytes);
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = self.worker.take() {
            worker.join().expect("server stopped");
        }
    }
}

fn signed_source(directory: &Path, version: &str, seed: u8, extra: bool) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use synra_plugin_api::publisher::{Digests, SigningSubject};

    std::fs::create_dir_all(directory).expect("source");
    let capabilities = if extra {
        serde_json::json!([{"cap":"log:*"}, {"cap":"device:send:*"}])
    } else {
        serde_json::json!([{"cap":"log:*"}])
    };
    let manifest = serde_json::json!({"id":"@acme/hello", "version":version, "title":"Hello", "publisher":{"id":"@acme"},
        "sdk":{"min":"0.1.0"}, "wit":synra_plugin_host::host_world(), "capabilities":capabilities,
        "runtime":{"headless":{"artifact":"plugin.wasm", "stateful":false}}}).to_string();
    let wasm_bytes = synra_testkit::component::inert_component().expect("a valid component");
    let wasm = wasm_bytes.as_slice();
    let mut artifacts = Digests::new();
    artifacts.insert(
        "plugin.wasm",
        synra_core::transfer::ObjectDigest::of(wasm)
            .as_sri()
            .to_string(),
    );
    let subject = SigningSubject {
        manifest: synra_plugin_api::manifest_digest(&manifest),
        artifacts,
    };
    let key = SigningKey::from_bytes(&[seed; 32]);
    let signature = serde_json::json!({"version":1, "publisher":{"id":"@acme"}, "algorithm":"ed25519", "signedAt":"2026-10-22T00:00:00Z",
        "pubkey":STANDARD.encode(key.verifying_key().as_bytes()),
        "subject":{"manifest":subject.manifest, "artifacts":subject.artifacts.iter().collect::<std::collections::BTreeMap<_,_>>()},
        "signature":STANDARD.encode(key.sign(&subject.canonical_bytes()).to_bytes())});
    std::fs::write(directory.join("manifest.json"), manifest).expect("manifest");
    std::fs::write(directory.join("signature.json"), signature.to_string()).expect("signature");
    std::fs::write(directory.join("plugin.wasm"), wasm).expect("wasm");
}

fn installed(root: &Path) -> Runtime {
    let runtime = crate::runtime::tests::runtime(root);
    let first = root.join("first");
    signed_source(&first, "1.0.0", 7, false);
    runtime
        .plugin_install(first.to_str().expect("path"))
        .expect("install");
    let fingerprint = runtime.db().publishers().expect("publishers")[0]
        .fingerprint
        .clone();
    runtime
        .db()
        .set_publisher_trust("@acme", &fingerprint, synra_store::TRUST_TRUSTED, 1)
        .expect("trust publisher");
    runtime
        .plugin_consent("@acme/hello", &["log:*".to_owned()])
        .expect("consent");
    runtime
        .plugin_set_enabled("@acme/hello", true)
        .expect("enable");
    runtime
}

fn configure(runtime: &Runtime, registry: &Registry, policy: &str, is_static: bool) {
    let url = if is_static {
        format!("static:{}", registry.base)
    } else {
        registry.base.clone()
    };
    runtime
        .db()
        .set_config(source::REGISTRY_KEY, &serde_json::json!(url), 1)
        .expect("registry");
    runtime
        .db()
        .set_config(AUTO_UPDATE_KEY, &serde_json::json!(policy), 1)
        .expect("policy");
}
