//! The cache's mapping, its lifetime, and what the client does when nobody answers.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{Cached, CatalogCache, CatalogClient, CatalogError, Fetches, Origin, packument_url};
use crate::registry::{PackagePattern, RegistryConfig, RegistryMirror};

/// A packument the parser accepts.
fn packument(name: &str, version: &str) -> String {
    format!(
        r#"{{"name":"{name}","dist-tags":{{"latest":"{version}"}},"versions":{{
            "{version}":{{"name":"{name}","version":"{version}","dist":{{"tarball":"https://x/y.tgz","integrity":"sha512-AAAA"}}}}
        }}}}"#
    )
}

/// A fetcher that answers from a table, and records what it was asked for.
#[derive(Default)]
struct Scripted {
    answers: RefCell<BTreeMap<String, Result<String, String>>>,
    asked: RefCell<Vec<String>>,
}

impl Scripted {
    fn answering(url: &str, body: &str) -> Self {
        let scripted = Self::default();
        scripted.answers.borrow_mut().insert(url.to_owned(), Ok(body.to_owned()));
        scripted
    }

    fn failing(url: &str, why: &str) -> Self {
        let scripted = Self::default();
        scripted.answers.borrow_mut().insert(url.to_owned(), Err(why.to_owned()));
        scripted
    }

    fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }
}

impl Fetches for &Scripted {
    /// ★ Matched by **suffix** rather than by the whole URL.
    ///
    /// Because `RegistryConfig::resolve` appends the default registry after whatever was configured, so a configured mirror
    /// is never the only URL a package resolves to. Keying the table on the whole URL made every test here fail against a
    /// third attempt nobody wrote — which is the same fact `nothing_at_all_is_an_error_that_names_every_attempt` asserts on
    /// purpose.
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        self.asked.borrow_mut().push(url.to_owned());
        for (key, answer) in self.answers.borrow().iter() {
            if url.starts_with(key) {
                return match answer {
                    Ok(body) => Ok(body.clone().into_bytes()),
                    Err(why) => Err(why.clone()),
                };
            }
        }
        Err("nothing is listening".to_owned())
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = format!("synra-catalog-{label}-{}", std::process::id());
        let path = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(mirrors: &[(&str, u8)]) -> RegistryConfig {
    let mut config = RegistryConfig::new();
    for (url, priority) in mirrors {
        config = config.with_mirror(RegistryMirror::new(*url, *priority));
    }
    config
}

mod paths;
mod lifetime;
mod client;
