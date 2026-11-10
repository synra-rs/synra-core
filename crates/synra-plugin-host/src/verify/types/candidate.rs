use synra_plugin_api::publisher::Digests;

use crate::{host_surface, verify::DependencyGraph};

/// What the pipeline is checking.
///
/// # Why the artifact's bytes are here rather than the artifact
///
/// Because the digest step is the first thing that happens to a package — before it has been parsed, before it has
/// been trusted, and before anything has decided it is worth parsing. A type that required a `Manifest` would make
/// "check the bytes" impossible to express without first doing the thing the check exists to protect.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// The manifest file's bytes, exactly as they arrived.
    pub manifest_json: &'a str,
    /// The artifact's bytes.
    pub artifact: &'a [u8],
    /// The digest the source declared for the artifact, if it declared one.
    ///
    /// `None` is not "trust anything": it means the source made no claim, which is the case for a local build an
    /// author is testing. A source that *did* make a claim is what the digest step enforces.
    pub declared_digest: Option<&'a str>,
    /// The artifact's own digest, computed by whoever fetched it.
    pub actual_digest: &'a str,
    /// The digest of the manifest's bytes, in the same SRI form the signature uses.
    ///
    /// A field rather than a value this pipeline computes, because this crate is given bytes and touches neither a
    /// filesystem nor a hash function: whoever read the package is who computes it, and a second implementation of
    /// "which bytes, which encoding" would be a second answer to a question that has one.
    pub manifest_digest: &'a str,
    /// Every artifact the package contains, by file name, with the SRI digest of its bytes.
    ///
    /// The whole set rather than the one artifact the runtime names, because the signature covers the set: a file
    /// added after signing makes a different package, and comparing a single digest would not see it.
    pub artifacts: &'a Digests,
    /// The `signature.json` text, when the package carries one.
    pub signature: Option<&'a str>,
    /// Whether this host requires a signature.
    ///
    /// A field rather than a constant because the answer depends on where the package came from: an author's own
    /// build has no publisher and a registry install has one, and a host that demanded a signature for both would
    /// make a local plugin impossible while a host that demanded neither would make `Unsigned` unrepresentable.
    pub signature_required: bool,
    /// Every plugin this one depends on, and what each of those depends on.
    ///
    /// The whole graph rather than this plugin's edges, because a cycle is a property of the graph: a plugin that
    /// depends on another which depends back on it cannot be detected from either one alone.
    pub dependencies: &'a DependencyGraph,
    /// What this host is.
    pub host: HostFacts,
}

/// What the host can do, for the two checks that are about it rather than about the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// The WIT world this host provides, as the contract declares it.
    pub wit: String,
    /// The platform actions this host can perform.
    ///
    /// A plugin that needs one this host cannot do is not *broken* — it is one whose button will fail on this machine
    /// and work on another, which is a warning rather than a refusal.
    pub actions: Vec<String>,
    /// Whether this host has a network at all.
    pub has_network: bool,
    /// The platform, for a message that names it.
    pub platform: String,
}

impl HostFacts {
    /// A host with everything, which is what a desktop test wants.
    #[must_use]
    pub fn desktop() -> Self {
        Self {
            wit: host_world(),
            actions: host_surface::CAPABILITIES.iter().map(|capability| (*capability).to_owned()).collect(),
            has_network: true,
            platform: "desktop".to_owned(),
        }
    }

    /// A host with nothing, which is what a headless kernel is.
    #[must_use]
    pub fn headless() -> Self {
        Self {
            wit: host_world(),
            actions: Vec::new(),
            has_network: false,
            platform: "headless".to_owned(),
        }
    }
}

/// The WIT world this build implements, as the contract names it.
///
/// `${PACKAGE}/${world}@${VERSION}`, which is how a WIT world is spelled. Read from the generated table rather than
/// written here, so a contract version bump cannot leave the compatibility check behind.
#[must_use]
pub fn host_world() -> String {
    format!(
        "{}@{}",
        host_surface::PACKAGE,
        host_surface::PACKAGE_VERSION
    )
}
