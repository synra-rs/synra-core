/// Why a package was refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The artifact is not the one the source declared.
    #[error("the artifact does not match what its source declared")]
    DigestMismatch,

    /// The signature is not valid, or there is none where one is required.
    #[error("the signature could not be verified: {reason}")]
    BadSignature {
        /// What was wrong.
        reason: String,
    },

    /// The signature is genuine, and it covers different bytes than the package contains.
    ///
    /// # Why this is not [`Self::BadSignature`]
    ///
    /// Because the next step differs. A bad signature is a document, a key or a transfer that was altered — signing
    /// again is the fix. This one is a package and a signature that do not belong together: an artifact rebuilt after
    /// signing, a manifest edited afterwards, a `signature.json` copied from another release. Re-signing is the right
    /// answer there too, but "the signature could not be verified" would send an author to look for a corruption that
    /// is not there.
    #[error("the signature is valid but covers different bytes: {detail}")]
    SignatureCoversOtherBytes {
        /// The first difference, in a sentence naming the file.
        detail: String,
    },

    /// A signature was required and there is none.
    #[error("this package is unsigned and this host requires a signature")]
    Unsigned,

    /// The publisher is one this device refuses.
    #[error("{why}")]
    UntrustedPublisher {
        /// Why, in a sentence a user can act on.
        why: synra_plugin_api::publisher::Untrusted,
    },

    /// The manifest is not valid.
    #[error("the manifest is not valid: {reason}")]
    InvalidManifest {
        /// What the validator said, which names the field.
        reason: String,
    },

    /// A capability is not one the contract mentions.
    #[error("the manifest declares {capability}, which no host function needs")]
    UnknownCapability {
        /// The capability string, as the manifest spells it.
        capability: String,
    },

    /// The plugin was built against a WIT world this host does not have.
    #[error("the plugin was built for {required} and this host provides {provided}")]
    WitIncompatible {
        /// What the plugin declares.
        required: String,
        /// What this host has.
        provided: String,
    },

    /// Actual component bytes do not implement the required plugin world.
    #[error("the component is invalid: {source}")]
    InvalidComponent {
        /// Classified static validation failure.
        source: crate::component::ComponentError,
    },

    /// The artifact imports a function no declared capability covers.
    #[error("the artifact imports {import}, which the manifest's capabilities do not cover")]
    UndeclaredImport {
        /// The import name, in full.
        import: String,
    },

    /// The artifact imports something the host refuses outright.
    #[error("the artifact imports {import}, which this host never provides")]
    ForbiddenImport {
        /// The import name.
        import: String,
    },

    /// A plugin depends on itself, directly or through others.
    #[error("the dependency graph has a cycle: {}", .cycle.join(" -> "))]
    DependencyCycle {
        /// The cycle, starting and ending at the same plugin.
        cycle: Vec<String>,
    },

    /// The archive is outside the bounds.
    #[error("the archive is outside the limits: {detail}")]
    ArchiveTooLarge {
        /// What was found.
        detail: String,
    },

    /// The plugin cannot run on this machine.
    #[error("the plugin needs {needed}, which this host does not support")]
    PlatformUnsupported {
        /// What it needs.
        needed: String,
    },
}
