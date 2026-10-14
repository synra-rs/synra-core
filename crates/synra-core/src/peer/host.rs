use synra_protocol::handshake::{Feature, Hello, HelloAck, PROTOCOL_VERSION, PairingState, SessionNonce};
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

/// What a device says about itself during a handshake.
///
/// # Why this is not `synra_core::Identity`
///
/// The identity is the kernel's and lives with the database; this is what the **wire** needs, which is the identity plus
/// the features this build has. Depending on the kernel from here would put a database behind a network layer, and a test
/// of an exchange would need one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPeer {
    /// Which device this is.
    pub device_id: DeviceId,
    /// The name to show the other user.
    pub display_name: String,
    /// Which platform.
    pub platform: PlatformKind,
    /// This build, for support conversations.
    pub app_version: String,
    /// What this build can do.
    pub features: Vec<Feature>,
    /// The features without which it would rather not connect.
    pub requires: Vec<Feature>,
}

impl LocalPeer {
    /// The features every build of this kernel has.
    ///
    /// A hand-written list with a test that checks it against the protocol's own catalogue, because the failure is
    /// silent: a build that forgot to announce a feature it implements would be one whose peers decline to use it, and
    /// nothing would say why.
    #[must_use]
    pub fn default_features() -> Vec<Feature> {
        // `Feature::ALL` is the protocol's catalogue, and announcing all of it is the honest answer for a build that has
        // no feature gate of its own. A build that gained one would subtract here rather than list from scratch.
        Feature::ALL.to_vec()
    }

    /// Builds one with the default features.
    #[must_use]
    pub fn new(
        device_id: DeviceId,
        display_name: impl Into<String>,
        platform: PlatformKind,
        app_version: impl Into<String>,
    ) -> Self {
        Self {
            device_id,
            display_name: display_name.into(),
            platform,
            app_version: app_version.into(),
            features: Self::default_features(),
            requires: Vec::new(),
        }
    }

    /// What this device announces to the network.
    ///
    /// # Why the port is an argument
    ///
    /// Because it is the **connection** port — where a peer opens a TCP link — and this type does not hold it: the
    /// listener is bound by the daemon, after the local peer is built. A `LocalPeer` that guessed would announce a port
    /// nothing is listening on, which is a device that appears in every list and cannot be connected to.
    ///
    /// # Why not every feature is announced
    ///
    /// `DeviceAnnouncement`'s feature list is a *hint*, and the protocol says so: discovery is unauthenticated, and the
    /// handshake is where ability is established. Announcing them anyway is what lets a peer skip an obviously
    /// incompatible candidate without a connection attempt.
    #[must_use]
    pub fn announcement(&self, port: u16) -> synra_protocol::discovery::DeviceAnnouncement {
        synra_protocol::discovery::DeviceAnnouncement {
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            protocol: PROTOCOL_VERSION,
            port,
            platform: Some(self.platform),
            app_version: Some(self.app_version.clone()),
            features: self.features.clone(),
        }
    }

    /// The `Hello` this device sends.
    #[must_use]
    pub fn hello(&self, nonce: SessionNonce, sequence: u64) -> Hello {
        Hello {
            protocol: PROTOCOL_VERSION,
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            platform: self.platform,
            app_version: self.app_version.clone(),
            nonce,
            features: self.features.clone(),
            requires: self.requires.clone(),
            token: None,
            sequence,
            endpoints: Vec::new(),
        }
    }

    /// The `HelloAck` this device sends in answer.
    ///
    /// # Why the pairing state is an argument
    ///
    /// Because deciding it needs the pairing store, which this layer does not have. An acceptor that guessed would be one
    /// that told a peer it was still paired when it was not — and the peer would then send work the other end cannot
    /// attribute.
    #[must_use]
    pub fn hello_ack(&self, nonce: SessionNonce, pairing: PairingState, sequence: u64) -> HelloAck {
        HelloAck {
            protocol: PROTOCOL_VERSION,
            device_id: self.device_id,
            display_name: self.display_name.clone(),
            platform: self.platform,
            app_version: self.app_version.clone(),
            nonce,
            features: self.features.clone(),
            requires: self.requires.clone(),
            pairing,
            refusal: None,
            sequence,
            endpoints: Vec::new(),
        }
    }
}
