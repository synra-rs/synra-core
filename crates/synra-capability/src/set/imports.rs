//! What a plugin declares it imports, and what it therefore receives.

use crate::capability::Capability;
use smallvec::SmallVec;

use super::limits::CapabilitySet;

/// The interfaces a Wasm module imports, as read from its type section.
///
/// The third of the three declarations that have to agree. A plugin can *ask* for a capability in its
/// manifest and be *granted* it by the user, and still be unable to call the corresponding host
/// function because the module never imported it. All three are needed, and the intersection is what
/// the plugin actually holds.
#[derive(Debug, Clone, Default)]
pub struct ImportSet {
    /// The imported interface names, such as `host:network-fetch`.
    interfaces: SmallVec<[compact_str::CompactString; 8]>,
}

impl ImportSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from interface names.
    #[must_use]
    pub fn from_interfaces<I, S>(interfaces: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::new();
        for interface in interfaces {
            set.insert(interface.as_ref());
        }
        set
    }

    /// Records an imported interface.
    pub fn insert(&mut self, interface: &str) {
        let interface = compact_str::CompactString::from(interface);
        if !self.interfaces.contains(&interface) {
            self.interfaces.push(interface);
        }
    }

    /// Whether an interface was imported.
    #[must_use]
    pub fn contains(&self, interface: &str) -> bool {
        self.interfaces.iter().any(|existing| existing == interface)
    }

    /// Every imported interface.
    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.interfaces.iter().map(compact_str::CompactString::as_str)
    }

    /// How many interfaces were imported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Whether nothing was imported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

/// The capabilities a plugin actually holds, after all three declarations are reconciled.
#[derive(Debug, Clone)]
pub struct EffectiveCaps {
    /// The reconciled set: manifest wanted, user granted, and module imported.
    pub granted: CapabilitySet,
    /// What the user granted that the module never imports.
    ///
    /// A warning rather than a refusal. It is not dangerous — an unimported function cannot be
    /// called — but it means the consent prompt showed the user something the plugin cannot use,
    /// which is worth reporting so the manifest can be fixed.
    pub unused: Vec<Capability>,
    /// What the module imports that no granted capability covers.
    ///
    /// A refusal. The plugin would call a host function with no authorisation behind it, and the gate
    /// would deny it at runtime — so the failure would appear once per call rather than once at load.
    pub uncovered: Vec<String>,
}

impl EffectiveCaps {
    /// Whether the plugin may be loaded.
    #[must_use]
    pub const fn is_loadable(&self) -> bool {
        self.uncovered.is_empty()
    }
}
