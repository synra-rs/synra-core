//! Queries over the interfaces selected by a parsed world.

use super::{Contract, Direction, Interface};

impl Contract {
    /// The host's interface, which is the one the capability table is about.
    #[must_use]
    pub fn host(&self) -> Option<&Interface> {
        let name = self.host_interface.as_deref()?;
        self.interfaces.iter().find(|interface| interface.name == name)
    }

    /// Every interface a plugin exports.
    #[must_use]
    pub fn exports(&self) -> Vec<&Interface> {
        // Only the interfaces the world *names* as exports. `types` is declared in the file and named by nobody, so a
        // filter on direction alone listed it — its default — and a reader would think the plugin had to implement it.
        self.world_names
            .iter()
            .filter(|(_, direction)| *direction == Direction::Export)
            .filter_map(|(name, _)| self.interfaces.iter().find(|interface| interface.name == *name))
            .collect()
    }
}
