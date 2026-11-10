use super::syntax::{Capability, CapabilityError};

impl TryFrom<String> for Capability {
    type Error = CapabilityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Capability::parse(&value)
    }
}
