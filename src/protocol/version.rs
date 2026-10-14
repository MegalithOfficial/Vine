use std::fmt;

use pumpkin_util::version::JavaMinecraftVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
    pub const V1_7_2: Self = Self(4);
    pub const V1_8: Self = Self(47);
    pub const V1_12_2: Self = Self(340);
    pub const V1_13: Self = Self(393);
    pub const V1_16: Self = Self(735);
    pub const V1_19: Self = Self(759);
    pub const V1_19_1: Self = Self(760);
    pub const V1_19_3: Self = Self(761);
    pub const V1_20_2: Self = Self(764);
    pub const V1_20_3: Self = Self(765);
    pub const V1_20_5: Self = Self(766);

    pub fn from_handshake(raw: i32) -> Self {
        Self(raw.max(0) as u32)
    }

    pub fn is_known(self) -> bool {
        self.to_pumpkin() != JavaMinecraftVersion::Unknown
    }

    pub fn name(self) -> String {
        if self.is_known() {
            self.to_pumpkin().to_string()
        } else {
            format!("unknown ({})", self.0)
        }
    }

    pub(crate) fn to_pumpkin(self) -> JavaMinecraftVersion {
        JavaMinecraftVersion::from_protocol(self.0)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (protocol {})", self.name(), self.0)
    }
}
