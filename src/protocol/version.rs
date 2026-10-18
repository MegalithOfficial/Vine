use std::fmt;

use super::generated::RELEASES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
    pub const V1_7_6: Self = Self(5);
    pub const V1_8: Self = Self(47);
    pub const V1_11: Self = Self(315);
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

    pub fn oldest() -> Self {
        Self(RELEASES[0].0)
    }

    pub fn latest() -> Self {
        Self(RELEASES[RELEASES.len() - 1].0)
    }

    pub fn is_known(self) -> bool {
        RELEASES.binary_search_by_key(&self.0, |(p, _)| *p).is_ok()
    }

    pub fn name(self) -> String {
        match RELEASES.binary_search_by_key(&self.0, |(p, _)| *p) {
            Ok(i) => RELEASES[i].1.to_string(),
            Err(_) => format!("unknown ({})", self.0),
        }
    }

    pub fn supported_range() -> String {
        let first = RELEASES[0].1.split('-').next().unwrap_or_default();
        let last = RELEASES[RELEASES.len() - 1]
            .1
            .rsplit('-')
            .next()
            .unwrap_or_default();
        format!("{first}-{last}")
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (protocol {})", self.name(), self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_versions() {
        assert!(ProtocolVersion(47).is_known());
        assert_eq!(ProtocolVersion(47).name(), "1.8-1.8.9");
        assert!(!ProtocolVersion(4).is_known());
        assert!(!ProtocolVersion(9999).is_known());
        assert!(ProtocolVersion::oldest() < ProtocolVersion::latest());
    }
}
