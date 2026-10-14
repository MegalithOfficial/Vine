use pumpkin_util::text::TextComponent;

use super::{Packet, PacketKind};
use crate::protocol::{ProtocolError, ProtocolVersion};

#[derive(Clone, Debug)]
pub struct ConfigDisconnect {
    pub reason: TextComponent,
}

impl Packet for ConfigDisconnect {
    const KIND: PacketKind = PacketKind::ConfigDisconnect;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: crate::protocol::text::read_component(buf, version)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        let json = serde_json::to_string(&self.reason)
            .map_err(|e| ProtocolError::Encode(e.to_string()))?;
        super::write_pumpkin(
            &pumpkin_protocol::java::client::config::CConfigDisconnect::new(&json),
            buf,
            version,
        )
    }
}
