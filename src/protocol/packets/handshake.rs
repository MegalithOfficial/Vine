use pumpkin_protocol::ConnectionState;
use pumpkin_protocol::ServerPacket;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::server::handshake::SHandShake;

use super::{Packet, PacketKind, read_error, write_pumpkin};
use crate::protocol::{ProtocolError, ProtocolVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeIntent {
    Status,
    Login,
    Transfer,
}

#[derive(Clone, Debug)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub intent: HandshakeIntent,
}

impl Packet for Handshake {
    const KIND: PacketKind = PacketKind::Handshake;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let packet = SHandShake::read(buf, &version.to_pumpkin()).map_err(read_error)?;
        let intent = match packet.next_state {
            ConnectionState::Status => HandshakeIntent::Status,
            ConnectionState::Login => HandshakeIntent::Login,
            ConnectionState::Transfer => HandshakeIntent::Transfer,
            other => {
                return Err(ProtocolError::Malformed(format!(
                    "invalid handshake intent {other:?}"
                )));
            }
        };
        Ok(Self {
            protocol_version: packet.protocol_version.0,
            server_address: packet.server_address.into_string(),
            server_port: packet.server_port,
            intent,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        let next_state = match self.intent {
            HandshakeIntent::Status => ConnectionState::Status,
            HandshakeIntent::Login => ConnectionState::Login,
            HandshakeIntent::Transfer => ConnectionState::Transfer,
        };
        let packet = SHandShake {
            protocol_version: VarInt(self.protocol_version),
            server_address: self.server_address.clone().into_boxed_str(),
            server_port: self.server_port,
            next_state,
        };
        write_pumpkin(&packet, buf, version)
    }
}
