use super::{Packet, PacketKind};
use crate::protocol::wire::{ReadExt, WriteExt};
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

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let protocol_version = buf.read_varint()?;
        let server_address = buf.read_string_bounded(255)?;
        let server_port = buf.read_u16()?;
        let intent = match buf.read_varint()? {
            1 => HandshakeIntent::Status,
            2 => HandshakeIntent::Login,
            3 => HandshakeIntent::Transfer,
            other => {
                return Err(ProtocolError::Malformed(format!(
                    "invalid handshake intent {other}"
                )));
            }
        };
        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            intent,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_varint(self.protocol_version);
        buf.write_string(&self.server_address);
        buf.write_u16(self.server_port);
        buf.write_varint(match self.intent {
            HandshakeIntent::Status => 1,
            HandshakeIntent::Login => 2,
            HandshakeIntent::Transfer => 3,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode_packet, encode_packet};

    #[test]
    fn test_handshake_round_trip() {
        let packet = Handshake {
            protocol_version: 769,
            server_address: "play.example.com".into(),
            server_port: 25565,
            intent: HandshakeIntent::Login,
        };
        let v = ProtocolVersion(769);
        let bytes = encode_packet(&packet, v).unwrap();
        assert_eq!(bytes[0], 0x00);
        let decoded: Handshake = decode_packet(&bytes[1..], v).unwrap();
        assert_eq!(decoded.protocol_version, 769);
        assert_eq!(decoded.server_address, "play.example.com");
        assert_eq!(decoded.server_port, 25565);
        assert_eq!(decoded.intent, HandshakeIntent::Login);
    }
}
