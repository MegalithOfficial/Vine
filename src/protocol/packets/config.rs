use serde_json::Value;

use super::{Packet, PacketKind};
use crate::protocol::text::{read_component, write_component};
use crate::protocol::wire::{ReadExt, WriteExt};
use crate::protocol::{ProtocolError, ProtocolVersion};

macro_rules! empty_packet {
    ($name:ident, $kind:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl Packet for $name {
            const KIND: PacketKind = PacketKind::$kind;

            fn read(_buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
                Ok(Self)
            }

            fn write(
                &self,
                _buf: &mut Vec<u8>,
                _version: ProtocolVersion,
            ) -> Result<(), ProtocolError> {
                Ok(())
            }
        }
    };
}

pub(crate) use empty_packet;

empty_packet!(ConfigFinish, ConfigFinish);
empty_packet!(ConfigFinishAck, ConfigFinishAck);
empty_packet!(ConfigAcceptCodeOfConduct, ConfigAcceptCodeOfConduct);

#[derive(Clone, Debug)]
pub struct ConfigDisconnect {
    pub reason: Value,
}

impl Packet for ConfigDisconnect {
    const KIND: PacketKind = PacketKind::ConfigDisconnect;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: read_component(buf, version)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_component(buf, &self.reason, version);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigKeepAlive {
    pub id: i64,
}

impl Packet for ConfigKeepAlive {
    const KIND: PacketKind = PacketKind::ConfigKeepAlive;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: buf.read_i64()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_i64(self.id);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigKeepAliveResponse {
    pub id: i64,
}

impl Packet for ConfigKeepAliveResponse {
    const KIND: PacketKind = PacketKind::ConfigKeepAliveResponse;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: buf.read_i64()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_i64(self.id);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigPing {
    pub id: i32,
}

impl Packet for ConfigPing {
    const KIND: PacketKind = PacketKind::ConfigPing;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: buf.read_i32()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_i32(self.id);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigPong {
    pub id: i32,
}

impl Packet for ConfigPong {
    const KIND: PacketKind = PacketKind::ConfigPong;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: buf.read_i32()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_i32(self.id);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ConfigCodeOfConduct {
    pub text: String,
}

impl Packet for ConfigCodeOfConduct {
    const KIND: PacketKind = PacketKind::ConfigCodeOfConduct;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            text: buf.read_string_bounded(262_144)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_string(&self.text);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode_packet, encode_packet};
    use serde_json::json;

    #[test]
    fn test_config_disconnect_switches_to_nbt() {
        let packet = ConfigDisconnect {
            reason: json!({"text": "bye"}),
        };
        let json_bytes = encode_packet(&packet, ProtocolVersion(764)).unwrap();
        assert_eq!(json_bytes[0], 0x01);
        let nbt_bytes = encode_packet(&packet, ProtocolVersion(766)).unwrap();
        assert_eq!(nbt_bytes[0], 0x02);
        assert_eq!(nbt_bytes[1], 10);

        for (bytes, protocol) in [(json_bytes, 764), (nbt_bytes, 766)] {
            let decoded: ConfigDisconnect =
                decode_packet(&bytes[1..], ProtocolVersion(protocol)).unwrap();
            assert_eq!(decoded.reason, packet.reason);
        }
    }

    #[test]
    fn test_config_packets_missing_before_1_20_2() {
        assert!(encode_packet(&ConfigFinishAck, ProtocolVersion(763)).is_err());
        assert!(encode_packet(&ConfigFinishAck, ProtocolVersion(764)).is_ok());
    }
}
