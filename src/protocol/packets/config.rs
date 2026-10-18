use serde_json::Value;

use super::{Packet, PacketKind};
use crate::protocol::text::{read_component, write_component};
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
}
