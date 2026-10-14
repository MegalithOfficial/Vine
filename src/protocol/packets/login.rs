use pumpkin_protocol::ServerPacket;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::login::{
    CEncryptionRequest, CLoginDisconnect, CSetCompression,
};
use pumpkin_protocol::java::server::login::{
    SEncryptionResponse, SLoginPluginResponse, SLoginStart,
};
use uuid::Uuid;

use super::{Packet, PacketKind, read_error, write_pumpkin};
use crate::protocol::wire::ReadExt;
use crate::protocol::{ProtocolError, ProtocolVersion};

#[derive(Clone, Debug)]
pub struct LoginStart {
    pub name: String,
    pub uuid: Option<Uuid>,
}

impl Packet for LoginStart {
    const KIND: PacketKind = PacketKind::LoginStart;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let packet = SLoginStart::read(buf, &version.to_pumpkin()).map_err(read_error)?;
        Ok(Self {
            name: packet.name.into_string(),
            uuid: Some(packet.uuid),
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        let packet = SLoginStart {
            name: self.name.clone().into_boxed_str(),
            uuid: self.uuid.unwrap_or_default(),
        };
        write_pumpkin(&packet, buf, version)
    }
}

#[derive(Clone, Debug)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
    pub should_authenticate: bool,
}

impl Packet for EncryptionRequest {
    const KIND: PacketKind = PacketKind::EncryptionRequest;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            server_id: buf.read_string_bounded(20)?,
            public_key: buf.read_byte_array()?,
            verify_token: buf.read_byte_array()?,
            should_authenticate: buf.read_bool().unwrap_or(true),
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        let packet = CEncryptionRequest::new(
            &self.server_id,
            &self.public_key,
            &self.verify_token,
            self.should_authenticate,
        );
        write_pumpkin(&packet, buf, version)
    }
}

#[derive(Clone, Debug)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl Packet for EncryptionResponse {
    const KIND: PacketKind = PacketKind::EncryptionResponse;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let packet = SEncryptionResponse::read(buf, &version.to_pumpkin()).map_err(read_error)?;
        Ok(Self {
            shared_secret: packet.shared_secret.into_vec(),
            verify_token: packet.verify_token.into_vec(),
        })
    }

    fn write(&self, _buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        Err(ProtocolError::UnsupportedPacket(Self::KIND, version))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SetCompression {
    pub threshold: i32,
}

impl Packet for SetCompression {
    const KIND: PacketKind = PacketKind::SetCompression;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            threshold: buf.read_varint()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(&CSetCompression::new(VarInt(self.threshold)), buf, version)
    }
}

// Always JSON, even on versions that use NBT components elsewhere
#[derive(Clone, Debug)]
pub struct LoginDisconnect {
    pub reason_json: String,
}

impl Packet for LoginDisconnect {
    const KIND: PacketKind = PacketKind::LoginDisconnect;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason_json: buf.read_string_bounded(262_144)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(
            &CLoginDisconnect::new(self.reason_json.clone()),
            buf,
            version,
        )
    }
}

#[derive(Clone, Debug)]
pub struct LoginPluginRequest {
    pub message_id: i32,
    pub channel: String,
    pub data: Vec<u8>,
}

impl Packet for LoginPluginRequest {
    const KIND: PacketKind = PacketKind::LoginPluginRequest;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let message_id = buf.read_varint()?;
        let channel = buf.read_string()?;
        let data = std::mem::take(buf).to_vec();
        Ok(Self {
            message_id,
            channel,
            data,
        })
    }

    fn write(&self, _buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        Err(ProtocolError::UnsupportedPacket(Self::KIND, version))
    }
}

// `data: None` tells the backend the channel is not understood
#[derive(Clone, Debug)]
pub struct LoginPluginResponse {
    pub message_id: i32,
    pub data: Option<Vec<u8>>,
}

impl Packet for LoginPluginResponse {
    const KIND: PacketKind = PacketKind::LoginPluginResponse;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let message_id = buf.read_varint()?;
        let data = if buf.read_bool()? {
            Some(std::mem::take(buf).to_vec())
        } else {
            None
        };
        Ok(Self { message_id, data })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        let packet = SLoginPluginResponse {
            message_id: VarInt(self.message_id),
            data: self.data.clone().map(Vec::into_boxed_slice),
        };
        write_pumpkin(&packet, buf, version)
    }
}
