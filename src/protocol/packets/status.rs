use pumpkin_protocol::java::client::status::{CPingResponse, CStatusResponse};

use super::{Packet, PacketKind, write_pumpkin};
use crate::protocol::wire::ReadExt;
use crate::protocol::{ProtocolError, ProtocolVersion};

#[derive(Clone, Debug)]
pub struct StatusResponse {
    pub json: String,
}

impl Packet for StatusResponse {
    const KIND: PacketKind = PacketKind::StatusResponse;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            json: buf.read_string()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(&CStatusResponse::new(self.json.clone()), buf, version)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PingRequest {
    pub payload: i64,
}

impl Packet for PingRequest {
    const KIND: PacketKind = PacketKind::PingRequest;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            payload: buf.read_i64()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.extend_from_slice(&self.payload.to_be_bytes());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PongResponse {
    pub payload: i64,
}

impl Packet for PongResponse {
    const KIND: PacketKind = PacketKind::PongResponse;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            payload: buf.read_i64()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(&CPingResponse::new(self.payload), buf, version)
    }
}
