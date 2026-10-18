use super::{Packet, PacketKind};
use crate::protocol::wire::{ReadExt, WriteExt};
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

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_string(&self.json);
        Ok(())
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
        buf.write_i64(self.payload);
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

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_i64(self.payload);
        Ok(())
    }
}
