use bytes::Bytes;
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::{PacketDecodeError, PacketEncodeError};
use tokio::io::{AsyncRead, AsyncWrite};

use super::ProtocolError;
use super::wire::WriteExt;

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub id: i32,
    pub payload: Bytes,
}

impl RawPacket {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.write_varint(self.id);
        buf.extend_from_slice(&self.payload);
        buf.into()
    }
}

impl From<PacketDecodeError> for ProtocolError {
    fn from(err: PacketDecodeError) -> Self {
        match err {
            PacketDecodeError::ConnectionClosed => ProtocolError::ConnectionClosed,
            other => ProtocolError::Malformed(other.to_string()),
        }
    }
}

impl From<PacketEncodeError> for ProtocolError {
    fn from(err: PacketEncodeError) -> Self {
        ProtocolError::Encode(err.to_string())
    }
}

pub struct PacketReader<R: AsyncRead + Unpin> {
    inner: TCPNetworkDecoder<R>,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            inner: TCPNetworkDecoder::new(reader),
        }
    }

    pub async fn read_packet(&mut self) -> Result<RawPacket, ProtocolError> {
        let packet = self.inner.get_raw_packet().await?;
        Ok(RawPacket {
            id: packet.id,
            payload: packet.payload,
        })
    }

    pub fn set_compression(&mut self, threshold: usize) {
        self.inner.set_compression(threshold);
    }

    pub fn enable_encryption(&mut self, key: &[u8; 16]) -> Result<(), ProtocolError> {
        Ok(self.inner.set_encryption(key)?)
    }
}

pub struct PacketWriter<W: AsyncWrite + Unpin> {
    inner: TCPNetworkEncoder<W>,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: TCPNetworkEncoder::new(writer),
        }
    }

    pub async fn write_packet(&mut self, packet: Bytes) -> Result<(), ProtocolError> {
        Ok(self.inner.write_packet(packet).await?)
    }

    pub async fn flush(&mut self) -> Result<(), ProtocolError> {
        Ok(self.inner.flush().await?)
    }

    pub async fn send(&mut self, packet: Bytes) -> Result<(), ProtocolError> {
        self.write_packet(packet).await?;
        self.flush().await
    }

    pub fn set_compression(&mut self, threshold: usize, level: u32) {
        self.inner.set_compression((threshold, level));
    }

    pub fn enable_encryption(&mut self, key: &[u8; 16]) -> Result<(), ProtocolError> {
        Ok(self.inner.set_encryption(key)?)
    }
}
