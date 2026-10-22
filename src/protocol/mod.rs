pub mod bedrock;
pub mod codec;
mod generated;
pub mod packets;
pub mod text;
pub mod version;
pub mod wire;

pub use codec::{Frame, PacketReader, PacketWriter, RawPacket};
pub use packets::{Packet, PacketKind, decode_packet, encode_packet};
pub use version::ProtocolVersion;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("malformed packet: {0}")]
    Malformed(String),
    #[error("packet {0:?} does not exist in protocol version {1}")]
    UnsupportedPacket(PacketKind, ProtocolVersion),
    #[error("failed to encode packet: {0}")]
    Encode(String),
}
