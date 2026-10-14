pub mod config;
pub mod handshake;
pub mod login;
pub mod play;
pub mod status;

use bytes::Bytes;
use pumpkin_protocol::java::{client, server};
use pumpkin_protocol::packet::MultiVersionJavaPacket;

use super::wire::WriteExt;
use super::{ProtocolError, ProtocolVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketKind {
    Handshake,

    StatusRequest,
    PingRequest,
    StatusResponse,
    PongResponse,

    LoginStart,
    EncryptionResponse,
    LoginPluginResponse,
    LoginDisconnect,
    EncryptionRequest,
    LoginSuccess,
    SetCompression,
    LoginPluginRequest,

    ConfigDisconnect,

    ChatCommand,
    ChatMessage,
    CommandSuggestionRequest,
    ServerboundPluginMessage,
    PlayDisconnect,
    SystemChat,
    Commands,
    CommandSuggestionsResponse,
    ClientboundPluginMessage,
    StartConfiguration,
    Transfer,
}

impl PacketKind {
    pub fn id(self, version: ProtocolVersion) -> Option<i32> {
        let v = version.to_pumpkin();
        let id = match self {
            Self::Handshake => server::handshake::SHandShake::to_id(v),
            Self::StatusRequest => server::status::SStatusRequest::to_id(v),
            Self::PingRequest => server::status::SStatusPingRequest::to_id(v),
            Self::StatusResponse => client::status::CStatusResponse::to_id(v),
            Self::PongResponse => client::status::CPingResponse::to_id(v),
            Self::LoginStart => server::login::SLoginStart::to_id(v),
            Self::EncryptionResponse => server::login::SEncryptionResponse::to_id(v),
            Self::LoginPluginResponse => server::login::SLoginPluginResponse::to_id(v),
            Self::LoginDisconnect => client::login::CLoginDisconnect::to_id(v),
            Self::EncryptionRequest => client::login::CEncryptionRequest::to_id(v),
            Self::LoginSuccess => client::login::CLoginSuccess::to_id(v),
            Self::SetCompression => client::login::CSetCompression::to_id(v),
            Self::LoginPluginRequest => client::login::CLoginPluginRequest::to_id(v),
            Self::ConfigDisconnect => client::config::CConfigDisconnect::to_id(v),
            Self::ChatCommand => server::play::SChatCommand::to_id(v),
            Self::ChatMessage => server::play::SChatMessage::to_id(v),
            Self::CommandSuggestionRequest => server::play::SCommandSuggestion::to_id(v),
            Self::ServerboundPluginMessage => server::play::SCustomPayload::to_id(v),
            Self::PlayDisconnect => client::play::CPlayDisconnect::to_id(v),
            Self::SystemChat => client::play::CSystemChatMessage::to_id(v),
            Self::Commands => client::play::CCommands::to_id(v),
            Self::CommandSuggestionsResponse => client::play::CCommandSuggestions::to_id(v),
            Self::ClientboundPluginMessage => client::play::CCustomPayload::to_id(v),
            Self::StartConfiguration => client::play::CStartConfiguration::to_id(v),
            Self::Transfer => client::play::CTransfer::to_id(v),
        };
        Some(id)
    }

    pub fn matches(self, id: i32, version: ProtocolVersion) -> bool {
        self.id(version) == Some(id)
    }
}

pub trait Packet: Sized {
    const KIND: PacketKind;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError>;

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError>;
}

pub fn encode_packet<P: Packet>(
    packet: &P,
    version: ProtocolVersion,
) -> Result<Bytes, ProtocolError> {
    let id = P::KIND
        .id(version)
        .ok_or(ProtocolError::UnsupportedPacket(P::KIND, version))?;
    let mut buf = Vec::new();
    buf.write_varint(id);
    packet.write(&mut buf, version)?;
    Ok(buf.into())
}

pub fn decode_packet<P: Packet>(
    payload: &[u8],
    version: ProtocolVersion,
) -> Result<P, ProtocolError> {
    let mut cur = payload;
    P::read(&mut cur, version)
}

fn write_pumpkin<P: pumpkin_protocol::ClientPacket>(
    packet: &P,
    buf: &mut Vec<u8>,
    version: ProtocolVersion,
) -> Result<(), ProtocolError> {
    packet
        .write_packet_data(&mut *buf, &version.to_pumpkin())
        .map_err(|e| ProtocolError::Encode(e.to_string()))
}

fn read_error(err: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::Malformed(err.to_string())
}
