pub mod config;
pub mod handshake;
pub mod login;
pub mod play;
pub mod status;
pub mod switch;

use bytes::Bytes;

use super::generated::PACKET_IDS;
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
    LoginAcknowledged,
    LoginDisconnect,
    EncryptionRequest,
    LoginSuccess,
    SetCompression,
    LoginPluginRequest,

    ConfigDisconnect,
    ConfigFinish,
    ConfigKeepAlive,
    ConfigPing,
    ConfigKnownPacks,
    ConfigCodeOfConduct,
    ConfigFinishAck,
    ConfigKeepAliveResponse,
    ConfigPong,
    ConfigKnownPacksResponse,
    ConfigAcceptCodeOfConduct,
    ConfigServerboundPluginMessage,
    ConfigClientboundPluginMessage,

    ChatCommand,
    SignedChatCommand,
    ChatMessage,
    CommandSuggestionRequest,
    ServerboundPluginMessage,
    ConfigurationAcknowledged,
    PlayKeepAliveResponse,
    PlayDisconnect,
    SystemChat,
    Commands,
    CommandSuggestionsResponse,
    ClientboundPluginMessage,
    StartConfiguration,
    Transfer,
    PlayKeepAlive,
    JoinGame,
    Respawn,
    PlayerInfo,
    PlayerInfoRemove,
    BossBar,
    Title,
    ClearTitles,
    ChatAcknowledgement,
}

impl PacketKind {
    pub fn id(self, version: ProtocolVersion) -> Option<i32> {
        if !version.is_known() {
            return None;
        }
        let (_, runs) = PACKET_IDS.iter().find(|(kind, _)| *kind == self)?;
        let idx = runs.partition_point(|(first, _)| *first <= version.0);
        let (_, id) = runs.get(idx.checked_sub(1)?)?;
        (*id >= 0).then_some(*id)
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

fn read_only(kind: PacketKind, version: ProtocolVersion) -> Result<(), ProtocolError> {
    Err(ProtocolError::UnsupportedPacket(kind, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::generated::LAYOUT_CHANGES;

    const HANDLED_LAYOUTS: &[(PacketKind, &[u32])] = &[
        (PacketKind::Handshake, &[]),
        (PacketKind::StatusRequest, &[]),
        (PacketKind::PingRequest, &[]),
        (PacketKind::StatusResponse, &[]),
        (PacketKind::PongResponse, &[]),
        (PacketKind::LoginStart, &[759, 760, 761, 764]),
        (PacketKind::EncryptionResponse, &[47, 759, 761]),
        (PacketKind::LoginPluginResponse, &[393]),
        (PacketKind::LoginAcknowledged, &[764]),
        (PacketKind::LoginDisconnect, &[]),
        (PacketKind::EncryptionRequest, &[47, 766]),
        (PacketKind::SetCompression, &[47]),
        (PacketKind::LoginPluginRequest, &[393]),
        (PacketKind::ConfigDisconnect, &[764, 765]),
        (PacketKind::ConfigFinish, &[764]),
        (PacketKind::ConfigKeepAlive, &[764]),
        (PacketKind::ConfigPing, &[764]),
        (PacketKind::ConfigCodeOfConduct, &[773]),
        (PacketKind::ConfigFinishAck, &[764]),
        (PacketKind::ConfigKeepAliveResponse, &[764]),
        (PacketKind::ConfigPong, &[764]),
        (PacketKind::ConfigAcceptCodeOfConduct, &[773]),
        (PacketKind::ConfigServerboundPluginMessage, &[764]),
        (PacketKind::ConfigClientboundPluginMessage, &[764]),
        // Read up to the acknowledgement offset, before the parts added later
        (PacketKind::ChatCommand, &[759, 760, 761, 766]),
        (PacketKind::SignedChatCommand, &[766, 770, 774, 775]),
        (PacketKind::ChatMessage, &[759, 760, 761, 770]),
        (PacketKind::CommandSuggestionRequest, &[47, 107, 393]),
        (PacketKind::ServerboundPluginMessage, &[47]),
        (PacketKind::ConfigurationAcknowledged, &[764]),
        (PacketKind::PlayKeepAliveResponse, &[47, 340]),
        (PacketKind::PlayDisconnect, &[765]),
        (PacketKind::SystemChat, &[47, 735, 759, 760, 765]),
        (PacketKind::Commands, &[393, 771]),
        (PacketKind::CommandSuggestionsResponse, &[393, 765]),
        (PacketKind::ClientboundPluginMessage, &[47]),
        (PacketKind::StartConfiguration, &[764]),
        (PacketKind::Transfer, &[]),
        (PacketKind::PlayKeepAlive, &[47, 340]),
        // Only read before 1.20.2, where switching backends skips the configuration phase
        (
            PacketKind::JoinGame,
            &[
                47, 109, 477, 573, 735, 751, 755, 757, 759, 763, 764, 766, 768, 773,
            ],
        ),
        (
            PacketKind::Respawn,
            &[477, 573, 735, 751, 759, 760, 763, 764, 766, 768, 773],
        ),
        (PacketKind::PlayerInfo, &[47, 759, 761, 765, 768, 769]),
        (PacketKind::PlayerInfoRemove, &[761]),
        (PacketKind::BossBar, &[107, 765]),
        (PacketKind::Title, &[47, 315, 755]),
        (PacketKind::ClearTitles, &[755]),
        (PacketKind::ChatAcknowledgement, &[760, 761]),
    ];

    const OPAQUE: &[PacketKind] = &[
        PacketKind::LoginSuccess,
        PacketKind::ConfigKnownPacks,
        PacketKind::ConfigKnownPacksResponse,
    ];

    #[test]
    fn test_layout_changes_are_handled() {
        for (kind, changes) in LAYOUT_CHANGES {
            if OPAQUE.contains(kind) {
                continue;
            }
            let handled = HANDLED_LAYOUTS
                .iter()
                .find(|(k, _)| k == kind)
                .unwrap_or_else(|| panic!("{kind:?} is neither handled nor opaque"))
                .1;
            assert_eq!(
                handled, *changes,
                "{kind:?} changes layout at {changes:?}, the code handles {handled:?}"
            );
        }
    }

    #[test]
    fn test_ids_follow_generated_runs() {
        let v1_8 = ProtocolVersion(47);
        let v1_21_4 = ProtocolVersion(769);
        assert_eq!(PacketKind::SystemChat.id(v1_8), Some(0x02));
        assert_eq!(PacketKind::PlayDisconnect.id(v1_8), Some(0x40));
        assert_eq!(PacketKind::SystemChat.id(v1_21_4), Some(0x73));
        assert_eq!(PacketKind::PlayDisconnect.id(v1_21_4), Some(0x1D));
        assert_eq!(PacketKind::SetCompression.id(ProtocolVersion(5)), None);
        assert_eq!(PacketKind::Transfer.id(ProtocolVersion(765)), None);
        assert_eq!(PacketKind::Handshake.id(ProtocolVersion(9999)), None);
    }
}
