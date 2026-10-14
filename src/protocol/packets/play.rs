use pumpkin_protocol::ServerPacket;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::play::{
    ArgumentType, CCommandSuggestions, CCustomPayload, CPlayDisconnect, CStartConfiguration,
    CSystemChatMessage, CTransfer, CommandSuggestion, ProtoNode, ProtoNodeType,
    StringProtoArgBehavior, SuggestionProviders,
};
use pumpkin_protocol::java::server::play::{SChatCommand, SCommandSuggestion, SCustomPayload};
use pumpkin_util::text::TextComponent;

use super::{Packet, PacketKind, read_error, write_pumpkin};
use crate::protocol::text::read_component;
use crate::protocol::wire::{ReadExt, WriteExt};
use crate::protocol::{ProtocolError, ProtocolVersion};

fn read_only(kind: PacketKind, version: ProtocolVersion) -> Result<(), ProtocolError> {
    Err(ProtocolError::UnsupportedPacket(kind, version))
}

#[derive(Clone, Debug)]
pub struct ChatCommand {
    pub command: String,
}

impl Packet for ChatCommand {
    const KIND: PacketKind = PacketKind::ChatCommand;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let packet = SChatCommand::read(buf, &version.to_pumpkin()).map_err(read_error)?;
        Ok(Self {
            command: packet.command.to_owned(),
        })
    }

    fn write(&self, _buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        read_only(Self::KIND, version)
    }
}

#[derive(Clone, Debug)]
pub struct ChatMessage {
    pub message: String,
}

impl Packet for ChatMessage {
    const KIND: PacketKind = PacketKind::ChatMessage;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            message: buf.read_string_bounded(256)?,
        })
    }

    fn write(&self, _buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        read_only(Self::KIND, version)
    }
}

#[derive(Clone, Debug)]
pub struct CommandSuggestionRequest {
    pub id: i32,
    pub text: String,
}

impl Packet for CommandSuggestionRequest {
    const KIND: PacketKind = PacketKind::CommandSuggestionRequest;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let packet = SCommandSuggestion::read(buf, &version.to_pumpkin()).map_err(read_error)?;
        Ok(Self {
            id: packet.id.0,
            text: packet.command.to_owned(),
        })
    }

    fn write(&self, _buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        read_only(Self::KIND, version)
    }
}

#[derive(Clone, Debug)]
pub struct ServerboundPluginMessage {
    pub channel: String,
    pub data: Vec<u8>,
}

impl Packet for ServerboundPluginMessage {
    const KIND: PacketKind = PacketKind::ServerboundPluginMessage;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let packet = SCustomPayload::read(buf, &version.to_pumpkin()).map_err(read_error)?;
        Ok(Self {
            channel: packet.channel.to_owned(),
            data: packet.data.to_vec(),
        })
    }

    fn write(&self, _buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        read_only(Self::KIND, version)
    }
}

#[derive(Clone, Debug)]
pub struct ClientboundPluginMessage {
    pub channel: String,
    pub data: Vec<u8>,
}

impl Packet for ClientboundPluginMessage {
    const KIND: PacketKind = PacketKind::ClientboundPluginMessage;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let channel = buf.read_string()?;
        Ok(Self {
            channel,
            data: std::mem::take(buf).to_vec(),
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(
            &CCustomPayload::new(&self.channel, &self.data),
            buf,
            version,
        )
    }
}

#[derive(Clone, Debug)]
pub struct PlayDisconnect {
    pub reason: TextComponent,
}

impl Packet for PlayDisconnect {
    const KIND: PacketKind = PacketKind::PlayDisconnect;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: read_component(buf, version)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(&CPlayDisconnect::new(&self.reason), buf, version)
    }
}

#[derive(Clone, Debug)]
pub struct SystemChat {
    pub content: TextComponent,
    pub overlay: bool,
}

impl Packet for SystemChat {
    const KIND: PacketKind = PacketKind::SystemChat;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let content = read_component(buf, version)?;
        Ok(Self {
            content,
            overlay: buf.read_bool().unwrap_or(false),
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(
            &CSystemChatMessage::new(&self.content, self.overlay),
            buf,
            version,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Suggestion {
    pub text: String,
    pub tooltip: Option<TextComponent>,
}

#[derive(Clone, Debug)]
pub struct CommandSuggestions {
    pub id: i32,
    pub start: i32,
    pub length: i32,
    pub matches: Vec<Suggestion>,
}

impl Packet for CommandSuggestions {
    const KIND: PacketKind = PacketKind::CommandSuggestionsResponse;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        if version < ProtocolVersion::V1_13 {
            return Err(ProtocolError::UnsupportedPacket(Self::KIND, version));
        }
        let id = buf.read_varint()?;
        let start = buf.read_varint()?;
        let length = buf.read_varint()?;
        let count = buf.read_varint()?;
        if !(0..=20000).contains(&count) {
            return Err(ProtocolError::Malformed(format!(
                "invalid suggestion count {count}"
            )));
        }
        let mut matches = Vec::with_capacity((count as usize).min(1024));
        for _ in 0..count {
            let text = buf.read_string()?;
            let tooltip = if buf.read_bool()? {
                read_component(buf, version).ok()
            } else {
                None
            };
            matches.push(Suggestion { text, tooltip });
        }
        Ok(Self {
            id,
            start,
            length,
            matches,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        let matches: Box<[CommandSuggestion]> = self
            .matches
            .iter()
            .map(|m| CommandSuggestion {
                suggestion: m.text.clone(),
                tooltip: m.tooltip.clone(),
            })
            .collect();
        let packet = CCommandSuggestions::new(
            VarInt(self.id),
            VarInt(self.start),
            VarInt(self.length),
            matches,
        );
        write_pumpkin(&packet, buf, version)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StartConfiguration;

impl Packet for StartConfiguration {
    const KIND: PacketKind = PacketKind::StartConfiguration;

    fn read(_buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self)
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(&CStartConfiguration, buf, version)
    }
}

#[derive(Clone, Debug)]
pub struct Transfer {
    pub host: String,
    pub port: u16,
}

impl Packet for Transfer {
    const KIND: PacketKind = PacketKind::Transfer;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let host = buf.read_string()?;
        let port = buf.read_varint()?;
        Ok(Self {
            host,
            port: port as u16,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_pumpkin(
            &CTransfer::new(&self.host, VarInt(i32::from(self.port))),
            buf,
            version,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InjectedCommand<'a> {
    pub name: &'a str,
    pub takes_args: bool,
    pub executable_without_args: bool,
}

/// Returns `None` when the backend's tree layout is not one we can safely rewrite.
pub fn inject_commands(
    payload: &[u8],
    version: ProtocolVersion,
    commands: &[InjectedCommand<'_>],
) -> Option<Vec<u8>> {
    if version < ProtocolVersion::V1_13 || commands.is_empty() {
        return None;
    }

    // Only trees whose root is node 0 are supported; the trailing VarInt is the root index
    if payload.last() != Some(&0) {
        return None;
    }

    let mut cur = payload;
    let node_count = cur.read_varint().ok()?;
    if node_count <= 0 {
        return None;
    }

    let flags = cur.read_u8().ok()?;
    if flags != 0 {
        return None;
    }

    let children_count = cur.read_varint().ok()?;
    if children_count < 0 {
        return None;
    }

    let mut original_children = Vec::with_capacity(children_count as usize);
    for _ in 0..children_count {
        original_children.push(cur.read_varint().ok()?);
    }

    if cur.is_empty() {
        return None;
    }

    let nodes1_to_end = &cur[..cur.len() - 1];
    let pumpkin_version = version.to_pumpkin();

    let mut next_node_idx = node_count as usize;
    let mut new_root_children = Vec::new();
    let mut extra_nodes_buf = Vec::new();

    for command in commands {
        if command.takes_args {
            let lit_node = ProtoNode {
                children: vec![VarInt((next_node_idx + 1) as i32)].into_boxed_slice(),
                node_type: ProtoNodeType::Literal {
                    name: command.name,
                    is_executable: command.executable_without_args,
                    redirect_target: None,
                    restricted: false,
                },
            };
            let arg_node = ProtoNode {
                children: Vec::new().into_boxed_slice(),
                node_type: ProtoNodeType::Argument {
                    name: "args",
                    is_executable: true,
                    redirect_target: None,
                    parser: ArgumentType::String(StringProtoArgBehavior::GreedyPhrase),
                    override_suggestion_type: Some(SuggestionProviders::AskServer),
                    restricted: false,
                },
            };
            lit_node
                .write_to(&mut extra_nodes_buf, &pumpkin_version)
                .ok()?;
            arg_node
                .write_to(&mut extra_nodes_buf, &pumpkin_version)
                .ok()?;
            new_root_children.push(next_node_idx as i32);
            next_node_idx += 2;
        } else {
            let lit_node = ProtoNode {
                children: Vec::new().into_boxed_slice(),
                node_type: ProtoNodeType::Literal {
                    name: command.name,
                    is_executable: true,
                    redirect_target: None,
                    restricted: false,
                },
            };
            lit_node
                .write_to(&mut extra_nodes_buf, &pumpkin_version)
                .ok()?;
            new_root_children.push(next_node_idx as i32);
            next_node_idx += 1;
        }
    }

    let mut new_payload = Vec::with_capacity(payload.len() + extra_nodes_buf.len() + 64);
    new_payload.write_varint(next_node_idx as i32);
    new_payload.push(0x00);
    new_payload.write_varint((original_children.len() + new_root_children.len()) as i32);
    for child in original_children.into_iter().chain(new_root_children) {
        new_payload.write_varint(child);
    }
    new_payload.extend_from_slice(nodes1_to_end);
    new_payload.extend_from_slice(&extra_nodes_buf);
    new_payload.push(0x00);

    Some(new_payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode_packet, encode_packet};

    const V1_21_4: ProtocolVersion = ProtocolVersion(769);

    #[test]
    fn test_command_suggestions_round_trip() {
        let packet = CommandSuggestions {
            id: 42,
            start: 1,
            length: 3,
            matches: vec![
                Suggestion {
                    text: "say".to_string(),
                    tooltip: Some(TextComponent::text("broadcast message")),
                },
                Suggestion {
                    text: "spawnpoint".to_string(),
                    tooltip: None,
                },
            ],
        };

        let bytes = encode_packet(&packet, V1_21_4).unwrap();
        let mut cur = &bytes[..];
        assert!(
            PacketKind::CommandSuggestionsResponse.matches(cur.read_varint().unwrap(), V1_21_4)
        );

        let decoded: CommandSuggestions = decode_packet(cur, V1_21_4).unwrap();
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.start, 1);
        assert_eq!(decoded.length, 3);
        assert_eq!(decoded.matches.len(), 2);
        assert_eq!(decoded.matches[0].text, "say");
        assert!(decoded.matches[0].tooltip.is_some());
        assert_eq!(decoded.matches[1].text, "spawnpoint");
        assert!(decoded.matches[1].tooltip.is_none());
    }

    #[test]
    fn test_inject_commands() {
        // root -> "say"
        let mut payload = Vec::new();
        payload.write_varint(2);
        payload.write_u8(0x00);
        payload.write_varint(1);
        payload.write_varint(1);
        payload.write_u8(0x01 | 0x04);
        payload.write_varint(0);
        payload.write_string("say");
        payload.write_varint(0);

        let commands = [
            InjectedCommand {
                name: "server",
                takes_args: true,
                executable_without_args: true,
            },
            InjectedCommand {
                name: "list",
                takes_args: false,
                executable_without_args: true,
            },
        ];
        let injected = inject_commands(&payload, V1_21_4, &commands).unwrap();

        let mut cur = &injected[..];
        // say, server literal + args, list
        assert_eq!(cur.read_varint().unwrap(), 5);
        assert_eq!(cur.read_u8().unwrap(), 0);
        assert_eq!(cur.read_varint().unwrap(), 3);
        assert_eq!(cur.read_varint().unwrap(), 1);
        assert_eq!(cur.read_varint().unwrap(), 2);
        assert_eq!(cur.read_varint().unwrap(), 4);
        assert_eq!(injected.last(), Some(&0));
    }

    #[test]
    fn test_inject_commands_rejects_non_zero_root() {
        let payload = [1, 0x00, 0, 5];
        let commands = [InjectedCommand {
            name: "list",
            takes_args: false,
            executable_without_args: true,
        }];
        assert!(inject_commands(&payload, V1_21_4, &commands).is_none());
    }
}
