use serde_json::Value;
use uuid::Uuid;

use super::config::empty_packet;
use super::{Packet, PacketKind, read_only};
use crate::protocol::generated::STRING_PARSER_IDS;
use crate::protocol::text::{read_component, write_component};
use crate::protocol::wire::{ReadExt, WriteExt};
use crate::protocol::{ProtocolError, ProtocolVersion};

const MAX_CHAT_LEN: usize = 256;
const MAX_SUGGESTION_INPUT_LEN: usize = 32500;

empty_packet!(StartConfiguration, StartConfiguration);
empty_packet!(ConfigurationAcknowledged, ConfigurationAcknowledged);

macro_rules! leading_string_packet {
    ($name:ident, $kind:ident, $field:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            pub $field: String,
        }

        impl Packet for $name {
            const KIND: PacketKind = PacketKind::$kind;

            fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
                Ok(Self {
                    $field: buf.read_string_bounded(MAX_CHAT_LEN)?,
                })
            }

            fn write(
                &self,
                _buf: &mut Vec<u8>,
                version: ProtocolVersion,
            ) -> Result<(), ProtocolError> {
                read_only(Self::KIND, version)
            }
        }
    };
}

leading_string_packet!(ChatCommand, ChatCommand, command);
leading_string_packet!(SignedChatCommand, SignedChatCommand, command);
leading_string_packet!(ChatMessage, ChatMessage, message);

pub fn chat_length_limit(version: ProtocolVersion) -> usize {
    if version < ProtocolVersion::V1_11 {
        100
    } else {
        MAX_CHAT_LEN
    }
}

/// Replaces the text a chat message or command packet starts with, keeping the rest as is.
pub fn replace_leading_string(payload: &[u8], text: &str) -> Result<Vec<u8>, ProtocolError> {
    let mut rest = payload;
    rest.read_string_bounded(MAX_CHAT_LEN)?;
    let mut out = Vec::with_capacity(text.len() + rest.len() + 3);
    out.write_string(text);
    out.extend_from_slice(rest);
    Ok(out)
}

const SIGNATURE_LEN: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChatSigning {
    pub signed: bool,
    pub acknowledged: i32,
}

pub fn chat_signing(
    kind: PacketKind,
    payload: &[u8],
    version: ProtocolVersion,
) -> Result<ChatSigning, ProtocolError> {
    let command = match kind {
        PacketKind::ChatCommand => true,
        PacketKind::ChatMessage => false,
        _ => return Ok(ChatSigning::default()),
    };
    if version < ProtocolVersion::V1_19 || (command && version >= ProtocolVersion::V1_20_5) {
        return Ok(ChatSigning::default());
    }
    let session = version >= ProtocolVersion::V1_19_3;
    let mut buf = payload;
    buf.read_string()?;
    buf.read_i64()?;
    buf.read_i64()?;
    let signed = if command {
        let arguments = buf.read_varint()?;
        for _ in 0..arguments {
            buf.read_string()?;
            if session {
                buf.read_bytes(SIGNATURE_LEN)?;
            } else {
                buf.read_byte_array()?;
            }
        }
        arguments > 0
    } else if session {
        let signed = buf.read_bool()?;
        if signed {
            buf.read_bytes(SIGNATURE_LEN)?;
        }
        signed
    } else {
        !buf.read_byte_array()?.is_empty()
    };
    let acknowledged = if session { buf.read_varint()? } else { 0 };
    Ok(ChatSigning {
        signed,
        acknowledged,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct ChatAcknowledgement {
    pub offset: i32,
}

impl Packet for ChatAcknowledgement {
    const KIND: PacketKind = PacketKind::ChatAcknowledgement;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        if version < ProtocolVersion::V1_19_3 {
            return Err(ProtocolError::UnsupportedPacket(Self::KIND, version));
        }
        Ok(Self {
            offset: buf.read_varint()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        if version < ProtocolVersion::V1_19_3 {
            return Err(ProtocolError::UnsupportedPacket(Self::KIND, version));
        }
        buf.write_varint(self.offset);
        Ok(())
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
        if version < ProtocolVersion::V1_13 {
            return Err(ProtocolError::UnsupportedPacket(Self::KIND, version));
        }
        Ok(Self {
            id: buf.read_varint()?,
            text: buf.read_string_bounded(MAX_SUGGESTION_INPUT_LEN)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        if version < ProtocolVersion::V1_13 {
            return Err(ProtocolError::UnsupportedPacket(Self::KIND, version));
        }
        buf.write_varint(self.id);
        buf.write_string(&self.text);
        Ok(())
    }
}

fn read_plugin_message(
    buf: &mut &[u8],
    version: ProtocolVersion,
) -> Result<(String, Vec<u8>), ProtocolError> {
    let channel = buf.read_string()?;
    let data = if version < ProtocolVersion::V1_8 {
        let len = usize::try_from(buf.read_i16()?)
            .map_err(|_| ProtocolError::Malformed("negative plugin message length".into()))?;
        buf.read_bytes(len)?.to_vec()
    } else {
        std::mem::take(buf).to_vec()
    };
    Ok((channel, data))
}

fn write_plugin_message(buf: &mut Vec<u8>, channel: &str, data: &[u8], version: ProtocolVersion) {
    buf.write_string(channel);
    if version < ProtocolVersion::V1_8 {
        buf.write_short_byte_array(data);
    } else {
        buf.extend_from_slice(data);
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
        let (channel, data) = read_plugin_message(buf, version)?;
        Ok(Self { channel, data })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_plugin_message(buf, &self.channel, &self.data, version);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ClientboundPluginMessage {
    pub channel: String,
    pub data: Vec<u8>,
}

impl Packet for ClientboundPluginMessage {
    const KIND: PacketKind = PacketKind::ClientboundPluginMessage;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let (channel, data) = read_plugin_message(buf, version)?;
        Ok(Self { channel, data })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_plugin_message(buf, &self.channel, &self.data, version);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PlayDisconnect {
    pub reason: Value,
}

impl Packet for PlayDisconnect {
    const KIND: PacketKind = PacketKind::PlayDisconnect;

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

// Before 1.19 this is the generic chat packet with a position byte (1 = system, 2 = action bar)
#[derive(Clone, Debug)]
pub struct SystemChat {
    pub content: Value,
    pub overlay: bool,
}

impl Packet for SystemChat {
    const KIND: PacketKind = PacketKind::SystemChat;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let content = read_component(buf, version)?;
        let overlay = if version < ProtocolVersion::V1_8 {
            false
        } else if version < ProtocolVersion::V1_19 {
            let position = buf.read_u8()?;
            if version >= ProtocolVersion::V1_16 {
                buf.read_uuid()?;
            }
            position == 2
        } else if version < ProtocolVersion::V1_19_1 {
            buf.read_varint()? == 2
        } else {
            buf.read_bool()?
        };
        Ok(Self { content, overlay })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_component(buf, &self.content, version);
        if version < ProtocolVersion::V1_8 {
            return Ok(());
        }
        if version < ProtocolVersion::V1_19 {
            buf.write_u8(if self.overlay { 2 } else { 1 });
            if version >= ProtocolVersion::V1_16 {
                buf.write_uuid(&Uuid::nil());
            }
        } else if version < ProtocolVersion::V1_19_1 {
            buf.write_varint(if self.overlay { 2 } else { 1 });
        } else {
            buf.write_bool(self.overlay);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Suggestion {
    pub text: String,
    pub tooltip: Option<Value>,
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
        let count = usize::try_from(count)
            .ok()
            .filter(|count| *count <= buf.len())
            .ok_or_else(|| ProtocolError::Malformed(format!("invalid suggestion count {count}")))?;
        let mut matches = Vec::with_capacity(count);
        for _ in 0..count {
            let text = buf.read_string()?;
            let tooltip = if buf.read_bool()? {
                Some(read_component(buf, version)?)
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
        if version < ProtocolVersion::V1_13 {
            return Err(ProtocolError::UnsupportedPacket(Self::KIND, version));
        }
        buf.write_varint(self.id);
        buf.write_varint(self.start);
        buf.write_varint(self.length);
        buf.write_varint(self.matches.len() as i32);
        for m in &self.matches {
            buf.write_string(&m.text);
            buf.write_bool(m.tooltip.is_some());
            if let Some(tooltip) = &m.tooltip {
                write_component(buf, tooltip, version);
            }
        }
        Ok(())
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
            port: u16::try_from(port)
                .map_err(|_| ProtocolError::Malformed(format!("invalid port {port}")))?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_string(&self.host);
        buf.write_varint(i32::from(self.port));
        Ok(())
    }
}

fn read_keep_alive(buf: &mut &[u8], version: ProtocolVersion) -> Result<i64, ProtocolError> {
    if version < ProtocolVersion::V1_8 {
        Ok(i64::from(buf.read_i32()?))
    } else if version < ProtocolVersion::V1_12_2 {
        Ok(i64::from(buf.read_varint()?))
    } else {
        buf.read_i64()
    }
}

fn write_keep_alive(buf: &mut Vec<u8>, id: i64, version: ProtocolVersion) {
    if version < ProtocolVersion::V1_8 {
        buf.write_i32(id as i32);
    } else if version < ProtocolVersion::V1_12_2 {
        buf.write_varint(id as i32);
    } else {
        buf.write_i64(id);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PlayKeepAlive {
    pub id: i64,
}

impl Packet for PlayKeepAlive {
    const KIND: PacketKind = PacketKind::PlayKeepAlive;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: read_keep_alive(buf, version)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_keep_alive(buf, self.id, version);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PlayKeepAliveResponse {
    pub id: i64,
}

impl Packet for PlayKeepAliveResponse {
    const KIND: PacketKind = PacketKind::PlayKeepAliveResponse;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            id: read_keep_alive(buf, version)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_keep_alive(buf, self.id, version);
        Ok(())
    }
}

const NODE_LITERAL: u8 = 0x01;
const NODE_ARGUMENT: u8 = 0x02;
const NODE_EXECUTABLE: u8 = 0x04;
const NODE_SUGGESTIONS: u8 = 0x10;
const GREEDY_PHRASE: i32 = 2;

fn string_parser_id(version: ProtocolVersion) -> Option<i32> {
    let idx = STRING_PARSER_IDS.partition_point(|(first, _)| *first <= version.0);
    let (_, id) = STRING_PARSER_IDS.get(idx.checked_sub(1)?)?;
    (*id >= 0).then_some(*id)
}

#[derive(Clone, Copy, Debug)]
pub struct InjectedCommand<'a> {
    pub name: &'a str,
    pub takes_args: bool,
    pub executable_without_args: bool,
}

fn write_literal(buf: &mut Vec<u8>, name: &str, executable: bool, child: Option<i32>) {
    let mut flags = NODE_LITERAL;
    if executable {
        flags |= NODE_EXECUTABLE;
    }
    buf.write_u8(flags);
    buf.write_varint(i32::from(child.is_some()));
    if let Some(child) = child {
        buf.write_varint(child);
    }
    buf.write_string(name);
}

fn write_greedy_argument(buf: &mut Vec<u8>, version: ProtocolVersion) -> Option<()> {
    buf.write_u8(NODE_ARGUMENT | NODE_EXECUTABLE | NODE_SUGGESTIONS);
    buf.write_varint(0);
    buf.write_string("args");
    if version >= ProtocolVersion::V1_19 {
        buf.write_varint(string_parser_id(version)?);
    } else {
        buf.write_string("brigadier:string");
    }
    buf.write_varint(GREEDY_PHRASE);
    buf.write_string("minecraft:ask_server");
    Some(())
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

    let mut original_children = Vec::with_capacity((children_count as usize).min(cur.len()));
    for _ in 0..children_count {
        original_children.push(cur.read_varint().ok()?);
    }

    if cur.is_empty() {
        return None;
    }

    let nodes1_to_end = &cur[..cur.len() - 1];

    let mut next_node_idx = node_count;
    let mut new_root_children = Vec::new();
    let mut extra_nodes_buf = Vec::new();

    for command in commands {
        new_root_children.push(next_node_idx);
        if command.takes_args {
            write_literal(
                &mut extra_nodes_buf,
                command.name,
                command.executable_without_args,
                Some(next_node_idx + 1),
            );
            write_greedy_argument(&mut extra_nodes_buf, version)?;
            next_node_idx += 2;
        } else {
            write_literal(&mut extra_nodes_buf, command.name, true, None);
            next_node_idx += 1;
        }
    }

    let mut new_payload = Vec::with_capacity(payload.len() + extra_nodes_buf.len() + 64);
    new_payload.write_varint(next_node_idx);
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

    fn chat_prefix(text: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_string(text);
        buf.write_i64(1);
        buf.write_i64(2);
        buf
    }

    #[test]
    fn test_chat_signing_reads_session_acknowledgements() {
        let version = ProtocolVersion(763);

        let mut command = chat_prefix("server lobby");
        command.write_varint(0);
        command.write_varint(3);
        command.extend_from_slice(&[0; 3]);
        assert_eq!(
            chat_signing(PacketKind::ChatCommand, &command, version).unwrap(),
            ChatSigning {
                signed: false,
                acknowledged: 3
            }
        );

        let mut signed_command = chat_prefix("msg Alex hi");
        signed_command.write_varint(1);
        signed_command.write_string("message");
        signed_command.extend_from_slice(&[7; SIGNATURE_LEN]);
        signed_command.write_varint(1);
        signed_command.extend_from_slice(&[0; 3]);
        assert_eq!(
            chat_signing(PacketKind::ChatCommand, &signed_command, version).unwrap(),
            ChatSigning {
                signed: true,
                acknowledged: 1
            }
        );

        let mut message = chat_prefix("hi");
        message.write_bool(true);
        message.extend_from_slice(&[7; SIGNATURE_LEN]);
        message.write_varint(2);
        message.extend_from_slice(&[0; 3]);
        assert_eq!(
            chat_signing(PacketKind::ChatMessage, &message, version).unwrap(),
            ChatSigning {
                signed: true,
                acknowledged: 2
            }
        );
    }

    #[test]
    fn test_chat_signing_before_and_after_sessions() {
        let mut keyed = chat_prefix("hi");
        keyed.write_byte_array(&[7; 256]);
        keyed.write_bool(false);
        assert_eq!(
            chat_signing(PacketKind::ChatMessage, &keyed, ProtocolVersion(760)).unwrap(),
            ChatSigning {
                signed: true,
                acknowledged: 0
            }
        );

        let mut unsigned = chat_prefix("hi");
        unsigned.write_byte_array(&[]);
        unsigned.write_bool(false);
        assert!(
            !chat_signing(PacketKind::ChatMessage, &unsigned, ProtocolVersion(759))
                .unwrap()
                .signed
        );

        let mut command = Vec::new();
        command.write_string("server lobby");
        assert_eq!(
            chat_signing(PacketKind::ChatCommand, &command, ProtocolVersion::V1_20_5).unwrap(),
            ChatSigning::default()
        );
        assert_eq!(
            chat_signing(PacketKind::ChatMessage, &command, ProtocolVersion(758)).unwrap(),
            ChatSigning::default()
        );
    }
    use crate::protocol::{decode_packet, encode_packet};
    use serde_json::json;

    const V1_21_4: ProtocolVersion = ProtocolVersion(769);

    #[test]
    fn test_command_suggestions_round_trip() {
        for protocol in [393, 764, 765, 777] {
            let version = ProtocolVersion(protocol);
            let packet = CommandSuggestions {
                id: 42,
                start: 1,
                length: 3,
                matches: vec![
                    Suggestion {
                        text: "say".to_string(),
                        tooltip: Some(json!({"text": "broadcast message"})),
                    },
                    Suggestion {
                        text: "spawnpoint".to_string(),
                        tooltip: None,
                    },
                ],
            };

            let bytes = encode_packet(&packet, version).unwrap();
            let mut cur = &bytes[..];
            assert!(
                PacketKind::CommandSuggestionsResponse.matches(cur.read_varint().unwrap(), version)
            );

            let decoded: CommandSuggestions = decode_packet(cur, version).unwrap();
            assert_eq!(decoded.id, 42);
            assert_eq!(decoded.start, 1);
            assert_eq!(decoded.length, 3);
            assert_eq!(decoded.matches, packet.matches);
        }
    }

    #[test]
    fn test_system_chat_layouts() {
        for protocol in [5, 47, 735, 759, 760, 765, 777] {
            let version = ProtocolVersion(protocol);
            for overlay in [false, true] {
                let packet = SystemChat {
                    content: json!({"text": "hello"}),
                    overlay,
                };
                let bytes = encode_packet(&packet, version).unwrap();
                let mut cur = &bytes[..];
                cur.read_varint().unwrap();
                let decoded: SystemChat = decode_packet(cur, version).unwrap();
                assert_eq!(decoded.content, packet.content, "protocol {protocol}");
                assert_eq!(
                    decoded.overlay,
                    overlay && protocol >= 47,
                    "protocol {protocol}"
                );
            }
        }
    }

    #[test]
    fn test_keep_alive_widths() {
        for (protocol, len) in [(5, 4), (47, 1), (340, 8), (777, 8)] {
            let version = ProtocolVersion(protocol);
            let bytes = encode_packet(&PlayKeepAlive { id: 5 }, version).unwrap();
            let mut cur = &bytes[..];
            cur.read_varint().unwrap();
            assert_eq!(cur.len(), len, "protocol {protocol}");
            let decoded: PlayKeepAliveResponse = decode_packet(cur, version).unwrap();
            assert_eq!(decoded.id, 5);
        }
    }

    #[test]
    fn test_plugin_message_1_7_length_prefix() {
        let packet = ClientboundPluginMessage {
            channel: "MC|Brand".into(),
            data: vec![1, 2, 3],
        };
        for protocol in [5, 47] {
            let version = ProtocolVersion(protocol);
            let bytes = encode_packet(&packet, version).unwrap();
            let mut cur = &bytes[..];
            cur.read_varint().unwrap();
            let decoded: ClientboundPluginMessage = decode_packet(cur, version).unwrap();
            assert_eq!(decoded.data, packet.data);
        }
    }

    fn root_with_say() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.write_varint(2);
        payload.write_u8(0x00);
        payload.write_varint(1);
        payload.write_varint(1);
        payload.write_u8(NODE_LITERAL | NODE_EXECUTABLE);
        payload.write_varint(0);
        payload.write_string("say");
        payload.write_varint(0);
        payload
    }

    #[test]
    fn test_inject_commands() {
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
        let injected = inject_commands(&root_with_say(), V1_21_4, &commands).unwrap();

        let mut cur = &injected[..];
        assert_eq!(cur.read_varint().unwrap(), 5);
        assert_eq!(cur.read_u8().unwrap(), 0);
        assert_eq!(cur.read_varint().unwrap(), 3);
        assert_eq!(cur.read_varint().unwrap(), 1);
        assert_eq!(cur.read_varint().unwrap(), 2);
        assert_eq!(cur.read_varint().unwrap(), 4);

        assert_eq!(cur.read_u8().unwrap(), NODE_LITERAL | NODE_EXECUTABLE);
        assert_eq!(cur.read_varint().unwrap(), 0);
        assert_eq!(cur.read_string().unwrap(), "say");
        assert_eq!(cur.read_u8().unwrap(), NODE_LITERAL | NODE_EXECUTABLE);
        assert_eq!(cur.read_varint().unwrap(), 1);
        assert_eq!(cur.read_varint().unwrap(), 3);
        assert_eq!(cur.read_string().unwrap(), "server");
        assert_eq!(
            cur.read_u8().unwrap(),
            NODE_ARGUMENT | NODE_EXECUTABLE | NODE_SUGGESTIONS
        );
        assert_eq!(cur.read_varint().unwrap(), 0);
        assert_eq!(cur.read_string().unwrap(), "args");
        assert_eq!(cur.read_varint().unwrap(), 5);
        assert_eq!(cur.read_varint().unwrap(), GREEDY_PHRASE);
        assert_eq!(cur.read_string().unwrap(), "minecraft:ask_server");
        assert_eq!(cur.read_u8().unwrap(), NODE_LITERAL | NODE_EXECUTABLE);
        assert_eq!(cur.read_varint().unwrap(), 0);
        assert_eq!(cur.read_string().unwrap(), "list");
        assert_eq!(cur.read_varint().unwrap(), 0);
        assert!(cur.is_empty());
    }

    #[test]
    fn test_inject_commands_uses_identifier_parser_before_1_19() {
        let commands = [InjectedCommand {
            name: "server",
            takes_args: true,
            executable_without_args: true,
        }];
        let injected = inject_commands(&root_with_say(), ProtocolVersion(404), &commands).unwrap();
        let needle = b"\x10brigadier:string\x02";
        assert!(injected.windows(needle.len()).any(|w| w == needle));
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
