use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncRead;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot, watch};
use tracing::{debug, error, warn};

use super::bridge::Phase;
use super::client_queue::ClientQueue;
use super::login::BackendReader;
use super::suggestions::{PendingSuggestion, Suggest, SuggestionRequest};
use super::tunnel::Served;
use crate::command::{CommandDispatcher, CommandSender, ProxyCommandSource};
use crate::config::Config;
use crate::i18n::translate;
use crate::plugin::PluginManager;
use crate::plugin::api::{
    PlayerChatEvent, PlayerCommandEvent, PluginMessageEvent, PluginMessageSource,
};
use crate::protocol::packets::config::ConfigDisconnect;
use crate::protocol::packets::play::{
    ChatAcknowledgement, ChatCommand, ChatMessage, ClientInformation, CommandSuggestionRequest,
    ConfigClientInformation, InjectedCommand, PlayDisconnect, PlayKeepAliveResponse,
    SignedChatCommand, chat_length_limit, chat_signing, command_length_limit, inject_commands,
    read_plugin_message, replace_leading_string, write_plugin_message,
};
use crate::protocol::text::plain_text;
use crate::protocol::{
    Frame, PacketKind, PacketReader, ProtocolVersion, decode_packet, encode_packet,
};
use crate::security::PacketRateLimiter;
use crate::session::{PlayerAction, SessionManager};
fn client_locale(
    packet: &crate::protocol::RawPacket,
    phase: Phase,
    version: ProtocolVersion,
) -> Option<String> {
    match phase {
        Phase::Config if PacketKind::ConfigClientInformation.matches(packet.id, version) => {
            decode_packet::<ConfigClientInformation>(&packet.payload, version)
                .ok()
                .map(|p| p.locale)
        }
        Phase::Play if PacketKind::ClientInformation.matches(packet.id, version) => {
            decode_packet::<ClientInformation>(&packet.payload, version)
                .ok()
                .map(|p| p.locale)
        }
        _ => None,
    }
}

/// A setting the client told its backend about
pub(super) enum Setting {
    Information(Bytes),
    Brand(Vec<u8>),
}

fn client_setting(
    packet: &crate::protocol::RawPacket,
    phase: Phase,
    version: ProtocolVersion,
) -> Option<Setting> {
    let (information, plugin_message) = match phase {
        Phase::Config => (
            PacketKind::ConfigClientInformation,
            PacketKind::ConfigServerboundPluginMessage,
        ),
        Phase::Play => (
            PacketKind::ClientInformation,
            PacketKind::ServerboundPluginMessage,
        ),
        Phase::Login => return None,
    };
    if information.matches(packet.id, version) {
        Some(Setting::Information(packet.payload.clone()))
    } else if plugin_message.matches(packet.id, version)
        && let Ok((channel, data)) = read_plugin_message(&mut &packet.payload[..], version)
        && channel == BRAND_CHANNEL
    {
        Some(Setting::Brand(data))
    } else {
        None
    }
}

pub(super) const BRAND_CHANNEL: &str = "minecraft:brand";

// The client's acknowledgements mark every phase change; the backend switches only after
// receiving them, so updating the phase before forwarding keeps both directions in step.
fn serverbound_transition(phase: Phase, id: i32, version: ProtocolVersion) -> Option<Phase> {
    match phase {
        Phase::Login if PacketKind::LoginAcknowledged.matches(id, version) => Some(Phase::Config),
        Phase::Config if PacketKind::ConfigFinishAck.matches(id, version) => Some(Phase::Play),
        Phase::Play if PacketKind::ConfigurationAcknowledged.matches(id, version) => {
            Some(Phase::Config)
        }
        _ => None,
    }
}

/// What one player's readers need to work out what the packets they read become
pub(super) struct Session {
    pub(super) username: String,
    pub(super) uuid: uuid::Uuid,
    pub(super) version: ProtocolVersion,
    pub(super) plugin_manager: Arc<PluginManager>,
    pub(super) session_manager: Arc<SessionManager>,
    pub(super) command_dispatcher: Arc<CommandDispatcher>,
    pub(super) proxy_config: Arc<Config>,
    pub(super) action_tx: mpsc::Sender<PlayerAction>,
    pub(super) client_out: ClientQueue,
    // The client's compression threshold; a backend using the same one has its frames passed on
    pub(super) client_compression: Option<usize>,
}

/// What the client reader hands the tunnel, in the order the client sent it. `served` is the
/// generation of the backend that was current when the packet was read.
pub(super) enum ClientEvent {
    /// A packet for the backend, and the phase the client entered by sending it
    Packet {
        packet: Bytes,
        entered: Option<Phase>,
        setting: Option<Setting>,
        completion: Option<PendingSuggestion>,
        served: u64,
    },
    KeepAliveResponse {
        id: i64,
        packet: Bytes,
    },
    Suggest {
        request: SuggestionRequest,
        served: u64,
    },
    Kick(String),
    Closed,
}

fn plain_packet(packet: Bytes, served: u64) -> ClientEvent {
    ClientEvent::Packet {
        packet,
        entered: None,
        setting: None,
        completion: None,
        served,
    }
}

pub(super) const CLIENT_EVENTS: usize = 16;

/// Reads the client for the whole session. Its packets are handled one at a time, plugin events
/// included, so a slow plugin only holds up what the client sends.
pub(super) async fn read_client<R: AsyncRead + Unpin>(
    session: Arc<Session>,
    mut reader: PacketReader<R>,
    mut rate_limiter: PacketRateLimiter,
    mut served: watch::Receiver<Served>,
    events: mpsc::Sender<ClientEvent>,
) {
    let mut phase = if session.version >= ProtocolVersion::V1_20_2 {
        Phase::Login
    } else {
        Phase::Play
    };
    loop {
        let event = match reader.read_packet().await {
            Ok(_) if !rate_limiter.record_packet() => {
                warn!(
                    "Player '{}' exceeded packet rate limit (flood protection kicked in)",
                    session.username
                );
                ClientEvent::Closed
            }
            Ok(packet) => {
                let current = served.borrow_and_update().clone();
                match session.client_packet(packet, &mut phase, &current).await {
                    Some(event) => event,
                    None => continue,
                }
            }
            Err(e) => {
                debug!("Client '{}' stream ended: {:?}", session.username, e);
                ClientEvent::Closed
            }
        };
        let closed = matches!(event, ClientEvent::Closed);
        if events.send(event).await.is_err() || closed {
            break;
        }
    }
}

impl Session {
    fn command_source(&self) -> ProxyCommandSource {
        ProxyCommandSource {
            sender: CommandSender::Player {
                username: self.username.clone(),
                action_tx: self.action_tx.clone(),
            },
            config: self.proxy_config.clone(),
            session_manager: self.session_manager.clone(),
        }
    }

    fn locale(&self) -> Option<String> {
        self.session_manager.locale(&self.username)
    }

    /// Works out what a packet from the client becomes; `None` when it is swallowed
    async fn client_packet(
        &self,
        mut raw_packet: crate::protocol::RawPacket,
        phase: &mut Phase,
        served: &Served,
    ) -> Option<ClientEvent> {
        let version = self.version;
        let current = *phase;
        let generation = served.generation;
        if let Some(locale) = client_locale(&raw_packet, current, version) {
            self.session_manager.update_locale(&self.username, &locale);
        }
        let mut completion = None;
        let entered = serverbound_transition(current, raw_packet.id, version);
        if let Some(next) = entered {
            *phase = next;
        } else if current == Phase::Config
            && PacketKind::ConfigServerboundPluginMessage.matches(raw_packet.id, version)
            && !self
                .plugin_message_event(&mut raw_packet, &served.name, PluginMessageSource::Player)
                .await
        {
            return None;
        } else if current == Phase::Play {
            if PacketKind::PlayKeepAliveResponse.matches(raw_packet.id, version)
                && let Ok(reply) =
                    decode_packet::<PlayKeepAliveResponse>(&raw_packet.payload, version)
            {
                return Some(ClientEvent::KeepAliveResponse {
                    id: reply.id,
                    packet: raw_packet.to_bytes(),
                });
            }

            let chat_message = if PacketKind::ChatMessage.matches(raw_packet.id, version) {
                decode_packet::<ChatMessage>(&raw_packet.payload, version)
                    .ok()
                    .map(|m| m.message)
            } else {
                None
            };
            let command = if PacketKind::ChatCommand.matches(raw_packet.id, version) {
                decode_packet::<ChatCommand>(&raw_packet.payload, version).map(|c| Some(c.command))
            } else if PacketKind::SignedChatCommand.matches(raw_packet.id, version) {
                decode_packet::<SignedChatCommand>(&raw_packet.payload, version)
                    .map(|c| Some(c.command))
            } else if version < ProtocolVersion::V1_19 {
                // Before 1.19 commands arrive as chat messages starting with '/'
                Ok(chat_message
                    .as_deref()
                    .and_then(|m| m.strip_prefix('/'))
                    .map(str::to_owned))
            } else {
                Ok(None)
            };
            // Passing on a command the plugins could not see would skip them
            let command = match command {
                Ok(command) => command,
                Err(e) => {
                    warn!(
                        "Dropping an unreadable command from '{}': {}",
                        self.username, e
                    );
                    return self.swallow_chat(&raw_packet, generation);
                }
            };

            if let Some(command) = command {
                let mut cmd_event = PlayerCommandEvent {
                    uuid: self.uuid.to_string(),
                    username: self.username.clone(),
                    command: command.clone(),
                    cancelled: false,
                };
                self.plugin_manager
                    .fire_player_command(&mut cmd_event)
                    .await;
                if cmd_event.cancelled {
                    return self.swallow_chat(&raw_packet, generation);
                }

                let first_word = cmd_event
                    .command
                    .split_whitespace()
                    .next()
                    .unwrap_or(&cmd_event.command);
                let source = self.command_source();
                if self.command_dispatcher.handles(first_word, &source) {
                    self.command_dispatcher
                        .handle_command(&source, &cmd_event.command);
                    return self.swallow_chat(&raw_packet, generation);
                }

                if cmd_event.command != command {
                    let text = if version < ProtocolVersion::V1_19 {
                        format!("/{}", cmd_event.command)
                    } else {
                        cmd_event.command
                    };
                    if let Some(reason) = self.rewrite_chat(&mut raw_packet, &text) {
                        return Some(ClientEvent::Kick(reason));
                    }
                }
            } else if let Some(message) = chat_message {
                let mut chat_event = PlayerChatEvent {
                    uuid: self.uuid.to_string(),
                    username: self.username.clone(),
                    message: message.clone(),
                    cancelled: false,
                };
                self.plugin_manager.fire_player_chat(&mut chat_event).await;
                if chat_event.cancelled {
                    return self.swallow_chat(&raw_packet, generation);
                }
                if chat_event.message != message
                    && let Some(reason) = self.rewrite_chat(&mut raw_packet, &chat_event.message)
                {
                    return Some(ClientEvent::Kick(reason));
                }
            }

            if PacketKind::ServerboundPluginMessage.matches(raw_packet.id, version)
                && !self
                    .plugin_message_event(
                        &mut raw_packet,
                        &served.name,
                        PluginMessageSource::Player,
                    )
                    .await
            {
                return None;
            }

            if PacketKind::CommandSuggestionRequest.matches(raw_packet.id, version)
                && let Ok(suggestion_req) =
                    decode_packet::<CommandSuggestionRequest>(&raw_packet.payload, version)
            {
                match self.suggest(suggestion_req) {
                    Suggest::Proxy(request) => {
                        return Some(ClientEvent::Suggest {
                            request,
                            served: generation,
                        });
                    }
                    Suggest::Completion(pending) => completion = Some(pending),
                    Suggest::Backend => {}
                }
            }
        }

        let setting = if version >= ProtocolVersion::V1_20_2 {
            client_setting(&raw_packet, current, version)
        } else {
            None
        };
        Some(ClientEvent::Packet {
            packet: raw_packet.to_bytes(),
            entered,
            setting,
            completion,
            served: generation,
        })
    }

    /// Works out who answers a suggestion request
    fn suggest(&self, suggestion_req: CommandSuggestionRequest) -> Suggest {
        let raw_cmd = &suggestion_req.text;
        let clean_cmd = raw_cmd.strip_prefix('/').unwrap_or(raw_cmd);
        let first_word = clean_cmd.split_whitespace().next().unwrap_or(clean_cmd);
        let source = self.command_source();
        let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };

        // 1. Arguments to a proxy command (contains a space, e.g. "/server ", "/send ")
        if clean_cmd.contains(' ') {
            if self.command_dispatcher.handles(first_word, &source) {
                return Suggest::Proxy(SuggestionRequest {
                    id: suggestion_req.id,
                    input: clean_cmd.to_string(),
                    offset,
                    source,
                });
            }
            return Suggest::Backend;
        }

        // 2. Root command name completion (no space, e.g. "/", "/s", "/ser", "/server")
        let clean_lower = clean_cmd.to_ascii_lowercase();
        let permitted = self.command_dispatcher.get_all_permitted_commands(&source);
        let proxy_matches: Vec<(String, Option<String>)> = permitted
            .into_iter()
            .filter(|(cmd_name, _)| cmd_name.starts_with(&clean_lower))
            .map(|(cmd_name, description)| (cmd_name.to_string(), Some(description.to_string())))
            .collect();
        if proxy_matches.is_empty() {
            return Suggest::Backend;
        }
        Suggest::Completion(PendingSuggestion {
            id: suggestion_req.id,
            clean_cmd: clean_cmd.to_string(),
            offset,
            proxy_matches,
        })
    }

    // The backend tracks which chat messages the client has seen through these packets, so one the
    // proxy drops must still hand its acknowledgements on, and a signed one cannot be dropped at all
    fn swallow_chat(
        &self,
        packet: &crate::protocol::RawPacket,
        served: u64,
    ) -> Option<ClientEvent> {
        let version = self.version;
        let kind = if PacketKind::ChatCommand.matches(packet.id, version) {
            PacketKind::ChatCommand
        } else if PacketKind::SignedChatCommand.matches(packet.id, version) {
            PacketKind::SignedChatCommand
        } else {
            PacketKind::ChatMessage
        };
        let signing = chat_signing(kind, &packet.payload, version).unwrap_or_default();
        if signing.signed && version >= ProtocolVersion::V1_19_1 {
            error!(
                "Disconnecting '{}': a signed chat message was cancelled, which would break their chat with the backend",
                self.username
            );
            return Some(ClientEvent::Kick(translate(
                self.locale().as_deref(),
                "vine.chat.signed_cancelled",
                &[],
            )));
        }
        if signing.acknowledged > 0
            && let Ok(ack) = encode_packet(
                &ChatAcknowledgement {
                    offset: signing.acknowledged,
                },
                version,
            )
        {
            return Some(plain_packet(ack, served));
        }
        None
    }

    /// Returns the reason to kick the player for, if the message cannot be changed
    fn rewrite_chat(&self, packet: &mut crate::protocol::RawPacket, text: &str) -> Option<String> {
        let version = self.version;
        let kind = if PacketKind::ChatCommand.matches(packet.id, version) {
            PacketKind::ChatCommand
        } else if PacketKind::SignedChatCommand.matches(packet.id, version) {
            PacketKind::SignedChatCommand
        } else {
            PacketKind::ChatMessage
        };
        if chat_signing(kind, &packet.payload, version)
            .unwrap_or_default()
            .signed
        {
            error!(
                "Disconnecting '{}': a plugin changed a signed chat message, which the backend would reject",
                self.username
            );
            return Some(translate(
                self.locale().as_deref(),
                "vine.chat.signed_changed",
                &[],
            ));
        }
        let limit = match kind {
            PacketKind::ChatMessage => chat_length_limit(version),
            _ => command_length_limit(version),
        };
        if text.encode_utf16().count() > limit {
            warn!(
                "A plugin made a chat message from '{}' longer than the client limit; sending the original",
                self.username
            );
            return None;
        }
        match replace_leading_string(&packet.payload, text) {
            Ok(payload) => packet.payload = payload.into(),
            Err(e) => warn!(
                "Could not rewrite a chat message from '{}': {}",
                self.username, e
            ),
        }
        None
    }

    /// Returns false when a plugin cancelled the message.
    async fn plugin_message_event(
        &self,
        packet: &mut crate::protocol::RawPacket,
        server_name: &str,
        source: PluginMessageSource,
    ) -> bool {
        let version = self.version;
        let Ok((channel, data)) = read_plugin_message(&mut &packet.payload[..], version) else {
            return true;
        };
        // Backends trust this channel to come from the proxy, so players cannot use it
        if source == PluginMessageSource::Player
            && (channel == "BungeeCord" || channel == "bungeecord:main")
        {
            return false;
        }
        let mut event = PluginMessageEvent {
            channel: channel.clone(),
            data: data.clone(),
            player_uuid: Some(self.uuid.to_string()),
            server_name: Some(server_name.to_string()),
            source,
            cancelled: false,
        };
        self.plugin_manager.fire_plugin_message(&mut event).await;
        if event.cancelled {
            return false;
        }
        if event.data != data {
            let mut payload = Vec::new();
            write_plugin_message(&mut payload, &channel, &event.data, version);
            packet.payload = payload.into();
        }
        true
    }
}

/// What a backend's reader hands the tunnel
pub(super) enum BackendEvent {
    /// A packet whose effect on the session the tunnel decides before queueing it for the client
    /// with the room already taken for it; the reader goes on once `done` is answered, so
    /// nothing it reads later overtakes it. `phase` is the one it was read in.
    Packet {
        packet: crate::protocol::RawPacket,
        phase: Phase,
        permit: OwnedSemaphorePermit,
        done: oneshot::Sender<()>,
    },
    Lost {
        reason: Option<String>,
    },
    ClientGone,
}

pub(super) async fn read_backend(
    session: Arc<Session>,
    mut reader: BackendReader,
    server_name: String,
    mut phase: Phase,
    events: mpsc::Sender<BackendEvent>,
    mut stop: oneshot::Receiver<()>,
) {
    let version = session.version;
    let passthrough = reader.compression() == session.client_compression;
    loop {
        let current = phase;
        let read = async {
            if passthrough {
                reader
                    .read_frame(|id| !inspected(id, current, version))
                    .await
            } else {
                reader.read_packet().await.map(Frame::Packet)
            }
        };
        let frame = tokio::select! {
            biased;
            _ = &mut stop => return,
            frame = read => frame,
        };
        let handled = match frame {
            Ok(Frame::Packet(packet)) => {
                session
                    .backend_packet(packet, &server_name, &mut phase, &events)
                    .await
            }
            Ok(Frame::Raw(frame)) => {
                if session.client_out.send_frame(frame).await {
                    Ok(())
                } else {
                    Err(Some(BackendEvent::ClientGone))
                }
            }
            Err(e) => {
                debug!("Backend stream ended for '{}': {:?}", session.username, e);
                Err(Some(BackendEvent::Lost {
                    reason: Some(e.to_string()),
                }))
            }
        };
        match handled {
            Ok(()) => {}
            Err(Some(event)) => {
                let _ = events.send(event).await;
                return;
            }
            Err(None) => return,
        }
    }
}

/// Backend packets the tunnel itself has to see, in the phase the reader reads them in
fn watched(id: i32, phase: Phase, version: ProtocolVersion) -> bool {
    match phase {
        Phase::Config => PacketKind::ConfigFinish.matches(id, version),
        Phase::Play => watched_in_play(id, version),
        Phase::Login => false,
    }
}

/// Backend packets the proxy reads or changes on their way to the client; the rest reach it as
/// the backend framed them when both connections compress the same way
fn inspected(id: i32, phase: Phase, version: ProtocolVersion) -> bool {
    watched(id, phase, version)
        || match phase {
            Phase::Config => {
                PacketKind::ConfigDisconnect.matches(id, version)
                    || PacketKind::ConfigClientboundPluginMessage.matches(id, version)
            }
            Phase::Play => {
                PacketKind::PlayDisconnect.matches(id, version)
                    || PacketKind::ClientboundPluginMessage.matches(id, version)
                    || PacketKind::Commands.matches(id, version)
            }
            Phase::Login => true,
        }
}

fn watched_in_play(id: i32, version: ProtocolVersion) -> bool {
    PacketKind::StartConfiguration.matches(id, version)
        || PacketKind::PlayKeepAlive.matches(id, version)
        || PacketKind::CommandSuggestionsResponse.matches(id, version)
        || (version < ProtocolVersion::V1_20_2
            && (PacketKind::PlayerInfo.matches(id, version)
                || PacketKind::PlayerInfoRemove.matches(id, version)
                || PacketKind::BossBar.matches(id, version)))
}

impl Session {
    /// Passes a packet from the backend on to the client queue, waiting for room there. `phase`
    /// follows what the backend sends: it switches right after its ConfigFinish and its
    /// StartConfiguration, as the client does on reading them.
    async fn backend_packet(
        &self,
        mut raw_packet: crate::protocol::RawPacket,
        server_name: &str,
        phase: &mut Phase,
        events: &mpsc::Sender<BackendEvent>,
    ) -> Result<(), Option<BackendEvent>> {
        let version = self.version;
        let current = *phase;
        let mut packet = None;
        if current == Phase::Config {
            if PacketKind::ConfigDisconnect.matches(raw_packet.id, version) {
                let reason = decode_packet::<ConfigDisconnect>(&raw_packet.payload, version)
                    .map(|d| plain_text(&d.reason))
                    .ok();
                return Err(Some(BackendEvent::Lost { reason }));
            }
            if PacketKind::ConfigClientboundPluginMessage.matches(raw_packet.id, version)
                && !self
                    .plugin_message_event(&mut raw_packet, server_name, PluginMessageSource::Server)
                    .await
            {
                return Ok(());
            }
            if watched(raw_packet.id, current, version) {
                *phase = Phase::Play;
                return self.through_tunnel(raw_packet, current, events).await;
            }
        } else if current == Phase::Play {
            if PacketKind::PlayDisconnect.matches(raw_packet.id, version) {
                let reason = decode_packet::<PlayDisconnect>(&raw_packet.payload, version)
                    .map(|d| plain_text(&d.reason))
                    .ok()
                    .or_else(|| {
                        let s = String::from_utf8_lossy(&raw_packet.payload).to_string();
                        if s.is_empty() { None } else { Some(s) }
                    });
                return Err(Some(BackendEvent::Lost { reason }));
            }

            if watched(raw_packet.id, current, version) {
                if PacketKind::StartConfiguration.matches(raw_packet.id, version) {
                    *phase = Phase::Config;
                }
                return self.through_tunnel(raw_packet, current, events).await;
            }

            if PacketKind::ClientboundPluginMessage.matches(raw_packet.id, version)
                && !self
                    .plugin_message_event(&mut raw_packet, server_name, PluginMessageSource::Server)
                    .await
            {
                return Ok(());
            } else if PacketKind::Commands.matches(raw_packet.id, version) {
                let source = self.command_source();
                let permitted = self
                    .command_dispatcher
                    .get_all_permitted_command_shapes(&source);
                let injected: Vec<InjectedCommand<'_>> = permitted
                    .iter()
                    .map(|shape| InjectedCommand {
                        name: shape.name.as_str(),
                        takes_args: shape.takes_args,
                        executable_without_args: shape.executable,
                    })
                    .collect();
                packet = inject_commands(&raw_packet.payload, version, &injected).map(
                    |modified_payload| {
                        crate::protocol::RawPacket {
                            id: raw_packet.id,
                            payload: modified_payload.into(),
                        }
                        .to_bytes()
                    },
                );
            }
        }

        let bytes = packet.unwrap_or_else(|| raw_packet.to_bytes());
        if !self.client_out.send(bytes).await {
            return Err(Some(BackendEvent::ClientGone));
        }
        Ok(())
    }

    /// Hands a packet to the tunnel and waits until it has been queued for the client
    async fn through_tunnel(
        &self,
        packet: crate::protocol::RawPacket,
        phase: Phase,
        events: &mpsc::Sender<BackendEvent>,
    ) -> Result<(), Option<BackendEvent>> {
        let Some(permit) = self.client_out.reserve(packet.payload.len() + 1).await else {
            return Err(Some(BackendEvent::ClientGone));
        };
        let (done, queued) = oneshot::channel();
        let event = BackendEvent::Packet {
            packet,
            phase,
            permit,
            done,
        };
        if events.send(event).await.is_err() {
            return Err(None);
        }
        queued.await.map_err(|_| None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serverbound_transitions_follow_acknowledgements() {
        let v = ProtocolVersion(769);
        let id = |kind: PacketKind| kind.id(v).unwrap();

        assert_eq!(
            serverbound_transition(Phase::Login, id(PacketKind::LoginAcknowledged), v),
            Some(Phase::Config)
        );
        assert_eq!(
            serverbound_transition(Phase::Config, id(PacketKind::ConfigFinishAck), v),
            Some(Phase::Play)
        );
        assert_eq!(
            serverbound_transition(Phase::Play, id(PacketKind::ConfigurationAcknowledged), v),
            Some(Phase::Config)
        );
        assert_eq!(
            serverbound_transition(Phase::Play, id(PacketKind::ConfigFinishAck), v),
            None
        );
        assert_eq!(
            serverbound_transition(Phase::Play, 0x0F, ProtocolVersion(763)),
            None
        );
    }
}
