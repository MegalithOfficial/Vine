use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use pumpkin_util::text::TextComponent;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::auth::AuthenticatedPlayer;
use crate::backend::forwarding::{
    ForwardingHelper, VELOCITY_PLAYER_INFO_CHANNEL, VINE_PLAYER_INFO_CHANNEL,
};
use crate::command::{CommandDispatcher, CommandSender, ProxyCommandSource};
use crate::config::{BackendConfig, Config, ForwardingMode, NetworkConfig};
use crate::i18n::translate;
use crate::network;
use crate::plugin::PluginManager;
use crate::plugin::api::{
    PlayerChatEvent, PlayerCommandEvent, PlayerDisconnectEvent, PlayerJoinEvent,
    PluginMessageEvent, PluginMessageSource, ServerConnectEvent, ServerConnectedEvent,
};
use crate::protocol::packets::config::ConfigDisconnect;
use crate::protocol::packets::handshake::{Handshake, HandshakeIntent};
use crate::protocol::packets::login::{
    LoginAcknowledged, LoginDisconnect, LoginPluginRequest, LoginPluginResponse, LoginStart,
    SetCompression,
};
use crate::protocol::packets::play::{
    ChatAcknowledgement, ChatCommand, ChatMessage, ClientInformation, ClientboundPluginMessage,
    CommandSuggestionRequest, CommandSuggestions, ConfigClientInformation, InjectedCommand,
    PlayDisconnect, PlayKeepAlive, PlayKeepAliveResponse, SignedChatCommand, StartConfiguration,
    Suggestion, SystemChat, chat_length_limit, chat_signing, inject_commands, read_plugin_message,
    replace_leading_string, write_plugin_message,
};
use crate::protocol::packets::switch::{Leftovers, join_game_sequence};
use crate::protocol::text::{component_json, parse_message, plain_text};
use crate::protocol::{
    Packet, PacketKind, PacketReader, PacketWriter, ProtocolError, ProtocolVersion, decode_packet,
    encode_packet,
};
use crate::security::PacketRateLimiter;
use crate::session::{PlayerAction, SessionManager};

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Failed to connect to backend server '{0}': {1}")]
    ConnectFailed(String, std::io::Error),
    #[error("Backend communication error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Backend server '{0}' login timed out")]
    LoginTimeout(String),
    #[error("Backend disconnected player during login: {0}")]
    LoginDisconnected(String),
    #[error("Velocity forwarding error: {0}")]
    VelocityError(String),
    #[error("Vine forwarding error: {0}")]
    VineError(String),
}

#[derive(Debug)]
enum TunnelExit {
    /// Client disconnected or connection closed
    ClientDisconnected,
    /// Player requested switch to another backend server
    Connect { server_name: String },
    /// Backend server closed connection or sent disconnect/kick
    BackendDisconnected { reason: Option<String> },
    /// The proxy kicked the player
    Kicked { reason: String },
    /// The backend being switched to finished logging in, or failed to
    Prepared(Box<Result<PreparedBackend, BridgeError>>),
}

type BackendReader = PacketReader<OwnedReadHalf>;
type BackendWriter = PacketWriter<OwnedWriteHalf>;

pub struct BackendBridge {
    server_name: String,
    config: BackendConfig,
    fallback_server: Option<(String, BackendConfig)>,
    client_ip: IpAddr,
    client_version: ProtocolVersion,
    virtual_host: String,
    player: AuthenticatedPlayer,
    max_packets_per_sec: u32,
    online_players: Arc<AtomicUsize>,
    network_config: Arc<NetworkConfig>,
    compression_level: i32,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    proxy_config: Arc<Config>,
    plugin_manager: Arc<PluginManager>,
}

impl BackendBridge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_name: String,
        config: BackendConfig,
        fallback_server: Option<(String, BackendConfig)>,
        client_ip: IpAddr,
        client_version: ProtocolVersion,
        virtual_host: String,
        player: AuthenticatedPlayer,
        max_packets_per_sec: u32,
        online_players: Arc<AtomicUsize>,
        network_config: Arc<NetworkConfig>,
        compression_level: i32,
        session_manager: Arc<SessionManager>,
        command_dispatcher: Arc<CommandDispatcher>,
        proxy_config: Arc<Config>,
        plugin_manager: Arc<PluginManager>,
    ) -> Self {
        Self {
            server_name,
            config,
            fallback_server,
            client_ip,
            client_version,
            virtual_host,
            player,
            max_packets_per_sec,
            online_players,
            network_config,
            compression_level,
            session_manager,
            command_dispatcher,
            proxy_config,
            plugin_manager,
        }
    }

    /// Establishes connection to backend with retry attempts and timeout
    async fn connect_to_backend(
        server_name: &str,
        address: &str,
        timeout_secs: u64,
        retries: u32,
    ) -> Result<TcpStream, BridgeError> {
        let connect_timeout = Duration::from_secs(timeout_secs);
        let mut last_err = None;

        for attempt in 1..=retries.max(1) {
            match timeout(connect_timeout, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    debug!(
                        "Connection attempt {}/{} to '{}' ({}) failed: {}",
                        attempt, retries, server_name, address, e
                    );
                    last_err = Some(e);
                }
                Err(_) => {
                    debug!(
                        "Connection attempt {}/{} to '{}' ({}) timed out after {}s",
                        attempt, retries, server_name, address, timeout_secs
                    );
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("Connection timed out after {}s", timeout_secs),
                    ));
                }
            }

            if attempt < retries {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }

        Err(BridgeError::ConnectFailed(
            server_name.to_string(),
            last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Failed to connect")
            }),
        ))
    }

    /// Connects to a backend server, configures the socket, and executes the login sequence
    async fn login_backend(
        &self,
        server_name: &str,
        active_config: &BackendConfig,
    ) -> Result<(BackendReader, BackendWriter, Bytes), BridgeError> {
        let backend_stream = Self::connect_to_backend(
            server_name,
            &active_config.address,
            self.network_config.backend_connect_timeout_secs,
            self.network_config.backend_connect_retry_attempts,
        )
        .await?;

        if let Err(e) = network::configure_backend_socket(&backend_stream, &self.network_config) {
            debug!("Failed to configure backend socket: {}", e);
        }

        let (backend_read, backend_write) = backend_stream.into_split();
        let mut backend_reader = PacketReader::new(backend_read);
        let mut backend_writer = PacketWriter::new(backend_write);
        let version = self.client_version;

        let backend_host = match active_config.forwarding {
            ForwardingMode::BungeeCord => ForwardingHelper::build_bungeecord_host(
                &self.virtual_host,
                &self.client_ip,
                &self.player,
            ),
            ForwardingMode::Velocity | ForwardingMode::Vine | ForwardingMode::None => {
                self.virtual_host.clone()
            }
        };

        let handshake = Handshake {
            protocol_version: version.0 as i32,
            server_address: backend_host,
            server_port: 25565,
            intent: HandshakeIntent::Login,
        };
        backend_writer
            .send(encode_packet(&handshake, version)?)
            .await?;

        let key = self.player.profile_key.as_ref();
        let login_start = LoginStart {
            name: self.player.username.clone(),
            uuid: match key {
                Some(key) => key.holder,
                None if version >= ProtocolVersion::V1_19_3 => Some(self.player.id),
                None => None,
            },
            profile_key: key.map(|key| key.key.clone()),
        };
        backend_writer
            .send(encode_packet(&login_start, version)?)
            .await?;

        let login_timeout_dur = Duration::from_secs(self.network_config.backend_login_timeout_secs);

        loop {
            let raw_packet = timeout(login_timeout_dur, backend_reader.read_packet())
                .await
                .map_err(|_| BridgeError::LoginTimeout(server_name.to_string()))??;

            if PacketKind::LoginDisconnect.matches(raw_packet.id, version) {
                let reason = decode_packet::<LoginDisconnect>(&raw_packet.payload, version)
                    .map(|d| d.reason_json)
                    .unwrap_or_else(|_| "Disconnected by backend during login".to_string());
                warn!(
                    "Backend '{}' disconnected '{}' during login: {}",
                    server_name, self.player.username, reason
                );
                return Err(BridgeError::LoginDisconnected(reason));
            } else if PacketKind::LoginPluginRequest.matches(raw_packet.id, version) {
                let request: LoginPluginRequest = decode_packet(&raw_packet.payload, version)?;

                debug!(
                    "Backend requested login plugin message on channel '{}'",
                    request.channel
                );

                // Only the scheme this backend is configured for is answered; anything else is refused
                let data = if request.channel == VINE_PLAYER_INFO_CHANNEL
                    && active_config.forwarding == ForwardingMode::Vine
                {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VineError("Secret missing".to_string()))?;

                    let cur = &request.data[..];
                    let mut challenge = [0u8; 16];
                    if cur.len() >= 17 {
                        challenge.copy_from_slice(&cur[1..17]);
                    } else if cur.len() >= 16 {
                        challenge.copy_from_slice(&cur[0..16]);
                    }

                    Some(
                        ForwardingHelper::build_vine_payload(
                            secret,
                            &self.client_ip,
                            &self.player,
                            &challenge,
                        )
                        .map_err(|e| BridgeError::VineError(e.to_string()))?,
                    )
                } else if request.channel == VELOCITY_PLAYER_INFO_CHANNEL
                    && active_config.forwarding == ForwardingMode::Velocity
                {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VelocityError("Secret missing".to_string()))?;

                    let forwarding_version = ForwardingHelper::velocity_forwarding_version(
                        &request.data,
                        version,
                        self.player.profile_key.as_ref(),
                    );
                    debug!(
                        "Answering Velocity forwarding request {:?} with version {}",
                        request.data, forwarding_version
                    );

                    Some(
                        ForwardingHelper::build_velocity_payload(
                            secret,
                            forwarding_version,
                            &self.client_ip,
                            &self.player,
                        )
                        .map_err(|e| BridgeError::VelocityError(e.to_string()))?,
                    )
                } else {
                    None
                };

                let response = LoginPluginResponse {
                    message_id: request.message_id,
                    data,
                };
                backend_writer
                    .send(encode_packet(&response, version)?)
                    .await?;
            } else if PacketKind::SetCompression.matches(raw_packet.id, version) {
                let compression: SetCompression = decode_packet(&raw_packet.payload, version)?;
                let threshold = compression.threshold;
                debug!("Backend enabled compression threshold: {} bytes", threshold);
                if threshold >= 0 {
                    backend_reader.set_compression(threshold as usize);
                    backend_writer
                        .set_compression(threshold as usize, self.compression_level as u32);
                }
            } else if PacketKind::LoginSuccess.matches(raw_packet.id, version) {
                debug!(
                    "Login successful on backend for '{}'!",
                    self.player.username
                );
                return Ok((backend_reader, backend_writer, raw_packet.to_bytes()));
            } else {
                debug!(
                    "Unhandled packet during login (ID: {}), skipping",
                    raw_packet.id
                );
            }
        }
    }

    /// Establishes connection to backend, handles login handshake, and tunnels packets
    pub async fn run<R, W>(
        self,
        mut client_reader: PacketReader<R>,
        mut client_writer: PacketWriter<W>,
        action_tx: mpsc::UnboundedSender<PlayerAction>,
        mut action_rx: mpsc::UnboundedReceiver<PlayerAction>,
    ) -> Result<(), BridgeError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        info!(
            "Connecting player '{}' ({}) to backend server '{}' at {}",
            self.player.username, self.player.id, self.server_name, self.config.address
        );

        let mut current_server_name = self.server_name.clone();

        let mut connect_event = ServerConnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            current_server: None,
            target_server: current_server_name.clone(),
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager
            .fire_server_connect(&mut connect_event)
            .await;
        if connect_event.cancelled {
            let reason = connect_event.cancel_reason.unwrap_or_else(|| {
                translate(
                    self.locale().as_deref(),
                    "vine.plugin.cancelled_connection",
                    &[],
                )
            });
            warn!(
                "Player '{}' connection to '{}' cancelled by plugin: {}",
                self.player.username, connect_event.target_server, reason
            );
            Self::disconnect_client(
                &mut client_writer,
                self.client_version,
                Phase::Login,
                self.locale().as_deref(),
                &reason,
            )
            .await;
            self.fire_disconnect(None).await;
            return Ok(());
        }
        let initial_backend_cfg = if connect_event.target_server == self.server_name {
            self.config.clone()
        } else if let Some(cfg) = self.proxy_config.servers.get(&connect_event.target_server) {
            current_server_name = connect_event.target_server;
            cfg.clone()
        } else {
            warn!(
                "A plugin sent '{}' to unknown server '{}'; using '{}'",
                self.player.username, connect_event.target_server, self.server_name
            );
            self.config.clone()
        };
        let requested_server = current_server_name.clone();

        let mut login = self
            .login_backend(&current_server_name, &initial_backend_cfg)
            .await;
        if let Err(e) = &login
            && let Some((fb_name, fb_cfg)) = &self.fallback_server
            && fb_name != &current_server_name
        {
            warn!(
                "Primary server '{}' unreachable ({}), attempting failover to fallback server '{}' at {}",
                current_server_name, e, fb_name, fb_cfg.address
            );
            current_server_name = fb_name.clone();
            login = self.login_backend(&current_server_name, fb_cfg).await;
        }
        let (mut backend_reader, mut backend_writer, success_bytes) = match login {
            Ok(res) => res,
            Err(e) => {
                let reason_json = match &e {
                    BridgeError::LoginDisconnected(json)
                        if serde_json::from_str::<serde_json::Value>(json).is_ok() =>
                    {
                        json.clone()
                    }
                    _ => {
                        let locale = self.locale();
                        let reason = translate(
                            locale.as_deref(),
                            "vine.server.initial_connect_failed",
                            &[&requested_server],
                        );
                        crate::client::kick_reason(locale.as_deref(), &reason, self.client_version)
                            .to_string()
                    }
                };
                send_best_effort(
                    &mut client_writer,
                    &LoginDisconnect { reason_json },
                    self.client_version,
                )
                .await;
                self.fire_disconnect(None).await;
                return Err(e);
            }
        };

        // Forward login success packet to the client
        client_writer.send(success_bytes).await?;
        // Keep-alive replies meant for a previous backend would make the current one kick the
        // player, so only replies to the current backend's latest challenge are forwarded
        let keep_alive_challenge = std::sync::Mutex::new(None::<i64>);
        let leftovers = std::sync::Mutex::new(Leftovers::default());
        let phase = PhaseCell::new(if self.client_version >= ProtocolVersion::V1_20_2 {
            Phase::Login
        } else {
            Phase::Play
        });

        self.online_players.fetch_add(1, Ordering::Relaxed);
        info!(
            "Player '{}' is now connected to backend '{}'! Online players: {}",
            self.player.username,
            current_server_name,
            self.online_players.load(Ordering::Relaxed)
        );

        let connected_event = ServerConnectedEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            server_name: current_server_name.clone(),
        };
        self.plugin_manager
            .fire_server_connected(&connected_event)
            .await;

        let join_event = PlayerJoinEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            client_ip: self.client_ip.to_string(),
            initial_server: current_server_name.clone(),
        };
        self.plugin_manager.fire_player_join(&join_event).await;

        self.session_manager
            .update_server(&self.player.username, &current_server_name);

        // Outlives each tunnel so packets still queued when one ends are not lost
        let (client_tx, mut client_rx) = ClientQueue::new();
        let bridge = &self;
        let mut connecting: Option<(String, Connecting<'_>)> = None;

        loop {
            let tunnel_res = Self::bridge_tunnel(
                &self.player.username,
                &mut client_reader,
                &mut client_writer,
                &client_tx,
                &mut client_rx,
                &mut backend_reader,
                &mut backend_writer,
                self.max_packets_per_sec,
                self.client_version,
                &mut action_rx,
                &action_tx,
                self.command_dispatcher.clone(),
                self.proxy_config.clone(),
                self.session_manager.clone(),
                self.plugin_manager.clone(),
                self.player.id,
                current_server_name.clone(),
                &phase,
                &keep_alive_challenge,
                &leftovers,
                connecting.as_mut().map(|(_, future)| future),
            )
            .await;

            let exit = match tunnel_res {
                Ok(exit) => exit,
                Err(e) => {
                    warn!(
                        "Bridge tunnel error for player '{}': {}",
                        self.player.username, e
                    );
                    TunnelExit::BackendDisconnected {
                        reason: Some(e.to_string()),
                    }
                }
            };
            if !matches!(exit, TunnelExit::ClientDisconnected) {
                Self::flush_queue(&mut client_rx, &mut client_writer).await;
            }

            match exit {
                TunnelExit::Kicked { reason } => {
                    info!("Kicking player '{}': {}", self.player.username, reason);
                    Self::disconnect_client(
                        &mut client_writer,
                        self.client_version,
                        phase.get(),
                        self.locale().as_deref(),
                        &reason,
                    )
                    .await;
                    break;
                }
                TunnelExit::ClientDisconnected => {
                    debug!(
                        "Player '{}' disconnected from client side",
                        self.player.username
                    );
                    break;
                }
                TunnelExit::Connect { server_name } => {
                    if connecting.is_some() {
                        self.notify(
                            &mut client_writer,
                            &phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.server.already_connecting",
                                &[],
                            ),
                        )
                        .await;
                        continue;
                    }
                    info!(
                        "Switching player '{}' to backend server '{}'...",
                        self.player.username, server_name
                    );

                    let mut connect_event = ServerConnectEvent {
                        uuid: self.player.id.to_string(),
                        username: self.player.username.clone(),
                        current_server: Some(current_server_name.clone()),
                        target_server: server_name.clone(),
                        cancelled: false,
                        cancel_reason: None,
                    };
                    self.plugin_manager
                        .fire_server_connect(&mut connect_event)
                        .await;
                    if connect_event.cancelled {
                        let reason = connect_event.cancel_reason.unwrap_or_else(|| {
                            translate(
                                self.locale().as_deref(),
                                "vine.plugin.cancelled_switch",
                                &[],
                            )
                        });
                        self.notify(
                            &mut client_writer,
                            &phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.server.switch_cancelled",
                                &[&reason],
                            ),
                        )
                        .await;
                        continue;
                    }
                    let server_name = connect_event.target_server;
                    if server_name == current_server_name {
                        self.notify(
                            &mut client_writer,
                            &phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.command.server.already_connected",
                                &[&server_name],
                            ),
                        )
                        .await;
                        continue;
                    }

                    let Some(target_config) = self.proxy_config.servers.get(&server_name).cloned()
                    else {
                        self.notify(
                            &mut client_writer,
                            &phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.server.unknown",
                                &[&server_name],
                            ),
                        )
                        .await;
                        continue;
                    };

                    let target = server_name.clone();
                    connecting = Some((
                        server_name,
                        Box::pin(
                            async move { bridge.prepare_backend(&target, &target_config).await },
                        ),
                    ));
                }
                TunnelExit::Prepared(prepared) => {
                    let Some((server_name, _)) = connecting.take() else {
                        continue;
                    };
                    let switched = match *prepared {
                        Ok(prepared) => {
                            self.finish_switch(
                                &mut client_reader,
                                &mut client_writer,
                                &phase,
                                &leftovers,
                                &server_name,
                                prepared,
                            )
                            .await
                        }
                        Err(e) => Err(SwitchError::Unreachable(e)),
                    };
                    match switched {
                        Ok((new_reader, new_writer)) => {
                            backend_reader = new_reader;
                            backend_writer = new_writer;
                            if let Ok(mut challenge) = keep_alive_challenge.lock() {
                                *challenge = None;
                            }
                            current_server_name = server_name;
                            self.session_manager
                                .update_server(&self.player.username, &current_server_name);
                            info!(
                                "Player '{}' successfully switched to '{}'",
                                self.player.username, current_server_name
                            );
                            let connected_event = ServerConnectedEvent {
                                uuid: self.player.id.to_string(),
                                username: self.player.username.clone(),
                                server_name: current_server_name.clone(),
                            };
                            self.plugin_manager
                                .fire_server_connected(&connected_event)
                                .await;
                        }
                        Err(SwitchError::Unreachable(e)) => {
                            warn!(
                                "Failed to switch player '{}' to '{}': {}",
                                self.player.username, server_name, e
                            );
                            self.notify(
                                &mut client_writer,
                                &phase,
                                translate(
                                    self.locale().as_deref(),
                                    "vine.server.connect_failed",
                                    &[&server_name, &e],
                                ),
                            )
                            .await;
                        }
                        Err(SwitchError::Fatal(e)) => {
                            warn!(
                                "Lost player '{}' while switching to '{}': {}",
                                self.player.username, server_name, e
                            );
                            Self::disconnect_client(
                                &mut client_writer,
                                self.client_version,
                                phase.get(),
                                self.locale().as_deref(),
                                &translate(
                                    self.locale().as_deref(),
                                    "vine.server.switch_failed",
                                    &[&server_name],
                                ),
                            )
                            .await;
                            break;
                        }
                    }
                }
                TunnelExit::BackendDisconnected { reason } => {
                    // The current backend is gone, so a switch in progress is abandoned
                    connecting = None;
                    warn!(
                        "Backend server '{}' disconnected player '{}': {:?}",
                        current_server_name, self.player.username, reason
                    );
                    let reason = reason.unwrap_or_else(|| {
                        translate(self.locale().as_deref(), "vine.server.lost_connection", &[])
                    });

                    let fallback = self
                        .fallback_server
                        .clone()
                        .filter(|(fb_name, _)| fb_name != &current_server_name);
                    let Some((fb_name, fb_cfg)) = fallback else {
                        Self::disconnect_client(
                            &mut client_writer,
                            self.client_version,
                            phase.get(),
                            self.locale().as_deref(),
                            &reason,
                        )
                        .await;
                        break;
                    };

                    // Plugins see this move like any other; with the old backend gone a cancelled
                    // one ends the session, and a different target must be a configured server
                    let mut connect_event = ServerConnectEvent {
                        uuid: self.player.id.to_string(),
                        username: self.player.username.clone(),
                        current_server: Some(current_server_name.clone()),
                        target_server: fb_name.clone(),
                        cancelled: false,
                        cancel_reason: None,
                    };
                    self.plugin_manager
                        .fire_server_connect(&mut connect_event)
                        .await;
                    if connect_event.cancelled {
                        let reason = connect_event.cancel_reason.unwrap_or(reason);
                        Self::disconnect_client(
                            &mut client_writer,
                            self.client_version,
                            phase.get(),
                            self.locale().as_deref(),
                            &reason,
                        )
                        .await;
                        break;
                    }
                    let (fb_name, fb_cfg) =
                        match self.proxy_config.servers.get(&connect_event.target_server) {
                            Some(cfg) if connect_event.target_server != fb_name => {
                                (connect_event.target_server, cfg.clone())
                            }
                            _ => (fb_name, fb_cfg),
                        };

                    info!(
                        "Rerouting player '{}' to fallback server '{}' (kicked from '{}': {})",
                        self.player.username, fb_name, current_server_name, reason
                    );
                    self.notify(
                        &mut client_writer,
                        &phase,
                        translate(
                            self.locale().as_deref(),
                            "vine.server.fallback",
                            &[&fb_name, &reason],
                        ),
                    )
                    .await;

                    match self
                        .switch_backend(
                            &mut client_reader,
                            &mut client_writer,
                            &phase,
                            &leftovers,
                            &fb_name,
                            &fb_cfg,
                        )
                        .await
                    {
                        Ok((new_reader, new_writer)) => {
                            backend_reader = new_reader;
                            backend_writer = new_writer;
                            if let Ok(mut challenge) = keep_alive_challenge.lock() {
                                *challenge = None;
                            }
                            current_server_name = fb_name;
                            self.session_manager
                                .update_server(&self.player.username, &current_server_name);
                            info!(
                                "Player '{}' successfully recovered to fallback '{}'",
                                self.player.username, current_server_name
                            );
                            let connected_event = ServerConnectedEvent {
                                uuid: self.player.id.to_string(),
                                username: self.player.username.clone(),
                                server_name: current_server_name.clone(),
                            };
                            self.plugin_manager
                                .fire_server_connected(&connected_event)
                                .await;
                        }
                        Err(SwitchError::Unreachable(e) | SwitchError::Fatal(e)) => {
                            warn!(
                                "Failed to connect player '{}' to fallback server '{}': {}",
                                self.player.username, fb_name, e
                            );
                            Self::disconnect_client(
                                &mut client_writer,
                                self.client_version,
                                phase.get(),
                                self.locale().as_deref(),
                                &translate(
                                    self.locale().as_deref(),
                                    "vine.server.fallback_failed",
                                    &[&current_server_name, &e],
                                ),
                            )
                            .await;
                            break;
                        }
                    }
                }
            }
        }

        self.fire_disconnect(Some(current_server_name)).await;

        self.online_players.fetch_sub(1, Ordering::Relaxed);
        info!(
            "Player '{}' disconnected from proxy. Online players: {}",
            self.player.username,
            self.online_players.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Logs into another backend and moves the client over to it. On 1.20.2+ the client is sent
    /// back into the configuration phase so the new backend can configure it from scratch.
    async fn switch_backend<R, W>(
        &self,
        client_reader: &mut PacketReader<R>,
        client_writer: &mut PacketWriter<W>,
        phase: &PhaseCell,
        leftovers: &std::sync::Mutex<Leftovers>,
        server_name: &str,
        config: &BackendConfig,
    ) -> Result<(BackendReader, BackendWriter), SwitchError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let prepared = self
            .prepare_backend(server_name, config)
            .await
            .map_err(SwitchError::Unreachable)?;
        self.finish_switch(
            client_reader,
            client_writer,
            phase,
            leftovers,
            server_name,
            prepared,
        )
        .await
    }

    /// Logs in to the next backend without touching the client, so the current one keeps running
    async fn prepare_backend(
        &self,
        server_name: &str,
        config: &BackendConfig,
    ) -> Result<PreparedBackend, BridgeError> {
        let (mut reader, writer, _) = self.login_backend(server_name, config).await?;
        let version = self.client_version;
        let join_game = if version < ProtocolVersion::V1_20_2 {
            // The backend may still be in the login state right after LoginSuccess; client
            // packets are only safe to forward once it has placed the player and sent JoinGame
            let mut pending = Vec::new();
            let joined = async {
                loop {
                    let packet = reader.read_packet().await?;
                    if PacketKind::JoinGame.matches(packet.id, version) {
                        return Ok::<_, ProtocolError>(packet);
                    }
                    pending.push(packet.to_bytes());
                }
            };
            let packet = match timeout(SWITCH_ACK_TIMEOUT, joined).await {
                Ok(Ok(packet)) => packet,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err(BridgeError::LoginTimeout(server_name.to_string())),
            };
            Some((pending, packet))
        } else {
            None
        };
        Ok(PreparedBackend {
            reader,
            writer,
            join_game,
        })
    }

    /// Moves the client over to a backend that `prepare_backend` already logged in to
    async fn finish_switch<R, W>(
        &self,
        client_reader: &mut PacketReader<R>,
        client_writer: &mut PacketWriter<W>,
        phase: &PhaseCell,
        leftovers: &std::sync::Mutex<Leftovers>,
        server_name: &str,
        prepared: PreparedBackend,
    ) -> Result<(BackendReader, BackendWriter), SwitchError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let PreparedBackend {
            reader: backend_reader,
            writer: mut backend_writer,
            join_game,
        } = prepared;
        let version = self.client_version;
        if let Some((mut pending, join_game)) = join_game {
            let joining = join_game_sequence(&join_game, version).unwrap_or_else(|e| {
                debug!(
                    "Forwarding JoinGame from '{}' unchanged: {}",
                    server_name, e
                );
                vec![join_game.to_bytes()]
            });
            {
                let mut leftovers = leftovers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.extend(leftovers.clear_players(version));
                pending.extend(joining);
                pending.extend(leftovers.clear_overlays(version));
            }
            for packet in pending {
                client_writer
                    .queue(&packet)
                    .map_err(|e| SwitchError::Fatal(e.into()))?;
            }
            match timeout(CLIENT_WRITE_TIMEOUT, client_writer.flush()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(SwitchError::Fatal(e.into())),
                Err(_) => return Err(SwitchError::Fatal(client_timeout())),
            }
            return Ok((backend_reader, backend_writer));
        }

        let awaited = match phase.get() {
            Phase::Play => {
                let start = encode_packet(&StartConfiguration, version)
                    .map_err(|e| SwitchError::Fatal(e.into()))?;
                match timeout(CLIENT_WRITE_TIMEOUT, client_writer.send(start)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(SwitchError::Fatal(e.into())),
                    Err(_) => return Err(SwitchError::Fatal(client_timeout())),
                }
                Some(PacketKind::ConfigurationAcknowledged)
            }
            Phase::Login => Some(PacketKind::LoginAcknowledged),
            Phase::Config => None,
        };

        // Packets the client sends before acknowledging belong to the old backend
        if let Some(kind) = awaited {
            let acknowledged = async {
                loop {
                    let packet = client_reader.read_packet().await?;
                    if kind.matches(packet.id, version) {
                        return Ok::<_, ProtocolError>(());
                    }
                }
            };
            match timeout(SWITCH_ACK_TIMEOUT, acknowledged).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(SwitchError::Fatal(e.into())),
                Err(_) => return Err(SwitchError::Fatal(client_timeout())),
            }
        }
        // The client is configuring from here on, so a failure below must disconnect it as such
        phase.set(Phase::Config);

        let ack =
            encode_packet(&LoginAcknowledged, version).map_err(|e| SwitchError::Fatal(e.into()))?;
        backend_writer
            .send(ack)
            .await
            .map_err(|e| SwitchError::Fatal(e.into()))?;
        Ok((backend_reader, backend_writer))
    }

    // The backend tracks which chat messages the client has seen through these packets, so one the
    // proxy drops must still hand its acknowledgements on, and a signed one cannot be dropped at all
    async fn swallow_chat<W: AsyncWrite + Unpin>(
        packet: &crate::protocol::RawPacket,
        version: ProtocolVersion,
        backend_writer: &mut PacketWriter<W>,
        username: &str,
        locale: Option<&str>,
    ) -> Option<TunnelExit> {
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
                username
            );
            return Some(TunnelExit::Kicked {
                reason: translate(locale, "vine.chat.signed_cancelled", &[]),
            });
        }
        if signing.acknowledged > 0
            && let Ok(ack) = encode_packet(
                &ChatAcknowledgement {
                    offset: signing.acknowledged,
                },
                version,
            )
            && backend_writer.send(ack).await.is_err()
        {
            return Some(TunnelExit::BackendDisconnected { reason: None });
        }
        None
    }

    fn rewrite_chat(
        packet: &mut crate::protocol::RawPacket,
        version: ProtocolVersion,
        text: &str,
        username: &str,
        locale: Option<&str>,
    ) -> Option<TunnelExit> {
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
                username
            );
            return Some(TunnelExit::Kicked {
                reason: translate(locale, "vine.chat.signed_changed", &[]),
            });
        }
        if text.encode_utf16().count() > chat_length_limit(version) {
            warn!(
                "A plugin made a chat message from '{}' longer than the client limit; sending the original",
                username
            );
            return None;
        }
        match replace_leading_string(&packet.payload, text) {
            Ok(payload) => packet.payload = payload.into(),
            Err(e) => warn!(
                "Could not rewrite a chat message from '{}': {}",
                username, e
            ),
        }
        None
    }

    /// Returns false when a plugin cancelled the message.
    async fn plugin_message_event(
        plugin_manager: &PluginManager,
        packet: &mut crate::protocol::RawPacket,
        version: ProtocolVersion,
        player_uuid: uuid::Uuid,
        server_name: &str,
        source: PluginMessageSource,
    ) -> bool {
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
            player_uuid: Some(player_uuid.to_string()),
            server_name: Some(server_name.to_string()),
            source,
            cancelled: false,
        };
        plugin_manager.fire_plugin_message(&mut event).await;
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

    /// Every player that got past PlayerLogin gets a PlayerDisconnect, even if no backend took them
    async fn fire_disconnect(&self, last_server: Option<String>) {
        let event = PlayerDisconnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            last_server,
        };
        self.plugin_manager.fire_player_disconnect(&event).await;
    }

    /// Sends whatever the last tunnel left in the client queue
    async fn flush_queue<W: AsyncWrite + Unpin>(
        rx: &mut ClientQueueRx,
        writer: &mut PacketWriter<W>,
    ) {
        while let Ok((bytes, _permit)) = rx.try_recv() {
            if !matches!(
                timeout(CLIENT_WRITE_TIMEOUT, writer.send(bytes)).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    }

    fn locale(&self) -> Option<String> {
        self.session_manager.locale(&self.player.username)
    }

    async fn notify<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut PacketWriter<W>,
        phase: &PhaseCell,
        text: String,
    ) {
        if phase.get() == Phase::Play {
            let content = component_json(&parse_message(&text), self.client_version);
            let message = SystemChat {
                content,
                overlay: false,
            };
            send_best_effort(writer, &message, self.client_version).await;
        }
    }

    /// Helper to send formatted disconnect packet to client in either play or configuration state
    async fn disconnect_client<W: AsyncWrite + Unpin>(
        writer: &mut PacketWriter<W>,
        version: ProtocolVersion,
        phase: Phase,
        locale: Option<&str>,
        reason: &str,
    ) {
        match phase {
            Phase::Login => {
                let kick = LoginDisconnect {
                    reason_json: crate::client::kick_reason(locale, reason, version).to_string(),
                };
                send_best_effort(writer, &kick, version).await;
            }
            Phase::Config => {
                let reason = crate::client::kick_reason(locale, reason, version);
                send_best_effort(writer, &ConfigDisconnect { reason }, version).await;
            }
            Phase::Play => {
                let reason = component_json(&parse_message(reason), version);
                send_best_effort(writer, &PlayDisconnect { reason }, version).await;
            }
        }
    }
}

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

async fn send_best_effort<P: Packet, W: AsyncWrite + Unpin>(
    writer: &mut PacketWriter<W>,
    packet: &P,
    version: ProtocolVersion,
) {
    match encode_packet(packet, version) {
        Ok(bytes) => {
            let _ = timeout(CLIENT_WRITE_TIMEOUT, writer.send(bytes)).await;
        }
        Err(e) => debug!("Skipping {:?} for {}: {}", P::KIND, version, e),
    }
}

const SWITCH_ACK_TIMEOUT: Duration = Duration::from_secs(10);

struct PreparedBackend {
    reader: BackendReader,
    writer: BackendWriter,
    // Before 1.20.2: the packets the backend sent up to its JoinGame, and the JoinGame itself
    join_game: Option<(Vec<Bytes>, crate::protocol::RawPacket)>,
}

impl std::fmt::Debug for PreparedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedBackend")
    }
}

type Connecting<'a> =
    std::pin::Pin<Box<dyn Future<Output = Result<PreparedBackend, BridgeError>> + Send + 'a>>;

enum SwitchError {
    // Nothing was sent to the client yet, so it can stay on its current backend
    Unreachable(BridgeError),
    Fatal(BridgeError),
}

fn client_timeout() -> BridgeError {
    BridgeError::IoError(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "client did not respond while switching servers",
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Login,
    Config,
    Play,
}

struct PhaseCell {
    phase: AtomicU8,
    // A backend that asks for reconfiguration switches what it sends at once, before the client
    // acknowledges, so its packets are read as configuration from then on
    backend_configuring: AtomicBool,
}

impl PhaseCell {
    fn new(phase: Phase) -> Self {
        Self {
            phase: AtomicU8::new(phase as u8),
            backend_configuring: AtomicBool::new(false),
        }
    }

    fn get(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            0 => Phase::Login,
            1 => Phase::Config,
            _ => Phase::Play,
        }
    }

    /// The phase of what the backend is sending
    fn backend(&self) -> Phase {
        match self.get() {
            Phase::Play if self.backend_configuring.load(Ordering::Acquire) => Phase::Config,
            phase => phase,
        }
    }

    fn set(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Release);
        self.backend_configuring.store(false, Ordering::Release);
    }

    fn backend_started_configuration(&self) {
        self.backend_configuring.store(true, Ordering::Release);
    }
}

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

// Caps memory buffered for a slow client; once full, reading from the backend pauses
const CLIENT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

type ClientQueueRx = mpsc::UnboundedReceiver<(Bytes, OwnedSemaphorePermit)>;

#[derive(Clone)]
struct ClientQueue {
    tx: mpsc::UnboundedSender<(Bytes, OwnedSemaphorePermit)>,
    budget: Arc<Semaphore>,
}

impl ClientQueue {
    fn new() -> (Self, ClientQueueRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let budget = Arc::new(Semaphore::new(CLIENT_QUEUE_BYTES));
        (Self { tx, budget }, rx)
    }

    async fn send(&self, bytes: Bytes) -> bool {
        let cost = bytes.len().clamp(1, CLIENT_QUEUE_BYTES) as u32;
        match Arc::clone(&self.budget).acquire_many_owned(cost).await {
            Ok(permit) => self.tx.send((bytes, permit)).is_ok(),
            Err(_) => false,
        }
    }
}

#[derive(Clone)]
struct PendingSuggestion {
    clean_cmd: String,
    offset: usize,
    proxy_matches: Vec<(String, Option<String>)>,
}

impl BackendBridge {
    /// Tunnels packets back and forth between client and backend
    #[allow(clippy::too_many_arguments)]
    async fn bridge_tunnel<R1, W1, R2, W2>(
        username: &str,
        client_reader: &mut PacketReader<R1>,
        client_writer: &mut PacketWriter<W1>,
        client_tx: &ClientQueue,
        client_rx: &mut ClientQueueRx,
        backend_reader: &mut PacketReader<R2>,
        backend_writer: &mut PacketWriter<W2>,
        max_packets_per_sec: u32,
        client_version: ProtocolVersion,
        action_rx: &mut mpsc::UnboundedReceiver<PlayerAction>,
        action_tx: &mpsc::UnboundedSender<PlayerAction>,
        command_dispatcher: Arc<CommandDispatcher>,
        proxy_config: Arc<Config>,
        session_manager: Arc<SessionManager>,
        plugin_manager: Arc<PluginManager>,
        player_uuid: uuid::Uuid,
        current_server_name: String,
        phase: &PhaseCell,
        keep_alive_challenge: &std::sync::Mutex<Option<i64>>,
        leftovers: &std::sync::Mutex<Leftovers>,
        connecting: Option<&mut Connecting<'_>>,
    ) -> Result<TunnelExit, BridgeError>
    where
        R1: AsyncRead + Unpin,
        W1: AsyncWrite + Unpin,
        R2: AsyncRead + Unpin,
        W2: AsyncWrite + Unpin,
    {
        let mut client_rate_limiter = PacketRateLimiter::new(max_packets_per_sec);

        let pending_suggestions: Arc<
            tokio::sync::Mutex<std::collections::HashMap<i32, PendingSuggestion>>,
        > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let client_writer = async {
            while let Some((packet_bytes, _permit)) = client_rx.recv().await {
                match timeout(CLIENT_WRITE_TIMEOUT, client_writer.send(packet_bytes)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        debug!("Client write failed for '{}': {:?}", username, e);
                        return TunnelExit::ClientDisconnected;
                    }
                    Err(_) => {
                        warn!("Client '{}' stopped reading, disconnecting", username);
                        return TunnelExit::ClientDisconnected;
                    }
                }
            }
            TunnelExit::ClientDisconnected
        };

        let client_to_backend = async {
            loop {
                match client_reader.read_packet().await {
                    Ok(mut raw_packet) => {
                        if !client_rate_limiter.record_packet() {
                            warn!(
                                "Player '{}' exceeded packet rate limit (flood protection kicked in)",
                                username
                            );
                            return TunnelExit::ClientDisconnected;
                        }

                        let current = phase.get();
                        if let Some(locale) = client_locale(&raw_packet, current, client_version) {
                            session_manager.update_locale(username, &locale);
                        }
                        if let Some(next) =
                            serverbound_transition(current, raw_packet.id, client_version)
                        {
                            phase.set(next);
                        } else if current == Phase::Config
                            && PacketKind::ConfigServerboundPluginMessage
                                .matches(raw_packet.id, client_version)
                            && !Self::plugin_message_event(
                                &plugin_manager,
                                &mut raw_packet,
                                client_version,
                                player_uuid,
                                &current_server_name,
                                PluginMessageSource::Player,
                            )
                            .await
                        {
                            continue;
                        } else if current == Phase::Play {
                            if PacketKind::PlayKeepAliveResponse
                                .matches(raw_packet.id, client_version)
                                && let Ok(reply) = decode_packet::<PlayKeepAliveResponse>(
                                    &raw_packet.payload,
                                    client_version,
                                )
                                && keep_alive_challenge.lock().ok().and_then(|c| *c)
                                    != Some(reply.id)
                            {
                                debug!(
                                    "Dropping stale keep-alive {} from '{}'",
                                    reply.id, username
                                );
                                continue;
                            }

                            let chat_message = if PacketKind::ChatMessage
                                .matches(raw_packet.id, client_version)
                            {
                                decode_packet::<ChatMessage>(&raw_packet.payload, client_version)
                                    .ok()
                                    .map(|m| m.message)
                            } else {
                                None
                            };
                            let command = if PacketKind::ChatCommand
                                .matches(raw_packet.id, client_version)
                            {
                                decode_packet::<ChatCommand>(&raw_packet.payload, client_version)
                                    .ok()
                                    .map(|c| c.command)
                            } else if PacketKind::SignedChatCommand
                                .matches(raw_packet.id, client_version)
                            {
                                decode_packet::<SignedChatCommand>(
                                    &raw_packet.payload,
                                    client_version,
                                )
                                .ok()
                                .map(|c| c.command)
                            } else if client_version < ProtocolVersion::V1_19 {
                                // Before 1.19 commands arrive as chat messages starting with '/'
                                chat_message
                                    .as_deref()
                                    .and_then(|m| m.strip_prefix('/'))
                                    .map(str::to_owned)
                            } else {
                                None
                            };

                            if let Some(command) = command {
                                let mut cmd_event = PlayerCommandEvent {
                                    uuid: player_uuid.to_string(),
                                    username: username.to_string(),
                                    command: command.clone(),
                                    cancelled: false,
                                };
                                plugin_manager.fire_player_command(&mut cmd_event).await;
                                if cmd_event.cancelled {
                                    match Self::swallow_chat(
                                        &raw_packet,
                                        client_version,
                                        backend_writer,
                                        username,
                                        session_manager.locale(username).as_deref(),
                                    )
                                    .await
                                    {
                                        Some(exit) => return exit,
                                        None => continue,
                                    }
                                }

                                let first_word = cmd_event
                                    .command
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or(&cmd_event.command);
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };
                                if command_dispatcher.handles(first_word, &source) {
                                    command_dispatcher.handle_command(&source, &cmd_event.command);
                                    match Self::swallow_chat(
                                        &raw_packet,
                                        client_version,
                                        backend_writer,
                                        username,
                                        session_manager.locale(username).as_deref(),
                                    )
                                    .await
                                    {
                                        Some(exit) => return exit,
                                        None => continue,
                                    }
                                }

                                if cmd_event.command != command {
                                    let text = if client_version < ProtocolVersion::V1_19 {
                                        format!("/{}", cmd_event.command)
                                    } else {
                                        cmd_event.command
                                    };
                                    if let Some(exit) = Self::rewrite_chat(
                                        &mut raw_packet,
                                        client_version,
                                        &text,
                                        username,
                                        session_manager.locale(username).as_deref(),
                                    ) {
                                        return exit;
                                    }
                                }
                            } else if let Some(message) = chat_message {
                                let mut chat_event = PlayerChatEvent {
                                    uuid: player_uuid.to_string(),
                                    username: username.to_string(),
                                    message: message.clone(),
                                    cancelled: false,
                                };
                                plugin_manager.fire_player_chat(&mut chat_event).await;
                                if chat_event.cancelled {
                                    match Self::swallow_chat(
                                        &raw_packet,
                                        client_version,
                                        backend_writer,
                                        username,
                                        session_manager.locale(username).as_deref(),
                                    )
                                    .await
                                    {
                                        Some(exit) => return exit,
                                        None => continue,
                                    }
                                }
                                if chat_event.message != message
                                    && let Some(exit) = Self::rewrite_chat(
                                        &mut raw_packet,
                                        client_version,
                                        &chat_event.message,
                                        username,
                                        session_manager.locale(username).as_deref(),
                                    )
                                {
                                    return exit;
                                }
                            }

                            if PacketKind::ServerboundPluginMessage
                                .matches(raw_packet.id, client_version)
                                && !Self::plugin_message_event(
                                    &plugin_manager,
                                    &mut raw_packet,
                                    client_version,
                                    player_uuid,
                                    &current_server_name,
                                    PluginMessageSource::Player,
                                )
                                .await
                            {
                                continue;
                            }

                            if PacketKind::CommandSuggestionRequest
                                .matches(raw_packet.id, client_version)
                                && let Ok(suggestion_req) = decode_packet::<CommandSuggestionRequest>(
                                    &raw_packet.payload,
                                    client_version,
                                )
                            {
                                let raw_cmd = &suggestion_req.text;
                                let clean_cmd = raw_cmd.strip_prefix('/').unwrap_or(raw_cmd);
                                let first_word =
                                    clean_cmd.split_whitespace().next().unwrap_or(clean_cmd);
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };

                                // 1. Arguments to a proxy command (contains a space, e.g. "/server ", "/send ")
                                if clean_cmd.contains(' ')
                                    && command_dispatcher.handles(first_word, &source)
                                {
                                    // Plugins answer these, so they run off the tunnel to keep its traffic flowing
                                    let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };
                                    let id = suggestion_req.id;
                                    let input = clean_cmd.to_string();
                                    let dispatcher = command_dispatcher.clone();
                                    let client_tx = client_tx.clone();
                                    tokio::spawn(async move {
                                        let Ok(suggestions) =
                                            tokio::task::spawn_blocking(move || {
                                                dispatcher.suggest_with_range(&input, &source)
                                            })
                                            .await
                                        else {
                                            return;
                                        };
                                        let response = CommandSuggestions {
                                            id,
                                            start: (suggestions.range.start + offset) as i32,
                                            length: suggestions.range.len() as i32,
                                            matches: suggestions
                                                .suggestions
                                                .into_iter()
                                                .map(|s| Suggestion {
                                                    text: s.text.cached_text().clone(),
                                                    tooltip: s.tooltip.map(|t| {
                                                        component_json(&t, client_version)
                                                    }),
                                                })
                                                .collect(),
                                        };
                                        if let Ok(bytes) = encode_packet(&response, client_version)
                                        {
                                            client_tx.send(bytes).await;
                                        }
                                    });
                                    continue;
                                }

                                // 2. Root command name completion (no space, e.g. "/", "/s", "/ser", "/server")
                                if !clean_cmd.contains(' ') {
                                    let clean_lower = clean_cmd.to_ascii_lowercase();
                                    let permitted =
                                        command_dispatcher.get_all_permitted_commands(&source);
                                    let proxy_matches: Vec<(String, Option<String>)> = permitted
                                        .into_iter()
                                        .filter(|(cmd_name, _)| cmd_name.starts_with(&clean_lower))
                                        .map(|(cmd_name, description)| {
                                            (cmd_name.to_string(), Some(description.to_string()))
                                        })
                                        .collect();

                                    if !proxy_matches.is_empty() {
                                        let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };
                                        let req_id = suggestion_req.id;

                                        pending_suggestions.lock().await.insert(
                                            req_id,
                                            PendingSuggestion {
                                                clean_cmd: clean_cmd.to_string(),
                                                offset,
                                                proxy_matches,
                                            },
                                        );

                                        let pending_ref = pending_suggestions.clone();
                                        let client_tx_clone = client_tx.clone();
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(200)).await;
                                            if let Some(pending) =
                                                pending_ref.lock().await.remove(&req_id)
                                            {
                                                let response = CommandSuggestions {
                                                    id: req_id,
                                                    start: pending.offset as i32,
                                                    length: pending.clean_cmd.len() as i32,
                                                    matches: pending
                                                        .proxy_matches
                                                        .into_iter()
                                                        .map(|(cmd, tip)| Suggestion {
                                                            text: cmd,
                                                            tooltip: tip.map(|t| {
                                                                component_json(
                                                                    &TextComponent::text(t),
                                                                    client_version,
                                                                )
                                                            }),
                                                        })
                                                        .collect(),
                                                };
                                                if let Ok(bytes) =
                                                    encode_packet(&response, client_version)
                                                {
                                                    client_tx_clone.send(bytes).await;
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }

                        if let Err(e) = backend_writer.send(raw_packet.to_bytes()).await {
                            debug!("Backend write failed for '{}': {:?}", username, e);
                            return TunnelExit::BackendDisconnected { reason: None };
                        }
                    }
                    Err(e) => {
                        debug!("Client '{}' stream ended: {:?}", username, e);
                        return TunnelExit::ClientDisconnected;
                    }
                }
            }
        };

        let backend_to_client = async {
            loop {
                match backend_reader.read_packet().await {
                    Ok(mut raw_packet) => {
                        let current = phase.backend();
                        if current == Phase::Play
                            && PacketKind::StartConfiguration.matches(raw_packet.id, client_version)
                        {
                            phase.backend_started_configuration();
                        }
                        if current == Phase::Config
                            && PacketKind::ConfigDisconnect.matches(raw_packet.id, client_version)
                        {
                            let reason = decode_packet::<ConfigDisconnect>(
                                &raw_packet.payload,
                                client_version,
                            )
                            .map(|d| plain_text(&d.reason))
                            .ok();
                            return TunnelExit::BackendDisconnected { reason };
                        }

                        if current == Phase::Config
                            && PacketKind::ConfigClientboundPluginMessage
                                .matches(raw_packet.id, client_version)
                            && !Self::plugin_message_event(
                                &plugin_manager,
                                &mut raw_packet,
                                client_version,
                                player_uuid,
                                &current_server_name,
                                PluginMessageSource::Server,
                            )
                            .await
                        {
                            continue;
                        }

                        if current == Phase::Play {
                            if client_version < ProtocolVersion::V1_20_2
                                && let Ok(mut leftovers) = leftovers.lock()
                            {
                                leftovers.observe(&raw_packet, client_version);
                            }

                            if PacketKind::PlayKeepAlive.matches(raw_packet.id, client_version)
                                && let Ok(challenge) = decode_packet::<PlayKeepAlive>(
                                    &raw_packet.payload,
                                    client_version,
                                )
                                && let Ok(mut current) = keep_alive_challenge.lock()
                            {
                                *current = Some(challenge.id);
                            }

                            if PacketKind::PlayDisconnect.matches(raw_packet.id, client_version) {
                                let reason = decode_packet::<PlayDisconnect>(
                                    &raw_packet.payload,
                                    client_version,
                                )
                                .map(|d| plain_text(&d.reason))
                                .ok()
                                .or_else(|| {
                                    let s =
                                        String::from_utf8_lossy(&raw_packet.payload).to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                });
                                return TunnelExit::BackendDisconnected { reason };
                            }

                            if PacketKind::CommandSuggestionsResponse
                                .matches(raw_packet.id, client_version)
                                && let Ok(mut backend_suggestions) =
                                    decode_packet::<CommandSuggestions>(
                                        &raw_packet.payload,
                                        client_version,
                                    )
                                && let Some(pending) = pending_suggestions
                                    .lock()
                                    .await
                                    .remove(&backend_suggestions.id)
                            {
                                merge_suggestions(
                                    &mut backend_suggestions.matches,
                                    pending.proxy_matches,
                                    client_version,
                                );
                                if let Ok(bytes) =
                                    encode_packet(&backend_suggestions, client_version)
                                {
                                    if !client_tx.send(bytes).await {
                                        return TunnelExit::ClientDisconnected;
                                    }
                                    continue;
                                }
                            }

                            if PacketKind::ClientboundPluginMessage
                                .matches(raw_packet.id, client_version)
                                && !Self::plugin_message_event(
                                    &plugin_manager,
                                    &mut raw_packet,
                                    client_version,
                                    player_uuid,
                                    &current_server_name,
                                    PluginMessageSource::Server,
                                )
                                .await
                            {
                                continue;
                            }

                            if PacketKind::Commands.matches(raw_packet.id, client_version) {
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };
                                let permitted =
                                    command_dispatcher.get_all_permitted_commands(&source);
                                let injected: Vec<InjectedCommand<'_>> = permitted
                                    .iter()
                                    .map(|(name, _)| InjectedCommand {
                                        name: name.as_str(),
                                        takes_args: matches!(
                                            name.as_str(),
                                            "server" | "send" | "help"
                                        ),
                                        executable_without_args: name != "send",
                                    })
                                    .collect();

                                if let Some(modified_payload) =
                                    inject_commands(&raw_packet.payload, client_version, &injected)
                                {
                                    let packet = crate::protocol::RawPacket {
                                        id: raw_packet.id,
                                        payload: modified_payload.into(),
                                    };
                                    if !client_tx.send(packet.to_bytes()).await {
                                        return TunnelExit::ClientDisconnected;
                                    }
                                    continue;
                                }
                            }
                        }

                        if !client_tx.send(raw_packet.to_bytes()).await {
                            return TunnelExit::ClientDisconnected;
                        }
                    }
                    Err(e) => {
                        debug!("Backend stream ended for '{}': {:?}", username, e);
                        return TunnelExit::BackendDisconnected {
                            reason: Some(e.to_string()),
                        };
                    }
                }
            }
        };

        let action_loop = async {
            while let Some(action) = action_rx.recv().await {
                match action {
                    PlayerAction::Connect { server_name } => {
                        return TunnelExit::Connect { server_name };
                    }
                    PlayerAction::Message(_) | PlayerAction::PluginMessage { .. }
                        if phase.get() != Phase::Play =>
                    {
                        debug!("Dropping {:?} for '{}' outside play", action, username);
                    }
                    PlayerAction::Message(content) => {
                        let chat_msg = SystemChat {
                            content: component_json(&content, client_version),
                            overlay: false,
                        };
                        if let Ok(bytes) = encode_packet(&chat_msg, client_version) {
                            client_tx.send(bytes).await;
                        }
                    }
                    PlayerAction::Disconnect(reason) => {
                        return TunnelExit::Kicked { reason };
                    }
                    PlayerAction::PluginMessage { channel, data } => {
                        let custom_payload = ClientboundPluginMessage { channel, data };
                        if let Ok(bytes) = encode_packet(&custom_payload, client_version) {
                            client_tx.send(bytes).await;
                        }
                    }
                }
            }
            TunnelExit::ClientDisconnected
        };

        // A switch logs in to the next backend while this tunnel keeps the current one running
        let prepared = async {
            match connecting {
                Some(future) => TunnelExit::Prepared(Box::new(future.as_mut().await)),
                None => std::future::pending().await,
            }
        };

        let exit = tokio::select! {
            exit = client_to_backend => exit,
            exit = backend_to_client => exit,
            exit = action_loop => exit,
            exit = client_writer => exit,
            exit = prepared => exit,
        };

        Ok(exit)
    }
}

fn merge_suggestions(
    backend_matches: &mut Vec<Suggestion>,
    proxy_matches: Vec<(String, Option<String>)>,
    version: ProtocolVersion,
) {
    for (cmd_name, tooltip) in proxy_matches {
        if !backend_matches
            .iter()
            .any(|bm| bm.text.eq_ignore_ascii_case(&cmd_name))
        {
            backend_matches.push(Suggestion {
                text: cmd_name,
                tooltip: tooltip.map(|t| component_json(&TextComponent::text(t), version)),
            });
        }
    }
    backend_matches.sort_by(|a, b| a.text.cmp(&b.text));
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

    #[test]
    fn test_phase_cell_round_trip() {
        let cell = PhaseCell::new(Phase::Login);
        for phase in [Phase::Config, Phase::Play, Phase::Login] {
            cell.set(phase);
            assert_eq!(cell.get(), phase);
        }
    }

    #[tokio::test]
    async fn test_client_queue_applies_backpressure() {
        let (queue, mut rx) = ClientQueue::new();
        assert!(
            queue
                .send(Bytes::from(vec![0u8; CLIENT_QUEUE_BYTES - 1]))
                .await
        );
        assert!(queue.send(Bytes::from_static(b"x")).await);

        let blocked = timeout(
            Duration::from_millis(50),
            queue.send(Bytes::from_static(b"y")),
        );
        assert!(blocked.await.is_err());

        let (first, permit) = rx.recv().await.unwrap();
        assert_eq!(first.len(), CLIENT_QUEUE_BYTES - 1);
        drop(permit);
        assert!(queue.send(Bytes::from_static(b"y")).await);

        drop(rx);
        assert!(!queue.send(Bytes::from_static(b"z")).await);
    }

    #[test]
    fn test_merge_suggestions_dedupes_and_sorts() {
        let mut backend_matches = vec![
            Suggestion {
                text: "server".to_string(),
                tooltip: None,
            },
            Suggestion {
                text: "status".to_string(),
                tooltip: None,
            },
        ];
        merge_suggestions(
            &mut backend_matches,
            vec![
                (
                    "server".to_string(),
                    Some("Switch or view backend server".to_string()),
                ),
                (
                    "send".to_string(),
                    Some("Send players to a backend".to_string()),
                ),
            ],
            ProtocolVersion(769),
        );

        let names: Vec<&str> = backend_matches.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(names, ["send", "server", "status"]);
        assert!(backend_matches[1].tooltip.is_none());
    }
}
