use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pumpkin_util::text::TextComponent;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
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
    Suggestion, SystemChat, chat_length_limit, chat_signing, command_length_limit, inject_commands,
    read_plugin_message, replace_leading_string, write_plugin_message,
};
use crate::protocol::packets::switch::{Leftovers, join_game_sequence};
use crate::protocol::text::{component_json, parse_message, plain_text};
use crate::protocol::{
    Packet, PacketKind, PacketReader, PacketWriter, ProtocolError, ProtocolVersion, decode_packet,
    encode_packet,
};
use crate::security::PacketRateLimiter;
use crate::session::{PlayerAction, SessionManager, send_reliably};

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
    #[error(
        "Backend server '{0}' is in online mode; set online-mode=false on it and use player info forwarding"
    )]
    OnlineMode(String),
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
    /// The client finished configuring while a switch was waiting for it
    ReachedPlay,
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
            } else if PacketKind::EncryptionRequest.matches(raw_packet.id, version) {
                return Err(BridgeError::OnlineMode(server_name.to_string()));
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
        client_reader: PacketReader<R>,
        mut client_writer: PacketWriter<W>,
        action_tx: mpsc::Sender<PlayerAction>,
        mut action_rx: mpsc::Receiver<PlayerAction>,
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
            if let Some(kick) = disconnect_packet(
                self.client_version,
                Phase::Login,
                self.locale().as_deref(),
                &reason,
            ) {
                let _ = timeout(CLIENT_WRITE_TIMEOUT, client_writer.send(kick)).await;
            }
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
        let (backend_reader, backend_writer, success_bytes) = match login {
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

        let (client_tx, client_rx) = ClientQueue::new();
        let writer = Task::spawn(write_client(
            client_writer,
            client_rx,
            client_tx.budget.clone(),
            self.player.username.clone(),
        ));
        let shared = Arc::new(Shared {
            username: self.player.username.clone(),
            uuid: self.player.id,
            version: self.client_version,
            plugin_manager: self.plugin_manager.clone(),
            session_manager: self.session_manager.clone(),
            command_dispatcher: self.command_dispatcher.clone(),
            proxy_config: self.proxy_config.clone(),
            action_tx: action_tx.clone(),
            client_tx,
            phase: PhaseCell::new(if self.client_version >= ProtocolVersion::V1_20_2 {
                Phase::Login
            } else {
                Phase::Play
            }),
            served: watch::Sender::new(current_server_name.clone()),
            keep_alive_challenge: std::sync::Mutex::new(None),
            leftovers: std::sync::Mutex::new(Leftovers::default()),
            client_settings: std::sync::Mutex::new(ClientSettings::default()),
            suggesting: std::sync::Mutex::new(Suggesting::default()),
            pending_suggestions: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        });
        let (client_events_tx, mut client_events) = mpsc::channel(CLIENT_EVENTS);
        let _client_reader = Task::spawn(read_client(
            shared.clone(),
            client_reader,
            PacketRateLimiter::new(self.max_packets_per_sec),
            client_events_tx,
        ));
        let mut backend = Backend::start(
            &shared,
            backend_reader,
            backend_writer,
            &current_server_name,
        );
        let client_tx = &shared.client_tx;
        let phase = &shared.phase;
        let bridge = &self;
        let mut connecting: Option<(String, Connecting<'_>)> = None;
        // A switch asked for, or a backend that finished logging in, while the client is still
        // logging in or configuring waits until it is playing
        let mut deferred: Option<String> = None;
        let mut early: Option<(Instant, Box<Result<PreparedBackend, BridgeError>>)> = None;
        // An exit to handle next without running the tunnel again
        let mut pending_exit: Option<TunnelExit> = None;
        // Set when the current backend is gone, so a waiting switch must finish right away
        let mut backend_gone = false;
        let mut carried = Carried::default();

        loop {
            let tunnel_res = if let Some(exit) = pending_exit.take() {
                Ok(exit)
            } else {
                Self::bridge_tunnel(
                    &shared,
                    &mut client_events,
                    &mut backend,
                    &mut action_rx,
                    connecting.as_mut().map(|(_, future)| future),
                    deferred.is_some() || early.is_some(),
                    &mut carried,
                )
                .await
            };

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

            match exit {
                TunnelExit::Kicked { reason } => {
                    info!("Kicking player '{}': {}", self.player.username, reason);
                    self.disconnect_client(writer, client_tx, phase.backend(), &reason)
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
                TunnelExit::ReachedPlay => {
                    if let Some(server_name) = deferred.take() {
                        send_reliably(&action_tx, PlayerAction::Connect { server_name });
                    }
                    if let Some((held_since, prepared)) = early.take() {
                        // A backend kept waiting this long may have given up on the login, so it
                        // is logged into again
                        if prepared.is_ok()
                            && held_since.elapsed() > HELD_BACKEND_LIMIT
                            && let Some((server_name, future)) = connecting.as_mut()
                            && let Some(again) = bridge.prepare_again(server_name)
                        {
                            *future = again;
                        } else {
                            pending_exit = Some(TunnelExit::Prepared(prepared));
                        }
                    }
                }
                TunnelExit::Connect { server_name } => {
                    if phase.backend() != Phase::Play {
                        deferred = Some(server_name);
                        continue;
                    }
                    if connecting.is_some() {
                        self.notify(
                            client_tx,
                            phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.server.already_connecting",
                                &[],
                            ),
                        );
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
                            client_tx,
                            phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.server.switch_cancelled",
                                &[&reason],
                            ),
                        );
                        continue;
                    }
                    let server_name = connect_event.target_server;
                    if server_name == current_server_name {
                        self.notify(
                            client_tx,
                            phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.command.server.already_connected",
                                &[&server_name],
                            ),
                        );
                        continue;
                    }

                    let Some(target_config) = self.proxy_config.servers.get(&server_name).cloned()
                    else {
                        self.notify(
                            client_tx,
                            phase,
                            translate(
                                self.locale().as_deref(),
                                "vine.server.unknown",
                                &[&server_name],
                            ),
                        );
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
                    let gone = std::mem::take(&mut backend_gone);
                    if phase.backend() != Phase::Play && !gone {
                        // Keep the slot taken so another switch waits; the result is replayed
                        // once the client is playing
                        if let Some((_, future)) = connecting.as_mut() {
                            *future = Box::pin(std::future::pending());
                        }
                        early = Some((Instant::now(), prepared));
                        continue;
                    }
                    let Some((server_name, _)) = connecting.take() else {
                        continue;
                    };
                    let switched = match *prepared {
                        Ok(prepared) => {
                            self.finish_switch(
                                &shared,
                                &mut client_events,
                                &mut backend,
                                &server_name,
                                prepared,
                            )
                            .await
                        }
                        Err(e) => Err(SwitchError::Unreachable(e)),
                    };
                    match switched {
                        Ok(next) => {
                            backend = next;
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
                                client_tx,
                                phase,
                                translate(
                                    self.locale().as_deref(),
                                    "vine.server.connect_failed",
                                    &[&server_name, &e],
                                ),
                            );
                        }
                        Err(SwitchError::Fatal(e)) => {
                            warn!(
                                "Lost player '{}' while switching to '{}': {}",
                                self.player.username, server_name, e
                            );
                            self.disconnect_client(
                                writer,
                                client_tx,
                                phase.backend(),
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
                    // A switch already on its way finishes instead, so a server that stops right
                    // after sending its players elsewhere still delivers them there
                    if let Some((held_since, prepared)) = early.take() {
                        if prepared.is_ok() && held_since.elapsed() <= HELD_BACKEND_LIMIT {
                            backend_gone = true;
                            pending_exit = Some(TunnelExit::Prepared(prepared));
                            continue;
                        }
                        // One held too long is logged into again below
                        let again = connecting.as_ref().and_then(|(server_name, _)| {
                            prepared
                                .is_ok()
                                .then(|| bridge.prepare_again(server_name))
                                .flatten()
                        });
                        match (again, connecting.as_mut()) {
                            (Some(again), Some((_, future))) => *future = again,
                            _ => connecting = None,
                        }
                    }
                    if let Some((_, future)) = connecting.as_mut() {
                        let prepared = future.as_mut().await;
                        if prepared.is_ok() {
                            backend_gone = true;
                            pending_exit = Some(TunnelExit::Prepared(Box::new(prepared)));
                            continue;
                        }
                        connecting = None;
                    }
                    deferred = None;
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
                        self.disconnect_client(writer, client_tx, phase.backend(), &reason)
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
                        self.disconnect_client(writer, client_tx, phase.backend(), &reason)
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
                        client_tx,
                        phase,
                        translate(
                            self.locale().as_deref(),
                            "vine.server.fallback",
                            &[&fb_name, &reason],
                        ),
                    );

                    match self
                        .switch_backend(
                            &shared,
                            &mut client_events,
                            &mut backend,
                            &fb_name,
                            &fb_cfg,
                        )
                        .await
                    {
                        Ok(next) => {
                            backend = next;
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
                            self.disconnect_client(
                                writer,
                                client_tx,
                                phase.backend(),
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

    /// Starts logging into a configured backend again
    fn prepare_again(&self, server_name: &str) -> Option<Connecting<'_>> {
        let config = self.proxy_config.servers.get(server_name)?.clone();
        let server_name = server_name.to_string();
        Some(Box::pin(async move {
            self.prepare_backend(&server_name, &config).await
        }))
    }

    /// Logs into another backend and moves the client over to it. On 1.20.2+ the client is sent
    /// back into the configuration phase so the new backend can configure it from scratch.
    async fn switch_backend(
        &self,
        shared: &Arc<Shared>,
        client_events: &mut mpsc::Receiver<ClientEvent>,
        old_backend: &mut Backend,
        server_name: &str,
        config: &BackendConfig,
    ) -> Result<Backend, SwitchError> {
        let prepared = self
            .prepare_backend(server_name, config)
            .await
            .map_err(SwitchError::Unreachable)?;
        self.finish_switch(shared, client_events, old_backend, server_name, prepared)
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
    async fn finish_switch(
        &self,
        shared: &Arc<Shared>,
        client_events: &mut mpsc::Receiver<ClientEvent>,
        old_backend: &mut Backend,
        server_name: &str,
        prepared: PreparedBackend,
    ) -> Result<Backend, SwitchError> {
        let PreparedBackend {
            reader: backend_reader,
            writer: mut backend_writer,
            join_game,
        } = prepared;
        let version = self.client_version;
        let client_tx = &shared.client_tx;
        let phase = &shared.phase;
        old_backend.stop_reading().await;
        shared.served.send_replace(server_name.to_string());
        if let Some((mut pending, join_game)) = join_game {
            let joining = join_game_sequence(&join_game, version).unwrap_or_else(|e| {
                debug!(
                    "Forwarding JoinGame from '{}' unchanged: {}",
                    server_name, e
                );
                vec![join_game.to_bytes()]
            });
            {
                let mut leftovers = shared
                    .leftovers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.extend(leftovers.clear_players(version));
                pending.extend(joining);
                pending.extend(leftovers.clear_overlays(version));
            }
            if !client_tx.push(pending) {
                return Err(SwitchError::Fatal(client_timeout()));
            }
            return Ok(Backend::start(
                shared,
                backend_reader,
                backend_writer,
                server_name,
            ));
        }

        let awaited = match phase.get() {
            // The old backend already asked for reconfiguration, so the client is about to
            // acknowledge that one
            Phase::Play if phase.backend() == Phase::Config => true,
            Phase::Play => {
                let start = encode_packet(&StartConfiguration, version)
                    .map_err(|e| SwitchError::Fatal(e.into()))?;
                // The client's wait for its acknowledgement starts once it has the request
                if !client_tx.push([start]) || !client_tx.written().await {
                    return Err(SwitchError::Fatal(client_timeout()));
                }
                phase.backend_started_configuration();
                true
            }
            Phase::Login => true,
            Phase::Config => false,
        };

        if awaited {
            // Packets the client sends before acknowledging, plugin events and all, still go to the
            // old backend; a kick over one of them is moot as that backend is left right after
            let acknowledged = async {
                loop {
                    let packet = match client_events.recv().await {
                        Some(ClientEvent::Packet {
                            entered: Some(Phase::Config),
                            ..
                        }) => return true,
                        Some(ClientEvent::Packet { packet, .. }) => packet,
                        Some(ClientEvent::KeepAliveResponse { id, packet })
                            if shared.answers_challenge(id) =>
                        {
                            packet
                        }
                        Some(ClientEvent::KeepAliveResponse { .. } | ClientEvent::Kick(_)) => {
                            continue;
                        }
                        Some(ClientEvent::Closed) | None => return false,
                    };
                    let _ = old_backend.writes.send(packet).await;
                }
            };
            match timeout(SWITCH_ACK_TIMEOUT, acknowledged).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(SwitchError::Fatal(ProtocolError::ConnectionClosed.into()));
                }
                Err(_) => return Err(SwitchError::Fatal(client_timeout())),
            }
        }
        // The client is configuring from here on, so a failure below must disconnect it as such
        phase.set(Phase::Config);

        let ack =
            encode_packet(&LoginAcknowledged, version).map_err(|e| SwitchError::Fatal(e.into()))?;
        let repeated = shared
            .client_settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .repeat(version);
        for packet in std::iter::once(ack).chain(repeated) {
            backend_writer
                .queue(&packet)
                .map_err(|e| SwitchError::Fatal(e.into()))?;
        }
        backend_writer
            .flush()
            .await
            .map_err(|e| SwitchError::Fatal(e.into()))?;
        Ok(Backend::start(
            shared,
            backend_reader,
            backend_writer,
            server_name,
        ))
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

    fn locale(&self) -> Option<String> {
        self.session_manager.locale(&self.player.username)
    }

    fn notify(&self, client_tx: &ClientQueue, phase: &PhaseCell, text: String) {
        let content = component_json(&parse_message(&text), self.client_version);
        let message = SystemChat {
            content,
            overlay: false,
        };
        match encode_packet(&message, self.client_version) {
            Ok(bytes) => {
                client_tx.push_in_play(bytes, phase);
            }
            Err(e) => debug!("Skipping a notice for {}: {}", self.client_version, e),
        }
    }

    /// Sends the kick after everything already queued and closes the connection behind it
    async fn disconnect_client(
        &self,
        mut writer: Task,
        client_tx: &ClientQueue,
        phase: Phase,
        reason: &str,
    ) {
        let locale = self.locale();
        if let Some(kick) = disconnect_packet(self.client_version, phase, locale.as_deref(), reason)
        {
            client_tx.push([kick]);
        }
        let _ = client_tx.tx.send(ClientWrite::Close);
        if timeout(CLIENT_WRITE_TIMEOUT, writer.join()).await.is_err() {
            debug!(
                "Gave up writing to '{}' before disconnecting",
                self.player.username
            );
        }
    }
}

fn disconnect_packet(
    version: ProtocolVersion,
    phase: Phase,
    locale: Option<&str>,
    reason: &str,
) -> Option<Bytes> {
    let encoded = match phase {
        Phase::Login => encode_packet(
            &LoginDisconnect {
                reason_json: crate::client::kick_reason(locale, reason, version).to_string(),
            },
            version,
        ),
        Phase::Config => encode_packet(
            &ConfigDisconnect {
                reason: crate::client::kick_reason(locale, reason, version),
            },
            version,
        ),
        Phase::Play => encode_packet(
            &PlayDisconnect {
                reason: component_json(&parse_message(reason), version),
            },
            version,
        ),
    };
    encoded
        .map_err(|e| debug!("Skipping a disconnect for {}: {}", version, e))
        .ok()
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

/// A backend switched to on 1.20.2+ configures the client from scratch, but the client only
/// tells the first backend about its settings and brand, so they are repeated to every next one
#[derive(Default)]
struct ClientSettings {
    information: Option<Bytes>,
    brand: Option<Vec<u8>>,
}

impl ClientSettings {
    fn observe(
        &mut self,
        packet: &crate::protocol::RawPacket,
        phase: Phase,
        version: ProtocolVersion,
    ) {
        let (information, plugin_message) = match phase {
            Phase::Config => (
                PacketKind::ConfigClientInformation,
                PacketKind::ConfigServerboundPluginMessage,
            ),
            Phase::Play => (
                PacketKind::ClientInformation,
                PacketKind::ServerboundPluginMessage,
            ),
            Phase::Login => return,
        };
        if information.matches(packet.id, version) {
            self.information = Some(packet.payload.clone());
        } else if plugin_message.matches(packet.id, version)
            && let Ok((channel, data)) = read_plugin_message(&mut &packet.payload[..], version)
            && channel == BRAND_CHANNEL
        {
            self.brand = Some(data);
        }
    }

    /// The packets to send a backend that has just entered configuration
    fn repeat(&self, version: ProtocolVersion) -> Vec<Bytes> {
        let mut packets = Vec::new();
        if let Some(data) = &self.brand
            && let Some(id) = PacketKind::ConfigServerboundPluginMessage.id(version)
        {
            let mut payload = Vec::new();
            write_plugin_message(&mut payload, BRAND_CHANNEL, data, version);
            packets.push(
                crate::protocol::RawPacket {
                    id,
                    payload: payload.into(),
                }
                .to_bytes(),
            );
        }
        if let Some(payload) = &self.information
            && let Some(id) = PacketKind::ConfigClientInformation.id(version)
        {
            packets.push(
                crate::protocol::RawPacket {
                    id,
                    payload: payload.clone(),
                }
                .to_bytes(),
            );
        }
        packets
    }
}

const BRAND_CHANNEL: &str = "minecraft:brand";

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

// Backends drop a login that is not acknowledged within about 30 seconds
const HELD_BACKEND_LIMIT: Duration = Duration::from_secs(20);

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

struct SuggestionRequest {
    id: i32,
    input: String,
    offset: usize,
    source: ProxyCommandSource,
    served: watch::Receiver<String>,
}

/// One argument suggestion per player is worked out at a time. The client only uses the answer
/// to its newest request, so only the newest one that arrives meanwhile is kept for next.
#[derive(Default)]
struct Suggesting {
    busy: bool,
    next: Option<SuggestionRequest>,
}

enum ClientWrite {
    // Packets of the proxy's own carry no permit, so they never wait for room
    Packet(Bytes, Option<OwnedSemaphorePermit>),
    // Answered once everything queued before it is written
    Written(tokio::sync::oneshot::Sender<()>),
    Close,
}

type ClientQueueRx = mpsc::UnboundedReceiver<ClientWrite>;

/// Everything for the client goes through here, in order, to the one task writing to it
#[derive(Clone)]
struct ClientQueue {
    tx: mpsc::UnboundedSender<ClientWrite>,
    budget: Arc<Semaphore>,
    // Held while the backend's reconfiguration is noted, so a packet checked as in play cannot
    // be queued behind the backend's StartConfiguration
    order: Arc<std::sync::Mutex<()>>,
}

impl ClientQueue {
    fn new() -> (Self, ClientQueueRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let budget = Arc::new(Semaphore::new(CLIENT_QUEUE_BYTES));
        let order = Arc::new(std::sync::Mutex::new(()));
        (Self { tx, budget, order }, rx)
    }

    async fn reserve(&self, bytes: &Bytes) -> Option<OwnedSemaphorePermit> {
        let cost = bytes.len().clamp(1, CLIENT_QUEUE_BYTES) as u32;
        Arc::clone(&self.budget).acquire_many_owned(cost).await.ok()
    }

    /// Queues a packet only if the client and backend are still playing
    async fn send_in_play(&self, bytes: Bytes, phase: &PhaseCell) -> bool {
        let Some(permit) = self.reserve(&bytes).await else {
            return false;
        };
        let _order = self.order.lock().unwrap_or_else(|e| e.into_inner());
        phase.backend() == Phase::Play
            && self
                .tx
                .send(ClientWrite::Packet(bytes, Some(permit)))
                .is_ok()
    }

    /// Queues the backend's StartConfiguration; its packets are read as configuration from then on
    async fn send_start_configuration(&self, bytes: Bytes, phase: &PhaseCell) -> bool {
        let Some(permit) = self.reserve(&bytes).await else {
            return false;
        };
        let _order = self.order.lock().unwrap_or_else(|e| e.into_inner());
        phase.backend_started_configuration();
        self.tx
            .send(ClientWrite::Packet(bytes, Some(permit)))
            .is_ok()
    }

    async fn send(&self, bytes: Bytes) -> bool {
        match self.reserve(&bytes).await {
            Some(permit) => self
                .tx
                .send(ClientWrite::Packet(bytes, Some(permit)))
                .is_ok(),
            None => false,
        }
    }

    fn push(&self, packets: impl IntoIterator<Item = Bytes>) -> bool {
        let _order = self.order.lock().unwrap_or_else(|e| e.into_inner());
        packets
            .into_iter()
            .all(|bytes| self.tx.send(ClientWrite::Packet(bytes, None)).is_ok())
    }

    fn push_in_play(&self, bytes: Bytes, phase: &PhaseCell) -> bool {
        let _order = self.order.lock().unwrap_or_else(|e| e.into_inner());
        phase.backend() == Phase::Play && self.tx.send(ClientWrite::Packet(bytes, None)).is_ok()
    }

    /// Waits until everything queued so far is written; false if the client is gone
    async fn written(&self) -> bool {
        let (done, wait) = tokio::sync::oneshot::channel();
        self.tx.send(ClientWrite::Written(done)).is_ok() && wait.await.is_ok()
    }

    /// Resolves once nothing is written to the client anymore
    async fn closed(&self) {
        self.tx.closed().await
    }
}

async fn write_client<W: AsyncWrite + Unpin>(
    mut writer: PacketWriter<W>,
    mut rx: ClientQueueRx,
    budget: Arc<Semaphore>,
    username: String,
) {
    while let Some(write) = rx.recv().await {
        match write {
            ClientWrite::Packet(bytes, _permit) => {
                match timeout(CLIENT_WRITE_TIMEOUT, writer.send(bytes)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        debug!("Client write failed for '{}': {:?}", username, e);
                        break;
                    }
                    Err(_) => {
                        warn!("Client '{}' stopped reading, disconnecting", username);
                        break;
                    }
                }
            }
            ClientWrite::Written(done) => {
                let _ = done.send(());
            }
            ClientWrite::Close => break,
        }
    }
    budget.close();
}

/// A task that is stopped when its handle is dropped
struct Task(Option<tokio::task::JoinHandle<()>>);

impl Task {
    fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(future)))
    }

    async fn join(&mut self) {
        if let Some(handle) = self.0.as_mut() {
            let _ = handle.await;
            self.0 = None;
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// A task that may finish what it has in hand once its handle is dropped, but not forever
struct Lingering(tokio::task::JoinHandle<()>);

impl Drop for Lingering {
    fn drop(&mut self) {
        let abort = self.0.abort_handle();
        tokio::spawn(async move {
            tokio::time::sleep(LINGER).await;
            abort.abort();
        });
    }
}

const LINGER: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct PendingSuggestion {
    clean_cmd: String,
    offset: usize,
    proxy_matches: Vec<(String, Option<String>)>,
}

/// What one player's session tasks and tunnel share
struct Shared {
    username: String,
    uuid: uuid::Uuid,
    version: ProtocolVersion,
    plugin_manager: Arc<PluginManager>,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    proxy_config: Arc<Config>,
    action_tx: mpsc::Sender<PlayerAction>,
    client_tx: ClientQueue,
    phase: PhaseCell,
    // The backend the client's packets go to; changing it drops answers worked out for the last one
    served: watch::Sender<String>,
    // Keep-alive replies meant for a previous backend would make the current one kick the
    // player, so only replies to the current backend's latest challenge are forwarded
    keep_alive_challenge: std::sync::Mutex<Option<i64>>,
    leftovers: std::sync::Mutex<Leftovers>,
    client_settings: std::sync::Mutex<ClientSettings>,
    suggesting: std::sync::Mutex<Suggesting>,
    pending_suggestions: tokio::sync::Mutex<std::collections::HashMap<i32, PendingSuggestion>>,
}

/// What the client reader hands the tunnel, in the order the client sent it
enum ClientEvent {
    /// A packet for the backend, and the phase the client entered by sending it
    Packet {
        packet: Bytes,
        entered: Option<Phase>,
    },
    KeepAliveResponse {
        id: i64,
        packet: Bytes,
    },
    Kick(String),
    Closed,
}

const CLIENT_EVENTS: usize = 16;

/// Reads the client for the whole session. Its packets are handled one at a time, plugin events
/// included, so a slow plugin only holds up what the client sends.
async fn read_client<R: AsyncRead + Unpin>(
    shared: Arc<Shared>,
    mut reader: PacketReader<R>,
    mut rate_limiter: PacketRateLimiter,
    events: mpsc::Sender<ClientEvent>,
) {
    let mut served = shared.served.subscribe();
    let mut phase = shared.phase.get();
    loop {
        let event = match reader.read_packet().await {
            Ok(_) if !rate_limiter.record_packet() => {
                warn!(
                    "Player '{}' exceeded packet rate limit (flood protection kicked in)",
                    shared.username
                );
                ClientEvent::Closed
            }
            Ok(packet) => {
                let server = served.borrow_and_update().clone();
                match shared
                    .client_packet(packet, &mut phase, &server, &served)
                    .await
                {
                    Some(event) => event,
                    None => continue,
                }
            }
            Err(e) => {
                debug!("Client '{}' stream ended: {:?}", shared.username, e);
                ClientEvent::Closed
            }
        };
        let closed = matches!(event, ClientEvent::Closed);
        if events.send(event).await.is_err() || closed {
            break;
        }
    }
}

impl Shared {
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

    fn answers_challenge(&self, id: i64) -> bool {
        self.keep_alive_challenge.lock().ok().and_then(|c| *c) == Some(id)
    }

    /// Works out what a packet from the client becomes; `None` when it is swallowed
    async fn client_packet(
        self: &Arc<Self>,
        mut raw_packet: crate::protocol::RawPacket,
        phase: &mut Phase,
        server: &str,
        served: &watch::Receiver<String>,
    ) -> Option<ClientEvent> {
        let version = self.version;
        let current = *phase;
        if let Some(locale) = client_locale(&raw_packet, current, version) {
            self.session_manager.update_locale(&self.username, &locale);
        }
        let entered = serverbound_transition(current, raw_packet.id, version);
        if let Some(next) = entered {
            *phase = next;
        } else if current == Phase::Config
            && PacketKind::ConfigServerboundPluginMessage.matches(raw_packet.id, version)
            && !self
                .plugin_message_event(&mut raw_packet, server, PluginMessageSource::Player)
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
                    return self.swallow_chat(&raw_packet);
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
                    return self.swallow_chat(&raw_packet);
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
                    return self.swallow_chat(&raw_packet);
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
                    return self.swallow_chat(&raw_packet);
                }
                if chat_event.message != message
                    && let Some(reason) = self.rewrite_chat(&mut raw_packet, &chat_event.message)
                {
                    return Some(ClientEvent::Kick(reason));
                }
            }

            if PacketKind::ServerboundPluginMessage.matches(raw_packet.id, version)
                && !self
                    .plugin_message_event(&mut raw_packet, server, PluginMessageSource::Player)
                    .await
            {
                return None;
            }

            if PacketKind::CommandSuggestionRequest.matches(raw_packet.id, version)
                && let Ok(suggestion_req) =
                    decode_packet::<CommandSuggestionRequest>(&raw_packet.payload, version)
                && self.suggest(suggestion_req, served).await
            {
                return None;
            }
        }

        if version >= ProtocolVersion::V1_20_2 {
            self.client_settings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .observe(&raw_packet, current, version);
        }
        Some(ClientEvent::Packet {
            packet: raw_packet.to_bytes(),
            entered,
        })
    }

    /// Answers a suggestion request for a proxy command; true when the backend must not see it
    async fn suggest(
        self: &Arc<Self>,
        suggestion_req: CommandSuggestionRequest,
        served: &watch::Receiver<String>,
    ) -> bool {
        let version = self.version;
        let raw_cmd = &suggestion_req.text;
        let clean_cmd = raw_cmd.strip_prefix('/').unwrap_or(raw_cmd);
        let first_word = clean_cmd.split_whitespace().next().unwrap_or(clean_cmd);
        let source = self.command_source();

        // 1. Arguments to a proxy command (contains a space, e.g. "/server ", "/send ")
        if clean_cmd.contains(' ') && self.command_dispatcher.handles(first_word, &source) {
            // Plugins answer these, so they run off the reader to keep its traffic flowing
            let request = SuggestionRequest {
                id: suggestion_req.id,
                input: clean_cmd.to_string(),
                offset: if raw_cmd.starts_with('/') { 1 } else { 0 },
                source,
                served: served.clone(),
            };
            {
                let mut state = self.suggesting.lock().unwrap_or_else(|e| e.into_inner());
                if state.busy {
                    state.next = Some(request);
                    return true;
                }
                state.busy = true;
            }
            let shared = self.clone();
            tokio::spawn(async move {
                let mut request = request;
                loop {
                    let SuggestionRequest {
                        id,
                        input,
                        offset,
                        source,
                        served,
                    } = request;
                    let dispatcher = shared.command_dispatcher.clone();
                    let suggestions = tokio::task::spawn_blocking(move || {
                        dispatcher.suggest_with_range(&input, &source)
                    })
                    .await;
                    let next = {
                        let mut state = shared.suggesting.lock().unwrap_or_else(|e| e.into_inner());
                        let next = state.next.take();
                        state.busy = next.is_some();
                        next
                    };
                    if next.is_none()
                        && served.has_changed().is_ok_and(|changed| !changed)
                        && let Ok(suggestions) = suggestions
                    {
                        let response = CommandSuggestions {
                            id,
                            start: (suggestions.range.start + offset) as i32,
                            length: suggestions.range.len() as i32,
                            matches: suggestions
                                .suggestions
                                .into_iter()
                                .map(|s| Suggestion {
                                    text: s.text.cached_text().clone(),
                                    tooltip: s.tooltip.map(|t| component_json(&t, version)),
                                })
                                .collect(),
                        };
                        if let Ok(bytes) = encode_packet(&response, version) {
                            shared.client_tx.send_in_play(bytes, &shared.phase).await;
                        }
                    }
                    match next {
                        Some(next) => request = next,
                        None => break,
                    }
                }
            });
            return true;
        }

        // 2. Root command name completion (no space, e.g. "/", "/s", "/ser", "/server")
        if !clean_cmd.contains(' ') {
            let clean_lower = clean_cmd.to_ascii_lowercase();
            let permitted = self.command_dispatcher.get_all_permitted_commands(&source);
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

                self.pending_suggestions.lock().await.insert(
                    req_id,
                    PendingSuggestion {
                        clean_cmd: clean_cmd.to_string(),
                        offset,
                        proxy_matches,
                    },
                );

                let shared = self.clone();
                let served = served.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if let Some(pending) = shared.pending_suggestions.lock().await.remove(&req_id) {
                        let response = CommandSuggestions {
                            id: req_id,
                            start: pending.offset as i32,
                            length: pending.clean_cmd.len() as i32,
                            matches: pending
                                .proxy_matches
                                .into_iter()
                                .map(|(cmd, tip)| Suggestion {
                                    text: cmd,
                                    tooltip: tip
                                        .map(|t| component_json(&TextComponent::text(t), version)),
                                })
                                .collect(),
                        };
                        if served.has_changed().is_ok_and(|changed| !changed)
                            && let Ok(bytes) = encode_packet(&response, version)
                        {
                            shared.client_tx.send_in_play(bytes, &shared.phase).await;
                        }
                    }
                });
            }
        }
        false
    }

    // The backend tracks which chat messages the client has seen through these packets, so one the
    // proxy drops must still hand its acknowledgements on, and a signed one cannot be dropped at all
    fn swallow_chat(&self, packet: &crate::protocol::RawPacket) -> Option<ClientEvent> {
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
            return Some(ClientEvent::Packet {
                packet: ack,
                entered: None,
            });
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

/// What a tunnel was in the middle of, for the next one to finish
#[derive(Default)]
struct Carried {
    // The client's acknowledgement that it is playing is on its way to the backend
    reached_play: bool,
    // A message for the client waiting for room in its queue
    message: Option<Bytes>,
}

/// Why a backend's reader stopped
enum BackendEvent {
    Disconnected { reason: Option<String> },
    ClientGone,
}

/// The backend the client is on; it is read and written by tasks of its own
struct Backend {
    writes: mpsc::Sender<Bytes>,
    events: mpsc::Receiver<BackendEvent>,
    reader: Task,
    _writer: Lingering,
}

impl Backend {
    fn start(
        shared: &Arc<Shared>,
        reader: BackendReader,
        writer: BackendWriter,
        server_name: &str,
    ) -> Self {
        if let Ok(mut challenge) = shared.keep_alive_challenge.lock() {
            *challenge = None;
        }
        let (events_tx, events) = mpsc::channel(1);
        let reader = Task::spawn(read_backend(
            shared.clone(),
            reader,
            server_name.to_string(),
            events_tx,
        ));
        let (writes, rx) = mpsc::channel(BACKEND_WRITES);
        let writer = Lingering(tokio::spawn(write_backend(
            writer,
            rx,
            shared.username.clone(),
        )));
        Self {
            writes,
            events,
            reader,
            _writer: writer,
        }
    }

    /// Stops reading once the packet in hand has reached the client queue; the rest is left unread
    async fn stop_reading(&mut self) {
        self.events.close();
        self.reader.join().await;
    }
}

const BACKEND_WRITES: usize = 128;

/// Writes what the client sends to the backend, flushing once per batch
async fn write_backend(mut writer: BackendWriter, mut rx: mpsc::Receiver<Bytes>, username: String) {
    let mut batch = Vec::new();
    while rx.recv_many(&mut batch, BACKEND_WRITES).await > 0 {
        let written = batch.drain(..).try_for_each(|packet| writer.queue(&packet));
        if let Err(e) = match written {
            Ok(()) => writer.flush().await,
            Err(e) => Err(e),
        } {
            debug!("Backend write failed for '{}': {:?}", username, e);
            return;
        }
    }
}

async fn read_backend(
    shared: Arc<Shared>,
    mut reader: BackendReader,
    server_name: String,
    events: mpsc::Sender<BackendEvent>,
) {
    let event = loop {
        let packet = tokio::select! {
            biased;
            _ = events.closed() => return,
            packet = reader.read_packet() => packet,
        };
        let handled = match packet {
            Ok(packet) => shared.backend_packet(packet, &server_name).await,
            Err(e) => {
                debug!("Backend stream ended for '{}': {:?}", shared.username, e);
                Err(BackendEvent::Disconnected {
                    reason: Some(e.to_string()),
                })
            }
        };
        if let Err(event) = handled {
            break event;
        }
    };
    let _ = events.send(event).await;
}

impl Shared {
    /// Passes a packet from the backend on to the client queue, waiting for room there
    async fn backend_packet(
        &self,
        mut raw_packet: crate::protocol::RawPacket,
        server_name: &str,
    ) -> Result<(), BackendEvent> {
        let version = self.version;
        let client_tx = &self.client_tx;
        let current = self.phase.backend();
        if current == Phase::Config && PacketKind::ConfigDisconnect.matches(raw_packet.id, version)
        {
            let reason = decode_packet::<ConfigDisconnect>(&raw_packet.payload, version)
                .map(|d| plain_text(&d.reason))
                .ok();
            return Err(BackendEvent::Disconnected { reason });
        }

        if current == Phase::Config
            && PacketKind::ConfigClientboundPluginMessage.matches(raw_packet.id, version)
            && !self
                .plugin_message_event(&mut raw_packet, server_name, PluginMessageSource::Server)
                .await
        {
            return Ok(());
        }

        let mut packet = None;
        if current == Phase::Play {
            if PacketKind::StartConfiguration.matches(raw_packet.id, version) {
                let bytes = raw_packet.to_bytes();
                if !client_tx.send_start_configuration(bytes, &self.phase).await {
                    return Err(BackendEvent::ClientGone);
                }
                return Ok(());
            }

            if version < ProtocolVersion::V1_20_2
                && let Ok(mut leftovers) = self.leftovers.lock()
            {
                leftovers.observe(&raw_packet, version);
            }

            if PacketKind::PlayKeepAlive.matches(raw_packet.id, version)
                && let Ok(challenge) = decode_packet::<PlayKeepAlive>(&raw_packet.payload, version)
                && let Ok(mut current) = self.keep_alive_challenge.lock()
            {
                *current = Some(challenge.id);
            }

            if PacketKind::PlayDisconnect.matches(raw_packet.id, version) {
                let reason = decode_packet::<PlayDisconnect>(&raw_packet.payload, version)
                    .map(|d| plain_text(&d.reason))
                    .ok()
                    .or_else(|| {
                        let s = String::from_utf8_lossy(&raw_packet.payload).to_string();
                        if s.is_empty() { None } else { Some(s) }
                    });
                return Err(BackendEvent::Disconnected { reason });
            }

            if PacketKind::CommandSuggestionsResponse.matches(raw_packet.id, version)
                && let Ok(mut backend_suggestions) =
                    decode_packet::<CommandSuggestions>(&raw_packet.payload, version)
                && let Some(pending) = self
                    .pending_suggestions
                    .lock()
                    .await
                    .remove(&backend_suggestions.id)
            {
                merge_suggestions(
                    &mut backend_suggestions.matches,
                    pending.proxy_matches,
                    version,
                );
                packet = encode_packet(&backend_suggestions, version).ok();
            } else if PacketKind::ClientboundPluginMessage.matches(raw_packet.id, version)
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
        if !client_tx.send(bytes).await {
            return Err(BackendEvent::ClientGone);
        }
        Ok(())
    }
}

impl BackendBridge {
    /// Tunnels packets back and forth between client and backend
    async fn bridge_tunnel(
        shared: &Arc<Shared>,
        client_events: &mut mpsc::Receiver<ClientEvent>,
        backend: &mut Backend,
        action_rx: &mut mpsc::Receiver<PlayerAction>,
        connecting: Option<&mut Connecting<'_>>,
        wake_on_play: bool,
        carried: &mut Carried,
    ) -> Result<TunnelExit, BridgeError> {
        let username = shared.username.as_str();
        let client_version = shared.version;
        let client_tx = &shared.client_tx;
        let phase = &shared.phase;
        let Backend {
            writes: backend_writes,
            events: backend_events,
            ..
        } = backend;
        let Carried {
            reached_play,
            message: held_message,
        } = carried;
        if std::mem::take(reached_play) {
            return Ok(TunnelExit::ReachedPlay);
        }

        let client_writer = async {
            client_tx.closed().await;
            TunnelExit::ClientDisconnected
        };

        let client_to_backend = async {
            loop {
                let packet = match client_events.recv().await {
                    Some(ClientEvent::Packet { packet, entered }) => {
                        if let Some(next) = entered {
                            phase.set(next);
                            *reached_play = next == Phase::Play && wake_on_play;
                        }
                        packet
                    }
                    Some(ClientEvent::KeepAliveResponse { id, packet }) => {
                        if !shared.answers_challenge(id) {
                            debug!("Dropping stale keep-alive {} from '{}'", id, username);
                            continue;
                        }
                        packet
                    }
                    Some(ClientEvent::Kick(reason)) => return TunnelExit::Kicked { reason },
                    Some(ClientEvent::Closed) | None => return TunnelExit::ClientDisconnected,
                };
                if backend_writes.send(packet).await.is_err() {
                    return TunnelExit::BackendDisconnected { reason: None };
                }
                if std::mem::take(reached_play) {
                    return TunnelExit::ReachedPlay;
                }
            }
        };

        let backend_to_client = async {
            match backend_events.recv().await {
                Some(BackendEvent::Disconnected { reason }) => {
                    TunnelExit::BackendDisconnected { reason }
                }
                Some(BackendEvent::ClientGone) => TunnelExit::ClientDisconnected,
                None => TunnelExit::BackendDisconnected { reason: None },
            }
        };

        let action_loop = async {
            loop {
                if let Some(bytes) = held_message.as_ref() {
                    if !client_tx.send_in_play(bytes.clone(), phase).await {
                        debug!("Dropping a message for '{}' outside play", username);
                    }
                    *held_message = None;
                }
                let Some(action) = action_rx.recv().await else {
                    return TunnelExit::ClientDisconnected;
                };
                let encoded = match action {
                    PlayerAction::Connect { server_name } => {
                        return TunnelExit::Connect { server_name };
                    }
                    PlayerAction::Disconnect(reason) => {
                        return TunnelExit::Kicked { reason };
                    }
                    PlayerAction::Message(content) => encode_packet(
                        &SystemChat {
                            content: component_json(&content, client_version),
                            overlay: false,
                        },
                        client_version,
                    ),
                    PlayerAction::PluginMessage { channel, data } => {
                        encode_packet(&ClientboundPluginMessage { channel, data }, client_version)
                    }
                };
                *held_message = encoded.ok();
            }
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

        let Some(ClientWrite::Packet(first, permit)) = rx.recv().await else {
            panic!("expected the first packet");
        };
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
