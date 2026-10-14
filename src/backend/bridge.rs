use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use pumpkin_util::text::TextComponent;
use pumpkin_util::text::color::NamedColor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth::AuthenticatedPlayer;
use crate::backend::forwarding::{
    ForwardingHelper, VELOCITY_PLAYER_INFO_CHANNEL, VINE_PLAYER_INFO_CHANNEL,
};
use crate::command::{CommandDispatcher, CommandSender, ProxyCommandSource};
use crate::config::{BackendConfig, Config, ForwardingMode, NetworkConfig};
use crate::network;
use crate::plugin::PluginManager;
use crate::plugin::api::{
    PlayerChatEvent, PlayerCommandEvent, PlayerDisconnectEvent, PlayerJoinEvent,
    PluginMessageEvent, ServerConnectEvent, ServerConnectedEvent,
};
use crate::protocol::packets::config::ConfigDisconnect;
use crate::protocol::packets::handshake::{Handshake, HandshakeIntent};
use crate::protocol::packets::login::{
    LoginDisconnect, LoginPluginRequest, LoginPluginResponse, LoginStart, SetCompression,
};
use crate::protocol::packets::play::{
    ChatCommand, ChatMessage, ClientboundPluginMessage, CommandSuggestionRequest,
    CommandSuggestions, InjectedCommand, PlayDisconnect, ServerboundPluginMessage,
    StartConfiguration, Suggestion, SystemChat, Transfer, inject_commands,
};
use crate::protocol::{
    Packet, PacketKind, PacketReader, PacketWriter, ProtocolError, ProtocolVersion, decode_packet,
    encode_packet,
};
use crate::security::PacketRateLimiter;
use crate::session::{PlayerAction, PlayerSession, SessionManager};

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
pub enum TunnelExit {
    /// Client disconnected or connection closed
    ClientDisconnected,
    /// Player requested switch to another backend server
    Connect { server_name: String },
    /// Direct client transfer requested
    Transfer { host: String, port: u16 },
    /// Backend server closed connection or sent disconnect/kick
    BackendDisconnected { reason: Option<String> },
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

        let login_start = LoginStart {
            name: self.player.username.clone(),
            uuid: Some(self.player.id),
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

                let data = if request.channel == VINE_PLAYER_INFO_CHANNEL {
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
                } else if request.channel == VELOCITY_PLAYER_INFO_CHANNEL {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VelocityError("Secret missing".to_string()))?;

                    Some(
                        ForwardingHelper::build_velocity_payload(
                            secret,
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
            let reason = connect_event
                .cancel_reason
                .unwrap_or_else(|| "Connection cancelled by plugin".to_string());
            warn!(
                "Player '{}' connection to '{}' cancelled by plugin: {}",
                self.player.username, connect_event.target_server, reason
            );
            return Err(BridgeError::VineError(reason));
        }
        current_server_name = connect_event.target_server;

        let initial_backend_cfg = if current_server_name == self.server_name {
            self.config.clone()
        } else if let Some(cfg) = self.proxy_config.servers.get(&current_server_name) {
            cfg.clone()
        } else {
            self.config.clone()
        };

        let (mut backend_reader, mut backend_writer, success_bytes) = match self
            .login_backend(&current_server_name, &initial_backend_cfg)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                if let Some((fb_name, fb_cfg)) = &self.fallback_server {
                    if fb_name != &current_server_name {
                        warn!(
                            "Primary server '{}' unreachable ({}), attempting failover to fallback server '{}' at {}",
                            current_server_name, e, fb_name, fb_cfg.address
                        );
                        current_server_name = fb_name.clone();
                        self.login_backend(&current_server_name, fb_cfg).await?
                    } else {
                        return Err(e);
                    }
                } else {
                    return Err(e);
                }
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

        let (action_tx, mut action_rx) = tokio::sync::mpsc::unbounded_channel();
        self.session_manager.register(PlayerSession {
            username: self.player.username.clone(),
            uuid: self.player.id,
            current_server: current_server_name.clone(),
            action_tx: action_tx.clone(),
            client_ip: self.client_ip.to_string(),
            protocol_version: self.client_version.0,
        });

        loop {
            let tunnel_res = Self::bridge_tunnel(
                &self.player.username,
                &mut client_reader,
                &mut client_writer,
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

            match exit {
                TunnelExit::ClientDisconnected => {
                    debug!(
                        "Player '{}' disconnected from client side",
                        self.player.username
                    );
                    break;
                }
                TunnelExit::Transfer { host, port } => {
                    let transfer = Transfer {
                        host: host.clone(),
                        port,
                    };
                    send_best_effort(&mut client_writer, &transfer, self.client_version).await;
                    info!(
                        "Transferring player '{}' to {}:{}",
                        self.player.username, host, port
                    );
                    break;
                }
                TunnelExit::Connect { server_name } => {
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
                        let reason = connect_event
                            .cancel_reason
                            .as_deref()
                            .unwrap_or("Server switch cancelled by plugin");
                        let msg = TextComponent::text(format!("§c{}", reason));
                        send_best_effort(
                            &mut client_writer,
                            &SystemChat {
                                content: msg,
                                overlay: false,
                            },
                            self.client_version,
                        )
                        .await;
                        continue;
                    }
                    let server_name = connect_event.target_server;

                    let target_config = match self.proxy_config.servers.get(&server_name) {
                        Some(cfg) => cfg.clone(),
                        None => {
                            let msg = TextComponent::text(format!(
                                "Server '{}' does not exist.",
                                server_name
                            ));
                            send_best_effort(
                                &mut client_writer,
                                &SystemChat {
                                    content: msg,
                                    overlay: false,
                                },
                                self.client_version,
                            )
                            .await;
                            break;
                        }
                    };

                    match self.login_backend(&server_name, &target_config).await {
                        Ok((new_dec, new_enc, _)) => {
                            if self.client_version >= ProtocolVersion::V1_20_2 {
                                send_best_effort(
                                    &mut client_writer,
                                    &StartConfiguration,
                                    self.client_version,
                                )
                                .await;
                            }
                            backend_reader = new_dec;
                            backend_writer = new_enc;
                            current_server_name = server_name.clone();
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
                        Err(e) => {
                            warn!(
                                "Failed to switch player '{}' to '{}': {}",
                                self.player.username, server_name, e
                            );
                            let msg = TextComponent::text(format!(
                                "§cFailed to connect to server '{}': {}",
                                server_name, e
                            ));
                            send_best_effort(
                                &mut client_writer,
                                &SystemChat {
                                    content: msg,
                                    overlay: false,
                                },
                                self.client_version,
                            )
                            .await;

                            let can_fallback = self
                                .fallback_server
                                .as_ref()
                                .is_some_and(|(fb_name, _)| fb_name != &server_name);

                            if can_fallback {
                                let (fb_name, fb_cfg) = self.fallback_server.as_ref().unwrap();
                                match self.login_backend(fb_name, fb_cfg).await {
                                    Ok((new_dec, new_enc, _)) => {
                                        if self.client_version >= ProtocolVersion::V1_20_2 {
                                            send_best_effort(
                                                &mut client_writer,
                                                &StartConfiguration,
                                                self.client_version,
                                            )
                                            .await;
                                        }
                                        backend_reader = new_dec;
                                        backend_writer = new_enc;
                                        current_server_name = fb_name.clone();
                                        self.session_manager.update_server(
                                            &self.player.username,
                                            &current_server_name,
                                        );
                                    }
                                    Err(_) => {
                                        let kick_reason = format!(
                                            "Lost connection to '{}' and fallback unavailable",
                                            current_server_name
                                        );
                                        Self::disconnect_client(
                                            &mut client_writer,
                                            self.client_version,
                                            false,
                                            &kick_reason,
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                TunnelExit::BackendDisconnected { reason } => {
                    warn!(
                        "Backend server '{}' disconnected player '{}': {:?}",
                        current_server_name, self.player.username, reason
                    );

                    let can_fallback = self
                        .fallback_server
                        .as_ref()
                        .is_some_and(|(fb_name, _)| fb_name != &current_server_name);

                    if can_fallback {
                        let (fb_name, fb_cfg) = self.fallback_server.as_ref().unwrap();
                        let reason_str = reason.as_deref().unwrap_or("Server closed");
                        info!(
                            "Rerouting player '{}' to fallback server '{}' (kicked from '{}': {})",
                            self.player.username, fb_name, current_server_name, reason_str
                        );

                        let notice = TextComponent::text(format!(
                            "§eConnecting to fallback server '{}'... (§c{}§e)",
                            fb_name, reason_str
                        ));
                        send_best_effort(
                            &mut client_writer,
                            &SystemChat {
                                content: notice,
                                overlay: false,
                            },
                            self.client_version,
                        )
                        .await;

                        match self.login_backend(fb_name, fb_cfg).await {
                            Ok((new_dec, new_enc, _)) => {
                                if self.client_version >= ProtocolVersion::V1_20_2 {
                                    send_best_effort(
                                        &mut client_writer,
                                        &StartConfiguration,
                                        self.client_version,
                                    )
                                    .await;
                                }
                                backend_reader = new_dec;
                                backend_writer = new_enc;
                                current_server_name = fb_name.clone();
                                self.session_manager
                                    .update_server(&self.player.username, &current_server_name);
                                info!(
                                    "Player '{}' successfully recovered to fallback '{}'",
                                    self.player.username, current_server_name
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to connect player '{}' to fallback server '{}': {}",
                                    self.player.username, fb_name, e
                                );
                                let kick_reason = format!(
                                    "Lost connection to '{}' and fallback unavailable: {}",
                                    current_server_name, e
                                );
                                Self::disconnect_client(
                                    &mut client_writer,
                                    self.client_version,
                                    false,
                                    &kick_reason,
                                )
                                .await;
                                break;
                            }
                        }
                    } else {
                        let reason_str = reason.as_deref().unwrap_or("Lost connection to server");
                        Self::disconnect_client(
                            &mut client_writer,
                            self.client_version,
                            false,
                            reason_str,
                        )
                        .await;
                        break;
                    }
                }
            }
        }

        let disconnect_event = PlayerDisconnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            last_server: Some(current_server_name.clone()),
        };
        self.plugin_manager
            .fire_player_disconnect(&disconnect_event)
            .await;

        self.session_manager.unregister(&self.player.username);
        self.online_players.fetch_sub(1, Ordering::Relaxed);
        info!(
            "Player '{}' disconnected from proxy. Online players: {}",
            self.player.username,
            self.online_players.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Helper to send formatted disconnect packet to client in either play or configuration state
    async fn disconnect_client<W: AsyncWrite + Unpin>(
        writer: &mut PacketWriter<W>,
        version: ProtocolVersion,
        is_config_state: bool,
        reason: &str,
    ) {
        if is_config_state {
            let reason =
                TextComponent::text(format!("[Vine Proxy] {reason}")).color_named(NamedColor::Red);
            send_best_effort(writer, &ConfigDisconnect { reason }, version).await;
        } else {
            let reason = TextComponent::text(reason.to_string());
            send_best_effort(writer, &PlayDisconnect { reason }, version).await;
        }
    }
}

async fn send_best_effort<P: Packet, W: AsyncWrite + Unpin>(
    writer: &mut PacketWriter<W>,
    packet: &P,
    version: ProtocolVersion,
) {
    match encode_packet(packet, version) {
        Ok(bytes) => {
            let _ = writer.send(bytes).await;
        }
        Err(e) => debug!("Skipping {:?} for {}: {}", P::KIND, version, e),
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
        backend_reader: &mut PacketReader<R2>,
        backend_writer: &mut PacketWriter<W2>,
        max_packets_per_sec: u32,
        client_version: ProtocolVersion,
        action_rx: &mut tokio::sync::mpsc::UnboundedReceiver<PlayerAction>,
        action_tx: &tokio::sync::mpsc::UnboundedSender<PlayerAction>,
        command_dispatcher: Arc<CommandDispatcher>,
        proxy_config: Arc<Config>,
        session_manager: Arc<SessionManager>,
        plugin_manager: Arc<PluginManager>,
        player_uuid: uuid::Uuid,
        current_server_name: String,
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

        let (client_tx, mut client_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

        let client_writer = async {
            while let Some(packet_bytes) = client_rx.recv().await {
                if let Err(e) = client_writer.send(packet_bytes).await {
                    debug!("Client write failed for '{}': {:?}", username, e);
                    return TunnelExit::ClientDisconnected;
                }
            }
            TunnelExit::ClientDisconnected
        };

        let client_to_backend = async {
            loop {
                match client_reader.read_packet().await {
                    Ok(raw_packet) => {
                        if !client_rate_limiter.record_packet() {
                            warn!(
                                "Player '{}' exceeded packet rate limit (flood protection kicked in)",
                                username
                            );
                            return TunnelExit::ClientDisconnected;
                        }

                        if PacketKind::ChatCommand.matches(raw_packet.id, client_version)
                            && let Ok(chat_cmd) =
                                decode_packet::<ChatCommand>(&raw_packet.payload, client_version)
                        {
                            let mut cmd_event = PlayerCommandEvent {
                                uuid: player_uuid.to_string(),
                                username: username.to_string(),
                                command: chat_cmd.command,
                                cancelled: false,
                            };
                            plugin_manager.fire_player_command(&mut cmd_event).await;
                            if cmd_event.cancelled {
                                continue;
                            }

                            let first_word = cmd_event
                                .command
                                .split_whitespace()
                                .next()
                                .unwrap_or(&cmd_event.command);
                            if command_dispatcher.has_command(first_word) {
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };
                                command_dispatcher.handle_command(&source, &cmd_event.command);
                                continue;
                            }
                        }

                        if PacketKind::ChatMessage.matches(raw_packet.id, client_version)
                            && let Ok(chat_msg) =
                                decode_packet::<ChatMessage>(&raw_packet.payload, client_version)
                        {
                            let mut chat_event = PlayerChatEvent {
                                uuid: player_uuid.to_string(),
                                username: username.to_string(),
                                message: chat_msg.message,
                                cancelled: false,
                            };
                            plugin_manager.fire_player_chat(&mut chat_event).await;
                            if chat_event.cancelled {
                                continue;
                            }
                        }

                        if PacketKind::ServerboundPluginMessage
                            .matches(raw_packet.id, client_version)
                            && let Ok(custom_payload) = decode_packet::<ServerboundPluginMessage>(
                                &raw_packet.payload,
                                client_version,
                            )
                        {
                            let mut msg_event = PluginMessageEvent {
                                channel: custom_payload.channel,
                                data: custom_payload.data,
                                player_uuid: Some(player_uuid.to_string()),
                                server_name: Some(current_server_name.clone()),
                                cancelled: false,
                            };
                            plugin_manager.fire_plugin_message(&mut msg_event).await;
                            if msg_event.cancelled {
                                continue;
                            }
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
                            if clean_cmd.contains(' ') && command_dispatcher.has_command(first_word)
                            {
                                let suggestions =
                                    command_dispatcher.suggest_with_range(clean_cmd, &source);
                                let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };
                                let response = CommandSuggestions {
                                    id: suggestion_req.id,
                                    start: (suggestions.range.start + offset) as i32,
                                    length: suggestions.range.len() as i32,
                                    matches: suggestions
                                        .suggestions
                                        .into_iter()
                                        .map(|s| Suggestion {
                                            text: s.text.cached_text().clone(),
                                            tooltip: s.tooltip,
                                        })
                                        .collect(),
                                };
                                if let Ok(bytes) = encode_packet(&response, client_version) {
                                    let _ = client_tx.send(bytes);
                                }
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
                                                        tooltip: tip.map(TextComponent::text),
                                                    })
                                                    .collect(),
                                            };
                                            if let Ok(bytes) =
                                                encode_packet(&response, client_version)
                                            {
                                                let _ = client_tx_clone.send(bytes);
                                            }
                                        }
                                    });
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
                    Ok(raw_packet) => {
                        if PacketKind::PlayDisconnect.matches(raw_packet.id, client_version) {
                            let reason = decode_packet::<PlayDisconnect>(
                                &raw_packet.payload,
                                client_version,
                            )
                            .map(|d| d.reason.to_pretty_console())
                            .ok()
                            .or_else(|| {
                                let s = String::from_utf8_lossy(&raw_packet.payload).to_string();
                                if s.is_empty() { None } else { Some(s) }
                            });
                            return TunnelExit::BackendDisconnected { reason };
                        }

                        if PacketKind::CommandSuggestionsResponse
                            .matches(raw_packet.id, client_version)
                            && let Ok(mut backend_suggestions) = decode_packet::<CommandSuggestions>(
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
                            );
                            if let Ok(bytes) = encode_packet(&backend_suggestions, client_version) {
                                if client_tx.send(bytes).is_err() {
                                    return TunnelExit::ClientDisconnected;
                                }
                                continue;
                            }
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
                            let permitted = command_dispatcher.get_all_permitted_commands(&source);
                            let injected: Vec<InjectedCommand<'_>> = permitted
                                .iter()
                                .map(|(name, _)| InjectedCommand {
                                    name: name.as_str(),
                                    takes_args: matches!(name.as_str(), "server" | "send" | "help"),
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
                                if client_tx.send(packet.to_bytes()).is_err() {
                                    return TunnelExit::ClientDisconnected;
                                }
                                continue;
                            }
                        }

                        if client_tx.send(raw_packet.to_bytes()).is_err() {
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
                    PlayerAction::Transfer { host, port } => {
                        return TunnelExit::Transfer { host, port };
                    }
                    PlayerAction::Message(content) => {
                        let chat_msg = SystemChat {
                            content,
                            overlay: false,
                        };
                        if let Ok(bytes) = encode_packet(&chat_msg, client_version) {
                            let _ = client_tx.send(bytes);
                        }
                    }
                    PlayerAction::Disconnect(reason) => {
                        let disconnect = PlayDisconnect {
                            reason: TextComponent::text(reason.clone()),
                        };
                        if let Ok(bytes) = encode_packet(&disconnect, client_version) {
                            let _ = client_tx.send(bytes);
                        }
                        return TunnelExit::BackendDisconnected {
                            reason: Some(reason),
                        };
                    }
                    PlayerAction::PluginMessage { channel, data } => {
                        let custom_payload = ClientboundPluginMessage { channel, data };
                        if let Ok(bytes) = encode_packet(&custom_payload, client_version) {
                            let _ = client_tx.send(bytes);
                        }
                    }
                }
            }
            TunnelExit::ClientDisconnected
        };

        let exit = tokio::select! {
            exit = client_to_backend => exit,
            exit = backend_to_client => exit,
            exit = action_loop => exit,
            exit = client_writer => exit,
        };

        Ok(exit)
    }
}

fn merge_suggestions(
    backend_matches: &mut Vec<Suggestion>,
    proxy_matches: Vec<(String, Option<String>)>,
) {
    for (cmd_name, tooltip) in proxy_matches {
        if !backend_matches
            .iter()
            .any(|bm| bm.text.eq_ignore_ascii_case(&cmd_name))
        {
            backend_matches.push(Suggestion {
                text: cmd_name,
                tooltip: tooltip.map(TextComponent::text),
            });
        }
    }
    backend_matches.sort_by(|a, b| a.text.cmp(&b.text));
}

#[cfg(test)]
mod tests {
    use super::*;

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
        );

        let names: Vec<&str> = backend_matches.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(names, ["send", "server", "status"]);
        assert!(backend_matches[1].tooltip.is_none());
    }
}
