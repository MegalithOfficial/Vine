use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::config::CConfigDisconnect;
use pumpkin_protocol::java::client::login::{
    CLoginDisconnect, CLoginPluginRequest, CLoginSuccess, CSetCompression,
};
use pumpkin_protocol::java::client::play::{
    ArgumentType, CCommandSuggestions, CCommands, CPlayDisconnect, CStartConfiguration,
    CSystemChatMessage, CTransfer, ProtoNode, ProtoNodeType, StringProtoArgBehavior,
    SuggestionProviders,
};
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::java::server::handshake::SHandShake;
use pumpkin_protocol::java::server::login::{SLoginPluginResponse, SLoginStart};
use pumpkin_protocol::java::server::play::{
    SChatCommand, SChatMessage, SCommandSuggestion, SCustomPayload,
};
use pumpkin_protocol::packet::MultiVersionJavaPacket;
use pumpkin_protocol::ser::{NetworkReadExt, NetworkReadSliceExt};
use pumpkin_protocol::{ClientPacket, ConnectionState, ServerPacket};
use pumpkin_util::text::TextComponent;
use pumpkin_util::version::JavaMinecraftVersion;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
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
use crate::security::PacketRateLimiter;
use crate::session::{PlayerAction, PlayerSession, SessionManager};

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Failed to connect to backend server '{0}': {1}")]
    ConnectFailed(String, std::io::Error),
    #[error("Backend communication error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Packet decode error: {0}")]
    DecodeError(String),
    #[error("Packet encode error: {0}")]
    EncodeError(String),
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

pub struct BackendBridge {
    server_name: String,
    config: BackendConfig,
    fallback_server: Option<(String, BackendConfig)>,
    client_ip: IpAddr,
    client_version: JavaMinecraftVersion,
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
        client_version: JavaMinecraftVersion,
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
    ) -> Result<
        (
            TCPNetworkDecoder<tokio::net::tcp::OwnedReadHalf>,
            TCPNetworkEncoder<tokio::net::tcp::OwnedWriteHalf>,
            Vec<u8>,
        ),
        BridgeError,
    > {
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
        let mut backend_decoder = TCPNetworkDecoder::new(backend_read);
        let mut backend_encoder = TCPNetworkEncoder::new(backend_write);

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

        let handshake_packet = SHandShake {
            protocol_version: VarInt(self.client_version.protocol_version()),
            server_address: backend_host.into_boxed_str(),
            server_port: 25565,
            next_state: ConnectionState::Login,
        };

        let handshake_bytes = handshake_packet
            .serialize_packet(&self.client_version)
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .write_packet(handshake_bytes)
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .flush()
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;

        let login_start_packet = SLoginStart {
            name: self.player.username.clone().into_boxed_str(),
            uuid: self.player.id,
        };
        let login_start_bytes = login_start_packet
            .serialize_packet(&self.client_version)
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .write_packet(login_start_bytes)
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .flush()
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;

        let login_timeout_dur = Duration::from_secs(self.network_config.backend_login_timeout_secs);
        let login_disconnect_id = CLoginDisconnect::to_id(self.client_version);
        let login_plugin_request_id = CLoginPluginRequest::to_id(self.client_version);
        let login_compression_id = CSetCompression::to_id(self.client_version);
        let login_success_id = CLoginSuccess::to_id(self.client_version);

        loop {
            let raw_packet = timeout(login_timeout_dur, backend_decoder.get_raw_packet())
                .await
                .map_err(|_| BridgeError::LoginTimeout(server_name.to_string()))?
                .map_err(|e| BridgeError::DecodeError(e.to_string()))?;

            if raw_packet.id == login_disconnect_id {
                let mut cur = &raw_packet.payload[..];
                let reason = cur
                    .get_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "Disconnected by backend during login".to_string());
                warn!(
                    "Backend '{}' disconnected '{}' during login: {}",
                    server_name, self.player.username, reason
                );
                return Err(BridgeError::LoginDisconnected(reason));
            } else if raw_packet.id == login_plugin_request_id {
                let mut cur = &raw_packet.payload[..];
                let message_id = cur
                    .get_var_int()
                    .map_err(|e| BridgeError::DecodeError(e.to_string()))?;
                let channel = cur
                    .get_str()
                    .map_err(|e| BridgeError::DecodeError(e.to_string()))?;

                debug!(
                    "Backend requested login plugin message on channel '{}'",
                    channel
                );

                if channel.as_ref() == VINE_PLAYER_INFO_CHANNEL {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VineError("Secret missing".to_string()))?;

                    let mut challenge = [0u8; 16];
                    if cur.len() >= 17 {
                        challenge.copy_from_slice(&cur[1..17]);
                    } else if cur.len() >= 16 {
                        challenge.copy_from_slice(&cur[0..16]);
                    }

                    let vine_data = ForwardingHelper::build_vine_payload(
                        secret,
                        &self.client_ip,
                        &self.player,
                        &challenge,
                    )
                    .map_err(|e| BridgeError::VineError(e.to_string()))?;

                    let plugin_response = SLoginPluginResponse {
                        message_id,
                        data: Some(vine_data.into_boxed_slice()),
                    };

                    let resp_bytes = plugin_response
                        .serialize_packet(&self.client_version)
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .write_packet(resp_bytes)
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .flush()
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                } else if channel.as_ref() == VELOCITY_PLAYER_INFO_CHANNEL {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VelocityError("Secret missing".to_string()))?;

                    let velocity_data = ForwardingHelper::build_velocity_payload(
                        secret,
                        &self.client_ip,
                        &self.player,
                    )
                    .map_err(|e| BridgeError::VelocityError(e.to_string()))?;

                    let plugin_response = SLoginPluginResponse {
                        message_id,
                        data: Some(velocity_data.into_boxed_slice()),
                    };

                    let resp_bytes = plugin_response
                        .serialize_packet(&self.client_version)
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .write_packet(resp_bytes)
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .flush()
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                } else {
                    let plugin_response = SLoginPluginResponse {
                        message_id,
                        data: None,
                    };
                    let resp_bytes = plugin_response
                        .serialize_packet(&self.client_version)
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .write_packet(resp_bytes)
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .flush()
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                }
            } else if raw_packet.id == login_compression_id {
                let mut cur = &raw_packet.payload[..];
                let threshold = cur
                    .get_var_int()
                    .map_err(|e| BridgeError::DecodeError(e.to_string()))?
                    .0;
                debug!("Backend enabled compression threshold: {} bytes", threshold);
                if threshold >= 0 {
                    backend_decoder.set_compression(threshold as usize);
                    backend_encoder
                        .set_compression((threshold as usize, self.compression_level as u32));
                }
            } else if raw_packet.id == login_success_id {
                debug!(
                    "Login successful on backend for '{}'!",
                    self.player.username
                );

                let mut full_packet = Vec::with_capacity(5 + raw_packet.payload.len());
                let _ = VarInt(raw_packet.id).encode(&mut full_packet);
                full_packet.extend_from_slice(&raw_packet.payload);
                return Ok((backend_decoder, backend_encoder, full_packet));
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
        mut client_decoder: TCPNetworkDecoder<R>,
        mut client_encoder: TCPNetworkEncoder<W>,
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

        let (mut backend_decoder, mut backend_encoder, success_bytes) = match self
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
        client_encoder
            .write_packet(success_bytes.into())
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        client_encoder
            .flush()
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;

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
            protocol_version: self.client_version.protocol_version() as u32,
        });

        loop {
            let tunnel_res = Self::bridge_tunnel(
                &self.player.username,
                &mut client_decoder,
                &mut client_encoder,
                &mut backend_decoder,
                &mut backend_encoder,
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
                    let transfer = CTransfer::new(&host, VarInt(port as i32));
                    if let Ok(bytes) = transfer.serialize_packet(&self.client_version) {
                        let _ = client_encoder.write_packet(bytes).await;
                        let _ = client_encoder.flush().await;
                    }
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
                        let chat_msg = CSystemChatMessage::new(&msg, false);
                        if let Ok(bytes) = chat_msg.serialize_packet(&self.client_version) {
                            let _ = client_encoder.write_packet(bytes).await;
                            let _ = client_encoder.flush().await;
                        }
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
                            let chat_msg = CSystemChatMessage::new(&msg, false);
                            if let Ok(bytes) = chat_msg.serialize_packet(&self.client_version) {
                                let _ = client_encoder.write_packet(bytes).await;
                                let _ = client_encoder.flush().await;
                            }
                            break;
                        }
                    };

                    match self.login_backend(&server_name, &target_config).await {
                        Ok((new_dec, new_enc, _)) => {
                            if self.client_version >= JavaMinecraftVersion::V_1_20_2
                                && let Ok(bytes) =
                                    CStartConfiguration.serialize_packet(&self.client_version)
                            {
                                let _ = client_encoder.write_packet(bytes).await;
                                let _ = client_encoder.flush().await;
                            }
                            backend_decoder = new_dec;
                            backend_encoder = new_enc;
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
                            let chat_msg = CSystemChatMessage::new(&msg, false);
                            if let Ok(bytes) = chat_msg.serialize_packet(&self.client_version) {
                                let _ = client_encoder.write_packet(bytes).await;
                                let _ = client_encoder.flush().await;
                            }

                            let can_fallback = self
                                .fallback_server
                                .as_ref()
                                .is_some_and(|(fb_name, _)| fb_name != &server_name);

                            if can_fallback {
                                let (fb_name, fb_cfg) = self.fallback_server.as_ref().unwrap();
                                match self.login_backend(fb_name, fb_cfg).await {
                                    Ok((new_dec, new_enc, _)) => {
                                        if self.client_version >= JavaMinecraftVersion::V_1_20_2
                                            && let Ok(bytes) = CStartConfiguration
                                                .serialize_packet(&self.client_version)
                                        {
                                            let _ = client_encoder.write_packet(bytes).await;
                                            let _ = client_encoder.flush().await;
                                        }
                                        backend_decoder = new_dec;
                                        backend_encoder = new_enc;
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
                                            &mut client_encoder,
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
                        let chat_msg = CSystemChatMessage::new(&notice, false);
                        if let Ok(bytes) = chat_msg.serialize_packet(&self.client_version) {
                            let _ = client_encoder.write_packet(bytes).await;
                            let _ = client_encoder.flush().await;
                        }

                        match self.login_backend(fb_name, fb_cfg).await {
                            Ok((new_dec, new_enc, _)) => {
                                if self.client_version >= JavaMinecraftVersion::V_1_20_2
                                    && let Ok(bytes) =
                                        CStartConfiguration.serialize_packet(&self.client_version)
                                {
                                    let _ = client_encoder.write_packet(bytes).await;
                                    let _ = client_encoder.flush().await;
                                }
                                backend_decoder = new_dec;
                                backend_encoder = new_enc;
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
                                    &mut client_encoder,
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
                            &mut client_encoder,
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
        encoder: &mut TCPNetworkEncoder<W>,
        version: JavaMinecraftVersion,
        is_config_state: bool,
        reason: &str,
    ) {
        if is_config_state {
            let json_reason = crate::client::kick_reason_json(reason);
            let pkt = CConfigDisconnect::new(&json_reason);
            if let Ok(bytes) = pkt.serialize_packet(&version) {
                let _ = encoder.write_packet(bytes).await;
                let _ = encoder.flush().await;
            }
        } else {
            let kick_reason = TextComponent::text(reason.to_string());
            let pkt = CPlayDisconnect::new(&kick_reason);
            if let Ok(bytes) = pkt.serialize_packet(&version) {
                let _ = encoder.write_packet(bytes).await;
                let _ = encoder.flush().await;
            }
        }
    }
}

#[derive(Clone)]
struct PendingSuggestion {
    clean_cmd: String,
    offset: usize,
    proxy_matches: Vec<(String, Option<String>)>,
}

fn decode_backend_suggestions(
    payload: &mut &[u8],
    version: &JavaMinecraftVersion,
) -> Result<
    (
        VarInt,
        VarInt,
        VarInt,
        Vec<pumpkin_protocol::java::client::play::CommandSuggestion>,
    ),
    (),
> {
    if *version >= JavaMinecraftVersion::V_1_13 {
        let id = payload.get_var_int().map_err(|_| ())?;
        let start = payload.get_var_int().map_err(|_| ())?;
        let length = payload.get_var_int().map_err(|_| ())?;
        let count = payload.get_var_int().map_err(|_| ())?.0;
        if !(0..=20000).contains(&count) {
            return Err(());
        }
        let mut matches = Vec::with_capacity((count as usize).min(1024));
        for _ in 0..count {
            let suggestion = payload.get_str().map_err(|_| ())?.to_string();
            let has_tooltip = payload.get_bool().map_err(|_| ())?;
            let tooltip = if has_tooltip {
                payload.get_component(version).ok()
            } else {
                None
            };
            matches.push(pumpkin_protocol::java::client::play::CommandSuggestion {
                suggestion,
                tooltip,
            });
        }
        Ok((id, start, length, matches))
    } else {
        Err(())
    }
}

fn inject_proxy_commands(
    payload: &[u8],
    client_version: &JavaMinecraftVersion,
    permitted_commands: &[(&str, &str)],
) -> Option<Vec<u8>> {
    if *client_version < JavaMinecraftVersion::V_1_13 || permitted_commands.is_empty() {
        return None;
    }

    if payload.last() != Some(&0) {
        return None;
    }

    let mut cur = payload;
    let node_count = cur.get_var_int().ok()?.0;
    if node_count <= 0 {
        return None;
    }

    let flags = cur.get_u8().ok()?;
    if flags != 0 {
        return None;
    }

    let children_count = cur.get_var_int().ok()?.0;
    if children_count < 0 {
        return None;
    }

    let mut original_children = Vec::with_capacity(children_count as usize);
    for _ in 0..children_count {
        let child = cur.get_var_int().ok()?;
        original_children.push(child);
    }

    if cur.is_empty() {
        return None;
    }

    let nodes1_to_end = &cur[..cur.len() - 1];

    let base_index = node_count as usize;
    let mut next_node_idx = base_index;
    let mut new_root_children = Vec::new();
    let mut extra_nodes_buf = Vec::new();

    for (cmd_name, _) in permitted_commands {
        let takes_args = matches!(*cmd_name, "server" | "send" | "help");
        if takes_args {
            let lit_node = ProtoNode {
                children: vec![VarInt((next_node_idx + 1) as i32)].into_boxed_slice(),
                node_type: ProtoNodeType::Literal {
                    name: cmd_name,
                    is_executable: *cmd_name != "send",
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
                .write_to(&mut extra_nodes_buf, client_version)
                .ok()?;
            arg_node
                .write_to(&mut extra_nodes_buf, client_version)
                .ok()?;

            new_root_children.push(VarInt(next_node_idx as i32));
            next_node_idx += 2;
        } else {
            let lit_node = ProtoNode {
                children: Vec::new().into_boxed_slice(),
                node_type: ProtoNodeType::Literal {
                    name: cmd_name,
                    is_executable: true,
                    redirect_target: None,
                    restricted: false,
                },
            };

            lit_node
                .write_to(&mut extra_nodes_buf, client_version)
                .ok()?;

            new_root_children.push(VarInt(next_node_idx as i32));
            next_node_idx += 1;
        }
    }

    let total_nodes = next_node_idx as i32;
    let total_root_children = original_children.len() + new_root_children.len();

    let mut new_payload = Vec::with_capacity(payload.len() + extra_nodes_buf.len() + 64);
    let _ = VarInt(total_nodes).encode(&mut new_payload);
    new_payload.push(0x00);
    let _ = VarInt(total_root_children as i32).encode(&mut new_payload);
    for child in original_children {
        let _ = child.encode(&mut new_payload);
    }
    for child in new_root_children {
        let _ = child.encode(&mut new_payload);
    }
    new_payload.extend_from_slice(nodes1_to_end);
    new_payload.extend_from_slice(&extra_nodes_buf);
    new_payload.push(0x00);

    Some(new_payload)
}

impl BackendBridge {
    /// Tunnels packets back and forth between client and backend
    #[allow(clippy::too_many_arguments)]
    async fn bridge_tunnel<R1, W1, R2, W2>(
        username: &str,
        client_decoder: &mut TCPNetworkDecoder<R1>,
        client_encoder: &mut TCPNetworkEncoder<W1>,
        backend_decoder: &mut TCPNetworkDecoder<R2>,
        backend_encoder: &mut TCPNetworkEncoder<W2>,
        max_packets_per_sec: u32,
        client_version: JavaMinecraftVersion,
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
        let chat_command_id = SChatCommand::to_id(client_version);
        let chat_message_id = SChatMessage::to_id(client_version);
        let custom_payload_id = SCustomPayload::to_id(client_version);
        let command_suggestion_id = SCommandSuggestion::to_id(client_version);
        let command_suggestions_clientbound_id = CCommandSuggestions::to_id(client_version);
        let commands_packet_id = CCommands::to_id(client_version);
        let play_disconnect_id = CPlayDisconnect::to_id(client_version);

        let pending_suggestions: Arc<
            tokio::sync::Mutex<std::collections::HashMap<i32, PendingSuggestion>>,
        > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let (client_tx, mut client_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

        let client_writer = async {
            while let Some(packet_bytes) = client_rx.recv().await {
                if let Err(e) = client_encoder.write_packet(packet_bytes).await {
                    debug!("Client write failed for '{}': {:?}", username, e);
                    return TunnelExit::ClientDisconnected;
                }
                if let Err(e) = client_encoder.flush().await {
                    debug!("Client flush failed for '{}': {:?}", username, e);
                    return TunnelExit::ClientDisconnected;
                }
            }
            TunnelExit::ClientDisconnected
        };

        let client_to_backend = async {
            loop {
                match client_decoder.get_raw_packet().await {
                    Ok(raw_packet) => {
                        if !client_rate_limiter.record_packet() {
                            warn!(
                                "Player '{}' exceeded packet rate limit (flood protection kicked in)",
                                username
                            );
                            return TunnelExit::ClientDisconnected;
                        }

                        if raw_packet.id == chat_command_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(chat_cmd) = SChatCommand::read(&mut payload, &client_version)
                            {
                                let cmd_text = chat_cmd.command;
                                let mut cmd_event = PlayerCommandEvent {
                                    uuid: player_uuid.to_string(),
                                    username: username.to_string(),
                                    command: cmd_text.to_string(),
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
                        }

                        if raw_packet.id == chat_message_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(chat_msg) = SChatMessage::read(&mut payload, &client_version)
                            {
                                let mut chat_event = PlayerChatEvent {
                                    uuid: player_uuid.to_string(),
                                    username: username.to_string(),
                                    message: chat_msg.message.to_string(),
                                    cancelled: false,
                                };
                                plugin_manager.fire_player_chat(&mut chat_event).await;
                                if chat_event.cancelled {
                                    continue;
                                }
                            }
                        }

                        if raw_packet.id == custom_payload_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(custom_payload) =
                                SCustomPayload::read(&mut payload, &client_version)
                            {
                                let mut msg_event = PluginMessageEvent {
                                    channel: custom_payload.channel.to_string(),
                                    data: custom_payload.data.to_vec(),
                                    player_uuid: Some(player_uuid.to_string()),
                                    server_name: Some(current_server_name.clone()),
                                    cancelled: false,
                                };
                                plugin_manager.fire_plugin_message(&mut msg_event).await;
                                if msg_event.cancelled {
                                    continue;
                                }
                            }
                        }

                        if raw_packet.id == command_suggestion_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(suggestion_req) =
                                SCommandSuggestion::read(&mut payload, &client_version)
                            {
                                let raw_cmd = &suggestion_req.command;
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
                                    && command_dispatcher.has_command(first_word)
                                {
                                    let suggestions =
                                        command_dispatcher.suggest_with_range(clean_cmd, &source);
                                    let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };
                                    let matches: Box<[pumpkin_protocol::java::client::play::CommandSuggestion]> = suggestions
                                        .suggestions
                                        .into_iter()
                                        .map(|s| pumpkin_protocol::java::client::play::CommandSuggestion {
                                            suggestion: s.text.cached_text().clone(),
                                            tooltip: s.tooltip,
                                        })
                                        .collect();
                                    let resp = CCommandSuggestions::new(
                                        suggestion_req.id,
                                        VarInt((suggestions.range.start + offset) as i32),
                                        VarInt(suggestions.range.len() as i32),
                                        matches,
                                    );
                                    if let Ok(bytes) = resp.serialize_packet(&client_version) {
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
                                        let req_id = suggestion_req.id.0;

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
                                        let cv = client_version;
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(200)).await;
                                            if let Some(pending) =
                                                pending_ref.lock().await.remove(&req_id)
                                            {
                                                let suggestions: Vec<pumpkin_protocol::java::client::play::CommandSuggestion> = pending
                                                    .proxy_matches
                                                    .into_iter()
                                                    .map(|(cmd, tip)| pumpkin_protocol::java::client::play::CommandSuggestion {
                                                        suggestion: cmd,
                                                        tooltip: tip.map(TextComponent::text),
                                                    })
                                                    .collect();
                                                let resp = CCommandSuggestions::new(
                                                    VarInt(req_id),
                                                    VarInt(pending.offset as i32),
                                                    VarInt(pending.clean_cmd.len() as i32),
                                                    suggestions.into_boxed_slice(),
                                                );
                                                if let Ok(bytes) = resp.serialize_packet(&cv) {
                                                    let _ = client_tx_clone.send(bytes);
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }

                        let mut full_packet = Vec::with_capacity(5 + raw_packet.payload.len());
                        let _ = VarInt(raw_packet.id).encode(&mut full_packet);
                        full_packet.extend_from_slice(&raw_packet.payload);

                        if let Err(e) = backend_encoder.write_packet(full_packet.into()).await {
                            debug!("Backend write failed for '{}': {:?}", username, e);
                            return TunnelExit::BackendDisconnected { reason: None };
                        }
                        if let Err(e) = backend_encoder.flush().await {
                            debug!("Backend flush failed for '{}': {:?}", username, e);
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
                match backend_decoder.get_raw_packet().await {
                    Ok(raw_packet) => {
                        if raw_packet.id == play_disconnect_id {
                            let mut cur = &raw_packet.payload[..];
                            let reason = cur
                                .get_component(&client_version)
                                .map(|c| c.to_pretty_console())
                                .ok()
                                .or_else(|| {
                                    let s =
                                        String::from_utf8_lossy(&raw_packet.payload).to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                });
                            return TunnelExit::BackendDisconnected { reason };
                        }

                        if raw_packet.id == command_suggestions_clientbound_id {
                            let mut cur = &raw_packet.payload[..];
                            if let Ok((id, start, length, mut backend_matches)) =
                                decode_backend_suggestions(&mut cur, &client_version)
                                && let Some(pending) =
                                    pending_suggestions.lock().await.remove(&id.0)
                            {
                                for (cmd_name, tooltip) in pending.proxy_matches {
                                    if !backend_matches
                                        .iter()
                                        .any(|bm| bm.suggestion.eq_ignore_ascii_case(&cmd_name))
                                    {
                                        backend_matches.push(pumpkin_protocol::java::client::play::CommandSuggestion {
                                            suggestion: cmd_name,
                                            tooltip: tooltip.map(TextComponent::text),
                                        });
                                    }
                                }
                                backend_matches.sort_by(|a, b| a.suggestion.cmp(&b.suggestion));

                                let merged = CCommandSuggestions::new(
                                    id,
                                    start,
                                    length,
                                    backend_matches.into_boxed_slice(),
                                );
                                if let Ok(bytes) = merged.serialize_packet(&client_version) {
                                    if client_tx.send(bytes).is_err() {
                                        return TunnelExit::ClientDisconnected;
                                    }
                                    continue;
                                }
                            }
                        }

                        if raw_packet.id == commands_packet_id {
                            let source = ProxyCommandSource {
                                sender: CommandSender::Player {
                                    username: username.to_string(),
                                    action_tx: action_tx.clone(),
                                },
                                config: proxy_config.clone(),
                                session_manager: session_manager.clone(),
                            };
                            let permitted = command_dispatcher.get_all_permitted_commands(&source);
                            let permitted_refs: Vec<(&str, &str)> = permitted
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();

                            if let Some(modified_payload) = inject_proxy_commands(
                                &raw_packet.payload,
                                &client_version,
                                &permitted_refs,
                            ) {
                                let mut full_packet =
                                    Vec::with_capacity(5 + modified_payload.len());
                                let _ = VarInt(raw_packet.id).encode(&mut full_packet);
                                full_packet.extend_from_slice(&modified_payload);

                                if client_tx.send(full_packet.into()).is_err() {
                                    return TunnelExit::ClientDisconnected;
                                }
                                continue;
                            }
                        }

                        let mut full_packet = Vec::with_capacity(5 + raw_packet.payload.len());
                        let _ = VarInt(raw_packet.id).encode(&mut full_packet);
                        full_packet.extend_from_slice(&raw_packet.payload);

                        if client_tx.send(full_packet.into()).is_err() {
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
                    PlayerAction::Message(text_comp) => {
                        let chat_msg = CSystemChatMessage::new(&text_comp, false);
                        if let Ok(bytes) = chat_msg.serialize_packet(&client_version) {
                            let _ = client_tx.send(bytes);
                        }
                    }
                    PlayerAction::Disconnect(reason) => {
                        let text = TextComponent::text(reason.clone());
                        let disconnect_pkt = CPlayDisconnect::new(&text);
                        if let Ok(bytes) = disconnect_pkt.serialize_packet(&client_version) {
                            let _ = client_tx.send(bytes);
                        }
                        return TunnelExit::BackendDisconnected {
                            reason: Some(reason),
                        };
                    }
                    PlayerAction::PluginMessage { channel, data } => {
                        let custom_payload =
                            pumpkin_protocol::java::client::play::CCustomPayload::new(
                                &channel, &data,
                            );
                        if let Ok(bytes) = custom_payload.serialize_packet(&client_version) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use pumpkin_protocol::java::client::play::CommandSuggestion;

    #[test]
    fn test_decode_backend_suggestions() {
        let version = JavaMinecraftVersion::V_1_21_4;
        let pkt = CCommandSuggestions::new(
            VarInt(42),
            VarInt(1),
            VarInt(3),
            vec![
                CommandSuggestion {
                    suggestion: "say".to_string(),
                    tooltip: Some(TextComponent::text("broadcast message")),
                },
                CommandSuggestion {
                    suggestion: "spawnpoint".to_string(),
                    tooltip: None,
                },
            ]
            .into_boxed_slice(),
        );

        let bytes = pkt
            .serialize_packet(&version)
            .expect("serialization failed");
        let mut slice = &bytes[..];
        let _pkt_id = slice.get_var_int().expect("packet id read failed");

        let (id, start, length, matches) =
            decode_backend_suggestions(&mut slice, &version).expect("decode failed");

        assert_eq!(id.0, 42);
        assert_eq!(start.0, 1);
        assert_eq!(length.0, 3);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].suggestion, "say");
        assert!(matches[0].tooltip.is_some());
        assert_eq!(matches[1].suggestion, "spawnpoint");
        assert!(matches[1].tooltip.is_none());
    }

    #[test]
    fn test_merge_pending_proxy_and_backend_suggestions() {
        let version = JavaMinecraftVersion::V_1_21_4;
        let mut backend_matches = vec![
            CommandSuggestion {
                suggestion: "server".to_string(), // duplicate name with proxy
                tooltip: None,
            },
            CommandSuggestion {
                suggestion: "status".to_string(),
                tooltip: None,
            },
        ];

        let pending_proxy_matches = vec![
            (
                "server".to_string(),
                Some("Switch or view backend server".to_string()),
            ),
            (
                "send".to_string(),
                Some("Send players to a backend".to_string()),
            ),
        ];

        // Deduplicate and merge proxy matches into backend matches
        for (cmd_name, tooltip) in pending_proxy_matches {
            if !backend_matches
                .iter()
                .any(|bm| bm.suggestion.eq_ignore_ascii_case(&cmd_name))
            {
                backend_matches.push(CommandSuggestion {
                    suggestion: cmd_name,
                    tooltip: tooltip.map(TextComponent::text),
                });
            }
        }
        backend_matches.sort_by(|a, b| a.suggestion.cmp(&b.suggestion));

        assert_eq!(backend_matches.len(), 3);
        assert_eq!(backend_matches[0].suggestion, "send");
        assert_eq!(backend_matches[1].suggestion, "server");
        assert_eq!(backend_matches[2].suggestion, "status");

        let merged = CCommandSuggestions::new(
            VarInt(10),
            VarInt(1),
            VarInt(1),
            backend_matches.into_boxed_slice(),
        );
        let serialized = merged.serialize_packet(&version);
        assert!(serialized.is_ok());
    }

    #[test]
    fn test_inject_proxy_commands() {
        let version = JavaMinecraftVersion::V_1_21_4;
        let root_node = ProtoNode {
            children: vec![VarInt(1)].into_boxed_slice(),
            node_type: ProtoNodeType::Root,
        };
        let say_node = ProtoNode {
            children: Vec::new().into_boxed_slice(),
            node_type: ProtoNodeType::Literal {
                name: "say",
                is_executable: true,
                redirect_target: None,
                restricted: false,
            },
        };
        let pkt = CCommands::new(vec![root_node, say_node].into_boxed_slice(), VarInt(0));
        let bytes = pkt.serialize_packet(&version).expect("serialize commands");
        let mut slice = &bytes[..];
        let _pkt_id = slice.get_var_int().expect("read pkt id");

        let permitted = [("server", "desc"), ("list", "desc")];
        let injected = inject_proxy_commands(slice, &version, &permitted)
            .expect("inject_proxy_commands failed");

        let mut cur = &injected[..];
        let total_nodes = cur.get_var_int().unwrap();
        // Original: 2 (root, say). Added: server (literal + args: 2), list (literal: 1). Total: 5.
        assert_eq!(total_nodes.0, 5);

        let root_flags = cur.get_u8().unwrap();
        assert_eq!(root_flags, 0); // Root node flag

        let root_children_count = cur.get_var_int().unwrap();
        // Original 1 (say) + 2 new root commands (server, list) = 3
        assert_eq!(root_children_count.0, 3);

        let c1 = cur.get_var_int().unwrap();
        assert_eq!(c1.0, 1); // say
        let c2 = cur.get_var_int().unwrap();
        assert_eq!(c2.0, 2); // server
        let c3 = cur.get_var_int().unwrap();
        assert_eq!(c3.0, 4); // list (index 2 is server literal, 3 is server args, 4 is list literal)

        // The packet must end with VarInt(0) for root_node_index
        assert_eq!(injected.last(), Some(&0));
    }
}
