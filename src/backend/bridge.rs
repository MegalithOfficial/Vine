use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pumpkin_util::text::TextComponent;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
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
    #[error(
        "Backend server '{0}' is in online mode; set online-mode=false on it and use player info forwarding"
    )]
    OnlineMode(String),
    #[error("Velocity forwarding error: {0}")]
    VelocityError(String),
    #[error("Vine forwarding error: {0}")]
    VineError(String),
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
        action_rx: mpsc::Receiver<PlayerAction>,
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

        let bridge = Arc::new(self);
        let (client_out, client_rx) = ClientQueue::new();
        let writer = Task::spawn(write_client(
            client_writer,
            client_rx,
            client_out.budget.clone(),
            bridge.player.username.clone(),
        ));
        let session = Arc::new(Session {
            username: bridge.player.username.clone(),
            uuid: bridge.player.id,
            version: bridge.client_version,
            plugin_manager: bridge.plugin_manager.clone(),
            session_manager: bridge.session_manager.clone(),
            command_dispatcher: bridge.command_dispatcher.clone(),
            proxy_config: bridge.proxy_config.clone(),
            action_tx,
            client_out: client_out.clone(),
        });
        let (served, served_rx) = watch::channel(Served {
            generation: 0,
            name: current_server_name.clone(),
        });
        let (client_events_tx, client_events) = mpsc::channel(CLIENT_EVENTS);
        let client_reader = Task::spawn(read_client(
            session.clone(),
            client_reader,
            PacketRateLimiter::new(bridge.max_packets_per_sec),
            served_rx,
            client_events_tx,
        ));
        let link = if bridge.client_version >= ProtocolVersion::V1_20_2 {
            Link::Login
        } else {
            Link::Play
        };
        let backend = Backend::start(
            &session,
            backend_reader,
            backend_writer,
            current_server_name,
            // A backend sends configuration right after its LoginSuccess
            match link {
                Link::Login => Phase::Config,
                _ => Phase::Play,
            },
            Vec::new(),
        );
        let mut tunnel = Tunnel {
            bridge: bridge.clone(),
            session,
            link,
            switch: Switch::Idle,
            backend,
            keep_alive: None,
            leftovers: Leftovers::default(),
            client_settings: ClientSettings::default(),
            suggesting: Suggesting::default(),
            client_out,
            client_events,
            actions: action_rx,
            message: None,
            stalled: None,
            served,
            stale_before: 0,
            plugin_events: None,
            _client_reader: client_reader,
        };

        match tunnel.run().await {
            End::Kicked(reason) => {
                info!("Kicking player '{}': {}", bridge.player.username, reason);
                tunnel.disconnect_client(writer, &reason).await;
            }
            End::Closed => debug!(
                "Player '{}' disconnected from client side",
                bridge.player.username
            ),
        }
        let last_server = tunnel.backend.name.clone();
        let plugin_events = tunnel.plugin_events.take();
        drop(tunnel);
        if let Some(events) = plugin_events {
            let _ = events.await;
        }
        bridge.fire_disconnect(Some(last_server)).await;

        bridge.online_players.fetch_sub(1, Ordering::Relaxed);
        info!(
            "Player '{}' disconnected from proxy. Online players: {}",
            bridge.player.username,
            bridge.online_players.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Tells plugins about a switch the player asked for, then logs into its target
    async fn switch_job(self: Arc<Self>, current: String, target: String) -> Connected {
        let mut event = ServerConnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            current_server: Some(current.clone()),
            target_server: target,
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager.fire_server_connect(&mut event).await;
        if event.cancelled {
            return Connected::Cancelled(event.cancel_reason);
        }
        let target = event.target_server;
        if target == current {
            return Connected::AlreadyThere(target);
        }
        let Some(config) = self.proxy_config.servers.get(&target).cloned() else {
            return Connected::Unknown(target);
        };
        let prepared = self.prepare_backend(&target, &config).await;
        Connected::Prepared(target, prepared)
    }

    /// Plugins see a move to the fallback server like any other; with the old backend gone a
    /// cancelled one ends the session, and a different target must be a configured server
    async fn fallback_job(
        self: Arc<Self>,
        current: String,
        target: String,
        config: BackendConfig,
    ) -> Connected {
        let mut event = ServerConnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            current_server: Some(current),
            target_server: target.clone(),
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager.fire_server_connect(&mut event).await;
        if event.cancelled {
            return Connected::Cancelled(event.cancel_reason);
        }
        let (target, config) = match self.proxy_config.servers.get(&event.target_server) {
            Some(cfg) if event.target_server != target => (event.target_server, cfg.clone()),
            _ => (target, config),
        };
        let prepared = self.prepare_backend(&target, &config).await;
        Connected::Prepared(target, prepared)
    }

    async fn prepare_job(self: Arc<Self>, target: String, config: BackendConfig) -> Connected {
        let prepared = self.prepare_backend(&target, &config).await;
        Connected::Prepared(target, prepared)
    }

    /// Logs in to the next backend without touching the client, so the current one keeps running
    async fn prepare_backend(
        &self,
        server_name: &str,
        config: &BackendConfig,
    ) -> Result<Box<PreparedBackend>, BridgeError> {
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
        Ok(Box::new(PreparedBackend {
            reader,
            writer,
            join_game,
        }))
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
}

/// Where the client is in the connection's phases
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Login,
    Config,
    Play,
    // The backend asked the client to reconfigure and the client has not acknowledged yet, so what
    // reaches the client is read as configuration while what it sends is still play
    Reconfiguring,
}

impl Link {
    /// The phase the client reads what is queued for it next in
    fn clientbound(self) -> Phase {
        match self {
            Link::Login => Phase::Login,
            Link::Config | Link::Reconfiguring => Phase::Config,
            Link::Play => Phase::Play,
        }
    }
}

/// A move to another backend, from being asked for to the client being handed over
enum Switch {
    Idle,
    /// Asked for while the client is not playing; started once it is
    Deferred {
        target: String,
    },
    /// Plugins are told and the next backend is logged into while the current one keeps running
    Connecting {
        target: String,
        job: Job,
    },
    /// The next backend finished logging in while the client was not playing
    Held {
        target: String,
        prepared: Box<PreparedBackend>,
        since: Instant,
    },
    /// The current backend's reader is let finish the packet in hand
    Stopping {
        target: String,
        prepared: Box<PreparedBackend>,
    },
    /// On 1.20.2+ the client is sent back into configuration so the next backend can configure
    /// it from scratch; packets it sends before acknowledging still go to the current backend
    AwaitingAck {
        target: String,
        prepared: Box<PreparedBackend>,
        clock: AckClock,
    },
    /// The current backend is gone and the player is moved to the fallback server
    Fallback {
        reason: String,
        job: Job,
    },
}

enum AckClock {
    // The client's wait for its acknowledgement starts once it has the request
    Writing(oneshot::Receiver<()>),
    Until(tokio::time::Instant),
}

/// What a connect job ends with
enum Connected {
    Cancelled(Option<String>),
    AlreadyThere(String),
    Unknown(String),
    Prepared(String, Result<Box<PreparedBackend>, BridgeError>),
}

/// Work on a task of its own, so the tunnel keeps running meanwhile; dropped, it is stopped
struct Job {
    result: oneshot::Receiver<Connected>,
    _task: Task,
}

impl Job {
    fn spawn(work: impl Future<Output = Connected> + Send + 'static) -> Self {
        let (done, result) = oneshot::channel();
        let task = Task::spawn(async move {
            let _ = done.send(work.await);
        });
        Self {
            result,
            _task: task,
        }
    }
}

enum SwitchEvent {
    Connected(Option<Connected>),
    Written,
    AckTimedOut,
}

async fn switch_progress(switch: &mut Switch) -> SwitchEvent {
    match switch {
        Switch::Connecting { job, .. } | Switch::Fallback { job, .. } => {
            SwitchEvent::Connected((&mut job.result).await.ok())
        }
        Switch::AwaitingAck {
            clock: AckClock::Writing(written),
            ..
        } => {
            let _ = written.await;
            SwitchEvent::Written
        }
        Switch::AwaitingAck {
            clock: AckClock::Until(deadline),
            ..
        } => {
            tokio::time::sleep_until(*deadline).await;
            SwitchEvent::AckTimedOut
        }
        _ => std::future::pending().await,
    }
}

/// The backend the client's packets go to, and which generation of the session's backends it is
#[derive(Clone)]
struct Served {
    generation: u64,
    name: String,
}

enum End {
    Closed,
    Kicked(String),
}

enum Event {
    ClientGone,
    Client(Option<ClientEvent>),
    BackendRoom(Option<mpsc::OwnedPermit<Bytes>>),
    Backend(Option<BackendEvent>),
    Action(Option<PlayerAction>),
    MessageRoom(Option<OwnedSemaphorePermit>),
    Switch(SwitchEvent),
    Suggestion(SuggestionEvent),
}

/// A proxy message waiting for room in the client queue
struct HeldMessage {
    bytes: Bytes,
    room: Room,
}

type Room = std::pin::Pin<
    Box<
        dyn Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>>
            + Send
            + Sync
            + 'static,
    >,
>;

async fn message_room(message: &mut Option<HeldMessage>) -> Option<OwnedSemaphorePermit> {
    match message {
        Some(held) => held.room.as_mut().await.ok(),
        None => std::future::pending().await,
    }
}

async fn backend_room(writes: Option<mpsc::Sender<Bytes>>) -> Option<mpsc::OwnedPermit<Bytes>> {
    match writes {
        Some(writes) => writes.reserve_owned().await.ok(),
        None => std::future::pending().await,
    }
}

/// One player's session after the first backend took them. Everything about it is decided here,
/// one event at a time; the readers, writers and connect jobs around it only report to it.
struct Tunnel {
    bridge: Arc<BackendBridge>,
    session: Arc<Session>,
    link: Link,
    switch: Switch,
    backend: Backend,
    // Keep-alive replies meant for a previous backend would make the current one kick the
    // player, so only replies to the current backend's latest challenge are forwarded
    keep_alive: Option<i64>,
    leftovers: Leftovers,
    client_settings: ClientSettings,
    suggesting: Suggesting,
    client_out: ClientQueue,
    client_events: mpsc::Receiver<ClientEvent>,
    actions: mpsc::Receiver<PlayerAction>,
    message: Option<HeldMessage>,
    // A client packet waiting for room in the backend's queue; the client is not read meanwhile
    stalled: Option<Bytes>,
    // The backend the client's packets go to; changing it drops answers worked out for the last one
    served: watch::Sender<Served>,
    // Configuration packets the client sent while an earlier backend was current are not passed on
    stale_before: u64,
    // Plugins hear about connections in order, without holding up the tunnel
    plugin_events: Option<tokio::task::JoinHandle<()>>,
    _client_reader: Task,
}

impl Tunnel {
    async fn run(&mut self) -> End {
        loop {
            let event = self.next().await;
            if let Err(end) = self.handle(event) {
                return end;
            }
        }
    }

    async fn next(&mut self) -> Event {
        let takes_client = self.takes_client();
        let held = self.message.is_some();
        let stalled = match (&self.backend.conn, &self.stalled) {
            (Conn::Open(open), Some(_)) => Some(open.writes.clone()),
            _ => None,
        };
        tokio::select! {
            () = self.client_out.closed() => Event::ClientGone,
            event = self.client_events.recv(), if takes_client => Event::Client(event),
            permit = backend_room(stalled) => Event::BackendRoom(permit),
            event = self.backend.next_event() => Event::Backend(event),
            action = self.actions.recv(), if !held => Event::Action(action),
            permit = message_room(&mut self.message) => Event::MessageRoom(permit),
            event = switch_progress(&mut self.switch) => Event::Switch(event),
            event = self.suggesting.progress() => Event::Suggestion(event),
        }
    }

    fn takes_client(&self) -> bool {
        self.stalled.is_none()
            && match self.switch {
                Switch::Stopping { .. } => false,
                Switch::AwaitingAck { .. } => true,
                // With the backend gone, what the client sends waits for the next one
                _ => matches!(self.backend.conn, Conn::Open(_)),
            }
    }

    fn handle(&mut self, event: Event) -> Result<(), End> {
        match event {
            Event::ClientGone | Event::Client(None) | Event::Action(None) => Err(End::Closed),
            Event::Client(Some(event)) => self.client_event(event),
            Event::BackendRoom(permit) => match (permit, self.stalled.take()) {
                (Some(permit), Some(packet)) => {
                    permit.send(packet);
                    Ok(())
                }
                (None, _) => self.backend_lost(None),
                (Some(_), None) => Ok(()),
            },
            Event::Backend(Some(BackendEvent::Packet {
                packet,
                permit,
                done,
            })) => {
                self.backend_packet(packet, permit);
                let _ = done.send(());
                Ok(())
            }
            Event::Backend(Some(BackendEvent::Lost { reason })) => self.backend_lost(reason),
            Event::Backend(Some(BackendEvent::ClientGone)) => Err(End::Closed),
            Event::Backend(None) => self.backend_stopped(),
            Event::Action(Some(action)) => self.action(action),
            Event::MessageRoom(permit) => {
                if let (Some(held), Some(permit)) = (self.message.take(), permit) {
                    self.send_play(held.bytes, Some(permit));
                }
                Ok(())
            }
            Event::Switch(event) => self.switch_event(event),
            Event::Suggestion(event) => {
                self.suggestion_event(event);
                Ok(())
            }
        }
    }

    fn generation(&self) -> u64 {
        self.served.borrow().generation
    }

    fn locale(&self) -> Option<String> {
        self.bridge.locale()
    }

    fn translate(&self, key: &str, args: &[&(dyn std::fmt::Display + Sync)]) -> String {
        translate(self.locale().as_deref(), key, args)
    }

    /// Every packet of the proxy's own for a playing client goes through here
    fn send_play(&self, bytes: Bytes, permit: Option<OwnedSemaphorePermit>) {
        if self.link == Link::Play {
            self.client_out.push(bytes, permit);
        } else {
            debug!(
                "Dropping a message for '{}' outside play",
                self.session.username
            );
        }
    }

    fn notify(&self, text: String) {
        let version = self.session.version;
        let message = SystemChat {
            content: component_json(&parse_message(&text), version),
            overlay: false,
        };
        match encode_packet(&message, version) {
            Ok(bytes) => self.send_play(bytes, None),
            Err(e) => debug!("Skipping a notice for {}: {}", version, e),
        }
    }

    fn client_event(&mut self, event: ClientEvent) -> Result<(), End> {
        match event {
            ClientEvent::Packet {
                packet,
                entered,
                setting,
                completion,
                served,
            } => {
                if let Some(setting) = setting {
                    self.client_settings.apply(setting);
                }
                if let Some(completion) = completion {
                    self.suggesting.expect(completion, served);
                }
                let sent_in = self.link;
                if let Some(next) = entered {
                    self.link = match next {
                        Phase::Login => Link::Login,
                        Phase::Config => Link::Config,
                        Phase::Play => Link::Play,
                    };
                }
                if entered == Some(Phase::Config)
                    && matches!(self.switch, Switch::AwaitingAck { .. })
                {
                    return self.acknowledged();
                }
                if sent_in == Link::Config && served < self.stale_before {
                    debug!(
                        "Dropping a configuration packet from '{}' meant for a previous backend",
                        self.session.username
                    );
                } else {
                    self.forward(packet)?;
                }
                if entered == Some(Phase::Play) {
                    return self.reached_play();
                }
                Ok(())
            }
            ClientEvent::KeepAliveResponse { id, packet } => {
                if self.keep_alive == Some(id) {
                    self.forward(packet)
                } else {
                    debug!(
                        "Dropping stale keep-alive {} from '{}'",
                        id, self.session.username
                    );
                    Ok(())
                }
            }
            ClientEvent::Suggest { request, served } => {
                self.suggesting.ask(&self.session, request, served);
                Ok(())
            }
            // The backend being left would have seen the packet; a kick over it is moot
            ClientEvent::Kick(_) if matches!(self.switch, Switch::AwaitingAck { .. }) => Ok(()),
            ClientEvent::Kick(reason) => Err(End::Kicked(reason)),
            ClientEvent::Closed => Err(End::Closed),
        }
    }

    /// Passes a client packet on to the current backend
    fn forward(&mut self, packet: Bytes) -> Result<(), End> {
        let Conn::Open(open) = &self.backend.conn else {
            return Ok(());
        };
        let leaving = matches!(self.switch, Switch::AwaitingAck { .. });
        match open.writes.try_send(packet) {
            Ok(()) => Ok(()),
            Err(_) if leaving => Ok(()),
            Err(mpsc::error::TrySendError::Full(packet)) => {
                self.stalled = Some(packet);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => self.backend_lost(None),
        }
    }

    /// A packet from the backend whose effect on the session is decided here before it is queued
    fn backend_packet(&mut self, packet: crate::protocol::RawPacket, permit: OwnedSemaphorePermit) {
        let version = self.session.version;
        let mut replaced = None;
        if PacketKind::StartConfiguration.matches(packet.id, version) {
            if self.link == Link::Play {
                self.link = Link::Reconfiguring;
            }
        } else if PacketKind::PlayKeepAlive.matches(packet.id, version) {
            if let Ok(challenge) = decode_packet::<PlayKeepAlive>(&packet.payload, version) {
                self.keep_alive = Some(challenge.id);
            }
        } else if PacketKind::CommandSuggestionsResponse.matches(packet.id, version) {
            if let Ok(mut answer) = decode_packet::<CommandSuggestions>(&packet.payload, version)
                && let Some(pending) = self.suggesting.answered(answer.id)
            {
                merge_suggestions(&mut answer.matches, pending.proxy_matches, version);
                replaced = encode_packet(&answer, version).ok();
            }
        } else {
            self.leftovers.observe(&packet, version);
        }
        self.client_out
            .push(replaced.unwrap_or_else(|| packet.to_bytes()), Some(permit));
    }

    fn action(&mut self, action: PlayerAction) -> Result<(), End> {
        let version = self.session.version;
        let encoded = match action {
            PlayerAction::Connect { server_name } => return self.request_switch(server_name),
            PlayerAction::Disconnect(reason) => return Err(End::Kicked(reason)),
            PlayerAction::Message(content) => encode_packet(
                &SystemChat {
                    content: component_json(&content, version),
                    overlay: false,
                },
                version,
            ),
            PlayerAction::PluginMessage { channel, data } => {
                encode_packet(&ClientboundPluginMessage { channel, data }, version)
            }
        };
        if let Ok(bytes) = encoded {
            let room = self.client_out.room(bytes.len());
            self.message = Some(HeldMessage { bytes, room });
        }
        Ok(())
    }

    fn request_switch(&mut self, target: String) -> Result<(), End> {
        let idle = matches!(self.switch, Switch::Idle | Switch::Deferred { .. });
        if self.link != Link::Play && idle {
            self.switch = Switch::Deferred { target };
            return Ok(());
        }
        if !idle {
            self.notify(self.translate("vine.server.already_connecting", &[]));
            return Ok(());
        }
        info!(
            "Switching player '{}' to backend server '{}'...",
            self.session.username, target
        );
        let job = Job::spawn(
            self.bridge
                .clone()
                .switch_job(self.backend.name.clone(), target.clone()),
        );
        self.switch = Switch::Connecting { target, job };
        Ok(())
    }

    fn switch_event(&mut self, event: SwitchEvent) -> Result<(), End> {
        match event {
            SwitchEvent::Connected(connected) => {
                match std::mem::replace(&mut self.switch, Switch::Idle) {
                    Switch::Connecting { target, .. } => {
                        let connected = connected
                            .unwrap_or_else(|| Connected::Prepared(target, Err(job_ended())));
                        self.connected(connected)
                    }
                    Switch::Fallback { reason, .. } => match connected {
                        Some(connected) => self.fallen_back(reason, connected),
                        None => Err(End::Kicked(reason)),
                    },
                    other => {
                        self.switch = other;
                        Ok(())
                    }
                }
            }
            SwitchEvent::Written => {
                if let Switch::AwaitingAck { clock, .. } = &mut self.switch {
                    *clock = AckClock::Until(tokio::time::Instant::now() + SWITCH_ACK_TIMEOUT);
                }
                Ok(())
            }
            SwitchEvent::AckTimedOut => {
                let Switch::AwaitingAck { target, .. } = &self.switch else {
                    return Ok(());
                };
                warn!(
                    "Lost player '{}' while switching to '{}': {}",
                    self.session.username,
                    target,
                    client_timeout()
                );
                Err(End::Kicked(
                    self.translate("vine.server.switch_failed", &[target]),
                ))
            }
        }
    }

    /// A switch the player asked for has its next backend logged in, or failed to
    fn connected(&mut self, connected: Connected) -> Result<(), End> {
        if let Conn::Gone { reason } = &self.backend.conn {
            // A server that stops right after sending its players elsewhere still delivers them
            return match connected {
                Connected::Prepared(target, Ok(prepared)) => self.leave(target, prepared),
                other => {
                    if let Connected::Prepared(target, Err(e)) = other {
                        warn!(
                            "Failed to switch player '{}' to '{}': {}",
                            self.session.username, target, e
                        );
                    }
                    let reason = reason.clone();
                    self.reroute(reason)
                }
            };
        }
        match connected {
            Connected::Cancelled(reason) => {
                let reason =
                    reason.unwrap_or_else(|| self.translate("vine.plugin.cancelled_switch", &[]));
                self.notify(self.translate("vine.server.switch_cancelled", &[&reason]));
            }
            Connected::AlreadyThere(target) => {
                self.notify(self.translate("vine.command.server.already_connected", &[&target]));
            }
            Connected::Unknown(target) => {
                self.notify(self.translate("vine.server.unknown", &[&target]));
            }
            Connected::Prepared(target, Err(e)) => {
                warn!(
                    "Failed to switch player '{}' to '{}': {}",
                    self.session.username, target, e
                );
                let e = e.to_string();
                self.notify(self.translate("vine.server.connect_failed", &[&target, &e]));
            }
            Connected::Prepared(target, Ok(prepared)) if self.link == Link::Play => {
                return self.leave(target, prepared);
            }
            // Kept so another switch waits; it goes ahead once the client is playing
            Connected::Prepared(target, Ok(prepared)) => {
                self.switch = Switch::Held {
                    target,
                    prepared,
                    since: Instant::now(),
                };
            }
        }
        Ok(())
    }

    fn fallen_back(&mut self, reason: String, connected: Connected) -> Result<(), End> {
        match connected {
            Connected::Prepared(target, Ok(prepared)) => {
                info!(
                    "Rerouting player '{}' to fallback server '{}' (kicked from '{}': {})",
                    self.session.username, target, self.backend.name, reason
                );
                self.notify(self.translate("vine.server.fallback", &[&target, &reason]));
                self.leave(target, prepared)
            }
            Connected::Prepared(target, Err(e)) => {
                warn!(
                    "Failed to connect player '{}' to fallback server '{}': {}",
                    self.session.username, target, e
                );
                let e = e.to_string();
                Err(End::Kicked(self.translate(
                    "vine.server.fallback_failed",
                    &[&self.backend.name, &e],
                )))
            }
            Connected::Cancelled(cancel_reason) => {
                Err(End::Kicked(cancel_reason.unwrap_or(reason)))
            }
            Connected::AlreadyThere(_) | Connected::Unknown(_) => Err(End::Kicked(reason)),
        }
    }

    /// The client finished configuring and is playing
    fn reached_play(&mut self) -> Result<(), End> {
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            Switch::Deferred { target } => self.request_switch(target),
            Switch::Held {
                target,
                prepared,
                since,
            } => {
                // A backend kept waiting this long may have given up on the login, so it is
                // logged into again
                if since.elapsed() > HELD_BACKEND_LIMIT
                    && let Some(config) = self.bridge.proxy_config.servers.get(&target).cloned()
                {
                    let job = Job::spawn(self.bridge.clone().prepare_job(target.clone(), config));
                    self.switch = Switch::Connecting { target, job };
                    return Ok(());
                }
                self.leave(target, prepared)
            }
            other => {
                self.switch = other;
                Ok(())
            }
        }
    }

    fn backend_lost(&mut self, reason: Option<String>) -> Result<(), End> {
        if matches!(self.backend.conn, Conn::Gone { .. }) {
            return Ok(());
        }
        self.backend.conn = Conn::Gone {
            reason: reason.clone(),
        };
        self.stalled = None;
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            // A switch already on its way finishes instead, so a server that stops right after
            // sending its players elsewhere still delivers them there
            Switch::Held {
                target,
                prepared,
                since,
            } if since.elapsed() <= HELD_BACKEND_LIMIT => self.leave(target, prepared),
            Switch::Held { target, .. } => {
                match self.bridge.proxy_config.servers.get(&target).cloned() {
                    Some(config) => {
                        let job =
                            Job::spawn(self.bridge.clone().prepare_job(target.clone(), config));
                        self.switch = Switch::Connecting { target, job };
                        Ok(())
                    }
                    None => self.reroute(reason),
                }
            }
            Switch::Stopping { target, prepared } => self.stopped(target, prepared),
            Switch::Idle | Switch::Deferred { .. } => self.reroute(reason),
            other => {
                self.switch = other;
                Ok(())
            }
        }
    }

    /// The current backend's reader finished
    fn backend_stopped(&mut self) -> Result<(), End> {
        if let Conn::Open(open) = &mut self.backend.conn {
            open.events = None;
        }
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            Switch::Stopping { target, prepared } => self.stopped(target, prepared),
            other => {
                self.switch = other;
                self.backend_lost(None)
            }
        }
    }

    /// With the current backend gone, moves the player to the fallback server or disconnects them
    fn reroute(&mut self, reason: Option<String>) -> Result<(), End> {
        warn!(
            "Backend server '{}' disconnected player '{}': {:?}",
            self.backend.name, self.session.username, reason
        );
        let reason = reason.unwrap_or_else(|| self.translate("vine.server.lost_connection", &[]));
        let fallback = self
            .bridge
            .fallback_server
            .clone()
            .filter(|(name, _)| name != &self.backend.name);
        let Some((target, config)) = fallback else {
            return Err(End::Kicked(reason));
        };
        let job = Job::spawn(self.bridge.clone().fallback_job(
            self.backend.name.clone(),
            target,
            config,
        ));
        self.switch = Switch::Fallback { reason, job };
        Ok(())
    }

    /// Starts moving the client over to a backend that is logged in
    fn leave(&mut self, target: String, prepared: Box<PreparedBackend>) -> Result<(), End> {
        if self.backend.stop_reading() {
            self.switch = Switch::Stopping { target, prepared };
            return Ok(());
        }
        self.stopped(target, prepared)
    }

    /// Nothing more of the current backend reaches the client; hands the client over
    fn stopped(&mut self, target: String, mut prepared: Box<PreparedBackend>) -> Result<(), End> {
        let version = self.session.version;
        if let Some((mut pending, join_game)) = prepared.join_game.take() {
            let joining = join_game_sequence(&join_game, version).unwrap_or_else(|e| {
                debug!("Forwarding JoinGame from '{}' unchanged: {}", target, e);
                vec![join_game.to_bytes()]
            });
            pending.extend(self.leftovers.clear_players(version));
            pending.extend(joining);
            pending.extend(self.leftovers.clear_overlays(version));
            if !self.client_out.push_all(pending) {
                return Err(End::Closed);
            }
            let PreparedBackend { reader, writer, .. } = *prepared;
            return self.install(target, reader, writer, Phase::Play, Vec::new());
        }

        let clock = match self.link {
            Link::Play => {
                let Ok(start) = encode_packet(&StartConfiguration, version) else {
                    return Err(End::Kicked(
                        self.translate("vine.server.switch_failed", &[&target]),
                    ));
                };
                self.client_out.push(start, None);
                self.link = Link::Reconfiguring;
                AckClock::Writing(self.client_out.written())
            }
            // The current backend already asked for reconfiguration, or the client is still
            // logging in, so it is about to acknowledge
            Link::Reconfiguring | Link::Login => {
                AckClock::Until(tokio::time::Instant::now() + SWITCH_ACK_TIMEOUT)
            }
            // Only reached with the current backend gone: what the client sent in this
            // configuration phase until now was meant for it
            Link::Config => {
                self.stale_before = self.generation() + 1;
                return self.configure(target, prepared);
            }
        };
        if let (Some(packet), Conn::Open(open)) = (self.stalled.take(), &self.backend.conn) {
            let _ = open.writes.try_send(packet);
        }
        self.switch = Switch::AwaitingAck {
            target,
            prepared,
            clock,
        };
        Ok(())
    }

    fn acknowledged(&mut self) -> Result<(), End> {
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            Switch::AwaitingAck {
                target, prepared, ..
            } => self.configure(target, prepared),
            other => {
                self.switch = other;
                Ok(())
            }
        }
    }

    /// Hands a configuring client to a 1.20.2+ backend that is waiting for its acknowledgement
    fn configure(&mut self, target: String, prepared: Box<PreparedBackend>) -> Result<(), End> {
        let version = self.session.version;
        let Ok(ack) = encode_packet(&LoginAcknowledged, version) else {
            return Err(End::Kicked(
                self.translate("vine.server.switch_failed", &[&target]),
            ));
        };
        let initial = std::iter::once(ack)
            .chain(self.client_settings.repeat(version))
            .collect();
        let PreparedBackend { reader, writer, .. } = *prepared;
        self.install(target, reader, writer, Phase::Config, initial)
    }

    fn install(
        &mut self,
        target: String,
        reader: BackendReader,
        writer: BackendWriter,
        phase: Phase,
        initial: Vec<Bytes>,
    ) -> Result<(), End> {
        self.backend = Backend::start(
            &self.session,
            reader,
            writer,
            target.clone(),
            phase,
            initial,
        );
        self.keep_alive = None;
        self.suggesting.forget();
        let generation = self.generation() + 1;
        self.served.send_replace(Served {
            generation,
            name: target.clone(),
        });
        self.session
            .session_manager
            .update_server(&self.session.username, &target);
        info!(
            "Player '{}' successfully switched to '{}'",
            self.session.username, target
        );
        self.fire_connected(target);
        match self.stalled.take() {
            Some(packet) => self.forward(packet),
            None => Ok(()),
        }
    }

    fn fire_connected(&mut self, server_name: String) {
        let previous = self.plugin_events.take();
        let bridge = self.bridge.clone();
        self.plugin_events = Some(tokio::spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            let event = ServerConnectedEvent {
                uuid: bridge.player.id.to_string(),
                username: bridge.player.username.clone(),
                server_name,
            };
            bridge.plugin_manager.fire_server_connected(&event).await;
        }));
    }

    fn suggestion_event(&mut self, event: SuggestionEvent) {
        let generation = self.generation();
        let answer = match event {
            SuggestionEvent::Answered(answer) => {
                let served = self.suggesting.running.take().map(|running| running.served);
                if let Some((request, served)) = self.suggesting.next.take() {
                    self.suggesting.ask(&self.session, request, served);
                    return;
                }
                answer.filter(|_| served == Some(generation))
            }
            SuggestionEvent::Due => self.suggesting.due(generation, self.session.version),
        };
        if let Some(bytes) = answer {
            self.send_play(bytes, None);
        }
    }

    /// Sends the kick after everything already queued and closes the connection behind it
    async fn disconnect_client(&self, mut writer: Task, reason: &str) {
        let locale = self.locale();
        if let Some(kick) = disconnect_packet(
            self.session.version,
            self.link.clientbound(),
            locale.as_deref(),
            reason,
        ) {
            self.client_out.push(kick, None);
        }
        self.client_out.close();
        if timeout(CLIENT_WRITE_TIMEOUT, writer.join()).await.is_err() {
            debug!(
                "Gave up writing to '{}' before disconnecting",
                self.session.username
            );
        }
    }
}

fn job_ended() -> BridgeError {
    BridgeError::IoError(std::io::Error::other("the connection attempt ended"))
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

/// A setting the client told its backend about
enum Setting {
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

impl ClientSettings {
    fn apply(&mut self, setting: Setting) {
        match setting {
            Setting::Information(payload) => self.information = Some(payload),
            Setting::Brand(data) => self.brand = Some(data),
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

// Backends drop a login that is not acknowledged within about 30 seconds
const HELD_BACKEND_LIMIT: Duration = Duration::from_secs(20);

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
}

/// Root command names of the proxy's own, waiting to be merged into the backend's answer
struct PendingSuggestion {
    id: i32,
    clean_cmd: String,
    offset: usize,
    proxy_matches: Vec<(String, Option<String>)>,
}

enum Suggest {
    /// Arguments to a proxy command, answered by the proxy alone
    Proxy(SuggestionRequest),
    /// A command name the proxy has matches for, merged into the backend's answer
    Completion(PendingSuggestion),
    Backend,
}

// The backend gets this long to answer before the proxy's own command names are sent alone
const COMPLETION_WAIT: Duration = Duration::from_millis(200);

/// The client's suggestion requests the proxy answers
#[derive(Default)]
struct Suggesting {
    // One argument suggestion per player is worked out at a time. The client only uses the answer
    // to its newest request, so only the newest one that arrives meanwhile is kept for next.
    running: Option<RunningSuggestion>,
    next: Option<(SuggestionRequest, u64)>,
    pending: HashMap<i32, (u64, PendingSuggestion)>,
    due: VecDeque<(tokio::time::Instant, i32)>,
}

struct RunningSuggestion {
    served: u64,
    answer: tokio::task::JoinHandle<Option<Bytes>>,
}

enum SuggestionEvent {
    Answered(Option<Bytes>),
    Due,
}

impl Suggesting {
    fn ask(&mut self, session: &Session, request: SuggestionRequest, served: u64) {
        if self.running.is_some() {
            self.next = Some((request, served));
            return;
        }
        let version = session.version;
        let dispatcher = session.command_dispatcher.clone();
        // Plugins answer these, so they are worked out off the tunnel
        let answer = tokio::task::spawn_blocking(move || {
            let SuggestionRequest {
                id,
                input,
                offset,
                source,
            } = request;
            let suggestions = dispatcher.suggest_with_range(&input, &source);
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
            encode_packet(&response, version).ok()
        });
        self.running = Some(RunningSuggestion { served, answer });
    }

    fn expect(&mut self, completion: PendingSuggestion, served: u64) {
        self.due
            .push_back((tokio::time::Instant::now() + COMPLETION_WAIT, completion.id));
        self.pending.insert(completion.id, (served, completion));
    }

    fn answered(&mut self, id: i32) -> Option<PendingSuggestion> {
        self.pending.remove(&id).map(|(_, pending)| pending)
    }

    /// The proxy's own answer to the oldest completion the backend has not answered in time
    fn due(&mut self, generation: u64, version: ProtocolVersion) -> Option<Bytes> {
        let (_, id) = self.due.pop_front()?;
        let (served, pending) = self.pending.remove(&id)?;
        if served != generation {
            return None;
        }
        let response = CommandSuggestions {
            id,
            start: pending.offset as i32,
            length: pending.clean_cmd.len() as i32,
            matches: pending
                .proxy_matches
                .into_iter()
                .map(|(cmd, tip)| Suggestion {
                    text: cmd,
                    tooltip: tip.map(|t| component_json(&TextComponent::text(t), version)),
                })
                .collect(),
        };
        encode_packet(&response, version).ok()
    }

    fn forget(&mut self) {
        self.pending.clear();
        self.due.clear();
    }

    async fn progress(&mut self) -> SuggestionEvent {
        let due = self.due.front().map(|(at, _)| *at);
        let running = &mut self.running;
        tokio::select! {
            answer = async {
                match running {
                    Some(running) => (&mut running.answer).await,
                    None => std::future::pending().await,
                }
            } => SuggestionEvent::Answered(answer.ok().flatten()),
            () = async {
                match due {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => SuggestionEvent::Due,
        }
    }
}

enum ClientWrite {
    // Packets of the proxy's own carry no permit, so they never wait for room
    Packet(Bytes, Option<OwnedSemaphorePermit>),
    // Answered once everything queued before it is written
    Written(oneshot::Sender<()>),
    Close,
}

type ClientQueueRx = mpsc::UnboundedReceiver<ClientWrite>;

/// Everything for the client goes through here, in order, to the one task writing to it
#[derive(Clone)]
struct ClientQueue {
    tx: mpsc::UnboundedSender<ClientWrite>,
    budget: Arc<Semaphore>,
}

impl ClientQueue {
    fn new() -> (Self, ClientQueueRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let budget = Arc::new(Semaphore::new(CLIENT_QUEUE_BYTES));
        (Self { tx, budget }, rx)
    }

    fn cost(len: usize) -> u32 {
        len.clamp(1, CLIENT_QUEUE_BYTES) as u32
    }

    async fn reserve(&self, len: usize) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.budget)
            .acquire_many_owned(Self::cost(len))
            .await
            .ok()
    }

    /// Resolves once there is room for a packet of this size
    fn room(&self, len: usize) -> Room {
        Box::pin(Arc::clone(&self.budget).acquire_many_owned(Self::cost(len)))
    }

    /// Queues a packet once there is room for it
    async fn send(&self, bytes: Bytes) -> bool {
        match self.reserve(bytes.len()).await {
            Some(permit) => self.push(bytes, Some(permit)),
            None => false,
        }
    }

    fn push(&self, bytes: Bytes, permit: Option<OwnedSemaphorePermit>) -> bool {
        self.tx.send(ClientWrite::Packet(bytes, permit)).is_ok()
    }

    fn push_all(&self, packets: impl IntoIterator<Item = Bytes>) -> bool {
        packets.into_iter().all(|bytes| self.push(bytes, None))
    }

    /// Answered once everything queued so far is written; dropped if the client is gone
    fn written(&self) -> oneshot::Receiver<()> {
        let (done, wait) = oneshot::channel();
        let _ = self.tx.send(ClientWrite::Written(done));
        wait
    }

    fn close(&self) {
        let _ = self.tx.send(ClientWrite::Close);
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

/// What one player's readers need to work out what the packets they read become
struct Session {
    username: String,
    uuid: uuid::Uuid,
    version: ProtocolVersion,
    plugin_manager: Arc<PluginManager>,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    proxy_config: Arc<Config>,
    action_tx: mpsc::Sender<PlayerAction>,
    client_out: ClientQueue,
}

/// What the client reader hands the tunnel, in the order the client sent it. `served` is the
/// generation of the backend that was current when the packet was read.
enum ClientEvent {
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

const CLIENT_EVENTS: usize = 16;

/// Reads the client for the whole session. Its packets are handled one at a time, plugin events
/// included, so a slow plugin only holds up what the client sends.
async fn read_client<R: AsyncRead + Unpin>(
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
enum BackendEvent {
    /// A packet whose effect on the session the tunnel decides before queueing it for the client
    /// with the room already taken for it; the reader goes on once `done` is answered, so
    /// nothing it reads later overtakes it
    Packet {
        packet: crate::protocol::RawPacket,
        permit: OwnedSemaphorePermit,
        done: oneshot::Sender<()>,
    },
    Lost {
        reason: Option<String>,
    },
    ClientGone,
}

/// The backend the client is on
struct Backend {
    name: String,
    conn: Conn,
}

enum Conn {
    Open(OpenBackend),
    Gone { reason: Option<String> },
}

/// A backend read and written by tasks of its own
struct OpenBackend {
    writes: mpsc::Sender<Bytes>,
    // None once the reader has finished
    events: Option<mpsc::Receiver<BackendEvent>>,
    // Dropped to stop the reader once the packet in hand has reached the client queue
    stop: Option<oneshot::Sender<()>>,
    _reader: Task,
    _writer: Lingering,
}

impl Backend {
    fn start(
        session: &Arc<Session>,
        reader: BackendReader,
        writer: BackendWriter,
        name: String,
        phase: Phase,
        initial: Vec<Bytes>,
    ) -> Self {
        let (events_tx, events) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let reader = Task::spawn(read_backend(
            session.clone(),
            reader,
            name.clone(),
            phase,
            events_tx,
            stopped,
        ));
        let (writes, rx) = mpsc::channel(BACKEND_WRITES);
        for packet in initial {
            let _ = writes.try_send(packet);
        }
        let writer = Lingering(tokio::spawn(write_backend(
            writer,
            rx,
            session.username.clone(),
        )));
        Self {
            name,
            conn: Conn::Open(OpenBackend {
                writes,
                events: Some(events),
                stop: Some(stop),
                _reader: reader,
                _writer: writer,
            }),
        }
    }

    /// Asks the reader to stop; false if it already has
    fn stop_reading(&mut self) -> bool {
        match &mut self.conn {
            Conn::Open(open) if open.events.is_some() => {
                open.stop = None;
                true
            }
            _ => false,
        }
    }

    /// The reader's next event; `None` once it has finished
    async fn next_event(&mut self) -> Option<BackendEvent> {
        match &mut self.conn {
            Conn::Open(OpenBackend {
                events: Some(events),
                ..
            }) => events.recv().await,
            _ => std::future::pending().await,
        }
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
    session: Arc<Session>,
    mut reader: BackendReader,
    server_name: String,
    mut phase: Phase,
    events: mpsc::Sender<BackendEvent>,
    mut stop: oneshot::Receiver<()>,
) {
    loop {
        let packet = tokio::select! {
            biased;
            _ = &mut stop => return,
            packet = reader.read_packet() => packet,
        };
        let handled = match packet {
            Ok(packet) => {
                session
                    .backend_packet(packet, &server_name, &mut phase, &events)
                    .await
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
fn watched(id: i32, version: ProtocolVersion) -> bool {
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
            if PacketKind::ConfigFinish.matches(raw_packet.id, version) {
                *phase = Phase::Play;
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

            if watched(raw_packet.id, version) {
                if PacketKind::StartConfiguration.matches(raw_packet.id, version) {
                    *phase = Phase::Config;
                }
                return self.through_tunnel(raw_packet, events).await;
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
        events: &mpsc::Sender<BackendEvent>,
    ) -> Result<(), Option<BackendEvent>> {
        let Some(permit) = self.client_out.reserve(packet.payload.len() + 1).await else {
            return Err(Some(BackendEvent::ClientGone));
        };
        let (done, queued) = oneshot::channel();
        let event = BackendEvent::Packet {
            packet,
            permit,
            done,
        };
        if events.send(event).await.is_err() {
            return Err(None);
        }
        queued.await.map_err(|_| None)
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
