use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::client_queue::{CLIENT_WRITE_TIMEOUT, ClientQueue, write_client};
use super::connection::Backend;
use super::readers::{CLIENT_EVENTS, Handlings, Session, read_client};
use super::suggestions::Suggesting;
use super::switch::Switch;
use super::task::Task;
use super::tunnel::{ClientSettings, End, Link, Served, Tunnel};
use crate::auth::AuthenticatedPlayer;
use crate::command::CommandDispatcher;
use crate::config::{BackendConfig, Config, NetworkConfig};
use crate::i18n::translate;
use crate::plugin::PluginManager;
use crate::plugin::api::{
    PlayerDisconnectEvent, PlayerJoinEvent, ServerConnectEvent, ServerConnectedEvent,
};
use crate::protocol::packets::config::ConfigDisconnect;
use crate::protocol::packets::login::LoginDisconnect;
use crate::protocol::packets::play::PlayDisconnect;
use crate::protocol::packets::switch::Leftovers;
use crate::protocol::text::{component_json, parse_message};
use crate::protocol::{
    Packet, PacketReader, PacketWriter, ProtocolError, ProtocolVersion, encode_packet,
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

pub struct BackendBridge {
    server_name: String,
    config: BackendConfig,
    pub(super) fallback_server: Option<(String, BackendConfig)>,
    pub(super) client_ip: IpAddr,
    pub(super) client_version: ProtocolVersion,
    pub(super) virtual_host: String,
    pub(super) player: AuthenticatedPlayer,
    max_packets_per_sec: u32,
    online_players: Arc<AtomicUsize>,
    pub(super) network_config: Arc<NetworkConfig>,
    pub(super) compression_level: i32,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    pub(super) proxy_config: Arc<Config>,
    pub(super) plugin_manager: Arc<PluginManager>,
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

    /// Establishes connection to backend, handles login handshake, and tunnels packets
    pub async fn run<R, W>(
        self,
        client_reader: PacketReader<R>,
        client_writer: PacketWriter<W>,
        action_tx: mpsc::Sender<PlayerAction>,
        action_rx: mpsc::Receiver<PlayerAction>,
    ) -> Result<(), BridgeError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let Some((mut tunnel, writer)) =
            Box::pin(self.prepare(client_reader, client_writer, action_tx, action_rx)).await?
        else {
            return Ok(());
        };
        let bridge = tunnel.bridge.clone();
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

    // Drop the login future and its temporary state before the long-lived tunnel starts.
    async fn prepare<R, W>(
        self,
        client_reader: PacketReader<R>,
        mut client_writer: PacketWriter<W>,
        action_tx: mpsc::Sender<PlayerAction>,
        action_rx: mpsc::Receiver<PlayerAction>,
    ) -> Result<Option<(Tunnel, Task)>, BridgeError>
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
            return Ok(None);
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
        let client_compression = client_writer.compression_threshold();
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
            client_compression,
            handlings: Handlings::new(bridge.client_version),
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
                Link::Login | Link::Config | Link::Reconfiguring => Phase::Config,
                Link::Play | Link::Finishing => Phase::Play,
            },
            Vec::new(),
        );
        let tunnel = Tunnel {
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
            notices: Vec::new(),
            stalled: None,
            served,
            stale_before: 0,
            plugin_events: None,
            _client_reader: client_reader,
        };

        Ok(Some((tunnel, writer)))
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

    pub(super) fn locale(&self) -> Option<String> {
        self.session_manager.locale(&self.player.username)
    }
}

pub(super) fn disconnect_packet(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Login,
    Config,
    Play,
}
