use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use thiserror::Error;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth::{
    AuthError, AuthenticatedPlayer, Authenticator, IdentifiedKey, KeyRevision, KeyStore,
    verify_signed_token,
};
use crate::backend::{BackendBridge, Router};
use crate::command::CommandDispatcher;
use crate::config::Config;
use crate::network::PrefixedRead;
use crate::plugin::PluginManager;
use crate::plugin::api::{PlayerLoginEvent, PlayerPreLoginEvent, ProxyPingEvent};
use crate::protocol::packets::handshake::{Handshake, HandshakeIntent};
use crate::protocol::packets::login::{
    EncryptionRequest, EncryptionResponse, LoginDisconnect, LoginStart, SetCompression,
    Verification,
};
use crate::protocol::packets::status::{PingRequest, PongResponse};
use crate::protocol::text::{component_json, parse_message};
use crate::protocol::{
    PacketKind, PacketReader, PacketWriter, ProtocolError, ProtocolVersion, decode_packet,
    encode_packet,
};
use crate::security::Sanitizer;
use crate::session::{PlayerSession, SessionManager};
use crate::status::StatusHandler;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Client IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Bridge error: {0}")]
    BridgeError(#[from] crate::backend::BridgeError),
    #[error("Connection timed out")]
    Timeout,
}

type ClientReader = PacketReader<PrefixedRead<OwnedReadHalf>>;
type ClientWriter = PacketWriter<OwnedWriteHalf>;

pub struct ClientHandler {
    peer_addr: SocketAddr,
    config: Arc<Config>,
    keystore: Arc<KeyStore>,
    authenticator: Arc<Authenticator>,
    status_handler: Arc<StatusHandler>,
    router: Arc<Router>,
    online_players: Arc<AtomicUsize>,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    plugin_manager: Arc<PluginManager>,
}

impl ClientHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_addr: SocketAddr,
        config: Arc<Config>,
        keystore: Arc<KeyStore>,
        authenticator: Arc<Authenticator>,
        status_handler: Arc<StatusHandler>,
        router: Arc<Router>,
        online_players: Arc<AtomicUsize>,
        session_manager: Arc<SessionManager>,
        command_dispatcher: Arc<CommandDispatcher>,
        plugin_manager: Arc<PluginManager>,
    ) -> Self {
        Self {
            peer_addr,
            config,
            keystore,
            authenticator,
            status_handler,
            router,
            online_players,
            session_manager,
            command_dispatcher,
            plugin_manager,
        }
    }

    pub async fn handle(
        self,
        stream: TcpStream,
        leftover_bytes: Vec<u8>,
    ) -> Result<(), ClientError> {
        let (read_half, write_half) = stream.into_split();
        let mut reader = PacketReader::new(PrefixedRead::new(read_half, leftover_bytes));
        let mut writer = PacketWriter::new(write_half);

        let handshake_timeout =
            Duration::from_secs(self.config.network.client_handshake_timeout_secs);
        let raw_handshake = timeout(handshake_timeout, reader.read_packet())
            .await
            .map_err(|_| ClientError::Timeout)??;

        // Handshake layout is version independent
        let handshake: Handshake = decode_packet(&raw_handshake.payload, ProtocolVersion::V1_8)?;

        let client_version = ProtocolVersion::from_handshake(handshake.protocol_version);
        let clean_host = Sanitizer::sanitize_host(&handshake.server_address);

        debug!(
            "[{}] Handshake: version={}, host='{}', intent={:?}",
            self.peer_addr, client_version, clean_host, handshake.intent
        );

        match handshake.intent {
            HandshakeIntent::Status => {
                if self.config.network.log_pings {
                    info!(
                        "[{}] Status ping: version={}, host='{}'",
                        self.peer_addr, client_version, clean_host
                    );
                }
                self.handle_status(&mut reader, &mut writer, client_version, &clean_host)
                    .await
            }
            HandshakeIntent::Login => {
                self.handle_login(
                    reader,
                    writer,
                    client_version,
                    clean_host,
                    self.peer_addr.ip(),
                )
                .await
            }
            HandshakeIntent::Transfer => {
                debug!(
                    "[{}] Unsupported handshake intent: {:?}",
                    self.peer_addr, handshake.intent
                );
                Ok(())
            }
        }
    }

    async fn handle_status(
        &self,
        reader: &mut ClientReader,
        writer: &mut ClientWriter,
        client_version: ProtocolVersion,
        virtual_host: &str,
    ) -> Result<(), ClientError> {
        let status_timeout = Duration::from_secs(self.config.network.client_status_timeout_secs);

        let raw_status = timeout(status_timeout, reader.read_packet())
            .await
            .map_err(|_| ClientError::Timeout)??;

        if PacketKind::StatusRequest.matches(raw_status.id, client_version) {
            let initial_motd = self.status_handler.resolve_motd_text(Some(virtual_host));
            let initial_online = self
                .online_players
                .load(std::sync::atomic::Ordering::Relaxed) as u32;
            let mut ping_event = ProxyPingEvent {
                client_ip: self.peer_addr.ip().to_string(),
                protocol_version: client_version.0,
                virtual_host: virtual_host.to_string(),
                motd: initial_motd,
                max_players: self.config.motd.max_players,
                online_players: initial_online,
                version_name: self.config.motd.version_name.clone(),
            };
            self.plugin_manager.fire_proxy_ping(&mut ping_event).await;

            let status = self.status_handler.create_custom_status_packet(
                client_version,
                &ping_event.motd,
                ping_event.max_players,
                ping_event.online_players,
                &ping_event.version_name,
                Some(virtual_host),
            );
            writer.send(encode_packet(&status, client_version)?).await?;
        }

        if let Ok(Ok(raw_ping)) = timeout(status_timeout, reader.read_packet()).await
            && PacketKind::PingRequest.matches(raw_ping.id, client_version)
            && let Ok(ping) = decode_packet::<PingRequest>(&raw_ping.payload, client_version)
        {
            let pong = PongResponse {
                payload: ping.payload,
            };
            let _ = writer.send(encode_packet(&pong, client_version)?).await;
        }

        Ok(())
    }

    async fn handle_login(
        &self,
        mut reader: ClientReader,
        mut writer: ClientWriter,
        client_version: ProtocolVersion,
        virtual_host: String,
        client_ip: IpAddr,
    ) -> Result<(), ClientError> {
        let login_timeout = Duration::from_secs(self.config.network.client_login_timeout_secs);

        if !client_version.is_known() {
            info!(
                "[{}] Rejecting unsupported client version {}",
                self.peer_addr, client_version
            );
            let reason = format!(
                "Unsupported Minecraft version. This proxy supports {}.",
                ProtocolVersion::supported_range()
            );
            Self::kick(&mut writer, client_version, &reason).await?;
            return Ok(());
        }

        let raw_login_start = timeout(login_timeout, reader.read_packet())
            .await
            .map_err(|_| ClientError::Timeout)??;

        let login_start: LoginStart = decode_packet(&raw_login_start.payload, client_version)?;
        let username = login_start.name.clone();

        let mut profile_key = login_start
            .profile_key
            .clone()
            .map(|key| IdentifiedKey::new(key, client_version));
        if let Some(key) = &mut profile_key {
            if key.has_expired() {
                warn!(
                    "[{}] Expired profile key for '{}'",
                    self.peer_addr, username
                );
                Self::kick(
                    &mut writer,
                    client_version,
                    "Invalid signature for profile public key. Try restarting your game.",
                )
                .await?;
                return Ok(());
            }
            let valid = match key.revision {
                KeyRevision::LinkedV2 => key.add_holder(login_start.uuid),
                KeyRevision::GenericV1 => key.is_signature_valid(),
            };
            if !valid {
                warn!(
                    "[{}] Invalid profile key for '{}'",
                    self.peer_addr, username
                );
                Self::kick(&mut writer, client_version, "Invalid profile public key.").await?;
                return Ok(());
            }
        } else if (ProtocolVersion::V1_19..ProtocolVersion::V1_19_3).contains(&client_version)
            && self.config.server.online_mode
            && self.config.server.force_key_authentication
        {
            Self::kick(
                &mut writer,
                client_version,
                "Missing profile public key. This server requires secure profiles.",
            )
            .await?;
            return Ok(());
        }

        let mut pre_login_event = PlayerPreLoginEvent {
            client_ip: client_ip.to_string(),
            username: username.clone(),
            protocol_version: client_version.0,
            virtual_host: virtual_host.clone(),
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager
            .fire_player_pre_login(&mut pre_login_event)
            .await;
        if pre_login_event.cancelled {
            let reason = pre_login_event
                .cancel_reason
                .as_deref()
                .unwrap_or("Connection cancelled by plugin");
            warn!(
                "[{}] Player '{}' pre-login cancelled by plugin: {}",
                self.peer_addr, username, reason
            );
            Self::kick(&mut writer, client_version, reason).await?;
            return Ok(());
        }

        if self.config.security.validate_usernames && !Sanitizer::is_valid_username(&username) {
            warn!(
                "[{}] Rejecting invalid username '{}' (failed sanitization)",
                self.peer_addr, username
            );
            Self::kick(
                &mut writer,
                client_version,
                "Invalid username characters or length (must be 2-16 alphanumeric or _)",
            )
            .await?;
            return Ok(());
        }

        info!(
            "[{}] Player '{}' initiating login (version: {})",
            self.peer_addr, username, client_version
        );

        let mut authenticated_player = if self.config.server.online_mode {
            let verify_token: [u8; 4] = rand::random();
            let encryption_request = EncryptionRequest {
                server_id: String::new(),
                public_key: self.keystore.public_key_der().to_vec(),
                verify_token: verify_token.to_vec(),
                should_authenticate: true,
            };
            writer
                .send(encode_packet(&encryption_request, client_version)?)
                .await?;

            let raw_enc_resp = timeout(login_timeout, reader.read_packet())
                .await
                .map_err(|_| ClientError::Timeout)??;

            let enc_resp: EncryptionResponse =
                decode_packet(&raw_enc_resp.payload, client_version)?;

            let shared_secret = self
                .keystore
                .decrypt(&enc_resp.shared_secret)
                .map_err(|e| ClientError::AuthError(e.to_string()))?;

            if shared_secret.len() != 16 {
                warn!(
                    "[{}] Shared secret has invalid length ({})",
                    self.peer_addr,
                    shared_secret.len()
                );
                Self::kick(&mut writer, client_version, "Invalid encryption key length").await?;
                return Err(ClientError::AuthError("Invalid key length".to_string()));
            }

            let mut aes_key = [0u8; 16];
            aes_key.copy_from_slice(&shared_secret);

            reader.enable_encryption(&aes_key)?;
            writer.enable_encryption(&aes_key)?;

            let token_valid = match &enc_resp.verification {
                Verification::Token(encrypted) => self
                    .keystore
                    .decrypt(encrypted)
                    .is_ok_and(|token| token == verify_token),
                Verification::Signature { salt, signature } => {
                    login_start.profile_key.as_ref().is_some_and(|key| {
                        verify_signed_token(&key.public_key, &verify_token, *salt, signature)
                    })
                }
            };

            if !token_valid {
                warn!(
                    "[{}] Verify token mismatch for '{}'",
                    self.peer_addr, username
                );
                Self::kick(
                    &mut writer,
                    client_version,
                    "Failed to verify encryption token",
                )
                .await?;
                return Err(ClientError::AuthError("Token mismatch".to_string()));
            }

            let server_hash = self.keystore.auth_digest("", &shared_secret);

            let auth_player = match self
                .authenticator
                .authenticate(
                    &username,
                    &server_hash,
                    &client_ip,
                    self.config.server.prevent_proxy_connections,
                )
                .await
            {
                Ok(player) => player,
                Err(e) => {
                    warn!(
                        "[{}] Mojang authentication failed for '{}': {}",
                        self.peer_addr, username, e
                    );
                    let reason = match e {
                        AuthError::NotJoined => "Failed to verify username!",
                        _ => {
                            "Failed to verify username with Mojang session servers! Please try again later."
                        }
                    };
                    Self::kick(&mut writer, client_version, reason).await?;
                    return Err(ClientError::AuthError(e.to_string()));
                }
            };

            debug!(
                "[{}] Stream encryption enabled for player '{}' ({})",
                self.peer_addr, auth_player.username, auth_player.id
            );

            auth_player
        } else {
            AuthenticatedPlayer::offline(&username)
        };

        if let Some(key) = &mut profile_key {
            let online = self.config.server.online_mode;
            let player_id = Some(authenticated_player.id);
            let linked = if online && key.revision == KeyRevision::LinkedV2 {
                key.add_holder(player_id)
            } else {
                key.holder.is_some() || key.add_holder(player_id)
            };
            if !linked && online {
                Self::kick(&mut writer, client_version, "Invalid profile public key.").await?;
                return Ok(());
            }
            if !linked {
                warn!(
                    "[{}] Profile key for '{}' could not be verified",
                    self.peer_addr, username
                );
            }
        }
        authenticated_player.profile_key = profile_key;

        let mut login_event = PlayerLoginEvent {
            uuid: authenticated_player.id.to_string(),
            username: authenticated_player.username.clone(),
            client_ip: client_ip.to_string(),
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager
            .fire_player_login(&mut login_event)
            .await;
        if login_event.cancelled {
            let reason = login_event
                .cancel_reason
                .as_deref()
                .unwrap_or("Login cancelled by plugin");
            warn!(
                "[{}] Player '{}' login cancelled by plugin: {}",
                self.peer_addr, authenticated_player.username, reason
            );
            Self::kick(&mut writer, client_version, reason).await?;
            return Ok(());
        }

        let comp_threshold = self.config.server.compression_threshold;
        if comp_threshold > 0 && PacketKind::SetCompression.id(client_version).is_some() {
            let set_compression = SetCompression {
                threshold: comp_threshold,
            };
            writer
                .send(encode_packet(&set_compression, client_version)?)
                .await?;

            reader.set_compression(comp_threshold as usize);
            writer.set_compression(
                comp_threshold as usize,
                self.config.server.compression_level as u32,
            );
        }

        let (server_name, backend_cfg) = match self.router.resolve_server(&virtual_host) {
            Some(res) => res,
            None => {
                warn!(
                    "[{}] No backend server found for host '{}'",
                    self.peer_addr, virtual_host
                );
                Self::kick(
                    &mut writer,
                    client_version,
                    "No default or matching backend Minecraft server is configured on the proxy.",
                )
                .await?;
                return Ok(());
            }
        };

        let fallback_server = if self.config.routing.try_fallback_on_connect_failure {
            self.config
                .routing
                .fallback_server
                .as_ref()
                .and_then(|fb_name| {
                    self.config
                        .servers
                        .get(fb_name)
                        .map(|cfg| (fb_name.clone(), cfg.clone()))
                })
        } else {
            None
        };

        let (action_tx, action_rx) = tokio::sync::mpsc::unbounded_channel();
        let Some(_session_guard) = self.session_manager.try_register(PlayerSession {
            username: authenticated_player.username.clone(),
            uuid: authenticated_player.id,
            current_server: server_name.clone(),
            action_tx: action_tx.clone(),
            client_ip: client_ip.to_string(),
            protocol_version: client_version.0,
            locale: None,
        }) else {
            warn!(
                "[{}] Rejecting duplicate login for '{}' ({})",
                self.peer_addr, authenticated_player.username, authenticated_player.id
            );
            Self::kick(
                &mut writer,
                client_version,
                "You are already connected to this proxy.",
            )
            .await?;
            return Ok(());
        };

        let bridge = BackendBridge::new(
            server_name,
            backend_cfg,
            fallback_server,
            client_ip,
            client_version,
            virtual_host,
            authenticated_player,
            self.config.security.max_packets_per_sec,
            self.online_players.clone(),
            Arc::new(self.config.network.clone()),
            self.config.server.compression_level,
            self.session_manager.clone(),
            self.command_dispatcher.clone(),
            self.config.clone(),
            self.plugin_manager.clone(),
        );

        bridge.run(reader, writer, action_tx, action_rx).await?;
        Ok(())
    }

    async fn kick(
        writer: &mut ClientWriter,
        version: ProtocolVersion,
        reason: &str,
    ) -> Result<(), ClientError> {
        let disconnect = LoginDisconnect {
            reason_json: kick_reason(reason, version).to_string(),
        };
        let bytes = encode_packet(&disconnect, version)?;
        let _ = writer.send(bytes).await;
        Ok(())
    }
}

pub(crate) fn kick_reason(reason: &str, version: ProtocolVersion) -> serde_json::Value {
    component_json(&parse_message(&format!("§c[Vine Proxy] {reason}")), version)
}
