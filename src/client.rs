use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::login::{
    CEncryptionRequest, CLoginDisconnect, CSetCompression,
};
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::java::server::handshake::SHandShake;
use pumpkin_protocol::java::server::login::{SEncryptionResponse, SLoginStart};
use pumpkin_protocol::java::server::status::SStatusPingRequest;
use pumpkin_protocol::{ClientPacket, ConnectionState, ServerPacket};
use pumpkin_util::version::JavaMinecraftVersion;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth::{AuthenticatedPlayer, Authenticator, KeyStore};
use crate::backend::{BackendBridge, Router};
use crate::command::CommandDispatcher;
use crate::config::Config;
use crate::network::PrefixedRead;
use crate::plugin::PluginManager;
use crate::plugin::api::{PlayerLoginEvent, PlayerPreLoginEvent, ProxyPingEvent};
use crate::security::Sanitizer;
use crate::session::SessionManager;
use crate::status::StatusHandler;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Client IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Protocol decode error: {0}")]
    DecodeError(String),
    #[error("Protocol encode error: {0}")]
    EncodeError(String),
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Bridge error: {0}")]
    BridgeError(#[from] crate::backend::BridgeError),
    #[error("Connection timed out")]
    Timeout,
}

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
        let reader = PrefixedRead::new(read_half, leftover_bytes);
        let mut decoder = TCPNetworkDecoder::new(reader);
        let mut encoder = TCPNetworkEncoder::new(write_half);

        let handshake_timeout =
            Duration::from_secs(self.config.network.client_handshake_timeout_secs);
        let raw_handshake = timeout(handshake_timeout, decoder.get_raw_packet())
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|e| ClientError::DecodeError(e.to_string()))?;

        let client_version_guess = JavaMinecraftVersion::V_26_2;
        let mut handshake_bytes = &raw_handshake.payload[..];
        let handshake = SHandShake::read(&mut handshake_bytes, &client_version_guess)
            .map_err(|e| ClientError::DecodeError(e.to_string()))?;

        let client_protocol = handshake.protocol_version.0 as u32;
        let client_version = JavaMinecraftVersion::from_protocol(client_protocol);
        let raw_host = &handshake.server_address;
        let clean_host = Sanitizer::sanitize_host(raw_host);

        debug!(
            "[{}] Handshake: protocol={}, resolved_version={:?}, host='{}', next_state={:?}",
            self.peer_addr, client_protocol, client_version, clean_host, handshake.next_state
        );

        match handshake.next_state {
            ConnectionState::Status => {
                if self.config.network.log_pings {
                    info!(
                        "[{}] Status ping: protocol={}, version={:?}, host='{}'",
                        self.peer_addr, client_protocol, client_version, clean_host
                    );
                }
                self.handle_status(&mut decoder, &mut encoder, client_version, &clean_host)
                    .await
            }
            ConnectionState::Login => {
                self.handle_login(
                    decoder,
                    encoder,
                    client_version,
                    clean_host,
                    self.peer_addr.ip(),
                )
                .await
            }
            other => {
                debug!(
                    "[{}] Unsupported handshake state: {:?}",
                    self.peer_addr, other
                );
                Ok(())
            }
        }
    }

    async fn handle_status(
        &self,
        decoder: &mut TCPNetworkDecoder<PrefixedRead<OwnedReadHalf>>,
        encoder: &mut TCPNetworkEncoder<OwnedWriteHalf>,
        client_version: JavaMinecraftVersion,
        virtual_host: &str,
    ) -> Result<(), ClientError> {
        let status_timeout = Duration::from_secs(self.config.network.client_status_timeout_secs);

        let raw_status = timeout(status_timeout, decoder.get_raw_packet())
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|e| ClientError::DecodeError(e.to_string()))?;

        if raw_status.id == 0x00 {
            let initial_motd = self.status_handler.resolve_motd_text(Some(virtual_host));
            let initial_online = self
                .online_players
                .load(std::sync::atomic::Ordering::Relaxed) as u32;
            let mut ping_event = ProxyPingEvent {
                client_ip: self.peer_addr.ip().to_string(),
                protocol_version: client_version.protocol_version() as u32,
                virtual_host: virtual_host.to_string(),
                motd: initial_motd,
                max_players: self.config.motd.max_players,
                online_players: initial_online,
                version_name: self.config.motd.version_name.clone(),
            };
            self.plugin_manager.fire_proxy_ping(&mut ping_event).await;

            let status_pkt = self.status_handler.create_custom_status_packet(
                client_version,
                &ping_event.motd,
                ping_event.max_players,
                ping_event.online_players,
                &ping_event.version_name,
                Some(virtual_host),
            );
            let status_bytes = status_pkt
                .serialize_packet(&client_version)
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
            encoder
                .write_packet(status_bytes)
                .await
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
            encoder
                .flush()
                .await
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
        }

        if let Ok(Ok(raw_ping)) = timeout(status_timeout, decoder.get_raw_packet()).await
            && raw_ping.id == 0x01
        {
            let mut ping_bytes = &raw_ping.payload[..];
            if let Ok(ping) = SStatusPingRequest::read(&mut ping_bytes, &client_version) {
                let pong_pkt = StatusHandler::create_pong_packet(ping.payload);
                let pong_bytes = pong_pkt
                    .serialize_packet(&client_version)
                    .map_err(|e| ClientError::EncodeError(e.to_string()))?;
                let _ = encoder.write_packet(pong_bytes).await;
                let _ = encoder.flush().await;
            }
        }

        Ok(())
    }

    async fn handle_login(
        &self,
        mut decoder: TCPNetworkDecoder<PrefixedRead<OwnedReadHalf>>,
        mut encoder: TCPNetworkEncoder<OwnedWriteHalf>,
        client_version: JavaMinecraftVersion,
        virtual_host: String,
        client_ip: IpAddr,
    ) -> Result<(), ClientError> {
        let login_timeout = Duration::from_secs(self.config.network.client_login_timeout_secs);

        let raw_login_start = timeout(login_timeout, decoder.get_raw_packet())
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|e| ClientError::DecodeError(e.to_string()))?;

        let mut login_start_bytes = &raw_login_start.payload[..];
        let login_start = SLoginStart::read(&mut login_start_bytes, &client_version)
            .map_err(|e| ClientError::DecodeError(e.to_string()))?;

        let username = login_start.name.to_string();

        let mut pre_login_event = PlayerPreLoginEvent {
            client_ip: client_ip.to_string(),
            username: username.clone(),
            protocol_version: client_version.protocol_version() as u32,
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
            Self::kick(&mut encoder, client_version, reason).await?;
            return Ok(());
        }

        if self.config.security.validate_usernames && !Sanitizer::is_valid_username(&username) {
            warn!(
                "[{}] Rejecting invalid username '{}' (failed sanitization)",
                self.peer_addr, username
            );
            Self::kick(
                &mut encoder,
                client_version,
                "Invalid username characters or length (must be 2-16 alphanumeric or _)",
            )
            .await?;
            return Ok(());
        }

        info!(
            "[{}] Player '{}' initiating login (version: {:?})",
            self.peer_addr, username, client_version
        );

        let authenticated_player = if self.config.server.online_mode {
            let verify_token: [u8; 4] = rand::random();
            let encryption_request =
                CEncryptionRequest::new("", self.keystore.public_key_der(), &verify_token, true);

            let enc_req_bytes = encryption_request
                .serialize_packet(&client_version)
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
            encoder
                .write_packet(enc_req_bytes)
                .await
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
            encoder
                .flush()
                .await
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;

            let raw_enc_resp = timeout(login_timeout, decoder.get_raw_packet())
                .await
                .map_err(|_| ClientError::Timeout)?
                .map_err(|e| ClientError::DecodeError(e.to_string()))?;

            let mut enc_resp_bytes = &raw_enc_resp.payload[..];
            let enc_resp = SEncryptionResponse::read(&mut enc_resp_bytes, &client_version)
                .map_err(|e| ClientError::DecodeError(e.to_string()))?;

            let decrypted_token = self
                .keystore
                .decrypt(&enc_resp.verify_token)
                .map_err(|e| ClientError::AuthError(e.to_string()))?;

            if decrypted_token != verify_token {
                warn!(
                    "[{}] Verify token mismatch for '{}'",
                    self.peer_addr, username
                );
                Self::kick(
                    &mut encoder,
                    client_version,
                    "Failed to verify encryption token",
                )
                .await?;
                return Err(ClientError::AuthError("Token mismatch".to_string()));
            }

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
                Self::kick(
                    &mut encoder,
                    client_version,
                    "Invalid encryption key length",
                )
                .await?;
                return Err(ClientError::AuthError("Invalid key length".to_string()));
            }

            let mut aes_key = [0u8; 16];
            aes_key.copy_from_slice(&shared_secret);

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
                    Self::kick(
                        &mut encoder,
                        client_version,
                        "Failed to verify username with Mojang session servers! Please try again later.",
                    )
                    .await?;
                    return Err(ClientError::AuthError(e.to_string()));
                }
            };

            decoder
                .set_encryption(&aes_key)
                .map_err(|e| ClientError::DecodeError(e.to_string()))?;
            encoder
                .set_encryption(&aes_key)
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;

            debug!(
                "[{}] Stream encryption enabled for player '{}' ({})",
                self.peer_addr, auth_player.username, auth_player.id
            );

            auth_player
        } else {
            AuthenticatedPlayer::offline(&username)
        };

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
            Self::kick(&mut encoder, client_version, reason).await?;
            return Ok(());
        }

        let comp_threshold = self.config.server.compression_threshold;
        if comp_threshold > 0 {
            let set_comp = CSetCompression::new(VarInt(comp_threshold));
            let comp_bytes = set_comp
                .serialize_packet(&client_version)
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
            encoder
                .write_packet(comp_bytes)
                .await
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;
            encoder
                .flush()
                .await
                .map_err(|e| ClientError::EncodeError(e.to_string()))?;

            decoder.set_compression(comp_threshold as usize);
            encoder.set_compression((
                comp_threshold as usize,
                self.config.server.compression_level as u32,
            ));
        }

        let (server_name, backend_cfg) = match self.router.resolve_server(&virtual_host) {
            Some(res) => res,
            None => {
                warn!(
                    "[{}] No backend server found for host '{}'",
                    self.peer_addr, virtual_host
                );
                Self::kick(
                    &mut encoder,
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

        bridge.run(decoder, encoder).await?;
        Ok(())
    }

    /// Helper to send formatted CLoginDisconnect packet to client
    async fn kick(
        encoder: &mut TCPNetworkEncoder<OwnedWriteHalf>,
        version: JavaMinecraftVersion,
        reason: &str,
    ) -> Result<(), ClientError> {
        let disconnect = CLoginDisconnect::new(kick_reason_json(reason));
        let bytes = disconnect
            .serialize_packet(&version)
            .map_err(|e| ClientError::EncodeError(e.to_string()))?;
        let _ = encoder.write_packet(bytes).await;
        let _ = encoder.flush().await;
        Ok(())
    }
}

pub(crate) fn kick_reason_json(reason: &str) -> String {
    serde_json::json!({
        "text": format!("[Vine Proxy] {reason}"),
        "color": "red",
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kick_reason_json_escapes_special_characters() {
        let reason = "bad \\ \"quote\"\nnext line";
        let json = kick_reason_json(reason);

        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["text"], format!("[Vine Proxy] {reason}"));
        assert_eq!(parsed["color"], "red");
    }
}
