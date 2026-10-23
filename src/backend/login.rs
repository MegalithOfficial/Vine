use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;
use tracing::{debug, warn};

use super::bridge::{BackendBridge, BridgeError};
use super::switch::SWITCH_ACK_TIMEOUT;
use crate::backend::forwarding::{
    ForwardingHelper, VELOCITY_PLAYER_INFO_CHANNEL, VINE_PLAYER_INFO_CHANNEL,
};
use crate::config::{BackendConfig, ForwardingMode};
use crate::network;
use crate::protocol::packets::handshake::{Handshake, HandshakeIntent};
use crate::protocol::packets::login::{
    LoginDisconnect, LoginPluginRequest, LoginPluginResponse, LoginStart, SetCompression,
};
use crate::protocol::{
    PacketKind, PacketReader, PacketWriter, ProtocolError, ProtocolVersion, decode_packet,
    encode_packet,
};
pub(super) type BackendReader = PacketReader<OwnedReadHalf>;
pub(super) type BackendWriter = PacketWriter<OwnedWriteHalf>;

impl BackendBridge {
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
    pub(super) async fn login_backend(
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
                    backend_writer.set_compression(threshold as usize, self.compression_level);
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

    /// Logs in to the next backend without touching the client, so the current one keeps running
    pub(super) async fn prepare_backend(
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
}

pub(super) struct PreparedBackend {
    pub(super) reader: BackendReader,
    pub(super) writer: BackendWriter,
    // Before 1.20.2: the packets the backend sent up to its JoinGame, and the JoinGame itself
    pub(super) join_game: Option<(Vec<Bytes>, crate::protocol::RawPacket)>,
}
