use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace};

use crate::bedrock::config::BedrockConfig;
use crate::bedrock::status::BedrockStatusHandler;
use crate::security::ConnectionRateLimiter;

const PONGS_PER_SEC_PER_IP: u32 = 2;
const PONG_BURST_PER_IP: u32 = 4;
const MAX_PONGS_PER_SEC: u32 = 500;

/// Runs the Bedrock UDP listener task.
pub async fn run_bedrock_listener(
    config: BedrockConfig,
    online_players: Arc<AtomicUsize>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_addr: SocketAddr = config.bind_address.parse()?;
    let socket = UdpSocket::bind(bind_addr).await?;
    let local_addr = socket.local_addr()?;

    info!("=====================================================");
    info!("  Vine Bedrock Listener is active on UDP {}", local_addr);
    info!(
        "  Bedrock Version: {} (Protocol {})",
        config.version_name, config.protocol_version
    );
    info!("=====================================================");

    let status_handler = BedrockStatusHandler::new(config, online_players, local_addr.port());
    let per_ip_limiter = ConnectionRateLimiter::new(true, PONGS_PER_SEC_PER_IP, PONG_BURST_PER_IP);
    let mut window_start = Instant::now();
    let mut pongs_in_window = 0u32;
    let mut buffer = [0u8; 2048];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buffer) => {
                match result {
                    Ok((length, peer_addr)) => {
                        let packet = &buffer[..length];
                        let now = Instant::now();
                        if now.duration_since(window_start) >= Duration::from_secs(1) {
                            window_start = now;
                            pongs_in_window = 0;
                        }
                        if pongs_in_window >= MAX_PONGS_PER_SEC
                            || !per_ip_limiter.check_connection(&peer_addr.ip())
                        {
                            trace!("[{}] Dropping rate limited Bedrock datagram", peer_addr);
                            continue;
                        }
                        if let Some(pong_bytes) = status_handler.handle_packet(packet) {
                            pongs_in_window += 1;
                            trace!("[{}] Received Bedrock status ping, sending pong ({} bytes)", peer_addr, pong_bytes.len());
                            if let Err(e) = socket.send_to(&pong_bytes, peer_addr).await {
                                debug!("[{}] Failed to send Bedrock pong: {}", peer_addr, e);
                            }
                        } else {
                            trace!("[{}] Received unrecognized Bedrock datagram ({} bytes)", peer_addr, length);
                        }
                    }
                    Err(e) => {
                        error!("Bedrock UDP receive error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Bedrock listener received shutdown signal, stopping...");
                break;
            }
        }
    }

    Ok(())
}
