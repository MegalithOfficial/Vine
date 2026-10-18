use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::bedrock::config::BedrockConfig;
use crate::protocol::bedrock::{OFFLINE_MAGIC, UnconnectedPing, encode_unconnected_pong};
use crate::protocol::text::legacy_message;

/// Handler for Bedrock RakNet status pings.
pub struct BedrockStatusHandler {
    config: BedrockConfig,
    online_players: Arc<AtomicUsize>,
    server_guid: u64,
    ipv4_port: u16,
    ipv6_port: u16,
}

impl BedrockStatusHandler {
    pub fn new(config: BedrockConfig, online_players: Arc<AtomicUsize>, ipv4_port: u16) -> Self {
        let server_guid = if config.server_guid != 0 {
            config.server_guid
        } else {
            rand::random()
        };
        let ipv6_port = ipv4_port.saturating_add(1);

        Self {
            config,
            online_players,
            server_guid,
            ipv4_port,
            ipv6_port,
        }
    }

    /// Formats the official Bedrock MCPE advertisement string
    pub fn build_advertisement_string(&self) -> String {
        let online = self.online_players.load(Ordering::Relaxed) as i32;

        format!(
            "MCPE;{};{};{};{};{};{};{};{};{};{};{};0;",
            legacy_message(&self.config.motd),
            self.config.protocol_version,
            self.config.version_name,
            online,
            self.config.max_players,
            self.server_guid,
            self.config.level_name,
            self.config.game_mode,
            self.config.game_mode_id,
            self.ipv4_port,
            self.ipv6_port,
        )
    }

    /// Inspects an incoming UDP datagram and, if it is an unconnected ping, builds the pong response.
    pub fn handle_packet(&self, data: &[u8]) -> Option<Vec<u8>> {
        let ping = UnconnectedPing::parse(data)?;
        if ping.magic != OFFLINE_MAGIC {
            return None;
        }
        encode_unconnected_pong(
            ping.time,
            self.server_guid,
            self.build_advertisement_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::bedrock::{UNCONNECTED_PING_ID, UNCONNECTED_PONG_ID};

    #[test]
    fn test_build_advertisement_string() {
        let config = BedrockConfig {
            enabled: true,
            bind_address: "0.0.0.0:19132".to_string(),
            motd: "Vine Server\nBedrock Proxy".to_string(),
            protocol_version: 2169,
            version_name: "1.26.45".to_string(),
            level_name: "Lobby".to_string(),
            game_mode: "Survival".to_string(),
            game_mode_id: 0,
            max_players: 50,
            server_guid: 12345,
        };

        let online = Arc::new(AtomicUsize::new(3));
        let handler = BedrockStatusHandler::new(config, online, 19132);
        let ad = handler.build_advertisement_string();

        assert!(ad.starts_with("MCPE;Vine Server\nBedrock Proxy;2169;1.26.45;3;50;12345;Lobby;Survival;0;19132;19133;0;"));
    }

    #[test]
    fn test_handle_unconnected_ping() {
        let config = BedrockConfig::default();
        let online = Arc::new(AtomicUsize::new(0));
        let handler = BedrockStatusHandler::new(config, online, 19132);

        let mut packet = vec![UNCONNECTED_PING_ID];
        packet.extend_from_slice(&1000u64.to_be_bytes());
        packet.extend_from_slice(&OFFLINE_MAGIC);
        packet.extend_from_slice(&9999u64.to_be_bytes());

        let response = handler.handle_packet(&packet);
        assert!(response.is_some());
        let res_bytes = response.unwrap();
        assert_eq!(res_bytes[0], UNCONNECTED_PONG_ID);
        assert_eq!(&res_bytes[1..9], &1000u64.to_be_bytes());
        assert_eq!(&res_bytes[17..33], &OFFLINE_MAGIC);
    }

    #[test]
    fn test_ignore_invalid_magic() {
        let config = BedrockConfig::default();
        let online = Arc::new(AtomicUsize::new(0));
        let handler = BedrockStatusHandler::new(config, online, 19132);

        let mut packet = vec![UNCONNECTED_PING_ID];
        packet.extend_from_slice(&1000u64.to_be_bytes());
        packet.extend_from_slice(&[0u8; 16]);
        packet.extend_from_slice(&9999u64.to_be_bytes());

        let response = handler.handle_packet(&packet);
        assert!(response.is_none());
    }
}
