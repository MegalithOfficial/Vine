pub mod icon;

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use crate::config::{BackendConfig, MotdConfig};
use crate::protocol::ProtocolVersion;
use crate::protocol::packets::status::StatusResponse;
use crate::protocol::text::{component_json, parse_message};
use tracing::warn;

const MAX_STATUS_LEN: usize = 32767;
pub use icon::StatusIconManager;

#[derive(Serialize)]
struct StatusJson<'a> {
    version: StatusVersion<'a>,
    players: StatusPlayers<'a>,
    description: serde_json::Value,
    #[serde(rename = "enforceSecureChat")]
    enforce_secure_chat: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    favicon: Option<&'a str>,
}

#[derive(Serialize)]
struct StatusVersion<'a> {
    name: &'a str,
    protocol: i32,
}

#[derive(Serialize)]
struct StatusPlayers<'a> {
    max: u32,
    online: usize,
    sample: Vec<PlayerSample<'a>>,
}

#[derive(Serialize)]
struct PlayerSample<'a> {
    name: &'a str,
    id: String,
}

pub struct StatusHandler {
    motd: MotdConfig,
    icon_manager: Arc<StatusIconManager>,
    servers: HashMap<String, BackendConfig>,
    forced_hosts: HashMap<String, String>,
}

impl StatusHandler {
    pub fn new(
        motd: MotdConfig,
        icon_manager: Arc<StatusIconManager>,
        servers: HashMap<String, BackendConfig>,
        forced_hosts: HashMap<String, String>,
    ) -> Self {
        Self {
            motd,
            icon_manager,
            servers,
            forced_hosts,
        }
    }

    /// Resolves MOTD description for the virtual host or falls back to global default
    pub fn resolve_motd_text(&self, host: Option<&str>) -> String {
        if let Some(h) = host {
            let normalized = crate::config::normalize_host(h);
            let clean_host = normalized.as_str();

            let target_server: Option<&str> = self
                .forced_hosts
                .get(clean_host)
                .map(|s| s.as_str())
                .or_else(|| {
                    if self.servers.contains_key(clean_host) {
                        Some(clean_host)
                    } else {
                        None
                    }
                });

            if let Some(server_name) = target_server
                && let Some(cfg) = self.servers.get(server_name)
                && let Some(motd) = &cfg.motd
            {
                return motd.clone();
            }
        }

        self.motd.text.clone()
    }

    /// Create custom status response with overridden fields from plugins
    pub fn create_custom_status_packet(
        &self,
        client_version: ProtocolVersion,
        motd: &str,
        max_players: u32,
        online_players: u32,
        version_name: &str,
        virtual_host: Option<&str>,
    ) -> StatusResponse {
        let protocol = if client_version.is_known() {
            client_version.0 as i32
        } else {
            self.motd.protocol_version
        };

        let icon_uri = self.icon_manager.get_icon_for_host(virtual_host);

        let sample: Vec<PlayerSample> = if self.motd.show_sample_players {
            self.motd
                .sample_players
                .iter()
                .map(|name| PlayerSample {
                    name,
                    id: Uuid::nil().to_string(),
                })
                .collect()
        } else {
            Vec::new()
        };

        let status = StatusJson {
            version: StatusVersion {
                name: version_name,
                protocol,
            },
            players: StatusPlayers {
                max: max_players,
                online: online_players as usize,
                sample,
            },
            description: component_json(&parse_message(motd), client_version),
            enforce_secure_chat: false,
            favicon: icon_uri.as_deref(),
        };

        let mut json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
        // Clients reject a status response longer than this, so the icon is the first to go
        if json.encode_utf16().count() > MAX_STATUS_LEN && status.favicon.is_some() {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                warn!("The status response is too long for clients; sending it without the icon");
            }
            json = serde_json::to_string(&StatusJson {
                favicon: None,
                ..status
            })
            .unwrap_or_else(|_| "{}".to_string());
        }
        StatusResponse { json }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ForwardingMode;

    #[test]
    fn test_status_response_with_icon_and_virtual_hosts() {
        let temp_icon_path = std::env::temp_dir().join("vine_test_status_icon.png");
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&crate::status::icon::PNG_SIGNATURE);
        png_bytes.extend_from_slice(&13u32.to_be_bytes());
        png_bytes.extend_from_slice(b"IHDR");
        png_bytes.extend_from_slice(&64u32.to_be_bytes());
        png_bytes.extend_from_slice(&64u32.to_be_bytes());
        png_bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        let _ = std::fs::write(&temp_icon_path, png_bytes);

        let icon_path_str = temp_icon_path.to_string_lossy().to_string();

        let mut servers = HashMap::new();
        servers.insert(
            "survival".to_string(),
            BackendConfig {
                address: "127.0.0.1:25567".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                icon_path: None,
                motd: Some("Survival Line 1\nSurvival Line 2".to_string()),
            },
        );

        let mut forced_hosts = HashMap::new();
        forced_hosts.insert("mc.survival.com".to_string(), "survival".to_string());

        let icon_mgr = Arc::new(StatusIconManager::new(
            Some(icon_path_str.clone()),
            HashMap::new(),
            forced_hosts.clone(),
            "lobby".to_string(),
        ));

        let motd = MotdConfig {
            text: "Global Line 1\nGlobal Line 2".to_string(),
            max_players: 50,
            version_name: "Vine Proxy".to_string(),
            protocol_version: 776,
            sample_players: vec!["SamplePlayer".to_string()],
            icon_path: Some(icon_path_str),
            show_sample_players: true,
        };

        let handler = StatusHandler::new(motd, icon_mgr, servers, forced_hosts);

        let global = handler.create_custom_status_packet(
            ProtocolVersion(776),
            &handler.resolve_motd_text(None),
            50,
            5,
            "Vine Proxy",
            None,
        );
        assert!(global.json.contains("Global Line 1\\nGlobal Line 2"));
        assert!(global.json.contains("\"favicon\":\"data:image/png;base64,"));

        assert_eq!(
            handler.resolve_motd_text(Some("mc.survival.com")),
            "Survival Line 1\nSurvival Line 2"
        );

        let _ = std::fs::remove_file(&temp_icon_path);
    }
}
