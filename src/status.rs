pub mod icon;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Serialize;
use uuid::Uuid;

use crate::config::{BackendConfig, MotdConfig};
use crate::protocol::ProtocolVersion;
use crate::protocol::packets::status::StatusResponse;
pub use icon::StatusIconManager;

#[derive(Serialize)]
struct StatusJson<'a> {
    version: StatusVersion<'a>,
    players: StatusPlayers<'a>,
    description: StatusDescription,
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

#[derive(Serialize)]
struct StatusDescription {
    text: String,
}

pub struct StatusHandler {
    motd: MotdConfig,
    online_players: Arc<AtomicUsize>,
    icon_manager: Arc<StatusIconManager>,
    servers: HashMap<String, BackendConfig>,
    forced_hosts: HashMap<String, String>,
}

impl StatusHandler {
    pub fn new(
        motd: MotdConfig,
        online_players: Arc<AtomicUsize>,
        icon_manager: Arc<StatusIconManager>,
        servers: HashMap<String, BackendConfig>,
        forced_hosts: HashMap<String, String>,
    ) -> Self {
        Self {
            motd,
            online_players,
            icon_manager,
            servers,
            forced_hosts,
        }
    }

    /// Build the JSON status response for the given client version and optional virtual host
    pub fn build_status_response(
        &self,
        client_version: ProtocolVersion,
        virtual_host: Option<&str>,
    ) -> String {
        let online = self.online_players.load(Ordering::Relaxed);

        let motd_text = self.resolve_motd_text(virtual_host);

        let icon_uri = self.icon_manager.get_icon_for_host(virtual_host);

        let protocol = if client_version.is_known() {
            client_version.0 as i32
        } else {
            self.motd.protocol_version
        };

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
                name: &self.motd.version_name,
                protocol,
            },
            players: StatusPlayers {
                max: self.motd.max_players,
                online,
                sample,
            },
            description: StatusDescription { text: motd_text },
            enforce_secure_chat: false,
            favicon: icon_uri.as_deref(),
        };

        serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string())
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
                && (cfg.motd_line1.is_some() || cfg.motd_line2.is_some())
            {
                let l1 = cfg.motd_line1.as_deref().unwrap_or(&self.motd.line1);
                let l2 = cfg.motd_line2.as_deref().unwrap_or(&self.motd.line2);
                return format!("{}\n{}", l1, l2);
            }
        }

        format!("{}\n{}", self.motd.line1, self.motd.line2)
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
            description: StatusDescription {
                text: motd.to_string(),
            },
            enforce_secure_chat: false,
            favicon: icon_uri.as_deref(),
        };

        let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
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
                motd_line1: Some("Survival Line 1".to_string()),
                motd_line2: Some("Survival Line 2".to_string()),
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
            line1: "Global Line 1".to_string(),
            line2: "Global Line 2".to_string(),
            max_players: 50,
            version_name: "Vine Proxy".to_string(),
            protocol_version: 776,
            sample_players: vec!["SamplePlayer".to_string()],
            icon_path: Some(icon_path_str),
            show_sample_players: true,
        };

        let online = Arc::new(AtomicUsize::new(5));
        let handler = StatusHandler::new(motd, online, icon_mgr, servers, forced_hosts);

        let global_json = handler.build_status_response(ProtocolVersion(776), None);
        assert!(global_json.contains("Global Line 1\\nGlobal Line 2"));
        assert!(global_json.contains("\"online\":5"));
        assert!(global_json.contains("\"favicon\":\"data:image/png;base64,"));

        let vhost_json =
            handler.build_status_response(ProtocolVersion(776), Some("mc.survival.com"));
        assert!(vhost_json.contains("Survival Line 1\\nSurvival Line 2"));

        let _ = std::fs::remove_file(&temp_icon_path);
    }

    #[test]
    fn test_status_response_default_without_icon() {
        let icon_mgr = Arc::new(StatusIconManager::new(
            None,
            HashMap::new(),
            HashMap::new(),
            "lobby".to_string(),
        ));

        let motd = MotdConfig {
            line1: "Vine Proxy".to_string(),
            line2: "No Icon".to_string(),
            max_players: 20,
            version_name: "Vine".to_string(),
            protocol_version: 776,
            sample_players: Vec::new(),
            icon_path: None,
            show_sample_players: false,
        };

        let online = Arc::new(AtomicUsize::new(0));
        let handler = StatusHandler::new(motd, online, icon_mgr, HashMap::new(), HashMap::new());

        let json = handler.build_status_response(ProtocolVersion(776), None);
        assert!(!json.contains("favicon"));
    }
}
