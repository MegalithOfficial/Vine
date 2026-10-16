use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write, path::Path};

fn default_true() -> bool {
    true
}

fn default_compression_level() -> i32 {
    6
}

fn default_shutdown_timeout() -> u64 {
    10
}

fn default_tcp_keepalive() -> u64 {
    60
}

fn default_handshake_timeout() -> u64 {
    10
}

fn default_status_timeout() -> u64 {
    5
}

fn default_login_timeout() -> u64 {
    15
}

fn default_backend_connect_timeout() -> u64 {
    5
}

fn default_backend_login_timeout() -> u64 {
    15
}

fn default_backend_retries() -> u32 {
    2
}

fn default_listen_backlog() -> u32 {
    1024
}

const LEGACY_PLACEHOLDER_SECRET: &str = "vine-velocity-secret-change-me";
const FORWARDING_SECRET_ENV: &str = "VINE_FORWARDING_SECRET";

fn default_forwarding_secret_file() -> String {
    "forwarding.secret".to_string()
}

fn generate_forwarding_secret() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    pub motd: MotdConfig,
    pub security: SecurityConfig,
    pub routing: RoutingConfig,
    pub servers: HashMap<String, BackendConfig>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub bedrock: crate::bedrock::BedrockConfig,
    #[serde(default)]
    pub permissions: PermissionsConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_plugins_dir")]
    pub plugin_dir: String,
}

fn default_plugins_dir() -> String {
    "./plugins".to_string()
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            plugin_dir: default_plugins_dir(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address and port for the proxy to listen on
    pub bind_address: String,
    /// Whether to verify player accounts with Mojang session servers
    pub online_mode: bool,
    /// Send player IP to Mojang during session authentication to prevent proxy hijacking
    pub prevent_proxy_connections: bool,
    /// Packet compression threshold (-1 to disable, e.g. 256 for standard compression)
    pub compression_threshold: i32,
    /// zlib / flate2 compression level (1 = fastest, 6 = default balance, 9 = best compression)
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,
    /// Graceful shutdown timeout in seconds to wait for active connections to close
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
    /// Shared secret for velocity and vine backends without their own `secret`
    #[serde(default = "default_forwarding_secret_file")]
    pub forwarding_secret_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable TCP_NODELAY (disable Nagle's algorithm) on client and backend sockets.
    /// Crucial for eliminating latency spikes in Minecraft packet transmission.
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,

    /// TCP keepalive interval in seconds on client and backend sockets (0 to disable).
    #[serde(default = "default_tcp_keepalive")]
    pub tcp_keepalive_secs: u64,

    /// Timeout in seconds to wait for initial client Handshake packet
    #[serde(default = "default_handshake_timeout")]
    pub client_handshake_timeout_secs: u64,

    /// Timeout in seconds to wait for client Status/Ping packets
    #[serde(default = "default_status_timeout")]
    pub client_status_timeout_secs: u64,

    /// Timeout in seconds to wait for client LoginStart and Encryption packets
    #[serde(default = "default_login_timeout")]
    pub client_login_timeout_secs: u64,

    /// Timeout in seconds when connecting to a backend server
    #[serde(default = "default_backend_connect_timeout")]
    pub backend_connect_timeout_secs: u64,

    /// Timeout in seconds for backend socket reads during the login handshake phase
    #[serde(default = "default_backend_login_timeout")]
    pub backend_login_timeout_secs: u64,

    /// Number of connection retry attempts when connecting to a backend server before failing
    #[serde(default = "default_backend_retries")]
    pub backend_connect_retry_attempts: u32,

    /// Optional TCP receive buffer size (SO_RCVBUF) in bytes
    #[serde(default)]
    pub recv_buffer_size: Option<usize>,

    /// Optional TCP send buffer size (SO_SNDBUF) in bytes
    #[serde(default)]
    pub send_buffer_size: Option<usize>,

    /// TCP listen backlog queue size
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: u32,

    /// Support HAProxy PROXY Protocol (v1 and v2) from upstream reverse proxies (e.g. Cloudflare Spectrum, HAProxy)
    #[serde(default)]
    pub proxy_protocol: bool,

    /// IPs or CIDR ranges allowed to send PROXY headers; empty accepts any peer
    #[serde(default)]
    pub proxy_protocol_trusted_proxies: Vec<String>,

    /// Log incoming server list status pings in the console
    #[serde(default)]
    pub log_pings: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tcp_nodelay: default_true(),
            tcp_keepalive_secs: default_tcp_keepalive(),
            client_handshake_timeout_secs: default_handshake_timeout(),
            client_status_timeout_secs: default_status_timeout(),
            client_login_timeout_secs: default_login_timeout(),
            backend_connect_timeout_secs: default_backend_connect_timeout(),
            backend_login_timeout_secs: default_backend_login_timeout(),
            backend_connect_retry_attempts: default_backend_retries(),
            recv_buffer_size: None,
            send_buffer_size: None,
            listen_backlog: default_listen_backlog(),
            proxy_protocol: false,
            proxy_protocol_trusted_proxies: Vec::new(),
            log_pings: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MotdConfig {
    /// Line 1 of the server list ping description
    pub line1: String,
    /// Line 2 of the server list ping description
    pub line2: String,
    /// Maximum players shown in the server list ping
    pub max_players: u32,
    /// Custom version display string (e.g. "Vine 1.7.x - 26.x")
    pub version_name: String,
    /// Protocol version reported to clients (776 is 26.2)
    pub protocol_version: i32,
    /// Optional sample player list shown on hover in server list
    pub sample_players: Vec<String>,
    /// Optional path to a 64x64 PNG file for the server list icon (favicons)
    #[serde(default)]
    pub icon_path: Option<String>,
    /// Whether to show the player sample list on hover in the multiplayer menu
    #[serde(default = "default_true")]
    pub show_sample_players: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable connection rate limiting per IP
    pub rate_limit_enabled: bool,
    /// Maximum new TCP connections per second per IP
    pub max_connections_per_sec: u32,
    /// Burst allowance for new connections
    pub connection_burst: u32,
    /// Maximum packets per second from a single client before being kicked for flooding
    pub max_packets_per_sec: u32,
    /// Maximum raw packet size allowed in bytes (default 2MB)
    pub max_packet_size: usize,
    /// Enforce strict Minecraft username validation (^[a-zA-Z0-9_]{2,16}$)
    pub validate_usernames: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Default backend server name to connect to
    pub default_server: String,
    /// Fallback server if default server is offline
    pub fallback_server: Option<String>,
    /// Virtual host routing: maps domain/hostname to backend server name
    pub forced_hosts: HashMap<String, String>,
    /// Automatically try fallback server if connection to target server fails
    #[serde(default = "default_true")]
    pub try_fallback_on_connect_failure: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingMode {
    /// Plain connection without forwarding info (for Vanilla servers in offline-mode)
    None,
    /// BungeeCord IP forwarding (for Bukkit, Spigot, PaperMC with bungeecord: true)
    BungeeCord,
    /// Velocity modern forwarding with HMAC-SHA256 secret (for PaperMC, Purpur, Pumpkin)
    Velocity,
    /// Vine modern forwarding with Ed25519 asymmetric signatures, timestamp, and challenge nonce (for Pumpkin)
    Vine,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Address of backend server (e.g. "127.0.0.1:25566")
    pub address: String,
    /// Forwarding mode to use when connecting to this backend
    pub forwarding: ForwardingMode,
    /// Secret key required if forwarding mode is Velocity
    pub secret: Option<String>,
    /// Optional custom 64x64 PNG status icon path for this backend / virtual host
    #[serde(default)]
    pub icon_path: Option<String>,
    /// Optional custom MOTD Line 1 for this backend / virtual host
    #[serde(default)]
    pub motd_line1: Option<String>,
    /// Optional custom MOTD Line 2 for this backend / virtual host
    #[serde(default)]
    pub motd_line2: Option<String>,
}

fn default_telemetry_interval() -> u64 {
    300
}

fn default_telemetry_endpoint() -> String {
    "https://market.pumpkinmc.org/api/v1/rest/telemetry/heartbeat".to_string()
}

/// Telemetry configuration options.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether anonymous telemetry is enabled (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Custom telemetry backend ingestion endpoint
    #[serde(default = "default_telemetry_endpoint")]
    pub endpoint: String,
    /// Heartbeat interval in seconds (default: 300 seconds / 5 minutes). Minimum 60s.
    #[serde(default = "default_telemetry_interval")]
    pub interval_secs: u64,
    /// Whether to opt-in to displaying this proxy in the public community directory.
    #[serde(default)]
    pub public: bool,
    /// Public server/proxy name displayed on the analytics dashboard if public is true.
    #[serde(default)]
    pub server_name: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: default_telemetry_endpoint(),
            interval_secs: 300,
            public: false,
            server_name: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut servers = HashMap::new();
        servers.insert(
            "lobby".to_string(),
            BackendConfig {
                address: "127.0.0.1:25566".to_string(),
                forwarding: ForwardingMode::Velocity,
                secret: None,
                icon_path: None,
                motd_line1: None,
                motd_line2: None,
            },
        );
        servers.insert(
            "survival".to_string(),
            BackendConfig {
                address: "127.0.0.1:25567".to_string(),
                forwarding: ForwardingMode::BungeeCord,
                secret: None,
                icon_path: None,
                motd_line1: Some("§b§lVine Survival §7» §fWelcome back!".to_string()),
                motd_line2: Some("§7Custom world • Economy • Land Claims".to_string()),
            },
        );
        servers.insert(
            "vanilla".to_string(),
            BackendConfig {
                address: "127.0.0.1:25568".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                icon_path: None,
                motd_line1: None,
                motd_line2: None,
            },
        );

        let mut forced_hosts = HashMap::new();
        forced_hosts.insert("survival.example.com".to_string(), "survival".to_string());
        forced_hosts.insert("vanilla.example.com".to_string(), "vanilla".to_string());

        Self {
            server: ServerConfig {
                bind_address: "0.0.0.0:25565".to_string(),
                online_mode: true,
                prevent_proxy_connections: true,
                compression_threshold: 256,
                compression_level: 6,
                shutdown_timeout_secs: 10,
                forwarding_secret_file: default_forwarding_secret_file(),
            },
            network: NetworkConfig::default(),
            motd: MotdConfig {
                line1: "§a§lVine §7» §fHigh-Performance Minecraft Proxy".to_string(),
                line2: "§7Multi-version support §8• §e1.7.x - 26.x".to_string(),
                max_players: 100,
                version_name: "Vine 1.7.x - 26.x".to_string(),
                protocol_version: 776,
                sample_players: vec![
                    "§aVine Multi-Version Proxy".to_string(),
                    "§7Secure • Fast • Reliable".to_string(),
                ],
                icon_path: None,
                show_sample_players: true,
            },
            security: SecurityConfig {
                rate_limit_enabled: true,
                max_connections_per_sec: 5,
                connection_burst: 10,
                max_packets_per_sec: 500,
                max_packet_size: 2 * 1024 * 1024,
                validate_usernames: true,
            },
            routing: RoutingConfig {
                default_server: "lobby".to_string(),
                fallback_server: Some("survival".to_string()),
                forced_hosts,
                try_fallback_on_connect_failure: true,
            },
            servers,
            telemetry: TelemetryConfig::default(),
            bedrock: crate::bedrock::BedrockConfig::default(),
            permissions: PermissionsConfig::default(),
            plugins: PluginConfig::default(),
        }
    }
}

pub use crate::permissions::{GroupConfig, PermissionsConfig, UserPermissionConfig};

pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn needs_shared_secret(server: &BackendConfig) -> bool {
    matches!(
        server.forwarding,
        ForwardingMode::Velocity | ForwardingMode::Vine
    ) && server.secret.as_deref().is_none_or(|s| s.trim().is_empty())
}

fn load_or_create_secret_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(path) {
        Ok(content) if content.trim().is_empty() => {
            Err(format!("forwarding secret file '{}' is empty", path.display()).into())
        }
        Ok(content) => Ok(content.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let secret = generate_forwarding_secret();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options.open(path)?.write_all(secret.as_bytes())?;
            tracing::info!(
                "Generated a new forwarding secret in '{}'; use it as proxies.velocity.secret in each Paper backend",
                path.display()
            );
            Ok(secret)
        }
        Err(e) => Err(format!(
            "failed to read forwarding secret file '{}': {e}",
            path.display()
        )
        .into()),
    }
}

impl Config {
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = path.as_ref();
        let mut config = if path.exists() {
            toml::from_str(&std::fs::read_to_string(path)?)?
        } else {
            let default_config = Config::default();
            std::fs::write(path, toml::to_string_pretty(&default_config)?)?;
            default_config
        };
        config.routing.forced_hosts = std::mem::take(&mut config.routing.forced_hosts)
            .into_iter()
            .map(|(host, server)| (normalize_host(&host), server))
            .collect();
        let env_secret = std::env::var(FORWARDING_SECRET_ENV).ok();
        config.resolve_forwarding_secret(path.parent().unwrap_or(Path::new("")), env_secret)?;
        config.validate()?;
        Ok(config)
    }

    fn resolve_forwarding_secret(
        &mut self,
        config_dir: &Path,
        env_secret: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.servers.values().any(needs_shared_secret) {
            return Ok(());
        }
        let secret = match env_secret.as_deref().map(str::trim) {
            Some(secret) if !secret.is_empty() => secret.to_string(),
            _ => load_or_create_secret_file(&config_dir.join(&self.server.forwarding_secret_file))?,
        };
        for server in self.servers.values_mut().filter(|s| needs_shared_secret(s)) {
            server.secret = Some(secret.clone());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        for entry in &self.network.proxy_protocol_trusted_proxies {
            if crate::network::IpRange::parse(entry).is_none() {
                return Err(format!(
                    "invalid entry '{entry}' in network.proxy_protocol_trusted_proxies"
                ));
            }
        }
        for (name, server) in &self.servers {
            if !matches!(
                server.forwarding,
                ForwardingMode::Velocity | ForwardingMode::Vine
            ) {
                continue;
            }
            let secret = server.secret.as_deref().map(str::trim).unwrap_or_default();
            if secret.is_empty() {
                return Err(format!(
                    "server '{name}' uses {:?} forwarding but has no secret configured",
                    server.forwarding
                ));
            }
            if secret == LEGACY_PLACEHOLDER_SECRET {
                return Err(format!(
                    "server '{name}' still uses the default placeholder forwarding secret; replace it with a random value"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret_file_is_generated_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Config::default();
        a.resolve_forwarding_secret(dir.path(), None).unwrap();
        assert!(a.validate().is_ok());

        let path = dir.path().join("forwarding.secret");
        let secret = std::fs::read_to_string(&path).unwrap();
        assert_eq!(secret.len(), 64);
        assert_eq!(a.servers["lobby"].secret.as_deref(), Some(secret.as_str()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let mut b = Config::default();
        b.resolve_forwarding_secret(dir.path(), None).unwrap();
        assert_eq!(b.servers["lobby"].secret, a.servers["lobby"].secret);
    }

    #[test]
    fn test_validate_rejects_placeholder_and_missing_secrets() {
        let mut config = Config::default();
        config.servers.get_mut("lobby").unwrap().secret =
            Some(LEGACY_PLACEHOLDER_SECRET.to_string());
        assert!(config.validate().is_err());

        config.servers.get_mut("lobby").unwrap().secret = Some("  ".to_string());
        assert!(config.validate().is_err());

        config.servers.get_mut("lobby").unwrap().secret = None;
        assert!(config.validate().is_err());

        config.servers.get_mut("lobby").unwrap().forwarding = ForwardingMode::None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_telemetry_config_defaults() {
        let default_config = TelemetryConfig::default();
        assert!(default_config.enabled);
        assert_eq!(
            default_config.endpoint,
            "https://market.pumpkinmc.org/api/v1/rest/telemetry/heartbeat"
        );
        assert_eq!(default_config.interval_secs, 300);
        assert!(!default_config.public);
        assert_eq!(default_config.server_name, None);
    }

    #[test]
    fn test_telemetry_toml_deserialization() {
        let toml_str = r#"
            enabled = false
            endpoint = "http://localhost:5000/api/v1/rest/telemetry/heartbeat"
            interval_secs = 120
            public = true
            server_name = "Vine Proxy Hub"
        "#;

        let config: TelemetryConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        assert_eq!(
            config.endpoint,
            "http://localhost:5000/api/v1/rest/telemetry/heartbeat"
        );
        assert_eq!(config.interval_secs, 120);
        assert!(config.public);
        assert_eq!(config.server_name.as_deref(), Some("Vine Proxy Hub"));
    }
}
