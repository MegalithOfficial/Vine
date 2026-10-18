use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type PluginFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub authors: Vec<String>,
    pub description: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventPriority {
    Lowest = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Highest = 4,
    Monitor = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    ProxyPing,
    PlayerPreLogin,
    PlayerLogin,
    PlayerJoin,
    ServerConnect,
    ServerConnected,
    PlayerDisconnect,
    PlayerChat,
    PlayerCommand,
    PluginMessage,
}

#[derive(Debug, Clone)]
pub struct ProxyPingEvent {
    pub client_ip: String,
    pub protocol_version: u32,
    pub virtual_host: String,
    pub motd: String,
    pub max_players: u32,
    pub online_players: u32,
    pub version_name: String,
}

#[derive(Debug, Clone)]
pub struct PlayerPreLoginEvent {
    pub client_ip: String,
    pub username: String,
    pub protocol_version: u32,
    pub virtual_host: String,
    pub cancelled: bool,
    pub cancel_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlayerLoginEvent {
    pub uuid: String,
    pub username: String,
    pub client_ip: String,
    pub cancelled: bool,
    pub cancel_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlayerJoinEvent {
    pub uuid: String,
    pub username: String,
    pub client_ip: String,
    pub initial_server: String,
}

#[derive(Debug, Clone)]
pub struct ServerConnectEvent {
    pub uuid: String,
    pub username: String,
    pub current_server: Option<String>,
    pub target_server: String,
    pub cancelled: bool,
    pub cancel_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServerConnectedEvent {
    pub uuid: String,
    pub username: String,
    pub server_name: String,
}

#[derive(Debug, Clone)]
pub struct PlayerDisconnectEvent {
    pub uuid: String,
    pub username: String,
    pub last_server: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlayerChatEvent {
    pub uuid: String,
    pub username: String,
    pub message: String,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct PlayerCommandEvent {
    pub uuid: String,
    pub username: String,
    pub command: String,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct PluginMessageEvent {
    pub channel: String,
    pub data: Vec<u8>,
    pub player_uuid: Option<String>,
    pub server_name: Option<String>,
    pub source: PluginMessageSource,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginMessageSource {
    Player,
    Server,
}

pub struct PluginContext {
    pub metadata: PluginMetadata,
    pub data_folder: PathBuf,
    pub registered_commands: Mutex<Vec<u32>>,
    pub registered_events: Mutex<Vec<(u32, EventType, EventPriority)>>,
}

impl PluginContext {
    #[must_use]
    pub fn new(metadata: PluginMetadata, data_folder: PathBuf) -> Self {
        Self {
            metadata,
            data_folder,
            registered_commands: Mutex::new(Vec::new()),
            registered_events: Mutex::new(Vec::new()),
        }
    }
}

pub trait Plugin: Send + Sync {
    fn on_load(&self, context: Arc<PluginContext>) -> PluginFuture<'_, Result<(), String>>;
    fn on_unload(&self, context: Arc<PluginContext>) -> PluginFuture<'_, Result<(), String>>;
}
