use serde::{Deserialize, Serialize};

/// Configuration options for Bedrock Edition support.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct BedrockConfig {
    /// Whether Bedrock Edition listener and status response are enabled
    pub enabled: bool,
    /// UDP address and port for the Bedrock listener (default Minecraft Bedrock port is 19132)
    pub bind_address: String,
    /// Server list description; use \n for a second line
    pub motd: String,
    /// Protocol version advertised (2169 corresponds to Bedrock 1.26.45)
    pub protocol_version: u32,
    /// Bedrock version string advertised (e.g. "1.26.45")
    pub version_name: String,
    /// Level / world name displayed in Bedrock client ping
    pub level_name: String,
    /// Game mode displayed in Bedrock client ping ("Survival", "Creative", etc.)
    pub game_mode: String,
    /// Game mode ID (0 = Survival, 1 = Creative, 2 = Adventure, 3 = Spectator)
    pub game_mode_id: u32,
    /// Maximum Bedrock players displayed in ping (0 to inherit global server max_players)
    pub max_players: u32,
    /// Server GUID for RakNet (0 automatically generates a random GUID on startup)
    pub server_guid: u64,
}

impl Default for BedrockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "0.0.0.0:19132".to_string(),
            motd: "A Vine Server".to_string(),
            protocol_version: 2169,
            version_name: "1.26.45".to_string(),
            level_name: "Vine Proxy".to_string(),
            game_mode: "Survival".to_string(),
            game_mode_id: 0,
            max_players: 100,
            server_guid: 0,
        }
    }
}
