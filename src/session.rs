use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use uuid::Uuid;

use pumpkin_util::text::TextComponent;

/// Actions that can be dispatched to an active player's connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayerAction {
    /// Request connecting the player to a target backend server in-proxy
    Connect { server_name: String },
    /// Send a system chat message to the player
    Message(TextComponent),
    /// Disconnect/kick the player with a reason
    Disconnect(String),
    /// Send a custom plugin message / payload to the player
    PluginMessage { channel: String, data: Vec<u8> },
}

/// Represents an active connected player session on the proxy
#[derive(Clone)]
pub struct PlayerSession {
    pub username: String,
    pub uuid: Uuid,
    pub current_server: String,
    pub action_tx: mpsc::UnboundedSender<PlayerAction>,
    pub client_ip: String,
    pub protocol_version: u32,
    /// Language reported by the client, e.g. `en_us`
    pub locale: Option<String>,
    /// Language set by a plugin, which wins over the client's
    pub locale_override: Option<String>,
}

impl PlayerSession {
    pub fn effective_locale(&self) -> Option<&str> {
        self.locale_override.as_deref().or(self.locale.as_deref())
    }
}

/// Thread-safe registry of connected player sessions
pub struct SessionManager {
    sessions: RwLock<HashMap<String, PlayerSession>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Registers the session unless the username or UUID is already online.
    /// The returned guard unregisters it when the connection ends.
    pub fn try_register(self: &Arc<Self>, session: PlayerSession) -> Option<SessionGuard> {
        let mut lock = self.sessions.write().ok()?;
        let key = session.username.to_ascii_lowercase();
        if lock.contains_key(&key) || lock.values().any(|s| s.uuid == session.uuid) {
            return None;
        }
        let guard = SessionGuard {
            manager: Arc::clone(self),
            key: key.clone(),
            uuid: session.uuid,
        };
        lock.insert(key, session);
        Some(guard)
    }

    /// Updates the current server for an active session
    pub fn update_server(&self, username: &str, new_server: &str) {
        if let Ok(mut lock) = self.sessions.write()
            && let Some(session) = lock.get_mut(&username.to_ascii_lowercase())
        {
            session.current_server = new_server.to_string();
        }
    }

    pub fn update_locale(&self, username: &str, locale: &str) {
        if let Ok(mut lock) = self.sessions.write()
            && let Some(session) = lock.get_mut(&username.to_ascii_lowercase())
        {
            session.locale = Some(locale.to_ascii_lowercase());
        }
    }

    pub fn locale(&self, username: &str) -> Option<String> {
        self.get_session(username)
            .and_then(|s| s.effective_locale().map(str::to_string))
    }

    pub fn locale_by_uuid(&self, uuid: Uuid) -> Option<String> {
        let lock = self.sessions.read().ok()?;
        let session = lock.values().find(|s| s.uuid == uuid)?;
        session.effective_locale().map(str::to_string)
    }

    pub fn set_locale_override(&self, uuid: Uuid, locale: Option<&str>) -> bool {
        let Ok(mut lock) = self.sessions.write() else {
            return false;
        };
        match lock.values_mut().find(|s| s.uuid == uuid) {
            Some(session) => {
                session.locale_override = locale.map(|l| l.to_ascii_lowercase().replace('-', "_"));
                true
            }
            None => false,
        }
    }

    /// Looks up an active session by username (case-insensitive)
    pub fn get_session(&self, username: &str) -> Option<PlayerSession> {
        if let Ok(lock) = self.sessions.read() {
            lock.get(&username.to_ascii_lowercase()).cloned()
        } else {
            None
        }
    }

    /// Returns a list of all active sessions
    pub fn list_sessions(&self) -> Vec<PlayerSession> {
        if let Ok(lock) = self.sessions.read() {
            lock.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Returns the number of currently registered sessions
    pub fn count(&self) -> usize {
        if let Ok(lock) = self.sessions.read() {
            lock.len()
        } else {
            0
        }
    }
}

pub struct SessionGuard {
    manager: Arc<SessionManager>,
    key: String,
    uuid: Uuid,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.manager.sessions.write()
            && lock.get(&self.key).is_some_and(|s| s.uuid == self.uuid)
        {
            lock.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_register_rejects_duplicates_until_guard_drops() {
        let manager = Arc::new(SessionManager::new());
        let session = |name: &str, uuid: u128| {
            let (tx, _rx) = mpsc::unbounded_channel();
            PlayerSession {
                username: name.to_string(),
                uuid: Uuid::from_u128(uuid),
                current_server: "lobby".to_string(),
                action_tx: tx,
                client_ip: "127.0.0.1".to_string(),
                protocol_version: 769,
                locale: None,
                locale_override: None,
            }
        };

        let guard = manager.try_register(session("Steve", 1)).unwrap();
        assert!(manager.try_register(session("steve", 2)).is_none());
        assert!(manager.try_register(session("Alex", 1)).is_none());
        assert_eq!(manager.count(), 1);

        drop(guard);
        assert_eq!(manager.count(), 0);
        assert!(manager.try_register(session("STEVE", 2)).is_some());
    }
}
