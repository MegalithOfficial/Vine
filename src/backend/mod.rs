pub mod bridge;
pub mod forwarding;

pub use bridge::{BackendBridge, BridgeError};

use crate::config::{BackendConfig, RoutingConfig, normalize_host};
use std::collections::HashMap;

pub struct Router {
    routing: RoutingConfig,
    servers: HashMap<String, BackendConfig>,
}

impl Router {
    pub fn new(routing: RoutingConfig, servers: HashMap<String, BackendConfig>) -> Self {
        Self { routing, servers }
    }

    /// Resolves which backend server to connect to based on virtual host or default
    pub fn resolve_server(&self, virtual_host: &str) -> Option<(String, BackendConfig)> {
        if let Some(target_name) = self.routing.forced_hosts.get(&normalize_host(virtual_host))
            && let Some(cfg) = self.servers.get(target_name)
        {
            return Some((target_name.clone(), cfg.clone()));
        }

        if let Some(cfg) = self.servers.get(&self.routing.default_server) {
            return Some((self.routing.default_server.clone(), cfg.clone()));
        }

        if let Some(fallback_name) = &self.routing.fallback_server
            && let Some(cfg) = self.servers.get(fallback_name)
        {
            return Some((fallback_name.clone(), cfg.clone()));
        }

        self.servers
            .iter()
            .next()
            .map(|(name, cfg)| (name.clone(), cfg.clone()))
    }
}
