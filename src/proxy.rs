use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::auth::{Authenticator, KeyStore};
use crate::backend::Router;
use crate::backend::forwarding::ForwardingHelper;
use crate::client::ClientHandler;
use crate::command::{CommandDispatcher, CommandSender, ProxyCommandSource};
use crate::config::{Config, ForwardingMode};
use crate::i18n::translate;
use crate::network;
use crate::security::ConnectionRateLimiter;
use crate::session::{PlayerAction, SessionManager, send_reliably};
use crate::status::{StatusHandler, StatusIconManager};
use crate::telemetry;

pub struct ProxyServer {
    config: Arc<Config>,
    keystore: Option<Arc<KeyStore>>,
    authenticator: Arc<Authenticator>,
    rate_limiter: Arc<ConnectionRateLimiter>,
    status_handler: Arc<StatusHandler>,
    router: Arc<Router>,
    online_players: Arc<AtomicUsize>,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    plugin_manager: Arc<crate::plugin::PluginManager>,
}

impl ProxyServer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(config);
        let keystore = if config.server.online_mode {
            Some(Arc::new(KeyStore::new()?))
        } else {
            None
        };
        let authenticator = Arc::new(Authenticator::new());

        let rate_limiter = Arc::new(ConnectionRateLimiter::new(
            config.security.rate_limit_enabled,
            config.security.max_connections_per_sec,
            config.security.connection_burst,
        ));

        let online_players = Arc::new(AtomicUsize::new(0));
        let session_manager = Arc::new(SessionManager::new());
        let command_dispatcher = Arc::new(CommandDispatcher::new());

        let server_icons: HashMap<String, String> = config
            .servers
            .iter()
            .filter_map(|(name, s)| s.icon_path.as_ref().map(|p| (name.clone(), p.clone())))
            .collect();

        let icon_manager = Arc::new(StatusIconManager::new(
            config.motd.icon_path.clone(),
            server_icons,
            config.routing.forced_hosts.clone(),
            config.routing.default_server.clone(),
        ));

        let status_handler = Arc::new(StatusHandler::new(
            config.motd.clone(),
            icon_manager,
            config.servers.clone(),
            config.routing.forced_hosts.clone(),
        ));

        let router = Arc::new(Router::new(config.routing.clone(), config.servers.clone()));

        let plugins_dir = std::path::PathBuf::from(&config.plugins.plugin_dir);
        let plugin_manager =
            crate::plugin::PluginManager::new(plugins_dir, (&config.plugins).into())?;
        plugin_manager.init_proxy_context(
            config.clone(),
            session_manager.clone(),
            command_dispatcher.clone(),
        );

        Ok(Self {
            config,
            keystore,
            authenticator,
            rate_limiter,
            status_handler,
            router,
            online_players,
            session_manager,
            command_dispatcher,
            plugin_manager,
        })
    }

    /// Run the proxy listener loop
    pub async fn run(
        &self,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let bind_addr = &self.config.server.bind_address;
        let listener = network::create_tcp_listener(bind_addr, &self.config.network)?;

        info!("=====================================================");
        info!("  Vine Minecraft Proxy is listening on {}", bind_addr);
        info!("  Online mode: {}", self.config.server.online_mode);
        info!(
            "  Supported Minecraft versions: {}",
            crate::protocol::ProtocolVersion::supported_range()
        );
        info!("  Networking options:");
        info!("    - TCP_NODELAY: {}", self.config.network.tcp_nodelay);
        info!(
            "    - TCP KeepAlive: {}s",
            self.config.network.tcp_keepalive_secs
        );
        info!(
            "    - PROXY Protocol v1/v2: {}",
            self.config.network.proxy_protocol
        );
        info!(
            "    - Handshake timeout: {}s",
            self.config.network.client_handshake_timeout_secs
        );
        info!(
            "    - Login timeout: {}s",
            self.config.network.client_login_timeout_secs
        );
        info!(
            "    - Backend connect timeout: {}s",
            self.config.network.backend_connect_timeout_secs
        );
        info!(
            "    - Compression level: {} (threshold: {} bytes)",
            self.config.server.compression_level, self.config.server.compression_threshold
        );
        info!(
            "  Configured backend servers: {}",
            self.config.servers.len()
        );
        for (name, server) in &self.config.servers {
            let icon_info = server.icon_path.as_deref().unwrap_or("none");
            info!(
                "    - [{}] {} (Forwarding: {:?}, Icon: {})",
                name, server.address, server.forwarding, icon_info
            );
            if server.forwarding == ForwardingMode::Vine
                && let Some(key) = server
                    .secret
                    .as_deref()
                    .and_then(|secret| ForwardingHelper::get_vine_public_key_hex(secret).ok())
            {
                info!("      Vine public key: {key} (networking.proxy.vine.public_key on Pumpkin)");
            }
        }
        info!("  Default route: '{}'", self.config.routing.default_server);
        if self.config.telemetry.enabled {
            info!(
                "  Telemetry: enabled (endpoint: {}, interval: {}s)",
                self.config.telemetry.endpoint, self.config.telemetry.interval_secs
            );
        } else {
            info!("  Telemetry: disabled");
        }
        if self.config.bedrock.enabled {
            info!(
                "  Bedrock Edition: enabled (listening on UDP {}, v{} / proto {})",
                self.config.bedrock.bind_address,
                self.config.bedrock.version_name,
                self.config.bedrock.protocol_version
            );
        } else {
            info!("  Bedrock Edition: disabled");
        }
        info!("=====================================================");

        let trusted_proxies: Arc<Vec<network::IpRange>> = Arc::new(
            self.config
                .network
                .proxy_protocol_trusted_proxies
                .iter()
                .filter_map(|entry| network::IpRange::parse(entry))
                .collect(),
        );

        let telemetry_handle = telemetry::start_telemetry(
            self.config.clone(),
            self.online_players.clone(),
            shutdown_rx.resubscribe(),
        );

        if self.config.bedrock.enabled {
            let mut bedrock_cfg = self.config.bedrock.clone();
            if bedrock_cfg.max_players == 0 {
                bedrock_cfg.max_players = self.config.motd.max_players;
            }
            let online_players = self.online_players.clone();
            let bedrock_shutdown = shutdown_rx.resubscribe();

            tokio::spawn(async move {
                if let Err(e) = crate::bedrock::run_bedrock_listener(
                    bedrock_cfg,
                    online_players,
                    bedrock_shutdown,
                )
                .await
                {
                    error!("Bedrock listener terminated with error: {}", e);
                }
            });
        }

        let console_dispatcher = self.command_dispatcher.clone();
        let console_config = self.config.clone();
        let console_session_manager = self.session_manager.clone();
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel();

        std::thread::Builder::new()
            .name("console-stdin".to_string())
            .spawn(move || {
                let stdin = std::io::stdin();
                let mut line = String::new();
                while let Ok(n) = stdin.read_line(&mut line) {
                    if n == 0 {
                        break;
                    }
                    if stdin_tx.send(line.trim().to_string()).is_err() {
                        break;
                    }
                    line.clear();
                }
            })
            .ok();

        let mut stdin_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stdin_shutdown.recv() => break,
                    cmd_opt = stdin_rx.recv() => {
                        match cmd_opt {
                            Some(trimmed) => {
                                if trimmed.eq_ignore_ascii_case("stop") || trimmed.eq_ignore_ascii_case("end") {
                                    info!("Shutting down (console)");
                                    let _ = shutdown_tx.send(());
                                } else if !trimmed.is_empty() {
                                    let source = ProxyCommandSource {
                                        sender: CommandSender::Console,
                                        config: console_config.clone(),
                                        session_manager: console_session_manager.clone(),
                                    };
                                    console_dispatcher.handle_command(&source, &trimmed);
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        if self.config.plugins.enabled {
            info!(
                "Loading plugins from '{}'...",
                self.config.plugins.plugin_dir
            );
            if let Err(e) = self.plugin_manager.load_plugins().await {
                error!("Failed to load plugins: {}", e);
            }
        }

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, peer_addr)) => {
                            let config = self.config.clone();
                            let keystore = self.keystore.clone();
                            let authenticator = self.authenticator.clone();
                            let status_handler = self.status_handler.clone();
                            let router = self.router.clone();
                            let online_players = self.online_players.clone();
                            let rate_limiter = self.rate_limiter.clone();
                            let session_manager = self.session_manager.clone();
                            let command_dispatcher = self.command_dispatcher.clone();
                            let plugin_manager = self.plugin_manager.clone();
                            let trusted_proxies = trusted_proxies.clone();

                            tokio::spawn(async move {
                                if let Err(e) = network::configure_client_socket(&stream, &config.network) {
                                    debug!("[{}] Failed to configure client socket: {}", peer_addr, e);
                                }

                                let mut stream = stream;
                                let mut effective_addr = peer_addr;
                                let mut leftover_bytes = Vec::new();

                                if config.network.proxy_protocol {
                                    if !trusted_proxies.iter().any(|range| range.contains(&peer_addr.ip()))
                                    {
                                        debug!("[{}] Dropped connection: peer is not a trusted PROXY protocol source", peer_addr);
                                        return;
                                    }

                                    let header_timeout = Duration::from_secs(config.network.client_handshake_timeout_secs);
                                    match tokio::time::timeout(header_timeout, network::parse_proxy_protocol(&mut stream, peer_addr)).await {
                                        Ok(Ok(res)) => {
                                             effective_addr = res.client_addr;
                                             leftover_bytes = res.leftover_bytes;
                                             debug!("[{}] PROXY protocol resolved client IP: {}", peer_addr, effective_addr);
                                        }
                                        Ok(Err(err)) => {
                                            warn!("[{}] Dropped connection: PROXY protocol error: {}", peer_addr, err);
                                            return;
                                        }
                                        Err(_) => {
                                            debug!("[{}] Dropped connection: PROXY protocol header timed out", peer_addr);
                                            return;
                                        }
                                    }
                                }

                                if !rate_limiter.check_connection(&effective_addr.ip()) {
                                    warn!("[{}] Dropped connection: Rate limit exceeded", effective_addr);
                                    return;
                                }

                                let handler = ClientHandler::new(
                                    effective_addr,
                                    config,
                                    keystore,
                                    authenticator,
                                    status_handler,
                                    router,
                                    online_players,
                                    session_manager,
                                    command_dispatcher,
                                    plugin_manager,
                                );

                                if let Err(err) = handler.handle(stream, leftover_bytes).await {
                                    debug!("[{}] Connection closed: {}", effective_addr, err);
                                }
                            });
                        }
                        Err(e) => {
                            error!("TCP listener accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }

        self.disconnect_players().await;

        if self.config.plugins.enabled {
            self.plugin_manager.unload_plugins().await;
        }

        if let Some(handle) = telemetry_handle {
            let timeout_secs = self.config.server.shutdown_timeout_secs.max(1);
            let _ = tokio::time::timeout(Duration::from_secs(timeout_secs), handle).await;
        }

        Ok(())
    }

    async fn disconnect_players(&self) {
        for session in self.session_manager.list_sessions() {
            let reason = translate(session.effective_locale(), "vine.shutdown", &[]);
            send_reliably(&session.action_tx, PlayerAction::Disconnect(reason));
        }
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.config.server.shutdown_timeout_secs.max(1));
        while self.session_manager.count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
