mod admin;
pub mod api;
pub mod loader;

pub use api::*;
pub use loader::wasm::WasmPlugin;
use loader::wasm::WasmPluginLoader;
use loader::wasm::wasm_host::state::ProxyPluginContext;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{OnceCell, RwLock};
use tracing::{error, info, warn};

use crate::command::{CommandSender, ProxyCommandSource};
use pumpkin_command::ArgumentBuilder;

#[derive(Clone)]
pub struct RegisteredEventHandler {
    pub handler_id: u32,
    pub priority: EventPriority,
    pub plugin: Arc<WasmPlugin>,
}

struct LoadedPlugin {
    plugin: Arc<WasmPlugin>,
    path: PathBuf,
}

#[derive(Clone)]
struct CommandRoute {
    plugin: Arc<WasmPlugin>,
    command_id: u32,
    permission: Option<String>,
}

// Command nodes outlive a reload, so they look up the plugin that currently owns the name
type CommandRoutes = Arc<std::sync::RwLock<HashMap<String, CommandRoute>>>;

// Senders with a plugin command still running; each may run one at a time, so spamming
// commands cannot pile up work or run them out of order. Players are keyed by name, the
// console by None.
type RunningCommands = Arc<std::sync::Mutex<std::collections::HashSet<Option<String>>>>;

type WitEvent = loader::wasm::wasm_host::wit::vine::plugin::event::Event;

// Monitor handlers cannot change an event, so they see it once it is decided, in order, without
// holding up the packet it came from. Events beyond this many waiting are not shown to them.
const MONITOR_QUEUE: usize = 1024;

struct MonitorJob {
    handlers: Vec<RegisteredEventHandler>,
    event: WitEvent,
    name: &'static str,
}

/// Event handlers a plugin may register across all events
pub const MAX_EVENT_HANDLERS: usize = 256;
/// Command names and aliases a plugin may register
pub const MAX_COMMAND_NAMES: usize = 64;

pub struct PluginManager {
    plugins_dir: PathBuf,
    loader: WasmPluginLoader,
    loaded_plugins: RwLock<Vec<LoadedPlugin>>,
    event_handlers: RwLock<HashMap<EventType, Vec<RegisteredEventHandler>>>,
    command_routes: CommandRoutes,
    running_commands: RunningCommands,
    proxy_ctx: OnceCell<ProxyPluginContext>,
    // Loading and reloading run one at a time so a plugin cannot end up loaded twice
    lifecycle: tokio::sync::Mutex<()>,
    monitors: std::sync::OnceLock<tokio::sync::mpsc::Sender<MonitorJob>>,
    monitors_behind: std::sync::atomic::AtomicBool,
}

impl PluginManager {
    pub fn new(
        plugins_dir: PathBuf,
        limits: loader::wasm::PluginLimits,
    ) -> Result<Arc<Self>, loader::wasm::wasm_host::PluginInitError> {
        let loader = WasmPluginLoader::new(limits)?;
        Ok(Arc::new(Self {
            plugins_dir,
            loader,
            loaded_plugins: RwLock::new(Vec::new()),
            event_handlers: RwLock::new(HashMap::new()),
            command_routes: Arc::default(),
            running_commands: Arc::default(),
            proxy_ctx: OnceCell::new(),
            lifecycle: tokio::sync::Mutex::new(()),
            monitors: std::sync::OnceLock::new(),
            monitors_behind: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    pub fn init_proxy_context(
        self: &Arc<Self>,
        config: Arc<crate::config::Config>,
        session_manager: Arc<crate::session::SessionManager>,
        command_dispatcher: Arc<crate::command::CommandDispatcher>,
    ) {
        let ctx = ProxyPluginContext {
            config,
            session_manager,
            command_dispatcher,
            plugin_manager: self.clone(),
        };
        admin::register(&ctx.command_dispatcher, self);
        let _ = self.proxy_ctx.set(ctx);
    }

    /// Returns false if the plugin already has as many handlers as it may register.
    /// Registering the same handler for the same event again changes nothing.
    pub async fn register_event_handler(
        &self,
        event_type: EventType,
        priority: EventPriority,
        handler_id: u32,
        plugin: Arc<WasmPlugin>,
    ) -> bool {
        let mut handlers = self.event_handlers.write().await;
        // Checked under the lock, which forget takes only after marking the plugin as stopping
        if plugin.is_stopping() || plugin.is_disabled() {
            return true;
        }
        let owned = |h: &RegisteredEventHandler| Arc::ptr_eq(&h.plugin, &plugin);
        if handlers
            .get(&event_type)
            .is_some_and(|list| list.iter().any(|h| owned(h) && h.handler_id == handler_id))
        {
            return true;
        }
        if handlers.values().flatten().filter(|h| owned(h)).count() >= MAX_EVENT_HANDLERS {
            return false;
        }
        let list = handlers.entry(event_type).or_default();
        let at = list.partition_point(|h| h.priority <= priority);
        list.insert(
            at,
            RegisteredEventHandler {
                handler_id,
                priority,
                plugin,
            },
        );
        true
    }

    /// Returns false if some names were left out because the plugin already has as many
    /// command names and aliases as it may register
    pub async fn register_command(
        &self,
        command_id: u32,
        name: String,
        description: String,
        aliases: Vec<String>,
        permission: Option<String>,
        plugin: Arc<WasmPlugin>,
    ) -> bool {
        let mut capped = false;
        if let Some(proxy) = self.proxy_ctx.get() {
            // A name owned by a built-in or another plugin instance would keep that owner's
            // permission. Owners are looked up in the routes, which change right away unlike
            // the dispatcher.
            let names = std::iter::once(name.clone())
                .chain(aliases)
                .filter(|cmd_name| {
                    let free = !proxy.command_dispatcher.is_builtin(cmd_name)
                        && self.command_routes.read().is_ok_and(|routes| {
                            routes
                                .get(&cmd_name.to_ascii_lowercase())
                                .is_none_or(|route| Arc::ptr_eq(&route.plugin, &plugin))
                        });
                    if !free {
                        warn!(
                            "Plugin '{}' cannot register '/{}', which is already taken",
                            plugin.metadata.name, cmd_name
                        );
                    }
                    free
                })
                .collect::<Vec<_>>();
            let Ok(mut routes) = self.command_routes.write() else {
                return true;
            };
            if plugin.is_stopping() || plugin.is_disabled() {
                return true;
            }
            let mut owned = routes
                .values()
                .filter(|route| Arc::ptr_eq(&route.plugin, &plugin))
                .count();
            let names = names
                .into_iter()
                .filter(|cmd_name| {
                    let key = cmd_name.to_ascii_lowercase();
                    if !routes.contains_key(&key) {
                        if owned >= MAX_COMMAND_NAMES {
                            capped = true;
                            return false;
                        }
                        owned += 1;
                    }
                    routes.insert(
                        key,
                        CommandRoute {
                            plugin: plugin.clone(),
                            command_id,
                            permission: permission.clone(),
                        },
                    );
                    true
                })
                .collect::<Vec<_>>();
            drop(routes);
            for cmd_name in names {
                let route = cmd_name.to_ascii_lowercase();
                let routes = self.command_routes.clone();
                let required = route.clone();
                // Read the permission from the current route, since a reload keeps the first node.
                // A disabled plugin's commands go on to the backend.
                let cmd_builder = pumpkin_command::argument_builder::command(cmd_name, description.clone())
                    .with_source(plugin.metadata.name.clone())
                    .requires(move |src: &ProxyCommandSource| {
                        resolve_route(&routes, &required).is_some_and(|route| {
                            !route.plugin.is_disabled()
                                && route
                                    .permission
                                    .as_deref()
                                    .is_none_or(|p| src.has_permission(p))
                        })
                    })
                    .executes(PluginCommandExecutor {
                        name: route.clone(),
                        routes: self.command_routes.clone(),
                        running: self.running_commands.clone(),
                    })
                    .then(
                        pumpkin_command::argument_builder::argument(
                            "args",
                            pumpkin_command::argument_types::core::string::StringArgumentType::GreedyPhrase,
                        )
                        .suggests(PluginCommandSuggestionProvider {
                            name: route.clone(),
                            routes: self.command_routes.clone(),
                        })
                        .executes(PluginCommandExecutor {
                            name: route.clone(),
                            routes: self.command_routes.clone(),
                            running: self.running_commands.clone(),
                        }),
                    );
                proxy
                    .command_dispatcher
                    .register_for(cmd_builder, &plugin.metadata.name);
                info!(
                    "Registered command '/{}' from plugin '{}'",
                    route, plugin.metadata.name
                );
            }
        }
        !capped
    }

    pub async fn load_plugins(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let _lifecycle = self.lifecycle.lock().await;
        if !self.plugins_dir.exists() {
            let _ = fs::create_dir_all(&self.plugins_dir);
            info!("Created plugins directory '{}'", self.plugins_dir.display());
            return Ok(0);
        }

        let mut count = 0;
        let start_time = std::time::Instant::now();
        let read_dir = match fs::read_dir(&self.plugins_dir) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read plugins directory: {}", e);
                return Ok(0);
            }
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_file() && self.loader.can_load(&path) {
                info!("Loading plugin from '{}'...", path.display());
                match self.load_plugin(&path).await {
                    Ok(_) => count += 1,
                    Err(e) => error!("{}", e),
                }
            }
        }

        info!("Loaded {} plugin(s) in {:?}", count, start_time.elapsed());
        Ok(count)
    }

    async fn load_plugin(&self, path: &Path) -> Result<PluginMetadata, String> {
        // Files like Foo.wasm and foo.wasm would share a data folder
        let data_folder = loader::wasm::wasm_host::data_folder(path);
        if let Some(other) = self
            .loaded_plugins
            .read()
            .await
            .iter()
            .find(|loaded| loader::wasm::wasm_host::data_folder(&loaded.path) == data_folder)
        {
            return Err(format!(
                "Plugin '{}' would share its data folder with '{}', which is already loaded",
                path.display(),
                other.path.display()
            ));
        }
        let (plugin, metadata) = self
            .loader
            .load(path, self.proxy_ctx.get().cloned())
            .await
            .map_err(|e| format!("Failed to load plugin '{}': {}", path.display(), e))?;
        if self.name_taken(&metadata.name, None).await {
            plugin.shutdown().await;
            return Err(format!(
                "Plugin '{}' from '{}' is already loaded",
                metadata.name,
                path.display()
            ));
        }
        self.enable_plugin(plugin, path.to_path_buf()).await?;
        Ok(metadata)
    }

    async fn enable_plugin(&self, plugin: Arc<WasmPlugin>, path: PathBuf) -> Result<(), String> {
        let metadata = plugin.metadata.clone();
        crate::i18n::load_namespace(&crate::i18n::namespace(&metadata.name));
        plugin.register_early_translations();
        if let Err(e) = plugin.on_load(Arc::default()).await {
            // Whatever it registered before failing would otherwise outlive it
            self.forget(&plugin, &metadata.name).await;
            return Err(format!(
                "Plugin '{}' failed to on_load: {}",
                metadata.name, e
            ));
        }
        info!(
            "Loaded plugin '{}' v{} by {}",
            metadata.name,
            metadata.version,
            metadata.authors.join(", ")
        );
        self.loaded_plugins
            .write()
            .await
            .push(LoadedPlugin { plugin, path });
        Ok(())
    }

    /// Returns true if a loaded plugin other than `except` uses this name. Names differing only
    /// in case or symbols count as the same, since they would share translations.
    async fn name_taken(&self, name: &str, except: Option<&str>) -> bool {
        let namespace = crate::i18n::namespace(name);
        self.loaded_plugins.read().await.iter().any(|loaded| {
            Some(loaded.plugin.metadata.name.as_str()) != except
                && crate::i18n::namespace(&loaded.plugin.metadata.name) == namespace
        })
    }

    pub async fn plugin_names(&self) -> Vec<String> {
        self.loaded_plugins
            .read()
            .await
            .iter()
            .map(|loaded| loaded.plugin.metadata.name.clone())
            .collect()
    }

    fn plugin_names_now(&self) -> Vec<String> {
        self.loaded_plugins
            .try_read()
            .map(|plugins| {
                plugins
                    .iter()
                    .map(|loaded| loaded.plugin.metadata.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn plugin_list(&self) -> Vec<(PluginMetadata, bool)> {
        self.loaded_plugins
            .read()
            .await
            .iter()
            .map(|loaded| (loaded.plugin.metadata.clone(), loaded.plugin.is_disabled()))
            .collect()
    }

    async fn unload_plugin(&self, name: &str) -> Option<PathBuf> {
        let loaded = {
            let mut plugins = self.loaded_plugins.write().await;
            let index = plugins
                .iter()
                .position(|loaded| loaded.plugin.metadata.name == name)?;
            plugins.remove(index)
        };
        let plugin = &loaded.plugin;
        if !plugin.is_disabled()
            && let Err(e) = plugin.on_unload(Arc::default()).await
        {
            error!("Error unloading plugin '{}': {}", name, e);
        }
        self.forget(plugin, name).await;
        info!("Unloaded plugin '{}'", name);
        Some(loaded.path)
    }

    /// Stops a plugin and drops its event handlers, commands and translations
    async fn forget(&self, plugin: &Arc<WasmPlugin>, name: &str) {
        plugin.shutdown().await;
        crate::i18n::unregister(&crate::i18n::namespace(name));
        for handlers in self.event_handlers.write().await.values_mut() {
            handlers.retain(|handler| !Arc::ptr_eq(&handler.plugin, plugin));
        }
        if let Ok(mut routes) = self.command_routes.write() {
            routes.retain(|_, route| !Arc::ptr_eq(&route.plugin, plugin));
        }
        if let Some(proxy) = self.proxy_ctx.get() {
            proxy.command_dispatcher.deactivate_source(name);
        }
    }

    /// Swaps a plugin for a fresh instance of its file. A file that fails to load or now reports
    /// a name that is already taken leaves the running instance untouched; once the old instance
    /// is unloaded, a new one that fails its on_load leaves the plugin unloaded.
    pub async fn reload_plugin(&self, name: &str) -> Result<PluginMetadata, String> {
        let _lifecycle = self.lifecycle.lock().await;
        let path = self
            .loaded_plugins
            .read()
            .await
            .iter()
            .find(|loaded| loaded.plugin.metadata.name == name)
            .map(|loaded| loaded.path.clone())
            .ok_or_else(|| format!("Plugin '{name}' is not loaded"))?;
        let (plugin, metadata) = self
            .loader
            .load(&path, self.proxy_ctx.get().cloned())
            .await
            .map_err(|e| format!("Failed to reload plugin '{}': {}", name, e))?;
        if self.name_taken(&metadata.name, Some(name)).await {
            plugin.shutdown().await;
            return Err(format!(
                "Plugin '{}' now reports the name '{}', which is already loaded",
                name, metadata.name
            ));
        }
        self.unload_plugin(name).await;
        self.enable_plugin(plugin, path).await?;
        Ok(metadata)
    }

    pub async fn unload_plugins(&self) {
        let _lifecycle = self.lifecycle.lock().await;
        for name in self.plugin_names().await {
            self.unload_plugin(&name).await;
        }
        self.event_handlers.write().await.clear();
    }

    // --- Event dispatchers ---

    pub async fn fire_proxy_ping(&self, event: &mut ProxyPingEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::ProxyPing).cloned().unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::ProxyPing(
                loader::wasm::wasm_host::wit::vine::plugin::event::ProxyPingEvent {
                    client_ip: event.client_ip.clone(),
                    protocol_version: event.protocol_version,
                    virtual_host: event.virtual_host.clone(),
                    motd: event.motd.clone(),
                    max_players: event.max_players,
                    online_players: event.online_players,
                    version_name: event.version_name.clone(),
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::ProxyPing(res))
                    if handler.priority != EventPriority::Monitor =>
                {
                    event.motd = res.motd;
                    event.max_players = res.max_players;
                    event.online_players = res.online_players;
                    event.version_name = res.version_name;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling ProxyPing: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
    }

    pub async fn fire_player_pre_login(&self, event: &mut PlayerPreLoginEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerPreLogin)
                .cloned()
                .unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerPreLogin(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerPreLoginEvent {
                    client_ip: event.client_ip.clone(),
                    username: event.username.clone(),
                    protocol_version: event.protocol_version,
                    virtual_host: event.virtual_host.clone(),
                    cancelled: event.cancelled,
                    cancel_reason: event.cancel_reason.clone(),
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerPreLogin(
                    res,
                )) if handler.priority != EventPriority::Monitor => {
                    event.cancelled = res.cancelled;
                    event.cancel_reason = res.cancel_reason;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling PlayerPreLogin: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
    }

    pub async fn fire_player_login(&self, event: &mut PlayerLoginEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerLogin)
                .cloned()
                .unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerLogin(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerLoginEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    client_ip: event.client_ip.clone(),
                    cancelled: event.cancelled,
                    cancel_reason: event.cancel_reason.clone(),
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerLogin(res))
                    if handler.priority != EventPriority::Monitor =>
                {
                    event.cancelled = res.cancelled;
                    event.cancel_reason = res.cancel_reason;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling PlayerLogin: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
    }

    pub async fn fire_player_join(&self, event: &PlayerJoinEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerJoin).cloned().unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerJoin(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerJoinEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    client_ip: event.client_ip.clone(),
                    initial_server: event.initial_server.clone(),
                },
            );
            let _ = handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await;
        }
    }

    pub async fn fire_server_connect(&self, event: &mut ServerConnectEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::ServerConnect)
                .cloned()
                .unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::ServerConnect(
                loader::wasm::wasm_host::wit::vine::plugin::event::ServerConnectEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    current_server: event.current_server.clone(),
                    target_server: event.target_server.clone(),
                    cancelled: event.cancelled,
                    cancel_reason: event.cancel_reason.clone(),
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::ServerConnect(
                    res,
                )) if handler.priority != EventPriority::Monitor => {
                    event.target_server = res.target_server;
                    event.cancelled = res.cancelled;
                    event.cancel_reason = res.cancel_reason;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling ServerConnect: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
    }

    pub async fn fire_server_connected(&self, event: &ServerConnectedEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::ServerConnected)
                .cloned()
                .unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::ServerConnected(
                loader::wasm::wasm_host::wit::vine::plugin::event::ServerConnectedEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    server_name: event.server_name.clone(),
                },
            );
            let _ = handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await;
        }
    }

    pub async fn fire_player_disconnect(&self, event: &PlayerDisconnectEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerDisconnect)
                .cloned()
                .unwrap_or_default()
        };
        for handler in handlers {
            let wit_evt =
                loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerDisconnect(
                    loader::wasm::wasm_host::wit::vine::plugin::event::PlayerDisconnectEvent {
                        uuid: event.uuid.clone(),
                        username: event.username.clone(),
                        last_server: event.last_server.clone(),
                    },
                );
            let _ = handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await;
        }
    }

    /// Shows a decided event to Monitor handlers on a task of their own
    fn watch(&self, handlers: Vec<RegisteredEventHandler>, event: WitEvent, name: &'static str) {
        use std::sync::atomic::Ordering;
        if handlers.is_empty() {
            return;
        }
        let monitors = self.monitors.get_or_init(|| {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<MonitorJob>(MONITOR_QUEUE);
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    for handler in job.handlers {
                        if let Err(e) = handler
                            .plugin
                            .handle_event(handler.handler_id, job.event.clone())
                            .await
                        {
                            error!(
                                "Error in plugin '{}' handling {}: {}",
                                handler.plugin.metadata.name, job.name, e
                            );
                        }
                    }
                }
            });
            tx
        });
        let job = MonitorJob {
            handlers,
            event,
            name,
        };
        if monitors.try_send(job).is_ok() {
            self.monitors_behind.store(false, Ordering::Relaxed);
        } else if !self.monitors_behind.swap(true, Ordering::Relaxed) {
            warn!(
                "Monitor event handlers are falling behind; some {} events skip them",
                name
            );
        }
    }

    pub async fn fire_player_chat(&self, event: &mut PlayerChatEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerChat).cloned().unwrap_or_default()
        };
        let (monitors, handlers): (Vec<_>, Vec<_>) = handlers
            .into_iter()
            .partition(|handler| handler.priority == EventPriority::Monitor);
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerChat(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerChatEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    message: event.message.clone(),
                    cancelled: event.cancelled,
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerChat(res)) => {
                    event.message = res.message;
                    event.cancelled = res.cancelled;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling PlayerChat: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
        self.watch(
            monitors,
            loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerChat(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerChatEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    message: event.message.clone(),
                    cancelled: event.cancelled,
                },
            ),
            "PlayerChat",
        );
    }

    pub async fn fire_player_command(&self, event: &mut PlayerCommandEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerCommand)
                .cloned()
                .unwrap_or_default()
        };
        let (monitors, handlers): (Vec<_>, Vec<_>) = handlers
            .into_iter()
            .partition(|handler| handler.priority == EventPriority::Monitor);
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerCommand(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerCommandEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    command: event.command.clone(),
                    cancelled: event.cancelled,
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerCommand(
                    res,
                )) => {
                    event.command = res.command;
                    event.cancelled = res.cancelled;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling PlayerCommand: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
        self.watch(
            monitors,
            loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerCommand(
                loader::wasm::wasm_host::wit::vine::plugin::event::PlayerCommandEvent {
                    uuid: event.uuid.clone(),
                    username: event.username.clone(),
                    command: event.command.clone(),
                    cancelled: event.cancelled,
                },
            ),
            "PlayerCommand",
        );
    }

    pub async fn fire_plugin_message(&self, event: &mut PluginMessageEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PluginMessage)
                .cloned()
                .unwrap_or_default()
        };
        let (monitors, handlers): (Vec<_>, Vec<_>) = handlers
            .into_iter()
            .partition(|handler| handler.priority == EventPriority::Monitor);
        for handler in handlers {
            let wit_evt = loader::wasm::wasm_host::wit::vine::plugin::event::Event::PluginMessage(
                loader::wasm::wasm_host::wit::vine::plugin::event::PluginMessageEvent {
                    channel: event.channel.clone(),
                    data: event.data.clone(),
                    player_uuid: event.player_uuid.clone(),
                    server_name: event.server_name.clone(),
                    source: match event.source {
                        PluginMessageSource::Player => {
                            loader::wasm::wasm_host::wit::vine::plugin::event::PluginMessageSource::Player
                        }
                        PluginMessageSource::Server => {
                            loader::wasm::wasm_host::wit::vine::plugin::event::PluginMessageSource::Server
                        }
                    },
                    cancelled: event.cancelled,
                },
            );
            match handler
                .plugin
                .handle_event(handler.handler_id, wit_evt)
                .await
            {
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::PluginMessage(
                    res,
                )) => {
                    event.data = res.data;
                    event.cancelled = res.cancelled;
                }
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "Error in plugin '{}' handling PluginMessage: {}",
                        handler.plugin.metadata.name, e
                    );
                }
            }
        }
        self.watch(monitors, loader::wasm::wasm_host::wit::vine::plugin::event::Event::PluginMessage(
            loader::wasm::wasm_host::wit::vine::plugin::event::PluginMessageEvent {
                channel: event.channel.clone(),
                data: event.data.clone(),
                player_uuid: event.player_uuid.clone(),
                server_name: event.server_name.clone(),
                source: match event.source {
                    PluginMessageSource::Player => {
                        loader::wasm::wasm_host::wit::vine::plugin::event::PluginMessageSource::Player
                    }
                    PluginMessageSource::Server => {
                        loader::wasm::wasm_host::wit::vine::plugin::event::PluginMessageSource::Server
                    }
                },
                cancelled: event.cancelled,
            },
        ), "PluginMessage");
    }
}

struct PluginCommandExecutor {
    name: String,
    routes: CommandRoutes,
    running: RunningCommands,
}

struct RunningGuard {
    running: RunningCommands,
    sender: Option<String>,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        if let Ok(mut running) = self.running.lock() {
            running.remove(&self.sender);
        }
    }
}

fn resolve_route(routes: &CommandRoutes, name: &str) -> Option<CommandRoute> {
    routes.read().ok()?.get(name).cloned()
}

impl pumpkin_command::node::CommandExecutor<ProxyCommandSource> for PluginCommandExecutor {
    fn execute(
        &self,
        context: &pumpkin_command::context::command_context::CommandContext<ProxyCommandSource>,
    ) -> pumpkin_command::node::CommandExecutorResult {
        let args: Vec<String> = if let Ok(phrase) =
            pumpkin_command::argument_types::core::string::StringArgumentType::get(context, "args")
        {
            phrase.split_whitespace().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };

        let sender = match &context.source.sender {
            CommandSender::Console => loader::wasm::wasm_host::wit::vine::plugin::types::CommandSender {
                sender_type:
                    loader::wasm::wasm_host::wit::vine::plugin::types::CommandSenderType::Console,
                name: "CONSOLE".to_string(),
                player_uuid: None,
            },
            CommandSender::Player { username, .. } => {
                let uuid = context
                    .source
                    .session_manager
                    .get_session(username)
                    .map(|s| s.uuid.to_string());
                loader::wasm::wasm_host::wit::vine::plugin::types::CommandSender {
                    sender_type:
                        loader::wasm::wasm_host::wit::vine::plugin::types::CommandSenderType::Player,
                    name: username.clone(),
                    player_uuid: uuid,
                }
            }
        };

        let Some(CommandRoute {
            plugin, command_id, ..
        }) = resolve_route(&self.routes, &self.name)
        else {
            context.source.reply("vine.plugin.command_unavailable", &[]);
            return Ok(0);
        };
        // Runs on its own task so a slow plugin doesn't hold up the player's connection
        let sender_name = match &context.source.sender {
            CommandSender::Console => None,
            CommandSender::Player { username, .. } => Some(username.clone()),
        };
        if !self
            .running
            .lock()
            .is_ok_and(|mut running| running.insert(sender_name.clone()))
        {
            context.source.reply("vine.plugin.command_busy", &[]);
            return Ok(0);
        }
        let guard = RunningGuard {
            running: self.running.clone(),
            sender: sender_name,
        };
        let source = context.source.clone();
        tokio::spawn(async move {
            let _guard = guard;
            match plugin.handle_command(command_id, sender, args).await {
                Ok(Ok(_)) => {}
                Ok(Err(err_msg)) => source.reply("vine.plugin.command_error", &[&err_msg]),
                Err(e) => source.reply("vine.plugin.command_error", &[&e]),
            }
        });
        Ok(1)
    }
}

struct PluginCommandSuggestionProvider {
    name: String,
    routes: CommandRoutes,
}

impl pumpkin_command::suggestion::provider::SuggestionProvider<ProxyCommandSource>
    for PluginCommandSuggestionProvider
{
    fn suggest(
        &self,
        context: &pumpkin_command::context::command_context::CommandContext<ProxyCommandSource>,
        builder: pumpkin_command::suggestion::suggestions::SuggestionsBuilder,
    ) -> pumpkin_command::suggestion::provider::SuggestionProviderResult {
        let args: Vec<String> = if let Ok(phrase) =
            pumpkin_command::argument_types::core::string::StringArgumentType::get(context, "args")
        {
            phrase.split_whitespace().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };

        let sender = match &context.source.sender {
            CommandSender::Console => loader::wasm::wasm_host::wit::vine::plugin::types::CommandSender {
                sender_type:
                    loader::wasm::wasm_host::wit::vine::plugin::types::CommandSenderType::Console,
                name: "CONSOLE".to_string(),
                player_uuid: None,
            },
            CommandSender::Player { username, .. } => {
                let uuid = context
                    .source
                    .session_manager
                    .get_session(username)
                    .map(|s| s.uuid.to_string());
                loader::wasm::wasm_host::wit::vine::plugin::types::CommandSender {
                    sender_type:
                        loader::wasm::wasm_host::wit::vine::plugin::types::CommandSenderType::Player,
                    name: username.clone(),
                    player_uuid: uuid,
                }
            }
        };

        let Some(CommandRoute {
            plugin, command_id, ..
        }) = resolve_route(&self.routes, &self.name)
        else {
            return builder.build();
        };
        // Suggestions are worked out on a blocking thread, so waiting for the plugin here is fine
        let suggestions_res = tokio::runtime::Handle::current().block_on(async move {
            plugin
                .handle_command_suggestion(command_id, sender, args)
                .await
        });

        let mut builder = builder;
        if let Ok(suggestions) = suggestions_res {
            for s in suggestions {
                builder = builder.suggest(s);
            }
        }
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::CommandDispatcher;
    use crate::config::Config;
    use crate::session::SessionManager;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_plugin_manager_empty_dir() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = Arc::new(Config::default());
        let dispatcher = Arc::new(CommandDispatcher::new());
        let session_manager = Arc::new(SessionManager::new());
        let manager = PluginManager::new(
            temp_dir.path().to_path_buf(),
            (&crate::config::PluginConfig::default()).into(),
        )
        .expect("failed to create manager");
        manager.init_proxy_context(config, session_manager, dispatcher);

        let count = manager.load_plugins().await.expect("load failed");
        assert_eq!(count, 0);

        manager.unload_plugins().await;
    }

    #[tokio::test]
    async fn test_plugin_manager_event_dispatch() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let config = Arc::new(Config::default());
        let dispatcher = Arc::new(CommandDispatcher::new());
        let session_manager = Arc::new(SessionManager::new());
        let manager = PluginManager::new(
            temp_dir.path().to_path_buf(),
            (&crate::config::PluginConfig::default()).into(),
        )
        .expect("failed to create manager");
        manager.init_proxy_context(config, session_manager, dispatcher);

        // Proxy ping
        let mut ping = ProxyPingEvent {
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 765,
            virtual_host: "localhost".to_string(),
            motd: "A Minecraft Proxy".to_string(),
            max_players: 100,
            online_players: 0,
            version_name: "Vine 1.21".to_string(),
        };
        manager.fire_proxy_ping(&mut ping).await;
        assert_eq!(ping.motd, "A Minecraft Proxy");
        assert_eq!(ping.max_players, 100);

        // Player pre-login
        let mut pre_login = PlayerPreLoginEvent {
            client_ip: "127.0.0.1".to_string(),
            username: "Player1".to_string(),
            protocol_version: 765,
            virtual_host: "localhost".to_string(),
            cancelled: false,
            cancel_reason: None,
        };
        manager.fire_player_pre_login(&mut pre_login).await;
        assert!(!pre_login.cancelled);

        // Player login
        let mut login = PlayerLoginEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            client_ip: "127.0.0.1".to_string(),
            cancelled: false,
            cancel_reason: None,
        };
        manager.fire_player_login(&mut login).await;
        assert!(!login.cancelled);

        // Server connect
        let mut connect = ServerConnectEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            current_server: None,
            target_server: "lobby".to_string(),
            cancelled: false,
            cancel_reason: None,
        };
        manager.fire_server_connect(&mut connect).await;
        assert_eq!(connect.target_server, "lobby");
        assert!(!connect.cancelled);

        // Server connected
        let connected = ServerConnectedEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            server_name: "lobby".to_string(),
        };
        manager.fire_server_connected(&connected).await;

        // Player join
        let join = PlayerJoinEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            client_ip: "127.0.0.1".to_string(),
            initial_server: "lobby".to_string(),
        };
        manager.fire_player_join(&join).await;

        // Player chat
        let mut chat = PlayerChatEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            message: "Hello proxy!".to_string(),
            cancelled: false,
        };
        manager.fire_player_chat(&mut chat).await;
        assert_eq!(chat.message, "Hello proxy!");
        assert!(!chat.cancelled);

        // Player command
        let mut cmd = PlayerCommandEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            command: "ping".to_string(),
            cancelled: false,
        };
        manager.fire_player_command(&mut cmd).await;
        assert!(!cmd.cancelled);

        // Plugin message
        let mut msg = PluginMessageEvent {
            channel: "vine:test".to_string(),
            data: vec![1, 2, 3],
            player_uuid: Some("00000000-0000-0000-0000-000000000001".to_string()),
            server_name: Some("lobby".to_string()),
            source: PluginMessageSource::Player,
            cancelled: false,
        };
        manager.fire_plugin_message(&mut msg).await;
        assert!(!msg.cancelled);

        // Player disconnect
        let disc = PlayerDisconnectEvent {
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "Player1".to_string(),
            last_server: Some("lobby".to_string()),
        };
        manager.fire_player_disconnect(&disc).await;
    }

    #[test]
    fn test_event_priority_ordering() {
        assert!(EventPriority::Lowest < EventPriority::Low);
        assert!(EventPriority::Low < EventPriority::Normal);
        assert!(EventPriority::Normal < EventPriority::High);
        assert!(EventPriority::High < EventPriority::Highest);
        assert!(EventPriority::Highest < EventPriority::Monitor);
    }

    #[test]
    fn test_plugin_metadata_serde() {
        let meta = PluginMetadata {
            name: "test-plugin".to_string(),
            version: "1.0.0".to_string(),
            authors: vec!["Author1".to_string()],
            description: Some("A test plugin".to_string()),
            dependencies: vec!["other-plugin".to_string()],
        };

        let json = serde_json::to_string(&meta).expect("serialization failed");
        let decoded: PluginMetadata = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(decoded.name, "test-plugin");
        assert_eq!(decoded.version, "1.0.0");
        assert_eq!(decoded.authors, vec!["Author1".to_string()]);
        assert_eq!(decoded.dependencies, vec!["other-plugin".to_string()]);
    }
}
