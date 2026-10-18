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
}

// Command nodes outlive a reload, so they look up the plugin that currently owns the name
type CommandRoutes = Arc<std::sync::RwLock<HashMap<String, CommandRoute>>>;

pub struct PluginManager {
    plugins_dir: PathBuf,
    loader: WasmPluginLoader,
    loaded_plugins: RwLock<Vec<LoadedPlugin>>,
    event_handlers: RwLock<HashMap<EventType, Vec<RegisteredEventHandler>>>,
    command_routes: CommandRoutes,
    proxy_ctx: OnceCell<ProxyPluginContext>,
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
            proxy_ctx: OnceCell::new(),
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

    pub async fn register_event_handler(
        &self,
        event_type: EventType,
        priority: EventPriority,
        handler_id: u32,
        plugin: Arc<WasmPlugin>,
    ) {
        let mut handlers = self.event_handlers.write().await;
        let list = handlers.entry(event_type).or_default();
        list.push(RegisteredEventHandler {
            handler_id,
            priority,
            plugin,
        });
        list.sort_by_key(|h| h.priority);
    }

    pub async fn register_command(
        &self,
        command_id: u32,
        name: String,
        description: String,
        aliases: Vec<String>,
        permission: Option<String>,
        plugin: Arc<WasmPlugin>,
    ) {
        if let Some(proxy) = self.proxy_ctx.get() {
            let names = std::iter::once(name.clone())
                .chain(aliases)
                .collect::<Vec<_>>();
            if let Ok(mut routes) = self.command_routes.write() {
                for cmd_name in &names {
                    routes.insert(
                        cmd_name.to_ascii_lowercase(),
                        CommandRoute {
                            plugin: plugin.clone(),
                            command_id,
                        },
                    );
                }
            }
            for cmd_name in names {
                let route = cmd_name.to_ascii_lowercase();
                let perm_check = permission.clone();
                let cmd_builder = pumpkin_command::argument_builder::command(cmd_name, description.clone())
                    .with_source(plugin.metadata.name.clone())
                    .requires(move |src: &ProxyCommandSource| {
                        if let Some(ref p) = perm_check {
                            src.has_permission(p)
                        } else {
                            true
                        }
                    })
                    .executes(PluginCommandExecutor {
                        name: route.clone(),
                        routes: self.command_routes.clone(),
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
                            name: route,
                            routes: self.command_routes.clone(),
                        }),
                    );
                proxy.command_dispatcher.register(cmd_builder);
            }
            info!(
                "Registered command '/{}' from plugin '{}'",
                name, plugin.metadata.name
            );
        }
    }

    pub async fn load_plugins(&self) -> Result<usize, Box<dyn std::error::Error>> {
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
        let (plugin, metadata) = self
            .loader
            .load(path, self.proxy_ctx.get().cloned())
            .await
            .map_err(|e| format!("Failed to load plugin '{}': {}", path.display(), e))?;
        if self.is_loaded(&metadata.name).await {
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
        plugin
            .on_load(Arc::default())
            .await
            .map_err(|e| format!("Plugin '{}' failed to on_load: {}", metadata.name, e))?;
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

    async fn is_loaded(&self, name: &str) -> bool {
        self.loaded_plugins
            .read()
            .await
            .iter()
            .any(|loaded| loaded.plugin.metadata.name == name)
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
        plugin.shutdown().await;
        for handlers in self.event_handlers.write().await.values_mut() {
            handlers.retain(|handler| !Arc::ptr_eq(&handler.plugin, plugin));
        }
        if let Ok(mut routes) = self.command_routes.write() {
            routes.retain(|_, route| !Arc::ptr_eq(&route.plugin, plugin));
        }
        if let Some(proxy) = self.proxy_ctx.get() {
            proxy.command_dispatcher.deactivate_source(name);
        }
        info!("Unloaded plugin '{}'", name);
        Some(loaded.path)
    }

    /// Swaps a plugin for a fresh instance of its file; a file that fails to load leaves the
    /// running instance untouched
    pub async fn reload_plugin(&self, name: &str) -> Result<PluginMetadata, String> {
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
        self.unload_plugin(name).await;
        if metadata.name != name && self.is_loaded(&metadata.name).await {
            return Err(format!(
                "Plugin '{}' now reports the name '{}', which is already loaded",
                name, metadata.name
            ));
        }
        self.enable_plugin(plugin, path).await?;
        Ok(metadata)
    }

    pub async fn unload_plugins(&self) {
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

    pub async fn fire_player_chat(&self, event: &mut PlayerChatEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerChat).cloned().unwrap_or_default()
        };
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
                Ok(loader::wasm::wasm_host::wit::vine::plugin::event::Event::PlayerChat(res))
                    if handler.priority != EventPriority::Monitor =>
                {
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
    }

    pub async fn fire_player_command(&self, event: &mut PlayerCommandEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PlayerCommand)
                .cloned()
                .unwrap_or_default()
        };
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
                )) if handler.priority != EventPriority::Monitor => {
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
    }

    pub async fn fire_plugin_message(&self, event: &mut PluginMessageEvent) {
        let handlers = {
            let map = self.event_handlers.read().await;
            map.get(&EventType::PluginMessage)
                .cloned()
                .unwrap_or_default()
        };
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
                )) if handler.priority != EventPriority::Monitor => {
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
    }
}

struct PluginCommandExecutor {
    name: String,
    routes: CommandRoutes,
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

        let Some(CommandRoute { plugin, command_id }) = resolve_route(&self.routes, &self.name)
        else {
            context.source.reply("vine.plugin.command_unavailable", &[]);
            return Ok(0);
        };
        let handle = tokio::runtime::Handle::current();
        let result = tokio::task::block_in_place(|| {
            handle.block_on(async move { plugin.handle_command(command_id, sender, args).await })
        });

        match result {
            Ok(Ok(code)) => Ok(code),
            Ok(Err(err_msg)) => {
                context
                    .source
                    .reply("vine.plugin.command_error", &[&err_msg]);
                Ok(0)
            }
            Err(e) => {
                context.source.reply("vine.plugin.command_error", &[&e]);
                Ok(0)
            }
        }
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

        let Some(CommandRoute { plugin, command_id }) = resolve_route(&self.routes, &self.name)
        else {
            return builder.build();
        };
        let handle = tokio::runtime::Handle::current();
        let suggestions_res = tokio::task::block_in_place(|| {
            handle.block_on(async move {
                plugin
                    .handle_command_suggestion(command_id, sender, args)
                    .await
            })
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
