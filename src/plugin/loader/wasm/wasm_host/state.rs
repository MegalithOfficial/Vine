use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};

use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::{FsPerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::command::CommandDispatcher;
use crate::config::Config;
use crate::plugin::PluginManager;
use crate::plugin::api::{EventPriority, EventType, PluginContext};
use crate::plugin::loader::wasm::wasm_host::WasmPlugin;
use crate::session::{PlayerAction, SessionManager};

use super::wit;

#[derive(Clone)]
pub struct ProxyPluginContext {
    pub config: Arc<Config>,
    pub session_manager: Arc<SessionManager>,
    pub command_dispatcher: Arc<CommandDispatcher>,
    pub plugin_manager: Arc<PluginManager>,
}

/// Where a plugin sees its data folder
const DATA_DIR: &str = "/data";

// A pointer per element, so this is about 8 MB of tables
const MAX_TABLE_ELEMENTS: usize = 1_000_000;

/// Caps what a plugin allocates across all of its memories and tables, not per memory
// Failed grows stay counted, since wasmtime also reports failures it never asked about
pub struct PluginLimiter {
    memory_limit: usize,
    memory_used: usize,
    table_elements: usize,
}

impl PluginLimiter {
    pub fn new(memory_limit: usize) -> Self {
        Self {
            memory_limit,
            memory_used: 0,
            table_elements: 0,
        }
    }
}

impl wasmtime::ResourceLimiter for PluginLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let growth = desired.saturating_sub(current);
        if self.memory_used.saturating_add(growth) > self.memory_limit {
            return Ok(false);
        }
        self.memory_used += growth;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let growth = desired.saturating_sub(current);
        if self.table_elements.saturating_add(growth) > MAX_TABLE_ELEMENTS {
            return Ok(false);
        }
        self.table_elements += growth;
        Ok(true)
    }
}

type Translations = Vec<(String, String)>;

pub struct ContextResource {
    pub context: Arc<PluginContext>,
}

pub struct PluginHostState {
    pub wasi_ctx: WasiCtx,
    pub resource_table: ResourceTable,
    pub limits: PluginLimiter,
    pub proxy: Option<ProxyPluginContext>,
    pub plugin_name: String,
    pub data_folder: PathBuf,
    pub plugin: Option<Weak<WasmPlugin>>,
    pub killed: Arc<AtomicBool>,
    // Translations registered before the plugin's name is known, which is their namespace
    early_translations: Option<Vec<(String, Translations)>>,
}

impl Default for PluginHostState {
    fn default() -> Self {
        Self::new(String::new(), PathBuf::new(), None)
    }
}

impl PluginHostState {
    #[must_use]
    pub fn new(
        plugin_name: String,
        data_folder: PathBuf,
        proxy: Option<ProxyPluginContext>,
    ) -> Self {
        let mut wasi = WasiCtxBuilder::new();
        wasi.inherit_stdout().inherit_stderr();
        if !data_folder.as_os_str().is_empty()
            && let Err(e) = wasi.preopened_dir(&data_folder, DATA_DIR, FsPerms::ReadWrite)
        {
            tracing::warn!(
                "Plugin '{}' gets no data folder; '{}' could not be opened: {}",
                plugin_name,
                data_folder.display(),
                e
            );
        }
        Self {
            wasi_ctx: wasi.build(),
            resource_table: ResourceTable::new(),
            limits: PluginLimiter::new(usize::MAX),
            proxy,
            plugin_name,
            data_folder,
            plugin: None,
            killed: Arc::new(AtomicBool::new(false)),
            early_translations: Some(Vec::new()),
        }
    }

    /// Registers the translations held back until the plugin reported its name
    pub fn register_early_translations(&mut self) {
        for (locale, entries) in self.early_translations.take().unwrap_or_default() {
            self.register_translations_now(locale, entries);
        }
    }

    fn register_translations_now(&self, locale: String, entries: Vec<(String, String)>) {
        if let Err(e) =
            crate::i18n::register(&crate::i18n::namespace(&self.plugin_name), &locale, entries)
        {
            tracing::warn!(
                "[Plugin: {}] Could not register '{}' translations: {}",
                self.plugin_name,
                locale,
                e
            );
        }
    }

    pub fn add_context(
        &mut self,
        context: Arc<PluginContext>,
    ) -> wasmtime::Result<Resource<wit::vine::plugin::context::Context>> {
        let res = self.resource_table.push(ContextResource { context })?;
        Ok(Resource::new_own(res.rep()))
    }

    pub fn get_context(
        &self,
        resource: &Resource<wit::vine::plugin::context::Context>,
    ) -> wasmtime::Result<&ContextResource> {
        Ok(self
            .resource_table
            .get(&Resource::new_borrow(resource.rep()))?)
    }
}

impl WasiView for PluginHostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

impl wit::vine::plugin::types::Host for PluginHostState {}
impl wit::vine::plugin::metadata::Host for PluginHostState {}
impl wit::vine::plugin::event::Host for PluginHostState {}
impl wit::vine::plugin::context::Host for PluginHostState {}

impl wit::vine::plugin::logging::Host for PluginHostState {
    async fn log(
        &mut self,
        level: wit::vine::plugin::logging::Level,
        message: String,
    ) -> wasmtime::Result<()> {
        match level {
            wit::vine::plugin::logging::Level::Trace => {
                tracing::trace!("[Plugin: {}] {}", self.plugin_name, message)
            }
            wit::vine::plugin::logging::Level::Debug => {
                tracing::debug!("[Plugin: {}] {}", self.plugin_name, message)
            }
            wit::vine::plugin::logging::Level::Info => {
                tracing::info!("[Plugin: {}] {}", self.plugin_name, message)
            }
            wit::vine::plugin::logging::Level::Warn => {
                tracing::warn!("[Plugin: {}] {}", self.plugin_name, message)
            }
            wit::vine::plugin::logging::Level::Error => {
                tracing::error!("[Plugin: {}] {}", self.plugin_name, message)
            }
        }
        Ok(())
    }
}

impl wit::vine::plugin::translation::Host for PluginHostState {
    async fn register_translations(
        &mut self,
        locale: String,
        entries: Vec<(String, String)>,
    ) -> wasmtime::Result<()> {
        match &mut self.early_translations {
            Some(early) => early.push((locale, entries)),
            None => self.register_translations_now(locale, entries),
        }
        Ok(())
    }

    async fn translate(
        &mut self,
        player_uuid: Option<String>,
        key: String,
        args: Vec<String>,
    ) -> wasmtime::Result<String> {
        let locale = player_uuid
            .and_then(|uuid| uuid::Uuid::parse_str(&uuid).ok())
            .and_then(|uuid| self.proxy.as_ref()?.session_manager.locale_by_uuid(uuid));
        // Namespaces are stored lowercase, like the folders they come from
        let key = match key.split_once(':') {
            Some((namespace, rest)) if namespace.eq_ignore_ascii_case("vine") => rest.to_string(),
            Some((namespace, rest)) => format!("{}:{rest}", crate::i18n::namespace(namespace)),
            None => format!("{}:{key}", crate::i18n::namespace(&self.plugin_name)),
        };
        let args: Vec<&(dyn std::fmt::Display + Sync)> = args
            .iter()
            .map(|arg| arg as &(dyn std::fmt::Display + Sync))
            .collect();
        Ok(crate::i18n::translate(locale.as_deref(), &key, &args))
    }

    async fn get_player_locale(&mut self, player_uuid: String) -> wasmtime::Result<Option<String>> {
        Ok(uuid::Uuid::parse_str(&player_uuid)
            .ok()
            .and_then(|uuid| self.proxy.as_ref()?.session_manager.locale_by_uuid(uuid)))
    }

    async fn set_player_locale(
        &mut self,
        player_uuid: String,
        locale: Option<String>,
    ) -> wasmtime::Result<bool> {
        let (Some(proxy), Ok(uuid)) = (&self.proxy, uuid::Uuid::parse_str(&player_uuid)) else {
            return Ok(false);
        };
        Ok(proxy
            .session_manager
            .set_locale_override(uuid, locale.as_deref()))
    }
}

impl wit::vine::plugin::command::Host for PluginHostState {
    async fn reply(
        &mut self,
        sender: wit::vine::plugin::types::CommandSender,
        message: String,
    ) -> wasmtime::Result<()> {
        if let Some(proxy) = &self.proxy {
            match sender.sender_type {
                wit::vine::plugin::types::CommandSenderType::Console => {
                    tracing::info!("[Console] {}", message);
                }
                wit::vine::plugin::types::CommandSenderType::Player => {
                    if let Some(uuid_str) = sender.player_uuid
                        && let Ok(target_uuid) = uuid::Uuid::parse_str(&uuid_str)
                        && let Some(session) = proxy
                            .session_manager
                            .list_sessions()
                            .into_iter()
                            .find(|s| s.uuid == target_uuid)
                    {
                        let _ = session.action_tx.send(PlayerAction::Message(
                            crate::protocol::text::parse_message(&message),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl wit::vine::plugin::proxy::Host for PluginHostState {
    async fn get_player_count(&mut self) -> wasmtime::Result<u32> {
        Ok(self
            .proxy
            .as_ref()
            .map(|p| p.session_manager.count() as u32)
            .unwrap_or(0))
    }

    async fn get_players(&mut self) -> wasmtime::Result<Vec<wit::vine::plugin::types::PlayerInfo>> {
        if let Some(proxy) = &self.proxy {
            let list = proxy
                .session_manager
                .list_sessions()
                .into_iter()
                .map(|s| wit::vine::plugin::types::PlayerInfo {
                    uuid: s.uuid.to_string(),
                    username: s.username,
                    current_server: s.current_server,
                    client_ip: s.client_ip,
                    protocol_version: s.protocol_version,
                })
                .collect();
            Ok(list)
        } else {
            Ok(Vec::new())
        }
    }

    async fn get_player_by_name(
        &mut self,
        username: String,
    ) -> wasmtime::Result<Option<wit::vine::plugin::types::PlayerInfo>> {
        if let Some(proxy) = &self.proxy {
            let session = proxy.session_manager.get_session(&username);
            Ok(session.map(|s| wit::vine::plugin::types::PlayerInfo {
                uuid: s.uuid.to_string(),
                username: s.username,
                current_server: s.current_server,
                client_ip: s.client_ip,
                protocol_version: s.protocol_version,
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_player_by_uuid(
        &mut self,
        uuid: String,
    ) -> wasmtime::Result<Option<wit::vine::plugin::types::PlayerInfo>> {
        if let Some(proxy) = &self.proxy
            && let Ok(target_uuid) = uuid::Uuid::parse_str(&uuid)
        {
            let session = proxy
                .session_manager
                .list_sessions()
                .into_iter()
                .find(|s| s.uuid == target_uuid);
            return Ok(session.map(|s| wit::vine::plugin::types::PlayerInfo {
                uuid: s.uuid.to_string(),
                username: s.username,
                current_server: s.current_server,
                client_ip: s.client_ip,
                protocol_version: s.protocol_version,
            }));
        }
        Ok(None)
    }

    async fn get_servers(&mut self) -> wasmtime::Result<Vec<wit::vine::plugin::types::ServerInfo>> {
        if let Some(proxy) = &self.proxy {
            let sessions = proxy.session_manager.list_sessions();
            let mut list = Vec::new();
            for (name, srv) in &proxy.config.servers {
                let player_count = sessions
                    .iter()
                    .filter(|s| s.current_server == *name)
                    .count() as u32;
                list.push(wit::vine::plugin::types::ServerInfo {
                    name: name.clone(),
                    address: srv.address.clone(),
                    player_count,
                });
            }
            Ok(list)
        } else {
            Ok(Vec::new())
        }
    }

    async fn broadcast(&mut self, message: String) -> wasmtime::Result<()> {
        if let Some(proxy) = &self.proxy {
            for session in proxy.session_manager.list_sessions() {
                let _ = session.action_tx.send(PlayerAction::Message(
                    crate::protocol::text::parse_message(&message),
                ));
            }
            tracing::info!("[Broadcast] {}", message);
        }
        Ok(())
    }

    async fn send_message(
        &mut self,
        player_uuid: String,
        message: String,
    ) -> wasmtime::Result<bool> {
        if let Some(proxy) = &self.proxy
            && let Ok(target_uuid) = uuid::Uuid::parse_str(&player_uuid)
            && let Some(session) = proxy
                .session_manager
                .list_sessions()
                .into_iter()
                .find(|s| s.uuid == target_uuid)
        {
            let _ = session.action_tx.send(PlayerAction::Message(
                crate::protocol::text::parse_message(&message),
            ));
            return Ok(true);
        }
        Ok(false)
    }

    async fn disconnect_player(
        &mut self,
        player_uuid: String,
        reason: String,
    ) -> wasmtime::Result<bool> {
        if let Some(proxy) = &self.proxy
            && let Ok(target_uuid) = uuid::Uuid::parse_str(&player_uuid)
            && let Some(session) = proxy
                .session_manager
                .list_sessions()
                .into_iter()
                .find(|s| s.uuid == target_uuid)
        {
            let _ = session.action_tx.send(PlayerAction::Disconnect(reason));
            return Ok(true);
        }
        Ok(false)
    }

    async fn connect_player(
        &mut self,
        player_uuid: String,
        server_name: String,
    ) -> wasmtime::Result<bool> {
        if let Some(proxy) = &self.proxy
            && proxy.config.servers.contains_key(&server_name)
            && let Ok(target_uuid) = uuid::Uuid::parse_str(&player_uuid)
            && let Some(session) = proxy
                .session_manager
                .list_sessions()
                .into_iter()
                .find(|s| s.uuid == target_uuid)
        {
            let _ = session
                .action_tx
                .send(PlayerAction::Connect { server_name });
            return Ok(true);
        }
        Ok(false)
    }

    async fn send_plugin_message(
        &mut self,
        player_uuid: String,
        channel: String,
        data: Vec<u8>,
    ) -> wasmtime::Result<bool> {
        if let Some(proxy) = &self.proxy
            && let Ok(target_uuid) = uuid::Uuid::parse_str(&player_uuid)
            && let Some(session) = proxy
                .session_manager
                .list_sessions()
                .into_iter()
                .find(|s| s.uuid == target_uuid)
        {
            let _ = session
                .action_tx
                .send(PlayerAction::PluginMessage { channel, data });
            return Ok(true);
        }
        Ok(false)
    }
}

impl wit::vine::plugin::context::HostContext for PluginHostState {
    async fn register_event(
        &mut self,
        context: Resource<wit::vine::plugin::context::Context>,
        handler_id: u32,
        event_type: wit::vine::plugin::event::EventType,
        priority: wit::vine::plugin::types::EventPriority,
    ) -> wasmtime::Result<()> {
        let plugin = self
            .plugin
            .as_ref()
            .and_then(|p| p.upgrade())
            .ok_or_else(|| wasmtime::Error::msg("Plugin reference is no longer valid"))?;

        let api_event_type = match event_type {
            wit::vine::plugin::event::EventType::ProxyPing => EventType::ProxyPing,
            wit::vine::plugin::event::EventType::PlayerPreLogin => EventType::PlayerPreLogin,
            wit::vine::plugin::event::EventType::PlayerLogin => EventType::PlayerLogin,
            wit::vine::plugin::event::EventType::PlayerJoin => EventType::PlayerJoin,
            wit::vine::plugin::event::EventType::ServerConnect => EventType::ServerConnect,
            wit::vine::plugin::event::EventType::ServerConnected => EventType::ServerConnected,
            wit::vine::plugin::event::EventType::PlayerDisconnect => EventType::PlayerDisconnect,
            wit::vine::plugin::event::EventType::PlayerChat => EventType::PlayerChat,
            wit::vine::plugin::event::EventType::PlayerCommand => EventType::PlayerCommand,
            wit::vine::plugin::event::EventType::PluginMessage => EventType::PluginMessage,
        };

        let api_priority = match priority {
            wit::vine::plugin::types::EventPriority::Lowest => EventPriority::Lowest,
            wit::vine::plugin::types::EventPriority::Low => EventPriority::Low,
            wit::vine::plugin::types::EventPriority::Normal => EventPriority::Normal,
            wit::vine::plugin::types::EventPriority::High => EventPriority::High,
            wit::vine::plugin::types::EventPriority::Highest => EventPriority::Highest,
            wit::vine::plugin::types::EventPriority::Monitor => EventPriority::Monitor,
        };

        if let Some(proxy) = &self.proxy {
            proxy
                .plugin_manager
                .register_event_handler(api_event_type, api_priority, handler_id, plugin)
                .await;
        }

        let ctx_res = self.get_context(&context)?;
        let mut events = ctx_res.context.registered_events.lock().await;
        events.push((handler_id, api_event_type, api_priority));

        Ok(())
    }

    async fn register_command(
        &mut self,
        context: Resource<wit::vine::plugin::context::Context>,
        command_id: u32,
        name: String,
        description: String,
        aliases: Vec<String>,
        permission: Option<String>,
    ) -> wasmtime::Result<()> {
        let plugin = self
            .plugin
            .as_ref()
            .and_then(|p| p.upgrade())
            .ok_or_else(|| wasmtime::Error::msg("Plugin reference is no longer valid"))?;

        if let Some(proxy) = &self.proxy {
            proxy
                .plugin_manager
                .register_command(command_id, name, description, aliases, permission, plugin)
                .await;
        }

        let ctx_res = self.get_context(&context)?;
        let mut commands = ctx_res.context.registered_commands.lock().await;
        commands.push(command_id);

        Ok(())
    }

    async fn get_data_folder(
        &mut self,
        _context: Resource<wit::vine::plugin::context::Context>,
    ) -> wasmtime::Result<String> {
        Ok(DATA_DIR.to_string())
    }

    async fn drop(
        &mut self,
        rep: Resource<wit::vine::plugin::context::Context>,
    ) -> wasmtime::Result<()> {
        let _ = self
            .resource_table
            .delete::<ContextResource>(Resource::new_own(rep.rep()));
        Ok(())
    }
}
