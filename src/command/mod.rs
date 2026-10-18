pub mod glist;
pub mod send;
pub mod server;

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use pumpkin_command::Requirement;
use pumpkin_command::argument_builder::{ArgumentBuilder, argument, command};
use pumpkin_command::argument_types::core::string::StringArgumentType;
use pumpkin_command::context::command_context::CommandContext;
use pumpkin_command::context::string_range::StringRange;
pub use pumpkin_command::dispatcher::CommandDispatcher as RawCommandDispatcher;
pub use pumpkin_command::errors::command_syntax_error::CommandSyntaxError;
pub use pumpkin_command::errors::error_types::LiteralCommandErrorType;
pub use pumpkin_command::node::{CommandExecutor, CommandExecutorResult};
pub use pumpkin_command::source::CommandSource;
use pumpkin_command::suggestion::Suggestion;
use pumpkin_command::suggestion::provider::{SuggestionProvider, SuggestionProviderResult};
pub use pumpkin_command::suggestion::suggestions::Suggestions;
use pumpkin_command::suggestion::suggestions::SuggestionsBuilder;
use pumpkin_util::text::TextComponent;

use crate::config::Config;
use crate::i18n::translate;
use crate::protocol::text::parse_message;
use crate::session::{PlayerAction, SessionManager};

pub static PROXY_COMMAND_ERROR: LiteralCommandErrorType =
    LiteralCommandErrorType::new("Proxy command execution failed");

pub fn command_error(msg: impl Into<String>) -> CommandSyntaxError {
    CommandSyntaxError::create_without_context(&PROXY_COMMAND_ERROR, parse_message(&msg.into()))
}

/// Represents the origin that invoked a command
#[derive(Clone)]
pub enum CommandSender {
    /// Command invoked via proxy console (stdin)
    Console,
    /// Command invoked by an in-game player
    Player {
        username: String,
        action_tx: mpsc::UnboundedSender<PlayerAction>,
    },
}

impl CommandSender {
    /// Sends response feedback to the command sender
    pub fn send_message(&self, message: TextComponent) {
        match self {
            Self::Console => {
                info!("{}", message.to_pretty_console());
            }
            Self::Player { action_tx, .. } => {
                let _ = action_tx.send(PlayerAction::Message(message));
            }
        }
    }
}

/// Execution context passed to commands
#[derive(Clone)]
pub struct ProxyCommandSource {
    pub sender: CommandSender,
    pub config: Arc<Config>,
    pub session_manager: Arc<SessionManager>,
}

impl ProxyCommandSource {
    /// Evaluates if the command source has the specified permission node.
    /// Console always returns `true`.
    pub fn has_permission(&self, node: &str) -> bool {
        match &self.sender {
            CommandSender::Console => true,
            CommandSender::Player { username, .. } => {
                self.config.permissions.has_permission(username, node)
            }
        }
    }

    /// Translates `key` into the sender's language
    pub fn tr(&self, key: &str, args: &[&(dyn std::fmt::Display + Sync)]) -> String {
        let locale = match &self.sender {
            CommandSender::Console => None,
            CommandSender::Player { username, .. } => self.session_manager.locale(username),
        };
        translate(locale.as_deref(), key, args)
    }

    /// Replies with a translated message
    pub fn reply(&self, key: &str, args: &[&(dyn std::fmt::Display + Sync)]) {
        self.send_message(parse_message(&self.tr(key, args)));
    }

    /// Returns true if the command sender has administrative privileges (node `vine.admin` or `*`)
    pub fn is_admin(&self) -> bool {
        self.has_permission("vine.admin")
    }
}

impl CommandSource for ProxyCommandSource {
    fn send_message(&self, message: TextComponent) {
        self.sender.send_message(message);
    }

    fn send_error(&self, error: TextComponent) {
        self.send_message(error);
    }

    fn has_permission(&self, permission: &str) -> bool {
        self.has_permission(permission)
    }
}

/// Help command listing registered commands
pub struct HelpCommandExecutor;

impl CommandExecutor<ProxyCommandSource> for HelpCommandExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        context.source.reply("vine.command.help", &[]);
        Ok(1)
    }
}

/// Suggestion provider for `/help [command]`
struct HelpSuggestionProvider;

impl SuggestionProvider<ProxyCommandSource> for HelpSuggestionProvider {
    fn suggest(
        &self,
        context: &CommandContext<ProxyCommandSource>,
        builder: SuggestionsBuilder,
    ) -> SuggestionProviderResult {
        let mut builder = builder;
        let remaining = builder.remaining_lowercase().to_string();
        let is_admin = context.source.is_admin();

        for (cmd_name, required_perm) in [
            ("server", Some("vine.command.server")),
            ("send", Some("vine.command.send")),
            ("list", Some("vine.command.list")),
            ("glist", Some("vine.command.glist")),
            ("help", Some("vine.command.help")),
        ] {
            if cmd_name.starts_with(&remaining) {
                let allowed = is_admin
                    || required_perm
                        .map(|p| context.source.has_permission(p))
                        .unwrap_or(true);
                if allowed {
                    builder = builder.suggest(cmd_name);
                }
            }
        }
        builder.build()
    }
}

/// Detailed help executor for `/help <command>`
struct CommandSpecificHelpExecutor;

impl CommandExecutor<ProxyCommandSource> for CommandSpecificHelpExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        let cmd = StringArgumentType::get(context, "command")?;
        let key = match cmd.to_ascii_lowercase().as_str() {
            "server" => "vine.command.help.server",
            "send" => "vine.command.help.send",
            "list" => "vine.command.help.list",
            "glist" => "vine.command.help.glist",
            "help" => "vine.command.help.help",
            _ => "vine.command.help.unknown",
        };
        context.source.reply(key, &[]);
        Ok(1)
    }
}

/// List command displaying online players
pub struct ListCommandExecutor;

impl CommandExecutor<ProxyCommandSource> for ListCommandExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        let sessions = context.source.session_manager.list_sessions();
        if sessions.is_empty() {
            context.source.reply("vine.command.list.empty", &[]);
            return Ok(0);
        }

        let players_info: Vec<String> = sessions
            .into_iter()
            .map(|s| {
                context
                    .source
                    .tr("vine.command.list.entry", &[&s.username, &s.current_server])
            })
            .collect();

        context.source.reply(
            "vine.command.list.players",
            &[&players_info.len(), &players_info.join(", ")],
        );
        Ok(players_info.len() as i32)
    }
}

use std::sync::{Mutex, RwLock, RwLockReadGuard, TryLockError};

type CommandBuilder = pumpkin_command::argument_builder::CommandArgumentBuilder<ProxyCommandSource>;

/// Central registry and dispatcher for commands using `pumpkin-command`
pub struct CommandDispatcher {
    inner: RwLock<RawCommandDispatcher<ProxyCommandSource>>,
    // Changes never wait for the write lock: a plugin call holding the read lock may need the
    // very worker thread a blocked writer would sit on. They queue and apply on the next access.
    pending: Mutex<Vec<PendingChange>>,
}

enum PendingChange {
    Register(CommandBuilder, Option<String>),
    Deactivate(String),
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandDispatcher {
    /// Creates a new CommandDispatcher with default built-in commands
    pub fn new() -> Self {
        let mut dispatcher = RawCommandDispatcher::new();
        server::register(&mut dispatcher);
        send::register(&mut dispatcher);
        glist::register(&mut dispatcher);
        dispatcher.register(
            command("list", "Lists online players connected to the proxy")
                .requires(Requirement::from("vine.command.list"))
                .executes(ListCommandExecutor),
        );
        dispatcher.register(
            command("help", "Displays list of available proxy commands")
                .requires(Requirement::from("vine.command.help"))
                .executes(HelpCommandExecutor)
                .then(
                    argument("command", StringArgumentType::SingleWord)
                        .suggests(HelpSuggestionProvider)
                        .executes(CommandSpecificHelpExecutor),
                ),
        );
        Self {
            inner: RwLock::new(dispatcher),
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Registers a new command builder into the dispatcher
    pub fn register(&self, builder: CommandBuilder) {
        self.change(PendingChange::Register(builder, None));
    }

    /// Registers a plugin's command. Registering onto an existing node keeps that node, so its
    /// owner is updated here to the plugin registering it now.
    pub fn register_for(&self, builder: CommandBuilder, plugin: &str) {
        self.change(PendingChange::Register(builder, Some(plugin.to_string())));
    }

    pub fn deactivate_source(&self, source: &str) {
        self.change(PendingChange::Deactivate(source.to_string()));
    }

    fn change(&self, change: PendingChange) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.push(change);
        }
        match self.inner.try_write() {
            Ok(mut lock) => self.drain_pending(&mut lock),
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {}
        }
    }

    fn drain_pending(&self, dispatcher: &mut RawCommandDispatcher<ProxyCommandSource>) {
        if let Ok(mut pending) = self.pending.lock() {
            for change in pending.drain(..) {
                match change {
                    PendingChange::Register(builder, owner) => {
                        let node = dispatcher.register(builder);
                        if owner.is_some() {
                            dispatcher.tree[node].meta.source = owner;
                        }
                    }
                    PendingChange::Deactivate(source) => {
                        dispatcher.deactivate_commands_from_source(&source);
                    }
                }
            }
        }
    }

    fn read(&self) -> Option<RwLockReadGuard<'_, RawCommandDispatcher<ProxyCommandSource>>> {
        if self.pending.lock().is_ok_and(|pending| !pending.is_empty())
            && let Ok(mut lock) = self.inner.try_write()
        {
            self.drain_pending(&mut lock);
        }
        self.inner.read().ok()
    }

    /// Returns true if a command with the given name is registered
    pub fn has_command(&self, name: &str) -> bool {
        let clean = name.trim_start_matches('/').to_ascii_lowercase();
        if let Some(lock) = self.read() {
            lock.has_command(&clean)
        } else {
            false
        }
    }

    /// Dispatches a command for execution, reporting any error messages back to the source
    pub fn handle_command(&self, source: &ProxyCommandSource, input: &str) {
        if let Some(lock) = self.read() {
            lock.handle_command(source, input);
        }
    }

    /// Executes raw input directly, returning the execution result
    pub fn execute_input(
        &self,
        input: &str,
        source: &ProxyCommandSource,
    ) -> Result<i32, CommandSyntaxError> {
        let trimmed = input.trim();
        let clean = trimmed.strip_prefix('/').unwrap_or(trimmed);
        if let Some(lock) = self.read() {
            lock.execute_input(clean, source)
        } else {
            Err(command_error("Command dispatcher lock poisoned"))
        }
    }

    /// Returns all permitted commands for the given source
    pub fn get_all_permitted_commands(&self, source: &ProxyCommandSource) -> Vec<(String, String)> {
        if let Some(lock) = self.read() {
            lock.get_all_permitted_commands(source)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Returns true if `plugin` may register `name`: it is free, already the plugin's, or was left
    /// by a plugin that is no longer active. Built-in commands are never handed over.
    pub fn can_claim(&self, name: &str, plugin: &str) -> bool {
        let clean = name.trim_start_matches('/').to_ascii_lowercase();
        let Some(lock) = self.read() else {
            return false;
        };
        let Some(node) = lock.tree.get(&clean) else {
            return true;
        };
        match lock.tree[node].meta.source.as_deref() {
            None => false,
            Some(owner) => owner == plugin || lock.is_disabled(&clean),
        }
    }

    /// Returns true if the proxy should run this command for `source`: it exists, is active and
    /// the source may use it. Anything else goes on to the backend.
    pub fn handles(&self, name: &str, source: &ProxyCommandSource) -> bool {
        let clean = name.trim_start_matches('/').to_ascii_lowercase();
        let Some(lock) = self.read() else {
            return false;
        };
        lock.tree
            .get(&clean)
            .is_some_and(|node| !lock.is_disabled(&clean) && lock.tree.can_use(node.into(), source))
    }

    /// Returns suggestions with range information for any command input.
    /// If input contains arguments (i.e. has a space), it evaluates argument suggestions.
    /// If input is typing the root command name, it suggests permitted root commands starting with the prefix.
    pub fn suggest_command(&self, input: &str, source: &ProxyCommandSource) -> Suggestions {
        let clean = input.strip_prefix('/').unwrap_or(input);
        if clean.contains(' ') {
            let first_word = clean.split_whitespace().next().unwrap_or(clean);
            if self.handles(first_word, source)
                && let Some(lock) = self.read()
            {
                return lock.suggest_with_range(clean, source);
            }
            return Suggestions::empty();
        }

        let clean_lower = clean.to_ascii_lowercase();
        let permitted = self.get_all_permitted_commands(source);
        let mut suggestions = Vec::new();
        for (cmd_name, description) in permitted {
            if cmd_name.starts_with(&clean_lower) {
                suggestions.push(Suggestion::with_tooltip(
                    StringRange::between(0, clean.len()),
                    cmd_name.to_string(),
                    TextComponent::text(description.to_string()),
                ));
            }
        }
        Suggestions::new(StringRange::between(0, clean.len()), suggestions)
    }

    /// Returns suggestions for the command string
    pub fn suggest(&self, input: &str, source: &ProxyCommandSource) -> Vec<String> {
        self.suggest_command(input, source)
            .suggestions
            .into_iter()
            .map(|s| s.text.cached_text().clone())
            .collect()
    }

    /// Returns suggestions with range information
    pub fn suggest_with_range(&self, input: &str, source: &ProxyCommandSource) -> Suggestions {
        self.suggest_command(input, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatcher_registration_and_dispatch() {
        let dispatcher = CommandDispatcher::new();
        assert!(dispatcher.has_command("send"));
        assert!(dispatcher.has_command("/send"));
        assert!(dispatcher.has_command("help"));
        assert!(dispatcher.has_command("list"));
        assert!(dispatcher.has_command("glist"));
        assert!(dispatcher.has_command("/glist"));
        assert!(!dispatcher.has_command("unknown"));

        let config = Arc::new(Config::default());
        let session_manager = Arc::new(SessionManager::new());
        let source = ProxyCommandSource {
            sender: CommandSender::Console,
            config,
            session_manager,
        };

        let res = dispatcher.execute_input("help", &source);
        assert!(res.is_ok());

        let res_slash = dispatcher.execute_input("/help", &source);
        assert!(res_slash.is_ok());

        let res_unknown = dispatcher.execute_input("unknown_cmd", &source);
        assert!(res_unknown.is_err());
    }

    #[test]
    fn test_register_while_dispatching_is_deferred() {
        let dispatcher = CommandDispatcher::new();
        {
            let _dispatching = dispatcher.inner.read().unwrap();
            dispatcher
                .register(command("late", "Registered mid-dispatch").executes(ListCommandExecutor));
        }
        assert!(dispatcher.has_command("late"));
    }

    #[test]
    fn test_suggest_various_inputs() {
        let dispatcher = CommandDispatcher::new();
        let config = Arc::new(Config::default());
        let session_manager = Arc::new(SessionManager::new());
        let source = ProxyCommandSource {
            sender: CommandSender::Console,
            config,
            session_manager,
        };

        let s_empty = dispatcher.suggest_with_range("", &source);
        let names_empty: Vec<&str> = s_empty
            .suggestions
            .iter()
            .map(|s| s.text.cached_text().as_str())
            .collect();
        assert!(names_empty.contains(&"server"));
        assert!(names_empty.contains(&"send"));
        assert!(names_empty.contains(&"glist"));
        assert!(names_empty.contains(&"list"));
        assert!(names_empty.contains(&"help"));

        let s_s = dispatcher.suggest_with_range("s", &source);
        let names_s: Vec<&str> = s_s
            .suggestions
            .iter()
            .map(|s| s.text.cached_text().as_str())
            .collect();
        assert_eq!(names_s, vec!["send", "server"]);

        let s_ser = dispatcher.suggest_with_range("ser", &source);
        let names_ser: Vec<&str> = s_ser
            .suggestions
            .iter()
            .map(|s| s.text.cached_text().as_str())
            .collect();
        assert_eq!(names_ser, vec!["server"]);

        let s_server = dispatcher.suggest_with_range("server", &source);
        let names_server: Vec<&str> = s_server
            .suggestions
            .iter()
            .map(|s| s.text.cached_text().as_str())
            .collect();
        assert_eq!(names_server, vec!["server"]);

        let s_server_space = dispatcher.suggest_with_range("server ", &source);
        let names_server_space: Vec<&str> = s_server_space
            .suggestions
            .iter()
            .map(|s| s.text.cached_text().as_str())
            .collect();
        assert!(names_server_space.contains(&"lobby"));

        let s_help_space = dispatcher.suggest_with_range("help ", &source);
        let names_help_space: Vec<&str> = s_help_space
            .suggestions
            .iter()
            .map(|s| s.text.cached_text().as_str())
            .collect();
        assert!(names_help_space.contains(&"server"));
        assert!(names_help_space.contains(&"send"));
        assert!(names_help_space.contains(&"glist"));
        assert!(names_help_space.contains(&"list"));
        assert!(names_help_space.contains(&"help"));
    }
}
