use pumpkin_command::CommandSource;
use pumpkin_command::Requirement;
use pumpkin_command::argument_builder::{ArgumentBuilder, argument, command};
use pumpkin_command::argument_types::core::string::StringArgumentType;
use pumpkin_command::context::command_context::CommandContext;
use pumpkin_command::dispatcher::CommandDispatcher as RawCommandDispatcher;
use pumpkin_command::node::{CommandExecutor, CommandExecutorResult};
use pumpkin_command::suggestion::provider::{SuggestionProvider, SuggestionProviderResult};
use pumpkin_command::suggestion::suggestions::SuggestionsBuilder;
use pumpkin_util::text::TextComponent;

use super::{CommandSender, ProxyCommandSource, command_error};
use crate::session::PlayerAction;

struct ServerSuggestionProvider;

impl SuggestionProvider<ProxyCommandSource> for ServerSuggestionProvider {
    fn suggest(
        &self,
        context: &CommandContext<ProxyCommandSource>,
        builder: SuggestionsBuilder,
    ) -> SuggestionProviderResult {
        let mut builder = builder;
        let remaining = builder.remaining_lowercase().to_string();
        for server in context.source.config.servers.keys() {
            if server.to_ascii_lowercase().starts_with(&remaining) {
                builder = builder.suggest(server.as_str());
            }
        }
        builder.build()
    }
}

/// /server (no args): shows current server (if player) and lists all available servers
struct ServerInfoCommandExecutor;

impl CommandExecutor<ProxyCommandSource> for ServerInfoCommandExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        if !context.source.has_permission("vine.command.server") {
            return Err(command_error(
                "You do not have permission to execute this command (required: vine.command.server).",
            ));
        }

        let mut available: Vec<&String> = context.source.config.servers.keys().collect();
        available.sort();
        let servers_str = available
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        match &context.source.sender {
            CommandSender::Player { username, .. } => {
                let current = context
                    .source
                    .session_manager
                    .get_session(username)
                    .map(|s| s.current_server)
                    .unwrap_or_else(|| "unknown".to_string());

                context.source.send_message(TextComponent::text(format!(
                    "§6[Vine] §fYou are currently connected to server '§a{}§f'.\n§6[Vine] §7Available servers: §e{}",
                    current, servers_str
                )));
            }
            CommandSender::Console => {
                context.source.send_message(TextComponent::text(format!(
                    "Available backend servers: {}",
                    servers_str
                )));
            }
        }

        Ok(1)
    }
}

/// /server <name>: connects the player to that backend server
struct ServerSwitchCommandExecutor;

impl CommandExecutor<ProxyCommandSource> for ServerSwitchCommandExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        if !context.source.has_permission("vine.command.server") {
            return Err(command_error(
                "You do not have permission to execute this command (required: vine.command.server).",
            ));
        }

        let server_name = StringArgumentType::get(context, "server")?;

        let (username, action_tx) = match &context.source.sender {
            CommandSender::Player {
                username,
                action_tx,
            } => (username.clone(), action_tx.clone()),
            CommandSender::Console => {
                return Err(command_error(
                    "Console cannot switch servers. Use '/send <player> <server>' instead.",
                ));
            }
        };

        let target_server = match context
            .source
            .config
            .servers
            .keys()
            .find(|k| k.eq_ignore_ascii_case(server_name))
        {
            Some(name) => name.clone(),
            None => {
                let mut available: Vec<&String> = context.source.config.servers.keys().collect();
                available.sort();
                return Err(command_error(format!(
                    "Unknown server '{}'. Available servers: [{}]",
                    server_name,
                    available
                        .into_iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        };

        if let Some(session) = context.source.session_manager.get_session(&username)
            && session.current_server.eq_ignore_ascii_case(&target_server)
        {
            return Err(command_error(format!(
                "You are already connected to '{}'!",
                target_server
            )));
        }

        context.source.send_message(TextComponent::text(format!(
            "§6[Vine] §eConnecting you to '§a{}§e'...",
            target_server
        )));

        let _ = action_tx.send(PlayerAction::Connect {
            server_name: target_server,
        });

        Ok(1)
    }
}

pub fn register(dispatcher: &mut RawCommandDispatcher<ProxyCommandSource>) {
    dispatcher.register(
        command("server", "View or connect to a backend server")
            .requires(Requirement::from("vine.command.server"))
            .executes(ServerInfoCommandExecutor)
            .then(
                argument("server", StringArgumentType::SingleWord)
                    .suggests(ServerSuggestionProvider)
                    .executes(ServerSwitchCommandExecutor),
            ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::session::{PlayerSession, SessionManager};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    #[test]
    fn test_server_command_execution() {
        let mut dispatcher = RawCommandDispatcher::new();
        register(&mut dispatcher);

        let config = Arc::new(Config::default());
        let session_manager = Arc::new(SessionManager::new());
        let (action_tx, mut action_rx) = mpsc::unbounded_channel();

        let session = PlayerSession {
            username: "Steve".to_string(),
            uuid: Uuid::new_v4(),
            current_server: "lobby".to_string(),
            action_tx: action_tx.clone(),
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 765,
            locale: None,
        };
        let _guard = session_manager.try_register(session).unwrap();

        let source = ProxyCommandSource {
            sender: CommandSender::Player {
                username: "Steve".to_string(),
                action_tx,
            },
            config: config.clone(),
            session_manager: session_manager.clone(),
        };

        // 1. /server (no args) succeeds
        let res = dispatcher.execute_input("server", &source);
        assert!(res.is_ok());
        let msg_action = action_rx.try_recv();
        assert!(matches!(msg_action, Ok(PlayerAction::Message(_))));

        // 2. /server survival requests connection to survival
        let res_switch = dispatcher.execute_input("server survival", &source);
        assert!(res_switch.is_ok());
        let switch_msg = action_rx.try_recv();
        assert!(matches!(switch_msg, Ok(PlayerAction::Message(_))));
        let action = action_rx.try_recv();
        assert_eq!(
            action.unwrap(),
            PlayerAction::Connect {
                server_name: "survival".to_string()
            }
        );

        // 3. /server lobby fails because player is already on lobby
        let res_already = dispatcher.execute_input("server lobby", &source);
        assert!(res_already.is_err());

        // 4. /server unknown fails
        let res_unknown = dispatcher.execute_input("server not_a_server", &source);
        assert!(res_unknown.is_err());
    }
}
