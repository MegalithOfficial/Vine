use std::collections::BTreeMap;

use crate::protocol::text::parse_message;
use pumpkin_command::CommandSource;
use pumpkin_command::argument_builder::{ArgumentBuilder, command};
use pumpkin_command::context::command_context::CommandContext;
use pumpkin_command::dispatcher::CommandDispatcher as RawCommandDispatcher;
use pumpkin_command::node::{CommandExecutor, CommandExecutorResult};

use super::{ProxyCommandSource, command_error};

/// Command to list players grouped by server across the entire proxy
pub struct GlistCommandExecutor;

impl CommandExecutor<ProxyCommandSource> for GlistCommandExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        if !context.source.has_permission("vine.command.glist") {
            return Err(command_error(
                context
                    .source
                    .tr("vine.command.no_permission", &[&"vine.command.glist"]),
            ));
        }

        let sessions = context.source.session_manager.list_sessions();
        let total_players = sessions.len();

        let mut server_players: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for server_name in context.source.config.servers.keys() {
            server_players.entry(server_name.clone()).or_default();
        }

        for session in sessions {
            server_players
                .entry(session.current_server.clone())
                .or_default()
                .push(session.username);
        }

        let mut lines = Vec::new();
        for (server_name, mut players) in server_players {
            players.sort_unstable();
            if players.is_empty() {
                lines.push(
                    context
                        .source
                        .tr("vine.command.glist.empty_server", &[&server_name]),
                );
            } else {
                lines.push(context.source.tr(
                    "vine.command.glist.server",
                    &[&server_name, &players.len(), &players.join(", ")],
                ));
            }
        }

        lines.push(
            context
                .source
                .tr("vine.command.glist.total", &[&total_players]),
        );
        context
            .source
            .send_message(parse_message(&lines.join("\n")));
        Ok(total_players as i32)
    }
}

use pumpkin_command::Requirement;

pub fn register(dispatcher: &mut RawCommandDispatcher<ProxyCommandSource>) {
    dispatcher.register(
        command(
            "glist",
            "Lists online players grouped by server across the proxy",
        )
        .requires(Requirement::from("vine.command.glist"))
        .executes(GlistCommandExecutor),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    use crate::command::{CommandDispatcher, CommandSender};
    use crate::config::{BackendConfig, Config, ForwardingMode};
    use crate::session::{PlayerAction, PlayerSession, SessionManager};

    #[tokio::test]
    async fn test_glist_empty() {
        let mut config = Config::default();
        config.servers.insert(
            "lobby".to_string(),
            BackendConfig {
                address: "127.0.0.1:25565".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd: None,
                icon_path: None,
            },
        );

        let session_manager = Arc::new(SessionManager::new());
        let (action_tx, mut action_rx) = mpsc::channel(16);
        let source = ProxyCommandSource {
            sender: CommandSender::Player {
                username: "TestPlayer".to_string(),
                action_tx,
            },
            config: Arc::new(config),
            session_manager,
        };

        let dispatcher = CommandDispatcher::new();
        let res = dispatcher.execute_input("glist", &source);
        assert!(res.is_ok());

        let msg = action_rx.recv().await.unwrap();
        match msg {
            PlayerAction::Message(text) => {
                let s = text.to_pretty_console();
                assert!(s.contains("[lobby] (0):"));
                assert!(s.contains("Total players online: 0"));
            }
            _ => panic!("Expected Message action"),
        }
    }

    #[tokio::test]
    async fn test_glist_with_players() {
        let mut config = Config::default();
        config.servers.insert(
            "lobby".to_string(),
            BackendConfig {
                address: "127.0.0.1:25565".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd: None,
                icon_path: None,
            },
        );
        config.servers.insert(
            "survival".to_string(),
            BackendConfig {
                address: "127.0.0.1:25566".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd: None,
                icon_path: None,
            },
        );

        let session_manager = Arc::new(SessionManager::new());
        let (tx1, _) = mpsc::channel(16);
        let (tx2, _) = mpsc::channel(16);

        let _guard1 = session_manager
            .try_register(PlayerSession {
                username: "Steve".to_string(),
                uuid: Uuid::new_v4(),
                current_server: "lobby".to_string(),
                action_tx: tx1,
                client_ip: "127.0.0.1".to_string(),
                protocol_version: 765,
                locale: None,
                locale_override: None,
                plugin_waiting: Default::default(),
            })
            .unwrap();
        let _guard2 = session_manager
            .try_register(PlayerSession {
                username: "Alex".to_string(),
                uuid: Uuid::new_v4(),
                current_server: "survival".to_string(),
                action_tx: tx2,
                client_ip: "127.0.0.1".to_string(),
                protocol_version: 765,
                locale: None,
                locale_override: None,
                plugin_waiting: Default::default(),
            })
            .unwrap();

        let (action_tx, mut action_rx) = mpsc::channel(16);
        let source = ProxyCommandSource {
            sender: CommandSender::Player {
                username: "Admin".to_string(),
                action_tx,
            },
            config: Arc::new(config),
            session_manager,
        };

        let dispatcher = CommandDispatcher::new();
        let res = dispatcher.execute_input("glist", &source);
        assert!(res.is_ok());

        let msg = action_rx.recv().await.unwrap();
        match msg {
            PlayerAction::Message(text) => {
                let s = text.to_pretty_console();
                assert!(s.contains("[lobby] (1): Steve"));
                assert!(s.contains("[survival] (1): Alex"));
                assert!(s.contains("Total players online: 2"));
            }
            _ => panic!("Expected Message action"),
        }
    }
}
