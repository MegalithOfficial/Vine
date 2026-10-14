use std::net::SocketAddr;

use pumpkin_command::CommandSource;
use pumpkin_command::argument_builder::{ArgumentBuilder, argument, command};
use pumpkin_command::argument_types::core::string::StringArgumentType;
use pumpkin_command::context::command_context::CommandContext;
use pumpkin_command::dispatcher::CommandDispatcher as RawCommandDispatcher;
use pumpkin_command::node::{CommandExecutor, CommandExecutorResult};
use pumpkin_command::suggestion::provider::{SuggestionProvider, SuggestionProviderResult};
use pumpkin_command::suggestion::suggestions::SuggestionsBuilder;
use pumpkin_util::text::TextComponent;

use super::{ProxyCommandSource, command_error};
use crate::session::PlayerAction;

/// Parses a host:port address string
pub fn parse_address(addr: &str) -> Option<(String, u16)> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return Some((socket_addr.ip().to_string(), socket_addr.port()));
    }
    if let Some((host, port_str)) = addr.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return Some((host.to_string(), port));
    }
    None
}

struct TargetSuggestionProvider;

impl SuggestionProvider<ProxyCommandSource> for TargetSuggestionProvider {
    fn suggest(
        &self,
        context: &CommandContext<ProxyCommandSource>,
        builder: SuggestionsBuilder,
    ) -> SuggestionProviderResult {
        let mut builder = builder;
        let remaining = builder.remaining_lowercase().to_string();
        if "all".starts_with(&remaining) {
            builder = builder.suggest("all");
        }
        for session in context.source.session_manager.list_sessions() {
            if session
                .username
                .to_ascii_lowercase()
                .starts_with(&remaining)
            {
                builder = builder.suggest(session.username);
            }
        }
        builder.build()
    }
}

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

struct SendCommandExecutor;

impl CommandExecutor<ProxyCommandSource> for SendCommandExecutor {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        if !context.source.has_permission("vine.command.send") {
            return Err(command_error(
                "You do not have permission to execute this command (required: vine.command.send).",
            ));
        }

        let target = StringArgumentType::get(context, "target")?;
        let server_name = StringArgumentType::get(context, "server")?;

        let canonical_server = match context
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
                    "Unknown backend server '{}'. Available servers: [{}]",
                    server_name,
                    available
                        .into_iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        };

        if target.eq_ignore_ascii_case("all") {
            let sessions = context.source.session_manager.list_sessions();
            if sessions.is_empty() {
                return Err(command_error("No players currently online to send."));
            }

            let count = sessions.len();
            for session in &sessions {
                let _ = session.action_tx.send(PlayerAction::Connect {
                    server_name: canonical_server.clone(),
                });
            }

            let msg = format!("Sent {} player(s) to '{}'", count, canonical_server);
            context.source.send_message(TextComponent::text(msg));
            Ok(count as i32)
        } else {
            let session = context
                .source
                .session_manager
                .get_session(target)
                .ok_or_else(|| command_error(format!("Player '{}' is not online.", target)))?;

            let _ = session.action_tx.send(PlayerAction::Connect {
                server_name: canonical_server.clone(),
            });

            let msg = format!("Sent '{}' to '{}'", session.username, canonical_server);
            context.source.send_message(TextComponent::text(msg));
            Ok(1)
        }
    }
}

pub fn register(dispatcher: &mut RawCommandDispatcher<ProxyCommandSource>) {
    dispatcher.register(
        command(
            "send",
            "Sends a player or all players to another backend server",
        )
        .then(
            argument("target", StringArgumentType::SingleWord)
                .suggests(TargetSuggestionProvider)
                .then(
                    argument("server", StringArgumentType::SingleWord)
                        .suggests(ServerSuggestionProvider)
                        .executes(SendCommandExecutor),
                ),
        ),
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
    use crate::session::{PlayerSession, SessionManager};

    #[test]
    fn test_parse_address() {
        assert_eq!(
            parse_address("127.0.0.1:25565"),
            Some(("127.0.0.1".to_string(), 25565))
        );
        assert_eq!(
            parse_address("mc.example.com:25577"),
            Some(("mc.example.com".to_string(), 25577))
        );
        assert_eq!(parse_address("invalid"), None);
    }

    #[tokio::test]
    async fn test_send_command_execution() {
        let mut config = Config::default();
        config.servers.insert(
            "survival".to_string(),
            BackendConfig {
                address: "127.0.0.1:25567".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd_line1: None,
                motd_line2: None,
                icon_path: None,
            },
        );

        let session_manager = Arc::new(SessionManager::new());
        let (tx, mut rx) = mpsc::unbounded_channel();
        session_manager.register(PlayerSession {
            username: "Steve".to_string(),
            uuid: Uuid::new_v4(),
            current_server: "lobby".to_string(),
            action_tx: tx,
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 765,
        });

        let source = ProxyCommandSource {
            sender: CommandSender::Console,
            config: Arc::new(config),
            session_manager,
        };

        let dispatcher = CommandDispatcher::new();
        let res = dispatcher.execute_input("send Steve survival", &source);
        assert!(res.is_ok());

        let action = rx.recv().await;
        assert_eq!(
            action,
            Some(PlayerAction::Connect {
                server_name: "survival".to_string(),
            })
        );

        // Player not in admin list is rejected
        let (non_admin_tx, _) = mpsc::unbounded_channel();
        let non_admin_source = ProxyCommandSource {
            sender: CommandSender::Player {
                username: "RegularPlayer".to_string(),
                action_tx: non_admin_tx,
            },
            config: Arc::new(Config::default()),
            session_manager: Arc::new(SessionManager::new()),
        };
        let res_denied = dispatcher.execute_input("send Steve survival", &non_admin_source);
        assert!(res_denied.is_err());
        assert!(
            res_denied
                .unwrap_err()
                .message
                .to_pretty_console()
                .contains("permission")
        );
    }

    #[test]
    fn test_send_command_unknown_server() {
        let config = Config::default();
        let session_manager = Arc::new(SessionManager::new());
        let source = ProxyCommandSource {
            sender: CommandSender::Console,
            config: Arc::new(config),
            session_manager,
        };

        let dispatcher = CommandDispatcher::new();
        let res = dispatcher.execute_input("send Steve nonexistent", &source);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .message
                .to_pretty_console()
                .contains("Unknown backend server")
        );
    }

    #[test]
    fn test_send_command_offline_player() {
        let mut config = Config::default();
        config.servers.insert(
            "survival".to_string(),
            BackendConfig {
                address: "127.0.0.1:25567".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd_line1: None,
                motd_line2: None,
                icon_path: None,
            },
        );

        let session_manager = Arc::new(SessionManager::new());
        let source = ProxyCommandSource {
            sender: CommandSender::Console,
            config: Arc::new(config),
            session_manager,
        };

        let dispatcher = CommandDispatcher::new();
        let res = dispatcher.execute_input("send Alex survival", &source);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .message
                .to_pretty_console()
                .contains("Player 'Alex' is not online")
        );
    }

    #[test]
    fn test_send_command_suggestions() {
        let mut config = Config::default();
        config.servers.insert(
            "survival".to_string(),
            BackendConfig {
                address: "127.0.0.1:25567".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd_line1: None,
                motd_line2: None,
                icon_path: None,
            },
        );
        config.servers.insert(
            "lobby".to_string(),
            BackendConfig {
                address: "127.0.0.1:25565".to_string(),
                forwarding: ForwardingMode::None,
                secret: None,
                motd_line1: None,
                motd_line2: None,
                icon_path: None,
            },
        );

        let session_manager = Arc::new(SessionManager::new());
        let (tx, _rx) = mpsc::unbounded_channel();
        session_manager.register(PlayerSession {
            username: "Steve".to_string(),
            uuid: Uuid::new_v4(),
            current_server: "lobby".to_string(),
            action_tx: tx,
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 765,
        });

        let source = ProxyCommandSource {
            sender: CommandSender::Console,
            config: Arc::new(config),
            session_manager,
        };

        let dispatcher = CommandDispatcher::new();
        let target_suggestions = dispatcher.suggest("send ", &source);
        let names: Vec<&str> = target_suggestions.iter().map(|s| s.text.as_str()).collect();
        assert!(names.contains(&"all"));
        assert!(names.contains(&"Steve"));

        let server_suggestions = dispatcher.suggest("send Steve ", &source);
        let servers: Vec<&str> = server_suggestions.iter().map(|s| s.text.as_str()).collect();
        assert!(servers.contains(&"survival"));
        assert!(servers.contains(&"lobby"));
    }
}
