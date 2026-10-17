use std::sync::{Arc, Weak};

use pumpkin_command::argument_builder::{ArgumentBuilder, argument, command, literal};
use pumpkin_command::argument_types::core::string::StringArgumentType;
use pumpkin_command::context::command_context::CommandContext;
use pumpkin_command::node::{CommandExecutor, CommandExecutorResult};
use pumpkin_command::suggestion::provider::{SuggestionProvider, SuggestionProviderResult};
use pumpkin_command::suggestion::suggestions::SuggestionsBuilder;
use pumpkin_command::{CommandSource, Requirement};
use pumpkin_util::text::TextComponent;
use pumpkin_util::text::color::NamedColor;

use super::PluginManager;
use crate::command::{CommandDispatcher, ProxyCommandSource};

const PERMISSION: &str = "vine.command.plugins";

pub fn register(dispatcher: &CommandDispatcher, manager: &Arc<PluginManager>) {
    let manager = Arc::downgrade(manager);
    dispatcher.register(
        command("vine", "Manages the proxy's plugins")
            .requires(Requirement::from(PERMISSION))
            .then(literal("plugins").executes(ListPlugins {
                manager: manager.clone(),
            }))
            .then(
                literal("reload")
                    .executes(ReloadPlugins {
                        manager: manager.clone(),
                    })
                    .then(
                        argument("plugin", StringArgumentType::SingleWord)
                            .suggests(PluginNames {
                                manager: manager.clone(),
                            })
                            .executes(ReloadPlugins { manager }),
                    ),
            ),
    );
}

// Runs off the dispatcher lock, since reloading registers and deactivates commands
fn spawn_reply<F, Fut>(context: &CommandContext<ProxyCommandSource>, task: F)
where
    F: FnOnce(Arc<ProxyCommandSource>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(task(context.source.clone()));
}

struct ListPlugins {
    manager: Weak<PluginManager>,
}

impl CommandExecutor<ProxyCommandSource> for ListPlugins {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        let manager = self.manager.clone();
        spawn_reply(context, move |source| async move {
            let Some(manager) = manager.upgrade() else {
                return;
            };
            let plugins = manager.plugin_list().await;
            let listed = plugins
                .iter()
                .map(|(metadata, disabled)| {
                    let state = if *disabled { " (disabled)" } else { "" };
                    format!("{} v{}{}", metadata.name, metadata.version, state)
                })
                .collect::<Vec<_>>()
                .join(", ");
            source.send_message(TextComponent::text(format!(
                "Plugins ({}): {}",
                plugins.len(),
                listed
            )));
        });
        Ok(1)
    }
}

struct ReloadPlugins {
    manager: Weak<PluginManager>,
}

impl CommandExecutor<ProxyCommandSource> for ReloadPlugins {
    fn execute(&self, context: &CommandContext<ProxyCommandSource>) -> CommandExecutorResult {
        let manager = self.manager.clone();
        let name = StringArgumentType::get(context, "plugin")
            .ok()
            .map(str::to_string);
        spawn_reply(context, move |source| async move {
            let Some(manager) = manager.upgrade() else {
                return;
            };
            let names = match name {
                Some(name) => vec![name],
                None => manager.plugin_names().await,
            };
            if names.is_empty() {
                source.send_message(TextComponent::text("No plugins are loaded."));
                return;
            }
            for name in names {
                let message = match manager.reload_plugin(&name).await {
                    Ok(metadata) => TextComponent::text(format!(
                        "Reloaded {} v{}",
                        metadata.name, metadata.version
                    ))
                    .color_named(NamedColor::Green),
                    Err(e) => TextComponent::text(e).color_named(NamedColor::Red),
                };
                source.send_message(message);
            }
        });
        Ok(1)
    }
}

struct PluginNames {
    manager: Weak<PluginManager>,
}

impl SuggestionProvider<ProxyCommandSource> for PluginNames {
    fn suggest(
        &self,
        _context: &CommandContext<ProxyCommandSource>,
        mut builder: SuggestionsBuilder,
    ) -> SuggestionProviderResult {
        if let Some(manager) = self.manager.upgrade() {
            let remaining = builder.remaining_lowercase().to_string();
            for name in manager.plugin_names_now() {
                if name.to_ascii_lowercase().starts_with(&remaining) {
                    builder = builder.suggest(name);
                }
            }
        }
        builder.build()
    }
}
