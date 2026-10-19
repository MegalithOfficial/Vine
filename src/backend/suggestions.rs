use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use bytes::Bytes;
use pumpkin_util::text::TextComponent;

use super::readers::Session;
use crate::command::ProxyCommandSource;
use crate::protocol::packets::play::{CommandSuggestions, Suggestion};
use crate::protocol::text::component_json;
use crate::protocol::{ProtocolVersion, encode_packet};
pub(super) struct SuggestionRequest {
    pub(super) id: i32,
    pub(super) input: String,
    pub(super) offset: usize,
    pub(super) source: ProxyCommandSource,
}

/// Root command names of the proxy's own, waiting to be merged into the backend's answer
pub(super) struct PendingSuggestion {
    pub(super) id: i32,
    pub(super) clean_cmd: String,
    pub(super) offset: usize,
    pub(super) proxy_matches: Vec<(String, Option<String>)>,
}

pub(super) enum Suggest {
    /// Arguments to a proxy command, answered by the proxy alone
    Proxy(SuggestionRequest),
    /// A command name the proxy has matches for, merged into the backend's answer
    Completion(PendingSuggestion),
    Backend,
}

// The backend gets this long to answer before the proxy's own command names are sent alone
const COMPLETION_WAIT: Duration = Duration::from_millis(200);

/// The client's suggestion requests the proxy answers
#[derive(Default)]
pub(super) struct Suggesting {
    // One argument suggestion per player is worked out at a time. The client only uses the answer
    // to its newest request, so only the newest one that arrives meanwhile is kept for next.
    pub(super) running: Option<RunningSuggestion>,
    pub(super) next: Option<(SuggestionRequest, u64)>,
    pending: HashMap<i32, (u64, PendingSuggestion)>,
    due: VecDeque<(tokio::time::Instant, i32)>,
}

pub(super) struct RunningSuggestion {
    pub(super) served: u64,
    answer: tokio::task::JoinHandle<Option<Bytes>>,
}

pub(super) enum SuggestionEvent {
    Answered(Option<Bytes>),
    Due,
}

impl Suggesting {
    pub(super) fn ask(&mut self, session: &Session, request: SuggestionRequest, served: u64) {
        if self.running.is_some() {
            self.next = Some((request, served));
            return;
        }
        let version = session.version;
        let dispatcher = session.command_dispatcher.clone();
        // Plugins answer these, so they are worked out off the tunnel
        let answer = tokio::task::spawn_blocking(move || {
            let SuggestionRequest {
                id,
                input,
                offset,
                source,
            } = request;
            let suggestions = dispatcher.suggest_with_range(&input, &source);
            let response = CommandSuggestions {
                id,
                start: (suggestions.range.start + offset) as i32,
                length: suggestions.range.len() as i32,
                matches: suggestions
                    .suggestions
                    .into_iter()
                    .map(|s| Suggestion {
                        text: s.text.cached_text().clone(),
                        tooltip: s.tooltip.map(|t| component_json(&t, version)),
                    })
                    .collect(),
            };
            encode_packet(&response, version).ok()
        });
        self.running = Some(RunningSuggestion { served, answer });
    }

    pub(super) fn expect(&mut self, completion: PendingSuggestion, served: u64) {
        self.due
            .push_back((tokio::time::Instant::now() + COMPLETION_WAIT, completion.id));
        self.pending.insert(completion.id, (served, completion));
    }

    pub(super) fn answered(&mut self, id: i32) -> Option<PendingSuggestion> {
        self.pending.remove(&id).map(|(_, pending)| pending)
    }

    /// The proxy's own answer to the oldest completion the backend has not answered in time
    pub(super) fn due(&mut self, generation: u64, version: ProtocolVersion) -> Option<Bytes> {
        let (_, id) = self.due.pop_front()?;
        let (served, pending) = self.pending.remove(&id)?;
        if served != generation {
            return None;
        }
        let response = CommandSuggestions {
            id,
            start: pending.offset as i32,
            length: pending.clean_cmd.len() as i32,
            matches: pending
                .proxy_matches
                .into_iter()
                .map(|(cmd, tip)| Suggestion {
                    text: cmd,
                    tooltip: tip.map(|t| component_json(&TextComponent::text(t), version)),
                })
                .collect(),
        };
        encode_packet(&response, version).ok()
    }

    pub(super) fn forget(&mut self) {
        self.pending.clear();
        self.due.clear();
    }

    pub(super) async fn progress(&mut self) -> SuggestionEvent {
        let due = self.due.front().map(|(at, _)| *at);
        let running = &mut self.running;
        tokio::select! {
            answer = async {
                match running {
                    Some(running) => (&mut running.answer).await,
                    None => std::future::pending().await,
                }
            } => SuggestionEvent::Answered(answer.ok().flatten()),
            () = async {
                match due {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => SuggestionEvent::Due,
        }
    }
}

pub(super) fn merge_suggestions(
    backend_matches: &mut Vec<Suggestion>,
    proxy_matches: Vec<(String, Option<String>)>,
    version: ProtocolVersion,
) {
    for (cmd_name, tooltip) in proxy_matches {
        if !backend_matches
            .iter()
            .any(|bm| bm.text.eq_ignore_ascii_case(&cmd_name))
        {
            backend_matches.push(Suggestion {
                text: cmd_name,
                tooltip: tooltip.map(|t| component_json(&TextComponent::text(t), version)),
            });
        }
    }
    backend_matches.sort_by(|a, b| a.text.cmp(&b.text));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_suggestions_dedupes_and_sorts() {
        let mut backend_matches = vec![
            Suggestion {
                text: "server".to_string(),
                tooltip: None,
            },
            Suggestion {
                text: "status".to_string(),
                tooltip: None,
            },
        ];
        merge_suggestions(
            &mut backend_matches,
            vec![
                (
                    "server".to_string(),
                    Some("Switch or view backend server".to_string()),
                ),
                (
                    "send".to_string(),
                    Some("Send players to a backend".to_string()),
                ),
            ],
            ProtocolVersion(769),
        );

        let names: Vec<&str> = backend_matches.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(names, ["send", "server", "status"]);
        assert!(backend_matches[1].tooltip.is_none());
    }
}
