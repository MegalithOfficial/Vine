use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, mpsc, watch};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::bridge::{BackendBridge, Phase, disconnect_packet};
use super::client_queue::{CLIENT_WRITE_TIMEOUT, ClientQueue, Room};
use super::connection::{Backend, Conn};
use super::login::{BackendReader, BackendWriter, PreparedBackend};
use super::readers::{BRAND_CHANNEL, BackendEvent, ClientEvent, Session, Setting};
use super::suggestions::{Suggesting, SuggestionEvent, merge_suggestions};
use super::switch::{
    AckClock, Connected, HELD_BACKEND_LIMIT, Job, SWITCH_ACK_TIMEOUT, Switch, SwitchEvent,
    client_timeout, job_ended, switch_progress,
};
use super::task::Task;
use crate::i18n::translate;
use crate::plugin::api::ServerConnectedEvent;
use crate::protocol::packets::login::LoginAcknowledged;
use crate::protocol::packets::play::{
    ClientboundPluginMessage, CommandSuggestions, PlayKeepAlive, StartConfiguration, SystemChat,
    write_plugin_message,
};
use crate::protocol::packets::switch::{Leftovers, join_game_sequence};
use crate::protocol::text::{component_json, parse_message};
use crate::protocol::{PacketKind, ProtocolVersion, decode_packet, encode_packet};
use crate::session::PlayerAction;
/// Where the client is in the connection's phases
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Link {
    Login,
    Config,
    Play,
    // The backend asked the client to reconfigure and the client has not acknowledged yet, so what
    // reaches the client is read as configuration while what it sends is still play
    Reconfiguring,
}

impl Link {
    /// The phase the client reads what is queued for it next in
    fn clientbound(self) -> Phase {
        match self {
            Link::Login => Phase::Login,
            Link::Config | Link::Reconfiguring => Phase::Config,
            Link::Play => Phase::Play,
        }
    }
}

/// The backend the client's packets go to, and which generation of the session's backends it is
#[derive(Clone)]
pub(super) struct Served {
    pub(super) generation: u64,
    pub(super) name: String,
}

pub(super) enum End {
    Closed,
    Kicked(String),
}

enum Event {
    ClientGone,
    Client(Option<ClientEvent>),
    BackendRoom(Option<mpsc::OwnedPermit<Bytes>>),
    Backend(Option<BackendEvent>),
    Action(Option<PlayerAction>),
    MessageRoom(Option<OwnedSemaphorePermit>),
    Switch(SwitchEvent),
    Suggestion(SuggestionEvent),
}

/// A proxy message waiting for room in the client queue
pub(super) struct HeldMessage {
    bytes: Bytes,
    room: Room,
}

async fn message_room(message: &mut Option<HeldMessage>) -> Option<OwnedSemaphorePermit> {
    match message {
        Some(held) => held.room.as_mut().await.ok(),
        None => std::future::pending().await,
    }
}

async fn backend_room(writes: Option<mpsc::Sender<Bytes>>) -> Option<mpsc::OwnedPermit<Bytes>> {
    match writes {
        Some(writes) => writes.reserve_owned().await.ok(),
        None => std::future::pending().await,
    }
}

/// One player's session after the first backend took them. Everything about it is decided here,
/// one event at a time; the readers, writers and connect jobs around it only report to it.
pub(super) struct Tunnel {
    pub(super) bridge: Arc<BackendBridge>,
    pub(super) session: Arc<Session>,
    pub(super) link: Link,
    pub(super) switch: Switch,
    pub(super) backend: Backend,
    // Keep-alive replies meant for a previous backend would make the current one kick the
    // player, so only replies to the current backend's latest challenge are forwarded
    pub(super) keep_alive: Option<i64>,
    pub(super) leftovers: Leftovers,
    pub(super) client_settings: ClientSettings,
    pub(super) suggesting: Suggesting,
    pub(super) client_out: ClientQueue,
    pub(super) client_events: mpsc::Receiver<ClientEvent>,
    pub(super) actions: mpsc::Receiver<PlayerAction>,
    pub(super) message: Option<HeldMessage>,
    // A client packet waiting for room in the backend's queue; the client is not read meanwhile
    pub(super) stalled: Option<Bytes>,
    // The backend the client's packets go to; changing it drops answers worked out for the last one
    pub(super) served: watch::Sender<Served>,
    // Configuration packets the client sent while an earlier backend was current are not passed on
    pub(super) stale_before: u64,
    // Plugins hear about connections in order, without holding up the tunnel
    pub(super) plugin_events: Option<tokio::task::JoinHandle<()>>,
    pub(super) _client_reader: Task,
}

impl Tunnel {
    pub(super) async fn run(&mut self) -> End {
        loop {
            let event = self.next().await;
            if let Err(end) = self.handle(event) {
                return end;
            }
        }
    }

    async fn next(&mut self) -> Event {
        let takes_client = self.takes_client();
        let held = self.message.is_some();
        let stalled = match (&self.backend.conn, &self.stalled) {
            (Conn::Open(open), Some(_)) => Some(open.writes.clone()),
            _ => None,
        };
        tokio::select! {
            () = self.client_out.closed() => Event::ClientGone,
            event = self.client_events.recv(), if takes_client => Event::Client(event),
            permit = backend_room(stalled) => Event::BackendRoom(permit),
            event = self.backend.next_event() => Event::Backend(event),
            action = self.actions.recv(), if !held => Event::Action(action),
            permit = message_room(&mut self.message) => Event::MessageRoom(permit),
            event = switch_progress(&mut self.switch) => Event::Switch(event),
            event = self.suggesting.progress() => Event::Suggestion(event),
        }
    }

    fn takes_client(&self) -> bool {
        self.stalled.is_none()
            && match self.switch {
                Switch::Stopping { .. } => false,
                Switch::AwaitingAck { .. } => true,
                // With the backend gone, what the client sends waits for the next one
                _ => matches!(self.backend.conn, Conn::Open(_)),
            }
    }

    fn handle(&mut self, event: Event) -> Result<(), End> {
        match event {
            Event::ClientGone | Event::Client(None) | Event::Action(None) => Err(End::Closed),
            Event::Client(Some(event)) => self.client_event(event),
            Event::BackendRoom(permit) => match (permit, self.stalled.take()) {
                (Some(permit), Some(packet)) => {
                    permit.send(packet);
                    Ok(())
                }
                (None, _) => self.backend_lost(None),
                (Some(_), None) => Ok(()),
            },
            Event::Backend(Some(BackendEvent::Packet {
                packet,
                permit,
                done,
            })) => {
                self.backend_packet(packet, permit);
                let _ = done.send(());
                Ok(())
            }
            Event::Backend(Some(BackendEvent::Lost { reason })) => self.backend_lost(reason),
            Event::Backend(Some(BackendEvent::ClientGone)) => Err(End::Closed),
            Event::Backend(None) => self.backend_stopped(),
            Event::Action(Some(action)) => self.action(action),
            Event::MessageRoom(permit) => {
                if let (Some(held), Some(permit)) = (self.message.take(), permit) {
                    self.send_play(held.bytes, Some(permit));
                }
                Ok(())
            }
            Event::Switch(event) => self.switch_event(event),
            Event::Suggestion(event) => {
                self.suggestion_event(event);
                Ok(())
            }
        }
    }

    fn generation(&self) -> u64 {
        self.served.borrow().generation
    }

    fn locale(&self) -> Option<String> {
        self.bridge.locale()
    }

    fn translate(&self, key: &str, args: &[&(dyn std::fmt::Display + Sync)]) -> String {
        translate(self.locale().as_deref(), key, args)
    }

    /// Every packet of the proxy's own for a playing client goes through here
    fn send_play(&self, bytes: Bytes, permit: Option<OwnedSemaphorePermit>) {
        if self.link == Link::Play {
            self.client_out.push(bytes, permit);
        } else {
            debug!(
                "Dropping a message for '{}' outside play",
                self.session.username
            );
        }
    }

    fn notify(&self, text: String) {
        let version = self.session.version;
        let message = SystemChat {
            content: component_json(&parse_message(&text), version),
            overlay: false,
        };
        match encode_packet(&message, version) {
            Ok(bytes) => self.send_play(bytes, None),
            Err(e) => debug!("Skipping a notice for {}: {}", version, e),
        }
    }

    fn client_event(&mut self, event: ClientEvent) -> Result<(), End> {
        match event {
            ClientEvent::Packet {
                packet,
                entered,
                setting,
                completion,
                served,
            } => {
                if let Some(setting) = setting {
                    self.client_settings.apply(setting);
                }
                if let Some(completion) = completion {
                    self.suggesting.expect(completion, served);
                }
                let sent_in = self.link;
                if let Some(next) = entered {
                    self.link = match next {
                        Phase::Login => Link::Login,
                        Phase::Config => Link::Config,
                        Phase::Play => Link::Play,
                    };
                }
                if entered == Some(Phase::Config)
                    && matches!(self.switch, Switch::AwaitingAck { .. })
                {
                    return self.acknowledged();
                }
                if sent_in == Link::Config && served < self.stale_before {
                    debug!(
                        "Dropping a configuration packet from '{}' meant for a previous backend",
                        self.session.username
                    );
                } else {
                    self.forward(packet)?;
                }
                if entered == Some(Phase::Play) {
                    return self.reached_play();
                }
                Ok(())
            }
            ClientEvent::KeepAliveResponse { id, packet } => {
                if self.keep_alive == Some(id) {
                    self.forward(packet)
                } else {
                    debug!(
                        "Dropping stale keep-alive {} from '{}'",
                        id, self.session.username
                    );
                    Ok(())
                }
            }
            ClientEvent::Suggest { request, served } => {
                self.suggesting.ask(&self.session, request, served);
                Ok(())
            }
            // The backend being left would have seen the packet; a kick over it is moot
            ClientEvent::Kick(_) if matches!(self.switch, Switch::AwaitingAck { .. }) => Ok(()),
            ClientEvent::Kick(reason) => Err(End::Kicked(reason)),
            ClientEvent::Closed => Err(End::Closed),
        }
    }

    /// Passes a client packet on to the current backend
    fn forward(&mut self, packet: Bytes) -> Result<(), End> {
        let Conn::Open(open) = &self.backend.conn else {
            return Ok(());
        };
        let leaving = matches!(self.switch, Switch::AwaitingAck { .. });
        match open.writes.try_send(packet) {
            Ok(()) => Ok(()),
            Err(_) if leaving => Ok(()),
            Err(mpsc::error::TrySendError::Full(packet)) => {
                self.stalled = Some(packet);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => self.backend_lost(None),
        }
    }

    /// A packet from the backend whose effect on the session is decided here before it is queued
    fn backend_packet(&mut self, packet: crate::protocol::RawPacket, permit: OwnedSemaphorePermit) {
        let version = self.session.version;
        let mut replaced = None;
        if PacketKind::StartConfiguration.matches(packet.id, version) {
            if self.link == Link::Play {
                self.link = Link::Reconfiguring;
            }
        } else if PacketKind::PlayKeepAlive.matches(packet.id, version) {
            if let Ok(challenge) = decode_packet::<PlayKeepAlive>(&packet.payload, version) {
                self.keep_alive = Some(challenge.id);
            }
        } else if PacketKind::CommandSuggestionsResponse.matches(packet.id, version) {
            if let Ok(mut answer) = decode_packet::<CommandSuggestions>(&packet.payload, version)
                && let Some(pending) = self.suggesting.answered(answer.id)
            {
                merge_suggestions(&mut answer.matches, pending.proxy_matches, version);
                replaced = encode_packet(&answer, version).ok();
            }
        } else {
            self.leftovers.observe(&packet, version);
        }
        self.client_out
            .push(replaced.unwrap_or_else(|| packet.to_bytes()), Some(permit));
    }

    fn action(&mut self, action: PlayerAction) -> Result<(), End> {
        let version = self.session.version;
        let encoded = match action {
            PlayerAction::Connect { server_name } => return self.request_switch(server_name),
            PlayerAction::Disconnect(reason) => return Err(End::Kicked(reason)),
            PlayerAction::Message(content) => encode_packet(
                &SystemChat {
                    content: component_json(&content, version),
                    overlay: false,
                },
                version,
            ),
            PlayerAction::PluginMessage { channel, data } => {
                encode_packet(&ClientboundPluginMessage { channel, data }, version)
            }
        };
        if let Ok(bytes) = encoded {
            let room = self.client_out.room(bytes.len());
            self.message = Some(HeldMessage { bytes, room });
        }
        Ok(())
    }

    fn request_switch(&mut self, target: String) -> Result<(), End> {
        let idle = matches!(self.switch, Switch::Idle | Switch::Deferred { .. });
        if self.link != Link::Play && idle {
            self.switch = Switch::Deferred { target };
            return Ok(());
        }
        if !idle {
            self.notify(self.translate("vine.server.already_connecting", &[]));
            return Ok(());
        }
        info!(
            "Switching player '{}' to backend server '{}'...",
            self.session.username, target
        );
        let job = Job::spawn(
            self.bridge
                .clone()
                .switch_job(self.backend.name.clone(), target.clone()),
        );
        self.switch = Switch::Connecting { target, job };
        Ok(())
    }

    fn switch_event(&mut self, event: SwitchEvent) -> Result<(), End> {
        match event {
            SwitchEvent::Connected(connected) => {
                match std::mem::replace(&mut self.switch, Switch::Idle) {
                    Switch::Connecting { target, .. } => {
                        let connected = connected
                            .unwrap_or_else(|| Connected::Prepared(target, Err(job_ended())));
                        self.connected(connected)
                    }
                    Switch::Fallback { reason, .. } => match connected {
                        Some(connected) => self.fallen_back(reason, connected),
                        None => Err(End::Kicked(reason)),
                    },
                    other => {
                        self.switch = other;
                        Ok(())
                    }
                }
            }
            SwitchEvent::Written => {
                if let Switch::AwaitingAck { clock, .. } = &mut self.switch {
                    *clock = AckClock::Until(tokio::time::Instant::now() + SWITCH_ACK_TIMEOUT);
                }
                Ok(())
            }
            SwitchEvent::AckTimedOut => {
                let Switch::AwaitingAck { target, .. } = &self.switch else {
                    return Ok(());
                };
                warn!(
                    "Lost player '{}' while switching to '{}': {}",
                    self.session.username,
                    target,
                    client_timeout()
                );
                Err(End::Kicked(
                    self.translate("vine.server.switch_failed", &[target]),
                ))
            }
        }
    }

    /// A switch the player asked for has its next backend logged in, or failed to
    fn connected(&mut self, connected: Connected) -> Result<(), End> {
        if let Conn::Gone { reason } = &self.backend.conn {
            // A server that stops right after sending its players elsewhere still delivers them
            return match connected {
                Connected::Prepared(target, Ok(prepared)) => self.leave(target, prepared),
                other => {
                    if let Connected::Prepared(target, Err(e)) = other {
                        warn!(
                            "Failed to switch player '{}' to '{}': {}",
                            self.session.username, target, e
                        );
                    }
                    let reason = reason.clone();
                    self.reroute(reason)
                }
            };
        }
        match connected {
            Connected::Cancelled(reason) => {
                let reason =
                    reason.unwrap_or_else(|| self.translate("vine.plugin.cancelled_switch", &[]));
                self.notify(self.translate("vine.server.switch_cancelled", &[&reason]));
            }
            Connected::AlreadyThere(target) => {
                self.notify(self.translate("vine.command.server.already_connected", &[&target]));
            }
            Connected::Unknown(target) => {
                self.notify(self.translate("vine.server.unknown", &[&target]));
            }
            Connected::Prepared(target, Err(e)) => {
                warn!(
                    "Failed to switch player '{}' to '{}': {}",
                    self.session.username, target, e
                );
                let e = e.to_string();
                self.notify(self.translate("vine.server.connect_failed", &[&target, &e]));
            }
            Connected::Prepared(target, Ok(prepared)) if self.link == Link::Play => {
                return self.leave(target, prepared);
            }
            // Kept so another switch waits; it goes ahead once the client is playing
            Connected::Prepared(target, Ok(prepared)) => {
                self.switch = Switch::Held {
                    target,
                    prepared,
                    since: Instant::now(),
                };
            }
        }
        Ok(())
    }

    fn fallen_back(&mut self, reason: String, connected: Connected) -> Result<(), End> {
        match connected {
            Connected::Prepared(target, Ok(prepared)) => {
                info!(
                    "Rerouting player '{}' to fallback server '{}' (kicked from '{}': {})",
                    self.session.username, target, self.backend.name, reason
                );
                self.notify(self.translate("vine.server.fallback", &[&target, &reason]));
                self.leave(target, prepared)
            }
            Connected::Prepared(target, Err(e)) => {
                warn!(
                    "Failed to connect player '{}' to fallback server '{}': {}",
                    self.session.username, target, e
                );
                let e = e.to_string();
                Err(End::Kicked(self.translate(
                    "vine.server.fallback_failed",
                    &[&self.backend.name, &e],
                )))
            }
            Connected::Cancelled(cancel_reason) => {
                Err(End::Kicked(cancel_reason.unwrap_or(reason)))
            }
            Connected::AlreadyThere(_) | Connected::Unknown(_) => Err(End::Kicked(reason)),
        }
    }

    /// The client finished configuring and is playing
    fn reached_play(&mut self) -> Result<(), End> {
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            Switch::Deferred { target } => self.request_switch(target),
            Switch::Held {
                target,
                prepared,
                since,
            } => {
                // A backend kept waiting this long may have given up on the login, so it is
                // logged into again
                if since.elapsed() > HELD_BACKEND_LIMIT
                    && let Some(config) = self.bridge.proxy_config.servers.get(&target).cloned()
                {
                    let job = Job::spawn(self.bridge.clone().prepare_job(target.clone(), config));
                    self.switch = Switch::Connecting { target, job };
                    return Ok(());
                }
                self.leave(target, prepared)
            }
            other => {
                self.switch = other;
                Ok(())
            }
        }
    }

    fn backend_lost(&mut self, reason: Option<String>) -> Result<(), End> {
        if matches!(self.backend.conn, Conn::Gone { .. }) {
            return Ok(());
        }
        self.backend.conn = Conn::Gone {
            reason: reason.clone(),
        };
        self.stalled = None;
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            // A switch already on its way finishes instead, so a server that stops right after
            // sending its players elsewhere still delivers them there
            Switch::Held {
                target,
                prepared,
                since,
            } if since.elapsed() <= HELD_BACKEND_LIMIT => self.leave(target, prepared),
            Switch::Held { target, .. } => {
                match self.bridge.proxy_config.servers.get(&target).cloned() {
                    Some(config) => {
                        let job =
                            Job::spawn(self.bridge.clone().prepare_job(target.clone(), config));
                        self.switch = Switch::Connecting { target, job };
                        Ok(())
                    }
                    None => self.reroute(reason),
                }
            }
            Switch::Stopping { target, prepared } => self.stopped(target, prepared),
            Switch::Idle | Switch::Deferred { .. } => self.reroute(reason),
            other => {
                self.switch = other;
                Ok(())
            }
        }
    }

    /// The current backend's reader finished
    fn backend_stopped(&mut self) -> Result<(), End> {
        if let Conn::Open(open) = &mut self.backend.conn {
            open.events = None;
        }
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            Switch::Stopping { target, prepared } => self.stopped(target, prepared),
            other => {
                self.switch = other;
                self.backend_lost(None)
            }
        }
    }

    /// With the current backend gone, moves the player to the fallback server or disconnects them
    fn reroute(&mut self, reason: Option<String>) -> Result<(), End> {
        warn!(
            "Backend server '{}' disconnected player '{}': {:?}",
            self.backend.name, self.session.username, reason
        );
        let reason = reason.unwrap_or_else(|| self.translate("vine.server.lost_connection", &[]));
        let fallback = self
            .bridge
            .fallback_server
            .clone()
            .filter(|(name, _)| name != &self.backend.name);
        let Some((target, config)) = fallback else {
            return Err(End::Kicked(reason));
        };
        let job = Job::spawn(self.bridge.clone().fallback_job(
            self.backend.name.clone(),
            target,
            config,
        ));
        self.switch = Switch::Fallback { reason, job };
        Ok(())
    }

    /// Starts moving the client over to a backend that is logged in
    fn leave(&mut self, target: String, prepared: Box<PreparedBackend>) -> Result<(), End> {
        if self.backend.stop_reading() {
            self.switch = Switch::Stopping { target, prepared };
            return Ok(());
        }
        self.stopped(target, prepared)
    }

    /// Nothing more of the current backend reaches the client; hands the client over
    fn stopped(&mut self, target: String, mut prepared: Box<PreparedBackend>) -> Result<(), End> {
        let version = self.session.version;
        if let Some((mut pending, join_game)) = prepared.join_game.take() {
            let joining = join_game_sequence(&join_game, version).unwrap_or_else(|e| {
                debug!("Forwarding JoinGame from '{}' unchanged: {}", target, e);
                vec![join_game.to_bytes()]
            });
            pending.extend(self.leftovers.clear_players(version));
            pending.extend(joining);
            pending.extend(self.leftovers.clear_overlays(version));
            if !self.client_out.push_all(pending) {
                return Err(End::Closed);
            }
            let PreparedBackend { reader, writer, .. } = *prepared;
            return self.install(target, reader, writer, Phase::Play, Vec::new());
        }

        let clock = match self.link {
            Link::Play => {
                let Ok(start) = encode_packet(&StartConfiguration, version) else {
                    return Err(End::Kicked(
                        self.translate("vine.server.switch_failed", &[&target]),
                    ));
                };
                self.client_out.push(start, None);
                self.link = Link::Reconfiguring;
                AckClock::Writing(self.client_out.written())
            }
            // The current backend already asked for reconfiguration, or the client is still
            // logging in, so it is about to acknowledge
            Link::Reconfiguring | Link::Login => {
                AckClock::Until(tokio::time::Instant::now() + SWITCH_ACK_TIMEOUT)
            }
            // Only reached with the current backend gone: what the client sent in this
            // configuration phase until now was meant for it
            Link::Config => {
                self.stale_before = self.generation() + 1;
                return self.configure(target, prepared);
            }
        };
        if let (Some(packet), Conn::Open(open)) = (self.stalled.take(), &self.backend.conn) {
            let _ = open.writes.try_send(packet);
        }
        self.switch = Switch::AwaitingAck {
            target,
            prepared,
            clock,
        };
        Ok(())
    }

    fn acknowledged(&mut self) -> Result<(), End> {
        match std::mem::replace(&mut self.switch, Switch::Idle) {
            Switch::AwaitingAck {
                target, prepared, ..
            } => self.configure(target, prepared),
            other => {
                self.switch = other;
                Ok(())
            }
        }
    }

    /// Hands a configuring client to a 1.20.2+ backend that is waiting for its acknowledgement
    fn configure(&mut self, target: String, prepared: Box<PreparedBackend>) -> Result<(), End> {
        let version = self.session.version;
        let Ok(ack) = encode_packet(&LoginAcknowledged, version) else {
            return Err(End::Kicked(
                self.translate("vine.server.switch_failed", &[&target]),
            ));
        };
        let initial = std::iter::once(ack)
            .chain(self.client_settings.repeat(version))
            .collect();
        let PreparedBackend { reader, writer, .. } = *prepared;
        self.install(target, reader, writer, Phase::Config, initial)
    }

    fn install(
        &mut self,
        target: String,
        reader: BackendReader,
        writer: BackendWriter,
        phase: Phase,
        initial: Vec<Bytes>,
    ) -> Result<(), End> {
        self.backend = Backend::start(
            &self.session,
            reader,
            writer,
            target.clone(),
            phase,
            initial,
        );
        self.keep_alive = None;
        self.suggesting.forget();
        let generation = self.generation() + 1;
        self.served.send_replace(Served {
            generation,
            name: target.clone(),
        });
        self.session
            .session_manager
            .update_server(&self.session.username, &target);
        info!(
            "Player '{}' successfully switched to '{}'",
            self.session.username, target
        );
        self.fire_connected(target);
        match self.stalled.take() {
            Some(packet) => self.forward(packet),
            None => Ok(()),
        }
    }

    fn fire_connected(&mut self, server_name: String) {
        let previous = self.plugin_events.take();
        let bridge = self.bridge.clone();
        self.plugin_events = Some(tokio::spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            let event = ServerConnectedEvent {
                uuid: bridge.player.id.to_string(),
                username: bridge.player.username.clone(),
                server_name,
            };
            bridge.plugin_manager.fire_server_connected(&event).await;
        }));
    }

    fn suggestion_event(&mut self, event: SuggestionEvent) {
        let generation = self.generation();
        let answer = match event {
            SuggestionEvent::Answered(answer) => {
                let served = self.suggesting.running.take().map(|running| running.served);
                if let Some((request, served)) = self.suggesting.next.take() {
                    self.suggesting.ask(&self.session, request, served);
                    return;
                }
                answer.filter(|_| served == Some(generation))
            }
            SuggestionEvent::Due => self.suggesting.due(generation, self.session.version),
        };
        if let Some(bytes) = answer {
            self.send_play(bytes, None);
        }
    }

    /// Sends the kick after everything already queued and closes the connection behind it
    pub(super) async fn disconnect_client(&self, mut writer: Task, reason: &str) {
        let locale = self.locale();
        if let Some(kick) = disconnect_packet(
            self.session.version,
            self.link.clientbound(),
            locale.as_deref(),
            reason,
        ) {
            self.client_out.push(kick, None);
        }
        self.client_out.close();
        if timeout(CLIENT_WRITE_TIMEOUT, writer.join()).await.is_err() {
            debug!(
                "Gave up writing to '{}' before disconnecting",
                self.session.username
            );
        }
    }
}

/// A backend switched to on 1.20.2+ configures the client from scratch, but the client only
/// tells the first backend about its settings and brand, so they are repeated to every next one
#[derive(Default)]
pub(super) struct ClientSettings {
    information: Option<Bytes>,
    brand: Option<Vec<u8>>,
}

impl ClientSettings {
    fn apply(&mut self, setting: Setting) {
        match setting {
            Setting::Information(payload) => self.information = Some(payload),
            Setting::Brand(data) => self.brand = Some(data),
        }
    }

    /// The packets to send a backend that has just entered configuration
    fn repeat(&self, version: ProtocolVersion) -> Vec<Bytes> {
        let mut packets = Vec::new();
        if let Some(data) = &self.brand
            && let Some(id) = PacketKind::ConfigServerboundPluginMessage.id(version)
        {
            let mut payload = Vec::new();
            write_plugin_message(&mut payload, BRAND_CHANNEL, data, version);
            packets.push(
                crate::protocol::RawPacket {
                    id,
                    payload: payload.into(),
                }
                .to_bytes(),
            );
        }
        if let Some(payload) = &self.information
            && let Some(id) = PacketKind::ConfigClientInformation.id(version)
        {
            packets.push(
                crate::protocol::RawPacket {
                    id,
                    payload: payload.clone(),
                }
                .to_bytes(),
            );
        }
        packets
    }
}
