use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use super::bridge::{BackendBridge, BridgeError};
use super::login::PreparedBackend;
use super::task::Task;
use crate::config::BackendConfig;
use crate::plugin::api::ServerConnectEvent;
/// A move to another backend, from being asked for to the client being handed over
pub(super) enum Switch {
    Idle,
    /// Asked for while the client is not playing; started once it is
    Deferred {
        target: String,
    },
    /// Plugins are told and the next backend is logged into while the current one keeps running
    Connecting {
        target: String,
        job: Job,
    },
    /// The next backend finished logging in while the client was not playing
    Held {
        target: String,
        prepared: Box<PreparedBackend>,
        since: Instant,
    },
    /// The current backend's reader is let finish the packet in hand
    Stopping {
        target: String,
        prepared: Box<PreparedBackend>,
    },
    /// On 1.20.2+ the client is sent back into configuration so the next backend can configure
    /// it from scratch; packets it sends before acknowledging still go to the current backend
    AwaitingAck {
        target: String,
        prepared: Box<PreparedBackend>,
        clock: AckClock,
    },
    /// The current backend is gone and the player is moved to the fallback server
    Fallback {
        reason: String,
        job: Job,
    },
}

pub(super) enum AckClock {
    // The client's wait for its acknowledgement starts once it has the request
    Writing(oneshot::Receiver<()>),
    Until(tokio::time::Instant),
}

/// What a connect job ends with
pub(super) enum Connected {
    Cancelled(Option<String>),
    AlreadyThere(String),
    Unknown(String),
    Prepared(String, Result<Box<PreparedBackend>, BridgeError>),
}

/// Work on a task of its own, so the tunnel keeps running meanwhile; dropped, it is stopped
pub(super) struct Job {
    result: oneshot::Receiver<Connected>,
    _task: Task,
}

impl Job {
    pub(super) fn spawn(work: impl Future<Output = Connected> + Send + 'static) -> Self {
        let (done, result) = oneshot::channel();
        let task = Task::spawn(async move {
            let _ = done.send(work.await);
        });
        Self {
            result,
            _task: task,
        }
    }
}

pub(super) enum SwitchEvent {
    Connected(Option<Connected>),
    Written,
    AckTimedOut,
}

pub(super) async fn switch_progress(switch: &mut Switch) -> SwitchEvent {
    match switch {
        Switch::Connecting { job, .. } | Switch::Fallback { job, .. } => {
            SwitchEvent::Connected((&mut job.result).await.ok())
        }
        Switch::AwaitingAck {
            clock: AckClock::Writing(written),
            ..
        } => {
            let _ = written.await;
            SwitchEvent::Written
        }
        Switch::AwaitingAck {
            clock: AckClock::Until(deadline),
            ..
        } => {
            tokio::time::sleep_until(*deadline).await;
            SwitchEvent::AckTimedOut
        }
        Switch::Idle | Switch::Deferred { .. } | Switch::Held { .. } | Switch::Stopping { .. } => {
            std::future::pending().await
        }
    }
}

impl BackendBridge {
    /// Tells plugins about a switch the player asked for, then logs into its target
    pub(super) async fn switch_job(self: Arc<Self>, current: String, target: String) -> Connected {
        let mut event = ServerConnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            current_server: Some(current.clone()),
            target_server: target,
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager.fire_server_connect(&mut event).await;
        if event.cancelled {
            return Connected::Cancelled(event.cancel_reason);
        }
        let target = event.target_server;
        if target == current {
            return Connected::AlreadyThere(target);
        }
        let Some(config) = self.proxy_config.servers.get(&target).cloned() else {
            return Connected::Unknown(target);
        };
        let prepared = self.prepare_backend(&target, &config).await;
        Connected::Prepared(target, prepared)
    }

    /// Plugins see a move to the fallback server like any other; with the old backend gone a
    /// cancelled one ends the session, and a different target must be a configured server
    pub(super) async fn fallback_job(
        self: Arc<Self>,
        current: String,
        target: String,
        config: BackendConfig,
    ) -> Connected {
        let mut event = ServerConnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            current_server: Some(current),
            target_server: target.clone(),
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager.fire_server_connect(&mut event).await;
        if event.cancelled {
            return Connected::Cancelled(event.cancel_reason);
        }
        let (target, config) = match self.proxy_config.servers.get(&event.target_server) {
            Some(cfg) if event.target_server != target => (event.target_server, cfg.clone()),
            _ => (target, config),
        };
        let prepared = self.prepare_backend(&target, &config).await;
        Connected::Prepared(target, prepared)
    }

    pub(super) async fn prepare_job(
        self: Arc<Self>,
        target: String,
        config: BackendConfig,
    ) -> Connected {
        let prepared = self.prepare_backend(&target, &config).await;
        Connected::Prepared(target, prepared)
    }
}

pub(super) fn job_ended() -> BridgeError {
    BridgeError::IoError(std::io::Error::other("the connection attempt ended"))
}

pub(super) const SWITCH_ACK_TIMEOUT: Duration = Duration::from_secs(10);

// Backends drop a login that is not acknowledged within about 30 seconds
pub(super) const HELD_BACKEND_LIMIT: Duration = Duration::from_secs(20);

pub(super) fn client_timeout() -> BridgeError {
    BridgeError::IoError(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "client did not respond while switching servers",
    ))
}
