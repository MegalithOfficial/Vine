use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::bridge::Phase;
use super::login::{BackendReader, BackendWriter};
use super::readers::{BackendEvent, Session, read_backend};
use super::task::{Lingering, Task};
/// The backend the client is on
pub(super) struct Backend {
    pub(super) name: String,
    pub(super) conn: Conn,
}

pub(super) enum Conn {
    Open(OpenBackend),
    Gone { reason: Option<String> },
}

/// A backend read and written by tasks of its own
pub(super) struct OpenBackend {
    pub(super) writes: mpsc::Sender<Bytes>,
    // None once the reader has finished
    pub(super) events: Option<mpsc::Receiver<BackendEvent>>,
    // Dropped to stop the reader once the packet in hand has reached the client queue
    stop: Option<oneshot::Sender<()>>,
    _reader: Task,
    _writer: Lingering,
}

impl Backend {
    pub(super) fn start(
        session: &Arc<Session>,
        reader: BackendReader,
        writer: BackendWriter,
        name: String,
        phase: Phase,
        initial: Vec<Bytes>,
    ) -> Self {
        let (events_tx, events) = mpsc::channel(1);
        let (stop, stopped) = oneshot::channel();
        let reader = Task::spawn(read_backend(
            session.clone(),
            reader,
            name.clone(),
            phase,
            events_tx,
            stopped,
        ));
        let (writes, rx) = mpsc::channel(BACKEND_WRITES);
        for packet in initial {
            let _ = writes.try_send(packet);
        }
        let writer = Lingering(tokio::spawn(write_backend(
            writer,
            rx,
            session.username.clone(),
        )));
        Self {
            name,
            conn: Conn::Open(OpenBackend {
                writes,
                events: Some(events),
                stop: Some(stop),
                _reader: reader,
                _writer: writer,
            }),
        }
    }

    /// Asks the reader to stop; false if it already has
    pub(super) fn stop_reading(&mut self) -> bool {
        match &mut self.conn {
            Conn::Open(open) if open.events.is_some() => {
                open.stop = None;
                true
            }
            Conn::Open(_) | Conn::Gone { .. } => false,
        }
    }

    /// The reader's next event; `None` once it has finished
    pub(super) async fn next_event(&mut self) -> Option<BackendEvent> {
        match &mut self.conn {
            Conn::Open(OpenBackend {
                events: Some(events),
                ..
            }) => events.recv().await,
            Conn::Open(OpenBackend { events: None, .. }) | Conn::Gone { .. } => {
                std::future::pending().await
            }
        }
    }
}

const BACKEND_WRITES: usize = 128;

/// Writes what the client sends to the backend, flushing once per batch
async fn write_backend(mut writer: BackendWriter, mut rx: mpsc::Receiver<Bytes>, username: String) {
    let mut batch = Vec::new();
    while rx.recv_many(&mut batch, BACKEND_WRITES).await > 0 {
        let written = batch.drain(..).try_for_each(|packet| writer.queue(&packet));
        if let Err(e) = match written {
            Ok(()) => writer.flush().await,
            Err(e) => Err(e),
        } {
            debug!("Backend write failed for '{}': {:?}", username, e);
            return;
        }
    }
}
