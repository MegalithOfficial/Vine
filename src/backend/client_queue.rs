use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::AsyncWrite;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::protocol::PacketWriter;
// Caps memory buffered for a slow client; once full, reading from the backend pauses
const CLIENT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub(super) const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) type Room = std::pin::Pin<
    Box<
        dyn Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>>
            + Send
            + Sync
            + 'static,
    >,
>;

pub(super) enum ClientWrite {
    // Packets of the proxy's own carry no permit, so they never wait for room
    Packet(Bytes, Option<OwnedSemaphorePermit>),
    // A backend frame written as it arrived
    Frame(Bytes, OwnedSemaphorePermit),
    // Answered once everything queued before it is written
    Written(oneshot::Sender<()>),
    Close,
}

pub(super) type ClientQueueRx = mpsc::UnboundedReceiver<ClientWrite>;

/// Everything for the client goes through here, in order, to the one task writing to it
#[derive(Clone)]
pub(super) struct ClientQueue {
    tx: mpsc::UnboundedSender<ClientWrite>,
    pub(super) budget: Arc<Semaphore>,
}

impl ClientQueue {
    pub(super) fn new() -> (Self, ClientQueueRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let budget = Arc::new(Semaphore::new(CLIENT_QUEUE_BYTES));
        (Self { tx, budget }, rx)
    }

    fn cost(len: usize) -> u32 {
        len.clamp(1, CLIENT_QUEUE_BYTES) as u32
    }

    pub(super) async fn reserve(&self, len: usize) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.budget)
            .acquire_many_owned(Self::cost(len))
            .await
            .ok()
    }

    /// Resolves once there is room for a packet of this size
    pub(super) fn room(&self, len: usize) -> Room {
        Box::pin(Arc::clone(&self.budget).acquire_many_owned(Self::cost(len)))
    }

    /// Queues a packet once there is room for it
    pub(super) async fn send(&self, bytes: Bytes) -> bool {
        match self.reserve(bytes.len()).await {
            Some(permit) => self.push(bytes, Some(permit)),
            None => false,
        }
    }

    /// Queues a backend frame once there is room for it
    pub(super) async fn send_frame(&self, frame: Bytes) -> bool {
        match self.reserve(frame.len()).await {
            Some(permit) => self.tx.send(ClientWrite::Frame(frame, permit)).is_ok(),
            None => false,
        }
    }

    pub(super) fn push(&self, bytes: Bytes, permit: Option<OwnedSemaphorePermit>) -> bool {
        self.tx.send(ClientWrite::Packet(bytes, permit)).is_ok()
    }

    pub(super) fn push_all(&self, packets: impl IntoIterator<Item = Bytes>) -> bool {
        packets.into_iter().all(|bytes| self.push(bytes, None))
    }

    /// Answered once everything queued so far is written; dropped if the client is gone
    pub(super) fn written(&self) -> oneshot::Receiver<()> {
        let (done, wait) = oneshot::channel();
        let _ = self.tx.send(ClientWrite::Written(done));
        wait
    }

    pub(super) fn close(&self) {
        let _ = self.tx.send(ClientWrite::Close);
    }

    /// Resolves once nothing is written to the client anymore
    pub(super) async fn closed(&self) {
        self.tx.closed().await
    }
}

pub(super) async fn write_client<W: AsyncWrite + Unpin>(
    mut writer: PacketWriter<W>,
    mut rx: ClientQueueRx,
    budget: Arc<Semaphore>,
    username: String,
) {
    while let Some(write) = rx.recv().await {
        let (written, _permit) = match write {
            ClientWrite::Packet(bytes, permit) => (
                timeout(CLIENT_WRITE_TIMEOUT, writer.send(bytes)).await,
                permit,
            ),
            ClientWrite::Frame(frame, permit) => (
                timeout(CLIENT_WRITE_TIMEOUT, writer.send_frame(frame)).await,
                Some(permit),
            ),
            ClientWrite::Written(done) => {
                let _ = done.send(());
                continue;
            }
            ClientWrite::Close => break,
        };
        match written {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                debug!("Client write failed for '{}': {:?}", username, e);
                break;
            }
            Err(_) => {
                warn!("Client '{}' stopped reading, disconnecting", username);
                break;
            }
        }
    }
    budget.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_queue_applies_backpressure() {
        let (queue, mut rx) = ClientQueue::new();
        assert!(
            queue
                .send(Bytes::from(vec![0u8; CLIENT_QUEUE_BYTES - 1]))
                .await
        );
        assert!(queue.send(Bytes::from_static(b"x")).await);

        let blocked = timeout(
            Duration::from_millis(50),
            queue.send(Bytes::from_static(b"y")),
        );
        assert!(blocked.await.is_err());

        let Some(ClientWrite::Packet(first, permit)) = rx.recv().await else {
            panic!("expected the first packet");
        };
        assert_eq!(first.len(), CLIENT_QUEUE_BYTES - 1);
        drop(permit);
        assert!(queue.send(Bytes::from_static(b"y")).await);

        drop(rx);
        assert!(!queue.send(Bytes::from_static(b"z")).await);
    }
}
