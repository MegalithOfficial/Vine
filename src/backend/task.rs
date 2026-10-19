use std::time::Duration;

/// A task that is stopped when its handle is dropped
pub(super) struct Task(Option<tokio::task::JoinHandle<()>>);

impl Task {
    pub(super) fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(future)))
    }

    pub(super) async fn join(&mut self) {
        if let Some(handle) = self.0.as_mut() {
            let _ = handle.await;
            self.0 = None;
        }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// A task that may finish what it has in hand once its handle is dropped, but not forever
pub(super) struct Lingering(pub(super) tokio::task::JoinHandle<()>);

impl Drop for Lingering {
    fn drop(&mut self) {
        let abort = self.0.abort_handle();
        tokio::spawn(async move {
            tokio::time::sleep(LINGER).await;
            abort.abort();
        });
    }
}

const LINGER: Duration = Duration::from_secs(10);
