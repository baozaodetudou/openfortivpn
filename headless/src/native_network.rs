//! Blocking privileged network port. HTTP tasks never invoke platform APIs.
use openfortivpn_manager_core::{network::Plan, network_control::InterfaceBinding, ControlError};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
pub(crate) struct Workers {
    running: AtomicUsize,
    finished: tokio::sync::Notify,
}
struct InFlight(Arc<Workers>);
impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::AcqRel);
        self.0.finished.notify_waiters();
    }
}
impl Workers {
    pub async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, tokio::task::JoinError> {
        self.running.fetch_add(1, Ordering::AcqRel);
        let guard = InFlight(self.clone());
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            // spawn_blocking still enters the Tokio runtime context. Native
            // providers own their own bounded runtime, so use a joined plain
            // thread and retain its guard even if the async waiter is aborted.
            std::thread::spawn(work)
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        })
        .await
    }
    pub async fn wait(&self) {
        loop {
            let notified = self.finished.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.running.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

pub trait NativeNetwork: Send + Sync {
    fn epoch(&self) -> Result<u64, ControlError>;
    fn apply(&self, plan: Plan, binding: InterfaceBinding) -> Result<(), ControlError>;
    fn release(&self, attempt: &str) -> Result<(), ControlError>;
}

#[cfg(target_os = "linux")]
impl NativeNetwork for openfortivpn_manager_core::network_linux_worker::LinuxTransactions {
    fn epoch(&self) -> Result<u64, ControlError> {
        self.epoch()
    }
    fn apply(&self, plan: Plan, binding: InterfaceBinding) -> Result<(), ControlError> {
        self.apply(plan, binding)
    }
    fn release(&self, attempt: &str) -> Result<(), ControlError> {
        self.release(attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_reader_cannot_release_ownership_of_a_running_worker() {
        let workers = Arc::new(Workers::default());
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let active = workers.clone();
        let caller = tokio::spawn(async move {
            active
                .run(move || {
                    started.send(()).unwrap();
                    blocked.recv().unwrap();
                })
                .await
        });
        running.await.unwrap();
        caller.abort();
        let _ = caller.await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), workers.wait())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), workers.wait())
            .await
            .unwrap();
    }
}
