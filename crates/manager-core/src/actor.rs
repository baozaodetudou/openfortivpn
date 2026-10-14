//! Bounded per-profile command mailboxes. Workers execute one admitted command
//! at a time, with independent profiles progressing concurrently. Platform
//! process supervisors remain alive when a caller drops its response future.
use crate::{ControlError, ErrorCode};
use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};
use tokio::sync::{mpsc, oneshot, Mutex};

type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct ProfileActors {
    mailboxes: Mutex<HashMap<String, mpsc::Sender<Work>>>,
    capacity: usize,
    idle_timeout: Duration,
}

impl Default for ProfileActors {
    fn default() -> Self {
        Self::new(512, Duration::from_secs(600))
    }
}

impl ProfileActors {
    pub fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            mailboxes: Mutex::default(),
            capacity,
            idle_timeout,
        }
    }

    pub async fn dispatch<T: Send + 'static>(
        &self,
        profile: &str,
        command: impl Future<Output = T> + Send + 'static,
    ) -> Result<T, ControlError> {
        if profile.is_empty() || profile.len() > 128 || profile.contains(['\0', '\n', '\r']) {
            return Err(ControlError::new(
                ErrorCode::InvalidInput,
                "invalid profile mailbox ID",
            ));
        }
        let sender = {
            let mut mailboxes = self.mailboxes.lock().await;
            mailboxes.retain(|_, sender| !sender.is_closed());
            if let Some(sender) = mailboxes.get(profile) {
                sender.clone()
            } else {
                if mailboxes.len() >= self.capacity {
                    return Err(ControlError::new(
                        ErrorCode::ProfileBusy,
                        "profile command capacity reached; retry later",
                    ));
                }
                let (sender, mut receiver) = mpsc::channel::<Work>(16);
                let idle = self.idle_timeout;
                tokio::spawn(async move {
                    while let Ok(Some(work)) = tokio::time::timeout(idle, receiver.recv()).await {
                        work.await;
                    }
                });
                mailboxes.insert(profile.into(), sender.clone());
                sender
            }
        };
        let (response, result) = oneshot::channel();
        let work = Box::pin(async move {
            let outcome = tokio::spawn(command).await.map_err(|_| {
                ControlError::new(
                    ErrorCode::RecoveryRequired,
                    "profile command worker failed; inspect recovery status",
                )
            });
            let _ = response.send(outcome);
        });
        sender.send(work).await.map_err(|_| {
            ControlError::new(
                ErrorCode::ProfileBusy,
                "profile mailbox expired; retry command",
            )
        })?;
        result.await.map_err(|_| {
            ControlError::new(
                ErrorCode::ShuttingDown,
                "profile command dispatcher stopped",
            )
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    #[tokio::test]
    async fn a_thousand_interleaved_commands_never_overlap_in_one_profile() {
        let actors = Arc::new(ProfileActors::default());
        let alive = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for _ in 0..1000 {
            let (actors, alive, completed) = (actors.clone(), alive.clone(), completed.clone());
            jobs.push(tokio::spawn(async move {
                actors
                    .dispatch("a", async move {
                        assert_eq!(alive.fetch_add(1, Ordering::SeqCst), 0);
                        tokio::task::yield_now().await;
                        assert_eq!(alive.fetch_sub(1, Ordering::SeqCst), 1);
                        completed.fetch_add(1, Ordering::SeqCst);
                    })
                    .await
                    .unwrap();
            }));
        }
        for job in jobs {
            job.await.unwrap();
        }
        assert_eq!(completed.load(Ordering::SeqCst), 1000);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_mailboxes_expire_and_a_panicking_job_does_not_lose_the_queue() {
        let actors = ProfileActors::new(1, Duration::from_secs(10));
        assert!(actors
            .dispatch("a", async { panic!("synthetic worker failure") })
            .await
            .is_err());
        assert_eq!(actors.dispatch("a", async { 7 }).await.unwrap(), 7);
        assert!(actors.dispatch("b", async { 8 }).await.is_err());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;
        assert_eq!(actors.dispatch("b", async { 9 }).await.unwrap(), 9);
    }
}
