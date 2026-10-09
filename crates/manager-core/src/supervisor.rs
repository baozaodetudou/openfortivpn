//! Owned process and stream completion primitives shared by platform adapters.
//! A stop request is never equivalent to wait/reap, and a wait is not EOF.
use std::{
    io,
    process::{Child, ExitStatus},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

/// The engine waits on this inherited socket before reading configuration or
/// contacting a gateway. Spawn still completes (the wait is after exec), so
/// the adapter can persist its process group before granting permission.
#[cfg(unix)]
pub struct LaunchGate(std::os::unix::net::UnixStream);
#[cfg(unix)]
impl LaunchGate {
    pub fn prepare(command: &mut std::process::Command) -> io::Result<Self> {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
        let fd = reader.as_raw_fd();
        command.arg(format!("--manager-launch-fd={fd}"));
        unsafe {
            command.pre_exec(move || {
                // Keep reader alive in the closure; all other descriptors keep
                // their CLOEXEC flag, including the parent's grant endpoint.
                let fd = reader.as_raw_fd();
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Self(writer))
    }
    pub fn release(mut self) -> io::Result<()> {
        use std::io::Write;
        self.0.write_all(&[1])
    }
}

#[derive(Clone)]
pub struct OwnedProcess {
    inner: Arc<ProcessInner>,
}
struct ProcessInner {
    child: Mutex<Option<Child>>,
}
/// A failed wait is an inspection failure, not proof of exit. Reapers retain
/// the child handle and retry with a capped delay; they never clear journals.
fn reap_until_done<T>(
    mut inspect: impl FnMut() -> io::Result<Option<T>>,
    mut pause: impl FnMut(Duration),
) -> T {
    let mut consecutive_errors = 0u32;
    loop {
        match inspect() {
            Ok(Some(status)) => return status,
            Ok(None) => {
                consecutive_errors = 0;
                pause(Duration::from_millis(10));
            }
            Err(_) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                let delay = 50u64.saturating_mul(1u64 << consecutive_errors.min(5));
                pause(Duration::from_millis(delay.min(1000)));
            }
        }
    }
}
pub struct ProcessGuard<'a>(MutexGuard<'a, Option<Child>>);
impl std::ops::Deref for ProcessGuard<'_> {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.0
            .as_ref()
            .expect("owned child is present until inner drop")
    }
}
impl std::ops::DerefMut for ProcessGuard<'_> {
    fn deref_mut(&mut self) -> &mut Child {
        self.0
            .as_mut()
            .expect("owned child is present until inner drop")
    }
}
impl OwnedProcess {
    pub fn new(child: Child) -> Self {
        Self {
            inner: Arc::new(ProcessInner {
                child: Mutex::new(Some(child)),
            }),
        }
    }
    pub fn lock(&self) -> io::Result<ProcessGuard<'_>> {
        Ok(ProcessGuard(
            self.inner.child.lock().unwrap_or_else(|e| e.into_inner()),
        ))
    }
    pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        self.lock()?.try_wait()
    }
    /// Keep adapter/component locks and the exact child until wait succeeds.
    /// An inspection failure cannot hand unfinished work to a thread that will
    /// disappear when a privileged helper exits.
    pub fn wait_reaped(&self) -> ExitStatus {
        reap_until_done(|| self.lock()?.wait().map(Some), thread::sleep)
    }
}
impl Drop for ProcessInner {
    fn drop(&mut self) {
        if let Some(mut child) = self
            .child
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            // The last adapter may disappear after an error. Transfer ownership
            // to a reaper without clearing journals or declaring cleanup.
            thread::spawn(move || {
                reap_until_done(|| child.wait().map(Some), thread::sleep);
            });
        }
    }
}

pub struct StreamWorker {
    pub join: thread::JoinHandle<bool>,
    pub cancelled: Arc<AtomicBool>,
}

pub struct AsyncOwnedProcess {
    child: Option<tokio::process::Child>,
}
impl AsyncOwnedProcess {
    pub fn new(child: tokio::process::Child) -> Self {
        Self { child: Some(child) }
    }
}
impl std::ops::Deref for AsyncOwnedProcess {
    type Target = tokio::process::Child;
    fn deref(&self) -> &Self::Target {
        self.child.as_ref().expect("owned child until drop")
    }
}
impl std::ops::DerefMut for AsyncOwnedProcess {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child.as_mut().expect("owned child until drop")
    }
}
impl Drop for AsyncOwnedProcess {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        // Cancellation is an abnormal termination, never cleanup confirmation.
        // The adapter's durable lease/journal survives it. Reap the exact Child
        // handle, not a possibly reused numeric PID.
        let _ = child.start_kill();
        // Native thread ownership survives cancellation/runtime teardown. A
        // Tokio cleanup task could itself be dropped while this child lives.
        thread::spawn(move || {
            reap_until_done(|| child.try_wait(), thread::sleep);
        });
    }
}
pub fn drain_streams(readers: Vec<StreamWorker>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while readers.iter().any(|reader| !reader.join.is_finished()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let mut complete = readers.iter().all(|reader| reader.join.is_finished());
    for reader in &readers {
        reader.cancelled.store(true, Ordering::Release);
    }
    for reader in readers {
        complete &= matches!(reader.join.join(), Ok(true));
    }
    complete
}

pub async fn drain_tasks(
    tasks: impl IntoIterator<Item = tokio::task::JoinHandle<bool>>,
    budget: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    let mut complete = true;
    for mut task in tasks {
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(Ok(true)) => {}
            Ok(_) => complete = false,
            Err(_) => {
                complete = false;
                task.abort();
                let _ = task.await;
            }
        }
    }
    complete
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{io::Read, os::unix::net::UnixStream, process::Command};
    #[test]
    fn wait_errors_and_pending_reads_retain_ownership_until_exit_proof() {
        let mut results = std::collections::VecDeque::from([
            Err(io::Error::other("injected wait failure")),
            Err(io::Error::other("injected wait failure")),
            Ok(None),
            Err(io::Error::other("injected wait failure")),
            Ok(Some(7)),
        ]);
        let mut pauses = Vec::new();
        let status = reap_until_done(
            || results.pop_front().expect("must stop at exit proof"),
            |delay| pauses.push(delay),
        );
        assert_eq!(status, 7);
        assert!(results.is_empty());
        assert_eq!(
            pauses,
            [
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(10),
                Duration::from_millis(100)
            ]
        );
        let mut attempts = 0;
        reap_until_done(
            || {
                attempts += 1;
                if attempts == 100 {
                    Ok(Some(()))
                } else {
                    Err(io::Error::other("persistent failure"))
                }
            },
            |delay| assert!(delay <= Duration::from_secs(1)),
        );
        assert_eq!(attempts, 100);
    }
    #[test]
    fn launch_endpoint_is_inherited_but_parent_grant_endpoint_is_not() {
        for grant in [true, false] {
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "eval \"exec dd bs=1 count=1 <&${1#--manager-launch-fd=}\"",
                "launch",
            ]);
            command.stdout(std::process::Stdio::piped());
            let gate = LaunchGate::prepare(&mut command).unwrap();
            let mut child = command.spawn().unwrap();
            drop(command);
            assert!(child.try_wait().unwrap().is_none());
            if grant {
                gate.release().unwrap();
            } else {
                drop(gate);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while child.try_wait().unwrap().is_none() {
                assert!(
                    Instant::now() < deadline,
                    "grant endpoint leaked into child"
                );
                thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, if grant { vec![1] } else { vec![] });
        }
    }
    #[test]
    fn dropping_an_adapter_preserves_the_child_for_the_reaper() {
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.05; exit 7"])
            .spawn()
            .unwrap();
        let process = OwnedProcess::new(child);
        let monitor = process.clone();
        drop(process);
        assert_eq!(monitor.wait_reaped().code(), Some(7));
    }
    #[test]
    fn inherited_writer_does_not_keep_a_terminal_attempt_draining_forever() {
        let (read, _writer) = UnixStream::pair().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::spawn(move || {
            crate::process_output::CancellablePipe::new(read, flag.clone())
                .read_to_end(&mut Vec::new())
                .unwrap();
            !flag.load(Ordering::Acquire)
        });
        let started = Instant::now();
        assert!(!drain_streams(
            vec![StreamWorker { join, cancelled }],
            Duration::from_millis(30)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[tokio::test]
    async fn shared_deadline_aborts_and_joins_every_incomplete_task() {
        let done = tokio::spawn(async { true });
        let stuck = tokio::spawn(async { std::future::pending::<bool>().await });
        assert!(!drain_tasks([done, stuck], Duration::from_millis(30)).await);
        assert!(drain_tasks([tokio::spawn(async { true })], Duration::from_secs(1)).await);
    }
    #[tokio::test]
    async fn cancelled_supervisor_reaps_the_exact_async_child() {
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;
        let process = AsyncOwnedProcess::new(child);
        drop(process);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "child was not reaped"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    #[test]
    fn async_child_reaper_survives_runtime_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pid = runtime.block_on(async {
            let child = tokio::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap();
            let pid = child.id().unwrap() as i32;
            drop(AsyncOwnedProcess::new(child));
            pid
        });
        drop(runtime);
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                Instant::now() < deadline,
                "runtime shutdown dropped the owned child"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
