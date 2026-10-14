//! An owned, cancellable control pipe. Writes never block the supervisor.
use crate::control::SecretFrame;
use std::{
    io,
    process::ChildStdin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};

pub struct PrivateInput {
    pipe: Mutex<ChildStdin>,
    cancelled: AtomicBool,
}
impl PrivateInput {
    pub fn new(pipe: ChildStdin) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = pipe.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::Pipes::{
                GetNamedPipeHandleStateW, SetNamedPipeHandleState, PIPE_NOWAIT,
            };
            let mode = PIPE_NOWAIT;
            if unsafe {
                SetNamedPipeHandleState(
                    pipe.as_raw_handle(),
                    &mode,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut state = 0;
            if unsafe {
                GetNamedPipeHandleStateW(
                    pipe.as_raw_handle(),
                    &mut state,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                )
            } == 0
                || state & PIPE_NOWAIT == 0
            {
                return Err(io::Error::other("private pipe must use nonblocking mode"));
            }
        }
        Ok(Self {
            pipe: Mutex::new(pipe),
            cancelled: AtomicBool::new(false),
        })
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn send(&self, frame: &SecretFrame, budget: Duration) -> io::Result<()> {
        use std::{io::Write, sync::TryLockError, time::Instant};
        let deadline = Instant::now() + budget;
        let interrupted = || io::Error::new(io::ErrorKind::Interrupted, "engine input cancelled");
        let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "engine input timed out");
        let mut pipe = loop {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(interrupted());
            }
            if Instant::now() >= deadline {
                self.cancel();
                return Err(timed_out());
            }
            match self.pipe.try_lock() {
                Ok(pipe) => break pipe,
                Err(TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("engine input unavailable"))
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        let mut bytes = frame.as_bytes();
        while !bytes.is_empty() {
            if self.cancelled.load(Ordering::Acquire) {
                return Err(interrupted());
            }
            if Instant::now() >= deadline {
                self.cancel();
                return Err(timed_out());
            }
            match pipe.write(bytes) {
                // A nonblocking Windows byte pipe reports zero when full.
                Ok(0) => std::thread::sleep(Duration::from_millis(5)),
                Ok(length) => bytes = &bytes[length..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => {
                    self.cancel();
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::control::{frame, Command as InputCommand};
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::Instant,
    };
    fn response() -> SecretFrame {
        frame(
            "00000000-0000-4000-8000-000000000001",
            "0123456789abcdef0123456789abcdef",
            InputCommand::AuthResponse,
            "synthetic-otp",
        )
        .unwrap()
    }
    #[test]
    fn private_input_delivers_and_cancellation_rejects_more_secrets() {
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = PrivateInput::new(child.stdin.take().unwrap()).unwrap();
        let bytes = response();
        input.send(&bytes, Duration::from_secs(1)).unwrap();
        let mut output = vec![0; bytes.as_bytes().len()];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut output)
            .unwrap();
        assert_eq!(output, bytes.as_bytes());
        input.cancel();
        assert!(input.send(&bytes, Duration::from_secs(1)).is_err());
        drop(input);
        assert!(child.wait().unwrap().success());
    }
    #[test]
    fn full_pipe_times_out_instead_of_blocking_control_plane() {
        let mut child = Command::new("/bin/sleep")
            .arg("10")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let input = PrivateInput::new(child.stdin.take().unwrap()).unwrap();
        let started = Instant::now();
        let bytes = response();
        let failed = (0..100000)
            .find_map(|_| input.send(&bytes, Duration::from_millis(50)).err())
            .unwrap();
        input.cancel();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(failed.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
