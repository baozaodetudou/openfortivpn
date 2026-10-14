//! Cancellation for child pipes, including pipes inherited by descendants.
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(unix)]
pub trait Pipe: Read + std::os::fd::AsRawFd {}
#[cfg(unix)]
impl<T: Read + std::os::fd::AsRawFd> Pipe for T {}
#[cfg(windows)]
pub trait Pipe: Read + std::os::windows::io::AsRawHandle {}
#[cfg(windows)]
impl<T: Read + std::os::windows::io::AsRawHandle> Pipe for T {}

pub struct CancellablePipe<R> {
    pipe: R,
    cancelled: Arc<AtomicBool>,
}

impl<R: Pipe> CancellablePipe<R> {
    pub fn new(pipe: R, cancelled: Arc<AtomicBool>) -> Self {
        Self { pipe, cancelled }
    }
}

impl<R: Pipe> Read for CancellablePipe<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        while !self.cancelled.load(Ordering::Acquire) {
            #[cfg(unix)]
            {
                let mut fd = libc::pollfd {
                    fd: self.pipe.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // Only this reader consumes the pipe. Read readiness cannot be
                // stolen by a second consumer before the blocking read.
                let ready = unsafe { libc::poll(&mut fd, 1, 50) };
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if ready == 0 {
                    continue;
                }
                if fd.revents & libc::POLLNVAL != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "invalid child pipe",
                    ));
                }
            }
            #[cfg(windows)]
            {
                use windows_sys::Win32::System::Pipes::PeekNamedPipe;
                let mut available = 0;
                if unsafe {
                    PeekNamedPipe(
                        self.pipe.as_raw_handle(),
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        &mut available,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(0);
                    }
                    return Err(error);
                }
                if available == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
            }
            return self.pipe.read(bytes);
        }
        Ok(0)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    #[test]
    fn cancellation_joins_reader_even_when_writer_remains_alive() {
        let (read, _inherited_writer) = UnixStream::pair().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let worker = std::thread::spawn(move || {
            CancellablePipe::new(read, flag).read(&mut [0; 64]).unwrap()
        });
        let started = Instant::now();
        cancelled.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn drains_output_before_eof() {
        use std::io::Write;
        let (read, mut write) = UnixStream::pair().unwrap();
        write.write_all(b"final cleanup\n").unwrap();
        drop(write);
        let mut contents = String::new();
        CancellablePipe::new(read, Arc::default())
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "final cleanup\n");
    }
}
