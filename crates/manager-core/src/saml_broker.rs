//! Low-privilege, attempt-bound loopback callback listener. A gateway must
//! support the exact generated callback URL; legacy fixed redirects fail closed.
use crate::{
    saml::{CallbackBinding, SessionId},
    ControlError, ErrorCode,
};
use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
};
use zeroize::Zeroizing;
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "SAML callback cancelled, expired or invalid",
    )
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
pub struct BrowserCallback {
    // Contains state: never serialize the broker or include this URL in logs.
    callback_url: String,
    result: Option<oneshot::Receiver<Result<SessionId, ControlError>>>,
    cancel: watch::Sender<bool>,
    worker: Option<tokio::task::JoinHandle<()>>,
}
impl BrowserCallback {
    pub fn url(&self) -> &str {
        &self.callback_url
    }
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
    pub async fn session(&mut self) -> Result<SessionId, ControlError> {
        let outcome = self
            .result
            .take()
            .ok_or_else(invalid)?
            .await
            .map_err(|_| invalid())?;
        // Delivery is not worker exit. Join before returning so all listener,
        // accepted-stream and binding ownership has actually converged.
        self.worker
            .take()
            .ok_or_else(invalid)?
            .await
            .map_err(|_| invalid())?;
        outcome
    }
}
fn target<'a>(request: &'a [u8], authority: &str) -> Result<&'a str, ControlError> {
    if request.len() > 8192 || !request.ends_with(b"\r\n\r\n") {
        return Err(invalid());
    }
    let request = std::str::from_utf8(request).map_err(|_| invalid())?;
    let mut lines = request[..request.len() - 4].split("\r\n");
    let mut first = lines.next().ok_or_else(invalid)?.split(' ');
    if first.next() != Some("GET") {
        return Err(invalid());
    }
    let target = first.next().ok_or_else(invalid)?;
    if target.len() > 1024
        || !matches!(first.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || first.next().is_some()
    {
        return Err(invalid());
    }
    let mut host = None;
    for line in lines {
        if line.bytes().any(|b| b < 32 || b == 127) {
            return Err(invalid());
        }
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(invalid());
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err(invalid());
            }
        } else if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("expect")
        {
            return Err(invalid());
        }
    }
    if host != Some(authority) {
        return Err(invalid());
    }
    Ok(target)
}
async fn request(stream: &mut TcpStream) -> Result<Zeroizing<Vec<u8>>, ControlError> {
    let mut bytes = Zeroizing::new(Vec::new());
    while bytes.len() < 8192 {
        let mut chunk = [0u8; 512];
        let size = stream.read(&mut chunk).await.map_err(|_| invalid())?;
        if size == 0 {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk[..size]);
        use zeroize::Zeroize;
        chunk.zeroize();
        if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(invalid())
}
async fn reply(stream: &mut TcpStream, success: bool) {
    let body = if success {
        "Authentication received. Return to the VPN manager."
    } else {
        "Invalid authentication callback."
    };
    let status = if success { "200 OK" } else { "400 Bad Request" };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        stream.write_all(response.as_bytes()),
    )
    .await;
}
pub async fn start(
    attempt: &str,
    generation: u64,
    timeout: Duration,
) -> Result<BrowserCallback, ControlError> {
    let timeout_ms = u64::try_from(timeout.as_millis()).map_err(|_| invalid())?;
    let mut random = Zeroizing::new([0u8; 32]);
    getrandom::fill(random.as_mut()).map_err(|_| invalid())?;
    let state = Zeroizing::new(
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let mut binding = CallbackBinding::new(attempt, generation, &state, now(), timeout_ms)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| invalid())?;
    let address = listener.local_addr().map_err(|_| invalid())?;
    let authority = address.to_string();
    let callback_url = format!("http://{authority}{}", binding.path());
    let (result, receiver) = oneshot::channel();
    let (cancel, mut cancelled) = watch::channel(false);
    let attempt = attempt.to_owned();
    let worker = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + timeout;
        let outcome = async {
            for _ in 0..32 {
                let (mut stream, peer) = tokio::select! {
                    _ = cancelled.changed() => return Err(invalid()),
                    _ = tokio::time::sleep_until(deadline) => return Err(invalid()),
                    accepted = listener.accept() => accepted.map_err(|_| invalid())?,
                };
                if !peer.ip().is_loopback() { reply(&mut stream, false).await; continue; }
                let bytes = tokio::select! {
                    _ = cancelled.changed() => return Err(invalid()),
                    _ = tokio::time::sleep_until(deadline) => return Err(invalid()),
                    request = tokio::time::timeout(Duration::from_secs(2), request(&mut stream)) => request.ok().and_then(Result::ok),
                };
                let session = bytes.as_ref().ok_or_else(invalid).and_then(|bytes| target(bytes, &authority))
                    .and_then(|target| binding.accept(peer.ip(), "GET", target, &attempt, generation, now()));
                reply(&mut stream, session.is_ok()).await;
                if *cancelled.borrow() || tokio::time::Instant::now() >= deadline { return Err(invalid()); }
                if let Ok(session) = session { return Ok(session); }
            }
            Err(invalid())
        }.await;
        binding.cancel();
        drop(listener);
        let _ = result.send(outcome);
    });
    Ok(BrowserCallback {
        callback_url,
        result: Some(receiver),
        cancel,
        worker: Some(worker),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const ATTEMPT: &str = "00000000-0000-4000-8000-000000000001";
    async fn send(url: &str, path: &str, extra: &str) -> String {
        let authority = url
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        let mut stream = TcpStream::connect(authority).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\n{extra}\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply
    }
    #[tokio::test]
    async fn real_loopback_listener_rejects_foreign_paths_and_accepts_one_bound_session() {
        let mut broker = start(ATTEMPT, 7, Duration::from_secs(3)).await.unwrap();
        assert!(send(broker.url(), "/?id=foreign", "")
            .await
            .starts_with("HTTP/1.1 400"));
        let path = format!(
            "/{}?id=synthetic-session",
            broker.url().splitn(4, '/').nth(3).unwrap()
        );
        assert!(send(broker.url(), &path, "Content-Length: 0\r\n")
            .await
            .starts_with("HTTP/1.1 400"));
        let reply = send(broker.url(), &path, "").await;
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(reply.contains("Cache-Control: no-store"));
        assert!(!reply.contains("synthetic-session"));
        assert_eq!(
            broker.session().await.unwrap().as_str(),
            "synthetic-session"
        );
        assert!(broker.session().await.is_err());
        let authority = broker
            .url()
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        assert!(TcpStream::connect(authority).await.is_err());
    }
    #[tokio::test]
    async fn cancellation_and_expiry_close_the_listener_without_a_response() {
        let mut broker = start(ATTEMPT, 7, Duration::from_secs(3)).await.unwrap();
        broker.cancel();
        assert!(broker.session().await.is_err());
        let mut broker = start(ATTEMPT, 8, Duration::from_millis(20)).await.unwrap();
        assert!(broker.session().await.is_err());
    }
    #[test]
    fn parser_rejects_duplicate_host_headers_bodies_and_partial_requests() {
        for request in [
            b"GET /?id=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\nHost: 127.0.0.1:1\r\n\r\n".as_slice(),
            b"GET /?id=x HTTP/1.1\r\nHost: localhost:1\r\n\r\n",
            b"GET /?id=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\nbody",
            b"GET /?id=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n",
        ] {
            assert!(target(request, "127.0.0.1:1").is_err());
        }
        assert_eq!(
            target(
                b"GET /?id=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
                "127.0.0.1:1"
            )
            .unwrap(),
            "/?id=x"
        );
    }
}
