pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
static LOG_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
pub fn next_log_id() -> u64 {
    LOG_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Default)]
pub struct EventCursor {
    last: Option<u64>,
}

impl EventCursor {
    /// A cursor belongs to one spawned process. Managers bind the stream to
    /// their attempt identity and reset this cursor only when spawning a child.
    pub fn accept(&mut self, protocol: u64, seq: Option<u64>) -> Result<bool, crate::ControlError> {
        if protocol > 2 || (protocol == 2 && seq.is_none()) {
            return Err(crate::ControlError::new(
                crate::ErrorCode::InvalidInput,
                "unsupported or malformed engine event protocol",
            ));
        }
        if let Some(seq) = seq {
            if self.last.is_some_and(|last| seq <= last) {
                return Ok(false);
            }
            self.last = Some(seq);
        }
        Ok(true)
    }
}

#[derive(Debug, PartialEq)]
pub enum Line {
    Text(String),
    Oversized,
    InvalidUtf8,
}

/// Frames arbitrary chunks without allocating beyond one bounded line. An
/// oversized record is discarded through its newline, never parsed as a prefix.
#[derive(Default)]
pub struct LineDecoder {
    bytes: Vec<u8>,
    oversized: bool,
}

impl LineDecoder {
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Line> {
        let mut lines = Vec::new();
        for &byte in chunk {
            if byte == b'\n' {
                lines.push(self.finish());
            } else if !self.oversized {
                if self.bytes.len() == MAX_LINE_BYTES {
                    self.bytes.clear();
                    self.oversized = true;
                } else {
                    self.bytes.push(byte);
                }
            }
        }
        lines
    }

    pub fn eof(&mut self) -> Option<Line> {
        (!self.bytes.is_empty() || self.oversized).then(|| self.finish())
    }

    fn finish(&mut self) -> Line {
        if std::mem::take(&mut self.oversized) {
            return Line::Oversized;
        }
        if self.bytes.last() == Some(&b'\r') {
            self.bytes.pop();
        }
        match String::from_utf8(std::mem::take(&mut self.bytes)) {
            Ok(line) => Line::Text(line),
            Err(_) => Line::InvalidUtf8,
        }
    }
}

pub fn redact(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if [
        "password",
        "authorization",
        "bearer ",
        "cookie",
        "otp=",
        "otp =",
        "private key",
        "private-key",
    ]
    .iter()
    .any(|key| lower.contains(key))
    {
        "[sensitive engine output redacted]".into()
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discards_oversized_event_and_resumes_at_next_record() {
        let mut decoder = LineDecoder::default();
        for _ in 0..1024 {
            assert!(decoder.feed(&[b'a'; 1024]).is_empty());
        }
        assert_eq!(
            decoder.feed(b"\nvalid\r\n"),
            vec![Line::Oversized, Line::Text("valid".into())]
        );
    }

    #[test]
    fn decodes_utf8_across_chunks_and_final_record() {
        let mut decoder = LineDecoder::default();
        assert!(decoder.feed(&[0xe4, 0xb8]).is_empty());
        assert_eq!(decoder.feed(&[0xad, b'\n']), vec![Line::Text("中".into())]);
        decoder.feed(&[0xff]);
        assert_eq!(decoder.eof(), Some(Line::InvalidUtf8));
    }

    #[test]
    fn diagnostic_output_does_not_contain_synthetic_secrets() {
        for line in [
            "Cookie: SVPNCOOKIE=synthetic",
            "Authorization: Bearer synthetic",
            "password = synthetic",
            "otp=synthetic",
        ] {
            assert!(!redact(line).contains("synthetic"));
        }
    }

    #[test]
    fn late_and_duplicate_events_never_move_the_cursor_backwards() {
        let mut cursor = EventCursor::default();
        for seq in 0..1000 {
            assert!(cursor.accept(2, Some(seq)).unwrap());
            assert!(!cursor.accept(2, Some(seq)).unwrap());
            if seq > 0 {
                assert!(!cursor.accept(2, Some(seq - 1)).unwrap());
            }
        }
        assert!(cursor.accept(2, None).is_err());
        assert!(cursor.accept(3, Some(1001)).is_err());
    }
}
