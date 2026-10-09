//! Bounded retention shared by every manager. Appending is O(1) amortized;
//! the byte budget includes all owned strings, not just the log message.
use crate::{
    domain::{LogEvent, LogSnapshot},
    protocol,
};
use std::{collections::VecDeque, sync::Arc};

pub const MAX_LOGS: usize = 2_000;

pub struct LogBuffer {
    events: VecDeque<Arc<LogEvent>>,
    bytes: usize,
    max_events: usize,
    max_bytes: usize,
    evicted: u64,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new(MAX_LOGS, protocol::MAX_LOG_BYTES)
    }
}

impl LogBuffer {
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            events: VecDeque::new(),
            bytes: 0,
            max_events,
            max_bytes,
            evicted: 0,
        }
    }

    pub fn push(&mut self, mut event: LogEvent) {
        event.line = protocol::redact(&event.line);
        if event.line.len() > protocol::MAX_LINE_BYTES {
            event.line = "[oversized log record discarded]".into();
        }
        let size = event_bytes(&event);
        if size > self.max_bytes || self.max_events == 0 {
            self.evicted = self.evicted.saturating_add(1);
            return;
        }
        while self.events.len() >= self.max_events
            || self.bytes > self.max_bytes.saturating_sub(size)
        {
            if let Some(old) = self.events.pop_front() {
                self.bytes -= event_bytes(&old);
                self.evicted = self.evicted.saturating_add(1);
            } else {
                break;
            }
        }
        self.bytes += size;
        self.events.push_back(Arc::new(event));
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &LogEvent> + ExactSizeIterator {
        self.events.iter().map(AsRef::as_ref)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn front(&self) -> Option<&LogEvent> {
        self.events.front().map(AsRef::as_ref)
    }

    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    pub fn recent(&self, instance: Option<&str>, limit: usize) -> LogSnapshot {
        let mut selected: Vec<_> = self
            .events
            .iter()
            .rev()
            .filter(|event| instance.is_none_or(|id| event.instance_id == id))
            .take(limit.clamp(1, self.max_events.max(1)))
            .cloned()
            .collect();
        selected.reverse();
        selected
    }
}

/// Reserve once for a bounded snapshot, including JSON escaping. Building an
/// intermediate serde_json::Value or repeatedly growing a response buffer can
/// allocate several copies of every retained message on each poll.
pub fn json_capacity(events: &[Arc<LogEvent>]) -> usize {
    fn string_bytes(value: &str) -> usize {
        2 + value
            .bytes()
            .map(|byte| match byte {
                b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
                0..=31 => 6,
                _ => 1,
            })
            .sum::<usize>()
    }
    2 + events
        .iter()
        .map(|event| {
            128 + string_bytes(&event.instance_id)
                + string_bytes(&event.stream)
                + string_bytes(&event.line)
        })
        .sum::<usize>()
}
pub fn encode_snapshot(events: &[Arc<LogEvent>]) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = Vec::with_capacity(json_capacity(events));
    serde_json::to_writer(&mut bytes, events)?;
    Ok(bytes)
}

fn event_bytes(event: &LogEvent) -> usize {
    std::mem::size_of::<LogEvent>()
        + event.line.len()
        + event.instance_id.len()
        + event.stream.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(id: u64, line: &str) -> LogEvent {
        LogEvent {
            id,
            instance_id: "a".into(),
            stream: "stdout".into(),
            line: line.into(),
            timestamp: id,
        }
    }

    #[test]
    fn stress_retention_counts_all_fields_and_preserves_cursor_order() {
        let mut buffer = LogBuffer::new(100, 16_384);
        for id in 1..=100_000 {
            buffer.push(event(id, &"x".repeat((id % 256) as usize)));
            assert!(buffer.len() <= 100);
            assert!(buffer.retained_bytes() <= 16_384);
        }
        assert_eq!(buffer.evicted() + buffer.len() as u64, 100_000);
        assert!(buffer
            .iter()
            .zip(buffer.iter().skip(1))
            .all(|(a, b)| a.id < b.id));
        let recent = buffer.recent(Some("a"), 3);
        assert_eq!(recent.last().unwrap().id, 100_000);
        assert_eq!(
            buffer.retained_bytes(),
            buffer.iter().map(event_bytes).sum::<usize>()
        );
    }

    #[test]
    fn serialization_budget_covers_escaping_utf8_and_max_integer_fields() {
        let events = vec![Arc::new(LogEvent {
            id: u64::MAX,
            instance_id: "a\\b\n".into(),
            stream: "中\t".into(),
            line: "\0\u{1}\u{8}\u{c}\n\r\t\\\"中".repeat(1000),
            timestamp: u64::MAX,
        })];
        let budget = json_capacity(&events);
        let bytes = encode_snapshot(&events).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&events).unwrap());
        assert_eq!(
            bytes.capacity(),
            budget,
            "serializer must not reallocate the response"
        );
    }

    #[test]
    fn full_snapshots_share_retained_entries_and_keep_wire_shape_after_eviction() {
        let mut buffer = LogBuffer::new(2, 200_000);
        buffer.push(event(1, &"x".repeat(64_000)));
        buffer.push(event(2, "safe"));
        let first = buffer.recent(None, 2);
        for _ in 0..1000 {
            let snapshot = buffer.recent(None, 2);
            assert!(Arc::ptr_eq(&first[0], &snapshot[0]));
            assert!(Arc::ptr_eq(&first[1], &snapshot[1]));
        }
        buffer.push(event(3, "new"));
        assert_eq!(buffer.front().unwrap().id, 2);
        let json = serde_json::to_value(&first).unwrap();
        assert_eq!(json[0]["line"].as_str().unwrap().len(), 64_000);
        assert_eq!(
            json[1],
            serde_json::json!({"id":2,"instanceId":"a","stream":"stdout","line":"safe","timestamp":2})
        );
    }

    #[test]
    fn oversized_fields_cannot_evict_everything_or_break_accounting() {
        let mut buffer = LogBuffer::new(3, 1024);
        buffer.push(event(1, "safe"));
        let mut large = event(2, "safe");
        large.instance_id = "x".repeat(2048);
        buffer.push(large);
        assert_eq!(buffer.len(), 1);
        buffer.push(event(3, "password=synthetic-secret"));
        buffer.push(event(4, &"x".repeat(protocol::MAX_LINE_BYTES + 1)));
        assert!(buffer.iter().all(|e| !e.line.contains("synthetic-secret")));
        assert_eq!(
            buffer.iter().last().unwrap().line,
            "[oversized log record discarded]"
        );
    }
}
