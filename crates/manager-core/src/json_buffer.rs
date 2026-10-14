//! Bounded reusable response buffers for public, redacted log payloads.
//! A lease returns only after the final HTTP body owner is dropped, so slow or
//! disconnected clients cannot observe data overwritten by another response.
use serde::Serialize;
use std::sync::{Arc, Mutex, OnceLock};
struct State {
    buffers: Vec<Vec<u8>>,
    max_buffers: usize,
    max_capacity: usize,
}
#[derive(Clone)]
pub struct JsonBuffers(Arc<Mutex<State>>);
impl JsonBuffers {
    pub fn new(max_buffers: usize, max_capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            buffers: Vec::new(),
            max_buffers,
            max_capacity,
        })))
    }
    pub fn encode<T: Serialize + ?Sized>(
        &self,
        value: &T,
        capacity: usize,
    ) -> Result<JsonLease, serde_json::Error> {
        let mut bytes = self
            .0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .buffers
            .pop()
            .unwrap_or_default();
        bytes.clear();
        // Vec::reserve is relative to len, not the previous capacity.
        bytes.reserve(capacity);
        let mut lease = JsonLease {
            bytes: Some(bytes),
            pool: self.clone(),
        };
        serde_json::to_writer(lease.bytes.as_mut().unwrap(), value)?;
        Ok(lease)
    }
}
pub struct JsonLease {
    bytes: Option<Vec<u8>>,
    pool: JsonBuffers,
}
impl AsRef<[u8]> for JsonLease {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_deref().unwrap_or_default()
    }
}
impl Drop for JsonLease {
    fn drop(&mut self) {
        let Some(mut bytes) = self.bytes.take() else {
            return;
        };
        let mut state = self
            .pool
            .0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.buffers.len() < state.max_buffers && bytes.capacity() <= state.max_capacity {
            bytes.clear();
            state.buffers.push(bytes);
        }
    }
}
pub fn log_buffers() -> &'static JsonBuffers {
    static POOL: OnceLock<JsonBuffers> = OnceLock::new();
    POOL.get_or_init(|| JsonBuffers::new(2, 2 * crate::protocol::MAX_LOG_BYTES))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlapping_leases_never_reuse_live_bytes_and_dropped_responses_recycle_capacity() {
        let pool = JsonBuffers::new(2, 1024);
        let first = pool.encode(&"first", 128).unwrap();
        let original = first.as_ref().as_ptr();
        let second = pool.encode(&"second", 128).unwrap();
        assert_ne!(original, second.as_ref().as_ptr());
        assert_eq!(first.as_ref(), br#""first""#);
        drop(first);
        for _ in 0..1000 {
            let next = pool.encode(&"later", 128).unwrap();
            assert_eq!(original, next.as_ref().as_ptr());
            assert_eq!(second.as_ref(), br#""second""#);
        }
        drop(second);
        assert_eq!(pool.0.lock().unwrap().buffers.len(), 2);
        let too_large = pool.encode(&"x".repeat(2048), 4096).unwrap();
        drop(too_large);
        assert_eq!(pool.0.lock().unwrap().buffers.len(), 1);
    }
    #[test]
    fn serialization_failure_returns_lease_and_pool_retention_stays_bounded() {
        struct Failure;
        impl Serialize for Failure {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("injected serialization failure"))
            }
        }
        let pool = JsonBuffers::new(1, 1024);
        assert!(pool.encode(&Failure, 128).is_err());
        let a = pool.encode(&"one", 128).unwrap();
        let b = pool.encode(&"two", 128).unwrap();
        drop(a);
        drop(b);
        assert_eq!(pool.0.lock().unwrap().buffers.len(), 1);
    }
}
