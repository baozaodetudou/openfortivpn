//! Terminal history bounds; active processes and recovery reservations are
//! filtered out by each adapter and must never participate in eviction.
use std::collections::HashSet;
pub const MAX_TERMINAL_INSTANCES: usize = 100;
pub const TERMINAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub fn terminal_ids_to_keep(
    entries: impl Iterator<Item = (String, u64)>,
    now: u64,
) -> HashSet<String> {
    let cutoff = now.saturating_sub(TERMINAL_TTL_SECONDS);
    let mut entries: Vec<_> = entries.filter(|(_, ended)| *ended >= cutoff).collect();
    entries.sort_unstable_by(|(id_a, time_a), (id_b, time_b)| {
        time_b.cmp(time_a).then_with(|| id_a.cmp(id_b))
    });
    entries
        .into_iter()
        .take(MAX_TERMINAL_INSTANCES)
        .map(|(id, _)| id)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_time_eviction_and_capacity_use_a_fake_clock() {
        let now = TERMINAL_TTL_SECONDS + 1000;
        let entries = || (0..1000).map(|time| (time.to_string(), now - time));
        let retained = terminal_ids_to_keep(entries(), now);
        assert_eq!(retained.len(), 100);
        assert!(retained.contains("0"));
        assert!(!retained.contains("100"));
        assert!(terminal_ids_to_keep(entries(), now + TERMINAL_TTL_SECONDS + 1).is_empty());
    }
}
