//! A bounded in-memory cache.
//!
//! oxblocks is stateless: this is the only thing it remembers, it lives in the
//! process, and losing it costs latency rather than correctness.
//!
//! Hand-written rather than pulled in. The project's argument is a small
//! audited dependency tree, and what is needed here is roughly a hundred lines
//! with invariants a reader can check: bounded size, in entries and, where the
//! values are daemon-sized, in bytes; optional expiry; least-recently-used
//! eviction. Eviction scans the map, which is O(n) — a
//! correct scan beats an intrusive linked list nobody wants to audit — but the
//! scan clears a batch rather than one entry, so its cost is amortised over
//! thousands of inserts.
//!
//! ## What may be cached
//!
//! Confirmed blocks and transactions are immutable *once buried*, and that
//! qualifier is the whole reorg story. Entries keyed by **hash** are always
//! safe: a hash names one object forever. Entries keyed by **height** are not,
//! because a reorg reassigns a height to a different block — so callers must
//! not cache by height within [`REORG_WINDOW`] of the tip.
//!
//! This type does not enforce that; it cannot see heights. [`crate::rpc_source`]
//! does.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many blocks below the tip are treated as still reorganisable.
///
/// Monero reorgs are shallow — the deepest seen in practice is a handful of
/// blocks — but the cost of being wrong here is serving a block that no longer
/// exists, so the window is generous.
pub const REORG_WINDOW: u64 = 60;

/// Deep enough that being wrong needs an unprecedented reorg, shallow enough
/// that paging back through history stays warm.
///
/// A compile-time assertion rather than a test: a runtime check on a constant
/// can never fail, so it would buy confidence it does not provide. This fails
/// the build instead.
const _: () = assert!(
    REORG_WINDOW >= 20,
    "REORG_WINDOW must stay deep enough that a height is a stable name for a block"
);

/// Whether an object this far from the tip may be cached under a key that a
/// reorg could reassign — a height, as opposed to a hash.
///
/// Split out as a function so the rule can be tested directly. It is the one
/// place where caching could serve a block that no longer exists, and
/// "obviously right" is not the same as checked.
#[must_use]
pub const fn safe_to_cache_by_height(depth: u64) -> bool {
    depth >= REORG_WINDOW
}

/// What one eviction pass clears, as a fraction of capacity.
///
/// Evicting a single entry per insert means an O(n) scan per insert, and the
/// scan runs while holding the lock, so every other request waits behind it.
/// Measured on a release build, once the cache is full: 0.003 ms per insert at
/// 512 entries, 0.043 ms at 8,192, and **0.347 ms at the 65,536 the ring-member
/// cache uses**. One mainnet transaction with 195 inputs touches 3,120 ring
/// members, which is over a second of lock held for eviction alone.
///
/// Clearing a sixteenth of the cache in one pass spreads that scan over
/// thousands of inserts and leaves the eviction order unchanged: it is still
/// the least recently used entries that go, just several at a time.
const EVICT_FRACTION: usize = 16;

struct Entry<V> {
    value: Arc<V>,
    /// What [`Cache::within_bytes`]'s measure gave the value, or 0 without
    /// one.
    weight: usize,
    /// Logical clock reading, for least-recently-used ordering. A counter
    /// rather than a timestamp so that ordering does not depend on clock
    /// resolution or monotonicity.
    used_at: u64,
    stored_at: Instant,
}

struct Inner<K, V> {
    map: HashMap<K, Entry<V>>,
    /// The sum of the entries' weights.
    bytes: usize,
    clock: u64,
    hits: u64,
    misses: u64,
}

pub struct Cache<K, V> {
    inner: Mutex<Inner<K, V>>,
    capacity: usize,
    ttl: Option<Duration>,
    budget: Option<Budget<V>>,
}

/// A ceiling on the bytes a cache's values hold, by a measure of each.
struct Budget<V> {
    bytes: usize,
    weigh: fn(&V) -> usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub len: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
}

impl<K: Eq + Hash + Clone, V> Cache<K, V> {
    /// A cache holding at most `capacity` entries forever.
    ///
    /// For immutable objects: a block that will never change does not need to
    /// be re-fetched on a timer.
    #[must_use]
    pub fn permanent(capacity: usize) -> Self {
        Self::new(capacity, None)
    }

    /// A cache whose entries expire after `ttl`.
    ///
    /// For values that track the chain tip — the height, the mempool, the fee
    /// estimate — where being a few seconds stale is fine and being a minute
    /// stale is not.
    #[must_use]
    pub fn expiring(capacity: usize, ttl: Duration) -> Self {
        Self::new(capacity, Some(ttl))
    }

    fn new(capacity: usize, ttl: Option<Duration>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                bytes: 0,
                clock: 0,
                hits: 0,
                misses: 0,
            }),
            // A zero-capacity cache would evict what it just inserted and then
            // return it, which reads as a cache that never works. Treat it as
            // one entry instead.
            capacity: capacity.max(1),
            ttl,
            budget: None,
        }
    }

    /// Hold the values to `bytes` in all, as `weigh` measures each, as well
    /// as to the entry count.
    ///
    /// For values whose size the daemon decides, such as a block's or a
    /// transaction's hex: a count alone bounds nothing when one entry can be
    /// as large as the daemon cares to make it. A value weighing more than a
    /// sixteenth of the budget is returned but not kept, so no one entry can
    /// empty the cache to make room for itself.
    #[must_use]
    pub fn within_bytes(mut self, bytes: usize, weigh: fn(&V) -> usize) -> Self {
        self.budget = Some(Budget { bytes, weigh });
        self
    }

    /// Fetch, if present and unexpired.
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        let Ok(mut inner) = self.inner.lock() else {
            // A poisoned lock means another thread panicked while holding it.
            // The cache is not worth propagating that: report a miss and let
            // the caller do the real work.
            return None;
        };

        if let Some(ttl) = self.ttl
            && inner
                .map
                .get(key)
                .is_some_and(|e| e.stored_at.elapsed() >= ttl)
            && let Some(old) = inner.map.remove(key)
        {
            inner.bytes = inner.bytes.saturating_sub(old.weight);
        }

        inner.clock += 1;
        let clock = inner.clock;
        match inner.map.get_mut(key) {
            Some(entry) => {
                entry.used_at = clock;
                let value = Arc::clone(&entry.value);
                inner.hits += 1;
                Some(value)
            }
            None => {
                inner.misses += 1;
                None
            }
        }
    }

    /// Drop the least recently used `capacity / EVICT_FRACTION` entries.
    ///
    /// One scan collects the ages, a linear selection finds the cut-off, and a
    /// second pass removes everything at or below it. `used_at` comes from a
    /// counter that increments on every access, so no two entries share a
    /// value and the cut is exact.
    fn evict_batch(inner: &mut Inner<K, V>, capacity: usize) {
        let drop_count = (capacity / EVICT_FRACTION).max(1);
        let mut ages: Vec<u64> = inner.map.values().map(|e| e.used_at).collect();
        if drop_count >= ages.len() {
            inner.map.clear();
            inner.bytes = 0;
            return;
        }
        // `select_nth_unstable(n)` puts the (n+1)-th smallest age at index n,
        // so exactly `drop_count` entries sit strictly below it. Keeping that
        // entry is what makes the count exact rather than one too many.
        let (_, cutoff, _) = ages.select_nth_unstable(drop_count);
        let cutoff = *cutoff;
        inner.map.retain(|_, e| e.used_at >= cutoff);
        inner.bytes = inner.map.values().map(|e| e.weight).sum();
    }

    /// Drop the least recently used entries until the rest weigh at most
    /// `target` bytes.
    fn evict_to_bytes(inner: &mut Inner<K, V>, target: usize) {
        let mut ages: Vec<(u64, usize)> =
            inner.map.values().map(|e| (e.used_at, e.weight)).collect();
        ages.sort_unstable();
        let mut bytes = inner.bytes;
        let mut cutoff = 0;
        for (used_at, weight) in ages {
            if bytes <= target {
                break;
            }
            bytes = bytes.saturating_sub(weight);
            cutoff = used_at + 1;
        }
        inner.map.retain(|_, e| e.used_at >= cutoff);
        inner.bytes = inner.map.values().map(|e| e.weight).sum();
    }

    /// Store, evicting a batch of the least recently used entries if that
    /// would exceed capacity. Returns the stored value so a caller can use it
    /// without a second lookup.
    pub fn insert(&self, key: K, value: V) -> Arc<V> {
        let weight = self.budget.as_ref().map_or(0, |b| (b.weigh)(&value));
        let value = Arc::new(value);
        if let Some(b) = &self.budget
            && weight > b.bytes / EVICT_FRACTION
        {
            return value;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return value;
        };

        inner.clock += 1;
        let clock = inner.clock;

        if let Some(old) = inner.map.remove(&key) {
            inner.bytes = inner.bytes.saturating_sub(old.weight);
        }
        if inner.map.len() >= self.capacity {
            Self::evict_batch(&mut inner, self.capacity);
        }
        if let Some(b) = &self.budget
            && inner.bytes.saturating_add(weight) > b.bytes
        {
            // Down to a sixteenth of the budget below what this entry needs,
            // so that the next few inserts do not each pay for a scan.
            let target = b
                .bytes
                .saturating_sub(weight)
                .saturating_sub(b.bytes / EVICT_FRACTION);
            Self::evict_to_bytes(&mut inner, target);
        }

        inner.bytes = inner.bytes.saturating_add(weight);
        inner.map.insert(
            key,
            Entry {
                value: Arc::clone(&value),
                weight,
                used_at: clock,
                stored_at: Instant::now(),
            },
        );
        value
    }

    pub fn stats(&self) -> Stats {
        self.inner.lock().map_or(
            Stats {
                len: 0,
                capacity: self.capacity,
                hits: 0,
                misses: 0,
            },
            |i| Stats {
                len: i.map.len(),
                capacity: self.capacity,
                hits: i.hits,
                misses: i.misses,
            },
        )
    }
}

/// One fetch at a time per key, so that callers missing a cache together wait
/// for the first one's answer rather than each asking the daemon.
///
/// A caller takes the key's turn with [`Flights::enter`], looks in the cache
/// again once it has it, and fetches only if the answer is still missing. A
/// key's lock lives only while someone holds or waits for it.
pub struct Flights<K> {
    locks: Mutex<HashMap<K, std::sync::Weak<tokio::sync::Mutex<()>>>>,
}

impl<K> Default for Flights<K> {
    fn default() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Hash + Eq + Clone> Flights<K> {
    /// Wait for `key`'s turn. Several keys taken at once must be taken in one
    /// order everywhere, or two callers can each hold what the other waits
    /// for.
    pub async fn enter(&self, key: &K) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = match self.locks.lock() {
            Ok(mut locks) => {
                locks.retain(|_, l| l.strong_count() > 0);
                match locks.get(key).and_then(std::sync::Weak::upgrade) {
                    Some(lock) => lock,
                    None => {
                        let lock = Arc::new(tokio::sync::Mutex::new(()));
                        locks.insert(key.clone(), Arc::downgrade(&lock));
                        lock
                    }
                }
            }
            // As for the cache: a poisoned map costs the coalescing, not the
            // answer.
            Err(_) => Arc::new(tokio::sync::Mutex::new(())),
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]

    use super::*;

    #[test]
    fn a_byte_budget_bounds_what_is_kept() {
        let cache: Cache<u32, Vec<u8>> = Cache::permanent(1000).within_bytes(1600, Vec::len);
        for k in 0..100 {
            cache.insert(k, vec![0; 50]);
        }
        let weights = |c: &Cache<u32, Vec<u8>>| {
            let inner = c.inner.lock().unwrap();
            (
                inner.bytes,
                inner.map.values().map(|e| e.weight).sum::<usize>(),
            )
        };
        let (held, summed) = weights(&cache);
        assert!(held <= 1600, "{held}");
        assert_eq!(held, summed);
        // The newest survive, and eviction takes only what it must.
        assert!(cache.get(&99).is_some());
        assert!(cache.get(&0).is_none());
        assert!(cache.stats().len >= 28, "{}", cache.stats().len);

        // Over a sixteenth of the budget, a value is handed back, not kept.
        let big = cache.insert(1000, vec![0; 101]);
        assert_eq!(big.len(), 101);
        assert!(cache.get(&1000).is_none());

        // Replacing an entry replaces its weight.
        cache.insert(99, vec![0; 10]);
        let (held, summed) = weights(&cache);
        assert_eq!(held, summed);
    }

    #[test]
    fn only_buried_blocks_may_be_cached_by_height() {
        // The tip and everything near it can still be reorganised onto a
        // different block, so a height is not yet a stable name for one.
        assert!(!safe_to_cache_by_height(0));
        assert!(!safe_to_cache_by_height(1));
        assert!(!safe_to_cache_by_height(REORG_WINDOW - 1));
        // At and beyond the window, a height names one block in practice.
        assert!(safe_to_cache_by_height(REORG_WINDOW));
        assert!(safe_to_cache_by_height(1_000_000));
    }

    #[test]
    fn stores_and_returns_a_value() {
        let c: Cache<u64, String> = Cache::permanent(4);
        assert!(c.get(&1).is_none());
        c.insert(1, "one".to_owned());
        assert_eq!(*c.get(&1).unwrap(), "one");
        let s = c.stats();
        assert_eq!((s.hits, s.misses, s.len), (1, 1, 1));
    }

    /// Eviction clears a batch, and the batch is exactly the size it claims.
    ///
    /// The cost of getting this wrong is not a wrong answer -- an evicted
    /// entry is refetched -- but a cache that quietly holds a fraction of what
    /// it was sized for, or one that goes back to scanning per insert. Both
    /// are invisible without counting.
    #[test]
    fn eviction_clears_a_batch_of_the_least_recently_used() {
        const CAPACITY: usize = 64;
        let expected_drop = CAPACITY / EVICT_FRACTION;
        assert!(expected_drop > 1, "the batch must be bigger than one entry");

        let c: Cache<u64, u64> = Cache::permanent(CAPACITY);
        for i in 0..CAPACITY as u64 {
            c.insert(i, i);
        }
        assert_eq!(c.stats().len, CAPACITY);

        // Touch the oldest half, so recency and insertion order disagree.
        for i in 0..(CAPACITY as u64 / 2) {
            assert!(c.get(&i).is_some());
        }

        c.insert(1000, 1000);
        assert_eq!(
            c.stats().len,
            CAPACITY - expected_drop + 1,
            "one pass should drop exactly {expected_drop} entries"
        );

        // The victims are the untouched ones, which are now least recent.
        let gone = (0..CAPACITY as u64).filter(|i| c.get(i).is_none()).count();
        assert_eq!(gone, expected_drop);
        for i in 0..(CAPACITY as u64 / 2) {
            assert!(c.get(&i).is_some(), "{i} was touched and must survive");
        }
    }

    #[test]
    fn evicts_the_least_recently_used_entry_not_the_oldest() {
        let c: Cache<u64, u64> = Cache::permanent(3);
        c.insert(1, 10);
        c.insert(2, 20);
        c.insert(3, 30);

        // Touch 1, making 2 the least recently used even though 1 is older.
        assert_eq!(*c.get(&1).unwrap(), 10);
        c.insert(4, 40);

        assert!(c.get(&2).is_none(), "2 was least recently used");
        assert!(c.get(&1).is_some(), "1 was touched and must survive");
        assert!(c.get(&3).is_some());
        assert!(c.get(&4).is_some());
        assert_eq!(c.stats().len, 3);
    }

    #[test]
    fn never_grows_past_capacity() {
        let c: Cache<u64, u64> = Cache::permanent(8);
        for i in 0..1000 {
            c.insert(i, i);
        }
        assert_eq!(c.stats().len, 8);
    }

    /// Re-inserting an existing key must not evict a different entry to make
    /// room for something already present.
    #[test]
    fn overwriting_an_existing_key_does_not_evict() {
        let c: Cache<u64, u64> = Cache::permanent(2);
        c.insert(1, 10);
        c.insert(2, 20);
        c.insert(1, 11);
        assert_eq!(c.stats().len, 2);
        assert_eq!(*c.get(&1).unwrap(), 11);
        assert_eq!(*c.get(&2).unwrap(), 20);
    }

    #[test]
    fn an_expired_entry_is_a_miss() {
        let c: Cache<u64, Vec<u8>> =
            Cache::expiring(4, Duration::from_millis(40)).within_bytes(1600, Vec::len);
        c.insert(1, vec![0; 10]);
        assert!(c.get(&1).is_some());
        std::thread::sleep(Duration::from_millis(60));
        assert!(c.get(&1).is_none(), "the entry outlived its ttl");
        assert_eq!(c.stats().len, 0, "and is dropped, not merely hidden");
        assert_eq!(c.inner.lock().unwrap().bytes, 0, "with its weight");
    }

    #[test]
    fn a_permanent_entry_does_not_expire() {
        let c: Cache<u64, u64> = Cache::permanent(4);
        c.insert(1, 10);
        std::thread::sleep(Duration::from_millis(30));
        assert!(c.get(&1).is_some());
    }

    /// A zero capacity would otherwise evict the entry being inserted, making
    /// every lookup a miss on a cache that looks configured.
    #[test]
    fn zero_capacity_is_treated_as_one() {
        let c: Cache<u64, u64> = Cache::permanent(0);
        c.insert(1, 10);
        assert_eq!(*c.get(&1).unwrap(), 10);
    }

    #[test]
    fn values_are_shared_not_copied() {
        let c: Cache<u64, Vec<u8>> = Cache::permanent(2);
        let stored = c.insert(1, vec![1, 2, 3]);
        let fetched = c.get(&1).unwrap();
        assert!(
            Arc::ptr_eq(&stored, &fetched),
            "a cache hit must not clone the value"
        );
    }

    #[test]
    fn is_usable_from_several_threads() {
        let c: Arc<Cache<u64, u64>> = Arc::new(Cache::permanent(64));
        let mut handles = Vec::new();
        for t in 0..8u64 {
            let c = Arc::clone(&c);
            handles.push(std::thread::spawn(move || {
                for i in 0..200 {
                    c.insert(t * 1000 + i, i);
                    let _ = c.get(&(t * 1000 + i));
                }
            }));
        }
        for h in handles {
            h.join().expect("no thread panicked");
        }
        assert!(c.stats().len <= 64);
    }

    /// Callers of one key take turns; callers of another do not wait.
    #[tokio::test]
    async fn flights_of_one_key_take_turns() {
        let flights: Arc<Flights<u8>> = Arc::default();
        let first = flights.enter(&1).await;
        let waiting = {
            let flights = Arc::clone(&flights);
            tokio::spawn(async move { drop(flights.enter(&1).await) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "the second caller of key 1 waits");
        drop(flights.enter(&2).await);
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(
            flights
                .locks
                .lock()
                .unwrap()
                .values()
                .all(|l| l.strong_count() == 0)
        );
    }
}
