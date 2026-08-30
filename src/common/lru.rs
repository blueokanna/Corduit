//! A capacity-bounded, least-recently-used (LRU) cache — Corduit's own.
//!
//! # Why this module exists
//!
//! The stock `lru` crate carried a panic-safety flaw (RUSTSEC-2026-0253): its
//! intrusive recency list is built on raw pointers, and `pop()` unlinked the
//! node only *after* its key had been dropped. A key whose `Drop` panicked
//! left the node dangling in the list; the next eviction then wrote through
//! freed memory — a use-after-free reachable from safe code.
//!
//! This module replaces that dependency with a shape that makes the failure
//! mode structurally impossible rather than merely patched:
//!
//! * **No pointers, no `unsafe`.** Entries live in a contiguous arena
//!   (`slots: Vec<Slot<K, V>>`) and the recency order is a doubly-linked
//!   list of *indices* (`Option<usize>`), never addresses. A "dangling
//!   index" is just a number; it cannot be dereferenced into freed memory.
//!   (This file sits under `common`'s `#![deny(unsafe_code)]`, so the
//!   guarantee is enforced by the compiler.)
//! * **Unlink before drop.** Every path that removes an entry — eviction,
//!   `pop`, `pop_lru`, `clear` — unlinks the node from the recency list and
//!   takes its key/value out of the slot *first*, then drops them. A
//!   panicking `Drop` can leave at worst a logically-incomplete cache, never
//!   a corrupt one.
//! * **Dense memory.** Walking recency order touches a compact page set
//!   instead of chasing heap allocations, and insert/remove recycles arena
//!   slots through a free list instead of reallocating.
//!
//! # Ownership model
//!
//! `map: HashMap<K, usize>` is the canonical store: it owns every key and
//! answers membership in O(1). Each live slot additionally caches a clone of
//! its key so eviction can unlink in O(1) without scanning the map. That one
//! clone per insert is the price of the safety guarantee — for the caches
//! this backs (DNS resolutions, fake-IP leases) it is a single `String`
//! clone on a cache miss, noise next to the lookup it serves.
//!
//! # Hash-DoS resistance
//!
//! The default hasher is `RandomState` (SipHash with per-process random
//! keys), so a hostile feed of cache keys — and proxy domain names are
//! attacker-influenced — cannot engineer hash collisions.

use std::borrow::Borrow;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::num::NonZeroUsize;

/// Default hasher — see module docs.
type DefaultHashBuilder = RandomState;

/// One arena slot. `key == None` marks a recycled (free) slot; `prev`/`next`
/// are indices into the arena that form the recency list.
struct Slot<K, V> {
    key: Option<K>,
    value: Option<V>,
    prev: Option<usize>,
    next: Option<usize>,
}

impl<K, V> Slot<K, V> {
    fn new() -> Self {
        Slot {
            key: None,
            value: None,
            prev: None,
            next: None,
        }
    }
}

/// A capacity-bounded LRU cache.
///
/// `get`/`put`/`pop`/`pop_lru` are O(1). Iteration yields entries from
/// most-recently-used to least-recently-used.
pub struct LruCache<K, V, S = DefaultHashBuilder> {
    /// Key -> arena index. Owns every key.
    map: HashMap<K, usize, S>,
    /// Contiguous entry storage (the arena).
    slots: Vec<Slot<K, V>>,
    /// Recycled arena indices.
    free: Vec<usize>,
    /// Head of the recency list = most-recently-used.
    head: Option<usize>,
    /// Tail of the recency list = least-recently-used.
    tail: Option<usize>,
    capacity: usize,
    len: usize,
}

impl<K, V> LruCache<K, V, DefaultHashBuilder>
where
    K: Eq + Hash,
{
    /// Create an empty cache holding at most `capacity` entries.
    ///
    /// There is deliberately no `Default`: a cache without a capacity bound
    /// is a different data structure.
    #[allow(clippy::new_without_default)]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self::with_hasher(capacity, RandomState::new())
    }
}

impl<K, V, S> LruCache<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    /// Create an empty cache with a custom hasher.
    pub fn with_hasher(capacity: NonZeroUsize, hash_builder: S) -> Self {
        LruCache {
            map: HashMap::with_hasher(hash_builder),
            slots: Vec::new(),
            free: Vec::new(),
            head: None,
            tail: None,
            capacity: capacity.get(),
            len: 0,
        }
    }

    /// Maximum number of entries this cache can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `key` is present, without changing recency order.
    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(key)
    }

    /// Look up `key`, promoting it to most-recently-used.
    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.map.get(key)?;
        self.move_to_front(idx);
        self.slots[idx].value.as_ref()
    }

    /// Look up `key` without changing recency order.
    pub fn peek<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.map.get(key)?;
        self.slots[idx].value.as_ref()
    }

    /// Look up `key` mutably, promoting it to most-recently-used.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.map.get(key)?;
        self.move_to_front(idx);
        self.slots[idx].value.as_mut()
    }

    /// Remove `key`, returning its value. Recency order of the survivors is
    /// unchanged.
    pub fn pop<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.map.get(key)?;
        // Take the value out first so no panic between unlink and map removal
        // can strand it in a recycled slot.
        let v = self.slots[idx]
            .value
            .take()
            .expect("live slot owns a value");
        self.remove_at(idx);
        self.map.remove(key);
        Some(v)
    }

    /// Remove and return the least-recently-used entry, if any.
    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        let idx = self.tail?;
        // Same ordering as `evict_lru`: take the slot's owned data out, then
        // unlink/recycle, then drop the map's canonical key.
        let k = self.slots[idx].key.take().expect("live slot owns a key");
        let v = self.slots[idx]
            .value
            .take()
            .expect("live slot owns a value");
        self.remove_at(idx);
        self.map.remove(&k);
        Some((k, v))
    }

    /// Remove every entry, keeping the capacity.
    pub fn clear(&mut self) {
        // Drop canonical keys first. `HashMap::clear` removes an entry before
        // its key's `Drop` runs, so a panicking key `Drop` can never leave a
        // map entry pointing at a recycled slot.
        self.map.clear();
        // Drop the auxiliary key clones and values. `take` first so a
        // panicking `Drop` leaves the slot inert rather than half-dropped.
        for slot in &mut self.slots {
            slot.key.take();
            slot.value.take();
        }
        self.slots.clear();
        self.free.clear();
        self.head = None;
        self.tail = None;
        self.len = 0;
    }

    /// Iterate from most-recently-used to least-recently-used.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            slots: &self.slots,
            cur: self.head,
        }
    }

    /// Iterate keys from most-recently-used to least-recently-used.
    pub fn keys(&self) -> Keys<'_, K, V> {
        Keys { inner: self.iter() }
    }

    // --- internals ---------------------------------------------------------

    /// Grab a slot, reusing a recycled one if available.
    fn alloc_slot(&mut self) -> usize {
        if let Some(idx) = self.free.pop() {
            idx
        } else {
            self.slots.push(Slot::new());
            self.slots.len() - 1
        }
    }

    /// Link `idx` at the head (most-recently-used) of the recency list.
    fn link_front(&mut self, idx: usize) {
        self.slots[idx].prev = None;
        self.slots[idx].next = self.head;
        match self.head {
            Some(h) => self.slots[h].prev = Some(idx),
            None => self.tail = Some(idx),
        }
        self.head = Some(idx);
    }

    /// Unlink `idx` from the recency list. Pure index bookkeeping — no owned
    /// data is touched, so a later panicking `Drop` cannot corrupt the list.
    fn unlink(&mut self, idx: usize) {
        let prev = self.slots[idx].prev;
        let next = self.slots[idx].next;
        match prev {
            Some(p) => self.slots[p].next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.slots[n].prev = prev,
            None => self.tail = prev,
        }
        self.slots[idx].prev = None;
        self.slots[idx].next = None;
    }

    /// Move `idx` to the head of the recency list.
    fn move_to_front(&mut self, idx: usize) {
        if self.head == Some(idx) {
            return;
        }
        self.unlink(idx);
        self.link_front(idx);
    }

    /// Remove the least-recently-used entry and recycle its slot. Returns its
    /// key and value.
    ///
    /// Ordering is the panic-safety core of this module:
    /// 1. unlink (list is consistent),
    /// 2. take the slot's key/value out (slot is inert),
    /// 3. update `len` and recycle the slot,
    /// 4. remove the canonical key from the map (entry removed before its
    ///    `Drop` runs),
    /// 5. only then drop the key/value.
    ///
    /// A panic at any step leaves the cache structurally consistent — the
    /// exact failure mode behind RUSTSEC-2026-0253 is impossible here.
    fn evict_lru(&mut self) -> Option<(K, V)> {
        let idx = self.tail?;
        self.unlink(idx);
        let k = self.slots[idx].key.take().expect("live slot owns a key");
        let v = self.slots[idx]
            .value
            .take()
            .expect("live slot owns a value");
        self.len -= 1;
        self.free.push(idx);
        self.map.remove(&k);
        Some((k, v))
    }

    /// Unlink `idx` and recycle its slot, returning the key/value still in
    /// the slot for the caller to dispose of. Used by `pop`/`pop_lru` after
    /// the canonical key has been removed from the map.
    fn remove_at(&mut self, idx: usize) {
        self.unlink(idx);
        self.len -= 1;
        self.free.push(idx);
    }
}

impl<K, V, S> LruCache<K, V, S>
where
    K: Eq + Hash + Clone,
    S: BuildHasher,
{
    /// Insert `key -> value`, promoting it to most-recently-used.
    ///
    /// Returns the displaced value, if any: the old value when `key` already
    /// existed, or the evicted least-recently-used value when the cache was
    /// full.
    ///
    /// Only this method needs `K: Clone`: the slot keeps an auxiliary clone
    /// of the key so eviction can unlink in O(1) without scanning the map.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        if let Some(&idx) = self.map.get(&key) {
            let old = self.slots[idx].value.replace(value);
            self.move_to_front(idx);
            return old;
        }
        let evicted = if self.len == self.capacity {
            self.evict_lru().map(|(_, v)| v)
        } else {
            None
        };
        let idx = self.alloc_slot();
        self.slots[idx].key = Some(key.clone());
        self.slots[idx].value = Some(value);
        self.map.insert(key, idx);
        self.link_front(idx);
        self.len += 1;
        evicted
    }
}

/// Iterator over `(&K, &V)`, MRU → LRU.
pub struct Iter<'a, K, V> {
    slots: &'a [Slot<K, V>],
    cur: Option<usize>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.cur?;
        let slot = &self.slots[idx];
        self.cur = slot.next;
        Some((slot.key.as_ref()?, slot.value.as_ref()?))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut n = 0usize;
        let mut cur = self.cur;
        while let Some(idx) = cur {
            n += 1;
            cur = self.slots[idx].next;
        }
        (n, Some(n))
    }
}

/// Iterator over `&K`, MRU → LRU.
pub struct Keys<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Keys<'a, K, V> {
    type Item = &'a K;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, _)| k)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Consuming iterator over `(K, V)`, LRU → MRU.
pub struct IntoIter<K, V, S = DefaultHashBuilder> {
    cache: LruCache<K, V, S>,
}

impl<K, V, S> Iterator for IntoIter<K, V, S>
where
    K: Eq + Hash + Clone,
    S: BuildHasher,
{
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.cache.pop_lru()
    }
}

impl<K, V, S> IntoIterator for LruCache<K, V, S>
where
    K: Eq + Hash + Clone,
    S: BuildHasher,
{
    type Item = (K, V);
    type IntoIter = IntoIter<K, V, S>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter { cache: self }
    }
}

impl<K, V, S> fmt::Debug for LruCache<K, V, S>
where
    K: Eq + Hash + fmt::Debug,
    V: fmt::Debug,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn cap(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn new_cache_is_empty_with_requested_capacity() {
        let mut c: LruCache<String, i32> = LruCache::new(cap(7));
        assert_eq!(c.capacity(), 7);
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
        assert!(c.get("missing").is_none());
        assert!(c.peek("missing").is_none());
        assert!(!c.contains("missing"));
    }

    #[test]
    fn put_then_get_roundtrips() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(3));
        assert_eq!(c.put("a", 1), None);
        c.put("b", 2);
        assert_eq!(c.len(), 2);
        assert!(c.contains("a") && c.contains("b"));
        assert_eq!(c.get("a"), Some(&1));
        assert_eq!(c.get("b"), Some(&2));
        assert_eq!(c.get_mut("a"), Some(&mut 1));
    }

    #[test]
    fn get_reorders_to_most_recently_used() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(2));
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.get("a"), Some(&1)); // "a" now MRU, "b" LRU
        c.put("c", 3); // evicts "b"
        assert!(!c.contains("b"));
        assert!(c.contains("a"));
        assert!(c.contains("c"));
    }

    #[test]
    fn peek_does_not_reorder() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(2));
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.peek("a"), Some(&1)); // peek must not move "a" to MRU
        c.put("c", 3); // "a" is still LRU -> evicted
        assert!(!c.contains("a"));
        assert!(c.contains("b"));
        assert!(c.contains("c"));
    }

    #[test]
    fn put_updates_existing_key_and_moves_to_front() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(2));
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.put("a", 10), Some(1)); // update returns the old value
        assert_eq!(c.len(), 2);
        assert_eq!(c.get("a"), Some(&10));
        c.put("c", 3); // "a" is MRU -> evicts "b"
        assert!(!c.contains("b"));
        assert!(c.contains("a"));
    }

    #[test]
    fn evicts_least_recently_used_when_full() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(3));
        c.put("a", 1);
        c.put("b", 2);
        c.put("c", 3);
        assert_eq!(c.len(), 3);
        assert_eq!(c.get("a"), Some(&1)); // "a" -> MRU, "b" -> LRU
        c.put("d", 4);
        assert_eq!(c.len(), 3);
        assert!(!c.contains("b"), "b should have been evicted");
        assert_eq!(c.get("a"), Some(&1));
        assert_eq!(c.get("c"), Some(&3));
        assert_eq!(c.get("d"), Some(&4));
    }

    #[test]
    fn put_returns_evicted_value_when_full() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(2));
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.put("c", 3), Some(1)); // evicts "a"
        assert_eq!(c.put("d", 4), Some(2)); // evicts "b"
        assert_eq!(c.put("e", 5), Some(3)); // evicts "c"
    }

    #[test]
    fn pop_removes_specific_key() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(3));
        c.put("a", 1);
        c.put("b", 2);
        c.put("c", 3);
        assert_eq!(c.pop("b"), Some(2));
        assert_eq!(c.len(), 2);
        assert!(!c.contains("b"));
        assert!(c.contains("a") && c.contains("c"));
        assert_eq!(c.pop("missing"), None);
        // The survivors keep their recency links intact.
        assert_eq!(c.iter().count(), 2);
    }

    #[test]
    fn pop_lru_returns_least_recently_used() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(3));
        c.put("a", 1);
        c.put("b", 2);
        c.put("c", 3);
        assert_eq!(c.get("c"), Some(&3)); // "c" MRU
        assert_eq!(c.pop_lru(), Some(("a", 1)));
        assert_eq!(c.pop_lru(), Some(("b", 2)));
        assert_eq!(c.len(), 1);
        assert_eq!(c.pop_lru(), Some(("c", 3)));
        assert!(c.is_empty());
        assert_eq!(c.pop_lru(), None);
    }

    #[test]
    fn clear_removes_everything_and_stays_usable() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(3));
        c.put("a", 1);
        c.put("b", 2);
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.capacity(), 3);
        assert!(c.get("a").is_none());
        c.put("z", 26); // still usable after clear
        assert_eq!(c.get("z"), Some(&26));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn single_entry_cache_evicts_itself() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(1));
        c.put("a", 1);
        assert_eq!(c.get("a"), Some(&1));
        c.put("b", 2); // evicts "a"
        assert!(!c.contains("a"));
        assert_eq!(c.get("b"), Some(&2));
        assert_eq!(c.len(), 1);
        c.put("b", 20); // update keeps len 1
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("b"), Some(&20));
    }

    #[test]
    fn iter_yields_most_to_least_recently_used() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(5));
        c.put("a", 1);
        c.put("b", 2);
        c.put("c", 3);
        assert_eq!(c.get("a"), Some(&1)); // "a" -> MRU
        let order: Vec<_> = c.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(order, vec![("a", 1), ("c", 3), ("b", 2)]);
    }

    #[test]
    fn keys_yields_keys_in_recency_order() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(4));
        c.put("x", 1);
        c.put("y", 2);
        let keys: Vec<_> = c.keys().copied().collect();
        assert_eq!(keys, vec!["y", "x"]);
    }

    #[test]
    fn into_iter_consumes_cache() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(4));
        c.put("a", 1);
        c.put("b", 2);
        c.put("c", 3);
        let mut items: Vec<_> = c.into_iter().collect();
        items.sort();
        assert_eq!(items, vec![("a", 1), ("b", 2), ("c", 3)]);
    }

    #[test]
    fn debug_output_is_a_map() {
        let mut c: LruCache<&'static str, i32> = LruCache::new(cap(4));
        c.put("a", 1);
        let s = format!("{c:?}");
        assert!(s.contains("\"a\": 1"), "unexpected Debug: {s}");
    }

    #[test]
    fn slot_reuse_keeps_invariants() {
        let mut c: LruCache<String, i32> = LruCache::new(cap(4));
        for i in 0..1000 {
            c.put(format!("k{i}"), i);
            if i % 3 == 0 {
                assert_eq!(c.pop(format!("k{i}").as_str()), Some(i));
            }
            assert!(c.len() <= 4);
            assert_eq!(c.len(), c.iter().count());
        }
        for (k, v) in c.iter() {
            assert_eq!(c.peek(k), Some(v));
        }
    }

    #[test]
    fn borrowed_str_lookup_works() {
        let mut c: LruCache<String, i32> = LruCache::new(cap(4));
        c.put("example.com".to_string(), 1);
        assert_eq!(c.get("example.com"), Some(&1)); // &str, not &String
        assert_eq!(c.peek("example.com"), Some(&1));
        assert!(c.contains("example.com"));
        assert_eq!(c.pop("example.com"), Some(1));
        assert!(c.is_empty());
    }

    /// Deterministic pseudo-random generator so the property test is
    /// reproducible across runs and platforms.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn randomized_operations_match_oracle() {
        let mut c: LruCache<i32, i32> = LruCache::new(cap(16));
        let mut oracle: StdMap<i32, i32> = StdMap::new();
        let mut rng = SplitMix64(0x1234_5678_9ABC_DEF0);
        for _ in 0..5000 {
            let k = (rng.next() % 24) as i32;
            match rng.next() % 5 {
                0 => {
                    c.put(k, k * 100);
                    oracle.insert(k, k * 100);
                }
                1 => assert_eq!(c.get(&k).copied(), oracle.get(&k).copied()),
                2 => assert_eq!(c.pop(&k), oracle.remove(&k)),
                3 => assert_eq!(c.peek(&k).copied(), oracle.get(&k).copied()),
                _ => {
                    if let Some((k2, v2)) = c.pop_lru() {
                        assert_eq!(oracle.remove(&k2), Some(v2));
                    }
                }
            }
            // Invariants after every step: recency list and map agree.
            assert_eq!(c.len(), c.iter().count(), "list/map length mismatch");
            assert!(c.len() <= c.capacity());
            for (k, v) in c.iter() {
                assert_eq!(oracle.get(k), Some(v), "cache holds a ghost entry");
            }
        }
        // Final state must agree exactly with the oracle.
        assert_eq!(c.len(), oracle.len());
        for (k, v) in c.iter() {
            assert_eq!(oracle.get(k), Some(v));
        }
        for (k, v) in &oracle {
            assert_eq!(c.peek(k), Some(v));
        }
    }

    /// A key whose `Drop` panics for a chosen value — used to prove the
    /// eviction path cannot corrupt the cache (the RUSTSEC-2026-0253
    /// scenario). It panics at most once per process so the test's unwinding
    /// never double-panics (which would abort).
    #[derive(Hash, PartialEq, Eq, Clone, Debug)]
    struct PanicKey(usize);

    static KEY_PANIC_ARMED: AtomicBool = AtomicBool::new(true);

    impl Drop for PanicKey {
        fn drop(&mut self) {
            if self.0 == 42 && KEY_PANIC_ARMED.swap(false, Ordering::SeqCst) {
                panic!("PanicKey(42) dropped");
            }
        }
    }

    #[test]
    fn panicking_key_drop_during_eviction_leaves_cache_usable() {
        KEY_PANIC_ARMED.store(true, Ordering::SeqCst);
        let mut c: LruCache<PanicKey, i32> = LruCache::new(cap(2));
        c.put(PanicKey(5), 1);
        c.put(PanicKey(6), 2);
        c.put(PanicKey(7), 3); // evicts 5 (harmless drop)
        c.put(PanicKey(42), 4); // evicts 6 (harmless); 42 now MRU
        assert_eq!(c.get(&PanicKey(7)), Some(&3)); // 7 -> MRU, 42 -> LRU
                                                   // The next put evicts PanicKey(42); dropping its canonical key panics
                                                   // mid-eviction. This is exactly the failure mode behind
                                                   // RUSTSEC-2026-0253: the cache must stay structurally consistent.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.put(PanicKey(8), 5);
        }));
        assert!(result.is_err(), "eviction of the panicking key must unwind");
        // Cache is consistent and fully usable afterwards.
        assert_eq!(c.len(), c.iter().count());
        assert!(c.len() <= 2);
        assert_eq!(c.get(&PanicKey(7)), Some(&3));
        assert!(!c.contains(&PanicKey(42)));
        c.put(PanicKey(9), 6);
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(&PanicKey(7)), Some(&3));
        assert_eq!(c.get(&PanicKey(9)), Some(&6));
    }

    /// A value whose `Drop` panics. The cache must hand it back (via
    /// `put`'s return / `pop_lru`) only after the structure is consistent, so
    /// a panicking value `Drop` can never corrupt anything.
    #[derive(Debug, PartialEq, Eq)]
    struct PanicValue(i32);

    static VALUE_PANIC_ARMED: AtomicBool = AtomicBool::new(true);

    impl Drop for PanicValue {
        fn drop(&mut self) {
            if self.0 == 42 && VALUE_PANIC_ARMED.swap(false, Ordering::SeqCst) {
                panic!("PanicValue(42) dropped");
            }
        }
    }

    #[test]
    fn panicking_value_drop_during_eviction_leaves_cache_usable() {
        VALUE_PANIC_ARMED.store(true, Ordering::SeqCst);
        let mut c: LruCache<&'static str, PanicValue> = LruCache::new(cap(2));
        c.put("a", PanicValue(1));
        c.put("b", PanicValue(2));
        c.put("c", PanicValue(3)); // evicts "a"
        c.put("z", PanicValue(42)); // evicts "b"; "z" now MRU
        assert_eq!(c.get("c"), Some(&PanicValue(3))); // "c" -> MRU, "z" -> LRU
                                                      // Evicting "z" returns its value to `put`'s caller, whose drop panics
                                                      // after the cache is already consistent.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.put("w", PanicValue(5));
        }));
        assert!(result.is_err(), "dropping the evicted value must unwind");
        // The eviction completed and "w" was inserted; only the *returned*
        // evicted value's drop panicked (in the caller). The cache is fully
        // consistent: [w, c].
        assert_eq!(c.len(), c.iter().count());
        assert_eq!(c.len(), 2);
        assert!(c.contains("c"));
        assert!(c.contains("w"));
        assert!(!c.contains("z"));
        c.put("q", PanicValue(6)); // full again -> evicts "c" (harmless)
        assert_eq!(c.len(), 2);
        assert!(c.contains("w") && c.contains("q"));
        assert!(!c.contains("c"));
    }
}
