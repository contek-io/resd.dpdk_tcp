//! Internal hashed timing wheel (spec §7.4). 8 levels × 256 buckets,
//! 10µs resolution. A5 internal; A6 adds public timer API on top.
//!
//! `allow(dead_code)` at the module level: Task 4 lands the wheel ahead
//! of its consumers (Task 5 adds `cancel`/per-conn id lists; Task 12/17/18
//! wire engine handlers). Variants `Tlp`, `SynRetrans`, `ApiPublic` and
//! fields `owner_handle`, `kind` are read by those later tasks.
#![allow(dead_code)]

use smallvec::SmallVec;

pub const TICK_NS: u64 = 10_000;
pub const LEVELS: usize = 8;
pub const BUCKETS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    Rto,
    Tlp,
    SynRetrans,
    /// Reserved for A6 public `dpdk_net_timer_add`.
    ApiPublic,
}

#[derive(Debug, Clone, Copy)]
pub struct TimerNode {
    pub fire_at_ns: u64,
    pub owner_handle: u32,
    pub kind: TimerKind,
    /// Opaque user payload; only meaningful for `TimerKind::ApiPublic`.
    /// Zero for kernel timers (RTO / TLP / SynRetrans). Round-tripped
    /// verbatim from `add` to `fire`.
    pub user_data: u64,
    pub generation: u32,
    pub cancelled: bool,
}

pub struct TimerWheel {
    slots: Vec<Option<TimerNode>>,
    /// Per-slot generation that survives the `Option::take` that
    /// `advance`/`cascade` use to drain a slot back to the free_list.
    /// Bumped on every slot reuse so TimerIds from the previous occupant
    /// cannot match — `cancel(id)` returns false on a stale id post-reuse.
    generations: Vec<u32>,
    free_list: Vec<u32>,
    buckets: [[Vec<u32>; BUCKETS]; LEVELS],
    cursors: [u16; LEVELS],
    last_tick: u64,
    /// A6.5 Task 10: scratch buffer used by `advance`/`cascade` to
    /// drain a bucket without releasing its heap capacity. We
    /// `mem::swap` this empty-scratch into the bucket slot, iterate
    /// the original bucket by value, clear it, then swap it back into
    /// the bucket array so the next push reuses the same allocation.
    /// Avoids the per-rotation `Vec::new()` replacement that caused
    /// first-push reallocations on every cursor sweep.
    drain_scratch: Vec<u32>,
}

impl TimerWheel {
    pub fn new(initial_slot_capacity: usize) -> Self {
        // A6.5 Task 10: pre-allocate each bucket's Vec<u32> with a
        // capacity large enough to absorb the steady-state arming
        // rate without a single realloc. Under the audit workload
        // (~100K ACKs/s with RTO-arm-per-ACK), each level-0 bucket
        // covers 10µs × 256 = 2.56ms of wall-time, so mean bucket
        // depth is ~80 slots.
        //
        // The worst case isn't steady-state arming into a level-0
        // bucket, though — it's CASCADE: when a level-1 bucket's
        // 655ms-of-arms cascade down, they distribute into a subset
        // of level-0 buckets and can push depth well past 128. The
        // first audit at cap=128 observed 14 amortized grows in a
        // 30s window (Vec grew from 128→256, 1024 bytes each) — all
        // from cascade re-push at `tcp_timer_wheel.rs:124` via
        // `TimerWheel::add`. Bumped to 512 to cover cascade's P99
        // without saturating asymptotically across hours.
        //
        // One-time footprint: 512 u32 × 4 B = 2 KiB per bucket;
        // BUCKETS=256, LEVELS=8 → 256 × 8 × 2 KiB = 4 MiB of
        // wheel-level heap at Engine::new. Acceptable for Stage 1
        // (single engine per process, single lcore). If this
        // becomes a concern, we can tune per-level caps (level-0
        // needs the high cap, level-7 can stay at 128).
        const BUCKET_INIT_CAP: usize = 512;
        // Build level arrays at runtime since `Vec::with_capacity`
        // isn't const. `MaybeUninit`-backed init avoids the
        // intermediate `Vec::new` that the old const-array path
        // produced.
        let buckets: [[Vec<u32>; BUCKETS]; LEVELS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| Vec::with_capacity(BUCKET_INIT_CAP))
        });
        Self {
            slots: Vec::with_capacity(initial_slot_capacity),
            generations: Vec::with_capacity(initial_slot_capacity),
            // free_list holds slot indices recycled by `advance` /
            // `cascade` after a timer fires (or its tombstoned slot is
            // re-encountered). Under sustained TX with TLP firing on
            // every poll, this can match the live-timer ceiling. We
            // pre-size to the same hint as `slots`/`generations` so
            // the no-alloc audit doesn't observe the geometric
            // doubling (0→4→…→64) during ramp.
            free_list: Vec::with_capacity(initial_slot_capacity),
            buckets,
            cursors: [0; LEVELS],
            last_tick: 0,
            drain_scratch: Vec::with_capacity(BUCKET_INIT_CAP),
        }
    }

    pub fn add(&mut self, now_ns: u64, mut node: TimerNode) -> TimerId {
        let delay_ticks = node.fire_at_ns.saturating_sub(now_ns) / TICK_NS;
        let (level, bucket_off) = level_and_bucket_offset(delay_ticks);
        let bucket_idx = (self.cursors[level] as usize + bucket_off) % BUCKETS;

        let slot: u32 = match self.free_list.pop() {
            Some(s) => {
                // Bump generation on reuse so outstanding TimerIds from
                // the previous occupant of this slot cannot match.
                self.generations[s as usize] = self.generations[s as usize].wrapping_add(1);
                s
            }
            None => {
                let s = self.slots.len() as u32;
                self.slots.push(None);
                self.generations.push(0);
                s
            }
        };

        let gen = self.generations[slot as usize];
        node.generation = gen;
        node.cancelled = false;
        self.slots[slot as usize] = Some(node);
        self.buckets[level][bucket_idx].push(slot);

        TimerId {
            slot,
            generation: gen,
        }
    }

    pub fn advance(&mut self, now_ns: u64) -> SmallVec<[(TimerId, TimerNode); 8]> {
        let now_tick = now_ns / TICK_NS;
        if now_tick <= self.last_tick {
            return SmallVec::new();
        }
        let mut fired: SmallVec<[(TimerId, TimerNode); 8]> = SmallVec::new();
        let target_delta = now_tick - self.last_tick;
        for _ in 0..target_delta.min((BUCKETS * LEVELS) as u64) {
            self.cursors[0] = (self.cursors[0] + 1) % BUCKETS as u16;
            self.last_tick += 1;
            let cursor = self.cursors[0] as usize;
            // A6.5 Task 10: iterate the bucket by index and `clear()` it
            // afterward instead of `std::mem::take` (which replaced the
            // bucket with `Vec::new()`, zero-cap). `clear` preserves the
            // Vec's heap capacity so the next push into this bucket
            // reuses the existing allocation — eliminating a steady-
            // state per-cursor-sweep alloc surfaced by the audit.
            let n = self.buckets[0][cursor].len();
            for i in 0..n {
                let slot = self.buckets[0][cursor][i];
                if let Some(node) = self.slots[slot as usize].take() {
                    if !node.cancelled {
                        fired.push((
                            TimerId {
                                slot,
                                generation: node.generation,
                            },
                            node,
                        ));
                    }
                    self.free_list.push(slot);
                }
            }
            self.buckets[0][cursor].clear();
            if self.cursors[0] == 0 {
                self.cascade(1);
            }
        }
        fired
    }

    /// Tombstone-cancel a scheduled timer by TimerId. Returns true if a
    /// live, matching timer was found and marked cancelled; false if the
    /// slot is empty, the generation is stale (slot was reused), or the
    /// timer was already cancelled. Cancelled timers are swept from their
    /// bucket at fire-time without invoking the fire path.
    pub fn cancel(&mut self, id: TimerId) -> bool {
        let slot_idx = id.slot as usize;
        match self.slots.get_mut(slot_idx) {
            Some(Some(node)) if node.generation == id.generation && !node.cancelled => {
                node.cancelled = true;
                true
            }
            _ => false,
        }
    }

    fn cascade(&mut self, level: usize) {
        if level >= LEVELS {
            return;
        }
        self.cursors[level] = (self.cursors[level] + 1) % BUCKETS as u16;
        let cursor = self.cursors[level] as usize;
        let now_ns = self.last_tick * TICK_NS;
        // A6.5 Task 10: swap the cascading bucket into `drain_scratch`
        // to avoid the double-mutable-borrow between the source bucket
        // and the destination bucket (`self.buckets[new_level][new_bucket]`).
        // Unlike `advance`, cascade RE-INSERTS into a different bucket
        // on the same array, so an index-loop on the source bucket
        // would require two overlapping `&mut self.buckets` borrows.
        // The scratch is owned by `self` directly, so there's no
        // aliasing with `self.buckets`. After iterating, we
        // `clear()` the scratch (preserving cap) and `swap` it back —
        // this also preserves the *bucket's* capacity, since the
        // scratch continually absorbs bucket allocations as they move.
        std::mem::swap(&mut self.drain_scratch, &mut self.buckets[level][cursor]);
        for i in 0..self.drain_scratch.len() {
            let slot = self.drain_scratch[i];
            if let Some(node) = self.slots[slot as usize].take() {
                if node.cancelled {
                    self.free_list.push(slot);
                    continue;
                }
                let delay_ticks = node.fire_at_ns.saturating_sub(now_ns) / TICK_NS;
                let (new_level, bucket_off) = level_and_bucket_offset(delay_ticks);
                let new_bucket = (self.cursors[new_level] as usize + bucket_off) % BUCKETS;
                self.slots[slot as usize] = Some(node);
                self.buckets[new_level][new_bucket].push(slot);
            }
        }
        self.drain_scratch.clear();
        std::mem::swap(&mut self.drain_scratch, &mut self.buckets[level][cursor]);
        if self.cursors[level] == 0 {
            self.cascade(level + 1);
        }
    }
}

fn level_and_bucket_offset(delay_ticks: u64) -> (usize, usize) {
    for level in 0..LEVELS {
        let level_span: u64 = 1u64 << (8 * (level + 1));
        if delay_ticks < level_span {
            let bucket_span: u64 = 1u64 << (8 * level);
            let off = (delay_ticks / bucket_span) as usize;
            return (level, off.clamp(1, BUCKETS - 1));
        }
    }
    (LEVELS - 1, BUCKETS - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(fire_at_ns: u64) -> TimerNode {
        TimerNode {
            fire_at_ns,
            owner_handle: 0,
            kind: TimerKind::Rto,
            user_data: 0,
            generation: 0,
            cancelled: false,
        }
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn add_and_fire_short_timer() {
        let mut w = TimerWheel::new(8);
        let _id = w.add(0, node(100_000));
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 1);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn advance_with_no_tick_skips() {
        let mut w = TimerWheel::new(8);
        w.add(0, node(100_000));
        assert!(w.advance(5_000).is_empty());
        assert_eq!(w.last_tick, 0);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn level_math_level0_level1() {
        assert_eq!(level_and_bucket_offset(1), (0, 1));
        assert_eq!(level_and_bucket_offset(255), (0, 255));
        assert_eq!(level_and_bucket_offset(256), (1, 1));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn long_timer_cascades() {
        let mut w = TimerWheel::new(8);
        let _short = w.add(0, node(300_000));
        let _long = w.add(0, node(3_000_000));
        assert_eq!(w.advance(300_000).len(), 1);
        assert_eq!(w.advance(3_000_000).len(), 1);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn cancel_tombstones_the_slot() {
        let mut w = TimerWheel::new(8);
        let id = w.add(0, node(100_000));
        assert!(w.cancel(id));
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 0);
        assert!(!w.cancel(id));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn cancel_stale_id_after_reuse_is_noop() {
        let mut w = TimerWheel::new(8);
        let id_a = w.add(0, node(100_000));
        let _ = w.advance(100_000);
        let id_b = w.add(100_000, node(200_000));
        assert!(!w.cancel(id_a));
        let fired = w.advance(200_000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, id_b);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn timer_node_carries_user_data_through_fire() {
        let mut w = TimerWheel::new(8);
        let id = w.add(0, TimerNode {
            fire_at_ns: 100_000,
            owner_handle: 0,
            kind: TimerKind::ApiPublic,
            user_data: 0xDEAD_BEEF_CAFE_BABE,
            generation: 0,
            cancelled: false,
        });
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 1);
        let (fired_id, node) = &fired[0];
        assert_eq!(*fired_id, id);
        assert_eq!(node.user_data, 0xDEAD_BEEF_CAFE_BABE);
    }
}
