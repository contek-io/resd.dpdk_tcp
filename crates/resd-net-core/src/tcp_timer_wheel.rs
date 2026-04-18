//! Internal hashed timing wheel (spec §7.4). 8 levels × 256 buckets,
//! 10µs resolution. A5 internal; A6 adds public timer API on top.
//!
//! `allow(dead_code)` at the module level: Task 4 lands the wheel ahead
//! of its consumers (Task 5 adds `cancel`/per-conn id lists; Task 12/17/18
//! wire engine handlers). Variants `Tlp`, `SynRetrans`, `ApiPublic` and
//! fields `owner_handle`, `kind` are read by those later tasks.
#![allow(dead_code)]

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
    /// Reserved for A6 public `resd_net_timer_add`.
    ApiPublic,
}

#[derive(Debug, Clone, Copy)]
pub struct TimerNode {
    pub fire_at_ns: u64,
    pub owner_handle: u32,
    pub kind: TimerKind,
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
}

impl TimerWheel {
    pub fn new(initial_slot_capacity: usize) -> Self {
        const EMPTY_BUCKET: Vec<u32> = Vec::new();
        const EMPTY_LEVEL: [Vec<u32>; BUCKETS] = [EMPTY_BUCKET; BUCKETS];
        Self {
            slots: Vec::with_capacity(initial_slot_capacity),
            generations: Vec::with_capacity(initial_slot_capacity),
            free_list: Vec::new(),
            buckets: [EMPTY_LEVEL; LEVELS],
            cursors: [0; LEVELS],
            last_tick: 0,
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

    pub fn advance(&mut self, now_ns: u64) -> Vec<(TimerId, TimerNode)> {
        let now_tick = now_ns / TICK_NS;
        if now_tick <= self.last_tick {
            return Vec::new();
        }
        let mut fired = Vec::new();
        let target_delta = now_tick - self.last_tick;
        for _ in 0..target_delta.min((BUCKETS * LEVELS) as u64) {
            self.cursors[0] = (self.cursors[0] + 1) % BUCKETS as u16;
            self.last_tick += 1;
            let cursor = self.cursors[0] as usize;
            let bucket = std::mem::take(&mut self.buckets[0][cursor]);
            for slot in bucket {
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
        let bucket = std::mem::take(&mut self.buckets[level][cursor]);
        let now_ns = self.last_tick * TICK_NS;
        for slot in bucket {
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
            generation: 0,
            cancelled: false,
        }
    }

    #[test]
    fn add_and_fire_short_timer() {
        let mut w = TimerWheel::new(8);
        let _id = w.add(0, node(100_000));
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn advance_with_no_tick_skips() {
        let mut w = TimerWheel::new(8);
        w.add(0, node(100_000));
        assert!(w.advance(5_000).is_empty());
        assert_eq!(w.last_tick, 0);
    }

    #[test]
    fn level_math_level0_level1() {
        assert_eq!(level_and_bucket_offset(1), (0, 1));
        assert_eq!(level_and_bucket_offset(255), (0, 255));
        assert_eq!(level_and_bucket_offset(256), (1, 1));
    }

    #[test]
    fn long_timer_cascades() {
        let mut w = TimerWheel::new(8);
        let _short = w.add(0, node(300_000));
        let _long = w.add(0, node(3_000_000));
        assert_eq!(w.advance(300_000).len(), 1);
        assert_eq!(w.advance(3_000_000).len(), 1);
    }

    #[test]
    fn cancel_tombstones_the_slot() {
        let mut w = TimerWheel::new(8);
        let id = w.add(0, node(100_000));
        assert!(w.cancel(id));
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 0);
        assert!(!w.cancel(id));
    }

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
}
