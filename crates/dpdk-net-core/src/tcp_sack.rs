//! Received-side SACK scoreboard (RFC 2018). Populated by tcp_input
//! from inbound-ACK SACK blocks; consumed by A5 RACK-TLP retransmit
//! (A4 only queries via `is_sacked` in integration tests).
//!
//! Storage: fixed 4-entry array + count. Merge on insert when ranges
//! touch or overlap; drop oldest on overflow. See AD-A4-sack-scoreboard-size.

use crate::tcp_options::SackBlock;
use crate::tcp_seq::{seq_le, seq_lt};

pub const MAX_SACK_SCOREBOARD_ENTRIES: usize = 4;

#[derive(Default)]
pub struct SackScoreboard {
    blocks: [SackBlock; MAX_SACK_SCOREBOARD_ENTRIES],
    count: u8,
}

impl SackScoreboard {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn len(&self) -> usize {
        self.count as usize
    }
    pub fn blocks(&self) -> &[SackBlock] {
        &self.blocks[..self.count as usize]
    }

    pub fn is_sacked(&self, seq: u32) -> bool {
        for b in self.blocks() {
            if seq_le(b.left, seq) && seq_lt(seq, b.right) {
                return true;
            }
        }
        false
    }

    pub fn insert(&mut self, block: SackBlock) -> bool {
        // Merge-with-existing pass.
        let mut merged_into: Option<usize> = None;
        for i in 0..(self.count as usize) {
            let cur = self.blocks[i];
            if seq_le(block.left, cur.right) && seq_le(cur.left, block.right) {
                let new_left = if seq_le(cur.left, block.left) {
                    cur.left
                } else {
                    block.left
                };
                let new_right = if seq_le(block.right, cur.right) {
                    cur.right
                } else {
                    block.right
                };
                self.blocks[i] = SackBlock {
                    left: new_left,
                    right: new_right,
                };
                merged_into = Some(i);
                break;
            }
        }
        if merged_into.is_some() {
            self.collapse();
            return true;
        }
        if (self.count as usize) < MAX_SACK_SCOREBOARD_ENTRIES {
            self.blocks[self.count as usize] = block;
            self.count += 1;
        } else {
            for i in 1..MAX_SACK_SCOREBOARD_ENTRIES {
                self.blocks[i - 1] = self.blocks[i];
            }
            self.blocks[MAX_SACK_SCOREBOARD_ENTRIES - 1] = block;
        }
        true
    }

    pub fn prune_below(&mut self, snd_una: u32) {
        let mut w = 0usize;
        for i in 0..(self.count as usize) {
            let b = self.blocks[i];
            if seq_le(b.right, snd_una) {
                continue;
            }
            let pruned = SackBlock {
                left: if seq_le(b.left, snd_una) {
                    snd_una
                } else {
                    b.left
                },
                right: b.right,
            };
            self.blocks[w] = pruned;
            w += 1;
        }
        self.count = w as u8;
    }

    fn collapse(&mut self) {
        loop {
            let mut pair: Option<(usize, usize)> = None;
            'outer: for i in 0..(self.count as usize) {
                for j in (i + 1)..(self.count as usize) {
                    let a = self.blocks[i];
                    let b = self.blocks[j];
                    if seq_le(a.left, b.right) && seq_le(b.left, a.right) {
                        pair = Some((i, j));
                        break 'outer;
                    }
                }
            }
            let Some((i, j)) = pair else { break };
            let a = self.blocks[i];
            let b = self.blocks[j];
            let new_left = if seq_le(a.left, b.left) {
                a.left
            } else {
                b.left
            };
            let new_right = if seq_le(b.right, a.right) {
                a.right
            } else {
                b.right
            };
            self.blocks[i] = SackBlock {
                left: new_left,
                right: new_right,
            };
            for k in (j + 1)..(self.count as usize) {
                self.blocks[k - 1] = self.blocks[k];
            }
            self.count -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scoreboard_claims_nothing_sacked() {
        let sb = SackScoreboard::new();
        assert!(!sb.is_sacked(100));
        assert_eq!(sb.len(), 0);
    }

    #[test]
    fn single_insert_reports_block() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 200,
        });
        assert_eq!(sb.len(), 1);
        assert!(sb.is_sacked(100));
        assert!(sb.is_sacked(150));
        assert!(!sb.is_sacked(200));
        assert!(!sb.is_sacked(99));
    }

    #[test]
    fn touching_inserts_merge() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 200,
        });
        sb.insert(SackBlock {
            left: 200,
            right: 300,
        });
        assert_eq!(sb.len(), 1);
        assert_eq!(
            sb.blocks()[0],
            SackBlock {
                left: 100,
                right: 300
            }
        );
    }

    #[test]
    fn overlapping_inserts_merge() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 200,
        });
        sb.insert(SackBlock {
            left: 150,
            right: 250,
        });
        assert_eq!(sb.len(), 1);
        assert_eq!(
            sb.blocks()[0],
            SackBlock {
                left: 100,
                right: 250
            }
        );
    }

    #[test]
    fn disjoint_inserts_stay_separate() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 200,
        });
        sb.insert(SackBlock {
            left: 300,
            right: 400,
        });
        assert_eq!(sb.len(), 2);
    }

    #[test]
    fn insert_filling_gap_collapses_three_to_one() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 200,
        });
        sb.insert(SackBlock {
            left: 300,
            right: 400,
        });
        sb.insert(SackBlock {
            left: 200,
            right: 300,
        });
        assert_eq!(sb.len(), 1);
        assert_eq!(
            sb.blocks()[0],
            SackBlock {
                left: 100,
                right: 400
            }
        );
    }

    #[test]
    fn overflow_evicts_oldest() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 150,
        });
        sb.insert(SackBlock {
            left: 200,
            right: 250,
        });
        sb.insert(SackBlock {
            left: 300,
            right: 350,
        });
        sb.insert(SackBlock {
            left: 400,
            right: 450,
        });
        assert_eq!(sb.len(), 4);
        sb.insert(SackBlock {
            left: 500,
            right: 550,
        });
        assert_eq!(sb.len(), 4);
        assert!(!sb.is_sacked(100));
        assert!(sb.is_sacked(500));
    }

    #[test]
    fn prune_below_drops_fully_covered_blocks() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 200,
        });
        sb.insert(SackBlock {
            left: 300,
            right: 400,
        });
        sb.prune_below(250);
        assert_eq!(sb.len(), 1);
        assert_eq!(
            sb.blocks()[0],
            SackBlock {
                left: 300,
                right: 400
            }
        );
    }

    #[test]
    fn prune_below_trims_left_edge_of_partially_covered_block() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock {
            left: 100,
            right: 300,
        });
        sb.prune_below(200);
        assert_eq!(sb.len(), 1);
        assert_eq!(
            sb.blocks()[0],
            SackBlock {
                left: 200,
                right: 300
            }
        );
    }
}
