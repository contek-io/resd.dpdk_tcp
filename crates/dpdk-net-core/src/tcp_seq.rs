//! Wrap-safe u32 TCP-sequence-space comparisons (RFC 9293 §3.4).
//! All comparisons are done via `a.wrapping_sub(b) as i32`, so the
//! "distance" between a and b is valid as long as they are within
//! 2^31 of each other — which is always true for in-flight TCP
//! data on a single connection.

#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// True iff `seq` lies within the half-open window `[start, start+len)`.
/// `len == 0` always returns false (empty window).
#[inline]
pub fn in_window(start: u32, seq: u32, len: u32) -> bool {
    if len == 0 {
        return false;
    }
    let offset = seq.wrapping_sub(start);
    offset < len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lt_across_zero_wrap() {
        // 0xFFFFFFFF is "before" 0 in seq space.
        assert!(seq_lt(0xFFFFFFFF, 0));
        assert!(!seq_lt(0, 0xFFFFFFFF));
        assert!(seq_lt(100, 200));
        assert!(!seq_lt(200, 100));
    }

    #[test]
    fn le_equal() {
        assert!(seq_le(42, 42));
        assert!(!seq_lt(42, 42));
    }

    #[test]
    fn in_window_basic() {
        assert!(in_window(100, 100, 10));
        assert!(in_window(100, 109, 10));
        assert!(!in_window(100, 110, 10));
        assert!(!in_window(100, 99, 10));
    }

    #[test]
    fn in_window_wraps() {
        // Window crossing the zero boundary.
        assert!(in_window(0xFFFFFFF0, 0xFFFFFFF5, 0x20));
        assert!(in_window(0xFFFFFFF0, 0x0000_000F, 0x20));
        assert!(!in_window(0xFFFFFFF0, 0x0000_0010, 0x20));
    }

    #[test]
    fn in_window_zero_len_is_empty() {
        assert!(!in_window(100, 100, 0));
        assert!(!in_window(0xFFFFFFFF, 0xFFFFFFFF, 0));
    }

    #[test]
    fn gt_and_ge_reflect_lt_and_le() {
        assert!(seq_gt(200, 100));
        assert!(!seq_gt(100, 200));
        assert!(seq_ge(100, 100));
    }
}
