//! A7 Task 9 scaffold: classifier is a stub until Task 13.

use std::path::Path;

pub enum Verdict {
    Runnable,
    SkippedUntranslatable(&'static str),
    SkippedOutOfScope(&'static str),
}

/// Placeholder classifier. Task 13 populates it from
/// tools/packetdrill-shim/classify/ligurio.toml.
pub fn classify(_path: &Path) -> Verdict {
    Verdict::Runnable
}
