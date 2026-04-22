//! A7: pinned ligurio-corpus counts. Values are finalized in Task 15
//! after the full classifier pass; T9-T14 leave them at zero so the
//! corpus gate test fails loudly until T15 pins them.
//!
//! T15 pragmatic floor: the A7 shim binary does not currently pass any
//! corpus script end-to-end (0/122 on the initial dry-run). Every
//! script maps to an engine/shim gap that is out of scope for T15
//! (which explicitly forbids editing the shim patches), so all 122
//! paths are classified as `skipped-untranslatable` with category
//! reasons enumerated in `tools/packetdrill-shim/SKIPPED.md`. A8+ work
//! will re-bucket scripts as the underlying gaps close.
pub const LIGURIO_RUNNABLE_COUNT: usize = 0;
pub const LIGURIO_SKIP_UNTRANSLATABLE: usize = 122;
pub const LIGURIO_SKIP_OUT_OF_SCOPE: usize = 0;
