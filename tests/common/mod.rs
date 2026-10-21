//! Helpers shared by more than one test file (`mod common;`). Cargo builds only the
//! top-level `tests/*.rs` as test targets, so this directory is not one.

use std::ops::Range;

/// The byte range of DESIGN §21 (1.0 Rename and distribution) in `design`: from the
/// start of its `## 21. ` heading line to the start of the next `## ` heading line (or
/// the end of the text). `tests/docs_consistency.rs` checks inside it and
/// `tests/program_name.rs` scans everything outside it, so both use one rule.
pub fn design_section_21(design: &str) -> Range<usize> {
    let start = design
        .find("\n## 21. ")
        .expect("DESIGN.md has a §21 heading (`## 21. `)")
        + 1;
    let end = design[start..]
        .find("\n## ")
        .map_or(design.len(), |at| start + at + 1);
    start..end
}
