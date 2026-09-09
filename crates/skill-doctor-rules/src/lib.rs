//! Skill Doctor Rules — compiled YARA-X rule packs.
//!
//! At build time, `build.rs` compiles all `.yar` files from `rules/` and
//! serializes them into the binary. This crate exposes the compiled rules
//! for use by the L1 pattern engine.
//!
//! Currently: YARA-X is not yet wired. Rule files exist as design artifacts
//! and the pattern engine in `skill-doctor-core::l1` uses regex as a stand-in.
//! When YARA-X is added, `build.rs` will compile the `.yar` files and this
//! crate will expose `compiled_rules() -> &[u8]`.

/// Placeholder: returns the list of rule file stems for coverage tracking.
pub fn rule_classes() -> &'static [&'static str] {
    &[
        "SD-01", "SD-02", "SD-03", "SD-04", "SD-05", "SD-06", "SD-07", "SD-08", "SD-09", "SD-10",
        "SD-11",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_classes_have_rules() {
        assert_eq!(rule_classes().len(), 11);
    }
}
