//! Skill Doctor Rules — compiled YARA rule packs.
//!
//! At build time, `build.rs` compiles all `.yar` files from `rules/` and
//! emits static rule tables embedded directly into the binary.
//! The scan path does NOT compile rules at runtime.

#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub rule_id: &'static str,
    pub class_id: &'static str,
    pub class_name: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub string_patterns: &'static [&'static str],
    pub regex_patterns: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/compiled_rules.rs"));

/// Return all build-time compiled rules.
pub fn compiled_rules() -> &'static [CompiledRule] {
    COMPILED_RULES
}

/// Return the list of rule file stems for coverage tracking.
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
        assert!(!compiled_rules().is_empty());
        assert_eq!(compiled_rules().len(), 11);
    }
}
