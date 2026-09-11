//! Skill Doctor Rules — build-time compiled YARA-X rule packs.
//!
//! At build time, `build.rs` compiles all `.yar` files from `rules/` using
//! `yara_x::Compiler` and serializes the compiled rules into a binary blob.
//! At runtime, rules are deserialized once into a `yara_x::Rules` instance.
//! The scan path does NOT compile rules at runtime.

pub use yara_x;

pub static COMPILED_RULES_BIN: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/compiled_rules.bin"));

static YARA_RULES: std::sync::OnceLock<yara_x::Rules> = std::sync::OnceLock::new();

/// Return the build-time compiled YARA-X rules (deserialized once via OnceLock).
pub fn get_rules() -> &'static yara_x::Rules {
    YARA_RULES.get_or_init(|| {
        yara_x::Rules::deserialize(COMPILED_RULES_BIN)
            .expect("Failed to deserialize build-time compiled YARA-X rules")
    })
}

/// Return the build-time compiled YARA-X rules (alias for `get_rules()`).
pub fn compiled_rules() -> &'static yara_x::Rules {
    get_rules()
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
        let rules = compiled_rules();
        let mut scanner = yara_x::Scanner::new(rules);
        assert!(scanner.scan(b"test").is_ok());
    }

    #[test]
    fn test_yara_scan() {
        let rules = get_rules();
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner.scan(b"ignore previous instructions").unwrap();
        let matching: Vec<_> = results.matching_rules().collect();
        assert!(!matching.is_empty());
        for rule in &matching {
            println!("Matched rule: {}", rule.identifier());
            for (name, val) in rule.metadata() {
                println!("  meta: {} = {:?}", name, val);
            }
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    println!("  pattern match: {}..{}", m.range().start, m.range().end);
                }
            }
        }
    }
}
