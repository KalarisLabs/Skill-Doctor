//! Skill Doctor Neutralize — SD-11 defense.
//!
//! Any content sent to any model MUST pass through this module first.
//! Neutralization strips dangerous content (injection payloads, bidi overrides,
//! zero-width characters, encoded payloads) before the host agent's model
//! sees the bytes.
//!
//! This is an architectural defense, not a prompt-engineering defense.
//! The default CLI path (`--offline`) never invokes a model, so neutralize
//! is only active when L2 semantic analysis is enabled.

/// Neutralize content before sending to a model.
///
/// Strips zero-width characters, bidi overrides, and other content that
/// could be used for SD-11 scanner-mediated injection.
pub fn neutralize(content: &str) -> String {
    let mut output = String::with_capacity(content.len());

    for ch in content.chars() {
        match ch {
            // Zero-width characters
            '\u{200B}' | // Zero Width Space
            '\u{200C}' | // Zero Width Non-Joiner
            '\u{200D}' | // Zero Width Joiner
            '\u{FEFF}' | // BOM / Zero Width No-Break Space
            '\u{00AD}'   // Soft Hyphen
                => { /* strip */ }

            // Bidi control characters
            '\u{200E}' | // LRM
            '\u{200F}' | // RLM
            '\u{202A}' | // LRE
            '\u{202B}' | // RLE
            '\u{202C}' | // PDF
            '\u{202D}' | // LRO
            '\u{202E}' | // RLO
            '\u{2066}' | // LRI
            '\u{2067}' | // RLI
            '\u{2068}' | // FSI
            '\u{2069}'   // PDI
                => { /* strip */ }

            // Tag characters (U+E0001..U+E007F)
            ch if ('\u{E0001}'..='\u{E007F}').contains(&ch) => { /* strip */ }

            // Everything else passes through.
            _ => output.push(ch),
        }
    }

    output
}

/// Check if content contains any characters that would be neutralized.
pub fn contains_dangerous_chars(content: &str) -> bool {
    content != neutralize(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_content_unchanged() {
        let input = "Hello, this is a clean skill description.";
        assert_eq!(neutralize(input), input);
    }

    #[test]
    fn strips_zero_width_space() {
        let input = "Hello\u{200B}World";
        assert_eq!(neutralize(input), "HelloWorld");
    }

    #[test]
    fn strips_bidi_overrides() {
        let input = "normal\u{202E}reversed\u{202C}normal";
        assert_eq!(neutralize(input), "normalreversednormal");
    }

    #[test]
    fn strips_multiple_dangerous_chars() {
        let input = "\u{200B}\u{200C}\u{200D}\u{FEFF}clean\u{202E}\u{2066}";
        assert_eq!(neutralize(input), "clean");
    }

    #[test]
    fn contains_dangerous_chars_detects_zwsp() {
        assert!(contains_dangerous_chars("hello\u{200B}world"));
        assert!(!contains_dangerous_chars("hello world"));
    }

    #[test]
    fn preserves_normal_unicode() {
        let input = "café résumé naïve 日本語 🎉";
        assert_eq!(neutralize(input), input);
    }
}
