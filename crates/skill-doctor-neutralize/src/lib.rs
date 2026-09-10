//! Skill Doctor Neutralize — SD-11 defense & host envelope creation.
//!
//! Any content sent to any model MUST pass through this crate first.
//! Neutralization strips dangerous content (bidi overrides, zero-width characters,
//! tag characters) and replaces UTS #39 homoglyphs with their ASCII skeletons
//! before placing the text inside a fenced envelope.
//!
//! This crate is intentionally pure: zero I/O, zero network, zero dependencies
//! on `Finding`, `Report`, or `skill-doctor-core`.

use std::fmt;
use unicode_security::confusable_detection::skeleton;

/// Type of dangerous content removed or replaced during neutralization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalKind {
    /// Bidi control characters (Trojan Source, SD-10).
    BidiOverride(char),
    /// Zero-width or invisible formatting characters (SD-01).
    ZeroWidth(char),
    /// Unicode tag characters (U+E0001..U+E007F, SD-11).
    TagChar(char),
    /// Confusable / homoglyph identifier (SD-10) replaced with its skeleton.
    Confusable { original: String, skeleton: String },
}

impl fmt::Display for RemovalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BidiOverride(c) => write!(f, "bidi control character U+{:04X}", *c as u32),
            Self::ZeroWidth(c) => write!(f, "zero-width character U+{:04X}", *c as u32),
            Self::TagChar(c) => write!(f, "tag character U+{:04X}", *c as u32),
            Self::Confusable { original, skeleton } => {
                write!(f, "confusable '{}' normalized to '{}'", original, skeleton)
            }
        }
    }
}

/// Recorded removal with byte offsets into the ORIGINAL un-neutralized content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// Start and end byte indices in the original content.
    pub byte_span: (usize, usize),
    /// What was removed or replaced.
    pub kind: RemovalKind,
    /// Contextual snippet from the original content.
    pub snippet: String,
}

/// Sanitized envelope prepared for host model evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Sanitized content with dangerous characters removed and confusables replaced.
    pub sanitized: String,
    /// Model-facing fenced wrapper.
    pub fence: String,
    /// Cryptographic nonce bound to this scan session.
    pub nonce: String,
    /// Canonical bundle digest.
    pub digest: String,
    /// Removals recorded during sanitization (for SD-11 / SD-10 / SD-01 findings).
    pub removals: Vec<Removal>,
}

/// Errors occurring during envelope generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeutralizeError {
    EmptyContent,
    InvalidNonce,
    InvalidDigest,
}

impl fmt::Display for NeutralizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyContent => write!(f, "cannot create envelope for empty content"),
            Self::InvalidNonce => write!(f, "nonce cannot be empty"),
            Self::InvalidDigest => write!(f, "bundle digest cannot be empty"),
        }
    }
}

impl std::error::Error for NeutralizeError {}

/// Check if a character is a zero-width or hidden formatting character.
pub fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // Zero Width Space
        | '\u{200C}' // Zero Width Non-Joiner
        | '\u{200D}' // Zero Width Joiner
        | '\u{FEFF}' // BOM / Zero Width No-Break Space
        | '\u{00AD}' // Soft Hyphen
    )
}

/// Check if a character is a bidirectional control character.
pub fn is_bidi_override(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' // LRM
        | '\u{200F}' // RLM
        | '\u{202A}' // LRE
        | '\u{202B}' // RLE
        | '\u{202C}' // PDF
        | '\u{202D}' // LRO
        | '\u{202E}' // RLO
        | '\u{2066}' // LRI
        | '\u{2067}' // RLI
        | '\u{2068}' // FSI
        | '\u{2069}' // PDI
    )
}

/// Check if a character is a tag character (U+E0001..U+E007F).
pub fn is_tag_char(ch: char) -> bool {
    ('\u{E0001}'..='\u{E007F}').contains(&ch)
}

/// Neutralize raw content, stripping dangerous characters and replacing confusables.
///
/// Returns the sanitized string and a list of removals (with offsets into the original text).
pub fn sanitize(content: &str) -> (String, Vec<Removal>) {
    let mut removals = Vec::new();
    let mut intermediate = String::with_capacity(content.len());

    // Phase 1: Strip Zero-Width, Bidi Overrides, and Tag Characters
    for (byte_offset, ch) in content.char_indices() {
        let char_len = ch.len_utf8();
        if is_zero_width(ch) {
            removals.push(Removal {
                byte_span: (byte_offset, byte_offset + char_len),
                kind: RemovalKind::ZeroWidth(ch),
                snippet: format!("U+{:04X}", ch as u32),
            });
        } else if is_bidi_override(ch) {
            removals.push(Removal {
                byte_span: (byte_offset, byte_offset + char_len),
                kind: RemovalKind::BidiOverride(ch),
                snippet: format!("U+{:04X}", ch as u32),
            });
        } else if is_tag_char(ch) {
            removals.push(Removal {
                byte_span: (byte_offset, byte_offset + char_len),
                kind: RemovalKind::TagChar(ch),
                snippet: format!("U+{:04X}", ch as u32),
            });
        } else {
            intermediate.push(ch);
        }
    }

    // Phase 2: Detect and replace UTS #39 Confusables / Homoglyphs across entire text
    let mut sanitized = String::with_capacity(intermediate.len());
    let mut current_word = String::new();
    let mut word_start_byte = 0;

    for (byte_offset, ch) in intermediate.char_indices() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' {
            if current_word.is_empty() {
                word_start_byte = byte_offset;
            }
            current_word.push(ch);
        } else {
            if !current_word.is_empty() {
                process_word(
                    &current_word,
                    word_start_byte,
                    content,
                    &mut sanitized,
                    &mut removals,
                );
                current_word.clear();
            }
            sanitized.push(ch);
        }
    }

    if !current_word.is_empty() {
        process_word(
            &current_word,
            word_start_byte,
            content,
            &mut sanitized,
            &mut removals,
        );
    }

    (sanitized, removals)
}

fn process_word(
    word: &str,
    _intermediate_start: usize,
    original_content: &str,
    sanitized: &mut String,
    removals: &mut Vec<Removal>,
) {
    if !word.is_ascii() {
        let skel: String = skeleton(word).collect();
        if skel != word {
            // Find span in original content if possible
            let byte_span = original_content
                .find(word)
                .map(|start| (start, start + word.len()))
                .unwrap_or((0, word.len()));

            removals.push(Removal {
                byte_span,
                kind: RemovalKind::Confusable {
                    original: word.to_string(),
                    skeleton: skel.clone(),
                },
                snippet: format!("{} -> {}", word, skel),
            });

            // Replace confusable with skeleton so the host model NEVER sees raw homoglyph
            sanitized.push_str(&skel);
            return;
        }
    }

    sanitized.push_str(word);
}

/// Create a neutralized envelope for host evaluation.
///
/// Strips dangerous characters, replaces confusables with their ASCII skeletons,
/// and encloses the result in a dead-simple fence:
/// ```text
/// <<<UNTRUSTED_SKILL nonce={nonce} digest={digest}>>>
/// {sanitized}
/// <<<END_UNTRUSTED_SKILL>>>
/// ```
pub fn create_envelope(
    content: &str,
    nonce: &str,
    digest: &str,
) -> Result<Envelope, NeutralizeError> {
    if content.is_empty() {
        return Err(NeutralizeError::EmptyContent);
    }
    if nonce.is_empty() {
        return Err(NeutralizeError::InvalidNonce);
    }
    if digest.is_empty() {
        return Err(NeutralizeError::InvalidDigest);
    }

    let (sanitized, removals) = sanitize(content);

    let fence = format!(
        "<<<UNTRUSTED_SKILL nonce={} digest={}>>>\n{}\n<<<END_UNTRUSTED_SKILL>>>",
        nonce, digest, sanitized
    );

    Ok(Envelope {
        sanitized,
        fence,
        nonce: nonce.to_string(),
        digest: digest.to_string(),
        removals,
    })
}

/// Helper function to check if content contains dangerous characters without building envelope.
pub fn contains_dangerous_chars(content: &str) -> bool {
    let (sanitized, removals) = sanitize(content);
    !removals.is_empty() || sanitized != content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_space() {
        let raw = "hello\u{200B}world";
        let (clean, removals) = sanitize(raw);
        assert_eq!(clean, "helloworld");
        assert_eq!(removals.len(), 1);
        assert_eq!(removals[0].byte_span, (5, 8)); // U+200B is 3 bytes
    }

    #[test]
    fn strips_bidi_overrides() {
        let raw = "safe = True # \u{202E} if safe: \u{202D} return False";
        let (clean, removals) = sanitize(raw);
        assert!(!clean.contains('\u{202E}'));
        assert!(!clean.contains('\u{202D}'));
        assert_eq!(removals.len(), 2);
    }

    #[test]
    fn replaces_homoglyphs_in_sanitized_fence() {
        // Cyrillic small letter a: U+0430
        let raw = "ev\u{0430}l('system')";
        let (clean, removals) = sanitize(raw);
        assert_eq!(clean, "eval('system')");
        assert!(
            !clean.contains('\u{0430}'),
            "Homoglyph must NOT remain in sanitized text"
        );
        assert_eq!(removals.len(), 1);
        match &removals[0].kind {
            RemovalKind::Confusable { original, skeleton } => {
                assert_eq!(original, "ev\u{0430}l");
                assert_eq!(skeleton, "eval");
            }
            _ => panic!("Expected Confusable removal"),
        }
    }

    #[test]
    fn envelope_fences_content_with_nonce_and_digest() {
        let raw = "run harmless task";
        let env = create_envelope(raw, "nonce123", "digestabc").unwrap();
        assert_eq!(env.nonce, "nonce123");
        assert_eq!(env.digest, "digestabc");
        assert!(env
            .fence
            .starts_with("<<<UNTRUSTED_SKILL nonce=nonce123 digest=digestabc>>>\n"));
        assert!(env.fence.ends_with("\n<<<END_UNTRUSTED_SKILL>>>"));
        assert_eq!(env.sanitized, "run harmless task");
    }

    #[test]
    fn empty_content_errors() {
        let res = create_envelope("", "nonce", "digest");
        assert_eq!(res, Err(NeutralizeError::EmptyContent));
    }
}
