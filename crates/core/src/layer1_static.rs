//! Layer 1: Static Analysis — YARA-X + tree-sitter AST + Entropy + Unicode.
//!
//! Equivalent to Python's `skill_doctor/scanner/layer1_static.py`.
//! Uses YARA-X and tree-sitter as native Rust libraries (no FFI overhead).

use std::collections::HashMap;
use std::path::Path;

use rust_embed::RustEmbed;
use walkdir::WalkDir;

use crate::intake::is_text_file;
use crate::models::{Engine, Finding, Severity};

/// Embedded YARA rule files — compiled into the binary at build time.
#[derive(RustEmbed)]
#[folder = "rules/core/"]
#[include = "*.yar"]
struct YaraRules;

/// Run all static analysis passes on a skill bundle directory.
pub fn scan_static(bundle_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(scan_yara(bundle_dir));
    findings.extend(scan_entropy(bundle_dir));
    findings.extend(scan_unicode(bundle_dir));

    // tree-sitter AST analysis for Python files
    findings.extend(scan_python_ast(bundle_dir));

    findings
}

// ---------------------------------------------------------------------------
// YARA-X scanning (native Rust — no bindings!)
// ---------------------------------------------------------------------------

fn scan_yara(bundle_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Compile all embedded YARA rules
    let mut compiler = yara_x::Compiler::new();

    for file_name in YaraRules::iter() {
        if let Some(rule_data) = YaraRules::get(&file_name) {
            let rule_text = String::from_utf8_lossy(&rule_data.data);
            if let Err(e) = compiler.add_source(rule_text.as_ref()) {
                tracing::warn!("Failed to compile YARA rule {}: {}", file_name, e);
                continue;
            }
        }
    }

    let rules = compiler.build();

    // Scan each text file in the bundle
    for entry in WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_text_file(e.path()))
    {
        let file_path = entry.path();
        let data = match std::fs::read(file_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(bundle_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let mut scanner = yara_x::Scanner::new(&rules);
        let scan_results = match scanner.scan(&data) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for matching_rule in scan_results.matching_rules() {
            let metadata: HashMap<&str, &str> = matching_rule
                .metadata()
                .map(|(k, v)| {
                    let val = match v {
                        yara_x::MetaValue::String(s) => s,
                        _ => "",
                    };
                    (k, val)
                })
                .collect();

            let severity = match metadata.get("severity").copied().unwrap_or("MEDIUM") {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::Medium,
            };

            let category = metadata
                .get("category")
                .copied()
                .unwrap_or(matching_rule.identifier());

            let description = metadata
                .get("description")
                .copied()
                .unwrap_or("YARA rule matched");

            findings.push(Finding::new(
                severity,
                category,
                &rel_path,
                None,
                description,
                format!(
                    "Review content flagged by rule '{}'",
                    matching_rule.identifier()
                ),
                Engine::Yara,
                0.85,
            ));
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Python AST analysis via tree-sitter
// ---------------------------------------------------------------------------

/// Dangerous function calls to detect in Python files.
const DANGEROUS_CALLS: &[(&str, Severity, &str, &str)] = &[
    (
        "subprocess.run",
        Severity::High,
        "SD-02 · Command Injection",
        "Command execution via subprocess.run",
    ),
    (
        "subprocess.call",
        Severity::High,
        "SD-02 · Command Injection",
        "Command execution via subprocess.call",
    ),
    (
        "subprocess.Popen",
        Severity::High,
        "SD-02 · Command Injection",
        "Command execution via subprocess.Popen",
    ),
    (
        "os.system",
        Severity::Critical,
        "SD-02 · Command Injection",
        "Shell command execution via os.system",
    ),
    (
        "os.popen",
        Severity::High,
        "SD-02 · Command Injection",
        "Shell command execution via os.popen",
    ),
    (
        "eval",
        Severity::Critical,
        "SD-02 · Command Injection",
        "Dynamic code execution via eval()",
    ),
    (
        "exec",
        Severity::Critical,
        "SD-02 · Command Injection",
        "Dynamic code execution via exec()",
    ),
    (
        "pickle.loads",
        Severity::High,
        "SD-02 · Command Injection",
        "Arbitrary code execution via pickle deserialization",
    ),
    (
        "requests.post",
        Severity::Medium,
        "SD-03 · Data Exfiltration",
        "Outbound HTTP POST — potential data exfiltration",
    ),
    (
        "requests.get",
        Severity::Low,
        "SD-03 · Data Exfiltration",
        "Outbound HTTP GET — review for data leakage",
    ),
    (
        "httpx.post",
        Severity::Medium,
        "SD-03 · Data Exfiltration",
        "Outbound HTTP POST — potential data exfiltration",
    ),
    (
        "urllib.request.urlopen",
        Severity::Medium,
        "SD-03 · Data Exfiltration",
        "Outbound HTTP request — potential data exfiltration",
    ),
];

/// Dangerous attribute access patterns.
const DANGEROUS_ATTRS: &[(&str, Severity, &str, &str)] = &[(
    "os.environ",
    Severity::Medium,
    "SD-03 · Data Exfiltration",
    "Environment variable access — may harvest secrets",
)];

fn scan_python_ast(bundle_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_python::LANGUAGE;
    if parser.set_language(&language.into()).is_err() {
        tracing::warn!("Failed to set tree-sitter Python language");
        return findings;
    }

    for entry in WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "py"))
    {
        let file_path = entry.path();
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(bundle_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => continue,
        };

        // Walk the AST looking for dangerous calls
        let mut cursor = tree.walk();
        walk_ast_for_calls(&source, &mut cursor, &rel_path, &mut findings);
    }

    findings
}

/// Recursively walk the tree-sitter AST to find dangerous function calls.
fn walk_ast_for_calls(
    source: &str,
    cursor: &mut tree_sitter::TreeCursor,
    rel_path: &str,
    findings: &mut Vec<Finding>,
) {
    loop {
        let node = cursor.node();

        if node.kind() == "call" {
            // Extract the function name from the call expression
            if let Some(func_node) = node.child_by_field_name("function") {
                let func_text = func_node.utf8_text(source.as_bytes()).unwrap_or("");

                // Check against dangerous calls
                for &(pattern, severity, category, description) in DANGEROUS_CALLS {
                    if func_text == pattern || func_text.ends_with(pattern) {
                        let line = node.start_position().row + 1; // 1-indexed
                        findings.push(Finding::new(
                            severity,
                            category,
                            rel_path,
                            Some(line),
                            description,
                            format!(
                                "Avoid {} or sanitize inputs; use allowlists for commands",
                                pattern
                            ),
                            Engine::Ast,
                            0.9,
                        ));
                    }
                }

                // Check for dangerous attribute access
                for &(pattern, severity, category, description) in DANGEROUS_ATTRS {
                    if func_text.starts_with(pattern) {
                        let line = node.start_position().row + 1;
                        findings.push(Finding::new(
                            severity,
                            category,
                            rel_path,
                            Some(line),
                            description,
                            "Do not access environment variables unless strictly necessary",
                            Engine::Ast,
                            0.8,
                        ));
                    }
                }
            }
        }

        // Recurse into children
        if cursor.goto_first_child() {
            walk_ast_for_calls(source, cursor, rel_path, findings);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Entropy analysis
// ---------------------------------------------------------------------------

/// Shannon entropy threshold for detecting encoded payloads.
const ENTROPY_THRESHOLD: f64 = 5.5;

fn scan_entropy(bundle_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for entry in WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_text_file(e.path()))
    {
        let file_path = entry.path();
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(bundle_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        // Check entropy in 1024-byte chunks
        for chunk in content.as_bytes().chunks(1024) {
            if chunk.len() < 64 {
                continue;
            }

            let entropy = calculate_entropy(chunk);
            if entropy > ENTROPY_THRESHOLD {
                findings.push(Finding::new(
                    Severity::Medium,
                    "SD-10 · Obfuscation and Evasion",
                    &rel_path,
                    None,
                    format!(
                        "High entropy ({:.2}) detected, possibly indicating encoded content",
                        entropy
                    ),
                    "Review this section for base64, hex, or other encoded payloads",
                    Engine::Entropy,
                    0.7,
                ));
                break; // One finding per file
            }
        }
    }

    findings
}

/// Calculate Shannon entropy of a byte slice.
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Unicode analysis
// ---------------------------------------------------------------------------

fn scan_unicode(bundle_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let zero_width_chars = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];
    let rtl_override = '\u{202E}';

    for entry in WalkDir::new(bundle_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_text_file(e.path()))
    {
        let file_path = entry.path();
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel_path = file_path
            .strip_prefix(bundle_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        for (line_num, line) in content.lines().enumerate() {
            let line_1indexed = line_num + 1;

            // Check for zero-width characters
            let zw_count = line
                .chars()
                .filter(|c| zero_width_chars.contains(c))
                .count();
            if zw_count > 0 {
                findings.push(Finding::new(
                    Severity::High,
                    "SD-01 · Prompt Injection (ASCII Smuggling)",
                    &rel_path,
                    Some(line_1indexed),
                    format!(
                        "Zero-width Unicode characters detected: {} instances",
                        zw_count
                    ),
                    "Strip all non-printable Unicode characters from skill content",
                    Engine::Unicode,
                    0.9,
                ));
            }

            // Check for RTL override
            if line.contains(rtl_override) {
                findings.push(Finding::new(
                    Severity::Medium,
                    "SD-10 · Obfuscation and Evasion",
                    &rel_path,
                    Some(line_1indexed),
                    "RTL override character detected, can be used for obfuscation",
                    "Remove RTL override characters or verify they are legitimate",
                    Engine::Unicode,
                    0.6,
                ));
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_low() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaa";
        let entropy = calculate_entropy(data);
        assert!(entropy < 1.0, "Entropy of repeated chars should be low");
    }

    #[test]
    fn test_calculate_entropy_high() {
        // Random-ish bytes should have high entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        assert!(
            entropy > 7.0,
            "Entropy of all byte values should be high: {}",
            entropy
        );
    }

    #[test]
    fn test_calculate_entropy_empty() {
        assert_eq!(calculate_entropy(b""), 0.0);
    }

    #[test]
    fn test_yara_rules_compile() {
        let mut compiler = yara_x::Compiler::new();
        let mut compiled_count = 0;

        for file_name in YaraRules::iter() {
            if let Some(rule_data) = YaraRules::get(&file_name) {
                let rule_text = String::from_utf8_lossy(&rule_data.data);
                if let Err(e) = compiler.add_source(rule_text.as_ref()) {
                    panic!("Failed to compile YARA rule {}: {}", file_name, e);
                }
                compiled_count += 1;
            }
        }

        assert!(compiled_count > 0, "No YARA rules found to compile");
        // Ensure the rules can actually be built
        let _rules = compiler.build();
    }
}
