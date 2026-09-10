use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=../../rules");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("compiled_rules.rs");

    let rules_dir = Path::new("../../rules");
    let mut generated_rules = String::new();

    generated_rules.push_str("pub static COMPILED_RULES: &[CompiledRule] = &[\n");

    if rules_dir.exists() {
        let mut paths: Vec<_> = fs::read_dir(rules_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "yar"))
            .collect();
        paths.sort();

        for path in paths {
            let content = fs::read_to_string(&path).unwrap();
            let (rule_id, class_name, severity, description, string_pats, regex_pats) =
                parse_yar(&content);

            generated_rules.push_str("    CompiledRule {\n");
            generated_rules.push_str(&format!("        rule_id: \"{}\",\n", rule_id));
            generated_rules.push_str(&format!("        class_id: \"{}\",\n", rule_id));
            generated_rules.push_str(&format!("        class_name: \"{}\",\n", class_name));
            generated_rules.push_str(&format!("        severity: \"{}\",\n", severity));
            generated_rules.push_str(&format!("        description: \"{}\",\n", description));

            generated_rules.push_str("        string_patterns: &[\n");
            for pat in string_pats {
                generated_rules.push_str(&format!("            \"{}\",\n", escape_str(&pat)));
            }
            generated_rules.push_str("        ],\n");

            generated_rules.push_str("        regex_patterns: &[\n");
            for reg in regex_pats {
                generated_rules.push_str(&format!("            \"{}\",\n", escape_str(&reg)));
            }
            generated_rules.push_str("        ],\n");
            generated_rules.push_str("    },\n");
        }
    }

    generated_rules.push_str("];\n");

    fs::write(&dest_path, generated_rules).unwrap();
}

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_yar(content: &str) -> (String, String, String, String, Vec<String>, Vec<String>) {
    let mut rule_id = String::new();
    let mut class_name = String::new();
    let mut severity = "HIGH".to_string();
    let mut description = String::new();
    let mut string_pats = Vec::new();
    let mut regex_pats = Vec::new();

    let mut in_strings = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("id = ") {
            rule_id = extract_quoted(trimmed);
        } else if trimmed.starts_with("class = ") {
            class_name = extract_quoted(trimmed);
        } else if trimmed.starts_with("severity = ") {
            severity = extract_quoted(trimmed);
        } else if trimmed.starts_with("description = ") {
            description = extract_quoted(trimmed);
        } else if trimmed == "strings:" {
            in_strings = true;
        } else if trimmed == "condition:" {
            in_strings = false;
        } else if in_strings && trimmed.starts_with('$') {
            if let Some(eq_idx) = trimmed.find('=') {
                let val_part = trimmed[eq_idx + 1..].trim();
                if val_part.starts_with('"') {
                    // String literal
                    let s = extract_quoted(val_part);
                    if !s.is_empty() {
                        string_pats.push(s);
                    }
                } else if let Some(stripped) = val_part.strip_prefix('/') {
                    // Regex
                    if let Some(end_slash) = stripped.rfind('/') {
                        let regex_str = &stripped[..end_slash];
                        regex_pats.push(regex_str.to_string());
                    }
                }
            }
        }
    }

    if rule_id.is_empty() {
        rule_id = "SD-00".to_string();
    }

    (
        rule_id,
        class_name,
        severity,
        description,
        string_pats,
        regex_pats,
    )
}

fn extract_quoted(s: &str) -> String {
    if let Some(first) = s.find('"') {
        if let Some(last) = s[first + 1..].find('"') {
            return s[first + 1..first + 1 + last].to_string();
        }
    }
    String::new()
}
