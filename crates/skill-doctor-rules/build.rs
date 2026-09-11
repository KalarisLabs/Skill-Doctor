use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=../../rules");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo");
    let dest_bin_path = Path::new(&out_dir).join("compiled_rules.bin");

    let rules_dir = Path::new("../../rules");
    let mut compiler = yara_x::Compiler::new();

    if rules_dir.exists() {
        let mut paths: Vec<_> = fs::read_dir(rules_dir)
            .expect("Failed to read rules directory")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "yar"))
            .collect();
        paths.sort();

        for path in paths {
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
            compiler
                .add_source(content.as_str())
                .unwrap_or_else(|e| panic!("Invalid YARA rule {}: {}", path.display(), e));
        }
    }

    let rules = compiler.build();
    let serialized = rules
        .serialize()
        .expect("Failed to serialize compiled YARA-X rules");
    fs::write(&dest_bin_path, serialized).expect("Failed to write compiled_rules.bin");
}
