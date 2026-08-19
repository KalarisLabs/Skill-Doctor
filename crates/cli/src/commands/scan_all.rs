//! The `scan-all` command — recursive scanning of directories.

use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;

pub async fn run(directory: &str) -> Result<()> {
    println!(
        "[SCAN-ALL] Scanning directory for skill bundles: {}",
        directory
    );

    let mut found_skills = 0;

    for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if file_name == "SKILL.md" || file_name == ".clauderules" || file_name == ".cursorrules"
            {
                let target_dir = path.parent().unwrap_or_else(|| Path::new("."));
                println!("\n=========================================");
                println!("[SCAN-ALL] Found skill bundle at: {}", target_dir.display());

                let target_str = target_dir.to_string_lossy().to_string();

                if let Err(e) = crate::commands::scan::run(
                    &target_str,
                    None,
                    None,
                    false,
                    false,
                    "core",
                    None,
                    None,
                )
                .await
                {
                    println!("[WARN] Scan failed for {}: {}", target_str, e);
                }
                found_skills += 1;
            }
        }
    }

    println!("\n=========================================");
    println!(
        "[SCAN-ALL] Completed. Scanned {} skill bundles.",
        found_skills
    );
    Ok(())
}
