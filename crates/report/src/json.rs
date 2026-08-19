//! JSON report generation.

use std::path::Path;

use anyhow::Result;
use skill_doctor_core::models::ScanResult;

/// Generate a JSON report file from scan results.
pub fn generate_json(result: &ScanResult, output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(output_path, json)?;
    Ok(())
}
