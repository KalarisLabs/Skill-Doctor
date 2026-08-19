//! The `scan-all` command — recursive scanning of directories.

use anyhow::Result;

pub async fn run(_directory: &str) -> Result<()> {
    println!("Scan-all command is not fully implemented yet.");
    println!("Future updates will traverse directories and run scans on each detected skill.");
    Ok(())
}
