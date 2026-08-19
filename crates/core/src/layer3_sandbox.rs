use anyhow::Result;
use microsandbox::NodeSandbox;
use std::path::Path;

use crate::models::Finding;

/// Run behavioral analysis using microsandbox
pub async fn run_sandbox(bundle_dir: &Path) -> Result<Vec<Finding>> {
    tracing::info!(
        "Initializing microsandbox session for {}",
        bundle_dir.display()
    );

    // Initialize the micro VM using the microsandbox Rust SDK
    let _sb = NodeSandbox::create("skill-doctor-sandbox")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create sandbox: {}", e))?;

    tracing::info!("Sandbox session started. Awaiting execution telemetry...");

    // Since this behavioral analysis isn't fully implemented yet, return an error
    // instead of an empty list, so it isn't recorded as successful coverage.
    Err(anyhow::anyhow!(
        "Behavioral sandbox analysis is not yet fully implemented. Telemetry analysis is unsupported."
    ))
}
