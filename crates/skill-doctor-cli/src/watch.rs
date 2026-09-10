//! Watch mode for continuous skill scanning on file changes.

use crate::ui::UiContext;
use anyhow::{Context, Result};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use skill_doctor_core::finding::Severity;
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

/// Run interactive watch mode.
pub fn run_watch(
    path: &Path,
    fail_on: Severity,
    deterministic: bool,
    ui: &UiContext,
) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    println!(
        "Watching '{}' for changes (Ctrl+C to exit)...",
        path.display()
    );

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                    let _ = tx.send(());
                }
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_millis(500)),
    )?;

    watcher
        .watch(path, RecursiveMode::Recursive)
        .context("Failed to attach file watcher")?;

    // Initial scan
    perform_watch_scan(path, fail_on, deterministic, ui);

    // Debounced loop on changes
    while let Ok(()) = rx.recv() {
        // Drain any bursts within 200ms
        while rx.recv_timeout(Duration::from_millis(200)).is_ok() {}

        // Clear screen if interactive
        if ui.is_tty {
            print!("\x1B[2J\x1B[1;1H");
        }
        println!("Change detected at {}. Rescanning...", chrono_now());
        perform_watch_scan(path, fail_on, deterministic, ui);
    }

    Ok(())
}

fn perform_watch_scan(path: &Path, fail_on: Severity, deterministic: bool, ui: &UiContext) {
    match l0::intake(path) {
        Ok(bundle) => {
            let report = l5::analyze(
                &bundle,
                &ReportOptions {
                    fail_on,
                    deterministic,
                },
            );
            ui.print_report(&report);
        }
        Err(e) => {
            eprintln!("Scan error: {:#}", e);
        }
    }
}

fn chrono_now() -> String {
    // Simple timestamp without pulling heavy date libraries
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() % 86400;
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02} UTC", hours, mins, s)
}
