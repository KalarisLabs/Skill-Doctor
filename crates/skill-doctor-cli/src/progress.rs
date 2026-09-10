//! Layer B — TTY Progress and Spinners.
//!
//! Activated ONLY when stderr is a TTY and neither `--deterministic` nor `--quiet` is set.
//! Provides brief \r updates that collapse cleanly upon scan completion.

use crate::ui::{ProgressStyleChoice, UiContext};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub struct ScanProgress {
    pb: Option<ProgressBar>,
}

impl ScanProgress {
    pub fn new(
        ui: &UiContext,
        deterministic: bool,
        quiet: bool,
        style_choice: ProgressStyleChoice,
    ) -> Self {
        if !ui.is_tty || deterministic || quiet || style_choice == ProgressStyleChoice::None {
            return Self { pb: None };
        }

        let pb = ProgressBar::new_spinner();
        let template = if ui.use_unicode {
            "{spinner:.green} [{elapsed_precise}] {msg}"
        } else {
            "[{elapsed_precise}] {spinner} {msg}"
        };

        let style = if ui.use_unicode {
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template(template)
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
        } else {
            ProgressStyle::default_spinner()
                .tick_chars(r#"-\|/"#)
                .template(template)
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
        };

        pb.set_style(style);
        pb.enable_steady_tick(Duration::from_millis(80));

        Self { pb: Some(pb) }
    }

    /// Update status message (e.g., L0/L1 layer timeline or current engine).
    pub fn set_status(&self, status: &str) {
        if let Some(pb) = &self.pb {
            pb.set_message(status.to_string());
        }
    }

    /// Update scanning progress on multiple items.
    pub fn set_item_progress(&self, current: usize, total: usize, name: &str) {
        if let Some(pb) = &self.pb {
            pb.set_message(format!(
                "{}/{} skills: scanning '{}' (L1 static engines)...",
                current, total, name
            ));
        }
    }

    /// Complete the progress spinner and clear or leave a brief message.
    pub fn finish_and_clear(self) {
        if let Some(pb) = self.pb {
            pb.finish_and_clear();
        }
    }
}
