//! Terminal UI, styling, and formatting (Layer A presentation).
//!
//! Features:
//! - Ripgrep-style finding lines
//! - Degraded severity glyphs (Unicode or ASCII-safe)
//! - One-line scan headers
//! - Coverage strip hero display
//! - Color palettes (Vivid, Dim, Ascii) via `anstyle`
//! - `NO_COLOR` and `--color auto|always|never` compliance

use anstyle::{AnsiColor, Color, Style};
use clap::ValueEnum;
use is_terminal::IsTerminal;
use skill_doctor_core::finding::{Finding, Severity};
use skill_doctor_core::report::Report;
use skill_doctor_core::taxonomy::ThreatClass;
use std::env;
use std::io;

/// Compact, 7-line static ASCII box banner.
/// Shown ONLY on interactive TTYs in human mode (never in CI / SARIF / JSON / deterministic).
pub const ASCII_BANNER: &str = r#" +---------------------------------------+
 |  ____  _     _ _ _   ____             |
 | / ___|| |__ (_) | | |  _ \  ___   ___ |
 | \___ \| '_ \| | | | | | | |/ _ \ / __||
 |  ___) | | | | | | | | |_| | (_) | (__ |
 | |____/|_| |_|_|_|_| |____/ \___/ \___||
 |        AI Agent Security Scanner      |
 +---------------------------------------+"#;

/// Color choice flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

/// Color theme palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub enum ThemeMode {
    #[default]
    Vivid,
    Dim,
    Ascii,
}

/// Glyph style for severity markers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub enum ProgressStyleChoice {
    #[default]
    Auto,
    Unicode,
    Ascii,
    None,
}

/// UI Context managing styling and output configuration.
#[derive(Clone, Debug)]
pub struct UiContext {
    pub use_color: bool,
    pub use_unicode: bool,
    pub theme: ThemeMode,
    pub is_tty: bool,
}

impl UiContext {
    pub fn new(color: ColorChoice, theme: ThemeMode, progress_choice: ProgressStyleChoice) -> Self {
        let is_tty = io::stderr().is_terminal();

        // Check NO_COLOR env (https://no-color.org/)
        let no_color_env = env::var_os("NO_COLOR").is_some();

        let use_color = match color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => is_tty && !no_color_env && theme != ThemeMode::Ascii,
        };

        let use_unicode = match progress_choice {
            ProgressStyleChoice::Unicode => true,
            ProgressStyleChoice::Ascii => false,
            ProgressStyleChoice::None => false,
            ProgressStyleChoice::Auto => {
                theme != ThemeMode::Ascii && !cfg!(windows)
                    || env::var("WT_SESSION").is_ok()
                    || env::var("TERM_PROGRAM").is_ok()
                    || env::var("LANG")
                        .map(|l| l.contains("UTF-8"))
                        .unwrap_or(false)
            }
        };

        Self {
            use_color,
            use_unicode,
            theme,
            is_tty,
        }
    }

    /// Style for CRITICAL severity.
    pub fn style_critical(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        match self.theme {
            ThemeMode::Vivid => Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightRed)))
                .bold(),
            ThemeMode::Dim => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))),
            ThemeMode::Ascii => Style::new(),
        }
    }

    /// Style for HIGH severity.
    pub fn style_high(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        match self.theme {
            ThemeMode::Vivid => Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightYellow)))
                .bold(),
            ThemeMode::Dim => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
            ThemeMode::Ascii => Style::new(),
        }
    }

    /// Style for MEDIUM severity.
    pub fn style_medium(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        match self.theme {
            ThemeMode::Vivid => Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightCyan))),
            ThemeMode::Dim => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))),
            ThemeMode::Ascii => Style::new(),
        }
    }

    /// Style for LOW / INFO severity.
    pub fn style_low(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        Style::new().dimmed()
    }

    /// Style for pass / success.
    pub fn style_pass(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::BrightGreen)))
            .bold()
    }

    /// Style for headers / metadata tags.
    pub fn style_bold(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        Style::new().bold()
    }

    /// Style for dim annotations.
    pub fn style_dim(&self) -> Style {
        if !self.use_color {
            return Style::new();
        }
        Style::new().dimmed()
    }

    /// Glyph for severity.
    pub fn severity_glyph(&self, sev: Severity) -> &'static str {
        if self.use_unicode {
            match sev {
                Severity::Critical => "×",
                Severity::High => "!",
                Severity::Medium => "▲",
                Severity::Low => "•",
                Severity::Info => "ℹ",
            }
        } else {
            match sev {
                Severity::Critical => "CRIT",
                Severity::High => "HIGH",
                Severity::Medium => "MED ",
                Severity::Low => "LOW ",
                Severity::Info => "INFO",
            }
        }
    }

    /// Severity style accessor.
    pub fn severity_style(&self, sev: Severity) -> Style {
        match sev {
            Severity::Critical => self.style_critical(),
            Severity::High => self.style_high(),
            Severity::Medium => self.style_medium(),
            Severity::Low | Severity::Info => self.style_low(),
        }
    }

    /// Print static banner if running interactively.
    pub fn print_banner_if_tty(&self) {
        if self.is_tty && self.theme != ThemeMode::Ascii {
            let dim = self.style_dim();
            let cyan = if self.use_color {
                Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightCyan)))
            } else {
                Style::new()
            };
            eprintln!("{}{}{}", cyan, ASCII_BANNER, dim);
            eprintln!();
        }
    }

    /// Render ripgrep-style finding.
    pub fn format_finding_line(&self, finding: &Finding) -> String {
        let glyph = self.severity_glyph(finding.severity);
        let sev_style = self.severity_style(finding.severity);
        let bold = self.style_bold();
        let dim = self.style_dim();

        let path_str = finding.path.display();
        let location = match &finding.byte_span {
            Some(span) => format!("{}:{}:", path_str, span.start),
            None => format!("{}:", path_str),
        };

        let glyph_str = if self.use_unicode {
            format!("{glyph} {}", finding.severity)
        } else {
            glyph.to_string()
        };

        let mut out = format!(
            "{bold}{location}{bold:#} {sev_style}[{glyph_str}]{sev_style:#} {dim}{}{dim:#} - {}",
            finding.class.id(),
            finding.rule_id
        );

        for ev in &finding.evidence {
            out.push_str(&format!("\n    {dim}evidence:{dim:#} {}", ev));
        }

        if let Some(fix) = &finding.remediation {
            out.push_str(&format!("\n    {dim}fix:{dim:#} {}", fix));
        }

        out
    }

    /// Render coverage strip hero meter.
    pub fn render_coverage_strip(&self, coverage: &skill_doctor_core::report::Coverage) -> String {
        let block_eval = if self.use_unicode { "█" } else { "#" };
        let block_none = if self.use_unicode { "░" } else { "-" };

        let mut parts = Vec::with_capacity(ThreatClass::ALL.len());

        for class in ThreatClass::ALL {
            let has = coverage.per_class.get(class.id()).copied().unwrap_or(false);
            let symbol = if has { block_eval } else { block_none };
            let style = if has {
                self.style_pass()
            } else {
                self.style_dim()
            };
            parts.push(format!("{style}{}{symbol}{style:#}", class.id()));
        }

        parts.join(" ")
    }

    /// Print Layer A report to standard output.
    pub fn print_report(&self, report: &Report) {
        let bold = self.style_bold();
        let dim = self.style_dim();

        // 1. One-line scan header
        let digest_short = if report.bundle_digest.len() >= 8 {
            &report.bundle_digest[..8]
        } else {
            &report.bundle_digest
        };

        let mut layers_active = vec!["L0", "L1"];
        if report.layers.l2 != skill_doctor_core::report::LayerRunState::Skipped {
            layers_active.push("L2");
        }
        if report.layers.l3 != skill_doctor_core::report::LayerRunState::Skipped {
            layers_active.push("L3");
        }
        if report.layers.l4 != skill_doctor_core::report::LayerRunState::Skipped {
            layers_active.push("L4");
        }
        let layers_str = layers_active.join(",");

        println!(
            "{bold}skill-doctor{bold:#} {} digest={dim}{}{dim:#} layers={} coverage={}/{}",
            report.scanner_version,
            digest_short,
            layers_str,
            report.coverage.evaluable,
            report.coverage.total
        );

        // 2. Coverage Strip
        let strip = self.render_coverage_strip(&report.coverage);
        println!(
            "Coverage: {} {dim}({:.0}%){dim:#}",
            strip,
            report.coverage.ratio() * 100.0
        );
        println!();

        // 3. Ripgrep-style findings
        let pass_style = self.style_pass();
        if report.findings.is_empty() {
            let mark = if self.use_unicode { "✓" } else { "[OK]" };
            println!("{pass_style}{mark} No security threats detected.{pass_style:#}");
        } else {
            for finding in &report.findings {
                println!("{}", self.format_finding_line(finding));
            }
        }
        println!();

        // 4. Counts summary & Verdict
        let mut crit = 0;
        let mut high = 0;
        let mut med = 0;
        let mut low = 0;
        for f in &report.findings {
            match f.severity {
                Severity::Critical => crit += 1,
                Severity::High => high += 1,
                Severity::Medium => med += 1,
                Severity::Low | Severity::Info => low += 1,
            }
        }

        let summary_counts = format!("{crit} critical, {high} high, {med} medium, {low} low");

        match report.verdict {
            skill_doctor_core::report::Verdict::Pass => {
                println!("Verdict: {pass_style}PASS{pass_style:#} ({summary_counts})");
            }
            skill_doctor_core::report::Verdict::Fail => {
                let fail_style = self.style_critical();
                println!("Verdict: {fail_style}FAIL{fail_style:#} ({summary_counts}, exit 2)");
            }
        }
    }
}
