//! Layer C — Opt-in Interactive Terminal Dashboard (TUI).
//!
//! Enabled ONLY with `--features tui` and `--tui`.
//! Uses `ratatui` + `crossterm`.

use anyhow::Result;
use skill_doctor_core::report::Report;

#[cfg(not(feature = "tui"))]
pub fn run_tui(_report: &Report) -> Result<i32> {
    eprintln!("Error: TUI mode was not compiled into this binary.");
    eprintln!("To enable the interactive dashboard, rebuild or reinstall with:");
    eprintln!("    cargo install skill-doctor --features tui");
    eprintln!("or run with:");
    eprintln!("    cargo run --features tui -- scan <PATH> --tui");
    Ok(1)
}

#[cfg(feature = "tui")]
pub fn run_tui(report: &Report) -> Result<i32> {
    use crossterm::{
        event::{self, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
        Terminal,
    };
    use skill_doctor_core::finding::Severity;
    use std::io;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut selected_idx = 0;
    let total_findings = report.findings.len();

    let res = (|| -> Result<()> {
        loop {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Header
                        Constraint::Min(10),   // Main area (split left/right)
                        Constraint::Length(4), // Footer & Coverage Radar
                    ])
                    .split(f.area());

                // Header Block
                let verdict_color = match report.verdict {
                    skill_doctor_core::report::Verdict::Pass => Color::Green,
                    skill_doctor_core::report::Verdict::Fail => Color::Red,
                };
                let header_text = vec![Line::from(vec![
                    Span::styled(
                        " Skill Doctor v2.0 Dashboard ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("| Digest: "),
                    Span::styled(
                        &report.bundle_digest[..8.min(report.bundle_digest.len())],
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(" | Verdict: "),
                    Span::styled(
                        format!("{:?}", report.verdict),
                        Style::default()
                            .fg(verdict_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])];
                let header = Paragraph::new(header_text)
                    .block(Block::default().borders(Borders::ALL).title(" Overview "));
                f.render_widget(header, chunks[0]);

                // Split Main area horizontally
                let main_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .split(chunks[1]);

                // Left: Findings List
                let items: Vec<ListItem> = report
                    .findings
                    .iter()
                    .enumerate()
                    .map(|(i, finding)| {
                        let (sev_str, color) = match finding.severity {
                            Severity::Critical => ("CRIT", Color::LightRed),
                            Severity::High => ("HIGH", Color::Yellow),
                            Severity::Medium => ("MED ", Color::Cyan),
                            Severity::Low => ("LOW ", Color::Gray),
                            Severity::Info => ("INFO", Color::DarkGray),
                        };
                        let prefix = if i == selected_idx { "▶ " } else { "  " };
                        let line = Line::from(vec![
                            Span::styled(prefix, Style::default().fg(Color::White)),
                            Span::styled(
                                format!("[{sev_str}] "),
                                Style::default().fg(color).add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(finding.class.id(), Style::default().fg(Color::White)),
                            Span::raw(" "),
                            Span::styled(&finding.rule_id, Style::default().fg(Color::DarkGray)),
                        ]);
                        ListItem::new(line)
                    })
                    .collect();

                let mut list_state = ListState::default();
                if !items.is_empty() {
                    list_state.select(Some(selected_idx));
                }
                let findings_list = List::new(items)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Detected Findings "),
                    )
                    .highlight_style(Style::default().bg(Color::Rgb(40, 40, 50)));
                f.render_stateful_widget(findings_list, main_chunks[0], &mut list_state);

                // Right: Finding Detail
                let detail_text = if let Some(finding) = report.findings.get(selected_idx) {
                    let mut lines = vec![
                        Line::from(vec![
                            Span::styled("Rule: ", Style::default().add_modifier(Modifier::BOLD)),
                            Span::raw(&finding.rule_id),
                        ]),
                        Line::from(vec![
                            Span::styled(
                                "Threat Class: ",
                                Style::default().add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(format!("{} ({:?})", finding.class.id(), finding.class)),
                        ]),
                        Line::from(vec![
                            Span::styled(
                                "Target Path: ",
                                Style::default().add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(finding.path.display().to_string()),
                        ]),
                        Line::raw(""),
                        Line::styled("Evidence:", Style::default().add_modifier(Modifier::BOLD)),
                    ];
                    for ev in &finding.evidence {
                        lines.push(Line::from(format!("  • {}", ev)));
                    }
                    if let Some(fix) = &finding.remediation {
                        lines.push(Line::raw(""));
                        lines.push(Line::styled(
                            "Recommended Fix:",
                            Style::default()
                                .add_modifier(Modifier::BOLD)
                                .fg(Color::Green),
                        ));
                        lines.push(Line::from(format!("  {}", fix)));
                    }
                    lines
                } else {
                    vec![Line::raw("No finding selected / clean bundle.")]
                };

                let detail_widget = Paragraph::new(detail_text).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Finding Details "),
                );
                f.render_widget(detail_widget, main_chunks[1]);

                // Bottom: Coverage Radar & Help
                let coverage_eval = format!(
                    "Coverage: {}/{} classes ({:.0}%) | Keys: [↑/k] Up  [↓/j] Down  [q/ESC] Quit",
                    report.coverage.evaluable,
                    report.coverage.total,
                    report.coverage.ratio() * 100.0
                );
                let footer = Paragraph::new(vec![Line::raw(coverage_eval)]).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Coverage Radar "),
                );
                f.render_widget(footer, chunks[2]);
            })?;

            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Down | KeyCode::Char('j') => {
                            if total_findings > 0 && selected_idx + 1 < total_findings {
                                selected_idx += 1;
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            selected_idx = selected_idx.saturating_sub(1);
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res?;
    match report.verdict {
        skill_doctor_core::report::Verdict::Pass => Ok(0),
        skill_doctor_core::report::Verdict::Fail => Ok(2),
    }
}
