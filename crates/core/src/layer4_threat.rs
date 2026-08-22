//! Layer 4: Threat Database (hash-based lookup against known-malicious skill fingerprints).
//!
//! Provides persistent storage of known-bad bundle hashes using SQLite.
//! When a bundle hash matches a previously flagged malicious payload,
//! the scan short-circuits with cached findings.

use std::path::PathBuf;

use crate::models::{Engine, Finding, Severity};

/// Database file name stored alongside the Skill Doctor config.
const DB_FILENAME: &str = "threat_db.sqlite";

/// Get the path to the threat database file.
///
/// Stores the DB in the user's config directory:
/// - Linux/macOS: `~/.config/skill-doctor/threat_db.sqlite`
/// - Windows: `%APPDATA%/skill-doctor/threat_db.sqlite`
fn db_path() -> PathBuf {
    let base = dirs_path();
    std::fs::create_dir_all(&base).ok();
    base.join(DB_FILENAME)
}

fn dirs_path() -> PathBuf {
    if let Some(config) = dirs::config_dir() {
        config.join("skill-doctor")
    } else {
        // Fallback to current directory
        PathBuf::from(".skill-doctor")
    }
}

/// Initialize the SQLite database schema if it doesn't exist.
fn init_db(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS threat_hashes (
            hash        TEXT PRIMARY KEY NOT NULL,
            category    TEXT NOT NULL,
            severity    TEXT NOT NULL,
            description TEXT NOT NULL,
            added_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_threat_hash ON threat_hashes(hash);",
    )?;
    Ok(())
}

/// Check bundle hash against the persistent threat database.
///
/// Returns cached findings if the hash exists in the database.
pub fn scan_threat_db(bundle_hash: &str) -> Option<Vec<Finding>> {
    let conn = match rusqlite::Connection::open(db_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Threat DB unavailable: {}", e);
            return None;
        }
    };

    if init_db(&conn).is_err() {
        return None;
    }

    tracing::debug!(
        "Threat DB lookup for hash: {}...",
        &bundle_hash[..bundle_hash.len().min(16)]
    );

    let mut stmt = match conn
        .prepare("SELECT category, severity, description FROM threat_hashes WHERE hash = ?1")
    {
        Ok(s) => s,
        Err(_) => return None,
    };

    let findings: Vec<Finding> = stmt
        .query_map([bundle_hash], |row| {
            let category: String = row.get(0)?;
            let severity_str: String = row.get(1)?;
            let description: String = row.get(2)?;
            Ok((category, severity_str, description))
        })
        .ok()?
        .filter_map(|r| r.ok())
        .map(|(category, severity_str, description)| {
            let severity = match severity_str.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::Info,
            };

            Finding::new(
                severity,
                &category,
                "bundle",
                None,
                format!("Known malicious payload (Threat DB): {}", description),
                "This skill bundle matches a known-malicious hash in the community threat database. Do NOT install.",
                Engine::ThreatDb,
                1.0, // Maximum confidence for DB matches
            )
        })
        .collect();

    if findings.is_empty() {
        None
    } else {
        tracing::warn!(
            "Threat DB HIT: {} cached finding(s) for hash {}",
            findings.len(),
            bundle_hash
        );
        Some(findings)
    }
}

/// Add CRITICAL/HIGH findings to the persistent threat database.
///
/// Only persists findings at CRITICAL or HIGH severity to avoid
/// polluting the database with low-confidence noise.
pub fn add_to_threat_db(bundle_hash: &str, findings: &[Finding]) {
    let critical_high: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .collect();

    if critical_high.is_empty() {
        return;
    }

    let conn = match rusqlite::Connection::open(db_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Threat DB write failed: {}", e);
            return;
        }
    };

    if init_db(&conn).is_err() {
        return;
    }

    for finding in &critical_high {
        let severity_str = format!("{}", finding.severity);
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO threat_hashes (hash, category, severity, description) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![bundle_hash, finding.category, severity_str, finding.description],
        ) {
            tracing::warn!("Failed to insert threat hash: {}", e);
        }
    }

    tracing::info!(
        "Added {} finding(s) to threat DB for hash {}",
        critical_high.len(),
        bundle_hash
    );
}

/// Get statistics about the threat database.
pub fn threat_db_stats() -> Option<(usize, String)> {
    let path = db_path();
    let conn = rusqlite::Connection::open(&path).ok()?;
    init_db(&conn).ok()?;

    let count: usize = conn
        .query_row("SELECT COUNT(*) FROM threat_hashes", [], |row| row.get(0))
        .ok()?;

    Some((count, path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Override db_path for tests by using an in-memory database.
    fn test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn
    }

    #[test]
    fn test_init_creates_table() {
        let conn = test_db();
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='threat_hashes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_and_lookup() {
        let conn = test_db();

        // Insert a threat hash
        conn.execute(
            "INSERT INTO threat_hashes (hash, category, severity, description) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "abc123deadbeef",
                "SD-01 · Prompt Injection",
                "CRITICAL",
                "Known malicious prompt injection payload"
            ],
        )
        .unwrap();

        // Verify it exists
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM threat_hashes WHERE hash = ?1",
                ["abc123deadbeef"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_no_match_returns_zero() {
        let conn = test_db();
        let count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM threat_hashes WHERE hash = ?1",
                ["nonexistent_hash"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_upsert_replaces() {
        let conn = test_db();

        conn.execute(
            "INSERT INTO threat_hashes (hash, category, severity, description) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["hash1", "SD-01", "HIGH", "First version"],
        )
        .unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO threat_hashes (hash, category, severity, description) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["hash1", "SD-01", "CRITICAL", "Updated to CRITICAL"],
        )
        .unwrap();

        let severity: String = conn
            .query_row(
                "SELECT severity FROM threat_hashes WHERE hash = ?1",
                ["hash1"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(severity, "CRITICAL");
    }
}
