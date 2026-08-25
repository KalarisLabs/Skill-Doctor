-- Skill Doctor initial schema (D1 / SQLite)
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  source TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  bundle_hash TEXT,
  risk_level TEXT,
  risk_score REAL,
  layers_run TEXT,
  duration_ms INTEGER,
  findings TEXT,
  client_ip TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threats (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT,
  description TEXT,
  remediation TEXT,
  pattern_hash TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,
  payload TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id, id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
