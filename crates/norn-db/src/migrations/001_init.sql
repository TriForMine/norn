PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  status TEXT NOT NULL,
  inventory_count INTEGER NOT NULL DEFAULT 0,
  finding_count INTEGER NOT NULL DEFAULT 0,
  scanner_errors_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS inventory_items (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  exposure TEXT NOT NULL,
  data_json TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_inventory_scan ON inventory_items(scan_id);
CREATE INDEX IF NOT EXISTS idx_inventory_item ON inventory_items(item_id);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  inventory_item_id TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  fix_available TEXT NOT NULL,
  data_json TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON vulnerability_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_service ON vulnerability_findings(vulnerability_id, inventory_item_id);

CREATE TABLE IF NOT EXISTS risk_evaluations (
  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  risk_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  inventory_item_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  risk TEXT NOT NULL,
  exposure TEXT NOT NULL,
  data_json TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_risks_scan ON risk_evaluations(scan_id);
CREATE INDEX IF NOT EXISTS idx_risks_vuln_service ON risk_evaluations(vulnerability_id, service_name);

CREATE TABLE IF NOT EXISTS ignored_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id TEXT NOT NULL,
  service TEXT,
  expires_at TEXT,
  reason TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ignored_vuln_service ON ignored_findings(vulnerability_id, service);

CREATE TABLE IF NOT EXISTS notification_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  event_type TEXT NOT NULL,
  service_name TEXT NOT NULL,
  vulnerability_id TEXT,
  risk TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
