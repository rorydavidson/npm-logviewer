export const SCHEMA = `
CREATE TABLE IF NOT EXISTS access_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id         INTEGER,
  source          TEXT NOT NULL,
  ts              INTEGER NOT NULL,
  status          INTEGER NOT NULL,
  upstream_status INTEGER,
  cache_status    TEXT,
  method          TEXT NOT NULL,
  scheme          TEXT NOT NULL,
  host            TEXT NOT NULL,
  uri             TEXT NOT NULL,
  client          TEXT NOT NULL,
  bytes           INTEGER NOT NULL DEFAULT 0,
  gzip            REAL,
  sent_to         TEXT,
  user_agent      TEXT NOT NULL DEFAULT '',
  referer         TEXT NOT NULL DEFAULT '',
  country         TEXT,
  region          TEXT,
  city            TEXT,
  lat             REAL,
  lon             REAL
);

CREATE INDEX IF NOT EXISTS idx_access_ts       ON access_log (ts);
CREATE INDEX IF NOT EXISTS idx_access_host_ts  ON access_log (host_id, ts);
CREATE INDEX IF NOT EXISTS idx_access_status   ON access_log (status);
CREATE INDEX IF NOT EXISTS idx_access_client   ON access_log (client);
CREATE INDEX IF NOT EXISTS idx_access_country  ON access_log (country);

CREATE TABLE IF NOT EXISTS error_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id   INTEGER,
  source    TEXT NOT NULL,
  ts        INTEGER NOT NULL,
  level     TEXT NOT NULL,
  message   TEXT NOT NULL,
  client    TEXT,
  server    TEXT,
  request   TEXT,
  upstream  TEXT
);

CREATE INDEX IF NOT EXISTS idx_error_ts      ON error_log (ts);
CREATE INDEX IF NOT EXISTS idx_error_host_ts ON error_log (host_id, ts);
CREATE INDEX IF NOT EXISTS idx_error_level   ON error_log (level);

-- One row per log file, tracking how far we have ingested so restarts and
-- log rotation are handled without re-reading or dropping lines.
CREATE TABLE IF NOT EXISTS ingest_state (
  source TEXT PRIMARY KEY,
  inode  INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  mtime  INTEGER NOT NULL
);
`;
