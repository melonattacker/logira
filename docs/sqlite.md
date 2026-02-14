# logira SQLite Schema

Each run directory contains `index.sqlite` for fast queries:

`$LOGIRA_HOME/runs/<run-id>/index.sqlite`

logira uses `modernc.org/sqlite` (no CGO required).

## Tables

### `runs`

```sql
CREATE TABLE runs(
  id TEXT PRIMARY KEY,
  start_ts INTEGER,
  end_ts INTEGER,
  command TEXT,
  tool TEXT,
  suspicious_count INTEGER,
  meta_json TEXT
);
```

### `events`

```sql
CREATE TABLE events(
  run_id TEXT,
  seq INTEGER,
  ts INTEGER,
  type TEXT,
  pid INTEGER,
  ppid INTEGER,
  uid INTEGER,
  summary TEXT,
  data_json TEXT,
  exe TEXT,
  path TEXT,
  dst_ip TEXT,
  dst_port INTEGER
);
```

`exe`/`path`/`dst_ip`/`dst_port` are extracted columns to accelerate common queries.

### `detections`

```sql
CREATE TABLE detections(
  run_id TEXT,
  seq INTEGER,
  ts INTEGER,
  rule_id TEXT,
  severity TEXT,
  message TEXT,
  related_seq INTEGER
);
```

## Indexes

```sql
CREATE INDEX idx_events_run_ts ON events(run_id, ts);
CREATE INDEX idx_events_run_type ON events(run_id, type);
CREATE INDEX idx_events_run_ts_type ON events(run_id, ts, type);
```
