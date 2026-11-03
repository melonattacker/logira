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

## Additive OS telemetry

`events.type` also accepts `process`; lifecycle details and new file/network fields
remain in `data_json`. No tables or columns are removed or migrated. Existing
JSONL and SQLite runs remain readable. `logira query --type process` selects the
new lifecycle events; `--type exec` retains its existing meaning. For rename,
`events.path` indexes the old path; the destination is available in `data_json`
(and through `--contains`).

`runs.meta_json` carries the same finalized coverage as `meta.json` after a
successful close. Missing coverage in older runs means unknown. See
[JSONL coverage semantics](jsonl.md#coverage-and-loss-accounting) for failure
counts, partial persistence, observation gaps and shutdown limitations.
