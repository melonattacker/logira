package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

import (
	_ "modernc.org/sqlite"
)

type SQLite struct {
	DB *sql.DB
}

func OpenSQLite(path string) (*SQLite, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	// Some environments restrict SQLite creating new files under $HOME, but allow
	// opening an existing file. Pre-create the DB file to avoid SQLITE_CANTOPEN.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("precreate sqlite db %s: %w", path, err)
	}
	_ = f.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &SQLite{DB: db}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func OpenSQLiteReadOnly(path string) (*SQLite, error) {
	// We intentionally don't force mode=ro here: some SQLite configurations (e.g.
	// WAL mode) require creating sidecar files to read, and enforcing ro can
	// surface as "attempt to write a readonly database".
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	var userVersion int
	if err := db.QueryRow(`PRAGMA user_version;`).Scan(&userVersion); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read user_version: %w", err)
	}
	if userVersion != 1 {
		_ = db.Close()
		return nil, fmt.Errorf("unsupported sqlite schema version %d", userVersion)
	}
	return &SQLite{DB: db}, nil
}

func (s *SQLite) Close() error { return s.DB.Close() }

func (s *SQLite) init() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA foreign_keys=ON;`,
	}
	for _, st := range stmts {
		if _, err := s.DB.Exec(st); err != nil {
			// Some environments open the DB read-only unexpectedly; treat this as
			// non-fatal so view/query can still read the DB.
			if strings.Contains(err.Error(), "readonly") {
				continue
			}
			return fmt.Errorf("sqlite pragma: %w", err)
		}
	}

	var userVersion int
	if err := s.DB.QueryRow(`PRAGMA user_version;`).Scan(&userVersion); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if userVersion == 0 {
		if err := s.migrateToV1(); err != nil {
			return err
		}
		if _, err := s.DB.Exec(`PRAGMA user_version=1;`); err != nil {
			return fmt.Errorf("set user_version: %w", err)
		}
		userVersion = 1
	}
	if userVersion != 1 {
		return fmt.Errorf("unsupported sqlite schema version %d", userVersion)
	}
	return nil
}

func (s *SQLite) migrateToV1() error {
	ddl := []string{
		`CREATE TABLE IF NOT EXISTS runs(
			id TEXT PRIMARY KEY,
			start_ts INTEGER,
			end_ts INTEGER,
			command TEXT,
			tool TEXT,
			suspicious_count INTEGER,
			meta_json TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS events(
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
			dst_port INTEGER,
			severity TEXT,
			PRIMARY KEY(run_id, seq)
		);`,
		`CREATE TABLE IF NOT EXISTS detections(
			run_id TEXT,
			seq INTEGER,
			ts INTEGER,
			rule_id TEXT,
			severity TEXT,
			message TEXT,
			related_seq INTEGER,
			PRIMARY KEY(run_id, seq)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_ts ON events(run_id, ts);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_type ON events(run_id, type);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_ts_type ON events(run_id, ts, type);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_path ON events(run_id, path);`,
		`CREATE INDEX IF NOT EXISTS idx_events_run_dst ON events(run_id, dst_ip, dst_port);`,
		`CREATE INDEX IF NOT EXISTS idx_detections_run_ts ON detections(run_id, ts);`,
		`CREATE INDEX IF NOT EXISTS idx_detections_run_sev ON detections(run_id, severity);`,
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, st := range ddl {
		if _, err := tx.Exec(st); err != nil {
			return fmt.Errorf("sqlite ddl: %w", err)
		}
	}
	return tx.Commit()
}

type RunRow struct {
	ID              string
	StartTS         int64
	EndTS           int64
	Command         string
	Tool            string
	SuspiciousCount int
	MetaJSON        string
}

func (s *SQLite) InsertRun(r RunRow) error {
	_, err := s.DB.Exec(
		`INSERT INTO runs(id, start_ts, end_ts, command, tool, suspicious_count, meta_json)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.StartTS, r.EndTS, r.Command, r.Tool, r.SuspiciousCount, r.MetaJSON,
	)
	return err
}

func (s *SQLite) UpdateRunEnd(runID string, endTS int64, suspiciousCount int, metaJSON string) error {
	_, err := s.DB.Exec(
		`UPDATE runs SET end_ts=?, suspicious_count=?, meta_json=? WHERE id=?`,
		endTS, suspiciousCount, metaJSON, runID,
	)
	return err
}

type EventRow struct {
	RunID    string
	Seq      int64
	TS       int64
	Type     string
	PID      int
	PPID     int
	UID      int
	Summary  string
	DataJSON string
	Exe      string
	Path     string
	DstIP    string
	DstPort  int
	Severity string
}

func (s *SQLite) InsertEvent(e EventRow) error {
	_, err := s.DB.Exec(
		`INSERT INTO events(run_id, seq, ts, type, pid, ppid, uid, summary, data_json, exe, path, dst_ip, dst_port, severity)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.RunID, e.Seq, e.TS, e.Type, nullInt(e.PID), nullInt(e.PPID), nullInt(e.UID), e.Summary, e.DataJSON,
		nullStr(e.Exe), nullStr(e.Path), nullStr(e.DstIP), nullInt(e.DstPort), nullStr(e.Severity),
	)
	return err
}

type DetectionRow struct {
	RunID      string
	Seq        int64
	TS         int64
	RuleID     string
	Severity   string
	Message    string
	RelatedSeq int64
}

func (s *SQLite) InsertDetection(d DetectionRow) error {
	_, err := s.DB.Exec(
		`INSERT INTO detections(run_id, seq, ts, rule_id, severity, message, related_seq)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		d.RunID, d.Seq, d.TS, d.RuleID, d.Severity, d.Message, nullInt64(d.RelatedSeq),
	)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
