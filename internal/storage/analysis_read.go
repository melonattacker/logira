package storage

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// AnalysisSnapshot is an uncapped offline input. This reader intentionally does
// not change the existing query limits or database initialization paths.
type AnalysisSnapshot struct {
	Events         []Event
	MetaJSON       json.RawMessage
	EventSource    string
	MetadataSource string
}

func ReadAnalysisSnapshot(ctx context.Context, runDir, runID string) (AnalysisSnapshot, error) {
	s := AnalysisSnapshot{Events: []Event{}, MetadataSource: "missing"}
	// Read finalization metadata before opening the JSONL snapshot, so a run
	// finishing during the read is still reported as provisional.
	meta, metaErr := os.ReadFile(filepath.Join(runDir, "meta.json")) //nolint:gosec // Resolved run directory; read only.
	if metaErr == nil {
		s.MetaJSON = meta
		s.MetadataSource = "meta.json"
	} else if !errors.Is(metaErr, os.ErrNotExist) {
		return s, fmt.Errorf("read meta.json: %w", metaErr)
	}
	events, err := readAnalysisJSONL(ctx, filepath.Join(runDir, "events.jsonl"))
	if err == nil {
		s.Events = events
		s.EventSource = "jsonl"
	} else if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	if s.EventSource == "" || s.MetadataSource == "missing" {
		path := filepath.Join(runDir, "index.sqlite")
		if _, statErr := os.Stat(path); statErr != nil {
			if s.EventSource == "" || !errors.Is(statErr, os.ErrNotExist) {
				return s, fmt.Errorf("read index.sqlite: %w", statErr)
			}
		} else if err := readAnalysisSQLite(ctx, path, runID, &s); err != nil {
			return s, err
		}
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	return s, nil
}

func readAnalysisJSONL(ctx context.Context, path string) ([]Event, error) {
	f, err := os.Open(path) //nolint:gosec // Resolved run input; no writes.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Do not chase a growing capture. A partially written JSON record fails
	// decoding; callers can retry after the run finishes.
	scanner := bufio.NewScanner(io.LimitReader(f, info.Size()))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	out := []Event{}
	line := 0
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("read %s line %d (possibly incomplete capture; retry after finalization): %w", path, line, err)
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s after line %d (maximum record size 8 MiB): %w", path, line, err)
	}
	return out, nil
}

func readAnalysisSQLite(ctx context.Context, path, runID string, s *AnalysisSnapshot) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("open read-only index.sqlite: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported sqlite schema version %d", version)
	}
	if s.EventSource == "" {
		events, err := readAllAnalysisEvents(ctx, tx, runID)
		if err != nil {
			return fmt.Errorf("read index.sqlite events: %w", err)
		}
		s.Events = events
		s.EventSource = "sqlite"
	}
	if s.MetadataSource == "missing" {
		var meta sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT meta_json FROM runs WHERE id=?`, runID).Scan(&meta)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read SQLite run metadata: %w", err)
		}
		if meta.Valid && strings.TrimSpace(meta.String) != "" {
			s.MetaJSON = json.RawMessage(meta.String)
			s.MetadataSource = "sqlite"
		}
	}
	return tx.Commit()
}

func readAllAnalysisEvents(ctx context.Context, tx *sql.Tx, runID string) ([]Event, error) {
	rows, err := tx.QueryContext(ctx, `SELECT run_id,seq,ts,type,pid,ppid,uid,summary,data_json FROM events WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Event{}
	for rows.Next() {
		var e Event
		var pid, ppid, uid sql.NullInt64
		var data string
		if err := rows.Scan(&e.RunID, &e.Seq, &e.TS, &e.Type, &pid, &ppid, &uid, &e.Summary, &data); err != nil {
			return nil, err
		}
		e.PID = int(pid.Int64)
		e.PPID = int(ppid.Int64)
		e.UID = int(uid.Int64)
		e.DataJSON = json.RawMessage(data)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Detection rows are included only as evidence of their type, allowing a
	// selected non-exec sequence to produce the same error on either backend.
	dets, err := tx.QueryContext(ctx, `SELECT seq,ts,rule_id,severity,message,related_seq FROM detections WHERE run_id=? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dets.Close() }()
	for dets.Next() {
		var e Event
		var d Detection
		var related sql.NullInt64
		if err := dets.Scan(&e.Seq, &e.TS, &d.RuleID, &d.Severity, &d.Message, &related); err != nil {
			return nil, err
		}
		d.RelatedEventSeq = related.Int64
		e.RunID = runID
		e.Type = TypeDetection
		e.Summary = fmt.Sprintf("[%s] %s: %s", d.Severity, d.RuleID, d.Message)
		e.DataJSON, err = json.Marshal(d)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := dets.Err(); err != nil {
		return nil, err
	}
	return out, dets.Close()
}
