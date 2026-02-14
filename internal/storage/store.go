package storage

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mu sync.Mutex

	runID string
	seq   int64

	jsonl *JSONLWriter
	sql   *SQLite

	suspiciousCount int
}

type OpenParams struct {
	RunID    string
	RunDir   string
	StartTS  int64
	Command  string
	Tool     string
	MetaJSON string
}

func Open(p OpenParams) (*Store, error) {
	jsonl, err := NewJSONLWriter(filepath.Join(p.RunDir, "events.jsonl"))
	if err != nil {
		return nil, err
	}
	sqlite, err := OpenSQLite(filepath.Join(p.RunDir, "index.sqlite"))
	if err != nil {
		_ = jsonl.Close()
		return nil, err
	}
	if err := sqlite.InsertRun(RunRow{
		ID:              p.RunID,
		StartTS:         p.StartTS,
		EndTS:           0,
		Command:         p.Command,
		Tool:            p.Tool,
		SuspiciousCount: 0,
		MetaJSON:        p.MetaJSON,
	}); err != nil {
		_ = sqlite.Close()
		_ = jsonl.Close()
		return nil, fmt.Errorf("insert run: %w", err)
	}
	return &Store{runID: p.RunID, jsonl: jsonl, sql: sqlite}, nil
}

func (s *Store) Close(endTS int64, metaJSON string) error {
	s.mu.Lock()
	sus := s.suspiciousCount
	s.mu.Unlock()

	var errs []error
	if s.sql != nil {
		if err := s.sql.UpdateRunEnd(s.runID, endTS, sus, metaJSON); err != nil {
			errs = append(errs, err)
		}
		if err := s.sql.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.jsonl != nil {
		if err := s.jsonl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return joinErrors(errs)
}

func (s *Store) nextSeqLocked() int64 {
	s.seq++
	return s.seq
}

// AppendObserved stores an observed (exec/file/net) event and returns the allocated seq.
func (s *Store) AppendObserved(ts int64, typ EventType, pid, ppid, uid int, summary string, data json.RawMessage, attrs EventRow) (int64, error) {
	s.mu.Lock()
	seq := s.nextSeqLocked()
	s.mu.Unlock()

	ev := Event{
		RunID:    s.runID,
		Seq:      seq,
		TS:       ts,
		Type:     typ,
		PID:      pid,
		PPID:     ppid,
		UID:      uid,
		Summary:  summary,
		DataJSON: data,
	}

	if err := s.jsonl.Append(ev); err != nil {
		return 0, err
	}
	attrs.RunID = s.runID
	attrs.Seq = seq
	attrs.TS = ts
	attrs.Type = string(typ)
	attrs.PID = pid
	attrs.PPID = ppid
	attrs.UID = uid
	attrs.Summary = summary
	attrs.DataJSON = string(data)
	if err := s.sql.InsertEvent(attrs); err != nil {
		return 0, err
	}
	return seq, nil
}

// AppendDetection stores a detection event. It is written to JSONL (type=detection) and to the detections table.
func (s *Store) AppendDetection(ts int64, det Detection, relatedSeq int64) (int64, error) {
	if det.RelatedEventSeq == 0 {
		det.RelatedEventSeq = relatedSeq
	}
	b, err := json.Marshal(det)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	seq := s.nextSeqLocked()
	s.suspiciousCount++
	s.mu.Unlock()

	ev := Event{
		RunID:    s.runID,
		Seq:      seq,
		TS:       ts,
		Type:     TypeDetection,
		Summary:  fmt.Sprintf("[%s] %s: %s", det.Severity, det.RuleID, det.Message),
		DataJSON: b,
	}
	if err := s.jsonl.Append(ev); err != nil {
		return 0, err
	}
	if err := s.sql.InsertDetection(DetectionRow{
		RunID:      s.runID,
		Seq:        seq,
		TS:         ts,
		RuleID:     det.RuleID,
		Severity:   det.Severity,
		Message:    det.Message,
		RelatedSeq: det.RelatedEventSeq,
	}); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *Store) SuspiciousCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suspiciousCount
}

func NowUnixNanos() int64 { return time.Now().UTC().UnixNano() }

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var out error
	for _, e := range errs {
		if e == nil {
			continue
		}
		if out == nil {
			out = e
		} else {
			out = fmt.Errorf("%v; %w", out, e)
		}
	}
	return out
}
