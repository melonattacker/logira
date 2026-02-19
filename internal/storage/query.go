package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type QueryOptions struct {
	RunID string

	Type                EventType // optional; if detection, only detections
	SinceTS             int64
	UntilTS             int64
	Contains            string
	Path                string
	DstIP               string
	DstPort             int
	Severity            string
	RelatedToDetections bool
	Limit               int
}

func (s *SQLite) Query(opts QueryOptions) ([]Event, error) {
	limit := opts.Limit
	if limit <= 0 || limit > 100000 {
		limit = 100000
	}
	opts.Contains = strings.TrimSpace(opts.Contains)
	opts.Path = strings.TrimSpace(opts.Path)
	opts.DstIP = strings.TrimSpace(opts.DstIP)
	opts.Severity = strings.TrimSpace(opts.Severity)

	var out []Event
	switch opts.Type {
	case TypeDetection:
		evs, err := s.queryDetections(opts, limit)
		if err != nil {
			return nil, err
		}
		return evs, nil
	case TypeExec, TypeFile, TypeNet:
		if opts.RelatedToDetections {
			return s.queryObservedRelatedToDetections(opts, limit)
		}
		evs, err := s.queryObserved(opts, limit)
		if err != nil {
			return nil, err
		}
		return evs, nil
	default:
		var (
			evs []Event
			err error
		)
		if opts.RelatedToDetections {
			evs, err = s.queryObservedRelatedToDetections(opts, limit)
		} else {
			evs, err = s.queryObserved(opts, limit)
		}
		if err != nil {
			return nil, err
		}
		dets, err := s.queryDetections(opts, limit)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
		out = append(out, dets...)
		sort.Slice(out, func(i, j int) bool {
			if out[i].TS == out[j].TS {
				return out[i].Seq < out[j].Seq
			}
			return out[i].TS < out[j].TS
		})
		if len(out) > limit {
			out = out[:limit]
		}
		return out, nil
	}
}

func (s *SQLite) queryObserved(opts QueryOptions, limit int) ([]Event, error) {
	where := []string{`run_id=?`}
	args := []any{opts.RunID}

	if opts.SinceTS > 0 {
		where = append(where, `ts>=?`)
		args = append(args, opts.SinceTS)
	}
	if opts.UntilTS > 0 {
		where = append(where, `ts<=?`)
		args = append(args, opts.UntilTS)
	}
	if opts.Type != "" {
		where = append(where, `type=?`)
		args = append(args, string(opts.Type))
	}
	if opts.Contains != "" {
		where = append(where, `(summary LIKE ? OR data_json LIKE ?)`)
		like := "%" + opts.Contains + "%"
		args = append(args, like, like)
	}
	if opts.Path != "" {
		where = append(where, `path LIKE ?`)
		args = append(args, "%"+opts.Path+"%")
	}
	if opts.DstIP != "" {
		where = append(where, `dst_ip=?`)
		args = append(args, opts.DstIP)
	}
	if opts.DstPort > 0 {
		where = append(where, `dst_port=?`)
		args = append(args, opts.DstPort)
	}

	q := fmt.Sprintf(
		`SELECT run_id, seq, ts, type, pid, ppid, uid, summary, data_json FROM events WHERE %s ORDER BY ts, seq LIMIT ?`,
		strings.Join(where, " AND "),
	)
	args = append(args, limit)

	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Event, 0, 1024)
	for rows.Next() {
		var runID string
		var seq, ts int64
		var typ string
		var pid, ppid, uid sql.NullInt64
		var summary string
		var data string
		if err := rows.Scan(&runID, &seq, &ts, &typ, &pid, &ppid, &uid, &summary, &data); err != nil {
			return nil, err
		}
		out = append(out, Event{
			RunID:    runID,
			Seq:      seq,
			TS:       ts,
			Type:     EventType(typ),
			PID:      int(pid.Int64),
			PPID:     int(ppid.Int64),
			UID:      int(uid.Int64),
			Summary:  summary,
			DataJSON: json.RawMessage(data),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLite) queryObservedRelatedToDetections(opts QueryOptions, limit int) ([]Event, error) {
	where := []string{
		`run_id=?`,
		`seq IN (SELECT related_seq FROM detections WHERE run_id=? AND related_seq IS NOT NULL)`,
	}
	args := []any{opts.RunID, opts.RunID}

	if opts.SinceTS > 0 {
		where = append(where, `ts>=?`)
		args = append(args, opts.SinceTS)
	}
	if opts.UntilTS > 0 {
		where = append(where, `ts<=?`)
		args = append(args, opts.UntilTS)
	}
	if opts.Type != "" {
		where = append(where, `type=?`)
		args = append(args, string(opts.Type))
	}
	if opts.Contains != "" {
		where = append(where, `(summary LIKE ? OR data_json LIKE ?)`)
		like := "%" + opts.Contains + "%"
		args = append(args, like, like)
	}
	if opts.Path != "" {
		where = append(where, `path LIKE ?`)
		args = append(args, "%"+opts.Path+"%")
	}
	if opts.DstIP != "" {
		where = append(where, `dst_ip=?`)
		args = append(args, opts.DstIP)
	}
	if opts.DstPort > 0 {
		where = append(where, `dst_port=?`)
		args = append(args, opts.DstPort)
	}

	q := fmt.Sprintf(
		`SELECT run_id, seq, ts, type, pid, ppid, uid, summary, data_json FROM events WHERE %s ORDER BY ts, seq LIMIT ?`,
		strings.Join(where, " AND "),
	)
	args = append(args, limit)

	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Event, 0, 1024)
	for rows.Next() {
		var runID string
		var seq, ts int64
		var typ string
		var pid, ppid, uid sql.NullInt64
		var summary string
		var data string
		if err := rows.Scan(&runID, &seq, &ts, &typ, &pid, &ppid, &uid, &summary, &data); err != nil {
			return nil, err
		}
		out = append(out, Event{
			RunID:    runID,
			Seq:      seq,
			TS:       ts,
			Type:     EventType(typ),
			PID:      int(pid.Int64),
			PPID:     int(ppid.Int64),
			UID:      int(uid.Int64),
			Summary:  summary,
			DataJSON: json.RawMessage(data),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLite) QueryObservedRelatedToDetections(opts QueryOptions) ([]Event, error) {
	limit := opts.Limit
	if limit <= 0 || limit > 100000 {
		limit = 100000
	}
	opts.Contains = strings.TrimSpace(opts.Contains)
	opts.Path = strings.TrimSpace(opts.Path)
	opts.DstIP = strings.TrimSpace(opts.DstIP)
	return s.queryObservedRelatedToDetections(opts, limit)
}

func (s *SQLite) queryDetections(opts QueryOptions, limit int) ([]Event, error) {
	where := []string{`run_id=?`}
	args := []any{opts.RunID}

	if opts.SinceTS > 0 {
		where = append(where, `ts>=?`)
		args = append(args, opts.SinceTS)
	}
	if opts.UntilTS > 0 {
		where = append(where, `ts<=?`)
		args = append(args, opts.UntilTS)
	}
	if opts.Contains != "" {
		where = append(where, `(rule_id LIKE ? OR message LIKE ?)`)
		like := "%" + opts.Contains + "%"
		args = append(args, like, like)
	}
	if opts.Severity != "" {
		where = append(where, `severity=?`)
		args = append(args, opts.Severity)
	}

	q := fmt.Sprintf(
		`SELECT run_id, seq, ts, rule_id, severity, message, related_seq FROM detections WHERE %s ORDER BY ts, seq LIMIT ?`,
		strings.Join(where, " AND "),
	)
	args = append(args, limit)

	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Event, 0, 128)
	for rows.Next() {
		var runID string
		var seq, ts int64
		var ruleID, sev, msg string
		var related sql.NullInt64
		if err := rows.Scan(&runID, &seq, &ts, &ruleID, &sev, &msg, &related); err != nil {
			return nil, err
		}
		d := Detection{
			RuleID:          ruleID,
			Severity:        sev,
			Message:         msg,
			RelatedEventSeq: related.Int64,
		}
		b, _ := json.Marshal(d)
		out = append(out, Event{
			RunID:    runID,
			Seq:      seq,
			TS:       ts,
			Type:     TypeDetection,
			Summary:  fmt.Sprintf("[%s] %s: %s", sev, ruleID, msg),
			DataJSON: b,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type TopPair struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type NetPair struct {
	Target string `json:"target"`
	Proto  string `json:"proto"`
	Conns  int    `json:"connections"`
	Sent   int64  `json:"sent_bytes"`
	Recv   int64  `json:"recv_bytes"`
}

func (s *SQLite) TopExec(runID string, n int) ([]TopPair, error) {
	return topPairs(s.DB, `SELECT exe, COUNT(*) FROM events WHERE run_id=? AND type='exec' AND exe IS NOT NULL AND exe!='' GROUP BY exe ORDER BY COUNT(*) DESC, exe ASC LIMIT ?`, runID, n)
}

func (s *SQLite) TopPaths(runID string, n int) ([]TopPair, error) {
	return topPairs(s.DB, `SELECT path, COUNT(*) FROM events WHERE run_id=? AND type='file' AND path IS NOT NULL AND path!='' GROUP BY path ORDER BY COUNT(*) DESC, path ASC LIMIT ?`, runID, n)
}

func (s *SQLite) TopDestinations(runID string, n int) ([]TopPair, error) {
	return topPairs(s.DB, `SELECT (dst_ip || ':' || dst_port), COUNT(*) FROM events WHERE run_id=? AND type='net' AND dst_ip IS NOT NULL AND dst_ip!='' AND dst_port IS NOT NULL GROUP BY dst_ip, dst_port ORDER BY COUNT(*) DESC LIMIT ?`, runID, n)
}

func topPairs(db *sql.DB, q string, runID string, n int) ([]TopPair, error) {
	if n <= 0 {
		n = 20
	}
	rows, err := db.Query(q, runID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TopPair, 0, n)
	for rows.Next() {
		var k sql.NullString
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		if !k.Valid {
			continue
		}
		out = append(out, TopPair{Key: k.String, Count: c})
	}
	return out, rows.Err()
}
