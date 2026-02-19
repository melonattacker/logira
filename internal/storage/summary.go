package storage

import (
	"database/sql"
	"encoding/json"
	"strings"
)

type GroupedDetection struct {
	Severity         string
	RuleID           string
	Message          string
	Count            int
	FirstTS          int64
	LastTS           int64
	SampleRelatedSeq int64
}

type DetectionWithRelated struct {
	RunID            string
	DetSeq           int64
	DetTS            int64
	RuleID           string
	Severity         string
	Message          string
	RelatedSeq       int64
	RelatedType      EventType
	RelatedTS        int64
	RelatedPID       int
	RelatedSummary   string
	RelatedDataJSON  json.RawMessage
	RelatedEventSeen bool
}

func (s *SQLite) GetRunRow(runID string) (RunRow, error) {
	var out RunRow
	err := s.DB.QueryRow(
		`SELECT id, start_ts, end_ts, command, tool, suspicious_count, meta_json FROM runs WHERE id=?`,
		runID,
	).Scan(&out.ID, &out.StartTS, &out.EndTS, &out.Command, &out.Tool, &out.SuspiciousCount, &out.MetaJSON)
	return out, err
}

func (s *SQLite) CountEventsByType(runID string) (map[EventType]int, error) {
	rows, err := s.DB.Query(`SELECT type, COUNT(*) FROM events WHERE run_id=? GROUP BY type`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[EventType]int{}
	for rows.Next() {
		var typ string
		var c int
		if err := rows.Scan(&typ, &c); err != nil {
			return nil, err
		}
		out[EventType(typ)] = c
	}
	return out, rows.Err()
}

func (s *SQLite) CountDetectionsBySeverity(runID string) (map[string]int, error) {
	rows, err := s.DB.Query(`SELECT severity, COUNT(*) FROM detections WHERE run_id=? GROUP BY severity`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var c int
		if err := rows.Scan(&sev, &c); err != nil {
			return nil, err
		}
		out[sev] = c
	}
	return out, rows.Err()
}

func (s *SQLite) ListGroupedDetections(runID string, limit int) ([]GroupedDetection, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.DB.Query(
		`SELECT severity, rule_id, message, COUNT(*) AS cnt, MIN(ts) AS first_ts, MAX(ts) AS last_ts, MIN(COALESCE(related_seq, 0))
		 FROM detections
		 WHERE run_id=?
		 GROUP BY severity, rule_id, message
		 ORDER BY CASE severity
			WHEN 'high' THEN 4
			WHEN 'medium' THEN 3
			WHEN 'low' THEN 2
			WHEN 'info' THEN 1
			ELSE 0
		 END DESC, cnt DESC, rule_id ASC
		 LIMIT ?`,
		runID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]GroupedDetection, 0, limit)
	for rows.Next() {
		var g GroupedDetection
		if err := rows.Scan(&g.Severity, &g.RuleID, &g.Message, &g.Count, &g.FirstTS, &g.LastTS, &g.SampleRelatedSeq); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *SQLite) ListDetectionsWithRelated(runID string, limit int, offset int) ([]DetectionWithRelated, error) {
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := s.DB.Query(
		`SELECT d.run_id, d.seq, d.ts, d.rule_id, d.severity, d.message, COALESCE(d.related_seq, 0),
		        e.seq, e.ts, e.type, e.pid, e.summary, e.data_json
		 FROM detections d
		 LEFT JOIN events e
		   ON e.run_id=d.run_id AND e.seq=d.related_seq
		 WHERE d.run_id=?
		 ORDER BY d.ts, d.seq
		 LIMIT ? OFFSET ?`,
		runID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]DetectionWithRelated, 0, limit)
	for rows.Next() {
		var (
			r             DetectionWithRelated
			evtSeq        sql.NullInt64
			evtTS         sql.NullInt64
			evtType       sql.NullString
			evtPID        sql.NullInt64
			evtSummary    sql.NullString
			evtData       sql.NullString
			relatedSeqRaw int64
		)
		if err := rows.Scan(
			&r.RunID, &r.DetSeq, &r.DetTS, &r.RuleID, &r.Severity, &r.Message, &relatedSeqRaw,
			&evtSeq, &evtTS, &evtType, &evtPID, &evtSummary, &evtData,
		); err != nil {
			return nil, err
		}
		r.RelatedSeq = relatedSeqRaw
		if evtSeq.Valid {
			r.RelatedEventSeen = true
			r.RelatedTS = evtTS.Int64
			r.RelatedType = EventType(evtType.String)
			r.RelatedPID = int(evtPID.Int64)
			r.RelatedSummary = evtSummary.String
			r.RelatedDataJSON = json.RawMessage(strings.TrimSpace(evtData.String))
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) GetDetectionBySeq(runID string, seq int64) (DetectionRow, error) {
	var (
		out        DetectionRow
		relatedSeq sql.NullInt64
	)
	err := s.DB.QueryRow(
		`SELECT run_id, seq, ts, rule_id, severity, message, related_seq
		 FROM detections
		 WHERE run_id=? AND seq=?`,
		runID, seq,
	).Scan(&out.RunID, &out.Seq, &out.TS, &out.RuleID, &out.Severity, &out.Message, &relatedSeq)
	if err != nil {
		return out, err
	}
	out.RelatedSeq = relatedSeq.Int64
	return out, nil
}

func (s *SQLite) GetEventBySeq(runID string, seq int64) (Event, error) {
	var (
		out             Event
		typ             string
		pid, ppid, uid  sql.NullInt64
		summary, dataJS string
	)
	err := s.DB.QueryRow(
		`SELECT run_id, seq, ts, type, pid, ppid, uid, summary, data_json
		 FROM events
		 WHERE run_id=? AND seq=?`,
		runID, seq,
	).Scan(&out.RunID, &out.Seq, &out.TS, &typ, &pid, &ppid, &uid, &summary, &dataJS)
	if err != nil {
		return out, err
	}
	out.Type = EventType(typ)
	out.PID = int(pid.Int64)
	out.PPID = int(ppid.Int64)
	out.UID = int(uid.Int64)
	out.Summary = summary
	out.DataJSON = json.RawMessage(dataJS)
	return out, nil
}
