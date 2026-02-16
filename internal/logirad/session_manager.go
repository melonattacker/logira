//go:build linux

package logirad

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/cgroupv2"
	"github.com/melonattacker/logira/internal/detect"
	"github.com/melonattacker/logira/internal/ipc"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type SessionManager struct {
	collector collector.Collector

	mu          sync.Mutex
	bySessionID map[string]*session
	byCgroupID  map[uint64]*session
}

func NewSessionManager(col collector.Collector) *SessionManager {
	return &SessionManager{
		collector:   col,
		bySessionID: make(map[string]*session),
		byCgroupID:  make(map[uint64]*session),
	}
}

func (m *SessionManager) StartRun(ctx context.Context, cred ipc.PeerCred, req ipc.StartRunRequest) (ipc.StartRunResponse, error) {
	var out ipc.StartRunResponse

	if strings.TrimSpace(req.RunID) == "" {
		return out, fmt.Errorf("missing run_id")
	}
	if len(req.CmdArgv) == 0 {
		return out, fmt.Errorf("missing cmd_argv")
	}
	cwd := strings.TrimSpace(req.CWD)
	if cwd == "" {
		cwd = "/"
	}

	homeDir, err := runs.HomeDirForUID(cred.UID)
	if err != nil {
		return out, fmt.Errorf("resolve home dir: %w", err)
	}

	base := m.pickLogiraHome(cred.UID, homeDir, strings.TrimSpace(req.LogiraHome))
	if err := os.MkdirAll(filepath.Join(base, "runs"), 0o755); err != nil {
		return out, fmt.Errorf("mkdir logira home: %w", err)
	}

	runDir := runs.RunDir(base, req.RunID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return out, fmt.Errorf("mkdir run dir: %w", err)
	}
	_ = runs.BestEffortChownTree(runDir, cred.UID, cred.GID)

	now := time.Now().UTC()
	startTS := now.UnixNano()
	meta := runs.Meta{
		RunID:       req.RunID,
		StartTS:     startTS,
		Tool:        runs.SanitizeTool(req.Tool),
		Command:     strings.Join(req.CmdArgv, " "),
		CommandArgv: append([]string{}, req.CmdArgv...),
		CWD:         cwd,
		WatchPaths:  append([]string{}, req.WatchPaths...),
		Version:     3,
	}
	if err := runs.WriteMeta(runDir, meta); err != nil {
		return out, err
	}

	// cgroup: /sys/fs/cgroup/logira/<uid>/<session>
	sessionID := uuid.NewString()
	cg, err := cgroupv2.CreateDelegated(req.RunID, cred.UID, cred.GID, sessionID)
	if err != nil {
		return out, err
	}
	meta.CgroupPath = cg.Path
	_ = runs.WriteMeta(runDir, meta)

	cgID, err := cgroupv2.CgroupID(cg.Path)
	if err != nil {
		_ = cg.Remove()
		return out, err
	}

	metaJSONBytes, _ := json.Marshal(meta)
	store, err := storage.Open(storage.OpenParams{
		RunID:    req.RunID,
		RunDir:   runDir,
		StartTS:  startTS,
		Command:  meta.Command,
		Tool:     meta.Tool,
		MetaJSON: string(metaJSONBytes),
	})
	if err != nil {
		_ = cg.Remove()
		return out, err
	}
	_ = runs.BestEffortChownTree(runDir, cred.UID, cred.GID)

	detector := detect.NewEngine(homeDir)

	s := newSession(sessionID, cred.UID, cred.GID, homeDir, req.EnableExec, req.EnableFile, req.EnableNet, base, runDir, meta, store, detector, cg, cgID)
	m.mu.Lock()
	if _, ok := m.bySessionID[sessionID]; ok {
		m.mu.Unlock()
		s.closeWithEnd(storage.NowUnixNanos(), metaJSONBytes)
		return out, fmt.Errorf("session id collision")
	}
	m.bySessionID[sessionID] = s
	m.byCgroupID[cgID] = s
	m.mu.Unlock()

	out = ipc.StartRunResponse{
		Type:       ipc.MsgTypeStartRunOK,
		SessionID:  sessionID,
		CgroupPath: cg.Path,
		RunDir:     runDir,
		CgroupID:   cgID,
	}
	return out, nil
}

func (m *SessionManager) StopRun(ctx context.Context, cred ipc.PeerCred, sessionID string, exitCode int) error {
	_ = ctx
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("missing session_id")
	}

	m.mu.Lock()
	s, ok := m.bySessionID[sessionID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown session_id")
	}
	if s.uid != cred.UID {
		return fmt.Errorf("permission denied")
	}

	endTS := storage.NowUnixNanos()
	meta := s.meta
	meta.EndTS = endTS
	meta.SuspiciousCount = s.store.SuspiciousCount()
	metaJSONBytes, _ := json.Marshal(meta)
	_ = runs.WriteMeta(s.runDir, meta)

	m.mu.Lock()
	delete(m.bySessionID, sessionID)
	delete(m.byCgroupID, s.cgroupID)
	m.mu.Unlock()

	s.closeWithEnd(endTS, metaJSONBytes)

	// Best-effort cleanup.
	_ = s.cg.Remove()
	_ = runs.BestEffortChownTree(s.runDir, s.uid, s.gid)
	_ = exitCode
	return nil
}

func (m *SessionManager) AttachPID(ctx context.Context, cred ipc.PeerCred, sessionID string, pid int) error {
	_ = ctx
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	m.mu.Lock()
	s, ok := m.bySessionID[sessionID]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown session_id")
	}
	if s.uid != cred.UID {
		return fmt.Errorf("permission denied")
	}
	// Verify pid belongs to the same uid, so clients can't move arbitrary pids.
	if u, err := procUID(pid); err != nil || u != cred.UID {
		return fmt.Errorf("attach pid denied")
	}
	return s.cg.JoinPID(pid)
}

func (m *SessionManager) RouteEvent(ev collector.Event) {
	cgID := extractCgroupID(ev.Type, ev.Detail)
	if cgID == 0 {
		return
	}
	m.mu.Lock()
	s := m.byCgroupID[cgID]
	m.mu.Unlock()
	if s == nil {
		return
	}
	s.enqueue(ev)
}

func extractCgroupID(typ string, detail json.RawMessage) uint64 {
	switch storage.EventType(strings.TrimSpace(typ)) {
	case storage.TypeExec, storage.TypeNet, storage.TypeFile:
	default:
		return 0
	}
	var x struct {
		CgroupID uint64 `json:"cgroup_id"`
	}
	_ = json.Unmarshal(detail, &x)
	return x.CgroupID
}

func (m *SessionManager) pickLogiraHome(uid int, homeDir string, requested string) string {
	homeDir = strings.TrimSpace(homeDir)
	if homeDir == "" {
		homeDir = "/"
	}
	if strings.TrimSpace(requested) == "" {
		return filepath.Join(homeDir, ".logira")
	}

	req := filepath.Clean(requested)
	if !filepath.IsAbs(req) {
		// Treat non-absolute requests as relative to home.
		req = filepath.Join(homeDir, req)
		req = filepath.Clean(req)
	}

	// Allow if it already exists and is owned by the user.
	if st, err := os.Stat(req); err == nil {
		if uidOwns(st, uid) {
			return req
		}
	}

	// Allow creation under home dir or a uid-scoped tmp.
	if strings.HasPrefix(req, filepath.Clean(homeDir)+string(os.PathSeparator)) || req == filepath.Clean(homeDir) {
		return req
	}
	tmpUID := filepath.Join(os.TempDir(), "logira-"+strconv.Itoa(uid))
	tmpUID = filepath.Clean(tmpUID)
	if strings.HasPrefix(req, tmpUID+string(os.PathSeparator)) || req == tmpUID {
		return req
	}

	// Fallback.
	return filepath.Join(homeDir, ".logira")
}

func uidOwns(st os.FileInfo, uid int) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return false
	}
	return int(sys.Uid) == uid
}

func procUID(pid int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				u, err := strconv.Atoi(f[1])
				if err != nil {
					return 0, err
				}
				return u, nil
			}
		}
	}
	return 0, fmt.Errorf("uid not found")
}
