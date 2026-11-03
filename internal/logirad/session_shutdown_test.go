//go:build linux

package logirad

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/ipc"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type shutdownCollector struct {
	mu       sync.Mutex
	drops    map[uint64]collector.DropCounts
	drain    func(context.Context) error
	finalize func()
}

func (c *shutdownCollector) Init(context.Context) error                          { return nil }
func (c *shutdownCollector) Start(context.Context, chan<- collector.Event) error { return nil }
func (c *shutdownCollector) Stop(context.Context) error                          { return nil }
func (c *shutdownCollector) Drain(ctx context.Context) error {
	if c.drain != nil {
		return c.drain(ctx)
	}
	return nil
}
func (c *shutdownCollector) FinalizeFileCorrelation(uint64) uint64 {
	if c.finalize != nil {
		c.finalize()
	}
	return 0
}
func (c *shutdownCollector) RegisterLossTarget(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drops[id] = collector.DropCounts{}
}
func (c *shutdownCollector) SnapshotLossTarget(id uint64) collector.DropCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.drops[id]
}
func (c *shutdownCollector) SnapshotAndUnregisterLossTarget(id uint64) collector.DropCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.drops[id]
	delete(c.drops, id)
	return v
}

func shutdownSession(t *testing.T, c *shutdownCollector) (*SessionManager, *session) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(storage.OpenParams{RunID: "tail", RunDir: dir, StartTS: 1, MetaJSON: `{}`})
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("s", os.Getuid(), os.Getgid(), dir, true, true, true, dir, dir, runs.Meta{RunID: "tail", Version: 5}, store, nil, nil, 42)
	m := NewSessionManager(c)
	m.bySessionID["s"] = s
	m.byCgroupID[42] = s
	c.RegisterLossTarget(42)
	return m, s
}

func TestConcurrentFinalizationAccountsForEveryDeliveredEvent(t *testing.T) {
	drainEntered, releaseDrain := make(chan struct{}), make(chan struct{})
	finalizerEntered, releaseFinalizer := make(chan struct{}), make(chan struct{})
	c := &shutdownCollector{drops: make(map[uint64]collector.DropCounts),
		drain: func(ctx context.Context) error {
			close(drainEntered)
			select {
			case <-releaseDrain:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		finalize: func() { close(finalizerEntered); <-releaseFinalizer }}
	m, s := shutdownSession(t, c)
	raw, _ := json.Marshal(model.ExecDetail{Filename: "/bin/true", CgroupID: 42})
	ev := collector.Event{Type: collector.EventTypeExec, Detail: raw}
	m.RouteEvent(ev)
	claimed, err := m.takeSessionForStop("s", s.uid, true)
	if err != nil || claimed != s {
		t.Fatalf("claim=%v %v", claimed, err)
	}
	// A collector delivery after stop is claimed must still reach this session.
	m.RouteEvent(ev)
	done := make(chan error, 1)
	go func() { done <- m.finalizeSession(s, 2) }()
	<-drainEntered
	var producers sync.WaitGroup
	for i := 0; i < 4; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for n := 0; n < 1000; n++ {
				m.RouteEvent(ev)
			}
		}()
	}
	close(releaseDrain)
	<-finalizerEntered // admission is now closed, but loss counters still live
	m.RouteEvent(ev)
	close(releaseFinalizer)
	producers.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	m.RouteEvent(ev) // retired routing must account this separately
	meta, err := runs.ReadMeta(s.runDir)
	if err != nil {
		t.Fatal(err)
	}
	events, err := storage.ReadJSONL(filepath.Join(s.runDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	late := m.LateRunLoss(s.uid)
	if len(late) != 1 {
		t.Fatalf("late=%+v", late)
	}
	known := meta.Coverage.Process.KnownLoss
	if got := uint64(len(events)) + known.SessionQueueDropped + known.ShutdownDropped + late[0].Process; got != 4004 {
		t.Fatalf("unaccounted events: got %d, persisted=%d known=%+v late=%+v", got, len(events), known, late)
	}
	if known.ShutdownDropped == 0 || meta.Coverage.Process.Capture != "partial" || meta.Coverage.DeliveryDrain != "snapshot" {
		t.Fatalf("coverage=%+v", meta.Coverage)
	}
	if got := m.LateRunLoss(s.uid + 12345); len(got) != 0 {
		t.Fatalf("leaked other user's run: %+v", got)
	}
	// Collector forwarding losses after the immutable snapshot remain visible.
	c.mu.Lock()
	c.drops[42] = collector.DropCounts{Exec: 7}
	c.mu.Unlock()
	if got := m.LateRunLoss(s.uid)[0].Process; got != late[0].Process+7 {
		t.Fatalf("late forwarding drops missing: %d", got)
	}
	db, err := storage.OpenSQLite(filepath.Join(s.runDir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var data string
	if err := db.DB.QueryRow("SELECT meta_json FROM runs WHERE id='tail'").Scan(&data); err != nil {
		t.Fatal(err)
	}
	var indexed runs.Meta
	if err := json.Unmarshal([]byte(data), &indexed); err != nil {
		t.Fatal(err)
	}
	if indexed.Coverage != meta.Coverage {
		t.Fatalf("coverage mismatch: %+v != %+v", indexed.Coverage, meta.Coverage)
	}
}

func TestFailedDeliveryDrainMakesCoveragePartial(t *testing.T) {
	c := &shutdownCollector{drops: make(map[uint64]collector.DropCounts), drain: func(context.Context) error { return errors.New("flush unavailable") }}
	m, s := shutdownSession(t, c)
	if err := m.StopRun(context.Background(), ipc.PeerCred{UID: s.uid}, "s", 0); err != nil {
		t.Fatal(err)
	}
	meta, err := runs.ReadMeta(s.runDir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Coverage.DeliveryDrain != "failed" || meta.Coverage.DrainFailures != 1 || meta.Coverage.Process.Capture != "partial" {
		t.Fatalf("coverage=%+v", meta.Coverage)
	}
}

func TestRetiredRoutesAreBoundedAndReusedIDsForgetOldRun(t *testing.T) {
	c := &shutdownCollector{drops: make(map[uint64]collector.DropCounts)}
	m := NewSessionManager(c)
	for i := uint64(1); i <= maxRetiredSessions+1; i++ {
		c.RegisterLossTarget(i)
		m.retireLocked(&session{cgroupID: i, meta: runs.Meta{RunID: "old"}}, collector.DropCounts{})
	}
	if len(m.retired) != maxRetiredSessions || len(c.drops) != maxRetiredSessions {
		t.Fatal("retired targets unbounded")
	}
	if m.retired[1] != nil {
		t.Fatal("oldest target not evicted")
	}
	m.forgetRetiredLocked(2)
	c.RegisterLossTarget(2)
	m.retireLocked(&session{cgroupID: 2, meta: runs.Meta{RunID: "new"}}, collector.DropCounts{})
	if len(m.retiredOrder) != maxRetiredSessions || m.retired[2].loss.RunID != "new" {
		t.Fatal("cgroup ID reuse corrupted retired routes")
	}
}
