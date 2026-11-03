//go:build linux

package logirad

import (
	"log"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/ipc"
)

// Retired routes contain only counters, not stores, channels or mutable run
// files. Finalized, user-owned files must not be reopened by the root daemon.
const maxRetiredSessions = 256

type retiredSession struct {
	uid                               int
	enableExec, enableFile, enableNet bool
	loss                              ipc.LateRunLoss
	forwardBase                       collector.DropCounts
}

func (r *retiredSession) record(typ string) {
	var count *uint64
	switch typ {
	case collector.EventTypeExec, collector.EventTypeProcess:
		if r.enableExec {
			count = &r.loss.Process
		}
	case collector.EventTypeFile:
		if r.enableFile {
			count = &r.loss.File
		}
	case collector.EventTypeNet:
		if r.enableNet {
			count = &r.loss.Network
		}
	}
	if count == nil {
		return
	}
	*count += 1
	if *count == 1 {
		log.Printf("late delivery after run %s finalized: type=%s (counts available in daemon status)", r.loss.RunID, typ)
	}
}

// Called under m.mu. Eviction bounds daemon memory and collector loss targets.
func (m *SessionManager) retireLocked(s *session, forward collector.DropCounts) {
	if m.retired == nil {
		m.retired = make(map[uint64]*retiredSession)
	}
	if len(m.retiredOrder) >= maxRetiredSessions {
		m.forgetRetiredLocked(m.retiredOrder[0])
	}
	m.retired[s.cgroupID] = &retiredSession{uid: s.uid, enableExec: s.enableExec, enableFile: s.enableFile, enableNet: s.enableNet,
		loss: ipc.LateRunLoss{RunID: s.meta.RunID}, forwardBase: forward}
	m.retiredOrder = append(m.retiredOrder, s.cgroupID)
}

func (m *SessionManager) lateLossLocked(cgroupID uint64, r *retiredSession) ipc.LateRunLoss {
	now := r.forwardBase
	if tracker, ok := m.collector.(collector.LossSnapshotter); ok {
		now = tracker.SnapshotLossTarget(cgroupID)
	}
	return r.withForwardLoss(now)
}

func (r *retiredSession) withForwardLoss(now collector.DropCounts) ipc.LateRunLoss {
	loss := r.loss
	if r.enableExec && now.Exec >= r.forwardBase.Exec {
		loss.Process += now.Exec - r.forwardBase.Exec
	}
	if r.enableFile && now.File >= r.forwardBase.File {
		loss.File += now.File - r.forwardBase.File
	}
	if r.enableNet && now.Net >= r.forwardBase.Net {
		loss.Network += now.Net - r.forwardBase.Net
	}
	return loss
}

// LateRunLoss supplements immutable persisted metadata with post-finalization
// observed losses. Only the owner (or root) may see a run's counters.
func (m *SessionManager) LateRunLoss(uid int) []ipc.LateRunLoss {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ipc.LateRunLoss
	for _, cgID := range m.retiredOrder {
		r := m.retired[cgID]
		if uid != 0 && r.uid != uid {
			continue
		}
		loss := m.lateLossLocked(cgID, r)
		if loss.Process+loss.File+loss.Network > 0 {
			out = append(out, loss)
		}
	}
	return out
}

func (m *SessionManager) forgetRetiredLocked(cgroupID uint64) {
	r := m.retired[cgroupID]
	if r == nil {
		return
	}
	now := r.forwardBase
	if tracker, ok := m.collector.(collector.LossSnapshotter); ok {
		now = tracker.SnapshotAndUnregisterLossTarget(cgroupID)
	}
	loss := r.withForwardLoss(now)
	log.Printf("retiring late-loss accounting for run %s: process=%d file=%d network=%d", loss.RunID, loss.Process, loss.File, loss.Network)
	delete(m.retired, cgroupID)
	for i, id := range m.retiredOrder {
		if id == cgroupID {
			m.retiredOrder = append(m.retiredOrder[:i], m.retiredOrder[i+1:]...)
			break
		}
	}
}
