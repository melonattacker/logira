//go:build linux

package filewatcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	collector "github.com/melonattacker/agentlogix/collector/common"
	"github.com/melonattacker/agentlogix/internal/model"
)

type Config struct {
	WatchPaths   []string
	HashMaxBytes int64
}

type hashState struct {
	Hash string
	Size int64
}

type Watcher struct {
	cfg Config

	mu       sync.Mutex
	started  bool
	mode     string
	fanFD    int
	inoFD    int
	wdToPath map[int]string
	hashes   map[string]hashState
	out      chan collector.Event
	runWG    sync.WaitGroup
}

func NewWatcher(cfg Config) *Watcher {
	if cfg.HashMaxBytes <= 0 {
		cfg.HashMaxBytes = 10 * 1024 * 1024
	}
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = []string{"."}
	}
	return &Watcher{
		cfg:      cfg,
		fanFD:    -1,
		inoFD:    -1,
		wdToPath: make(map[int]string),
		hashes:   make(map[string]hashState),
	}
}

func (w *Watcher) Init(ctx context.Context) error {
	_ = ctx
	for i, p := range w.cfg.WatchPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("resolve watch path %s: %w", p, err)
		}
		w.cfg.WatchPaths[i] = abs
	}
	return nil
}

func (w *Watcher) Start(ctx context.Context) (<-chan collector.Event, error) {
	if w.started {
		return nil, fmt.Errorf("file watcher already started")
	}

	// Don't hold w.mu while initializing watchers: startInotify walks directories and
	// addInotifyWatch also takes w.mu, which would deadlock.
	w.mu.Lock()
	w.started = true
	w.mu.Unlock()

	if fanErr := w.startFanotify(); fanErr != nil {
		if inoErr := w.startInotify(); inoErr != nil {
			w.mu.Lock()
			w.started = false
			w.mu.Unlock()
			return nil, fmt.Errorf("fanotify failed: %v; inotify failed: %w", fanErr, inoErr)
		}
		w.mode = "inotify"
	} else {
		w.mode = "fanotify"
	}

	out := make(chan collector.Event, 2048)
	w.mu.Lock()
	w.out = out
	w.mu.Unlock()

	w.runWG.Add(1)
	go func() {
		defer w.runWG.Done()
		defer close(out)
		switch w.mode {
		case "fanotify":
			w.runFanotify(ctx)
		case "inotify":
			w.runInotify(ctx)
		}
	}()

	return out, nil
}

func (w *Watcher) Stop(ctx context.Context) error {
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return nil
	}
	fanFD := w.fanFD
	inoFD := w.inoFD
	w.fanFD = -1
	w.inoFD = -1
	w.started = false
	w.mu.Unlock()

	if fanFD >= 0 {
		_ = unix.Close(fanFD)
	}
	if inoFD >= 0 {
		_ = unix.Close(inoFD)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.runWG.Wait()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (w *Watcher) startFanotify() error {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return err
	}

	mask := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_CREATE | unix.FAN_DELETE | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO)
	flags := uint(unix.FAN_MARK_ADD | unix.FAN_MARK_ONLYDIR | unix.FAN_EVENT_ON_CHILD)
	for _, p := range w.cfg.WatchPaths {
		if err := unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, p); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("fanotify mark %s: %w", p, err)
		}
	}

	w.fanFD = fd
	return nil
}

func (w *Watcher) runFanotify(ctx context.Context) {
	const fanMetaSize = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

	buf := make([]byte, 256*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Read(w.fanFD, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			return
		}
		if n <= 0 {
			continue
		}

		offset := 0
		for offset+fanMetaSize <= n {
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if int(meta.Event_len) < fanMetaSize {
				break
			}

			path := ""
			if meta.Fd >= 0 {
				path = w.fdPath(meta.Fd)
				_ = unix.Close(int(meta.Fd))
			}

			op := fanMaskToOp(meta.Mask)
			if op != "" && path != "" {
				ev := w.makeFileEvent(op, path, int(meta.Pid))
				w.emit(ev)
			}

			offset += int(meta.Event_len)
		}
	}
}

func (w *Watcher) startInotify() error {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	w.inoFD = fd

	for _, root := range w.cfg.WatchPaths {
		if err := w.addInotifyRecursive(root); err != nil {
			_ = unix.Close(fd)
			w.inoFD = -1
			return err
		}
	}
	return nil
}

func (w *Watcher) addInotifyRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		return w.addInotifyWatch(path)
	})
}

func (w *Watcher) addInotifyWatch(path string) error {
	mask := uint32(unix.IN_CREATE | unix.IN_CLOSE_WRITE | unix.IN_MODIFY | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF)
	wd, err := unix.InotifyAddWatch(w.inoFD, path, mask)
	if err != nil {
		return fmt.Errorf("inotify add watch %s: %w", path, err)
	}
	w.mu.Lock()
	w.wdToPath[wd] = path
	w.mu.Unlock()
	return nil
}

func (w *Watcher) runInotify(ctx context.Context) {
	buf := make([]byte, 256*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Read(w.inoFD, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				time.Sleep(25 * time.Millisecond)
				continue
			}
			return
		}
		if n <= 0 {
			continue
		}

		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			offset += unix.SizeofInotifyEvent

			name := ""
			if raw.Len > 0 && offset+int(raw.Len) <= n {
				name = strings.TrimRight(string(buf[offset:offset+int(raw.Len)]), "\x00")
				offset += int(raw.Len)
			}

			base := w.watchPath(int(raw.Wd))
			path := base
			if name != "" {
				path = filepath.Join(base, name)
			}

			if raw.Mask&unix.IN_ISDIR != 0 && raw.Mask&unix.IN_CREATE != 0 {
				_ = w.addInotifyWatch(path)
			}

			op := inMaskToOp(raw.Mask)
			if op != "" && path != "" {
				ev := w.makeFileEvent(op, path, 0)
				w.emit(ev)
			}
		}
	}
}

func (w *Watcher) makeFileEvent(op, path string, pid int) collector.Event {
	absPath := path
	if abs, err := filepath.Abs(path); err == nil {
		absPath = abs
	}

	w.mu.Lock()
	before, beforeOK := w.hashes[absPath]
	w.mu.Unlock()

	detail := model.FileDetail{Op: op, Path: absPath}
	if beforeOK {
		detail.HashBefore = before.Hash
		sz := before.Size
		detail.SizeBefore = &sz
	}

	if op == "delete" {
		w.mu.Lock()
		delete(w.hashes, absPath)
		w.mu.Unlock()
	} else {
		h, sz, truncated, err := hashFile(absPath, w.cfg.HashMaxBytes)
		if err == nil {
			detail.HashAfter = h
			detail.HashTruncated = truncated
			sza := sz
			detail.SizeAfter = &sza
			w.mu.Lock()
			w.hashes[absPath] = hashState{Hash: h, Size: sz}
			w.mu.Unlock()
		}
	}

	b, _ := json.Marshal(detail)
	return collector.Event{
		Type:      collector.EventTypeFile,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PID:       pid,
		Detail:    b,
	}
}

func hashFile(path string, maxBytes int64) (hash string, size int64, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err == nil {
		size = st.Size()
	}

	h := sha256.New()
	if maxBytes > 0 {
		_, err = io.CopyN(h, f, maxBytes)
		if err != nil && err != io.EOF {
			return "", size, false, err
		}
		if size > maxBytes {
			truncated = true
		}
	} else {
		if _, err := io.Copy(h, f); err != nil {
			return "", size, false, err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), size, truncated, nil
}

func (w *Watcher) fdPath(fd int32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return path
}

func fanMaskToOp(mask uint64) string {
	if mask&unix.FAN_DELETE != 0 || mask&unix.FAN_MOVED_FROM != 0 {
		return "delete"
	}
	if mask&unix.FAN_CREATE != 0 || mask&unix.FAN_MOVED_TO != 0 {
		return "create"
	}
	if mask&unix.FAN_CLOSE_WRITE != 0 {
		return "modify"
	}
	return ""
}

func inMaskToOp(mask uint32) string {
	if mask&unix.IN_DELETE != 0 || mask&unix.IN_DELETE_SELF != 0 || mask&unix.IN_MOVED_FROM != 0 {
		return "delete"
	}
	if mask&unix.IN_CREATE != 0 || mask&unix.IN_MOVED_TO != 0 {
		return "create"
	}
	if mask&unix.IN_CLOSE_WRITE != 0 || mask&unix.IN_MODIFY != 0 {
		return "modify"
	}
	return ""
}

func (w *Watcher) watchPath(wd int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.wdToPath[wd]
}

func (w *Watcher) emit(ev collector.Event) {
	select {
	case w.out <- ev:
	default:
	}
}
