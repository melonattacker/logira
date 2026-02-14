package logging

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/melonattacker/logira/collector"
)

type JSONLWriter struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("empty log path")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	return &JSONLWriter{f: f, w: bufio.NewWriterSize(f, 256*1024)}, nil
}

func (jw *JSONLWriter) WriteEvent(ev collector.Event) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if _, err := jw.w.Write(b); err != nil {
		return err
	}
	if err := jw.w.WriteByte('\n'); err != nil {
		return err
	}
	return nil
}

func (jw *JSONLWriter) Close() error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	var ret error
	if jw.w != nil {
		if err := jw.w.Flush(); err != nil {
			ret = err
		}
	}
	if jw.f != nil {
		if err := jw.f.Close(); err != nil && ret == nil {
			ret = err
		}
	}
	return ret
}

func CollectLogFiles(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fi.IsDir() {
		return []string{path}, nil
	}

	files := make([]string, 0, 8)
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".jsonl") || strings.HasSuffix(d.Name(), ".log") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no log files found under %s", path)
	}
	sort.Strings(files)
	return files, nil
}

func ReadEvents(paths []string) ([]collector.Event, error) {
	out := make([]collector.Event, 0, 1024)
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}

		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 64*1024), 8*1024*1024)
		line := 0
		for s.Scan() {
			line++
			if strings.TrimSpace(s.Text()) == "" {
				continue
			}
			var ev collector.Event
			if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("unmarshal %s:%d: %w", path, line, err)
			}
			out = append(out, ev)
		}
		if err := s.Err(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("scan %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		ti, ei := time.Parse(time.RFC3339Nano, out[i].Timestamp)
		tj, ej := time.Parse(time.RFC3339Nano, out[j].Timestamp)
		if ei != nil || ej != nil {
			return out[i].Timestamp < out[j].Timestamp
		}
		if ti.Equal(tj) {
			return i < j
		}
		return ti.Before(tj)
	})

	return out, nil
}
