package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type JSONLWriter struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &JSONLWriter{f: f, w: bufio.NewWriterSize(f, 256*1024)}, nil
}

func (jw *JSONLWriter) Append(ev Event) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()

	b, err := json.Marshal(ev)
	if err != nil {
		return err
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
