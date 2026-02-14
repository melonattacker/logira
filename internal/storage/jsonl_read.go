package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

func ReadJSONL(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 8*1024*1024)
	out := make([]Event, 0, 1024)
	line := 0
	for s.Scan() {
		line++
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("unmarshal %s:%d: %w", path, line, err)
		}
		out = append(out, ev)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].TS == out[j].TS {
			return out[i].Seq < out[j].Seq
		}
		return out[i].TS < out[j].TS
	})
	return out, nil
}
