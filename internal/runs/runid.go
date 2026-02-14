package runs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var toolSanitizeRe = regexp.MustCompile(`[^a-z0-9._-]+`)

func SanitizeTool(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = toolSanitizeRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	if len(s) > 48 {
		s = s[:48]
		s = strings.TrimRight(s, "-")
		if s == "" {
			return "unknown"
		}
	}
	return s
}

// NewRunID returns a unique run id under <home>/runs.
// Format: YYYYMMDD-HHMMSS-<tool>[-N]
func NewRunID(home, tool string, now time.Time) (string, error) {
	tool = SanitizeTool(tool)
	base := fmt.Sprintf("%s-%s", now.UTC().Format("20060102-150405"), tool)
	id := base
	for i := 1; i < 1000; i++ {
		p := filepath.Join(home, "runs", id)
		_, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return id, nil
			}
			return "", fmt.Errorf("stat %s: %w", p, err)
		}
		id = fmt.Sprintf("%s-%d", base, i+1)
	}
	return "", fmt.Errorf("unable to allocate unique run id for base %q", base)
}
