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
var runIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

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

// ValidateRunID rejects path traversal and unexpected characters. run_id is used
// in filesystem paths and must be safe.
func ValidateRunID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("empty run_id")
	}
	if id == "." || id == ".." {
		return fmt.Errorf("invalid run_id %q", id)
	}
	// Explicitly reject path separators even though most callers use filepath.Join,
	// since Join+Clean would turn ".." into parent traversal.
	if strings.ContainsAny(id, string(os.PathSeparator)+"/\\") {
		return fmt.Errorf("invalid run_id %q", id)
	}
	if !runIDRe.MatchString(id) {
		return fmt.Errorf("invalid run_id %q", id)
	}
	return nil
}

// NewRunID returns a unique run id under <home>/runs.
// Format: YYYYMMDD-HHMMSS-<tool>[-N]
func NewRunID(home, tool string, now time.Time) (string, error) {
	tool = SanitizeTool(tool)
	base := fmt.Sprintf("%s-%s", now.UTC().Format("20060102-150405"), tool)
	id := base
	for i := 1; i < 1000; i++ {
		if err := ValidateRunID(id); err != nil {
			return "", err
		}
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
