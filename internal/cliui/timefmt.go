package cliui

import (
	"fmt"
	"strings"
	"time"
)

type TSMode string

const (
	TSRel  TSMode = "rel"
	TSAbs  TSMode = "abs"
	TSBoth TSMode = "both"
)

func ParseTSMode(v string) (TSMode, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	switch TSMode(v) {
	case TSRel, TSAbs, TSBoth:
		return TSMode(v), nil
	default:
		return "", fmt.Errorf("invalid --ts %q (expected abs|rel|both)", v)
	}
}

func FormatTimestamp(ts, startTS int64, mode TSMode) string {
	switch mode {
	case TSAbs:
		return FormatAbsShort(ts)
	case TSBoth:
		if startTS <= 0 {
			return FormatAbsShort(ts)
		}
		return fmt.Sprintf("%s (%s)", FormatRel(ts, startTS), FormatAbsShort(ts))
	case TSRel:
		fallthrough
	default:
		if startTS <= 0 {
			return FormatAbsShort(ts)
		}
		return FormatRel(ts, startTS)
	}
}

func FormatAbsShort(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(0, ts).UTC().Format("15:04:05.000Z")
}

func FormatAbsFull(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(0, ts).UTC().Format(time.RFC3339Nano)
}

func FormatRel(ts, startTS int64) string {
	if ts <= 0 || startTS <= 0 {
		return "-"
	}
	d := time.Duration(ts - startTS)
	return signedSeconds(d)
}

func FormatDuration(startTS, endTS int64) string {
	if startTS <= 0 || endTS <= 0 || endTS < startTS {
		return "-"
	}
	return seconds(time.Duration(endTS - startTS))
}

func signedSeconds(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign = "-"
		d = -d
	}
	return sign + seconds(d)
}

func seconds(d time.Duration) string {
	sec := float64(d) / float64(time.Second)
	s := fmt.Sprintf("%.3f", sec)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		s = "0"
	}
	return s + "s"
}
