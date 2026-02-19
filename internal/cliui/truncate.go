package cliui

import "unicode/utf8"

// Truncate returns s trimmed to at most max runes. If truncated, "..." is appended.
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if runeCount(s) <= max {
		return s
	}
	if max <= 3 {
		rs := []rune(s)
		if len(rs) > max {
			rs = rs[:max]
		}
		return string(rs)
	}
	rs := []rune(s)
	return string(rs[:max-3]) + "..."
}

func runeCount(s string) int {
	return utf8.RuneCountInString(s)
}
