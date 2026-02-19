package cliui

import (
	"io"
	"strings"
	"unicode/utf8"
)

type Column struct {
	Name       string
	MaxWidth   int
	AlignRight bool
}

func RenderTable(w io.Writer, cols []Column, rows [][]string) {
	if len(cols) == 0 {
		return
	}
	widths := computeWidths(cols, rows)
	for i, c := range cols {
		_, _ = io.WriteString(w, padCell(c.Name, widths[i], c.AlignRight))
		if i < len(cols)-1 {
			_, _ = io.WriteString(w, "  ")
		}
	}
	_, _ = io.WriteString(w, "\n")
	for i, c := range cols {
		_, _ = io.WriteString(w, strings.Repeat("-", max(widths[i], len(c.Name))))
		if i < len(cols)-1 {
			_, _ = io.WriteString(w, "  ")
		}
	}
	_, _ = io.WriteString(w, "\n")
	for _, row := range rows {
		for i, c := range cols {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			cell = truncateForTable(cell, widths[i])
			_, _ = io.WriteString(w, padCell(cell, widths[i], c.AlignRight))
			if i < len(cols)-1 {
				_, _ = io.WriteString(w, "  ")
			}
		}
		_, _ = io.WriteString(w, "\n")
	}
}

func computeWidths(cols []Column, rows [][]string) []int {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = runeLen(c.Name)
	}
	for _, row := range rows {
		for i := range cols {
			if i >= len(row) {
				continue
			}
			widths[i] = max(widths[i], visibleRuneLen(row[i]))
		}
	}
	for i := range cols {
		if cols[i].MaxWidth > 0 && widths[i] > cols[i].MaxWidth {
			widths[i] = cols[i].MaxWidth
		}
	}
	return widths
}

func padCell(s string, width int, right bool) string {
	n := visibleRuneLen(s)
	if n >= width {
		return s
	}
	pad := strings.Repeat(" ", width-n)
	if right {
		return pad + s
	}
	return s + pad
}

func runeLen(s string) int {
	return len([]rune(s))
}

func visibleRuneLen(s string) int {
	return runeLen(stripANSI(s))
}

func truncateForTable(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if visibleRuneLen(s) <= width {
		return s
	}
	return Truncate(stripANSI(s), width)
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if j, ok := consumeANSI(s, i); ok {
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

func consumeANSI(s string, i int) (int, bool) {
	if i+1 >= len(s) || s[i] != 0x1b || s[i+1] != '[' {
		return i, false
	}
	j := i + 2
	for j < len(s) {
		c := s[j]
		if c >= 0x40 && c <= 0x7e {
			return j + 1, true
		}
		j++
	}
	return len(s), true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func SprintTable(cols []Column, rows [][]string) string {
	var b strings.Builder
	RenderTable(&b, cols, rows)
	return b.String()
}
