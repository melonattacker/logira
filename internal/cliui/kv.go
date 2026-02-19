package cliui

import "strings"

type KV struct {
	K string
	V string
}

func JoinKV(pairs ...KV) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if strings.TrimSpace(p.K) == "" {
			continue
		}
		parts = append(parts, p.K+"="+p.V)
	}
	return strings.Join(parts, "  ")
}
