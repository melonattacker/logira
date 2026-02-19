package cliui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type Colorizer struct {
	Enabled bool
}

type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

func ParseColorMode(v string) (ColorMode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return ColorAuto, nil
	case "always":
		return ColorAlways, nil
	case "never":
		return ColorNever, nil
	default:
		return "", fmt.Errorf("invalid --color %q (expected auto|always|never)", v)
	}
}

func NewColorizer(mode ColorMode, noColor bool, out io.Writer) Colorizer {
	if noColor {
		return Colorizer{}
	}
	switch mode {
	case ColorNever:
		return Colorizer{}
	case ColorAlways:
		return Colorizer{Enabled: true}
	}
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return Colorizer{}
	}
	if forceColorEnabled() {
		return Colorizer{Enabled: true}
	}
	f, ok := out.(*os.File)
	if !ok {
		return Colorizer{}
	}
	fi, err := f.Stat()
	if err != nil {
		return Colorizer{}
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return Colorizer{}
	}
	return Colorizer{Enabled: true}
}

func forceColorEnabled() bool {
	for _, k := range []string{"CLICOLOR_FORCE", "FORCE_COLOR"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" || v == "0" {
			continue
		}
		return true
	}
	return false
}

func (c Colorizer) Severity(v string) string {
	if !c.Enabled {
		return v
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "high":
		return wrap(v, "31")
	case "medium":
		return wrap(v, "33")
	case "low":
		return wrap(v, "36")
	case "info":
		return wrap(v, "34")
	default:
		return v
	}
}

func (c Colorizer) Type(v string) string {
	if !c.Enabled {
		return v
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "exec":
		return wrap(v, "32")
	case "file":
		return wrap(v, "35")
	case "net":
		return wrap(v, "36")
	case "detection":
		return wrap(v, "31")
	default:
		return v
	}
}

func wrap(s, code string) string {
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
