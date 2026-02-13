//go:build linux

package collector

import linuxcollector "github.com/melonattacker/agentlogix/collector/linux"

func New(cfg Config) Collector {
	return linuxcollector.NewCollector(cfg)
}
