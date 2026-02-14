//go:build linux

package collector

import linuxcollector "github.com/melonattacker/logira/collector/linux"

func New(cfg Config) Collector {
	return linuxcollector.NewCollector(cfg)
}
