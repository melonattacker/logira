//go:build !linux

package collector

func New(cfg Config) Collector {
	_ = cfg
	return &stubCollector{}
}
