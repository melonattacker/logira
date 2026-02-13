//go:build !linux

package collector

import "context"

type stubCollector struct{}

func (s *stubCollector) Init(context.Context) error               { return ErrLinuxOnly }
func (s *stubCollector) Start(context.Context, chan<- Event) error { return ErrLinuxOnly }
func (s *stubCollector) Stop(context.Context) error               { return nil }
func (s *stubCollector) SetTargetPID(int)                         {}
func (s *stubCollector) WaitForIdle(context.Context) error        { return nil }
