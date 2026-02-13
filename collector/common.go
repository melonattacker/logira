package collector

import common "github.com/melonattacker/agentlogix/collector/common"

const (
	EventTypeExec = common.EventTypeExec
	EventTypeFile = common.EventTypeFile
	EventTypeNet  = common.EventTypeNet
)

var ErrLinuxOnly = common.ErrLinuxOnly

type Event = common.Event
type Config = common.Config
type Collector = common.Collector
type TargetSetter = common.TargetSetter
type ChildWaiter = common.ChildWaiter
