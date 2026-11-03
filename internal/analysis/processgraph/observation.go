package processgraph

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func decode(ev storage.Event) (Observation, error) {
	o := Observation{Event: ev}
	var target any
	switch ev.Type {
	case storage.TypeExec:
		o.Exec = &model.ExecDetail{}
		target = o.Exec
	case storage.TypeProcess:
		o.Process = &model.ProcessDetail{}
		target = o.Process
	case storage.TypeFile:
		o.File = &model.FileDetail{}
		target = o.File
	case storage.TypeNet:
		o.Net = &model.NetDetail{}
		target = o.Net
	default:
		return o, nil
	}
	if b := bytes.TrimSpace(ev.DataJSON); len(b) == 0 || b[0] != '{' {
		return o, fmt.Errorf("seq %d (%s): data_json must be an object", ev.Seq, ev.Type)
	}
	if err := json.Unmarshal(ev.DataJSON, target); err != nil {
		return o, fmt.Errorf("seq %d (%s): %w", ev.Seq, ev.Type, err)
	}
	switch {
	case o.Exec != nil:
		d := o.Exec
		o.Identity = Identity{TID: d.TID, TGID: d.TGID, Birth: d.TaskStartKernelNS, FirstObserved: d.FirstObservedKernelNS}
		// The exec envelope PID identifies the post-exec task (unlike file/net
		// envelopes, where PID may only identify the thread group).
		if o.Identity.TID == 0 {
			o.Identity.TID = ev.PID
		}
		o.KernelNS = d.KernelTimeNS
	case o.Process != nil:
		d := o.Process
		o.Identity = Identity{TID: d.TID, TGID: d.TGID, Birth: d.TaskStartKernelNS, FirstObserved: d.FirstObservedKernelNS}
		o.KernelNS = d.KernelTimeNS
		switch d.Kind {
		case "fork":
			o.Identity.TID, o.Identity.TGID = d.ChildTID, d.ChildTGID
			if d.TaskStartKernelNS != 0 {
				o.KernelNS = d.TaskStartKernelNS
			}
		case "exec_rekey", "exit":
		default:
			return o, fmt.Errorf("seq %d: unsupported process kind %q", ev.Seq, d.Kind)
		}
	case o.File != nil:
		d := o.File
		o.Identity = Identity{TID: d.TID, TGID: d.TGID, Birth: d.TaskStartKernelNS}
		o.KernelNS = d.KernelTimeNS
	case o.Net != nil:
		d := o.Net
		o.Identity = Identity{TID: d.TID, TGID: d.TGID, Birth: d.TaskStartKernelNS}
		o.KernelNS = d.KernelTimeNS
	}
	if o.Identity.TID < 0 || o.Identity.TGID < 0 {
		return o, fmt.Errorf("seq %d: negative task identity", ev.Seq)
	}
	return o, nil
}

func identityKey(id Identity) string {
	if id.TID <= 0 {
		return ""
	}
	if id.Birth != 0 {
		return fmt.Sprintf("b:%d:%d", id.TID, id.Birth)
	}
	if id.FirstObserved != 0 {
		return fmt.Sprintf("f:%d:%d", id.TID, id.FirstObserved)
	}
	return ""
}
