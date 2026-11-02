//go:build linux && integration

package exectrace

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melonattacker/logira/internal/model"
)

func TestForkOnlyExecReplacementAndExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for eBPF integration test")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for fork and non-leader exec fixture")
	}
	tracer := NewTracer(Config{})
	events, err := tracer.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lifecycle []model.ProcessDetail
	var executions []model.ExecDetail
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range events {
			mu.Lock()
			if ev.Type == "process" {
				var d model.ProcessDetail
				if json.Unmarshal(ev.Detail, &d) == nil {
					lifecycle = append(lifecycle, d)
				}
			}
			if ev.Type == "exec" {
				var d model.ExecDetail
				if json.Unmarshal(ev.Detail, &d) == nil {
					executions = append(executions, d)
				}
			}
			mu.Unlock()
		}
	}()
	defer func() {
		if err := tracer.Stop(context.Background()); err != nil {
			t.Error(err)
		}
		<-done
	}()
	//nolint:gosec // Fixed lifecycle fixture executed with the locally resolved Python interpreter.
	out, err := exec.Command(python, "-c", `import os, threading
print(os.getpid(), flush=True)
pid = os.fork()
if pid == 0:
    os._exit(0)
print(pid, flush=True)
os.waitpid(pid, 0)
def replace():
    print(threading.get_native_id(), flush=True)
    os.execv('/bin/true', ['true'])
t = threading.Thread(target=replace)
t.start()
t.join()
`).Output()
	if err != nil {
		t.Fatal(err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != 3 {
		t.Fatalf("fixture ids=%q", out)
	}
	parent, _ := strconv.Atoi(ids[0])
	child, _ := strconv.Atoi(ids[1])
	thread, _ := strconv.Atoi(ids[2])
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	var fork, exit, rekey *model.ProcessDetail
	for i := range lifecycle {
		d := &lifecycle[i]
		if d.Kind == "fork" && d.ChildTID == child {
			fork = d
		}
		if d.Kind == "exit" && d.TID == child {
			exit = d
		}
		if d.Kind == "exec_rekey" && d.OldPID == thread && d.TID == parent {
			rekey = d
		}
	}
	if fork == nil || exit == nil || rekey == nil {
		t.Fatalf("missing lifecycle: fork=%+v exit=%+v rekey=%+v", fork, exit, rekey)
	}
	if fork.ParentTGID != parent || fork.TaskStartKernelNS == 0 || fork.TaskStartKernelNS != exit.TaskStartKernelNS {
		t.Fatalf("fork-only identity mismatch: fork=%+v exit=%+v", fork, exit)
	}
	found := false
	for _, d := range executions {
		if d.TID == child {
			t.Fatal("fork-only task fabricated exec")
		}
		if d.TID == parent && d.OldPID == thread && d.Filename == "/bin/true" {
			found = true
			if d.TaskStartKernelNS != rekey.TaskStartKernelNS || d.TaskStartKernelNS == 0 {
				t.Fatalf("exec replacement identity=%+v rekey=%+v", d, rekey)
			}
		}
	}
	if !found {
		t.Fatal("non-leader exec missing")
	}
}
