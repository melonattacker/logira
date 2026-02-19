package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/melonattacker/logira/internal/cgroupv2"
	"github.com/melonattacker/logira/internal/ipc"
	"golang.org/x/sys/unix"
)

type statusRequired struct {
	Exec bool `json:"exec"`
	File bool `json:"file"`
	Net  bool `json:"net"`
}

type statusJSON struct {
	Daemon struct {
		Running      bool   `json:"running"`
		PID          int    `json:"pid"`
		UID          int    `json:"uid"`
		GID          int    `json:"gid"`
		RulesProfile string `json:"rules_profile,omitempty"`
		Sock         string `json:"sock"`
		SocketAccess string `json:"socket_access"`
		SocketError  string `json:"socket_error,omitempty"`

		StatusOK    bool   `json:"status_ok"`
		StatusError string `json:"status_error,omitempty"`
	} `json:"daemon"`
	Kernel struct {
		Release string `json:"release"`
	} `json:"kernel"`
	CgroupV2 struct {
		Enabled bool `json:"enabled"`
	} `json:"cgroup_v2"`
	BPFProbes struct {
		Exec bool `json:"exec"`
		File bool `json:"file"`
		Net  bool `json:"net"`
	} `json:"bpf_probes"`
	Required statusRequired `json:"required"`
	Ready    bool           `json:"ready"`
	Reasons  []string       `json:"reasons"`
}

func StatusCommand(ctx context.Context, args []string) error {
	fs := newFlagSet("status", args, statusUsage)

	var asJSON bool
	var req statusRequired
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.BoolVar(&req.Exec, "exec", true, "require exec tracing")
	fs.BoolVar(&req.File, "file", true, "require file tracing")
	fs.BoolVar(&req.Net, "net", true, "require network tracing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var out statusJSON
	out.Required = req
	out.Daemon.Sock = ipc.SockPath()

	kr := kernelRelease()
	out.Kernel.Release = kr

	out.CgroupV2.Enabled = cgroupv2.Available()

	client, err := ipc.Dial(ctx)
	if err != nil {
		out.Daemon.Running = false
		out.Daemon.SocketAccess = "fail"
		out.Daemon.SocketError = err.Error()
		out.Reasons = append(out.Reasons, "daemon_not_running")
		if !out.CgroupV2.Enabled {
			out.Reasons = append(out.Reasons, "cgroup_v2_disabled")
		}
		out.Ready = false
		return writeStatus(out, asJSON)
	}
	defer client.Close()
	out.Daemon.Running = true
	out.Daemon.SocketAccess = "ok"

	st, err := client.Status(ctx)
	if err != nil {
		out.Daemon.StatusOK = false
		out.Daemon.StatusError = err.Error()
		out.Reasons = append(out.Reasons, "daemon_status_unavailable")
		if !out.CgroupV2.Enabled {
			out.Reasons = append(out.Reasons, "cgroup_v2_disabled")
		}
		out.Ready = false
		return writeStatus(out, asJSON)
	}
	out.Daemon.StatusOK = true
	out.Daemon.PID = st.PID
	out.Daemon.UID = st.UID
	out.Daemon.GID = st.GID
	out.Daemon.RulesProfile = st.RulesProfile
	out.BPFProbes.Exec = st.EnableExec
	out.BPFProbes.File = st.EnableFile
	out.BPFProbes.Net = st.EnableNet

	out.Ready, out.Reasons = decideReady(out, st, req)
	return writeStatus(out, asJSON)
}

func decideReady(out statusJSON, st ipc.StatusResponse, req statusRequired) (bool, []string) {
	reasons := make([]string, 0, 4)
	if !out.CgroupV2.Enabled {
		reasons = append(reasons, "cgroup_v2_disabled")
	}
	if st.UID != 0 {
		reasons = append(reasons, "daemon_not_root")
	}
	if req.Exec && !st.EnableExec {
		reasons = append(reasons, "probe_exec_disabled_in_daemon")
	}
	if req.File && !st.EnableFile {
		reasons = append(reasons, "probe_file_disabled_in_daemon")
	}
	if req.Net && !st.EnableNet {
		reasons = append(reasons, "probe_net_disabled_in_daemon")
	}
	return len(reasons) == 0, reasons
}

func statusUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s status: check if logira is ready on this machine\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s status [flags]\n\n", prog)

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  Ready=YES requires: logirad reachable, logirad running as root, cgroup v2 enabled, and required probes enabled in logirad.")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s status\n", prog)
	fmt.Fprintf(w, "  %s status --json\n", prog)
	fmt.Fprintf(w, "  %s status --net=false\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}

func writeStatus(s statusJSON, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}

	daemonLine := "not running"
	if s.Daemon.Running && s.Daemon.StatusOK {
		daemonLine = fmt.Sprintf("running (pid %d, uid %d)", s.Daemon.PID, s.Daemon.UID)
	} else if s.Daemon.Running {
		daemonLine = "running (socket ok; status unavailable)"
	}

	sockAccess := strings.ToUpper(s.Daemon.SocketAccess)
	if sockAccess == "" {
		sockAccess = "UNKNOWN"
	}
	if strings.TrimSpace(s.Daemon.SocketError) != "" {
		sockAccess = fmt.Sprintf("%s (%s)", sockAccess, strings.TrimSpace(s.Daemon.SocketError))
	}

	probeWord := func(ok bool) string {
		if ok {
			return "OK"
		}
		return "FAIL"
	}

	readyWord := "NO"
	if s.Ready {
		readyWord = "YES"
	}

	fmt.Fprintf(os.Stdout, "Daemon:        %s\n", daemonLine)
	if strings.TrimSpace(s.Kernel.Release) != "" {
		fmt.Fprintf(os.Stdout, "Kernel:        %s\n", s.Kernel.Release)
	}
	if s.CgroupV2.Enabled {
		fmt.Fprintf(os.Stdout, "cgroup v2:     enabled\n")
	} else {
		fmt.Fprintf(os.Stdout, "cgroup v2:     disabled\n")
	}
	if s.Daemon.StatusOK {
		fmt.Fprintf(os.Stdout, "BPF probes:    exec %s  file %s  net %s\n", probeWord(s.BPFProbes.Exec), probeWord(s.BPFProbes.File), probeWord(s.BPFProbes.Net))
		if strings.TrimSpace(s.Daemon.RulesProfile) != "" {
			fmt.Fprintf(os.Stdout, "Rules profile: %s\n", s.Daemon.RulesProfile)
		}
	} else {
		fmt.Fprintf(os.Stdout, "BPF probes:    exec UNKNOWN  file UNKNOWN  net UNKNOWN\n")
	}
	fmt.Fprintf(os.Stdout, "Socket access: %s\n", sockAccess)
	fmt.Fprintf(os.Stdout, "Ready:         %s\n", readyWord)
	return nil
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return utsString(uts.Release[:])
}

func utsString(b []byte) string {
	// Utsname fields are fixed-size NUL-terminated byte arrays.
	n := 0
	for ; n < len(b); n++ {
		if b[n] == 0 {
			break
		}
	}
	return strings.TrimSpace(string(b[:n]))
}
