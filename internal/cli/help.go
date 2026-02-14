package cli

import (
	"flag"
	"io"
	"os"
	"path/filepath"
)

func progName() string {
	if len(os.Args) == 0 {
		return "logira"
	}
	return filepath.Base(os.Args[0])
}

func isHelpRequest(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			return true
		}
	}
	return false
}

func usageWriter(args []string) io.Writer {
	if isHelpRequest(args) {
		return os.Stdout
	}
	return os.Stderr
}

// newFlagSet creates a FlagSet that:
// - prints usage to stdout for help requests, stderr otherwise
// - suppresses flag package's own error printing (main prints errors once)
func newFlagSet(name string, args []string, usage func(w io.Writer, fs *flag.FlagSet)) *flag.FlagSet {
	w := usageWriter(args)
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		// Allow fs.PrintDefaults() to work, but keep parse-time errors suppressed.
		fs.SetOutput(w)
		defer fs.SetOutput(io.Discard)
		usage(w, fs)
	}
	return fs
}
