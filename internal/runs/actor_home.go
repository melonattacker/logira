package runs

import (
	"fmt"
	"os"
)

// ActorHomeDir returns the home directory of the "actor" who should be used for
// $HOME-based rule evaluation.
//
// - When invoked via sudo, this is the sudo-invoking user's home (best-effort).
// - Otherwise, it is os.UserHomeDir().
func ActorHomeDir() (string, error) {
	// Prefer sudo invoker when running as root under sudo.
	if os.Geteuid() == 0 {
		if inv, ok := sudoInvokerFromEnv(os.Getenv); ok && inv.UID != 0 {
			passwd, err := readPasswd()
			if err == nil {
				if h, ok := lookupHomeFromPasswd(inv.User, inv.UID, passwd); ok {
					return h, nil
				}
			}
		}
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return h, nil
}
