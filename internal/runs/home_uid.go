package runs

import (
	"fmt"
)

// HomeDirForUID returns the user's home directory using /etc/passwd lookup.
// This is intended for root daemons which cannot rely on os.UserHomeDir().
func HomeDirForUID(uid int) (string, error) {
	if uid <= 0 {
		return "", fmt.Errorf("invalid uid %d", uid)
	}
	passwd, err := readPasswd()
	if err != nil {
		return "", err
	}
	h, ok := lookupHomeFromPasswd("", uid, passwd)
	if !ok || h == "" {
		return "", fmt.Errorf("home dir not found for uid %d", uid)
	}
	return h, nil
}
